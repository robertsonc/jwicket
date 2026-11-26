"""Sign-in limits that only failed sign-ins can use up.

Junos applies its own login retry options to the NETCONF session as well; these limits exist so a
browser-facing endpoint cannot be used to drive those attempts (or RADIUS/TACACS+ load) at speed,
without letting anyone who cannot sign in lock everyone else out:

* Only an attempt that reached the backend and failed counts. A malformed request, an empty field, a
  user name that fails the format check, a refused origin and a successful sign-in cost nothing.
* Failures are counted per (source address, user name), so one person's typing mistakes, or a
  guesser working on one account, do not block other accounts. A looser count per source address
  over all user names stops one address from spraying names. Behind the SSH tunnel every client is
  127.0.0.1, so for tunnel users that looser count is a daemon-wide budget; filling it still takes
  real failed sign-ins, each of which Junos itself logs and applies its retry options to.
* Sources are compared as networks, not spellings: an IPv6 source counts as its /64 and an
  IPv4-mapped address as the IPv4 address, so rotating addresses inside one /64 does not reset the
  source's budget.
* There is no failure count per user name across sources, on the owner's decision (2026-11-26):
  it would let anyone who can reach the listener and knows a user name keep that account out of
  J-Wicket. Junos's own ``system login retry-options`` apply to every attempt that reaches it, and
  are where an across-source lockout policy belongs.
* There is no daemon-wide per-minute budget. Instead at most ``concurrent`` sign-ins are checked by
  the backend at once, which bounds the load on Junos and its AAA servers.

A named account can still be locked out on purpose by failing its sign-in repeatedly, as it can with
Junos retry options (qualification Q-AUTH-04).
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from typing import Callable, Deque, Optional, Tuple, TypeVar

from jwicket.peer import peer_key

MAX_TRACKED_SOURCES = 1024
MAX_TRACKED_NAMES = 4096
K = TypeVar("K")


def name_key(user: str) -> str:
    """User names compared for limits: RADIUS or TACACS+ may accept case variants of one name."""
    return user.strip().casefold()


class LoginThrottle:
    def __init__(
        self,
        *,
        per_name: int,
        per_source: int,
        concurrent: int = 2,
        window_s: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._per_name = per_name
        self._per_source = per_source
        self._window = window_s
        self._clock = clock
        self._lock = threading.Lock()
        self._names: OrderedDict[Tuple[str, str], Deque[float]] = OrderedDict()
        self._sources: OrderedDict[str, Deque[float]] = OrderedDict()
        self._slots = threading.BoundedSemaphore(concurrent)

    def _prune(self, q: Deque[float], now: float) -> None:
        while q and now - q[0] >= self._window:
            q.popleft()

    def _wait(self, q: Optional[Deque[float]], limit: int, now: float) -> Optional[float]:
        if q is None:
            return None
        self._prune(q, now)
        if len(q) >= limit:
            return max(1.0, self._window - (now - q[0]))
        return None

    def _check(self, source: str, account: str, now: float) -> Optional[float]:
        waits = [
            w
            for w in (
                self._wait(self._names.get((source, account)), self._per_name, now),
                self._wait(self._sources.get(source), self._per_source, now),
            )
            if w is not None
        ]
        return max(waits) if waits else None

    def check(self, source: str, user: str) -> Optional[float]:
        """None if a sign-in may proceed, else the seconds to wait. Does not reserve a slot."""
        with self._lock:
            return self._check(peer_key(source), name_key(user), self._clock())

    def begin_for(self, source: str, user: str) -> Tuple[Optional[float], bool]:
        """Check the budgets and take a backend slot under one lock: ``(wait, False)`` when a budget is
        used up, ``(None, False)`` when every slot is busy, ``(None, True)`` when admitted. The caller
        records the outcome, then calls :meth:`end_for`."""
        with self._lock:
            wait = self._check(peer_key(source), name_key(user), self._clock())
            if wait is not None:
                return wait, False
            return None, self.begin()

    def end_for(self, user: str) -> None:
        """Release the slot taken by :meth:`begin_for` for ``user``, after the outcome is recorded."""
        self.end()

    def _record(self, table: OrderedDict[K, Deque[float]], key: K, cap: int, now: float) -> None:
        q = table.get(key)
        if q is None:
            q = deque()
            table[key] = q
            while len(table) > cap:
                table.popitem(last=False)
        else:
            table.move_to_end(key)
        self._prune(q, now)
        q.append(now)

    def failed(self, source: str, user: str) -> None:
        """Record a sign-in that reached the backend and was refused."""
        source_key = peer_key(source)
        account = name_key(user)
        with self._lock:
            now = self._clock()
            self._record(self._names, (source_key, account), MAX_TRACKED_NAMES, now)
            self._record(self._sources, source_key, MAX_TRACKED_SOURCES, now)

    def succeeded(self, source: str, user: str) -> None:
        """A successful sign-in clears that user name's failures from that source, not the source's
        own budget."""
        with self._lock:
            self._names.pop((peer_key(source), name_key(user)), None)

    def begin(self) -> bool:
        """Take one of the concurrent backend sign-in slots without waiting. False if none is free."""
        return self._slots.acquire(blocking=False)

    def end(self) -> None:
        self._slots.release()
