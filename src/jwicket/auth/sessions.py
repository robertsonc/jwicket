"""Browser sessions, each bound to one device session.

* The browser holds a random token in an HttpOnly cookie; the server keeps only its SHA-256.
* Idle and absolute timeouts; a hard cap on concurrent sessions (small routing engines, and every
  session holds a NETCONF session on the device). When the cap is reached, sign-in is refused.
* A per-person limit (``max_per_user``, setting default 2): a new sign-in by the same Junos user beyond
  the limit closes that user's oldest session, so one account cannot hold every slot. The default is 2,
  not 1, so that one person in two browsers, or two engineers sharing an account, do not keep signing
  each other out. User names are compared
  case-insensitively, because RADIUS or TACACS+ may accept case variants of one name. The caller
  decides which sessions have a person behind them: the lab-token backend's sessions all carry the
  daemon account's name, so they are not limited this way. Distinct accounts can still fill the cap.
* Ending a session for any reason closes its device session.
* Idle time is counted from the last *foreground* request: ``get(token, touch=False)`` (a background
  poll) checks expiry but does not refresh ``last_seen``. That can only shorten a session, never
  lengthen it.
* Why a session ended is kept as a small tombstone (the reason and the time, keyed by the token's
  digest), so a later request with the same cookie can be told why. Tombstones are bounded
  (``max(64, 4 * max_sessions)`` entries, pruned after ``absolute_s``), hold no user name, source,
  CSRF token, token or device data, and never authenticate anything.
"""

from __future__ import annotations

import hashlib
import logging
import math
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from jwicket.junos.session import DeviceSession

LOG = logging.getLogger("jwicket.sessions")


class SessionLimit(Exception):
    """Too many people are signed in. Carries counts and bounds only: no other user's name or source.

    ``slot_free_by_s`` is a guaranteed bound (the absolute limit cannot be extended, though another
    sign-in may take the slot first); ``slot_may_free_in_s`` is when a session would end if its user did
    nothing more (idle or absolute, whichever comes first)."""

    def __init__(self, message: str, *, open_count: int, max_sessions: int, slot_free_by_s: int,
                 slot_may_free_in_s: int) -> None:
        super().__init__(message)
        self.open_count = open_count
        self.max_sessions = max_sessions
        self.slot_free_by_s = slot_free_by_s
        self.slot_may_free_in_s = slot_may_free_in_s


# Why a session ended. Tombstones are written for the first four; "shutdown" and "new-sign-in" are
# reported to ``on_end`` only (after a shutdown the memory is gone, and a new sign-in in the same
# browser overwrites the cookie).
END_REASONS = ("replaced", "idle", "absolute", "signed-out", "session-lost", "shutdown", "new-sign-in")
_NO_TOMBSTONE = frozenset({"shutdown", "new-sign-in"})
MIN_TOMBSTONES = 64


@dataclass(frozen=True)
class Ended:
    """A tombstone: why the session behind a cookie ended, and when (wall clock). Nothing else."""

    reason: str
    at_wall: float


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass
class WebSession:
    key: str
    user: str
    backend: str
    device: DeviceSession
    csrf: str
    source: str
    created: float
    last_seen: float
    # Wall-clock time of the sign-in, for display only (expiry uses the monotonic ``created``).
    created_wall: float = 0.0
    # Per-endpoint time of the last device read, for read-rate limits.
    last_read: Dict[str, float] = field(default_factory=dict)
    # Small per-session cache (for example discovered log files), keyed by name: (stored at, value).
    cache: Dict[str, Tuple[float, Any]] = field(default_factory=dict, repr=False)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    # The per-person limit's key (normalised user name), or None when the session is not limited.
    user_key: Optional[str] = None
    # What was last written to the audit trail per kind of read, so repeated polls are not recorded.
    audit_marks: Dict[str, str] = field(default_factory=dict, repr=False)
    # Deduplication marks per validated log source: (last audited peer, status, monotonic time).
    log_audit: Dict[str, Tuple[str, str, float]] = field(default_factory=dict, repr=False)
    # B-8: the last read per bucket, (key, monotonic time the read began, payload), so this session's
    # other tabs asking the same thing within the read floor get it instead of a 429. One value per
    # bucket, never shared across sessions, dropped with the session.
    reuse: Dict[str, Tuple[Any, float, Any]] = field(default_factory=dict, repr=False)
    # The key of the read running per bucket, so an identical request waits for it.
    inflight: Dict[str, Any] = field(default_factory=dict, repr=False)
    # How many requests wait for the read in flight, per bucket (api.MAX_REUSE_WAITERS).
    reuse_waiters: Dict[str, int] = field(default_factory=dict, repr=False)


class SessionStore:
    def __init__(
        self,
        *,
        idle_s: int,
        absolute_s: int,
        max_sessions: int,
        max_per_user: int = 2,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
        on_end: Optional[Callable[[WebSession, str], None]] = None,
    ) -> None:
        self._idle = idle_s
        self._absolute = absolute_s
        self._max = max_sessions
        self._per_user = max(1, max_per_user)
        self._clock = clock
        self._wall = wall_clock
        # Called after a session's device session is closed, outside the store lock, for every end.
        self.on_end = on_end
        self._lock = threading.Lock()
        self._sessions: Dict[str, WebSession] = {}
        self._ended: OrderedDict[str, Ended] = OrderedDict()
        self._ended_cap = max(MIN_TOMBSTONES, 4 * max_sessions)

    @property
    def idle_s(self) -> int:
        return self._idle

    @property
    def absolute_s(self) -> int:
        return self._absolute

    @property
    def max_per_user(self) -> int:
        return self._per_user

    def _expired(self, sess: WebSession, now: float) -> Optional[str]:
        """None while the session is valid, else which limit ended it: "idle" or "absolute". When both
        have passed, the one whose deadline came first."""
        idle_end = sess.last_seen + self._idle
        absolute_end = sess.created + self._absolute
        idle = now - sess.last_seen > self._idle
        absolute = now - sess.created > self._absolute
        if idle and absolute:
            return "absolute" if absolute_end < idle_end else "idle"
        if idle:
            return "idle"
        if absolute:
            return "absolute"
        return None

    # --- tombstones (call with self._lock held) ---

    def _bury(self, key: str, reason: str) -> None:
        if reason in _NO_TOMBSTONE:
            return
        now = self._wall()
        self._ended.pop(key, None)
        self._ended[key] = Ended(reason=reason, at_wall=now)
        while self._ended:
            oldest_key, oldest = next(iter(self._ended.items()))
            if len(self._ended) > self._ended_cap or now - oldest.at_wall > self._absolute:
                del self._ended[oldest_key]
            else:
                break

    def ended(self, token: Optional[str]) -> Optional[Ended]:
        """Why the session behind ``token`` ended, if this store remembers. Never authenticates."""
        if not token:
            return None
        with self._lock:
            found = self._ended.get(_digest(token))
        if found is None or self._wall() - found.at_wall > self._absolute:
            return None
        return found

    def tombstones(self) -> int:
        with self._lock:
            return len(self._ended)

    # --- sessions ---

    def _limit(self, now: float) -> SessionLimit:
        """The refusal at the cap, with bounds computed from the sessions held (lock held)."""
        open_now = list(self._sessions.values())
        free_by = min((s.created + self._absolute - now for s in open_now), default=0.0)
        may_free = min((min(s.last_seen + self._idle, s.created + self._absolute) - now for s in open_now),
                       default=0.0)
        return SessionLimit(
            f"{len(open_now)} sessions open, limit {self._max}",
            open_count=len(open_now),
            max_sessions=self._max,
            slot_free_by_s=max(0, math.ceil(free_by)),
            slot_may_free_in_s=max(0, math.ceil(may_free)),
        )

    def create(
        self,
        *,
        user: str,
        backend: str,
        device: DeviceSession,
        source: str,
        user_key: Optional[str] = None,
        replaced: Optional[List[WebSession]] = None,
    ) -> Tuple[str, WebSession]:
        """Open a session. With ``user_key``, that user's oldest sessions beyond ``max_per_user - 1``
        are closed first (and appended to ``replaced``); without it only the overall cap applies."""
        expired = self.reap()
        del expired
        now = self._clock()
        token = secrets.token_urlsafe(32)
        sess = WebSession(
            key=_digest(token),
            user=user,
            backend=backend,
            device=device,
            csrf=secrets.token_urlsafe(32),
            source=source,
            created=now,
            last_seen=now,
            created_wall=self._wall(),
            user_key=user_key,
        )
        evicted: List[WebSession] = []
        refusal: Optional[SessionLimit] = None
        with self._lock:
            if user_key is not None:
                mine = sorted((s for s in self._sessions.values() if s.user_key == user_key), key=lambda s: s.created)
                while len(mine) >= self._per_user:
                    old = mine.pop(0)
                    del self._sessions[old.key]
                    self._bury(old.key, "replaced")
                    evicted.append(old)
            if len(self._sessions) >= self._max:
                refusal = self._limit(now)
            else:
                self._sessions[sess.key] = sess
        for old in evicted:
            self._end(old, "replaced", "replaced by a new sign-in for the same user")
        if replaced is not None:
            replaced.extend(evicted)
        if refusal is not None:
            raise refusal
        return token, sess

    def get(self, token: Optional[str], *, touch: bool = True) -> Optional[WebSession]:
        """The live session for ``token``, or None. An expired session is ended here whatever ``touch``
        says; ``touch=False`` (a background request) leaves the idle clock where it was."""
        if not token:
            return None
        key = _digest(token)
        now = self._clock()
        stale: Optional[WebSession] = None
        why: Optional[str] = None
        with self._lock:
            sess = self._sessions.get(key)
            if sess is None:
                return None
            why = self._expired(sess, now)
            if why is not None:
                stale = self._sessions.pop(key)
                self._bury(key, why)
            elif touch:
                sess.last_seen = now
        if stale is not None:
            self._end(stale, why or "idle", "expired")
            return None
        return sess

    def remove(self, token: Optional[str], *, reason: str = "signed-out") -> Optional[WebSession]:
        """End the session for ``token``: "signed-out" (the default, a tombstone is kept) or
        "new-sign-in" (the browser signs in again and gets a new cookie; no tombstone)."""
        if not token:
            return None
        key = _digest(token)
        with self._lock:
            sess = self._sessions.pop(key, None)
            if sess is not None:
                self._bury(key, reason)
        if sess is not None:
            self._end(sess, reason, "signed out" if reason == "signed-out" else reason)
        return sess

    def drop(self, sess: WebSession, reason: str) -> None:
        """End a session whose device session was lost. ``reason`` is for the diagnostic log; the
        tombstone and ``on_end`` reason is always "session-lost"."""
        with self._lock:
            removed = self._sessions.pop(sess.key, None)
            if removed is not None:
                self._bury(sess.key, "session-lost")
        if removed is not None:
            self._end(removed, "session-lost", reason)

    def reap(self) -> List[WebSession]:
        now = self._clock()
        ended: List[Tuple[WebSession, str]] = []
        with self._lock:
            for sess in list(self._sessions.values()):
                why = self._expired(sess, now)
                if why is not None:
                    del self._sessions[sess.key]
                    self._bury(sess.key, why)
                    ended.append((sess, why))
        for sess, why in ended:
            self._end(sess, why, "expired")
        return [sess for sess, _why in ended]

    def close_all(self) -> None:
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for sess in sessions:
            self._end(sess, "shutdown", "shutdown")

    def count(self) -> int:
        with self._lock:
            return len(self._sessions)

    def live(self) -> List[WebSession]:
        """A snapshot of the signed-in sessions (expired ones included until the next reap)."""
        with self._lock:
            return list(self._sessions.values())

    def _end(self, sess: WebSession, reason: str, log_text: str) -> None:
        self._close(sess, log_text)
        # Drop what the session held for its own other tabs (B-8) with the session.
        sess.reuse.clear()
        sess.inflight.clear()
        if self.on_end is None:
            return
        try:
            self.on_end(sess, reason)
        except Exception as exc:  # noqa: BLE001 - a failing hook (the audit trail) must not break the store
            LOG.warning("session end hook for %s failed: %r", sess.user, exc)

    @staticmethod
    def _close(sess: WebSession, reason: str) -> None:
        LOG.info("session for %s ended: %s", sess.user, reason)
        try:
            sess.device.close()
        except Exception as exc:  # noqa: BLE001 - a failing close must not break the caller
            LOG.warning("closing device session for %s failed: %r", sess.user, exc)
