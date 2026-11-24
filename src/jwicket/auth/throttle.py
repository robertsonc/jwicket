"""Sign-in rate limits: per source address and for the whole daemon.

Junos applies its own login retry options to the NETCONF session as well; this limit exists so a
browser-facing endpoint cannot be used to drive those attempts (or RADIUS/TACACS+ load) at speed.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from typing import Callable, Deque, Optional

MAX_TRACKED_SOURCES = 1024


class LoginThrottle:
    def __init__(
        self,
        *,
        per_source: int,
        overall: int,
        window_s: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._per_source = per_source
        self._overall = overall
        self._window = window_s
        self._clock = clock
        self._lock = threading.Lock()
        self._sources: OrderedDict[str, Deque[float]] = OrderedDict()
        self._all: Deque[float] = deque()

    def _prune(self, q: Deque[float], now: float) -> None:
        while q and now - q[0] >= self._window:
            q.popleft()

    def attempt(self, source: str) -> Optional[float]:
        """Record an attempt. Return None if allowed, else seconds until the next one would be."""
        now = self._clock()
        with self._lock:
            self._prune(self._all, now)
            q = self._sources.get(source)
            if q is None:
                q = deque()
                self._sources[source] = q
                while len(self._sources) > MAX_TRACKED_SOURCES:
                    self._sources.popitem(last=False)
            else:
                self._sources.move_to_end(source)
            self._prune(q, now)
            if len(q) >= self._per_source:
                return max(1.0, self._window - (now - q[0]))
            if len(self._all) >= self._overall:
                return max(1.0, self._window - (now - self._all[0]))
            q.append(now)
            self._all.append(now)
            return None
