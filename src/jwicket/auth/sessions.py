"""Browser sessions, each bound to one device session.

* The browser holds a random token in an HttpOnly cookie; the server keeps only its SHA-256.
* Idle and absolute timeouts; a hard cap on concurrent sessions (small routing engines, and every
  session holds a NETCONF session on the device). When the cap is reached, sign-in is refused; no
  one is evicted.
* Ending a session for any reason closes its device session.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from jwicket.junos.session import DeviceSession

LOG = logging.getLogger("jwicket.sessions")


class SessionLimit(Exception):
    """Too many people are signed in."""


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
    # Per-endpoint time of the last device read, for read-rate limits.
    last_read: Dict[str, float] = field(default_factory=dict)
    # Small per-session cache (for example discovered log files), keyed by name: (stored at, value).
    cache: Dict[str, Tuple[float, Any]] = field(default_factory=dict, repr=False)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)


class SessionStore:
    def __init__(
        self,
        *,
        idle_s: int,
        absolute_s: int,
        max_sessions: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._idle = idle_s
        self._absolute = absolute_s
        self._max = max_sessions
        self._clock = clock
        self._lock = threading.Lock()
        self._sessions: Dict[str, WebSession] = {}

    def _expired(self, sess: WebSession, now: float) -> bool:
        return now - sess.last_seen > self._idle or now - sess.created > self._absolute

    def create(self, *, user: str, backend: str, device: DeviceSession, source: str) -> Tuple[str, WebSession]:
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
        )
        with self._lock:
            if len(self._sessions) >= self._max:
                raise SessionLimit(f"{len(self._sessions)} sessions open, limit {self._max}")
            self._sessions[sess.key] = sess
        return token, sess

    def get(self, token: Optional[str]) -> Optional[WebSession]:
        if not token:
            return None
        key = _digest(token)
        now = self._clock()
        stale: Optional[WebSession] = None
        with self._lock:
            sess = self._sessions.get(key)
            if sess is None:
                return None
            if self._expired(sess, now):
                stale = self._sessions.pop(key)
            else:
                sess.last_seen = now
        if stale is not None:
            self._close(stale, "expired")
            return None
        return sess

    def remove(self, token: Optional[str]) -> Optional[WebSession]:
        if not token:
            return None
        with self._lock:
            sess = self._sessions.pop(_digest(token), None)
        if sess is not None:
            self._close(sess, "signed out")
        return sess

    def drop(self, sess: WebSession, reason: str) -> None:
        with self._lock:
            removed = self._sessions.pop(sess.key, None)
        if removed is not None:
            self._close(removed, reason)

    def reap(self) -> List[WebSession]:
        now = self._clock()
        with self._lock:
            stale = [s for s in self._sessions.values() if self._expired(s, now)]
            for sess in stale:
                del self._sessions[sess.key]
        for sess in stale:
            self._close(sess, "expired")
        return stale

    def close_all(self) -> None:
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for sess in sessions:
            self._close(sess, "shutdown")

    def count(self) -> int:
        with self._lock:
            return len(self._sessions)

    @staticmethod
    def _close(sess: WebSession, reason: str) -> None:
        LOG.info("session for %s ended: %s", sess.user, reason)
        try:
            sess.device.close()
        except Exception as exc:  # noqa: BLE001 - a failing close must not break the caller
            LOG.warning("closing device session for %s failed: %r", sess.user, exc)
