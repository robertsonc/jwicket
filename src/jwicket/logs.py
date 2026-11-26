"""Diagnostics logging and the audit trail.

Two streams with different jobs. The diagnostic log is for whoever debugs the daemon. The audit
trail answers "who did what, from where, when" and is one JSON object per line. Neither ever holds
a password, a session token, a cookie or raw device configuration.

* Diagnostic messages are escaped before they are written: control characters (C0, DEL, C1) and
  the backslash become ``\\xNN`` / ``\\\\``. Request lines and paths come from anyone who can
  connect, before any check, and must not plant terminal escapes or forge log lines.
* The audit trail records a failed sign-in under a keyed hash of the submitted user name
  (``user_hash``), never the name itself: the commonest malformed name is a password typed into the
  user-name field. The key is random per process, so the hash correlates attempts within one run
  only. The plain name is recorded once Junos has accepted the sign-in.
* Refusals of clients that have no session (cross-origin or throttled sign-ins, malformed user
  names) are aggregated: the first per kind, source and reason in each window is written at once,
  repeats are counted and written as one line (``repeated``) when the window ends, so anyone who can
  send requests cannot rotate the audit history away.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import logging.handlers
import os
import secrets
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, TextIO, Tuple

from jwicket.settings import ConfigError, LogSettings, check_output_directory, check_output_stat

LOG = logging.getLogger("jwicket")

# Fields that must never reach the audit trail, whatever a caller passes.
_FORBIDDEN = frozenset({"password", "passwd", "token", "cookie", "secret", "authorization", "csrf"})
_MAX_FIELD = 200
REFUSAL_WINDOW_S = 60.0
# Distinct (event, source, fields) aggregates per window; beyond this, refusals from further sources
# are counted together under source "various", so a client with many addresses cannot add lines.
MAX_REFUSAL_KEYS = 64


def _escape_table() -> Dict[int, str]:
    # The standard library's own table (http.server, Python 3.11+ and security backports), built here
    # so that every supported interpreter gets it.
    table = {c: f"\\x{c:02x}" for c in (*range(0x20), *range(0x7F, 0xA0))}
    table[ord("\\")] = "\\\\"
    return table


_ESCAPES = _escape_table()


def escape_controls(text: str) -> str:
    return text.translate(_ESCAPES)


class EscapeControls(logging.Filter):
    """Escapes the formatted message of every record a diagnostic handler writes.

    The traceback (``exc_text``) is formatted later by the handler and keeps its line breaks.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if getattr(record, "_jwicket_escaped", False):
            return True  # several handlers share one record: escape once
        try:
            message = record.getMessage()
        except (TypeError, ValueError):
            return True  # logging reports the broken format string itself
        record.msg = escape_controls(message)
        record.args = None
        record._jwicket_escaped = True
        return True


def escape_handlers(handlers: Iterable[logging.Handler]) -> None:
    for handler in handlers:
        if not any(isinstance(f, EscapeControls) for f in handler.filters):
            handler.addFilter(EscapeControls())


class PrivateRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """Append only to a trusted, private regular file, including after rotation."""

    def __init__(self, path: Path, *, max_bytes: int, backups: int) -> None:
        check_output_directory(path, label="log output")
        try:
            path = path.parent.resolve(strict=True) / path.name
        except OSError as exc:
            raise ConfigError(f"log output {path} has no usable parent directory: {exc}") from exc
        super().__init__(path, maxBytes=max_bytes, backupCount=backups)

    def _open(self) -> TextIO:
        path = Path(self.baseFilename)
        label = "log output"
        check_output_directory(path, label=label)
        # A non-regular file must not block before its descriptor can be checked. Never truncate
        # or pass an unchecked descriptor to the logging handler.
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
        try:
            try:
                existing = path.lstat()
            except FileNotFoundError:
                existing = None
            if existing is not None:
                check_output_stat(existing, path, label=label)
            fd = os.open(path, flags, 0o600)
        except OSError as exc:
            raise ConfigError(f"{label} {path} cannot be opened: {exc}") from exc
        try:
            opened = os.fstat(fd)
            check_output_stat(opened, path, label=label)
            current = path.lstat()
            if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                raise ConfigError(f"{label} {path} changed while it was opened")
            return os.fdopen(os.dup(fd), "a", encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"{label} {path} could not be checked: {exc}") from exc
        finally:
            os.close(fd)


def setup_logging(settings: LogSettings) -> None:
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    fmt.converter = time.gmtime
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if settings.file is not None:
        handlers.append(
            PrivateRotatingFileHandler(
                settings.file, max_bytes=settings.max_bytes, backups=settings.backups
            )
        )
    root = logging.getLogger()
    root.setLevel(settings.level)
    for handler in handlers:
        handler.setFormatter(fmt)
        root.addHandler(handler)
    escape_handlers(handlers)
    # PyEZ logs whole RPC replies at INFO through ncclient (spike finding); paramiko is chatty too.
    for noisy in ("ncclient", "paramiko", "jnpr"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def _clean(value: Any) -> Any:
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    text = str(value).replace("\n", " ").replace("\r", " ")
    return text if len(text) <= _MAX_FIELD else text[: _MAX_FIELD - 1] + "…"


RefusalKey = Tuple[str, str, Tuple[Tuple[str, Any], ...]]


class AuditTrail:
    """Append-only JSON-lines audit log. Thread-safe. Falls back to the diagnostic log if unset."""

    def __init__(
        self,
        path: Optional[Path],
        max_bytes: int = 1_000_000,
        backups: int = 3,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._lock = threading.Lock()
        self._clock = clock
        self._key = secrets.token_bytes(32)
        self._refusals_lock = threading.Lock()
        # key -> [window start, repeats not yet written]
        self._refusals: Dict[RefusalKey, List[Any]] = {}
        if path is None:
            self._logger = logging.getLogger("jwicket.audit")
            return
        # A Logger constructed directly is not registered with the logging manager, so each trail
        # owns its handler; two trails never write into each other's files.
        self._logger = logging.Logger("jwicket.audit.file", logging.INFO)
        handler = PrivateRotatingFileHandler(path, max_bytes=max_bytes, backups=backups)
        handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(handler)

    def close(self) -> None:
        self.flush(force=True)
        if self._logger.name != "jwicket.audit.file":
            return
        for handler in list(self._logger.handlers):
            handler.close()
            self._logger.removeHandler(handler)

    def record(self, event: str, *, user: Optional[str], source: str, **fields: Any) -> None:
        entry: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event,
            "user": _clean(user),
            "source": _clean(source),
        }
        for key, value in fields.items():
            if key.lower() in _FORBIDDEN:
                continue
            entry[key] = _clean(value)
        line = json.dumps(entry, sort_keys=True, ensure_ascii=True)
        with self._lock:
            self._logger.info(line)

    def pseudonym(self, value: str) -> str:
        """A keyed hash that correlates one value within this process run and reveals nothing else."""
        return hmac.new(self._key, value.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:16]

    def record_refusal(self, event: str, *, source: str, **fields: Any) -> None:
        """A refusal of a client that has no session. The first per (event, source, fields) in each
        window is written at once; repeats are counted and written as one line when the window ends."""
        now = self._clock()
        frozen = tuple(sorted((k, _clean(v)) for k, v in fields.items() if k.lower() not in _FORBIDDEN))
        key: RefusalKey = (event, _clean(source), frozen)
        write_first = False
        with self._refusals_lock:
            pending = self._expired(now)
            if key not in self._refusals and len(self._refusals) >= MAX_REFUSAL_KEYS:
                key = (event, "various", frozen)
            entry = self._refusals.get(key)
            if entry is None:
                self._refusals[key] = [now, 0]
                write_first = True
            else:
                entry[1] += 1
        self._write_repeats(pending)
        if write_first:
            self.record(key[0], user=None, source=key[1], **dict(key[2]))

    def flush(self, *, force: bool = False) -> None:
        """Write the repeat counts of windows that have ended (all of them with ``force``)."""
        with self._refusals_lock:
            pending = self._expired(self._clock(), force=force)
        self._write_repeats(pending)

    def _expired(self, now: float, *, force: bool = False) -> List[Tuple[RefusalKey, int]]:
        done = [k for k, (start, _n) in self._refusals.items() if force or now - start >= REFUSAL_WINDOW_S]
        return [(k, int(self._refusals.pop(k)[1])) for k in done]

    def _write_repeats(self, pending: List[Tuple[RefusalKey, int]]) -> None:
        for (event, source, frozen), repeats in pending:
            if repeats:
                self.record(event, user=None, source=source, repeated=repeats, window_s=int(REFUSAL_WINDOW_S),
                            **dict(frozen))
