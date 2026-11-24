"""Diagnostics logging and the audit trail.

Two streams with different jobs. The diagnostic log is for whoever debugs the daemon. The audit
trail answers "who did what, from where, when" and is one JSON object per line. Neither ever holds
a password, a session token, a cookie or raw device configuration.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
import threading
import time
from pathlib import Path
from typing import Any, Optional

from jwicket.settings import LogSettings

LOG = logging.getLogger("jwicket")

# Fields that must never reach the audit trail, whatever a caller passes.
_FORBIDDEN = frozenset({"password", "passwd", "token", "cookie", "secret", "authorization", "csrf"})
_MAX_FIELD = 200


def setup_logging(settings: LogSettings) -> None:
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    fmt.converter = time.gmtime
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if settings.file is not None:
        handlers.append(
            logging.handlers.RotatingFileHandler(
                settings.file, maxBytes=settings.max_bytes, backupCount=settings.backups
            )
        )
    root = logging.getLogger()
    root.setLevel(settings.level)
    for handler in handlers:
        handler.setFormatter(fmt)
        root.addHandler(handler)
    # PyEZ logs whole RPC replies at INFO through ncclient (spike finding); paramiko is chatty too.
    for noisy in ("ncclient", "paramiko", "jnpr"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def _clean(value: Any) -> Any:
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    text = str(value).replace("\n", " ").replace("\r", " ")
    return text if len(text) <= _MAX_FIELD else text[: _MAX_FIELD - 1] + "…"


class AuditTrail:
    """Append-only JSON-lines audit log. Thread-safe. Falls back to the diagnostic log if unset."""

    def __init__(self, path: Optional[Path], max_bytes: int = 1_000_000, backups: int = 3) -> None:
        self._lock = threading.Lock()
        if path is None:
            self._logger = logging.getLogger("jwicket.audit")
            return
        # A Logger constructed directly is not registered with the logging manager, so each trail
        # owns its handler; two trails never write into each other's files.
        self._logger = logging.Logger("jwicket.audit.file", logging.INFO)
        handler = logging.handlers.RotatingFileHandler(path, maxBytes=max_bytes, backupCount=backups)
        handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(handler)

    def close(self) -> None:
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
