"""The workstation's records of what the installer did (Spec 006 sections 7.10 and 8.10). LAB ONLY.

Everything lives in one private state directory: ``$JWICKET_INSTALL_STATE_DIR`` (the container wrapper
sets it to its mounted ``/state``), else ``$XDG_STATE_HOME/jwicket-install``, else
``~/.local/state/jwicket-install``. The directory is 0700 and owned by this account; every file is
0600, written to a new name with ``O_EXCL | O_NOFOLLOW`` and renamed into place.

* ``<sha256 of the host-key fingerprint>.json``: the workstation receipt (schema 2, plan.Receipt),
  written after the last confirming commit. The host name never becomes a path component.
* ``<same>.journal.json``: the journal, updated after each step, so a run that fails half-way can be
  repaired, reverted or removed. It holds tokens, step names and Junos's own diff text (control
  characters stripped, secret-looking lines withheld); never a credential or the lab token.
* ``known_hosts``: keys accepted with ``--accept-new-host-key``.
* ``run-*`` directories: the per-run pinned known_hosts and SSH configuration for ncclient, removed at
  the end of the run.
* ``./evidence-<12 hex of the fingerprint>-<UTC time>/`` (in the working directory): the log, audit and
  result files fetched before an uninstall (deploy-lab step 8), 0700 and 0600.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import shutil
import stat
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence

from . import plan

LOG = logging.getLogger("jwicket_install.receipt")

STATE_ENV = "JWICKET_INSTALL_STATE_DIR"
JOURNAL_SCHEMA = 2
MAX_RECORD_BYTES = 1024 * 1024
_SECRET_MARKERS = ("$9$", "$6$", "$5$", "$1$", "secret", "password", "encrypted", "pre-shared", "://", "token")


class StoreError(Exception):
    """The state directory or a record in it cannot be trusted or written."""


def default_state_dir(env: Optional[Mapping[str, str]] = None) -> Path:
    environ = os.environ if env is None else env
    explicit = environ.get(STATE_ENV)
    if explicit:
        if not Path(explicit).is_absolute():
            raise StoreError(f"{STATE_ENV} must be an absolute path")
        return Path(explicit)
    xdg = environ.get("XDG_STATE_HOME")
    if xdg:
        return Path(xdg) / "jwicket-install"
    return Path.home() / ".local" / "state" / "jwicket-install"


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def fingerprint_key(fingerprint: str) -> str:
    """The file key of a device: the SHA-256 of its host-key fingerprint (never device text)."""
    if plan.FINGERPRINT_RE.match(fingerprint) is None:
        raise StoreError("not a host-key fingerprint")
    return hashlib.sha256(fingerprint.encode("ascii")).hexdigest()


def safe_line(text: str) -> str:
    """A device line made safe to store or print: control characters stripped, one line, and withheld when
    it looks like it carries a secret or a URL (INV-08). Display only."""
    flat = plan.sanitize_display(text, 400)
    lowered = flat.lower()
    if any(marker in lowered for marker in _SECRET_MARKERS):
        return "[line withheld: it may hold a secret or a URL]"
    return flat


def safe_lines(text: Optional[str], limit: int = 400) -> List[str]:
    if not text:
        return []
    lines = [safe_line(line) for line in text.splitlines() if line.strip()]
    if len(lines) > limit:
        lines = [*lines[:limit], f"[{len(lines) - limit} more lines not shown]"]
    return lines


def check_private_dir(path: Path) -> None:
    """A directory this account owns, not a symbolic link, not writable or readable by others."""
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise StoreError(f"cannot check {path}: {exc.strerror or type(exc).__name__}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise StoreError(f"{path} is not a directory (a symbolic link is refused)")
    if info.st_uid != os.geteuid():
        raise StoreError(f"{path} is owned by uid {info.st_uid}, not by this account")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise StoreError(f"{path} is open to group or others (mode {stat.S_IMODE(info.st_mode):04o}); chmod 700 it")


def write_private(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` as a 0600 file: a new temporary name in the same directory (O_EXCL,
    O_NOFOLLOW), flushed, then renamed over ``path``."""
    directory = path.parent
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=str(directory))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        Path(tmp).replace(path)
    except BaseException:
        with contextlib.suppress(OSError):
            Path(tmp).unlink()
        raise


def read_private(path: Path, limit: int = MAX_RECORD_BYTES) -> Optional[str]:
    """A record's text, or None when absent. Refuses links, foreign owners, loose modes, huge files."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise StoreError(f"cannot open {path}: {exc.strerror or type(exc).__name__}") from exc
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise StoreError(f"{path} is not a private regular file of this account (0600)")
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise StoreError(f"{path} is larger than {limit} bytes")
    return data.decode("utf-8", "replace")


class Journal:
    """The run's journal: rewritten after each step (spec 7.10). Fields are tokens and constant names,
    plus Junos's diff text made safe by safe_lines."""

    def __init__(self, path: Path, *, command: str, fingerprints: Sequence[str]) -> None:
        self.path = path
        self.data: Dict[str, Any] = {
            "schema": JOURNAL_SCHEMA,
            "command": command,
            "host_key_sha256": list(fingerprints),
            "started": utc_now(),
            "steps": [],
            "confirmed_stages": [],
            "files_created": [],
            "device_diffs": {},
            "outcome": "running",
            "exit": None,
        }

    def step(self, name: str, outcome: str, **detail: Any) -> None:
        entry: Dict[str, Any] = {"step": name, "outcome": outcome, "time": utc_now()}
        for key, value in detail.items():
            entry[key] = value if isinstance(value, (int, bool)) or value is None else plan.sanitize_display(str(value))
        self.data["steps"].append(entry)
        self.save()

    def confirmed(self, stage: str) -> None:
        self.data["confirmed_stages"].append(stage)
        self.save()

    def created(self, path: str) -> None:
        if path not in self.data["files_created"]:
            self.data["files_created"].append(path)
            self.save()

    def diff(self, stage: str, text: Optional[str]) -> None:
        self.data["device_diffs"][stage] = safe_lines(text)
        self.save()

    def finish(self, outcome: str, code: int) -> None:
        self.data["outcome"] = outcome
        self.data["exit"] = code
        self.save()

    def save(self) -> None:
        try:
            write_private(self.path, (json.dumps(self.data, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        except OSError as exc:
            LOG.warning("journal %s not written: %s", self.path, exc.strerror or type(exc).__name__)


class Store:
    """The state directory and the records keyed by the device's host-key fingerprint."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def ensure(self) -> None:
        if not self.root.exists():
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.root.chmod(0o700)
        check_private_dir(self.root)

    def receipt_path(self, fingerprint: str) -> Path:
        return self.root / f"{fingerprint_key(fingerprint)}.json"

    def journal_path(self, fingerprint: str) -> Path:
        return self.root / f"{fingerprint_key(fingerprint)}.journal.json"

    def known_hosts(self) -> Path:
        return self.root / "known_hosts"

    def read_receipt(self, fingerprint: str) -> Optional[str]:
        """The workstation receipt's text for this device, refused when it names another fingerprint."""
        text = read_private(self.receipt_path(fingerprint))
        if text is None:
            return None
        receipt = _receipt_or_none(text)
        if receipt is None:
            LOG.warning(
                "the workstation receipt %s does not parse as schema 2; ignored", self.receipt_path(fingerprint)
            )
            return None
        if fingerprint not in receipt.host_key_sha256:
            raise StoreError("the workstation receipt for this file name records another host key: refused (spec 7.9)")
        return text

    def write_receipt(self, fingerprint: str, receipt: plan.Receipt) -> Path:
        self.ensure()
        path = self.receipt_path(fingerprint)
        write_private(path, receipt.to_json().encode("utf-8"))
        return path

    def remove_receipt(self, fingerprint: str) -> None:
        with contextlib.suppress(FileNotFoundError):
            self.receipt_path(fingerprint).unlink()

    def journal(self, command: str, fingerprints: Sequence[str]) -> Journal:
        self.ensure()
        return Journal(self.journal_path(fingerprints[0]), command=command, fingerprints=fingerprints)

    @contextlib.contextmanager
    def run_dir(self) -> Iterator[Path]:
        self.ensure()
        path = Path(tempfile.mkdtemp(prefix="run-", dir=str(self.root)))
        try:
            path.chmod(0o700)
            yield path
        finally:
            shutil.rmtree(path, ignore_errors=True)


def evidence_dir(base: Path, fingerprint: str) -> Path:
    """./evidence-<12 hex>-<UTC time>/ (0700): named by the fingerprint, never by device text."""
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    name = f"evidence-{fingerprint_key(fingerprint)[:12]}-{stamp}"
    for attempt in range(1, 100):
        path = base / (name if attempt == 1 else f"{name}-{attempt}")
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            continue
        path.chmod(0o700)
        return path
    raise StoreError(f"cannot create a new evidence directory in {base}")


def _receipt_or_none(text: str) -> Optional[plan.Receipt]:
    try:
        return plan.Receipt.from_json(text)
    except plan.InputError:
        return None
