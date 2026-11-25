"""The health checks before a confirming commit (Spec 006 sections 7.6 and 8.6). LAB ONLY.

Pure functions over text the executor read from the device: the self-test and probe results (C2, C3),
the log after the offset recorded before the commit (C4), the audit trail (C5), the process status
(C7) and the HTTP answer of ``GET /api/session`` (C8, ``https_session``: with ``--access tls`` an HTTPS
read of the listen address, the certificate pinned, by the workstation or by the on-box op script). No
check reads anything through an SSH channel (revision R3): forwarding was refused on a lab SRX4100
running 25.2R1-S1.4 (verified), so C8 is "not available" with ``--access tunnel``, and C9 (NETCONF's
banner through a channel) is retired. Each returns a ``Result``: ``pass``, ``fail``, ``not-available``
(recorded with a warning) or ``not-checked`` (a bundle without D2 whose start reply carried no output:
proceeds only with ``--accept-unchecked-diagnostics``).

Every shape parsed here is the J-Wicket daemon's own (``jwicket.app``, ``jwicket.logs``, ``jwicket.api``,
``tools/bundle.py``), except two device shapes that are inferred: the extension-service status text
('Process-id: <n>', from the CLI reference's field list) and the start reply's ``output`` leaf (YANG
23.2R1; whether it carries the app's standard output is unknown (Q-INST-05), though the CLI printed it on
SRX4100). Device text is never echoed unsanitised. Embedded in the on-box op script: Python 3.7.
"""

from __future__ import annotations

import datetime
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from . import plan

PASS = "pass"  # noqa: S105 - a check status, not a password
FAIL = "fail"
NOT_AVAILABLE = "not-available"
NOT_CHECKED = "not-checked"

MAX_JSON_BYTES = 256 * 1024
_LOG_TIME_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
_PID_RE = re.compile(r"Process-id\s*:?\s*(\d{1,9})\b", re.IGNORECASE)
_STATUS_LINE_RE = re.compile(rb"^HTTP/1\.[01] (\d{3})")
_HEX16_RE = re.compile(r"^[0-9a-f]{16}\Z")


@dataclass(frozen=True)
class Result:
    check: str
    status: str
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == PASS

    @property
    def acceptable(self) -> bool:
        """Pass, or 'not available' (recorded with a warning)."""
        return self.status in (PASS, NOT_AVAILABLE)


def _short(text: str) -> str:
    return plan.sanitize_display(text, 200)


def json_object(text: Optional[str]) -> Optional[Dict[str, Any]]:
    """The JSON object in ``text``: the whole text, or (start reply output with other lines around it) the
    span from the first '{' to the last '}'. None when there is none."""
    if not text or len(text) > MAX_JSON_BYTES:
        return None
    for candidate in (text, text[text.find("{") : text.rfind("}") + 1] if "{" in text else ""):
        if not candidate:
            continue
        try:
            value = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(value, dict):
            return value
    return None


# -- C2, C3 ----------------------------------------------------------------------------------------


def selftest(text: Optional[str], expect: Mapping[str, str]) -> Result:
    """C2: the self-test reports ok, with this bundle's version and payload SHA-256."""
    data = json_object(text)
    if data is None:
        return Result("C2", NOT_CHECKED if not text else FAIL, "no self-test result" if not text else "not JSON")
    if data.get("ok") is not True:
        failures = data.get("failures")
        first = failures[0] if isinstance(failures, list) and failures and isinstance(failures[0], str) else ""
        return Result("C2", FAIL, "the self-test reported failures: " + _short(first))
    if data.get("version") != expect.get("version"):
        return Result("C2", FAIL, f"version {_short(str(data.get('version')))} is not {expect.get('version')}")
    if data.get("payload_sha256") != expect.get("payload_sha256"):
        return Result("C2", FAIL, "the payload SHA-256 differs from this bundle's (a stale result or another build)")
    return Result("C2", PASS, f"ok, version {expect.get('version')}")


def probe(text: Optional[str], expect: Mapping[str, str]) -> Result:
    """C3: every module the backend (and, with --access tls, the listener) needs is 'ok'; the others in
    ``expect['recorded']`` ('ssl' with --access tunnel) are only recorded."""
    data = json_object(text)
    if data is None:
        return Result("C3", NOT_CHECKED if not text else FAIL, "no probe result" if not text else "not JSON")
    modules = data.get("modules")
    if not isinstance(modules, dict):
        return Result("C3", FAIL, "the probe result has no module list")
    required = [m for m in expect.get("modules", "").split(",") if m]
    missing = [m for m in required if modules.get(m) != "ok"]
    if missing:
        return Result("C3", FAIL, "modules not ok: " + ", ".join(missing))
    recorded = [m for m in expect.get("recorded", "").split(",") if m]
    notes = ", ".join(f"{m} {'ok' if modules.get(m) == 'ok' else 'absent'}" for m in recorded)
    return Result("C3", PASS, "every required module ok" + (f" ({notes}, recorded only)" if notes else ""))


# -- C4, C5: the log and the audit trail after the offset --------------------------------------------


def new_text(data: bytes, offset: int) -> Tuple[str, bool]:
    """The bytes after ``offset``; a file shorter than the offset was rotated: read from its start."""
    if len(data) < offset:
        return data.decode("utf-8", "replace"), True
    return data[offset:].decode("utf-8", "replace"), False


def _log_time(line: str) -> Optional[datetime.datetime]:
    match = _LOG_TIME_RE.match(line)
    if match is None:
        return None
    try:
        return datetime.datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def commit_time(date_time: Optional[str]) -> Optional[datetime.datetime]:
    """The commit's time from the device's own history ('2026-11-24 20:48:00 UTC'), without its zone
    name: that the daemon's log stamps use the same zone is inferred."""
    if not date_time:
        return None
    try:
        return datetime.datetime.strptime(date_time[:19].replace("T", " "), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def start_lines(
    data: bytes, offset: int, expect: Mapping[str, str], since: Optional[datetime.datetime]
) -> Tuple[List[str], bool]:
    """The matching 'listening on' lines after the offset (after rotation, only those stamped at or after
    the commit time when both times parse)."""
    text, rotated = new_text(data, offset)
    prefix = expect.get("line", "")
    lines: List[str] = []
    for line in text.splitlines():
        index = line.find(" " + prefix)
        if index < 0 or not prefix:
            continue
        if rotated and since is not None:
            stamped = _log_time(line)
            if stamped is not None and stamped < since:
                continue
        lines.append(line[index + 1 :].strip())
    return lines, rotated


def start_line(data: bytes, offset: int, expect: Mapping[str, str], since: Optional[datetime.datetime]) -> Result:
    """C4: exactly one new start line; with D3 it names this version and payload."""
    lines, rotated = start_lines(data, offset, expect, since)
    note = " (log rotated; read from its start)" if rotated else ""
    if not lines:
        return Result("C4", FAIL, "no new start line yet" + note)
    if len(lines) > 1:
        return Result("C4", FAIL, f"{len(lines)} new start lines: J-Wicket is restarting in a loop" + note)
    build = expect.get("build", "")
    tail = lines[0][len(expect.get("line", "")) :].strip()
    if build and tail != build:
        return Result("C4", FAIL, f"the start line names another build: {_short(tail) or 'none'}" + note)
    return Result("C4", PASS, "one new start line" + (f", {build}" if build else "") + note)


def audit_start(data: bytes, offset: int, expect: Mapping[str, str]) -> Result:
    """C5: exactly one new audit record with event 'start' and this version (and payload with D3)."""
    text, rotated = new_text(data, offset)
    starts: List[Dict[str, Any]] = []
    for line in text.splitlines():
        record = json_object(line.strip()) if line.strip().startswith("{") else None
        if record is not None and record.get("event") == "start":
            starts.append(record)
    note = " (audit file rotated)" if rotated else ""
    if len(starts) != 1:
        return Result("C5", FAIL, f"{len(starts)} new audit start records, expected 1" + note)
    record = starts[0]
    if record.get("version") != expect.get("version"):
        return Result("C5", FAIL, "the audit start record names another version" + note)
    payload = expect.get("payload_sha256", "")
    if payload and record.get("payload_sha256") != payload:
        return Result("C5", FAIL, "the audit start record names another payload" + note)
    return Result("C5", PASS, "one new audit start record" + note)


# -- C7 --------------------------------------------------------------------------------------------


def process_id(output: Optional[str]) -> Optional[int]:
    """The Process-id in 'show extension-service status <app>' output (field name from the CLI reference,
    EXT-12; the reply text through NETCONF is inferred). None when no process is listed."""
    if not output:
        return None
    match = _PID_RE.search(output)
    return int(match.group(1)) if match else None


def stable(first: Optional[int], second: Optional[int]) -> Result:
    if first is None:
        return Result("C7", FAIL, "no J-Wicket process is listed")
    if second is None:
        return Result("C7", FAIL, f"the process {first} is gone at the second read")
    if first != second:
        return Result("C7", FAIL, f"the process id changed from {first} to {second}: J-Wicket restarted")
    return Result("C7", PASS, f"the same process {first} at both reads")


# -- C8: GET /api/session ----------------------------------------------------------------------------


def session_request(port: int, host: Optional[str] = None) -> bytes:
    """The request C8 sends; ``host`` is the Host header (default 127.0.0.1:<port>, the on-box form)."""
    header = host if host is not None else f"{plan.LOOPBACK}:{port}"
    return (
        f"GET /api/session HTTP/1.1\r\nHost: {header}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    ).encode("ascii")


def api_session(raw: bytes, expect: Mapping[str, str], *, available: bool, reason: str = "") -> Result:
    """C8's answer: 200 with this version (and, with D3, 'build' equal to the payload's first 16 hex)."""
    where = expect.get("host") or f"{plan.LOOPBACK} on the device"
    if not available:
        return Result("C8", NOT_AVAILABLE, reason or f"nothing answered on {where}")
    match = _STATUS_LINE_RE.match(raw)
    if match is None:
        return Result("C8", FAIL, f"no HTTP answer from {where}" + (f": {reason}" if reason else ""))
    if match.group(1) != expect.get("status", "200").encode("ascii"):
        return Result("C8", FAIL, f"GET /api/session answered {match.group(1).decode('ascii')}")
    _, _, body = raw.partition(b"\r\n\r\n")
    data = json_object(body.decode("utf-8", "replace"))
    if data is None:
        return Result("C8", FAIL, "GET /api/session did not answer JSON")
    if data.get("version") != expect.get("version"):
        return Result("C8", FAIL, "GET /api/session names another version")
    build = expect.get("build", "")
    if build and data.get("build") != build:
        return Result("C8", FAIL, "GET /api/session names another build: an earlier process may be listening")
    return Result("C8", PASS, f"200, version {expect.get('version')}" + (f", build {build}" if build else ""))


def https_session(raw: bytes, expect: Mapping[str, str], *, connected: bool, pinned: bool, reason: str = "") -> Result:
    """C8 with ``--access tls`` (R3): the workstation's HTTPS read of ``expect['host']``, trusting only
    the certificate whose SHA-256 the installer made. No TLS session is a failure from a NETCONF executor
    (``if_unavailable`` 'fail') and "not available" where the plan says so; another certificate is always
    a failure, and nothing was sent to it."""
    where = expect.get("host", "the listen address")
    if not connected:
        status = NOT_AVAILABLE if expect.get("if_unavailable") == "not-available" else FAIL
        return Result("C8", status, f"no HTTPS answer from {where}" + (f": {_short(reason)}" if reason else ""))
    if not pinned:
        return Result(
            "C8",
            FAIL,
            f"{where} presented a certificate other than the one this installer made (pinned SHA-256); "
            "nothing was sent to it",
        )
    result = api_session(raw, expect, available=True, reason=_short(reason))
    if result.ok:
        return Result("C8", PASS, result.detail + ", over HTTPS with the pinned certificate")
    return result


def not_available(check: str, reason: str) -> Result:
    """A check the plan records as not available (C8 with ``--access tunnel``: no SSH channel, R3)."""
    return Result(check, NOT_AVAILABLE, _short(reason) or "not available")


def summary(results: Sequence[Result]) -> Tuple[bool, List[str]]:
    """Whether every result is acceptable, and the warnings for the not-available ones."""
    warnings = [f"{r.check} not available: {r.detail}" for r in results if r.status == NOT_AVAILABLE]
    return all(r.acceptable for r in results), warnings


def payload_short_ok(value: str) -> bool:
    return _HEX16_RE.match(value) is not None
