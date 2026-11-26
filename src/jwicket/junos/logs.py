"""Spec 004: log viewing, read-only, with the operator's own rights.

Where logs are depends on configuration, and the UI must say so instead of showing an empty pane:

* ``system syslog file <name>`` entries are files on the routing engine. They are read with the
  operator's NETCONF session (``show log <name>``), never by opening /var/log as the daemon's account,
  so a login class that cannot read logs sees "denied".
* ``security log mode stream`` sends traffic logs to the listed stream destinations: a remote host
  (not on the device) or a local stream file (on the device, which J-Wicket cannot read yet).
  ``security log mode event`` processes them on the routing engine, so they are expected in the
  security log buffer and in a syslog file that takes RT_FLOW (inferred; Spec 004 section 7.10,
  confirmed by qualification Q-LOG-01). ``security log report`` keeps an on-box reporting database
  (J-Web's Monitor > Logs pages probably read it: inferred, research note 51 section 3.3); querying
  it uses ``get-sec-log-report-detail-<type>`` (``live._read_report``), whose reply wrapper is
  unverified (Q-REL-01).
* Deactivated statements are not in effect: a deactivated mode, report, stream or ``security log``
  is reported as such, never as configured. ``security log disable`` is reported, and the on-box
  sources are marked disabled rather than hidden (records written before may still be there).

Tailing: Junos returns the whole file. J-Wicket keeps the last ``MAX_WINDOW`` lines, applies the
operator's substring filters on the device side of the wire (plain substring only: a regular
expression from a browser must never run on the routing engine), and gives the browser a cursor so
each poll returns only new lines. Rotation is detected and reported as a reset.

Lines are returned raw (control characters removed). Tokenising and highlighting happen in the
browser, which keeps CPU work off small routing engines.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple

from jwicket.junos.errors import RpcFailed
from jwicket.junos.xmlutil import Element, active_kid, is_inactive, kid, kids, local, names, path, text, text_of

Json = Dict[str, Any]

MAX_WINDOW = 5000
# Downstream only: ncclient/PyEZ have already received and parsed the XML before this check.
MAX_FILE_REPLY_CHARS = 4 * 1024 * 1024
DEFAULT_LINES = 500
MAX_LINES = 2000
MAX_TERMS = 4
MAX_TERM_LEN = 120
_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,63}\Z")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_CURSOR = re.compile(r"^(\d{1,9}):([0-9a-f]{12})\Z")


class LogQueryError(ValueError):
    """A log request parameter failed validation."""


# On-box reporting (``show security log report in-detail <type>``): one RPC per type.
REPORT_TYPES = (
    "session-all", "session-close", "session-create", "session-deny",
    "screen", "idp-all", "utm-all", "ipsec-vpn", "threat", "all",
)
MAX_EXPRESSION = 256  # documented limit of the report "expression" option, brackets included
_EXPRESSION = re.compile(r"^[A-Za-z0-9_.:/=!<>&|() \-]{1,256}\Z")
_REPORT_TIME = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\Z")
_BUFFER_TIME = re.compile(r"^\d{4}-\d\d-\d\d\.\d\d:\d\d:\d\d\Z")

# Junos records every NETCONF RPC as UI_NETCONF_CMD (authorization, info), so J-Wicket's own reads
# appear in any syslog file that takes authorization info. Whether the factory "messages" file takes
# it is not confirmed here; qualification Q-LOAD-03 measures the volume.
SELF_NOISE = (
    "Junos logs every NETCONF request as UI_NETCONF_CMD, so each J-Wicket read adds a line to files "
    "that record authorization messages. The viewer hides your own J-Wicket reads by default."
)


# Defaults from the "mode (Security Logging)" statement reference (research note 51 section 1.1),
# by exact model name. Models it does not name get no default.
_EVENT_MODELS = frozenset({"srx100", "srx110", "srx210", "srx220", "srx240", "srx650"})
_STREAM_MODELS = frozenset({"srx1400", "srx3400", "srx3600", "srx5400", "srx5600", "srx5800", "srx4100", "srx4200"})
# "Apart from Junos OS Release 18.4R1, 18.4R2, 19.1 and 19.2R1, in all the other releases starting in
# Junos OS Release 18.3R3, the default logging mode for SRX300, SRX320, SRX340, SRX345, SRX550, and
# SRX550M devices is stream mode"; event otherwise.
_RELEASE_MODELS = frozenset({"srx300", "srx320", "srx340", "srx345", "srx550", "srx550m"})
# "vsrx" is the product-model the spike vSRX (24.4R2-S3.5) reported; other vSRX spellings are unverified.
_VSRX_MODELS = frozenset({"vsrx"})
# On-box reporting: Feature Explorer 8049 lists these platforms and needs "set security log report"
# with "set security log mode stream" (research note 51 section 1.4).
_REPORT_MODELS = frozenset({
    "vsrx", "srx300", "srx320", "srx340", "srx345", "srx380", "srx1500", "srx1600", "srx2300", "srx4100",
    "srx4200", "srx4120", "srx4300", "srx4600", "srx4700",
})
# "show security log report in-detail": "Command introduced in Junos OS Release 23.1R1" (CLI
# reference, research note 51 section 2.1).
REPORT_MIN_RELEASE = (23, 1, 1)
_RELEASE = re.compile(r"^(\d+)\.(\d+)(?:R(\d+))?")


def release(version: Optional[str]) -> Optional[Tuple[int, int, int]]:
    """(major, minor, R number) of a Junos version string such as 24.4R2-S3.5; R is 0 for X releases."""
    m = _RELEASE.match(version or "")
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def default_mode(model: Optional[str], version: Optional[str] = None) -> Tuple[Optional[str], str]:
    """The documented default security log mode for a model (and release), when none is configured."""
    m = (model or "").strip().lower()
    if m in _VSRX_MODELS:
        return "event", (
            "event is the documented default on vSRX, although another Junos page says the default is stream "
            "in general; check 'show security log' on the device"
        )
    if m in _EVENT_MODELS:
        return "event", "event is the documented default for this model"
    if m in _STREAM_MODELS:
        return "stream", "stream is the documented default for this model"
    rel = release(version)
    if m in _RELEASE_MODELS:
        if rel is None:
            return None, "the documented default for this model depends on the release, which is not known"
        exceptions = {(18, 4, 1), (18, 4, 2), (19, 2, 1)}
        if rel < (18, 3, 3) or rel in exceptions or rel[:2] == (19, 1):
            return "event", f"event is the documented default for this model on {version}"
        return "stream", f"stream is the documented default for this model on {version}"
    if m == "srx1500":
        if rel is None:
            return None, "the documented default for this model depends on the release, which is not known"
        x49 = re.search(r"X49-D(\d+)", version or "")
        if x49 and int(x49.group(1)) < 140:
            return "event", f"event is the documented default for this model on {version}"
        return "stream", f"stream is the documented default for this model on {version}"
    return None, "the default for this model is not documented"


# --- sources --------------------------------------------------------------------------------------


def _stream(stream: Element, off: bool) -> Json:
    host = kid(stream, "host")
    local_file = kid(stream, "file")
    radius = path(stream, "radius", "ipaddr")
    return {
        "name": text(stream, "name"),
        "host": (text(host, "ipaddr") or text(host, "name") or text_of(host)) if host is not None else None,
        "port": text(host, "port"),
        # A local stream file ("file is exclusive with host"). The XML tag is unverified: the YANG
        # names it localfilename, the documentation writes "file name".
        "file": (text(local_file, "localfilename") or text(local_file, "name") or "?") if local_file is not None
        else None,
        "radius": text(radius, "primary") or ("?" if kid(stream, "radius") is not None else None),
        "format": text(stream, "format"),
        "category": names(stream, "category") or [text_of(c) or "" for c in kids(stream, "category")],
        "inactive": off or is_inactive(stream),
    }


def _where_streamed(streams: List[Json], effective: str, report: bool) -> str:
    active = [s for s in streams if not s["inactive"]]
    hosts = [str(s["host"] or "?") for s in active if s["host"] is not None or (s["file"] is None and not s["radius"])]
    files = [str(s["file"]) for s in active if s["file"] is not None]
    radius = [str(s["radius"]) for s in active if s["radius"] is not None]
    parts = []
    if hosts or not active:
        parts.append("streamed off the device" + (f" to {', '.join(hosts)}" if hosts else ""))
    if radius:
        parts.append(f"sent to the RADIUS server(s) {', '.join(radius)}")
    if files:
        parts.append(f"written to local stream file(s) {', '.join(files)} on this device (J-Wicket cannot read "
                     "stream files yet)")
    text_ = "Traffic logs are " + " and ".join(parts)
    # Pure stream mode with no local stream file keeps nothing on the device.
    text_ += "." if effective == "stream-event" or files else "; they are not stored here."
    if report:
        text_ += " On-box reporting keeps a local copy."
    return text_


def sources(config: Optional[Element], model: Optional[str] = None, version: Optional[str] = None) -> Json:
    """What the configuration says about where logs are. ``config`` holds system/syslog and security/log;
    ``model`` and ``version`` (from get-software-information) decide the documented default mode when
    none is set, and whether on-box reporting is documented for this device."""
    files: List[Json] = []
    syslog = path(config, "system", "syslog")
    syslog_off = is_inactive(kid(config, "system")) or is_inactive(syslog)
    for node in kids(syslog, "file"):
        name = text(node, "name")
        if not name or not _FILE.match(name):
            continue
        contents = []
        for c in kids(node, "contents"):
            facility = text(c, "name") or "?"
            severity = next((local(x.tag) for x in kids(c) if local(x.tag) != "name"), None)
            contents.append(f"{facility} {severity}" if severity else facility)
        files.append(
            {
                "id": f"file:{name}",
                "name": name,
                "contents": contents,
                "match": text(node, "match"),
                "structured_data": active_kid(node, "structured-data") is not None,
                "group": None,
                # Deactivated: Junos no longer writes it, but the file may still be on disk and readable.
                "inactive": syslog_off or is_inactive(node),
            }
        )
    if not any(f["name"] == "messages" for f in files):
        files.insert(
            0,
            {"id": "file:messages", "name": "messages", "contents": [], "match": None,
             "structured_data": False, "group": None, "assumed": True, "inactive": False},
        )

    seclog = path(config, "security", "log")
    seclog_off = is_inactive(kid(config, "security")) or is_inactive(seclog)
    mode_node = kid(seclog, "mode")
    written_mode = text_of(mode_node) or next((local(c.tag) for c in kids(mode_node)), None)
    mode_off = written_mode is not None and (seclog_off or is_inactive(mode_node))
    mode = None if mode_off else written_mode
    effective, basis = (mode, "set in the configuration") if mode else default_mode(model, version)
    streams = [_stream(stream, seclog_off) for stream in kids(seclog, "stream")]
    report_node = kid(seclog, "report")
    report_off = report_node is not None and (seclog_off or is_inactive(report_node))
    report = report_node is not None and not report_off
    disabled_node = kid(seclog, "disable")
    disabled = disabled_node is not None and not (seclog_off or is_inactive(disabled_node))
    traffic: Json = {
        "mode": mode,
        "mode_inactive": written_mode if mode_off else None,
        "effective_mode": effective,
        "mode_basis": basis,
        "streams": streams,
        "report": report,
        "report_inactive": report_off,
        "format": text(seclog, "format"),
        "disabled": disabled,
    }
    if disabled:
        traffic["where"] = (
            "Security logging is disabled in the configuration (security log disable), so the device writes no "
            "new security logs. Records written before it was disabled may still be readable below."
        )
    elif effective in ("stream", "stream-event"):
        traffic["where"] = _where_streamed(streams, effective, report)
    elif effective == "event":
        traffic["where"] = (
            "Traffic logs are handled by the routing engine: they are expected in the security log buffer and in "
            "any syslog file that takes them (for example one matching RT_FLOW). Inferred from the documentation; "
            "not yet confirmed on a device."
        )
    else:
        traffic["where"] = f"The security log mode is not set and {basis}; check 'show security log' on the device."
    if mode_off:
        traffic["where"] += f" The configured mode {written_mode} is deactivated, so it is not in effect."

    extra: List[Json] = []
    if report:
        # Shown whenever it is configured: hiding a configured database would make "not shown" look like
        # "not there". Where the documentation does not cover this model or mode, say so.
        entry: Json = {"id": "report", "name": "On-box reporting", "types": list(REPORT_TYPES)}
        m = (model or "").strip().lower()
        if m not in _REPORT_MODELS or effective != "stream":
            entry["note"] = (
                "On-box reporting is documented for stream mode on vSRX, SRX300-line, SRX380, SRX1500, SRX1600, "
                "SRX2300 and SRX4000-line models (Feature Explorer 8049), not for this model or log mode; reads "
                "may fail."
            )
        rel = release(version)
        if rel is not None and rel < REPORT_MIN_RELEASE:
            entry["supported"] = False
            entry["note"] = (
                f"Report queries (in-detail) were introduced in Junos OS Release 23.1R1; this device runs {version}."
            )
        if disabled:
            entry["disabled"] = True
        extra.append(entry)
    if effective in ("event", "stream-event"):
        buffer: Json = {"id": "buffer", "name": "Security log buffer (routing engine)"}
        if disabled:
            buffer["disabled"] = True
        extra.append(buffer)
    return {"status": "ok", "files": files, "traffic": traffic, "databases": extra, "self_noise": SELF_NOISE}


def valid_file_name(name: str) -> bool:
    """The syntax of a syslog file name J-Wicket will ask for (no path, no options)."""
    return bool(_FILE.match(name))


def validate_file(name: str, known: List[Json]) -> str:
    if not _FILE.match(name) or not any(f["name"] == name for f in known):
        raise LogQueryError("unknown log file")
    return name


# --- reading and tailing --------------------------------------------------------------------------


def reply_text(reply: Element) -> str:
    """``show log`` replies carry the file as text, under <output> or <file-content> or bare."""
    for tag in ("file-content", "output"):
        found = next((e for e in reply.iter() if local(e.tag) == tag), None)
        if found is not None:
            return str(found.text or "")
    return str(reply.text or "") if local(reply.tag) != "rpc-reply" else ""


def _digest(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8", "replace")).hexdigest()[:12]


def clean_lines(raw: str) -> List[str]:
    lines = [_CONTROL.sub("", ln.rstrip("\r")) for ln in raw.split("\n")]
    while lines and not lines[-1].strip():
        lines.pop()
    # Junos text output usually starts with a newline; leading blank lines are not log lines.
    start = 0
    while start < len(lines) and not lines[start].strip():
        start += 1
    lines = lines[start:]
    return lines[-MAX_WINDOW:] if len(lines) > MAX_WINDOW else lines


def clean_file_reply(reply: Element) -> List[str]:
    """Refuse an oversized decoded file reply before splitting/copying its lines in J-Wicket."""
    raw = reply_text(reply)
    if len(raw) > MAX_FILE_REPLY_CHARS:
        raise RpcFailed("decoded file log exceeds the local reply budget", (
            "This log file is too large for J-Wicket to process. Use a smaller, rotated log file."
        ))
    return clean_lines(raw)


def parse_expression(raw: Optional[str]) -> Optional[str]:
    """A report ``expression`` (operators = != >= <= && || and parentheses). Sent as an RPC
    parameter value, never as CLI text; the character set and length are still checked."""
    if not raw:
        return None
    if len(raw.encode("utf-8")) > MAX_EXPRESSION or not _EXPRESSION.match(raw):
        raise LogQueryError(
            f"expression must be at most {MAX_EXPRESSION} characters of A-Z 0-9 _ . : / = ! < > & | ( ) -"
        )
    return raw


def parse_report_time(raw: Optional[str], label: str) -> Optional[str]:
    if not raw:
        return None
    if not _REPORT_TIME.match(raw):
        raise LogQueryError(f"{label} must look like 2026-11-24T06:00:00")
    return raw


def parse_buffer_time(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    if not _BUFFER_TIME.match(raw):
        raise LogQueryError("since must look like 2026-11-24.06:00:00")
    return raw


def buffer_events(reply: Element) -> Json:
    """``get-security-log-information``: structured events from the routing engine's log buffer."""
    events: List[Json] = []
    lines: List[str] = []
    disabled = any(local(e.tag) == "security-logs-disabled" for e in reply.iter())
    for ev in (e for e in reply.iter() if local(e.tag) == "security-event"):
        proc = kid(ev, "process")
        item = {
            "time": text(ev, "security-event-time"),
            "id": text(ev, "security-event-id"),
            "message": text(ev, "security-event-message"),
            "severity": text(ev, "severity"),
            "result": text(ev, "security-event-result"),
            "user": text(ev, "security-event-username"),
            "interface": text(ev, "security-event-interface-name"),
            "protocol": text(ev, "security-event-protocol"),
            "policy": text(ev, "security-event-policy-name"),
            "src": text(ev, "security-event-source-address"),
            "sport": text(ev, "security-event-source-port"),
            "dst": text(ev, "security-event-destination-address"),
            "dport": text(ev, "security-event-destination-port"),
            "process": text(proc, "name"),
            "pid": text(proc, "pid"),
        }
        events.append(item)
        proc_part = f"{item['process'] or '-'}" + (f"[{item['pid']}]" if item["pid"] else "")
        line = f"{item['time'] or '-'} {proc_part}: {item['id'] or '-'}: {item['message'] or ''}"
        lines.append(_CONTROL.sub("", line))
    return {"events": events[-MAX_LINES:], "lines": lines[-MAX_LINES:], "disabled": disabled}


def parse_terms(raw: Optional[str], label: str) -> List[str]:
    if not raw:
        return []
    terms = [t for t in (x.strip() for x in raw.split("\n")) if t]
    if len(terms) > MAX_TERMS or any(len(t) > MAX_TERM_LEN for t in terms):
        raise LogQueryError(f"{label}: at most {MAX_TERMS} terms of {MAX_TERM_LEN} characters")
    return [t.lower() for t in terms]


def parse_lines(raw: Optional[str]) -> int:
    if not raw:
        return DEFAULT_LINES
    if not raw.isdigit():
        raise LogQueryError("lines must be a number")
    return max(1, min(MAX_LINES, int(raw)))


def parse_cursor(raw: Optional[str]) -> Optional[Tuple[int, str]]:
    if not raw:
        return None
    m = _CURSOR.match(raw)
    if not m:
        raise LogQueryError("bad cursor")
    return int(m.group(1)), m.group(2)


def tail(
    lines: List[str],
    *,
    cursor: Optional[Tuple[int, str]],
    want: int,
    contains: List[str],
    exclude: List[str],
) -> Json:
    """Lines after the cursor (or the last ``want`` lines), filtered, plus the next cursor.

    The cursor is ``<count>:<digest of the last line seen>``. If the line at that position no longer
    has that digest, the file rotated or was rewritten; the window is searched backwards for the
    digest, and if it is gone the response is a fresh tail marked ``reset``.
    """
    reset = False
    # Without a cursor the whole window is scanned, so a filtered first read finds the newest
    # ``want`` *matching* lines, not just the matches among the newest ``want`` lines.
    start = 0
    if cursor is not None:
        count, digest = cursor
        idx = count - 1
        if 0 <= idx < len(lines) and _digest(lines[idx]) == digest:
            start = idx + 1
        else:
            match = next((i for i in range(len(lines) - 1, -1, -1) if _digest(lines[i]) == digest), None)
            if match is not None:
                start = match + 1
            else:
                reset = True
    selected = lines[start:]

    def keep(line: str) -> bool:
        low = line.lower()
        return all(t in low for t in contains) and not any(t in low for t in exclude)

    matched = [ln for ln in selected if keep(ln)] if (contains or exclude) else selected
    dropped = max(0, len(matched) - want)
    out = matched[-want:] if dropped else matched
    next_cursor = f"{len(lines)}:{_digest(lines[-1])}" if lines else None
    return {
        "lines": out,
        "cursor": next_cursor,
        "reset": reset,
        "dropped": dropped,
        "window": len(lines),
        "scanned": len(selected),
    }
