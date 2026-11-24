"""Spec 004: log viewing, read-only, with the operator's own rights.

Where logs are depends on configuration, and the UI must say so instead of showing an empty pane:

* ``system syslog file <name>`` entries are files on the routing engine. They are read with the
  operator's NETCONF session (``show log <name>``), never by opening /var/log as the daemon's account,
  so a login class that cannot read logs sees "denied".
* ``security log mode stream`` sends traffic logs straight to the listed stream hosts; they are not on
  the device. ``security log mode event`` writes them through syslog, so they appear in a syslog file
  that matches RT_FLOW. ``security log report`` keeps an on-box reporting database (what J-Web's
  Monitor > Logs pages read); querying it is a separate adapter, added once its RPC is recorded.

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

from jwicket.junos.xmlutil import Element, kid, kids, local, names, path, present, text, text_of

Json = Dict[str, Any]

MAX_WINDOW = 5000
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
# appear in any syslog file that takes authorization info, including the default "messages".
SELF_NOISE = (
    "Junos logs every NETCONF request as UI_NETCONF_CMD, so each J-Wicket read adds a line to files "
    "that record authorization messages. The viewer hides your own J-Wicket reads by default."
)


def default_mode(model: Optional[str]) -> Tuple[Optional[str], str]:
    """The documented default security log mode for a model, when the configuration sets none."""
    m = (model or "").lower()
    if m.startswith("vsrx"):
        return "event", "event is the documented default on vSRX"
    if m.startswith(("srx3", "srx5", "srx1500", "srx4100", "srx4200")):
        return "stream", "stream is the documented default for this model"
    return None, "the default for this model is not documented"


# --- sources --------------------------------------------------------------------------------------


def sources(config: Optional[Element], model: Optional[str] = None) -> Json:
    """What the configuration says about where logs are. ``config`` holds system/syslog and security/log;
    ``model`` (from get-software-information) decides the documented default mode when none is set."""
    files: List[Json] = []
    syslog = path(config, "system", "syslog")
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
                "structured_data": present(node, "structured-data"),
                "group": None,
            }
        )
    if not any(f["name"] == "messages" for f in files):
        files.insert(
            0,
            {"id": "file:messages", "name": "messages", "contents": [], "match": None,
             "structured_data": False, "group": None, "assumed": True},
        )

    seclog = path(config, "security", "log")
    mode = text(seclog, "mode")
    if mode is None and seclog is not None:
        mode = next((local(c.tag) for c in kids(kid(seclog, "mode"))), None)
    effective, basis = (mode, "set in the configuration") if mode else default_mode(model)
    streams = []
    for stream in kids(seclog, "stream"):
        host = path(stream, "host")
        streams.append(
            {
                "name": text(stream, "name"),
                "host": text(host, "ipaddr") or text(host, "name") or text_of(host),
                "port": text(host, "port"),
                "format": text(stream, "format"),
                "category": names(stream, "category") or [text_of(c) or "" for c in kids(stream, "category")],
            }
        )
    report = present(seclog, "report")
    high_end = (model or "").lower().startswith(("srx54", "srx56", "srx58"))
    traffic: Json = {
        "mode": mode,
        "effective_mode": effective,
        "mode_basis": basis,
        "streams": streams,
        "report": report,
        "format": text(seclog, "format"),
    }
    if effective in ("stream", "stream-event"):
        hosts = ", ".join(str(s["host"] or "?") for s in streams)
        traffic["where"] = (
            "Traffic logs are streamed off the device"
            + (f" to {hosts}" if streams else "")
            + ("." if effective == "stream-event" else "; they are not stored here.")
            + (" On-box reporting keeps a local copy." if report else "")
        )
    elif effective == "event":
        traffic["where"] = (
            "Traffic logs are handled by the routing engine: they appear in the security log buffer and "
            "in any syslog file that takes them (for example one matching RT_FLOW)."
        )
    else:
        traffic["where"] = f"The security log mode is not set and {basis}; check 'show security log' on the device."

    extra: List[Json] = []
    if report and effective in ("stream", "stream-event") and not high_end:
        extra.append({"id": "report", "name": "On-box reporting", "types": list(REPORT_TYPES)})
    if effective in ("event", "stream-event"):
        extra.append({"id": "buffer", "name": "Security log buffer (routing engine)"})
    return {"status": "ok", "files": files, "traffic": traffic, "databases": extra, "self_noise": SELF_NOISE}


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
