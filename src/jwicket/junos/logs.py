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
_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,63}$")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_CURSOR = re.compile(r"^(\d{1,9}):([0-9a-f]{12})$")


class LogQueryError(ValueError):
    """A log request parameter failed validation."""


# --- sources --------------------------------------------------------------------------------------


def sources(config: Optional[Element]) -> Json:
    """What the configuration says about where logs are. ``config`` holds system/syslog and security/log."""
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
    traffic: Json = {"mode": mode, "streams": streams, "report": report, "format": text(seclog, "format")}
    if mode == "stream" or (mode is None and streams):
        hosts = ", ".join(str(s["host"] or "?") for s in streams)
        traffic["where"] = (
            "Traffic logs are streamed off the device"
            + (f" to {hosts}" if streams else "")
            + "; they are not stored here."
            + (" On-box reporting keeps a local copy for reports." if report else "")
        )
    elif mode == "event":
        traffic["where"] = "Traffic logs go through syslog: look in a syslog file that matches RT_FLOW."
    else:
        traffic["where"] = "The security log mode is not set; the platform default applies (see Spec 004)."
    return {"status": "ok", "files": files, "traffic": traffic}


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
    while lines and not lines[-1]:
        lines.pop()
    return lines[-MAX_WINDOW:] if len(lines) > MAX_WINDOW else lines


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
