"""Spec 004: live flow sessions (``show security flow session``), read-only.

The session table is the largest thing on an SRX that an operator wants to look at: tens of
thousands of entries on a branch box, millions on a data-centre box. Three rules follow.

1. Filters go to the device. Every filter that ``get-flow-session-information`` understands is
   validated here and sent as an RPC parameter, so mgd and flowd do the narrowing. The browser
   filters further, but only over what the device returned, and the UI says which is which.
2. Unbounded pulls are refused. Before fetching rows, the session summary is read; if more sessions
   are active than ``MAX_UNFILTERED`` and no device-side filter is set, J-Wicket returns the count and
   asks for a narrower filter instead of pulling the table.
3. Rows are capped (``limit``) after parsing and the response says how many were dropped.

Reply element names follow J-Wicket's reading of the documentation and are confirmed per release by
qualification Q-REL-01. The parser is tolerant: it finds ``flow-session`` elements at any depth (so
per-SPU groupings on high-end SRX and per-node results on chassis clusters both work) and records
the node or SPU it found them under.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple

from jwicket.junos.xmlutil import Element, kids, local, text, text_of

Json = Dict[str, Any]

# Above this many matching sessions, J-Wicket refuses to pull rows and asks for a narrower filter.
# The device sends every matching session from the SPUs to the routing engine for a list request
# (Juniper KB28956), so this protects the control plane; the count itself is cheap (filtered summary).
MAX_UNFILTERED = 5000
DEFAULT_LIMIT = 500
MAX_LIMIT = 2000

PROTOCOLS = ("tcp", "udp", "icmp", "icmp6", "gre", "esp", "ah", "sctp", "pim", "ospf")
_APP = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,63}\Z")
_IFACE = re.compile(r"^[a-z][a-z0-9\-]{1,9}(\d+(/\d+){0,3})?(\.\d{1,5})?\Z")


class FilterError(ValueError):
    """A filter value failed validation. The message names the filter."""


# Request parameter -> (RPC parameter, validator)
def _prefix(value: str) -> str:
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError as exc:
        raise FilterError(f"{value!r} is not an IP address or prefix") from exc


def _port(value: str) -> str:
    if not value.isdigit() or not 0 <= int(value) <= 65535:
        raise FilterError(f"{value!r} is not a port number")
    return str(int(value))


def _protocol(value: str) -> str:
    low = value.lower()
    if low in PROTOCOLS:
        return low
    if low.isdigit() and 0 <= int(low) <= 255:
        return str(int(low))
    raise FilterError(f"{value!r} is not a protocol name or number")


def _application(value: str) -> str:
    if not _APP.match(value):
        raise FilterError(f"{value!r} is not an application name")
    return value


def _interface(value: str) -> str:
    if not _IFACE.match(value):
        raise FilterError(f"{value!r} is not an interface name")
    return value


PUSHDOWN: Dict[str, Tuple[str, Any]] = {
    "src": ("source-prefix", _prefix),
    "dst": ("destination-prefix", _prefix),
    "sport": ("source-port", _port),
    "dport": ("destination-port", _port),
    "proto": ("protocol", _protocol),
    "app": ("application", _application),
    "iface": ("interface", _interface),
}


def device_filters(query: Dict[str, str]) -> Dict[str, str]:
    """Validated device-side filters, keyed by RPC parameter name. Unknown keys are ignored."""
    out: Dict[str, str] = {}
    for key, (rpc_param, validate) in PUSHDOWN.items():
        raw = (query.get(key) or "").strip()
        if raw:
            out[rpc_param] = validate(raw)
    return out


def rpc_kwargs(filters: Dict[str, str]) -> Dict[str, str]:
    """PyEZ keyword arguments: RPC parameter names with hyphens as underscores."""
    return {k.replace("-", "_"): v for k, v in filters.items()}


def parse_limit(raw: Optional[str]) -> int:
    if not raw:
        return DEFAULT_LIMIT
    if not raw.isdigit():
        raise FilterError(f"limit {raw!r} is not a number")
    return max(1, min(MAX_LIMIT, int(raw)))


# --- parsing --------------------------------------------------------------------------------------


def _int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _wing(node: Element) -> Json:
    return {
        "direction": text(node, "direction"),
        "src": text(node, "source-address"),
        "sport": _int(text(node, "source-port")),
        "dst": text(node, "destination-address"),
        "dport": _int(text(node, "destination-port")),
        "proto": text(node, "protocol"),
        "iface": text(node, "interface-name"),
        "packets": _int(text(node, "pkt-cnt")),
        "bytes": _int(text(node, "byte-cnt")),
        "tunnel": text(node, "tunnel-information"),
    }


def _split_policy(value: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    # Session output shows "policy-name/policy-index" (for example "allow-web/5").
    if not value:
        return None, None
    name, sep, index = value.rpartition("/")
    if sep and index.isdigit():
        return name, index
    return value, None


_KNOWN_SESSION_TAGS = {
    "session-identifier", "status", "session-state", "policy", "timeout", "configured-timeout",
    "start-time", "duration", "application", "dynamic-application-name", "flow-information",
}


def _extra(node: Element) -> Dict[str, str]:
    """Scalar fields the model does not name (reply tags vary by release); shown, never dropped."""
    out: Dict[str, str] = {}
    for child in kids(node):
        tag = local(child.tag)
        if tag in _KNOWN_SESSION_TAGS or len(child):
            continue
        value = text_of(child)
        if value is not None and len(out) < 24:
            out[tag] = value[:200]
    return out


def _session(node: Element, location: Optional[str]) -> Json:
    wings = [_wing(w) for w in kids(node, "flow-information")]
    inbound = next((w for w in wings if (w["direction"] or "").lower().startswith("in")), wings[0] if wings else None)
    outbound = next((w for w in wings if (w["direction"] or "").lower().startswith("out")), None)
    policy, policy_index = _split_policy(text(node, "policy"))
    nat = {"source": False, "destination": False}
    if inbound and outbound:
        # The reverse wing of an un-NATed session mirrors the forward wing exactly.
        nat["source"] = outbound["dst"] != inbound["src"] or outbound["dport"] != inbound["sport"]
        nat["destination"] = outbound["src"] != inbound["dst"] or outbound["sport"] != inbound["dport"]
    sid = text(node, "session-identifier")
    return {
        "id": f"{location}:{sid}" if location else sid,
        "session_id": sid,
        "location": location,
        "status": text(node, "status"),
        "state": text(node, "session-state"),
        "policy": policy,
        "policy_index": policy_index,
        "timeout": _int(text(node, "timeout")),
        "configured_timeout": _int(text(node, "configured-timeout")),
        "start_time": text(node, "start-time"),
        "duration": _int(text(node, "duration")),
        "application": text(node, "application") or text(node, "dynamic-application-name"),
        "in": inbound,
        "out": outbound,
        "nat": nat,
        "extra": _extra(node),
    }


def _location_of(path: List[Element]) -> Optional[str]:
    parts: List[str] = []
    for element in path:
        tag = local(element.tag)
        if tag == "multi-routing-engine-item":
            node_name = text(element, "re-name")
            if node_name:
                parts.append(node_name)
    return "/".join(parts) or None


def parse_sessions(reply: Element, limit: int) -> Json:
    rows: List[Json] = []
    total = 0

    def walk(node: Element, path: List[Element]) -> None:
        nonlocal total
        # A "flow-fpc-pic-id" label applies to the sessions that follow it inside the same
        # container only; a new container (another node, another SPU group) starts unlabelled.
        spu: Optional[str] = None
        for child in kids(node):
            tag = local(child.tag)
            if tag == "flow-fpc-pic-id":
                spu = text_of(child)
            elif tag == "flow-session":
                total += 1
                if len(rows) < limit:
                    loc = _location_of(path)
                    if spu:
                        loc = f"{loc} {spu}" if loc else spu
                    rows.append(_session(child, loc))
            else:
                walk(child, [*path, child])

    walk(reply, [reply])
    displayed: List[int] = []
    for element in reply.iter():
        if local(element.tag) == "displayed-session-count":
            value = _int(text_of(element))
            if value is not None:
                displayed.append(value)
    return {
        "status": "ok",
        "rows": rows,
        "returned": total,
        "truncated": total > len(rows),
        "device_count": sum(displayed) if displayed else None,
    }


def parse_summary(reply: Element) -> Json:
    """Active and maximum sessions, summed over nodes/SPUs when the reply has several."""
    def total(tag: str) -> Optional[int]:
        values: List[int] = []
        for element in reply.iter():
            if local(element.tag) == tag:
                value = _int(text_of(element))
                if value is not None:
                    values.append(value)
        return sum(values) if values else None

    return {
        "status": "ok",
        "active": total("active-sessions"),
        "max": total("max-sessions"),
        "failed": total("failed-sessions"),
        # A summary request carrying filters reports how many sessions match them.
        "matching": total("displayed-session-count"),
    }
