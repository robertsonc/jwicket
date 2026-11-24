"""Spec 004: live flow sessions (``show security flow session``), read-only.

The session table is the largest thing on an SRX that an operator wants to look at: tens of
thousands of entries on a branch box, millions on a data-centre box. Three rules follow.

1. Filters go to the device. Every filter that ``get-flow-session-information`` understands is
   validated here and sent as an RPC parameter, so mgd and flowd do the narrowing. The browser
   filters further, but only over what the device returned, and the UI says which is which.
2. Unbounded pulls are refused. Before fetching rows, a (filtered) session summary is read; if
   more sessions match the request, filtered or not, than ``MAX_UNFILTERED``, J-Wicket returns the
   count and asks for a narrower filter instead of pulling the table. It also lists nothing when it
   cannot tell how many match (the summary failed, or its reply had no count) unless the active
   session count bounds the match below the limit: the guard fails closed.
3. Rows are capped (``limit``) after parsing and the response says how many were dropped.

On a chassis cluster every session is held by both nodes (Active on one, Backup on the other), and
each node reports its own counts, so counts are summed over the SPUs of one node and the largest
node's figure is used, never the sum over nodes. Both copies of a session are still returned as rows
(with their node) so the browser can tell Active from Backup.

Reply element names follow J-Wicket's reading of the documentation and are confirmed per release by
qualification Q-REL-01. The per-session list XML is inferred from the CLI output; how per-SPU
groupings on high-end SRX and per-node results on chassis clusters are laid out in it is also
inferred, and is checked by Q-REL-01 before J-Wicket relies on it. The parser is tolerant: it finds
``flow-session`` elements at any depth and records the node and SPU label it found them under (an
SPU label applies to the sessions that follow it inside the same container).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple

from jwicket.junos.xmlutil import Element, kids, local, text, text_of

Json = Dict[str, Any]

# Above this many matching sessions, J-Wicket refuses to pull rows and asks for a narrower filter.
# The device sends every matching session from the SPUs to the routing engine for a list request,
# so this protects the control plane; the count itself is cheap (filtered summary). Source: Juniper
# support as quoted in the HPE community thread "info over logs" (https://community.networking.hpe.com/
# discussion/info-over-logs), which cites KB28956; the KB itself was not retrieved. The threshold is
# checked by qualification Q-LOAD-02.
MAX_UNFILTERED = 5000
DEFAULT_LIMIT = 500
MAX_LIMIT = 2000

# The protocol keywords "show security flow session protocol" documents (CLI reference,
# show-security-flow-session.html), besides a protocol number 0..255.
PROTOCOLS = (
    "ah", "egp", "esp", "gre", "icmp", "icmp6", "igmp", "ipip", "ospf", "pim", "rsvp", "sctp", "tcp", "udp",
)
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
    # Session output shows "policy-name/policy-index" (for example "allow-web/5"). The CLI reference
    # also shows "pre-id-default-policy/n": the suffix "n" is split off and its index left unknown,
    # since its meaning is not documented. "N/A" stays whole.
    if not value:
        return None, None
    name, sep, index = value.rpartition("/")
    if sep and name and index.isdigit():
        return name, index
    if sep and name and index == "n":
        return name, None
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
    per_node = _per_node(reply, ("displayed-session-count",))
    counts = [n["displayed-session-count"] for n in per_node if n["displayed-session-count"] is not None]
    out: Json = {
        "status": "ok",
        "rows": rows,
        "returned": total,
        "truncated": total > len(rows),
        # Sessions on the device that matched: the largest node's count, since a cluster's nodes
        # each hold a copy of every session.
        "device_count": max(counts) if counts else None,
    }
    if len(per_node) > 1:
        out["nodes"] = [{"node": n["node"], "device_count": n["displayed-session-count"]} for n in per_node]
    return out


def _per_node(reply: Element, tags: Tuple[str, ...]) -> List[Json]:
    """For each node (``multi-routing-engine-item``, or the whole reply when there is none), each tag's
    integer values summed over the node's SPUs; None where the node has no such value."""
    items = [e for e in reply.iter() if local(e.tag) == "multi-routing-engine-item"]
    scopes = [(text(item, "re-name"), item) for item in items] if items else [(None, reply)]
    nodes: List[Json] = []
    for name, scope in scopes:
        entry: Json = {"node": name}
        for tag in tags:
            values = [v for v in (_int(text_of(e)) for e in scope.iter() if local(e.tag) == tag) if v is not None]
            entry[tag] = sum(values) if values else None
        nodes.append(entry)
    return nodes


def parse_summary(reply: Element) -> Json:
    """Active, maximum and failed sessions. Summed over the SPUs of one node; on a chassis cluster the
    largest node's active, maximum and matching counts are used (each node holds a copy of every
    session), failed counts are summed (each node fails its own), and ``nodes`` lists each node."""
    tags = ("active-sessions", "max-sessions", "failed-sessions", "displayed-session-count")
    per_node = _per_node(reply, tags)

    def largest(tag: str) -> Optional[int]:
        values = [n[tag] for n in per_node if n[tag] is not None]
        return max(values) if values else None

    failed = [n["failed-sessions"] for n in per_node if n["failed-sessions"] is not None]
    out: Json = {
        "status": "ok",
        "active": largest("active-sessions"),
        "max": largest("max-sessions"),
        "failed": sum(failed) if failed else None,
        # A summary request carrying filters reports how many sessions match them.
        "matching": largest("displayed-session-count"),
    }
    if len(per_node) > 1:
        out["nodes"] = [
            {
                "node": n["node"],
                "active": n["active-sessions"],
                "max": n["max-sessions"],
                "failed": n["failed-sessions"],
                "matching": n["displayed-session-count"],
            }
            for n in per_node
        ]
    return out
