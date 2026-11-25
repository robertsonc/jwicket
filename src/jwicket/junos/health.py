"""Device health for the Overview: routing-engine CPU, memory, load and temperature, and data-plane
(SPU) CPU, memory and session counts. Read-only.

* ``get-route-engine-information`` (``show chassis routing-engine``)
* ``get-performance-summary-information`` (``show security monitoring``)

The element names below were read from replies on an SRX4100, Junos 25.2R1-S1.4 (24 November 2026;
docs/evidence/2026-11-24-srx4100-lab). Other platforms and releases are Q-REL-01's to confirm, so
the parsers match local names, accept a chassis-cluster wrapper (``multi-routing-engine-item`` with
``re-name``) and dual routing engines (``slot``), and report a missing number as ``None`` rather
than guess. CPU and memory figures are the device's own percentages, not computed here.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterator, List, Optional, Tuple

from jwicket.junos.xmlutil import Element, attr, kid, kids, local, text

Json = Dict[str, Any]

_NUMBER = re.compile(r"^-?\d+(?:\.\d+)?$")


def _num(node: Optional[Element], name: str) -> Optional[float]:
    value = text(node, name)
    if value is None or not _NUMBER.match(value.strip()):
        return None
    return float(value)


def _int(node: Optional[Element], name: str) -> Optional[int]:
    value = _num(node, name)
    return None if value is None else int(value)


def _celsius(node: Optional[Element], name: str) -> Optional[int]:
    """``<temperature junos:celsius="29">29 degrees C / 84 degrees F</temperature>``."""
    el = kid(node, name)
    if el is None:
        return None
    raw = attr(el, "celsius")
    if raw is None:
        m = re.match(r"\s*(-?\d+)\s*degrees C", el.text or "")
        raw = m.group(1) if m else None
    return int(raw) if raw is not None and _NUMBER.match(raw) else None


def _seconds(node: Optional[Element], name: str) -> Optional[int]:
    raw = attr(kid(node, name), "seconds")
    return int(raw) if raw is not None and raw.isdigit() else None


def _per_node(reply: Element, wrapper: str) -> Iterator[Tuple[Optional[str], Element]]:
    """(node name, wrapper element) for each node: one per cluster node, or one with no name."""
    found = False
    for item in (e for e in reply.iter() if local(e.tag) == "multi-routing-engine-item"):
        inner = next((e for e in item.iter() if local(e.tag) == wrapper), None)
        if inner is not None:
            found = True
            yield text(item, "re-name"), inner
    if found:
        return
    if local(reply.tag) == wrapper:
        yield None, reply
        return
    inner = next((e for e in reply.iter() if local(e.tag) == wrapper), None)
    if inner is not None:
        yield None, inner


def route_engines(reply: Element) -> Json:
    """One entry per routing engine (per node and slot), with the device's percentages."""
    engines: List[Json] = []
    for node, info in _per_node(reply, "route-engine-information"):
        for re_el in kids(info, "route-engine"):
            # The aggregate figures only. The reply also carries cpu-user1.. cpu-idle3 per something
            # (core, or thread); which is not documented, so they are not interpreted here.
            idle = _num(re_el, "cpu-idle")
            engines.append({
                "node": node,
                "slot": _int(re_el, "slot"),
                "mastership": text(re_el, "mastership-state"),
                "status": text(re_el, "status"),
                "model": text(re_el, "model"),
                "cpu": {
                    "user": _num(re_el, "cpu-user"),
                    "background": _num(re_el, "cpu-background"),
                    "system": _num(re_el, "cpu-system"),
                    "interrupt": _num(re_el, "cpu-interrupt"),
                    "idle": idle,
                    "busy": None if idle is None else max(0.0, 100.0 - idle),
                },
                "memory": {
                    "total_mb": _int(re_el, "memory-system-total") or _int(re_el, "memory-dram-size"),
                    "used_mb": _int(re_el, "memory-system-total-used"),
                    # Releases without the system figure report only the buffer one, which the CLI
                    # labels "Memory utilization"; it is used then and the source is named.
                    "util": _num(re_el, "memory-system-total-util"),
                    "buffer_util": _num(re_el, "memory-buffer-utilization"),
                },
                "load": [_num(re_el, f"load-average-{n}") for n in ("one", "five", "fifteen")],
                "temperature_c": _celsius(re_el, "temperature"),
                "cpu_temperature_c": _celsius(re_el, "cpu-temperature"),
                "uptime_s": _seconds(re_el, "up-time"),
                "last_reboot_reason": text(re_el, "last-reboot-reason"),
            })
    if not engines:
        return {"status": "failed", "message": "The routing-engine reply held no routing engine.", "engines": []}
    return {"status": "ok", "engines": engines}


def spus(reply: Element) -> Json:
    """One entry per SPU (per node, FPC and PIC): data-plane CPU and memory, and session counts."""
    units: List[Json] = []
    for node, info in _per_node(reply, "performance-summary-information"):
        for st in kids(info, "performance-summary-statistics"):
            units.append({
                "node": node,
                "fpc": _int(st, "fpc-number"),
                "pic": _int(st, "pic-number"),
                "cpu": _num(st, "spu-cpu-utilization"),
                "memory": _num(st, "spu-memory-utilization"),
                "flow_sessions": _int(st, "spu-current-flow-session"),
                "flow_max": _int(st, "spu-max-flow-session"),
                "cp_sessions": _int(st, "spu-current-cp-session"),
                "cp_max": _int(st, "spu-max-cp-session"),
            })
    if not units:
        return {"status": "failed", "message": "The security monitoring reply held no SPU.", "units": []}
    return {"status": "ok", "units": units}
