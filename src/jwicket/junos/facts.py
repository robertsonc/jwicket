"""Device facts for the scope banner: identity, high availability and central management.

These answer "what exactly am I looking at?" before anyone reads a policy: which device and
release, whether it is one node of a cluster, and whether something else (Security Director,
Security Director Cloud, Mist or another manager) also writes this configuration.

Field names for ``get-chassis-cluster-status`` are not yet confirmed against a recorded reply
(qualification Q-REL-01), so that parser is tolerant: it accepts node fields either grouped per
node or as a flat repeated sequence, and reports ``unknown`` rather than guessing.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from jwicket.junos.xmlutil import Element, kid, kids, local, path, text, text_of

Json = Dict[str, Any]

def software(reply: Element) -> Json:
    """Hostname, model and release. In a cluster the reply holds one item per node."""
    items = []
    for re_item in (e for e in reply.iter() if local(e.tag) == "multi-routing-engine-item"):
        sw = next((e for e in re_item.iter() if local(e.tag) == "software-information"), None)
        if sw is not None:
            items.append((text(re_item, "re-name"), sw))
    if not items:
        sw = next((e for e in reply.iter() if local(e.tag) == "software-information"), None)
        if sw is not None:
            items.append((None, sw))
    if not items:
        return {"status": "failed", "message": "The software information reply was empty."}
    nodes = [
        {
            "node": node,
            "hostname": text(sw, "host-name"),
            "model": text(sw, "product-model"),
            "version": text(sw, "junos-version"),
        }
        for node, sw in items
    ]
    first = nodes[0]
    return {
        "status": "ok",
        "hostname": first["hostname"],
        "model": first["model"],
        "version": first["version"],
        "nodes": nodes if len(nodes) > 1 else [],
    }


def cluster(reply: Element) -> Json:
    """Chassis cluster status. Tolerant of grouped or flat device-stats layouts."""
    status = reply if local(reply.tag) == "chassis-cluster-status" else next(
        (e for e in reply.iter() if local(e.tag) == "chassis-cluster-status"), None
    )
    if status is None:
        return {"status": "ok", "mode": "unknown", "message": "Unrecognised cluster status reply."}
    groups: List[Json] = []
    for rg in kids(status, "redundancy-group"):
        nodes: List[Json] = []
        for stats in kids(rg, "device-stats"):
            current: Optional[Json] = None
            for field in kids(stats):
                tag = local(field.tag)
                if tag == "device-name":
                    current = {"name": text_of(field), "priority": None, "status": None}
                    nodes.append(current)
                elif current is not None and tag == "device-priority":
                    current["priority"] = text_of(field)
                elif current is not None and tag == "redundancy-group-status":
                    current["status"] = text_of(field)
        groups.append({"id": text(rg, "redundancy-group-id"), "nodes": nodes})
    return {
        "status": "ok",
        "mode": "chassis-cluster",
        "cluster_id": text(status, "cluster-id"),
        "redundancy_groups": groups,
        # Which node is serving this page is not in this reply; see qualification Q-HA-02.
        "local_node": None,
    }


def standalone() -> Json:
    return {"status": "ok", "mode": "standalone"}


def mnha_configured(config: Optional[Element]) -> bool:
    return path(config, "chassis", "high-availability") is not None


def central_management(config: Optional[Element]) -> Json:
    """Outbound-SSH clients in the root configuration. Their presence means another system may own
    this configuration. Only the client name and non-secret fields are returned; ``secret`` never is.
    """
    clients = []
    outbound = path(config, "system", "services", "outbound-ssh")
    for client in kids(outbound, "client"):
        name = text(client, "name")
        if name is None:
            continue
        targets = []
        for child in kids(client):
            tag = local(child.tag)
            if tag in ("name", "secret", "device-id", "services", "keep-alive", "reconnect-strategy"):
                continue
            # A target is a keyed entry (an address or host name) with an optional port.
            address = text(child, "name")
            if address is not None:
                port = text(child, "port")
                targets.append(f"{address}:{port}" if port else address)
        services = [local(s.tag) for s in kids(kid(client, "services"))]
        clients.append({"client": name, "targets": targets, "services": services})
    return {"status": "ok", "clients": clients, "managed": bool(clients)}
