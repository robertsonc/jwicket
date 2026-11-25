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

from jwicket.junos.xmlutil import Element, active_path, is_inactive, kid, kids, local, text, text_of

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
        # A standalone device answers with an error in the reply body, which PyEZ returns rather than
        # raises (recorded on SRX4100 25.2R1-S1.4: <xnm:error> from jsrpd, "error: Chassis cluster is
        # not enabled").
        message = next((text_of(e) for e in reply.iter() if local(e.tag) == "message"), None)
        is_error = local(reply.tag) == "error" or any(local(e.tag) == "error" for e in reply.iter())
        if is_error and message and "not enabled" in message.lower():
            return standalone()
        if is_error:
            return {"status": "ok", "mode": "unknown", "message": "The cluster status read returned an error."}
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
    """Multinode High Availability is configured and in effect (not deactivated, nor its chassis)."""
    return active_path(config, "chassis", "high-availability") is not None


def central_management(config: Optional[Element]) -> Json:
    """Outbound-SSH clients in the root configuration. Their presence means another system may own
    this configuration. Only the client name and non-secret fields are returned; ``secret`` never is.
    A deactivated client (or a deactivated outbound-ssh, services or system above it) is listed with
    ``inactive`` and does not make the device ``managed``.
    """
    clients = []
    system = kid(config, "system")
    services = kid(system, "services")
    outbound = kid(services, "outbound-ssh")
    above_off = any(is_inactive(node) for node in (system, services, outbound))
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
        # Recorded on 25.2R1-S1.4 as a leaf-list (<services>netconf</services>); older fixtures used
        # child elements (<services><netconf/></services>). Both are read.
        client_services: List[str] = []
        for svc in kids(client, "services"):
            value = text_of(svc)
            client_services += [local(s.tag) for s in kids(svc)] or ([value] if value else [])
        clients.append({
            "client": name, "targets": targets, "services": client_services,
            "inactive": above_off or is_inactive(client),
        })
    return {"status": "ok", "clients": clients, "managed": any(not c["inactive"] for c in clients)}
