"""Canonical network peers for local admission and authentication budgets."""

from __future__ import annotations

import ipaddress


def peer_key(peer: str) -> str:
    """One bucket per IPv4 address or IPv6 /64, independent of textual spelling or mapped form."""
    try:
        address = ipaddress.ip_address(peer.split("%", 1)[0])
    except ValueError:
        return peer  # socket peers are numeric; preserve non-IP identifiers for synthetic callers
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        return str(ipaddress.IPv6Network((int(address), 64), strict=False))
    return str(address)
