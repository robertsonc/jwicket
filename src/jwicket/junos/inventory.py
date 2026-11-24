"""Spec 001: the scoped, read-only security policy inventory.

Input: one ``<configuration>`` element read from the *committed* database with group inheritance
expanded and annotated (``inherit="inherit" groups="groups"``). Output: plain, JSON-ready dicts.

Rules this module keeps (each one is a test in tests/test_inventory.py):

* Evaluation order is explicit. Within a scope, Junos evaluates the zone-pair policies for the
  matching from-zone/to-zone in configuration order, then global policies in configuration order,
  then the default policy. Rows carry that order; the UI never re-sorts it silently.
* Nothing is dropped silently. Configuration the model does not understand is reported per policy
  (``unmodeled``) and per scope (``warnings``), so "not shown" is never mistaken for "not there".
* Provenance is kept. Each object says whether it came from a configuration group, which group,
  and which of its parts were inherited. Writes (Spec 002) depend on this.
* Inactive configuration is shown and marked, with the reason (the policy itself, or its zone pair).
* Scopes are kept apart: the root system, each logical system and each tenant system are separate
  inventories and never merged.
* Secrets never leave this module: only modeled fields are copied out; raw XML is never returned.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from jwicket.junos.xmlutil import (
    Element,
    child_tags,
    group_of,
    groups_in,
    inherited_parts,
    is_inactive,
    kid,
    kids,
    local,
    names,
    path,
    present,
    text,
    text_of,
    texts,
)

SCHEMA = "jwicket.inventory/1"
ANY_ADDRESSES = ("any", "any-ipv4", "any-ipv6")
MAX_EXPANSION_DEPTH = 16
MAX_LEAVES = 512

_POLICY_KNOWN = {"name", "description", "match", "then", "scheduler-name", "policy-id"}
_MATCH_KNOWN = {
    "source-address",
    "destination-address",
    "application",
    "source-address-excluded",
    "destination-address-excluded",
    "source-identity",
    "dynamic-application",
    "url-category",
    "source-end-user-profile",
    "from-zone",
    "to-zone",
}
_THEN_KNOWN = {"permit", "deny", "reject", "log", "count"}
_PERMIT_KNOWN = {"application-services", "tunnel"}
_LOG_KNOWN = {"session-init", "session-close"}
_POLICIES_KNOWN = {"policy", "global", "default-policy", "pre-id-default-policy", "policy-rematch"}

Json = Dict[str, Any]


# --- configuration root and scopes ----------------------------------------------------------------


def configuration_root(reply: Element) -> Element:
    """Accept a bare <configuration> or any wrapper (rpc-reply, data) around one."""
    if local(reply.tag) == "configuration":
        return reply
    for element in reply.iter():
        if local(element.tag) == "configuration":
            return element
    raise ValueError("the reply holds no <configuration> element")


def list_scopes(config: Element) -> List[Tuple[str, str, Element, bool]]:
    """(scope id, label, scope element, inactive) for root, each logical system and each tenant."""
    scopes: List[Tuple[str, str, Element, bool]] = [("root", "Root system", config, False)]
    for kind, tag, label in (("lsys", "logical-systems", "Logical system"), ("tenant", "tenants", "Tenant system")):
        for node in kids(config, tag):
            name = text(node, "name")
            if name is None:
                continue
            scopes.append((f"{kind}:{name}", f"{label} {name}", node, is_inactive(node)))
    return scopes


# --- address books and applications ---------------------------------------------------------------


def _address_entry(node: Element) -> Json:
    name = text(node, "name") or "?"
    kind, value = "unknown", None
    if present(node, "ip-prefix"):
        kind, value = "prefix", text(node, "ip-prefix")
    elif present(node, "dns-name"):
        dns = kid(node, "dns-name")
        kind, value = "dns", text(dns, "name") or text_of(dns)
    elif present(node, "range-address"):
        rng = kid(node, "range-address")
        low = text(rng, "name")
        high = text(path(rng, "to"), "range-high")
        kind, value = "range", f"{low}-{high}" if low and high else low
    elif present(node, "wildcard-address"):
        kind, value = "wildcard", text(kid(node, "wildcard-address"), "name")
    return {
        "name": name,
        "kind": kind,
        "value": value,
        "description": text(node, "description"),
        "group": group_of(node),
        "inactive": is_inactive(node),
    }


def _address_set(node: Element) -> Json:
    return {
        "name": text(node, "name") or "?",
        "addresses": names(node, "address"),
        "sets": names(node, "address-set"),
        "description": text(node, "description"),
        "group": group_of(node),
        "inactive": is_inactive(node),
    }


def _book(name: str, node: Element, attach: List[str], legacy_zone: Optional[str]) -> Json:
    return {
        "name": name,
        "attach": attach,
        "legacy_zone": legacy_zone,
        "addresses": [_address_entry(a) for a in kids(node, "address")],
        "sets": [_address_set(s) for s in kids(node, "address-set")],
        "group": group_of(node),
        "inactive": is_inactive(node),
    }


def parse_address_books(security: Optional[Element]) -> List[Json]:
    books = []
    for node in kids(security, "address-book"):
        name = text(node, "name") or "?"
        attach = names(kid(node, "attach"), "zone")
        books.append(_book(name, node, attach, None))
    for zone in kids(kid(security, "zones"), "security-zone"):
        legacy = kid(zone, "address-book")
        if legacy is not None and (present(legacy, "address") or present(legacy, "address-set")):
            zname = text(zone, "name") or "?"
            books.append(_book(f"zone {zname}", legacy, [zname], zname))
    return books


def parse_applications(apps: Optional[Element]) -> List[Json]:
    rows: List[Json] = []
    for node in kids(apps, "application"):
        terms = list(kids(node, "term"))
        rows.append(
            {
                "name": text(node, "name") or "?",
                "kind": "application",
                "protocol": text(node, "protocol"),
                "destination_port": text(node, "destination-port"),
                "source_port": text(node, "source-port"),
                "terms": len(terms),
                "members": [],
                "sets": [],
                "description": text(node, "description"),
                "group": group_of(node),
                "inactive": is_inactive(node),
            }
        )
    for node in kids(apps, "application-set"):
        rows.append(
            {
                "name": text(node, "name") or "?",
                "kind": "set",
                "protocol": None,
                "destination_port": None,
                "source_port": None,
                "terms": 0,
                "members": names(node, "application"),
                "sets": names(node, "application-set"),
                "description": text(node, "description"),
                "group": group_of(node),
                "inactive": is_inactive(node),
            }
        )
    return rows


class AddressResolver:
    """Expands policy address names into their leaves, saying which address book each came from.

    Lookup order for a zone-pair policy: the zone's legacy address book, then books attached to the
    zone, then the book named ``global``. Global policies use the global book only. This order is
    J-Wicket's reading of the Junos documentation and is listed for verification in Spec 001.
    """

    def __init__(self, books: List[Json]) -> None:
        self._global = next((b for b in books if b["name"] == "global" and not b["legacy_zone"]), None)
        self._by_zone: Dict[str, List[Json]] = {}
        for book in books:
            for zone in book["attach"]:
                self._by_zone.setdefault(zone, [])
                if book["legacy_zone"]:
                    self._by_zone[zone].insert(0, book)
                else:
                    self._by_zone[zone].append(book)

    def _books_for(self, zones: List[str]) -> List[Json]:
        ordered: List[Json] = []
        for zone in zones:
            for book in self._by_zone.get(zone, []):
                if book not in ordered:
                    ordered.append(book)
        if self._global is not None and self._global not in ordered:
            ordered.append(self._global)
        return ordered

    def resolve(self, name: str, zones: List[str]) -> Json:
        if name in ANY_ADDRESSES:
            return {"name": name, "kind": "any", "book": None, "leaves": [], "truncated": False, "unresolved": []}
        found = self._lookup(name, self._books_for(zones))
        if found is None:
            return {"name": name, "kind": "unresolved", "book": None, "leaves": [], "truncated": False,
                    "unresolved": [name]}
        book, kind, _entry = found
        leaves: List[Json] = []
        unresolved: List[str] = []
        state = {"limited": False}
        # Junos lets an address set contain only entries of its own address book, so members are
        # looked up in the book that holds the set, never along the policy's lookup chain.
        self._expand(name, [book], leaves, unresolved, set(), 0, state)
        return {
            "name": name,
            "kind": kind,
            "book": book["name"],
            "leaves": leaves[:MAX_LEAVES],
            "truncated": len(leaves) > MAX_LEAVES or state["limited"],
            "unresolved": unresolved,
        }

    @staticmethod
    def _lookup(name: str, books: List[Json]) -> Optional[Tuple[Json, str, Json]]:
        for book in books:
            for entry in book["addresses"]:
                if entry["name"] == name:
                    return book, "address", entry
            for entry in book["sets"]:
                if entry["name"] == name:
                    return book, "set", entry
        return None

    def _expand(
        self,
        name: str,
        books: List[Json],
        leaves: List[Json],
        unresolved: List[str],
        seen: Set[str],
        depth: int,
        state: Dict[str, bool],
    ) -> None:
        if name in seen:
            return
        if depth > MAX_EXPANSION_DEPTH or len(leaves) > MAX_LEAVES:
            state["limited"] = True
            return
        seen.add(name)
        found = self._lookup(name, books)
        if found is None:
            unresolved.append(name)
            return
        _book, kind, entry = found
        if kind == "address":
            leaves.append({"name": entry["name"], "kind": entry["kind"], "value": entry["value"]})
            return
        for member in list(entry["addresses"]) + list(entry["sets"]):
            self._expand(member, books, leaves, unresolved, seen, depth + 1, state)


class ApplicationResolver:
    def __init__(self, apps: List[Json]) -> None:
        self._apps = {a["name"]: a for a in apps}

    def resolve(self, name: str) -> Json:
        if name == "any":
            return {"name": name, "kind": "any", "leaves": [], "unresolved": []}
        if name not in self._apps:
            kind = "predefined" if name.startswith("junos-") else "unresolved"
            return {"name": name, "kind": kind, "leaves": [], "unresolved": [] if kind == "predefined" else [name]}
        leaves: List[Json] = []
        unresolved: List[str] = []
        self._expand(name, leaves, unresolved, set(), 0)
        return {"name": name, "kind": self._apps[name]["kind"], "leaves": leaves[:MAX_LEAVES], "unresolved": unresolved}

    def _expand(self, name: str, leaves: List[Json], unresolved: List[str], seen: Set[str], depth: int) -> None:
        if name in seen or depth > MAX_EXPANSION_DEPTH or len(leaves) > MAX_LEAVES:
            return
        seen.add(name)
        app = self._apps.get(name)
        if app is None:
            if name.startswith("junos-"):
                leaves.append({"name": name, "predefined": True})
            else:
                unresolved.append(name)
            return
        if app["kind"] == "application":
            leaves.append(
                {
                    "name": name,
                    "protocol": app["protocol"],
                    "destination_port": app["destination_port"],
                    "source_port": app["source_port"],
                    "terms": app["terms"],
                }
            )
            return
        for member in list(app["members"]) + list(app["sets"]):
            self._expand(member, leaves, unresolved, seen, depth + 1)


# --- policies -------------------------------------------------------------------------------------


def _leaf_list(node: Optional[Element], name: str, inactive_out: List[str], prefix: str) -> List[str]:
    """Active values of a leaf-list; deactivated values are reported in ``inactive_out``."""
    values: List[str] = []
    for child in kids(node, name):
        value = text_of(child)
        if value is None:
            continue
        if is_inactive(child):
            inactive_out.append(f"{prefix}{name} {value}")
        else:
            values.append(value)
    return values


def _flag(node: Optional[Element], name: str, inactive_out: List[str], prefix: str) -> bool:
    """An empty-element flag is set only if present and active; a deactivated one is reported."""
    child = kid(node, name)
    if child is None:
        return False
    if is_inactive(child):
        inactive_out.append(f"{prefix}{name}")
        return False
    return True


def _unmodeled(node: Optional[Element], known: Iterable[str], prefix: str) -> List[str]:
    known_set = set(known)
    return [f"{prefix}{tag}" for tag in child_tags(node) if tag not in known_set]


def _policy(
    node: Element,
    *,
    scope: str,
    kind: str,
    seq: int,
    from_zones: List[str],
    to_zones: List[str],
    pair_inactive: bool,
    pair_group: Optional[str],
) -> Json:
    name = text(node, "name") or "?"
    match = kid(node, "match")
    then = kid(node, "then")
    inactive_parts: List[str] = []
    action = next((a for a in ("permit", "deny", "reject") if _flag(then, a, inactive_parts, "then ")), "unknown")
    permit = kid(then, "permit") if action == "permit" else None
    log = kid(then, "log")
    if is_inactive(log):
        inactive_parts.append("then log")
        log = None
    tunnel = path(permit, "tunnel")
    unmodeled = (
        _unmodeled(node, _POLICY_KNOWN, "")
        + _unmodeled(match, _MATCH_KNOWN, "match ")
        + _unmodeled(then, _THEN_KNOWN, "then ")
        + _unmodeled(permit, _PERMIT_KNOWN, "then permit ")
        + _unmodeled(tunnel, {"ipsec-vpn"}, "then permit tunnel ")
        + _unmodeled(kid(then, "deny"), (), "then deny ")
        + _unmodeled(kid(then, "reject"), (), "then reject ")
        + _unmodeled(log, _LOG_KNOWN, "then log ")
    )

    def leaf(name_: str) -> List[str]:
        return _leaf_list(match, name_, inactive_parts, "match ")

    inactive_reason = "policy" if is_inactive(node) else ("zone-pair" if pair_inactive else None)
    group = group_of(node) or pair_group
    if kind == "global":
        pair_key = "global"
    else:
        pair_key = f"{from_zones[0] if from_zones else '?'}>{to_zones[0] if to_zones else '?'}"
    return {
        "id": f"{scope}|{kind}|{pair_key}|{name}",
        "scope": scope,
        "kind": kind,
        "seq": seq,
        "from": from_zones,
        "to": to_zones,
        "name": name,
        "description": text(node, "description"),
        "match": {
            "source": leaf("source-address"),
            "destination": leaf("destination-address"),
            "application": leaf("application"),
            "source_excluded": _flag(match, "source-address-excluded", inactive_parts, "match "),
            "destination_excluded": _flag(match, "destination-address-excluded", inactive_parts, "match "),
            "source_identity": leaf("source-identity"),
            "dynamic_application": leaf("dynamic-application"),
            "url_category": leaf("url-category"),
            "source_end_user_profile": leaf("source-end-user-profile"),
        },
        "action": action,
        "application_services": child_tags(kid(permit, "application-services")),
        "tunnel": text(tunnel, "ipsec-vpn"),
        "log": {
            "init": _flag(log, "session-init", inactive_parts, "then log "),
            "close": _flag(log, "session-close", inactive_parts, "then log "),
        },
        "count": _flag(then, "count", inactive_parts, "then "),
        "scheduler": text(node, "scheduler-name"),
        "inactive": inactive_reason is not None,
        "inactive_reason": inactive_reason,
        "group": group,
        "inherited": inherited_parts(node),
        "groups": groups_in(node),
        "unmodeled": unmodeled,
        # Deactivated parts of an otherwise active policy: not in effect, so not in the match lists.
        "inactive_parts": inactive_parts,
    }


def _resolve_policy(row: Json, addresses: AddressResolver, apps: ApplicationResolver) -> None:
    src_zones = row["from"] if row["kind"] == "zone" else []
    dst_zones = row["to"] if row["kind"] == "zone" else []
    row["resolved"] = {
        "source": [addresses.resolve(n, src_zones) for n in row["match"]["source"]],
        "destination": [addresses.resolve(n, dst_zones) for n in row["match"]["destination"]],
        "application": [apps.resolve(n) for n in row["match"]["application"]],
    }


def parse_policies(scope: str, security: Optional[Element]) -> Json:
    policies = kid(security, "policies")
    rows: List[Json] = []
    for pair in kids(policies, "policy"):
        frm = text(pair, "from-zone-name")
        to = text(pair, "to-zone-name")
        for seq, node in enumerate(kids(pair, "policy"), 1):
            rows.append(
                _policy(
                    node,
                    scope=scope,
                    kind="zone",
                    seq=seq,
                    from_zones=[frm] if frm else [],
                    to_zones=[to] if to else [],
                    pair_inactive=is_inactive(pair),
                    pair_group=group_of(pair),
                )
            )
    glob = kid(policies, "global")
    for seq, node in enumerate(kids(glob, "policy"), 1):
        match = kid(node, "match")
        rows.append(
            _policy(
                node,
                scope=scope,
                kind="global",
                seq=seq,
                from_zones=texts(match, "from-zone"),
                to_zones=texts(match, "to-zone"),
                pair_inactive=is_inactive(glob),
                pair_group=group_of(glob),
            )
        )
    default = kid(policies, "default-policy")
    default_action = next((t for t in ("permit-all", "deny-all") if present(default, t)), None)
    return {
        "rows": rows,
        "default_policy": default_action,
        "default_policy_group": group_of(default),
        "pre_id_default_policy": present(policies, "pre-id-default-policy"),
        "policy_rematch": present(policies, "policy-rematch"),
        "other_settings": _unmodeled(policies, _POLICIES_KNOWN, ""),
    }


def parse_zones(security: Optional[Element]) -> List[Json]:
    rows = []
    for zone in kids(kid(security, "zones"), "security-zone"):
        hit = kid(zone, "host-inbound-traffic")
        interfaces = []
        for ifc in kids(zone, "interfaces"):
            ihit = kid(ifc, "host-inbound-traffic")
            interfaces.append(
                {
                    "name": text(ifc, "name") or "?",
                    "services": names(ihit, "system-services"),
                    "protocols": names(ihit, "protocols"),
                    "group": group_of(ifc),
                }
            )
        rows.append(
            {
                "name": text(zone, "name") or "?",
                "interfaces": interfaces,
                "services": names(hit, "system-services"),
                "protocols": names(hit, "protocols"),
                "screen": text(zone, "screen"),
                "description": text(zone, "description"),
                "group": group_of(zone),
                "inactive": is_inactive(zone),
            }
        )
    return rows


def _zone_pairs(rows: List[Json]) -> List[Json]:
    pairs: Dict[Tuple[str, str], Json] = {}
    for row in rows:
        if row["kind"] != "zone" or not row["from"] or not row["to"]:
            continue
        key = (row["from"][0], row["to"][0])
        entry = pairs.setdefault(
            key, {"from": key[0], "to": key[1], "count": 0, "inactive": 0, "permit": 0, "deny": 0, "reject": 0}
        )
        entry["count"] += 1
        if row["inactive"]:
            entry["inactive"] += 1
        elif row["action"] in ("permit", "deny", "reject"):
            entry[row["action"]] += 1
    return list(pairs.values())


def _scope_inventory(scope_id: str, label: str, node: Element, scope_inactive: bool) -> Json:
    security = kid(node, "security")
    apps = parse_applications(kid(node, "applications"))
    books = parse_address_books(security)
    policies = parse_policies(scope_id, security)
    addresses = AddressResolver(books)
    app_resolver = ApplicationResolver(apps)
    for row in policies["rows"]:
        _resolve_policy(row, addresses, app_resolver)

    warnings: List[str] = []
    if scope_inactive:
        warnings.append(f"{label} is deactivated in the configuration; nothing in it is in effect.")
    for row in policies["rows"]:
        if row["unmodeled"]:
            warnings.append(
                f"Policy {row['name']} has settings J-Wicket does not display yet: {', '.join(row['unmodeled'])}."
            )
        if row["inactive_parts"] and not row["inactive"]:
            warnings.append(
                f"Policy {row['name']} has deactivated parts (not in effect): {', '.join(row['inactive_parts'])}."
            )
        if row["action"] == "unknown":
            warnings.append(f"Policy {row['name']} has no permit, deny or reject action J-Wicket recognises.")
    if policies["other_settings"]:
        warnings.append(
            "Policy settings J-Wicket does not display yet: " + ", ".join(policies["other_settings"]) + "."
        )
    if policies["pre_id_default_policy"]:
        warnings.append("A pre-ID default policy is configured; J-Wicket shows its presence but not its contents.")

    group_counts: Dict[str, int] = {}
    for row in policies["rows"]:
        for grp in row["groups"]:
            group_counts[grp] = group_counts.get(grp, 0) + 1

    return {
        "id": scope_id,
        "label": label,
        "inactive": scope_inactive,
        "policies": {
            "status": "ok",
            "rows": policies["rows"],
            "default_policy": policies["default_policy"],
            "default_policy_group": policies["default_policy_group"],
            "policy_rematch": policies["policy_rematch"],
            "pre_id_default_policy": policies["pre_id_default_policy"],
            "zone_pairs": _zone_pairs(policies["rows"]),
            "global_count": sum(1 for r in policies["rows"] if r["kind"] == "global"),
        },
        "zones": {"status": "ok", "rows": parse_zones(security)},
        "address_books": {"status": "ok", "rows": books},
        "applications": {"status": "ok", "rows": apps},
        "groups": [{"name": k, "policies": v} for k, v in group_counts.items()],
        "warnings": warnings,
    }


def build_inventory(reply: Element) -> Dict[str, Json]:
    """Every scope in the configuration, keyed by scope id."""
    config = configuration_root(reply)
    return {
        scope_id: _scope_inventory(scope_id, label, node, inactive)
        for scope_id, label, node, inactive in list_scopes(config)
    }


def scope_summaries(inventories: Dict[str, Json]) -> List[Json]:
    return [
        {
            "id": inv["id"],
            "label": inv["label"],
            "policies": len(inv["policies"]["rows"]),
            "inactive": inv["inactive"],
        }
        for inv in inventories.values()
    ]
