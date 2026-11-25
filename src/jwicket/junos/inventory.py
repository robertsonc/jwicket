"""Spec 001: the scoped, read-only security policy inventory.

Input: one ``<configuration>`` element read from the *committed* database with group inheritance
expanded and annotated (``inherit="inherit" groups="groups"``). Output: plain, JSON-ready dicts.

Rules this module keeps (each one is a test in tests/test_inventory.py):

* Evaluation order is explicit. Within a scope, Junos evaluates the zone-pair policies for the
  matching from-zone/to-zone in configuration order, then global policies in configuration order,
  then the default policy. Rows carry that order; the UI never re-sorts it silently. Unified
  policies (those with a dynamic application) are the exception: before the application is
  identified, Junos may match a list of potential policies rather than one ("a policy search might
  return a list of policies instead of a fixed policy", configuring-unified-policies). That
  configuration order is then the order of those candidates is J-Wicket's inference, not a
  documented statement.
* Nothing is dropped silently. Configuration the model does not understand is reported per object
  (``unmodeled`` on policies, zones, interfaces, address entries, sets and books, applications and
  application sets) and per scope (``warnings``), so "not shown" is never mistaken for "not there".
  Configuration comments (``annotate``) are not settings: they are attached to the statement they
  annotate (``comment``).
* Provenance is kept. Each object says whether it came from a configuration group, which group,
  and which of its parts were inherited. Writes (Spec 002) depend on this.
* Inactive configuration is shown and marked, with the reason: the policy itself, its zone pair (or
  ``global`` block), or a deactivated ancestor (``policies``, ``security``, or the logical or tenant
  system: ``scope``). Deactivated statements are never treated as in effect: not in the default
  policy, rematch and pre-ID settings, not in host-inbound services and protocols, and not when
  addresses and applications are resolved (deactivated set members, address entries, books and
  ``attach`` zones are skipped and listed).
* Scopes are kept apart: the root system, each logical system and each tenant system are separate
  inventories and never merged.
* Secrets never leave this module: only modeled fields are copied out; raw XML is never returned.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from jwicket.junos.errors import MalformedReply
from jwicket.junos.xmlutil import (
    Element,
    comments_before,
    deactivated_parts,
    group_of,
    groups_in,
    inherited_parts,
    inner_comments,
    is_inactive,
    kid,
    kids,
    local,
    path,
    present,
    split_names,
    statement_tags,
    text,
    text_of,
    trailing_comment,
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
_ADDRESS_KNOWN = {"name", "description", "ip-prefix", "dns-name", "range-address", "wildcard-address"}
_ADDRESS_SET_KNOWN = {"name", "description", "address", "address-set"}
_BOOK_KNOWN = {"name", "description", "address", "address-set", "attach"}
_LEGACY_BOOK_KNOWN = {"address", "address-set"}
_APPLICATION_KNOWN = {"name", "description", "protocol", "destination-port", "source-port", "term"}
_APPLICATION_SET_KNOWN = {"name", "description", "application", "application-set"}
_ZONE_KNOWN = {"name", "description", "host-inbound-traffic", "interfaces", "screen", "address-book"}
_INTERFACE_KNOWN = {"name", "host-inbound-traffic"}
_HOST_INBOUND_KNOWN = {"system-services", "protocols"}
# "application junos-defaults" is a match keyword of unified policies: the dynamic application's own
# default ports and protocols (configuring-unified-policies). It is not a predefined application.
DYNAMIC_DEFAULTS = "junos-defaults"
# The logical-system and tenant names J-Wicket can address in a scope id (``api._SCOPE``). Junos may
# accept other characters; until that character set is verified (owner decision OD-12) such scopes
# are listed but not selectable.
SELECTABLE_NAME = re.compile(r"^[A-Za-z0-9._\-]{1,63}\Z")
NOT_SELECTABLE = (
    "J-Wicket cannot address this name yet (it accepts letters, digits, dot, underscore and hyphen, up to 63 "
    "characters)."
)

Json = Dict[str, Any]


# --- configuration root and scopes ----------------------------------------------------------------


def configuration_root(reply: Element) -> Element:
    """Accept a bare <configuration> or any wrapper (rpc-reply, data) around one."""
    if local(reply.tag) == "configuration":
        return reply
    for element in reply.iter():
        if local(element.tag) == "configuration":
            return element
    raise MalformedReply(f"the {local(reply.tag) or 'reply'} reply holds no <configuration> element")


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


def _unmodeled(node: Optional[Element], known: Iterable[str], prefix: str) -> List[str]:
    """Statements under ``node`` the model does not show. Configuration comments are not statements."""
    known_set = set(known)
    return [f"{prefix}{tag}" for tag in statement_tags(node) if tag not in known_set]


def _address_entry(node: Element, comment: Optional[str] = None) -> Json:
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
        "inherited": inherited_parts(node),
        "groups": groups_in(node),
        "inactive": is_inactive(node),
        # Deactivated statements of an otherwise active entry (not in effect).
        "inactive_parts": deactivated_parts(node),
        "comment": comment,
        "unmodeled": _unmodeled(node, _ADDRESS_KNOWN, ""),
    }


def _address_set(node: Element, comment: Optional[str] = None) -> Json:
    addresses, inactive_addresses = split_names(node, "address")
    sets, inactive_sets = split_names(node, "address-set")
    return {
        "name": text(node, "name") or "?",
        # Members in effect only; deactivated members are listed apart (not in effect).
        "addresses": addresses,
        "sets": sets,
        "inactive_members": inactive_addresses + inactive_sets,
        "inactive_addresses": inactive_addresses,
        "inactive_sets": inactive_sets,
        "description": text(node, "description"),
        "group": group_of(node),
        "inherited": inherited_parts(node),
        "groups": groups_in(node),
        "inactive": is_inactive(node),
        "comment": comment,
        "part_comments": inner_comments(node),
        "unmodeled": _unmodeled(node, _ADDRESS_SET_KNOWN, ""),
    }


def _book(
    name: str, node: Element, attach: List[str], legacy_zone: Optional[str], *,
    inactive_attach: Optional[List[str]] = None, comment: Optional[str] = None, known: Iterable[str] = _BOOK_KNOWN,
) -> Json:
    notes = comments_before(node)
    return {
        "name": name,
        "attach": attach,
        "inactive_attach": inactive_attach or [],
        "legacy_zone": legacy_zone,
        "addresses": [_address_entry(a, notes.get(id(a))) for a in kids(node, "address")],
        "sets": [_address_set(s, notes.get(id(s))) for s in kids(node, "address-set")],
        "description": text(node, "description"),
        "group": group_of(node),
        "inherited": inherited_parts(node),
        "groups": groups_in(node),
        "inactive": is_inactive(node),
        "comment": comment,
        "part_comments": inner_comments(node),
        "unmodeled": _unmodeled(node, known, ""),
    }


def parse_address_books(security: Optional[Element]) -> List[Json]:
    books = []
    notes = comments_before(security)
    for node in kids(security, "address-book"):
        name = text(node, "name") or "?"
        attach_node = kid(node, "attach")
        attach, inactive_attach = split_names(attach_node, "zone")
        if is_inactive(attach_node):
            attach, inactive_attach = [], attach + inactive_attach
        books.append(_book(name, node, attach, None, inactive_attach=inactive_attach, comment=notes.get(id(node))))
    for zone in kids(kid(security, "zones"), "security-zone"):
        legacy = kid(zone, "address-book")
        if legacy is not None and (present(legacy, "address") or present(legacy, "address-set")):
            zname = text(zone, "name") or "?"
            books.append(_book(f"zone {zname}", legacy, [zname], zname, known=_LEGACY_BOOK_KNOWN,
                               comment=comments_before(zone).get(id(legacy))))
    return books


def _active_leaf(node: Element, name: str) -> Optional[str]:
    """A leaf's value when it is present and not deactivated, else None."""
    leaf = kid(node, name)
    return None if leaf is None or is_inactive(leaf) else text_of(leaf)


def parse_applications(apps: Optional[Element]) -> List[Json]:
    rows: List[Json] = []
    notes = comments_before(apps)
    for node in kids(apps, "application"):
        terms = [t for t in kids(node, "term") if not is_inactive(t)]
        rows.append(
            {
                "name": text(node, "name") or "?",
                "kind": "application",
                # Null when the leaf is deactivated (not in effect); the leaf is then in inactive_parts.
                "protocol": _active_leaf(node, "protocol"),
                "destination_port": _active_leaf(node, "destination-port"),
                "source_port": _active_leaf(node, "source-port"),
                # Terms in effect are counted, not shown: their contents are J-Wicket's next step (Spec 001).
                "terms": len(terms),
                "members": [],
                "sets": [],
                "inactive_members": [],
                "inactive_applications": [],
                "inactive_sets": [],
                "description": text(node, "description"),
                "group": group_of(node),
                "inherited": inherited_parts(node),
                "groups": groups_in(node),
                "inactive": is_inactive(node),
                # For example "destination-port 2121" (that such a leaf is a deactivatable one-liner is
                # inferred).
                "inactive_parts": deactivated_parts(node),
                "comment": notes.get(id(node)),
                "part_comments": inner_comments(node),
                # For example application-protocol (an ALG), icmp-type, inactivity-timeout.
                "unmodeled": _unmodeled(node, _APPLICATION_KNOWN, ""),
            }
        )
    for node in kids(apps, "application-set"):
        members, inactive_members = split_names(node, "application")
        sets, inactive_sets = split_names(node, "application-set")
        rows.append(
            {
                "name": text(node, "name") or "?",
                "kind": "set",
                "protocol": None,
                "destination_port": None,
                "source_port": None,
                "terms": 0,
                "members": members,
                "sets": sets,
                "inactive_members": inactive_members + inactive_sets,
                "inactive_applications": inactive_members,
                "inactive_sets": inactive_sets,
                "description": text(node, "description"),
                "group": group_of(node),
                "inherited": inherited_parts(node),
                "groups": groups_in(node),
                "inactive": is_inactive(node),
                # Deactivated members are listed above, not here.
                "inactive_parts": deactivated_parts(node, ("name", "application", "application-set")),
                "comment": notes.get(id(node)),
                "part_comments": inner_comments(node),
                "unmodeled": _unmodeled(node, _APPLICATION_SET_KNOWN, ""),
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
        # A deactivated book, and a deactivated attach statement, are not in effect.
        active = [b for b in books if not b["inactive"]]
        self._global = next((b for b in active if b["name"] == "global" and not b["legacy_zone"]), None)
        self._by_zone: Dict[str, List[Json]] = {}
        for book in active:
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
            return {"name": name, "kind": "any", "book": None, "leaves": [], "truncated": False, "unresolved": [],
                    "inactive_skipped": []}
        skipped: List[str] = []
        found = self._lookup(name, self._books_for(zones), skipped)
        if found is None:
            # "unresolved" (the kind) means no active entry; the list names only what has no entry at
            # all, so a deactivated entry is in inactive_skipped and not listed twice.
            missing = [] if self._deactivated_entry(name, self._books_for(zones)) else [name]
            return {"name": name, "kind": "unresolved", "book": None, "leaves": [], "truncated": False,
                    "unresolved": missing, "inactive_skipped": skipped}
        book, kind, _entry = found
        leaves: List[Json] = []
        unresolved: List[str] = []
        state = {"limited": False}
        # Junos lets an address set contain only entries of its own address book, so members are
        # looked up in the book that holds the set, never along the policy's lookup chain.
        self._expand(name, [book], leaves, unresolved, set(), 0, state, skipped)
        return {
            "name": name,
            "kind": kind,
            "book": book["name"],
            "leaves": leaves[:MAX_LEAVES],
            "truncated": len(leaves) > MAX_LEAVES or state["limited"],
            "unresolved": unresolved,
            # Deactivated entries of the same name that the lookup passed over ("book:name").
            "inactive_skipped": skipped,
        }

    @staticmethod
    def _deactivated_entry(name: str, books: List[Json]) -> bool:
        return any(entry["name"] == name and entry["inactive"]
                   for book in books for entry in list(book["addresses"]) + list(book["sets"]))

    @staticmethod
    def _lookup(name: str, books: List[Json], skipped: List[str]) -> Optional[Tuple[Json, str, Json]]:
        for book in books:
            for kind, entries in (("address", book["addresses"]), ("set", book["sets"])):
                for entry in entries:
                    if entry["name"] != name:
                        continue
                    if entry["inactive"]:
                        note = f"{book['name']}:{name}"
                        if note not in skipped:
                            skipped.append(note)
                        continue
                    return book, kind, entry
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
        skipped: List[str],
    ) -> None:
        if name in seen:
            return
        if depth > MAX_EXPANSION_DEPTH or len(leaves) > MAX_LEAVES:
            state["limited"] = True
            return
        seen.add(name)
        found = self._lookup(name, books, skipped)
        if found is None:
            # A deactivated entry of that name is reported in skipped only.
            if not self._deactivated_entry(name, books):
                unresolved.append(name)
            return
        _book, kind, entry = found
        if kind == "address":
            leaves.append({"name": entry["name"], "kind": entry["kind"], "value": entry["value"]})
            return
        # Members in effect only: deactivated members are in the set's inactive_members.
        for member in list(entry["addresses"]) + list(entry["sets"]):
            self._expand(member, books, leaves, unresolved, seen, depth + 1, state, skipped)


class ApplicationResolver:
    def __init__(self, apps: List[Json]) -> None:
        # A deactivated application or application set is not in effect.
        self._apps = {a["name"]: a for a in apps if not a["inactive"]}
        self._inactive = {a["name"] for a in apps if a["inactive"]}

    def resolve(self, name: str) -> Json:
        """``unresolved`` names only what has no definition at all; a deactivated application or set
        (the name itself, a member or a nested set) is in ``inactive_skipped``, which is always present.
        ``kind`` "unresolved" still means no active definition."""
        if name == "any":
            return {"name": name, "kind": "any", "leaves": [], "unresolved": [], "inactive_skipped": []}
        if name == DYNAMIC_DEFAULTS:
            # Unified policies: the dynamic application's own default ports and protocols.
            return {"name": name, "kind": "dynamic-defaults", "leaves": [], "unresolved": [], "inactive_skipped": []}
        if name not in self._apps:
            kind = "predefined" if name.startswith("junos-") else "unresolved"
            off = name in self._inactive
            return {"name": name, "kind": kind, "leaves": [],
                    "unresolved": [] if kind == "predefined" or off else [name],
                    "inactive_skipped": [name] if off else []}
        leaves: List[Json] = []
        unresolved: List[str] = []
        skipped: List[str] = []
        self._expand(name, leaves, unresolved, set(), 0, skipped)
        return {"name": name, "kind": self._apps[name]["kind"], "leaves": leaves[:MAX_LEAVES], "unresolved": unresolved,
                "inactive_skipped": skipped}

    def _expand(
        self, name: str, leaves: List[Json], unresolved: List[str], seen: Set[str], depth: int, skipped: List[str]
    ) -> None:
        if name in seen or depth > MAX_EXPANSION_DEPTH or len(leaves) > MAX_LEAVES:
            return
        seen.add(name)
        app = self._apps.get(name)
        if app is None:
            if name in self._inactive:
                if name not in skipped:
                    skipped.append(name)
            elif name.startswith("junos-"):
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
                    "unmodeled": app["unmodeled"],
                }
            )
            return
        for member in list(app["members"]) + list(app["sets"]):
            self._expand(member, leaves, unresolved, seen, depth + 1, skipped)


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
    ancestor_inactive: Optional[str] = None,
    inactive_parts_in: Optional[List[str]] = None,
    comment: Optional[str] = None,
    pair_comment: Optional[str] = None,
) -> Json:
    name = text(node, "name") or "?"
    match = kid(node, "match")
    then = kid(node, "then")
    inactive_parts: List[str] = list(inactive_parts_in or [])
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

    # The nearest deactivated statement: the policy, its zone pair (or global block), then the
    # ancestors that hold every policy (policies, security, the logical or tenant system).
    if is_inactive(node):
        inactive_reason: Optional[str] = "policy"
    elif pair_inactive:
        inactive_reason = "zone-pair"
    else:
        inactive_reason = ancestor_inactive
    group = group_of(node) or pair_group
    application = leaf("application")
    dynamic_application = leaf("dynamic-application")
    # Unified policies: with a dynamic application and no application, Junos implicitly adds
    # "application junos-defaults", or "application any" when the dynamic application is any
    # (configuring-unified-policies).
    application_implicit = bool(dynamic_application) and not application
    if application_implicit:
        application = ["any"] if "any" in dynamic_application else [DYNAMIC_DEFAULTS]
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
            "application": application,
            "application_implicit": application_implicit,
            "source_excluded": _flag(match, "source-address-excluded", inactive_parts, "match "),
            "destination_excluded": _flag(match, "destination-address-excluded", inactive_parts, "match "),
            "source_identity": leaf("source-identity"),
            "dynamic_application": dynamic_application,
            "url_category": leaf("url-category"),
            "source_end_user_profile": leaf("source-end-user-profile"),
        },
        "action": action,
        "application_services": statement_tags(kid(permit, "application-services")),
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
        # Configuration comments (annotate): on the rule, inside it, and on its zone-pair context.
        "comment": comment,
        "part_comments": inner_comments(node),
        "pair_comment": pair_comment,
    }


def _resolve_policy(row: Json, addresses: AddressResolver, apps: ApplicationResolver) -> None:
    src_zones = row["from"] if row["kind"] == "zone" else []
    dst_zones = row["to"] if row["kind"] == "zone" else []
    row["resolved"] = {
        "source": [addresses.resolve(n, src_zones) for n in row["match"]["source"]],
        "destination": [addresses.resolve(n, dst_zones) for n in row["match"]["destination"]],
        "application": [apps.resolve(n) for n in row["match"]["application"]],
    }


def _ancestor_inactive(security: Optional[Element], policies: Optional[Element], scope_inactive: bool) -> Optional[str]:
    """The nearest deactivated statement above every policy of the scope, if any."""
    if is_inactive(policies):
        return "policies"
    if is_inactive(security):
        return "security"
    if scope_inactive:
        return "scope"
    return None


def _setting(policies: Optional[Element], name: str, ancestor: Optional[str]) -> Tuple[bool, bool]:
    """(in effect, written but deactivated) for an empty-or-container statement under <policies>."""
    node = kid(policies, name)
    if node is None:
        return False, False
    off = ancestor is not None or is_inactive(node)
    return not off, off


def parse_policies(scope: str, security: Optional[Element], scope_inactive: bool = False) -> Json:
    policies = kid(security, "policies")
    ancestor = _ancestor_inactive(security, policies, scope_inactive)
    rows: List[Json] = []
    notes = comments_before(policies)
    pair_trailing: Dict[Tuple[str, str], Optional[str]] = {}
    for pair in kids(policies, "policy"):
        frm = text(pair, "from-zone-name")
        to = text(pair, "to-zone-name")
        if frm and to:
            pair_trailing.setdefault((frm, to), trailing_comment(pair))
        rule_notes = comments_before(pair)
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
                    ancestor_inactive=ancestor,
                    comment=rule_notes.get(id(node)),
                    pair_comment=notes.get(id(pair)),
                )
            )
    glob = kid(policies, "global")
    global_notes = comments_before(glob)
    for seq, node in enumerate(kids(glob, "policy"), 1):
        match = kid(node, "match")
        zone_parts: List[str] = []
        rows.append(
            _policy(
                node,
                scope=scope,
                kind="global",
                seq=seq,
                # Deactivated from-zone/to-zone values are not in effect. If every value is
                # deactivated the list is empty, which (as in Junos) means any zone.
                from_zones=_leaf_list(match, "from-zone", zone_parts, "match "),
                to_zones=_leaf_list(match, "to-zone", zone_parts, "match "),
                pair_inactive=is_inactive(glob),
                pair_group=group_of(glob),
                ancestor_inactive=ancestor,
                inactive_parts_in=zone_parts,
                comment=global_notes.get(id(node)),
                pair_comment=notes.get(id(glob)) if glob is not None else None,
            )
        )
    default = kid(policies, "default-policy")
    default_child = next((c for c in kids(default) if local(c.tag) in ("permit-all", "deny-all")), None)
    configured = local(default_child.tag) if default_child is not None else None
    # The nearest deactivated statement: the default policy itself (or its action), then its ancestors.
    default_reason: Optional[str] = None
    if configured is not None:
        default_reason = "self" if is_inactive(default) or is_inactive(default_child) else ancestor
    default_off = default_reason is not None
    rematch_node = kid(policies, "policy-rematch")
    rematch, rematch_off = _setting(policies, "policy-rematch", ancestor)
    extensive = kid(rematch_node, "extensive")
    pre_id_node = kid(policies, "pre-id-default-policy")
    pre_id, pre_id_off = _setting(policies, "pre-id-default-policy", ancestor)
    other = _unmodeled(policies, _POLICIES_KNOWN, "") + _unmodeled(rematch_node, ("extensive",), "policy-rematch ")
    return {
        "rows": rows,
        # In effect only. A deactivated default policy leaves the Junos default (deny-all) in force.
        "default_policy": None if default_off else configured,
        "default_policy_inactive": configured if default_off else None,
        "default_policy_inactive_reason": default_reason,
        "default_policy_group": group_of(default),
        "default_policy_comment": notes.get(id(default)) if default is not None else None,
        "pre_id_default_policy": pre_id,
        "pre_id_default_policy_inactive": pre_id_off,
        "pre_id_default_policy_comment": notes.get(id(pre_id_node)) if pre_id_node is not None else None,
        "policy_rematch": rematch,
        "policy_rematch_inactive": rematch_off,
        # "extensive" under an in-effect policy-rematch, itself active.
        "policy_rematch_extensive": rematch and extensive is not None and not is_inactive(extensive),
        "policy_rematch_extensive_inactive": rematch and extensive is not None and is_inactive(extensive),
        "policy_rematch_comment": notes.get(id(rematch_node)) if rematch_node is not None else None,
        "global_trailing_comment": trailing_comment(glob),
        "pair_trailing": pair_trailing,
        "other_settings": other,
        "ancestor_inactive": ancestor,
    }


def _host_inbound(hit: Optional[Element]) -> Json:
    """Host-inbound system services and protocols: allowed, excluded with ``except`` (allowed only
    together with ``all``: "Type of incoming system-service traffic to disallow", 24.4R2 YANG), and
    deactivated (not in effect)."""
    out: Json = {}
    hit_off = is_inactive(hit)
    for key, tag in (("services", "system-services"), ("protocols", "protocols")):
        allowed: List[str] = []
        excluded: List[str] = []
        off: List[str] = []
        for entry in kids(hit, tag):
            name = text(entry, "name")
            if name is None:
                continue
            exclusion = kid(entry, "except")
            if hit_off or is_inactive(entry):
                off.append(f"{name} except" if exclusion is not None else name)
            elif exclusion is not None and not is_inactive(exclusion):
                excluded.append(name)
            else:
                allowed.append(name)
        out[key] = allowed
        out[f"{key}_except"] = excluded
        out[f"inactive_{key}"] = off
    out["unmodeled"] = _unmodeled(hit, _HOST_INBOUND_KNOWN, "host-inbound-traffic ")
    return out


def _host_inbound_facts(node: Element) -> Json:
    """Whether ``node`` (a zone or an interface) has its own host-inbound-traffic, and how it stands."""
    hit = kid(node, "host-inbound-traffic")
    state = "absent" if hit is None else "inactive" if is_inactive(hit) else "active"
    first = next(iter(_statement_nodes(hit)), None)
    return {
        "host_inbound": state,
        # Entries written, active or not (a block can hold only deactivated entries).
        "services_present": kid(hit, "system-services") is not None,
        "protocols_present": kid(hit, "protocols") is not None,
        "host_inbound_group": group_of(hit) or group_of(first),
    }


def _statement_nodes(node: Optional[Element]) -> List[Element]:
    """Child elements that are configuration statements (comments left out)."""
    return [child for child in kids(node) if local(child.tag) != "comment"]


def parse_zones(security: Optional[Element]) -> List[Json]:
    rows = []
    zones = kid(security, "zones")
    notes = comments_before(zones)
    for zone in kids(zones, "security-zone"):
        hit = _host_inbound(kid(zone, "host-inbound-traffic"))
        interfaces = []
        if_notes = comments_before(zone)
        for ifc in kids(zone, "interfaces"):
            ihit = _host_inbound(kid(ifc, "host-inbound-traffic"))
            interfaces.append(
                {
                    "name": text(ifc, "name") or "?",
                    "services": ihit["services"],
                    "protocols": ihit["protocols"],
                    "services_except": ihit["services_except"],
                    "protocols_except": ihit["protocols_except"],
                    "inactive_services": ihit["inactive_services"],
                    "inactive_protocols": ihit["inactive_protocols"],
                    **_host_inbound_facts(ifc),
                    "group": group_of(ifc),
                    "inherited": inherited_parts(ifc),
                    "groups": groups_in(ifc),
                    "inactive": is_inactive(ifc),
                    "inactive_parts": deactivated_parts(ifc),
                    "comment": if_notes.get(id(ifc)),
                    "unmodeled": _unmodeled(ifc, _INTERFACE_KNOWN, "") + ihit["unmodeled"],
                }
            )
        screen = kid(zone, "screen")
        rows.append(
            {
                "name": text(zone, "name") or "?",
                "interfaces": interfaces,
                "services": hit["services"],
                "protocols": hit["protocols"],
                "services_except": hit["services_except"],
                "protocols_except": hit["protocols_except"],
                "inactive_services": hit["inactive_services"],
                "inactive_protocols": hit["inactive_protocols"],
                **_host_inbound_facts(zone),
                # Null when the screen statement is deactivated (then in inactive_parts): not in effect.
                "screen": None if screen is None or is_inactive(screen) else text_of(screen),
                "description": text(zone, "description"),
                "group": group_of(zone),
                "inherited": inherited_parts(zone),
                "groups": groups_in(zone),
                "inactive": is_inactive(zone),
                # Interfaces and the zone's own address book carry their own inactive flag.
                "inactive_parts": deactivated_parts(zone, ("name", "interfaces", "address-book")),
                "comment": notes.get(id(zone)),
                "part_comments": inner_comments(zone),
                # For example tcp-rst, application-tracking, source-identity-log.
                "unmodeled": _unmodeled(zone, _ZONE_KNOWN, "") + hit["unmodeled"],
            }
        )
    return rows


def zones_unmodeled(security: Optional[Element]) -> List[str]:
    """Zone-level configuration not modelled as rows. ``functional-zone management`` exists as a
    hierarchy level (verified on the Junos ES 9.3 page; its presence in 24.4 is inferred)."""
    return ["functional-zone management"] if kid(kid(security, "zones"), "functional-zone") is not None else []


def _zone_pairs(rows: List[Json], trailing: Optional[Dict[Tuple[str, str], Optional[str]]] = None) -> List[Json]:
    pairs: Dict[Tuple[str, str], Json] = {}
    for row in rows:
        if row["kind"] != "zone" or not row["from"] or not row["to"]:
            continue
        key = (row["from"][0], row["to"][0])
        entry = pairs.setdefault(
            key,
            {
                "from": key[0], "to": key[1], "count": 0, "inactive": 0, "permit": 0, "deny": 0, "reject": 0,
                "comment": row.get("pair_comment"),
                # A comment after the pair's last rule.
                "trailing_comment": (trailing or {}).get(key),
            },
        )
        entry["count"] += 1
        if row["inactive"]:
            entry["inactive"] += 1
        elif row["action"] in ("permit", "deny", "reject"):
            entry[row["action"]] += 1
    return list(pairs.values())


def _list(names_: List[str]) -> str:
    return ", ".join(names_)


def _object_warnings(books: List[Json], apps: List[Json], zones: List[Json]) -> List[str]:
    """Settings not shown, deactivated members and host-inbound exceptions, per object."""
    out: List[str] = []
    not_shown = "has settings J-Wicket does not display yet"
    for book in books:
        if book["unmodeled"]:
            out.append(f"Address book {book['name']} {not_shown}: {_list(book['unmodeled'])}.")
        if book["inactive_attach"]:
            out.append(f"Address book {book['name']} has deactivated attach zones (not in effect): "
                       f"{_list(book['inactive_attach'])}.")
        for entry in book["addresses"]:
            if entry["unmodeled"]:
                out.append(f"Address {entry['name']} in book {book['name']} {not_shown}: {_list(entry['unmodeled'])}.")
        for entry in book["sets"]:
            if entry["unmodeled"]:
                out.append(
                    f"Address set {entry['name']} in book {book['name']} {not_shown}: {_list(entry['unmodeled'])}."
                )
            if entry["inactive_members"]:
                out.append(f"Address set {entry['name']} in book {book['name']} has deactivated members (not in "
                           f"effect): {_list(entry['inactive_members'])}.")
    for app in apps:
        label = "Application" if app["kind"] == "application" else "Application set"
        if app["unmodeled"]:
            out.append(f"{label} {app['name']} {not_shown}: {_list(app['unmodeled'])}.")
        if app["inactive_members"]:
            out.append(f"{label} {app['name']} has deactivated members (not in effect): "
                       f"{_list(app['inactive_members'])}.")
        if app["kind"] == "application" and app["inactive_parts"] and not app["inactive"]:
            out.append(f"{_parts_off('Application', app['name'], app['inactive_parts'])}")
    for book in books:
        if book["inactive"]:
            continue
        for entry in book["addresses"]:
            if entry["inactive_parts"] and not entry["inactive"]:
                out.append(_parts_off("Address", entry["name"], entry["inactive_parts"]))
    for zone in zones:
        if not zone["inactive"]:
            if zone["inactive_parts"]:
                out.append(_parts_off("Zone", zone["name"], zone["inactive_parts"]))
            for ifc in zone["interfaces"]:
                if ifc["inactive_parts"] and not ifc["inactive"]:
                    out.append(_parts_off("Interface", ifc["name"], ifc["inactive_parts"]))
        places = [(f"Zone {zone['name']}", zone)] + [
            (f"Zone {zone['name']} interface {ifc['name']}", ifc) for ifc in zone["interfaces"]
        ]
        for where, item in places:
            if item["unmodeled"]:
                out.append(f"{where} {not_shown}: {_list(item['unmodeled'])}.")
            for key, label in (("services", "system services"), ("protocols", "protocols")):
                if item[f"{key}_except"]:
                    allowed = _list(item[key]) or "none listed"
                    out.append(f"{where}: host-inbound {label} {allowed}, except {_list(item[f'{key}_except'])}.")
                if item[f"inactive_{key}"]:
                    out.append(f"{where} has deactivated host-inbound {label} (not in effect): "
                               f"{_list(item[f'inactive_{key}'])}.")
    return out


def _parts_off(kind: str, name: str, parts: List[str]) -> str:
    return f"{kind} {name} has deactivated parts (not in effect): {', '.join(parts)}."


_ANCESTOR_TEXT = {
    "policies": "[edit security policies] is deactivated",
    "security": "[edit security] is deactivated",
}


def _default_off_text(action: str, reason: Optional[str], label: str) -> str:
    if reason == "self":
        return f"The default policy {action} is deactivated in the configuration (not in effect)."
    because = _ANCESTOR_TEXT.get(reason or "", f"{label} is deactivated")
    return f"The default policy {action} is not in effect because {because}."


def _scope_inventory(scope_id: str, label: str, node: Element, scope_inactive: bool) -> Json:
    security = kid(node, "security")
    apps = parse_applications(kid(node, "applications"))
    books = parse_address_books(security)
    policies = parse_policies(scope_id, security, scope_inactive)
    zones = parse_zones(security)
    zones_extra = zones_unmodeled(security)
    addresses = AddressResolver(books)
    app_resolver = ApplicationResolver(apps)
    for row in policies["rows"]:
        _resolve_policy(row, addresses, app_resolver)

    warnings: List[str] = []
    if scope_inactive:
        warnings.append(f"{label} is deactivated in the configuration; nothing in it is in effect.")
    ancestor = policies["ancestor_inactive"]
    if ancestor in _ANCESTOR_TEXT:
        warnings.append(f"In {label}, {_ANCESTOR_TEXT[ancestor]}: none of its security policies is in effect.")
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
    if policies["default_policy_inactive"]:
        warnings.append(_default_off_text(policies["default_policy_inactive"],
                                          policies["default_policy_inactive_reason"], label))
    if policies["policy_rematch_inactive"]:
        warnings.append("policy-rematch is configured but deactivated (not in effect).")
    elif policies["policy_rematch_extensive_inactive"]:
        warnings.append("policy-rematch extensive is configured but deactivated (not in effect).")
    if policies["pre_id_default_policy"]:
        warnings.append("A pre-ID default policy is configured; J-Wicket shows its presence but not its contents.")
    elif policies["pre_id_default_policy_inactive"]:
        warnings.append("A pre-ID default policy is configured but deactivated (not in effect).")
    if zones_extra:
        warnings.append("Functional zone management is configured; J-Wicket does not display it yet.")
    warnings.extend(_object_warnings(books, apps, zones))

    group_counts: Dict[str, int] = {}
    for row in policies["rows"]:
        for grp in row["groups"]:
            group_counts[grp] = group_counts.get(grp, 0) + 1

    return {
        "id": scope_id,
        "label": label,
        "inactive": scope_inactive,
        # Whether this scope's configuration node has these children at all (an empty inventory is
        # not evidence that nothing is configured: Junos may leave out what a login class cannot view).
        "security_present": security is not None,
        "applications_present": kid(node, "applications") is not None,
        "policies": {
            "status": "ok",
            "rows": policies["rows"],
            "default_policy": policies["default_policy"],
            "default_policy_inactive": policies["default_policy_inactive"],
            "default_policy_inactive_reason": policies["default_policy_inactive_reason"],
            "default_policy_group": policies["default_policy_group"],
            "default_policy_comment": policies["default_policy_comment"],
            "policy_rematch": policies["policy_rematch"],
            "policy_rematch_inactive": policies["policy_rematch_inactive"],
            "policy_rematch_extensive": policies["policy_rematch_extensive"],
            "policy_rematch_comment": policies["policy_rematch_comment"],
            "pre_id_default_policy": policies["pre_id_default_policy"],
            "pre_id_default_policy_inactive": policies["pre_id_default_policy_inactive"],
            "pre_id_default_policy_comment": policies["pre_id_default_policy_comment"],
            "ancestor_inactive": policies["ancestor_inactive"],
            "global_trailing_comment": policies["global_trailing_comment"],
            "zone_pairs": _zone_pairs(policies["rows"], policies["pair_trailing"]),
            "global_count": sum(1 for r in policies["rows"] if r["kind"] == "global"),
        },
        "zones": {"status": "ok", "rows": zones, "unmodeled": zones_extra},
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


def _scope_name(scope_id: str) -> Optional[str]:
    """The logical-system or tenant name of a scope id, None for root."""
    kind, sep, name = scope_id.partition(":")
    return name if sep and kind in ("lsys", "tenant") else None


def selectable(scope_id: str) -> bool:
    """Whether J-Wicket can address this scope in a request (``api._SCOPE``; owner decision OD-12)."""
    name = _scope_name(scope_id)
    return name is None or bool(SELECTABLE_NAME.match(name))


def scope_summaries(inventories: Dict[str, Json]) -> List[Json]:
    out: List[Json] = []
    for inv in inventories.values():
        entry: Json = {
            "id": inv["id"],
            "label": inv["label"],
            "policies": len(inv["policies"]["rows"]),
            "inactive": inv["inactive"],
            "selectable": selectable(inv["id"]),
        }
        if not entry["selectable"]:
            entry["reason"] = NOT_SELECTABLE
        out.append(entry)
    return out


def unselectable_warnings(inventories: Dict[str, Json]) -> List[str]:
    """A snapshot warning per logical or tenant system whose name J-Wicket cannot address yet."""
    return [
        f"{inv['label']} cannot be opened in J-Wicket: its name has characters J-Wicket does not accept in a "
        "scope yet."
        for inv in inventories.values()
        if not selectable(inv["id"])
    ]
