"""junos/inventory.py (Spec 001): evaluation order, provenance, inactive state, resolution, scopes."""

from __future__ import annotations

import json
import time
import unittest
from typing import Any, Dict, List
from xml.etree import ElementTree

from helpers import BRANCH, BRANCH_SECRETS, CLUSTER, config, xml

from jwicket.junos import inventory as I


def load(path: Any) -> Any:
    return ElementTree.parse(path).getroot()


def rows(inv: Dict[str, Any], scope: str = "root") -> List[Dict[str, Any]]:
    return list(inv[scope]["policies"]["rows"])


def by_name(inv: Dict[str, Any], name: str, scope: str = "root") -> Dict[str, Any]:
    found = [r for r in rows(inv, scope) if r["name"] == name]
    if len(found) != 1:
        raise AssertionError(f"expected one policy {name!r} in {scope}, found {len(found)}")
    return found[0]


def pair(frm: str, to: str, body: str, attrs: str = "") -> str:
    return f"<policy{attrs}><from-zone-name>{frm}</from-zone-name><to-zone-name>{to}</to-zone-name>{body}</policy>"


def pol(name: str, src: str = "any", dst: str = "any", app: str = "any", then: str = "<permit/>", attrs: str = "",
        extra: str = "", match_extra: str = "") -> str:
    return (
        f"<policy{attrs}><name>{name}</name><match><source-address>{src}</source-address>"
        f"<destination-address>{dst}</destination-address><application>{app}</application>{match_extra}</match>"
        f"<then>{then}</then>{extra}</policy>"
    )


class BranchFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.inv = I.build_inventory(load(BRANCH / "config.xml"))

    def test_only_root_scope(self) -> None:
        self.assertEqual(list(self.inv), ["root"])
        self.assertEqual(self.inv["root"]["label"], "Root system")
        self.assertFalse(self.inv["root"]["inactive"])

    def test_evaluation_order_zone_pairs_then_global(self) -> None:
        got = [(r["kind"], r["seq"], r["name"]) for r in rows(self.inv)]
        self.assertEqual(
            got,
            [
                ("zone", 1, "baseline-dns"),
                ("zone", 2, "allow-web"),
                ("zone", 3, "block-telnet"),
                ("zone", 1, "admin-to-dmz"),
                ("zone", 1, "publish-web"),
                ("zone", 2, "publish-mail"),
                ("zone", 1, "deny-inbound"),
                ("zone", 1, "dmz-updates"),
                ("global", 1, "global-blocklist"),
                ("global", 2, "global-printers"),
            ],
        )
        self.assertEqual(self.inv["root"]["policies"]["default_policy"], "deny-all")
        self.assertEqual(self.inv["root"]["policies"]["global_count"], 2)

    def test_row_identity_and_zones(self) -> None:
        row = by_name(self.inv, "allow-web")
        self.assertEqual(row["id"], "root|zone|trust>untrust|allow-web")
        self.assertEqual(row["scope"], "root")
        self.assertEqual((row["from"], row["to"]), (["trust"], ["untrust"]))
        glob = by_name(self.inv, "global-blocklist")
        self.assertEqual(glob["id"], "root|global|global|global-blocklist")
        self.assertEqual((glob["from"], glob["to"]), ([], []))  # empty means any zone
        printers = by_name(self.inv, "global-printers")
        self.assertEqual((printers["from"], printers["to"]), (["trust"], ["dmz"]))
        ids = [r["id"] for r in rows(self.inv)]
        self.assertEqual(len(ids), len(set(ids)))

    def test_actions_log_count_scheduler(self) -> None:
        web = by_name(self.inv, "allow-web")
        self.assertEqual(web["action"], "permit")
        self.assertEqual(web["log"], {"init": False, "close": True})
        self.assertTrue(web["count"])
        self.assertEqual(by_name(self.inv, "deny-inbound")["action"], "deny")
        self.assertEqual(by_name(self.inv, "deny-inbound")["log"], {"init": True, "close": False})
        self.assertEqual(by_name(self.inv, "publish-mail")["scheduler"], "business-hours")
        self.assertEqual(by_name(self.inv, "publish-web")["application_services"], ["idp-policy"])

    def test_inactive_policy(self) -> None:
        row = by_name(self.inv, "block-telnet")
        self.assertTrue(row["inactive"])
        self.assertEqual(row["inactive_reason"], "policy")
        self.assertIsNone(by_name(self.inv, "allow-web")["inactive_reason"])

    def test_group_provenance(self) -> None:
        dns = by_name(self.inv, "baseline-dns")
        self.assertEqual(dns["group"], "corp-baseline")
        self.assertEqual(dns["groups"], ["corp-baseline"])
        self.assertIsNone(by_name(self.inv, "allow-web")["group"])
        self.assertEqual(by_name(self.inv, "allow-web")["groups"], [])
        self.assertEqual(self.inv["root"]["groups"], [{"name": "corp-baseline", "policies": 2}])
        corp = next(a for a in self.inv["root"]["address_books"]["rows"][0]["addresses"] if a["name"] == "corp-lan")
        self.assertEqual(corp["group"], "corp-baseline")

    def test_unmodeled_permit_option_reported(self) -> None:
        row = by_name(self.inv, "dmz-updates")
        self.assertEqual(row["unmodeled"], ["then permit firewall-authentication"])
        warnings = self.inv["root"]["warnings"]
        self.assertTrue(any("dmz-updates" in w and "firewall-authentication" in w for w in warnings))

    def test_zone_pairs_summary(self) -> None:
        pairs = {(p["from"], p["to"]): p for p in self.inv["root"]["policies"]["zone_pairs"]}
        self.assertEqual(
            pairs[("trust", "untrust")],
            {"from": "trust", "to": "untrust", "count": 3, "inactive": 1, "permit": 2, "deny": 0, "reject": 0,
             "comment": None},
        )
        self.assertEqual(next(iter(pairs)), ("trust", "untrust"))  # config order
        self.assertEqual(len(pairs), 5)

    def test_address_resolution_nested_sets_and_attached_book(self) -> None:
        row = by_name(self.inv, "admin-to-dmz")
        dmz_all, dmz_jump = row["resolved"]["destination"]
        self.assertEqual(dmz_all["kind"], "set")
        self.assertEqual(dmz_all["book"], "global")
        self.assertEqual([leaf["name"] for leaf in dmz_all["leaves"]], ["mail", "web1", "web2"])
        self.assertFalse(dmz_all["truncated"])
        self.assertEqual(dmz_jump["kind"], "address")
        self.assertEqual(dmz_jump["book"], "dmz-book")
        self.assertEqual(dmz_jump["leaves"], [{"name": "dmz-jump", "kind": "prefix", "value": "10.20.0.50/32"}])
        any_dst = by_name(self.inv, "allow-web")["resolved"]["destination"][0]
        self.assertEqual(any_dst["kind"], "any")

    def test_address_kinds(self) -> None:
        book = self.inv["root"]["address_books"]["rows"][0]
        entries = {a["name"]: a for a in book["addresses"]}
        self.assertEqual((entries["web1"]["kind"], entries["web1"]["value"]), ("prefix", "10.20.0.10/32"))
        self.assertEqual((entries["partner-portal"]["kind"], entries["partner-portal"]["value"]),
                         ("dns", "portal.partner.example"))
        self.assertEqual((entries["branch-printers"]["kind"], entries["branch-printers"]["value"]),
                         ("range", "10.10.40.10-10.10.40.19"))
        self.assertEqual(entries["mail"]["description"], "Inbound mail relay")
        sets = {s["name"]: s for s in book["sets"]}
        self.assertEqual(sets["dmz-all"]["addresses"], ["mail"])
        self.assertEqual(sets["dmz-all"]["sets"], ["web-servers"])
        dmz_book = self.inv["root"]["address_books"]["rows"][1]
        self.assertEqual((dmz_book["name"], dmz_book["attach"], dmz_book["legacy_zone"]), ("dmz-book", ["dmz"], None))

    def test_application_resolution(self) -> None:
        web = by_name(self.inv, "allow-web")["resolved"]["application"][0]
        self.assertEqual(web["kind"], "set")
        self.assertEqual(
            web["leaves"],
            [
                {"name": "junos-http", "predefined": True},
                {"name": "junos-https", "predefined": True},
                {"name": "tcp-8443", "protocol": "tcp", "destination_port": "8443", "source_port": None, "terms": 0,
                 "unmodeled": []},
            ],
        )
        self.assertEqual(web["unresolved"], [])
        dns = by_name(self.inv, "baseline-dns")["resolved"]["application"][0]
        self.assertEqual((dns["kind"], dns["unresolved"]), ("predefined", []))
        self.assertEqual(by_name(self.inv, "deny-inbound")["resolved"]["application"][0]["kind"], "any")

    def test_zones(self) -> None:
        zones = {z["name"]: z for z in self.inv["root"]["zones"]["rows"]}
        self.assertEqual(zones["trust"]["services"], ["ssh", "ping", "https"])
        self.assertEqual(zones["untrust"]["screen"], "untrust-screen")
        self.assertEqual(zones["untrust"]["interfaces"][0]["services"], ["ike", "dhcp"])
        self.assertEqual(zones["dmz"]["interfaces"][0]["name"], "ge-0/0/2.0")

    def test_applications_panel(self) -> None:
        apps = {a["name"]: a for a in self.inv["root"]["applications"]["rows"]}
        self.assertEqual(apps["tcp-8443"]["kind"], "application")
        self.assertEqual(apps["web-apps"]["kind"], "set")
        self.assertEqual(apps["web-apps"]["members"], ["junos-http", "junos-https", "tcp-8443"])

    def test_no_secret_or_device_id_in_serialised_inventory(self) -> None:
        dumped = json.dumps(self.inv)
        for value in BRANCH_SECRETS:
            with self.subTest(value=value):
                self.assertNotIn(value, dumped)
        self.assertNotIn("outbound-ssh", dumped)

    def test_scope_summaries(self) -> None:
        self.assertEqual(I.scope_summaries(self.inv),
                         [{"id": "root", "label": "Root system", "policies": 10, "inactive": False}])

    def test_snapshot_shape_keys(self) -> None:
        scope = self.inv["root"]
        for key in ("id", "label", "inactive", "policies", "zones", "address_books", "applications", "groups",
                    "warnings"):
            self.assertIn(key, scope)
        for key in ("status", "rows", "default_policy", "default_policy_group", "policy_rematch",
                    "pre_id_default_policy", "zone_pairs", "global_count", "default_policy_inactive",
                    "policy_rematch_inactive", "pre_id_default_policy_inactive"):
            self.assertIn(key, scope["policies"])
        row_keys = {"id", "scope", "kind", "seq", "from", "to", "name", "description", "match", "action",
                    "application_services", "tunnel", "log", "count", "scheduler", "inactive", "inactive_reason",
                    "group", "inherited", "groups", "unmodeled", "inactive_parts", "resolved", "comment",
                    "part_comments", "pair_comment"}
        for row in rows(self.inv):
            self.assertEqual(set(row), row_keys)

    def test_every_resolved_address_has_the_documented_keys(self) -> None:
        """Spec shape: {name, kind, book, leaves, truncated, unresolved} for every entry, any/unresolved too."""
        doc = config(
            "<address-book><name>global</name><address><name>h</name><ip-prefix>192.0.2.1/32</ip-prefix></address>"
            "</address-book><policies>"
            + pair("a", "b", pol("p", src="h", dst="any"))
            + pair("a", "b", pol("q", src="nope"))
            + "</policies>"
        )
        inv = I.build_inventory(doc)
        for row in rows(inv):
            for entry in row["resolved"]["source"] + row["resolved"]["destination"]:
                with self.subTest(policy=row["name"], name=entry["name"], kind=entry["kind"]):
                    self.assertEqual(set(entry), {"name", "kind", "book", "leaves", "truncated", "unresolved",
                                                  "inactive_skipped"})


class ClusterLsysFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.inv = I.build_inventory(load(CLUSTER / "config.xml"))

    def test_scopes_are_separate(self) -> None:
        self.assertEqual(list(self.inv), ["root", "lsys:LS-A", "tenant:T-1"])
        self.assertEqual([r["name"] for r in rows(self.inv, "root")], ["node0-mgmt-out", "inside-out"])
        self.assertEqual([r["name"] for r in rows(self.inv, "lsys:LS-A")], ["a-out"])
        self.assertEqual([r["name"] for r in rows(self.inv, "tenant:T-1")], ["t-out-web"])
        self.assertEqual(self.inv["lsys:LS-A"]["label"], "Logical system LS-A")
        self.assertEqual(self.inv["tenant:T-1"]["label"], "Tenant system T-1")
        for scope_id, inv in self.inv.items():
            for row in inv["policies"]["rows"]:
                self.assertEqual(row["scope"], scope_id)
                self.assertTrue(row["id"].startswith(scope_id + "|"))

    def test_lsys_resolves_in_its_own_books(self) -> None:
        a_out = by_name(self.inv, "a-out", "lsys:LS-A")
        src = a_out["resolved"]["source"][0]
        self.assertEqual((src["kind"], src["book"]), ("address", "global"))
        self.assertEqual(src["leaves"][0]["value"], "172.16.10.0/24")
        root_zones = {z["name"] for z in self.inv["root"]["zones"]["rows"]}
        self.assertEqual(root_zones, {"inside", "outside"})
        self.assertEqual(self.inv["root"]["address_books"]["rows"], [])

    def test_inactive_tenant_is_marked_and_warned(self) -> None:
        tenant = self.inv["tenant:T-1"]
        self.assertTrue(tenant["inactive"])
        self.assertTrue(any("deactivated" in w for w in tenant["warnings"]))
        self.assertFalse(self.inv["lsys:LS-A"]["inactive"])
        self.assertEqual(by_name(self.inv, "t-out-web", "tenant:T-1")["action"], "reject")
        summaries = {s["id"]: s for s in I.scope_summaries(self.inv)}
        self.assertTrue(summaries["tenant:T-1"]["inactive"])
        self.assertEqual(summaries["lsys:LS-A"]["policies"], 1)

    def test_default_policy_present_and_absent(self) -> None:
        self.assertEqual(self.inv["root"]["policies"]["default_policy"], "deny-all")
        self.assertIsNone(self.inv["lsys:LS-A"]["policies"]["default_policy"])

    def test_group_named_like_a_node(self) -> None:
        row = by_name(self.inv, "node0-mgmt-out")
        self.assertEqual(row["group"], "node0")


class ConfigurationRootTests(unittest.TestCase):
    def test_bare_configuration(self) -> None:
        cfg = xml("<configuration/>")
        self.assertIs(I.configuration_root(cfg), cfg)

    def test_rpc_reply_wrapper_with_namespaces(self) -> None:
        reply = xml(
            '<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><data><configuration>'
            "<security/></configuration></data></rpc-reply>"
        )
        root = I.configuration_root(reply)
        self.assertEqual(root.tag, "{urn:ietf:params:xml:ns:netconf:base:1.0}configuration")
        self.assertEqual(list(I.build_inventory(reply)), ["root"])

    def test_no_configuration_is_a_value_error(self) -> None:
        for text in ("<rpc-reply><ok/></rpc-reply>", "<rpc-error><error-message>x</error-message></rpc-error>"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                I.configuration_root(xml(text))
        with self.assertRaises(ValueError):
            I.build_inventory(xml("<rpc-reply/>"))

    def test_no_configuration_is_a_failed_read(self) -> None:
        """CONS-02: callers that map JunosError to a panel state show "failed", not an HTTP 500."""
        from jwicket.junos.errors import JunosError, MalformedReply

        with self.assertRaises(MalformedReply) as ctx:
            I.configuration_root(xml("<rpc-reply><ok/></rpc-reply>"))
        self.assertIsInstance(ctx.exception, JunosError)
        self.assertEqual(ctx.exception.kind, "failed")
        self.assertTrue(ctx.exception.public)

    def test_empty_configuration(self) -> None:
        inv = I.build_inventory(xml("<configuration/>"))
        self.assertEqual(rows(inv), [])
        self.assertIsNone(inv["root"]["policies"]["default_policy"])
        self.assertEqual(inv["root"]["zones"]["rows"], [])


class EvaluationOrderTests(unittest.TestCase):
    def test_zone_pairs_in_config_order_then_global_regardless_of_xml_position(self) -> None:
        # <global> first in the XML: Junos still evaluates zone-pair policies before global ones.
        doc = config(
            "<policies><global>" + pol("g1") + pol("g2") + "</global>"
            + pair("b", "a", pol("ba1") + pol("ba2"))
            + pair("a", "b", pol("ab1"))
            + "<default-policy><permit-all/></default-policy></policies>"
        )
        inv = I.build_inventory(doc)
        self.assertEqual(
            [(r["kind"], r["seq"], r["name"]) for r in rows(inv)],
            [("zone", 1, "ba1"), ("zone", 2, "ba2"), ("zone", 1, "ab1"), ("global", 1, "g1"), ("global", 2, "g2")],
        )
        self.assertEqual(inv["root"]["policies"]["default_policy"], "permit-all")

    def test_default_policy_absent_and_group(self) -> None:
        inv = I.build_inventory(config("<policies>" + pair("a", "b", pol("p")) + "</policies>"))
        self.assertIsNone(inv["root"]["policies"]["default_policy"])
        self.assertIsNone(inv["root"]["policies"]["default_policy_group"])
        inv = I.build_inventory(config('<policies><default-policy junos:group="base"><deny-all junos:group="base"/>'
                                       "</default-policy></policies>"))
        self.assertEqual(inv["root"]["policies"]["default_policy"], "deny-all")
        self.assertEqual(inv["root"]["policies"]["default_policy_group"], "base")

    def test_reject_and_unknown_actions(self) -> None:
        body = pol("r", then="<reject/>") + pol("u", then="<log><session-init/></log>")
        inv = I.build_inventory(config("<policies>" + pair("a", "b", body) + "</policies>"))
        self.assertEqual(by_name(inv, "r")["action"], "reject")
        self.assertEqual(by_name(inv, "u")["action"], "unknown")
        self.assertTrue(any("Policy u" in w and "no permit, deny or reject" in w for w in inv["root"]["warnings"]))

    def test_policy_rematch_and_pre_id(self) -> None:
        inv = I.build_inventory(config("<policies><policy-rematch/><pre-id-default-policy><then><log><session-close/>"
                                       "</log></then></pre-id-default-policy></policies>"))
        pols = inv["root"]["policies"]
        self.assertTrue(pols["policy_rematch"])
        self.assertTrue(pols["pre_id_default_policy"])
        self.assertTrue(any("pre-ID default policy" in w for w in inv["root"]["warnings"]))


class InactiveReasonTests(unittest.TestCase):
    def test_policy_vs_zone_pair(self) -> None:
        doc = config(
            "<policies>"
            + pair("a", "b", pol("off-pair-1") + pol("off-pair-2"), attrs=' inactive="inactive"')
            + pair("b", "a", pol("off-self", attrs=' inactive="inactive"') + pol("on"))
            + "</policies>"
        )
        inv = I.build_inventory(doc)
        self.assertEqual(by_name(inv, "off-pair-1")["inactive_reason"], "zone-pair")
        self.assertEqual(by_name(inv, "off-pair-2")["inactive_reason"], "zone-pair")
        self.assertTrue(by_name(inv, "off-pair-1")["inactive"])
        self.assertEqual(by_name(inv, "off-self")["inactive_reason"], "policy")
        self.assertFalse(by_name(inv, "on")["inactive"])
        self.assertIsNone(by_name(inv, "on")["inactive_reason"])
        pairs = {(p["from"], p["to"]): p for p in inv["root"]["policies"]["zone_pairs"]}
        self.assertEqual((pairs[("a", "b")]["inactive"], pairs[("a", "b")]["permit"]), (2, 0))
        self.assertEqual((pairs[("b", "a")]["inactive"], pairs[("b", "a")]["permit"]), (1, 1))

    def test_inactive_match_entry_is_not_shown_as_active(self) -> None:
        """'Inactive configuration is shown and marked': a deactivated source-address must not be
        presented as an active match condition without any marker."""
        doc = config(
            "<policies>" + pair("a", "b", '<policy><name>p</name><match><source-address>keep</source-address>'
                                '<source-address inactive="inactive">dropped</source-address>'
                                "<destination-address>any</destination-address><application>any</application>"
                                "</match><then><permit/></then></policy>") + "</policies>"
        )
        row = by_name(I.build_inventory(doc), "p")
        shown_as_active = "dropped" in row["match"]["source"]
        marked = any("dropped" in u or "inactive" in u for u in row["unmodeled"])
        self.assertFalse(shown_as_active and not marked, row["match"]["source"])


class ProvenanceTests(unittest.TestCase):
    def test_policy_inherits_group_from_zone_pair(self) -> None:
        doc = config("<policies>" + pair("a", "b", pol("p"), attrs=' junos:group="pairs"') + "</policies>")
        row = by_name(I.build_inventory(doc), "p")
        self.assertEqual(row["group"], "pairs")

    def test_partial_inheritance(self) -> None:
        doc = config(
            "<policies>" + pair("a", "b", "<policy><name>p</name><match><source-address>any</source-address>"
                                "<destination-address>any</destination-address><application>any</application></match>"
                                '<then><permit/><log junos:group="logging"><session-close junos:group="logging"/></log>'
                                "</then></policy>") + "</policies>"
        )
        inv = I.build_inventory(doc)
        row = by_name(inv, "p")
        self.assertIsNone(row["group"])
        self.assertEqual(row["inherited"], ["then"])
        self.assertEqual(row["groups"], ["logging"])
        self.assertEqual(row["log"], {"init": False, "close": True})
        self.assertEqual(inv["root"]["groups"], [{"name": "logging", "policies": 1}])

    def test_fully_inherited_policy(self) -> None:
        g = ' junos:group="g"'
        doc = config(
            "<policies>"
            + pair("a", "b", f"<policy{g}><name{g}>p</name><match{g}><source-address{g}>any</source-address>"
                   f"<destination-address{g}>any</destination-address><application{g}>any</application>"
                   f"</match><then{g}><deny{g}/></then></policy>")
            + "</policies>"
        )
        row = by_name(I.build_inventory(doc), "p")
        self.assertEqual((row["group"], row["inherited"], row["groups"]), ("g", [], ["g"]))

    def test_plain_group_attribute_after_pyez_strips_namespaces(self) -> None:
        doc = xml(
            "<configuration><security><policies><policy><from-zone-name>a</from-zone-name><to-zone-name>b</to-zone-name>"
            '<policy group="base"><name>p</name><match><source-address>any</source-address>'
            "<destination-address>any</destination-address><application>any</application></match>"
            '<then><permit/></then></policy></policy></policies></security></configuration>'
        )
        self.assertEqual(by_name(I.build_inventory(doc), "p")["group"], "base")


class UnmodeledTests(unittest.TestCase):
    def build(self, policy: str, policies_extra: str = "") -> Dict[str, Any]:
        return I.build_inventory(config("<policies>" + pair("a", "b", policy) + policies_extra + "</policies>"))

    def test_each_level_is_reported(self) -> None:
        cases = (
            ("policy", pol("p", extra="<future-knob/>"), "future-knob"),
            ("match", pol("p", match_extra="<source-l3vpn-vrf-group>v</source-l3vpn-vrf-group>"),
             "match source-l3vpn-vrf-group"),
            ("then", pol("p", then="<permit/><future-action/>"), "then future-action"),
            ("permit", pol("p", then="<permit><tcp-options><syn-check-required/></tcp-options></permit>"),
             "then permit tcp-options"),
            ("log", pol("p", then="<permit/><log><session-update/></log>"), "then log session-update"),
        )
        for level, policy, expected in cases:
            with self.subTest(level=level):
                inv = self.build(policy)
                row = by_name(inv, "p")
                self.assertIn(expected, row["unmodeled"])
                self.assertTrue(any(expected in w for w in inv["root"]["warnings"]), inv["root"]["warnings"])

    def test_policies_level_settings_are_warned(self) -> None:
        inv = self.build(pol("p"), "<traceoptions><file><name>x</name></file></traceoptions>")
        self.assertEqual(by_name(inv, "p")["unmodeled"], [])
        self.assertTrue(any("traceoptions" in w for w in inv["root"]["warnings"]))

    def test_modeled_policy_has_no_unmodeled(self) -> None:
        inv = self.build(pol("p", then="<permit><application-services><utm-policy>u</utm-policy></application-services>"
                                       "<tunnel><ipsec-vpn>vpn1</ipsec-vpn></tunnel></permit>"
                                       "<log><session-init/><session-close/></log><count/>",
                             extra="<scheduler-name>s</scheduler-name>"))
        row = by_name(inv, "p")
        self.assertEqual(row["unmodeled"], [])
        self.assertEqual(row["tunnel"], "vpn1")
        self.assertEqual(row["application_services"], ["utm-policy"])
        self.assertEqual(inv["root"]["warnings"], [])

    def test_children_of_modeled_containers_are_not_dropped_silently(self) -> None:
        """'Nothing is dropped silently': options inside containers the row only partly reads (the
        tunnel's pair-policy, a reject profile) change behaviour and must be reported."""
        cases = (
            ("tunnel pair-policy",
             "<permit><tunnel><ipsec-vpn>vpn1</ipsec-vpn><pair-policy>back</pair-policy></tunnel></permit>",
             "pair-policy"),
            ("reject profile", "<reject><profile>block-page</profile></reject>", "profile"),
        )
        for label, then, needle in cases:
            with self.subTest(label):
                row = by_name(self.build(pol("p", then=then)), "p")
                self.assertTrue(any(needle in u for u in row["unmodeled"]), row["unmodeled"])

    def test_match_fields_are_copied(self) -> None:
        inv = self.build(pol("p", match_extra="<source-identity>role-a</source-identity>"
                                              "<dynamic-application>junos:HTTP</dynamic-application>"
                                              "<url-category>cat1</url-category>"
                                              "<source-end-user-profile>prof</source-end-user-profile>"
                                              "<source-address-excluded/><destination-address-excluded/>"))
        match = by_name(inv, "p")["match"]
        self.assertEqual(match["source_identity"], ["role-a"])
        self.assertEqual(match["dynamic_application"], ["junos:HTTP"])
        self.assertEqual(match["url_category"], ["cat1"])
        self.assertEqual(match["source_end_user_profile"], ["prof"])
        self.assertTrue(match["source_excluded"])
        self.assertTrue(match["destination_excluded"])
        self.assertEqual(by_name(inv, "p")["unmodeled"], [])


class DeactivatedStatementTests(unittest.TestCase):
    """Deactivated statements are written down but not in effect (JUNO-2, -3, -4, -8, -10)."""

    def test_deactivated_default_policy_rematch_and_pre_id(self) -> None:
        for default in ('<default-policy inactive="inactive"><permit-all/></default-policy>',
                        '<default-policy><permit-all inactive="inactive"/></default-policy>'):
            with self.subTest(default=default):
                inv = I.build_inventory(config(
                    "<policies>" + pair("a", "b", pol("p")) + default + '<policy-rematch inactive="inactive"/>'
                    '<pre-id-default-policy inactive="inactive"><then><log><session-close/></log></then>'
                    "</pre-id-default-policy></policies>"
                ))
                policies = inv["root"]["policies"]
                self.assertIsNone(policies["default_policy"])
                self.assertEqual(policies["default_policy_inactive"], "permit-all")
                self.assertEqual((policies["policy_rematch"], policies["policy_rematch_inactive"]), (False, True))
                self.assertEqual((policies["pre_id_default_policy"], policies["pre_id_default_policy_inactive"]),
                                 (False, True))
                warnings = inv["root"]["warnings"]
                self.assertTrue(any("deny-all" in w and "deactivated" in w for w in warnings), warnings)
                self.assertFalse(any("shows its presence" in w for w in warnings))

    def test_active_settings_are_unchanged(self) -> None:
        inv = I.build_inventory(config("<policies>" + pair("a", "b", pol("p"))
                                       + "<default-policy><permit-all/></default-policy><policy-rematch/>"
                                       "</policies>"))
        policies = inv["root"]["policies"]
        self.assertEqual((policies["default_policy"], policies["default_policy_inactive"]), ("permit-all", None))
        self.assertEqual((policies["policy_rematch"], policies["policy_rematch_inactive"]), (True, False))

    def test_deactivated_policies_or_security_makes_every_rule_inactive(self) -> None:
        body = pair("trust", "untrust", pol("allow-all")) + "<default-policy><permit-all/></default-policy>"
        cases = (
            ("policies", xml(f'<configuration><security><policies inactive="inactive">{body}</policies>'
                             "</security></configuration>")),
            ("security", xml(f'<configuration><security inactive="inactive"><policies>{body}</policies>'
                             "</security></configuration>")),
        )
        for reason, doc in cases:
            with self.subTest(reason=reason):
                inv = I.build_inventory(doc)
                row = by_name(inv, "allow-all")
                self.assertEqual((row["inactive"], row["inactive_reason"]), (True, reason))
                pairs = inv["root"]["policies"]["zone_pairs"]
                self.assertEqual((pairs[0]["permit"], pairs[0]["inactive"]), (0, 1))
                self.assertIsNone(inv["root"]["policies"]["default_policy"])
                self.assertTrue(any("is deactivated" in w for w in inv["root"]["warnings"]))

    def test_rules_in_a_deactivated_logical_system_are_inactive(self) -> None:
        doc = xml('<configuration><logical-systems inactive="inactive"><name>LS1</name><security><policies>'
                  + pair("a", "b", pol("ls-allow")) + "</policies></security></logical-systems></configuration>")
        inv = I.build_inventory(doc)
        row = by_name(inv, "ls-allow", "lsys:LS1")
        self.assertEqual((row["inactive"], row["inactive_reason"]), (True, "scope"))
        self.assertEqual(inv["lsys:LS1"]["policies"]["zone_pairs"][0]["permit"], 0)

    def test_the_nearest_deactivated_statement_is_the_reason(self) -> None:
        doc = xml('<configuration><security><policies inactive="inactive">'
                  + pair("a", "b", pol("p", attrs=' inactive="inactive"')) + "</policies></security></configuration>")
        self.assertEqual(by_name(I.build_inventory(doc), "p")["inactive_reason"], "policy")

    def test_deactivated_global_zone_values_are_not_in_effect(self) -> None:
        doc = config("<policies><global><policy><name>g1</name><match><source-address>any</source-address>"
                     "<destination-address>any</destination-address><application>any</application>"
                     '<from-zone inactive="inactive">trust</from-zone><from-zone>dmz</from-zone></match>'
                     "<then><permit/></then></policy></global></policies>")
        row = by_name(I.build_inventory(doc), "g1")
        self.assertEqual(row["from"], ["dmz"])
        self.assertIn("match from-zone trust", row["inactive_parts"])

    def test_host_inbound_except_and_deactivated_entries(self) -> None:
        hit = ("<host-inbound-traffic><system-services><name>all</name></system-services>"
               "<system-services><name>telnet</name><except/></system-services>"
               '<system-services inactive="inactive"><name>ssh</name></system-services>'
               "<protocols><name>all</name></protocols><protocols><name>bgp</name><except/></protocols>"
               "</host-inbound-traffic>")
        doc = config(f"<zones><security-zone><name>untrust</name>{hit}<interfaces><name>ge-0/0/0.0</name>{hit}"
                     "</interfaces></security-zone></zones>")
        inv = I.build_inventory(doc)["root"]
        zone = inv["zones"]["rows"][0]
        for item in (zone, zone["interfaces"][0]):
            with self.subTest(item=item["name"]):
                self.assertEqual(item["services"], ["all"])
                self.assertEqual(item["services_except"], ["telnet"])
                self.assertEqual(item["inactive_services"], ["ssh"])
                self.assertEqual((item["protocols"], item["protocols_except"]), (["all"], ["bgp"]))
        self.assertIn("Zone untrust: host-inbound system services all, except telnet.", inv["warnings"])
        self.assertTrue(any("interface ge-0/0/0.0" in w and "except bgp" in w for w in inv["warnings"]))

    def test_resolution_skips_deactivated_members_entries_books_and_attach(self) -> None:
        doc = config(
            "<address-book><name>global</name>"
            "<address><name>web</name><ip-prefix>192.0.2.10/32</ip-prefix></address>"
            "<address><name>web1</name><ip-prefix>192.0.2.11/32</ip-prefix></address>"
            "<address><name>web2</name><ip-prefix>192.0.2.12/32</ip-prefix></address>"
            "<address><name>db</name><ip-prefix>192.0.2.20/32</ip-prefix></address>"
            '<address-set><name>web-servers</name><address><name>web1</name></address><address inactive="inactive">'
            "<name>web2</name></address></address-set></address-book>"
            '<address-book><name>trust-book</name><address inactive="inactive"><name>web</name>'
            "<ip-prefix>10.0.0.10/32</ip-prefix></address><attach><zone><name>trust</name></zone></attach>"
            "</address-book>"
            '<address-book><name>off-book</name><address><name>db</name><ip-prefix>10.9.9.9/32</ip-prefix></address>'
            '<attach><zone inactive="inactive"><name>trust</name></zone></attach></address-book>'
            "<policies>" + pair("trust", "untrust", pol("p", src="web", dst="web-servers"))
            + pair("trust", "untrust", pol("q", src="db")) + "</policies>"
        )
        inv = I.build_inventory(doc)
        resolved = by_name(inv, "p")["resolved"]
        src = resolved["source"][0]
        self.assertEqual((src["book"], src["leaves"][0]["value"]), ("global", "192.0.2.10/32"))
        self.assertEqual(src["inactive_skipped"], ["trust-book:web"])
        self.assertEqual([leaf["name"] for leaf in resolved["destination"][0]["leaves"]], ["web1"])
        db = by_name(inv, "q")["resolved"]["source"][0]
        self.assertEqual((db["book"], db["leaves"][0]["value"]), ("global", "192.0.2.20/32"))
        books = {b["name"]: b for b in inv["root"]["address_books"]["rows"]}
        self.assertEqual((books["off-book"]["attach"], books["off-book"]["inactive_attach"]), ([], ["trust"]))
        sets = {x["name"]: x for x in books["global"]["sets"]}
        self.assertEqual((sets["web-servers"]["addresses"], sets["web-servers"]["inactive_members"]),
                         (["web1"], ["web2"]))
        warnings = inv["root"]["warnings"]
        self.assertTrue(any("web-servers" in w and "web2" in w for w in warnings), warnings)
        self.assertTrue(any("off-book" in w and "attach" in w for w in warnings), warnings)

    def test_deactivated_book_is_not_used(self) -> None:
        doc = config('<address-book inactive="inactive"><name>global</name><address><name>h</name>'
                     "<ip-prefix>192.0.2.1/32</ip-prefix></address></address-book>"
                     "<policies>" + pair("a", "b", pol("p", src="h")) + "</policies>")
        self.assertEqual(by_name(I.build_inventory(doc), "p")["resolved"]["source"][0]["kind"], "unresolved")

    def test_deactivated_application_set_members_and_applications(self) -> None:
        apps = ("<application><name>a1</name><protocol>tcp</protocol><destination-port>1</destination-port>"
                "</application><application><name>a2</name><protocol>tcp</protocol><destination-port>2"
                '</destination-port></application><application inactive="inactive"><name>a3</name>'
                "<protocol>tcp</protocol></application>"
                '<application-set><name>s</name><application><name>a1</name></application><application inactive='
                '"inactive"><name>a2</name></application></application-set>')
        inv = I.build_inventory(config("<policies>" + pair("a", "b", pol("p", app="s"))
                                       + pair("a", "b", pol("q", app="a3")) + "</policies>", applications=apps))
        leaves = by_name(inv, "p")["resolved"]["application"][0]["leaves"]
        self.assertEqual([leaf["name"] for leaf in leaves], ["a1"])
        a3 = by_name(inv, "q")["resolved"]["application"][0]
        self.assertEqual((a3["kind"], a3["inactive_skipped"]), ("unresolved", ["a3"]))
        rows_by_name = {a["name"]: a for a in inv["root"]["applications"]["rows"]}
        self.assertEqual((rows_by_name["s"]["members"], rows_by_name["s"]["inactive_members"]), (["a1"], ["a2"]))


class UnifiedPolicyTests(unittest.TestCase):
    """JUNO-5: application junos-defaults and the implicit application of unified policies."""

    def build(self, *policies: str) -> Dict[str, Any]:
        return I.build_inventory(config("<policies>" + pair("trust", "untrust", "".join(policies)) + "</policies>"))

    @staticmethod
    def unified(name: str, app: str, dyn: str) -> str:
        app_xml = f"<application>{app}</application>" if app else ""
        return (f"<policy><name>{name}</name><match><source-address>any</source-address>"
                f"<destination-address>any</destination-address>{app_xml}"
                f"<dynamic-application>{dyn}</dynamic-application></match><then><permit/></then></policy>")

    def test_junos_defaults_is_its_own_kind(self) -> None:
        row = by_name(self.build(self.unified("web", "junos-defaults", "junos:HTTP")), "web")
        self.assertEqual(row["match"]["application"], ["junos-defaults"])
        self.assertFalse(row["match"]["application_implicit"])
        got = row["resolved"]["application"][0]
        self.assertEqual((got["kind"], got["unresolved"]), ("dynamic-defaults", []))

    def test_implicit_application(self) -> None:
        inv = self.build(self.unified("fb", "", "junos:FACEBOOK-ACCESS"), self.unified("all", "", "any"))
        fb = by_name(inv, "fb")
        self.assertEqual((fb["match"]["application"], fb["match"]["application_implicit"]), (["junos-defaults"], True))
        self.assertEqual(fb["resolved"]["application"][0]["kind"], "dynamic-defaults")
        everything = by_name(inv, "all")
        self.assertEqual((everything["match"]["application"], everything["match"]["application_implicit"]),
                         (["any"], True))

    def test_plain_policy_has_no_implicit_application(self) -> None:
        row = by_name(self.build(pol("p")), "p")
        self.assertEqual((row["match"]["application"], row["match"]["application_implicit"]), (["any"], False))


class CommentTests(unittest.TestCase):
    """JUNO-12: configuration comments are attached, never reported as unmodeled settings."""

    def test_comments_on_rules_contexts_and_objects(self) -> None:
        doc = config(
            "<junos:comment>/* book note */</junos:comment>"
            "<address-book><name>global</name><junos:comment>/* host note */</junos:comment>"
            "<address><name>h</name><ip-prefix>192.0.2.1/32</ip-prefix></address></address-book>"
            "<policies><junos:comment>/* CHG-1234 internet edge */</junos:comment>"
            "<policy><from-zone-name>trust</from-zone-name><to-zone-name>untrust</to-zone-name>"
            "<junos:comment>/* owner: web team, ticket CHG-42 */</junos:comment>"
            "<policy><name>allow-web</name><match><source-address>h</source-address>"
            "<destination-address>any</destination-address><application>junos-https</application></match>"
            "<junos:comment># temporary, remove after migration</junos:comment><then><permit/></then></policy>"
            "</policy></policies>"
            "<zones><junos:comment>/* zone note */</junos:comment><security-zone><name>trust</name></security-zone>"
            "</zones>",
            applications="<junos:comment>/* app note */</junos:comment><application><name>x</name>"
                         "<protocol>tcp</protocol></application>",
        )
        inv = I.build_inventory(doc)["root"]
        row = inv["policies"]["rows"][0]
        self.assertEqual(row["comment"], "/* owner: web team, ticket CHG-42 */")
        self.assertEqual(row["part_comments"], [{"before": "then", "text": "# temporary, remove after migration"}])
        self.assertEqual(row["pair_comment"], "/* CHG-1234 internet edge */")
        self.assertEqual(inv["policies"]["zone_pairs"][0]["comment"], "/* CHG-1234 internet edge */")
        self.assertEqual(row["unmodeled"], [])
        self.assertEqual(inv["warnings"], [])
        book = inv["address_books"]["rows"][0]
        self.assertEqual((book["comment"], book["addresses"][0]["comment"]), ("/* book note */", "/* host note */"))
        self.assertEqual(inv["zones"]["rows"][0]["comment"], "/* zone note */")
        self.assertEqual(inv["applications"]["rows"][0]["comment"], "/* app note */")
        self.assertEqual(inv["applications"]["rows"][0]["unmodeled"], [])


class ObjectUnmodeledTests(unittest.TestCase):
    """CONS-03: settings the model does not show are listed for objects too, not only for policies."""

    def test_application_settings(self) -> None:
        apps = ("<application><name>app1</name><protocol>icmp</protocol><icmp-type>8</icmp-type>"
                "<application-protocol>ftp</application-protocol><inactivity-timeout>5</inactivity-timeout>"
                "</application><application-set><name>s</name><application><name>app1</name></application>"
                "<future-knob/></application-set>")
        inv = I.build_inventory(config("<policies>" + pair("a", "b", pol("p", app="app1")) + "</policies>",
                                       applications=apps))
        rows_by_name = {a["name"]: a for a in inv["root"]["applications"]["rows"]}
        self.assertEqual(rows_by_name["app1"]["unmodeled"], ["icmp-type", "application-protocol", "inactivity-timeout"])
        self.assertEqual(rows_by_name["s"]["unmodeled"], ["future-knob"])
        leaf = by_name(inv, "p")["resolved"]["application"][0]["leaves"][0]
        self.assertEqual(leaf["unmodeled"], ["icmp-type", "application-protocol", "inactivity-timeout"])
        warnings = inv["root"]["warnings"]
        self.assertIn("Application app1 has settings J-Wicket does not display yet: icmp-type, "
                      "application-protocol, inactivity-timeout.", warnings)
        self.assertTrue(any("Application set s" in w and "future-knob" in w for w in warnings))

    def test_zone_interface_and_address_settings(self) -> None:
        doc = config(
            "<address-book><name>global</name><address><name>h</name><ip-prefix>192.0.2.1/32</ip-prefix>"
            "<future-address-knob/></address><address-set><name>s</name><address><name>h</name></address>"
            "<future-set-knob/></address-set><future-book-knob/></address-book>"
            "<zones><security-zone><name>a</name><tcp-rst/><application-tracking/><source-identity-log/>"
            "<host-inbound-traffic><future-hit-knob/></host-inbound-traffic>"
            "<interfaces><name>ge-0/0/0.0</name><future-ifc-knob/></interfaces></security-zone></zones>"
        )
        inv = I.build_inventory(doc)["root"]
        zone = inv["zones"]["rows"][0]
        self.assertEqual(zone["unmodeled"], ["tcp-rst", "application-tracking", "source-identity-log",
                                             "host-inbound-traffic future-hit-knob"])
        self.assertEqual(zone["interfaces"][0]["unmodeled"], ["future-ifc-knob"])
        book = inv["address_books"]["rows"][0]
        self.assertEqual(book["unmodeled"], ["future-book-knob"])
        self.assertEqual(book["addresses"][0]["unmodeled"], ["future-address-knob"])
        self.assertEqual(book["sets"][0]["unmodeled"], ["future-set-knob"])
        warnings = inv["warnings"]
        for needle in ("Zone a has settings", "tcp-rst", "interface ge-0/0/0.0", "future-book-knob",
                       "Address h in book global", "Address set s in book global"):
            with self.subTest(needle=needle):
                self.assertTrue(any(needle in w for w in warnings), warnings)

    def test_branch_fixture_has_no_object_warnings(self) -> None:
        inv = I.build_inventory(load(BRANCH / "config.xml"))
        self.assertFalse(any(w.startswith(("Zone", "Address", "Application")) for w in inv["root"]["warnings"]),
                         inv["root"]["warnings"])


BOOKS = """
<address-book><name>global</name>
  <address><name>h</name><ip-prefix>192.0.2.1/32</ip-prefix></address>
  <address><name>g-only</name><ip-prefix>192.0.2.9/32</ip-prefix></address>
  <address-set><name>S</name><address><name>h</name></address></address-set>
</address-book>
<address-book><name>abook</name>
  <address><name>h</name><ip-prefix>198.51.100.2/32</ip-prefix></address>
  <attach><zone><name>a</name></zone></attach>
</address-book>
<address-book><name>cbook</name>
  <address><name>h</name><ip-prefix>198.51.100.4/32</ip-prefix></address>
  <attach><zone><name>c</name></zone></attach>
</address-book>
<zones>
  <security-zone><name>a</name>
    <address-book><address><name>h</name><ip-prefix>203.0.113.3/32</ip-prefix></address></address-book>
  </security-zone>
  <security-zone><name>c</name></security-zone>
  <security-zone><name>d</name></security-zone>
</zones>
"""


class AddressResolutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        doc = config(
            BOOKS + "<policies>"
            + pair("a", "d", pol("from-a", src="h", dst="h"))
            + pair("c", "d", pol("from-c", src="h"))
            + pair("d", "a", pol("from-d", src="h", dst="h"))
            + pair("a", "d", pol("set-from-a", src="S"))
            + pair("a", "d", pol("unknown", src="nope", dst="g-only"))
            + "<global>" + pol("glob", src="h", dst="h", match_extra="<from-zone>a</from-zone><to-zone>a</to-zone>")
            + "</global></policies>"
        )
        cls.inv = I.build_inventory(doc)

    def src(self, name: str) -> Dict[str, Any]:
        return dict(by_name(self.inv, name)["resolved"]["source"][0])

    def dst(self, name: str) -> Dict[str, Any]:
        return dict(by_name(self.inv, name)["resolved"]["destination"][0])

    def test_legacy_zone_book_first(self) -> None:
        got = self.src("from-a")
        self.assertEqual((got["book"], got["leaves"][0]["value"]), ("zone a", "203.0.113.3/32"))

    def test_attached_book_before_global(self) -> None:
        got = self.src("from-c")
        self.assertEqual((got["book"], got["leaves"][0]["value"]), ("cbook", "198.51.100.4/32"))

    def test_global_book_last(self) -> None:
        got = self.src("from-d")
        self.assertEqual((got["book"], got["leaves"][0]["value"]), ("global", "192.0.2.1/32"))

    def test_destination_uses_the_to_zone(self) -> None:
        self.assertEqual(self.dst("from-d")["book"], "zone a")
        self.assertEqual(self.dst("from-a")["book"], "global")
        self.assertEqual(self.dst("unknown")["book"], "global")

    def test_global_policies_use_the_global_book_only(self) -> None:
        self.assertEqual(self.src("glob")["book"], "global")
        self.assertEqual(self.dst("glob")["book"], "global")
        self.assertEqual(self.src("glob")["leaves"][0]["value"], "192.0.2.1/32")

    def test_unresolved_name(self) -> None:
        got = self.src("unknown")
        self.assertEqual((got["kind"], got["book"], got["leaves"], got["unresolved"]),
                         ("unresolved", None, [], ["nope"]))

    def test_set_members_resolve_in_the_sets_own_book(self) -> None:
        """Junos: an address set can contain only entries of its own address book. Set S lives in the
        global book, so its member h is the global h, not the h of a book attached to the zone."""
        got = self.src("set-from-a")
        self.assertEqual((got["kind"], got["book"]), ("set", "global"))
        self.assertEqual(got["leaves"], [{"name": "h", "kind": "prefix", "value": "192.0.2.1/32"}])

    def test_legacy_zone_book_listed(self) -> None:
        books = {b["name"]: b for b in self.inv["root"]["address_books"]["rows"]}
        self.assertEqual(books["zone a"]["legacy_zone"], "a")
        self.assertEqual(books["zone a"]["attach"], ["a"])
        self.assertEqual(books["abook"]["attach"], ["a"])


def big_book(count: int, depth_chain: int = 0) -> Any:
    addrs = "".join(f"<address><name>n{i}</name><ip-prefix>10.0.{i // 256}.{i % 256}/32</ip-prefix></address>"
                    for i in range(count))
    members = "".join(f"<address><name>n{i}</name></address>" for i in range(count))
    chain = ""
    for level in range(depth_chain):
        inner = f"<address-set><name>c{level + 1}</name></address-set>" if level + 1 < depth_chain else \
            "<address><name>n0</name></address>"
        chain += f"<address-set><name>c{level}</name>{inner}</address-set>"
    return config(
        f"<address-book><name>global</name>{addrs}<address-set><name>big</name>{members}</address-set>{chain}"
        "<address-set><name>loop-a</name><address><name>n0</name></address><address-set><name>loop-b</name></address-set>"
        "</address-set><address-set><name>loop-b</name><address><name>n1</name></address>"
        "<address-set><name>loop-a</name></address-set></address-set>"
        "<address-set><name>self</name><address-set><name>self</name></address-set></address-set>"
        "</address-book><policies>"
        + pair("x", "y", pol("big", src="big") + pol("loop", src="loop-a", dst="self") + pol("chain", src="c0"))
        + "</policies>"
    )


class ExpansionLimitTests(unittest.TestCase):
    def test_max_leaves_truncation_flag(self) -> None:
        inv = I.build_inventory(big_book(I.MAX_LEAVES + 40))
        got = by_name(inv, "big")["resolved"]["source"][0]
        self.assertTrue(got["truncated"])
        self.assertEqual(len(got["leaves"]), I.MAX_LEAVES)

    def test_exactly_max_leaves_is_not_truncated(self) -> None:
        inv = I.build_inventory(big_book(I.MAX_LEAVES))
        got = by_name(inv, "big")["resolved"]["source"][0]
        self.assertFalse(got["truncated"])
        self.assertEqual(len(got["leaves"]), I.MAX_LEAVES)

    def test_cycles_terminate(self) -> None:
        start = time.monotonic()
        inv = I.build_inventory(big_book(2))
        self.assertLess(time.monotonic() - start, 2.0)
        row = by_name(inv, "loop")
        self.assertEqual([leaf["name"] for leaf in row["resolved"]["source"][0]["leaves"]], ["n0", "n1"])
        self.assertEqual(row["resolved"]["destination"][0]["leaves"], [])

    def test_deep_chain_terminates(self) -> None:
        start = time.monotonic()
        I.build_inventory(big_book(1, depth_chain=I.MAX_EXPANSION_DEPTH + 10))
        self.assertLess(time.monotonic() - start, 2.0)

    def test_shallow_chain_reaches_the_leaf(self) -> None:
        inv = I.build_inventory(big_book(1, depth_chain=5))
        self.assertEqual([leaf["name"] for leaf in by_name(inv, "chain")["resolved"]["source"][0]["leaves"]], ["n0"])

    def test_depth_limit_is_not_silent(self) -> None:
        """'Nothing is dropped silently': hitting the nesting limit must be visible in the result."""
        inv = I.build_inventory(big_book(1, depth_chain=I.MAX_EXPANSION_DEPTH + 10))
        got = by_name(inv, "chain")["resolved"]["source"][0]
        self.assertTrue(got["leaves"] or got["truncated"] or got["unresolved"], got)


class ApplicationResolutionTests(unittest.TestCase):
    APPS = (
        "<application><name>multi</name><term><name>t1</name><protocol>tcp</protocol></term>"
        "<term><name>t2</name><protocol>udp</protocol></term></application>"
        "<application><name>udp-53</name><protocol>udp</protocol><destination-port>53</destination-port>"
        "<source-port>1024-65535</source-port></application>"
        "<application-set><name>outer</name><application><name>udp-53</name></application>"
        "<application><name>missing-app</name></application><application-set><name>inner</name></application-set>"
        "</application-set>"
        "<application-set><name>inner</name><application><name>junos-ssh</name></application>"
        "<application-set><name>outer</name></application-set></application-set>"
    )

    def resolve(self, name: str) -> Dict[str, Any]:
        doc = config("<policies>" + pair("a", "b", pol("p", app=name)) + "</policies>", applications=self.APPS)
        return dict(by_name(I.build_inventory(doc), "p")["resolved"]["application"][0])

    def test_any(self) -> None:
        self.assertEqual(self.resolve("any")["kind"], "any")

    def test_predefined(self) -> None:
        got = self.resolve("junos-ssh")
        self.assertEqual((got["kind"], got["unresolved"]), ("predefined", []))

    def test_unresolved(self) -> None:
        got = self.resolve("no-such-app")
        self.assertEqual((got["kind"], got["unresolved"]), ("unresolved", ["no-such-app"]))

    def test_custom_application_with_terms(self) -> None:
        got = self.resolve("multi")
        self.assertEqual(got["kind"], "application")
        self.assertEqual(got["leaves"], [{"name": "multi", "protocol": None, "destination_port": None,
                                          "source_port": None, "terms": 2, "unmodeled": []}])

    def test_nested_sets_with_cycle_predefined_and_unresolved_members(self) -> None:
        got = self.resolve("outer")
        self.assertEqual(got["kind"], "set")
        self.assertEqual(
            got["leaves"],
            [
                {"name": "udp-53", "protocol": "udp", "destination_port": "53", "source_port": "1024-65535",
                 "terms": 0, "unmodeled": []},
                {"name": "junos-ssh", "predefined": True},
            ],
        )
        self.assertEqual(got["unresolved"], ["missing-app"])


class LsysTenantInlineTests(unittest.TestCase):
    def test_scopes_never_merge_and_inactive_lsys(self) -> None:
        doc = xml(
            "<configuration><security><address-book><name>global</name><address><name>root-net</name>"
            "<ip-prefix>10.0.0.0/8</ip-prefix></address></address-book><policies>"
            + pair("a", "b", pol("root-p", src="lsys-net")) + "</policies></security>"
            '<logical-systems inactive="inactive"><name>LS-1</name><security><address-book><name>global</name>'
            "<address><name>lsys-net</name><ip-prefix>172.16.0.0/12</ip-prefix></address></address-book><policies>"
            + pair("a", "b", pol("lsys-p", src="root-net")) + "</policies></security></logical-systems>"
            "<logical-systems><name>LS-2</name></logical-systems>"
            "<tenants><name>T-9</name><security><policies>" + pair("x", "y", pol("t-p"))
            + "</policies></security></tenants>"
            "<logical-systems><security/></logical-systems>"
            "</configuration>"
        )
        inv = I.build_inventory(doc)
        self.assertEqual(list(inv), ["root", "lsys:LS-1", "lsys:LS-2", "tenant:T-9"])
        self.assertEqual(by_name(inv, "root-p")["resolved"]["source"][0]["kind"], "unresolved")
        self.assertEqual(by_name(inv, "lsys-p", "lsys:LS-1")["resolved"]["source"][0]["kind"], "unresolved")
        self.assertTrue(inv["lsys:LS-1"]["inactive"])
        self.assertTrue(any("deactivated" in w for w in inv["lsys:LS-1"]["warnings"]))
        self.assertFalse(inv["tenant:T-9"]["inactive"])
        self.assertEqual(rows(inv, "lsys:LS-2"), [])
        self.assertEqual([r["name"] for r in rows(inv)], ["root-p"])


if __name__ == "__main__":
    unittest.main()
