"""Reply parsing with explicit rules (Spec 006 sections 7.2, 7.11, 8.3; AC-006-22 SecretTests).

Every reply here is synthetic (tests/fixtures/install/README.md). The tests fix the parse rules, not
the device's reply shapes, which lab test Q-INST-01 records.
"""

from __future__ import annotations

import unittest
from pathlib import Path

import install_support as s
from install_support import plan, state

from jwicket_install import render

EXT = "system extensions extension-service application file"


class FactsTests(unittest.TestCase):
    def test_fresh_vsrx(self) -> None:
        facts = s.facts_of("fresh-vsrx")
        self.assertEqual(facts.hostname, s.HOST)
        self.assertEqual(facts.model, "vsrx")
        self.assertEqual(facts.junos_version, "24.4R2-S3.5")
        self.assertEqual(facts.serial, "FIXTURE-SN-0001")
        self.assertIs(facts.srx_cluster, False)
        self.assertIs(facts.mnha, False)
        self.assertIs(facts.fips_configured, False)
        self.assertEqual(facts.routing_engines, 1)
        self.assertEqual(facts.flow_sessions, 12)

    def test_cluster_rules(self) -> None:
        self.assertIs(s.facts_of("cluster").srx_cluster, True)
        self.assertIsNone(s.facts_of("cluster-rpc-error").srx_cluster)
        self.assertIsNone(
            state.cluster_state("<rpc-reply><rpc-error><error-message>x</error-message></rpc-error></rpc-reply>")
        )
        self.assertIsNone(state.cluster_state("<rpc-reply><something-else/></rpc-reply>"))
        self.assertIsNone(state.cluster_state(None))
        self.assertIs(state.cluster_state("<error><message>Chassis cluster is not enabled.</message></error>"), False)

    def test_model_host_and_config_flags(self) -> None:
        self.assertEqual(s.facts_of("physical-srx345").model, "srx345")
        self.assertIsNone(s.facts_of("no-hostname").hostname)
        self.assertIs(s.facts_of("mnha").mnha, True)
        self.assertIs(s.facts_of("fips").fips_configured, True)
        odd = state.facts_from_replies(
            "<software-information><host-name>bad host;</host-name>"
            "<product-model>{{x}}</product-model></software-information>",
            None,
            None,
            None,
        )
        self.assertIsNone(odd.hostname)
        self.assertIsNone(odd.model)
        self.assertIsNone(odd.fips_configured)

    def test_the_lab_srx4100(self) -> None:
        """The reference case of R5 (docs/evidence/2026-11-24-srx4100-lab): model and release as recorded."""
        facts = s.facts_of("lab-srx4100")
        self.assertEqual((facts.model, facts.junos_version), ("srx4100", "25.2R1-S1.4"))
        self.assertIs(facts.srx_cluster, False)
        self.assertEqual((facts.routing_engines, facts.flow_sessions), (1, 40))
        self.assertIsNone(plan.VSRX_MODEL_RE.match(facts.model or ""))
        self.assertIsNotNone(plan.SRX_HARDWARE_MODEL_RE.match(facts.model or ""))

    def test_multi_routing_engine_reply(self) -> None:
        reply = (
            "<multi-routing-engine-results><multi-routing-engine-item><re-name>re0</re-name>"
            "<software-information><host-name>a</host-name></software-information></multi-routing-engine-item>"
            "<multi-routing-engine-item><re-name>re1</re-name><software-information/></multi-routing-engine-item>"
            "</multi-routing-engine-results>"
        )
        self.assertEqual(state.facts_from_replies(reply, None, None, None).routing_engines, 2)


RECORDED = Path(__file__).resolve().parent / "fixtures" / "recorded-srx4100-25.2R1-S1.4"


class RecordedReplyTests(unittest.TestCase):
    """The three replies the installer also asks for, as recorded on the lab SRX4100 (25.2R1-S1.4)."""

    def reply(self, name: str) -> bytes:
        return (RECORDED / name).read_bytes()

    def test_software_information_and_standalone_cluster_status(self) -> None:
        facts = state.facts_from_replies(
            self.reply("get-software-information.xml"),
            self.reply("get-chassis-cluster-status.xml"),
            None,
            None,
        )
        self.assertIsNotNone(facts.hostname)
        self.assertEqual(facts.model, "srx4100")
        self.assertEqual(facts.junos_version, "25.2R1-S1.4")
        self.assertIs(facts.srx_cluster, False)  # the namespaced <xnm:error> "Chassis cluster is not enabled"

    def test_flow_summary_counts_active_sessions_not_unicast(self) -> None:
        # The recording lists active-unicast-sessions 21 before active-sessions 43 (21 valid + 22 invalidated).
        self.assertEqual(state.flow_session_count(self.reply("get-flow-session-information-summary.xml")), 43)

    def test_unicast_count_only_without_active_sessions(self) -> None:
        reply = (
            b"<flow-session-summary-information><active-unicast-sessions>7</active-unicast-sessions>"
            b"</flow-session-summary-information>"
        )
        self.assertEqual(state.flow_session_count(reply), 7)


class ConfigTests(unittest.TestCase):
    def test_statements_of_a_full_install(self) -> None:
        prior = s.prior_of("running-install")
        pairs = prior.direct.pairs
        self.assertIn(("system scripts language", "python3"), pairs)
        self.assertIn(("system services netconf ssh", ""), pairs)
        self.assertIn((f"{EXT} jwicket.py daemonize", ""), pairs)
        self.assertIn((f"{EXT} jwicket.py username", s.USER), pairs)
        self.assertIn((f"{EXT} jwicket.py checksum sha-256", s.BUNDLE_SHA), pairs)
        self.assertEqual(set(prior.jwicket_stanzas), {"jwicket.py", "jwicket_probe.py", "jwicket_selftest.py"})
        self.assertEqual(prior.language, "python3")

    def test_derived_views(self) -> None:
        self.assertEqual(s.prior_of("outbound-ssh").outbound_ssh_clients, ("sd-cloud",))
        self.assertEqual(s.prior_of("commit-scripts").commit_scripts, ("check-policy.slax",))
        self.assertEqual(s.prior_of("other-python").configured_python, ("op:tools.py", "event:on-link.py"))
        self.assertIn("listed:/var/db/scripts/jet/helper.py", s.prior_of("other-python").other_python)
        ports = s.prior_of("port-collision")
        self.assertEqual((ports.web_ports, ports.rest_ports), ((9443,), (8443,)))
        self.assertIn("R-PORT", {r.code for r in s.plan_for("port-collision").refusals})
        self.assertIn("R-PORT", {r.code for r in s.plan_for("port-collision", access="tunnel").refusals})
        self.assertTrue(s.prior_of("load-scripts-from-flash").load_scripts_from_flash)
        self.assertEqual(s.prior_of("language-python").language, "python")
        self.assertTrue(s.prior_of("mnha").mnha_configured)
        group = s.prior_of("foreign-group")
        self.assertEqual(group.jwicket_group_paths, frozenset({"groups jwicket system scripts language"}))
        self.assertEqual(group.apply_groups, ("jwicket",))

    def test_management_instance(self) -> None:
        """An empty leaf (junos-es 23.2R1 conf-system YANG); inactive does not count."""
        self.assertIn(("system management-instance", ""), s.prior_of("management-instance").direct.pairs)
        self.assertTrue(s.prior_of("lab-srx4100").management_instance)
        self.assertIn(("system", "management-instance"), state.WALKED)
        inactive = state.statements_from_config(
            '<configuration><system><management-instance inactive="inactive"/></system></configuration>'
        )
        self.assertFalse(plan.PriorState(effective=inactive, direct=inactive).management_instance)

    def test_unknown_values_are_hashed_inactive_and_bad_names_marked(self) -> None:
        reply = (
            '<configuration><system><scripts><language>py thon</language><op inactive="inactive">'
            "<allow-url-for-python/></op></scripts><extensions><extension-service><application>"
            "<file><name>jwicket.py</name><arguments>--x {{y}}</arguments></file>"
            "<file><name>bad name;</name><daemonize/></file></application></extension-service></extensions>"
            "</system></configuration>"
        )
        found = state.statements_from_config(reply)
        keys = dict(found.pairs)
        self.assertTrue(keys["system scripts language"].startswith("h:"))
        self.assertTrue(keys[f"{EXT} jwicket.py arguments"].startswith("h:"))
        self.assertIn("system scripts inactive:op allow-url-for-python", keys)
        self.assertIn(f"{EXT} invalid-name-1 daemonize", keys)
        self.assertNotIn("{{", repr(found))

    def test_only_selected_subtrees_are_read(self) -> None:
        reply = (
            "<configuration><system><login><user><name>x</name><class>super-user</class></user></login>"
            "<host-name>h</host-name></system><security><policies/></security></configuration>"
        )
        self.assertEqual(state.statements_from_config(reply), plan.StatementSet())


class HistoryTests(unittest.TestCase):
    def test_states(self) -> None:
        self.assertIs(s.prior_of("fresh-vsrx").pending, plan.Pending.NONE)
        self.assertIs(s.prior_of("pending-other-user").pending, plan.Pending.OTHER)
        prepared = s.prior_of("prepared-commit")
        self.assertIs(prepared.pending, plan.Pending.OTHER)
        self.assertTrue(prepared.prepared_commit)
        scheduled = s.prior_of("scheduled-commit")
        self.assertTrue(scheduled.scheduled_commit)
        self.assertIs(s.prior_of("unreadable-commit").pending, plan.Pending.UNREADABLE)
        self.assertIs(state.commit_state_from_reply(None).pending, plan.Pending.UNREADABLE)
        self.assertIs(state.commit_state_from_reply("<rpc-reply/>").pending, plan.Pending.UNREADABLE)
        duplicate = (
            "<commit-information><commit-history><sequence-number>0</sequence-number></commit-history>"
            "<commit-history><sequence-number>0</sequence-number></commit-history></commit-information>"
        )
        self.assertIs(state.commit_state_from_reply(duplicate).pending, plan.Pending.UNREADABLE)

    def test_entries_and_comment_or_log(self) -> None:
        pending, entries = state.history_from_reply(s.replies("own-bootstrap")["commit-information"])
        self.assertIs(pending, plan.Pending.OTHER)
        self.assertEqual(entries[0].comment, "jwicket-bootstrap netconf k3v9qt")
        self.assertEqual(entries[0].user, s.USER)
        self.assertTrue(entries[0].pending_confirm)
        in_log = (
            "<commit-information><commit-history><sequence-number>0</sequence-number><user>labadmin</user>"
            "<log>jwicket-bootstrap netconf k3v9qt</log><commit-confirmed>yes</commit-confirmed>"
            "</commit-history></commit-information>"
        )
        entry = state.history_from_reply(in_log)[1][0]
        self.assertEqual(entry.texts, ("jwicket-bootstrap netconf k3v9qt",))

    def test_template_injection_comments_are_dropped(self) -> None:
        prior = s.prior_of("template-injection")
        for entry in prior.history:
            self.assertIsNone(entry.comment)
            self.assertIsNone(entry.log)
        text = repr(prior)
        for marker in ("{{", "{%", "lookup", "example.net", '"hello"'):
            self.assertNotIn(marker, text)
        install = s.plan_for("template-injection")
        for output in (render.plan_to_json(install), render.render_plan_text(install, prior)):
            self.assertNotIn("{{", output)
            self.assertNotIn("lookup", output)


class FileListTests(unittest.TestCase):
    def test_listed_entries(self) -> None:
        prior = s.prior_of("running-install")
        info = prior.files[plan.DAEMON_PATH]
        self.assertEqual((info.owner, info.mode, info.is_dir, info.is_symlink), (s.USER, 0o644, False, False))
        directory = prior.files[plan.STATE_DIR]
        self.assertEqual((directory.owner, directory.mode, directory.is_dir), (s.USER, 0o700, True))
        self.assertEqual(prior.directories[plan.STATE_DIR], "listed")
        self.assertEqual(prior.checksums[plan.DAEMON_PATH], s.BUNDLE_SHA)

    def test_absent_paths_are_absent_not_unreadable(self) -> None:
        prior = s.prior_of("absent-paths")
        self.assertEqual(prior.directories[plan.STATE_DIR], "absent")
        self.assertEqual(prior.unreadable, ())
        self.assertNotIn(plan.STATE_DIR, prior.files)
        fresh = s.prior_of("fresh-vsrx")  # the root step done: listed, empty, the account's, 0700
        self.assertEqual(fresh.directories[plan.STATE_DIR], "listed")
        info = fresh.files[plan.STATE_DIR]
        self.assertEqual((info.owner, info.mode, info.is_dir, info.is_symlink), (s.USER, 0o700, True, False))
        reply = s.replies("absent-paths")["device-receipt-show"]
        self.assertIsNone(state.file_text_from_reply(reply))
        self.assertTrue(state.is_absent_path_error("error: /x: No such file or directory"))
        self.assertFalse(state.is_absent_path_error("permission denied"))

    def test_unexpected_listing_is_unreadable(self) -> None:
        self.assertIsNone(state.file_list_from_reply("<rpc-reply><weird/></rpc-reply>", "/var/db"))
        self.assertIsNone(state.file_list_from_reply(state.RpcErrorReply("permission denied"), "/var/db"))
        prior = state.prior_from_replies(None, None, None, {plan.VAR_DB: "<x/>"}, {}, None)
        self.assertEqual(prior.unreadable, ("configuration", "file list /var/db"))
        install = plan.build_install_plan(
            s.bundle(), s.provenance(), s.options(), s.facts_of("fresh-vsrx"), prior, method=plan.Method.WORKSTATION
        )
        self.assertIn("R-UNREADABLE", {r.code for r in install.refusals})

    def test_permissions_and_odd_names(self) -> None:
        reply = (
            "<directory-list><directory><directory-name>/var/db/jwicket</directory-name>"
            "<file-information><file-name>link</file-name><file-symlink-target>/tmp/x</file-symlink-target>"
            "<file-permissions>777</file-permissions><file-owner>root</file-owner></file-information>"
            '<file-information><file-name>we ird;name</file-name><file-permissions format="-rw-------">600'
            "</file-permissions><file-owner>labadmin</file-owner></file-information>"
            "</directory></directory-list>"
        )
        listing = state.file_list_from_reply(reply, plan.STATE_DIR)
        assert listing is not None
        link, odd = listing.entries
        self.assertTrue(link.is_symlink)
        self.assertEqual(link.mode, 0o777)
        self.assertEqual(odd.path, plan.STATE_DIR + "/invalid-name-1")
        self.assertEqual(odd.mode, 0o600)

    def test_checksums(self) -> None:
        good = s.replies("running-install")["sha256-jwicket.py"]
        self.assertEqual(state.checksum_from_reply(good), s.BUNDLE_SHA)
        self.assertEqual(state.checksum_from_reply(str(good).replace(s.BUNDLE_SHA, s.BUNDLE_SHA.upper())), s.BUNDLE_SHA)
        self.assertIsNone(state.checksum_from_reply("<checksum-information/>"))
        self.assertIsNone(state.checksum_from_reply(state.RpcErrorReply("error")))
        self.assertIsNone(state.checksum_from_reply(str(good).replace(s.BUNDLE_SHA, "zz")))


class SecretTests(unittest.TestCase):
    """AC-006-22: no secret, hash or URL with user information survives parsing or reaches an output."""

    def test_planted_secrets_never_survive(self) -> None:
        for name in s.scenario_names():
            prior = s.prior_of(name)
            text = repr(prior)
            for secret in s.PLANTED_SECRETS:
                self.assertNotIn(secret, text, (name, secret))
            install = s.plan_for(name, overrides=s.all_overrides(name))
            outputs = [render.plan_to_json(install), render.render_plan_text(install, prior), repr(install)]
            for output in outputs:
                for secret in s.PLANTED_SECRETS:
                    self.assertNotIn(secret, output, (name, secret))

    def test_secret_leaf_dropped_entirely(self) -> None:
        keys = {k for k, _ in s.prior_of("outbound-ssh").direct.pairs}
        self.assertFalse([k for k in keys if k.endswith(" secret")])
        self.assertIn("system services outbound-ssh client sd-cloud device-id", keys)
        self.assertFalse([k for k in keys if "login" in k])

    def test_source_url_is_hashed(self) -> None:
        values = dict(s.prior_of("outbound-ssh").direct.pairs)
        self.assertTrue(values[f"{EXT} other_app.py source"].startswith("h:"))


class SafetyTests(unittest.TestCase):
    def test_size_cap_and_declarations(self) -> None:
        with self.assertRaises(state.ReplyError):
            state.parse_xml("<a>" + "x" * (state.MAX_REPLY_BYTES + 1) + "</a>")
        laughs = (
            '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]>'
            "<lolz>&lol2;</lolz>"
        )
        with self.assertRaises(state.ReplyError):
            state.parse_xml(laughs)
        with self.assertRaises(state.ReplyError):
            state.parse_xml("<a><b></a>")
        self.assertEqual(state.statements_from_config(laughs), plan.StatementSet())

    def test_strip_control(self) -> None:
        self.assertEqual(state.strip_control("a\x1b[31mb\x07\nc"), "a[31mb c")


class VeriexecTests(unittest.TestCase):
    def test_forms(self) -> None:
        self.assertEqual(
            state.parse_veriexec("security.mac.veriexec.state: loaded active enforce\n"), "loaded active enforce"
        )
        self.assertEqual(state.parse_veriexec("loaded active enforce"), "loaded active enforce")
        self.assertEqual(
            state.parse_veriexec("% sysctl x\nsecurity.mac.veriexec.state:   loaded  active\n%"), "loaded active"
        )
        for bad in ("", "one\ntwo", "security.mac.veriexec.state: LOADED; rm", None, "x" * 5000):
            self.assertIsNone(state.parse_veriexec(bad), bad)
        self.assertEqual(s.prior_of("fresh-vsrx").veriexec, plan.VERIEXEC_ENFORCING)


class ReceiptTests(unittest.TestCase):
    def test_round_trip_and_strictness(self) -> None:
        text = s.raw_files("running-install")["workstation-receipt.json"]
        receipt = state.receipt_from_text(text)
        assert receipt is not None
        self.assertEqual(plan.Receipt.from_json(receipt.to_json()), receipt)
        self.assertEqual(receipt.blast_radius, plan.root_blast_radius(s.USER))
        self.assertEqual(receipt.schema, 3)
        self.assertEqual((receipt.access, receipt.listen_address, receipt.port), ("tls", s.LISTEN, 9443))
        self.assertEqual(receipt.tls_cert_sha256, s.CERT_SHA)
        self.assertIsNone(state.receipt_from_text(text.replace('"schema": 3', '"schema": 2')))
        self.assertIsNone(
            state.receipt_from_text(text.replace('"listen_address": "192.0.2.10"', '"listen_address": null'))
        )
        self.assertIsNone(state.receipt_from_text(text.replace('"access": "tls"', '"access": "tunnel"')))
        self.assertIsNone(
            state.receipt_from_text(text.replace('"lab_hardware_attested": false', '"lab_hardware_attested": true'))
        )
        self.assertIsNone(
            state.receipt_from_text(text.replace('"routing_instance": null', '"routing_instance": "red"'))
        )
        self.assertIsNone(state.receipt_from_text(text.replace("J-Wicket will run", "J-Wicket may run")))
        self.assertIsNone(state.receipt_from_text(text.replace('"S1"', '"S99"')))
        self.assertIsNone(state.receipt_from_text(text.replace('"time"', '"extra": 1, "time"')))
        self.assertIsNone(state.receipt_from_text("not json"))
        self.assertIsNone(state.receipt_from_text(None))

    def test_receipt_holds_no_secret(self) -> None:
        install = s.plan_for("python3-netconf-present", backend="lab-token")
        receipt = plan.receipt_for_run(install, host_key_sha256=(s.FINGERPRINT,), time="2026-11-24T21:00:00Z")
        text = receipt.to_json()
        self.assertNotIn("token_hex", text)
        self.assertEqual(plan.Receipt.from_json(text), receipt)
        lab_token = next(f for f in install.files if f.content == "lab-token")
        self.assertIsNone(lab_token.sha256)


if __name__ == "__main__":
    unittest.main()
