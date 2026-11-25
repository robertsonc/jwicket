"""The shared install plan (Spec 006 section 7, the pure rules of section 8; AC-006-01, 03-08, 11, 12).

Every test runs against synthetic fixtures (tests/fixtures/install/) and a model of the configuration:
it shows what the plan contains and how it reacts, never what a device does (Q-INST-06).
"""

from __future__ import annotations

import ast
import dataclasses
import re
import sys
import unittest
from pathlib import Path
from typing import Optional

import install_support as s
from install_support import plan, state

from jwicket import __version__ as daemon_version
from jwicket import settings as jwicket_settings

D = plan.Layout.DIRECT
G = plan.Layout.GROUP
EXT = "system extensions extension-service application file"


def lines_of(install: plan.InstallPlan, stage: str) -> tuple:
    found = install.stage(stage)
    return () if found is None else plan.stage_lines(found, install.layout)


def _string_literal(node: ast.AST) -> Optional[str]:
    """A string literal's value: ast.Constant from Python 3.8, ast.Str on 3.7 (whose parser makes no Constant)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if sys.version_info < (3, 8) and isinstance(node, getattr(ast, "Str", ())):
        return node.s
    return None


def parse_37(source: str, filename: str) -> ast.Module:
    """ast.parse with Python 3.7's grammar: feature_version on 3.8 and later (best effort), the interpreter's
    own grammar on 3.7, where feature_version does not exist."""
    if sys.version_info >= (3, 8):
        return ast.parse(source, filename=filename, feature_version=(3, 7))
    return ast.parse(source, filename=filename)


class ConstantsTests(unittest.TestCase):
    """AC-006-12 and the constants the other packages build on."""

    def test_state_dir_and_settings_path_match_the_daemon(self) -> None:
        self.assertEqual(plan.SETTINGS_PATH, str(jwicket_settings.DEFAULT_CONFIG_PATH))
        self.assertEqual(plan.STATE_DIR, str(jwicket_settings.DEFAULT_CONFIG_PATH.parent))

    def test_diagnostic_files_are_the_bundle_aliases(self) -> None:
        tree = ast.parse((s.REPO / "tools" / "bundle.py").read_text(encoding="utf-8"))
        runtime = next(
            text
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "_RUNTIME" for t in node.targets)
            for text in (_string_literal(node.value),)
            if text is not None
        )
        match = re.search(r"^ALIASES = (\{.*\})$", runtime, re.M)
        assert match is not None
        aliases = ast.literal_eval(match.group(1))
        # Cut C1: the setup alias (D1) is deferred, so the aliases are exactly the two diagnostics.
        self.assertEqual(set(plan.DIAGNOSTIC_FILES), set(aliases))

    def test_bundle_header_and_build_match_the_checks(self) -> None:
        """Contract with tools/bundle.py and app.py (bundle changes D2, D3): what C2 to C5 expect is what the
        bundle declares and writes; only declared features are relied on."""
        import hashlib

        import bundle as bundle_tool  # tools/bundle.py (tools/ is on sys.path via install_support)

        built = bundle_tool.build()
        data = built.text.encode("ascii")
        found = plan.BundleId.from_header(built.text[:4096], hashlib.sha256(data).hexdigest(), len(data))
        self.assertEqual(found.payload_sha256, built.payload_sha256)
        self.assertEqual(found.version, built.version)
        self.assertLessEqual(found.features, set(plan.FEATURES))
        if found.has("result-files"):
            self.assertEqual(bundle_tool.RESULT_DIR, plan.STATE_DIR)
            names = dict(bundle_tool.RESULT_FILES)
            self.assertEqual(f"{plan.STATE_DIR}/{names['self-test']}", plan.SELFTEST_RESULT_PATH)
            self.assertEqual(f"{plan.STATE_DIR}/{names['probe']}", plan.PROBE_RESULT_PATH)
        if found.has("build-line"):
            source = (s.REPO / "src" / "jwicket" / "app.py").read_text(encoding="utf-8")
            match = re.search(r'LOG\.info\(\s*"(listening on [^"]+)"', source)
            assert match is not None
            # app.py's start line, for each access mode and routing instance the plan renders (R2).
            for name, options, args in (
                ("python3-netconf-present", {}, (s.LISTEN, 9443, True, "netconf", "default")),
                ("python3-netconf-present", {"access": "tunnel"}, ("127.0.0.1", 8443, False, "netconf", "default")),
                ("management-instance", {}, (s.LISTEN, 9443, True, "netconf", "mgmt_junos")),
                (
                    "python3-netconf-present",
                    {"backend": "lab-token"},
                    ("127.0.0.1", 8443, False, "lab-token", "default"),
                ),
            ):
                line = match.group(1) % (*args, found.version, s.PAYLOAD_SHA[:16])
                bundle_id = dataclasses.replace(s.bundle(), version=found.version)
                runtime = s.plan_for(name, bundle_id=bundle_id, **options).stage("runtime")
                assert runtime is not None
                c4 = next(c for c in runtime.checks if c.id == "C4")
                with self.subTest(name=name, options=options):
                    self.assertEqual(line, f"{c4.expect['line']} {c4.expect['build']}")

    def test_required_modules_are_ones_the_probe_reports(self) -> None:
        from jwicket import app

        for backend, modules in plan.REQUIRED_MODULES.items():
            self.assertLessEqual(set(modules), set(app.PROBE_MODULES), backend)
        self.assertEqual(set(plan.REQUIRED_MODULES), set(jwicket_settings.BACKENDS))

    def test_version_and_schemas(self) -> None:
        import jwicket_install

        self.assertEqual(jwicket_install.__version__, daemon_version)
        self.assertEqual(plan.PLAN_SCHEMA, 2)
        self.assertEqual(plan.RECEIPT_SCHEMA, 3)

    def test_statement_keys_s1_to_s14_with_s6_s7_reserved(self) -> None:
        keys = [spec.key for spec in plan.STATEMENT_TABLE]
        expected = [f"S{n}" for n in range(1, 15) if n not in (6, 7)]
        self.assertEqual(keys, expected)
        self.assertEqual(plan.RESERVED_KEYS, ("S6", "S7"))
        for key in plan.RESERVED_KEYS:
            with self.assertRaises(plan.InputError):
                plan.make_statement(key, "diagnostics", user=s.USER, bundle_sha256=s.BUNDLE_SHA)

    def test_texts_are_single_constants_and_name_their_junos_command(self) -> None:
        command = re.compile(
            r"'(?:set|show|delete|file|sysctl|request|start shell|commit|su|mkdir|chmod|chown|ssh|"
            r"username|language|system)[^']*'"
        )
        for warning_id, text in plan.WARNINGS.items():
            self.assertIs(getattr(plan, warning_id), text)
            if warning_id != "DEVICE_STATUS":
                self.assertRegex(text, command, warning_id)
        self.assertRegex(plan.LAB_GATE_PROMPT, command)

    def test_device_status_and_gate_prompt_exact(self) -> None:
        self.assertEqual(
            plan.DEVICE_STATUS,
            "This installer has not yet run on any device. Every device step is unverified until lab test "
            "Q-INST-06 is certified.",
        )
        self.assertIn("Type the host name of the lab device you intend to change", plan.LAB_GATE_PROMPT)
        self.assertIn("it does not prove it", plan.LAB_GATE_PROMPT)
        self.assertNotIn(s.HOST, plan.LAB_GATE_PROMPT)
        self.assertNotIn("<user>", plan.LAB_GATE_PROMPT)

    def test_refusal_table_covers_spec_8_11(self) -> None:
        spec_codes = {
            "R-MODEL",
            "R-NOHOST",
            "R-ROOT",
            "R-CLUSTER",
            "R-MNHA",
            "R-DUAL-RE",
            "R-FLASH",
            "R-LANG",
            "R-PENDING",
            "R-FOREIGN",
            "R-USER",
            "R-PORT",
            "R-FIPS",
            "R-VERIEXEC",
            "R-MANAGED",
            "R-COMMIT-SCRIPTS",
            "R-RELEASE",
            "R-UPGRADE-NOCHECKSUM",
            "R-PROVENANCE",
            "R-HOSTKEY",
            "R-BIND",
        }
        self.assertLessEqual(spec_codes, set(plan.REFUSALS))
        overrides = {code: override for code, (_, override) in plan.REFUSALS.items()}
        self.assertEqual(overrides["R-FOREIGN"], "--adopt")
        self.assertEqual(overrides["R-VERIEXEC"], "--veriexec-not-enforcing-ok")
        self.assertEqual(overrides["R-MANAGED"], "--ack-managed")
        self.assertEqual(overrides["R-COMMIT-SCRIPTS"], "--ack-commit-scripts")
        self.assertEqual(overrides["R-PROVENANCE"], "--trust-release-page-only")
        self.assertEqual(overrides["R-MODEL"], plan.LAB_HARDWARE_FLAG)  # R5
        for code in ("R-NOHOST", "R-ROOT", "R-CLUSTER", "R-MNHA", "R-DUAL-RE", "R-PENDING", "R-BIND", "R-STATEDIR"):
            self.assertIsNone(overrides[code], code)

    def test_checks_as_data(self) -> None:
        self.assertEqual(set(plan.CHECKS), {"K1", "K2", *(f"C{n}" for n in range(1, 14))})
        self.assertEqual(plan.CHECKS["C1"].kind, "reserved")
        self.assertEqual(plan.CHECKS["C9"].kind, "retired")  # R3: ids stay stable
        self.assertEqual(plan.RETIRED_CHECKS, ("C9",))

    def test_cut_c1_setup_mode_is_not_planned(self) -> None:
        self.assertNotIn("use_setup_alias", {f.name for f in dataclasses.fields(plan.Options)})
        self.assertFalse(hasattr(plan, "SETUP_FILE"))
        self.assertNotIn("setup", plan.STAGE_NAMES)
        for name in s.scenario_names():
            install = s.plan_for(name, overrides=s.all_overrides(name))
            text = repr(install)
            self.assertNotIn("jwicket_setup.py", text, name)


class StatementSetTests(unittest.TestCase):
    """AC-006-01: exactly the statements of 7.3 for each method, backend, layout and prior state."""

    FRESH_DIAG = (
        "set system scripts language python3",
        f"set {EXT} jwicket_selftest.py username labadmin",
        f"set {EXT} jwicket_selftest.py checksum sha-256 {s.BUNDLE_SHA}",
        f"set {EXT} jwicket_probe.py username labadmin",
        f"set {EXT} jwicket_probe.py checksum sha-256 {s.BUNDLE_SHA}",
    )
    FRESH_RUNTIME = (
        f"set {EXT} jwicket.py daemonize",
        f"set {EXT} jwicket.py respawn-on-normal-exit",
        f"set {EXT} jwicket.py username labadmin",
        f"set {EXT} jwicket.py checksum sha-256 {s.BUNDLE_SHA}",
    )

    def test_workstation_fresh_direct(self) -> None:
        install = s.plan_for("python3-netconf-present")
        self.assertEqual(lines_of(install, "diagnostics"), self.FRESH_DIAG[1:])
        self.assertEqual(lines_of(install, "runtime"), self.FRESH_RUNTIME)
        install = s.plan_for("fresh-vsrx")
        self.assertEqual(lines_of(install, "diagnostics"), self.FRESH_DIAG)
        self.assertNotIn("set system services netconf ssh", lines_of(install, "diagnostics"))

    def test_cli_netconf_adds_netconf_in_diagnostics(self) -> None:
        install = s.plan_for("fresh-vsrx", method=plan.Method.CLI)
        self.assertEqual(lines_of(install, "diagnostics"), (*self.FRESH_DIAG, "set system services netconf ssh"))
        lab = s.plan_for("fresh-vsrx", method=plan.Method.CLI, backend="lab-token")
        self.assertEqual(lines_of(lab, "diagnostics"), self.FRESH_DIAG)

    def test_no_jet_checksum_drops_s3_s5_s13(self) -> None:
        install = s.plan_for("fresh-vsrx", jet_checksum=False)
        joined = "\n".join((*lines_of(install, "diagnostics"), *lines_of(install, "runtime")))
        self.assertNotIn("checksum", joined)
        self.assertIn("--no-jet-checksum", install.receipt.overrides)

    def test_group_layout_lines(self) -> None:
        install = s.plan_for("fresh-vsrx", layout=G)
        diag = lines_of(install, "diagnostics")
        self.assertEqual(diag[-1], "set apply-groups jwicket")
        for line in diag[:-1]:
            self.assertTrue(line.startswith("set groups jwicket system "), line)
        self.assertIn("GROUP_LAYOUT_WARNING", install.warnings)
        self.assertTrue(all(line.startswith("set groups jwicket ") for line in lines_of(install, "runtime")))

    def test_present_statements_are_not_added_and_recorded(self) -> None:
        install = s.plan_for("python3-netconf-present")
        self.assertIn("POSTURE_ALREADY_SET", install.warnings)
        self.assertNotIn("POSTURE_WARNING", install.warnings)
        self.assertEqual(install.receipt.statements_present_before, ("S1", "S8"))
        self.assertEqual(install.present_before, ("S1", "S8"))

    def test_idempotent_rerun_plans_nothing(self) -> None:
        install = s.plan_for("running-install")
        self.assertFalse(install.blocked)
        self.assertTrue(install.no_change)
        self.assertEqual(install.stages, ())
        self.assertEqual(install.final_files, ())
        self.assertEqual({c.id for c in install.status_checks}, {"C4", "C5", "C6", "C7", "C8"})
        tls_files = {f.path: f.action for f in install.files if f.content in ("tls-key", "tls-cert")}
        self.assertEqual(tls_files, {plan.TLS_KEY_PATH: "keep", plan.TLS_CERT_PATH: "keep"})
        self.assertEqual(install.receipt.tls_cert_sha256, s.CERT_SHA)  # the C8 pin of a re-run

    def test_half_finished_completes_the_missing_pieces(self) -> None:
        install = s.plan_for("half-finished")
        self.assertEqual({f.action for f in install.files if f.content == "bundle"}, {"keep"})
        self.assertEqual(lines_of(install, "runtime"), self.FRESH_RUNTIME)

    def test_on_box_url_removes_allow_url_in_runtime(self) -> None:
        facts, prior = s.facts_of("python3-netconf-present"), s.prior_of("python3-netconf-present")
        boot = plan.build_bootstrap(plan.Method.ONBOX_URL, s.options(), prior, None)
        assert boot is not None
        self.assertEqual(boot.keys, ("S9",))
        pending, delta = s.with_bootstrap(prior, boot)
        found = plan.recognise_bootstrap(
            pending, method=plan.Method.ONBOX_URL, user=s.USER, nonce=None, delta_text=delta
        )
        assert found is not None
        install = plan.build_install_plan(
            s.bundle(),
            s.provenance(),
            s.options(),
            facts,
            plan.mark_own_bootstrap(pending, found),
            method=plan.Method.ONBOX_URL,
        )
        self.assertIn("delete system scripts op allow-url-for-python", lines_of(install, "runtime"))
        self.assertIn("ALLOW_URL_WARNING", boot.warnings)

    def test_never_rendered_statements_absent_everywhere(self) -> None:
        for name in s.scenario_names():
            for method in (plan.Method.WORKSTATION, plan.Method.CLI):
                install = s.plan_for(name, method=method, overrides=s.all_overrides(name))
                for stage in install.stages:
                    for line in plan.stage_lines(stage, install.layout):
                        self.assertFalse(set(line.split()) & plan.NEVER_RENDERED, (name, line))

    def test_keep_diagnostics_false_removes_them_after_runtime(self) -> None:
        install = s.plan_for("fresh-vsrx", keep_diagnostics=False)
        runtime = install.stage("runtime")
        assert runtime is not None
        self.assertIn(f"delete {EXT} jwicket_selftest.py", plan.stage_lines(runtime, D))
        deleted = {f.path for f in runtime.files_after_confirm if f.action == "delete"}
        self.assertIn(f"{plan.JET_DIR}/jwicket_selftest.py", deleted)


class InverseTests(unittest.TestCase):
    """AC-006-03: install then uninstall on the configuration model gives the original back."""

    def test_every_fixture(self) -> None:
        for name in s.scenario_names():
            with self.subTest(name=name):
                self._check(name)

    def _check(self, name: str) -> None:
        facts, prior = s.prepared(name)
        overrides = s.all_overrides(name)
        original = prior.direct
        deltas = s.deltas_of(name)
        if prior.own_bootstrap is None and not prior.effective.under("system services netconf ssh"):
            boot = plan.build_bootstrap(plan.Method.WORKSTATION, s.options(), prior, s.NONCE)
            if boot is not None and prior.pending is plan.Pending.NONE:
                pending, delta = s.with_bootstrap(prior, boot)
                deltas = {k + 1: v for k, v in deltas.items()}
                deltas[0] = delta
                found = plan.recognise_bootstrap(
                    pending, method=plan.Method.WORKSTATION, user=s.USER, nonce=s.NONCE, delta_text=delta
                )
                self.assertIsNotNone(found)
                assert found is not None
                prior = plan.mark_own_bootstrap(pending, found)
        evidence = plan.ownership_from_history(prior.history, deltas, user=s.USER)
        install = plan.build_install_plan(
            s.bundle(),
            s.provenance(),
            s.options(),
            facts,
            prior,
            method=plan.Method.WORKSTATION,
            overrides=overrides,
            evidence=evidence,
        )
        if install.blocked:
            self.assertTrue(meta_refusals(name) - {"R-FOREIGN", "R-MANAGED", "R-COMMIT-SCRIPTS"}, name)
            return
        run = s.simulate_install(install, prior, deltas)
        after_evidence = plan.ownership_from_history(run.prior.history, run.deltas, user=s.USER)
        uplan = plan.build_uninstall_plan(
            after_evidence, facts, run.prior, method=plan.Method.WORKSTATION, remove_shared=True, overrides=overrides
        )
        self.assertFalse(uplan.blocked, [r.code for r in uplan.refusals])
        final = s.simulate_uninstall(uplan, run.prior)
        # The original model, less what scenario.json says a run cannot or must not give back (each with
        # its reason in "inverse_note"): adopted stanzas, a pending own bootstrap, an install already there.
        info = s.meta(name)
        prefixes = info.get("inverse_removed_prefixes", ())
        expected = {
            pair for pair in original.pairs if not any(pair[0] == pre or pair[0].startswith(pre) for pre in prefixes)
        }
        expected |= {tuple(pair) for pair in info.get("inverse_added", ())}
        self.assertEqual(final.pairs, expected, f"{name}: {info.get('inverse_note', 'exact inverse')}")
        removed_files = {f.path for f in uplan.files} | {f.path for st in uplan.stages for f in st.files_after_confirm}
        self.assertLessEqual({f.path for f in install.files if f.action in ("copy", "write")}, removed_files, name)

    def test_group_layout_inverse(self) -> None:
        facts, prior = s.prepared("python3-netconf-present")
        install = plan.build_install_plan(
            s.bundle(), s.provenance(), s.options(layout=G), facts, prior, method=plan.Method.WORKSTATION
        )
        run = s.simulate_install(install, prior, {})
        uplan = plan.build_uninstall_plan(
            plan.ownership_from_history(run.prior.history, run.deltas, user=s.USER),
            facts,
            run.prior,
            method=plan.Method.WORKSTATION,
        )
        self.assertEqual([st.name for st in uplan.stages], ["uninstall"])
        self.assertEqual(plan.stage_lines(uplan.stages[0], G), ("delete apply-groups jwicket", "delete groups jwicket"))
        self.assertEqual(s.simulate_uninstall(uplan, run.prior), prior.direct)


def meta_refusals(name: str) -> set:
    return set(s.meta(name).get("refusals", ()))


class ConfiguredPathTests(unittest.TestCase):
    """AC-006-04: INV-06 in check_invariants."""

    def setUp(self) -> None:
        self.prior = s.prior_of("upgrade")
        self.install = s.plan_for("upgrade")

    def test_upgrade_restores_by_copy_never_by_delete(self) -> None:
        plan.check_invariants(self.install, self.prior)
        configured = self.prior.configured_paths
        runtime = self.install.stage("runtime")
        assert runtime is not None
        self.assertEqual([f.action for f in runtime.files_before_commit], ["backup", "replace"])
        self.assertEqual(runtime.restore_on_failure[0].source, plan.BACKUP_PATH)
        for stage in self.install.stages:
            for step in stage.files_after_confirm:
                self.assertNotIn(step.path, configured)
        for step in self.install.files:
            if step.path in configured:
                self.assertEqual(step.action, "keep")

    def _broken(self, **stage_changes: object) -> plan.InstallPlan:
        runtime = self.install.stage("runtime")
        assert runtime is not None
        broken = dataclasses.replace(runtime, **stage_changes)  # type: ignore[arg-type]
        return dataclasses.replace(
            self.install, stages=tuple(broken if st.name == "runtime" else st for st in self.install.stages)
        )

    def test_replace_without_its_checksum_commit_is_rejected(self) -> None:
        runtime = self.install.stage("runtime")
        assert runtime is not None
        bad = self._broken(add=(), remove=())
        with self.assertRaises(plan.InvariantError):
            plan.check_invariants(bad, self.prior)

    def test_delete_of_a_configured_path_is_rejected(self) -> None:
        delete = plan.FileStep(plan.DAEMON_PATH, "any", 0o644, None, "delete", "post-confirm", stage="runtime")
        with self.assertRaises(plan.InvariantError):
            plan.check_invariants(self._broken(files_after_confirm=(delete,)), self.prior)

    def test_write_or_stage_onto_a_configured_path_is_rejected(self) -> None:
        for action in ("write", "copy", "stage"):
            step = plan.FileStep(plan.DAEMON_PATH, "bundle", 0o644, s.BUNDLE_SHA, action, "files")
            bad = dataclasses.replace(self.install, files=(*self.install.files, step))
            with self.subTest(action=action), self.assertRaises(plan.InvariantError):
                plan.check_invariants(bad, self.prior)

    def test_transfer_only_to_the_staging_name(self) -> None:
        step = plan.FileStep(plan.JET_DIR + "/other.py", "bundle", 0o644, s.BUNDLE_SHA, "stage", "files")
        bad = dataclasses.replace(self.install, files=(*self.install.files, step))
        with self.assertRaises(plan.InvariantError):
            plan.check_invariants(bad, self.prior)

    def test_restore_without_replace_is_rejected(self) -> None:
        diag = self.install.stage("diagnostics")
        assert diag is not None
        bad_diag = dataclasses.replace(diag, files_before_commit=())
        bad = dataclasses.replace(
            self.install, stages=(bad_diag, *(st for st in self.install.stages if st.name != "diagnostics"))
        )
        with self.assertRaises(plan.InvariantError):
            plan.check_invariants(bad, self.prior)

    def test_a_tampered_configured_file_is_refused_not_overwritten(self) -> None:
        prior = s.prior_of("running-install")
        tampered = dataclasses.replace(prior, checksums={**prior.checksums, plan.DAEMON_PATH: s.OLD_SHA})
        install = plan.build_install_plan(
            s.bundle(),
            s.provenance(),
            s.options(),
            s.facts_of("running-install"),
            tampered,
            method=plan.Method.WORKSTATION,
            evidence=s.evidence_of("running-install"),
        )
        self.assertIn("R-MISMATCH", [r.code for r in install.refusals])
        self.assertTrue(install.blocked)

    def test_unread_checksum_of_a_configured_file_refuses(self) -> None:
        prior = s.prior_of("running-install")
        missing = dataclasses.replace(prior, checksums={})
        install = plan.build_install_plan(
            s.bundle(),
            s.provenance(),
            s.options(),
            s.facts_of("running-install"),
            missing,
            method=plan.Method.WORKSTATION,
            evidence=s.evidence_of("running-install"),
        )
        self.assertIn("R-UNREADABLE", [r.code for r in install.refusals])

    def test_upgrade_without_checksum_is_refused(self) -> None:
        install = s.plan_for("upgrade", jet_checksum=False)
        self.assertIn("R-UPGRADE-NOCHECKSUM", [r.code for r in install.refusals])
        self.assertTrue(install.blocked)

    def test_every_unblocked_fixture_plan_passes(self) -> None:
        for name in s.scenario_names():
            install = s.plan_for(name, overrides=s.all_overrides(name))
            if not install.blocked:
                plan.check_invariants(install, s.prepared(name)[1])


class OwnershipTests(unittest.TestCase):
    """AC-006-05: shared statements removed only when the sources agree and nothing relies on them."""

    def _uninstall(self, name: str, **kw: object) -> plan.UninstallPlan:
        facts, prior = s.prepared(name)
        return plan.build_uninstall_plan(s.evidence_of(name, prior), facts, prior, method=plan.Method.WORKSTATION, **kw)  # type: ignore[arg-type]

    def test_history_and_receipt_agree(self) -> None:
        evidence = s.evidence_of("running-install")
        self.assertTrue(evidence.history_available)
        self.assertEqual(evidence.keys, {"S1", "S2", "S3", "S4", "S5", "S8", "S10", "S11", "S12", "S13"})
        uplan = self._uninstall("running-install")
        keys = [st.key for st in uplan.stages[0].remove]
        self.assertIn("S1", keys)
        self.assertEqual({k.key for k in uplan.kept}, {"S8"})
        self.assertIn("REMOVE_LANGUAGE_WARNING", uplan.warnings)

    def test_inflated_device_receipt_removes_nothing(self) -> None:
        uplan = self._uninstall("receipt-disagrees", remove_shared=True)
        keys = [st.key for stage in uplan.stages for st in stage.remove]
        self.assertNotIn("S1", keys)
        kept = {k.key: k.reason for k in uplan.kept}
        self.assertIn("present before install", kept["S1"])

    def test_device_receipt_alone_is_not_enough(self) -> None:
        facts, prior = s.prepared("running-install")
        no_ws = dataclasses.replace(prior, workstation_receipt=None)
        uplan = plan.build_uninstall_plan(
            plan.OwnershipEvidence.none(), facts, no_ws, method=plan.Method.WORKSTATION, remove_shared=True
        )
        self.assertNotIn("S1", [st.key for stage in uplan.stages for st in stage.remove])
        both = plan.build_uninstall_plan(
            plan.OwnershipEvidence.none(), facts, prior, method=plan.Method.WORKSTATION, remove_shared=True
        )
        self.assertIn("S1", [st.key for stage in both.stages for st in stage.remove])

    def test_language_kept_while_other_python_exists(self) -> None:
        facts, prior = s.prepared("running-install")
        other = s.prior_of("other-python")
        combined = dataclasses.replace(prior, files={**prior.files, **other.files})
        uplan = plan.build_uninstall_plan(
            s.evidence_of("running-install"), facts, combined, method=plan.Method.WORKSTATION
        )
        reason = {k.key: k.reason for k in uplan.kept}["S1"]
        self.assertIn("listed:/var/db/scripts/jet/helper.py", reason)

    def _s1_reason(self, prior: plan.PriorState) -> str:
        facts, _ = s.prepared("running-install")
        evidence = s.evidence_of("running-install")
        uplan = plan.build_uninstall_plan(evidence, facts, prior, method=plan.Method.WORKSTATION)
        return {k.key: k.reason for k in uplan.kept}.get("S1", "")

    def test_a_listed_event_python_script_keeps_the_language(self) -> None:
        """JF-07: the preflight lists /var/db/scripts/event too, and a *.py there keeps S1."""
        _, prior = s.prepared("running-install")
        listing = (
            "<rpc-reply><directory-list><directory><directory-name>/var/db/scripts/event</directory-name>"
            "<file-information><file-name>on-link.py</file-name><file-permissions format=\"-rw-r--r--\">644"
            "</file-permissions><file-owner>root</file-owner><file-size>10</file-size></file-information>"
            "</directory></directory-list></rpc-reply>"
        )
        with_event = state.prior_from_replies(
            None, None, None, {}, {}, None, script_lists={"/var/db/scripts/event": listing}
        )
        self.assertIn("listed:/var/db/scripts/event/on-link.py", with_event.other_python)
        combined = dataclasses.replace(
            prior,
            files={**prior.files, **with_event.files},
            directories={**prior.directories, **with_event.directories},
        )
        self.assertIn("listed:/var/db/scripts/event/on-link.py", self._s1_reason(combined))

    def test_a_configured_event_script_keeps_the_language(self) -> None:
        """JF-02: event scripts are configured under 'event-options event-script file'."""
        _, prior = s.prepared("running-install")
        pair = ("event-options event-script file on-link.py", "")
        configured = dataclasses.replace(prior, effective=plan.StatementSet.of(prior.effective.pairs | {pair}))
        self.assertIn("event:on-link.py", configured.configured_python)
        self.assertIn("/var/db/scripts/event/on-link.py", configured.configured_paths)
        self.assertIn("event:on-link.py", self._s1_reason(configured))

    def test_an_unreadable_script_directory_keeps_the_language_and_blocks_nothing(self) -> None:
        _, prior = s.prepared("running-install")
        unread = state.prior_from_replies(
            None, None, None, {}, {}, None, script_lists={"/var/db/scripts/commit": state.RpcErrorReply("denied")}
        )
        self.assertEqual(unread.directories["/var/db/scripts/commit"], "unreadable")
        self.assertNotIn("file list /var/db/scripts/commit", unread.unreadable)
        combined = dataclasses.replace(prior, directories={**prior.directories, **unread.directories})
        self.assertIn("unreadable:/var/db/scripts/commit", self._s1_reason(combined))

    def test_netconf_kept_without_remove_shared_and_refused_with_outbound(self) -> None:
        uplan = self._uninstall("running-install")
        self.assertNotIn("netconf-removal", [st.name for st in uplan.stages])
        removed = self._uninstall("running-install", remove_shared=True)
        self.assertEqual(removed.stages[-1].name, "netconf-removal")
        self.assertIn("REMOVE_NETCONF_WARNING", removed.warnings)
        facts, prior = s.prepared("running-install")
        outbound = s.prior_of("outbound-ssh")
        managed = dataclasses.replace(
            prior, effective=plan.StatementSet.of(prior.effective.pairs | outbound.effective.pairs)
        )
        uplan = plan.build_uninstall_plan(
            s.evidence_of("running-install"),
            facts,
            managed,
            method=plan.Method.WORKSTATION,
            remove_shared=True,
            overrides=frozenset({"--ack-managed"}),
        )
        self.assertNotIn("netconf-removal", [st.name for st in uplan.stages])

    def test_present_before_never_in_an_uninstall(self) -> None:
        facts, prior = s.prepared("python3-netconf-present")
        install = plan.build_install_plan(
            s.bundle(), s.provenance(), s.options(), facts, prior, method=plan.Method.WORKSTATION
        )
        run = s.simulate_install(install, prior, {})
        uplan = plan.build_uninstall_plan(
            plan.ownership_from_history(run.prior.history, run.deltas, user=s.USER),
            facts,
            run.prior,
            method=plan.Method.WORKSTATION,
            remove_shared=True,
        )
        removed = {st.key for stage in uplan.stages for st in stage.remove}
        self.assertFalse(removed & {"S1", "S8"})

    def test_forged_history_without_the_record_removes_nothing_shared(self) -> None:
        facts, prior = s.prepared("python3-netconf-present")
        entry = plan.CommitEntry(
            0, s.USER, "cli", f"jwicket 0.1.0.dev1 sha256:{s.BUNDLE_SHA[:12]} diagnostics lab-install", None, ""
        )
        forged = dataclasses.replace(prior, history=(entry,))
        evidence = plan.ownership_from_history(
            forged.history, {0: "[edit system scripts]\n+    language python3;\n"}, user=s.USER
        )
        self.assertIn("S1", evidence.keys)
        uplan = plan.build_uninstall_plan(evidence, facts, forged, method=plan.Method.WORKSTATION)
        self.assertNotIn("S1", {st.key for stage in uplan.stages for st in stage.remove})

    def test_jwicket_stanzas_removed_whole_and_files_after(self) -> None:
        uplan = self._uninstall("running-install")
        stage = uplan.stages[0]
        self.assertEqual(stage.post_confirm_checks[0].id, "C13")
        deletes = {f.path for f in stage.files_after_confirm if f.action == "delete"}
        self.assertIn(plan.DAEMON_PATH, deletes)
        self.assertNotIn(plan.JET_DIR + "/nc_grpc_app", deletes)
        self.assertIn(f"delete {EXT} jwicket.py", plan.stage_lines(stage, D))

    def test_unknown_file_keeps_the_directory(self) -> None:
        facts, prior = s.prepared("running-install")
        extra = plan.FileInfo(plan.STATE_DIR + "/notes.txt", "labadmin", 0o600, 10)
        uplan = plan.build_uninstall_plan(
            s.evidence_of("running-install"),
            facts,
            dataclasses.replace(prior, files={**prior.files, extra.path: extra}),
            method=plan.Method.WORKSTATION,
        )
        actions = {(f.action, f.path) for st in uplan.stages for f in st.files_after_confirm}
        self.assertNotIn(("rmdir", plan.STATE_DIR), actions)
        self.assertEqual(uplan.leftovers, (extra.path,))

    def test_half_finished_uninstall_removes_files_only(self) -> None:
        uplan = self._uninstall("half-finished")
        self.assertEqual(uplan.stages, ())
        self.assertIn(plan.DAEMON_PATH, {f.path for f in uplan.files})
        self.assertEqual(uplan.file_checks[0].id, "C13")


class ValidationTests(unittest.TestCase):
    """AC-006-06: hostile inputs are refused before anything is rendered."""

    def test_hostile_user_names(self) -> None:
        for user in (
            "lab admin",
            "lab'admin",
            'lab"admin',
            "lab;admin",
            "lab\nadmin",
            "",
            "1admin",
            "a" * 40,
            "{{x}}",
            "lab$admin",
            "../etc",
        ):
            with self.subTest(user=user), self.assertRaises(plan.InputError):
                s.options(user=user)

    def test_root_is_a_refusal(self) -> None:
        install = s.plan_for("python3-netconf-present", user="root")
        self.assertIn("R-ROOT", [r.code for r in install.refusals])
        self.assertTrue(install.blocked)

    def test_urls(self) -> None:
        good = "https://github.com/o/r/releases/download/v0.1.0.dev1/jwicket.py"
        s.options(transfer="file-copy", pull_url=good)
        for url in (
            "https://user:pw@github.com/x.py",
            "https://github.com/x.py?a=b",
            "https://github.com/x.py#f",
            "ftp://github.com/x.py",
            "https://github.com/x y.py",
            "https://github.com/" + "a" * 600,
            "https://github.com/{{x}}.py",
        ):
            with self.subTest(url=url), self.assertRaises(plan.InputError):
                s.options(transfer="file-copy", pull_url=url)
        with self.assertRaises(plan.InputError):
            s.options(transfer="file-copy", pull_url="http://lab.example/jwicket.py")
        s.options(transfer="file-copy", pull_url="http://lab.example/jwicket.py", allow_plain_http=True)

    def test_hashes_ports_and_cert_file(self) -> None:
        for bad in ("A" * 64, "1" * 63, "g" * 64, "1" * 64 + "\n"):
            with self.subTest(sha=bad), self.assertRaises(plan.InputError):
                s.bundle(sha=bad)
        for port in (-1, 80, 1023, 65536, True):
            with self.subTest(port=port), self.assertRaises(plan.InputError):
                s.options(port=port)
        self.assertEqual(s.options(port=0).port, plan.DEFAULT_TLS_PORT)  # 0: the access mode's default
        self.assertEqual(s.options(access="tunnel").port, plan.DEFAULT_PORT)
        for minutes in (2, 31):
            with self.assertRaises(plan.InputError):
                s.options(confirm_minutes=minutes)
        url = "https://lab.example/jwicket.py"
        for cert in ("/etc/ca.pem", "/var/db/jwicket/../x.pem", "relative.pem", "/var/db/jwicket/a b.pem"):
            with self.subTest(cert=cert), self.assertRaises(plan.InputError):
                s.options(transfer="refresh-from", pull_url=url, cert_file=cert)
        with self.assertRaises(plan.InputError):
            s.options(transfer="refresh-from", pull_url=url)
        s.options(transfer="refresh-from", pull_url=url, cert_file="/var/db/jwicket/lab-ca.pem")

    def test_remove_netconf_needs_lab_token(self) -> None:
        with self.assertRaises(plan.InputError):
            s.options(remove_netconf_after=True)
        self.assertTrue(s.options(backend="lab-token").remove_netconf)
        self.assertFalse(s.options().remove_netconf)

    def test_bundle_header(self) -> None:
        head = (
            '#!/usr/bin/env python3\n"""J-Wicket single-file bundle. GENERATED by tools/bundle.py\n\n'
            "jwicket version: 0.1.0.dev1\nsource ref:      not recorded\n"
            f"payload sha256:  {s.PAYLOAD_SHA}\nfeatures:        result-files, build-line\n"
        )
        found = plan.BundleId.from_header(head, s.BUNDLE_SHA, 1000)
        self.assertEqual(found.version, "0.1.0.dev1")
        self.assertIsNone(found.source_ref)
        self.assertEqual(found.features, frozenset({"result-files", "build-line"}))
        old = plan.BundleId.from_header(
            head.replace("features:        result-files, build-line\n", ""), s.BUNDLE_SHA, 1
        )
        self.assertEqual(old.features, frozenset())
        with self.assertRaises(plan.InputError):
            plan.BundleId.from_header("jwicket version: 0.1.0.dev1\n", s.BUNDLE_SHA, 1)
        with self.assertRaises(plan.InputError):
            plan.BundleId.from_header(head.replace("0.1.0.dev1", "0.1 {{x}}"), s.BUNDLE_SHA, 1)
        with self.assertRaises(plan.InputError):
            plan.BundleId.from_header(head, s.BUNDLE_SHA, plan.MAX_BUNDLE_SIZE + 1)

    def test_device_text_never_reaches_statements(self) -> None:
        with self.assertRaises(plan.InputError):
            plan.make_statement("S12", "runtime", value="lab admin")
        with self.assertRaises(plan.InputError):
            plan.DeviceFacts("bad host;", "vsrx", None, None, False, False, None, False)
        facts = plan.DeviceFacts.of(hostname="bad host;", model="vsrx", srx_cluster=False)
        self.assertIsNone(facts.hostname)

    def test_unknown_override_and_ztp(self) -> None:
        facts, prior = s.prepared("fresh-vsrx")
        with self.assertRaises(plan.InputError):
            plan.build_install_plan(
                s.bundle(),
                s.provenance(),
                s.options(),
                facts,
                prior,
                method=plan.Method.WORKSTATION,
                overrides=frozenset({"--yolo"}),
            )
        with self.assertRaises(plan.InputError):
            plan.build_install_plan(s.bundle(), s.provenance(), s.options(), facts, prior, method=plan.Method.ZTP)


class RefusalTests(unittest.TestCase):
    """AC-006-06: each refusal of 8.11 fires on its fixture with its code and override."""

    def test_each_fixture_refuses_as_described(self) -> None:
        for name in s.scenario_names():
            with self.subTest(name=name):
                install = s.plan_for(name)
                codes = {r.code for r in install.refusals}
                self.assertEqual(codes, set(s.meta(name).get("refusals", ())), name)
                needs = s.meta(name).get("needs")
                if needs:
                    overridden = s.plan_for(name, overrides=needs)
                    self.assertFalse(overridden.blocked, name)
                    self.assertTrue(all(r.overridden for r in overridden.refusals))

    def test_veriexec_provenance_release_and_dual_re(self) -> None:
        facts, prior = s.prepared("python3-netconf-present")

        def build(**kw: object) -> plan.InstallPlan:
            values = {
                "bundle": s.bundle(),
                "provenance": s.provenance(),
                "options": s.options(),
                "facts": facts,
                "prior": prior,
            }
            values.update(kw)
            return plan.build_install_plan(
                values["bundle"],
                values["provenance"],
                values["options"],  # type: ignore[arg-type]
                values["facts"],
                values["prior"],
                method=plan.Method.WORKSTATION,  # type: ignore[arg-type]
                overrides=frozenset(kw.get("overrides", ())),
            )  # type: ignore[arg-type]

        weak = dataclasses.replace(prior, veriexec="loaded active")
        self.assertEqual({r.code for r in build(prior=weak).refusals}, {"R-VERIEXEC"})
        ok = build(prior=weak, overrides=("--veriexec-not-enforcing-ok",))
        self.assertFalse(ok.blocked)
        self.assertTrue(ok.receipt.not_evidence)
        self.assertIn("VERIEXEC_WARNING", ok.warnings)
        unread = dataclasses.replace(prior, veriexec=None)
        self.assertIn("R-VERIEXEC", {r.code for r in build(prior=unread).refusals})
        page = build(provenance=s.provenance("release-page-only"))
        self.assertEqual({r.code for r in page.refusals}, {"R-PROVENANCE"})
        stamped = build(provenance=s.provenance("release-page-only"), overrides=("--trust-release-page-only",))
        self.assertFalse(stamped.blocked)
        self.assertTrue(stamped.receipt.not_evidence)
        old = dataclasses.replace(facts, junos_version="20.4R3.8")
        url = "https://lab.example/jwicket.py"
        refresh = s.options(transfer="refresh-from", pull_url=url, cert_file="/var/db/jwicket/lab-ca.pem")
        self.assertIn("R-RELEASE", {r.code for r in build(facts=old, options=refresh).refusals})
        self.assertNotIn("R-RELEASE", {r.code for r in build(options=refresh).refusals})
        dual = dataclasses.replace(facts, routing_engines=2)
        self.assertIn("R-DUAL-RE", {r.code for r in build(facts=dual).refusals})

    def test_root_owned_files_and_foreign_user(self) -> None:
        facts, prior = s.prepared("half-finished")
        info = prior.files[plan.DAEMON_PATH]
        rooted = dataclasses.replace(prior, files={**prior.files, info.path: dataclasses.replace(info, owner="root")})
        install = plan.build_install_plan(
            s.bundle(), s.provenance(), s.options(), facts, rooted, method=plan.Method.WORKSTATION
        )
        self.assertIn("R-ROOT", {r.code for r in install.refusals})
        other = s.plan_for("running-install", user="otheradmin")
        self.assertIn("R-USER", {r.code for r in other.refusals})

    def test_a_stanza_username_alone_is_r_user(self) -> None:
        """SC-16 (RF7): files owned by --user, but one stanza names another account."""
        facts, prior = s.prepared("running-install")
        key = " ".join((*plan.STANZA_KEYS["F-SELFTEST"], "username"))
        pairs = {pair for pair in prior.effective.pairs if pair[0] != key} | {(key, "otheradmin")}
        changed = dataclasses.replace(prior, effective=plan.StatementSet.of(pairs))
        own = [prior.files[f"{plan.JET_DIR}/{name}"] for name in plan.JWICKET_JET_FILES]
        self.assertTrue(all(info.owner == s.USER for info in own))
        install = plan.build_install_plan(
            s.bundle(), s.provenance(), s.options(), facts, changed, method=plan.Method.WORKSTATION,
            evidence=s.evidence_of("running-install", changed),
        )
        reasons = [r.detail for r in install.refusals if r.code == "R-USER"]
        self.assertEqual(len(reasons), 1, install.refusals)
        self.assertIn("username otheradmin", reasons[0])

    def test_untrusted_state_directory(self) -> None:
        facts, prior = s.prepared("running-install")
        listed = prior.files[plan.STATE_DIR]
        for bad in (
            dataclasses.replace(listed, mode=0o770),
            dataclasses.replace(listed, mode=0o755),  # R4: mode 0700, not only "not writable by others"
            dataclasses.replace(listed, owner="admin"),
            dataclasses.replace(listed, owner="root"),
            dataclasses.replace(listed, is_symlink=True),
            dataclasses.replace(listed, is_dir=False),
        ):
            changed = dataclasses.replace(prior, files={**prior.files, plan.STATE_DIR: bad})
            install = plan.build_install_plan(
                s.bundle(),
                s.provenance(),
                s.options(),
                facts,
                changed,
                method=plan.Method.WORKSTATION,
                evidence=s.evidence_of("running-install"),
            )
            with self.subTest(bad=bad):
                self.assertIn("R-STATEDIR", {r.code for r in install.refusals})
                self.assertTrue(install.blocked)
        text = plan.directory_fallback(s.USER)
        self.assertIn("'mkdir -m 700 /var/db/jwicket && chown labadmin /var/db/jwicket'", text)
        self.assertNotIn("su root", text)  # R4: the installer never asks for the root password
        self.assertIn("never asks for the root password", text)

    def test_unreadable_commit_state_refuses(self) -> None:
        install = s.plan_for("unreadable-commit")
        self.assertEqual([r.detail for r in install.refusals], ["commit state: unreadable"])


class GateTests(unittest.TestCase):
    """AC-006-07: the gate compares with the device's own host name, exactly."""

    def test_matching(self) -> None:
        facts = s.facts_of("fresh-vsrx")
        self.assertEqual(facts.hostname, s.HOST)
        self.assertTrue(plan.lab_gate_matches(s.HOST, facts))
        self.assertTrue(plan.lab_gate_matches(f"  {s.HOST}\n", facts))
        for typed in ("", "   ", None, s.HOST.upper(), s.HOST + "x", "lab-vsrx", "\n"):
            self.assertFalse(plan.lab_gate_matches(typed, facts), typed)
        self.assertFalse(plan.lab_gate_matches("", plan.DeviceFacts.unknown()))
        self.assertFalse(plan.lab_gate_matches(s.HOST, s.facts_of("no-hostname")))

    def test_no_hostname_refuses(self) -> None:
        self.assertEqual({r.code for r in s.plan_for("no-hostname").refusals}, {"R-NOHOST"})

    def test_host_name_not_in_pre_gate_outputs(self) -> None:
        from install_support import plan as _plan  # noqa: F401 - same module

        from jwicket_install import render

        install = s.plan_for("python3-netconf-present")
        prior = s.prior_of("python3-netconf-present")
        self.assertNotIn(s.HOST, render.plan_to_json(install))
        self.assertNotIn(s.HOST, render.render_plan_text(install, prior))
        self.assertNotIn(s.HOST, "\n".join(install.production_signs))


class SettingsTests(unittest.TestCase):
    """AC-006-08: render_settings passes the daemon's own parser, for both access modes (R2)."""

    def test_netconf_and_lab_token(self) -> None:
        for backend in ("netconf", "lab-token"):
            for port in (8443, 9443):
                text = plan.render_settings(s.options(backend=backend, port=port, access="tunnel"))
                parsed = jwicket_settings.parse_settings(text)
                self.assertEqual(parsed.server.bind, "127.0.0.1")
                self.assertTrue(parsed.server.loopback)
                self.assertFalse(parsed.server.tls_enabled)
                self.assertEqual(parsed.server.port, port)
                self.assertEqual(parsed.server.allowed_hosts, (f"127.0.0.1:{port}", f"localhost:{port}"))
                self.assertEqual(parsed.auth.backend, backend)
                self.assertEqual(str(parsed.log.file), plan.LOG_PATH)
                self.assertEqual(str(parsed.log.audit_file), plan.AUDIT_PATH)
                if backend == "lab-token":
                    self.assertEqual(str(parsed.auth.lab_token_file), plan.LAB_TOKEN_PATH)

    def test_tls(self) -> None:
        for routing_instance in (None, plan.MGMT_INSTANCE):
            for address, host in ((s.LISTEN, f"{s.LISTEN}:9443"), ("2001:db8::10", "[2001:db8::10]:9443")):
                options = s.options(listen_address=address)
                text = plan.render_settings(options, routing_instance=routing_instance)
                parsed = jwicket_settings.parse_settings(text)
                with self.subTest(address=address, routing_instance=routing_instance):
                    self.assertEqual(parsed.server.bind, address)
                    self.assertFalse(parsed.server.loopback)
                    self.assertTrue(parsed.server.tls_enabled)
                    self.assertEqual(str(parsed.server.tls_cert), plan.TLS_CERT_PATH)
                    self.assertEqual(str(parsed.server.tls_key), plan.TLS_KEY_PATH)
                    self.assertEqual(parsed.server.port, 9443)
                    self.assertEqual(parsed.server.allowed_hosts, (host,))
                    self.assertEqual(parsed.server.routing_instance, routing_instance)
                    self.assertEqual(parsed.auth.backend, "netconf")
        with self.assertRaises(plan.InputError):
            plan.render_settings(s.options(), routing_instance="other")
        with self.assertRaises(plan.InputError):
            plan.render_settings(s.options(access="tunnel"), routing_instance=plan.MGMT_INSTANCE)

    def test_no_parameter_changes_the_bind(self) -> None:
        """INV-10: the bind is 127.0.0.1 (tunnel) or the validated listen address (tls), nothing else; the
        only routing instance rendered is mgmt_junos, which the plan derives from the configuration."""
        import inspect

        self.assertEqual(list(inspect.signature(plan.render_settings).parameters), ["options", "routing_instance"])
        fields = {f.name for f in dataclasses.fields(plan.Options)}
        self.assertFalse(fields & {"bind", "listen", "address", "routing_instance", "tls_cert", "tls_key"})
        self.assertEqual(s.options(access="tunnel").bind_address, plan.LOOPBACK)
        self.assertEqual(s.options().bind_address, s.LISTEN)

    def test_deterministic(self) -> None:
        self.assertEqual(plan.settings_sha256(s.options()), plan.settings_sha256(s.options()))
        self.assertNotEqual(plan.settings_sha256(s.options()), plan.settings_sha256(s.options(port=8443)))
        self.assertNotEqual(
            plan.settings_sha256(s.options()), plan.settings_sha256(s.options(), routing_instance=plan.MGMT_INSTANCE)
        )


class BootstrapTests(unittest.TestCase):
    """AC-006-11: only the own bootstrap is recognised; every near miss is R-PENDING."""

    def test_netconf_bootstrap_built_when_absent(self) -> None:
        boot = plan.build_bootstrap(plan.Method.WORKSTATION, s.options(), None, s.NONCE)
        assert boot is not None
        self.assertEqual(boot.comment, "jwicket-bootstrap netconf k3v9qt")
        self.assertEqual(boot.keys, ("S8",))
        self.assertEqual(boot.minutes, 10)
        self.assertIn("NETCONF_WARNING", boot.warnings)
        self.assertIsNone(
            plan.build_bootstrap(plan.Method.WORKSTATION, s.options(), s.prior_of("python3-netconf-present"), s.NONCE)
        )
        with self.assertRaises(plan.InputError):
            plan.build_bootstrap(plan.Method.WORKSTATION, s.options(), None, None)
        with self.assertRaises(plan.InputError):
            plan.build_bootstrap(plan.Method.CLI, s.options(), None, None)

    def test_op_bootstrap(self) -> None:
        boot = plan.build_bootstrap(plan.Method.ONBOX_LOCAL, s.options(), None, None, op_sha256=s.OP_SHA)
        assert boot is not None
        self.assertEqual(boot.keys, ("S1", "S14"))
        self.assertEqual(boot.comment, "jwicket-bootstrap op")
        self.assertIn("POSTURE_WARNING", boot.warnings)
        known = plan.build_bootstrap(
            plan.Method.ONBOX_LOCAL, s.options(), s.prior_of("python3-netconf-present"), None, op_sha256=s.OP_SHA
        )
        assert known is not None
        self.assertEqual(known.keys, ("S14",))

    def test_own_bootstrap_recognised(self) -> None:
        prior = s.prior_of("own-bootstrap")
        self.assertIs(prior.pending, plan.Pending.OTHER)
        delta = s.deltas_of("own-bootstrap")[0]
        self.assertTrue(
            plan.own_bootstrap_pending(
                prior, method=plan.Method.WORKSTATION, user=s.USER, nonce=s.NONCE, delta_text=delta
            )
        )
        install = s.plan_for("own-bootstrap")
        first = install.stages[0]
        self.assertEqual(first.name, "bootstrap")
        self.assertTrue(first.already_committed)
        self.assertEqual(first.check_ids, ("K1", "K2", "C10", "C11"))
        self.assertEqual(first.confirm_comment, "jwicket-bootstrap netconf k3v9qt confirmed")
        self.assertEqual(install.receipt.bootstrap_added, ("S8",))

    def test_near_misses_are_pending(self) -> None:
        for name in ("near-miss-other-user", "near-miss-other-nonce", "near-miss-extra-line", "pending-other-user"):
            prior = s.prior_of(name)
            delta = s.deltas_of(name).get(0, "")
            with self.subTest(name=name):
                self.assertFalse(
                    plan.own_bootstrap_pending(
                        prior, method=plan.Method.WORKSTATION, user=s.USER, nonce=s.NONCE, delta_text=delta
                    )
                )
                self.assertIn("R-PENDING", {r.code for r in s.plan_for(name).refusals})

    def test_other_shapes_never_match(self) -> None:
        prior = s.prior_of("own-bootstrap")
        delta = s.deltas_of("own-bootstrap")[0]
        rec = plan.recognise_bootstrap
        method = plan.Method.WORKSTATION
        self.assertIsNone(rec(prior, method=method, user=s.USER, nonce="aaaaaa", delta_text=delta))
        self.assertIsNone(rec(prior, method=method, user=s.USER, nonce=s.NONCE, delta_text=""))
        self.assertIsNone(
            rec(
                prior,
                method=method,
                user=s.USER,
                nonce=s.NONCE,
                delta_text=delta.replace("+    netconf", "-    netconf"),
            )
        )
        self.assertIsNone(rec(prior, method=method, user=s.USER, nonce=s.NONCE, delta_text=delta + "garbage\n"))
        self.assertIsNone(rec(prior, method=plan.Method.ONBOX_LOCAL, user=s.USER, nonce=None, delta_text=delta))
        scheduled = dataclasses.replace(prior, scheduled_commit=True)
        self.assertIsNone(rec(scheduled, method=method, user=s.USER, nonce=s.NONCE, delta_text=delta))
        not_pending = dataclasses.replace(prior, pending=plan.Pending.NONE)
        self.assertIsNone(rec(not_pending, method=method, user=s.USER, nonce=s.NONCE, delta_text=delta))

    def test_bootstrap_units_never_confirm(self) -> None:
        from jwicket_install import render

        for method, nonce, op in (
            (plan.Method.WORKSTATION, s.NONCE, None),
            (plan.Method.ONBOX_LOCAL, None, s.OP_SHA),
            (plan.Method.ONBOX_URL, None, None),
        ):
            boot = plan.build_bootstrap(method, s.options(), None, nonce, op_sha256=op)
            assert boot is not None
            units = render.render_bootstrap_units(boot, follow_up=("jwicket-install install --apply",))
            lines = [line for unit in units for line in unit.lines]
            commits = [line for line in lines if line.startswith("commit")]
            self.assertEqual(len(commits), 1, method)
            self.assertTrue(commits[0].startswith(f"commit confirmed {boot.minutes} comment "))
            self.assertNotIn("commit check", "\n".join(lines))


class RevertTests(unittest.TestCase):
    """Spec 8.8: the revert stage removes exactly what this run's confirmed stages added."""

    def test_revert_after_diagnostics(self) -> None:
        install = s.plan_for("fresh-vsrx")
        stage = plan.build_revert_stage(install, ("diagnostics",))
        self.assertEqual(stage.name, "revert")
        self.assertEqual(
            plan.stage_lines(stage, D),
            ("delete system scripts language", f"delete {EXT} jwicket_selftest.py", f"delete {EXT} jwicket_probe.py"),
        )
        self.assertEqual(stage.check_ids, ("C12", "C10", "C11"))
        deleted = [f.path for f in stage.files_after_confirm]
        self.assertIn(plan.DAEMON_PATH, deleted)
        self.assertIn(plan.TLS_KEY_PATH, deleted)
        self.assertNotIn(plan.STATE_DIR, deleted)  # R4: root's directory, never removed by the installer
        self.assertEqual({f.action for f in stage.files_after_confirm}, {"delete"})
        model = plan.apply_lines(plan.StatementSet(), lines_of(install, "diagnostics"))
        self.assertEqual(plan.apply_lines(model, plan.stage_lines(stage, D)), plan.StatementSet())

    def test_present_before_is_never_reverted(self) -> None:
        install = s.plan_for("python3-netconf-present")
        stage = plan.build_revert_stage(install, ("diagnostics",))
        self.assertNotIn("delete system scripts language", plan.stage_lines(stage, D))

    def test_bootstrap_only_when_asked(self) -> None:
        install = s.plan_for("own-bootstrap")
        without = plan.build_revert_stage(install, ("bootstrap", "diagnostics"))
        self.assertNotIn("delete system services netconf ssh", plan.stage_lines(without, D))
        with_boot = plan.build_revert_stage(install, ("bootstrap", "diagnostics"), include_bootstrap=True)
        self.assertIn("delete system services netconf ssh", plan.stage_lines(with_boot, D))
        with self.assertRaises(plan.InputError):
            plan.build_revert_stage(install, ("uninstall",))

    def test_an_upgrade_has_no_revert_stage(self) -> None:
        """OPD-06: deleting an upgrade's changed checksums would leave the diagnostic copies unpinned."""
        upgrade = s.plan_for("upgrade")
        self.assertTrue(upgrade.upgrade)
        with self.assertRaises(plan.PlanError):
            plan.build_revert_stage(upgrade, ("diagnostics",))

    def test_an_unreadable_text_diff_is_outside_the_plan(self) -> None:
        """SC-01: no text diff (None or empty) while a stage changes something fails the header check."""
        install = s.plan_for("python3-netconf-present")
        diag = install.stage("diagnostics")
        assert diag is not None
        for diff in (None, "", "  \n"):
            with self.subTest(diff=diff):
                self.assertEqual(plan.headers_outside(diag, D, diff), (plan.UNREADABLE_DIFF,))
        empty = dataclasses.replace(diag, add=(), remove=())
        self.assertEqual(plan.headers_outside(empty, D, None), ())


class PatchTests(unittest.TestCase):
    """The model, the patch parser and the structural and header checks (SC-06, 8.7)."""

    def test_patch_round_trip(self) -> None:
        before = s.prior_of("python3-netconf-present").direct
        install = s.plan_for("python3-netconf-present")
        model = before
        for stage in install.stages:
            after = plan.apply_lines(model, plan.stage_lines(stage, D))
            delta = plan.parse_patch(plan.patch_text(model, after))
            self.assertEqual(delta.problems, ())
            self.assertEqual(delta.added, after.pairs - model.pairs)
            self.assertEqual(delta.removed, model.pairs - after.pairs)
            model = after

    def test_compare_text_groups_new_levels_and_round_trips(self) -> None:
        """JFR-02: Junos prints a new level as a braced block under the deepest level that exists (its
        NETCONF guide's '[edit interfaces]' + 'ge-1/0/1 { ... }' sample); parse_patch reads it back exactly."""
        cases = []
        for name, layout in (("fresh-vsrx", D), ("python3-netconf-present", D), ("fresh-vsrx", G)):
            model = s.prior_of(name).direct
            for stage in s.plan_for(name, layout=layout).stages:
                after = plan.apply_lines(model, plan.stage_lines(stage, layout))
                cases.append((f"{name}/{layout.value}/{stage.name}", model, after))
                model = after
        facts, uprior = s.prepared("running-install")
        uplan = plan.build_uninstall_plan(
            s.evidence_of("running-install", uprior), facts, uprior, method=plan.Method.CLI, remove_shared=True
        )
        model = uprior.direct
        for stage in uplan.stages:
            after = plan.apply_lines(model, plan.stage_lines(stage, uplan.layout))
            cases.append((f"uninstall/{stage.name}", model, after))
            model = after
        for label, before, after in cases:
            with self.subTest(label):
                for assumed in ((), plan.ASSUMED_LEVELS):
                    delta = plan.parse_patch(plan.compare_text(before, after, assumed=assumed))
                    self.assertEqual(delta.problems, ())
                    self.assertEqual(delta.added, after.pairs - before.pairs)
                    self.assertEqual(delta.removed, before.pairs - after.pairs)
        fresh = plan.StatementSet.of({("system services ssh", ""), (f"{EXT} other.py username", "x")})
        lines = [
            f"set {EXT} jwicket.py daemonize",
            f"set {EXT} jwicket.py username {s.USER}",
            "set system services netconf ssh",
        ]
        text = plan.compare_text(fresh, plan.apply_lines(fresh, lines))
        self.assertEqual(
            text.splitlines(),
            [
                "[edit system services]",
                "+    netconf {",
                "+        ssh;",
                "+    }",
                "[edit system extensions extension-service application]",
                "+    file jwicket.py {",
                "+        daemonize;",
                f"+        username {s.USER};",
                "+    }",
            ],
        )
        removed = plan.compare_text(plan.apply_lines(fresh, lines), fresh)
        self.assertIn("-    file jwicket.py {", removed.splitlines())  # a whole entry deleted: the same, with '-'
        self.assertEqual(plan.compare_text(fresh, fresh), "")

    def test_compare_text_prints_in_configuration_order(self) -> None:
        """The illustrative comparison follows the SRX schema's order (junos-es-conf-system 23.2R1: system
        lists scripts, services, extensions; scripts lists op before language; scripts op lists file before
        allow-url-for-python; an extension-service file lists checksum before daemonize, respawn-on-normal-
        exit and username), then the plan's render order (selftest, probe, daemon; groups, apply-groups),
        never alphabetically or leaves first. The lines are given in reverse, so input order cannot help."""
        from jwicket_install import render

        sha, op_sha, new_sha = "a" * 64, "b" * 64, "c" * 64
        base = plan.StatementSet.of({("system host-name", "lab-vsrx"), ("system services ssh", "")})
        lines = [
            "set system services netconf ssh",
            f"set {EXT} {plan.DAEMON_FILE} username {s.USER}",
            f"set {EXT} {plan.DAEMON_FILE} respawn-on-normal-exit",
            f"set {EXT} {plan.DAEMON_FILE} daemonize",
            f"set {EXT} {plan.DAEMON_FILE} checksum sha-256 {sha}",
            f"set {EXT} {plan.PROBE_FILE} username {s.USER}",
            f"set {EXT} {plan.SELFTEST_FILE} username {s.USER}",
            "set system scripts op allow-url-for-python",
            f"set system scripts op file {plan.OP_FILE} checksum sha-256 {op_sha}",
            "set system scripts language python3",
        ]
        after = plan.apply_lines(base, lines)
        self.assertEqual(
            plan.compare_text(base, after).splitlines(),
            [
                "[edit system]",
                "+    scripts {",
                "+        op {",
                f"+            file {plan.OP_FILE} {{",
                "+                checksum {",
                f"+                    sha-256 {op_sha};",
                "+                }",
                "+            }",
                "+            allow-url-for-python;",
                "+        }",
                "+        language python3;",
                "+    }",
                "+    extensions {",
                "+        extension-service {",
                "+            application {",
                f"+                file {plan.SELFTEST_FILE} {{",
                f"+                    username {s.USER};",
                "+                }",
                f"+                file {plan.PROBE_FILE} {{",
                f"+                    username {s.USER};",
                "+                }",
                f"+                file {plan.DAEMON_FILE} {{",
                "+                    checksum {",
                f"+                        sha-256 {sha};",
                "+                    }",
                "+                    daemonize;",
                "+                    respawn-on-normal-exit;",
                f"+                    username {s.USER};",
                "+                }",
                "+            }",
                "+        }",
                "+    }",
                "[edit system services]",
                "+    netconf {",
                "+        ssh;",
                "+    }",
            ],
        )
        # Headers follow their first change: with no 'scripts' change, 'services' comes before 'extensions'.
        no_scripts = plan.apply_lines(base, [line for line in lines if " scripts " not in line])
        headers = [line for line in plan.compare_text(base, no_scripts).splitlines() if line.startswith("[")]
        self.assertEqual(headers, ["[edit system services]", "[edit system]"])
        # A value change: the removed line just before the line that replaces it, in the schema's order.
        changes = [
            f"set {EXT} {plan.DAEMON_FILE} username lab2",
            f"set {EXT} {plan.DAEMON_FILE} checksum sha-256 {new_sha}",
        ]
        upgraded = plan.apply_lines(after, changes)
        self.assertEqual(
            plan.compare_text(after, upgraded).splitlines(),
            [
                f"[edit system extensions extension-service application file {plan.DAEMON_FILE} checksum]",
                f"-    sha-256 {sha};",
                f"+    sha-256 {new_sha};",
                f"[edit system extensions extension-service application file {plan.DAEMON_FILE}]",
                f"-    username {s.USER};",
                "+    username lab2;",
            ],
        )
        # The group layout orders the same way under 'groups jwicket', and 'apply-groups' follows 'groups'.
        group_lines = [line.replace("set system", "set groups jwicket system") for line in lines[1:5]]
        grouped = plan.apply_lines(base, [*group_lines, "set apply-groups jwicket"])
        text = plan.compare_text(base, grouped).splitlines()
        self.assertEqual(text[:3], ["[edit]", "+    groups {", "+        jwicket {"])
        self.assertEqual(text[-1], "+    apply-groups jwicket;")
        names = ("checksum", "daemonize", "respawn-on-normal-exit", "username")
        order = [line.strip("+ ;{") for line in text if line.strip("+ ;{").split(" ")[0] in names]
        self.assertEqual(order, ["checksum", "daemonize", "respawn-on-normal-exit", f"username {s.USER}"])
        # Every rendering reads back exactly, and the rule that introduces the blocks still says illustrative.
        for old, new in ((base, after), (after, base), (after, upgraded), (base, grouped)):
            delta = plan.parse_patch(plan.compare_text(old, new))
            self.assertEqual(delta.problems, ())
            self.assertEqual((delta.added, delta.removed), (new.pairs - old.pairs, old.pairs - new.pairs))
        self.assertIn("illustrative", render.COMPARE_KNOWN)

    def test_nested_blocks_parse(self) -> None:
        delta = plan.parse_patch(s.deltas_of("running-install")[3])
        self.assertEqual(delta.problems, ())
        self.assertIn(("system scripts language", "python3"), delta.added)
        self.assertIn((f"{EXT} jwicket_probe.py checksum sha-256", s.BUNDLE_SHA), delta.added)

    def test_structural_check(self) -> None:
        install = s.plan_for("python3-netconf-present")
        diag = install.stage("diagnostics")
        assert diag is not None
        before = s.prior_of("python3-netconf-present").direct
        after = plan.apply_lines(before, plan.stage_lines(diag, D))
        self.assertEqual(plan.structural_unexpected(diag, D, before, after), ())
        extra = plan.StatementSet.of(after.pairs | {(f"{EXT} jwicket_probe.py optional", "")})
        self.assertEqual(
            plan.structural_unexpected(diag, D, before, extra), (f"unexpected + {EXT} jwicket_probe.py optional",)
        )
        missing = plan.StatementSet.of(after.pairs - {(f"{EXT} jwicket_probe.py username", s.USER)})
        self.assertTrue(plan.structural_unexpected(diag, D, before, missing)[0].startswith("missing +"))
        changed = plan.StatementSet.of(after.pairs - {("system scripts language", "python3")})
        self.assertTrue(plan.structural_unexpected(diag, D, before, changed)[0].startswith("unexpected -"))

    def test_headers_outside(self) -> None:
        install = s.plan_for("fresh-vsrx")
        diag = install.stage("diagnostics")
        assert diag is not None
        ok = plan.patch_text(plan.StatementSet(), plan.apply_lines(plan.StatementSet(), plan.stage_lines(diag, D)))
        self.assertEqual(plan.headers_outside(diag, D, ok), ())
        nested_ok = "[edit system]\n+   scripts {\n+       language python3;\n+   }\n"
        self.assertEqual(plan.headers_outside(diag, D, nested_ok), ())
        sneaky = "[edit system]\n+   login {\n+       user eve {\n+           class super-user;\n+       }\n+   }\n"
        self.assertTrue(plan.headers_outside(diag, D, sneaky))
        outside = "[edit security policies]\n+    default-policy permit-all;\n"
        self.assertEqual(
            plan.headers_outside(diag, D, outside),
            ("header [edit security policies]", "line + security policies default-policy permit-all"),
        )
        self.assertTrue(
            plan.headers_outside(
                diag, D, "[edit system scripts]\n+  /* hidden */ language python3;\n" "+ inactive: op;\n"
            )
        )
        self.assertTrue(plan.headers_outside(diag, D, "+ language python3;\n"))

    def test_group_expansion_equals_direct(self) -> None:
        for name in ("fresh-vsrx", "python3-netconf-present", "half-finished"):
            direct = s.plan_for(name)
            group = s.plan_for(name, layout=G)
            base = s.prior_of(name).direct
            d_model, g_model = base, base
            for d_stage, g_stage in zip(direct.stages, group.stages):
                d_model = plan.apply_lines(d_model, plan.stage_lines(d_stage, D))
                g_model = plan.apply_lines(g_model, plan.stage_lines(g_stage, G))
            self.assertEqual(plan.expand_groups(g_model), plan.expand_groups(d_model), name)
            self.assertNotEqual(g_model, d_model)

    def test_confirm_allowed(self) -> None:
        self.assertTrue(plan.confirm_allowed(239, 5))
        self.assertTrue(plan.confirm_allowed(240, 5))
        self.assertFalse(plan.confirm_allowed(241, 5))
        self.assertFalse(plan.confirm_allowed(-1, 5))

    def test_installer_comments(self) -> None:
        for comment in (
            "jwicket 0.1.0.dev1 sha256:1f1f1f1f1f1f diagnostics lab-install",
            "jwicket-bootstrap netconf k3v9qt",
            "jwicket-bootstrap op confirmed",
            "jwicket uninstall lab-install",
            "jwicket uninstall netconf confirmed",
            plan.rollback_now_comment(s.bundle()),
        ):
            self.assertTrue(plan.is_installer_comment(comment), comment)
            self.assertLessEqual(len(comment), 100)
        for comment in ("jwicket", "jwicket-bootstrap netconf K3V9QT", "{{ lookup('pipe','id') }}", None):
            self.assertFalse(plan.is_installer_comment(comment))


class AccessTests(unittest.TestCase):
    """Revision R2: --access tls (default) and --access tunnel; R3: C8 pinned HTTPS, C9 retired."""

    def test_defaults_and_validation(self) -> None:
        options = s.options()
        self.assertEqual((options.access, options.port, options.listen_address), ("tls", 9443, s.LISTEN))
        bare = plan.Options(user=s.USER)  # enough for a bootstrap, which never listens
        self.assertEqual((bare.access, bare.port), ("tls", 9443))
        self.assertIsNotNone(plan.build_bootstrap(plan.Method.WORKSTATION, bare, None, s.NONCE))
        facts, prior = s.prepared("fresh-vsrx")
        for needs_address in (
            lambda: plan.build_install_plan(
                s.bundle(), s.provenance(), bare, facts, prior, method=plan.Method.WORKSTATION
            ),
            lambda: plan.render_settings(bare),
            lambda: bare.bind_address,
        ):
            with self.assertRaises(plan.InputError):
                needs_address()
        self.assertEqual(plan.Options(user=s.USER, backend="lab-token").access, "tunnel")
        for bad in ("192.0.2.010", "2001:DB8::1", "lab-srx-1", "", "192.0.2.10 ", "fe80::1%fxp0"):
            with self.subTest(address=bad), self.assertRaises(plan.InputError):
                s.options(listen_address=bad)
        with self.assertRaises(plan.InputError):
            s.options(access="tunnel", listen_address=s.LISTEN)
        with self.assertRaises(plan.InputError):
            s.options(access="tls", backend="lab-token")  # the daemon refuses a shared token off loopback
        with self.assertRaises(plan.InputError):
            s.options(access="ssh")
        self.assertEqual(plan.default_listen_address("192.0.2.10"), "192.0.2.10")
        self.assertIsNone(plan.default_listen_address("lab-srx-1"))
        self.assertIsNone(plan.default_listen_address(None))

    def test_wildcard_loopback_and_others_are_r_bind(self) -> None:
        wildcard = ".".join(["0"] * 4)  # the address R-BIND exists for, built so no linter mistakes it for a bind
        for address in (wildcard, "::", "127.0.0.1", "::1", "224.0.0.1", "169.254.1.1", "fe80::1", "240.0.0.1"):
            install = s.plan_for("python3-netconf-present", listen_address=address)
            with self.subTest(address=address):
                self.assertEqual({r.code for r in install.refusals}, {"R-BIND"})
                self.assertTrue(install.blocked)

    def test_an_ipv6_listen_address_is_r_bind(self) -> None:
        """SEC-R3, SPEC-07: INV-10 and 8.10 take IPv4 only (as --host and the Ansible play)."""
        for address in ("2001:db8::1", "fd00::1"):
            install = s.plan_for("python3-netconf-present", listen_address=address)
            with self.subTest(address=address):
                self.assertEqual({r.code for r in install.refusals}, {"R-BIND"})
                self.assertIn("an IPv6 address", install.refusals[0].detail)
        loopback = s.plan_for("python3-netconf-present", listen_address="127.0.0.1")
        self.assertIn("loopback", loopback.refusals[0].detail)  # OPX-13: the detail names the address's class

    def test_routing_instance_follows_the_management_instance(self) -> None:
        self.assertTrue(s.prior_of("management-instance").management_instance)
        self.assertFalse(s.prior_of("fresh-vsrx").management_instance)
        mgmt = s.plan_for("management-instance")
        self.assertEqual(mgmt.routing_instance, plan.MGMT_INSTANCE)
        self.assertIn("routing_instance = mgmt_junos", mgmt.settings_text)
        settings = next(f for f in mgmt.files if f.content == "settings")
        self.assertEqual(settings.sha256, plan.settings_sha256(mgmt.options, routing_instance=plan.MGMT_INSTANCE))
        self.assertIsNone(s.plan_for("management-instance", access="tunnel").routing_instance)
        self.assertIsNone(s.plan_for("fresh-vsrx").routing_instance)
        self.assertEqual(mgmt.receipt.routing_instance, plan.MGMT_INSTANCE)

    def test_extension_service_routing_instance_is_never_rendered(self) -> None:
        """Verified ineffective for the listener on SRX4100: only [server] routing_instance moves it."""
        self.assertIn("routing-instance", plan.NEVER_RENDERED)
        for name in ("management-instance", "lab-srx4100"):
            install = s.plan_for(name, overrides=s.all_overrides(name))
            for stage in install.stages:
                for line in plan.stage_lines(stage, install.layout):
                    self.assertNotIn("routing-instance", line)
                    self.assertNotIn("management-instance", line)

    def test_tls_files(self) -> None:
        install = s.plan_for("fresh-vsrx")
        steps = {f.content: f for f in install.files if f.content in ("tls-key", "tls-cert")}
        key, cert = steps["tls-key"], steps["tls-cert"]
        self.assertEqual((key.path, key.mode, key.sha256, key.action), (plan.TLS_KEY_PATH, 0o600, None, "write"))
        self.assertEqual((cert.path, cert.mode, cert.action), (plan.TLS_CERT_PATH, 0o644, "write"))
        self.assertEqual(key.source, "in-memory")
        self.assertEqual(s.plan_for("fresh-vsrx", method=plan.Method.CLI).files[-2].source, "device-openssl")
        self.assertIn(plan.TLS_KEY_PATH, install.receipt.files_created)
        tunnel = s.plan_for("fresh-vsrx", access="tunnel")
        self.assertFalse([f for f in tunnel.files if f.content in ("tls-key", "tls-cert")])
        moved = s.plan_for("running-install", listen_address="192.0.2.20")  # a new address: a new certificate
        self.assertEqual({f.action for f in moved.files if f.content in ("tls-key", "tls-cert")}, {"write"})
        self.assertIsNone(moved.receipt.tls_cert_sha256)
        with self.assertRaises(plan.InputError):
            plan.receipt_for_run(install)  # a new certificate's SHA-256 belongs in the receipt
        receipt = plan.receipt_for_run(install, tls_cert_sha256=s.CERT_SHA)
        self.assertEqual(plan.Receipt.from_json(receipt.to_json()).tls_cert_sha256, s.CERT_SHA)
        self.assertEqual(plan.fingerprint_display(s.CERT_SHA)[:8], "5B:5B:5B")

    def test_the_key_never_enters_the_plan(self) -> None:
        install = s.plan_for("fresh-vsrx")
        bad_key = dataclasses.replace(
            install,
            files=tuple(
                dataclasses.replace(f, sha256=s.CERT_SHA) if f.content == "tls-key" else f for f in install.files
            ),
        )
        with self.assertRaises(plan.InvariantError):
            plan.check_invariants(bad_key, s.prepared("fresh-vsrx")[1])

    def test_c8_pinned_https_and_c9_retired(self) -> None:
        for method in (plan.Method.WORKSTATION, plan.Method.CLI):
            install = s.plan_for("python3-netconf-present", method=method)
            runtime = install.stage("runtime")
            assert runtime is not None
            c8 = next(c for c in runtime.checks if c.id == "C8")
            with self.subTest(method=method):
                self.assertEqual(c8.expect["url"], f"https://{s.LISTEN}:9443/api/session")
                self.assertEqual(c8.expect["host"], f"{s.LISTEN}:9443")
                self.assertEqual(c8.expect["pin"], "tls_cert_sha256")
                self.assertEqual(c8.expect["build"], s.PAYLOAD_SHA[:16])
                self.assertEqual(c8.required, method is plan.Method.WORKSTATION)
                expected = "fail" if method is plan.Method.WORKSTATION else "by-hand"
                self.assertEqual(c8.expect["if_unavailable"], expected)
                self.assertNotIn("C9", runtime.check_ids)
        tunnel = s.plan_for("python3-netconf-present", access="tunnel").stage("runtime")
        assert tunnel is not None
        c8 = next(c for c in tunnel.checks if c.id == "C8")
        self.assertEqual(
            (c8.target, c8.expect["if_unavailable"], c8.required), ("not-available", "not-available", False)
        )
        for name in s.scenario_names():
            install = s.plan_for(name, overrides=s.all_overrides(name))
            ids = {c.id for st in install.stages for c in st.checks} | {c.id for c in install.status_checks}
            self.assertFalse(ids & set(plan.RETIRED_CHECKS), name)

    def test_c3_requires_ssl_with_tls(self) -> None:
        diag = s.plan_for("fresh-vsrx").stage("diagnostics")
        assert diag is not None
        c3 = next(c for c in diag.checks if c.id == "C3")
        self.assertIn("ssl", c3.expect["modules"].split(","))
        self.assertEqual(c3.expect["recorded"], "")
        tunnel = s.plan_for("fresh-vsrx", access="tunnel").stage("diagnostics")
        assert tunnel is not None
        c3 = next(c for c in tunnel.checks if c.id == "C3")
        self.assertNotIn("ssl", c3.expect["modules"].split(","))
        self.assertEqual(c3.expect["recorded"], "ssl")

    def test_posture_warning_per_access_mode(self) -> None:
        tls = s.plan_for("fresh-vsrx")
        self.assertIn("TLS_POSTURE_WARNING", tls.warnings)
        self.assertNotIn("TUNNEL_WARNING", tls.warnings)
        tunnel = s.plan_for("fresh-vsrx", access="tunnel")
        self.assertIn("TUNNEL_WARNING", tunnel.warnings)
        self.assertNotIn("TLS_POSTURE_WARNING", tunnel.warnings)
        text = plan.TLS_POSTURE_WARNING
        for needed in ("new HTTPS listener", "management address", "reachable by anything that reaches that address",
                       "gate G1", "security review (Q-SEC-01)"):
            self.assertIn(needed, text)
        for needed in ("administratively prohibited", "'set system services ssh tcp-forwarding' is a syntax error",
                       "25.2R1-S1.4"):
            self.assertIn(needed, plan.TUNNEL_WARNING)
        self.assertIn("NETCONF_NOT_CHECKED", tls.warnings)


class TlsRenewalTests(unittest.TestCase):
    """SEC-R1 and OPX-04: a rerun keeps the recorded TLS pair only while the device's tls.crt is the file this
    installer recorded (its SHA-256) and the certificate is more than TLS_RENEW_DAYS from its notAfter;
    otherwise it plans a new pair, says why, and (no runtime commit) that J-Wicket must restart (OPX-05)."""

    NAME = "running-install"

    def _plan(self, prior: plan.PriorState, now: Optional[str]) -> plan.InstallPlan:
        return plan.build_install_plan(
            s.bundle(),
            s.provenance(),
            s.options(),
            s.facts_of(self.NAME),
            prior,
            method=plan.Method.WORKSTATION,
            evidence=s.evidence_of(self.NAME, prior),
            now=now,
        )

    @staticmethod
    def _tls(install: plan.InstallPlan) -> dict[str, str]:
        return {f.path: f.action for f in install.files if f.content in ("tls-key", "tls-cert")}

    def test_a_recorded_valid_pair_is_kept_with_its_dates(self) -> None:
        prior = s.prior_of(self.NAME)
        self.assertEqual(prior.checksums[plan.TLS_CERT_PATH], s.CERT_FILE_SHA)
        install = self._plan(prior, "2098-12-01T00:00:00Z")
        self.assertEqual(self._tls(install), {plan.TLS_KEY_PATH: "keep", plan.TLS_CERT_PATH: "keep"})
        self.assertTrue(install.no_change)
        for warning in ("TLS_RENEW_EXPIRY", "TLS_RENEW_CHANGED", "RESTART_NEEDED"):
            self.assertNotIn(warning, install.warnings)
        self.assertEqual(
            (install.receipt.tls_cert_sha256, install.receipt.tls_cert_not_after, install.receipt.tls_cert_file_sha256),
            (s.CERT_SHA, s.CERT_NOT_AFTER, s.CERT_FILE_SHA),
        )

    def test_a_certificate_near_or_past_its_not_after_is_renewed(self) -> None:
        for now in ("2098-12-20T00:00:00Z", "2099-01-01T00:00:00Z", "2099-03-01T00:00:00Z"):
            with self.subTest(now=now):
                install = self._plan(s.prior_of(self.NAME), now)
                self.assertEqual(self._tls(install), {plan.TLS_KEY_PATH: "write", plan.TLS_CERT_PATH: "write"})
                self.assertIn("TLS_RENEW_EXPIRY", install.warnings)
                self.assertIn("RESTART_NEEDED", install.warnings)  # no runtime commit restarts J-Wicket
                self.assertIsNone(install.receipt.tls_cert_sha256)  # the run's new certificate goes in
                self.assertFalse(install.no_change)

    def test_a_tls_crt_that_is_not_the_recorded_file_is_replaced(self) -> None:
        prior = s.prior_of(self.NAME)
        other = dict(prior.checksums)
        other[plan.TLS_CERT_PATH] = "7c" * 32  # remade on the box with 'openssl req', for example
        unread = dict(prior.checksums)
        del unread[plan.TLS_CERT_PATH]
        no_dates = dataclasses.replace(
            prior,
            workstation_receipt=dataclasses.replace(
                prior.workstation_receipt, tls_cert_not_after=None, tls_cert_file_sha256=None
            ),
        )
        for label, case in (
            ("other file", dataclasses.replace(prior, checksums=other)),
            ("unread", dataclasses.replace(prior, checksums=unread)),
            ("record without dates", no_dates),
        ):
            with self.subTest(label):
                install = self._plan(case, "2098-12-01T00:00:00Z")
                self.assertEqual(self._tls(install), {plan.TLS_KEY_PATH: "write", plan.TLS_CERT_PATH: "write"})
                self.assertIn("TLS_RENEW_CHANGED", install.warnings)
                self.assertIn("RESTART_NEEDED", install.warnings)

    def test_expiry_helpers(self) -> None:
        now = "2026-11-25T00:00:00Z"
        self.assertIsNone(plan.certificate_expiry(None, now))
        self.assertIsNone(plan.certificate_expiry("2027-02-23T00:00:00Z", now))
        self.assertIn("expires on 2026-12-01T00:00:00Z", str(plan.certificate_expiry("2026-12-01T00:00:00Z", now)))
        self.assertIn("expired on 2026-11-24T00:00:00Z", str(plan.certificate_expiry("2026-11-24T00:00:00Z", now)))
        self.assertTrue(plan.certificate_expired("2026-11-25T00:00:00Z", now))
        self.assertFalse(plan.certificate_expired("2026-11-26T00:00:00Z", now))
        self.assertFalse(plan.certificate_expired(None, now))
        with self.assertRaises(plan.InputError):
            plan.certificate_expiry("2026-12-01 00:00:00", now)

    def test_the_receipt_validates_and_round_trips_the_dates(self) -> None:
        record = s.prior_of(self.NAME).workstation_receipt
        assert record is not None
        self.assertEqual(plan.Receipt.from_json(record.to_json()), record)
        for bad in (
            {"tls_cert_not_after": "2099-01-01"},
            {"tls_cert_file_sha256": "zz"},
            {"tls_cert_sha256": None},  # dates without the fingerprint they belong to
        ):
            with self.subTest(bad=bad), self.assertRaises(plan.InputError):
                dataclasses.replace(record, **bad)
        with self.assertRaises(plan.InputError):
            dataclasses.replace(
                record, access="tunnel", listen_address=None, tls_cert_sha256=None, tls_cert_file_sha256=None
            )  # a tunnel record with a notAfter


class StateDirectoryTests(unittest.TestCase):
    """Revision R4: root makes /var/db/jwicket once; the installer reads, refuses, never creates."""

    def test_absent_is_r_statedir_with_the_root_step(self) -> None:
        install = s.plan_for("absent-paths")
        refusal = next(r for r in install.refusals if r.code == "R-STATEDIR")
        self.assertIsNone(refusal.override)
        self.assertIn("mkdir -m 700 /var/db/jwicket && chown labadmin /var/db/jwicket", refusal.detail)
        self.assertTrue(install.blocked)
        self.assertEqual(install.directory.action if install.directory else None, "require")
        self.assertEqual(
            plan.state_dir_root_step(s.USER), "mkdir -m 700 /var/db/jwicket && chown labadmin /var/db/jwicket"
        )

    def test_trusted_directory_is_kept_and_nothing_makes_one(self) -> None:
        self.assertNotIn("mkdir", plan.FILE_ACTIONS)
        self.assertNotIn("rmdir", plan.FILE_ACTIONS)
        self.assertFalse(hasattr(plan, "cli_file_make_directory"))
        for name in s.scenario_names():
            install = s.plan_for(name, overrides=s.all_overrides(name))
            with self.subTest(name=name):
                assert install.directory is not None
                expected = "require" if "R-STATEDIR" in {r.code for r in install.refusals} else "keep"
                self.assertEqual(install.directory.action, expected)
                self.assertFalse(install.receipt.state_dir_created)
                every = [*install.files, *(f for st in install.stages for f in (*st.files_before_commit,
                                                                               *st.files_after_confirm))]
                self.assertFalse([f for f in every if f.path == plan.STATE_DIR])
        self.assertEqual(s.plan_for("fresh-vsrx").directory, plan.FileStep(
            plan.STATE_DIR, "directory", 0o700, None, "keep", "files", owner=s.USER))

    def test_an_invariant_rejects_a_directory_step(self) -> None:
        install = s.plan_for("fresh-vsrx")
        made = dataclasses.replace(install, directory=dataclasses.replace(install.directory, action="mkdir"))  # type: ignore[arg-type]
        with self.assertRaises(plan.InvariantError):
            plan.check_invariants(made, s.prepared("fresh-vsrx")[1])

    def test_uninstall_leaves_the_directory_for_root(self) -> None:
        facts, prior = s.prepared("running-install")
        evidence = s.evidence_of("running-install")
        uplan = plan.build_uninstall_plan(evidence, facts, prior, method=plan.Method.WORKSTATION)
        self.assertTrue(uplan.state_dir_left)
        self.assertIn("STATE_DIR_LEFT", uplan.warnings)
        actions = {f.action for st in uplan.stages for f in st.files_after_confirm}
        self.assertEqual(actions, {"delete"})
        deleted = {f.path for st in uplan.stages for f in st.files_after_confirm}
        self.assertLessEqual({plan.TLS_KEY_PATH, plan.TLS_CERT_PATH}, deleted)
        self.assertNotIn(plan.STATE_DIR, deleted)


class HardwareTests(unittest.TestCase):
    """Revision R5: R-MODEL refuses anything but vSRX unless --lab-hardware, which adds 'lab only'."""

    def test_uninstall_of_the_srx4100_reference_case_needs_ack_managed(self) -> None:
        """SPEC-06: the removal on the R5 reference case (SD Cloud over outbound-ssh) is R-MANAGED without
        --ack-managed, refused before any write; with it (and --lab-hardware) it proceeds."""
        name = "lab-srx4100"
        facts, prior = s.prepared(name)
        evidence = s.evidence_of(name, prior)
        self.assertTrue(prior.outbound_ssh_clients)
        refused = plan.build_uninstall_plan(
            evidence, facts, prior, method=plan.Method.WORKSTATION, overrides=frozenset({plan.LAB_HARDWARE_FLAG})
        )
        self.assertIn("R-MANAGED", {r.code for r in refused.refusals if not r.overridden})
        self.assertTrue(refused.blocked)
        allowed = plan.build_uninstall_plan(
            evidence,
            facts,
            prior,
            method=plan.Method.WORKSTATION,
            overrides=frozenset({plan.LAB_HARDWARE_FLAG, "--ack-managed"}),
        )
        self.assertNotIn("R-MANAGED", {r.code for r in allowed.refusals if not r.overridden})
        self.assertFalse(allowed.blocked, [r.code for r in allowed.refusals if not r.overridden])

    def test_physical_srx_needs_the_flag(self) -> None:
        blocked = s.plan_for("physical-srx345")
        self.assertEqual({r.code for r in blocked.refusals}, {"R-MODEL"})
        self.assertTrue(blocked.blocked)
        self.assertFalse(blocked.lab_hardware)
        allowed = s.plan_for("physical-srx345", overrides=(plan.LAB_HARDWARE_FLAG,))
        self.assertFalse(allowed.blocked)
        self.assertTrue(allowed.lab_hardware)
        self.assertIn("LAB_HARDWARE_WARNING", allowed.warnings)
        self.assertIn(plan.LAB_HARDWARE_FLAG, allowed.receipt.overrides)
        with self.assertRaises(plan.InputError):
            plan.receipt_for_run(allowed, tls_cert_sha256=s.CERT_SHA)  # no attestation yet
        receipt = plan.receipt_for_run(allowed, tls_cert_sha256=s.CERT_SHA, lab_hardware_attested=True)
        self.assertTrue(plan.Receipt.from_json(receipt.to_json()).lab_hardware_attested)
        vsrx = s.plan_for("fresh-vsrx", overrides=(plan.LAB_HARDWARE_FLAG,))
        self.assertFalse(vsrx.lab_hardware)

    def test_the_flag_never_lets_a_non_srx_through(self) -> None:
        blocked = s.plan_for("cluster-rpc-error", overrides=(plan.LAB_HARDWARE_FLAG,))
        self.assertTrue(blocked.blocked)
        self.assertIn("does not apply", next(r.detail for r in blocked.refusals if r.code == "R-MODEL"))
        facts, prior = s.prepared("fresh-vsrx")
        for model in ("mx480", "ex4300", "qfx5120", None):
            other = plan.build_install_plan(
                s.bundle(), s.provenance(), s.options(), dataclasses.replace(facts, model=model), prior,
                method=plan.Method.WORKSTATION, overrides=frozenset({plan.LAB_HARDWARE_FLAG}),
            )
            with self.subTest(model=model):
                self.assertTrue(other.blocked)
                self.assertFalse(other.lab_hardware)

    def test_cluster_mnha_and_dual_re_still_refuse(self) -> None:
        facts, prior = s.prepared("physical-srx345")
        flag = frozenset({plan.LAB_HARDWARE_FLAG})

        def codes(**changes: object) -> set:
            built = plan.build_install_plan(
                s.bundle(), s.provenance(), s.options(), dataclasses.replace(facts, **changes), prior,  # type: ignore[arg-type]
                method=plan.Method.WORKSTATION, overrides=flag,
            )
            return {r.code for r in built.refusals if not r.overridden}

        self.assertEqual(codes(srx_cluster=True), {"R-CLUSTER"})
        self.assertEqual(codes(mnha=True), {"R-MNHA"})
        self.assertEqual(codes(routing_engines=2), {"R-DUAL-RE"})
        self.assertEqual(codes(routing_engines=None), {"R-DUAL-RE"})  # unknown on hardware: fail closed
        self.assertEqual(codes(), set())

    def test_the_srx4100_reference_case(self) -> None:
        """The recorded lab SRX4100: Security Director Cloud over outbound-ssh, management-instance."""
        name = "lab-srx4100"
        facts = s.facts_of(name)
        self.assertEqual((facts.model, facts.junos_version, facts.srx_cluster), ("srx4100", "25.2R1-S1.4", False))
        install = s.plan_for(name, overrides=s.all_overrides(name))
        self.assertFalse(install.blocked)
        self.assertTrue(install.lab_hardware)
        self.assertEqual(install.routing_instance, plan.MGMT_INSTANCE)
        self.assertTrue(install.upgrade)  # its files are the lab run's bundle
        signs = "\n".join(install.production_signs)
        for needed in ("model: srx4100", "release: 25.2R1-S1.4", "serial: FIXTURE-SN-4100", "active flow sessions: 40",
                       "outbound-ssh client: sd-cloud", "committers: labadmin, sd-cloud", "last commit: 2026-11-24"):
            self.assertIn(needed, signs)
        self.assertEqual(install.present_before, ("S1", "S8"))
        for override in ("--ack-managed", "--adopt"):
            without = s.plan_for(name, overrides=[o for o in s.all_overrides(name) if o != override])
            self.assertTrue(without.blocked, override)

    def test_lab_only_must_be_typed_exactly(self) -> None:
        self.assertTrue(plan.lab_hardware_matches("lab only"))
        self.assertTrue(plan.lab_hardware_matches("  lab only\n"))
        for typed in ("Lab only", "lab-only", "labonly", "yes", "", None, "lab only!", "lab  only"):
            self.assertFalse(plan.lab_hardware_matches(typed), typed)
        self.assertIn("'lab only'", plan.LAB_HARDWARE_PROMPT)
        self.assertNotIn(s.HOST, plan.LAB_HARDWARE_PROMPT)

    def test_uninstall_on_hardware(self) -> None:
        facts, prior = s.prepared("physical-srx345")
        evidence = s.evidence_of("physical-srx345", prior)
        blocked = plan.build_uninstall_plan(evidence, facts, prior, method=plan.Method.WORKSTATION)
        self.assertIn("R-MODEL", {r.code for r in blocked.refusals if not r.overridden})
        allowed = plan.build_uninstall_plan(
            evidence, facts, prior, method=plan.Method.WORKSTATION, overrides=frozenset({plan.LAB_HARDWARE_FLAG})
        )
        self.assertFalse(allowed.blocked)
        self.assertTrue(allowed.lab_hardware)


class UninstallCommitterTests(unittest.TestCase):
    """SC-04: the uninstall stages' C11 names the committing account, as the install stages' do."""

    def test_c11_has_the_user(self) -> None:
        facts, prior = s.prepared("running-install")
        evidence = s.evidence_of("running-install")
        uplan = plan.build_uninstall_plan(evidence, facts, prior, method=plan.Method.WORKSTATION, remove_shared=True)
        for stage in uplan.stages:
            c11 = next(c for c in stage.checks if c.id == "C11")
            self.assertEqual(c11.expect["newest_user"], s.USER, stage.name)
            self.assertEqual(c11.expect["newest_comment"], stage.comment)
        other = plan.build_uninstall_plan(evidence, facts, prior, method=plan.Method.WORKSTATION, user="otheradmin")
        self.assertEqual(next(c for c in other.stages[0].checks if c.id == "C11").expect["newest_user"], "otheradmin")
        self.assertEqual(other.user, "otheradmin")
        no_record = dataclasses.replace(prior, workstation_receipt=None, device_receipt=None)
        bare = plan.build_uninstall_plan(evidence, facts, no_record, method=plan.Method.WORKSTATION)
        for stage in bare.stages:
            self.assertNotIn("newest_user", next(c for c in stage.checks if c.id == "C11").expect)
        with self.assertRaises(plan.InputError):
            plan.build_uninstall_plan(evidence, facts, prior, method=plan.Method.WORKSTATION, user="bad user")


INSTALLER_DIR = s.TOOLS / "jwicket_install"
# Names that do not exist at run time on Python 3.7 (revision R1). typing's are allowed only under
# 'if TYPE_CHECKING:'; the attributes are flagged wherever they are used.
PY38_TYPING = frozenset({"Protocol", "Literal", "Final", "TypedDict", "Annotated", "get_origin", "get_args",
                         "ParamSpec", "TypeAlias", "Concatenate", "TypeGuard", "SupportsIndex", "runtime_checkable"})
PY38_ATTRIBUTES = frozenset({"removeprefix", "removesuffix", "cached_property", "prod", "isqrt", "readlink",
                             "bit_count", "is_relative_to", "with_stem", "fmean", "geometric_mean", "unlink_missing"})
PY38_FUNCTOOLS = frozenset({"cached_property", "cache", "singledispatchmethod"})
SELF_DOCUMENTING = re.compile(r"(?<!\{)\{\s*[^{}'\"!:=<>]+?\s*=\s*[}!:]")


def _type_checking_lines(tree: ast.AST) -> set:
    lines = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and isinstance(node.test, ast.Name) and node.test.id == "TYPE_CHECKING":
            for inner in node.body:
                for sub in ast.walk(inner):
                    if hasattr(sub, "lineno"):
                        lines.add(sub.lineno)
    return lines


BUILTIN_GENERICS = frozenset({"list", "dict", "tuple", "set", "frozenset", "type"})


def _annotation_nodes(tree: ast.AST) -> set:
    """ids of every node inside an annotation (never evaluated under 'from __future__ import annotations')."""
    roots = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.returns is not None:
            roots.append(node.returns)
        if isinstance(node, ast.arg) and node.annotation is not None:
            roots.append(node.annotation)
        if isinstance(node, ast.AnnAssign):
            roots.append(node.annotation)
    return {id(inner) for root in roots for inner in ast.walk(root)}


def py37_problems(source: str, name: str) -> list:
    """What would fail on Python 3.7. ast.parse(feature_version=(3, 7)) is best effort and differs between
    interpreters (3.8 and 3.9 accept ':=' and '/', 3.13 accepts f"{x=}"), so the grammar is checked here
    too: assignment expressions, positional-only parameters, the f-string '=' specifier; then the run-time
    names: typing's newer names outside TYPE_CHECKING, functools.cached_property, str.removeprefix, dict
    union, zip(strict=), and built-in generics such as list[str] outside annotations."""
    import sys

    tree = ast.parse(source, filename=name)
    guarded = _type_checking_lines(tree)
    annotations = _annotation_nodes(tree)
    named_expr = getattr(ast, "NamedExpr", None)
    out = []
    for node in ast.walk(tree):
        line = getattr(node, "lineno", 0)
        if named_expr is not None and isinstance(node, named_expr):
            out.append(f"{name}:{line}: assignment expression")
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)) and getattr(
            node.args, "posonlyargs", None
        ):
            out.append(f"{name}:{line}: positional-only parameters")
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and node.value.id in BUILTIN_GENERICS
            and id(node) not in annotations
        ):
            out.append(f"{name}:{line}: {node.value.id}[...] at run time")
        if isinstance(node, ast.ImportFrom) and line not in guarded:
            names = {a.name for a in node.names}
            if node.module == "typing" and names & PY38_TYPING:
                out.append(f"{name}:{line}: typing {sorted(names & PY38_TYPING)} at run time")
            if node.module == "functools" and names & PY38_FUNCTOOLS:
                out.append(f"{name}:{line}: functools {sorted(names & PY38_FUNCTOOLS)}")
            if node.module in ("importlib.metadata", "zoneinfo", "graphlib"):
                out.append(f"{name}:{line}: {node.module}")
        if isinstance(node, ast.Attribute) and node.attr in PY38_ATTRIBUTES and line not in guarded:
            out.append(f"{name}:{line}: .{node.attr}")
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "typing"
            and node.attr in PY38_TYPING
            and line not in guarded
        ):
            out.append(f"{name}:{line}: typing.{node.attr}")
        dicts = (ast.Dict, ast.DictComp)
        if (
            isinstance(node, ast.BinOp)
            and isinstance(node.op, ast.BitOr)
            and (isinstance(node.left, dicts) or isinstance(node.right, dicts))
        ):
            out.append(f"{name}:{line}: dict union")
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "zip"
            and any(k.arg == "strict" for k in node.keywords)
        ):
            out.append(f"{name}:{line}: zip(strict=)")
        if isinstance(node, ast.JoinedStr) and sys.version_info >= (3, 8):
            segment = ast.get_source_segment(source, node) or ""
            if SELF_DOCUMENTING.search(segment):
                out.append(f"{name}:{line}: f-string '=' specifier")
    return out


class Python37Tests(unittest.TestCase):
    """Revision R1: Junos 25.2R1-S1.4 ships Python 3.7.10 (verified on SRX4100). The CI test job runs these
    tests on 3.7; here the grammar is checked with feature_version=(3, 7) and the 3.8+ run-time names by AST."""

    def _sources(self) -> list:
        return sorted(INSTALLER_DIR.glob("*.py"))

    def test_every_installer_module_parses_as_python_3_7(self) -> None:
        self.assertTrue(self._sources())
        for path in self._sources():
            with self.subTest(module=path.name):
                parse_37(path.read_text(encoding="utf-8"), str(path))

    def test_the_generated_op_script_parses_as_python_3_7(self) -> None:
        from jwicket_install import build_op

        modules = build_op.collect_modules()
        text, _url, _digest = build_op.render_op(s.bundle(), "v0.1.0.dev1", "example/jwicket", modules)
        parse_37(text, plan.OP_FILE)
        embedded = {m.name for m in modules}
        self.assertLessEqual(
            {"jwicket_install.plan", "jwicket_install.state", "jwicket_install.render"}, embedded
        )

    def test_no_python_3_8_names_at_run_time(self) -> None:
        problems = []
        for path in self._sources():
            problems.extend(py37_problems(path.read_text(encoding="utf-8"), path.name))
        self.assertEqual(problems, [])

    def test_the_checker_catches_what_it_should(self) -> None:
        import sys

        bad = (
            "from typing import Protocol\nimport functools\nx = 'a'.removeprefix('a')\n"
            "y = {**{}} | {}\nz = {1: 2} | {3: 4}\n"
        )
        found = py37_problems(bad, "bad.py")
        self.assertTrue(any("Protocol" in p for p in found))
        self.assertTrue(any("removeprefix" in p for p in found))
        self.assertTrue(any("dict union" in p for p in found))
        ok = "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from typing import Protocol\n"
        self.assertEqual(py37_problems(ok, "ok.py"), [])
        self.assertTrue(py37_problems("X = list[str]\n", "g.py"))
        self.assertEqual(py37_problems("from __future__ import annotations\nx: list[str] = []\n", "g.py"), [])
        if sys.version_info >= (3, 8):  # 3.7 cannot even parse these
            self.assertTrue(py37_problems("x = 1\ny = f'{x=}'\n", "f.py"))
            self.assertEqual(py37_problems("x = 1\ny = f'x={x} {x == 1} {x:=^4}'\n", "f.py"), [])
            self.assertTrue(py37_problems("if (n := 1):\n    pass\n", "w.py"))
            self.assertTrue(py37_problems("def f(a, /):\n    pass\n", "p.py"))


if __name__ == "__main__":
    unittest.main()


_ = Path  # keep the import for readers grepping fixture paths
