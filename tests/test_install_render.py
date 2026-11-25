"""Renderings of the shared plan (Spec 006 sections 6.8, 7.7, 7.8; AC-006-02, 06, 08, 09, 10).

Golden files are in tests/fixtures/install/golden/. To refresh them after a deliberate change, run the
suite with JWICKET_UPDATE_GOLDEN=1 and review the diff: a golden file is a reviewed rendering.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import unittest
from typing import Iterator, List, Sequence, Tuple

import install_support as s
from install_support import plan

from jwicket_install import render

D = plan.Layout.DIRECT
G = plan.Layout.GROUP
EXT = "system extensions extension-service application file"


def offline(**option_overrides: object) -> plan.InstallPlan:
    return plan.build_install_plan(
        s.bundle(),
        s.provenance(),
        s.options(**option_overrides),
        plan.DeviceFacts.unknown(),
        plan.PriorState.fresh(),
        method=plan.Method.CLI,
        offline=True,
    )


# (backend, access) pairs the daemon accepts: lab-token needs the tunnel (a shared token never faces a network).
ACCESS_VARIANTS = (("netconf", "tls"), ("netconf", "tunnel"), ("lab-token", "tunnel"))


def bootstraps() -> Iterator[plan.Bootstrap]:
    for method, nonce, op in (
        (plan.Method.WORKSTATION, s.NONCE, None),
        (plan.Method.ONBOX_LOCAL, None, s.OP_SHA),
        (plan.Method.ONBOX_URL, None, None),
    ):
        boot = plan.build_bootstrap(method, s.options(), None, nonce, op_sha256=op)
        assert boot is not None
        yield boot


def uninstall_of(name: str, **kw: object) -> Tuple[plan.UninstallPlan, plan.PriorState]:
    facts, prior = s.prepared(name)
    uplan = plan.build_uninstall_plan(s.evidence_of(name, prior), facts, prior, method=plan.Method.CLI, **kw)  # type: ignore[arg-type]
    return uplan, prior


def all_unit_sets() -> List[Tuple[str, Sequence[render.PasteUnit]]]:
    sets: List[Tuple[str, Sequence[render.PasteUnit]]] = []
    for backend, access in ACCESS_VARIANTS:
        for checksum in (True, False):
            for layout in (D, G):
                for set_files in (False, True):
                    install = offline(backend=backend, access=access, jet_checksum=checksum, layout=layout)
                    sets.append(
                        (
                            f"offline {backend} {access} {checksum} {layout.value} {set_files}",
                            render.render_cli_units(install, set_files=set_files),
                        )
                    )
    for name in ("python3-netconf-present", "upgrade", "half-finished", "other-python", "management-instance"):
        install = s.plan_for(name, method=plan.Method.CLI)
        sets.append(
            (
                f"host {name}",
                render.render_cli_units(
                    install, prior=s.prior_of(name), stamp_host=s.HOST, stamp_time="2026-11-24T21:00:00Z"
                ),
            )
        )
    for name, shared in (("running-install", True), ("running-install", False), ("half-finished", False)):
        uplan, prior = uninstall_of(name, remove_shared=shared)
        sets.append((f"uninstall {name} {shared}", render.render_cli_uninstall_units(uplan, prior=prior)))
    for boot in bootstraps():
        sets.append((f"bootstrap {boot.kind}", render.render_bootstrap_units(boot, follow_up=("next",))))
    return sets


class PasteUnitTests(unittest.TestCase):
    """AC-006-09: the paste-unit rules, over every rendering."""

    def test_rules(self) -> None:
        for label, units in all_unit_sets():
            with self.subTest(label=label):
                self._check(units)

    def _check(self, units: Sequence[render.PasteUnit]) -> None:
        confirmed = 0
        for unit in units:
            lines = list(unit.lines)
            device = unit.where.startswith("device")
            for index, line in enumerate(lines):
                self.assertNotIn("commit check", line)
                self.assertNotRegex(line, r"\bload\b.*\bterminal\b")
                self.assertNotIn("\x04", line)
                self.assertNotIn("^D", line)
                self.assertNotIn("\n", line)
                if line.startswith("commit confirmed"):
                    confirmed += 1
                    self.assertEqual(index, len(lines) - 1, f"unit {unit.number}: something follows commit confirmed")
                if device and re.match(r"^(run )?show |^(run )?file show |.*\| compare", line):
                    self.assertIn("| no-more", line, line)
                if device and not line.startswith(("commit ", "commit confirmed")):
                    self.assertNotRegex(line, r"[{}\"\\;]", line)
            commits = [line for line in lines if re.match(r"^commit\b", line)]
            confirms = [line for line in commits if not line.startswith("commit confirmed")]
            if confirms:
                self.assertEqual(len(lines), 2, unit.number)
                self.assertTrue(lines[0].startswith('commit comment "'), unit.number)
                self.assertEqual(lines[1], "exit")
            if "configure exclusive" in lines or any(line.startswith("configure") for line in lines):
                self.assertTrue(unit.opens_configuration, unit.number)
            if unit.opens_configuration:
                self.assertEqual(lines[:2], ["configure exclusive", "run show system commit | no-more"])
                self.assertEqual(unit.where, "device-configuration")
            if commits:
                self.assertEqual(unit.where, "device-configuration")
        self.assertGreaterEqual(confirmed, 0)

    def test_one_commit_confirmed_per_stage_and_confirm_after_checks(self) -> None:
        units = render.render_cli_units(offline())
        numbers = [u.number for u in units]
        stage_numbers = [n[:-1] for n in numbers if re.match(r"^[0-9]+A$", n)]
        self.assertEqual(len(stage_numbers), 2)
        for stage_number in stage_numbers:
            stage_units = [u for u in units if re.match(rf"^{stage_number}[A-Z]", u.number)]
            kinds = [u.number[len(stage_number) :] for u in stage_units]
            self.assertEqual(kinds[:4], ["A", "B", "C", "D"])
            self.assertEqual(kinds[-1], "E")
            self.assertEqual(sum(1 for u in stage_units for line in u.lines if line.startswith("commit confirmed")), 1)
            self.assertTrue(any("Only if every check above matched" in p for p in stage_units[-1].before))
        self.assertEqual(numbers[0], "1")


class ReviewFixTests(unittest.TestCase):
    """Units the review found wrong: the pending-commit sign, the comparison form, the root fallback, the
    lab token's mode, offline notes and the overwrite units (JF-03, JF-06, JF-14, OPD-01, OPD-02,
    OPD-15, SEC-09)."""

    def text_of(self, units: Sequence[render.PasteUnit]) -> str:
        return render.units_to_text(units)

    def test_no_unit_looks_for_the_literal_rollback_pending(self) -> None:
        """JF-03: '<rollback pending>' is a field name; Juniper's sample shows 'rollback in <n>mins'."""
        for name, units in all_unit_sets():
            with self.subTest(units=name):
                text = self.text_of(units)
                self.assertNotIn("'rollback pending'", text)
                if plan.CLI_SHOW_COMMIT in text or plan.OP_SHOW_COMMIT in text:
                    self.assertIn("rollback in <n>mins", text)

    def test_bootstrap_comparison_is_in_patch_form(self) -> None:
        """JF-06: 'show | compare' prints patch form, never the typed set lines."""
        for boot in bootstraps():
            unit_b = next(u for u in render.render_bootstrap_units(boot) if u.number == "B")
            expected = "\n".join(unit_b.after)
            with self.subTest(kind=boot.kind):
                self.assertIn("    [edit ", expected)
                self.assertNotIn("    set ", expected)
                self.assertIn("If it shows anything else, type 'rollback 0' and 'exit'.", expected)

    def test_the_state_directory_unit_is_the_root_step(self) -> None:
        """OPD-01, OPD-15 and revision R4: the account cannot create /var/db/jwicket ('mkdir' and 'file
        make-directory' refused on SRX4100, verified); root does it once, with the lab's own command."""
        units = render.render_cli_units(offline())
        unit3 = next(u for u in units if u.number == "3")
        self.assertEqual(unit3.where, "device-shell")
        self.assertEqual(unit3.lines, (f"mkdir -m 700 /var/db/jwicket && chown {s.USER} /var/db/jwicket",))
        self.assertIn("verified on SRX4100 25.2R1-S1.4 as root", unit3.status)
        self.assertIn("outside Juniper support", unit3.status)
        text = render.units_to_text(units)
        self.assertNotIn("make-directory /var", text.replace("'file make-directory' were refused", ""))
        self.assertNotIn("su root", text)
        host = render.render_cli_units(
            s.plan_for("python3-netconf-present", method=plan.Method.CLI), prior=s.prior_of("python3-netconf-present")
        )
        self.assertFalse([u for u in host if "as root" in u.title])  # trusted directory: no root unit

    def test_the_directory_fallback_warns_about_a_link(self) -> None:
        """OPD-07: chmod and chown as root follow a symbolic link, so the link goes first."""
        text = plan.directory_fallback(s.USER)
        self.assertIn("remove the link itself, as root, with 'rm /var/db/jwicket' (never 'rm -r')", text)
        self.assertLess(text.index("symbolic link (its permissions"), text.index("'chmod 700"))
        # The root step for an absent directory is harmless on a link: mkdir fails, and '&&' skips chown.
        self.assertIn("&& chown", plan.STATE_DIR_ROOT_STEP)

    def test_the_lab_token_is_created_private(self) -> None:
        """SEC-09: the token file is 0600 from its first byte; the chmod is only a check."""
        units = render.render_cli_units(offline(backend="lab-token"))
        lines = [line for u in units for line in u.lines]
        create = lines.index(plan.WS_TOKEN_CREATE)
        self.assertTrue(plan.WS_TOKEN_CREATE.startswith("(umask 077 && "))
        self.assertLess(create, lines.index(plan.WS_TOKEN_CHMOD))

    def test_offline_units_say_a_shared_statement_may_already_be_set(self) -> None:
        """OPD-02: offline, 'language python3' or 'netconf ssh' may already be on the device."""
        text = self.text_of(render.render_cli_units(offline()))
        self.assertIn("If the comparison does not list 'language python3', it was already set: that is fine.", text)
        self.assertIn("If the comparison does not list 'netconf ssh', it was already set: that is fine.", text)
        name = "python3-netconf-present"
        host = self.text_of(
            render.render_cli_units(s.plan_for(name, method=plan.Method.CLI), prior=s.prior_of(name))
        )
        self.assertNotIn("it was already set: that is fine", host)

    def test_each_overwrite_is_its_own_unit_before_the_commit(self) -> None:
        """JF-14: a 'file copy' prompt would otherwise take the next pasted line as its answer."""
        units = render.render_cli_units(s.plan_for("upgrade", method=plan.Method.CLI), prior=s.prior_of("upgrade"))
        for unit in units:
            copies = [line for line in unit.lines if line.startswith("run file copy") and "jwicket-next.py" in line]
            if copies and any(line.startswith("commit confirmed") for line in unit.lines):
                self.fail(f"unit {unit.number} pastes an overwrite together with its commit")
        overwrite = [u for u in units if "overwrite a file before the commit" in u.title]
        self.assertTrue(overwrite)
        self.assertTrue(all(len(u.lines) == 1 and "Q-INST-01" in u.status for u in overwrite))


class NoDriftTests(unittest.TestCase):
    """AC-006-02: one plan, many renderings, the same set lines (P1)."""

    def _variants(self) -> Iterator[Tuple[str, plan.InstallPlan]]:
        for backend, access in ACCESS_VARIANTS:
            for layout in (D, G):
                for checksum in (True, False):
                    yield (
                        f"offline {backend} {access} {layout.value} {checksum}",
                        offline(backend=backend, access=access, layout=layout, jet_checksum=checksum),
                    )
        for name in s.scenario_names():
            install = s.plan_for(name, method=plan.Method.CLI, overrides=s.all_overrides(name))
            if not install.blocked:
                yield f"host {name}", install

    def test_every_rendering_has_the_same_lines(self) -> None:
        for label, install in self._variants():
            with self.subTest(label=label):
                expected = tuple(line for st in install.stages for line in plan.stage_lines(st, install.layout))
                units = render.set_lines_of_units(render.render_cli_units(install))
                self.assertEqual(units, expected)
                set_file_units = render.render_cli_units(install, set_files=True)
                from_files = tuple(
                    line
                    for u in set_file_units
                    if u.where == "file" and u.filename and u.filename.endswith(".set")
                    for line in u.lines
                )
                self.assertEqual(from_files, expected)
                set_files = tuple(
                    line for st in install.stages for line in render.render_set_file(st, install.layout).splitlines()
                )
                self.assertEqual(set_files, expected)
                document = json.loads(render.plan_to_json(install))
                self.assertEqual(tuple(line for st in document["stages"] for line in st["lines"]), expected)
                payload = render.op_payload(install.bundle, {}, plan=install)
                stages = payload["stages"]
                assert isinstance(stages, list)
                self.assertEqual(tuple(line for st in stages for line in st["lines"]), expected)

    def test_payload_statement_table_renders_the_same_lines(self) -> None:
        payload = render.op_payload(s.bundle(), {})
        for install in (offline(), s.plan_for("python3-netconf-present")):
            for stage in install.stages:
                keys = [st.key for st in stage.add if st.key in plan.SPEC_BY_KEY]
                lines = render.payload_lines(payload, keys, user=s.USER, bundle_sha256=s.BUNDLE_SHA)
                self.assertEqual(lines, tuple(line for line in plan.stage_lines(stage, D) if line.startswith("set ")))
        op = render.payload_lines(payload, ["S14"], user=s.USER, bundle_sha256=s.BUNDLE_SHA, op_sha256=s.OP_SHA)
        self.assertEqual(op, (f"set system scripts op file jwicket-install-op.py checksum sha-256 {s.OP_SHA}",))

    def test_methods_differ_only_where_the_spec_says(self) -> None:
        cli = s.plan_for("python3-netconf-present", method=plan.Method.CLI)
        ws = s.plan_for("python3-netconf-present")
        self.assertEqual([plan.stage_lines(st, D) for st in cli.stages], [plan.stage_lines(st, D) for st in ws.stages])
        fresh_cli = s.plan_for("fresh-vsrx", method=plan.Method.CLI)
        fresh_ws = s.plan_for("fresh-vsrx")
        diag_cli = plan.stage_lines(fresh_cli.stages[0], D)
        diag_ws = plan.stage_lines(fresh_ws.stages[0], D)
        self.assertEqual(set(diag_cli) - set(diag_ws), {"set system services netconf ssh"})

    def test_group_units_expand_to_the_direct_units(self) -> None:
        direct = render.set_lines_of_units(render.render_cli_units(offline()))
        group = render.set_lines_of_units(render.render_cli_units(offline(layout=G)))
        self.assertEqual(
            plan.expand_groups(plan.apply_lines(plan.StatementSet(), group)),
            plan.expand_groups(plan.apply_lines(plan.StatementSet(), direct)),
        )

    # deploy-lab.md steps 2, 4, 5 and 6: the spike-verified reference (statements verified with the spike's
    # file name; scp -O verified). Copied here so a docs edit cannot silently change the reference.
    DEPLOY_LAB_SCP = (
        "scp -O dist/jwicket.py <user>@<device>:/var/db/scripts/jet/jwicket.py",
        "scp -O dist/jwicket.py <user>@<device>:/var/db/scripts/jet/jwicket_selftest.py",
        "scp -O dist/jwicket.py <user>@<device>:/var/db/scripts/jet/jwicket_probe.py",
    )
    DEPLOY_LAB_SET = (
        "set system scripts language python3",
        f"set {EXT} jwicket_selftest.py username <user>",
        f"set {EXT} jwicket_probe.py username <user>",
        "set system services netconf ssh",
        f"set {EXT} jwicket.py daemonize",
        f"set {EXT} jwicket.py respawn-on-normal-exit",
        f"set {EXT} jwicket.py username <user>",
    )

    def test_primary_path_equals_deploy_lab(self) -> None:
        reference = plan.apply_lines(
            plan.StatementSet(), [line.replace("<user>", s.USER) for line in self.DEPLOY_LAB_SET]
        )
        without = offline(jet_checksum=False)
        units = render.render_cli_units(without)
        self.assertEqual(plan.apply_lines(plan.StatementSet(), render.set_lines_of_units(units)), reference)
        scp = [
            line
            for u in units
            if u.where == "workstation" and u.title.startswith("copy the bundle")
            for line in u.lines
        ]
        self.assertEqual(
            scp,
            [line.replace("dist/jwicket.py", "jwicket.py").replace("<user>", s.USER) for line in self.DEPLOY_LAB_SCP],
        )
        with_checksum = plan.apply_lines(
            plan.StatementSet(), render.set_lines_of_units(render.render_cli_units(offline()))
        )
        extra = with_checksum.pairs - reference.pairs
        self.assertEqual({k for k, _ in extra}, {f"{EXT} {n} checksum sha-256" for n in plan.JWICKET_JET_FILES})
        self.assertLessEqual(reference.pairs, with_checksum.pairs)


class WarningTests(unittest.TestCase):
    """AC-006-10: one constant each, verbatim in every rendering."""

    def test_cli_units(self) -> None:
        units = render.render_cli_units(offline())
        text = render.units_to_text(units)
        self.assertTrue(text.startswith(plan.DEVICE_STATUS + "\n"))
        for needed in (
            plan.POSTURE_WARNING,
            plan.TLS_POSTURE_WARNING,
            plan.root_blast_radius(s.USER),
            plan.NETCONF_WARNING,
            plan.NETCONF_NOT_CHECKED,
            plan.warning_text("OFFLINE_STAMP", s.USER),
            plan.directory_fallback(s.USER),
        ):
            self.assertIn(needed, text)
        self.assertNotIn(plan.TUNNEL_WARNING, text)
        tunnel = render.units_to_text(render.render_cli_units(offline(access="tunnel")))
        self.assertIn(plan.TUNNEL_WARNING, tunnel)
        self.assertNotIn(plan.TLS_POSTURE_WARNING, tunnel)
        present = render.units_to_text(
            render.render_cli_units(s.plan_for("python3-netconf-present", method=plan.Method.CLI))
        )
        self.assertIn(plan.POSTURE_ALREADY_SET, present)
        self.assertNotIn(plan.POSTURE_WARNING, present)

    def test_bootstrap_units(self) -> None:
        texts = {boot.kind: render.units_to_text(render.render_bootstrap_units(boot)) for boot in bootstraps()}
        for text in texts.values():
            self.assertTrue(text.startswith(plan.DEVICE_STATUS))
            self.assertIn(plan.KEEP_SESSION_OPEN, text)
        self.assertIn(plan.NETCONF_WARNING, texts["netconf"])
        self.assertIn(plan.POSTURE_WARNING, texts["op"])
        self.assertIn(plan.POSTURE_WARNING, texts["op-url"])
        self.assertIn(plan.ALLOW_URL_WARNING, texts["op-url"])
        self.assertNotIn(plan.ALLOW_URL_WARNING, texts["op"])

    def test_plan_text_and_uninstall(self) -> None:
        prior = s.prior_of("python3-netconf-present")
        text = render.render_plan_text(s.plan_for("python3-netconf-present"), prior)
        self.assertTrue(text.startswith(plan.DEVICE_STATUS + "\n"))
        self.assertIn(plan.POSTURE_ALREADY_SET, text)
        self.assertIn(plan.root_blast_radius(s.USER), text)
        uplan, uprior = uninstall_of("running-install", remove_shared=True)
        utext = render.units_to_text(render.render_cli_uninstall_units(uplan, prior=uprior))
        self.assertTrue(utext.startswith(plan.DEVICE_STATUS))
        for needed in (plan.REMOVE_LANGUAGE_WARNING, plan.REMOVE_NETCONF_WARNING, plan.NOT_REMOVED_BY_TOOL):
            self.assertIn(needed, utext)

    def test_payload_and_release_notes(self) -> None:
        payload = render.op_payload(s.bundle(), {})
        self.assertEqual(payload["warnings"], dict(plan.WARNINGS))
        self.assertEqual(payload["device_status"], plan.DEVICE_STATUS)
        self.assertEqual(payload["lab_gate_prompt"], plan.LAB_GATE_PROMPT)
        notes = s.REPO / ".github" / "release-notes-lab-only.md"
        if not notes.exists():
            self.skipTest("the release-notes template (RELEASE package) is not in this tree")
        text = notes.read_text(encoding="utf-8")
        self.assertIn(plan.DEVICE_STATUS, text)
        self.assertIn(plan.POSTURE_WARNING, text)


class JsonTokenTests(unittest.TestCase):
    """AC-006-06: the plan JSON carries validated tokens only (INV-12), never the host name (INV-05)."""

    def test_every_fixture(self) -> None:
        for name in s.scenario_names():
            install = s.plan_for(name, overrides=s.all_overrides(name))
            text = render.plan_to_json(install)
            document = json.loads(text)
            self.assertEqual(document["schema"], 2)
            for value in s.strings_in(document):
                self.assertRegex(value, render.JSON_TOKEN_RE, (name, value))
                self.assertNotIn("{", value)
                self.assertNotIn("}", value)
            self.assertNotIn(s.HOST, text, name)
            self.assertEqual(document["blocked"], install.blocked)
            self.assertEqual([r["code"] for r in document["refusals"]], [r.code for r in install.refusals])

    def test_untokenised_text_is_refused(self) -> None:
        install = s.plan_for("python3-netconf-present")
        with self.assertRaises(plan.InvariantError):
            render.plan_to_json(dataclasses.replace(install, production_signs=("{{ lookup('pipe','id') }}",)))


class TunnelTests(unittest.TestCase):
    """AC-006-08: the tunnel binds 127.0.0.1 explicitly."""

    def test_forms(self) -> None:
        self.assertEqual(render.render_tunnel(s.USER, 8443), "ssh -L 127.0.0.1:8443:127.0.0.1:8443 labadmin@<device>")
        self.assertEqual(
            render.render_tunnel(s.USER, 9443, host=s.HOST, ssh_port=2222),
            "ssh -p 2222 -L 127.0.0.1:9443:127.0.0.1:9443 labadmin@lab-vsrx-1",
        )
        for bad in (
            {"user": "x y", "port": 8443},
            {"user": s.USER, "port": 80},
            {"user": s.USER, "port": 8443, "host": "a;b"},
        ):
            with self.assertRaises(plan.InputError):
                render.render_tunnel(**bad)  # type: ignore[arg-type]
        last = render.render_cli_units(offline(access="tunnel"))[-1]
        self.assertEqual(last.lines, ("ssh -L 127.0.0.1:8443:127.0.0.1:8443 labadmin@<device>",))
        self.assertIn(plan.TUNNEL_WARNING, last.after)
        tls_last = render.render_cli_units(offline())[-1]
        self.assertEqual(tls_last.lines, (f"https://{s.LISTEN}:9443/",))
        self.assertIn("SHA-256 fingerprint", " ".join(tls_last.after))


class TlsUnitTests(unittest.TestCase):
    """Revision R2 in M6: the certificate is made on the device (the lab's verified variant), so the key
    never leaves it; the settings and the open unit follow the access mode."""

    def test_offline_tls_units(self) -> None:
        units = render.render_cli_units(offline())
        tls_unit = next(u for u in units if u.title == "the TLS certificate (on the device)")
        self.assertEqual(tls_unit.where, "device-shell")
        self.assertEqual(tls_unit.lines, plan.shell_tls_lines(s.LISTEN))
        self.assertIn("-addext subjectAltName=IP:192.0.2.10", " ".join(tls_unit.lines))
        self.assertIn("rsa:2048", " ".join(tls_unit.lines))
        self.assertIn("verified on SRX4100 25.2R1-S1.4", tls_unit.status)
        workstation = [line for u in units if u.where == "workstation" for line in u.lines]
        self.assertFalse([line for line in workstation if "tls.key" in line or "openssl" in line])
        settings = next(u for u in units if u.filename == "jwicket.ini")
        self.assertIn("tls_key = /var/db/jwicket/tls.key", settings.lines)
        unit2 = next(u for u in units if u.number == "2")
        self.assertIn(plan.SHOW_MANAGEMENT_INSTANCE, unit2.lines)
        self.assertIn("routing_instance = mgmt_junos", " ".join(unit2.after))

    def test_host_rendering_with_a_management_instance(self) -> None:
        name = "management-instance"
        units = render.render_cli_units(s.plan_for(name, method=plan.Method.CLI), prior=s.prior_of(name))
        settings = next(u for u in units if u.filename == "jwicket.ini")
        self.assertIn("routing_instance = mgmt_junos", settings.lines)
        unit2 = next(u for u in units if u.number == "2")
        self.assertNotIn(plan.SHOW_MANAGEMENT_INSTANCE, unit2.lines)  # read by the plan, not by hand
        text = render.units_to_text(units)
        self.assertIn(f"listening on {s.LISTEN}:9443 tls=True backend=netconf routing_instance=mgmt_junos", text)

    def test_render_open(self) -> None:
        install = s.plan_for("fresh-vsrx")
        lines = render.render_open(install, cert_sha256=s.CERT_SHA)
        self.assertEqual(lines[0], f"https://{s.LISTEN}:9443/")
        self.assertIn(plan.fingerprint_display(s.CERT_SHA), lines[1])
        tunnel = render.render_open(s.plan_for("fresh-vsrx", access="tunnel"))
        self.assertEqual(tunnel[0], "ssh -L 127.0.0.1:8443:127.0.0.1:8443 labadmin@<device>")

    def test_uninstall_leaves_the_directory_to_root(self) -> None:
        uplan, prior = uninstall_of("running-install")
        units = render.render_cli_uninstall_units(uplan, prior=prior)
        root = next(u for u in units if u.title == "the empty state directory, as root")
        self.assertEqual(root.lines, (plan.STATE_DIR_ROOT_REMOVE,))
        self.assertIn(plan.STATE_DIR_LEFT, root.before)
        deletes = [line for u in units for line in u.lines if line.startswith("file delete")]
        self.assertIn(f"file delete {plan.TLS_KEY_PATH}", deletes)


class PayloadTests(unittest.TestCase):
    def test_urls(self) -> None:
        url = "https://github.com/o/r/releases/download/v0.1.0.dev1/jwicket.py"
        self.assertEqual(render.op_payload(s.bundle(), {"bundle": url})["urls"], {"bundle": url})
        for bad in (
            "http://github.com/o/r/releases/download/v0.1.0.dev1/jwicket.py",
            "https://github.com/o/r/releases/latest/download/jwicket.py",
            "https://user@github.com/x.py",
        ):
            with self.subTest(url=bad), self.assertRaises(plan.InputError):
                render.op_payload(s.bundle(), {"bundle": bad})
        payload = render.op_payload(s.bundle(), {})
        self.assertEqual(payload["required_modules"], {k: list(v) for k, v in plan.REQUIRED_MODULES.items()})
        json.dumps(payload)


class PullTests(unittest.TestCase):
    """M5 in M6: a device pull lands in the staging name, never on a configured name (INV-06)."""

    def test_file_copy_and_refresh_from(self) -> None:
        url = "https://lab.example/jwicket.py"
        copy = render.render_cli_units(offline(transfer="file-copy", pull_url=url))
        lines = [line for u in copy for line in u.lines]
        self.assertIn(f"file copy {url} {plan.STAGING_PATH}", lines)
        refresh = render.render_cli_units(
            offline(transfer="refresh-from", pull_url=url, cert_file="/var/db/jwicket/lab-ca.pem")
        )
        lines = [line for u in refresh for line in u.lines]
        self.assertIn(
            f"request system scripts refresh-from extension-service file {plan.STAGING_FILE} url {url} "
            "cert-file /var/db/jwicket/lab-ca.pem",
            lines,
        )
        with self.assertRaises(plan.InputError):
            plan.cli_refresh_from(plan.DAEMON_FILE, url, None)


class PlanDiffTests(unittest.TestCase):
    def test_diff_is_patch_form_and_parses_back(self) -> None:
        prior = s.prior_of("upgrade")
        text = render.render_plan_diff(s.plan_for("upgrade"), prior)
        self.assertIn(f"-    sha-256 {s.OLD_SHA};", text)
        self.assertIn(f"+    sha-256 {s.BUNDLE_SHA};", text)
        body = "\n".join(line for line in text.splitlines() if not line.startswith("#"))
        delta = plan.parse_patch(body)
        self.assertEqual(delta.problems, ())
        self.assertEqual({k for k, _ in delta.added}, {f"{EXT} {n} checksum sha-256" for n in plan.JWICKET_JET_FILES})


GOLDEN_UPDATE = os.environ.get("JWICKET_UPDATE_GOLDEN") == "1"


def golden_renderings() -> List[Tuple[str, str]]:
    netconf = offline()
    lab = offline(backend="lab-token")
    srx = "lab-srx4100"
    upgrade_prior = s.prior_of("upgrade")
    uplan, uprior = uninstall_of("running-install", remove_shared=True)
    boots = {boot.kind: boot for boot in bootstraps()}
    return [
        ("cli-offline-netconf.txt", render.units_to_text(render.render_cli_units(netconf))),
        ("cli-offline-lab-token-set-files.txt", render.units_to_text(render.render_cli_units(lab, set_files=True))),
        (
            "cli-upgrade.txt",
            render.units_to_text(
                render.render_cli_units(
                    s.plan_for("upgrade", method=plan.Method.CLI),
                    prior=upgrade_prior,
                    stamp_host=s.HOST,
                    stamp_time="2026-11-24T21:00:00Z",
                )
            ),
        ),
        (
            "bootstrap-netconf.txt",
            render.units_to_text(
                render.render_bootstrap_units(
                    boots["netconf"],
                    follow_up=(
                        f"jwicket-install install --apply --release v0.1.0.dev1 --host <device> "
                        f"--user {s.USER} --bootstrap-nonce {s.NONCE}",
                    ),
                )
            ),
        ),
        ("bootstrap-op.txt", render.units_to_text(render.render_bootstrap_units(boots["op"]))),
        ("bootstrap-op-url.txt", render.units_to_text(render.render_bootstrap_units(boots["op-url"]))),
        ("uninstall-running-install.txt", render.units_to_text(render.render_cli_uninstall_units(uplan, prior=uprior))),
        (
            # JFR-02: a fresh box read by --host; the comparison grouped as Junos prints new levels (illustrative).
            "cli-fresh-vsrx.txt",
            render.units_to_text(
                render.render_cli_units(
                    s.plan_for("fresh-vsrx", method=plan.Method.CLI),
                    prior=s.prior_of("fresh-vsrx"),
                    stamp_host=s.HOST,
                    stamp_time="2026-11-24T21:00:00Z",
                )
            ),
        ),
        ("plan-python3-netconf-present.json", render.plan_to_json(s.plan_for("python3-netconf-present"))),
        ("plan-own-bootstrap-lab-token.json", render.plan_to_json(s.plan_for("own-bootstrap", backend="lab-token"))),
        ("plan-diff-upgrade.txt", render.render_plan_diff(s.plan_for("upgrade"), upgrade_prior)),
        (
            "plan-text-python3-netconf-present.txt",
            render.render_plan_text(s.plan_for("python3-netconf-present"), s.prior_of("python3-netconf-present")),
        ),
        (
            "plan-text-lab-srx4100.txt",
            render.render_plan_text(s.plan_for(srx, overrides=s.all_overrides(srx)), s.prior_of(srx)),
        ),
        ("cli-offline-tunnel.txt", render.units_to_text(render.render_cli_units(offline(access="tunnel")))),
        ("jwicket-diagnostics.set", render.render_set_file(netconf.stages[0], D)),
        ("jwicket-runtime.set", render.render_set_file(netconf.stages[1], D)),
        ("jwicket-diagnostics-group.set", render.render_set_file(offline(layout=G).stages[0], G)),
        ("jwicket.ini", plan.render_settings(s.options())),
        ("jwicket-mgmt-junos.ini", plan.render_settings(s.options(), routing_instance=plan.MGMT_INSTANCE)),
        ("jwicket-tunnel.ini", plan.render_settings(s.options(access="tunnel"))),
        ("jwicket-lab-token.ini", plan.render_settings(s.options(backend="lab-token"))),
    ]


class CompareExpectationTests(unittest.TestCase):
    """JFR-02: the STOP rule after the set lines groups the change the way Junos prints it when the
    device's configuration is known, and says plainly that the grouping may differ when it is not."""

    def test_known_and_unknown_wording(self) -> None:
        lines = [f"set {EXT} jwicket.py daemonize", "set system services netconf ssh"]
        unknown = render.compare_expectation(lines)
        self.assertEqual(unknown[0], render.COMPARE_UNKNOWN)
        self.assertIn("the same statements and nothing else", unknown[0])
        self.assertIn(f"    [edit {EXT} jwicket.py]", unknown)  # one leaf per header, as typed
        before = plan.StatementSet.of({("system services ssh", ""), (f"{EXT} other.py username", "x")})
        known = render.compare_expectation(lines, before=before)
        self.assertEqual(known[0], render.COMPARE_KNOWN)
        self.assertIn("    [edit system extensions extension-service application]", known)
        self.assertIn("    +    file jwicket.py {", known)
        self.assertEqual(known[-1], "If it shows anything else, type 'rollback 0' and 'exit'.")

    def test_offline_units_and_bootstraps_use_the_unknown_wording(self) -> None:
        for label, units in (
            ("offline", render.render_cli_units(offline())),
            *((f"bootstrap {b.kind}", render.render_bootstrap_units(b)) for b in bootstraps()),
        ):
            with self.subTest(label):
                prose = [line for u in units for line in u.after if line.startswith("STOP unless 'show | compare'")]
                self.assertTrue(prose)
                self.assertTrue(all(line == render.COMPARE_UNKNOWN for line in prose), prose)

    def test_a_fresh_box_read_by_host_shows_the_new_entry_braced(self) -> None:
        units = render.render_cli_units(
            s.plan_for("fresh-vsrx", method=plan.Method.CLI), prior=s.prior_of("fresh-vsrx")
        )
        after = [line for u in units for line in u.after]
        self.assertIn(render.COMPARE_KNOWN, after)
        self.assertIn("    +    file jwicket.py {", after)


class BlastRadiusTests(unittest.TestCase):
    def test_posture_follows_what_this_plan_adds(self) -> None:
        """OPX-11: a rerun after this installer added language python3 commits nothing, so the blast radius
        must not say it adds it (the posture warning says it is already set)."""
        cases = (("running-install", "language python3 already set"), ("fresh-vsrx", "adds language python3"))
        for name, expected in cases:
            with self.subTest(name):
                text = render.render_plan_text(s.plan_for(name), s.prior_of(name))
                line = next(x for x in text.splitlines() if x.startswith("Blast radius:"))
                self.assertIn(f"posture: {expected};", line)


class PullInstanceTests(unittest.TestCase):
    """JFR-05: a device pull on a management-instance device names mgmt_junos; offline units say when to."""

    URL = "https://lab-mirror.example/jwicket.py"

    def test_pull_lines(self) -> None:
        self.assertEqual(
            plan.cli_file_copy(self.URL, plan.STAGING_PATH, plan.MGMT_INSTANCE),
            f"file copy {self.URL} {plan.STAGING_PATH} routing-instance mgmt_junos",
        )
        self.assertTrue(
            plan.cli_refresh_from(plan.STAGING_FILE, self.URL, None, plan.MGMT_INSTANCE).endswith(
                " routing-instance mgmt_junos"
            )
        )
        with self.assertRaises(plan.InputError):
            plan.cli_file_copy(self.URL, plan.STAGING_PATH, "other")

    def test_offline_pull_unit_carries_the_note(self) -> None:
        units = render.render_cli_units(offline(transfer="file-copy", pull_url=self.URL))
        pull = next(u for u in units if u.title == "the device fetches the bundle")
        self.assertIn(plan.PULL_INSTANCE_NOTE, pull.before)
        self.assertNotIn("routing-instance", " ".join(pull.lines))


class GoldenTests(unittest.TestCase):
    def test_golden_renderings(self) -> None:
        for name, text in golden_renderings():
            path = s.GOLDEN / name
            if GOLDEN_UPDATE:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
            with self.subTest(golden=name):
                self.assertTrue(path.exists(), f"missing golden {name}: run with JWICKET_UPDATE_GOLDEN=1 and review")
                self.assertEqual(text, path.read_text(encoding="utf-8"), name)

    def test_no_stray_golden_files(self) -> None:
        expected = {name for name, _ in golden_renderings()}
        found = {p.name for p in s.GOLDEN.iterdir()} if s.GOLDEN.exists() else set()
        self.assertEqual(found, expected)


if __name__ == "__main__":
    unittest.main()
