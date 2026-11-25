"""The workstation executor against a recording fake device (Spec 006, AC-006-07, -11, -13, -14, -17 to
-20, -26, -27 and revisions R2 to R5). Every test runs against tests/fakes_junos.py: a passing test shows
what the installer sends and how it reacts; it proves nothing about what a device does (Q-INST-06)."""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import json
import logging
import ssl
import stat
import tempfile
import unittest
from pathlib import Path
from typing import Any, List, Optional, Tuple

import fakes_junos as f
from install_support import plan

from jwicket_install import receipt, tunnel

LANG = f.LANGUAGE_PAIR
APP = " ".join(plan.STANZA_KEYS["F-DAEMON"])


def commits(device: f.FakeDevice) -> List[Tuple[Any, ...]]:
    return [c for c in device.calls if c[0] == "commit"]


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.device = f.FakeDevice()
        self.harness = f.Harness(self.device, self.root)
        self.original_config = self.device.committed
        self.original_files = self.device.plain_files()

    def console(self, *answers: str, **kwargs: Any) -> f.FakeConsole:
        return f.FakeConsole(self.device, answers or f.gate_answers(), **kwargs)

    def install(self, data: bytes = b"", *answers: str, **kwargs: Any) -> Tuple[int, f.FakeConsole]:
        console = kwargs.pop("console", None) or self.console(*answers)
        code, _ = f.install(self.harness, data or f.make_bundle(), console, **kwargs)
        return code, console


class DryRunTests(Base):
    """AC-006-13: a dry run sends only the reads of 8.3."""

    def test_dry_run_reads_only(self) -> None:
        code, console = self.install(apply=False)
        self.assertEqual(code, plan.EXIT_OK)
        writes = [
            c for c in self.device.calls if c[0] in f.WRITES or (c[0] == "rpc" and c[1] in f.transport.WRITE_RPCS)
        ]
        self.assertEqual(writes, [])
        self.assertNotIn(("gate",), self.device.calls)
        text = console.text()
        self.assertIn(plan.DEVICE_STATUS, text)  # the CLI prints it first (test_install_cli.SurfaceTests)
        self.assertLess(text.find(plan.DEVICE_STATUS), text.find(plan.POSTURE_WARNING))
        self.assertIn("Dry run: nothing was written", text)

    def test_host_name_never_printed_before_the_gate(self) -> None:
        _, console = self.install(apply=False)
        self.assertNotIn(f.HOST, console.text())
        _, console = self.install()
        text = console.text()
        self.assertLess(text.find("verified on port"), text.find(f.HOST))
        self.assertIn(f"Lab gate passed for {f.HOST}", text)

    def test_json_dry_run_stdout_is_the_plan_document_only(self) -> None:
        console = self.console(json_mode=True)
        code, executor = f.install(self.harness, f.make_bundle(), console, apply=False)
        self.assertEqual(code, 0)
        self.assertEqual(console.out.getvalue(), "")  # the CLI prints executor.json_doc["plan"]
        document = json.loads(str(executor.json_doc["plan"]))
        self.assertEqual(document["schema"], 2)
        self.assertFalse(document["blocked"])

    def test_netconf_off_prints_the_bootstrap_units_and_reads_nothing(self) -> None:
        self.device.committed = plan.StatementSet()
        self.device.candidate = self.device.committed
        code, console = self.install(apply=False)
        self.assertEqual(code, plan.EXIT_REFUSED)
        text = console.text()
        self.assertIn('commit confirmed 10 comment "jwicket-bootstrap netconf', text)
        self.assertIsNotNone(f.bootstrap_nonce(text))
        self.assertNotIn("commit comment", text)  # SC-22: no confirming line in the units
        self.assertNotIn("netconf-open", self.device.names())
        self.assertIn(plan.NETCONF_WARNING, text)

    def test_device_diff_runs_after_the_gate_and_never_commits(self) -> None:
        code, console = self.install(apply=False, device_diff=True)
        self.assertEqual(code, plan.EXIT_OK)
        self.assertEqual(self.device.writes_before("gate"), [])
        names = self.device.names()
        self.assertIn("load", names)
        self.assertIn("discard", names)
        self.assertEqual(commits(self.device), [])
        self.assertEqual(self.device.committed, self.original_config)
        self.assertIn("Junos's own 'show | compare'", console.text())


class GateTests(Base):
    """AC-006-07: the typed name against the device's own host name; never an option or a default."""

    def test_wrong_name_exits_3_with_no_write(self) -> None:
        code, console = self.install(b"", "lab-vsrx-2")
        self.assertEqual(code, plan.EXIT_GATE)
        self.assertEqual(self.device.writes_before("never"), [])
        self.assertIn("Nothing was written", console.text())

    def test_empty_answer_never_matches(self) -> None:
        code, _ = self.install(b"", "   ")
        self.assertEqual(code, plan.EXIT_GATE)

    def test_no_terminal_exits_3(self) -> None:
        console = self.console(interactive=False)
        code, _ = self.install(console=console)
        self.assertEqual(code, plan.EXIT_GATE)
        self.assertEqual(self.device.writes_before("never"), [])

    def test_gate_from_stdin_for_the_ansible_play(self) -> None:
        console = self.console(interactive=False, stdin_text=f.HOST + "\n")
        code, _ = self.install(console=console, gate_from_stdin=True)
        self.assertEqual(code, plan.EXIT_OK)
        console = f.FakeConsole(self.device, interactive=False, stdin_text="")
        code, _ = f.install(self.harness, f.make_bundle(filler="x"), console, gate_from_stdin=True)
        self.assertEqual(code, plan.EXIT_GATE)

    def test_first_write_follows_the_gate(self) -> None:
        code, _ = self.install()
        self.assertEqual(code, plan.EXIT_OK)
        self.assertEqual(self.device.writes_before("gate"), [])

    def test_no_host_name_refuses_before_the_gate(self) -> None:
        self.device.hostname = None
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_REFUSED)
        self.assertIn("R-NOHOST", console.text())
        self.assertNotIn(("gate",), self.device.calls)

    def test_no_terminal_with_the_name_on_standard_input_still_exits_3(self) -> None:
        """SC-05: without --gate-from-stdin, a non-terminal standard input is never read for the gate."""
        console = self.console(interactive=False, stdin_text=f.HOST + "\n")
        code, _ = self.install(console=console)
        self.assertEqual(code, plan.EXIT_GATE)
        self.assertNotIn(("gate",), self.device.calls)
        self.assertEqual(self.device.writes_before("never"), [])

    def test_only_the_devices_own_host_name_passes(self) -> None:
        """SC-06, INV-05: the --host value or a recorded name never passes the gate."""
        for typed in (f.ADDRESS, "192.0.2.10 ", f.HOST.upper() + "x"):
            with self.subTest(typed=typed):
                device = f.FakeDevice()
                harness = f.Harness(device, self.root / f"gate-{len(typed)}")
                console = f.FakeConsole(device, [typed])
                code, _ = f.install(harness, f.make_bundle(), console)
                self.assertEqual(code, plan.EXIT_GATE)
                self.assertEqual(device.writes_before("never"), [])
        self.device.hostname = "lab-vsrx-9"  # the receipt or inventory may still say lab-vsrx-1
        code, _ = self.install(b"", f.HOST)
        self.assertEqual(code, plan.EXIT_GATE)
        self.assertEqual(self.device.writes_before("never"), [])

    def test_a_netconf_host_key_other_than_the_pinned_one_is_r_hostkey(self) -> None:
        """SEC-03: never reported as 'NETCONF is off', never the bootstrap units."""
        self.device.inject.netconf_key_rejected = True
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_REFUSED)
        text = console.text()
        self.assertIn("R-HOSTKEY", text)
        self.assertNotIn("jwicket-bootstrap", text)
        self.assertNotIn("Unit A", text)
        self.assertEqual(self.device.writes_before("never"), [])


class BootstrapTests(Base):
    """AC-006-11 and cut C5: the operator's own bootstrap is confirmed only after the gate."""

    def setUp(self) -> None:
        super().setUp()
        self.device.committed = plan.StatementSet()
        self.device.candidate = self.device.committed
        self.original_config = self.device.committed

    def paste(self) -> str:
        code, console = self.install(apply=False)
        self.assertEqual(code, plan.EXIT_REFUSED)
        nonce = f.bootstrap_nonce(console.text())
        assert nonce is not None
        self.device.cli_commit(["set system services netconf ssh"], f"jwicket-bootstrap netconf {nonce}", confirm=10)
        return nonce

    def test_bootstrap_confirmed_after_the_gate_then_installed(self) -> None:
        nonce = self.paste()
        code, console = self.install(bootstrap_nonce=nonce)
        self.assertEqual(code, plan.EXIT_OK, console.text())
        calls = self.device.calls
        gate = calls.index(("gate",))
        confirm = next(i for i, c in enumerate(calls) if c[0] == "commit" and c[1].endswith(f"{nonce} confirmed"))
        self.assertGreater(confirm, gate)
        self.assertIsNone(self.device.pending)
        stored = self.harness.store.read_receipt(fp_of_a())
        assert stored is not None
        data = json.loads(stored)
        self.assertEqual(data["bootstrap"]["nonce"], nonce)
        self.assertTrue(data["bootstrap"]["confirmed_by_installer"])
        self.assertEqual(data["bootstrap"]["added"], ["S8"])

    def _bootstrap_c10(self, **inject: Any) -> None:
        """SPEC-02 (SC-01 at the workstation): C10 on the bootstrap's own committed delta, after the gate."""
        nonce = self.paste()
        for name, value in inject.items():
            setattr(self.device.inject, name, value)
        code, console = self.install(bootstrap_nonce=nonce)
        self.assertEqual(code, plan.EXIT_UNEXPECTED_DIFF, console.text())
        self.assertEqual(commits(self.device), [])  # no confirming commit, from this or any session
        self.assertIsNotNone(self.device.pending)  # the bootstrap still pending: Junos removes it at its deadline
        self.assertIn("The bootstrap's committed delta changes something outside it", console.text())

    def test_an_unreadable_bootstrap_delta_leaves_the_bootstrap_unconfirmed(self) -> None:
        self._bootstrap_c10(compare_unreadable=True)

    def test_a_bootstrap_delta_with_a_foreign_change_leaves_the_bootstrap_unconfirmed(self) -> None:
        self._bootstrap_c10(compare_extra="[edit system login]\n+    user intruder;\n")

    def test_gate_failure_leaves_the_bootstrap_unconfirmed(self) -> None:
        nonce = self.paste()
        code, console = self.install(b"", "wrong-name", bootstrap_nonce=nonce)
        self.assertEqual(code, plan.EXIT_GATE)
        self.assertEqual(commits(self.device), [])
        self.assertIsNotNone(self.device.pending)
        self.assertIn("stays unconfirmed", console.text())
        self.device.clock.sleep(600)
        self.assertFalse(self.device.netconf_on())  # Junos removed it at its deadline

    def test_other_nonce_is_r_pending(self) -> None:
        self.paste()
        code, console = self.install(bootstrap_nonce="zzzzzz")
        self.assertEqual(code, plan.EXIT_REFUSED)
        self.assertIn("R-PENDING", console.text())
        self.assertEqual(self.device.writes_before("never"), [])

    def test_r_statedir_leaves_the_bootstrap_unconfirmed(self) -> None:
        """R4, spec 9.3 step 2: while R-STATEDIR holds, --apply refuses before the gate and any write; the
        operator's pending bootstrap rolls back by itself."""
        nonce = self.paste()
        del self.device.files[plan.STATE_DIR]
        code, console = self.install(bootstrap_nonce=nonce)
        self.assertEqual(code, plan.EXIT_REFUSED)
        self.assertEqual(commits(self.device), [])
        self.assertIsNotNone(self.device.pending)
        self.assertNotIn(("gate",), self.device.calls)
        self.assertIn(plan.directory_fallback(f.USER), console.text())

    def test_the_delta_is_read_with_the_older_entry_as_the_base(self) -> None:
        """JF-01: <rollback> is the base ([netconf-pdf]); base 1 compared with 0 is what entry 0 added."""
        nonce = self.paste()
        mark = len(self.device.calls)
        self.install(apply=False, bootstrap_nonce=nonce)
        reads = [c[2] for c in self.device.calls[mark:] if c[0] == "rpc" and c[1] == "get-rollback-information"]
        self.assertIn({"rollback": "1", "compare": "0"}, reads)
        self.assertTrue(all(int(str(r["rollback"])) == int(str(r["compare"])) + 1 for r in reads))
        # Read the other way round, the bootstrap's own delta shows a removal and is never recognised.
        backwards = f.rollback_delta(self.device.history, 0, 1)
        self.assertIn("-    ssh;", backwards)
        self.assertIsNone(plan.parse_patch(backwards).added or None)

    def test_k1_refuses_when_the_pending_state_changed_before_the_confirm(self) -> None:
        """SC-07: the re-read on the locked session (K1) right before the bootstrap's confirm."""
        nonce = self.paste()
        for change in (
            lambda d: setattr(d, "scheduled", True),
            lambda d: d._entry("otheradmin", "cli", "maintenance", "", "commit confirmed, rollback in 10mins"),
        ):
            with self.subTest():
                device_calls = len(self.device.calls)
                self.device.on(lambda c: c[0] == "lock", change)
                code, console = self.install(bootstrap_nonce=nonce)
                self.assertEqual(code, plan.EXIT_REFUSED)
                self.assertIn("R-PENDING", console.text())
                self.assertFalse([c for c in self.device.calls[device_calls:] if c[0] == "commit"])
                self.device.scheduled = False

    def test_a_bootstrap_still_pending_after_the_confirm_is_not_counted(self) -> None:
        """JF-08: that this session's commit confirms the CLI's commit confirmed is inferred: read it back."""
        nonce = self.paste()
        pending = self.device.pending
        assert pending is not None

        def keep_pending(device: f.FakeDevice) -> None:
            def restore() -> None:
                device.pending = pending
                pending.entry.confirmed = "commit confirmed, rollback in 10mins"

            reads = lambda c: c[0] == "rpc" and c[1] == "get-commit-information"  # noqa: E731 - a one-off match
            device.hooks.append((reads, lambda d: restore(), [True]))

        self.device.on(lambda c: c[0] == "commit" and str(c[1]).endswith(" confirmed"), keep_pending)
        code, console = self.install(bootstrap_nonce=nonce)
        self.assertEqual(code, plan.EXIT_DEVICE_REFUSED)
        self.assertIn("still shows as pending", console.text())
        self.assertNotIn("scp-put", self.device.names())

    def test_gate_failure_names_the_deadline_it_read(self) -> None:
        """SC-20: the deadline is quoted from the entry ('rollback in <n>mins'), never an assumed 10."""
        code, console = self.install(apply=False)
        nonce = f.bootstrap_nonce(console.text())
        assert nonce is not None
        self.device.cli_commit(["set system services netconf ssh"], f"jwicket-bootstrap netconf {nonce}", confirm=20)
        code, console = self.install(b"", "wrong-name", bootstrap_nonce=nonce)
        self.assertEqual(code, plan.EXIT_GATE)
        self.assertIn("'rollback in 20mins'", console.text())
        self.assertNotIn("10 minutes after you committed it", console.text())


def _days_from_now(days: int) -> str:
    when = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def fp_of_a() -> str:
    from jwicket_install import hostkeys

    return hostkeys.fingerprint(f.KEY_A)


class StateDirTests(Base):
    """Revision R4 (spec 9.3, AC-006-27): root made /var/db/jwicket once (a super-user-class account's
    'mkdir' and 'file make-directory' were refused on SRX4100, verified). The installer only lists /var/db
    and /var/db/jwicket; anything but a directory owned by the account, mode 0700, is R-STATEDIR with the
    one-time root step, in the dry run and with --apply, before any write."""

    ROOT_STEP = "mkdir -m 700 /var/db/jwicket && chown labadmin /var/db/jwicket"

    def test_a_root_made_directory_is_kept_and_never_touched(self) -> None:
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_OK, console.text())
        info = self.device.files[plan.STATE_DIR]
        self.assertEqual((info.owner, info.mode, info.is_dir), (f.USER, 0o700, True))
        names = self.device.names()
        for banned in ("make-directory", "delete-directory"):
            self.assertNotIn(banned, names)
        on_directory = [
            c
            for c in self.device.calls
            if c[0] == "rpc" and c[1] in f.transport.WRITE_RPCS and plan.STATE_DIR in c[2].values()
        ]
        self.assertEqual(on_directory, [])  # no write of any kind names the directory itself
        reads = [c[2]["path"] for c in self.device.calls if c[0] == "rpc" and c[1] == "file-list"]
        self.assertIn(plan.VAR_DB, reads)
        self.assertIn(plan.STATE_DIR, reads)

    def cases(self) -> List[Tuple[str, Optional[f.FakeFile]]]:
        return [
            ("absent", None),
            ("another owner", f.FakeFile(owner="otheradmin", mode=0o700, is_dir=True)),
            ("owned by root", f.FakeFile(owner="root", mode=0o700, is_dir=True)),
            ("mode 0755", f.FakeFile(owner=f.USER, mode=0o755, is_dir=True)),
            ("group-writable", f.FakeFile(owner=f.USER, mode=0o770, is_dir=True)),
            ("a symbolic link", f.FakeFile(owner=f.USER, mode=0o700, is_symlink=True)),
            ("a plain file", f.FakeFile(b"x", owner=f.USER, mode=0o600)),
        ]

    def test_absent_or_untrusted_is_r_statedir_in_the_dry_run_and_with_apply(self) -> None:
        for label, entry in self.cases():
            for apply in (False, True):
                with self.subTest(case=label, apply=apply):
                    device = f.FakeDevice(state_dir=entry is not None)
                    if entry is not None:
                        device.files[plan.STATE_DIR] = entry
                    harness = f.Harness(device, self.root / f"{label.replace(' ', '-')}-{apply}")
                    console = f.FakeConsole(device, f.gate_answers())
                    code, _ = f.install(harness, f.make_bundle(), console, apply=apply)
                    self.assertEqual(code, plan.EXIT_REFUSED)
                    text = console.text()
                    self.assertIn("R-STATEDIR (blocks)", text)
                    self.assertIn(self.ROOT_STEP, text)
                    self.assertIn(plan.directory_fallback(f.USER), text)
                    self.assertIn("Refused before any write", text)
                    self.assertNotIn(("gate",), device.calls)
                    self.assertEqual(device.writes_before("never"), [])
                    self.assertNotIn("su root", text)

    def test_the_mode_half_of_the_trust_rule_on_its_own(self) -> None:
        """SC-12: a directory owned by the account with mode 0755 refuses as surely as another owner."""
        self.device.files[plan.STATE_DIR] = f.FakeFile(owner=f.USER, mode=0o755, is_dir=True)
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_REFUSED)
        self.assertIn("has mode 0755, not 0700", console.text())
        self.assertEqual(self.device.writes_before("never"), [])

    def test_a_directory_replaced_after_the_dry_run_is_refused_after_the_gate(self) -> None:
        """The listing is read once more after the gate (a read): a link put there meanwhile stops the run
        before any write, with the root step."""

        class Console(f.FakeConsole):
            def prompt(self, text: str) -> Optional[str]:
                answer = super().prompt(text)
                if text == plan.LAB_GATE_PROMPT:
                    self.device.files[plan.STATE_DIR] = f.FakeFile(owner=f.USER, mode=0o700, is_symlink=True)
                return answer

        console = Console(self.device, f.gate_answers())
        code, _ = f.install(self.harness, f.make_bundle(), console)
        self.assertEqual(code, plan.EXIT_REFUSED)
        text = console.text()
        self.assertIn("R-STATEDIR", text)
        self.assertIn("a symbolic link", text)
        self.assertIn(self.ROOT_STEP, text)
        self.assertEqual([c for c in self.device.calls if c[0] in f.WRITES], [])
        self.assertEqual(commits(self.device), [])

    def test_a_directory_whose_mode_or_owner_changes_after_the_dry_run_is_refused_after_the_gate(self) -> None:
        """SPEC-05: the re-read after the gate applies the whole trust rule (plan.state_dir_untrusted), not
        only the link test: mode 0755, or owner root, stops the run before any write."""
        for label, replacement, shown in (
            ("mode", f.FakeFile(owner=f.USER, mode=0o755, is_dir=True), "has mode 0755, not 0700"),
            ("owner", f.FakeFile(owner="root", mode=0o700, is_dir=True), "is owned by root"),
        ):
            with self.subTest(label):
                device = f.FakeDevice()
                harness = f.Harness(device, self.root / label)

                class Console(f.FakeConsole):
                    after_gate: f.FakeFile

                    def prompt(self, text: str) -> Optional[str]:
                        answer = super().prompt(text)
                        if text == plan.LAB_GATE_PROMPT:
                            self.device.files[plan.STATE_DIR] = self.after_gate
                        return answer

                console = Console(device, f.gate_answers())
                console.after_gate = replacement
                code, _ = f.install(harness, f.make_bundle(), console)
                self.assertEqual(code, plan.EXIT_REFUSED, console.text())
                self.assertIn("R-STATEDIR", console.text())
                self.assertIn(shown, console.text())
                self.assertEqual([c for c in device.calls if c[0] in f.WRITES], [])
                self.assertEqual(commits(device), [])

    def test_no_directory_rpc_exists_to_send(self) -> None:
        for name in ("make-directory", "delete-directory"):
            self.assertNotIn(name, f.transport.INSTALL_RPCS)
            with self.assertRaises(ValueError):
                f.transport.check_rpc(name, {"directory": plan.STATE_DIR}, "write")

    def test_uninstall_leaves_the_directory_for_root(self) -> None:
        self.assertEqual(self.install()[0], 0)
        console = self.console()
        executor = self.harness.executor(console, apply=True)
        self.assertEqual(executor.uninstall(), plan.EXIT_OK, console.text())
        self.assertIn(plan.STATE_DIR, self.device.files)
        self.assertEqual(self.device.plain_files(), self.original_files)
        self.assertIn(plan.STATE_DIR_LEFT, console.text())
        self.assertNotIn("delete-directory", self.device.names())


class ApplyOrderTests(Base):
    """AC-006-14: files verified before the load; a candidate unlike the plan is discarded (exit 6)."""

    def test_files_are_verified_before_the_first_load(self) -> None:
        code, _ = self.install()
        self.assertEqual(code, 0)
        names = self.device.names()
        first_load = names.index("load")
        last_checksum = max(i for i, n in enumerate(names[:first_load]) if n == "get-sha256-checksum-information")
        self.assertLess(last_checksum, first_load)
        self.assertLess(names.index("scp-put"), first_load)

    def test_an_extra_statement_in_the_candidate_discards_with_exit_6(self) -> None:
        self.device.inject.load_extra = ("set system scripts commit file evil.slax",)
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_UNEXPECTED_DIFF)
        self.assertEqual(commits(self.device), [])
        self.assertIn("discard", self.device.names())
        self.assertIn("unexpected + system scripts commit file evil.slax", console.text())
        self.assertEqual(self.device.committed, self.original_config)

    def test_a_header_outside_the_stage_discards_with_exit_6(self) -> None:
        self.device.inject.compare_extra = "[edit system login]\n+    user intruder;\n"
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_UNEXPECTED_DIFF)
        self.assertEqual(commits(self.device), [])
        self.assertIn("header [edit system login]", console.text())

    def test_a_change_outside_the_select_only_read_is_caught_by_the_header_check(self) -> None:
        """SC-02: the fake's configuration reads return only what CONFIG_FILTER selects, so only the text
        diff can show 'system login'."""
        self.device.inject.load_extra = ("set system login user intruder class super-user",)
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_UNEXPECTED_DIFF)
        self.assertEqual(commits(self.device), [])
        self.assertIn("system login", console.text())
        self.assertNotIn("unexpected + system login", console.text())  # the structural read cannot see it

    def test_an_unreadable_text_diff_discards_with_exit_6(self) -> None:
        """SC-01: no text diff means changes outside the read cannot be ruled out (fail closed)."""
        self.device.inject.compare_unreadable = True
        self.device.inject.load_extra = ("set system login user intruder class super-user",)
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_UNEXPECTED_DIFF)
        self.assertEqual(commits(self.device), [])
        self.assertIn("could not be read", console.text())
        self.assertNotIn(("system login user intruder class", "super-user"), self.device.committed.pairs)

    def test_a_refused_on_device_copy_is_exit_7(self) -> None:
        """SC-17: spec 9.7 row 7, a refused copy of the files phase is a transfer failure."""

        def refuse(device: f.FakeDevice) -> None:
            raise f.transport.DeviceRefused("error: could not copy (fake)")

        self.device.on(lambda c: c[0] == "rpc" and c[1] == "file-copy", refuse)
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_INTEGRITY, console.text())
        self.assertIn("the device refused the copy", console.text())
        self.assertEqual(commits(self.device), [])
        self.assertNotIn(plan.STAGING_PATH, self.device.files)  # the staging file is deleted (INV-06)

    def test_a_lost_session_in_the_file_steps_is_exit_4(self) -> None:
        """SC-17: spec 9.7, a session lost before the stage's commit."""
        self.device.on(lambda c: c[0] == "scp-put", lambda d: d.drop_latest())
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_DEVICE_REFUSED, console.text())
        self.assertEqual(commits(self.device), [])

    def test_junos_diff_is_printed_and_journaled(self) -> None:
        code, console = self.install()
        self.assertEqual(code, 0)
        self.assertIn("Junos's own 'show | compare' for stage diagnostics", console.text())
        journal = json.loads(self.harness.store.journal_path(fp_of_a()).read_text(encoding="utf-8"))
        self.assertIn("diagnostics", journal["device_diffs"])
        self.assertEqual(journal["confirmed_stages"], ["diagnostics", "runtime"])
        self.assertEqual(journal["outcome"], "ok")

    def test_a_refused_load_is_exit_4(self) -> None:
        self.device.inject.refuse_commit = "error: syntax error, expecting <data>: checksum (unknown statement)"
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_DEVICE_REFUSED)
        self.assertIn("--no-jet-checksum", console.text())
        self.assertEqual(self.device.committed, self.original_config)


class ConfirmTests(Base):
    """AC-006-17: commit confirmed N with a comment; the confirm only with 60 s to spare."""

    def test_commit_confirmed_carries_minutes_and_comment(self) -> None:
        code, _ = self.install(opts=f.options(confirm_minutes=7))
        self.assertEqual(code, 0)
        confirmed = [c for c in commits(self.device) if c[2] is not None]
        self.assertEqual([c[2] for c in confirmed], [7, 7])
        self.assertTrue(all(plan.is_installer_comment(c[1]) for c in commits(self.device)))
        confirms = [c for c in commits(self.device) if c[2] is None]
        self.assertTrue(all(c[1].endswith(" confirmed") for c in confirms))

    def test_checks_too_close_to_the_deadline_are_not_confirmed(self) -> None:
        self.device.inject.slow_reads = {"jet-application-status": 120.0}
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_CHECK_FAILED)
        runtime_confirms = [c for c in commits(self.device) if c[1].endswith("runtime confirmed")]
        self.assertEqual(runtime_confirms, [])
        self.assertIn("NOT confirmed", console.text())
        self.assertNotIn(
            ("system extensions extension-service application file jwicket.py daemonize", ""),
            self.device.committed.pairs,
        )

    def test_no_commit_check_or_validate_is_ever_sent(self) -> None:
        self.install()
        for call in self.device.calls:
            text = repr(call).lower()
            self.assertNotIn("commit check", text)
            self.assertNotIn("<check", text)
            self.assertNotIn("validate", text)

    def test_a_commit_script_change_fails_c10_and_is_not_confirmed(self) -> None:
        """SC-08: a change that appears only in the committed result (as a commit script's would)."""
        for extra, shown in (
            ("set system scripts commit file evil.slax", "system scripts commit file evil.slax"),
            ("set system login user intruder class super-user", "system login"),
        ):
            with self.subTest(extra=extra):
                device = f.FakeDevice()
                harness = f.Harness(device, self.root / f"c10-{len(extra)}")
                device.inject.commit_extra = (extra,)
                original = device.committed
                console = f.FakeConsole(device, f.gate_answers())
                code, _ = f.install(harness, f.make_bundle(), console)
                self.assertEqual(code, plan.EXIT_CHECK_FAILED)
                self.assertIn("C10 fail", console.text())
                self.assertIn(shown, console.text())
                self.assertFalse([c for c in commits(device) if c[1].endswith("diagnostics confirmed")])
                self.assertEqual(device.committed, original)  # Junos rolled it back at the deadline

    def test_a_slow_last_check_is_not_confirmed(self) -> None:
        """SC-09: the final INV-04 guard, when only C11 crosses the 60 s margin."""

        def slow(device: f.FakeDevice) -> None:
            device.inject.slow_reads = {"get-commit-information": 250.0}

        self.device.on(lambda c: c[0] == "commit" and c[2] is not None, slow)
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_CHECK_FAILED)
        text = console.text()
        self.assertIn("C11 pass", text)
        self.assertIn("did not finish at least 60 s before the deadline", text)
        self.assertFalse([c for c in commits(self.device) if c[1].endswith(" confirmed")])


class RevertTests(Base):
    """AC-006-18: a failed runtime stage rolls back, then the revert stage removes the diagnostics."""

    def test_failed_runtime_reverts_to_the_original_device(self) -> None:
        self.device.inject.refuse_start = True
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_CHECK_FAILED)
        text = console.text()
        self.assertIn("C4 fail", text)
        self.assertIn("Reverted", text)
        self.assertEqual(self.device.committed, self.original_config)
        remaining = set(self.device.files) - set(self.original_files)
        self.assertEqual(remaining, set())
        revert = [c for c in commits(self.device) if " revert " in c[1]]
        self.assertEqual(len(revert), 2)  # its confirmed commit and its confirm

    def test_keep_partial_skips_the_revert(self) -> None:
        self.device.inject.refuse_start = True
        code, console = self.install(opts=f.options(keep_partial=True))
        self.assertEqual(code, plan.EXIT_CHECK_FAILED)
        self.assertIn("--keep-partial", console.text())
        self.assertIn(LANG, self.device.committed.pairs)
        self.assertFalse([c for c in commits(self.device) if " revert " in c[1]])

    def test_rollback_now_acts_only_on_a_typed_rollback(self) -> None:
        self.device.inject.refuse_start = True
        code, _ = self.install(b"", f.HOST, "rollback", rollback_now=True)
        self.assertEqual(code, plan.EXIT_CHECK_FAILED)
        self.assertIn("load-rollback", self.device.names())
        self.assertTrue(any("rolled back by installer" in c[1] for c in commits(self.device)))

    def test_rollback_now_waits_on_enter(self) -> None:
        self.device.inject.refuse_start = True
        code, _ = self.install(b"", f.HOST, "", rollback_now=True)
        self.assertEqual(code, plan.EXIT_CHECK_FAILED)
        self.assertNotIn("load-rollback", self.device.names())
        self.assertIn(("device-rollback", "deadline"), self.device.calls)

    def test_failed_diagnostics_removes_this_runs_files(self) -> None:
        self.device.inject.probe_missing = ("lxml",)
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_CHECK_FAILED)
        self.assertIn("C3 fail", console.text())
        self.assertEqual(self.device.committed, self.original_config)
        self.assertEqual(set(self.device.files) - set(self.original_files), set())

    def test_a_failed_install_keeps_a_confirmed_netconf_bootstrap_without_remove_shared(self) -> None:
        """SC-10, spec 8.8: M1's NETCONF bootstrap is reverted only with --remove-shared."""
        for remove_shared in (False, True):
            with self.subTest(remove_shared=remove_shared):
                device = f.FakeDevice(netconf=False)
                harness = f.Harness(device, self.root / f"boot-{remove_shared}")
                console = f.FakeConsole(device, f.gate_answers())
                code, _ = f.install(harness, f.make_bundle(), console, apply=False)
                nonce = f.bootstrap_nonce(console.text())
                assert nonce is not None
                device.cli_commit(["set system services netconf ssh"], f"jwicket-bootstrap netconf {nonce}", confirm=10)
                device.inject.refuse_start = True
                console = f.FakeConsole(device, f.gate_answers())
                code, _ = f.install(
                    harness, f.make_bundle(), console, bootstrap_nonce=nonce, remove_shared=remove_shared
                )
                self.assertEqual(code, plan.EXIT_CHECK_FAILED, console.text())
                self.assertIn("Reverted", console.text())
                self.assertEqual(device.netconf_on(), not remove_shared)


class IdempotencyTests(Base):
    """AC-006-20: a re-run plans nothing, writes nothing and runs only the read checks."""

    def test_rerun_writes_nothing(self) -> None:
        self.assertEqual(self.install()[0], 0)
        mark = len(self.device.calls)
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_OK)
        later = self.device.calls[mark:]
        writes = [c for c in later if c[0] in f.WRITES or (c[0] == "rpc" and c[1] in f.transport.WRITE_RPCS)]
        self.assertEqual(writes, [])
        self.assertNotIn(("gate",), later)
        self.assertIn("Nothing to change", console.text())
        self.assertIn("Healthy.", console.text())


class UpgradeTests(Base):
    """AC-006-19 and spec 9.4: staging, the previous copy kept, restore by copy, refused overwrite."""

    def setUp(self) -> None:
        super().setUp()
        self.old = f.make_bundle(payload="3d" * 32, filler="old")
        self.new = f.make_bundle(payload="4c" * 32, filler="new")
        self.assertEqual(self.install(self.old)[0], 0)
        self.mark = len(self.device.calls)

    def later(self) -> List[Tuple[Any, ...]]:
        return self.device.calls[self.mark :]

    def test_upgrade_through_staging_keeps_prev_until_confirmed(self) -> None:
        code, console = self.install(self.new)
        self.assertEqual(code, plan.EXIT_OK, console.text())
        later = self.later()
        self.assertIn(("scp-put", plan.STAGING_PATH, 0o644), later)
        copies = [c[2] for c in later if c[0] == "rpc" and c[1] == "file-copy"]
        self.assertIn({"source": plan.DAEMON_PATH, "destination": plan.BACKUP_PATH}, copies)
        self.assertIn({"source": plan.STAGING_PATH, "destination": plan.DAEMON_PATH}, copies)
        names = [c[1] if c[0] == "rpc" else c[0] for c in later]
        self.assertLess(names.index("lock"), names.index("file-copy"))  # replaced inside the stage's lock
        self.assertNotIn(plan.BACKUP_PATH, self.device.files)  # deleted after the runtime confirm
        self.assertNotIn(plan.STAGING_PATH, self.device.files)
        self.assertEqual(self.device.files[plan.DAEMON_PATH].data, self.new)
        assert self.device.daemon is not None
        self.assertEqual(self.device.daemon.payload, "4c" * 32)

    def test_failed_upgrade_restores_the_old_bytes_by_copy(self) -> None:
        self.device.inject.restart_loop = True
        code, console = self.install(self.new)
        self.assertEqual(code, plan.EXIT_CHECK_FAILED)
        self.assertIn("restarting in a loop", console.text())
        self.assertEqual(self.device.files[plan.DAEMON_PATH].data, self.old)
        restore = [
            c for c in self.later() if c[0] == "rpc" and c[1] == "file-copy" and c[2]["source"] == plan.BACKUP_PATH
        ]
        self.assertTrue(restore)
        self.assertFalse(
            [c for c in self.later() if c[0] == "rpc" and c[1] == "file-delete" and c[2]["path"] == plan.DAEMON_PATH]
        )
        pinned = self.device.committed.values(APP + " checksum sha-256")
        self.assertEqual(pinned, (f.bundle_identity(self.old).file_sha256,))

    def test_refused_overwrite_stops_before_the_commit(self) -> None:
        self.device.inject.refuse_overwrite = True
        code, console = self.install(self.new)
        self.assertEqual(code, plan.EXIT_DEVICE_REFUSED)
        later_commits = [c for c in self.later() if c[0] == "commit"]
        self.assertEqual(later_commits, [])
        self.assertIn("nothing was deleted", console.text())
        self.assertFalse(
            [
                c
                for c in self.later()
                if c[0] == "rpc"
                and c[1] == "file-delete"
                and c[2]["path"]
                in (plan.DAEMON_PATH, f"{plan.JET_DIR}/{plan.SELFTEST_FILE}", f"{plan.JET_DIR}/{plan.PROBE_FILE}")
            ]
        )

    def test_after_a_session_drop_the_committed_checksum_is_read_before_restoring(self) -> None:
        self.device.on(
            lambda c: c[0] == "rpc" and c[1] == "jet-application-status",
            lambda d: d.drop_latest(),
        )
        code, console = self.install(self.new)
        self.assertEqual(code, plan.EXIT_CHECK_FAILED, console.text())
        later = self.later()
        drop = next(i for i, c in enumerate(later) if c[0] == "rpc" and c[1] == "jet-application-status")
        after = later[drop + 1 :]
        reads = [i for i, c in enumerate(after) if c[0] == "get-configuration" and c[1] == "committed"]
        restores = [i for i, c in enumerate(after) if c[0] == "rpc" and c[1] == "file-copy"]
        self.assertTrue(reads and restores)
        self.assertLess(reads[0], restores[0])
        late_commits = [c for c in after if c[0] == "commit"]
        self.assertEqual(late_commits, [])  # never a confirm from the new session
        self.assertEqual(self.device.files[plan.DAEMON_PATH].data, self.old)


class UninstallTests(Base):
    """AC-006-26: owned statements and known names only, evidence first, exit 8 with a live process."""

    def setUp(self) -> None:
        super().setUp()
        self.assertEqual(self.install()[0], 0)

    def uninstall(self, *answers: str, **run: Any) -> Tuple[int, f.FakeConsole]:
        console = self.console(*answers)
        run.setdefault("apply", True)
        executor = self.harness.executor(console, **run)
        return executor.uninstall(), console

    def test_uninstall_gives_back_the_original_device(self) -> None:
        code, console = self.uninstall()
        self.assertEqual(code, plan.EXIT_OK, console.text())
        self.assertEqual(self.device.committed, self.original_config)
        self.assertEqual(self.device.plain_files(), self.original_files)
        self.assertIn(plan.NOT_REMOVED_BY_TOOL, console.text())
        self.assertIsNone(self.harness.store.read_receipt(fp_of_a()))

    def test_evidence_is_fetched_first_into_private_files(self) -> None:
        mark = len(self.device.calls)
        code, _ = self.uninstall()
        self.assertEqual(code, 0)
        names = self.device.names()[mark:]
        self.assertLess(names.index("scp-get"), names.index("load"))
        evidence = [p for p in self.root.iterdir() if p.name.startswith("evidence-")]
        self.assertEqual(len(evidence), 1)
        self.assertEqual(stat.S_IMODE(evidence[0].stat().st_mode), 0o700)
        files = list(evidence[0].iterdir())
        self.assertTrue(files)
        for path in files:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertNotIn("lab-token", [p.name for p in files])

    def test_a_process_still_listed_gives_exit_8_with_files_kept(self) -> None:
        self.device.inject.stop_ignored = True
        code, console = self.uninstall()
        self.assertEqual(code, plan.EXIT_UNINSTALL_INCOMPLETE)
        self.assertIn(plan.DAEMON_PATH, self.device.files)
        self.assertIn("extension-service-stop", self.device.names())
        self.assertIn("kill", console.text())

    def test_unknown_files_keep_the_directory(self) -> None:
        self.device.files[plan.STATE_DIR + "/notes.txt"] = f.FakeFile(b"mine", owner=f.USER, mode=0o600)
        code, console = self.uninstall()
        self.assertEqual(code, 0)
        self.assertIn(plan.STATE_DIR, self.device.files)
        self.assertIn(plan.STATE_DIR + "/notes.txt", self.device.files)
        self.assertFalse([c for c in self.device.calls if c[0] == "rpc" and c[1] == "delete-directory"])
        self.assertIn("notes.txt", console.text())

    def test_netconf_kept_without_remove_shared(self) -> None:
        code, console = self.uninstall()
        self.assertEqual(code, 0)
        self.assertTrue(self.device.netconf_on())
        self.assertIn("Stays: S8", console.text())

    def test_dry_run_and_gate(self) -> None:
        mark = len(self.device.calls)
        code, _ = self.uninstall(apply=False)
        self.assertEqual(code, 0)
        later = self.device.calls[mark:]
        self.assertFalse([c for c in later if c[0] in f.WRITES or (c[0] == "rpc" and c[1] in f.transport.WRITE_RPCS)])
        code, _ = self.uninstall("nope")
        self.assertEqual(code, plan.EXIT_GATE)
        self.assertIn(plan.DAEMON_PATH, self.device.files)

    def test_c12_fails_when_a_removed_statement_comes_back(self) -> None:
        """SC-11: a commit-time re-add of a removed statement fails C12: no confirm, exit 5."""
        self.device.inject.commit_extra = (f"set {APP} daemonize",)
        mark = len(self.device.calls)
        code, console = self.uninstall()
        self.assertEqual(code, plan.EXIT_CHECK_FAILED)
        self.assertIn("C12 fail", console.text())
        self.assertFalse([c for c in self.device.calls[mark:] if c[0] == "commit" and str(c[1]).endswith(" confirmed")])
        self.assertIn(plan.DAEMON_PATH, self.device.files)  # files go only after the confirm

    def test_c11_refuses_a_newest_entry_by_another_account(self) -> None:
        """SC-04, INV-03: the uninstall stages' C11 checks the committing account too."""
        self.device.on(lambda c: c[0] == "commit" and c[2] is not None, lambda d: setattr(d, "user", "otheradmin"))
        mark = len(self.device.calls)
        code, console = self.uninstall()
        self.assertEqual(code, plan.EXIT_CHECK_FAILED)
        self.assertIn("C11 fail: the newest commit is by another account", console.text())
        self.assertFalse([c for c in self.device.calls[mark:] if c[0] == "commit" and str(c[1]).endswith(" confirmed")])

    def test_an_unwritable_evidence_directory_stops_before_any_write(self) -> None:
        """SEC-05: an OSError creating the evidence directory is reported (exit 2), never a traceback."""
        console = self.console()
        executor = self.harness.executor(console, apply=True)
        executor.run.evidence_base = self.root / "missing" / "deeper"
        mark = len(self.device.calls)
        code = executor.uninstall()
        self.assertEqual(code, plan.EXIT_INPUT)
        self.assertIn("evidence directory cannot be created", console.text())
        later = self.device.calls[mark:]
        self.assertFalse([c for c in later if c[0] in f.WRITES or (c[0] == "rpc" and c[1] in f.transport.WRITE_RPCS)])
        self.assertIn(plan.DAEMON_PATH, self.device.files)


class StoreTests(unittest.TestCase):
    """Spec 7.10: records keyed by the host-key fingerprint, 0700 and 0600, never device text."""

    def test_receipt_paths_and_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            device = f.FakeDevice()
            harness = f.Harness(device, Path(tmp))
            code, _ = f.install(harness, f.make_bundle(), f.FakeConsole(device, f.gate_answers()))
            self.assertEqual(code, 0)
            root = harness.store.root
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
            for path in root.iterdir():
                if path.is_file():
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, path)
                    self.assertNotIn(f.HOST, path.name)
            text = harness.store.read_receipt(fp_of_a())
            assert text is not None
            parsed = plan.Receipt.from_json(text)
            self.assertEqual(parsed.host_key_sha256, (fp_of_a(),))
            self.assertEqual(parsed.statements_added, ("S1", "S2", "S3", "S4", "S5", "S10", "S11", "S12", "S13"))
            self.assertEqual(parsed.statements_present_before, ("S8",))
            self.assertEqual(json.loads(device.files[plan.RECEIPT_PATH].data)["user"], f.USER)

    def test_safe_lines_withhold_secrets(self) -> None:
        lines = receipt.safe_lines('+ secret "$9$abc";\n+ url https://u:p@host/x;\n+ username labadmin;')
        self.assertEqual(lines[2], "+ username labadmin;")
        self.assertTrue(lines[0].startswith("[line withheld"))
        self.assertTrue(lines[1].startswith("[line withheld"))


if __name__ == "__main__":
    unittest.main()


class TransferTests(Base):
    """M5 (spec 6.7): a device pull lands in the staging name and is checked like an SCP push."""

    URL = "https://lab-mirror.example/jwicket.py"

    def test_file_copy_pull_into_staging(self) -> None:
        data = f.make_bundle()
        self.device.inject.pull_files[self.URL] = data
        code, console = self.install(data, opts=f.options(transfer="file-copy", pull_url=self.URL))
        self.assertEqual(code, plan.EXIT_OK, console.text())
        pulls = [
            c[2] for c in self.device.calls if c[0] == "rpc" and c[1] == "file-copy" and c[2]["source"] == self.URL
        ]
        self.assertEqual(pulls, [{"source": self.URL, "destination": plan.STAGING_PATH}])
        self.assertNotIn(("scp-put", plan.STAGING_PATH, 0o644), self.device.calls)

    def test_a_pulled_file_with_other_bytes_is_exit_7(self) -> None:
        self.device.inject.pull_files[self.URL] = f.make_bundle(filler="tampered")
        code, console = self.install(opts=f.options(transfer="file-copy", pull_url=self.URL))
        self.assertEqual(code, plan.EXIT_INTEGRITY)
        self.assertNotIn(plan.STAGING_PATH, self.device.files)  # the staging file it wrote is deleted
        self.assertEqual(commits(self.device), [])

    def test_refresh_from_needs_its_cert_and_targets_staging(self) -> None:
        data = f.make_bundle()
        self.device.inject.pull_files[self.URL] = data
        opts = f.options(transfer="refresh-from", pull_url=self.URL, cert_file="/var/db/jwicket/lab-ca.pem")
        code, console = self.install(data, opts=opts)
        self.assertEqual(code, plan.EXIT_OK, console.text())
        refresh = [c[2] for c in self.device.calls if c[0] == "rpc" and c[1] == "request-script-refresh-from"]
        self.assertTrue(refresh and all(args.get("type") == "extension-service" for args in refresh))  # JF-04
        self.assertEqual(refresh[0]["file"], plan.STAGING_FILE)
        self.assertEqual(refresh[0]["cert-file"], "/var/db/jwicket/lab-ca.pem")

    def test_a_management_instance_device_pulls_in_mgmt_junos(self) -> None:
        """JFR-05: fxp0's route is in mgmt_junos there (verified on SRX4100), so both pulls name it (the
        option documented; that it routes the download is inferred)."""
        for transfer, extra, rpc in (
            ("file-copy", {}, "file-copy"),
            ("refresh-from", {"cert_file": "/var/db/jwicket/lab-ca.pem"}, "request-script-refresh-from"),
        ):
            with self.subTest(transfer=transfer):
                device = f.FakeDevice(config=[(plan.MANAGEMENT_INSTANCE_KEY, "")])
                harness = f.Harness(device, self.root / transfer)
                data = f.make_bundle()
                device.inject.pull_files[self.URL] = data
                console = f.FakeConsole(device, f.gate_answers())
                opts = f.options(transfer=transfer, pull_url=self.URL, **extra)
                code, _ = f.install(harness, data, console, opts=opts)
                self.assertEqual(code, plan.EXIT_OK, console.text())
                sent = [c[2] for c in device.calls if c[0] == "rpc" and c[1] == rpc]
                self.assertEqual(sent[0].get("routing-instance"), plan.MGMT_INSTANCE)
                self.assertIn("routing-instance mgmt_junos", console.text())
        plain = [c[2] for c in self.device.calls if c[0] == "rpc" and c[1] == "file-copy"]
        self.assertFalse([a for a in plain if "routing-instance" in a])  # none on a box without it

    def test_refused_pull_is_exit_7(self) -> None:
        code, _ = self.install(opts=f.options(transfer="file-copy", pull_url=self.URL))
        self.assertEqual(code, plan.EXIT_INTEGRITY)


class BackendAndLayoutTests(Base):
    """The lab-token backend's NETCONF removal stage, and the group layout, end to end in the fake."""

    def test_lab_token_install_removes_the_bootstrap_netconf(self) -> None:
        self.device.committed = plan.StatementSet()
        self.device.candidate = self.device.committed
        code, console = self.install(apply=False)
        nonce = f.bootstrap_nonce(console.text())
        assert nonce is not None
        self.device.cli_commit(["set system services netconf ssh"], f"jwicket-bootstrap netconf {nonce}", confirm=10)
        code, console = self.install(opts=f.options(backend="lab-token"), bootstrap_nonce=nonce)
        self.assertEqual(code, plan.EXIT_OK, console.text())
        self.assertFalse(self.device.netconf_on())
        self.assertIn(plan.REMOVE_NETCONF_WARNING, console.text())
        names = [c[1].split(" ")[3] for c in commits(self.device) if c[1].startswith("jwicket 0")]
        self.assertEqual(names[-2:], ["netconf-removal", "netconf-removal"])
        self.assertEqual(self.device.files[plan.LAB_TOKEN_PATH].mode, 0o600)

    def test_group_layout_installs_and_uninstalls(self) -> None:
        code, console = self.install(opts=f.options(layout=plan.Layout.GROUP))
        self.assertEqual(code, plan.EXIT_OK, console.text())
        self.assertIn(("apply-groups", "jwicket"), self.device.committed.pairs)
        self.assertTrue(self.device.committed.under("groups jwicket system extensions"))
        self.assertIsNotNone(self.device.daemon)
        console = self.console()
        executor = self.harness.executor(console, apply=True)
        self.assertEqual(executor.uninstall(), plan.EXIT_OK, console.text())
        self.assertEqual(self.device.committed, self.original_config)

    def test_remove_shared_netconf_needs_its_own_typed_word(self) -> None:
        self.device.committed = plan.StatementSet()
        self.device.candidate = self.device.committed
        _, console = self.install(apply=False)
        nonce = f.bootstrap_nonce(console.text())
        assert nonce is not None
        self.device.cli_commit(["set system services netconf ssh"], f"jwicket-bootstrap netconf {nonce}", confirm=10)
        self.assertEqual(self.install(bootstrap_nonce=nonce)[0], 0)
        console = self.console(f.HOST, "")
        executor = self.harness.executor(console, apply=True, remove_shared=True)
        self.assertEqual(executor.uninstall(), plan.EXIT_OK, console.text())
        self.assertTrue(self.device.netconf_on())  # Enter keeps it
        self.assertIn(plan.REMOVE_NETCONF_WARNING, console.text())
        self.assertEqual(self.install(bootstrap_nonce=nonce)[0], 0)  # reinstall (NETCONF still there)
        console = self.console(f.HOST, "remove-netconf")
        executor = self.harness.executor(console, apply=True, remove_shared=True)
        self.assertEqual(executor.uninstall(), plan.EXIT_OK, console.text())


class PartialRunTests(Base):
    """Spec 7.10: a run that stops half-way leaves a record that lets uninstall remove it cleanly."""

    def test_keep_partial_then_uninstall_removes_the_language_statement(self) -> None:
        self.device.inject.refuse_start = True
        code, _ = self.install(opts=f.options(keep_partial=True))
        self.assertEqual(code, plan.EXIT_CHECK_FAILED)
        self.assertIn(LANG, self.device.committed.pairs)
        self.assertIsNotNone(self.harness.store.read_receipt(fp_of_a()))
        self.device.inject.refuse_start = False
        console = self.console()
        executor = self.harness.executor(console, apply=True)
        self.assertEqual(executor.uninstall(), plan.EXIT_OK, console.text())
        self.assertEqual(self.device.committed, self.original_config)
        self.assertEqual(set(self.device.files) - set(self.original_files), set())

    def test_a_clean_revert_leaves_no_receipt(self) -> None:
        self.device.inject.refuse_start = True
        self.assertEqual(self.install()[0], plan.EXIT_CHECK_FAILED)
        self.assertIsNone(self.harness.store.read_receipt(fp_of_a()))


class FileOwnerTests(Base):
    """Spec 9.2 A4: owners and modes read back after every transfer and copy."""

    def test_a_copy_with_another_owner_is_sent_by_scp_instead(self) -> None:
        self.device.inject.copy_owner = "otheradmin"
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_OK, console.text())
        for name in plan.JWICKET_JET_FILES:
            self.assertEqual(self.device.files[f"{plan.JET_DIR}/{name}"].owner, f.USER)
        self.assertIn(("scp-put", plan.DAEMON_PATH, 0o644), self.device.calls)

    def test_files_owned_by_root_are_r_root_and_exit_7(self) -> None:
        self.device.inject.scp_owner = "root"
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_INTEGRITY)
        self.assertIn("R-ROOT", console.text())
        self.assertNotIn(plan.STAGING_PATH, self.device.files)
        self.assertEqual(commits(self.device), [])


def _scan(root: Path, needle: bytes) -> List[str]:
    """Every file under ``root`` (the harness: the installer's state, evidence, known_hosts) holding
    ``needle``."""
    return [str(path) for path in root.rglob("*") if path.is_file() and needle in path.read_bytes()]


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.lines: List[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))


class TlsAccessTests(Base):
    """Revision R2: --access tls (the default) listens with TLS on the listen address; the installer makes
    the certificate in memory, sends the key by SCP (0600) and nowhere else, and prints and records only
    the certificate's SHA-256 fingerprint, which C8 pins (R3)."""

    def setUp(self) -> None:
        super().setUp()
        self.capture = _Capture()
        logger = logging.getLogger("jwicket_install")
        old = logger.level
        logger.addHandler(self.capture)
        logger.setLevel(logging.DEBUG)
        self.addCleanup(logger.removeHandler, self.capture)
        self.addCleanup(logger.setLevel, old)
        self.pairs = self.harness.tls_pairs

    def test_the_pair_is_made_in_memory_and_the_key_sent_0600_by_scp(self) -> None:
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_OK, console.text())
        self.assertEqual(len(self.pairs), 1)
        pair = self.pairs[0]
        key, cert = self.device.files[plan.TLS_KEY_PATH], self.device.files[plan.TLS_CERT_PATH]
        self.assertEqual((key.owner, key.mode, key.data), (f.USER, 0o600, pair.key_pem))
        self.assertEqual((cert.owner, cert.mode, cert.data), (f.USER, 0o644, pair.cert_pem))
        self.assertIn(("scp-put", plan.TLS_KEY_PATH, 0o600), self.device.calls)
        self.assertIn(("scp-put", plan.TLS_CERT_PATH, 0o644), self.device.calls)
        text = console.text()
        fingerprint = plan.fingerprint_display(pair.cert_sha256)
        self.assertIn(fingerprint, text)
        self.assertIn(f"Browse to https://{f.ADDRESS}:{plan.DEFAULT_TLS_PORT}/", text)
        stored = self.harness.store.read_receipt(fp_of_a())
        assert stored is not None
        record = plan.Receipt.from_json(stored)
        self.assertEqual(
            (record.access, record.listen_address, record.port, record.tls_cert_sha256),
            ("tls", f.ADDRESS, plan.DEFAULT_TLS_PORT, pair.cert_sha256),
        )
        der = ssl.PEM_cert_to_DER_cert(cert.data.decode("ascii"))
        self.assertEqual(hashlib.sha256(der).hexdigest(), pair.cert_sha256)  # the fingerprint is the DER's

    def test_the_key_is_never_on_the_workstation_in_a_log_or_on_the_console(self) -> None:
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_OK, console.text())
        key = self.pairs[0].key_pem
        body = key.split(b"\n")[1]  # a line of the key's base64: in no output, record or call log
        self.assertEqual(_scan(self.root, body), [])
        self.assertEqual(_scan(self.root, b"PRIVATE KEY"), [])
        for text in (console.text(), "\n".join(self.capture.lines), repr(self.device.calls)):
            self.assertNotIn(body.decode("ascii"), text)
            self.assertNotIn("PRIVATE KEY-----", text)
        self.assertNotIn(hashlib.sha256(key).hexdigest(), console.text())  # not even its digest is shown
        read_back = [
            c
            for c in self.device.calls
            if c[0] == "rpc"
            and c[1] in ("file-show", "get-sha256-checksum-information")
            and plan.TLS_KEY_PATH in c[2].values()
        ]
        self.assertEqual(read_back, [])  # spec 7.5: owner and mode only, never read back

    def test_the_settings_are_the_plans_and_pass_the_daemons_parser(self) -> None:
        from jwicket import settings as daemon_settings

        code, console = self.install()
        self.assertEqual(code, plan.EXIT_OK, console.text())
        text = self.device.files[plan.SETTINGS_PATH].data.decode("utf-8")
        parsed = daemon_settings.parse_settings(text)
        self.assertEqual(parsed.server.bind, f.ADDRESS)
        self.assertEqual(parsed.server.port, plan.DEFAULT_TLS_PORT)
        self.assertEqual(parsed.server.allowed_hosts, (f"{f.ADDRESS}:{plan.DEFAULT_TLS_PORT}",))
        self.assertIsNone(parsed.server.routing_instance)  # no 'system management-instance' here
        self.assertNotIn("routing-instance", repr(self.device.committed.pairs))  # never the JET statement

    def test_c8_reads_https_with_the_pin_and_never_an_ssh_channel(self) -> None:
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_OK, console.text())
        gets = [c for c in self.device.calls if c[0] == "https-get"]
        self.assertEqual(gets[0][1:4], (f.ADDRESS, plan.DEFAULT_TLS_PORT, f"{f.ADDRESS}:{plan.DEFAULT_TLS_PORT}"))
        self.assertIn("C8 pass", console.text())
        self.assertNotIn("  C9 ", console.text())  # no check line (a fingerprint may hold C9)
        self.assertFalse([c for c in self.device.calls if "channel" in str(c[0])])

    def test_a_rerun_keeps_the_pair_and_pins_the_recorded_certificate(self) -> None:
        self.assertEqual(self.install()[0], 0)
        mark = len(self.device.calls)
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_OK, console.text())
        later = self.device.calls[mark:]
        self.assertFalse([c for c in later if c[0] == "scp-put"])
        self.assertEqual(len(self.pairs), 1)  # no second pair
        self.assertIn("C8 pass", console.text())

    def test_the_record_holds_the_certificates_not_after_and_file_sha256(self) -> None:
        """SEC-R1, OPX-04: what a rerun needs to renew in time and to notice a replaced tls.crt."""
        self.assertEqual(self.install()[0], 0)
        stored = self.harness.store.read_receipt(fp_of_a())
        assert stored is not None
        record = plan.Receipt.from_json(stored)
        cert = self.device.files[plan.TLS_CERT_PATH]
        self.assertEqual(record.tls_cert_file_sha256, hashlib.sha256(cert.data).hexdigest())
        self.assertEqual(record.tls_cert_not_after, self.pairs[0].not_after)
        self.assertIsNotNone(record.tls_cert_not_after)
        key_reads = [c for c in self.device.calls if c[0] == "rpc" and plan.TLS_KEY_PATH in c[2].values()]
        self.assertFalse([c for c in key_reads if c[1] in ("file-show", "get-sha256-checksum-information")])

    def test_a_certificate_remade_on_the_box_is_replaced_and_the_restart_is_asked_for(self) -> None:
        """OPX-04: the pair is kept only while tls.crt is the recorded file; OPX-05: a new pair with no runtime
        commit does not reach the running process, so the read checks fail C8 (exit 1) until it restarts."""
        self.assertEqual(self.install()[0], 0)
        self.device.files[plan.TLS_CERT_PATH] = f.FakeFile(f.LAB_CERT_PEM, owner=f.USER, mode=0o644)
        self.device.files[plan.TLS_KEY_PATH] = f.FakeFile(f.LAB_KEY_PEM, owner=f.USER, mode=0o600)
        self.device.reconcile()  # 'kill <pid>': J-Wicket restarts with the operator's pair
        code, console = self.install()
        text = console.text()
        self.assertEqual(code, plan.EXIT_REFUSED, text)
        self.assertEqual(len(self.pairs), 2)  # a new pair, made here
        self.assertIn(plan.TLS_RENEW_CHANGED, text)
        self.assertIn(plan.RESTART_NEEDED, text)
        self.assertIn("C8 fail", text)
        self.assertIn("Not healthy until J-Wicket restarts", text)
        self.assertIn("After that restart: Browse to", text)
        self.device.reconcile()  # the operator restarts it
        code, console = self.install()  # a rerun now keeps the new pair, and C8 passes
        self.assertEqual(code, plan.EXIT_OK, console.text())
        self.assertEqual(len(self.pairs), 2)
        self.assertIn("C8 pass", console.text())

    def test_a_rerun_without_the_record_reports_the_restart_and_fails_c8(self) -> None:
        """OPX-05: a second workstation (no record) writes a new pair the running J-Wicket does not load:
        the run says so, runs the read checks and exits 1, never 0 with no check."""
        self.assertEqual(self.install()[0], 0)
        other = f.Harness(self.device, self.root / "ws2")
        console = f.FakeConsole(self.device, f.gate_answers())
        code, _ = f.install(other, f.make_bundle(), console)
        text = console.text()
        self.assertEqual(code, plan.EXIT_REFUSED, text)
        self.assertIn(plan.RESTART_NEEDED, text)
        self.assertIn("C8 fail", text)
        self.assertNotIn("Not healthy: nothing was changed", text)

    def test_status_and_open_warn_about_an_expiring_certificate(self) -> None:
        """SEC-R1: C8 pins the fingerprint, not the dates, so status and open say when it expires."""
        self.assertEqual(self.install()[0], 0)
        stored = self.harness.store.read_receipt(fp_of_a())
        assert stored is not None
        record = plan.Receipt.from_json(stored)
        for not_after, healthy in (("2020-01-01T00:00:00Z", False), (_days_from_now(5), True)):
            with self.subTest(not_after=not_after):
                aged = dataclasses.replace(record, tls_cert_not_after=not_after)
                self.harness.store.write_receipt(fp_of_a(), aged)
                console = self.console()
                code = self.harness.executor(console).status()
                self.assertEqual(code, plan.EXIT_OK, console.text())
                self.assertIn(f"on {not_after}: 'install --apply' makes a new pair", console.text())
                lines = tunnel.reach_lines(aged, user=f.USER, host=f.ADDRESS)
                self.assertIn(f"on {not_after}", lines[-1])
                executor = self.harness.executor(self.console())
                executor.status()
                self.assertEqual(executor.json_doc["healthy"], healthy)

    def test_an_existing_key_with_a_loose_mode_is_removed_before_the_new_key_is_sent(self) -> None:
        self.device.files[plan.TLS_KEY_PATH] = f.FakeFile(f.LAB_KEY_PEM, owner=f.USER, mode=0o644)
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_OK, console.text())
        delete = next(
            i
            for i, c in enumerate(self.device.calls)
            if c[0] == "rpc" and c[1] == "file-delete" and c[2].get("path") == plan.TLS_KEY_PATH
        )
        put = self.device.calls.index(("scp-put", plan.TLS_KEY_PATH, 0o600))
        self.assertLess(delete, put)
        self.assertEqual(self.device.files[plan.TLS_KEY_PATH].mode, 0o600)

    def test_a_key_left_with_another_mode_after_scp_is_set_to_0600_or_refused(self) -> None:
        self.device.inject.scp_mode = 0o640
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_OK, console.text())
        self.assertEqual(self.device.files[plan.TLS_KEY_PATH].mode, 0o600)
        device = f.FakeDevice()
        harness = f.Harness(device, self.root / "refused")
        device.inject.scp_mode = 0o640
        device.inject.refuse_chmod = True
        console = f.FakeConsole(device, f.gate_answers())
        code, _ = f.install(harness, f.make_bundle(), console)
        self.assertEqual(code, plan.EXIT_DEVICE_REFUSED, console.text())
        self.assertEqual(commits(device), [])

    def test_the_certificate_is_recorded_only_once_it_is_on_the_device(self) -> None:
        def fail_cert(device: f.FakeDevice) -> None:
            raise f.transport.DeviceRefused("scp: Disk full (fake)")

        self.device.on(lambda c: c[0] == "scp-put" and c[1] == plan.TLS_CERT_PATH, fail_cert)
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_INTEGRITY, console.text())
        self.assertNotIn(plan.fingerprint_display(self.pairs[0].cert_sha256), console.text())  # shown once on it
        stored = self.harness.store.read_receipt(fp_of_a())
        if stored is not None:
            self.assertIsNone(plan.Receipt.from_json(stored).tls_cert_sha256)
        self.assertEqual(commits(self.device), [])

    def test_management_instance_puts_the_listener_in_mgmt_junos(self) -> None:
        """Verified on SRX4100: with 'system management-instance' the daemon listens only with
        [server] routing_instance = mgmt_junos (the fake refuses to start otherwise)."""
        device = f.FakeDevice(config=[(plan.MANAGEMENT_INSTANCE_KEY, "")])
        harness = f.Harness(device, self.root / "mgmt")
        console = f.FakeConsole(device, f.gate_answers())
        code, _ = f.install(harness, f.make_bundle(), console)
        self.assertEqual(code, plan.EXIT_OK, console.text())
        self.assertIn(f"routing_instance = {plan.MGMT_INSTANCE}", device.files[plan.SETTINGS_PATH].data.decode())
        self.assertIn(f"routing_instance={plan.MGMT_INSTANCE}", device.files[plan.LOG_PATH].data.decode())
        stored = harness.store.read_receipt(fp_of_a())
        assert stored is not None
        self.assertEqual(plan.Receipt.from_json(stored).routing_instance, plan.MGMT_INSTANCE)

    def test_tunnel_access_writes_no_tls_files_and_warns(self) -> None:
        code, console = self.install(opts=f.options(access="tunnel"))
        self.assertEqual(code, plan.EXIT_OK, console.text())
        self.assertNotIn(plan.TLS_KEY_PATH, self.device.files)
        self.assertEqual(self.pairs, [])
        text = console.text()
        self.assertIn(plan.TUNNEL_WARNING, text)
        self.assertIn("ssh -L 127.0.0.1:8443:127.0.0.1:8443 labadmin@192.0.2.10", text)
        self.assertIn("C8 not-available", text)


class _PromptMarkingConsole(f.FakeConsole):
    """A FakeConsole that keeps the text printed before each prompt."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.before: List[Tuple[str, str]] = []

    def prompt(self, text: str) -> Optional[str]:
        self.before.append((text, self.text()))
        return super().prompt(text)


class LabHardwareTests(unittest.TestCase):
    """Revision R5 and the reference case: the lab SRX4100 (standalone, 25.2R1-S1.4, Security Director
    Cloud over outbound-ssh, management-instance, the adopted manual install of the lab run)."""

    NEEDS = (plan.LAB_HARDWARE_FLAG, "--ack-managed", "--adopt")

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.device = f.lab_srx4100()
        self.harness = f.Harness(self.device, self.root)

    def run_install(self, *answers: str, overrides: Tuple[str, ...] = NEEDS, **run: Any) -> Tuple[int, f.FakeConsole]:
        console = run.pop("console", None) or f.FakeConsole(self.device, list(answers))
        code, _ = f.install(self.harness, f.make_bundle(), console, overrides=overrides, **run)
        return code, console

    def test_without_lab_hardware_a_physical_srx_is_r_model(self) -> None:
        code, console = self.run_install(f.SRX4100_HOST, "lab only", overrides=("--ack-managed", "--adopt"))
        self.assertEqual(code, plan.EXIT_REFUSED)
        self.assertIn("R-MODEL (blocks)", console.text())
        self.assertEqual(self.device.writes_before("never"), [])

    def test_the_reference_case_installs_after_lab_only(self) -> None:
        code, console = self.run_install(f.SRX4100_HOST, "lab only")
        self.assertEqual(code, plan.EXIT_OK, console.text())
        prompts = console.prompts
        self.assertEqual(prompts[:2], [plan.LAB_GATE_PROMPT, plan.LAB_HARDWARE_PROMPT])
        text = console.text()
        signs = text.find("outbound-ssh client: sd-cloud")
        self.assertGreater(signs, -1)
        self.assertLess(signs, text.find("Lab gate passed"))  # the production signs come first
        self.assertIn(plan.LAB_HARDWARE_WARNING, text)
        self.assertIn("committers:", text)
        self.assertIn(f"routing_instance = {plan.MGMT_INSTANCE}", self.device.files[plan.SETTINGS_PATH].data.decode())
        self.assertIn("C8 pass", text)
        stored = self.harness.store.read_receipt(fp_of_a())
        assert stored is not None
        record = plan.Receipt.from_json(stored)
        self.assertTrue(record.lab_hardware_attested)
        self.assertIn(plan.LAB_HARDWARE_FLAG, record.overrides)
        self.assertEqual((record.model, record.junos_version), ("srx4100", f.SRX4100_RELEASE))
        self.assertNotEqual(self.device.files[plan.TLS_KEY_PATH].data, f.LAB_KEY_PEM)  # a new pair, made here

    def test_anything_but_lab_only_stops_with_exit_3_and_no_write(self) -> None:
        for typed in ("lab-only", "Lab only", "", "lab only please", "yes"):
            with self.subTest(typed=typed):
                device = f.lab_srx4100()
                harness = f.Harness(device, self.root / f"t{len(typed)}{typed[:1]}")
                console = f.FakeConsole(device, [f.SRX4100_HOST, typed])
                code, _ = f.install(harness, f.make_bundle(), console, overrides=self.NEEDS)
                self.assertEqual(code, plan.EXIT_GATE)
                self.assertEqual(device.writes_before("never"), [])
                self.assertIn("'lab only' was not typed", console.text())
        console = f.FakeConsole(f.lab_srx4100(), [f.SRX4100_HOST, "  lab only  "])
        harness = f.Harness(console.device, self.root / "spaces")
        code, _ = f.install(harness, f.make_bundle(), console, overrides=self.NEEDS)
        self.assertEqual(code, plan.EXIT_OK, console.text())  # surrounding whitespace is stripped

    def test_r_managed_still_applies(self) -> None:
        code, console = self.run_install(f.SRX4100_HOST, "lab only", overrides=(plan.LAB_HARDWARE_FLAG, "--adopt"))
        self.assertEqual(code, plan.EXIT_REFUSED)
        self.assertIn("R-MANAGED (blocks)", console.text())

    def test_the_printed_uninstall_command_carries_what_uninstall_needs(self) -> None:
        """OPX-02: on the R5 reference case the summary's uninstall command names --lab-hardware and
        --ack-managed (uninstall refuses R-MODEL and R-MANAGED too), not --adopt, and it is accepted."""
        code, console = self.run_install(f.SRX4100_HOST, "lab only")
        self.assertEqual(code, plan.EXIT_OK, console.text())
        line = next(x for x in console.text().splitlines() if x.startswith("Remove it later: "))
        command = line[len("Remove it later: ") :]
        self.assertEqual(
            command,
            f"jwicket-install uninstall --apply --host {f.ADDRESS} --user {f.USER} --ack-managed --lab-hardware",
        )
        words = command.split()
        overrides = frozenset(w for w in words if w in {plan.LAB_HARDWARE_FLAG, "--ack-managed", "--adopt"})
        uconsole = f.FakeConsole(self.device, [f.SRX4100_HOST, "lab only", f.USER])
        executor = self.harness.executor(uconsole, apply=True)
        code = executor.uninstall(overrides=overrides)
        self.assertNotIn("R-MANAGED (blocks)", uconsole.text())
        self.assertNotIn("R-MODEL (blocks)", uconsole.text())
        self.assertEqual(code, plan.EXIT_OK, uconsole.text())

    def test_the_play_gives_lab_only_on_the_line_after_the_host_name(self) -> None:
        console = f.FakeConsole(self.device, interactive=False, stdin_text=f"{f.SRX4100_HOST}\nlab only\n")
        code, _ = self.run_install(console=console, gate_from_stdin=True)
        self.assertEqual(code, plan.EXIT_OK, console.text())
        self.assertIn(("lab-only",), self.device.calls)
        device = f.lab_srx4100()
        harness = f.Harness(device, self.root / "one-line")
        console = f.FakeConsole(device, interactive=False, stdin_text=f"{f.SRX4100_HOST}\n")
        code, _ = f.install(harness, f.make_bundle(), console, overrides=self.NEEDS, gate_from_stdin=True)
        self.assertEqual(code, plan.EXIT_GATE)
        self.assertEqual(device.writes_before("never"), [])

    def test_a_vsrx_is_never_asked_for_lab_only(self) -> None:
        device = f.FakeDevice()
        harness = f.Harness(device, self.root / "vsrx")
        console = f.FakeConsole(device, f.gate_answers())
        code, _ = f.install(harness, f.make_bundle(), console, overrides=(plan.LAB_HARDWARE_FLAG,))
        self.assertEqual(code, plan.EXIT_OK, console.text())
        self.assertNotIn(plan.LAB_HARDWARE_PROMPT, console.prompts)
        stored = harness.store.read_receipt(fp_of_a())
        assert stored is not None
        self.assertFalse(plan.Receipt.from_json(stored).lab_hardware_attested)

    def test_uninstall_on_lab_hardware_asks_lab_only_too(self) -> None:
        self.assertEqual(self.run_install(f.SRX4100_HOST, "lab only")[0], 0)
        console = f.FakeConsole(self.device, [f.SRX4100_HOST, "no"])
        executor = self.harness.executor(console, apply=True)
        code = executor.uninstall(overrides=frozenset(self.NEEDS))
        self.assertEqual(code, plan.EXIT_GATE)
        self.assertIn(plan.DAEMON_PATH, self.device.files)
        console = f.FakeConsole(self.device, [f.SRX4100_HOST, "lab only"])
        executor = self.harness.executor(console, apply=True)
        code = executor.uninstall(overrides=frozenset(self.NEEDS))
        self.assertEqual(code, plan.EXIT_OK, console.text())
        self.assertNotIn(plan.DAEMON_PATH, self.device.files)
        self.assertIn(plan.STATE_DIR, self.device.files)

    def test_uninstall_shows_the_production_signs_before_the_host_name(self) -> None:
        """Spec 8.2: the production signs come before both prompts, on uninstall as on install."""
        self.assertEqual(self.run_install(f.SRX4100_HOST, "lab only")[0], 0)
        console = _PromptMarkingConsole(self.device, [f.SRX4100_HOST, "lab only"])
        executor = self.harness.executor(console, apply=True)
        code = executor.uninstall(overrides=frozenset(self.NEEDS))
        self.assertEqual(code, plan.EXIT_OK, console.text())
        before_gate = dict(console.before)[plan.LAB_GATE_PROMPT]
        self.assertIn("Shown, not judged", before_gate)
        self.assertIn("outbound-ssh client: sd-cloud", before_gate)
        self.assertIn("committers:", before_gate)
        self.assertNotIn(f.SRX4100_HOST, before_gate)
