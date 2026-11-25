"""Adversarial timing and health scenarios against the recording fake (Spec 006, AC-006-15, -16, -28,
-37), and C8's pinned HTTPS read against a real local TLS listener on 127.0.0.1 port 0. A passing test
shows how the installer reacts to these events in the fake; real reply shapes and timings are recorded by
lab tests Q-INST-01 and Q-INST-06."""

from __future__ import annotations

import datetime
import hashlib
import socket
import ssl
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional, Tuple

import fakes_junos as f
import install_support as s
from install_support import plan

from jwicket_install import health, transport


def commits(device: f.FakeDevice) -> List[Tuple[Any, ...]]:
    return [c for c in device.calls if c[0] == "commit"]


def nth(name: str, number: int) -> Any:
    seen = [0]

    def match(call: Tuple[Any, ...]) -> bool:
        if call[0] == name or (call[0] == "rpc" and call[1] == name):
            seen[0] += 1
            return seen[0] == number
        return False

    return match


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.device = f.FakeDevice()
        self.harness = f.Harness(self.device, Path(self._tmp.name))

    def install(self, data: bytes = b"", *answers: str, **kwargs: Any) -> Tuple[int, f.FakeConsole]:
        console = f.FakeConsole(self.device, answers or f.gate_answers())
        code, _ = f.install(self.harness, data or f.make_bundle(), console, **kwargs)
        return code, console


class ForeignPendingTests(Base):
    """AC-006-15: another commit pending after the preflight, or between stages, stops the run before any
    commit of ours, and no revert commit is sent (it would confirm theirs)."""

    def test_foreign_confirmed_commit_before_the_first_lock(self) -> None:
        self.device.on(nth("lock", 1), lambda d: d.foreign_commit(confirmed=True))
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_REFUSED)
        self.assertEqual(commits(self.device), [])
        self.assertFalse(self.device.confirmed_foreign)
        self.assertIn("R-PENDING", console.text())
        self.assertIsNotNone(self.device.pending)  # theirs, untouched

    def test_foreign_confirmed_commit_between_stages(self) -> None:
        self.device.on(nth("lock", 2), lambda d: d.foreign_commit(confirmed=True))
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_REFUSED)
        ours = commits(self.device)
        self.assertEqual([c[1].split(" ")[3] for c in ours], ["diagnostics", "diagnostics"])
        self.assertFalse(self.device.confirmed_foreign)
        self.assertFalse([c for c in ours if " revert " in c[1]])
        self.assertIn("Installed and confirmed so far: stage(s) diagnostics", console.text())

    def test_prepared_commit_appearing_refuses(self) -> None:
        self.device.on(nth("lock", 1), lambda d: setattr(d, "prepared", True))
        code, _ = self.install()
        self.assertEqual(code, plan.EXIT_REFUSED)
        self.assertEqual(commits(self.device), [])

    def test_scheduled_commit_appearing_refuses(self) -> None:
        self.device.on(nth("lock", 1), lambda d: setattr(d, "scheduled", True))
        code, _ = self.install()
        self.assertEqual(code, plan.EXIT_REFUSED)
        self.assertEqual(commits(self.device), [])

    def test_pending_at_preflight_refuses_before_the_gate(self) -> None:
        self.device.foreign_commit(confirmed=True)
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_REFUSED)
        self.assertNotIn(("gate",), self.device.calls)
        self.assertIn("R-PENDING", console.text())

    def test_foreign_commit_between_load_and_commit(self) -> None:
        self.device.on(nth("compare", 1), lambda d: setattr(d, "scheduled", True))
        code, _ = self.install()
        self.assertEqual(code, plan.EXIT_REFUSED)
        self.assertEqual(commits(self.device), [])
        self.assertIn("discard", self.device.names())


class ConfirmGuardTests(Base):
    """AC-006-16: no confirm when the newest entry is not this stage's, or the session is lost."""

    def test_newest_entry_not_ours_before_the_confirm(self) -> None:
        def sneak(device: f.FakeDevice) -> None:
            device._entry("otheradmin", "junos", "commit at fired", "")

        # The C11 read of the diagnostics stage is the 3rd get-commit-information of that stage's lock.
        self.device.on(nth("get-commit-information", 4), sneak)
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_CHECK_FAILED)
        self.assertFalse([c for c in commits(self.device) if c[1].endswith("diagnostics confirmed")])
        self.assertIn("C11 fail", console.text())

    def test_c11_fails_on_another_comment_by_the_same_account(self) -> None:
        """SC-15: the comment half of C11 on its own."""
        self.device.on(nth("get-commit-information", 4), lambda d: d._entry(f.USER, "netconf", "maintenance", ""))
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_CHECK_FAILED)
        self.assertIn("C11 fail: the newest commit is not this stage's", console.text())
        self.assertFalse([c for c in commits(self.device) if c[1].endswith("diagnostics confirmed")])

    def test_c11_fails_on_this_stages_comment_by_another_account(self) -> None:
        """SC-15: the account half of C11 on its own."""
        self.device.on(
            nth("get-commit-information", 4),
            lambda d: d._entry("otheradmin", "netconf", d.history[0].comment, ""),
        )
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_CHECK_FAILED)
        self.assertIn("C11 fail: the newest commit is by another account", console.text())
        self.assertFalse([c for c in commits(self.device) if c[1].endswith("diagnostics confirmed")])

    def test_rollback_now_rereads_the_newest_entry(self) -> None:
        """SC-16 (REV4): --rollback-now re-reads INV-03 and does nothing once the newest entry changed."""
        self.device.inject.refuse_start = True

        class Console(f.FakeConsole):
            def prompt(self, text: str) -> Any:
                answer = super().prompt(text)
                if "restore the previous configuration" in text:  # someone commits while the operator types
                    self.device._entry("otheradmin", "cli", "maintenance", "", "commit confirmed, rollback in 10mins")
                return answer

        console = Console(self.device, f.gate_answers("rollback"))
        code, _ = f.install(self.harness, f.make_bundle(), console, rollback_now=True)
        self.assertEqual(code, plan.EXIT_CHECK_FAILED)
        self.assertIn("no longer this stage's pending commit", console.text())
        self.assertNotIn("load-rollback", self.device.names())

    def test_session_lost_during_the_health_window(self) -> None:
        self.device.on(nth("jet-application-status", 1), lambda d: d.drop_latest())
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_CHECK_FAILED)
        dropped = 1  # the first NETCONF session
        late = [c for c in commits(self.device) if c[-1] != dropped]
        self.assertEqual(late, [])  # never a confirm (or any commit) from the new session
        self.assertFalse([c for c in commits(self.device) if c[1].endswith("runtime confirmed")])
        self.assertIn("Reconnecting only to read", console.text())
        self.assertIn("does not run after a lost session", console.text())

    def test_session_lost_before_the_commit_commits_nothing(self) -> None:
        self.device.on(nth("load", 1), lambda d: d.drop_latest())
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_DEVICE_REFUSED)
        self.assertEqual(commits(self.device), [])
        self.assertIn("lost before the commit", console.text())
        self.assertEqual(self.device.sessions, 1)  # no reconnect: nothing to wait for

    def test_lock_lost_mid_stage_is_a_lost_session(self) -> None:
        self.device.on(nth("extension-service-start", 1), lambda d: d.drop_latest())
        code, _ = self.install()
        self.assertEqual(code, plan.EXIT_CHECK_FAILED)
        self.assertFalse([c for c in commits(self.device) if c[1].endswith("confirmed")])


class HealthTests(Base):
    """AC-006-28 and -37: stale result files, restart loops, changed pids, rotation, refused channels, and
    the degraded path of a bundle without D2 and D3."""

    def test_stale_result_file_fails_c2(self) -> None:
        stale = b'{"ok": true, "version": "0.1.0.dev1", "payload_sha256": "' + b"99" * 32 + b'"}'
        self.device.files[plan.STATE_DIR] = f.FakeFile(owner=f.USER, mode=0o700, is_dir=True)
        self.device.files[plan.SELFTEST_RESULT_PATH] = f.FakeFile(stale, owner=f.USER, mode=0o600)
        self.device.inject.keep_on_delete = {plan.SELFTEST_RESULT_PATH}
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_CHECK_FAILED)
        self.assertIn("C2 fail", console.text())
        self.assertIn("stale", console.text())

    def test_two_start_lines_fail_c4(self) -> None:
        self.device.inject.restart_loop = True
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_CHECK_FAILED)
        self.assertIn("restarting in a loop", console.text())

    def test_changed_process_id_fails_c7(self) -> None:
        self.device.inject.pid_changes = True
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_CHECK_FAILED)
        self.assertIn("C7 fail", console.text())
        self.assertIn("restarted", console.text())

    def test_tunnel_access_records_c8_not_available_and_opens_no_channel(self) -> None:
        """R3: with --access tunnel no check reads through SSH (forwarding refused on SRX4100): C8 is
        recorded 'not available' with a warning, and C9 never runs."""
        code, console = self.install(opts=f.options(access="tunnel"))
        self.assertEqual(code, plan.EXIT_OK, console.text())
        text = console.text()
        self.assertIn("C8 not-available", text)
        self.assertIn("warning: C8 not available", text)
        self.assertNotIn("  C9 ", text)  # no check line
        names = self.device.names()
        self.assertNotIn("https-get", names)
        self.assertFalse([n for n in names if "channel" in str(n)])

    def test_c8_trusts_only_the_certificate_this_run_made(self) -> None:
        """AC-006-28: another certificate on the listen address fails C8 before anything is sent to it."""
        self.device.inject.https_other_cert = True
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_CHECK_FAILED)
        text = console.text()
        self.assertIn("C8 fail", text)
        self.assertIn("presented a certificate other than the one this installer made", text)
        self.assertNotIn("https-request", self.device.names())  # nothing was sent to it
        self.assertFalse([c for c in commits(self.device) if c[1].endswith("runtime confirmed")])

    def test_c8_fails_when_nothing_answers_or_the_connection_times_out(self) -> None:
        for inject in ("https_refused", "https_timeout"):
            with self.subTest(inject=inject):
                device = f.FakeDevice()
                harness = f.Harness(device, Path(self._tmp.name) / inject)
                setattr(device.inject, inject, True)
                console = f.FakeConsole(device, f.gate_answers())
                code, _ = f.install(harness, f.make_bundle(), console)
                self.assertEqual(code, plan.EXIT_CHECK_FAILED)
                self.assertIn("C8 fail: no HTTPS answer from 192.0.2.10:9443", console.text())
                self.assertFalse([c for c in commits(device) if c[1].endswith("runtime confirmed")])
                attempts = [c for c in device.calls if c[0] == "https-get"]
                self.assertGreaterEqual(len(attempts), 2 if inject == "https_refused" else 1)  # a read: retried

    def test_c8_sends_the_listen_address_as_host_and_checks_the_build(self) -> None:
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_OK, console.text())
        request = next(c for c in self.device.calls if c[0] == "https-request")
        self.assertEqual(request[1:], ("/api/session", "192.0.2.10:9443"))
        self.assertIn("C8 pass: 200, version 0.1.0.dev1, build 2e2e2e2e2e2e2e2e, over HTTPS", console.text())

    def test_bundle_without_d2_d3_reads_the_start_output(self) -> None:
        self.device.inject.start_output = True
        code, console = self.install(f.make_bundle(features=()))
        self.assertEqual(code, plan.EXIT_OK, console.text())
        self.assertNotIn(plan.SELFTEST_RESULT_PATH, self.device.files)
        self.assertIn("C4 pass: one new start line (", console.text())

    def test_without_d2_and_no_output_needs_the_override(self) -> None:
        code, console = self.install(f.make_bundle(features=()))
        self.assertEqual(code, plan.EXIT_CHECK_FAILED)
        self.assertIn("--accept-unchecked-diagnostics", console.text())
        device = f.FakeDevice()
        harness = f.Harness(device, Path(self._tmp.name) / "second")
        console = f.FakeConsole(device, f.gate_answers())
        code, _ = f.install(harness, f.make_bundle(features=()), console, overrides=["--accept-unchecked-diagnostics"])
        self.assertEqual(code, plan.EXIT_OK, console.text())
        self.assertIn("not checked (--accept-unchecked-diagnostics, recorded)", console.text())

    def test_startup_refusal_fails_and_is_shown(self) -> None:
        self.device.inject.refuse_start = True
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_CHECK_FAILED)
        self.assertIn("startup-refused.txt: jwicket: refused to start", console.text())

    def test_a_refusal_written_after_the_start_line_fails_c6(self) -> None:
        """SC-14: C4 and C5 pass, then J-Wicket writes startup-refused.txt: C6 fails on its own."""

        def refuse_after_start(device: f.FakeDevice) -> None:
            device._append(plan.STARTUP_REFUSED_PATH, b"jwicket: refused to start: late check failed\n", replace=True)

        self.device.on(
            lambda c: c[0] == "rpc" and c[1] == "file-show" and c[2].get("filename") == plan.AUDIT_PATH,
            refuse_after_start,
        )
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_CHECK_FAILED)
        text = console.text()
        self.assertIn("C4 pass", text)
        self.assertIn("C6 fail: J-Wicket refused to start", text)

    def test_a_second_start_line_during_c7_fails_it(self) -> None:
        """SC-14: the second half of C7, C4 read again after the 30 s wait."""

        def restart(device: f.FakeDevice) -> None:
            options = f.options()
            line, build = plan.start_line(f.bundle_identity(f.make_bundle()), options, None)
            device._append(plan.LOG_PATH, f"{device.stamp()} INFO jwicket {line} {build}\n".encode("ascii"))

        self.device.on(nth("jet-application-status", 1), restart)
        code, console = self.install()
        self.assertEqual(code, plan.EXIT_CHECK_FAILED)
        self.assertIn("C7 fail: at the second read", console.text())


class HealthUnitTests(unittest.TestCase):
    """The pure checks, on the daemon's own shapes."""

    # The SRX4100 lab run's form (docs/evidence/2026-11-24-srx4100-lab): TLS on the fxp0 address, mgmt_junos.
    EXPECT: ClassVar[Dict[str, str]] = {
        "line": "listening on 192.0.2.10:9443 tls=True backend=netconf routing_instance=mgmt_junos",
        "build": "version=0.1.0.dev1 payload=2e2e2e2e2e2e2e2e",
    }

    def line(self, stamp: str = "2026-11-24 21:00:05,000") -> bytes:
        return (
            f"{stamp} INFO jwicket listening on 192.0.2.10:9443 tls=True backend=netconf routing_instance=mgmt_junos "
            "version=0.1.0.dev1 payload=2e2e2e2e2e2e2e2e\n"
        ).encode("ascii")

    def test_the_expected_line_is_the_plans(self) -> None:
        options = f.options()
        line, build = plan.start_line(f.bundle_identity(f.make_bundle()), options, plan.MGMT_INSTANCE)
        self.assertEqual((line, build), (self.EXPECT["line"], self.EXPECT["build"]))

    def test_exactly_one_new_line_after_the_offset(self) -> None:
        old = self.line("2026-11-24 20:00:00,000")
        data = old + b"2026-11-24 21:00:04,000 WARNING jwicket TLS is off; listening on loopback only\n" + self.line()
        self.assertTrue(health.start_line(data, len(old), self.EXPECT, None).ok)
        self.assertFalse(health.start_line(data, 0, self.EXPECT, None).ok)  # two lines from the start

    def test_rotated_log_is_read_from_its_start_counting_only_new_stamps(self) -> None:
        rotated = self.line("2026-11-24 20:59:00,000") + self.line("2026-11-24 21:00:05,000")
        since = datetime.datetime(2026, 11, 24, 21, 0, 0)
        result = health.start_line(rotated, 10_000, self.EXPECT, since)
        self.assertTrue(result.ok, result.detail)
        self.assertIn("rotated", result.detail)

    def test_another_build_fails(self) -> None:
        data = self.line().replace(b"payload=2e2e", b"payload=ffff")
        self.assertIn("another build", health.start_line(data, 0, self.EXPECT, None).detail)

    def test_without_d3_any_suffix_matches_the_prefix(self) -> None:
        old_line = b"2026-11-24 21:00:05,000 INFO jwicket listening on 127.0.0.1:8443 tls=False backend=netconf\n"
        prefix = "listening on 127.0.0.1:8443 tls=False backend=netconf"
        self.assertTrue(health.start_line(old_line, 0, {"line": prefix, "build": ""}, None).ok)

    def test_audit_start(self) -> None:
        records = b'{"event": "login"}\n{"event": "start", "version": "0.1.0.dev1", "payload_sha256": "ab"}\n'
        self.assertTrue(health.audit_start(records, 0, {"version": "0.1.0.dev1", "payload_sha256": "ab"}).ok)
        self.assertFalse(health.audit_start(records + records, 0, {"version": "0.1.0.dev1"}).ok)

    def test_process_id_and_stability(self) -> None:
        self.assertEqual(health.process_id("Name : jwicket.py\nProcess-id: 4242\n"), 4242)
        self.assertIsNone(health.process_id("warning: No active extension-services"))
        self.assertTrue(health.stable(1, 1).ok)
        self.assertFalse(health.stable(1, 2).ok)
        self.assertFalse(health.stable(None, None).ok)

    def test_api_session_over_pinned_https(self) -> None:
        body = b'{"version": "0.1.0.dev1", "build": "2e2e2e2e2e2e2e2e"}'
        raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n" + body
        expect = {
            "status": "200",
            "version": "0.1.0.dev1",
            "build": "2e2e2e2e2e2e2e2e",
            "host": "192.0.2.10:9443",
            "if_unavailable": "fail",
        }
        self.assertTrue(health.api_session(raw, expect, available=True).ok)
        self.assertTrue(health.https_session(raw, expect, connected=True, pinned=True).ok)
        other_build = raw.replace(b"2e2e2e2e2e2e2e2e", b"0" * 16)
        self.assertIn("another build", health.https_session(other_build, expect, connected=True, pinned=True).detail)
        # SPEC-01 (AC-006-28): a wrong version fails C8, with the same build and for a bundle without D3
        # (no build field), where the version is C8's only identity check.
        other_version = raw.replace(b'"0.1.0.dev1"', b'"0.0.9"')
        for want in (expect, {**expect, "build": ""}):
            with self.subTest(build=want["build"]):
                result = health.https_session(other_version, want, connected=True, pinned=True)
                self.assertEqual(result.status, health.FAIL)
                self.assertIn("another version", result.detail)
                result = health.api_session(other_version, want, available=True)
                self.assertEqual(result.status, health.FAIL)
        no_d3 = b'HTTP/1.1 200 OK\r\n\r\n{"version": "0.1.0.dev1"}'
        self.assertTrue(health.https_session(no_d3, {**expect, "build": ""}, connected=True, pinned=True).ok)
        self.assertFalse(health.https_session(raw, expect, connected=True, pinned=False).ok)
        refused = health.https_session(b"", expect, connected=False, pinned=False, reason="Connection refused")
        self.assertEqual(refused.status, health.FAIL)  # from a NETCONF executor: a failure, never "not available"
        lenient = {**expect, "if_unavailable": "not-available"}
        self.assertEqual(health.https_session(b"", lenient, connected=False, pinned=False).status, health.NOT_AVAILABLE)
        misdirected = health.https_session(b"HTTP/1.1 421 Misdirected\r\n\r\n", expect, connected=True, pinned=True)
        self.assertIn("answered 421", misdirected.detail)
        self.assertIn(b"Host: 192.0.2.10:9443", health.session_request(9443, "192.0.2.10:9443"))
        self.assertIn(b"Host: 127.0.0.1:8443", health.session_request(8443))
        self.assertEqual(health.not_available("C8", plan.TUNNEL_C8_REASON).status, health.NOT_AVAILABLE)

    def test_c9_is_retired_and_never_planned(self) -> None:
        self.assertEqual(plan.RETIRED_CHECKS, ("C9",))
        self.assertEqual(plan.CHECKS["C9"].kind, "retired")
        for access in plan.ACCESS_MODES:
            built = s.plan_for("python3-netconf-present", access=access)
            ids = {c.id for stage in built.stages for c in stage.checks} | {c.id for c in built.status_checks}
            self.assertNotIn("C9", ids, access)

    def test_selftest_and_probe(self) -> None:
        expect = {"version": "0.1.0.dev1", "payload_sha256": "ab"}
        self.assertTrue(health.selftest('{"ok": true, "version": "0.1.0.dev1", "payload_sha256": "ab"}', expect).ok)
        self.assertFalse(health.selftest('{"ok": false, "failures": ["x"]}', expect).ok)
        self.assertEqual(health.selftest("", expect).status, health.NOT_CHECKED)
        probe = '{"modules": {"json": "ok", "lxml": "missing: x"}}'
        self.assertFalse(health.probe(probe, {"modules": "json,lxml"}).ok)
        self.assertTrue(health.probe(probe, {"modules": "json"}).ok)
        self.assertTrue(health.probe("noise\n" + probe + "\nmore", {"modules": "json"}).ok)


CRYPTOGRAPHY = f.cryptography_works()
if f.REQUIRE_PYEZ and not CRYPTOGRAPHY:  # the install-autospec job installs requirements-install.txt
    raise AssertionError("JWICKET_REQUIRE_PYEZ=1 but cryptography (pinned in requirements-install.txt) does not work")


class _Listener:
    """A one-connection TLS server on 127.0.0.1 port 0 with a given certificate (a local HTTPS fixture)."""

    def __init__(self, pair: transport.TlsPair, directory: Path, answer: bytes, *, silent: bool = False) -> None:
        cert, key = directory / "tls.crt", directory / "tls.key"
        cert.write_bytes(pair.cert_pem)
        key.write_bytes(pair.key_pem)
        key.chmod(0o600)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(str(cert), str(key))
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(1)
        self.server.settimeout(10)
        self.port = int(self.server.getsockname()[1])
        self.answer = answer
        self.silent = silent
        self.received: List[bytes] = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        try:
            conn, _ = self.server.accept()
        except OSError:
            return
        try:
            with self.context.wrap_socket(conn, server_side=True) as tls:
                tls.settimeout(5)
                try:
                    data = tls.recv(4096)
                except OSError:
                    return
                self.received.append(data)
                if data and not self.silent:
                    tls.sendall(self.answer)
                elif self.silent:
                    threading.Event().wait(3)
        except OSError:
            return

    def close(self) -> None:
        self.server.close()
        self.thread.join(10)


@unittest.skipUnless(CRYPTOGRAPHY, "cryptography is not installed in this Python (requirements-install.txt pins it)")
class PinnedHttpsTests(unittest.TestCase):
    """AC-006-28 against a real TLS stack: transport.make_tls_pair and transport.https_get, the C8 read."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.pair = transport.make_tls_pair("127.0.0.1")
        cls.other = transport.make_tls_pair("127.0.0.1")

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def listen(self, pair: transport.TlsPair, answer: bytes = b"", *, silent: bool = False) -> _Listener:
        directory = self.root / str(len(list(self.root.iterdir())))
        directory.mkdir()
        listener = _Listener(pair, directory, answer, silent=silent)
        self.addCleanup(listener.close)
        return listener

    def get(self, listener: _Listener, pin: str, timeout: float = 5.0) -> transport.HttpsResult:
        host = f"127.0.0.1:{listener.port}"
        return transport.https_get("127.0.0.1", listener.port, "/api/session", host, pin, timeout=timeout)

    def test_the_pinned_certificate_is_read(self) -> None:
        body = b'{"authenticated": false, "version": "0.1.0.dev1", "build": "2e2e2e2e2e2e2e2e"}'
        answer = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + body
        listener = self.listen(self.pair, answer)
        result = self.get(listener, self.pair.cert_sha256)
        self.assertTrue(result.connected and result.pinned, result.reason)
        self.assertEqual(result.peer_sha256, self.pair.cert_sha256)
        expect = {"status": "200", "version": "0.1.0.dev1", "build": "2e2e2e2e2e2e2e2e", "host": "x"}
        self.assertTrue(health.https_session(result.data, expect, connected=True, pinned=True).ok)
        sent = listener.received[0]
        self.assertTrue(sent.startswith(b"GET /api/session HTTP/1.1\r\n"))
        self.assertIn(f"Host: 127.0.0.1:{listener.port}\r\n".encode(), sent)

    def test_the_pair_records_the_certificates_not_after(self) -> None:
        """SEC-R1: the notAfter the receipt records is the certificate's own (read back from the PEM)."""
        import datetime

        from cryptography import x509

        start = datetime.datetime(2026, 11, 25, 12, 0, 0, tzinfo=datetime.timezone.utc)
        pair = transport.make_tls_pair("192.0.2.10", now=start)
        cert = x509.load_pem_x509_certificate(pair.cert_pem)
        after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        self.assertEqual(pair.not_after, after.strftime("%Y-%m-%dT%H:%M:%SZ"))
        self.assertEqual(pair.not_after, "2027-02-23T12:00:00Z")  # 90 days from five minutes before, plus five
        self.assertIsNone(plan.certificate_expiry(pair.not_after, "2026-11-25T12:00:00Z"))
        self.assertIsNotNone(plan.certificate_expiry(pair.not_after, "2027-02-20T00:00:00Z"))

    def test_another_certificate_gets_nothing(self) -> None:
        listener = self.listen(self.other, b"HTTP/1.1 200 OK\r\n\r\n{}")
        result = self.get(listener, self.pair.cert_sha256)
        self.assertTrue(result.connected)
        self.assertFalse(result.pinned)
        self.assertEqual(result.peer_sha256, self.other.cert_sha256)
        listener.close()
        self.assertNotIn(b"GET", b"".join(listener.received))  # the client closed without sending the request

    def test_a_silent_listener_times_out(self) -> None:
        listener = self.listen(self.pair, silent=True)
        result = self.get(listener, self.pair.cert_sha256, timeout=1.0)
        self.assertTrue(result.connected and result.pinned)
        self.assertIn("no answer within", result.reason)

    def test_nothing_listening_is_not_connected(self) -> None:
        free = socket.socket()
        free.bind(("127.0.0.1", 0))
        port = int(free.getsockname()[1])
        free.close()
        result = transport.https_get("127.0.0.1", port, "/api/session", "h:1", self.pair.cert_sha256, timeout=2.0)
        self.assertFalse(result.connected)
        self.assertIn("failed", result.reason)

    def test_the_certificate_is_rsa_2048_for_the_address_and_never_shows_its_key(self) -> None:
        x509 = __import__("cryptography.x509", fromlist=["x509"])
        pair = transport.make_tls_pair("192.0.2.10")
        cert = x509.load_pem_x509_certificate(pair.cert_pem)
        self.assertEqual(cert.public_key().key_size, plan.TLS_KEY_BITS)
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertEqual([str(ip) for ip in names.get_values_for_type(x509.IPAddress)], ["192.0.2.10"])
        der = ssl.PEM_cert_to_DER_cert(pair.cert_pem.decode("ascii"))
        self.assertEqual(pair.cert_sha256, hashlib.sha256(der).hexdigest())
        self.assertEqual(transport.pem_certificate_sha256(pair.cert_pem), pair.cert_sha256)
        lifetime = _not_after(cert) - _not_before(cert)
        self.assertEqual(lifetime.days, plan.TLS_CERT_DAYS)
        self.assertTrue(pair.key_pem.startswith(b"-----BEGIN PRIVATE KEY-----"))
        self.assertNotIn("PRIVATE", repr(pair))
        pair.forget_key()
        self.assertEqual(pair.key_pem, b"")
        with self.assertRaises(plan.InputError):
            transport.make_tls_pair("192.0.2.010")  # not canonical


def _not_after(cert: Any) -> datetime.datetime:
    value: Optional[datetime.datetime] = getattr(cert, "not_valid_after_utc", None)
    return value.replace(tzinfo=None) if value is not None else cert.not_valid_after


def _not_before(cert: Any) -> datetime.datetime:
    value: Optional[datetime.datetime] = getattr(cert, "not_valid_before_utc", None)
    return value.replace(tzinfo=None) if value is not None else cert.not_valid_before


if __name__ == "__main__":
    unittest.main()
