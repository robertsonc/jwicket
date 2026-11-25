"""Host-key trust for every connection (Spec 006 section 8.10, INV-09, AC-006-23). No device is
contacted: keys are synthetic blobs, and PyEZ and paramiko are replaced by recording stand-ins."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import stat
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional

import fakes_junos as f
from install_support import plan

from jwicket_install import hostkeys, transport

KEY = f.KEY_A
OTHER = f.KEY_B
B64 = base64.b64encode(KEY[1]).decode("ascii")


def hashed_name(name: str, salt: bytes = b"0123456789abcdefghij") -> str:
    digest = hmac.new(salt, name.encode("ascii"), hashlib.sha1).digest()
    return f"|1|{base64.b64encode(salt).decode()}|{base64.b64encode(digest).decode()}"


class KnownHostsTests(unittest.TestCase):
    def test_fingerprint_is_openssh_sha256_form(self) -> None:
        fp = hostkeys.fingerprint(KEY)
        self.assertRegex(fp, plan.FINGERPRINT_RE)
        expected = "SHA256:" + base64.b64encode(hashlib.sha256(KEY[1]).digest()).decode().rstrip("=")
        self.assertEqual(fp, expected)

    def test_plain_port_hashed_wildcard_negated_and_revoked_entries(self) -> None:
        text = "\n".join(
            [
                "# comment",
                f"lab1,lab1.example {KEY[0]} {B64}",
                f"[lab2]:2222 {KEY[0]} {B64}",
                f"{hashed_name('lab3')} {KEY[0]} {B64}",
                f"lab-*,!lab-bad {KEY[0]} {B64}",
                f"@revoked lab5 {KEY[0]} {B64}",
                f"@cert-authority *.example {KEY[0]} {B64}",
                "garbage line",
            ]
        )
        entries = hostkeys.parse_known_hosts(text, "test")
        self.assertTrue(hostkeys.judge(entries, "lab1", 22, KEY).known)
        self.assertTrue(hostkeys.judge(entries, "lab2", 2222, KEY).known)
        self.assertFalse(hostkeys.judge(entries, "lab2", 22, KEY).known)
        self.assertTrue(hostkeys.judge(entries, "lab3", 22, KEY).known)
        self.assertTrue(hostkeys.judge(entries, "lab-x", 22, KEY).known)
        self.assertFalse(hostkeys.judge(entries, "lab-bad", 22, KEY).known)
        with self.assertRaises(hostkeys.HostKeyError):
            hostkeys.judge(entries, "lab5", 22, KEY)
        self.assertFalse(hostkeys.judge(entries, "other", 22, KEY).known)  # cert-authority lines ignored

    def test_a_different_key_of_the_same_type_is_always_refused(self) -> None:
        entries = hostkeys.parse_known_hosts(f"lab1 {KEY[0]} {B64}\n", "test")
        with self.assertRaises(hostkeys.HostKeyError) as caught:
            hostkeys.judge(entries, "lab1", 22, OTHER)
        self.assertIn("differs", str(caught.exception))

    def test_non_default_port_accepts_the_host_entry_as_ncclient_does(self) -> None:
        entries = hostkeys.parse_known_hosts(f"lab1 {KEY[0]} {B64}\n", "test")
        self.assertTrue(hostkeys.judge(entries, "lab1", 830, KEY).known)

    def test_two_ports_with_different_keys_refuse(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            known = Path(tmp) / "known_hosts"
            known.write_text(f"lab1 {KEY[0]} {B64}\n", encoding="utf-8")
            keys = {22: KEY, 830: OTHER}
            with self.assertRaises(hostkeys.HostKeyError) as caught:
                hostkeys.verify_ports("lab1", (22, 830), lambda port, types: keys[port], [known])
            self.assertIn("different host keys", str(caught.exception))

    def test_key_types_steer_the_exchange(self) -> None:
        entries = hostkeys.parse_known_hosts(f"lab1 ssh-rsa {B64}\n", "test")
        types = hostkeys.algorithms_for(hostkeys.key_types_for(entries, "lab1", 22))
        self.assertEqual(types, ("rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"))

    def test_pinned_files_hold_only_the_verified_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            known, config = hostkeys.pinned_files(Path(tmp), "lab1", [830], KEY)
            self.assertEqual(
                known.read_text(encoding="utf-8").splitlines(),
                [f"[lab1]:830 {KEY[0]} {B64}", f"lab1 {KEY[0]} {B64}"],
            )
            self.assertIn(f"UserKnownHostsFile {known}", config.read_text(encoding="utf-8"))
            for path in (known, config):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_append_private_creates_0600_and_refuses_a_loose_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "known_hosts"
            hostkeys.append_private(path, [hostkeys.known_line("lab1", 22, KEY)])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            path.chmod(0o644)
            with self.assertRaises(hostkeys.HostKeyError):
                hostkeys.append_private(path, ["x"])


class ExecutorHostKeyTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.device = f.FakeDevice()
        self.harness = f.Harness(self.device, self.root)

    def run_install(self, console: f.FakeConsole, **run: Any) -> int:
        code, _ = f.install(self.harness, f.make_bundle(), console, **run)
        return code

    def test_unknown_key_refuses_without_accept_new(self) -> None:
        self.harness.known.write_text("", encoding="utf-8")
        console = f.FakeConsole(self.device, f.gate_answers())
        self.assertEqual(self.run_install(console), plan.EXIT_REFUSED)
        self.assertIn("R-HOSTKEY", console.text())
        self.assertIn(hostkeys.fingerprint(KEY), console.text())
        self.assertNotIn("ssh-open", self.device.names())
        self.assertEqual(self.device.writes_before("never"), [])

    def test_accept_new_prints_the_fingerprint_and_writes_the_private_file(self) -> None:
        self.harness.known.write_text("", encoding="utf-8")
        console = f.FakeConsole(self.device, ["yes", f.HOST])
        self.assertEqual(self.run_install(console, accept_new_host_key=True), plan.EXIT_OK, console.text())
        private = self.harness.store.known_hosts()
        self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o600)
        self.assertIn(B64, private.read_text(encoding="utf-8"))
        self.assertIn(hostkeys.fingerprint(KEY), console.text())
        stored = self.harness.store.read_receipt(hostkeys.fingerprint(KEY))
        assert stored is not None
        self.assertIn("--accept-new-host-key", plan.Receipt.from_json(stored).overrides)

    def test_accept_new_needs_a_typed_yes(self) -> None:
        self.harness.known.write_text("", encoding="utf-8")
        console = f.FakeConsole(self.device, ["no"])
        self.assertEqual(self.run_install(console, accept_new_host_key=True), plan.EXIT_REFUSED)
        self.assertFalse(self.harness.store.known_hosts().exists())

    def test_different_keys_per_port_refuse_before_any_write(self) -> None:
        self.device.host_keys = {22: KEY, 830: OTHER}
        console = f.FakeConsole(self.device, f.gate_answers())
        executor = self.harness.executor(console, netconf_port=830, apply=True)
        code = executor.install(f.bundle_identity(f.make_bundle()), f.make_bundle(), f.provenance_ok(), f.options())
        self.assertEqual(code, plan.EXIT_REFUSED)
        self.assertIn("different host keys", console.text())
        self.assertEqual(self.device.writes_before("never"), [])
        self.assertNotIn("netconf-open", self.device.names())

    def test_ncclient_is_pinned_to_the_one_verified_key(self) -> None:
        console = f.FakeConsole(self.device, f.gate_answers())
        connector = f.FakeConnector(self.device)
        executor = self.harness.executor(console, apply=False)
        executor.connector = connector
        executor.install(f.bundle_identity(f.make_bundle()), f.make_bundle(), f.provenance_ok(), f.options())
        self.assertEqual(len(connector.ssh_configs), 1)
        self.assertIn("UserKnownHostsFile", connector.ssh_configs[0])
        self.assertFalse(list(self.harness.store.root.glob("run-*")))  # removed after the run

    def test_by_default_ssh_and_netconf_share_one_host_and_port(self) -> None:
        target = transport.Target("lab1", f.USER)
        self.assertEqual(target.ports, (22,))
        self.assertEqual(target.nc_port, target.ssh_port)
        self.assertEqual(transport.Target("lab1", f.USER, 2222).ports, (2222,))


class AdapterTests(unittest.TestCase):
    """The PyEZ adapter and the own client, with recording stand-ins (no PyEZ or paramiko needed)."""

    def test_device_is_built_with_hostkey_verify_true_on_the_ssh_port(self) -> None:
        built: List[Dict[str, Any]] = []

        class Device:
            def __init__(self, **kwargs: Any) -> None:
                built.append(kwargs)

        class Errors:
            pass

        session = transport.PyezNetconf(
            transport.Target("lab1", f.USER, 2222),
            transport.Credentials(),
            "/state/run-x/ssh_config",
            f.FakeClock(f.FakeDevice()),
            device_factory=Device,
            config_factory=lambda dev: None,
            errors=Errors,
        )
        kwargs = session.device_kwargs()
        self.assertIs(kwargs["hostkey_verify"], True)
        self.assertEqual(kwargs["port"], 2222)
        self.assertEqual(kwargs["ssh_config"], "/state/run-x/ssh_config")
        self.assertEqual(kwargs["conn_open_timeout"], 30)
        self.assertNotIn("passwd", kwargs)
        with_830 = transport.PyezNetconf(
            transport.Target("lab1", f.USER, 22, 830),
            transport.Credentials(password="fixture-pass"),
            "c",
            f.FakeClock(f.FakeDevice()),
            device_factory=Device,
            config_factory=lambda d: None,
            errors=Errors,
        ).device_kwargs()
        self.assertEqual(with_830["port"], 830)
        self.assertEqual(with_830["passwd"], "fixture-pass")
        self.assertNotIn("fixture-pass", repr(transport.Credentials(password="fixture-pass")))

    def test_a_rejected_netconf_host_key_is_not_netconf_off(self) -> None:
        """SEC-03: PyEZ 2.8.3 raises ConnectRefusedError for ncclient's SSHUnknownHostError within 3 s; the
        adapter looks at the chained exception and reports the host key, not 'NETCONF is off'."""

        class Errors:
            class ConnectError(Exception):
                pass

            class ConnectAuthError(ConnectError):
                pass

            class ConnectRefusedError(ConnectError):
                pass

        class SSHUnknownHostError(Exception):  # the class name ncclient uses
            pass

        def opener(cause: Optional[BaseException]) -> Any:
            class Device:
                def __init__(self, **kwargs: Any) -> None:
                    pass

                def open(self) -> None:
                    # As PyEZ 2.8.3 does: the ncclient error is the context of its ConnectRefusedError.
                    inner = cause if cause is not None else OSError("connection refused")
                    raise Errors.ConnectRefusedError("refused") from inner

            return Device

        def session(cause: Optional[BaseException]) -> transport.PyezNetconf:
            return transport.PyezNetconf(
                transport.Target("lab1", f.USER),
                transport.Credentials(),
                "c",
                f.FakeClock(f.FakeDevice()),
                device_factory=opener(cause),
                config_factory=lambda d: None,
                errors=Errors,
            )

        with self.assertRaises(transport.HostKeyRejected):
            session(SSHUnknownHostError("unknown host key")).open()
        with self.assertRaises(transport.NetconfUnavailable):
            session(None).open()

    def test_own_client_policy_rejects_every_key_but_the_pinned_one(self) -> None:
        class SSHException(Exception):
            pass

        class RejectPolicy:
            def missing_host_key(self, client: Any, hostname: str, key: Any) -> None:
                raise SSHException(f"Server {hostname!r} not found in known_hosts")

        class FakeParamiko:
            pass

        FakeParamiko.RejectPolicy = RejectPolicy  # type: ignore[attr-defined]

        class Key:
            def __init__(self, blob: tuple) -> None:
                self.blob = blob

            def get_name(self) -> str:
                return self.blob[0]

            def asbytes(self) -> bytes:
                return self.blob[1]

        policy = transport.pinned_policy(FakeParamiko, KEY)
        self.assertIsInstance(policy, RejectPolicy)
        policy.missing_host_key(None, "lab1", Key(KEY))
        with self.assertRaises(SSHException):
            policy.missing_host_key(None, "lab1", Key(OTHER))

    def test_own_client_connect_keywords(self) -> None:
        client = transport.OwnSsh(
            transport.Target("lab1", f.USER, 2222), transport.Credentials(), KEY, hostkeys.algorithms_for([KEY[0]])
        )
        kwargs = client.connect_kwargs(object())
        self.assertEqual((kwargs["hostname"], kwargs["port"], kwargs["username"]), ("lab1", 2222, f.USER))
        for name in ("timeout", "banner_timeout", "auth_timeout", "channel_timeout"):
            self.assertEqual(kwargs[name], 30)
        self.assertNotIn("ssh-ed25519", kwargs["disabled_algorithms"]["keys"])
        self.assertIn("ssh-rsa", kwargs["disabled_algorithms"]["keys"])
        self.assertNotIn("password", kwargs)

    def test_rpc_choke_point(self) -> None:
        with self.assertRaises(ValueError):
            transport.check_rpc("request-shell-execute", {}, "write")
        with self.assertRaises(ValueError):
            transport.check_rpc("delete-directory", {"directory": "/var/db/jwicket", "recurse": True}, "write")
        with self.assertRaises(ValueError):
            transport.check_rpc("file-delete", {"path": "/x"}, "read")
        with self.assertRaises(ValueError):
            transport.check_rpc("file-list", {"path": "/x\n<check/>"}, "read")
        transport.check_rpc("file-list", {"detail": True, "path": "/var/db"}, "read")

    def test_read_retries_with_back_off_and_writes_do_not(self) -> None:
        sleeps: List[float] = []
        attempts = [0]

        def flaky() -> transport.Reply:
            attempts[0] += 1
            if attempts[0] < 3:
                raise transport.ReadTimeout("slow")
            return "<ok/>"

        self.assertEqual(transport.retry_read(flaky, "x", sleeps.append), "<ok/>")
        self.assertEqual(sleeps, [1, 2])
        sleeps.clear()

        def always() -> transport.Reply:
            raise transport.ReadTimeout("slow")

        with self.assertRaises(transport.ReadTimeout):
            transport.retry_read(always, "x", sleeps.append)
        self.assertEqual(sleeps, [1, 2, 4])

        calls = [0]

        class Rpc:
            def file_delete(self, **kwargs: Any) -> Any:
                calls[0] += 1
                raise Errors.RpcTimeoutError()

        class Errors:
            class RpcError(Exception):
                pass

            class RpcTimeoutError(RpcError):
                pass

            class ConnectClosedError(Exception):
                pass

        session = transport.PyezNetconf(
            transport.Target("lab1", f.USER),
            transport.Credentials(),
            "c",
            f.FakeClock(f.FakeDevice()),
            device_factory=lambda **k: None,
            config_factory=lambda d: None,
            errors=Errors,
        )
        session._dev = type("D", (), {"rpc": Rpc()})()
        with self.assertRaises(transport.OutcomeUnknown):
            session.write("file-delete", path="/var/db/scripts/jet/jwicket-next.py")
        self.assertEqual(calls[0], 1)  # never retried

    def test_state_dir_with_unsafe_characters_is_refused_for_the_ssh_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            odd = Path(tmp) / "with space"
            odd.mkdir()
            with self.assertRaises(hostkeys.HostKeyError):
                hostkeys.pinned_files(odd, "lab1", [22], KEY)

    def test_known_hosts_file_modes_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kh"
            path.write_text(f"lab1 {KEY[0]} {B64}\n", encoding="utf-8")
            os.chmod(path, 0o644)
            hostkeys.read_known_hosts([path])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)


if __name__ == "__main__":
    unittest.main()
