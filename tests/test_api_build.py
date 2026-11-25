"""Spec 006 bundle change D3: the build is visible to an installer's health check.

The start log line, the audit ``start`` record and ``GET /api/session`` carry the bundle's payload
digest (checks C4, C5 and C8), so an installer can prove that the build it just installed is the
one listening and not an earlier process. The digest comes from ``jwicket._embedded``, which only
the bundle has; from src/ it is absent and said to be absent.

The daemon tests start the real daemon (from src/ and from a built bundle) in a child process on
127.0.0.1 with a temporary settings file and the netconf backend, which opens nothing until
somebody signs in; nothing here talks to a device. They hold the daemon's own start line, audit
record and session answer against what the installer expects of them: ``plan.start_line`` and
``health.start_line`` (C4), ``health.audit_start`` (C5) and the version and build C8 compares. One
run listens with TLS in the ``mgmt_junos`` routing instance, as ``--access tls`` renders it for a
device with ``system management-instance`` (verified on a lab SRX4100,
docs/evidence/2026-11-24-srx4100-lab); a stand-in for the Junos ``jcs`` module records the switch.
"""

from __future__ import annotations

import dataclasses
import hashlib
import http.client
import importlib
import json
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest import mock

from helpers import FIXTURE_PASSWORD, LiveServer, make_app

from jwicket import __version__, api, resources
from jwicket.devserver import FixtureBackend

REPO = Path(__file__).resolve().parent.parent
TOOLS = REPO / "tools"
BRANCH = Path(__file__).resolve().parent / "fixtures" / "branch"
TIMEOUT_S = 120
START_TIMEOUT_S = 30.0
# Ports another build on this machine uses; a test never picks one of them.
RESERVED_PORTS = range(8341, 8361)
DIGEST = "0123456789abcdef" * 4
# The start line as the diagnostic log formats it. The TLS warning just before it also contains
# "listening on", so a health check must match this, not the bare words.
START_LINE = " INFO jwicket listening on "
_HEADER_PAYLOAD = re.compile(r"^payload sha256:  ([0-9a-f]{64})$", re.MULTILINE)
INSTALL_USER = "jwicket"

# A stand-in for the Junos on-box jcs module, for the routing-instance run only: it records each
# set_routing_instance call, so the test sees the listener's instance chosen and the default restored.
FAKE_JCS = """
import os


def set_routing_instance(name):
    with open(os.environ["JWICKET_TEST_JCS_CALLS"], "a", encoding="utf-8") as handle:
        handle.write(name + "\\n")
"""


def tool(name: str) -> types.ModuleType:
    """A module from tools/ (jwicket_install.plan, jwicket_install.health), imported as test_bundle does."""
    if str(TOOLS) not in sys.path:
        sys.path.append(str(TOOLS))
    return importlib.import_module(name)


def fake_embedded(**attrs: Any) -> types.ModuleType:
    module = types.ModuleType("jwicket._embedded")
    module.RESOURCES = {}  # type: ignore[attr-defined]
    for name, value in attrs.items():
        setattr(module, name, value)
    return module


class PayloadDigestTests(unittest.TestCase):
    def tearDown(self) -> None:
        resources.reset_cache()  # in case anything read the fake module's (empty) resources

    def test_absent_when_running_from_src(self) -> None:
        self.assertNotIn("jwicket._embedded", sys.modules)
        self.assertIsNone(api.bundle_payload_sha256())

    def test_read_from_the_embedded_module(self) -> None:
        with mock.patch.dict(sys.modules, {"jwicket._embedded": fake_embedded(PAYLOAD_SHA256=DIGEST)}):
            self.assertEqual(api.bundle_payload_sha256(), DIGEST)

    def test_anything_but_64_lowercase_hex_is_treated_as_absent(self) -> None:
        for value in (DIGEST.upper(), DIGEST[:-1], DIGEST + "0", DIGEST + "\n", 12, None, b"0" * 64):
            fake = fake_embedded(PAYLOAD_SHA256=value)
            # One line, not a parenthesised group: that form of "with" needs Python 3.9 (the floor is 3.7).
            with self.subTest(value=value), mock.patch.dict(sys.modules, {"jwicket._embedded": fake}):
                self.assertIsNone(api.bundle_payload_sha256())
        with mock.patch.dict(sys.modules, {"jwicket._embedded": fake_embedded()}):
            self.assertIsNone(api.bundle_payload_sha256())


class SessionBuildTests(unittest.TestCase):
    def setUp(self) -> None:
        resources.reset_cache()
        self.srv = LiveServer(make_app(FixtureBackend(BRANCH)))
        self.addCleanup(self.srv.stop)
        self.addCleanup(resources.reset_cache)

    def session(self, cookie: Optional[str] = None) -> Dict[str, Any]:
        reply = self.srv.get("/api/session", cookie)
        self.assertEqual(reply.status, 200, reply.body)
        body: Dict[str, Any] = reply.json()
        return body

    def test_build_is_null_from_src(self) -> None:
        body = self.session()
        self.assertIn("build", body)
        self.assertIsNone(body["build"])
        self.assertEqual(body["version"], __version__)

    def test_build_is_the_first_16_hex_of_the_payload_signed_out_and_in(self) -> None:
        with mock.patch.dict(sys.modules, {"jwicket._embedded": fake_embedded(PAYLOAD_SHA256=DIGEST)}):
            self.assertEqual(self.session()["build"], DIGEST[:16])
            reply, cookie = self.srv.login("admin", FIXTURE_PASSWORD)
            self.assertEqual(reply.status, 200, reply.body)
            body = self.session(cookie)
            self.assertTrue(body["authenticated"])
            self.assertEqual((body["build"], body["version"]), (DIGEST[:16], __version__))


# --- the daemon itself ------------------------------------------------------------------------------


def free_port() -> int:
    """A port the kernel just handed out for 127.0.0.1 (bound to port 0), outside RESERVED_PORTS."""
    for _attempt in range(20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = int(sock.getsockname()[1])
        if port >= 1024 and port not in RESERVED_PORTS:
            return port
    raise AssertionError("no usable loopback port")


def self_signed(directory: Path) -> Optional[Tuple[Path, Path]]:
    """A throwaway RSA-2048 certificate for 127.0.0.1 made with the openssl command (as
    test_http_server does), both files mode 0600; None if openssl is missing or too old for -addext."""
    openssl = shutil.which("openssl")
    if openssl is None:
        return None
    cert, key = directory / "tls.crt", directory / "tls.key"
    proc = subprocess.run(  # noqa: S603 - fixed argument list, no shell
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=127.0.0.1",
         "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", str(key), "-out", str(cert)],
        capture_output=True, timeout=60, check=False,
    )
    if proc.returncode != 0:
        return None
    for path in (cert, key):
        os.chmod(path, 0o600)
    return cert, key


class Daemon:
    """One daemon process with its own state directory and settings file.

    ``tls`` adds a throwaway certificate (tls_cert, tls_key); ``routing_instance`` sets [server]
    routing_instance and puts the stand-in jcs module on PYTHONPATH (so the command must not use -I)."""

    def __init__(
        self,
        command: List[str],
        env: Optional[Dict[str, str]] = None,
        *,
        tls: bool = False,
        routing_instance: Optional[str] = None,
    ) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="jwicket-daemon-"))
        os.chmod(self.dir, 0o700)
        self.port = free_port()
        self.log = self.dir / "jwicket.log"
        self.audit = self.dir / "audit.jsonl"
        self.jcs_calls = self.dir / "jcs-calls.txt"
        self.cert: Optional[Path] = None
        server = ["bind = 127.0.0.1", f"port = {self.port}", f"allowed_hosts = 127.0.0.1:{self.port}"]
        if tls:
            made = self_signed(self.dir)
            if made is None:
                shutil.rmtree(self.dir, ignore_errors=True)
                raise unittest.SkipTest("the openssl command is not available (or has no -addext)")
            self.cert, key = made
            server += [f"tls_cert = {self.cert}", f"tls_key = {key}"]
        if routing_instance is not None:
            server.append(f"routing_instance = {routing_instance}")
            fake = self.dir / "fake-jcs"
            fake.mkdir(mode=0o700)
            (fake / "jcs.py").write_text(FAKE_JCS, encoding="utf-8")
            env = {**(os.environ if env is None else env), "PYTHONPATH": str(fake),
                   "JWICKET_TEST_JCS_CALLS": str(self.jcs_calls)}
        ini = self.dir / "jwicket.ini"
        ini.write_text(
            "[server]\n" + "".join(f"{line}\n" for line in server)
            + "[auth]\n"
            "backend = netconf\n"
            "[log]\n"
            f"file = {self.log}\n"
            f"audit_file = {self.audit}\n",
            encoding="utf-8",
        )
        os.chmod(ini, 0o600)
        self.proc = subprocess.Popen(  # noqa: S603 - fixed argument list, no shell, this interpreter
            [sys.executable, *command, "--config", str(ini)],
            cwd=str(self.dir),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def wait_listening(self) -> str:
        deadline = time.monotonic() + START_TIMEOUT_S
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                out, err = self.proc.communicate(timeout=TIMEOUT_S)
                raise AssertionError(f"daemon exited {self.proc.returncode}: {out}{err}")
            text = self.log.read_text(encoding="utf-8") if self.log.exists() else ""
            if START_LINE in text:
                return text
            time.sleep(0.05)
        raise AssertionError("the daemon did not log its start line in time")

    def get(self, path: str) -> Tuple[int, Any]:
        """GET over plain HTTP, or over TLS trusting only this daemon's certificate and checking that
        the certificate presented is that one by its SHA-256 (as installer check C8 pins it)."""
        conn: http.client.HTTPConnection
        if self.cert is None:
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        else:
            context = ssl.create_default_context(cafile=str(self.cert))
            conn = http.client.HTTPSConnection("127.0.0.1", self.port, timeout=10, context=context)
        try:
            conn.connect()
            if self.cert is not None:
                sock = conn.sock
                if not isinstance(sock, ssl.SSLSocket):
                    raise AssertionError(f"not a TLS connection: {sock!r}")
                presented = hashlib.sha256(sock.getpeercert(binary_form=True) or b"").hexdigest()
                pinned = hashlib.sha256(ssl.PEM_cert_to_DER_cert(self.cert.read_text(encoding="ascii"))).hexdigest()
                if presented != pinned:
                    raise AssertionError(f"the daemon presented certificate {presented}, not {pinned}")
            conn.request("GET", path, headers={"Host": f"127.0.0.1:{self.port}"})
            resp = conn.getresponse()
            return resp.status, json.loads(resp.read().decode("utf-8"))
        finally:
            conn.close()

    def stop(self) -> str:
        """SIGTERM, then the audit trail the run wrote."""
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.communicate(timeout=TIMEOUT_S)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.communicate(timeout=TIMEOUT_S)
        return self.audit.read_text(encoding="utf-8") if self.audit.exists() else ""

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.communicate(timeout=TIMEOUT_S)
        shutil.rmtree(self.dir, ignore_errors=True)


class DaemonBuildTests(unittest.TestCase):
    bundle_dir: Path
    bundle: Path
    digest: str
    found: Any  # jwicket_install.plan.BundleId: the bundle as the installer reads its header
    plan: types.ModuleType
    health: types.ModuleType

    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = tool("jwicket_install.plan")
        cls.health = tool("jwicket_install.health")
        cls.bundle_dir = Path(tempfile.mkdtemp(prefix="jwicket-build-"))
        os.chmod(cls.bundle_dir, 0o700)
        cls.bundle = cls.bundle_dir / "jwicket.py"
        proc = subprocess.run(  # noqa: S603 - fixed argument list, no shell, this interpreter
            [sys.executable, str(REPO / "tools" / "bundle.py"), "--out", str(cls.bundle)],
            cwd=str(REPO),
            capture_output=True,
            text=True,
            timeout=TIMEOUT_S,
            check=False,
        )
        if proc.returncode != 0:
            raise AssertionError(f"bundle build failed: {proc.stdout}{proc.stderr}")
        data = cls.bundle.read_bytes()
        head = data[:4096].decode("ascii")
        found = _HEADER_PAYLOAD.search(head)
        if found is None:
            raise AssertionError("the bundle header has no payload sha256 line")
        cls.digest = found.group(1)
        cls.found = cls.plan.BundleId.from_header(head, hashlib.sha256(data).hexdigest(), len(data))

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.bundle_dir, ignore_errors=True)

    def start(self, command: List[str], env: Optional[Dict[str, str]] = None, **kwargs: Any) -> Daemon:
        daemon = Daemon(command, env, **kwargs)
        self.addCleanup(daemon.close)
        return daemon

    def check_run(
        self, daemon: Daemon, payload: Optional[str], *, tls: bool = False, instance: str = "default"
    ) -> Tuple[str, Dict[str, Any], str]:
        """The start line, GET /api/session and the audit start record of one run, which ends here;
        returns the log, the session answer and the audit trail."""
        log = daemon.wait_listening()
        short = payload[:16] if payload else "none"
        expected = (
            f"listening on 127.0.0.1:{daemon.port} tls={tls} backend=netconf routing_instance={instance} "
            f"version={__version__} payload={short}"
        )
        lines = [line for line in log.splitlines() if START_LINE in line]
        self.assertEqual(len(lines), 1, log)
        self.assertTrue(lines[0].endswith(" INFO jwicket " + expected), lines[0])
        status, body = daemon.get("/api/session")
        self.assertEqual(status, 200, body)
        self.assertEqual((body["version"], body["build"]), (__version__, payload[:16] if payload else None))
        audit = daemon.stop()
        records = [json.loads(line) for line in audit.splitlines()]
        starts = [r for r in records if r["event"] == "start"]
        self.assertEqual(len(starts), 1, records)
        self.assertEqual(starts[0]["version"], __version__)
        self.assertEqual(starts[0]["backend"], "netconf")
        self.assertIn("payload_sha256", starts[0])
        self.assertEqual(starts[0]["payload_sha256"], payload)
        self.assertEqual(daemon.proc.returncode, 0)
        return log, body, audit

    def c4(self, log: str, options: Any, instance: Optional[str], bundle: Any = None) -> Any:
        """Installer check C4 on this log, with the expectation the plan builds for ``bundle``."""
        line, build = self.plan.start_line(bundle or self.found, options, instance)
        return self.health.start_line(log.encode("utf-8"), 0, {"line": line, "build": build}, None)

    def assert_installer_checks_pass(
        self, log: str, body: Dict[str, Any], audit: str, options: Any, instance: Optional[str]
    ) -> None:
        """C4, C5 and C8's comparison pass on what the real daemon wrote, and C4 fails when the plan
        expects another routing instance or another build: the match is exact, not a loose prefix."""
        passed = self.c4(log, options, instance)
        self.assertEqual(passed.status, self.health.PASS, passed.detail)
        other_instance = None if instance else self.plan.MGMT_INSTANCE
        self.assertEqual(self.c4(log, options, other_instance).status, self.health.FAIL)
        other_build = dataclasses.replace(self.found, payload_sha256="f" * 64)
        self.assertEqual(self.c4(log, options, instance, other_build).status, self.health.FAIL)
        # A bundle without "build-line" (D3) is matched on the prefix up to the backend only.
        older = dataclasses.replace(self.found, features=frozenset())
        self.assertEqual(self.c4(log, options, instance, older).status, self.health.PASS)
        c5 = self.health.audit_start(
            audit.encode("utf-8"), 0, {"version": self.found.version, "payload_sha256": self.found.payload_sha256}
        )
        self.assertEqual(c5.status, self.health.PASS, c5.detail)
        # C8 compares these two fields of GET /api/session with the bundle's header.
        self.assertEqual((body["version"], body["build"]), (self.found.version, self.found.payload_short))

    def test_the_bundle_names_its_build(self) -> None:
        daemon = self.start(["-I", str(self.bundle)])
        log, body, audit = self.check_run(daemon, self.digest)
        options = self.plan.Options(user=INSTALL_USER, access="tunnel", port=daemon.port)
        self.assert_installer_checks_pass(log, body, audit, options, None)

    def test_tls_in_the_management_instance(self) -> None:
        """--access tls on a device with 'system management-instance': TLS on the listen address and
        routing_instance = mgmt_junos give the start line C4 expects, and only the listener is created
        in that instance (jcs is switched there and back to the default before anything else)."""
        daemon = self.start([str(self.bundle)], tls=True, routing_instance="mgmt_junos")
        log, body, audit = self.check_run(daemon, self.digest, tls=True, instance="mgmt_junos")
        self.assertEqual(daemon.jcs_calls.read_text(encoding="utf-8").splitlines(), ["mgmt_junos", "default"])
        options = self.plan.Options(user=INSTALL_USER, access="tls", listen_address="127.0.0.1", port=daemon.port)
        self.assert_installer_checks_pass(log, body, audit, options, self.plan.MGMT_INSTANCE)

    def test_the_source_tree_says_it_has_no_build(self) -> None:
        env = {**os.environ, "PYTHONPATH": str(REPO / "src")}
        self.check_run(self.start(["-m", "jwicket"], env), None)


if __name__ == "__main__":
    unittest.main()
