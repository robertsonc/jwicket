"""The on-box op-script installer, M4 and M4U (Spec 006 sections 6.5 and 6.6; AC-006-32).

Everything here runs against fakes (tests/fakes_onbox.py): a fake ``jcs``, a fake local PyEZ ``Device`` and
``Config``, and a configuration model. A passing test shows what the op script does with these fakes; it
proves nothing about what a device sends or does (lab tests Q-INST-01, Q-INST-05 and Q-INST-06). No
junos-eznc, paramiko, scp or cryptography is needed. The revision's rules are tested here as the op script
keeps them: R1 (Python 3.7), R2 (tls with the operator's own TLS pair, or tunnel), R3 (C8 without an SSH
channel, C9 retired), R4 (the state directory is root's) and R5 (--lab-hardware and 'lab only').
"""

from __future__ import annotations

import ast
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tokenize
import unittest
from pathlib import Path
from typing import Any, List, Tuple

import fakes_onbox as f
import install_support

from jwicket_install import build_op, op_template, plan, transport
from jwicket_install.plan import Method

TOOLS = install_support.TOOLS
OP_SOURCE = TOOLS / "jwicket_install" / "op_template.py"
BUILD_SOURCE = TOOLS / "jwicket_install" / "build_op.py"


def _bundle_file(directory: Path, data: bytes = b"") -> Path:
    path = directory / "jwicket.py"
    path.write_bytes(data or f.make_bundle())
    return path


def _commits_after(box: f.FakeBox, index: int) -> List[Tuple[object, ...]]:
    return [c for c in box.calls[index:] if c[0] == "commit"]


class BuildTests(unittest.TestCase):
    """build_op.py: reproducible, embeds the bundle's SHA-256 and the plan modules (AC-006-32)."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.bundle = _bundle_file(self.dir)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_two_builds_are_byte_identical_and_embed_the_bundle_hash(self) -> None:
        one = build_op.build(self.bundle, f.TAG, f.REPO)
        two = build_op.build(self.bundle, f.TAG, f.REPO)
        self.assertEqual(one.text, two.text)
        sha = hashlib.sha256(self.bundle.read_bytes()).hexdigest()
        self.assertIn(f"bundle sha256:     {sha}", one.text)
        self.assertIn(f"BUNDLE_SHA256 = {sha!a}", one.text)
        self.assertTrue(one.text.isascii())
        self.assertEqual(one.url, f"https://github.com/{f.REPO}/releases/download/{f.TAG}/jwicket.py")
        self.assertNotIn("/releases/latest", one.text.split('"""', 2)[1], "per-tag URLs only")

    def test_cli_writes_the_same_bytes_twice_and_check_detects_an_edit(self) -> None:
        out1, out2 = self.dir / "a.py", self.dir / "b.py"
        args = ["--bundle", str(self.bundle), "--tag", f.TAG, "--repo", f.REPO]
        self.assertEqual(build_op.main([*args, "--out", str(out1)]), 0)
        self.assertEqual(build_op.main([*args, "--out", str(out2)]), 0)
        self.assertEqual(out1.read_bytes(), out2.read_bytes())
        self.assertEqual(stat.S_IMODE(out1.stat().st_mode), 0o644)
        self.assertEqual(build_op.main([*args, "--out", str(out1), "--check"]), 0)
        out1.write_bytes(out1.read_bytes() + b"# edited\n")
        self.assertEqual(build_op.main([*args, "--out", str(out1), "--check"]), 1)

    def test_payload_is_op_payload_with_the_release(self) -> None:
        script = build_op.build(self.bundle, f.TAG, f.REPO)
        tree = ast.parse(script.text)
        found = {
            node.targets[0].id: node.value
            for node in tree.body
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
        }
        payload = json.loads(ast.literal_eval(found["PAYLOAD_JSON"]))
        self.assertEqual(payload["schema"], plan.PLAN_SCHEMA)
        self.assertEqual(payload["bundle"]["file_sha256"], script.bundle.file_sha256)
        self.assertEqual(payload["urls"], {"bundle": script.url})
        self.assertEqual(payload["release"], {"tag": f.TAG, "repo": f.REPO})
        self.assertEqual(payload["device_status"], plan.DEVICE_STATUS)
        parsed = op_template.Payload.from_json(ast.literal_eval(found["PAYLOAD_JSON"]))
        self.assertEqual(parsed.bundle, script.bundle)

    def test_embeds_exactly_the_plan_modules_and_their_digest(self) -> None:
        script = build_op.build(self.bundle, f.TAG, f.REPO)
        names = [m.name for m in script.modules]
        self.assertEqual(
            names,
            sorted(["jwicket_install", *(f"jwicket_install.{n}" for n in build_op.EMBEDDED if n != "__init__")]),
        )
        for required in ("plan", "state", "render", "op_template"):
            self.assertIn(f"jwicket_install.{required}", names)
        self.assertNotIn("jwicket_install.workstation", names)
        self.assertNotIn("jwicket_install.cli", names)
        for module in script.modules:
            source = (TOOLS / module.relpath).read_text(encoding="utf-8")
            self.assertEqual(module.source, source)
        self.assertIn(f"modules sha256:    {build_op.modules_sha256(script.modules)}", script.text)

    def test_refuses_a_tag_that_is_not_the_bundles_version(self) -> None:
        with self.assertRaises(build_op.BuildError):
            build_op.build(self.bundle, "v9.9.9.dev9", f.REPO)
        with self.assertRaises(build_op.BuildError):
            build_op.build(self.bundle, f.TAG, "not a repo")
        with self.assertRaises(build_op.BuildError):
            build_op.build(self.bundle, f.TAG, "owner/repo/../x")

    def test_refuses_a_file_that_is_not_a_bundle(self) -> None:
        other = self.dir / "other.py"
        other.write_text("print('hello')\n", encoding="ascii")
        with self.assertRaises(build_op.BuildError):
            build_op.build(other, f.TAG, f.REPO)
        self.assertEqual(build_op.main(["--bundle", str(other), "--tag", f.TAG, "--repo", f.REPO, "--out", "x"]), 2)

    def _package_copy(self) -> Path:
        package = self.dir / "jwicket_install"
        package.mkdir()
        for stem in build_op.EMBEDDED:
            shutil.copyfile(str(TOOLS / "jwicket_install" / f"{stem}.py"), str(package / f"{stem}.py"))
        return package

    def test_refuses_an_embedded_module_beyond_python_3_7(self) -> None:
        """R1: a module-level import Python 3.7 lacks, or 3.8+ grammar, fails the build, not the device."""
        cases = {
            "graphlib": "import graphlib\n",
            "importlib.metadata": "import importlib.metadata\n",
            "a third-party module": "import yaml\n",
            "an assignment expression": "if (n := 1):\n    pass\n",
            "positional-only parameters": "def g(a, /):\n    return a\n",
        }
        for name, extra in cases.items():
            with self.subTest(name):
                package = self._package_copy()
                try:
                    source = (package / "render.py").read_text(encoding="utf-8")
                    (package / "render.py").write_text(source + "\n" + extra, encoding="utf-8")
                    with self.assertRaises(build_op.BuildError):
                        build_op.collect_modules(package)
                finally:
                    shutil.rmtree(str(package))

    def test_the_standard_library_list_is_python_3_7s(self) -> None:
        self.assertEqual(build_op.MIN_PYTHON, (3, 7))
        self.assertEqual(op_template.MIN_PYTHON, build_op.MIN_PYTHON)
        names = getattr(sys, "stdlib_module_names", None)
        if names is None:
            self.skipTest("sys.stdlib_module_names is Python 3.10+")
        self.assertLessEqual(set(build_op.STDLIB_37), set(names))
        for newer in ("graphlib", "zoneinfo", "tomllib"):
            self.assertNotIn(newer, build_op.STDLIB_37)

    def test_the_header_says_who_makes_the_directory_and_the_tls_pair(self) -> None:
        script = build_op.build(self.bundle, f.TAG, f.REPO)
        header = script.text.split('"""', 2)[1]
        self.assertIn(plan.STATE_DIR_ROOT_STEP, header)
        self.assertIn("never makes the TLS key pair", header)
        self.assertIn("_MIN_PYTHON = (3, 7)", script.text)


def _parse_as_python_3_7(source: str, filename: str) -> ast.Module:
    """ast.parse with Python 3.7's grammar: feature_version on 3.8 and later, the interpreter's own on 3.7."""
    if sys.version_info >= (3, 8):
        return ast.parse(source, filename=filename, feature_version=(3, 7))
    return ast.parse(source, filename=filename)


class Python37Tests(unittest.TestCase):
    """Revision R1: Junos 25.2R1-S1.4 ships Python 3.7.10 (verified on a lab SRX4100). Every installer module
    and the generated op script must parse with Python 3.7's grammar (CI also runs these tests on 3.7)."""

    def test_every_installer_module_parses_as_python_3_7(self) -> None:
        sources = sorted((TOOLS / "jwicket_install").glob("*.py"))
        self.assertTrue(sources)
        for path in sources:
            with self.subTest(module=path.name):
                _parse_as_python_3_7(path.read_text(encoding="utf-8"), str(path))

    def test_the_generated_op_script_parses_as_python_3_7(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            script = build_op.build(_bundle_file(Path(tmp)), f.TAG, f.REPO)
        _parse_as_python_3_7(script.text, plan.OP_FILE)
        for module in script.modules:
            with self.subTest(module=module.name):
                _parse_as_python_3_7(module.source, module.relpath)
        self.assertEqual(build_op.parse_37("x = 1\n", "x.py").body[0].lineno, 1)

    def test_the_parse_refuses_newer_grammar(self) -> None:
        sources = ["if (n := 1):\n    pass\n", "def g(a, /):\n    return a\n"]
        if sys.version_info >= (3, 8):  # 3.7 cannot even tokenize the last as such; it fails there anyway
            sources.append("x = 1\ny = f'{x=}'\n")
        for source in sources:
            with self.subTest(source=source), self.assertRaises(SyntaxError):
                build_op.parse_37(source, "new.py")
        build_op.parse_37("x = 1\ny = f'x={x} {x == 1} {x:=^4} {x!r}'\n", "ok.py")  # all Python 3.7


class GeneratedScriptTests(unittest.TestCase):
    """The generated file itself: the Python version and the jcs and PyEZ imports are checked first."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls.tmp.name)
        bundle = _bundle_file(cls.dir)
        cls.script = cls.dir / "op" / plan.OP_FILE
        cls.script.parent.mkdir()
        cls.script.write_bytes(build_op.build(bundle, f.TAG, f.REPO).text.encode("ascii"))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def _run(self, args: List[str], env_path: str = "") -> subprocess.CompletedProcess[str]:
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        if env_path:
            env["PYTHONPATH"] = env_path
        return subprocess.run(  # noqa: S603 - this interpreter and a test file, as an argument list
            [sys.executable, *args],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(self.dir),
            env=env,
            check=False,
        )

    def test_without_jcs_it_prints_device_status_first_and_reads_nothing(self) -> None:
        done = self._run(["-I", str(self.script)])
        self.assertEqual(done.returncode, plan.EXIT_REFUSED, done.stderr)
        lines = done.stdout.splitlines()
        self.assertEqual(lines[0], plan.DEVICE_STATUS)
        self.assertIn("'jcs' module is not available", done.stdout)

    def test_an_old_python_stops_before_anything_is_compiled(self) -> None:
        code = (
            "import sys\n"
            "sys.version_info = (3, 6, 15, 'final', 0)\n"
            f"path = {str(self.script)!r}\n"
            "source = open(path, encoding='ascii').read()\n"
            "exec(compile(source, path, 'exec'), {'__name__': '__main__', '__file__': path})\n"
        )
        done = self._run(["-I", "-c", code])
        self.assertEqual(done.returncode, 1)
        self.assertEqual(done.stdout.splitlines()[0], plan.DEVICE_STATUS)
        self.assertIn("needs Python 3.7 or later; this device runs 3.6", done.stdout)

    def test_pyez_import_is_checked_before_any_read(self) -> None:
        fake = self.dir / "fakemods"
        (fake / "jnpr").mkdir(parents=True)
        (fake / "jcs.py").write_text("def get_input(prompt):\n    raise AssertionError('no prompt')\n")
        (fake / "jnpr" / "__init__.py").write_text("raise ImportError('no PyEZ here (test)')\n")
        # -S: where junos-eznc is installed (CI's install-autospec job), its *-nspkg.pth file puts the real
        # 'jnpr' namespace in sys.modules at start-up, before PYTHONPATH's fake could be imported.
        done = self._run(["-S", str(self.script)], env_path=str(fake))
        self.assertEqual(done.returncode, plan.EXIT_REFUSED, done.stderr)
        self.assertIn("On-box PyEZ (jnpr.junos) does not import", done.stdout)

    def test_a_module_beside_the_script_cannot_stand_in(self) -> None:
        planted = self.script.parent / "jwicket_install"
        planted.mkdir(exist_ok=True)
        (planted / "__init__.py").write_text("raise SystemExit('planted package imported')\n")
        (self.script.parent / "jcs.py").write_text("raise SystemExit('planted jcs imported')\n")
        try:
            done = self._run([str(self.script)])
        finally:
            (planted / "__init__.py").unlink()
            planted.rmdir()
            (self.script.parent / "jcs.py").unlink()
        self.assertNotIn("planted", done.stdout + done.stderr)
        self.assertIn("'jcs' module is not available", done.stdout)


class PayloadTests(unittest.TestCase):
    def test_rejects_a_bad_payload(self) -> None:
        good = json.loads(f.payload_text(f.make_bundle()))
        for change in (
            {"schema": 1},
            {"urls": {"bundle": "http://example.net/jwicket.py"}},
            {"urls": {"bundle": "https://user:pw@example.net/jwicket.py"}},
            {"release": {"tag": "v1 ; rm", "repo": f.REPO}},
        ):
            data = dict(good)
            data.update(change)
            with self.assertRaises(plan.PlanError):
                op_template.Payload.from_json(json.dumps(data))
        with self.assertRaises(plan.PlanError):
            op_template.Payload.from_json("not json")

    def test_a_bad_payload_exits_2_before_anything(self) -> None:
        box = f.FakeBox()
        harness = f.Harness(box)
        code = op_template.main(
            "{}", jcs_module=object(), pyez=(lambda: f.FakeDevice(box), f.FakeConfig, f.FakeErrors), out=io.StringIO()
        )
        self.assertEqual(code, plan.EXIT_INPUT)
        self.assertEqual(box.calls, [])
        del harness


class PrecheckTests(unittest.TestCase):
    def test_old_python_and_missing_modules_send_nothing(self) -> None:
        box = f.FakeBox()
        box.paste_bootstrap()
        before = len(box.calls)
        harness = f.Harness(box)
        self.assertEqual(harness.run(f.HOST, version=(3, 6, 15)), plan.EXIT_REFUSED)
        self.assertIn("needs Python 3.7 or later; this device runs 3.6.15", harness.output)
        self.assertEqual(harness.output.splitlines()[0], plan.DEVICE_STATUS)
        self.assertEqual(len(box.calls), before, "nothing read or written")

        def no_pyez() -> Tuple[object, object, object]:
            raise ImportError("No module named 'jnpr'")

        original = op_template.import_pyez
        op_template.import_pyez = no_pyez  # type: ignore[assignment]
        try:
            self.assertEqual(harness.run(f.HOST, pyez=None), plan.EXIT_REFUSED)
        finally:
            op_template.import_pyez = original  # type: ignore[assignment]
        self.assertIn("On-box PyEZ (jnpr.junos) does not import", harness.output)
        self.assertEqual(len(box.calls), before, "nothing read or written")

    def test_the_srx4100s_python_3_7_10_runs(self) -> None:
        box = f.FakeBox()
        box.paste_bootstrap()
        harness = f.Harness(box)
        self.assertEqual(harness.run(f.HOST, version=(3, 7, 10)), plan.EXIT_OK, harness.output)

    def test_root_is_refused_before_any_read(self) -> None:
        box = f.FakeBox()
        harness = f.Harness(box)
        code = harness.run(f.HOST, account=op_template.Account(0, "root", "/root"))
        self.assertEqual(code, plan.EXIT_REFUSED)
        self.assertIn("R-ROOT", harness.output)
        self.assertEqual(box.calls, [])


class DryRunTests(unittest.TestCase):
    """SC-01: without the matching typed host name only reads are sent, and the host name is not shown."""

    def setUp(self) -> None:
        self.box = f.FakeBox()
        self.boot = self.box.paste_bootstrap()
        self.mark = len(self.box.calls)

    def test_enter_at_the_gate_writes_nothing_and_leaves_the_bootstrap_pending(self) -> None:
        harness = f.Harness(self.box)
        self.assertEqual(harness.run(""), plan.EXIT_GATE)
        self.assertEqual(self.box.writes(), [])
        self.assertIsNotNone(self.box.pending, "the bootstrap stays unconfirmed: Junos removes it at its deadline")
        self.assertIn("Junos removes it at its deadline", harness.output)
        self.assertIn("The plan's change (patch form", harness.output)
        self.assertIn(plan.POSTURE_WARNING, harness.output)
        self.assertIn(plan.TLS_POSTURE_WARNING, harness.output)  # R2: a new HTTPS listener, not past G1
        self.assertIn(plan.root_blast_radius(f.USER), harness.output)
        self.assertNotIn(f.HOST, harness.output, "the host name is never printed before or at a failed gate")

    def test_a_wrong_name_writes_nothing(self) -> None:
        harness = f.Harness(self.box)
        self.assertEqual(harness.run("lab-vsrx-2"), plan.EXIT_GATE)
        self.assertEqual(self.box.writes(), [])

    def test_the_gate_prompt_is_the_lab_gate_text_and_the_host_name_appears_only_after_it(self) -> None:
        harness = f.Harness(self.box)
        self.assertEqual(harness.run(f.HOST), plan.EXIT_OK, harness.output)
        assert harness.jcs is not None
        prompts = [p for p, _, _ in harness.jcs.prompts]
        self.assertEqual(
            prompts, [op_template.access_prompt("tls"), op_template.listen_prompt(None), plan.LAB_GATE_PROMPT]
        )
        self.assertEqual(harness.jcs.asked(), [plan.LAB_GATE_PROMPT])
        self.assertNotIn(f.HOST, plan.LAB_GATE_PROMPT)
        self.assertNotIn(f.HOST, harness.output_before_prompt(2))
        self.assertIn(f"Lab gate passed for {f.HOST}.", harness.output)

    def test_the_dry_run_shows_the_listener_and_the_certificate_fingerprint_before_the_gate(self) -> None:
        harness = f.Harness(self.box)
        self.assertEqual(harness.run(""), plan.EXIT_GATE)
        before = harness.output_before_prompt(2)
        self.assertIn(plan.fingerprint_display(f.CERT_SHA), before)
        self.assertIn(f"https://{f.LISTEN}:{plan.DEFAULT_TLS_PORT}/", before)
        self.assertIn(f"check    {plan.TLS_KEY_PATH} mode 0600 (yours, made in the shell", before)
        self.assertNotIn("from op-script", before)
        self.assertNotIn(f.KEY_PEM.decode("ascii").splitlines()[1], harness.output, "the key is never shown")

    def test_every_write_follows_the_gate(self) -> None:
        harness = f.Harness(self.box)
        self.assertEqual(harness.run(f.HOST), plan.EXIT_OK, harness.output)
        gate = harness.gate_index()
        early = [c for c in self.box.writes() if self.box.calls.index(c) < gate]
        self.assertEqual(early, [])
        reads = {c[1] for c in self.box.calls[self.mark : gate] if c[0] == "rpc"}
        self.assertLessEqual(reads, transport.READ_RPCS)
        self.assertNotIn("commit-configuration", reads)


class BootstrapTests(unittest.TestCase):
    """AC-006-11 / cut C5: only the script's own unconfirmed bootstrap is recognised and confirmed, after the gate."""

    def test_confirms_its_own_bootstrap_after_the_gate(self) -> None:
        box = f.FakeBox()
        boot = box.paste_bootstrap()
        harness = f.Harness(box)
        self.assertEqual(harness.run(f.HOST), plan.EXIT_OK, harness.output)
        gate = harness.gate_index()
        confirms = [c for c in box.calls if c[0] == "commit" and c[1] == boot.confirm_comment]
        self.assertEqual(len(confirms), 1)
        self.assertIsNone(confirms[0][2], "the bootstrap's confirm is a plain commit with its comment")
        self.assertGreater(box.calls.index(confirms[0]), gate)
        self.assertIsNone(box.pending)
        receipt = harness.receipt()
        self.assertTrue(receipt.bootstrap_confirmed_by_installer)
        self.assertEqual(receipt.bootstrap_kind, "op")
        self.assertEqual(set(receipt.bootstrap_added), {"S1", "S14"})

    def test_near_misses_are_r_pending_and_nothing_is_written(self) -> None:
        cases = {
            "another user": lambda box: box.paste_bootstrap(user=f.OTHER),
            "an extra line": lambda box: box.paste_bootstrap(extra=["set system services netconf ssh"]),
            "a foreign pending commit": lambda box: box.foreign_commit(confirmed=True),
        }
        for name, setup in cases.items():
            with self.subTest(name):
                box = f.FakeBox()
                setup(box)
                harness = f.Harness(box)
                self.assertEqual(harness.run(f.HOST), plan.EXIT_REFUSED, harness.output)
                self.assertIn("R-PENDING", harness.output)
                self.assertEqual(box.writes(), [])
                assert harness.jcs is not None
                self.assertEqual(harness.jcs.asked(), [], "no gate is asked when a refusal blocks")

    def test_op_url_bootstrap_removes_allow_url_for_python_at_the_end(self) -> None:
        box = f.FakeBox()
        boot = box.paste_bootstrap(Method.ONBOX_URL)
        self.assertEqual(boot.comment, "jwicket-bootstrap op-url")
        harness = f.Harness(box)
        self.assertEqual(harness.run(f.HOST), plan.EXIT_OK, harness.output)
        self.assertIn(plan.ALLOW_URL_WARNING, harness.output)
        self.assertFalse(box.committed.under("system scripts op allow-url-for-python"))
        self.assertTrue(box.committed.has("system scripts language", "python3"))
        self.assertEqual(harness.receipt().method, "op-url")

    def test_a_bootstrap_that_junos_rolled_back_is_not_reported(self) -> None:
        box = f.FakeBox()
        box.paste_bootstrap()
        box.clock.sleep(11 * 60)  # the operator never ran the script: Junos rolls the bootstrap back
        self.assertIsNone(box.pending)
        harness = f.Harness(box)
        harness.run("")
        self.assertNotIn("was confirmed by a later commit", harness.output)

    def test_a_bootstrap_confirmed_by_someone_else_is_reported(self) -> None:
        box = f.FakeBox()
        box.paste_bootstrap()
        box.foreign_commit(confirmed=False)  # another administrator's commit confirms the bootstrap
        harness = f.Harness(box)
        harness.run("")
        self.assertIn("was confirmed by a later commit that this script did not make", harness.output)


class ApplyTests(unittest.TestCase):
    def test_install_from_the_release_url(self) -> None:
        box, harness = f.installed_box()
        bundle = harness.bundle
        sha = hashlib.sha256(bundle).hexdigest()
        for name in plan.JWICKET_JET_FILES:
            info = box.files[f"{plan.JET_DIR}/{name}"]
            self.assertEqual((info.sha256, info.owner, info.mode), (sha, f.USER, 0o644))
        self.assertNotIn(plan.STAGING_PATH, box.files, "the staging file is deleted once the copies are verified")
        self.assertEqual(box.files[plan.STATE_DIR].mode, 0o700)
        for path in (plan.SETTINGS_PATH, plan.RECEIPT_PATH, plan.UNINSTALL_CLI_PATH):
            self.assertEqual(box.files[path].mode, 0o600, path)
            self.assertEqual(box.files[path].owner, f.USER, path)
        settings = box.files[plan.SETTINGS_PATH].data.decode("utf-8")
        self.assertEqual(settings, plan.render_settings(f.plan_options()))
        self.assertIn(f"bind = {f.LISTEN}\nport = {plan.DEFAULT_TLS_PORT}", settings)
        self.assertIn(f"allowed_hosts = {f.LISTEN}:{plan.DEFAULT_TLS_PORT}", settings)
        self.assertNotIn("routing_instance", settings, "no management-instance on this vSRX")
        self.assertIsNotNone(box.daemon)
        pulls = [c for c in box.calls if c[0] == "rpc" and c[1] == "file-copy" and str(c[2]["source"]) == f.URL]
        self.assertEqual(len(pulls), 1)
        self.assertEqual(pulls[0][2]["destination"], plan.STAGING_PATH, "every transfer lands in the staging name")
        receipt = harness.receipt()
        self.assertEqual(receipt.method, "op")
        self.assertEqual(receipt.provenance_kind, "operator-hash")
        self.assertEqual(receipt.veriexec_source, "op script read")
        self.assertEqual([c.stage for c in receipt.commits], ["bootstrap", "diagnostics", "runtime"])
        self.assertTrue(all(c.confirmed for c in receipt.commits))
        self.assertEqual(
            (receipt.access, receipt.listen_address, receipt.port, receipt.routing_instance),
            ("tls", f.LISTEN, plan.DEFAULT_TLS_PORT, None),
        )
        self.assertEqual(receipt.tls_cert_sha256, f.CERT_SHA)
        self.assertFalse(receipt.state_dir_created)
        self.assertFalse(receipt.lab_hardware_attested)
        self.assertIn("C8 pass: 200, version", harness.output)
        self.assertIn(f"Open it: https://{f.LISTEN}:{plan.DEFAULT_TLS_PORT}/", harness.output)
        self.assertIn(plan.fingerprint_display(f.CERT_SHA), harness.output.split("is installed on")[1])

    def test_the_operators_tls_pair_is_checked_never_written_and_the_key_never_read(self) -> None:
        box, harness = f.installed_box()
        self.assertEqual(box.files[plan.TLS_KEY_PATH].data, f.KEY_PEM)
        self.assertEqual(box.files[plan.TLS_CERT_PATH].data, f.CERT_PEM)
        for call in box.calls:
            if call[0] == "local-write":
                self.assertNotIn(call[1], (plan.TLS_KEY_PATH, plan.TLS_CERT_PATH))
            if call[0] == "rpc" and call[1] in ("file-show", "file-copy", "file-delete"):
                self.assertNotIn(plan.TLS_KEY_PATH, json.dumps(call[2]), call)
        https = [c for c in box.calls if c[0] == "https"]
        self.assertEqual(len(https), 1)
        self.assertEqual(
            https[0][1:], (f.LISTEN, plan.DEFAULT_TLS_PORT, "/api/session", f"{f.LISTEN}:9443", f.CERT_SHA)
        )
        self.assertNotIn("FIXTURE-PLACEHOLDER", harness.output)
        self.assertNotIn(plan.TLS_KEY_PATH, harness.receipt().files_created)

    def test_each_stage_is_commit_confirmed_and_confirmed_by_its_comment(self) -> None:
        box, _ = f.installed_box()
        commits = [c for c in box.calls if c[0] == "commit"]
        confirmed = [c for c in commits if c[2] is not None]
        self.assertEqual([c[2] for c in confirmed], [5, 5])
        for call in commits:
            self.assertTrue(plan.is_installer_comment(str(call[1])), call)
        self.assertNotIn("check", " ".join(str(c) for c in box.calls).replace("checksum", ""))

    def test_uninstall_cli_txt_holds_the_removal_units(self) -> None:
        box, _ = f.installed_box()
        text = box.files[plan.UNINSTALL_CLI_PATH].data.decode("utf-8")
        self.assertIn("delete system extensions extension-service application file jwicket.py", text)
        self.assertIn("delete system scripts op file jwicket-install-op.py", text)
        self.assertIn('commit confirmed 5 comment "jwicket uninstall lab-install"', text)
        self.assertIn(plan.DEVICE_STATUS, text)
        self.assertNotIn("commit check", text)

    def test_install_from_a_home_directory_copy(self) -> None:
        box = f.FakeBox()
        box.paste_bootstrap()
        harness = f.Harness(box, home_copy=True)
        self.assertEqual(harness.run(f.HOST), plan.EXIT_OK, harness.output)
        writes = [c for c in box.calls if c[0] == "local-write"]
        self.assertEqual(writes[0][1:], (plan.STAGING_PATH, 0o644))
        self.assertFalse(any(c[0] == "rpc" and c[1] == "file-copy" and str(c[2]["source"]) == f.URL for c in box.calls))
        self.assertIn("the copy in your home directory", harness.output)
        for call in writes:
            path = str(call[1])
            self.assertTrue(path == plan.STAGING_PATH or path.startswith(plan.STATE_DIR + "/"), path)

    def test_a_home_copy_that_fails_its_checks_stops_before_the_gate(self) -> None:
        cases = {
            "another hash": {"data": f.make_bundle(filler="tampered")},
            "a symbolic link": {"is_symlink": True},
            "group-writable": {"mode": 0o664},
            "another owner": {"owner": f.OTHER},
        }
        for name, change in cases.items():
            with self.subTest(name):
                box = f.FakeBox()
                box.paste_bootstrap()
                harness = f.Harness(box, home_copy=True)
                home = box.files[f"{f.HOME}/jwicket.py"]
                for attr, value in change.items():
                    setattr(home, attr, value)
                self.assertEqual(harness.run(f.HOST), plan.EXIT_INTEGRITY, harness.output)
                self.assertEqual(box.writes(), [])
                assert harness.jcs is not None
                self.assertEqual(harness.jcs.prompts, [], "the home copy is read before any question")

    def test_a_stale_staging_file_is_replaced_never_trusted(self) -> None:
        box = f.FakeBox()
        box.paste_bootstrap()
        box.files[plan.STAGING_PATH] = f.FakeFile(b"stale bytes", owner=f.USER, mode=0o644)
        harness = f.Harness(box)
        self.assertEqual(harness.run(f.HOST), plan.EXIT_OK, harness.output)
        self.assertNotIn(plan.STAGING_PATH, box.files)
        self.assertEqual(box.files[plan.DAEMON_PATH].sha256, hashlib.sha256(harness.bundle).hexdigest())

    def test_a_rerun_changes_nothing_and_runs_the_read_checks(self) -> None:
        box, harness = f.installed_box()
        mark = len(box.calls)
        self.assertEqual(harness.run(""), plan.EXIT_OK, harness.output)  # Enter: plan an install, not uninstall
        self.assertIn("Nothing to change", harness.output)
        self.assertIn("Healthy.", harness.output)
        self.assertEqual([c for c in box.writes() if box.calls.index(c) >= mark], [])


class UpgradeTests(unittest.TestCase):
    """Spec 9.4 through the op script: new bytes to the staging name, configured copies replaced only right
    before the commit that changes their checksum, the old daemon kept as jwicket-prev.py until confirmed."""

    NEW = f.make_bundle(filler="second build", payload="3d" * 32)
    NEW_OP_SHA = "5b" * 32

    def _operator_repins(self, box: f.FakeBox, *, confirm: bool) -> None:
        line = f"set {' '.join(plan.SPEC_BY_KEY['S14'].path)} {self.NEW_OP_SHA}"
        box.cli_commit([line], "jwicket-bootstrap op", confirm=10 if confirm else None)

    def test_an_upgrade_replaces_the_files_inside_their_stages(self) -> None:
        box, _ = f.installed_box()
        old_sha = box.files[plan.DAEMON_PATH].sha256
        self._operator_repins(box, confirm=False)
        harness = f.Harness(box, bundle=self.NEW)
        self.assertEqual(harness.run("", f.HOST), plan.EXIT_OK, harness.output)
        new_sha = hashlib.sha256(self.NEW).hexdigest()
        for name in plan.JWICKET_JET_FILES:
            self.assertEqual(box.files[f"{plan.JET_DIR}/{name}"].sha256, new_sha, name)
        self.assertNotIn(plan.BACKUP_PATH, box.files)
        self.assertNotIn(plan.STAGING_PATH, box.files)
        self.assertIsNotNone(box.daemon)
        assert box.daemon is not None
        self.assertEqual(box.daemon.payload, "3d" * 32)
        backups = [
            c for c in box.calls if c[0] == "rpc" and c[1] == "file-copy" and c[2]["destination"] == plan.BACKUP_PATH
        ]
        self.assertEqual(len(backups), 1)
        self.assertNotEqual(old_sha, new_sha)

    def test_a_failed_upgrade_restores_the_old_bytes_by_copy(self) -> None:
        box, _ = f.installed_box()
        old_sha = box.files[plan.DAEMON_PATH].sha256
        self._operator_repins(box, confirm=False)
        box.on(
            lambda call: call[0] == "commit" and "runtime lab-install" in str(call[1]),
            lambda b: setattr(b.inject, "refuse_start", True),
        )
        harness = f.Harness(box, bundle=self.NEW)
        self.assertEqual(harness.run("", f.HOST), plan.EXIT_CHECK_FAILED, harness.output)
        self.assertEqual(box.files[plan.DAEMON_PATH].sha256, old_sha, "restored by copy, never deleted")
        pinned = box.committed.values(" ".join(plan.SPEC_BY_KEY["S13"].path))
        self.assertEqual(pinned, (old_sha,))
        self.assertIn("The upgrade was rolled back to the previous build", harness.output)

    def test_a_pending_upgrade_unit_a_is_r_pending_until_plan_accepts_the_value_change(self) -> None:
        # The upgrade's unit A replaces S14's value, so its delta removes the old value; recognise_bootstrap
        # accepts additions only (PLAN), so the op script refuses it and Junos rolls it back.
        box, _ = f.installed_box()
        self._operator_repins(box, confirm=True)
        harness = f.Harness(box, bundle=self.NEW)
        self.assertEqual(harness.run("", f.HOST), plan.EXIT_REFUSED, harness.output)
        self.assertIn("R-PENDING", harness.output)


class DirectoryTests(unittest.TestCase):
    """Revision R4: /var/db/jwicket is root's to make (a super-user-class account could not, on SRX4100:
    verified). The op script only reads /var/db and /var/db/jwicket, refuses R-STATEDIR with the root step
    before any write, and never sends make-directory or delete-directory."""

    def _refused(self, box: f.FakeBox, *why: str) -> f.Harness:
        box.paste_bootstrap()
        harness = f.Harness(box)
        self.assertEqual(harness.run(f.HOST), plan.EXIT_REFUSED, harness.output)
        self.assertIn("R-STATEDIR (blocks)", harness.output)
        self.assertIn(plan.directory_fallback(f.USER), harness.output)
        self.assertIn(plan.state_dir_root_step(f.USER), harness.output)
        for text in why:
            self.assertIn(text, harness.output)
        self.assertEqual(box.writes(), [])
        assert harness.jcs is not None
        self.assertEqual(harness.jcs.asked(), [], "no gate while R-STATEDIR holds")
        self.assertIsNotNone(box.pending, "the bootstrap stays unconfirmed: Junos removes it at its deadline")
        return harness

    def test_an_absent_directory_is_r_statedir_with_the_root_step(self) -> None:
        box = f.FakeBox(state_dir=False)
        harness = self._refused(box, f"{plan.STATE_DIR} is absent")
        listed = [c[2]["path"] for c in box.calls if c[0] == "rpc" and c[1] == "file-list"]
        self.assertIn(plan.VAR_DB, listed)
        self.assertIn(plan.STATE_DIR, listed)
        self.assertNotIn("su root", harness.output)

    def test_an_untrusted_directory_is_r_statedir(self) -> None:
        cases = {
            "a symbolic link": (f.FakeFile(owner=f.USER, mode=0o700, is_symlink=True), "is a symbolic link"),
            "owned by root": (f.FakeFile(owner="root", mode=0o700, is_dir=True), "owned by root"),
            "mode 0755": (f.FakeFile(owner=f.USER, mode=0o755, is_dir=True), "has mode 0755, not 0700"),
            "mode 0777": (f.FakeFile(owner=f.USER, mode=0o777, is_dir=True), "has mode 0777, not 0700"),
            "a file": (f.FakeFile(owner=f.USER, mode=0o700), "is not a directory"),
        }
        for name, (entry, why) in cases.items():
            with self.subTest(name):
                box = f.FakeBox(tls_pair=False)
                box.files[plan.STATE_DIR] = entry
                self._refused(box, why)

    def test_the_root_step_comes_before_the_tls_unit(self) -> None:
        box = f.FakeBox(state_dir=False)
        harness = self._refused(box)
        text = harness.output
        self.assertLess(text.index(plan.state_dir_root_step(f.USER)), text.index(plan.shell_tls_lines(f.LISTEN)[3]))

    def test_a_trusted_directory_made_by_root_is_kept(self) -> None:
        box, _ = f.installed_box()
        self.assertEqual((box.files[plan.STATE_DIR].owner, box.files[plan.STATE_DIR].mode), (f.USER, 0o700))
        names = {c[1] for c in box.calls if c[0] == "rpc"}
        self.assertFalse(names & {"make-directory", "delete-directory"})

    def test_a_directory_that_changes_after_the_gate_stops_before_the_bootstrap_confirm(self) -> None:
        box = f.FakeBox()
        box.paste_bootstrap()
        box.on(
            lambda call: call[0] == "prompt" and call[1] == plan.LAB_GATE_PROMPT[:40],
            lambda b: setattr(b.files[plan.STATE_DIR], "mode", 0o777),
        )
        harness = f.Harness(box)
        self.assertEqual(harness.run(f.HOST), plan.EXIT_REFUSED, harness.output)
        self.assertIn("changed since it was read", harness.output)
        self.assertEqual([c for c in box.calls if c[0] == "commit"], [])
        self.assertIsNotNone(box.pending)


class AccessTests(unittest.TestCase):
    """Revision R2 on the box: tls (the default) with the operator's own TLS pair, or tunnel."""

    def test_tunnel_listens_on_loopback_and_c8_is_not_available(self) -> None:
        box, harness = f.installed_box(access="tunnel")
        settings = box.files[plan.SETTINGS_PATH].data.decode("utf-8")
        self.assertEqual(settings, plan.render_settings(f.plan_options("tunnel")))
        self.assertIn("bind = 127.0.0.1", settings)
        self.assertIn(f"C8 not-available: {plan.TUNNEL_C8_REASON}", harness.output)
        self.assertFalse([c for c in box.calls if c[0] == "https"], "no check through any channel")
        self.assertIn(plan.TUNNEL_WARNING, harness.output.split("is installed on")[1])
        self.assertIn(f"ssh -L 127.0.0.1:8443:127.0.0.1:8443 {f.USER}@<device>", harness.output)
        receipt = harness.receipt()
        self.assertEqual((receipt.access, receipt.listen_address, receipt.tls_cert_sha256), ("tunnel", None, None))

    def test_tls_without_the_operators_pair_is_refused_with_the_shell_unit(self) -> None:
        cases = {
            "no pair": lambda box: [box.files.pop(p) for p in (plan.TLS_KEY_PATH, plan.TLS_CERT_PATH)],
            "a key others can read": lambda box: setattr(box.files[plan.TLS_KEY_PATH], "mode", 0o644),
            "a key owned by another account": lambda box: setattr(box.files[plan.TLS_KEY_PATH], "owner", f.OTHER),
            "a group-writable certificate": lambda box: setattr(box.files[plan.TLS_CERT_PATH], "mode", 0o664),
            "a certificate that is not PEM": lambda box: setattr(box.files[plan.TLS_CERT_PATH], "data", b"junk"),
            "a linked certificate": lambda box: setattr(box.files[plan.TLS_CERT_PATH], "is_symlink", True),
        }
        for name, change in cases.items():
            with self.subTest(name):
                box = f.FakeBox()
                change(box)
                box.paste_bootstrap()
                harness = f.Harness(box)
                self.assertEqual(harness.run(f.HOST), plan.EXIT_REFUSED, harness.output)
                self.assertIn(op_template.TLS_NOT_MADE, harness.output)
                for line in plan.shell_tls_lines(f.LISTEN):
                    self.assertIn(line, harness.output)
                self.assertEqual(box.writes(), [])
                assert harness.jcs is not None
                self.assertEqual(harness.jcs.asked(), [])
                self.assertIsNotNone(box.pending)

    def test_management_instance_puts_the_listener_in_mgmt_junos_and_c8_is_not_available_here(self) -> None:
        box = f.FakeBox(config=[(plan.MANAGEMENT_INSTANCE_KEY, "")])
        box, harness = f.installed_box(box)
        settings = box.files[plan.SETTINGS_PATH].data.decode("utf-8")
        self.assertIn(f"routing_instance = {plan.MGMT_INSTANCE}", settings)
        self.assertNotIn("routing-instance", " ".join(p[0] for p in box.committed.pairs))
        self.assertIn("C8 not-available: the listener is in routing instance mgmt_junos", harness.output)
        self.assertFalse([c for c in box.calls if c[0] == "https"])
        self.assertEqual(harness.receipt().routing_instance, plan.MGMT_INSTANCE)
        self.assertIn(f"routing_instance={plan.MGMT_INSTANCE}", box.files[plan.LOG_PATH].data.decode("ascii"))

    def test_bad_answers_stop_before_anything(self) -> None:
        for access, listen in (("both", f.LISTEN), ("tls", "192.0.2.010"), ("tls", "lab-srx-1"), ("tls", "")):
            with self.subTest(access=access, listen=listen):
                box = f.FakeBox()
                box.paste_bootstrap()
                harness = f.Harness(box, access=access, listen=listen)
                self.assertEqual(harness.run(f.HOST), plan.EXIT_INPUT, harness.output)
                self.assertIn("Nothing was written.", harness.output)
                self.assertEqual(box.writes(), [])

    def test_a_wildcard_or_loopback_listen_address_is_r_bind(self) -> None:
        for address in ("0.0.0.0", "127.0.0.1"):  # noqa: S104 - typed answers R-BIND must refuse; nothing binds
            with self.subTest(address=address):
                box = f.FakeBox()
                box.paste_bootstrap()
                harness = f.Harness(box, listen=address)
                self.assertEqual(harness.run(f.HOST), plan.EXIT_REFUSED, harness.output)
                self.assertIn("R-BIND (blocks)", harness.output)
                self.assertEqual(box.writes(), [])

    def test_c8_sends_nothing_to_another_certificate_and_the_stage_is_not_confirmed(self) -> None:
        box = f.FakeBox()
        box.paste_bootstrap()
        other = f.FakeFile(f.ssl_pem(b"another certificate"), owner=f.USER, mode=0o644)
        box.on(lambda call: call[0] == "https", lambda b: b.files.__setitem__(plan.TLS_CERT_PATH, other))
        harness = f.Harness(box)
        self.assertEqual(harness.run(f.HOST), plan.EXIT_CHECK_FAILED, harness.output)
        self.assertIn("C8 fail", harness.output)
        self.assertIn("presented a certificate other than the one", harness.output)
        self.assertIn("Stage runtime is NOT confirmed", harness.output)

    def test_an_https_connection_the_box_refuses_is_not_available_and_the_stage_confirms(self) -> None:
        box = f.FakeBox()
        box.paste_bootstrap()
        box.inject.https_refused = True
        harness = f.Harness(box)
        self.assertEqual(harness.run(f.HOST), plan.EXIT_OK, harness.output)
        self.assertIn("C8 not-available: no HTTPS answer", harness.output)
        self.assertIn("warning: C8 not available", harness.output)

    def test_a_rerun_with_tls_reads_the_pair_again_and_changes_nothing(self) -> None:
        box, harness = f.installed_box()
        mark = len(box.calls)
        self.assertEqual(harness.run(""), plan.EXIT_OK, harness.output)
        self.assertIn("Nothing to change", harness.output)
        self.assertIn("C8 pass", harness.output)
        self.assertEqual([c for c in box.writes() if box.calls.index(c) >= mark], [])
        assert harness.jcs is not None
        self.assertNotIn(plan.LAB_GATE_PROMPT, harness.jcs.asked())

    def test_the_device_receipt_suggests_the_defaults(self) -> None:
        box, harness = f.installed_box(access="tunnel")
        harness.access = ""  # Enter: the receipt's access mode
        harness.run("")
        assert harness.jcs is not None
        self.assertEqual(harness.jcs.prompts[1][0], op_template.access_prompt("tunnel"))


class LabHardwareTests(unittest.TestCase):
    """Revision R5 on the box: R-MODEL refuses all but vSRX unless --lab-hardware, for a physical SRX only;
    then, after the host name, the production signs and the typed 'lab only', recorded. The reference case is
    the SRX4100 of docs/evidence/2026-11-24-srx4100-lab (Security Director Cloud over outbound-ssh)."""

    NEEDS = (plan.LAB_HARDWARE_FLAG, "--ack-managed", "--adopt")

    def _run(self, *answers: str, overrides: Tuple[str, ...] = NEEDS) -> Tuple[f.FakeBox, f.Harness, int]:
        """The lab run's manual install is there, so the first question is install or uninstall (Enter)."""
        box = f.lab_srx4100_box()
        box.paste_bootstrap()
        harness = f.Harness(box, overrides=overrides)
        return box, harness, harness.run("", *answers)

    def test_the_reference_case_installs_after_lab_only(self) -> None:
        box, harness, code = self._run(f.SRX4100_HOST, "lab only")
        self.assertEqual(code, plan.EXIT_OK, harness.output)
        assert harness.jcs is not None
        asked = harness.jcs.asked()
        self.assertEqual(asked[-2:], [plan.LAB_GATE_PROMPT, plan.LAB_HARDWARE_PROMPT])
        text = harness.output
        passed = text.index("Lab gate passed")
        signs = text.index("outbound-ssh client: sd-cloud", passed)  # shown again, after the gate
        self.assertLess(signs, len(harness.output_before_prompt(len(harness.jcs.prompts) - 1)))
        self.assertIn(plan.LAB_HARDWARE_WARNING, text)
        self.assertIn("committers:", text)
        self.assertIn("model: srx4100", text)
        self.assertIn(f"release: {f.SRX4100_RELEASE}", text)
        receipt = harness.receipt()
        self.assertTrue(receipt.lab_hardware_attested)
        for flag in self.NEEDS:
            self.assertIn(flag, receipt.overrides)
        self.assertEqual((receipt.model, receipt.junos_version), ("srx4100", f.SRX4100_RELEASE))
        self.assertEqual(receipt.routing_instance, plan.MGMT_INSTANCE)
        self.assertIn(f"routing_instance = {plan.MGMT_INSTANCE}", box.files[plan.SETTINGS_PATH].data.decode())
        self.assertIn("C8 not-available", text)
        self.assertEqual(box.files[plan.TLS_KEY_PATH].data, f.KEY_PEM, "the lab's own pair, kept")
        # JFR-05: fxp0's route is in mgmt_junos, so the release URL is fetched there (inferred to route it).
        pulls = [c[2] for c in box.calls if c[0] == "rpc" and c[1] == "file-copy" and str(c[2]["source"]) == f.URL]
        self.assertEqual([p.get("routing-instance") for p in pulls], [plan.MGMT_INSTANCE])

    def test_without_lab_hardware_a_physical_srx_is_r_model(self) -> None:
        box, harness, code = self._run(f.SRX4100_HOST, "lab only", overrides=("--ack-managed", "--adopt"))
        self.assertEqual(code, plan.EXIT_REFUSED, harness.output)
        self.assertIn("R-MODEL (blocks)", harness.output)
        self.assertEqual(box.writes(), [])

    def test_r_managed_still_applies(self) -> None:
        box, harness, code = self._run(f.SRX4100_HOST, "lab only", overrides=(plan.LAB_HARDWARE_FLAG, "--adopt"))
        self.assertEqual(code, plan.EXIT_REFUSED, harness.output)
        self.assertIn("R-MANAGED (blocks)", harness.output)
        self.assertEqual(box.writes(), [])

    def test_anything_but_lab_only_stops_with_exit_3_and_no_write(self) -> None:
        for typed in ("lab-only", "Lab only", "", "lab only please", "yes"):
            with self.subTest(typed=typed):
                box, harness, code = self._run(f.SRX4100_HOST, typed)
                self.assertEqual(code, plan.EXIT_GATE, harness.output)
                self.assertIn("'lab only' was not typed", harness.output)
                self.assertEqual(box.writes(), [])
                self.assertIsNotNone(box.pending, "the bootstrap stays unconfirmed")
        box, harness, code = self._run(f.SRX4100_HOST, "  lab only  ")
        self.assertEqual(code, plan.EXIT_OK, harness.output)

    def test_a_device_that_is_not_an_srx_cannot_be_overridden(self) -> None:
        box = f.FakeBox(model="mx204")
        box.paste_bootstrap()
        harness = f.Harness(box, overrides=(plan.LAB_HARDWARE_FLAG,))
        self.assertEqual(harness.run(f.HOST, "lab only"), plan.EXIT_REFUSED, harness.output)
        self.assertIn("--lab-hardware does not apply", harness.output)
        self.assertEqual(box.writes(), [])

    def test_a_vsrx_is_never_asked_for_lab_only(self) -> None:
        box, harness = f.installed_box()
        assert harness.jcs is not None
        self.assertNotIn(plan.LAB_HARDWARE_PROMPT, harness.jcs.asked())
        self.assertFalse(harness.receipt().lab_hardware_attested)

    def test_uninstall_on_the_reference_case_asks_for_lab_only_too(self) -> None:
        box, harness, code = self._run(f.SRX4100_HOST, "lab only")
        self.assertEqual(code, plan.EXIT_OK, harness.output)
        uninstall = f.Harness(box, overrides=(plan.LAB_HARDWARE_FLAG, "--ack-managed"))
        self.assertEqual(uninstall.run(op_template.UNINSTALL_ANSWER, f.SRX4100_HOST, "no"), plan.EXIT_GATE)
        self.assertIn(plan.DAEMON_PATH, box.files)
        self.assertEqual(uninstall.run(op_template.UNINSTALL_ANSWER, f.SRX4100_HOST, "lab only"), plan.EXIT_OK)
        self.assertNotIn(plan.DAEMON_PATH, box.files)

    def test_uninstall_shows_the_production_signs_before_the_host_name(self) -> None:
        """Spec 8.2: the production signs come before both prompts, on uninstall as on install."""
        box, harness, code = self._run(f.SRX4100_HOST, "lab only")
        self.assertEqual(code, plan.EXIT_OK, harness.output)
        uninstall = f.Harness(box, overrides=(plan.LAB_HARDWARE_FLAG, "--ack-managed"))
        self.assertEqual(uninstall.run(op_template.UNINSTALL_ANSWER, f.SRX4100_HOST, "lab only"), plan.EXIT_OK)
        assert uninstall.jcs is not None
        gate = [p[0] for p in uninstall.jcs.prompts].index(plan.LAB_GATE_PROMPT)
        before_gate = uninstall.output_before_prompt(gate)
        self.assertIn("Shown, not judged", before_gate)
        self.assertIn("outbound-ssh client: sd-cloud", before_gate)
        self.assertNotIn(f.SRX4100_HOST, before_gate)


class UnreadableDiffTests(unittest.TestCase):
    """SC-01 on the box: a text diff that cannot be read fails closed (plan.headers_outside), so a change
    outside the select-only read can never be committed and confirmed unseen."""

    def test_an_unreadable_bootstrap_delta_leaves_the_bootstrap_unconfirmed(self) -> None:
        box = f.FakeBox()
        box.paste_bootstrap()
        box.inject.compare_unreadable = True
        harness = f.Harness(box)
        self.assertEqual(harness.run(f.HOST), plan.EXIT_UNEXPECTED_DIFF, harness.output)
        self.assertIn("could not be read", harness.output)
        self.assertEqual([c for c in box.calls if c[0] == "commit"], [])
        self.assertIsNotNone(box.pending)

    def test_an_unreadable_stage_diff_is_discarded_before_its_commit(self) -> None:
        box = f.FakeBox()
        box.paste_bootstrap()
        box.on(lambda call: call[0] == "load", lambda b: setattr(b.inject, "compare_unreadable", True))
        harness = f.Harness(box)
        self.assertEqual(harness.run(f.HOST), plan.EXIT_UNEXPECTED_DIFF, harness.output)
        self.assertIn("differs from the plan; discarded, nothing committed", harness.output)
        confirmed = [c for c in box.calls if c[0] == "commit" and c[2] is not None]
        self.assertEqual(confirmed, [], "no commit confirmed after an unreadable diff")


class CommittedDeltaTests(unittest.TestCase):
    """SPEC-03 (spec 8.7(4), SC-01): the op script's C10 reads the committed delta after 'commit confirmed'
    and before the confirm; an unreadable one, or one with a change outside the select-only read (a commit
    script's), fails C10 while Junos can still roll it back: no confirm, exit 5, the revert."""

    def _run(self, **inject: Any) -> Tuple[f.FakeBox, f.Harness, int]:
        box = f.FakeBox()
        box.paste_bootstrap()

        def arm(b: f.FakeBox) -> None:
            for name, value in inject.items():
                setattr(b.inject, name, value)

        # Armed as the diagnostics stage's commit confirmed is sent: its pre-commit diff was already read.
        box.on(lambda call: call[0] == "commit" and call[2] is not None and "diagnostics" in str(call[1]), arm)
        harness = f.Harness(box)
        return box, harness, harness.run(f.HOST)

    def _check(self, box: f.FakeBox, harness: f.Harness, code: int) -> None:
        self.assertEqual(code, plan.EXIT_CHECK_FAILED, harness.output)
        self.assertIn("C10 fail", harness.output)
        self.assertNotIn("Stage diagnostics confirmed", harness.output)
        confirms = [c for c in box.calls if c[0] == "commit" and c[2] is None and "diagnostics" in str(c[1])]
        self.assertEqual(confirms, [], "the diagnostics stage is never confirmed")
        self.assertIn("Reverted: the device's configuration is as it was before this run.", harness.output)
        self.assertIsNone(box.pending)

    def test_an_unreadable_committed_delta_fails_c10(self) -> None:
        self._check(*self._run(next_delta_unreadable=True))

    def test_a_change_outside_the_plan_in_the_committed_delta_fails_c10(self) -> None:
        self._check(*self._run(next_delta_extra="[edit system login]\n+    user intruder;\n"))


class RevertTests(unittest.TestCase):
    """Spec 6.5 'Failure': everything after the bootstrap's confirm runs inside try/finally."""

    def test_a_failed_runtime_check_reverts_everything_this_run_added(self) -> None:
        box = f.FakeBox()
        box.paste_bootstrap()
        box.inject.refuse_start = True
        harness = f.Harness(box)
        self.assertEqual(harness.run(f.HOST), plan.EXIT_CHECK_FAILED, harness.output)
        self.assertIn("Stage runtime is NOT confirmed", harness.output)
        self.assertNotIn("Stage runtime confirmed", harness.output)
        self.assertEqual(box.committed, box.original, "the bootstrap's statements went too (history provenance)")
        self.assertIn("Reverted: the device's configuration is as it was before this run.", harness.output)
        for name in plan.JWICKET_JET_FILES:
            self.assertNotIn(f"{plan.JET_DIR}/{name}", box.files)
        self.assertNotIn(plan.SETTINGS_PATH, box.files, "the settings this run wrote are deleted")
        self.assertIn(plan.STATE_DIR, box.files, "R4: root's directory stays")
        self.assertEqual(box.files[plan.TLS_KEY_PATH].data, f.KEY_PEM, "the operator's TLS pair stays")
        self.assertIn(plan.STARTUP_REFUSED_PATH, box.files, "the daemon's own refusal stays as evidence")
        self.assertIsNone(box.pending)
        revert = [c for c in box.calls if c[0] == "commit" and "revert" in str(c[1])]
        self.assertEqual([c[2] for c in revert], [5, None], "the revert is a confirmed commit, then its confirm")

    def test_a_failed_download_after_the_bootstrap_confirm_reverts_the_bootstrap(self) -> None:
        box = f.FakeBox()
        box.paste_bootstrap()
        harness = f.Harness(box)
        box.inject.pull_files.clear()
        self.assertEqual(harness.run(f.HOST), plan.EXIT_INTEGRITY, harness.output)
        self.assertEqual(box.committed, box.original)
        self.assertIn(plan.STATE_DIR, box.files, "R4: root's directory stays")
        self.assertNotIn(plan.SETTINGS_PATH, box.files)

    def test_statements_present_before_this_run_are_never_reverted(self) -> None:
        box = f.FakeBox()
        box.paste_bootstrap()
        box.cli_commit([], "jwicket-bootstrap op confirmed")  # confirmed earlier, not by this run
        box.original = box.committed
        box.inject.refuse_start = True
        harness = f.Harness(box)
        self.assertEqual(harness.run(f.HOST), plan.EXIT_CHECK_FAILED, harness.output)
        self.assertEqual(box.committed, box.original, "only this run's diagnostics stage was reverted")
        self.assertTrue(box.committed.has("system scripts language", "python3"))
        self.assertTrue(box.committed.under(" ".join(plan.STANZA_KEYS["F-OP"])))

    def test_an_op_stanza_without_history_needs_the_typed_adopt(self) -> None:
        box = f.FakeBox(
            config=[("system scripts language", "python3"), (" ".join(plan.SPEC_BY_KEY["S14"].path), f.OP_SHA)]
        )
        harness = f.Harness(box)
        self.assertEqual(harness.run(f.HOST), plan.EXIT_REFUSED, harness.output)
        self.assertIn("R-FOREIGN", harness.output)
        self.assertEqual(box.writes(), [])
        self.assertEqual(harness.run("--adopt", f.HOST), plan.EXIT_OK, harness.output)
        self.assertIn("--adopt", harness.receipt().overrides)

    def test_a_foreign_pending_commit_between_stages_stops_without_a_revert_commit(self) -> None:
        box = f.FakeBox()
        box.paste_bootstrap()
        harness = f.Harness(box)
        runtime_lock: List[int] = []

        def is_runtime_lock(call: Tuple[object, ...]) -> bool:
            if call[0] == "lock":
                runtime_lock.append(1)
                return len(runtime_lock) == 3  # bootstrap confirm, diagnostics, then runtime
            return False

        box.on(is_runtime_lock, lambda b: b.foreign_commit(confirmed=True))
        self.assertEqual(harness.run(f.HOST), plan.EXIT_REFUSED, harness.output)
        self.assertIn("R-PENDING", harness.output)
        foreign = next(i for i, e in enumerate(box.history) if e.user == f.OTHER)
        ours_after = [e for e in box.history[:foreign] if e.user == f.USER]
        self.assertEqual(ours_after, [], "no commit after the foreign one: it would confirm theirs")
        self.assertIn("sends no revert commit", harness.output)

    def test_the_revert_units_follow_the_paste_rules(self) -> None:
        box = f.FakeBox()
        box.paste_bootstrap()
        facts, prior = _prepared(box)
        built = _plan(facts, prior)
        revert = plan.build_revert_stage(built, ["bootstrap", "diagnostics"], include_bootstrap=True)
        units = op_template.revert_units(revert, plan.Layout.DIRECT)
        text = "\n".join(line for u in units for line in u.lines)
        self.assertNotIn("commit check", text)
        for unit in units:
            lines = list(unit.lines)
            if any(line.startswith("commit confirmed") for line in lines):
                self.assertTrue(lines[-1].startswith("commit confirmed"))
            if unit.opens_configuration:
                self.assertEqual(lines[:2], [plan.CLI_CONFIGURE, plan.CLI_SHOW_COMMIT])
            if any(line.startswith("commit comment") for line in lines):
                self.assertEqual(lines[1:], [plan.CLI_EXIT])
            for line in lines:
                if line.startswith(("show", "run show")):
                    self.assertTrue(line.endswith("| no-more"), line)


class VeriexecTests(unittest.TestCase):
    def test_sysctl_refused_falls_back_to_a_typed_attestation(self) -> None:
        box = f.FakeBox()
        box.paste_bootstrap()
        harness = f.Harness(box, sysctl=(None, "Operation not permitted"))
        self.assertEqual(harness.run(f.ENFORCING, f.HOST), plan.EXIT_OK, harness.output)
        assert harness.jcs is not None
        self.assertIn(plan.SHELL_VERIEXEC, harness.jcs.prompts[0][0])
        self.assertEqual(harness.receipt().veriexec_source, "read by hand")

    def test_not_enforcing_needs_the_typed_override(self) -> None:
        box = f.FakeBox()
        box.paste_bootstrap()
        harness = f.Harness(box, sysctl=(None, "Operation not permitted"))
        self.assertEqual(harness.run("", ""), plan.EXIT_REFUSED, harness.output)
        self.assertIn("R-VERIEXEC", harness.output)
        self.assertEqual(box.writes(), [])
        harness = f.Harness(box, sysctl=(None, "Operation not permitted"))
        self.assertEqual(harness.run("", "--veriexec-not-enforcing-ok", f.HOST), plan.EXIT_OK, harness.output)
        receipt = harness.receipt()
        self.assertIn("--veriexec-not-enforcing-ok", receipt.overrides)
        self.assertTrue(receipt.not_evidence)

    def test_the_sysctl_reader_uses_a_fixed_argument_list(self) -> None:
        self.assertEqual(op_template.SYSCTL_ARGV, ("/sbin/sysctl", "security.mac.veriexec.state"))
        self.assertEqual(" ".join(("sysctl", *op_template.SYSCTL_ARGV[1:])), plan.SHELL_VERIEXEC)


class UninstallTests(unittest.TestCase):
    def test_uninstall_after_install(self) -> None:
        box, harness = f.installed_box()
        self.assertEqual(harness.run(op_template.UNINSTALL_ANSWER, f.HOST), plan.EXIT_OK, harness.output)
        self.assertIsNone(box.daemon)
        for name in (*plan.JWICKET_JET_FILES, plan.STAGING_FILE):
            self.assertNotIn(f"{plan.JET_DIR}/{name}", box.files)
        self.assertNotIn(plan.OP_PATH, box.files)
        self.assertIn(plan.STATE_DIR, box.files, "R4: the directory is root's to remove")
        left = [path for path in box.files if path.startswith(plan.STATE_DIR + "/")]
        self.assertEqual(left, [], "every J-Wicket name in it is deleted")
        self.assertIn(plan.STATE_DIR_LEFT, harness.output)
        self.assertFalse({c[1] for c in box.calls if c[0] == "rpc"} & {"make-directory", "delete-directory"})
        self.assertFalse(box.committed.under("system extensions"))
        self.assertFalse(box.committed.under(" ".join(plan.STANZA_KEYS["F-OP"])))
        self.assertIn(plan.NOT_REMOVED_BY_TOOL, harness.output)
        # Without a workstation receipt the plan keeps the shared statements (spec 7.9's second source).
        self.assertTrue(box.committed.has("system scripts language", "python3"))
        self.assertIn("Stays: S1", harness.output)

    def test_a_process_that_keeps_running_keeps_the_files(self) -> None:
        box, harness = f.installed_box()
        box.inject.stop_ignored = True
        self.assertEqual(
            harness.run(op_template.UNINSTALL_ANSWER, f.HOST), plan.EXIT_UNINSTALL_INCOMPLETE, harness.output
        )
        self.assertIn(plan.DAEMON_PATH, box.files)
        self.assertIn("exit 8, incomplete", harness.output)

    def test_uninstall_cli_txt_ends_with_roots_rmdir(self) -> None:
        box, _ = f.installed_box()
        text = box.files[plan.UNINSTALL_CLI_PATH].data.decode("utf-8")
        self.assertIn(plan.STATE_DIR_ROOT_REMOVE, text)
        self.assertNotIn("file make-directory", text)

    def test_uninstall_is_gated_too(self) -> None:
        box, harness = f.installed_box()
        mark = len(box.calls)
        self.assertEqual(harness.run(op_template.UNINSTALL_ANSWER, ""), plan.EXIT_GATE, harness.output)
        self.assertEqual([c for c in box.writes() if box.calls.index(c) >= mark], [])


class LocalFilesTests(unittest.TestCase):
    """The real LocalFiles on a temporary directory: O_NOFOLLOW, fstat and O_EXCL checks."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.files = op_template.LocalFiles(self.root)
        self.uid = os.geteuid()
        os.makedirs(self.root + "/home/u")
        os.makedirs(self.root + plan.JET_DIR)
        os.makedirs(self.root + plan.STATE_DIR, mode=0o700)
        os.chmod(self.root + plan.STATE_DIR, 0o700)
        self.home_copy = "/home/u/jwicket.py"
        Path(self.root + self.home_copy).write_bytes(b"bundle bytes")
        os.chmod(self.root + self.home_copy, 0o644)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_read_once_reads_a_regular_owned_file(self) -> None:
        self.assertEqual(self.files.read_once(self.home_copy, self.uid, 1024), b"bundle bytes")

    def test_read_once_refuses_a_link_a_loose_mode_another_owner_and_a_directory(self) -> None:
        os.symlink(self.root + self.home_copy, self.root + "/home/u/link.py")
        with self.assertRaisesRegex(op_template.LocalFileError, "without following a link"):
            self.files.read_once("/home/u/link.py", self.uid, 1024)
        os.chmod(self.root + self.home_copy, 0o664)
        with self.assertRaisesRegex(op_template.LocalFileError, "writable by group or others"):
            self.files.read_once(self.home_copy, self.uid, 1024)
        os.chmod(self.root + self.home_copy, 0o644)
        with self.assertRaisesRegex(op_template.LocalFileError, "not the account"):
            self.files.read_once(self.home_copy, self.uid + 1, 1024)
        with self.assertRaisesRegex(op_template.LocalFileError, "more than"):
            self.files.read_once(self.home_copy, self.uid, 4)
        with self.assertRaises(op_template.LocalFileError):
            self.files.read_once("/home/u", self.uid, 1024)

    def test_write_new_refuses_an_existing_file_or_link_and_sets_the_mode_exactly(self) -> None:
        old = os.umask(0o077)
        try:
            self.files.write_new(plan.STAGING_PATH, b"abc", 0o644)
        finally:
            os.umask(old)
        info = os.stat(self.root + plan.STAGING_PATH)
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o644)
        with self.assertRaisesRegex(op_template.LocalFileError, "could not be created"):
            self.files.write_new(plan.STAGING_PATH, b"again", 0o644)
        target = self.root + "/home/u/elsewhere"
        os.symlink(target, self.root + plan.JET_DIR + "/jwicket.py")
        with self.assertRaises(op_template.LocalFileError):
            self.files.write_new(plan.DAEMON_PATH, b"x", 0o644)
        self.assertFalse(os.path.exists(target), "a planted link is never followed")

    def test_write_private_needs_a_trusted_directory_and_never_follows_a_link(self) -> None:
        self.files.write_private(plan.SETTINGS_PATH, b"one", 0o600, self.uid)
        self.files.write_private(plan.SETTINGS_PATH, b"two", 0o600, self.uid)
        self.assertEqual(Path(self.root + plan.SETTINGS_PATH).read_bytes(), b"two")
        self.assertEqual(stat.S_IMODE(os.stat(self.root + plan.SETTINGS_PATH).st_mode), 0o600)
        target = self.root + "/home/u/stolen"
        os.symlink(target, self.root + plan.RECEIPT_PATH)
        with self.assertRaises(op_template.LocalFileError):
            self.files.write_private(plan.RECEIPT_PATH, b"x", 0o600, self.uid)
        self.assertFalse(os.path.exists(target))
        with self.assertRaises(op_template.LocalFileError):
            self.files.write_private("/home/u/x", b"x", 0o600, self.uid)
        os.chmod(self.root + plan.STATE_DIR, 0o777)  # noqa: S103 - deliberately loose, in a temporary directory
        with self.assertRaisesRegex(op_template.LocalFileError, "closed to others"):
            self.files.write_private(plan.SETTINGS_PATH, b"three", 0o600, self.uid)

    def test_paths_must_be_plain_and_absolute(self) -> None:
        for bad in ("relative/x", "/var/db/../etc/passwd", "/var/db/x\x00y"):
            with self.assertRaises(op_template.LocalFileError):
                self.files.exists(bad)


class StaticTests(unittest.TestCase):
    """AC-006-21 for the op script: no shell, no eval or exec of input, no /var/tmp, no commit check."""

    def test_no_shell_eval_exec_or_forbidden_calls(self) -> None:
        for path in (OP_SOURCE, BUILD_SOURCE):
            code = _code_without_docstrings(path)
            for forbidden in ("shell=True", "os.system", "os.popen", "commit_check", "request_shell_execute"):
                self.assertNotIn(forbidden, code, f"{path.name}: {forbidden}")
            for node in ast.walk(ast.parse(code)):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    self.assertNotIn(node.func.id, ("eval", "exec"), f"{path.name}: {node.func.id}")
        code = _code_without_docstrings(OP_SOURCE)
        for forbidden in (
            "/var/tmp",
            "/tmp/",
            "<check",
            "<validate",
            "commit check",
            "kill_session",
            "safe_copy",
            "make-directory",  # R4: the state directory is root's
            "delete-directory",
            "direct-tcpip",  # R3: no SSH channel
        ):
            self.assertNotIn(forbidden, code, forbidden)
        self.assertNotIn("_file_text(plan.TLS_KEY_PATH", code, "the TLS key is never read")
        self.assertNotIn("read_once(plan.TLS_KEY_PATH", code)
        for node in ast.walk(ast.parse(code)):
            # jcs.set_routing_instance is process-wide: it stopped the process's own NETCONF on SRX4100.
            if isinstance(node, ast.Attribute):
                self.assertNotEqual(node.attr, "set_routing_instance")
        self.assertEqual(code.count("subprocess.run("), 1, "the one fixed veriexec read")
        self.assertNotIn("/tmp", OP_SOURCE.read_text(encoding="utf-8"), "never a shared temporary directory")

    def test_every_rpc_is_in_install_rpcs(self) -> None:
        source = OP_SOURCE.read_text(encoding="utf-8")
        names = set(re.findall(r'(?:_read|\.read|\.write)\(\s*"([a-z-]+)"', source))
        self.assertTrue(names)
        self.assertLessEqual(names, set(transport.INSTALL_RPCS), names - set(transport.INSTALL_RPCS))

    def test_runs_of_the_fake_device_pass_check_rpc(self) -> None:
        box, _ = f.installed_box()
        for call in box.calls:
            if call[0] == "rpc":
                kind = "read" if call[1] in transport.READ_RPCS else "write"
                transport.check_rpc(str(call[1]), dict(call[2]), kind)  # type: ignore[arg-type]


def _code_without_docstrings(path: Path) -> str:
    """The module's source with every docstring replaced by an empty string (they may say what is never
    sent). Token positions, not ast.unparse (Python 3.9+), so this runs on Python 3.7 as CI does."""
    source = path.read_text(encoding="utf-8")
    kinds = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
    docs = {ast.get_docstring(n, clean=False) for n in ast.walk(ast.parse(source)) if isinstance(n, kinds)}
    starts = [0]
    for line in source.splitlines(keepends=True):
        starts.append(starts[-1] + len(line))
    out: List[str] = []
    last = 0
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type != tokenize.STRING:
            continue
        try:
            value = ast.literal_eval(token.string)
        except (ValueError, SyntaxError):  # an f-string token (Python < 3.12)
            continue
        if value in docs:
            begin = starts[token.start[0] - 1] + token.start[1]
            out.extend((source[last:begin], '""'))
            last = starts[token.end[0] - 1] + token.end[1]
    out.append(source[last:])
    return "".join(out)


def _prepared(box: f.FakeBox) -> Tuple[plan.DeviceFacts, plan.PriorState]:
    """The facts and prior an op-script run would read from ``box`` (no PyEZ, no prompts)."""
    harness = f.Harness(box)
    harness.out = io.StringIO()
    harness.jcs = f.FakeJcs([], harness.out, box)
    payload = op_template.Payload.from_json(f.payload_text(harness.bundle))
    device = f.FakeDevice(box)
    executor = op_template.OpExecutor(
        payload,
        op_template.LocalJunos(lambda: device, f.FakeConfig, f.FakeErrors, box.clock, xml=lambda t: t),
        op_template.Console(harness.jcs.get_input, harness.out),
        box.clock,
        op_template.Account(f.UID, f.USER, f.HOME),
        files=f.FakeLocalFiles(box),
        sysctl=lambda: (f.ENFORCING, ""),
        https=box.https,
    )
    executor.box.open()
    pre = executor.preflight()
    return pre.facts, pre.prior


def _plan(facts: plan.DeviceFacts, prior: plan.PriorState) -> plan.InstallPlan:
    bundle = f.bundle_identity(f.make_bundle())
    return plan.build_install_plan(
        bundle,
        plan.Provenance("operator-hash", ("pinned-by:S14",), True),
        f.plan_options(),
        facts,
        prior,
        method=Method.ONBOX_LOCAL,
        op_sha256=f.OP_SHA,
    )


if __name__ == "__main__":
    unittest.main()
