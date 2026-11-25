"""tools/bundle.py output: nothing placed beside the bundle may run inside it (SECU-8).

Run as a script, the bundle's own directory is sys.path[0]. The generated file removes it before any
other import, so a json.py or typing.py beside it cannot replace the standard library, and its
self-test fails if any module was loaded from that directory anyway (an embedding runner, say).
These tests build the bundle into a temporary directory and run it without -I, as Junos would.

The bundle also carries what Spec 006 section 10 adds for the installers: a ``features:`` header line,
the payload digest on ``jwicket._embedded`` (D3) and the diagnostics' result-file names (D2). Those
must agree with what tools/jwicket_install/plan.py expects, and the build must stay reproducible.
"""

from __future__ import annotations

import ast
import importlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, List, Tuple
from unittest import mock

from jwicket import __version__
from jwicket.settings import DEFAULT_CONFIG_PATH

REPO = Path(__file__).resolve().parent.parent
TOOLS = REPO / "tools"
TIMEOUT_S = 120

# Loads the bundle as a module in a child process, installs its importer and reports what the
# daemon's modules see (the bundle changes sys.path and sys.meta_path, so never in this process).
INSPECT = """
import importlib, importlib.util, json, sys
bundle = sys.argv[1]
spec = importlib.util.spec_from_file_location("jwicket_bundle_under_test", bundle)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
module._install()
api = importlib.import_module("jwicket.api")
embedded = importlib.import_module("jwicket._embedded")
print(json.dumps({
    "PAYLOAD_SHA256": module.PAYLOAD_SHA256,
    "embedded": embedded.PAYLOAD_SHA256,
    "api": api.bundle_payload_sha256(),
    "recomputed": module._payload_sha256(),
    "aliases": sorted(module.ALIASES),
    "alias_modes": sorted(module.ALIASES.values()),
    "result_dir": module.RESULT_DIR,
    "result_files": module.RESULT_FILES,
}))
"""


def tool(name: str) -> ModuleType:
    """A module from tools/ (bundle, jwicket_install.plan), imported the way test_build_wheel does."""
    if str(TOOLS) not in sys.path:
        sys.path.append(str(TOOLS))
    return importlib.import_module(name)


def run(args: List[str], cwd: Path) -> Tuple[int, str, str]:
    proc = subprocess.run(  # noqa: S603 - fixed argument list, no shell, this interpreter
        [sys.executable, *args], cwd=str(cwd), capture_output=True, text=True, timeout=TIMEOUT_S, check=False
    )
    return proc.returncode, proc.stdout, proc.stderr


class BundleIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="jwicket-bundle-"))
        cls.jet = cls.tmp / "jet"
        cls.jet.mkdir()
        cls.bundle = cls.jet / "jwicket.py"
        code, out, err = run([str(REPO / "tools" / "bundle.py"), "--out", str(cls.bundle)], REPO)
        if code != 0:
            raise AssertionError(f"bundle build failed: {out}{err}")
        # Shadows of modules the bundle imports at its top, later, and through `from __future__`.
        for name in ("json", "hashlib", "base64", "typing", "secrets", "__future__", "contextlib", "stat"):
            (cls.jet / f"{name}.py").write_text(
                f"import sys\nsys.stderr.write('SHADOW {name} executed\\n')\n", encoding="utf-8"
            )

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def self_test(self, script: Path, cwd: Path) -> Tuple[int, Dict[str, Any], str]:
        code, out, err = run([str(script), "--bundle-self-test"], cwd)
        return code, json.loads(out), err

    def test_modules_beside_the_bundle_never_run(self) -> None:
        for cwd in (self.jet, self.tmp):
            with self.subTest(cwd=str(cwd)):
                code, summary, err = self.self_test(self.bundle, cwd)
                self.assertNotIn("SHADOW", err)
                self.assertEqual(code, 0, summary["failures"])
                self.assertTrue(summary["ok"])
                self.assertEqual(summary["foreign_modules"], [])
                self.assertIn(str(self.jet), summary["path_removed"])

    def test_run_through_a_symbolic_link(self) -> None:
        links = self.tmp / "links"
        links.mkdir(exist_ok=True)
        link = links / "jwicket_link.py"
        if not link.exists():
            link.symlink_to(self.bundle)
        code, summary, err = self.self_test(link, self.tmp)
        self.assertNotIn("SHADOW", err)
        self.assertEqual(code, 0, summary["failures"])

    def embedded_run(self, argv: List[str]) -> Tuple[int, str, str]:
        """A runner that loaded a module from the bundle's directory before running the bundle (an
        embedding the scrub cannot undo): the bundle must notice."""
        planted = self.tmp / "planted-dir"
        planted.mkdir(exist_ok=True)
        bundle = planted / "jwicket.py"
        if not bundle.exists():
            shutil.copyfile(self.bundle, bundle)
        (planted / "planted.py").write_text("X = 1\n", encoding="utf-8")
        runner = (
            "import runpy, sys\n"
            f"sys.path.insert(0, {str(planted)!r})\n"
            "import planted\n"
            "sys.path.pop(0)\n"
            f"sys.argv = [{str(bundle)!r}, *{argv!r}]\n"
            f"runpy.run_path({str(bundle)!r}, run_name='__main__')\n"
        )
        return run(["-c", runner], self.tmp)

    def test_a_module_already_loaded_from_the_directory_fails_the_self_test(self) -> None:
        code, out, err = self.embedded_run(["--bundle-self-test"])
        summary = json.loads(out or "{}")
        self.assertEqual(code, 1, err)
        self.assertFalse(summary["ok"])
        self.assertTrue(any(m.startswith("planted ") for m in summary["foreign_modules"]), summary)

    def test_the_daemon_refuses_to_start_with_a_foreign_module(self) -> None:
        code, _out, err = self.embedded_run([])
        self.assertEqual(code, 2, err)
        self.assertIn("refusing to start", err)
        self.assertIn("planted", err)


class BundleFeatureTests(unittest.TestCase):
    """What the installers read from the bundle (Spec 006 section 10, D2 and D3)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="jwicket-bundle-features-"))
        cls.bundle = cls.tmp / "jwicket.py"
        code, out, err = run([str(TOOLS / "bundle.py"), "--out", str(cls.bundle), "--source-ref", "abc123"], REPO)
        if code != 0:
            raise AssertionError(f"bundle build failed: {out}{err}")
        cls.text = cls.bundle.read_text(encoding="ascii")
        cls.head = cls.text[:4096]
        (cls.tmp / "inspect.py").write_text(INSPECT, encoding="utf-8")
        code, out, err = run([str(cls.tmp / "inspect.py"), str(cls.bundle)], cls.tmp)
        if code != 0:
            raise AssertionError(f"inspecting the bundle failed: {out}{err}")
        cls.inside: Dict[str, Any] = json.loads(out)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_the_header_lists_the_features(self) -> None:
        self.assertEqual(re.findall(r"(?m)^features:.*$", self.head), ["features:        result-files,build-line"])
        self.assertEqual(tuple(tool("bundle").FEATURES), ("result-files", "build-line"))

    def test_the_installer_reads_the_header(self) -> None:
        plan = tool("jwicket_install.plan")
        found = plan.BundleId.from_header(self.head, "0" * 64, len(self.text))
        self.assertEqual(found.version, __version__)
        self.assertEqual(found.source_ref, "abc123")
        self.assertEqual(found.payload_sha256, self.inside["PAYLOAD_SHA256"])
        self.assertEqual(found.features, frozenset(plan.FEATURES))
        self.assertEqual(set(plan.FEATURES), set(tool("bundle").FEATURES))
        self.assertTrue(found.has("result-files") and found.has("build-line"))

    def test_the_header_still_parses_for_the_release_record(self) -> None:
        record = tool("release_record")
        version, source, payload = record.bundle_header(self.bundle)
        self.assertEqual((version, source, payload), (__version__, "abc123", self.inside["PAYLOAD_SHA256"]))

    def test_the_embedded_module_carries_the_payload_digest(self) -> None:
        digest = self.inside["PAYLOAD_SHA256"]
        self.assertRegex(digest, r"^[0-9a-f]{64}\Z")
        self.assertIn(f"payload sha256:  {digest}\n", self.head)
        self.assertEqual(self.inside["recomputed"], digest)
        self.assertEqual(self.inside["embedded"], digest)
        self.assertEqual(self.inside["api"], digest)  # what the start line, audit and /api/session use

    def test_result_files_agree_with_the_daemon_and_the_installer(self) -> None:
        plan = tool("jwicket_install.plan")
        self.assertEqual(self.inside["result_dir"], str(DEFAULT_CONFIG_PATH.parent))
        self.assertEqual(self.inside["result_dir"], plan.STATE_DIR)
        self.assertEqual(
            self.inside["result_files"],
            {
                "self-test": plan.SELFTEST_RESULT_PATH.rpartition("/")[2],
                "probe": plan.PROBE_RESULT_PATH.rpartition("/")[2],
            },
        )
        self.assertEqual(sorted(self.inside["result_files"]), self.inside["alias_modes"])
        self.assertEqual(self.inside["aliases"], sorted(plan.DIAGNOSTIC_FILES))
        self.assertEqual(plan.SELFTEST_RESULT_PATH, f"{plan.STATE_DIR}/selftest-result.json")

    def test_two_builds_of_the_same_tree_are_identical(self) -> None:
        bundle = tool("bundle")
        first = bundle.build(bundle.PACKAGE_DIR, "abc123")
        second = bundle.build(bundle.PACKAGE_DIR, "abc123")
        self.assertEqual(first.text, second.text)
        self.assertEqual(first.text, self.text)  # and equal to the file tools/bundle.py wrote

    def test_the_floor_is_python_3_7(self) -> None:
        """Junos 25.2R1-S1.4 ships Python 3.7.10 (docs/evidence/2026-11-24-srx4100-lab): the generated
        bundle and this build tool parse with 3.7's grammar. The CI job on Python 3.7 runs both."""
        self.assertEqual(tool("bundle").MIN_PYTHON, (3, 7))
        sources = {"tools/bundle.py": (TOOLS / "bundle.py").read_text(encoding="utf-8"), "the bundle": self.text}
        for name, source in sources.items():
            with self.subTest(source=name):
                if sys.version_info >= (3, 8):
                    ast.parse(source, filename=name, feature_version=(3, 7))
                else:  # 3.7's own grammar is the floor; feature_version is 3.8+
                    ast.parse(source, filename=name)

    def test_a_failed_write_leaves_no_temporary_file(self) -> None:
        """write_atomic removes its temporary file when the final rename fails, and still raises that
        failure if the file is already gone (Python 3.7 has no Path.unlink(missing_ok=...))."""
        bundle = tool("bundle")
        out_dir = Path(tempfile.mkdtemp(prefix="write-", dir=self.tmp))
        full = OSError(28, "No space left on device")

        def vanish_then_fail(_target: Path) -> None:
            for leftover in out_dir.iterdir():
                leftover.unlink()
            raise full

        for side_effect in (full, vanish_then_fail):
            with self.subTest(side_effect=side_effect):
                with mock.patch.object(Path, "replace", side_effect=side_effect), self.assertRaises(OSError) as cm:
                    bundle.write_atomic(out_dir / "jwicket.py", b"data")
                self.assertIs(cm.exception, full)
                self.assertEqual(list(out_dir.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
