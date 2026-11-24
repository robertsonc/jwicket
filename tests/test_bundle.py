"""tools/bundle.py output: nothing placed beside the bundle may run inside it (SECU-8).

Run as a script, the bundle's own directory is sys.path[0]. The generated file removes it before any
other import, so a json.py or typing.py beside it cannot replace the standard library, and its
self-test fails if any module was loaded from that directory anyway (an embedding runner, say).
These tests build the bundle into a temporary directory and run it without -I, as Junos would.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Tuple

REPO = Path(__file__).resolve().parent.parent
TIMEOUT_S = 120


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
        for name in ("json", "hashlib", "base64", "typing", "secrets", "__future__"):
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


if __name__ == "__main__":
    unittest.main()
