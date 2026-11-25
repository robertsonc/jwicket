"""Spec 006 bundle change D2: the diagnostics' result files, and the fail-closed startup it must not touch.

Whether ``extension-service-start`` hands a JET application's standard output back over NETCONF is
unknown (Q-INST-05), so the self-test and the probe also leave their JSON in the state directory,
where ``file show`` can read it. These tests run the built bundle in a child process (it changes
``sys.path`` and ``sys.meta_path``, which must not happen to the test runner) and hand it a temporary
directory through ``_main(..., result_dir=...)``; under Junos the directory is always
``/var/db/jwicket``. Nothing here talks to a device.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import List, Tuple

REPO = Path(__file__).resolve().parent.parent
TIMEOUT_S = 120
SELFTEST_RESULT = "selftest-result.json"
PROBE_RESULT = "probe-result.json"

# Loads the bundle as a module (so its own "if __name__" block does not run) and calls its entry
# point with an injected result directory: the only way to point the result files elsewhere.
RUNNER = """
import importlib.util, sys
bundle, result_dir, *args = sys.argv[1:]
spec = importlib.util.spec_from_file_location("jwicket_bundle_under_test", bundle)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
if args[:1] == ["--no-stdout"]:  # as Python sets it up when the process starts without fd 1
    args = args[1:]
    sys.stdout = None
sys.exit(module._main([bundle, *args], result_dir=result_dir))
"""

# The directory trust rule on its own, with stat results built by hand (no root needed).
TRUST_RULE = """
import importlib.util, json, os, sys
bundle = sys.argv[1]
spec = importlib.util.spec_from_file_location("jwicket_bundle_under_test", bundle)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
def st(mode, uid, ino=7):
    return os.stat_result((mode, ino, 1, 2, uid, 0, 4096, 0, 0, 0))
me, other = os.geteuid(), os.geteuid() + 1
cases = {
    "trusted": (st(0o040700, me), st(0o040700, me)),
    "other uid": (st(0o040700, other), st(0o040700, other)),
    "group writable": (st(0o040770, me), st(0o040770, me)),
    "other writable": (st(0o040703, me), st(0o040703, me)),
    "swapped": (st(0o040700, me, ino=7), st(0o040700, me, ino=8)),
}
print(json.dumps({k: module._result_dir_refusal("/d", b, o) for k, (b, o) in cases.items()}))
"""


def run(args: List[str], cwd: Path) -> Tuple[int, str, str]:
    proc = subprocess.run(  # noqa: S603 - fixed argument list, no shell, this interpreter
        [sys.executable, *args], cwd=str(cwd), capture_output=True, text=True, timeout=TIMEOUT_S, check=False
    )
    return proc.returncode, proc.stdout, proc.stderr


class BundleCase(unittest.TestCase):
    """Builds the bundle once and saves it under the daemon's and both diagnostics' file names."""

    tmp: Path
    jet: Path

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="jwicket-results-"))
        cls.jet = cls.tmp / "jet"
        cls.jet.mkdir()
        bundle = cls.jet / "jwicket.py"
        code, out, err = run([str(REPO / "tools" / "bundle.py"), "--out", str(bundle)], REPO)
        if code != 0:
            raise AssertionError(f"bundle build failed: {out}{err}")
        for name in ("jwicket_selftest.py", "jwicket_probe.py"):
            shutil.copyfile(bundle, cls.jet / name)
        (cls.tmp / "runner.py").write_text(RUNNER, encoding="utf-8")

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self) -> None:
        self.work = Path(tempfile.mkdtemp(prefix="case-", dir=self.tmp))
        self.state = self.work / "state"
        self.state.mkdir(mode=0o700)
        os.chmod(self.state, 0o700)  # mkdir's mode is filtered by the umask; be exact

    def diagnose(self, script: str, result_dir: Path, *args: str) -> Tuple[int, str, str]:
        return run([str(self.tmp / "runner.py"), str(self.jet / script), str(result_dir), *args], self.work)


class ResultFileTests(BundleCase):
    def test_the_self_test_alias_writes_its_standard_output_to_the_result_file(self) -> None:
        code, out, err = self.diagnose("jwicket_selftest.py", self.state)
        self.assertEqual(code, 0, err)
        result = self.state / SELFTEST_RESULT
        self.assertEqual(result.read_text(encoding="utf-8"), out)
        summary = json.loads(out)
        self.assertTrue(summary["ok"], summary["failures"])
        self.assertRegex(summary["payload_sha256"], r"^[0-9a-f]{64}\Z")
        self.assertEqual(stat.S_IMODE(result.stat().st_mode), 0o600)
        self.assertEqual(result.stat().st_uid, os.geteuid())
        self.assertEqual(err, "")

    def test_the_self_test_flag_writes_the_same_file(self) -> None:
        code, out, err = self.diagnose("jwicket.py", self.state, "--bundle-self-test")
        self.assertEqual(code, 0, err)
        self.assertEqual((self.state / SELFTEST_RESULT).read_text(encoding="utf-8"), out)
        self.assertFalse((self.state / PROBE_RESULT).exists())

    def test_the_probe_alias_writes_its_result_and_keeps_its_exit_status(self) -> None:
        absent = self.work / "absent"
        expected, expected_out, _ = self.diagnose("jwicket_probe.py", absent)
        code, out, err = self.diagnose("jwicket_probe.py", self.state)
        # Without PyEZ on this machine the probe reports the missing modules and exits 1; with it,
        # 0. Either way the result file must not change the status or the output.
        self.assertEqual(code, expected, err)
        self.assertEqual(json.loads(out)["modules"].keys(), json.loads(expected_out)["modules"].keys())
        result = self.state / PROBE_RESULT
        self.assertEqual(result.read_text(encoding="utf-8"), out)
        self.assertEqual(stat.S_IMODE(result.stat().st_mode), 0o600)
        self.assertIn("http.server", json.loads(result.read_text(encoding="utf-8"))["modules"])
        self.assertFalse((self.state / SELFTEST_RESULT).exists())

    def test_the_result_is_written_when_there_is_no_standard_output(self) -> None:
        code, out, err = self.diagnose("jwicket_selftest.py", self.state, "--no-stdout")
        self.assertEqual(code, 0, err)
        self.assertEqual(out, "")
        self.assertTrue(json.loads((self.state / SELFTEST_RESULT).read_text(encoding="utf-8"))["ok"])

    def test_a_stale_result_is_replaced_whole(self) -> None:
        (self.state / SELFTEST_RESULT).write_text("x" * 100_000, encoding="utf-8")
        code, out, err = self.diagnose("jwicket_selftest.py", self.state)
        self.assertEqual(code, 0, err)
        self.assertEqual((self.state / SELFTEST_RESULT).read_text(encoding="utf-8"), out)

    def test_an_absent_directory_is_silent_and_creates_nothing(self) -> None:
        absent = self.work / "absent"
        code, out, err = self.diagnose("jwicket_selftest.py", absent)
        self.assertEqual(code, 0, err)
        self.assertTrue(json.loads(out)["ok"])
        self.assertFalse(absent.exists())
        self.assertEqual(err, "")


class UntrustedDirectoryTests(BundleCase):
    """Nothing is written where another account could redirect or read-modify the write, and the
    diagnostic's own result (exit status, standard output) is unchanged."""

    def assert_refused(self, result_dir: Path, why: str) -> None:
        code, out, err = self.diagnose("jwicket_selftest.py", result_dir)
        self.assertEqual(code, 0, err)
        self.assertTrue(json.loads(out)["ok"])
        self.assertIn("self-test result not written", err)
        self.assertIn(why, err)

    def test_a_group_or_other_writable_directory_is_refused(self) -> None:
        for mode in (0o770, 0o702, 0o1777):
            with self.subTest(mode=oct(mode)):
                os.chmod(self.state, mode)
                self.assert_refused(self.state, "writable by group or others")
                self.assertEqual(list(self.state.iterdir()), [])

    def test_a_symbolic_link_to_a_trusted_directory_is_refused(self) -> None:
        link = self.work / "link"
        link.symlink_to(self.state, target_is_directory=True)
        self.assert_refused(link, "not a directory")
        self.assertEqual(list(self.state.iterdir()), [])

    def test_a_regular_file_in_place_of_the_directory_is_refused(self) -> None:
        not_dir = self.work / "file"
        not_dir.write_text("", encoding="utf-8")
        self.assert_refused(not_dir, "not a directory")

    def test_a_planted_link_in_place_of_the_result_file_is_not_followed(self) -> None:
        victim = self.work / "victim.txt"
        victim.write_text("unchanged\n", encoding="utf-8")
        (self.state / SELFTEST_RESULT).symlink_to(victim)
        self.assert_refused(self.state, "cannot write")
        self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged\n")
        self.assertTrue((self.state / SELFTEST_RESULT).is_symlink())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs FIFOs")
    def test_a_fifo_in_place_of_the_result_file_does_not_block(self) -> None:
        os.mkfifo(self.state / SELFTEST_RESULT, 0o600)
        self.assert_refused(self.state, "cannot write")  # run() times out if the open blocks

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "needs root to give the directory away")
    def test_a_directory_owned_by_another_uid_is_refused(self) -> None:
        os.chown(self.state, 65534, 65534)
        self.assert_refused(self.state, "is owned by uid 65534")
        self.assertEqual(list(self.state.iterdir()), [])

    def test_the_trust_rule(self) -> None:
        script = self.tmp / "trust_rule.py"
        script.write_text(TRUST_RULE, encoding="utf-8")
        code, out, err = run([str(script), str(self.jet / "jwicket.py")], self.work)
        self.assertEqual(code, 0, err)
        verdicts = json.loads(out)
        self.assertIsNone(verdicts["trusted"])
        self.assertIn("is owned by uid", verdicts["other uid"])
        self.assertIn("writable by group or others (mode 0770)", verdicts["group writable"])
        self.assertIn("writable by group or others (mode 0703)", verdicts["other writable"])
        self.assertIn("changed while it was being checked", verdicts["swapped"])


class FailClosedTests(BundleCase):
    """Regression (AC-006-38): D2 and D3 change nothing about a missing settings file. The daemon
    still refuses with exit status 2 and leaves startup-refused.txt next to the settings path, and
    writes no result file."""

    def assert_refused(self, code: int, err: str) -> None:
        self.assertEqual(code, 2, err)
        self.assertIn("startup refused", err)
        refused = (self.state / "startup-refused.txt").read_text(encoding="utf-8")
        self.assertRegex(refused, r"^jwicket \S+ refused to start: ")
        self.assertIn("jwicket.ini", refused)
        self.assertEqual(sorted(p.name for p in self.state.iterdir()), ["startup-refused.txt"])
        self.assertEqual(stat.S_IMODE((self.state / "startup-refused.txt").stat().st_mode), 0o600)

    def test_from_the_bundle(self) -> None:
        ini = self.state / "jwicket.ini"
        code, _out, err = run(["-I", str(self.jet / "jwicket.py"), "--config", str(ini)], self.work)
        self.assert_refused(code, err)

    def test_from_the_source_tree(self) -> None:
        env = {**os.environ, "PYTHONPATH": str(REPO / "src")}
        proc = subprocess.run(  # noqa: S603 - fixed argument list, no shell, this interpreter
            [sys.executable, "-m", "jwicket", "--config", str(self.state / "jwicket.ini")],
            cwd=str(self.work),
            capture_output=True,
            text=True,
            timeout=TIMEOUT_S,
            check=False,
            env=env,
        )
        self.assert_refused(proc.returncode, proc.stderr)


if __name__ == "__main__":
    unittest.main()
