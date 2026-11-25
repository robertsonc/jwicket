"""tools/build_wheel.py: the installer wheel is byte-identical on every build (AC-006-40).

Spec 006 sections 6.2 and 11.3: each lab pre-release carries ``jwicket_install-<v>-py3-none-any.whl``,
and the ``rebuild`` job requires the same bytes on Python 3.7 (the SRX's), 3.9 and 3.13. These tests
build a small stand-in package (and the real ``tools/jwicket_install`` when it exists) twice, and on
every other Python 3.7+ interpreter found on this machine, and check the archive's structure, its
``Requires-Python`` (revision R1: the pinned junos-eznc's floor) and that every module parses with
Python 3.7's grammar.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import importlib
import io
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import ModuleType
from typing import List

REPO = Path(__file__).resolve().parent.parent
TOOLS = REPO / "tools"
TIMEOUT_S = 120
EPOCH = 1764000000  # 2025-11-24 16:00:00 UTC
VERSION = "0.1.0.dev1"


def _load(name: str) -> ModuleType:
    if str(TOOLS) not in sys.path:
        sys.path.append(str(TOOLS))
    return importlib.import_module(name)


build_wheel = _load("build_wheel")


def make_package(root: Path, *, version: str = VERSION, cli: str = "def main() -> int:\n    return 0\n") -> Path:
    package = root / "jwicket_install"
    (package / "sub").mkdir(parents=True)
    (package / "__init__.py").write_text(f'"""Stand-in."""\n\n__version__ = "{version}"\n', encoding="utf-8")
    (package / "cli.py").write_text(cli, encoding="utf-8")
    (package / "plan.py").write_text(
        "STATE_DIR = '/var/db/jwicket'\n\n\ndef late() -> None:\n    import jwicket\n", encoding="utf-8"
    )
    (package / "sub" / "__init__.py").write_text("", encoding="utf-8")
    (package / "sub" / "data.json").write_text('{"schema": 2}\n', encoding="utf-8")
    (package / "__pycache__").mkdir()
    (package / "__pycache__" / "plan.cpython-313.pyc").write_bytes(b"\x00compiled")
    (package / "stale.pyc").write_bytes(b"\x00compiled")
    return package


def interpreters() -> List[str]:
    """Distinct Python 3.7+ interpreters on PATH besides this one (by resolved path)."""
    seen = {str(Path(sys.executable).resolve())}
    found = []
    for name in (f"python3.{minor}" for minor in range(7, 15)):
        exe = shutil.which(name)
        if exe is None or str(Path(exe).resolve()) in seen:
            continue
        seen.add(str(Path(exe).resolve()))
        found.append(exe)
    return found


def run_tool(python: str, package: Path, out: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argument list, no shell
        [
            python,
            "-I",
            str(TOOLS / "build_wheel.py"),
            "--out",
            str(out),
            "--package-dir",
            str(package),
            "--source-date-epoch",
            str(EPOCH),
        ],
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
        check=False,
    )


def grammar_refuses(source: str) -> bool:
    """Whether this interpreter refuses ``source`` under Python 3.7's grammar, as build_wheel parses."""
    try:
        if sys.version_info >= (3, 8):
            ast.parse(source, feature_version=(3, 7))
        else:
            ast.parse(source)
    except SyntaxError:
        return True
    return False


class DeterminismTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="jwicket-wheel-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.package = make_package(self.tmp / "src")

    def test_two_builds_are_identical(self) -> None:
        first = build_wheel.build(self.package, source_date_epoch=EPOCH)
        second = build_wheel.build(self.package, source_date_epoch=EPOCH)
        self.assertEqual(first.data, second.data)
        self.assertEqual(first.name, f"jwicket_install-{VERSION}-py3-none-any.whl")

    def test_the_command_line_writes_the_same_bytes(self) -> None:
        proc = run_tool(sys.executable, self.package, self.tmp / "out")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        written = (self.tmp / "out" / f"jwicket_install-{VERSION}-py3-none-any.whl").read_bytes()
        self.assertEqual(written, build_wheel.build(self.package, source_date_epoch=EPOCH).data)
        self.assertIn(hashlib.sha256(written).hexdigest(), proc.stdout)

    def test_every_other_interpreter_writes_the_same_bytes(self) -> None:
        others = interpreters()
        if not others:
            self.skipTest("no second Python interpreter on PATH")
        expected = build_wheel.build(self.package, source_date_epoch=EPOCH).data
        compared = 0
        for index, python in enumerate(others):
            version = subprocess.run(  # noqa: S603 - fixed argument list, no shell
                [python, "-I", "-c", "import sys; print(sys.version_info >= (3, 7))"],
                capture_output=True,
                text=True,
                timeout=TIMEOUT_S,
                check=False,
            )
            if version.stdout.strip() != "True":
                continue
            with self.subTest(python=python):
                out = self.tmp / f"out{index}"
                proc = run_tool(python, self.package, out)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual((out / f"jwicket_install-{VERSION}-py3-none-any.whl").read_bytes(), expected)
                compared += 1
        if not compared:
            self.skipTest("no second Python 3.7+ interpreter on PATH")

    def test_the_timestamp_changes_the_bytes_and_nothing_else_does(self) -> None:
        a = build_wheel.build(self.package, source_date_epoch=EPOCH)
        b = build_wheel.build(self.package, source_date_epoch=EPOCH + 3600)
        self.assertNotEqual(a.data, b.data)
        self.assertEqual(a.entries, b.entries)

    def test_the_real_installer_package_builds_reproducibly(self) -> None:
        package = TOOLS / "jwicket_install"
        if not (package / "cli.py").is_file():
            self.skipTest("tools/jwicket_install/cli.py does not exist in this tree")
        first = build_wheel.build(package, source_date_epoch=EPOCH)
        self.assertEqual(first.data, build_wheel.build(package, source_date_epoch=EPOCH).data)
        self.assertEqual(first.version, _load("release_check").read_init_version(package / "__init__.py"))


class StructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="jwicket-wheel-"))
        cls.wheel = build_wheel.build(make_package(cls.tmp / "src"), source_date_epoch=EPOCH)
        cls.archive = zipfile.ZipFile(io.BytesIO(cls.wheel.data))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.archive.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def read(self, name: str) -> str:
        return self.archive.read(f"jwicket_install-{VERSION}.dist-info/{name}").decode("utf-8")

    def test_entries_are_sorted_with_the_record_last(self) -> None:
        names = self.archive.namelist()
        package = [n for n in names if n.startswith("jwicket_install/")]
        self.assertEqual(package, sorted(package))
        self.assertEqual(names[: len(package)], package)
        self.assertEqual(names[-1], f"jwicket_install-{VERSION}.dist-info/RECORD")
        self.assertIn("jwicket_install/sub/data.json", names)
        self.assertFalse([n for n in names if "__pycache__" in n or n.endswith(".pyc")])
        self.assertIsNone(self.archive.testzip())

    def test_every_entry_has_the_fixed_time_mode_and_no_compression(self) -> None:
        for info in self.archive.infolist():
            with self.subTest(name=info.filename):
                self.assertEqual(info.date_time, (2025, 11, 24, 16, 0, 0))
                self.assertEqual(info.compress_type, zipfile.ZIP_STORED)
                self.assertEqual(info.external_attr >> 16, 0o100644)
                self.assertEqual(info.create_system, 3)
                self.assertEqual(info.extra, b"")

    def test_record_lists_every_entry_with_its_hash(self) -> None:
        rows = [line.split(",") for line in self.read("RECORD").splitlines()]
        names = self.archive.namelist()
        self.assertEqual([r[0] for r in rows], names)
        for name, digest, size in rows[:-1]:
            data = self.archive.read(name)
            expected = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
            self.assertEqual(digest, f"sha256={expected}", name)
            self.assertEqual(int(size), len(data), name)
        self.assertEqual(rows[-1][1:], ["", ""])

    def test_metadata_entry_point_and_tag(self) -> None:
        metadata = self.read("METADATA")
        self.assertIn("Metadata-Version: 2.1\n", metadata)
        self.assertIn("Name: jwicket-install\n", metadata)
        self.assertIn(f"Version: {VERSION}\n", metadata)
        self.assertIn(f"Requires-Python: {build_wheel.REQUIRES_PYTHON}\n", metadata)
        self.assertNotIn("Requires-Dist", metadata)
        self.assertIn("LAB ONLY", metadata)
        wheel = self.read("WHEEL")
        self.assertIn("Tag: py3-none-any\n", wheel)
        self.assertIn("Root-Is-Purelib: true\n", wheel)
        self.assertEqual(
            self.read("entry_points.txt"), "[console_scripts]\njwicket-install = jwicket_install.cli:main\n"
        )

    def test_the_epoch_is_clamped_to_the_zip_minimum(self) -> None:
        wheel = build_wheel.build(make_package(self.tmp / "early"), source_date_epoch=0)
        with zipfile.ZipFile(io.BytesIO(wheel.data)) as archive:
            self.assertEqual(archive.infolist()[0].date_time, (1980, 1, 1, 0, 0, 0))


# junos-eznc's own Requires-Python, by the version requirements-install.txt pins (PyPI metadata, read on
# 2026-11-25). A bump of the pin fails FloorTests until its floor is read again and recorded here.
JUNOS_EZNC_REQUIRES_PYTHON = {"2.8.3": ">=3.8"}


class FloorTests(unittest.TestCase):
    """Revision R1: the wheel's Requires-Python is the workstation floor, the pinned junos-eznc's."""

    def test_requires_python_is_the_pinned_junos_eznc_floor(self) -> None:
        text = (REPO / "requirements-install.txt").read_text(encoding="utf-8")
        pins = re.findall(r"(?m)^junos-eznc==(\S+)", text)
        self.assertEqual(len(pins), 1, "requirements-install.txt must pin junos-eznc exactly once")
        self.assertIn(
            pins[0],
            JUNOS_EZNC_REQUIRES_PYTHON,
            f"junos-eznc {pins[0]} is pinned now: read its Requires-Python on PyPI and record it in this test",
        )
        self.assertEqual(build_wheel.REQUIRES_PYTHON, JUNOS_EZNC_REQUIRES_PYTHON[pins[0]])

    def test_the_grammar_floor_is_the_srx_python(self) -> None:
        self.assertEqual(build_wheel.MIN_PYTHON, (3, 7))

    def test_the_release_notes_agree(self) -> None:
        template = (REPO / ".github" / "release-notes-lab-only.md").read_text(encoding="utf-8")
        floor = build_wheel.REQUIRES_PYTHON.replace(">=", "")
        self.assertIn(f"`junos-eznc` 2.8.3 itself declares {floor}", template)


class RefusalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="jwicket-wheel-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def refused(self, package: Path, fragment: str) -> None:
        with self.assertRaises(build_wheel.BuildError) as ctx:
            build_wheel.build(package, source_date_epoch=EPOCH)
        self.assertIn(fragment, str(ctx.exception))

    def test_a_symbolic_link_is_refused(self) -> None:
        package = make_package(self.tmp / "a")
        (package / "link.py").symlink_to(package / "cli.py")
        self.refused(package, "symbolic link")

    def test_a_hidden_file_is_refused(self) -> None:
        package = make_package(self.tmp / "b")
        (package / ".env").write_text("TOKEN=x\n", encoding="utf-8")
        self.refused(package, "not allowed")

    def test_the_console_script_needs_cli_main(self) -> None:
        self.refused(make_package(self.tmp / "c", cli="def run() -> int:\n    return 0\n"), "main()")

    def test_a_module_level_import_of_the_daemon_package_is_refused(self) -> None:
        package = make_package(self.tmp / "d")
        (package / "state.py").write_text("from jwicket.settings import DEFAULT_CONFIG_PATH\n", encoding="utf-8")
        self.refused(package, "imports jwicket")

    def test_syntax_newer_than_python_3_7_is_refused(self) -> None:
        # Revision R1: every module of the package runs on the SRX's Python 3.7. On 3.8+ the build parses
        # with feature_version=(3, 7); on 3.7 its own parser refuses the same sources. feature_version is
        # best-effort (3.8 accepts both sources below with it, 3.13 accepts f"{x=}"), so this asserts only
        # where this interpreter can tell, and the CI test job on 3.7 stays the proof.
        for label, source in (
            ("walrus", "if (n := 1):\n    pass\n"),
            ("positional-only", "def f(a, /):\n    return a\n"),
        ):
            with self.subTest(label):
                if not grammar_refuses(source):
                    self.skipTest(f"Python {sys.version_info[0]}.{sys.version_info[1]}'s feature_version accepts it")
                package = make_package(self.tmp / f"g-{label.replace(' ', '')}")
                (package / "late.py").write_text(source, encoding="utf-8")
                self.refused(package, "not valid Python 3.7 syntax")

    def test_a_version_that_is_not_pep440_simple_is_refused(self) -> None:
        for version in ("0.1.0-dev.1", "0.1", "0.1.0.dev1+local", "latest"):
            with self.subTest(version=version):
                self.refused(make_package(self.tmp / f"e{version}", version=version), "__version__")

    def test_a_bad_epoch_is_refused_on_the_command_line(self) -> None:
        package = make_package(self.tmp / "f")
        proc = subprocess.run(  # noqa: S603 - fixed argument list, no shell
            [
                sys.executable,
                "-I",
                str(TOOLS / "build_wheel.py"),
                "--out",
                str(self.tmp / "out"),
                "--package-dir",
                str(package),
                "--source-date-epoch",
                "yesterday",
            ],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_S,
            check=False,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("source date epoch", proc.stderr)
        self.assertFalse((self.tmp / "out").exists())


if __name__ == "__main__":
    unittest.main()
