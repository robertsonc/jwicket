"""The three copies of the version agree (Spec 006 section 11.1; AC-006-40).

``src/jwicket/__init__.py`` (read by tools/bundle.py into the bundle header), ``pyproject.toml`` and
``tools/jwicket_install/__init__.py`` (the installer and its wheel) must carry the same PEP 440
``X.Y.Z.devN`` version, and a release tag is exactly ``v`` plus that version. The release workflow's
``verify`` job refuses a mismatch; this test catches it in every pull request first.
"""

from __future__ import annotations

import importlib
import sys
import unittest
from pathlib import Path
from types import ModuleType

import jwicket

REPO = Path(__file__).resolve().parent.parent
TOOLS = REPO / "tools"


def _load(name: str) -> ModuleType:
    if str(TOOLS) not in sys.path:
        sys.path.append(str(TOOLS))
    return importlib.import_module(name)


release_check = _load("release_check")


class VersionTests(unittest.TestCase):
    def test_the_installer_package_carries_a_version(self) -> None:
        self.assertTrue(
            (REPO / release_check.INSTALLER_INIT).is_file(),
            "tools/jwicket_install/__init__.py must exist and assign __version__ (Spec 006 section 11.1)",
        )

    def test_the_three_versions_are_equal(self) -> None:
        versions = release_check.read_versions(REPO)
        self.assertEqual(set(versions), {p.as_posix() for p in release_check.VERSION_FILES})
        self.assertEqual(len(set(versions.values())), 1, f"the versions differ: {dict(versions)}")

    def test_the_version_is_a_dev_pre_release(self) -> None:
        version = release_check.read_init_version(REPO / release_check.DAEMON_INIT)
        self.assertRegex(version, release_check.VERSION_PATTERN)
        self.assertRegex(release_check.tag_for_version(version), release_check.TAG_PATTERN)

    def test_every_reader_sees_the_same_version(self) -> None:
        version = release_check.read_init_version(REPO / release_check.DAEMON_INIT)
        self.assertEqual(jwicket.__version__, version)
        self.assertEqual(_load("bundle").read_version(REPO / "src" / "jwicket"), version)
        installer = TOOLS / "jwicket_install"
        if (installer / "__init__.py").is_file():
            self.assertEqual(_load("build_wheel").read_version(installer), version)


if __name__ == "__main__":
    unittest.main()
