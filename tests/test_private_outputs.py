"""Defensive checks for output ownership, rotation and startup reporting."""

import json
import os
import stat
import tempfile
import unittest
from typing import Optional
from pathlib import Path
from unittest.mock import patch

from jwicket.app import record_startup_refusal
from jwicket.junos.session import PyEzUserSession
from jwicket.logs import AuditTrail, PrivateRotatingFileHandler
from jwicket.settings import ConfigError, LogSettings, check_log_paths, parse_settings


class PrivateOutputsTests(unittest.TestCase):
    def test_startup_note_created_only_in_private_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config = directory / "jwicket.ini"
            note = directory / "startup-refused.txt"
            directory.chmod(0o770)
            record_startup_refusal(config, "check failed")
            self.assertFalse(note.exists())
            directory.chmod(0o700)
            record_startup_refusal(config, "check failed")
            original = note.stat()
            record_startup_refusal(config, "another refusal")
            self.assertNotEqual(original.st_ino, note.stat().st_ino)
            self.assertEqual(stat.S_IMODE(note.stat().st_mode), 0o600)
            self.assertIn("another refusal", note.read_text(encoding="utf-8"))

    def test_log_preflight_has_no_writes_and_rejects_shared_parent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            path = directory / "audit.log"
            check_log_paths(LogSettings(audit_file=path))
            self.assertFalse(path.exists())
            directory.chmod(0o1777)
            with self.assertRaises(ConfigError):
                check_log_paths(LogSettings(audit_file=path))

    def test_open_rejects_untrusted_existing_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "log"
            path.touch(0o600)
            path.chmod(0o640)
            with self.assertRaises(ConfigError):
                PrivateRotatingFileHandler(path, max_bytes=100, backups=1)

    def test_open_rejects_duplicate_inode_or_link(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "log"
            other = Path(tmp) / "duplicate"
            path.touch(0o600)
            os.link(path, other)
            with self.assertRaises(ConfigError):
                PrivateRotatingFileHandler(path, max_bytes=100, backups=1)
            other.unlink()
            other.symlink_to(path)
            with self.assertRaises(ConfigError):
                PrivateRotatingFileHandler(other, max_bytes=100, backups=1)

    def test_audit_writes_and_rotates_privately(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.log"
            trail = AuditTrail(path, max_bytes=120, backups=1)
            try:
                trail.record("first", user="operator", source="127.0.0.1")
                trail.record("second", user="operator", source="127.0.0.1")
            finally:
                trail.close()
            backup = path.with_name("audit.log.1")
            for out in (path, backup):
                self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
            self.assertEqual(json.loads(backup.read_text(encoding="utf-8"))["event"], "first")
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["event"], "second")

    def test_netconf_only_settings(self) -> None:
        self.assertEqual(parse_settings("[auth]\nnetconf_port = 830").auth.netconf_port, 830)
        with self.assertRaisesRegex(ConfigError, "console mode"):
            parse_settings("[auth]\nnetconf_port = 23")


class FakePyEzDevice:
    last: Optional["FakePyEzDevice"] = None

    def __init__(self, **kwargs: object) -> None:
        self._password = kwargs["passwd"]
        self.timeout = 0
        self.saw_password = False
        FakePyEzDevice.last = self

    @property
    def password(self) -> None:
        return None

    @password.setter
    def password(self, value: object) -> None:
        self._password = value

    def open(self, *, gather_facts: bool) -> None:
        self.saw_password = bool(self._password)
        if gather_facts:
            raise AssertionError("facts should not be fetched")


class CredentialLifetimeTests(unittest.TestCase):
    def test_established_session_releases_pyez_password_reference(self) -> None:
        with patch("jwicket.junos.session._import_pyez", return_value=FakePyEzDevice):
            session = PyEzUserSession.open(host="127.0.0.1", port=830, user="operator", password="fixture", timeout_s=5)
        self.assertEqual(session.user, "operator")
        dev = FakePyEzDevice.last
        self.assertIsNotNone(dev)
        if dev is not None:
            self.assertTrue(dev.saw_password)
            self.assertIsNone(dev._password)
            self.assertEqual(dev.timeout, 5)
