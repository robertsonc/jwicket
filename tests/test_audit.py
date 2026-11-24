"""logs.AuditTrail: one JSON object per line; never a password, token, cookie, secret or CSRF value."""

from __future__ import annotations

import json
import logging
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List

from jwicket.logs import AuditTrail

AUDIT_LOGGER = "jwicket.audit"


class AuditIsolation(unittest.TestCase):
    """Restores the shared ``jwicket.audit`` logger after each test, closing any file handlers."""

    def setUp(self) -> None:
        logger = logging.getLogger(AUDIT_LOGGER)
        self._handlers = list(logger.handlers)
        self._propagate = logger.propagate
        self._level = logger.level
        self.dir = Path(tempfile.mkdtemp(prefix="jwicket-audit-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.addCleanup(self._restore)

    def _restore(self) -> None:
        logger = logging.getLogger(AUDIT_LOGGER)
        for handler in list(logger.handlers):
            if handler not in self._handlers:
                logger.removeHandler(handler)
                handler.close()
        logger.propagate = self._propagate
        logger.setLevel(self._level)

    @staticmethod
    def lines(path: Path) -> List[Dict[str, Any]]:
        text = path.read_text(encoding="utf-8")
        return [json.loads(line) for line in text.splitlines()]


class AuditTrailTests(AuditIsolation):
    def test_one_json_object_per_line(self) -> None:
        path = self.dir / "audit.log"
        trail = AuditTrail(path)
        trail.record("login", user="alice", source="127.0.0.1", backend="netconf")
        trail.record("read_inventory", user="alice", source="127.0.0.1", scope="root", policies=10)
        trail.record("start", user=None, source="local")
        entries = self.lines(path)
        self.assertEqual([e["event"] for e in entries], ["login", "read_inventory", "start"])
        self.assertEqual(entries[0]["user"], "alice")
        self.assertEqual(entries[0]["source"], "127.0.0.1")
        self.assertEqual(entries[1]["policies"], 10)
        self.assertIsNone(entries[2]["user"])
        for entry in entries:
            self.assertRegex(entry["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

    def test_forbidden_fields_are_dropped(self) -> None:
        path = self.dir / "audit.log"
        trail = AuditTrail(path)
        trail.record(
            "login", user="alice", source="127.0.0.1",
            password="hunter2-pw", passwd="hunter3-pw", token="tok-value", cookie="jwicket=cookie-value",
            secret="secret-value", csrf="csrf-value", authorization="Basic auth-value",
            Password="upper-pw", TOKEN="upper-token", Cookie="upper-cookie", kept="visible",
        )
        raw = path.read_text(encoding="utf-8")
        for value in ("hunter2-pw", "hunter3-pw", "tok-value", "cookie-value", "secret-value", "csrf-value",
                      "auth-value", "upper-pw", "upper-token", "upper-cookie"):
            with self.subTest(value=value):
                self.assertNotIn(value, raw)
        entry = self.lines(path)[0]
        self.assertEqual(entry["kept"], "visible")
        for key in ("password", "passwd", "token", "cookie", "secret", "csrf", "authorization", "Password", "TOKEN"):
            self.assertNotIn(key, entry)

    def test_long_values_truncated_and_newlines_removed(self) -> None:
        path = self.dir / "audit.log"
        trail = AuditTrail(path)
        trail.record("login_failed", user="x" * 500, source="127.0.0.1", note="line1\nline2\r\nline3", big="y" * 1000)
        raw = path.read_text(encoding="utf-8")
        self.assertEqual(len(raw.splitlines()), 1)  # a forged newline cannot start a second record
        entry = self.lines(path)[0]
        self.assertLessEqual(len(entry["user"]), 200)
        self.assertLessEqual(len(entry["big"]), 200)
        self.assertTrue(entry["big"].startswith("yyy"))
        self.assertNotIn("\n", entry["note"])
        self.assertIn("line3", entry["note"])

    def test_non_string_values_kept_typed(self) -> None:
        path = self.dir / "audit.log"
        AuditTrail(path).record("x", user="a", source="s", n=3, f=1.5, b=True, none=None, obj=["a", 1])
        entry = self.lines(path)[0]
        self.assertEqual((entry["n"], entry["f"], entry["b"], entry["none"]), (3, 1.5, True, None))
        self.assertEqual(entry["obj"], "['a', 1]")

    def test_separate_trails_do_not_share_records(self) -> None:
        """Two trails (for example a test harness and a restarted app in one process) must not write
        each other's events."""
        first, second = self.dir / "first.log", self.dir / "second.log"
        AuditTrail(first).record("one", user="a", source="s")
        AuditTrail(second).record("two", user="b", source="s")
        self.assertEqual([e["event"] for e in self.lines(first)], ["one"])
        self.assertEqual([e["event"] for e in self.lines(second)], ["two"])


if __name__ == "__main__":
    unittest.main()
