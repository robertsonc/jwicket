"""logs.AuditTrail: one JSON object per line; never a password, token, cookie, secret or CSRF value."""

from __future__ import annotations

import json
import logging
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List
from unittest import mock

from jwicket import logs as logs_mod
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
        self.addCleanup(trail.close)
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
        self.addCleanup(trail.close)
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
        self.addCleanup(trail.close)
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
        trail = AuditTrail(path)
        self.addCleanup(trail.close)
        trail.record("x", user="a", source="s", n=3, f=1.5, b=True, none=None, obj=["a", 1])
        entry = self.lines(path)[0]
        self.assertEqual((entry["n"], entry["f"], entry["b"], entry["none"]), (3, 1.5, True, None))
        self.assertEqual(entry["obj"], "['a', 1]")

    def test_separate_trails_do_not_share_records(self) -> None:
        """Two trails (for example a test harness and a restarted app in one process) must not write
        each other's events."""
        first, second = self.dir / "first.log", self.dir / "second.log"
        one, two = AuditTrail(first), AuditTrail(second)
        self.addCleanup(one.close)
        self.addCleanup(two.close)
        one.record("one", user="a", source="s")
        two.record("two", user="b", source="s")
        self.assertEqual([e["event"] for e in self.lines(first)], ["one"])
        self.assertEqual([e["event"] for e in self.lines(second)], ["two"])



class RefusalAggregationTests(AuditIsolation):
    """SECU-4: refusals of clients without a session cannot flood the trail."""

    def setUp(self) -> None:
        super().setUp()
        self.now = 1000.0
        self.path = self.dir / "audit.log"
        self.trail = AuditTrail(self.path, clock=lambda: self.now)
        self.addCleanup(self.trail.close)

    def test_first_is_written_repeats_are_counted(self) -> None:
        for _ in range(500):
            self.trail.record_refusal("login_refused", source="127.0.0.1", reason="cross-origin")
        entries = self.lines(self.path)
        self.assertEqual(len(entries), 1)
        self.assertEqual((entries[0]["event"], entries[0]["reason"], entries[0]["user"]),
                         ("login_refused", "cross-origin", None))
        self.now += 61
        self.trail.flush()
        entries = self.lines(self.path)
        self.assertEqual(len(entries), 2)
        self.assertEqual((entries[1]["repeated"], entries[1]["window_s"]), (499, 60))
        self.trail.record_refusal("login_refused", source="127.0.0.1", reason="cross-origin")
        self.assertEqual(len(self.lines(self.path)), 3)  # a new window starts with a line of its own

    def test_a_window_with_no_repeats_adds_no_count_line(self) -> None:
        self.trail.record_refusal("login_throttled", source="s", reason="failures")
        self.now += 61
        self.trail.flush()
        self.assertEqual(len(self.lines(self.path)), 1)

    def test_kinds_sources_and_reasons_are_kept_apart(self) -> None:
        self.trail.record_refusal("login_refused", source="a", reason="cross-origin")
        self.trail.record_refusal("login_refused", source="b", reason="cross-origin")
        self.trail.record_refusal("login_throttled", source="a", reason="busy")
        self.assertEqual(len(self.lines(self.path)), 3)

    def test_many_sources_are_counted_together(self) -> None:
        with mock.patch.object(logs_mod, "MAX_REFUSAL_KEYS", 4):
            for i in range(100):
                self.trail.record_refusal("login_refused", source=f"2001:db8::{i:x}", reason="cross-origin")
            self.trail.close()
        entries = self.lines(self.path)
        self.assertEqual(len(entries), 4 + 2)  # four sources, then one "various" line and its count
        various = [e for e in entries if e["source"] == "various"]
        self.assertEqual([e.get("repeated") for e in various], [None, 95])

    def test_close_writes_pending_counts(self) -> None:
        for _ in range(3):
            self.trail.record_refusal("login_failed", source="s", kind="rejected", reason="format")
        self.trail.close()
        entries = self.lines(self.path)
        self.assertEqual([e.get("repeated") for e in entries], [None, 2])
        self.assertEqual(entries[1]["kind"], "rejected")

    def test_forbidden_fields_are_dropped_here_too(self) -> None:
        self.trail.record_refusal("login_failed", source="s", password="hunter2", token="t0k")
        raw = self.path.read_text(encoding="utf-8")
        self.assertNotIn("hunter2", raw)
        self.assertNotIn("t0k", raw)


class PseudonymTests(AuditIsolation):
    def test_keyed_hash_correlates_within_a_trail_only(self) -> None:
        first, second = AuditTrail(None), AuditTrail(None)
        self.assertEqual(first.pseudonym("P@ssw0rd-2024"), first.pseudonym("P@ssw0rd-2024"))
        self.assertNotEqual(first.pseudonym("a"), first.pseudonym("b"))
        self.assertNotEqual(first.pseudonym("a"), second.pseudonym("a"))
        self.assertRegex(first.pseudonym("a"), r"^[0-9a-f]{16}$")
        self.assertNotIn("P@ss", first.pseudonym("P@ssw0rd-2024"))


if __name__ == "__main__":
    unittest.main()
