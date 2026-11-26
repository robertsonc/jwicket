"""Replay sanitized 24.4R2-S3.5 vSRX replies as Q-REL-01 partial evidence."""

from __future__ import annotations

import unittest
from pathlib import Path
from xml.etree import ElementTree

from jwicket.junos import logs, sessions
from jwicket.junos.errors import RpcDenied, classify

REC = Path(__file__).resolve().parent / "fixtures" / "recorded-vsrx-24.4R2-S3.5"


def reply(name: str) -> ElementTree.Element:
    return ElementTree.parse(REC / f"{name}.xml").getroot()


def inner(name: str) -> ElementTree.Element:
    """Mirror the single payload element that PyEZ returns to the parser."""
    root = reply(name)
    return root[0] if len(root) == 1 else root


class RpcError(Exception):
    """Stand in for PyEZ's exception, preserving the recorded Junos error message."""


class RecordedVsrxTests(unittest.TestCase):
    def test_filtered_transit_sessions(self) -> None:
        table = sessions.parse_sessions(inner("get-flow-session-information-filtered"), sessions.MAX_LIMIT)
        self.assertEqual((table["status"], table["returned"], table["device_count"]), ("ok", 4, 4))
        self.assertFalse(table["truncated"])
        self.assertEqual(len(table["rows"]), 4)
        self.assertEqual(len({row["id"] for row in table["rows"]}), 4)
        for row in table["rows"]:
            with self.subTest(id=row["id"]):
                self.assertEqual((row["policy"], row["policy_index"]), ("JW-QREL-ICMP", "8"))
                self.assertEqual(row["state"] or row["extra"].get("sess-state"), "Valid")
                self.assertEqual(row["nat"], {"source": False, "destination": False})
                incoming, outgoing = row["in"], row["out"]
                self.assertEqual((incoming["src"], incoming["dst"]), ("192.0.2.10", "198.51.100.20"))
                self.assertEqual((outgoing["src"], outgoing["dst"]), ("198.51.100.20", "192.0.2.10"))
                self.assertEqual((incoming["proto"], outgoing["proto"]), ("icmp", "icmp"))
                self.assertEqual((incoming["iface"], outgoing["iface"]), ("ge-0/0/0.0", "st0.0"))
                for wing in (incoming, outgoing):
                    self.assertEqual((wing["packets"], wing["bytes"]), (1, 84))

    def test_filtered_matches_are_not_the_table_wide_gauge(self) -> None:
        matching = sessions.parse_summary(inner("get-flow-session-information-matching"))
        self.assertEqual((matching["status"], matching["matching"]), ("ok", 4))
        self.assertIsNone(matching["active"])
        self.assertIsNone(matching["max"])

        gauge = sessions.parse_summary(inner("get-flow-session-information-summary"))
        self.assertEqual((gauge["status"], gauge["active"], gauge["max"]), ("ok", 6, 524288))
        self.assertEqual((gauge["valid"], gauge["invalidated"], gauge["failed"]), (6, 0, 0))
        self.assertIsNone(gauge["matching"])

    def test_file_content_reply_contains_the_synthetic_log_marker(self) -> None:
        message = "Nov 26 20:00:00  vSRX-LAB JWICKET-QREL[4242]: JWICKET-QREL-20261126"
        self.assertEqual(logs.clean_file_reply(reply("get-log-allowed")), [message])
        self.assertEqual(logs.clean_file_reply(inner("get-log-allowed")), [message])

    def test_recorded_file_read_error_is_classified_as_denied(self) -> None:
        error = inner("get-log-denied")
        self.assertTrue(error.tag.endswith("}rpc-error"))
        fields = {child.tag.rsplit("}", 1)[-1]: (child.text or "").strip() for child in error}
        self.assertEqual(fields["error-tag"], "operation-failed")
        self.assertEqual(fields["error-severity"], "error")
        self.assertEqual(fields["error-message"], "could not open 'jwicket-qrel': Permission denied")
        self.assertIsInstance(classify(RpcError(fields["error-message"])), RpcDenied)


if __name__ == "__main__":
    unittest.main()
