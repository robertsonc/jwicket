"""Replay sanitized 24.4R2-S3.5 vSRX replies as Q-REL-01 partial evidence."""

from __future__ import annotations

import unittest
from pathlib import Path
from typing import Any, Dict, List, Tuple
from xml.etree import ElementTree

from jwicket.junos import logs, sessions
from jwicket.junos.errors import RpcDenied, classify
from jwicket.junos.session import LOGS_FILTER, PyEzUserSession
from jwicket.web.http import COOKIE_PLAIN

from test_live import LiveHttpBase

FIXTURES = Path(__file__).resolve().parent / "fixtures"
REC = FIXTURES / "recorded-vsrx-24.4R2-S3.5"
SRX4100 = FIXTURES / "recorded-srx4100-25.2R1-S1.4"


def reply(name: str) -> ElementTree.Element:
    return ElementTree.parse(REC / f"{name}.xml").getroot()


def inner(name: str, directory: Path = REC) -> ElementTree.Element:
    """Mirror the single payload element that PyEZ returns to the parser."""
    root = ElementTree.parse(directory / f"{name}.xml").getroot()
    kids = [k for k in root if isinstance(k.tag, str)]
    return kids[0] if len(kids) == 1 else root


def denied_message() -> str:
    """The recorded ``error-message`` text of the restricted class's ``get-log`` reply."""
    found = next(e for e in inner("get-log-denied") if e.tag.rsplit("}", 1)[-1] == "error-message")
    return (found.text or "").strip()


class RpcError(Exception):
    """Stand in for PyEZ's exception, preserving the recorded Junos error message."""


# Per session id: ((in source port, in destination port), (out source port, out destination port)),
# as recorded in get-flow-session-information-filtered.xml (pseudonymized ICMP identifiers).
RECORDED_PORTS: Dict[str, Tuple[Tuple[int, int], Tuple[int, int]]] = {
    "1001": ((4200, 0), (0, 4200)),
    "1002": ((4200, 4202), (4202, 4200)),
    "1003": ((4200, 4203), (4203, 4200)),
    "1004": ((4200, 4204), (4204, 4200)),
}


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
                self.assertEqual(row["status"], "Normal")
                # The rows carry sess-state and no session-state, so sess-state fills state and is
                # not repeated in extra (Spec 004 section 5.2, Spec 005 DF-05).
                self.assertEqual(row["state"], "Valid")
                self.assertNotIn("sess-state", row["extra"])
                self.assertNotIn("session-state", row["extra"])
                self.assertEqual(row["nat"], {"source": False, "destination": False})
                incoming, outgoing = row["in"], row["out"]
                self.assertEqual((incoming["src"], incoming["dst"]), ("192.0.2.10", "198.51.100.20"))
                self.assertEqual((outgoing["src"], outgoing["dst"]), ("198.51.100.20", "192.0.2.10"))
                self.assertEqual((incoming["proto"], outgoing["proto"]), ("icmp", "icmp"))
                self.assertEqual((incoming["iface"], outgoing["iface"]), ("ge-0/0/0.0", "st0.0"))
                for wing in (incoming, outgoing):
                    self.assertEqual((wing["packets"], wing["bytes"]), (1, 84))
                ports_in, ports_out = RECORDED_PORTS[row["session_id"]]
                self.assertEqual((incoming["sport"], incoming["dport"]), ports_in)
                self.assertEqual((outgoing["sport"], outgoing["dport"]), ports_out)
                # No wing carries tunnel-information, so tunnel falls back to tunnel-id, verbatim, and
                # tunnel-type and tunnel-info stay in the wing's extra (Spec 004 sections 5.2 and 7.3).
                # The ids are the redaction's pseudonyms (SOURCE.md).
                self.assertEqual((incoming["tunnel"], outgoing["tunnel"]), ("0", "800002"))
                self.assertEqual(incoming["extra"]["tunnel-type"], "None")
                self.assertNotIn("tunnel-info", incoming["extra"])
                out_extra = outgoing["extra"]
                self.assertEqual((out_extra["tunnel-type"], out_extra["tunnel-info"]), ("IPsec", "800003"))
                for wing in (incoming, outgoing):
                    self.assertNotIn("tunnel-id", wing["extra"])
                    # Other unmodelled wing scalars are kept too, not dropped.
                    self.assertEqual(wing["extra"]["conn-tag"], "0x0")

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


# Synthetic, not recorded: one syslog file named jwicket-qrel, with element names copied from the
# recorded SRX4100 25.2R1-S1.4 reply to the same configuration read (get-configuration-logs.xml).
SYNTHETIC_LOG_CONFIG = (
    "<configuration><system><syslog><file><name>jwicket-qrel</name>"
    "<contents><name>any</name><any/></contents></file></syslog></system></configuration>"
)


class FakePyEzRpc:
    """Stands in for PyEZ's ``dev.rpc`` with only the calls the log endpoints make."""

    def __init__(self) -> None:
        self.calls: List[Tuple[str, Dict[str, Any]]] = []

    def get_config(self, **kwargs: Any) -> ElementTree.Element:
        self.calls.append(("get_config", kwargs))
        return ElementTree.fromstring(SYNTHETIC_LOG_CONFIG)

    def get_software_information(self, **kwargs: Any) -> ElementTree.Element:
        self.calls.append(("get_software_information", kwargs))
        # Recorded on SRX4100 25.2R1-S1.4; the vSRX recording has no software reply.
        return inner("get-software-information", SRX4100)

    def get_log(self, **kwargs: Any) -> ElementTree.Element:
        self.calls.append(("get_log", kwargs))
        raise RpcError(denied_message())


class FakePyEzDevice:
    def __init__(self) -> None:
        self.rpc = FakePyEzRpc()

    def close(self) -> None:
        return None


class RecordedVsrxHttpTests(LiveHttpBase):
    """AC-004-06: a class that may read the log configuration but not the file gets a denied panel."""

    def test_listed_file_denied_after_sources_ok(self) -> None:
        dev = FakePyEzDevice()
        device = PyEzUserSession(dev, "op")
        token, _ = self.app.sessions.create(user="op", backend="netconf", device=device, source="t")
        cookie = f"{COOKIE_PLAIN}={token}"

        status, _, data = self.get("/api/logs/sources", cookie)
        self.assertEqual((status, data["sources"]["status"]), (200, "ok"))
        self.assertIn("jwicket-qrel", [f["name"] for f in data["sources"]["files"]])

        status, _, data = self.get("/api/logs?file=jwicket-qrel", cookie)
        self.assertEqual(status, 200)
        self.assertEqual((data["log"]["status"], data["log"]["lines"]), ("denied", []))
        self.assertNotIn(denied_message(), data["log"]["message"])  # the device's text stays in the log
        self.assertIn(("get_log", {"filename": "jwicket-qrel"}), dev.rpc.calls)
        config_reads = [kw for name, kw in dev.rpc.calls if name == "get_config"]
        self.assertEqual([kw["filter_xml"] for kw in config_reads], [LOGS_FILTER])


if __name__ == "__main__":
    unittest.main()
