"""Q-REL-01: J-Wicket's parsers on replies recorded from a lab SRX4100, Junos 25.2R1-S1.4.

The replies are whole NETCONF <rpc-reply> documents (tests/fixtures/recorded-srx4100-25.2R1-S1.4/
SOURCE.md). PyEZ hands the parsers the single element inside the reply, and so does ``inner`` here.
Live values (session counts, CPU) are checked for shape and consistency, not for one number, except
where the file is the record and the number is part of what it shows.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from jwicket.junos import facts, health
from jwicket.junos import logs as L
from jwicket.junos import sessions as S
from jwicket.junos.errors import RpcDenied, RpcUnsupported, classify
from jwicket.junos.inventory import configuration_root, list_scopes

REC = Path(__file__).resolve().parent / "fixtures" / "recorded-srx4100-25.2R1-S1.4"


def inner(name: str) -> Any:
    root = ElementTree.parse(REC / f"{name}.xml").getroot()
    kids = [k for k in root if isinstance(k.tag, str)]
    return kids[0] if len(kids) == 1 else root


class RpcError(Exception):
    """Stands in for PyEZ's RpcError, which classify() recognises by message, not by import."""


class RecordedReplyTests(unittest.TestCase):
    def test_software(self) -> None:
        got = facts.software(inner("get-software-information"))
        self.assertEqual((got["status"], got["hostname"], got["model"], got["version"]),
                         ("ok", "CRX-SRX-FW-01", "srx4100", "25.2R1-S1.4"))
        self.assertEqual(got["nodes"], [])

    def test_standalone_cluster_status_is_unsupported(self) -> None:
        reply = ElementTree.parse(REC / "get-chassis-cluster-status.xml").getroot()
        message = next(e.text for e in reply.iter() if e.tag.endswith("message"))
        self.assertEqual(message, "error: Chassis cluster is not enabled")
        self.assertIsInstance(classify(RpcError(message)), RpcUnsupported)
        # PyEZ returns this error element rather than raising: the parser must read it as standalone.
        self.assertEqual(facts.cluster(inner("get-chassis-cluster-status")), {"status": "ok", "mode": "standalone"})
        self.assertEqual(facts.cluster(reply), {"status": "ok", "mode": "standalone"})
        # The denial wording seen for a read-only class (jwicket.log on the same device).
        self.assertIsInstance(classify(RpcError("error: permission denied")), RpcDenied)

    def test_summary_splits_valid_and_invalidated(self) -> None:
        got = S.parse_summary(inner("get-flow-session-information-summary"))
        self.assertEqual(got["status"], "ok")
        self.assertEqual(got["max"], 10485760)
        self.assertEqual(got["active"], got["valid"] + got["invalidated"])
        self.assertEqual((got["active"], got["valid"], got["invalidated"]), (43, 21, 22))

    def test_session_list(self) -> None:
        got = S.parse_sessions(inner("get-flow-session-information"), S.MAX_LIMIT)
        self.assertEqual(got["status"], "ok")
        rows = got["rows"]
        self.assertEqual(len(rows), 25)
        for row in rows:
            with self.subTest(id=row["id"]):
                self.assertTrue(row["id"].isdigit())
                self.assertIn(row["in"]["proto"], ("tcp", "udp", "icmp", "icmp6", "gre", "esp"))
                self.assertIsInstance(row["in"]["bytes"], int)
                self.assertTrue(row["policy"])
                self.assertTrue(row["in"]["iface"])
                # Spec 004 section 5.2: sess-state (no session-state here) fills state, and each wing's
                # tunnel-id fills tunnel, with tunnel-type kept in the wing's extra.
                self.assertEqual((row["status"], row["state"]), ("Normal", "Valid"))
                self.assertNotIn("sess-state", row["extra"])
                for wing in (row["in"], row["out"]):
                    self.assertEqual((wing["tunnel"], wing["extra"]["tunnel-type"]), ("0", "None"))
                    self.assertNotIn("tunnel-id", wing["extra"])
        self.assertEqual(len({r["id"] for r in rows}), len(rows))

    def test_log_sources_stream_mode(self) -> None:
        sw = facts.software(inner("get-software-information"))
        got = L.sources(configuration_root(inner("get-configuration-logs")), sw["model"], sw["version"])
        self.assertEqual(got["status"], "ok")
        self.assertEqual(got["traffic"]["effective_mode"], "stream")
        self.assertEqual([s["host"] for s in got["traffic"]["streams"]], ["srx.sdcloud.juniperclouds.net"])
        self.assertEqual([f["name"] for f in got["files"]], ["interactive-commands", "messages", "sdcloud-messages"])

    def test_security_log_buffer_disabled(self) -> None:
        self.assertEqual(L.buffer_events(inner("get-security-log-information")),
                         {"events": [], "lines": [], "disabled": True})

    def test_inventory_and_central_management(self) -> None:
        config = configuration_root(inner("get-configuration-inventory"))
        self.assertEqual([s[0] for s in list_scopes(config)], ["root"])
        cm = facts.central_management(config)
        self.assertTrue(cm["managed"])
        self.assertEqual(cm["clients"], [{
            "client": "EMS-srx.sdcloud.juniperclouds.net", "targets": ["srx.sdcloud.juniperclouds.net:7804"],
            "services": ["netconf"], "inactive": False}])

    def test_inventory_reply_holds_no_outbound_ssh_secret(self) -> None:
        text = (REC / "get-configuration-inventory.xml").read_text(encoding="utf-8")
        self.assertNotIn("<secret>", text)
        self.assertNotIn("<device-id>", text)

    def test_health(self) -> None:
        engines = health.route_engines(inner("get-route-engine-information"))["engines"]
        self.assertEqual(len(engines), 1)
        cpu = engines[0]["cpu"]
        self.assertAlmostEqual(cpu["busy"] + cpu["idle"], 100.0)
        units = health.spus(inner("get-performance-summary-information"))["units"]
        self.assertEqual([(u["fpc"], u["pic"]) for u in units], [(0, 0)])


if __name__ == "__main__":
    unittest.main()
