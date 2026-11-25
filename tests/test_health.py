"""Overview health: routing-engine and SPU parsers (recorded and synthetic replies) and /api/health."""

from __future__ import annotations

import unittest
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from jwicket.junos import health as H
from jwicket.junos.session import ALLOWED_RPCS

from test_live import LiveHttpBase

FIXTURES = Path(__file__).resolve().parent / "fixtures"
RECORDED = FIXTURES / "recorded-srx4100-25.2R1-S1.4"


def load(path: Path) -> Any:
    return ElementTree.parse(path).getroot()


def xml(text: str) -> Any:
    return ElementTree.fromstring(text)


class RecordedReplyTests(unittest.TestCase):
    """The replies recorded on SRX4100 25.2R1-S1.4, parsed as they came from the device."""

    def test_route_engine(self) -> None:
        got = H.route_engines(load(RECORDED / "get-route-engine-information.xml"))
        self.assertEqual(got["status"], "ok")
        (re_,) = got["engines"]
        self.assertEqual(re_["cpu"], {"user": 8.0, "background": 0.0, "system": 11.0, "interrupt": 2.0,
                                      "idle": 78.0, "busy": 22.0})
        self.assertEqual(re_["memory"], {"total_mb": 3119, "used_mb": 1435, "util": 46.0, "buffer_util": 25.0})
        self.assertEqual(re_["load"], [1.80, 2.14, 2.11])
        self.assertEqual((re_["temperature_c"], re_["cpu_temperature_c"]), (30, 30))
        self.assertEqual(re_["uptime_s"], 28177151)
        self.assertEqual((re_["node"], re_["slot"], re_["status"]), (None, None, "OK"))

    def test_spu(self) -> None:
        got = H.spus(load(RECORDED / "get-performance-summary-information.xml"))
        self.assertEqual(got, {"status": "ok", "units": [{
            "node": None, "fpc": 0, "pic": 0, "cpu": 0.0, "memory": 42.0, "flow_sessions": 39,
            "flow_max": 10485760, "cp_sessions": 0, "cp_max": 0}]})

    def test_both_rpcs_are_allowlisted(self) -> None:
        self.assertIn("get-route-engine-information", ALLOWED_RPCS)
        self.assertIn("get-performance-summary-information", ALLOWED_RPCS)


class LayoutTests(unittest.TestCase):
    def test_cluster_and_dual_routing_engines(self) -> None:
        reply = xml("""
<multi-routing-engine-results>
  <multi-routing-engine-item><re-name>node0</re-name>
    <route-engine-information><route-engine><slot>0</slot><mastership-state>master</mastership-state>
      <cpu-idle>90</cpu-idle><memory-system-total-util>30</memory-system-total-util></route-engine>
    <route-engine><slot>1</slot><mastership-state>backup</mastership-state><cpu-idle>99</cpu-idle></route-engine>
    </route-engine-information></multi-routing-engine-item>
  <multi-routing-engine-item><re-name>node1</re-name>
    <route-engine-information><route-engine><cpu-idle>95</cpu-idle></route-engine></route-engine-information>
  </multi-routing-engine-item>
</multi-routing-engine-results>""")
        got = H.route_engines(reply)["engines"]
        self.assertEqual([(e["node"], e["slot"], e["mastership"], e["cpu"]["busy"]) for e in got],
                         [("node0", 0, "master", 10.0), ("node0", 1, "backup", 1.0), ("node1", None, None, 5.0)])
        self.assertEqual(got[0]["memory"]["util"], 30.0)
        self.assertIsNone(got[1]["memory"]["util"])

    def test_missing_and_malformed_numbers_are_none_not_guesses(self) -> None:
        reply = xml("<route-engine-information><route-engine><cpu-idle>n/a</cpu-idle>"
                    "<temperature>hot</temperature></route-engine></route-engine-information>")
        (re_,) = H.route_engines(reply)["engines"]
        self.assertIsNone(re_["cpu"]["idle"])
        self.assertIsNone(re_["cpu"]["busy"])
        self.assertIsNone(re_["temperature_c"])
        self.assertEqual(re_["load"], [None, None, None])

    def test_temperature_from_text_when_the_attribute_is_absent(self) -> None:
        reply = xml("<route-engine-information><route-engine><temperature>41 degrees C / 105 degrees F"
                    "</temperature></route-engine></route-engine-information>")
        self.assertEqual(H.route_engines(reply)["engines"][0]["temperature_c"], 41)

    def test_several_spus_per_node(self) -> None:
        reply = xml("""
<multi-routing-engine-results><multi-routing-engine-item><re-name>node0</re-name>
  <performance-summary-information>
    <performance-summary-statistics><fpc-number>1</fpc-number><pic-number>0</pic-number><spu-cpu-utilization>7</spu-cpu-utilization></performance-summary-statistics>
    <performance-summary-statistics><fpc-number>1</fpc-number><pic-number>1</pic-number><spu-cpu-utilization>9</spu-cpu-utilization></performance-summary-statistics>
  </performance-summary-information></multi-routing-engine-item></multi-routing-engine-results>""")
        units = H.spus(reply)["units"]
        self.assertEqual([(u["node"], u["fpc"], u["pic"], u["cpu"]) for u in units],
                         [("node0", 1, 0, 7.0), ("node0", 1, 1, 9.0)])

    def test_empty_replies_are_failed_states(self) -> None:
        self.assertEqual(H.route_engines(xml("<route-engine-information/>"))["status"], "failed")
        self.assertEqual(H.spus(xml("<performance-summary-information/>"))["status"], "failed")


class HealthHttpTests(LiveHttpBase):
    def test_requires_sign_in(self) -> None:
        self.assertEqual(self.request("GET", "/api/health")[0], 401)

    def test_read_and_rate_limit(self) -> None:
        status, _, data = self.get("/api/health")
        self.assertEqual(status, 200)
        self.assertEqual((data["route_engine"]["status"], data["spu"]["status"]), ("ok", "ok"))
        re_ = data["route_engine"]["engines"][0]
        self.assertAlmostEqual(re_["cpu"]["busy"] + re_["cpu"]["idle"], 100.0)
        self.assertGreater(re_["memory"]["used_mb"], 0)
        self.assertEqual(data["meta"]["suggested_interval_s"], 10)
        self.assertEqual(self.get("/api/health")[0], 429)
        self.clock.now += 5
        self.assertEqual(self.get("/api/health")[0], 200)

    def test_one_part_denied_leaves_the_other(self) -> None:
        cookie = self.login("auditor")
        status, _, data = self.get("/api/health", cookie)
        self.assertEqual(status, 200)
        self.assertEqual(data["route_engine"]["status"], "ok")
        self.assertEqual(data["spu"]["status"], "denied")
        self.assertNotIn("fixture:", data["spu"]["message"])  # the device's text stays in the log


class UnsupportedFixtureTests(LiveHttpBase):
    fixture = "cluster-lsys"  # has no health replies: both parts say unsupported

    def test_unsupported_is_a_state(self) -> None:
        status, _, data = self.get("/api/health")
        self.assertEqual(status, 200)
        self.assertEqual((data["route_engine"]["status"], data["spu"]["status"]), ("unsupported", "unsupported"))


if __name__ == "__main__":
    unittest.main()
