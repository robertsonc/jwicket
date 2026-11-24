"""Spec 004: flow sessions and log tailing (adapters and HTTP endpoints)."""

from __future__ import annotations

import http.client
import json
import threading
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode
from xml.etree import ElementTree

from jwicket.api import App, build_router
from jwicket.auth.sessions import SessionStore
from jwicket.auth.throttle import LoginThrottle
from jwicket.devserver import FixtureBackend
from jwicket.junos import logs as L
from jwicket.junos import sessions as S
from jwicket.junos.errors import RpcDenied
from jwicket.logs import AuditTrail
from jwicket.web.http import COOKIE_PLAIN
from jwicket.web.server import JWicketServer

from helpers import FakeDevice

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def xml(text: str) -> Any:
    return ElementTree.fromstring(text)


class SessionFilterTests(unittest.TestCase):
    def test_valid_filters_map_to_rpc_parameters(self) -> None:
        got = S.device_filters(
            {"src": "10.10.0.0/16", "dst": "198.51.100.7", "sport": "1024", "dport": "443",
             "proto": "TCP", "app": "junos-https", "iface": "ge-0/0/1.0", "other": "ignored"}
        )
        self.assertEqual(
            got,
            {"source-prefix": "10.10.0.0/16", "destination-prefix": "198.51.100.7/32", "source-port": "1024",
             "destination-port": "443", "protocol": "tcp", "application": "junos-https", "interface": "ge-0/0/1.0"},
        )
        self.assertEqual(S.rpc_kwargs({"source-prefix": "10.0.0.0/8"}), {"source_prefix": "10.0.0.0/8"})

    def test_host_bits_are_normalised_not_rejected(self) -> None:
        self.assertEqual(S.device_filters({"src": "10.10.3.4/16"}), {"source-prefix": "10.10.0.0/16"})

    def test_bad_values_are_refused(self) -> None:
        for key, value in (("src", "10.0.0.0/33"), ("src", "host.example"), ("dport", "70000"), ("dport", "-1"),
                           ("sport", "4a"), ("proto", "tcp;show"), ("app", "a b"), ("app", "x" * 70),
                           ("iface", "ge-0/0/0.0 | display"), ("iface", "../../etc")):
            with self.subTest(key=key, value=value), self.assertRaises(S.FilterError):
                S.device_filters({key: value})

    def test_limit(self) -> None:
        self.assertEqual(S.parse_limit(None), S.DEFAULT_LIMIT)
        self.assertEqual(S.parse_limit("99999"), S.MAX_LIMIT)
        self.assertEqual(S.parse_limit("0"), 1)
        with self.assertRaises(S.FilterError):
            S.parse_limit("ten")


SESSION_REPLY = """
<flow-session-information>
  <flow-session>
    <session-identifier>42</session-identifier><status>Normal</status><session-state>Valid</session-state>
    <policy>allow-web/5</policy><configured-timeout>1800</configured-timeout><timeout>1790</timeout>
    <start-time>1795500000</start-time><duration>10</duration>
    <flow-information><direction>In</direction><source-address>10.10.0.5</source-address><source-port>51234</source-port>
      <destination-address>198.51.100.20</destination-address><destination-port>443</destination-port>
      <protocol>tcp</protocol><interface-name>ge-0/0/1.0</interface-name><pkt-cnt>4</pkt-cnt><byte-cnt>520</byte-cnt></flow-information>
    <flow-information><direction>Out</direction><source-address>198.51.100.20</source-address><source-port>443</source-port>
      <destination-address>203.0.113.2</destination-address><destination-port>40123</destination-port>
      <protocol>tcp</protocol><interface-name>ge-0/0/0.0</interface-name><pkt-cnt>3</pkt-cnt><byte-cnt>4000</byte-cnt></flow-information>
  </flow-session>
  <displayed-session-count>1</displayed-session-count>
</flow-session-information>
"""

CLUSTER_REPLY = """
<multi-routing-engine-results>
  <multi-routing-engine-item><re-name>node0</re-name>
    <flow-session-information>
      <flow-fpc-pic-id>on FPC0 PIC1:</flow-fpc-pic-id>
      <flow-session><session-identifier>1</session-identifier><policy>p</policy></flow-session>
      <flow-session><session-identifier>2</session-identifier><policy>p</policy></flow-session>
      <displayed-session-count>2</displayed-session-count>
    </flow-session-information>
  </multi-routing-engine-item>
  <multi-routing-engine-item><re-name>node1</re-name>
    <flow-session-information>
      <flow-session><session-identifier>1</session-identifier><policy>p</policy></flow-session>
      <displayed-session-count>1</displayed-session-count>
    </flow-session-information>
  </multi-routing-engine-item>
</multi-routing-engine-results>
"""


class SessionParseTests(unittest.TestCase):
    def test_wings_policy_and_source_nat(self) -> None:
        got = S.parse_sessions(xml(SESSION_REPLY), 10)
        self.assertEqual(got["returned"], 1)
        self.assertEqual(got["device_count"], 1)
        row = got["rows"][0]
        self.assertEqual((row["policy"], row["policy_index"]), ("allow-web", "5"))
        self.assertEqual(row["in"]["src"], "10.10.0.5")
        self.assertEqual(row["out"]["dst"], "203.0.113.2")
        self.assertEqual(row["nat"], {"source": True, "destination": False})
        self.assertEqual(row["in"]["bytes"], 520)

    def test_cluster_and_spu_locations_keep_ids_distinct(self) -> None:
        got = S.parse_sessions(xml(CLUSTER_REPLY), 10)
        ids = [r["id"] for r in got["rows"]]
        self.assertEqual(len(ids), len(set(ids)), ids)
        self.assertEqual(got["rows"][0]["location"], "node0 on FPC0 PIC1:")
        self.assertEqual(got["rows"][2]["location"], "node1")
        # JUNO-6: both nodes hold a copy of session 1, so the device count is the largest node's,
        # not the sum; both copies stay rows (the browser marks Backup copies).
        self.assertEqual(got["device_count"], 2)
        self.assertEqual(got["nodes"], [{"node": "node0", "device_count": 2}, {"node": "node1", "device_count": 1}])
        self.assertEqual(got["returned"], 3)

    def test_limit_truncates_and_says_so(self) -> None:
        got = S.parse_sessions(xml(CLUSTER_REPLY), 2)
        self.assertEqual((len(got["rows"]), got["returned"], got["truncated"]), (2, 3, True))

    def test_policy_without_index(self) -> None:
        self.assertEqual(S._split_policy("plain"), ("plain", None))
        self.assertEqual(S._split_policy("a/b/7"), ("a/b", "7"))
        self.assertEqual(S._split_policy("N/A"), ("N/A", None))

    def test_documented_n_suffix_is_split_off(self) -> None:
        """JUNO-14: the CLI reference shows "pre-id-default-policy/n"."""
        self.assertEqual(S._split_policy("pre-id-default-policy/n"), ("pre-id-default-policy", None))
        self.assertEqual(S._split_policy("/n"), ("/n", None))

    def test_documented_protocol_keywords(self) -> None:
        """JUNO-17: every keyword the CLI reference lists is accepted."""
        for name in ("ah", "egp", "esp", "gre", "icmp", "icmp6", "igmp", "ipip", "ospf", "pim", "rsvp", "sctp",
                     "tcp", "udp", "IPIP"):
            with self.subTest(name=name):
                self.assertEqual(S.device_filters({"proto": name}), {"protocol": name.lower()})

    def test_summary_sums_spus_within_one_node(self) -> None:
        reply = xml(
            "<r><a><active-sessions>10</active-sessions><max-sessions>100</max-sessions></a>"
            "<b><active-sessions>5</active-sessions><max-sessions>100</max-sessions></b></r>"
        )
        got = S.parse_summary(reply)
        self.assertEqual((got["active"], got["max"]), (15, 200))
        self.assertNotIn("nodes", got)

    def test_cluster_summary_uses_the_largest_node(self) -> None:
        """JUNO-6: 3,000 sessions synced on both nodes are 3,000 sessions, not 6,000."""
        reply = xml(
            "<multi-routing-engine-results>"
            "<multi-routing-engine-item><re-name>node0</re-name><flow-session-information>"
            "<active-sessions>3000</active-sessions><max-sessions>524288</max-sessions>"
            "<failed-sessions>2</failed-sessions><displayed-session-count>2900</displayed-session-count>"
            "</flow-session-information></multi-routing-engine-item>"
            "<multi-routing-engine-item><re-name>node1</re-name><flow-session-information>"
            "<active-sessions>2990</active-sessions><max-sessions>524288</max-sessions>"
            "<failed-sessions>1</failed-sessions><displayed-session-count>2890</displayed-session-count>"
            "</flow-session-information></multi-routing-engine-item>"
            "</multi-routing-engine-results>"
        )
        got = S.parse_summary(reply)
        self.assertEqual((got["active"], got["max"], got["matching"], got["failed"]), (3000, 524288, 2900, 3))
        self.assertEqual([n["node"] for n in got["nodes"]], ["node0", "node1"])
        self.assertEqual(got["nodes"][1]["active"], 2990)


LOG_CONFIG = """
<configuration>
  <system><syslog>
    <file><name>messages</name><contents><name>any</name><notice/></contents></file>
    <file><name>traffic</name><contents><name>any</name><any/></contents><match>RT_FLOW</match><structured-data/></file>
    <file><name>../../etc/passwd</name></file>
  </syslog></system>
  <security><log><mode>stream</mode><report/>
    <stream><name>siem</name><host><ipaddr>192.0.2.50</ipaddr><port>514</port></host></stream>
  </log></security>
</configuration>
"""


class LogSourceTests(unittest.TestCase):
    def test_files_and_stream_mode(self) -> None:
        got = L.sources(xml(LOG_CONFIG))
        names = [f["name"] for f in got["files"]]
        self.assertEqual(names, ["messages", "traffic"])  # the path-like name is never offered
        self.assertTrue(got["files"][1]["structured_data"])
        self.assertEqual(got["traffic"]["mode"], "stream")
        self.assertIn("192.0.2.50", got["traffic"]["where"])
        self.assertIn("not stored here", got["traffic"]["where"])

    def test_messages_assumed_when_not_configured(self) -> None:
        got = L.sources(xml("<configuration/>"))
        self.assertEqual(got["files"][0]["name"], "messages")
        self.assertTrue(got["files"][0].get("assumed"))

    def test_validate_file_allowlist(self) -> None:
        files = L.sources(xml(LOG_CONFIG))["files"]
        self.assertEqual(L.validate_file("traffic", files), "traffic")
        for bad in ("../../etc/passwd", "secrets", "messages/../x", ""):
            with self.subTest(bad=bad), self.assertRaises(L.LogQueryError):
                L.validate_file(bad, files)


class LogSourceStateTests(unittest.TestCase):
    """JUNO-9, -10, -11, -13: what the log configuration really puts in effect."""

    def sources(self, seclog: str, syslog: str = "", model: Optional[str] = "srx345",
                version: Optional[str] = "24.4R2") -> Dict[str, Any]:
        return L.sources(xml(f"<configuration><system><syslog>{syslog}</syslog></system>"
                             f"<security><log>{seclog}</log></security></configuration>"), model, version)

    def test_local_stream_file_is_on_the_device(self) -> None:
        got = self.sources("<mode>stream</mode><stream><name>local</name><format>sd-syslog</format>"
                           "<file><localfilename>traffic.log</localfilename><size>5</size></file></stream>")
        where = got["traffic"]["where"]
        self.assertIn("local stream file(s) traffic.log on this device", where)
        self.assertNotIn("not stored here", where)
        self.assertNotIn("?", where)
        self.assertEqual(got["traffic"]["streams"][0]["file"], "traffic.log")
        named = self.sources("<mode>stream</mode><stream><name>l</name><file><name>f2.pb</name></file></stream>")
        self.assertIn("f2.pb", named["traffic"]["where"])

    def test_radius_and_host_streams(self) -> None:
        got = self.sources("<mode>stream</mode><stream><name>siem</name><host><ipaddr>192.0.2.50</ipaddr></host>"
                           "</stream><stream><name>r</name><radius><ipaddr><primary>192.0.2.9</primary></ipaddr>"
                           "</radius></stream>")
        where = got["traffic"]["where"]
        self.assertIn("streamed off the device to 192.0.2.50", where)
        self.assertIn("RADIUS server(s) 192.0.2.9", where)

    def test_deactivated_mode_report_and_stream(self) -> None:
        got = self.sources('<mode inactive="inactive">event</mode><report inactive="inactive"/>'
                           '<stream inactive="inactive"><name>s</name><host><ipaddr>192.0.2.50</ipaddr></host>'
                           "</stream>")
        traffic = got["traffic"]
        self.assertIsNone(traffic["mode"])
        self.assertEqual(traffic["mode_inactive"], "event")
        self.assertEqual(traffic["effective_mode"], "stream")  # the documented default for srx345 on 24.4
        self.assertNotEqual(traffic["mode_basis"], "set in the configuration")
        self.assertEqual((traffic["report"], traffic["report_inactive"]), (False, True))
        self.assertTrue(traffic["streams"][0]["inactive"])
        self.assertNotIn("192.0.2.50", traffic["where"])
        self.assertIn("deactivated", traffic["where"])
        self.assertEqual([d["id"] for d in got["databases"]], [])

    def test_deactivated_security_log_block(self) -> None:
        got = L.sources(xml('<configuration><security><log inactive="inactive"><mode>event</mode><report/>'
                            "</log></security></configuration>"), "vsrx", "24.4R2")
        self.assertEqual((got["traffic"]["mode"], got["traffic"]["report"]), (None, False))

    def test_deactivated_syslog_file_is_marked_not_dropped(self) -> None:
        got = self.sources("<mode>stream</mode>", syslog='<file inactive="inactive"><name>traffic</name>'
                           "<contents><name>any</name><any/></contents></file>")
        files = {f["name"]: f for f in got["files"]}
        self.assertTrue(files["traffic"]["inactive"])
        self.assertFalse(files["messages"]["inactive"])

    def test_security_log_disable(self) -> None:
        got = self.sources("<disable/><mode>stream</mode><stream><name>siem</name><host><ipaddr>192.0.2.50</ipaddr>"
                           "</host></stream><report/>")
        traffic = got["traffic"]
        self.assertTrue(traffic["disabled"])
        self.assertIn("disabled in the configuration", traffic["where"])
        self.assertNotIn("192.0.2.50", traffic["where"])
        report = next(d for d in got["databases"] if d["id"] == "report")
        self.assertTrue(report["disabled"])  # marked, not hidden: older records may still be there
        inactive_disable = self.sources('<disable inactive="inactive"/><mode>stream</mode>')
        self.assertFalse(inactive_disable["traffic"]["disabled"])

    def test_report_is_shown_whenever_configured_with_a_note_where_undocumented(self) -> None:
        documented = self.sources("<mode>stream</mode><report/>", model="srx345")
        report = next(d for d in documented["databases"] if d["id"] == "report")
        self.assertNotIn("note", report)
        for seclog, model in (("<mode>stream-event</mode><report/>", "srx345"),
                              ("<mode>stream</mode><report/>", "srx550"),
                              ("<mode>stream</mode><report/>", "srx5800")):
            with self.subTest(seclog=seclog, model=model):
                got = self.sources(seclog, model=model)
                report = next(d for d in got["databases"] if d["id"] == "report")
                self.assertIn("not for this model or log mode", report["note"])

    def test_report_queries_need_23_1(self) -> None:
        got = self.sources("<mode>stream</mode><report/>", model="srx345", version="22.4R3")
        report = next(d for d in got["databases"] if d["id"] == "report")
        self.assertIs(report["supported"], False)
        self.assertIn("23.1R1", report["note"])


class TailTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lines = [f"line {i}" for i in range(100)]

    def test_first_read_returns_last_n(self) -> None:
        got = L.tail(self.lines, cursor=None, want=10, contains=[], exclude=[])
        self.assertEqual(got["lines"], self.lines[-10:])
        self.assertFalse(got["reset"])

    def test_incremental_read_returns_only_new_lines(self) -> None:
        first = L.tail(self.lines, cursor=None, want=10, contains=[], exclude=[])
        grown = [*self.lines, "line 100", "line 101"]
        got = L.tail(grown, cursor=L.parse_cursor(first["cursor"]), want=10, contains=[], exclude=[])
        self.assertEqual(got["lines"], ["line 100", "line 101"])

    def test_window_slide_is_found_by_digest(self) -> None:
        first = L.tail(self.lines, cursor=None, want=10, contains=[], exclude=[])
        slid = [*self.lines[50:], "line 100"]  # older lines trimmed, so positions moved
        got = L.tail(slid, cursor=L.parse_cursor(first["cursor"]), want=10, contains=[], exclude=[])
        self.assertEqual(got["lines"], ["line 100"])
        self.assertFalse(got["reset"])

    def test_rotation_is_a_reset(self) -> None:
        first = L.tail(self.lines, cursor=None, want=10, contains=[], exclude=[])
        rotated = ["fresh 1", "fresh 2"]
        got = L.tail(rotated, cursor=L.parse_cursor(first["cursor"]), want=10, contains=[], exclude=[])
        self.assertTrue(got["reset"])
        self.assertEqual(got["lines"], rotated)

    def test_substring_filters_and_drop_count(self) -> None:
        got = L.tail(self.lines, cursor=None, want=3, contains=["line 9"], exclude=["line 99"])
        self.assertEqual(got["lines"], ["line 96", "line 97", "line 98"])
        self.assertGreater(got["dropped"], 0)

    def test_terms_and_cursor_validation(self) -> None:
        self.assertEqual(L.parse_terms("A\nb", "contains"), ["a", "b"])
        with self.assertRaises(L.LogQueryError):
            L.parse_terms("\n".join("x" for _ in range(L.MAX_TERMS + 1)), "contains")
        with self.assertRaises(L.LogQueryError):
            L.parse_cursor("12:nothex")

    def test_control_characters_removed(self) -> None:
        self.assertEqual(L.clean_lines("a\x1b[31mred\x07\r\nb\tc\n\n"), ["a[31mred", "b\tc"])

    def test_reply_text_shapes(self) -> None:
        self.assertEqual(L.reply_text(xml("<file-content>x\ny</file-content>")), "x\ny")
        self.assertEqual(L.reply_text(xml("<rpc-reply><output>z</output></rpc-reply>")), "z")


# --- HTTP -----------------------------------------------------------------------------------------


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class LiveHttpBase(unittest.TestCase):
    """A real server over a fixture, signed in as admin. Helpers only; tests are in subclasses."""

    fixture = "branch"

    def setUp(self) -> None:
        self.clock = Clock()
        # Freeze the live fixture's wall clock so the synthetic session table is identical on every read.
        backend = FixtureBackend(FIXTURES / self.fixture, clock=lambda: 1_795_503_600.0)
        self.app = App(
            backend=backend,  # type: ignore[arg-type]
            sessions=SessionStore(idle_s=900, absolute_s=3600, max_sessions=4, clock=self.clock),
            throttle=LoginThrottle(per_name=50, per_source=50, clock=self.clock),
            audit=AuditTrail(None),
            session_idle_s=900,
            fixture=True,
            mono_clock=self.clock,
        )
        self.server = JWicketServer(
            ("127.0.0.1", 0), build_router(self.app), tls=None, max_connections=8, socket_timeout_s=5,
            max_body_bytes=8192,
        )
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        self.cookie = self.login("admin")

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def request(self, method: str, path: str, body: Optional[Dict[str, Any]] = None,
                headers: Optional[Dict[str, str]] = None) -> Tuple[int, Dict[str, str], Any]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        hdrs = {"Host": f"127.0.0.1:{self.port}", **(headers or {})}
        payload = None
        if body is not None:
            payload = json.dumps(body)
            hdrs["Content-Type"] = "application/json"
        conn.request(method, path, body=payload, headers=hdrs)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        try:
            data = json.loads(raw)
        except ValueError:
            data = raw
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, data

    def login(self, user: str) -> str:
        status, headers, _ = self.request(
            "POST", "/api/login", {"username": user, "password": "x"},
            {"Origin": f"http://127.0.0.1:{self.port}"},
        )
        self.assertEqual(status, 200)
        return headers["set-cookie"].split(";", 1)[0]

    def get(self, path: str, cookie: Optional[str] = None) -> Tuple[int, Dict[str, str], Any]:
        return self.request("GET", path, headers={"Cookie": cookie or self.cookie})



class LiveHttpTests(LiveHttpBase):
    def test_requires_sign_in(self) -> None:
        for path in ("/api/sessions", "/api/logs/sources", "/api/logs?file=messages"):
            with self.subTest(path=path):
                self.assertEqual(self.request("GET", path)[0], 401)

    def test_sessions_read_and_rate_limit(self) -> None:
        status, _, data = self.get("/api/sessions")
        self.assertEqual(status, 200)
        self.assertEqual(data["sessions"]["status"], "ok")
        self.assertTrue(data["meta"]["fixture"])
        self.assertEqual(data["meta"]["device_filters"], {})
        self.assertGreater(len(data["sessions"]["rows"]), 0)
        status, headers, _ = self.get("/api/sessions")
        self.assertEqual(status, 429)
        self.assertIn("retry-after", headers)
        self.clock.now += 2
        self.assertEqual(self.get("/api/sessions")[0], 200)

    def test_sessions_pushdown_filters(self) -> None:
        status, _, data = self.get("/api/sessions?dport=53&proto=udp")
        self.assertEqual(status, 200)
        self.assertEqual(data["meta"]["device_filters"], {"destination-port": "53", "protocol": "udp"})
        self.assertTrue(all(r["in"]["dport"] == 53 for r in data["sessions"]["rows"]))

    def test_sessions_bad_filter_is_400(self) -> None:
        status, _, data = self.get("/api/sessions?src=not-an-ip")
        self.assertEqual(status, 400)
        self.assertIn("not an IP", data["error"])

    def test_sessions_scope_other_than_root_refused(self) -> None:
        self.assertEqual(self.get("/api/sessions?scope=lsys:LS-A")[0], 400)

    def test_refusal_follows_the_matching_count(self) -> None:
        status, _, data = self.get("/api/sessions")
        self.assertEqual(status, 200)
        everything = data["matching"]
        self.assertEqual(everything, data["summary"]["active"])
        self.clock.now += 2
        _, _, narrow = self.get("/api/sessions?dport=53")
        few = narrow["matching"]
        self.assertLess(few, everything)
        self.assertEqual(few, len(narrow["sessions"]["rows"]))
        original = S.MAX_UNFILTERED
        S.MAX_UNFILTERED = few  # the unfiltered table is now "too big"; the narrow one is not
        try:
            self.clock.now += 2
            _, _, data = self.get("/api/sessions")
            self.assertEqual(data["sessions"]["status"], "refused")
            self.assertEqual(data["sessions"]["rows"], [])
            self.assertIn(f"{everything:,} sessions match", data["sessions"]["message"])
            self.clock.now += 2
            _, _, data = self.get("/api/sessions?dport=53")
            self.assertEqual(data["sessions"]["status"], "ok")
        finally:
            S.MAX_UNFILTERED = original

    def test_filtered_read_keeps_the_table_wide_gauge(self) -> None:
        _, _, first = self.get("/api/sessions")
        self.clock.now += 2
        _, _, narrow = self.get("/api/sessions?dport=53")
        self.assertEqual(narrow["summary"]["max"], first["summary"]["max"])
        self.assertIsNotNone(narrow["summary"]["active"])

    def test_log_sources_and_tail(self) -> None:
        status, _, data = self.get("/api/logs/sources")
        self.assertEqual(status, 200)
        names = [f["name"] for f in data["sources"]["files"]]
        self.assertIn("traffic-log", names)
        status, _, data = self.get("/api/logs?file=traffic-log&lines=50")
        self.assertEqual(status, 200)
        log = data["log"]
        self.assertEqual(log["status"], "ok")
        self.assertLessEqual(len(log["lines"]), 50)
        self.assertTrue(data["meta"]["structured_data"])
        self.clock.now += 2
        status, _, again = self.get(f"/api/logs?file=traffic-log&cursor={log['cursor']}")
        self.assertEqual(status, 200)
        self.assertFalse(again["log"]["reset"])

    def test_event_mode_buffer_source(self) -> None:
        _, _, data = self.get("/api/logs/sources")
        traffic = data["sources"]["traffic"]
        self.assertEqual(traffic["effective_mode"], "event")
        self.assertIn("buffer", [d["id"] for d in data["sources"]["databases"]])
        self.assertIn("UI_NETCONF_CMD", data["sources"]["self_noise"])
        status, _, data = self.get("/api/logs?source=buffer")
        self.assertEqual(status, 200)
        log = data["log"]
        self.assertEqual(log["status"], "ok")
        self.assertTrue(log["events"])
        self.assertTrue(all(e["id"].startswith("RT_FLOW_SESSION_") for e in log["events"]))
        self.assertEqual(len(log["events"]), len(log["lines"]))
        self.clock.now += 2
        self.assertEqual(self.get("/api/logs?source=buffer&since=2026-11-24%2006:00")[0], 400)

    def test_report_source_is_offered_only_when_configured(self) -> None:
        _, _, data = self.get("/api/logs/sources")
        self.assertNotIn("report", [d["id"] for d in data["sources"]["databases"]])

    def test_log_file_allowlist_and_validation(self) -> None:
        for path in ("/api/logs?file=..%2F..%2Fetc%2Fpasswd", "/api/logs?file=nope", "/api/logs?lines=many",
                     "/api/logs?cursor=garbage"):
            with self.subTest(path=path):
                self.clock.now += 2
                self.assertEqual(self.get(path)[0], 400)

    def test_log_contains_filter_pushdown(self) -> None:
        status, _, data = self.get("/api/logs?file=messages&contains=RT_FLOW_SESSION_DENY")
        self.assertEqual(status, 200)
        self.assertTrue(all("RT_FLOW_SESSION_DENY" in ln for ln in data["log"]["lines"]))

    def test_denied_log_read_is_an_explicit_state(self) -> None:
        class DenyingDevice:
            user = "admin"
            backend = "fixture"

            def get_configuration(self, filter_xml: str) -> Any:
                raise RpcDenied("no")

            def rpc(self, name: str, **params: Any) -> Any:
                raise RpcDenied("no")

            def close(self) -> None:
                return None

        token, _sess = self.app.sessions.create(user="limited", backend="fixture", device=DenyingDevice(), source="t")
        cookie = f"{COOKIE_PLAIN}={token}"
        status, _, data = self.get("/api/logs/sources", cookie)
        self.assertEqual((status, data["sources"]["status"]), (200, "denied"))
        status, _, data = self.get("/api/logs?file=messages", cookie)
        self.assertEqual((status, data["log"]["status"], data["log"]["lines"]), (200, "denied", []))
        status, _, data = self.get("/api/sessions", cookie)
        self.assertEqual((data["summary"]["status"], data["sessions"]["status"]), ("denied", "denied"))


SUMMARY_OK = "<flow-session-information><active-sessions>{n}</active-sessions><max-sessions>1000</max-sessions>" \
             "</flow-session-information>"


class SessionsDevice(FakeDevice):
    """Answers summaries and lists of get-flow-session-information separately."""

    def __init__(self, summary: Any, listing: Any = None, filtered_summary: Any = None) -> None:
        super().__init__("op")
        self.summary = summary
        self.filtered_summary = filtered_summary if filtered_summary is not None else summary
        self.listing = listing if listing is not None else xml(SESSION_REPLY)

    def rpc(self, name: str, **params: Any) -> Any:
        self.calls.append((name, params))
        if name != "get-flow-session-information":
            raise RpcDenied("not in this fake")
        answer = self.listing
        if params.get("summary"):
            answer = self.filtered_summary if len(params) > 1 else self.summary
        if isinstance(answer, BaseException):
            raise answer
        return answer


class SessionGuardTests(LiveHttpBase):
    """JUNO-1: the session-table guard fails closed when the match count is unknown."""

    def session_for(self, device: Any) -> str:
        token, _ = self.app.sessions.create(user="op", backend="fixture", device=device, source="t")
        return f"{COOKIE_PLAIN}={token}"

    def lists(self, device: SessionsDevice) -> List[Dict[str, Any]]:
        return [p for n, p in device.calls if n == "get-flow-session-information" and not p.get("summary")]

    def test_summary_timeout_sends_no_list(self) -> None:
        from jwicket.junos.errors import RpcTimeout

        device = SessionsDevice(RpcTimeout("RpcTimeoutError: timed out"))
        _, _, data = self.get("/api/sessions", self.session_for(device))
        self.assertEqual(data["sessions"]["status"], "count-unknown")
        self.assertEqual(data["sessions"]["rows"], [])
        self.assertIn("took too long", data["sessions"]["message"])
        self.assertIsNone(data["matching"])
        self.assertEqual(self.lists(device), [])

    def test_summary_without_a_count_sends_no_list(self) -> None:
        device = SessionsDevice(xml("<flow-session-information/>"))
        _, _, data = self.get("/api/sessions", self.session_for(device))
        self.assertEqual(data["sessions"]["status"], "count-unknown")
        self.assertEqual(self.lists(device), [])

    def test_filtered_summary_without_a_count_is_bounded_by_the_active_count(self) -> None:
        small = SessionsDevice(xml(SUMMARY_OK.format(n=40)), filtered_summary=xml("<flow-session-information/>"))
        _, _, data = self.get("/api/sessions?dport=443", self.session_for(small))
        self.assertEqual(data["sessions"]["status"], "ok")
        self.assertEqual(len(self.lists(small)), 1)
        big = SessionsDevice(xml(SUMMARY_OK.format(n=S.MAX_UNFILTERED + 1)),
                             filtered_summary=xml("<flow-session-information/>"))
        _, _, data = self.get("/api/sessions?dport=443", self.session_for(big))
        self.assertEqual(data["sessions"]["status"], "count-unknown")
        self.assertIn(f"{S.MAX_UNFILTERED + 1:,} sessions are active", data["sessions"]["message"])
        self.assertEqual(self.lists(big), [])

    def test_denied_or_unsupported_summary_is_that_state_without_a_list(self) -> None:
        from jwicket.junos.errors import RpcUnsupported

        cases = ((RpcDenied("permission denied"), "denied"), (RpcUnsupported("syntax error"), "unsupported"))
        for err, status in cases:
            with self.subTest(status=status):
                device = SessionsDevice(err)
                _, _, data = self.get("/api/sessions", self.session_for(device))
                self.assertEqual(data["sessions"]["status"], status)
                self.assertEqual(self.lists(device), [])

    def test_known_small_count_lists(self) -> None:
        device = SessionsDevice(xml(SUMMARY_OK.format(n=12)))
        _, _, data = self.get("/api/sessions", self.session_for(device))
        self.assertEqual((data["sessions"]["status"], data["matching"]), ("ok", 12))
        self.assertEqual(len(self.lists(device)), 1)

    def test_busy_device_session_is_429_not_a_queue(self) -> None:
        """SECU-2: a request waits only briefly for its operator's device session."""
        import jwicket.api as api_mod

        device = SessionsDevice(xml(SUMMARY_OK.format(n=12)))
        cookie = self.session_for(device)
        sess = next(s for s in self.app.sessions._sessions.values() if s.device is device)
        original = api_mod.SESSION_WAIT_S
        api_mod.SESSION_WAIT_S = 0.05
        sess.lock.acquire()
        try:
            for path in ("/api/sessions", "/api/inventory", "/api/logs/sources", "/api/logs?file=messages"):
                with self.subTest(path=path):
                    self.clock.now += 5
                    status, headers, data = self.get(path, cookie)
                    self.assertEqual(status, 429)
                    self.assertEqual(headers.get("retry-after"), "2")
                    self.assertIn("still running", data["error"])
        finally:
            sess.lock.release()
            api_mod.SESSION_WAIT_S = original
        self.assertEqual(device.calls, [])

    def test_repeated_polls_are_audited_once(self) -> None:
        """SECU-4: one read_sessions audit line per change of filters or outcome, not per poll."""
        records: List[Tuple[str, Dict[str, Any]]] = []

        class Spy(AuditTrail):
            def record(self, event: str, *, user: Optional[str], source: str, **fields: Any) -> None:
                records.append((event, fields))

        self.app.audit = Spy(None)
        for path in ("/api/sessions",) * 3 + ("/api/sessions?dport=53",) * 2 + ("/api/sessions",):
            self.clock.now += 2
            self.assertEqual(self.get(path)[0], 200)
        reads = [f["filters"] for e, f in records if e == "read_sessions"]
        self.assertEqual(reads, ["", "destination-port=53", ""])


class LogSourcesFailureTests(LiveHttpBase):
    """SECU-6, CONS-01, CONS-07: a failed sources read is cached and the log endpoints stay bounded."""

    def device(self, error: Exception) -> FakeDevice:
        sw = xml("<software-information><product-model>vsrx</product-model></software-information>")
        return FakeDevice("op", {"get-configuration": error, "get-software-information": sw})

    def cookie_for(self, device: Any) -> str:
        token, _ = self.app.sessions.create(user="op", backend="fixture", device=device, source="t")
        return f"{COOKIE_PLAIN}={token}"

    def config_reads(self, device: FakeDevice) -> int:
        return sum(1 for name, _ in device.calls if name == "get-configuration")

    def test_denied_sources_are_read_once_per_ttl(self) -> None:
        device = self.device(RpcDenied("permission denied"))
        cookie = self.cookie_for(device)
        for _ in range(20):
            status, _, data = self.get("/api/logs/sources", cookie)
            self.assertEqual((status, data["sources"]["status"]), (200, "denied"))
        statuses = [self.get("/api/logs?file=messages", cookie)[0] for _ in range(5)]
        self.assertEqual(statuses, [200, 429, 429, 429, 429])
        self.assertEqual(self.config_reads(device), 1)
        self.assertEqual(len(device.calls), 2)  # plus one software read for the model
        self.clock.now += 61
        self.assertEqual(self.get("/api/logs/sources", cookie)[2]["sources"]["status"], "denied")
        self.assertEqual(self.config_reads(device), 2)

    def test_other_failures_are_retried_sooner(self) -> None:
        from jwicket.junos.errors import RpcFailed

        device = self.device(RpcFailed("RpcError: boom"))
        cookie = self.cookie_for(device)
        for _ in range(3):
            self.assertEqual(self.get("/api/logs/sources", cookie)[2]["sources"]["status"], "failed")
        self.assertEqual(self.config_reads(device), 1)
        self.clock.now += 11
        self.get("/api/logs/sources", cookie)
        self.assertEqual(self.config_reads(device), 2)

    def test_bad_parameters_are_400_before_any_device_read(self) -> None:
        device = self.device(RpcDenied("permission denied"))
        cookie = self.cookie_for(device)
        for path in ("/api/logs?file=messages&cursor=garbage", "/api/logs?source=nonsense",
                     "/api/logs?file=..%2Fetc", "/api/logs?source=report&type=nope",
                     "/api/logs?source=report&expression=a%27b", "/api/logs?source=buffer&since=yesterday",
                     "/api/logs?file=messages&lines=many"):
            with self.subTest(path=path):
                self.assertEqual(self.get(path, cookie)[0], 400)
        self.assertEqual(device.calls, [])

    def test_a_bad_request_does_not_use_up_the_read_slot(self) -> None:
        self.assertEqual(self.get("/api/logs?file=messages&cursor=garbage")[0], 400)
        self.assertEqual(self.get("/api/logs?file=messages")[0], 200)


class ReportReleaseTests(LiveHttpBase):
    """JUNO-13: the in-detail report queries were introduced in 23.1R1; older releases are not asked."""

    def test_old_release_report_read_is_unsupported_without_an_rpc(self) -> None:
        sw = xml("<software-information><product-model>srx345</product-model><junos-version>22.4R3</junos-version>"
                 "</software-information>")
        cfg = xml("<configuration><security><log><mode>stream</mode><report/></log></security></configuration>")
        device = FakeDevice("op", {"get-configuration": cfg, "get-software-information": sw})
        token, _ = self.app.sessions.create(user="op", backend="fixture", device=device, source="t")
        cookie = f"{COOKIE_PLAIN}={token}"
        _, _, data = self.get("/api/logs/sources", cookie)
        report = next(d for d in data["sources"]["databases"] if d["id"] == "report")
        self.assertIs(report["supported"], False)
        status, _, data = self.get("/api/logs?source=report&type=session-all", cookie)
        self.assertEqual((status, data["log"]["status"]), (200, "unsupported"))
        self.assertIn("23.1R1", data["log"]["message"])
        self.assertFalse(any(name.startswith("get-sec-log-report") for name, _ in device.calls))


class MalformedReplyTests(LiveHttpBase):
    """CONS-02: a reply with no <configuration> is a failed panel, never HTTP 500."""

    def test_every_configuration_reader_reports_failed(self) -> None:
        sw = xml("<software-information><host-name>fw</host-name><product-model>vsrx</product-model>"
                 "</software-information>")
        device = FakeDevice("op", {"get-configuration": xml("<rpc-reply><ok/></rpc-reply>"),
                                   "get-software-information": sw})
        token, _ = self.app.sessions.create(user="op", backend="fixture", device=device, source="t")
        cookie = f"{COOKIE_PLAIN}={token}"
        status, _, data = self.get("/api/inventory", cookie)
        self.assertEqual(status, 200)
        self.assertEqual(data["config"]["status"], "failed")
        self.assertEqual(data["device"]["status"], "ok")  # the panels already read are kept
        status, _, data = self.get("/api/logs/sources", cookie)
        self.assertEqual((status, data["sources"]["status"]), (200, "failed"))
        self.clock.now += 2
        status, _, data = self.get("/api/logs?file=messages", cookie)
        self.assertEqual((status, data["log"]["status"]), (200, "failed"))


class ReportHttpTests(LiveHttpTests):
    """The cluster fixture streams traffic logs off-box and keeps an on-box report database."""

    fixture = "cluster-lsys"

    def test_sources_explain_stream_mode(self) -> None:
        _, _, data = self.get("/api/logs/sources")
        traffic = data["sources"]["traffic"]
        self.assertEqual((traffic["mode"], traffic["effective_mode"]), ("stream", "stream"))
        self.assertIn("192.0.2.50", traffic["where"])
        self.assertIn("report", [d["id"] for d in data["sources"]["databases"]])
        self.assertNotIn("buffer", [d["id"] for d in data["sources"]["databases"]])

    def test_report_read_and_validation(self) -> None:
        status, _, data = self.get("/api/logs?source=report&type=session-all&count=50")
        self.assertEqual(status, 200)
        self.assertEqual(len(data["log"]["lines"]), 3)
        self.assertTrue(data["log"]["lines"][0].startswith("<14>1 "))
        for bad in ("type=session-everything", "expression=" + "x" * 300, "expression=a%3Bb",
                    "start=yesterday", "count=lots"):
            with self.subTest(bad=bad):
                self.clock.now += 2
                self.assertEqual(self.get(f"/api/logs?source=report&{bad}")[0], 400)
        self.clock.now += 2
        ok = urlencode({"expression": "(source-address=10.30.1.0/24 && destination-port=443)"})
        self.assertEqual(self.get(f"/api/logs?source=report&{ok}")[0], 200)

    def test_first_report_read_asks_for_the_newest_records(self) -> None:
        """JUNO-7: without a start time, ``descending`` is sent and the lines come back in time order."""
        calls: List[Dict[str, Any]] = []
        sess = next(iter(self.app.sessions._sessions.values()))
        real_rpc = sess.device.rpc

        def spy(name: str, **params: Any) -> Any:
            if name.startswith("get-sec-log-report-detail-"):
                calls.append(params)
            return real_rpc(name, **params)

        sess.device.rpc = spy  # type: ignore[method-assign]
        _, _, first = self.get("/api/logs?source=report&type=session-all&count=50")
        self.assertEqual(calls[-1], {"count": "50", "descending": True})
        times = [ln.split()[1] for ln in first["log"]["lines"]]
        self.assertEqual(times, sorted(times))
        self.clock.now += 2
        _, _, later = self.get("/api/logs?source=report&type=session-all&start=2026-11-24T06:40:00")
        self.assertEqual(calls[-1], {"count": "500", "start_time": "2026-11-24T06:40:00"})
        self.assertEqual(later["log"]["lines"], first["log"]["lines"])

    # The branch-fixture tests below do not apply to this fixture.
    test_sessions_read_and_rate_limit = None  # type: ignore[assignment]
    test_sessions_pushdown_filters = None  # type: ignore[assignment]
    test_refusal_follows_the_matching_count = None  # type: ignore[assignment]
    test_filtered_read_keeps_the_table_wide_gauge = None  # type: ignore[assignment]
    test_log_sources_and_tail = None  # type: ignore[assignment]
    test_log_contains_filter_pushdown = None  # type: ignore[assignment]
    test_event_mode_buffer_source = None  # type: ignore[assignment]
    test_report_source_is_offered_only_when_configured = None  # type: ignore[assignment]


class ModeAndExpressionTests(unittest.TestCase):
    def test_default_modes(self) -> None:
        """JUNO-13: exact models, with the release exceptions the mode reference lists."""
        mode, basis = L.default_mode("vsrx")
        self.assertEqual(mode, "event")
        self.assertIn("stream in general", basis)  # the conflicting general statement is mentioned
        self.assertEqual(L.default_mode("srx345", "24.4R2-S3.5")[0], "stream")
        self.assertEqual(L.default_mode("srx550m", "18.3R3.8")[0], "stream")
        for version in ("18.3R2.7", "18.4R1.8", "18.4R2-S3", "19.1R3-S1", "19.2R1.8", "15.1X49-D170.4"):
            with self.subTest(version=version):
                self.assertEqual(L.default_mode("srx300", version)[0], "event")
        self.assertEqual(L.default_mode("srx340", "19.2R2")[0], "stream")
        self.assertIsNone(L.default_mode("srx345")[0])  # depends on the release, which is unknown
        self.assertEqual(L.default_mode("srx1500", "15.1X49-D130.1")[0], "event")
        self.assertEqual(L.default_mode("srx1500", "15.1X49-D140.2")[0], "stream")
        self.assertEqual(L.default_mode("srx1500", "22.4R3")[0], "stream")
        self.assertEqual(L.default_mode("srx1400")[0], "stream")
        self.assertEqual(L.default_mode("srx5800")[0], "stream")
        self.assertEqual(L.default_mode("srx240")[0], "event")
        self.assertEqual(L.default_mode("srx650")[0], "event")
        for model in ("srx380", "srx4600", "srx5", "srx3xx", None):
            with self.subTest(model=model):
                self.assertIsNone(L.default_mode(model, "24.4R1")[0])

    def test_release_parsing(self) -> None:
        self.assertEqual(L.release("24.4R2-S3.5"), (24, 4, 2))
        self.assertEqual(L.release("15.1X49-D140.2"), (15, 1, 0))
        self.assertIsNone(L.release(None))
        self.assertIsNone(L.release("unknown"))

    def test_expression_validation(self) -> None:
        self.assertEqual(L.parse_expression("(a=1 && b!=2) || c>=3"), "(a=1 && b!=2) || c>=3")
        for bad in ("x" * 257, "a=1; show", "a='1'", 'a="1"', "a=1\n"):
            with self.subTest(bad=bad), self.assertRaises(L.LogQueryError):
                L.parse_expression(bad)

    def test_buffer_events_shape(self) -> None:
        reply = xml(
            "<security-log-information><security-event><security-event-time>2026-11-24.06:00:01</security-event-time>"
            "<security-event-id>RT_FLOW_SESSION_DENY</security-event-id><security-event-message>session denied x"
            "</security-event-message><process><name>flowd</name><pid>12</pid></process></security-event>"
            "</security-log-information>"
        )
        got = L.buffer_events(reply)
        self.assertEqual(got["lines"], ["2026-11-24.06:00:01 flowd[12]: RT_FLOW_SESSION_DENY: session denied x"])
        self.assertFalse(got["disabled"])


class SnapshotVisibilityTests(unittest.TestCase):
    """Facts from the research: hidden configuration and undocumented cluster error text."""

    def snapshot(self, device: Any) -> Dict[str, Any]:
        from jwicket.api import read_snapshot

        app = App(
            backend=FixtureBackend(FIXTURES / "branch"),  # type: ignore[arg-type]
            sessions=SessionStore(idle_s=900, absolute_s=3600, max_sessions=4),
            throttle=LoginThrottle(per_name=5, per_source=5),
            audit=AuditTrail(None),
            session_idle_s=900,
        )
        _token, sess = app.sessions.create(user="viewer", backend="fixture", device=device, source="t")
        status, payload = read_snapshot(app, sess, "root")
        self.assertEqual(status, 200)
        return payload

    def device(self, config: str, cluster_error: Exception) -> Any:
        class Device:
            user = "viewer"
            backend = "fixture"

            def get_configuration(self, filter_xml: str) -> Any:
                return xml(config)

            def rpc(self, name: str, **params: Any) -> Any:
                if name == "get-chassis-cluster-status":
                    raise cluster_error
                return xml("<software-information><host-name>h</host-name></software-information>")

            def close(self) -> None:
                return None

        return Device()

    def test_missing_security_section_is_not_presented_as_empty(self) -> None:
        from jwicket.junos.errors import RpcUnsupported

        payload = self.snapshot(self.device("<configuration><applications/></configuration>", RpcUnsupported("x")))
        self.assertTrue(any("no security section" in w for w in payload["warnings"]), payload["warnings"])
        self.assertEqual(payload["ha"]["mode"], "standalone")

    def test_unexpected_cluster_error_reads_as_standalone_with_reason(self) -> None:
        from jwicket.junos.errors import RpcFailed

        payload = self.snapshot(self.device("<configuration><security/></configuration>", RpcFailed("weird text")))
        self.assertEqual(payload["ha"]["mode"], "standalone")
        self.assertIn("not available", payload["ha"]["message"])
        self.assertFalse(any("no security section" in w for w in payload["warnings"]))

    def test_denied_cluster_status_stays_denied(self) -> None:
        payload = self.snapshot(self.device("<configuration><security/></configuration>", RpcDenied("no")))
        self.assertEqual(payload["ha"]["status"], "denied")


def _rows(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = data["sessions"]["rows"]
    return rows


if __name__ == "__main__":
    unittest.main()
