"""Spec 004: flow sessions and log tailing (adapters and HTTP endpoints)."""

from __future__ import annotations

import http.client
import json
import threading
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from xml.etree import ElementTree

from jwicket.api import App, build_router
from jwicket.auth.sessions import SessionStore
from jwicket.auth.throttle import LoginThrottle
from jwicket.devserver import FixtureBackend
from jwicket.junos import logs as L
from jwicket.junos import sessions as S
from jwicket.junos.errors import RpcDenied
from jwicket.logs import AuditTrail
from jwicket.web.server import JWicketServer

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
        self.assertEqual(got["device_count"], 3)

    def test_limit_truncates_and_says_so(self) -> None:
        got = S.parse_sessions(xml(CLUSTER_REPLY), 2)
        self.assertEqual((len(got["rows"]), got["returned"], got["truncated"]), (2, 3, True))

    def test_policy_without_index(self) -> None:
        self.assertEqual(S._split_policy("plain"), ("plain", None))
        self.assertEqual(S._split_policy("a/b/7"), ("a/b", "7"))

    def test_summary_sums_nodes(self) -> None:
        reply = xml(
            "<r><a><active-sessions>10</active-sessions><max-sessions>100</max-sessions></a>"
            "<b><active-sessions>5</active-sessions><max-sessions>100</max-sessions></b></r>"
        )
        self.assertEqual(S.parse_summary(reply)["active"], 15)


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


class LiveHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = Clock()
        backend = FixtureBackend(FIXTURES / "branch")
        self.app = App(
            backend=backend,  # type: ignore[arg-type]
            sessions=SessionStore(idle_s=900, absolute_s=3600, max_sessions=4, clock=self.clock),
            throttle=LoginThrottle(per_source=50, overall=50, clock=self.clock),
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

    def test_unfiltered_read_refused_on_large_tables(self) -> None:
        original = S.MAX_UNFILTERED
        S.MAX_UNFILTERED = 1
        try:
            status, _, data = self.get("/api/sessions")
            self.assertEqual(status, 200)
            self.assertEqual(data["sessions"]["status"], "refused")
            self.assertEqual(data["sessions"]["rows"], [])
            self.clock.now += 2
            status, _, data = self.get("/api/sessions?dport=443")
            self.assertEqual(data["sessions"]["status"], "ok")
        finally:
            S.MAX_UNFILTERED = original

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
        cookie = f"jwicket={token}"
        status, _, data = self.get("/api/logs/sources", cookie)
        self.assertEqual((status, data["sources"]["status"]), (200, "denied"))
        status, _, data = self.get("/api/logs?file=messages", cookie)
        self.assertEqual((status, data["log"]["status"], data["log"]["lines"]), (200, "denied", []))
        status, _, data = self.get("/api/sessions", cookie)
        self.assertEqual((data["summary"]["status"], data["sessions"]["status"]), ("denied", "denied"))


def _rows(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = data["sessions"]["rows"]
    return rows


if __name__ == "__main__":
    unittest.main()
