"""Unit tests below the HTTP layer: read_snapshot, CSV export, request/cookie helpers, router, assets."""

from __future__ import annotations

import csv
import io
import json
import unittest
from typing import Any, Dict, List

from helpers import BRANCH, FakeClock, FakeDevice, make_app, xml

from jwicket import api, resources
from jwicket.auth.sessions import WebSession
from jwicket.junos.errors import RpcDenied, RpcFailed, RpcTimeout, RpcUnsupported
from jwicket.junos.session import INVENTORY_FILTER, INVENTORY_FILTER_MINIMAL
from jwicket.web import http as H
from jwicket.web.server import Router

SW = xml("<software-information><host-name>fw1</host-name><product-model>srx345</product-model>"
         "<junos-version>24.4R2</junos-version></software-information>")
CFG = xml(
    "<configuration><security><policies><policy><from-zone-name>a</from-zone-name><to-zone-name>b</to-zone-name>"
    "<policy><name>p</name><match><source-address>any</source-address><destination-address>any</destination-address>"
    "<application>any</application></match><then><permit/></then></policy></policy></policies></security>"
    "<logical-systems><name>LS-1</name></logical-systems></configuration>"
)


class FilterAwareDevice(FakeDevice):
    """Rejects the full inventory filter, like a release without tenant systems."""

    def get_configuration(self, filter_xml: str) -> Any:
        self.calls.append(("get-configuration", filter_xml))
        if filter_xml == INVENTORY_FILTER:
            raise RpcUnsupported("syntax error: tenants")
        return CFG


class ReadSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        self.app = make_app(None, self.clock, warnings=["extra warning"])
        self.app.wall_clock = lambda: 1795500000.0

    def session(self, device: FakeDevice) -> WebSession:
        _token, sess = self.app.sessions.create(user=device.user, backend="netconf", device=device, source="127.0.0.1")
        return sess

    def snapshot(self, replies: Dict[str, Any], scope: str = "root") -> Any:
        dev = FakeDevice("alice", replies)
        status, payload = api.read_snapshot(self.app, self.session(dev), scope)
        return status, payload, dev

    def test_ok_snapshot(self) -> None:
        status, payload, dev = self.snapshot({"get-software-information": SW, "get-configuration": CFG,
                                              "get-chassis-cluster-status": RpcUnsupported("not enabled")})
        self.assertEqual(status, 200)
        self.assertEqual(payload["meta"]["read_at"], "2026-11-24T06:00:00Z")
        self.assertEqual(payload["meta"]["read_as"], {"user": "alice", "backend": "netconf"})
        self.assertEqual(payload["meta"]["fixture"], True)
        self.assertEqual([s["id"] for s in payload["meta"]["scopes"]], ["root", "lsys:LS-1"])
        self.assertEqual(payload["device"]["hostname"], "fw1")
        self.assertEqual(payload["ha"], {"status": "ok", "mode": "standalone"})
        self.assertEqual(payload["management"], {"status": "ok", "clients": [], "managed": False})
        self.assertEqual(payload["warnings"], ["extra warning"])
        self.assertEqual([c[0] for c in dev.calls],
                         ["get-software-information", "get-configuration", "get-chassis-cluster-status"])
        self.assertEqual(dev.calls[1][1], INVENTORY_FILTER)
        json.dumps(payload)  # JSON-ready

    def test_lsys_scope_and_unknown_scope(self) -> None:
        replies = {"get-software-information": SW, "get-configuration": CFG,
                   "get-chassis-cluster-status": RpcUnsupported("x")}
        status, payload, _ = self.snapshot(replies, "lsys:LS-1")
        self.assertEqual((status, payload["scope"]["id"]), (200, "lsys:LS-1"))
        status, payload, _ = self.snapshot(replies, "lsys:NOPE")
        self.assertEqual(status, 404)
        self.assertEqual([s["id"] for s in payload["scopes"]], ["root", "lsys:LS-1"])

    def test_mnha_detected_when_cluster_rpc_unsupported(self) -> None:
        cfg = xml("<configuration><chassis><high-availability><local-id>1</local-id></high-availability></chassis>"
                  "</configuration>")
        _, payload, _ = self.snapshot({"get-software-information": SW, "get-configuration": cfg,
                                       "get-chassis-cluster-status": RpcUnsupported("not enabled")})
        self.assertEqual(payload["ha"]["mode"], "mnha")

    def test_each_panel_fails_on_its_own(self) -> None:
        _, payload, _ = self.snapshot({"get-software-information": RpcDenied("no"),
                                       "get-configuration": RpcFailed("timeout"),
                                       "get-chassis-cluster-status": RpcTimeout("boom")})
        self.assertEqual(payload["device"]["status"], "denied")
        self.assertEqual(payload["config"]["status"], "failed")
        self.assertEqual(payload["ha"]["status"], "failed")
        self.assertTrue(all(payload[k]["message"] for k in ("device", "config", "ha")))
        self.assertIsNone(payload["scope"])
        self.assertEqual(payload["management"]["status"], "failed")
        self.assertNotIn("timeout", json.dumps(payload))  # internal text stays in the logs

    def test_reply_without_configuration_is_a_failed_panel(self) -> None:
        """CONS-02: a malformed reply is a failed configuration panel; the other panels are kept."""
        status, payload, _ = self.snapshot({"get-software-information": SW,
                                            "get-configuration": xml("<rpc-reply><ok/></rpc-reply>"),
                                            "get-chassis-cluster-status": RpcUnsupported("x")})
        self.assertEqual(status, 200)
        self.assertEqual(payload["config"]["status"], "failed")
        self.assertTrue(payload["config"]["message"])
        self.assertEqual(payload["device"]["hostname"], "fw1")
        self.assertEqual(payload["ha"]["mode"], "standalone")
        self.assertIsNone(payload["scope"])

    def test_device_error_text_goes_to_the_diagnostic_log_only(self) -> None:
        """CONS-05: the Junos wording is kept for the lab (INFO, truncated), never sent to the browser."""
        marker = "MARKER-DEVICE-TEXT"
        with self.assertLogs("jwicket.api", level="INFO") as logged:
            _, payload, _ = self.snapshot({"get-software-information": RpcDenied(f"error: {marker}"),
                                           "get-configuration": RpcFailed("x" * 2000),
                                           "get-chassis-cluster-status": RpcFailed(f"odd {marker}")})
        text = "\n".join(logged.output)
        self.assertIn(marker, text)
        self.assertNotIn("x" * (api.MAX_ERROR_TEXT + 1), text)
        self.assertNotIn(marker, json.dumps(payload))

    def test_denied_configuration(self) -> None:
        status, payload, _ = self.snapshot({"get-software-information": SW, "get-configuration": RpcDenied("x"),
                                            "get-chassis-cluster-status": RpcUnsupported("x")}, "lsys:ANY")
        self.assertEqual(status, 200)
        self.assertEqual(payload["config"]["status"], "denied")
        self.assertIsNone(payload["scope"])

    def test_filter_fallback_warning_reaches_the_snapshot(self) -> None:
        dev = FilterAwareDevice("alice", {"get-software-information": SW,
                                          "get-chassis-cluster-status": RpcUnsupported("x")})
        with self.assertLogs("jwicket.junos", level="WARNING"):
            status, payload = api.read_snapshot(self.app, self.session(dev), "root")
        self.assertEqual(status, 200)
        self.assertEqual(payload["config"], {"status": "ok", "filter": "minimal"})
        self.assertEqual([c[1] for c in dev.calls if c[0] == "get-configuration"],
                         [INVENTORY_FILTER, INVENTORY_FILTER_MINIMAL])
        self.assertTrue(any("rejected" in w for w in payload["warnings"]))
        self.assertEqual(payload["warnings"][0], "extra warning")
        # CRT-02: what the minimal filter does not read is "not read", never "not configured".
        self.assertEqual(payload["management"], {
            "status": "unsupported",
            "message": ("Central management was not read: the device rejected the configuration filter that "
                        "includes it."),
        })
        self.assertNotIn("managed", payload["management"])
        self.assertEqual(payload["ha"]["mode"], "standalone")
        self.assertEqual(payload["ha"]["message"],
                         "Multinode HA settings were not read (the device rejected the full configuration filter).")
        self.assertEqual(payload["clock"]["status"], "unsupported")
        self.assertEqual(payload["clock"]["message"],
                         "The time zone was not read: the device rejected the configuration filter that includes it.")

    def test_minimal_filter_note_follows_an_existing_ha_message(self) -> None:
        dev = FilterAwareDevice("alice", {"get-software-information": SW,
                                          "get-chassis-cluster-status": RpcFailed("odd reply")})
        with self.assertLogs("jwicket.junos", level="WARNING"):
            _status, payload = api.read_snapshot(self.app, self.session(dev), "root")
        message = payload["ha"]["message"]
        self.assertTrue(message.startswith("Chassis cluster status was not available ("), message)
        self.assertTrue(message.endswith(".). Multinode HA settings were not read (the device rejected the full "
                                         "configuration filter)."), message)

    def test_full_filter_reads_the_time_zone(self) -> None:
        cfg = xml("<configuration><system><time-zone>Europe/Paris</time-zone></system><security/></configuration>")
        _, payload, dev = self.snapshot({"get-software-information": SW, "get-configuration": cfg,
                                         "get-chassis-cluster-status": RpcUnsupported("x")})
        self.assertEqual(payload["config"], {"status": "ok", "filter": "full"})
        self.assertEqual(payload["clock"], {"status": "ok", "time_zone": "Europe/Paris", "configured": True,
                                            "deactivated": None, "source": "configuration"})
        self.assertIn("<time-zone/>", dev.calls[1][1])

    def test_no_security_section_keeps_the_root_warning(self) -> None:
        """OBJ-03: security_present false, and the snapshot still says why it may be empty."""
        cfg = xml("<configuration><applications/><logical-systems><name>LS-1</name></logical-systems></configuration>")
        _, payload, _ = self.snapshot({"get-software-information": SW, "get-configuration": cfg,
                                       "get-chassis-cluster-status": RpcUnsupported("x")})
        self.assertIs(payload["scope"]["security_present"], False)
        self.assertIs(payload["scope"]["applications_present"], True)
        self.assertTrue(any("no security section" in w for w in payload["warnings"]), payload["warnings"])
        _, lsys, _ = self.snapshot({"get-software-information": SW, "get-configuration": cfg,
                                    "get-chassis-cluster-status": RpcUnsupported("x")}, "lsys:LS-1")
        self.assertIs(lsys["scope"]["security_present"], False)

    def test_unaddressable_scope_names_are_listed_but_not_selectable(self) -> None:
        """CRT-13: a name _SCOPE cannot carry is listed, marked and warned about; _SCOPE is unchanged."""
        cfg = xml("<configuration><security/><logical-systems><name>LS A</name><security/></logical-systems>"
                  "<tenants><name>T-1</name></tenants></configuration>")
        _, payload, _ = self.snapshot({"get-software-information": SW, "get-configuration": cfg,
                                       "get-chassis-cluster-status": RpcUnsupported("x")})
        scopes = {s["id"]: s for s in payload["meta"]["scopes"]}
        self.assertEqual({k: v["selectable"] for k, v in scopes.items()},
                         {"root": True, "lsys:LS A": False, "tenant:T-1": True})
        self.assertEqual(scopes["lsys:LS A"]["reason"], "J-Wicket cannot address this name yet (it accepts letters, "
                                                        "digits, dot, underscore and hyphen, up to 63 characters).")
        self.assertNotIn("reason", scopes["root"])
        self.assertIn("Logical system LS A cannot be opened in J-Wicket: its name has characters J-Wicket does not "
                      "accept in a scope yet.", payload["warnings"])
        self.assertIsNone(api._SCOPE.match("lsys:LS A"))


def payload_with(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"meta": {"read_at": "2026-11-24T00:00:00Z", "read_as": {"user": "alice"}, "scope": "root"},
            "device": {"hostname": "fw"}, "scope": {"policies": {"rows": rows}}}


def row(**overrides: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "scope": "root", "kind": "zone", "seq": 1, "from": ["a"], "to": ["b"], "name": "p", "action": "permit",
        "match": {"source": ["any"], "destination": ["h1", "h2"], "application": ["junos-ssh"]},
        "inactive_reason": None, "group": None, "inherited": [], "log": {"init": False, "close": True},
        "count": False, "scheduler": None, "description": None,
    }
    base.update(overrides)
    return base


class CsvTests(unittest.TestCase):
    def test_csv_columns_and_branch_values(self) -> None:
        """POL-BE-05: 22 columns; the implicit application, dynamic applications and comments are exported."""
        from xml.etree import ElementTree

        from jwicket.junos.inventory import build_inventory

        ns = "http://xml.juniper.net/junos/24.4R2/junos"
        tree = ElementTree.parse(BRANCH / "config.xml").getroot()
        policies = next(e for e in tree.iter() if e.tag == "policies")
        pair = next(e for e in policies if e.tag == "policy")
        pair_note = ElementTree.Element(f"{{{ns}}}comment")
        pair_note.text = '=HYPERLINK("x") /* CHG-9 */'
        policies.insert(list(policies).index(pair), pair_note)
        rule_note = ElementTree.Element(f"{{{ns}}}comment")
        rule_note.text = "/* unified, owner web team */"
        unified = ElementTree.fromstring(
            f'<policy xmlns:junos="{ns}"><name>uni</name><match><source-address>any</source-address>'
            "<destination-address>any</destination-address><dynamic-application>junos:HTTP</dynamic-application>"
            "<dynamic-application>junos:SSL</dynamic-application></match>"
            "<junos:comment># before then</junos:comment><then><permit/></then></policy>"
        )
        pair.append(rule_note)
        pair.append(unified)
        inv = build_inventory(tree)
        payload = payload_with(inv["root"]["policies"]["rows"])
        table = list(csv.reader(io.StringIO(api._to_csv(payload).decode("utf-8"))))
        header = table[1]
        self.assertEqual(len(header), 22)
        self.assertEqual(header[:18], list(api._CSV_COLUMNS[:18]))
        self.assertEqual(header[18:], ["application_implicit", "dynamic_application", "comment", "pair_comment"])
        rows = {r[header.index("name")]: dict(zip(header, r)) for r in table[2:]}
        self.assertEqual(rows["uni"]["application_implicit"], "true")
        self.assertEqual(rows["uni"]["application"], "junos-defaults")
        self.assertEqual(rows["uni"]["dynamic_application"], "junos:HTTP junos:SSL")
        self.assertEqual(rows["uni"]["comment"], "/* unified, owner web team */ | before then: # before then")
        self.assertEqual(rows["allow-web"]["application_implicit"], "false")
        self.assertEqual((rows["allow-web"]["dynamic_application"], rows["allow-web"]["comment"]), ("", ""))
        # The pair comment starts with "=": neutralised like every cell.
        self.assertEqual(rows["baseline-dns"]["pair_comment"], "'=HYPERLINK(\"x\") /* CHG-9 */")
        self.assertEqual(rows["uni"]["pair_comment"], "'=HYPERLINK(\"x\") /* CHG-9 */")
        self.assertEqual(rows["admin-to-dmz"]["pair_comment"], "")
        for line in table:
            for cell in line:
                self.assertNotIn(cell[:1], ("=", "+", "-", "@", "\t", "\r"))

    def test_comment_cell(self) -> None:
        cases = (
            ({"comment": "/* on rule */", "part_comments": []}, "/* on rule */"),
            ({"comment": None, "part_comments": [{"before": "then", "text": "# a"}]}, "before then: # a"),
            ({"comment": "/* r */", "part_comments": [{"before": "then", "text": "# a"},
                                                       {"before": None, "text": "# z"}]},
             "/* r */ | before then: # a | at the end: # z"),
            ({"comment": None, "part_comments": []}, ""),
        )
        for row_, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(api._csv_comment(row_), expected)

    def test_formula_prefixes_are_neutralised(self) -> None:
        for value in ("=1+2", "+1", "-1", "@SUM(A1)", "\tx", "\rx", "=HYPERLINK(\"u\",\"t\")"):
            with self.subTest(value=value):
                self.assertEqual(api._csv_cell(value), "'" + value)
        for value, expected in (("safe", "safe"), (None, ""), (["a", "b"], "a b"), (3, "3"), (True, "True"),
                                (["=x", "y"], "'=x y"), ("a=b", "a=b")):
            with self.subTest(value=value):
                self.assertEqual(api._csv_cell(value), expected)

    def test_csv_layout(self) -> None:
        data = api._to_csv(payload_with([row(), row(name="q", description="=cmd", inactive_reason="zone-pair")]))
        self.assertTrue(data.endswith(b"\r\n"))
        table = list(csv.reader(io.StringIO(data.decode("utf-8"))))
        self.assertTrue(table[0][0].startswith("# J-Wicket policy inventory"))
        self.assertEqual(tuple(table[1]), api._CSV_COLUMNS)
        first = dict(zip(table[1], table[2]))
        self.assertEqual(first["destination"], "h1 h2")
        self.assertEqual(first["log_close"], "True")
        second = dict(zip(table[1], table[3]))
        self.assertEqual((second["description"], second["inactive"]), ("'=cmd", "zone-pair"))

    def test_csv_without_scope(self) -> None:
        payload = payload_with([])
        payload["scope"] = None
        payload["device"] = {"status": "denied"}
        table = list(csv.reader(io.StringIO(api._to_csv(payload).decode())))
        self.assertEqual(len(table), 2)
        self.assertIn("unknown", table[0][0])


class ReadThrottleTests(unittest.TestCase):
    def test_retry_after_rounds_up(self) -> None:
        clock = FakeClock()
        app = make_app(None, clock)
        _t, sess = app.sessions.create(user="a", backend="x", device=FakeDevice(), source="s")
        self.assertIsNone(api.throttle_read(app, sess, "inventory", 2.0))
        clock.advance(0.5)
        resp = api.throttle_read(app, sess, "inventory", 2.0)
        self.assertIsNotNone(resp)
        assert resp is not None
        self.assertEqual(resp.status, 429)
        self.assertIn(("Retry-After", "2"), resp.headers)
        self.assertEqual(json.loads(resp.body), {"error": "Reading too often.", "reason": "rate", "retry_after_s": 2,
                                                 "interval_s": 2.0})
        self.assertIsNone(api.throttle_read(app, sess, "other-bucket", 2.0))
        clock.advance(1.5)
        self.assertIsNone(api.throttle_read(app, sess, "inventory", 2.0))


class SignInRequiredTests(unittest.TestCase):
    """BE-02 (B-5): the 401 body says why, from the cookie's tombstone."""

    def test_wording_by_reason(self) -> None:
        app = make_app(None, FakeClock())
        cookie = {"Cookie": f"{H.COOKIE_PLAIN}=tok"}
        request = H.Request(method="GET", path="/api/inventory", query={}, headers=cookie, client="c", tls=False)
        self.assertEqual(api._ended_text(app, "idle"), "Your session ended after 15 min without activity.")
        self.assertEqual(api._ended_text(app, "absolute"), "Your session reached its 1 h limit.")
        app.sessions = api.SessionStore(idle_s=900, absolute_s=5400, max_sessions=2)
        self.assertEqual(api._ended_text(app, "absolute"), "Your session reached its 90 min limit.")
        self.assertEqual(json.loads(api.signin_required(app, request).body),
                         {"error": "Your J-Wicket session has ended.", "reason": "unknown"})
        bare = H.Request(method="GET", path="/", query={}, headers={}, client="c", tls=False)
        self.assertEqual(json.loads(api.signin_required(app, bare).body),
                         {"error": "sign-in required", "reason": "none"})

    def test_busy_body(self) -> None:
        self.assertEqual(json.loads(api.busy().body), {
            "error": "Another read for your session is still running. Try again shortly.", "reason": "busy",
            "retry_after_s": 2})


def req(headers: Dict[str, str], tls: bool = False, body: bytes = b"") -> H.Request:
    return H.Request(method="POST", path="/api/login", query={}, headers=headers, client="127.0.0.1", tls=tls,
                     body=body)


class RequestTests(unittest.TestCase):
    def test_cookie_names(self) -> None:
        """SECU-11: a per-daemon suffix, so two daemons behind two tunnels on 127.0.0.1 do not share a name."""
        self.assertRegex(H.INSTANCE_ID, r"^[0-9a-f]{8}$")
        self.assertEqual(req({}).cookie_name, f"jwicket-{H.INSTANCE_ID}")
        self.assertEqual(req({}, tls=True).cookie_name, f"__Host-jwicket-{H.INSTANCE_ID}")
        self.assertEqual((H.COOKIE_PLAIN, H.COOKIE_TLS), (req({}).cookie_name, req({}, tls=True).cookie_name))

    def test_cookie_parsing(self) -> None:
        plain, tls = H.COOKIE_PLAIN, H.COOKIE_TLS
        self.assertEqual(req({"Cookie": f"a=1; {plain}=tok; b=2"}).cookie(), "tok")
        self.assertIsNone(req({"Cookie": f"{plain}x=1; x{plain}=2"}).cookie())
        self.assertIsNone(req({"Cookie": f"{plain}="}).cookie())
        self.assertIsNone(req({}).cookie())
        # Another daemon's cookie (another tunnel, same 127.0.0.1) and the old fixed name are not ours.
        self.assertIsNone(req({"Cookie": "jwicket=tok; jwicket-0badc0de=tok2"}).cookie())
        self.assertIsNone(req({"Cookie": f"{plain}=plain"}, tls=True).cookie())  # TLS uses the __Host- name
        self.assertEqual(req({"Cookie": f"{tls}=t"}, tls=True).cookie(), "t")

    def test_same_origin(self) -> None:
        self.assertTrue(req({"Host": "127.0.0.1:8443", "Origin": "http://127.0.0.1:8443"}).same_origin())
        self.assertFalse(req({"Host": "127.0.0.1:8443", "Origin": "https://127.0.0.1:8443"}).same_origin())
        self.assertTrue(req({"Host": "fw:8443", "Origin": "https://fw:8443"}, tls=True).same_origin())
        self.assertFalse(req({"Host": "fw:8443"}).same_origin())
        self.assertFalse(req({"Origin": "http://fw:8443"}).same_origin())
        self.assertFalse(req({"Host": "fw:8443", "Origin": "http://evil:8443"}).same_origin())

    def test_json_body(self) -> None:
        self.assertEqual(req({"Content-Type": "application/json"}, body=b'{"a": 1}').json(), {"a": 1})
        self.assertEqual(req({"Content-Type": "Application/JSON; charset=utf-8"}, body=b"{}").json(), {})
        for headers, body in (({"Content-Type": "text/plain"}, b"{}"), ({}, b"{}"),
                              ({"Content-Type": "application/json"}, b"[]"),
                              ({"Content-Type": "application/json"}, b"nope")):
            with self.subTest(headers=headers, body=body), self.assertRaises(ValueError):
                req(headers, body=body).json()

    def test_cookies(self) -> None:
        plain = H.session_cookie("jwicket", "v", tls=False)
        self.assertEqual(plain, "jwicket=v; Path=/; HttpOnly; SameSite=Strict")
        secure = H.session_cookie("__Host-jwicket", "v", tls=True)
        self.assertIn("; Secure", secure)
        self.assertIn("Path=/", secure)
        self.assertNotIn("Domain", secure)  # __Host- prefix rules
        self.assertTrue(H.clear_cookie("jwicket", tls=False).endswith("; Max-Age=0"))
        self.assertTrue(H.clear_cookie("jwicket", tls=False).startswith("jwicket=;"))

    def test_parse_query(self) -> None:
        self.assertEqual(H.parse_query("scope=root&format=csv"), {"scope": "root", "format": "csv"})
        self.assertEqual(H.parse_query("scope=a&scope=b"), {"scope": "a"})
        self.assertEqual(H.parse_query("scope=&x=1"), {"x": "1"})
        self.assertEqual(H.parse_query(""), {})

    def test_response_json_is_ascii(self) -> None:
        resp = H.Response.json(200, {"name": "caf\u00e9 \u2028"})
        resp.body.decode("ascii")
        self.assertEqual(json.loads(resp.body), {"name": "caf\u00e9 \u2028"})
        err = H.Response.error(401, "msg", signed_out=True)
        self.assertEqual(json.loads(err.body), {"error": "msg", "signed_out": True})

    def test_csp_is_strict(self) -> None:
        for directive in ("default-src 'none'", "script-src 'self'", "style-src 'self'", "object-src 'none'",
                          "frame-ancestors 'none'", "base-uri 'none'", "require-trusted-types-for 'script'"):
            self.assertIn(directive, H.CSP)
        self.assertNotIn("unsafe", H.CSP)
        names = [n for n, _v in H.BASE_HEADERS]
        for name in ("Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Cache-Control"):
            self.assertIn(name, names)


class RouterTests(unittest.TestCase):
    def make(self) -> Router:
        router = Router()
        router.add("GET", "/a", lambda r: H.Response.json(200, {"route": "a"}))
        router.add("POST", "/a", lambda r: H.Response.json(200, {"route": "post-a"}))
        router.add("POST", "/b", lambda r: H.Response.json(200, {"route": "b"}))
        router.add_prefix("GET", "/static/", lambda r, rest: H.Response.json(200, {"rest": rest}))
        return router

    def dispatch(self, method: str, path: str) -> H.Response:
        return self.make().dispatch(H.Request(method=method, path=path, query={}, headers={}, client="c", tls=False))

    def test_exact_and_prefix(self) -> None:
        self.assertEqual(json.loads(self.dispatch("GET", "/a").body), {"route": "a"})
        self.assertEqual(json.loads(self.dispatch("POST", "/a").body), {"route": "post-a"})
        self.assertEqual(json.loads(self.dispatch("GET", "/static/x/y.js").body), {"rest": "x/y.js"})

    def test_405_lists_allowed_methods(self) -> None:
        resp = self.dispatch("GET", "/b")
        self.assertEqual(resp.status, 405)
        self.assertIn(("Allow", "POST"), resp.headers)
        self.assertIn(("Allow", "GET, POST"), self.dispatch("DELETE", "/a").headers)
        self.assertIn(("Allow", "GET"), self.dispatch("POST", "/static/app.js").headers)

    def test_404(self) -> None:
        self.assertEqual(self.dispatch("GET", "/c").status, 404)
        self.assertEqual(self.dispatch("GET", "/aa").status, 404)


class ResourceTests(unittest.TestCase):
    def setUp(self) -> None:
        resources.reset_cache()

    def test_allowlisted_assets(self) -> None:
        for name, ctype in (("index.html", "text/html"), ("js/main.js", "text/javascript"), ("css/app.css", "text/css"),
                            ("logo.svg", "image/svg+xml")):
            with self.subTest(name=name):
                found = resources.asset(name)
                self.assertIsNotNone(found)
                assert found is not None
                body, content_type, etag = found
                self.assertTrue(body)
                self.assertTrue(content_type.startswith(ctype))
                self.assertRegex(etag, r"^[0-9a-f]{16}$")

    def test_anything_else_is_refused(self) -> None:
        for name in ("../api.py", "/etc/passwd", "APP.JS", "app.py", "app.js/", "", ".app.js", "app.js\x00",
                     "static/app.js", "x" * 10 + ".exe", "../static/app.js", "app.js.map"):
            with self.subTest(name=name):
                self.assertIsNone(resources.asset(name))

    def test_manifest_only_matching_names(self) -> None:
        for key in resources.manifest():
            self.assertRegex(key, r"^[a-z0-9][a-z0-9_\-]*(/[a-z0-9][a-z0-9_\-]*)*\.(html|js|css|svg)$")


class FixtureBackendTests(unittest.TestCase):
    def test_fixture_backend_users(self) -> None:
        from jwicket.devserver import FixtureBackend
        from jwicket.junos.errors import LoginRejected

        backend = FixtureBackend(BRANCH)
        self.assertEqual(backend.users, ["admin", "auditor"])
        self.assertEqual(backend.authenticate("admin", "anything").user, "admin")
        with self.assertRaises(LoginRejected):
            backend.authenticate("mallory", "anything")
        with self.assertRaises(LoginRejected):
            backend.authenticate("admin", "")


if __name__ == "__main__":
    unittest.main()
