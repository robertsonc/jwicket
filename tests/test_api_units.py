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
        self.assertEqual(payload["config"], {"status": "ok"})
        self.assertEqual([c[1] for c in dev.calls if c[0] == "get-configuration"],
                         [INVENTORY_FILTER, INVENTORY_FILTER_MINIMAL])
        self.assertTrue(any("rejected" in w for w in payload["warnings"]))
        self.assertEqual(payload["warnings"][0], "extra warning")


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
        self.assertIsNone(api.throttle_read(app, sess, "other-bucket", 2.0))
        clock.advance(1.5)
        self.assertIsNone(api.throttle_read(app, sess, "inventory", 2.0))


def req(headers: Dict[str, str], tls: bool = False, body: bytes = b"") -> H.Request:
    return H.Request(method="POST", path="/api/login", query={}, headers=headers, client="127.0.0.1", tls=tls,
                     body=body)


class RequestTests(unittest.TestCase):
    def test_cookie_names(self) -> None:
        self.assertEqual(req({}).cookie_name, "jwicket")
        self.assertEqual(req({}, tls=True).cookie_name, "__Host-jwicket")

    def test_cookie_parsing(self) -> None:
        self.assertEqual(req({"Cookie": "a=1; jwicket=tok; b=2"}).cookie(), "tok")
        self.assertIsNone(req({"Cookie": "jwicketx=1; xjwicket=2"}).cookie())
        self.assertIsNone(req({"Cookie": "jwicket="}).cookie())
        self.assertIsNone(req({}).cookie())
        self.assertIsNone(req({"Cookie": "jwicket=plain"}, tls=True).cookie())  # TLS uses the __Host- name
        self.assertEqual(req({"Cookie": "__Host-jwicket=t"}, tls=True).cookie(), "t")

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
