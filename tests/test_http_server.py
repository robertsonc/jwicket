"""HTTP integration: the real JWicketServer and API router on 127.0.0.1, fed from synthetic fixtures."""

from __future__ import annotations

import csv
import io
import logging
import re
import shutil
import socket
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional

from helpers import (
    BRANCH,
    BRANCH_SECRETS,
    CLUSTER,
    CSV_INJECTION,
    FakeClock,
    FakeDevice,
    LiveServer,
    Reply,
    StaticBackend,
    make_app,
    parse_raw_response,
    wait_until,
    xml,
)

from jwicket import resources
from jwicket.auth.backends import LabTokenBackend
from jwicket.auth.sessions import SessionStore
from jwicket.auth.throttle import LoginThrottle
from jwicket.devserver import FixtureBackend
from jwicket.fixtures import FixtureSession
from jwicket.junos.errors import LoginUnavailable, SessionLost
from jwicket.junos.session import PyEzUserSession
from jwicket.logs import AuditTrail
from jwicket.web.http import CSP

FIXTURE_WARNING = "Fixture data: synthetic, not read from a device."


def assert_security_headers(case: unittest.TestCase, reply: Reply, label: str = "") -> None:
    h = reply.headers
    case.assertEqual(h.get("content-security-policy"), CSP, label)
    case.assertEqual(h.get("x-content-type-options"), "nosniff", label)
    case.assertEqual(h.get("x-frame-options"), "DENY", label)
    case.assertEqual(h.get("cache-control"), "no-store", label)
    case.assertEqual(h.get("referrer-policy"), "no-referrer", label)
    case.assertNotIn("strict-transport-security", h, label)  # plain HTTP on loopback
    server = h.get("server", "")
    case.assertFalse(re.search(r"\d", server), f"{label}: Server header carries a version: {server!r}")
    case.assertNotIn("python", server.lower(), label)


class HttpCase(unittest.TestCase):
    fixture: Path = BRANCH
    server_options: ClassVar[Dict[str, Any]] = {}

    def setUp(self) -> None:
        resources.reset_cache()
        self.clock = FakeClock()
        self.backend = self.make_backend()
        self.app = make_app(self.backend, self.clock, warnings=[FIXTURE_WARNING])
        self.srv = LiveServer(self.app, **self.server_options)
        self.addCleanup(self.srv.stop)

    def make_backend(self) -> Any:
        return FixtureBackend(self.fixture)

    def signed_in(self, user: str = "admin") -> str:
        reply, cookie = self.srv.login(user)
        self.assertEqual(reply.status, 200, reply.body)
        self.assertTrue(cookie)
        return cookie

    def token_of(self, cookie: str) -> str:
        return cookie.split("=", 1)[1]

    def read(self, path: str, cookie: str) -> Reply:
        """A device read: move the fake clock past the per-operator read interval first."""
        self.clock.advance(5)
        return self.srv.get(path, cookie)


class SecurityHeaderTests(HttpCase):
    def test_headers_on_every_response_including_errors(self) -> None:
        cookie = self.signed_in()
        cases = [
            ("GET /", lambda: self.srv.get("/"), 200),
            ("GET /static/app.js", lambda: self.srv.get("/static/app.js"), 200),
            ("GET /healthz", lambda: self.srv.get("/healthz"), 200),
            ("GET /api/session", lambda: self.srv.get("/api/session"), 200),
            ("GET /api/inventory", lambda: self.read("/api/inventory", cookie), 200),
            ("401", lambda: self.srv.get("/api/inventory"), 401),
            ("403", lambda: self.srv.post_json("/api/login", {}, origin="http://evil.example"), 403),
            ("404", lambda: self.srv.get("/no/such/page"), 404),
            ("405 POST", lambda: self.srv.request("POST", "/api/inventory", body=b""), 405),
            ("405 PUT", lambda: self.srv.request("PUT", "/api/session"), 405),
            ("400 scope", lambda: self.srv.get("/api/inventory?scope=../etc", cookie), 400),
            ("429", lambda: self.srv.get("/api/inventory", cookie), 429),
        ]
        for label, call, status in cases:
            with self.subTest(label):
                reply = call()
                self.assertEqual(reply.status, status, reply.body)
                assert_security_headers(self, reply, label)
        host = self.srv.host.encode()
        for label, raw, status in (
            ("413", b"POST /api/login HTTP/1.1\r\nHost: " + host + b"\r\nContent-Length: 999999\r\n\r\n", 413),
            ("411", b"POST /api/login HTTP/1.1\r\nHost: " + host + b"\r\nTransfer-Encoding: chunked\r\n\r\n", 411),
            ("400 target", b"GET http://evil.example/ HTTP/1.1\r\nHost: " + host + b"\r\n\r\n", 400),
        ):
            with self.subTest(label):
                reply = parse_raw_response(self.srv.raw(raw))
                self.assertEqual(reply.status, status)
                assert_security_headers(self, reply, label)

    def test_stdlib_generated_errors_also_carry_security_headers(self) -> None:
        host = self.srv.host.encode()
        for label, raw in (
            ("unknown method", b"BREW / HTTP/1.1\r\nHost: " + host + b"\r\n\r\n"),
            ("malformed request line", b"GARBAGE\r\n\r\n"),
        ):
            with self.subTest(label):
                data = self.srv.raw(raw)
                # Python < 3.12 answers a one-word request line HTTP/0.9-style: body only, no headers.
                self.assertTrue(data.startswith(b"HTTP/"), f"response has no status line or headers: {data[:80]!r}")
                reply = parse_raw_response(data)
                self.assertGreaterEqual(reply.status, 400)
                assert_security_headers(self, reply, label)

    def test_too_many_query_fields_is_a_clean_400(self) -> None:
        errors: List[Any] = []
        self.srv.server.handle_error = lambda request, address: errors.append(address)  # type: ignore[method-assign]
        query = "&".join(f"k{i}=v" for i in range(30))
        data = self.srv.raw(f"GET /healthz?{query} HTTP/1.1\r\nHost: {self.srv.host}\r\n\r\n".encode())
        self.assertTrue(data, "the server closed the connection without any response")
        reply = parse_raw_response(data)
        self.assertEqual(reply.status, 400)
        assert_security_headers(self, reply)
        self.assertEqual(errors, [])

    def test_server_header_has_no_version(self) -> None:
        reply = self.srv.get("/healthz")
        self.assertEqual(reply.headers.get("server"), "jwicket")

    def test_healthz(self) -> None:
        reply = self.srv.get("/healthz")
        self.assertEqual((reply.status, reply.json()), (200, {"status": "ok"}))
        self.assertTrue(reply.headers["content-type"].startswith("application/json"))


class RoutingTests(HttpCase):
    def test_index_and_static_assets(self) -> None:
        index = self.srv.get("/")
        self.assertEqual(index.status, 200)
        self.assertEqual(index.headers["content-type"], "text/html; charset=utf-8")
        self.assertIn(b"/static/app.js", index.body)
        self.assertEqual(self.srv.get("/static/index.html").body, index.body)
        for name, ctype in (("app.js", "text/javascript"), ("app.css", "text/css"), ("logo.svg", "image/svg+xml")):
            with self.subTest(name=name):
                reply = self.srv.get(f"/static/{name}")
                self.assertEqual(reply.status, 200)
                self.assertTrue(reply.headers["content-type"].startswith(ctype))
                self.assertRegex(reply.headers.get("etag", ""), r'^"[0-9a-f]{16}"$')

    def test_unknown_and_non_allowlisted_paths_are_404(self) -> None:
        for path in (
            "/nope", "/api", "/api/nope", "/static", "/static/", "/static/nope.js", "/static/APP.JS",
            "/static/../src/jwicket/api.py", "/static/..%2f..%2fsettings.py", "/static/%2e%2e/api.py",
            "/static//etc/passwd", "/static/app.py", "/static/.hidden.js", "/static/app.js.map",
            "/static/app.js%00.css", "/staticapp.js", "/favicon.ico", "/index.html",
        ):
            with self.subTest(path=path):
                reply = self.srv.get(path)
                self.assertEqual(reply.status, 404, reply.body)
                self.assertEqual(reply.json(), {"error": "not found"})

    def test_wrong_method_is_405_with_allow(self) -> None:
        for method, path, allow in (
            ("POST", "/api/inventory", "GET"),
            ("POST", "/api/export", "GET"),
            ("POST", "/api/session", "GET"),
            ("GET", "/api/login", "POST"),
            ("GET", "/api/logout", "POST"),
            ("POST", "/healthz", "GET"),
            ("POST", "/", "GET"),
            ("POST", "/static/app.js", "GET"),
        ):
            with self.subTest(method=method, path=path):
                reply = self.srv.request(method, path, body=b"" if method == "POST" else None)
                self.assertEqual(reply.status, 405)
                self.assertEqual(reply.headers.get("allow"), allow)

    def test_put_delete_options_patch_head_are_405(self) -> None:
        for method in ("PUT", "DELETE", "OPTIONS", "PATCH", "HEAD", "TRACE"):
            with self.subTest(method=method):
                reply = self.srv.request(method, "/api/inventory")
                self.assertEqual(reply.status, 405)
                assert_security_headers(self, reply, method)


class LoginTests(HttpCase):
    def test_session_when_signed_out(self) -> None:
        body = self.srv.get("/api/session").json()
        self.assertEqual(body["authenticated"], False)
        self.assertEqual((body["credential"], body["backend"], body["fixture"]), ("password", "fixture", True))
        self.assertIn("version", body)
        self.assertNotIn("csrf", body)

    def test_api_requires_a_session_cookie(self) -> None:
        paths = ("/api/inventory", "/api/inventory?scope=root", "/api/export?format=json", "/api/export?format=csv")
        for path in paths:
            for cookie in (None, "jwicket=forged-token", "__Host-jwicket=forged"):
                with self.subTest(path=path, cookie=cookie):
                    reply = self.srv.get(path, cookie)
                    self.assertEqual(reply.status, 401)
                    self.assertIn("error", reply.json())

    def test_login_requires_same_origin(self) -> None:
        port = self.srv.port
        for origin in (None, "http://evil.example", f"https://127.0.0.1:{port}", f"http://127.0.0.1:{port + 1}",
                       "null", f"http://127.0.0.1:{port}/", f"http://localhost:{port}", ""):
            with self.subTest(origin=origin):
                if origin == "":
                    reply = self.srv.request("POST", "/api/login", body=b'{"username":"admin","password":"x"}',
                                             headers={"Content-Type": "application/json", "Origin": ""})
                else:
                    reply = self.srv.post_json("/api/login", {"username": "admin", "password": "x"}, origin=origin)
                self.assertEqual(reply.status, 403)
                self.assertNotIn("set-cookie", reply.headers)
        self.assertEqual(self.app.sessions.count(), 0)

    def test_wrong_content_type_or_body_is_400(self) -> None:
        good = {"username": "admin", "password": "x"}
        for ctype in ("text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x",
                      "application/jsonx", ""):
            with self.subTest(ctype=ctype):
                self.assertEqual(self.srv.post_json("/api/login", good, content_type=ctype).status, 400)
        for raw in (b"not json", b"[1, 2]", b'"admin"', b"\xff\xfe{}", b""):
            with self.subTest(raw=raw):
                self.assertEqual(self.srv.post_json("/api/login", raw).status, 400)
        self.assertEqual(self.app.sessions.count(), 0)

    def test_json_content_type_with_charset_is_accepted(self) -> None:
        reply = self.srv.post_json("/api/login", {"username": "admin", "password": "x"},
                                   content_type="application/json; charset=utf-8")
        self.assertEqual(reply.status, 200)

    def test_bad_credentials_are_401(self) -> None:
        for user, password in (("mallory", "x"), ("bob smith", "x"), ("admin", ""), ("a" * 100, "x")):
            with self.subTest(user=user[:12], password=password):
                reply = self.srv.post_json("/api/login", {"username": user, "password": password})
                self.assertEqual(reply.status, 401)
                self.assertIn("error", reply.json())
                self.assertNotIn("set-cookie", reply.headers)

    def test_login_sets_a_strict_session_cookie(self) -> None:
        reply, cookie = self.srv.login("admin")
        self.assertEqual(reply.status, 200)
        body = reply.json()
        self.assertEqual((body["authenticated"], body["user"], body["backend"]), (True, "admin", "fixture"))
        self.assertTrue(body["csrf"])
        set_cookie = reply.all("set-cookie")
        self.assertEqual(len(set_cookie), 1)
        name, _, rest = set_cookie[0].partition("=")
        self.assertEqual(name, "jwicket")
        attrs = [a.strip() for a in rest.split(";")]
        token = attrs[0]
        self.assertGreaterEqual(len(token), 40)
        flags = {a.split("=", 1)[0].lower(): a for a in attrs[1:]}
        self.assertIn("httponly", flags)
        self.assertEqual(flags.get("samesite"), "SameSite=Strict")
        self.assertEqual(flags.get("path"), "Path=/")
        self.assertNotIn("secure", flags)  # plain HTTP on loopback; Secure would make the cookie unusable
        self.assertNotIn("domain", flags)
        self.assertNotIn(token.encode(), reply.body)

    def test_signed_in_session_endpoint(self) -> None:
        reply, cookie = self.srv.login("admin")
        csrf = reply.json()["csrf"]
        body = self.srv.get("/api/session", cookie).json()
        self.assertEqual((body["authenticated"], body["user"], body["csrf"]), (True, "admin", csrf))
        self.assertEqual(body["idle_timeout_s"], 900)

    def test_new_login_replaces_the_old_session(self) -> None:
        first = self.signed_in()
        old = self.app.sessions.get(self.token_of(first))
        self.assertIsNotNone(old)
        reply, second = self.srv.login("admin", cookie=first)
        self.assertEqual(reply.status, 200)
        self.assertNotEqual(first, second)
        self.assertFalse(self.srv.get("/api/session", first).json()["authenticated"])
        self.assertTrue(self.srv.get("/api/session", second).json()["authenticated"])
        self.assertTrue(old.device.closed)  # type: ignore[union-attr]
        self.assertEqual(self.app.sessions.count(), 1)

    def test_planted_cookie_is_never_adopted(self) -> None:
        planted = "jwicket=attacker-chosen-value-0123456789abcdefghijklmnop"
        reply, cookie = self.srv.login("admin", cookie=planted)
        self.assertEqual(reply.status, 200)
        self.assertNotEqual(cookie, planted)
        self.assertFalse(self.srv.get("/api/session", planted).json()["authenticated"])

    def test_logout_needs_origin_and_csrf_and_clears_the_cookie(self) -> None:
        reply, cookie = self.srv.login("admin")
        csrf = reply.json()["csrf"]
        sess = self.app.sessions.get(self.token_of(cookie))
        for label, origin, extra in (
            ("no csrf", "", {}),
            ("wrong csrf", "", {"X-CSRF-Token": "wrong"}),
            ("empty csrf", "", {"X-CSRF-Token": ""}),
            ("no origin", None, {"X-CSRF-Token": csrf}),
            ("cross origin", "http://evil.example", {"X-CSRF-Token": csrf}),
        ):
            with self.subTest(label):
                out = self.srv.post_json("/api/logout", {}, origin=origin, cookie=cookie, extra=extra)
                self.assertEqual(out.status, 403)
                self.assertTrue(self.srv.get("/api/session", cookie).json()["authenticated"])
        out = self.srv.post_json("/api/logout", {}, cookie=cookie, extra={"X-CSRF-Token": csrf})
        self.assertEqual(out.status, 200)
        self.assertEqual(out.json(), {"authenticated": False})
        cleared = out.headers.get("set-cookie", "")
        self.assertTrue(cleared.startswith("jwicket=;"), cleared)
        self.assertIn("Max-Age=0", cleared)
        self.assertFalse(self.srv.get("/api/session", cookie).json()["authenticated"])
        self.assertTrue(sess.device.closed)  # type: ignore[union-attr]
        self.assertEqual(self.app.sessions.count(), 0)

    def test_logout_without_a_session(self) -> None:
        out = self.srv.post_json("/api/logout", {})
        self.assertEqual(out.status, 200)
        self.assertIn("Max-Age=0", out.headers.get("set-cookie", ""))

    def test_login_is_throttled_with_retry_after(self) -> None:
        self.app.throttle = LoginThrottle(per_source=2, overall=100, clock=self.clock)
        self.assertEqual(self.srv.post_json("/api/login", {"username": "mallory", "password": "x"}).status, 401)
        self.assertEqual(self.srv.post_json("/api/login", {"username": "mallory", "password": "x"}).status, 401)
        reply = self.srv.post_json("/api/login", {"username": "admin", "password": "x"})
        self.assertEqual(reply.status, 429)
        self.assertGreaterEqual(int(reply.headers["retry-after"]), 1)
        self.assertIn("error", reply.json())
        self.clock.advance(61)
        self.assertEqual(self.srv.login("admin")[0].status, 200)

    def test_audit_trail_never_holds_credentials(self) -> None:
        audit_dir = Path(tempfile.mkdtemp(prefix="jwicket-http-audit-"))
        self.addCleanup(shutil.rmtree, audit_dir, True)
        logger = logging.getLogger("jwicket.audit")
        before, propagate = list(logger.handlers), logger.propagate

        def restore() -> None:
            for handler in list(logger.handlers):
                if handler not in before:
                    logger.removeHandler(handler)
                    handler.close()
            logger.propagate = propagate

        self.addCleanup(restore)
        self.app.audit = AuditTrail(audit_dir / "audit.log")
        password = "pw-that-must-not-be-logged"
        reply, cookie = self.srv.login("admin", password=password)
        csrf = reply.json()["csrf"]
        self.read("/api/inventory", cookie)
        self.srv.post_json("/api/login", {"username": "mallory", "password": password})
        self.srv.post_json("/api/logout", {}, cookie=cookie, extra={"X-CSRF-Token": csrf})
        text = (audit_dir / "audit.log").read_text(encoding="utf-8")
        for value in (password, self.token_of(cookie), csrf):
            self.assertNotIn(value, text)
        events = [line for line in text.splitlines() if line]
        self.assertTrue(any('"event": "login"' in e for e in events))
        self.assertTrue(any('"event": "read_inventory"' in e for e in events))
        self.assertTrue(any('"event": "login_failed"' in e for e in events))
        self.assertTrue(any('"event": "logout"' in e for e in events))


class InventoryTests(HttpCase):
    def test_inventory_snapshot_shape(self) -> None:
        cookie = self.signed_in()
        reply = self.read("/api/inventory", cookie)
        self.assertEqual(reply.status, 200)
        data = reply.json()
        meta = data["meta"]
        self.assertEqual(meta["schema"], "jwicket.inventory/1")
        self.assertEqual(meta["scope"], "root")
        self.assertEqual(meta["read_as"], {"user": "admin", "backend": "fixture"})
        self.assertIs(meta["fixture"], True)
        self.assertEqual(meta["source"], {"database": "committed", "inheritance": True, "groups_annotated": True})
        self.assertRegex(meta["read_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertTrue(meta["generator"].startswith("jwicket "))
        self.assertEqual(meta["scopes"], [{"id": "root", "label": "Root system", "policies": 10, "inactive": False}])
        self.assertEqual(data["device"]["hostname"], "branch-fw-01")
        self.assertEqual(data["device"]["status"], "ok")
        self.assertEqual(data["ha"], {"status": "ok", "mode": "standalone"})
        self.assertTrue(data["management"]["managed"])
        self.assertEqual(data["management"]["clients"][0]["client"], "central-mgr")
        self.assertEqual(data["config"], {"status": "ok"})
        self.assertEqual(data["scope"]["id"], "root")
        self.assertEqual(len(data["scope"]["policies"]["rows"]), 10)
        self.assertIn(FIXTURE_WARNING, data["warnings"])

    def test_no_secret_in_any_response(self) -> None:
        cookie = self.signed_in()
        bodies = [self.read(path, cookie).body for path in
                  ("/api/inventory", "/api/export?format=json", "/api/export?format=csv")]
        for body in bodies:
            for value in BRANCH_SECRETS:
                self.assertNotIn(value.encode(), body)

    def test_auditor_is_denied_the_configuration(self) -> None:
        cookie = self.signed_in("auditor")
        reply = self.read("/api/inventory", cookie)
        self.assertEqual(reply.status, 200)
        data = reply.json()
        self.assertEqual(data["config"]["status"], "denied")
        self.assertTrue(data["config"]["message"])
        self.assertIsNone(data["scope"])
        self.assertEqual(data["meta"]["scopes"], [])
        self.assertEqual(data["meta"]["read_as"]["user"], "auditor")
        self.assertNotIn(b'"rows"', reply.body)
        self.assertNotIn(b"allow-web", reply.body)
        csv_reply = self.read("/api/export?format=csv", cookie)
        self.assertEqual(csv_reply.status, 200)
        self.assertEqual(len(list(csv.reader(io.StringIO(csv_reply.body.decode())))), 2)  # title and header only

    def test_reading_again_within_two_seconds_is_429(self) -> None:
        cookie = self.signed_in()
        self.assertEqual(self.read("/api/inventory", cookie).status, 200)
        reply = self.srv.get("/api/inventory", cookie)
        self.assertEqual(reply.status, 429)
        self.assertEqual(reply.headers.get("retry-after"), "2")
        self.assertEqual(reply.json()["retry_after_s"], 2)
        self.clock.advance(1)
        reply = self.srv.get("/api/inventory", cookie)
        self.assertEqual((reply.status, reply.headers.get("retry-after")), (429, "1"))
        self.clock.advance(1)
        self.assertEqual(self.srv.get("/api/inventory", cookie).status, 200)

    def test_rate_limit_is_per_operator(self) -> None:
        a = self.signed_in()
        b = self.signed_in("auditor")
        self.assertEqual(self.read("/api/inventory", a).status, 200)
        self.assertEqual(self.srv.get("/api/inventory", b).status, 200)

    def test_unknown_scope_is_404_with_scopes(self) -> None:
        cookie = self.signed_in()
        for scope in ("lsys:NOPE", "tenant:T-1"):
            with self.subTest(scope=scope):
                reply = self.read(f"/api/inventory?scope={scope}", cookie)
                self.assertEqual(reply.status, 404)
                self.assertEqual([s["id"] for s in reply.json()["scopes"]], ["root"])

    def test_malformed_scope_is_400(self) -> None:
        cookie = self.signed_in()
        for scope in ("../etc", "lsys:", "tenant:", "lsys:a%20b", "LSYS:x", "root;x", "root%00", "lsys:" + "a" * 64,
                      "lsys:a/b", "global", "%27or%201=1"):
            with self.subTest(scope=scope):
                self.assertEqual(self.srv.get(f"/api/inventory?scope={scope}", cookie).status, 400)

    def test_scope_with_trailing_newline_is_malformed(self) -> None:
        cookie = self.signed_in()
        self.assertEqual(self.read("/api/inventory?scope=root%0A", cookie).status, 400)

    def test_export_json_is_an_attachment(self) -> None:
        cookie = self.signed_in()
        reply = self.read("/api/export?format=json", cookie)
        self.assertEqual(reply.status, 200)
        self.assertRegex(reply.headers["content-disposition"],
                         r'^attachment; filename="jwicket-branch-fw-01-root-\d{8}T\d{6}Z\.json"$')
        self.assertTrue(reply.headers["content-type"].startswith("application/json"))
        data = reply.json()
        self.assertEqual(data["meta"]["schema"], "jwicket.inventory/1")
        self.assertEqual(len(data["scope"]["policies"]["rows"]), 10)

    def test_export_csv(self) -> None:
        cookie = self.signed_in()
        reply = self.read("/api/export?format=csv", cookie)
        self.assertEqual(reply.status, 200)
        self.assertEqual(reply.headers["content-type"], "text/csv; charset=utf-8")
        self.assertRegex(reply.headers["content-disposition"],
                         r'^attachment; filename="jwicket-branch-fw-01-root-\d{8}T\d{6}Z\.csv"$')
        table = list(csv.reader(io.StringIO(reply.body.decode("utf-8"))))
        self.assertEqual(len(table[0]), 1)
        self.assertTrue(table[0][0].startswith("# J-Wicket policy inventory"))
        self.assertIn("branch-fw-01", table[0][0])
        self.assertIn("as admin", table[0][0])
        header = table[1]
        self.assertEqual(header[:6], ["scope", "kind", "seq", "from", "to", "name"])
        self.assertEqual(len(table), 2 + 10)
        rows = [dict(zip(header, r)) for r in table[2:]]
        self.assertEqual([r["name"] for r in rows][:3], ["baseline-dns", "allow-web", "block-telnet"])
        telnet = rows[2]
        self.assertEqual((telnet["inactive"], telnet["action"]), ("policy", "deny"))
        admin = next(r for r in rows if r["name"] == "admin-to-dmz")
        self.assertEqual(admin["destination"], "dmz-all dmz-jump")
        self.assertEqual(rows[0]["group"], "corp-baseline")

    def test_export_bad_format_and_sign_in(self) -> None:
        cookie = self.signed_in()
        self.assertEqual(self.srv.get("/api/export?format=xml", cookie).status, 400)
        self.assertEqual(self.srv.get("/api/export?format=csv").status, 401)

    def test_export_is_rate_limited(self) -> None:
        cookie = self.signed_in()
        self.assertEqual(self.read("/api/export?format=json", cookie).status, 200)
        self.assertEqual(self.srv.get("/api/export?format=csv", cookie).status, 429)

    def test_export_right_after_loading_the_page_is_allowed(self) -> None:
        # Export has its own read bucket: loading the inventory and then exporting it is normal use.
        cookie = self.signed_in()
        self.assertEqual(self.read("/api/inventory", cookie).status, 200)
        self.assertEqual(self.srv.get("/api/export?format=csv", cookie).status, 200)


class CsvInjectionTests(HttpCase):
    fixture = CSV_INJECTION

    def test_formula_cells_are_neutralised(self) -> None:
        cookie = self.signed_in()
        reply = self.read("/api/export?format=csv", cookie)
        self.assertEqual(reply.status, 200)
        table = list(csv.reader(io.StringIO(reply.body.decode("utf-8"))))
        header = table[1]
        rows = {r[header.index("name")]: dict(zip(header, r)) for r in table[2:]}
        self.assertEqual(rows["formula-desc"]["description"], "'=1+2")
        self.assertEqual(rows["plus-desc"]["description"], "'+SUM(A1:A9)")
        self.assertEqual(rows["plus-desc"]["scheduler"], "'@sched")
        self.assertEqual(rows["minus-desc"]["description"], "'-2+3")
        self.assertEqual(rows["minus-desc"]["group"], "'=grp")
        self.assertTrue(rows["at-desc"]["description"].startswith("'@cmd"))
        self.assertEqual(rows["plain-desc"]["description"], "An ordinary description, with a comma")
        for line in table:
            for cell in line:
                with self.subTest(cell=cell):
                    self.assertNotIn(cell[:1], ("=", "+", "-", "@", "\t", "\r"))

    def test_filename_is_sanitised(self) -> None:
        cookie = self.signed_in()
        reply = self.read("/api/export?format=csv", cookie)
        disposition = reply.headers["content-disposition"]
        self.assertRegex(disposition, r'^attachment; filename="jwicket-[A-Za-z0-9._\-]+-root-\d{8}T\d{6}Z\.csv"$')
        self.assertEqual(disposition.count('"'), 2)

    def test_json_export_keeps_the_real_value(self) -> None:
        cookie = self.signed_in()
        data = self.read("/api/export?format=json", cookie).json()
        descs = {r["name"]: r["description"] for r in data["scope"]["policies"]["rows"]}
        self.assertEqual(descs["formula-desc"], "=1+2")


class ClusterHttpTests(HttpCase):
    fixture = CLUSTER

    def test_cluster_scopes_and_ha(self) -> None:
        cookie = self.signed_in()
        data = self.read("/api/inventory", cookie).json()
        self.assertEqual(data["ha"]["mode"], "chassis-cluster")
        self.assertEqual(len(data["ha"]["redundancy_groups"]), 2)
        self.assertEqual(len(data["device"]["nodes"]), 2)
        self.assertFalse(data["management"]["managed"])
        scopes = {s["id"]: s for s in data["meta"]["scopes"]}
        self.assertEqual(list(scopes), ["root", "lsys:LS-A", "tenant:T-1"])
        self.assertTrue(scopes["tenant:T-1"]["inactive"])
        lsys = self.read("/api/inventory?scope=lsys:LS-A", cookie).json()
        self.assertEqual(lsys["scope"]["id"], "lsys:LS-A")
        self.assertEqual([r["name"] for r in lsys["scope"]["policies"]["rows"]], ["a-out"])
        tenant = self.read("/api/inventory?scope=tenant:T-1", cookie).json()
        self.assertTrue(tenant["scope"]["inactive"])
        self.assertTrue(tenant["scope"]["warnings"])
        export = self.read("/api/export?scope=lsys:LS-A&format=csv", cookie)
        self.assertIn("-lsys_LS-A-", export.headers["content-disposition"])


class LostSessionBackendDevice:
    """A PyEZ-like device whose transport has gone: every RPC raises ConnectClosedError."""

    class _Rpc:
        def __getattr__(self, name: str) -> Any:
            def call(**_kw: Any) -> Any:
                raise type("ConnectClosedError", (Exception,), {})("transport closed")

            return call

    def __init__(self) -> None:
        self.rpc = self._Rpc()
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1


class SessionLostTests(HttpCase):
    def make_backend(self) -> Any:
        return StaticBackend(lambda user: PyEzUserSession(LostSessionBackendDevice(), user))

    def test_lost_device_session_signs_the_operator_out(self) -> None:
        cookie = self.signed_in("alice")
        for path in ("/api/inventory", "/api/export?format=csv"):
            with self.subTest(path=path):
                if path != "/api/inventory":
                    cookie = self.signed_in("alice")
                reply = self.read(path, cookie)
                self.assertEqual(reply.status, 401)
                body = reply.json()
                self.assertIs(body.get("signed_out"), True)
                self.assertTrue(body["error"])
                self.assertFalse(self.srv.get("/api/session", cookie).json()["authenticated"])
                self.assertEqual(self.app.sessions.count(), 0)

    def test_session_lost_mid_snapshot_closes_the_device_session(self) -> None:
        sw = xml("<software-information><host-name>fw</host-name></software-information>")
        device = FakeDevice("bob", {"get-software-information": sw, "get-configuration": SessionLost("gone")})
        self.app.backend = StaticBackend(lambda user: device)
        cookie = self.signed_in("bob")
        reply = self.read("/api/inventory", cookie)
        self.assertEqual(reply.status, 401)
        self.assertIs(reply.json().get("signed_out"), True)
        self.assertEqual(device.closed, 1)
        self.assertEqual(self.app.sessions.count(), 0)


class CapacityTests(HttpCase):
    def make_backend(self) -> Any:
        self.devices: List[FakeDevice] = []

        def factory(user: str) -> FakeDevice:
            dev = FakeDevice(user)
            self.devices.append(dev)
            return dev

        return StaticBackend(factory)

    def test_session_cap_is_503_and_closes_the_new_device_session(self) -> None:
        self.app.sessions = SessionStore(idle_s=900, absolute_s=3600, max_sessions=1, clock=self.clock)
        self.assertEqual(self.srv.login("alice")[0].status, 200)
        reply = self.srv.post_json("/api/login", {"username": "bob", "password": "x"})
        self.assertEqual(reply.status, 503)
        self.assertNotIn("set-cookie", reply.headers)
        self.assertEqual([d.closed for d in self.devices], [0, 1])

    def test_device_service_unreachable_is_503(self) -> None:
        def factory(_user: str) -> Any:
            raise LoginUnavailable("connection refused on 127.0.0.1:830")

        self.app.backend = StaticBackend(factory)
        reply = self.srv.post_json("/api/login", {"username": "alice", "password": "x"})
        self.assertEqual(reply.status, 503)
        self.assertNotIn("127.0.0.1:830", reply.json()["error"])  # operator-safe message only


class LabTokenHttpTests(HttpCase):
    TOKEN = "lab-token-" + "0123456789" * 4

    def make_backend(self) -> Any:
        return LabTokenBackend(token=self.TOKEN.encode(), timeout_s=5, account="jwicket-svc",
                               factory=lambda account, _t: FixtureSession(BRANCH, account))

    def test_token_sign_in(self) -> None:
        body = self.srv.get("/api/session").json()
        self.assertEqual((body["credential"], body["backend"]), ("token", "lab-token"))
        self.assertEqual(self.srv.post_json("/api/login", {"token": "wrong"}).status, 401)
        reply = self.srv.post_json("/api/login", {"token": self.TOKEN})
        self.assertEqual(reply.status, 200)
        self.assertEqual((reply.json()["user"], reply.json()["backend"]), ("jwicket-svc", "lab-token"))
        cookie = reply.headers["set-cookie"].split(";", 1)[0]
        data = self.read("/api/inventory", cookie).json()
        self.assertEqual(data["meta"]["read_as"], {"user": "jwicket-svc", "backend": "lab-token"})


class BodyAndHostTests(HttpCase):
    server_options: ClassVar[Dict[str, Any]] = {"max_body_bytes": 1024}

    def test_body_over_the_limit_is_413(self) -> None:
        head = f"POST /api/login HTTP/1.1\r\nHost: {self.srv.host}\r\nOrigin: {self.srv.origin}\r\n" \
               "Content-Type: application/json\r\n"
        for length in ("1025", "999999999", "-1"):
            with self.subTest(length=length):
                reply = parse_raw_response(self.srv.raw(f"{head}Content-Length: {length}\r\n\r\n".encode()))
                self.assertEqual(reply.status, 413)
        reply = parse_raw_response(self.srv.raw(f"{head}Content-Length: ten\r\n\r\n".encode()))
        self.assertEqual(reply.status, 400)

    def test_body_at_the_limit_is_read(self) -> None:
        body = b'{"username": "mallory", "password": "x"}'
        body += b" " * (1024 - len(body))
        reply = self.srv.post_json("/api/login", body)
        self.assertEqual(reply.status, 401)  # parsed and rejected on its merits, not on size

    def test_chunked_body_is_411(self) -> None:
        raw = (f"POST /api/login HTTP/1.1\r\nHost: {self.srv.host}\r\nOrigin: {self.srv.origin}\r\n"
               "Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n").encode()
        reply = parse_raw_response(self.srv.raw(raw))
        self.assertEqual(reply.status, 411)
        self.assertEqual(self.app.sessions.count(), 0)


class HostAllowlistTests(HttpCase):
    server_options: ClassVar[Dict[str, Any]] = {"allowed_hosts": ("fw.example.test:8443",)}

    def test_unexpected_host_is_421(self) -> None:
        reply = self.srv.get("/healthz")
        self.assertEqual(reply.status, 421)
        assert_security_headers(self, reply, "421")
        self.assertEqual(self.srv.get("/healthz", host="evil.example").status, 421)
        self.assertEqual(self.srv.get("/api/session", host="fw.example.test").status, 421)  # port matters
        self.assertEqual(parse_raw_response(self.srv.raw(b"GET /healthz HTTP/1.0\r\n\r\n")).status, 421)
        self.assertEqual(self.srv.get("/healthz", host="fw.example.test:8443").status, 200)
        self.assertEqual(self.srv.get("/healthz", host="FW.Example.Test:8443").status, 200)


class ConnectionCapTests(HttpCase):
    server_options: ClassVar[Dict[str, Any]] = {"max_connections": 2, "socket_timeout_s": 5.0}

    def test_connections_over_the_cap_are_closed_promptly(self) -> None:
        held = [socket.create_connection(("127.0.0.1", self.srv.port), timeout=5) for _ in range(2)]
        try:
            with self.assertLogs("jwicket.web", level="WARNING") as logged:
                third = socket.create_connection(("127.0.0.1", self.srv.port), timeout=5)
                third.settimeout(3)
                start = time.monotonic()
                try:
                    data: Optional[bytes] = third.recv(1024)
                except ConnectionResetError:
                    data = b""
                except socket.timeout:
                    data = None
                finally:
                    third.close()
            self.assertEqual(data, b"", "the third connection was not closed by the server")
            self.assertLess(time.monotonic() - start, 2.0)
            self.assertTrue(any("connection limit" in line for line in logged.output))
        finally:
            for sock in held:
                sock.close()

        def serves() -> bool:
            try:
                return self.srv.get("/healthz").status == 200
            except (ConnectionError, OSError):
                return False

        self.assertTrue(wait_until(serves, timeout=5), "server did not recover after held connections closed")


class IdleConnectionTests(HttpCase):
    server_options: ClassVar[Dict[str, Any]] = {"max_connections": 2, "socket_timeout_s": 0.3}

    def test_idle_connections_time_out_and_free_their_slot(self) -> None:
        held = [socket.create_connection(("127.0.0.1", self.srv.port), timeout=5) for _ in range(2)]
        try:
            for sock in held:
                sock.settimeout(3)
                self.assertEqual(sock.recv(1024), b"")  # the server gave up on the silent client

            def serves() -> bool:
                try:
                    return self.srv.get("/healthz").status == 200
                except (ConnectionError, OSError):
                    return False

            self.assertTrue(wait_until(serves, timeout=3))
        finally:
            for sock in held:
                sock.close()


if __name__ == "__main__":
    unittest.main()
