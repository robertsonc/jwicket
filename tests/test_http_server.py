"""HTTP integration: the real JWicketServer and API router on 127.0.0.1, fed from synthetic fixtures."""

from __future__ import annotations

import contextlib
import csv
import http.client
import io
import json
import logging
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional, Tuple

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

from jwicket import api as api_mod
from jwicket import resources
from jwicket.api import build_router
from jwicket.auth.backends import LabTokenBackend
from jwicket.auth.sessions import SessionStore
from jwicket.auth.throttle import LoginThrottle
from jwicket.devserver import FixtureBackend
from jwicket.fixtures import FixtureSession
from jwicket.junos.errors import LoginUnavailable, RpcUnsupported, SessionLost
from jwicket.junos.session import PyEzUserSession
from jwicket.logs import AuditTrail, EscapeControls, escape_handlers, setup_logging
from jwicket.settings import LogSettings
from jwicket.web.http import COOKIE_PLAIN, COOKIE_TLS, CSP, Request
from jwicket.web.server import CONNECTION_QUEUE_S, JWicketServer, make_tls_context

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
            ("GET /static/js/main.js", lambda: self.srv.get("/static/js/main.js"), 200),
            ("GET /healthz", lambda: self.srv.get("/healthz"), 200),
            ("GET /api/session", lambda: self.srv.get("/api/session"), 200),
            ("GET /api/inventory", lambda: self.read("/api/inventory", cookie), 200),
            ("401", lambda: self.srv.get("/api/inventory"), 401),
            ("403", lambda: self.srv.post_json("/api/login", {}, origin="http://evil.example"), 403),
            ("404", lambda: self.srv.get("/no/such/page"), 404),
            ("405 POST", lambda: self.srv.request("POST", "/api/inventory", body=b""), 405),
            ("405 PUT", lambda: self.srv.request("PUT", "/api/session"), 405),
            ("400 scope", lambda: self.srv.get("/api/inventory?scope=../etc", cookie), 400),
            ("429", lambda: self.srv.get("/api/inventory?scope=lsys:OTHER", cookie), 429),
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
        self.assertIn(b"/static/js/main.js", index.body)
        self.assertIn(b"/static/css/app.css", index.body)
        self.assertEqual(self.srv.get("/static/index.html").body, index.body)
        for name, ctype in (
            ("js/main.js", "text/javascript"), ("css/app.css", "text/css"), ("logo.svg", "image/svg+xml"),
        ):
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
        paths = ("/api/inventory", "/api/inventory?scope=root", "/api/export?format=json", "/api/export?format=csv",
                 "/api/sessions", "/api/sessions?rows=none", "/api/logs/sources", "/api/logs?file=messages")
        for path in paths:
            for cookie, reason in ((None, "none"), (f"{COOKIE_PLAIN}=forged-token", "unknown"),
                                   (f"{COOKIE_TLS}=forged", "none"), ("jwicket=forged", "none")):
                with self.subTest(path=path, cookie=cookie):
                    reply = self.srv.get(path, cookie)
                    self.assertEqual(reply.status, 401)
                    body = reply.json()
                    self.assertEqual(body["reason"], reason)
                    self.assertNotIn("at", body)
                    self.assertEqual(body["error"], "sign-in required" if reason == "none"
                                     else "Your J-Wicket session has ended.")
                    self.assertNotIn("set-cookie", reply.headers)

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
        self.assertEqual(name, COOKIE_PLAIN)
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

    def test_session_facts_for_honest_wording(self) -> None:
        """BE-08 (B-6): the absolute limit, when the session started and must end, the per-user limit."""
        reply, cookie = self.srv.login("admin")
        for label, body in (("login", reply.json()), ("session", self.srv.get("/api/session", cookie).json())):
            with self.subTest(label):
                self.assertEqual((body["absolute_timeout_s"], body["max_sessions_per_user"]), (3600, 1))
                started = time.mktime(time.strptime(body["signed_in_at"], "%Y-%m-%dT%H:%M:%SZ"))
                ends = time.mktime(time.strptime(body["ends_by"], "%Y-%m-%dT%H:%M:%SZ"))
                self.assertEqual(ends - started, 3600)
        self.assertNotIn("ends_by", self.srv.get("/api/session").json())

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
        # The same browser signing in again overwrites its cookie, so the old one keeps no reason.
        self.assertEqual(self.srv.get("/api/inventory", first).json()["reason"], "unknown")
        # The same Junos user signing in from another browser replaces this session, and says so.
        self.assertEqual(self.srv.login("admin")[0].status, 200)
        reply = self.srv.get("/api/inventory", second)
        self.assertEqual(reply.status, 401)
        body = reply.json()
        self.assertEqual((body["reason"], body["error"]),
                         ("replaced", "You were signed out: the same Junos user signed in again elsewhere."))
        self.assertRegex(body["at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertNotIn("by", body)
        self.assertNotIn("set-cookie", reply.headers)  # every tab of this browser gets the same reason
        session = self.srv.get("/api/session", second).json()
        self.assertEqual((session["authenticated"], session["ended"]["reason"]), (False, "replaced"))
        self.assertEqual(session["ended"]["at"], body["at"])

    def test_planted_cookie_is_never_adopted(self) -> None:
        planted = f"{COOKIE_PLAIN}=attacker-chosen-value-0123456789abcdefghijklmnop"
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
        self.assertTrue(cleared.startswith(f"{COOKIE_PLAIN}=;"), cleared)
        self.assertIn("Max-Age=0", cleared)
        self.assertFalse(self.srv.get("/api/session", cookie).json()["authenticated"])
        self.assertTrue(sess.device.closed)  # type: ignore[union-attr]
        self.assertEqual(self.app.sessions.count(), 0)

    def test_signing_out_tells_the_other_tabs(self) -> None:
        reply, cookie = self.srv.login("admin")
        csrf = reply.json()["csrf"]
        self.assertEqual(self.srv.post_json("/api/logout", {}, cookie=cookie, extra={"X-CSRF-Token": csrf}).status, 200)
        body = self.srv.get("/api/sessions", cookie).json()
        self.assertEqual((body["reason"], body["error"]), ("signed-out", "You signed out in another tab or window."))
        self.assertEqual(self.srv.get("/api/session", cookie).json()["ended"]["reason"], "signed-out")

    def test_no_ended_without_a_tombstone(self) -> None:
        self.assertNotIn("ended", self.srv.get("/api/session").json())
        self.assertNotIn("ended", self.srv.get("/api/session", f"{COOKIE_PLAIN}=never-issued").json())

    def test_failed_sign_in_keeps_the_existing_session(self) -> None:
        """BE-10: the browser's session is ended only after Junos accepted the new credentials."""
        reply, cookie = self.srv.login("admin")
        self.assertEqual(reply.status, 200)
        self.assertEqual(self.srv.post_json("/api/login", {"username": "mallory", "password": "x"},
                                            cookie=cookie).status, 401)
        self.assertTrue(self.srv.get("/api/session", cookie).json()["authenticated"])
        self.assertEqual(self.app.sessions.count(), 1)

    def test_sign_in_throttle_reasons(self) -> None:
        self.app.throttle = LoginThrottle(per_name=1, per_source=100, concurrent=1, clock=self.clock)
        self.assertEqual(self.srv.post_json("/api/login", {"username": "mallory", "password": "x"}).status, 401)
        body = self.srv.post_json("/api/login", {"username": "mallory", "password": "x"}).json()
        self.assertEqual(body["reason"], "login-failures")
        self.assertTrue(self.app.throttle.begin())
        try:
            body = self.srv.post_json("/api/login", {"username": "admin", "password": "x"}).json()
        finally:
            self.app.throttle.end()
        self.assertEqual(body["reason"], "login-busy")

    def test_logout_without_a_session(self) -> None:
        out = self.srv.post_json("/api/logout", {})
        self.assertEqual(out.status, 200)
        self.assertIn("Max-Age=0", out.headers.get("set-cookie", ""))

    def test_login_is_throttled_with_retry_after(self) -> None:
        self.app.throttle = LoginThrottle(per_name=2, per_source=100, clock=self.clock)
        self.assertEqual(self.srv.post_json("/api/login", {"username": "mallory", "password": "x"}).status, 401)
        self.assertEqual(self.srv.post_json("/api/login", {"username": "mallory", "password": "x"}).status, 401)
        reply = self.srv.post_json("/api/login", {"username": "mallory", "password": "x"})
        self.assertEqual(reply.status, 429)
        self.assertGreaterEqual(int(reply.headers["retry-after"]), 1)
        self.assertIn("error", reply.json())
        self.assertEqual(self.srv.login("admin")[0].status, 200)  # another user name is not blocked
        self.clock.advance(61)
        self.assertEqual(self.srv.post_json("/api/login", {"username": "mallory", "password": "x"}).status, 401)

    def test_requests_that_never_reach_junos_do_not_lock_anyone_out(self) -> None:
        """SECU-3: junk bodies, empty or malformed fields and successful sign-ins cost no budget."""
        self.app.throttle = LoginThrottle(per_name=5, per_source=20, clock=self.clock)
        for _ in range(30):
            self.assertEqual(self.srv.post_json("/api/login", b"not json").status, 400)
            self.assertEqual(self.srv.post_json("/api/login", {"username": "", "password": ""}).status, 401)
            self.assertEqual(self.srv.post_json("/api/login", {"username": "bad name!", "password": "x"}).status, 401)
        for _ in range(8):
            self.assertEqual(self.srv.login("admin")[0].status, 200)
        self.assertEqual(self.srv.login("admin")[0].status, 200)

    def test_spraying_user_names_hits_the_per_source_cap(self) -> None:
        self.app.throttle = LoginThrottle(per_name=5, per_source=3, clock=self.clock)
        for i in range(3):
            self.assertEqual(self.srv.post_json("/api/login", {"username": f"nobody{i}", "password": "x"}).status, 401)
        self.assertEqual(self.srv.post_json("/api/login", {"username": "nobody9", "password": "x"}).status, 429)

    def test_too_many_concurrent_sign_ins_is_429(self) -> None:
        self.app.throttle = LoginThrottle(per_name=5, per_source=5, concurrent=1, clock=self.clock)
        self.assertTrue(self.app.throttle.begin())  # another sign-in is being checked
        reply = self.srv.post_json("/api/login", {"username": "admin", "password": "x"})
        self.assertEqual(reply.status, 429)
        self.assertGreaterEqual(int(reply.headers["retry-after"]), 1)
        self.app.throttle.end()
        self.assertEqual(self.srv.login("admin")[0].status, 200)

    def test_one_account_cannot_hold_every_slot(self) -> None:
        """SECU-5: signing in again as the same user replaces that user's session."""
        cookies = [self.signed_in("auditor") for _ in range(6)]
        self.assertEqual(self.app.sessions.count(), 1)
        self.assertTrue(self.srv.get("/api/session", cookies[-1]).json()["authenticated"])
        self.assertFalse(self.srv.get("/api/session", cookies[0]).json()["authenticated"])
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
        self.addCleanup(self.app.audit.close)
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

    def test_failed_sign_in_records_a_hash_not_the_user_name(self) -> None:
        """SECU-10: a password typed into the user-name field must not reach the audit trail, even one
        that fits the user-name pattern."""
        audit_dir = Path(tempfile.mkdtemp(prefix="jwicket-http-audit-"))
        self.addCleanup(shutil.rmtree, audit_dir, True)
        self.app.audit = AuditTrail(audit_dir / "audit.log")
        self.addCleanup(self.app.audit.close)
        for name in ("Corr3ct-Horse!Battery#Staple", "P@ssw0rd-2024", "P@ssw0rd-2024"):
            self.assertEqual(self.srv.post_json("/api/login", {"username": name, "password": "x"}).status, 401)
        self.srv.login("admin")
        self.app.audit.flush(force=True)
        text = (audit_dir / "audit.log").read_text(encoding="utf-8")
        for name in ("Corr3ct-Horse", "P@ssw0rd"):
            self.assertNotIn(name, text)
        entries = [json.loads(line) for line in text.splitlines()]
        failed = [e for e in entries if e["event"] == "login_failed" and e.get("user_hash")]
        self.assertEqual(len(failed), 2)
        self.assertEqual(failed[0]["user_hash"], failed[1]["user_hash"])  # attempts on one name correlate
        self.assertRegex(failed[0]["user_hash"], r"^[0-9a-f]{16}$")
        self.assertTrue(all(e["user"] is None for e in failed))
        self.assertEqual([e["user"] for e in entries if e["event"] == "login"], ["admin"])

    def test_unauthenticated_refusals_cannot_flush_the_audit_trail(self) -> None:
        """SECU-4: one line per kind, source and reason per window, plus a count when the window ends."""
        audit_dir = Path(tempfile.mkdtemp(prefix="jwicket-http-audit-"))
        self.addCleanup(shutil.rmtree, audit_dir, True)
        self.app.audit = AuditTrail(audit_dir / "audit.log", 10_000, 1)
        self.addCleanup(self.app.audit.close)
        self.app.throttle = LoginThrottle(per_name=1, per_source=100, clock=self.clock)
        self.assertEqual(self.srv.login("admin")[0].status, 200)
        for _ in range(200):
            self.srv.post_json("/api/login", b"{}", origin="http://evil.example")
        self.srv.post_json("/api/login", {"username": "mallory", "password": "x"})
        for _ in range(20):
            self.assertEqual(self.srv.post_json("/api/login", {"username": "mallory", "password": "x"}).status, 429)
            self.srv.post_json("/api/login", {"username": "bad name!", "password": "x"})
        text = "".join(p.read_text(encoding="utf-8") for p in audit_dir.iterdir())
        entries = [json.loads(line) for line in text.splitlines()]
        self.assertIn("login", [e["event"] for e in entries])
        self.assertEqual(sum(1 for e in entries if e["event"] == "login_refused"), 1)
        self.assertEqual(sum(1 for e in entries if e["event"] == "login_throttled"), 1)
        self.app.audit.flush(force=True)
        entries = [json.loads(line) for line in (audit_dir / "audit.log").read_text(encoding="utf-8").splitlines()]
        repeats = {(e["event"], e.get("reason")): e.get("repeated") for e in entries if e.get("repeated")}
        self.assertEqual(repeats[("login_refused", "cross-origin")], 199)
        self.assertEqual(repeats[("login_throttled", "failures")], 19)
        self.assertEqual(repeats[("login_failed", "format")], 19)


BACKGROUND = {"X-JWicket-Background": "1"}


class BackgroundRequestTests(HttpCase):
    """BE-01 (B-4): background polls never refresh the idle clock; the header can only shorten."""

    def get(self, path: str, cookie: str, value: Optional[str] = "1") -> Reply:
        headers = {} if value is None else {"X-JWicket-Background": value}
        return self.srv.get(path, cookie, headers=headers)

    def test_background_polls_do_not_refresh_the_idle_clock(self) -> None:
        cookie = self.signed_in()
        self.clock.advance(600)
        reply = self.get("/api/session", cookie)
        self.assertEqual(reply.status, 200)
        self.assertTrue(reply.json()["authenticated"])
        self.clock.advance(301)  # 901 s after the last foreground request
        reply = self.get("/api/inventory", cookie)
        self.assertEqual(reply.status, 401)
        body = reply.json()
        self.assertEqual((body["reason"], body["error"]), ("idle", "Your session ended after 15 min without activity."))
        self.assertRegex(body["at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        session = self.get("/api/session", cookie, None).json()
        self.assertEqual((session["authenticated"], session["ended"]["reason"]), (False, "idle"))

    def test_foreground_requests_keep_the_session(self) -> None:
        cookie = self.signed_in()
        self.clock.advance(600)
        self.assertEqual(self.get("/api/session", cookie, None).status, 200)  # no header: foreground
        self.clock.advance(600)
        self.assertTrue(self.get("/api/session", cookie).json()["authenticated"])

    def test_background_header_on_post_is_ignored(self) -> None:
        cookie = self.signed_in()
        self.clock.advance(600)
        # A POST always counts as foreground, even when it is then refused (here: no CSRF token).
        refused = self.srv.post_json("/api/logout", {}, cookie=cookie, extra=dict(BACKGROUND))
        self.assertEqual(refused.status, 403)
        self.clock.advance(600)
        self.assertTrue(self.get("/api/session", cookie).json()["authenticated"])

    def test_header_values_other_than_1_are_foreground(self) -> None:
        for value in ("true", "0", "yes", "11", "", "1 1"):
            with self.subTest(value=value):
                cookie = self.signed_in()
                self.clock.advance(600)
                self.assertTrue(self.get("/api/session", cookie, value).json()["authenticated"])
                self.clock.advance(600)  # 600 s after the request above, 1200 s after sign-in
                self.assertTrue(self.get("/api/session", cookie).json()["authenticated"])
        self.assertTrue(api_mod.is_background(Request(method="GET", path="/", query={}, headers={
            "X-JWicket-Background": " 1 "}, client="c", tls=False)))
        self.assertFalse(api_mod.is_background(Request(method="HEAD", path="/", query={}, headers=dict(BACKGROUND),
                                                       client="c", tls=False)))

    def test_background_never_extends_past_the_absolute_limit(self) -> None:
        cookie = self.signed_in()
        for _ in range(4):
            self.clock.advance(800)
            self.assertEqual(self.get("/api/session", cookie, None).status, 200)
        self.clock.advance(401)
        body = self.get("/api/sessions?rows=none", cookie).json()
        self.assertEqual((body["reason"], body["error"]), ("absolute", "Your session reached its 1 h limit."))

    def test_idle_expiry_is_audited_once_without_secrets(self) -> None:
        audit_dir = Path(tempfile.mkdtemp(prefix="jwicket-http-audit-"))
        self.addCleanup(shutil.rmtree, audit_dir, True)
        self.app.audit = AuditTrail(audit_dir / "audit.log")
        self.addCleanup(self.app.audit.close)
        password = "pw-that-must-not-be-logged"
        reply, cookie = self.srv.login("admin", password=password)
        self.clock.advance(901)
        self.assertEqual(self.get("/api/inventory", cookie).status, 401)
        self.assertEqual(self.get("/api/inventory", cookie).status, 401)
        text = (audit_dir / "audit.log").read_text(encoding="utf-8")
        entries = [json.loads(line) for line in text.splitlines()]
        ended = [e for e in entries if e["event"] == "session_ended"]
        self.assertEqual(len(ended), 1)
        self.assertEqual((ended[0]["reason"], ended[0]["user"]), ("idle", "admin"))
        for value in (password, self.token_of(cookie), reply.json()["csrf"]):
            self.assertNotIn(value, text)

    def test_new_sign_in_in_the_same_browser_is_audited_as_a_logout(self) -> None:
        audit_dir = Path(tempfile.mkdtemp(prefix="jwicket-http-audit-"))
        self.addCleanup(shutil.rmtree, audit_dir, True)
        self.app.audit = AuditTrail(audit_dir / "audit.log")
        self.addCleanup(self.app.audit.close)
        cookie = self.signed_in("admin")
        self.assertEqual(self.srv.login("auditor", cookie=cookie)[0].status, 200)
        entries = [json.loads(line) for line in (audit_dir / "audit.log").read_text(encoding="utf-8").splitlines()]
        logouts = [e for e in entries if e["event"] == "logout"]
        self.assertEqual([(e["user"], e["reason"]) for e in logouts], [("admin", "new-sign-in")])
        self.assertFalse(any(e["event"] == "session_ended" for e in entries))


class SlowDevice(FakeDevice):
    """Holds the software read until released, so a second request arrives while the first reads."""

    def __init__(self, user: str) -> None:
        super().__init__(user, {"get-software-information": xml(
            "<software-information><host-name>fw</host-name></software-information>"),
            "get-configuration": xml("<configuration><security/></configuration>"),
            "get-chassis-cluster-status": RpcUnsupported("not a cluster")})
        self.started = threading.Event()
        self.release = threading.Event()

    def rpc(self, name: str, **params: Any) -> Any:
        if name == "get-software-information":
            self.started.set()
            self.release.wait(5)
        return super().rpc(name, **params)


class ReuseHttpTests(HttpCase):
    """BE-05 (B-8): another tab's identical read within the floor gets the read just made."""

    def make_backend(self) -> Any:
        self.devices: List[Any] = []

        def factory(user: str) -> Any:
            dev = SlowDevice(user) if user == "slow" else FixtureSession(BRANCH, user)
            self.devices.append(dev)
            return dev

        return StaticBackend(factory)

    def count_rpcs(self, cookie: str) -> List[str]:
        calls: List[str] = []
        sess = self.app.sessions.get(self.token_of(cookie))
        assert sess is not None
        real_rpc = sess.device.rpc

        def spy(name: str, **params: Any) -> Any:
            calls.append(name)
            return real_rpc(name, **params)

        sess.device.rpc = spy  # type: ignore[method-assign]
        return calls

    def test_two_inventory_reads_share_one_device_read(self) -> None:
        cookie = self.signed_in()
        calls = self.count_rpcs(cookie)
        first = self.read("/api/inventory", cookie)
        self.assertEqual(first.status, 200)
        rpcs = len(calls)
        self.app.wall_clock = lambda: 1_795_600_000.0
        second = self.srv.get("/api/inventory", cookie)
        self.assertEqual(second.status, 200)
        self.assertEqual(second.json()["meta"]["read_at"], first.json()["meta"]["read_at"])
        self.assertIs(second.json()["meta"]["reused"], True)
        self.assertNotIn("reused", first.json()["meta"])
        self.assertEqual(second.json()["scope"], first.json()["scope"])
        self.assertEqual(len(calls), rpcs)
        other = self.srv.get("/api/inventory?scope=lsys:OTHER", cookie)
        self.assertEqual((other.status, other.json()["reason"]), (429, "rate"))
        # An export promises a fresh read: right after an inventory read it reads again.
        export = self.srv.get("/api/export?format=json", cookie)
        self.assertEqual(export.status, 200)
        self.assertNotIn("reused", export.json()["meta"])
        self.assertGreater(len(calls), rpcs)
        self.assertEqual(self.srv.get("/api/export?format=json", cookie).status, 429)

    def test_reused_reads_are_not_audited(self) -> None:
        records: List[str] = []

        class Spy(AuditTrail):
            def record(self, event: str, *, user: Optional[str], source: str, **fields: Any) -> None:
                records.append(event)

        self.app.audit = Spy(None)
        cookie = self.signed_in()
        self.read("/api/inventory", cookie)
        self.srv.get("/api/inventory", cookie)
        self.assertEqual(records.count("read_inventory"), 1)

    def test_reuse_is_never_across_sessions(self) -> None:
        a = self.signed_in("admin")
        b = self.signed_in("operator")
        self.assertEqual(self.read("/api/inventory", a).status, 200)
        reply = self.srv.get("/api/inventory", b)
        self.assertEqual(reply.status, 200)
        self.assertNotIn("reused", reply.json()["meta"])
        self.assertEqual(reply.json()["meta"]["read_as"]["user"], "operator")

    def test_a_waiting_request_gets_the_read_in_flight(self) -> None:
        cookie = self.signed_in("slow")
        device = self.devices[-1]
        results: List[Reply] = []
        self.clock.advance(5)
        first = threading.Thread(target=lambda: results.append(self.srv.get("/api/inventory", cookie)))
        first.start()
        self.assertTrue(device.started.wait(5))
        second = threading.Thread(target=lambda: results.append(self.srv.get("/api/inventory", cookie)))
        second.start()
        time.sleep(0.2)  # the second request is now waiting for the device turn
        device.release.set()
        first.join(10)
        second.join(10)
        self.assertEqual([r.status for r in results], [200, 200])
        self.assertEqual([c[0] for c in device.calls].count("get-software-information"), 1)
        bodies = [r.json() for r in results]
        self.assertEqual(bodies[0]["meta"]["read_at"], bodies[1]["meta"]["read_at"])
        self.assertEqual(sorted(bool(b["meta"].get("reused")) for b in bodies), [False, True])

    def test_a_failed_read_in_flight_leaves_the_waiter_busy(self) -> None:
        cookie = self.signed_in("slow")
        device = self.devices[-1]
        device.replies["get-software-information"] = SessionLost("gone")
        results: List[Reply] = []
        self.clock.advance(5)
        first = threading.Thread(target=lambda: results.append(self.srv.get("/api/inventory", cookie)))
        first.start()
        self.assertTrue(device.started.wait(5))
        second = threading.Thread(target=lambda: results.append(self.srv.get("/api/inventory", cookie)))
        second.start()
        time.sleep(0.2)
        device.release.set()
        first.join(10)
        second.join(10)
        statuses = sorted(r.status for r in results)
        self.assertEqual(statuses, [401, 429])
        busy = next(r for r in results if r.status == 429).json()
        self.assertEqual(busy["reason"], "busy")

    def test_only_one_request_waits_for_the_read_in_flight(self) -> None:
        """SEC-4: a third identical request while one already waits gets a busy 429 at once, so one
        session cannot hold the server's connection slots with copies of one request."""
        cookie = self.signed_in("slow")
        device = self.devices[-1]
        results: List[Reply] = []
        self.clock.advance(5)
        first = threading.Thread(target=lambda: results.append(self.srv.get("/api/inventory", cookie)))
        first.start()
        self.assertTrue(device.started.wait(5))
        second = threading.Thread(target=lambda: results.append(self.srv.get("/api/inventory", cookie)))
        second.start()
        time.sleep(0.2)  # the second request now waits for the read in flight
        began = time.monotonic()
        third = self.srv.get("/api/inventory", cookie)
        self.assertLess(time.monotonic() - began, 2.0)
        self.assertEqual((third.status, third.json()["reason"]), (429, "busy"))
        device.release.set()
        first.join(10)
        second.join(10)
        self.assertEqual(sorted(r.status for r in results), [200, 200])
        sess = self.app.sessions.get(self.token_of(cookie))
        assert sess is not None
        self.assertEqual(sess.reuse_waiters, {})

    def test_reused_reads_are_dropped_after_their_window(self) -> None:
        """SEC-3 (OD-07): a stored read is held for its window only, not for the session's life."""
        cookie = self.signed_in()
        self.assertEqual(self.read("/api/inventory", cookie).status, 200)
        sess = self.app.sessions.get(self.token_of(cookie))
        assert sess is not None
        self.assertIn("inventory", sess.reuse)
        self.clock.advance(api_mod.REUSE_MAX_S + 0.1)
        api_mod.prune_reuse(self.app)  # what the reaper runs every 30 s
        self.assertEqual(sess.reuse, {})
        # So does the session's next request of any kind (here a foreground /api/session).
        self.clock.advance(5)
        self.assertEqual(self.read("/api/inventory", cookie).status, 200)
        self.clock.advance(api_mod.REUSE_MAX_S)
        self.assertTrue(self.srv.get("/api/session", cookie).json()["authenticated"])
        self.assertEqual(sess.reuse, {})
        # A lookup past the window drops the entry too.
        self.clock.advance(5)
        self.assertEqual(self.read("/api/inventory", cookie).status, 200)
        self.assertIn("inventory", sess.reuse)
        self.clock.advance(api_mod.MIN_READ_INTERVAL_S)
        self.assertIsNone(api_mod.reuse_hit(self.app, sess, "inventory", "root", api_mod.MIN_READ_INTERVAL_S))
        self.assertNotIn("inventory", sess.reuse)
        # Storing a read drops the session's other entries past the window.
        sess.reuse["logs:file:messages"] = ("messages", self.clock() - 10, ["old line"])
        api_mod.remember(self.app, sess, "inventory", "root", self.clock(), {"meta": {}})
        self.assertEqual(sorted(sess.reuse), ["inventory"])
        # A read slower than the longest window is not kept at all.
        api_mod.remember(self.app, sess, "inventory", "root", self.clock() - 3, {"meta": {}})
        self.assertNotIn("inventory", sess.reuse)


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
        self.assertEqual(meta["scopes"], [{"id": "root", "label": "Root system", "policies": 10, "inactive": False,
                                           "selectable": True}])
        self.assertEqual(data["device"]["hostname"], "branch-fw-01")
        self.assertEqual(data["device"]["status"], "ok")
        self.assertEqual(data["ha"], {"status": "ok", "mode": "standalone"})
        self.assertTrue(data["management"]["managed"])
        self.assertEqual(data["management"]["clients"][0]["client"], "central-mgr")
        self.assertEqual(data["config"], {"status": "ok", "filter": "full"})
        # The branch configuration sets no time zone, so the Junos default (UTC) applies.
        self.assertEqual(data["clock"], {"status": "ok", "time_zone": None, "configured": False, "deactivated": None,
                                         "source": "configuration"})
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
        # Never assume UTC when the configuration was not read.
        self.assertEqual(data["clock"], data["config"])
        self.assertEqual(data["clock"]["status"], "denied")
        self.assertEqual(data["management"]["status"], "denied")
        self.assertNotIn("filter", data["config"])
        # CRT-03: an empty CSV would read as "no policies"; it is refused with the reason instead.
        csv_reply = self.read("/api/export?format=csv", cookie)
        self.assertEqual(csv_reply.status, 409)
        self.assertNotIn("content-disposition", csv_reply.headers)
        body = csv_reply.json()
        self.assertEqual(body["config"], {"status": "denied", "message": data["config"]["message"]})
        self.assertEqual(body["error"], f"The configuration was not read (denied: {data['config']['message']}), so "
                                        "there are no policies to export as CSV.")
        json_reply = self.read("/api/export?format=json", cookie)
        self.assertEqual(json_reply.status, 200)
        self.assertRegex(json_reply.headers["content-disposition"],
                         r'^attachment; filename="jwicket-branch-fw-01-root-\d{8}T\d{6}Z-config-denied\.json"$')
        self.assertEqual(json_reply.json()["config"]["status"], "denied")

    def test_reading_again_within_two_seconds_is_429(self) -> None:
        """A different read within the floor is refused; the identical one is answered from the first."""
        cookie = self.signed_in()
        self.assertEqual(self.read("/api/inventory", cookie).status, 200)
        reply = self.srv.get("/api/inventory?scope=lsys:OTHER", cookie)
        self.assertEqual(reply.status, 429)
        self.assertEqual(reply.headers.get("retry-after"), "2")
        body = reply.json()
        self.assertEqual((body["retry_after_s"], body["reason"], body["interval_s"]), (2, "rate", 2.0))
        self.clock.advance(1)
        reply = self.srv.get("/api/inventory?scope=lsys:OTHER", cookie)
        self.assertEqual((reply.status, reply.headers.get("retry-after")), (429, "1"))
        self.clock.advance(1)
        self.assertEqual(self.srv.get("/api/inventory?scope=lsys:OTHER", cookie).status, 404)
        self.assertEqual(self.srv.get("/api/inventory", cookie).status, 429)

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
        for scope in ("../etc", "lsys:", "tenant:", "lsys:a%20b", "lsys:LS%20A", "LSYS:x", "root;x", "root%00",
                      "lsys:" + "a" * 64, "lsys:a/b", "global", "%27or%201=1"):
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
        """An export promises a fresh read, so it is never answered from a stored one (B-8)."""
        cookie = self.signed_in()
        self.assertEqual(self.read("/api/export?format=json", cookie).status, 200)
        reply = self.srv.get("/api/export?format=json", cookie)
        self.assertEqual((reply.status, reply.json()["reason"]), (429, "rate"))

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
                self.assertEqual((body["error"], body["reason"]), ("Your device session ended. Sign in again.",
                                                                   "session-lost"))
                self.assertRegex(body["at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
                self.assertFalse(self.srv.get("/api/session", cookie).json()["authenticated"])
                self.assertEqual(self.app.sessions.count(), 0)
                # Later requests with the same cookie say why too.
                later = self.read(path, cookie).json()
                self.assertEqual((later["reason"], later["error"], later["at"]),
                                 ("session-lost", "Your device session ended. Sign in again.", body["at"]))
                self.assertNotIn("signed_out", later)

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
        self.app.wall_clock = lambda: 1_795_500_000.0
        self.assertEqual(self.srv.login("alice")[0].status, 200)
        self.clock.advance(100)
        reply = self.srv.post_json("/api/login", {"username": "bob", "password": "x"})
        self.assertEqual(reply.status, 503)
        self.assertNotIn("set-cookie", reply.headers)
        self.assertNotIn("retry-after", reply.headers)  # an automatic retry would not help
        self.assertEqual([d.closed for d in self.devices], [0, 1])
        body = reply.json()
        self.assertEqual(body["error"], "Too many people are signed in to J-Wicket on this device. Try again later.")
        self.assertEqual(body["reason"], "session-limit")
        self.assertEqual(body["sessions"], {"open": 1, "max": 1})
        self.assertEqual((body["slot_free_by_s"], body["slot_may_free_in_s"]), (3500, 800))
        self.assertEqual(body["slot_free_by"], "2026-11-24T06:58:20Z")  # 06:00:00 wall time + 3500 s
        self.assertNotIn(b"alice", reply.body)  # no other user's name or source
        self.assertNotIn(b"127.0.0.1", reply.body)

    def test_device_service_unreachable_is_503(self) -> None:
        def factory(_user: str) -> Any:
            raise LoginUnavailable("connection refused on 127.0.0.1:830")

        self.app.backend = StaticBackend(factory)
        reply = self.srv.post_json("/api/login", {"username": "alice", "password": "x"})
        self.assertEqual(reply.status, 503)
        body = reply.json()
        self.assertNotIn("127.0.0.1:830", body["error"])  # operator-safe message only
        self.assertEqual(body["reason"], "unavailable")
        for key in ("sessions", "slot_free_by", "slot_free_by_s", "slot_may_free_in_s"):
            self.assertNotIn(key, body)


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
            # The server waits CONNECTION_QUEUE_S for a free slot before closing; allow a loaded runner 1 s more.
            self.assertLess(time.monotonic() - start, CONNECTION_QUEUE_S + 1.0)
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

    def test_a_connection_over_the_cap_waits_briefly_for_a_slot(self) -> None:
        """F1: two browser profiles loading at once go over the cap for a moment; a connection that
        finds every slot taken is served when one frees within CONNECTION_QUEUE_S, not dropped."""
        held = [socket.create_connection(("127.0.0.1", self.srv.port), timeout=5) for _ in range(2)]
        replies: List[int] = []

        def third() -> None:
            try:
                replies.append(self.srv.get("/healthz").status)
            except (ConnectionError, OSError):
                replies.append(0)

        worker = threading.Thread(target=third)
        try:
            time.sleep(0.2)  # both slots are taken by the silent connections
            worker.start()
            time.sleep(0.3)
            held[0].close()  # a slot frees well inside the queue wait
            worker.join(5)
            self.assertEqual(replies, [200])
        finally:
            for sock in held:
                sock.close()


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


class SlowClientTests(HttpCase):
    """SECU-2: a client that trickles bytes cannot keep a connection slot past one read deadline."""

    server_options: ClassVar[Dict[str, Any]] = {"max_connections": 2, "socket_timeout_s": 1.0}

    def test_trickled_requests_lose_their_slot_at_the_deadline(self) -> None:
        held = []
        stop = threading.Event()
        for _ in range(2):
            sock = socket.create_connection(("127.0.0.1", self.srv.port), timeout=5)
            sock.sendall(b"GET /healthz HTTP/1.0\r\n")
            held.append(sock)

        def trickle() -> None:
            while not stop.wait(0.3):  # one header byte every 0.3 s: each read is well inside the timeout
                for sock in held:
                    with contextlib.suppress(OSError):
                        sock.sendall(b"X")

        worker = threading.Thread(target=trickle, daemon=True)
        worker.start()
        try:
            started = time.monotonic()
            for sock in held:
                sock.settimeout(5)
                try:
                    while sock.recv(1024):
                        pass
                except (ConnectionResetError, socket.timeout):
                    pass
            self.assertLess(time.monotonic() - started, 4.0, "trickling clients kept their slots")

            def serves() -> bool:
                try:
                    return self.srv.get("/healthz").status == 200
                except (ConnectionError, OSError):
                    return False

            self.assertTrue(wait_until(serves, timeout=3), "a real client was still locked out")
        finally:
            stop.set()
            worker.join(timeout=2)
            for sock in held:
                sock.close()

    def test_a_request_that_arrives_in_time_is_served(self) -> None:
        self.assertEqual(self.srv.get("/healthz").status, 200)
        reply, cookie = self.srv.login("admin")
        self.assertEqual(reply.status, 200)
        self.assertEqual(self.read("/api/inventory", cookie).status, 200)


def _self_signed(directory: Path) -> Optional[Tuple[Path, Path]]:
    """A throwaway certificate for 127.0.0.1, made with the openssl command; None if it is missing."""
    openssl = shutil.which("openssl")
    if openssl is None:
        return None
    cert, key = directory / "cert.pem", directory / "key.pem"
    proc = subprocess.run(  # noqa: S603 - fixed argument list, no shell
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=127.0.0.1",
         "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", str(key), "-out", str(cert)],
        capture_output=True, timeout=60, check=False,
    )
    return (cert, key) if proc.returncode == 0 else None


class TlsDeadlineTests(unittest.TestCase):
    """SECU-2: the read deadline covers the TLS handshake too."""

    def setUp(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="jwicket-tls-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        made = _self_signed(tmp)
        if made is None:
            self.skipTest("the openssl command is not available")
        cert, key = made
        self.client_ctx = ssl.create_default_context(cafile=str(cert))
        self.server = JWicketServer(
            ("127.0.0.1", 0), build_router(make_app(FixtureBackend(BRANCH))), tls=make_tls_context(str(cert), str(key)),
            max_connections=2, socket_timeout_s=1.0, max_body_bytes=8192,
        )
        self.port = int(self.server.server_address[1])
        thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        thread.start()

        def stop() -> None:
            self.server.shutdown()
            self.server.server_close()
            thread.join(timeout=5)

        self.addCleanup(stop)

    def healthz(self) -> int:
        conn = http.client.HTTPSConnection("127.0.0.1", self.port, timeout=5, context=self.client_ctx)
        try:
            conn.request("GET", "/healthz")
            return conn.getresponse().status
        finally:
            conn.close()

    def test_tls_request_is_served_with_hsts(self) -> None:
        conn = http.client.HTTPSConnection("127.0.0.1", self.port, timeout=5, context=self.client_ctx)
        try:
            conn.request("GET", "/healthz")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            self.assertIn("max-age", resp.getheader("Strict-Transport-Security") or "")
        finally:
            conn.close()

    def test_trickled_handshakes_lose_their_slot(self) -> None:
        held = [socket.create_connection(("127.0.0.1", self.port), timeout=5) for _ in range(2)]
        stop = threading.Event()

        def trickle() -> None:
            # A TLS record header, then one byte at a time: each read is well inside the timeout.
            for sock in held:
                with contextlib.suppress(OSError):
                    sock.sendall(b"\x16\x03\x01\x02\x00")
            while not stop.wait(0.3):
                for sock in held:
                    with contextlib.suppress(OSError):
                        sock.sendall(b"\x01")

        worker = threading.Thread(target=trickle, daemon=True)
        worker.start()
        try:
            started = time.monotonic()
            for sock in held:
                sock.settimeout(5)
                try:
                    while sock.recv(1024):
                        pass
                except (ConnectionResetError, socket.timeout):
                    pass
            self.assertLess(time.monotonic() - started, 4.0, "trickled handshakes kept their slots")

            def serves() -> bool:
                try:
                    return self.healthz() == 200
                except (ConnectionError, OSError):
                    return False

            self.assertTrue(wait_until(serves, timeout=3))
        finally:
            stop.set()
            worker.join(timeout=2)
            for sock in held:
                sock.close()


class HeadSizeTests(HttpCase):
    def test_headers_over_the_total_cap_are_431(self) -> None:
        many = "".join(f"X-Pad-{i}: {'a' * 1000}\r\n" for i in range(20))  # 20 KiB, each line small
        raw = f"GET /healthz HTTP/1.0\r\nHost: {self.srv.host}\r\n{many}\r\n".encode()
        reply = parse_raw_response(self.srv.raw(raw))
        self.assertEqual(reply.status, 431)
        assert_security_headers(self, reply, "431")

    def test_request_line_over_the_cap_is_414(self) -> None:
        raw = f"GET /healthz?{'a=1&' * 5000} HTTP/1.0\r\nHost: {self.srv.host}\r\n\r\n".encode()
        reply = parse_raw_response(self.srv.raw(raw))
        self.assertEqual(reply.status, 414)
        assert_security_headers(self, reply, "414")

    def test_normal_headers_are_served(self) -> None:
        reply = self.srv.request("GET", "/healthz", headers={"X-Pad": "a" * 4000})
        self.assertEqual(reply.status, 200)


class DiagnosticLogEscapeTests(unittest.TestCase):
    """SECU-7: request data reaches the diagnostic log with control characters escaped."""

    def test_control_characters_are_escaped_once(self) -> None:
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        escape_handlers([handler])
        second = logging.StreamHandler(io.StringIO())
        escape_handlers([second])
        logger = logging.getLogger("jwicket.test-escape")
        logger.propagate = False
        logger.addHandler(handler)
        logger.addHandler(second)
        self.addCleanup(logger.removeHandler, handler)
        self.addCleanup(logger.removeHandler, second)
        logger.warning("%s %s", "127.0.0.1", 'GET /x\x1b[2J\rFORGED jwicket INFO login ok \\ \x85 HTTP/1.0')
        line = stream.getvalue()
        self.assertEqual(line.count("\n"), 1)
        self.assertNotIn("\x1b", line)
        self.assertNotIn("\r", line)
        self.assertIn("\\x1b[2J\\x0dFORGED", line)
        self.assertIn(" \\\\ \\x85 ", line)  # backslash escaped once, not twice

    def test_traceback_keeps_its_line_breaks(self) -> None:
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        escape_handlers([handler])
        logger = logging.getLogger("jwicket.test-escape-tb")
        logger.propagate = False
        logger.addHandler(handler)
        self.addCleanup(logger.removeHandler, handler)
        try:
            int("boom")
        except ValueError:
            logger.exception("serving %s", "/a\x1bb")
        text = stream.getvalue()
        self.assertIn("serving /a\\x1bb\nTraceback", text)
        self.assertIn("ValueError: invalid literal", text)

    def test_setup_logging_escapes_its_handlers(self) -> None:
        root = logging.getLogger()
        before = list(root.handlers)
        level = root.level
        setup_logging(LogSettings(level="INFO"))
        added = [h for h in root.handlers if h not in before]

        def restore() -> None:
            for h in added:
                root.removeHandler(h)
            root.setLevel(level)

        self.addCleanup(restore)
        self.assertTrue(added)
        for h in added:
            self.assertTrue(any(isinstance(f, EscapeControls) for f in h.filters))

    def test_request_line_is_escaped_through_the_daemon_handlers(self) -> None:
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        escape_handlers([handler])
        web = logging.getLogger("jwicket.web")
        web.addHandler(handler)
        level = web.level
        web.setLevel(logging.INFO)
        self.addCleanup(web.removeHandler, handler)
        self.addCleanup(web.setLevel, level)
        srv = LiveServer(make_app(FixtureBackend(BRANCH)))
        self.addCleanup(srv.stop)
        srv.raw(b"GET /healthz\x1b[2J\x1b[1;1H\rFORGED jwicket INFO login ok HTTP/1.0\r\nHost: "
                + srv.host.encode() + b"\r\n\r\n")
        self.assertTrue(wait_until(lambda: "FORGED" in stream.getvalue()))
        text = stream.getvalue()
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\r", text)
        self.assertIn("\\x1b[2J", text)


if __name__ == "__main__":
    unittest.main()
