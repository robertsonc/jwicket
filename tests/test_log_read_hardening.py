"""Audit and admission invariants at the dispatcher and the decoded reply boundary."""

from __future__ import annotations

import json
import threading
import unittest
from typing import Dict, List, Optional, Tuple
from unittest.mock import MagicMock, patch
from xml.etree import ElementTree

from jwicket import api, live
from jwicket.auth.sessions import SessionStore
from jwicket.auth.throttle import LoginThrottle
from jwicket.junos import logs as logmod
from jwicket.junos.errors import RpcFailed
from jwicket.logs import AuditTrail
from jwicket.web.http import COOKIE_PLAIN, Request, Response


class AuditRecorder(AuditTrail):
    def __init__(self) -> None:
        super().__init__(None)
        self.records: List[Tuple[str, Optional[str], str, Dict[str, str]]] = []

    def record(self, event: str, *, user: Optional[str], source: str, **fields: str) -> None:
        self.records.append((event, user, source, fields))


class ReadGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 1000.0
        self.audit = AuditRecorder()
        self.app = api.App(
            backend=MagicMock(),
            sessions=SessionStore(idle_s=900, absolute_s=3600, max_sessions=4, clock=lambda: self.now),
            throttle=LoginThrottle(per_name=5, per_source=20),
            audit=self.audit,
            session_idle_s=900,
            mono_clock=lambda: self.now,
        )

    def token(self, user: str) -> str:
        return self.app.sessions.create(user=user, backend="fixture", device=MagicMock(), source="operator")[0]

    def request(self, token: str, path: str, **query: str) -> Request:
        return Request("GET", path, query, {"Cookie": f"{COOKIE_PLAIN}={token}"}, "operator", False)

    def test_fresh_log_access_is_audited_by_server_state_even_for_a_time_window(self) -> None:
        token = self.token("operator")
        router = api.build_router(self.app)
        query = self.request(token, "/api/logs", source="report", start="2026-11-24T06:00:00")
        other = self.request(token, "/api/logs", source="buffer", since="2026-11-24.06:00:00")
        empty = {"status": "ok", "lines": []}
        with patch.object(live, "_log_sources", return_value={}), patch.object(
            live, "_read_report", return_value=empty
        ) as report, patch.object(live, "_read_buffer", return_value=empty):
            self.assertEqual(router.dispatch(query).status, 200)
            self.assertEqual(router.dispatch(other).status, 200)
            self.now += 2
            self.assertEqual(router.dispatch(query).status, 200)
            self.assertEqual(report.call_count, 2)
            self.assertEqual([f[3]["log"] for f in self.audit.records], ["report", "buffer"])
            self.now += live.LOG_AUDIT_INTERVAL_S
            self.assertEqual(router.dispatch(query).status, 200)
            self.assertEqual([f[3]["log"] for f in self.audit.records], ["report", "buffer", "report"])

    def test_file_time_window_is_rejected_before_discovery(self) -> None:
        router = api.build_router(self.app)
        token = self.token("operator")
        with patch.object(live, "_log_sources") as discovery:
            query = self.request(token, "/api/logs", source="file:messages", start="2026-11-24T06:00:00")
            response = router.dispatch(query)
            self.assertEqual(response.status, 400)
            self.assertIn("file logs use a cursor", json.loads(response.body)["error"])
            discovery.assert_not_called()

    def test_first_file_read_of_session_is_audited_with_a_valid_cursor(self) -> None:
        token = self.token("operator")
        router = api.build_router(self.app)
        cursor = logmod.tail(["prior line"], cursor=None, want=10, contains=[], exclude=[])["cursor"]
        with patch.object(live, "_log_sources", return_value={"files": [{"name": "messages"}]}), patch.object(
            live, "_read_file", return_value=["prior line", "new line"]
        ):
            result = router.dispatch(self.request(token, "/api/logs", source="file:messages", cursor=cursor))
        self.assertEqual(result.status, 200)
        self.assertEqual(json.loads(result.body)["log"]["lines"], ["new line"])
        self.assertEqual(self.audit.records, [("read_log", "operator", "operator", {
            "log": "file:messages", "status": "ok",
        })])

    def test_read_admission_is_shared_across_sessions_and_routes_without_delaying_another_account(self) -> None:
        self.app.max_account_reads = 1
        first, same, other = (self.token(user) for user in ("operator", "OPERATOR", "auditor"))
        entered = threading.Event()
        release = threading.Event()
        results: List[int] = []

        def hold(_app: api.App, _req: Request) -> Response:
            entered.set()
            if not release.wait(2):
                return Response.error(500, "test handler did not finish")
            return Response.json(200, {})

        with patch.object(api, "inventory", side_effect=hold), patch.object(
            live, "health", return_value=Response.json(200, {})
        ) as health:
            router = api.build_router(self.app)
            thread = threading.Thread(target=lambda: results.append(router.dispatch(
                self.request(first, "/api/inventory")
            ).status))
            thread.start()
            try:
                self.assertTrue(entered.wait(2))
                denied = router.dispatch(self.request(same, "/api/health"))
                self.assertEqual((denied.status, json.loads(denied.body)["reason"]), (429, "busy"))
                health.assert_not_called()
                self.assertEqual(router.dispatch(self.request(other, "/api/health")).status, 200)
            finally:
                release.set()
                thread.join(2)
            self.assertEqual(results, [200])
            self.assertEqual(router.dispatch(self.request(same, "/api/health")).status, 200)


class FileReplyBudgetTests(unittest.TestCase):
    def test_decoded_file_reply_is_refused_before_cleaning(self) -> None:
        reply = ElementTree.fromstring("<output>plain log line\n</output>")
        self.assertEqual(logmod.clean_file_reply(reply), ["plain log line"])
        with patch.object(logmod, "MAX_FILE_REPLY_CHARS", 8), patch.object(logmod, "clean_lines") as clean:
            with self.assertRaisesRegex(RpcFailed, "local reply budget"):
                logmod.clean_file_reply(reply)
            clean.assert_not_called()
