"""Defensive admission-policy tests, without a network-facing listener."""

from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from jwicket.auth.backends import NetconfBackend, validate_username
from jwicket.auth.throttle import LoginThrottle
from jwicket.junos.errors import LoginRejected
from jwicket.peer import peer_key
from jwicket.web import server


class PeerBudgetTests(unittest.TestCase):
    def test_numeric_sources_have_stable_buckets(self) -> None:
        self.assertEqual(peer_key("::ffff:192.0.2.5"), peer_key("192.0.2.5"))
        self.assertEqual(peer_key("2001:db8:12::1"), peer_key("2001:db8:12::dead:beef"))
        self.assertNotEqual(peer_key("2001:db8:12::1"), peer_key("2001:db8:13::1"))

    def test_external_admission_preserves_capacity_for_distinct_peers(self) -> None:
        slots = server._PeerSlots(4)
        for peer in ("2001:db8::1", "2001:db8::2", "2001:db8::3"):
            self.assertTrue(slots.acquire(peer))
        self.assertFalse(slots.acquire("2001:db8::4"))
        self.assertTrue(slots.acquire("192.0.2.1"))
        self.assertFalse(slots.acquire("192.0.2.2"))
        slots.release("2001:db8::1")
        self.assertTrue(slots.acquire("192.0.2.2"))
        for peer in ("2001:db8::2", "2001:db8::3", "192.0.2.1", "192.0.2.2"):
            slots.release(peer)
        self.assertEqual(slots._peers, {})

    def test_external_accept_path_does_not_wait_for_a_slot(self) -> None:
        with patch.object(server.ThreadingHTTPServer, "__init__", return_value=None):
            httpd = server.JWicketServer(
                ("192.0.2.1", 8443), server.Router(), tls=None, max_connections=2,
                socket_timeout_s=10, max_body_bytes=4096,
            )
        assert httpd._peer_slots is not None
        self.assertTrue(httpd._peer_slots.acquire("192.0.2.2"))
        refused = Mock()
        with patch.object(httpd._slots, "acquire", side_effect=AssertionError("must not wait")), patch.object(
            server.ThreadingHTTPServer, "process_request",
        ) as dispatch, patch.object(httpd, "shutdown_request") as shutdown:
            httpd.process_request(refused, ("192.0.2.2", 1111))
            shutdown.assert_called_once_with(refused)
            dispatch.assert_not_called()
            accepted = Mock()
            httpd.process_request(accepted, ("192.0.2.3", 1112))
            dispatch.assert_called_once_with(accepted, ("192.0.2.3", 1112))
        httpd._peer_slots.release("192.0.2.2")
        httpd._peer_slots.release("192.0.2.3")

    def test_external_tls_retargets_both_timers_and_head_leaves_body_budget(self) -> None:
        def inspect_handler(request: object, peer: object) -> None:
            self.assertIs(request, tls_socket)
            self.assertEqual(peer, ("192.0.2.2", 443))
            self.assertTrue(httpd.head_read())
            instances[1].cancel.assert_called_once()
            instances[0].cancel.assert_not_called()
            self.assertTrue(httpd.request_read())
            instances[0].cancel.assert_called_once()

        raw_socket = Mock()
        tls_socket = Mock()
        tls = Mock()
        tls.wrap_socket.return_value = tls_socket
        with patch.object(server.ThreadingHTTPServer, "__init__", return_value=None):
            httpd = server.JWicketServer(
                ("192.0.2.1", 8443), server.Router(), tls=tls, max_connections=8,
                socket_timeout_s=10, max_body_bytes=4096,
            )
        instances = (Mock(), Mock())
        assert httpd._peer_slots is not None
        self.assertTrue(httpd._peer_slots.acquire("192.0.2.2"))
        peer = ("192.0.2.2", 443)
        with patch.object(server, "_ReadDeadline", side_effect=instances) as timer, patch.object(
            server.ThreadingHTTPServer, "process_request_thread", side_effect=inspect_handler,
        ):
            httpd.process_request_thread(raw_socket, peer)
        self.assertEqual([c[0] for c in timer.call_args_list], [(10,), (server.HEAD_TIMEOUT_S,)])
        for deadline in instances:
            deadline.start.assert_called_once_with(raw_socket)
            deadline.retarget.assert_called_once_with(tls_socket)
        tls_socket.do_handshake.assert_called_once()
        self.assertEqual(httpd._peer_slots._peers, {})


class LoginBudgetTests(unittest.TestCase):
    def test_pending_check_reserves_last_account_slot_and_expiry_restores_it(self) -> None:
        now = 0.0
        t = LoginThrottle(per_name=1, per_source=10, clock=lambda: now)
        t.failed("192.0.2.1", "Alice")
        self.assertEqual(t.begin_for("192.0.2.2", "ALICE"), (None, True))
        self.assertEqual(t.begin_for("192.0.2.3", "alice"), (None, False))
        t.failed("192.0.2.2", "ALICE")
        t.end_for("ALICE")
        self.assertEqual(t.begin_for("192.0.2.3", "alice"), (60.0, False))
        self.assertEqual(t.begin_for("192.0.2.3", "bob"), (None, True))
        t.end_for("bob")
        now = 60.0
        self.assertEqual(t.begin_for("192.0.2.3", "alice"), (None, True))
        t.end_for("alice")

    def test_one_ipv6_subnet_has_one_source_budget(self) -> None:
        t = LoginThrottle(per_name=1, per_source=1, clock=lambda: 0.0)
        t.failed("2001:db8:2::1", "alice")
        self.assertEqual(t.check("2001:db8:2::2", "bob"), 60.0)
        self.assertIsNone(t.check("2001:db8:3::1", "bob"))

    def test_shared_lab_token_has_no_cross_source_account_budget(self) -> None:
        t = LoginThrottle(per_name=1, per_source=1, clock=lambda: 0.0)
        t.failed("192.0.2.1", "")
        t.failed("192.0.2.2", "")
        self.assertEqual(t.begin_for("192.0.2.3", ""), (None, True))
        t.end_for("")

    def test_local_root_is_refused_before_opening_netconf(self) -> None:
        opener = Mock()
        backend = NetconfBackend(host="127.0.0.1", port=830, timeout_s=3, opener=opener)
        for username in ("root", "ROOT"):
            with self.assertRaises(LoginRejected):
                backend.authenticate(username, "fixture-password")
        opener.assert_not_called()
        self.assertEqual(validate_username("alice@corp.example"), "alice@corp.example")
