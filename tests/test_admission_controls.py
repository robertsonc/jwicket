"""Defensive admission-policy tests, without a network-facing listener."""

from __future__ import annotations

import threading
import time
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

    def _external(self, max_connections: int) -> server.JWicketServer:
        with patch.object(server.ThreadingHTTPServer, "__init__", return_value=None):
            return server.JWicketServer(
                ("192.0.2.1", 8443), server.Router(), tls=None, max_connections=max_connections,
                socket_timeout_s=10, max_body_bytes=4096,
            )

    def test_external_over_cap_waits_off_the_accept_thread_and_is_served(self) -> None:
        httpd = self._external(2)  # one slot per peer; waiting places: QUEUE_PLACES_PER_SLOT x 2, 6 per peer
        assert httpd._peer_slots is not None and httpd._peer_waiters is not None
        self.assertTrue(httpd._peer_slots.acquire("192.0.2.2"))
        held = 0
        while httpd._peer_waiters.acquire("192.0.2.2"):  # leave this peer exactly one waiting place
            held += 1
        httpd._peer_waiters.release("192.0.2.2")
        held -= 1
        self.assertEqual(held + 1, (3 * server.QUEUE_PLACES_PER_SLOT * 2) // 4)
        served = threading.Event()
        with patch.object(httpd, "process_request_thread", side_effect=lambda r, a: served.set()), patch.object(
            httpd._slots, "acquire", side_effect=AssertionError("the loopback path must not be used"),
        ), patch.object(httpd, "shutdown_request") as shutdown:
            began = time.monotonic()
            httpd.process_request(Mock(), ("192.0.2.2", 1111))
            self.assertLess(time.monotonic() - began, 0.2)  # the accept thread did not wait
            third = Mock()
            httpd.process_request(third, ("192.0.2.2", 1112))  # this peer's only waiting place is taken
            shutdown.assert_called_once_with(third)
            httpd._peer_slots.release("192.0.2.2")
            self.assertTrue(served.wait(2.0))
        for _ in range(held):
            httpd._peer_waiters.release("192.0.2.2")
        self.assertEqual(httpd._peer_waiters._peers, {})

    def test_external_wait_is_bounded_then_the_connection_is_closed(self) -> None:
        httpd = self._external(2)
        assert httpd._peer_slots is not None and httpd._peer_waiters is not None
        self.assertTrue(httpd._peer_slots.acquire("192.0.2.2"))
        closed = threading.Event()
        waiting = Mock()
        with patch.object(server, "CONNECTION_QUEUE_S", 0.05), patch.object(
            httpd, "shutdown_request", side_effect=lambda r: closed.set(),
        ), patch.object(httpd, "process_request_thread", side_effect=AssertionError("must not be served")):
            httpd.process_request(waiting, ("192.0.2.2", 1111))
            self.assertTrue(closed.wait(2.0))
        self.assertEqual(httpd._peer_waiters._peers, {})
        httpd._peer_slots.release("192.0.2.2")

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
    def test_failures_from_other_sources_never_lock_a_name_out(self) -> None:
        # Owner decision 2026-11-26: no budget per user name across sources (Junos retry-options apply).
        t = LoginThrottle(per_name=1, per_source=10, clock=lambda: 0.0)
        for i in range(50):
            t.failed(f"198.51.100.{i}", "admin")
        self.assertEqual(t.begin_for("203.0.113.7", "ADMIN"), (None, True))
        t.end_for("ADMIN")
        self.assertEqual(t.begin_for("198.51.100.3", "admin"), (60.0, False))  # that source/name pair is spent

    def test_begin_for_checks_and_reserves_a_backend_slot_atomically(self) -> None:
        t = LoginThrottle(per_name=5, per_source=10, concurrent=1, clock=lambda: 0.0)
        self.assertEqual(t.begin_for("192.0.2.1", "alice"), (None, True))
        self.assertEqual(t.begin_for("192.0.2.2", "bob"), (None, False))  # busy, not throttled
        t.end_for("alice")
        self.assertEqual(t.begin_for("192.0.2.2", "bob"), (None, True))
        t.end_for("bob")

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
