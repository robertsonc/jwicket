"""auth/: browser sessions, sign-in throttling and the authentication backends."""

from __future__ import annotations

import hashlib
import hmac
import unittest
from typing import Any, List, Tuple
from unittest import mock

from helpers import FakeClock, FakeDevice

from jwicket.auth import throttle as throttle_mod
from jwicket.auth.backends import LabTokenBackend, NetconfBackend, validate_secret, validate_username
from jwicket.auth.sessions import SessionLimit, SessionStore
from jwicket.auth.throttle import LoginThrottle
from jwicket.junos.errors import LoginRejected, LoginUnavailable


class ExplodingDevice(FakeDevice):
    def close(self) -> None:
        super().close()
        raise RuntimeError("close failed")


class SessionStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        self.store = SessionStore(idle_s=100, absolute_s=300, max_sessions=2, clock=self.clock)

    def create(self, user: str = "alice") -> Tuple[str, Any, FakeDevice]:
        dev = FakeDevice(user)
        token, sess = self.store.create(user=user, backend="netconf", device=dev, source="127.0.0.1")
        return token, sess, dev

    def test_create_and_get(self) -> None:
        token, sess, _dev = self.create()
        self.assertIs(self.store.get(token), sess)
        self.assertEqual((sess.user, sess.backend, sess.source), ("alice", "netconf", "127.0.0.1"))
        self.assertGreaterEqual(len(token), 43)  # 32 random bytes, URL-safe
        self.assertGreaterEqual(len(sess.csrf), 43)
        self.assertNotEqual(token, sess.csrf)

    def test_raw_token_is_not_stored(self) -> None:
        token, sess, _dev = self.create()
        self.assertEqual(sess.key, hashlib.sha256(token.encode("utf-8")).hexdigest())
        self.assertNotIn(token, self.store._sessions)
        self.assertNotIn(token, repr(sess))
        self.assertNotIn(token, sess.key)

    def test_unknown_and_empty_tokens(self) -> None:
        self.create()
        for token in (None, "", "not-a-token"):
            with self.subTest(token=token):
                self.assertIsNone(self.store.get(token))
                self.assertIsNone(self.store.remove(token))

    def test_tokens_and_csrf_are_unique(self) -> None:
        t1, s1, _ = self.create("a")
        t2, s2, _ = self.create("b")
        self.assertNotEqual(t1, t2)
        self.assertNotEqual(s1.csrf, s2.csrf)

    def test_idle_expiry_closes_device(self) -> None:
        token, _sess, dev = self.create()
        self.clock.advance(99)
        self.assertIsNotNone(self.store.get(token))  # also refreshes last_seen
        self.clock.advance(99)
        self.assertIsNotNone(self.store.get(token))  # sliding idle window
        self.clock.advance(101)
        self.assertIsNone(self.store.get(token))
        self.assertEqual(dev.closed, 1)
        self.assertEqual(self.store.count(), 0)
        self.assertIsNone(self.store.get(token))
        self.assertEqual(dev.closed, 1)

    def test_absolute_expiry_despite_activity(self) -> None:
        token, _sess, dev = self.create()
        for _ in range(5):
            self.clock.advance(60)
            self.assertIsNotNone(self.store.get(token))
        self.assertEqual(self.clock.now - 1000.0, 300)
        self.clock.advance(1)
        self.assertIsNone(self.store.get(token))
        self.assertEqual(dev.closed, 1)

    def test_cap_refuses_new_sessions_without_evicting(self) -> None:
        t1, _s1, d1 = self.create("a")
        t2, _s2, d2 = self.create("b")
        with self.assertRaises(SessionLimit):
            self.create("c")
        self.assertEqual(self.store.count(), 2)
        self.assertIsNotNone(self.store.get(t1))
        self.assertIsNotNone(self.store.get(t2))
        self.assertEqual((d1.closed, d2.closed), (0, 0))

    def test_expired_sessions_do_not_count_against_the_cap(self) -> None:
        _t1, _s1, d1 = self.create("a")
        _t2, _s2, d2 = self.create("b")
        self.clock.advance(101)
        self.create("c")
        self.assertEqual((d1.closed, d2.closed), (1, 1))
        self.assertEqual(self.store.count(), 1)

    def test_remove_drop_close_all_close_devices(self) -> None:
        t1, _s1, d1 = self.create("a")
        _t2, s2, d2 = self.create("b")
        self.assertIsNotNone(self.store.remove(t1))
        self.assertEqual(d1.closed, 1)
        self.assertIsNone(self.store.get(t1))
        self.store.drop(s2, "device session lost")
        self.assertEqual(d2.closed, 1)
        self.store.drop(s2, "again")  # already gone: no second close
        self.assertEqual(d2.closed, 1)
        _t3, _s3, d3 = self.create("c")
        _t4, _s4, d4 = self.create("d")
        self.store.close_all()
        self.assertEqual((d3.closed, d4.closed), (1, 1))
        self.assertEqual(self.store.count(), 0)

    def test_reap(self) -> None:
        _t1, _s1, d1 = self.create("a")
        self.clock.advance(50)
        t2, _s2, d2 = self.create("b")
        self.clock.advance(60)
        reaped = self.store.reap()
        self.assertEqual([s.user for s in reaped], ["a"])
        self.assertEqual((d1.closed, d2.closed), (1, 0))
        self.assertIsNotNone(self.store.get(t2))

    def test_one_session_per_user_the_new_sign_in_replaces_the_oldest(self) -> None:
        """SECU-5: one account cannot hold every slot; a new sign-in by the same user closes its oldest."""
        store = SessionStore(idle_s=100, absolute_s=300, max_sessions=4, max_per_user=1, clock=self.clock)
        devices = [FakeDevice("auditor") for _ in range(4)]
        tokens = []
        replaced: List[Any] = []
        for dev in devices:
            token, _ = store.create(user="auditor", backend="netconf", device=dev, source="127.0.0.1",
                                    user_key="auditor", replaced=replaced)
            tokens.append(token)
            self.clock.advance(1)
        self.assertEqual(store.count(), 1)
        self.assertEqual([d.closed for d in devices], [1, 1, 1, 0])
        self.assertEqual(len(replaced), 3)
        self.assertIsNone(store.get(tokens[0]))
        self.assertIsNotNone(store.get(tokens[-1]))
        # Another person can still sign in.
        store.create(user="admin", backend="netconf", device=FakeDevice("admin"), source="127.0.0.1", user_key="admin")
        self.assertEqual(store.count(), 2)

    def test_per_user_limit_above_one_keeps_the_newest(self) -> None:
        store = SessionStore(idle_s=100, absolute_s=300, max_sessions=4, max_per_user=2, clock=self.clock)
        devices = [FakeDevice("a") for _ in range(3)]
        for dev in devices:
            store.create(user="a", backend="netconf", device=dev, source="s", user_key="a")
            self.clock.advance(1)
        self.assertEqual([d.closed for d in devices], [1, 0, 0])

    def test_sessions_without_a_user_key_are_not_limited_per_user(self) -> None:
        """Lab-token sessions all carry the daemon account's name: only the overall cap applies."""
        store = SessionStore(idle_s=100, absolute_s=300, max_sessions=2, max_per_user=1, clock=self.clock)
        store.create(user="svc", backend="lab-token", device=FakeDevice("svc"), source="s")
        store.create(user="svc", backend="lab-token", device=FakeDevice("svc"), source="s")
        self.assertEqual(store.count(), 2)
        with self.assertRaises(SessionLimit):
            store.create(user="svc", backend="lab-token", device=FakeDevice("svc"), source="s")

    def test_failing_device_close_does_not_break_the_store(self) -> None:
        dev = ExplodingDevice("x")
        token, _ = self.store.create(user="x", backend="netconf", device=dev, source="127.0.0.1")
        with self.assertLogs("jwicket.sessions", level="WARNING") as logged:
            self.assertIsNotNone(self.store.remove(token))
        self.assertTrue(any("failed" in line for line in logged.output))
        self.assertEqual(dev.closed, 1)
        self.assertEqual(self.store.count(), 0)


class ThrottleTests(unittest.TestCase):
    """SECU-3: only failed sign-ins that reached the backend count; per (source, user name), with a
    looser cap per source; concurrency instead of a daemon-wide per-minute budget."""

    def setUp(self) -> None:
        self.clock = FakeClock(0.0)

    def test_per_name_limit_and_retry_after(self) -> None:
        t = LoginThrottle(per_name=3, per_source=100, clock=self.clock)
        for _ in range(3):
            self.assertIsNone(t.check("192.0.2.1", "alice"))
            t.failed("192.0.2.1", "alice")
            self.clock.advance(1)
        self.clock.now = 10.0
        wait = t.check("192.0.2.1", "alice")
        self.assertIsNotNone(wait)
        self.assertAlmostEqual(wait or 0, 50.0)  # the oldest failure (t=0) leaves the 60 s window at t=60
        self.assertIsNone(t.check("192.0.2.2", "alice"))  # another source is unaffected
        self.assertIsNone(t.check("192.0.2.1", "bob"))  # so is another user name from the same source

    def test_user_names_compare_case_insensitively(self) -> None:
        t = LoginThrottle(per_name=1, per_source=100, clock=self.clock)
        t.failed("a", "Alice")
        self.assertIsNotNone(t.check("a", "ALICE"))

    def test_checking_records_nothing(self) -> None:
        t = LoginThrottle(per_name=1, per_source=1, clock=self.clock)
        for _ in range(50):
            self.assertIsNone(t.check("a", "alice"))

    def test_success_clears_that_names_failures(self) -> None:
        t = LoginThrottle(per_name=2, per_source=100, clock=self.clock)
        t.failed("a", "alice")
        t.succeeded("a", "alice")
        t.failed("a", "alice")
        self.assertIsNone(t.check("a", "alice"))

    def test_source_cap_over_all_names(self) -> None:
        t = LoginThrottle(per_name=5, per_source=3, clock=self.clock)
        for i in range(3):
            t.failed("192.0.2.9", f"user{i}")
        self.clock.now = 15.0
        self.assertAlmostEqual(t.check("192.0.2.9", "fresh-name") or 0, 45.0)
        self.assertIsNone(t.check("192.0.2.10", "fresh-name"))  # other sources are unaffected
        self.clock.now = 60.0
        self.assertIsNone(t.check("192.0.2.9", "fresh-name"))

    def test_window_expiry(self) -> None:
        t = LoginThrottle(per_name=2, per_source=100, clock=self.clock)
        t.failed("a", "u")
        t.failed("a", "u")
        self.assertIsNotNone(t.check("a", "u"))
        self.clock.advance(60)
        self.assertIsNone(t.check("a", "u"))

    def test_retry_after_is_at_least_one_second(self) -> None:
        t = LoginThrottle(per_name=1, per_source=100, clock=self.clock)
        t.failed("a", "u")
        self.clock.now = 59.9
        self.assertEqual(t.check("a", "u"), 1.0)

    def test_concurrent_backend_checks_are_capped(self) -> None:
        t = LoginThrottle(per_name=5, per_source=5, concurrent=2, clock=self.clock)
        self.assertTrue(t.begin())
        self.assertTrue(t.begin())
        self.assertFalse(t.begin())
        t.end()
        self.assertTrue(t.begin())

    def test_tracked_sources_and_names_are_capped(self) -> None:
        with mock.patch.object(throttle_mod, "MAX_TRACKED_SOURCES", 8), \
                mock.patch.object(throttle_mod, "MAX_TRACKED_NAMES", 8):
            t = LoginThrottle(per_name=5, per_source=10_000, clock=self.clock)
            for i in range(50):
                t.failed(f"198.51.100.{i}", f"u{i}")
            self.assertLessEqual(len(t._sources), 8)
            self.assertLessEqual(len(t._names), 8)
            # The most recently seen sources are the ones kept.
            self.assertIn("198.51.100.49", t._sources)
            self.assertNotIn("198.51.100.0", t._sources)

    def test_default_cap_bounds_memory(self) -> None:
        t = LoginThrottle(per_name=5, per_source=10_000_000, clock=self.clock)
        for i in range(throttle_mod.MAX_TRACKED_NAMES + 200):
            t.failed(f"src-{i % (throttle_mod.MAX_TRACKED_SOURCES + 100)}", f"u{i}")
        self.assertLessEqual(len(t._sources), throttle_mod.MAX_TRACKED_SOURCES)
        self.assertLessEqual(len(t._names), throttle_mod.MAX_TRACKED_NAMES)


class UsernameTests(unittest.TestCase):
    def test_accepts_local_and_realm_names(self) -> None:
        for name in ("admin", "a", "alice.smith", "ops-1", "j_doe", "alice@corp.example", "ALICE@CORP.EXAMPLE",
                     "u" * 64):
            with self.subTest(name=name):
                self.assertEqual(validate_username(name), name)

    def test_rejects_spaces_control_characters_and_long_names(self) -> None:
        for name in ("", " ", "bob smith", " bob", "bob ", "bob\n", "bob\r", "bob\t", "bo\x00b", "bob\x7f",
                     "u" * 65, "-bob", ".bob", "@realm", "bob;id", "bob/../x", "b\u00f6b", "bob\u2028"):
            with self.subTest(name=repr(name)), self.assertRaises(LoginRejected):
                validate_username(name)

    def test_secret_limits(self) -> None:
        self.assertEqual(validate_secret("x"), "x")
        self.assertEqual(validate_secret("p" * 512), "p" * 512)
        for secret in ("", "p" * 513):
            with self.subTest(length=len(secret)), self.assertRaises(LoginRejected):
                validate_secret(secret)


class NetconfBackendTests(unittest.TestCase):
    def test_passes_everything_to_the_opener(self) -> None:
        calls: List[dict] = []
        dev = FakeDevice("alice")

        def opener(**kwargs: Any) -> FakeDevice:
            calls.append(kwargs)
            return dev

        backend = NetconfBackend(host="127.0.0.1", port=830, timeout_s=17, opener=opener)
        self.assertEqual((backend.name, backend.credential), ("netconf", "password"))
        self.assertIs(backend.authenticate("alice@corp.example", "s3cret"), dev)
        self.assertEqual(calls, [{"host": "127.0.0.1", "port": 830, "user": "alice@corp.example",
                                  "password": "s3cret", "timeout_s": 17}])

    def test_bad_input_never_reaches_junos(self) -> None:
        calls: List[dict] = []

        def opener(**kwargs: Any) -> FakeDevice:
            calls.append(kwargs)
            return FakeDevice()

        backend = NetconfBackend(host="127.0.0.1", port=830, timeout_s=17, opener=opener)
        for user, secret in (("bob smith", "pw"), ("alice", ""), ("alice", "p" * 600), ("bob\x00", "pw")):
            with self.subTest(user=repr(user)), self.assertRaises(LoginRejected):
                backend.authenticate(user, secret)
        self.assertEqual(calls, [])

    def test_opener_errors_propagate(self) -> None:
        def opener(**_kwargs: Any) -> FakeDevice:
            raise LoginUnavailable("refused")

        with self.assertRaises(LoginUnavailable):
            NetconfBackend(host="127.0.0.1", port=830, timeout_s=5, opener=opener).authenticate("alice", "pw")


TOKEN = b"T" * 20 + b"0123456789abcdef"


class LabTokenBackendTests(unittest.TestCase):
    def setUp(self) -> None:
        self.made: List[Tuple[str, int]] = []

        def factory(account: str, timeout: int) -> FakeDevice:
            self.made.append((account, timeout))
            return FakeDevice(account)

        self.backend = LabTokenBackend(token=TOKEN, timeout_s=12, account="jwicket-svc", factory=factory)

    def test_right_token_opens_a_session_as_the_daemon_account(self) -> None:
        dev = self.backend.authenticate("", TOKEN.decode())
        self.assertEqual(dev.user, "jwicket-svc")
        self.assertEqual(self.made, [("jwicket-svc", 12)])
        self.assertEqual((self.backend.name, self.backend.credential, self.backend.account),
                         ("lab-token", "token", "jwicket-svc"))
        self.backend.authenticate("ignored-user", "  " + TOKEN.decode() + "\n")  # surrounding whitespace

    def test_wrong_tokens_rejected(self) -> None:
        for presented in ("", "x", TOKEN.decode()[:-1], TOKEN.decode() + "x", TOKEN.decode().lower(), "\u00e9" * 36):
            with self.subTest(presented=presented[:8]), self.assertRaises(LoginRejected) as ctx:
                self.backend.authenticate("", presented)
            self.assertTrue(ctx.exception.public)
        self.assertEqual(self.made, [])

    def test_comparison_is_constant_time(self) -> None:
        with mock.patch("jwicket.auth.backends.hmac.compare_digest", wraps=hmac.compare_digest) as spy:
            self.backend.authenticate("", TOKEN.decode())
            with self.assertRaises(LoginRejected):
                self.backend.authenticate("", "wrong-token")
        self.assertEqual(spy.call_count, 2)

    def test_default_account_is_the_daemon_user(self) -> None:
        backend = LabTokenBackend(token=TOKEN, timeout_s=5, factory=lambda a, t: FakeDevice(a))
        self.assertTrue(backend.account)


if __name__ == "__main__":
    unittest.main()
