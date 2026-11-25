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

    def test_store_exposes_its_limits(self) -> None:
        store = SessionStore(idle_s=900, absolute_s=3600, max_sessions=4, max_per_user=2, clock=self.clock)
        self.assertEqual((store.idle_s, store.absolute_s, store.max_per_user), (900, 3600, 2))

    def test_created_wall_is_the_wall_clock(self) -> None:
        store = SessionStore(idle_s=900, absolute_s=3600, max_sessions=4, clock=self.clock,
                             wall_clock=lambda: 1_795_500_000.0)
        _token, sess = store.create(user="a", backend="netconf", device=FakeDevice("a"), source="s")
        self.assertEqual((sess.created, sess.created_wall), (1000.0, 1_795_500_000.0))

    def test_failing_device_close_does_not_break_the_store(self) -> None:
        dev = ExplodingDevice("x")
        token, _ = self.store.create(user="x", backend="netconf", device=dev, source="127.0.0.1")
        with self.assertLogs("jwicket.sessions", level="WARNING") as logged:
            self.assertIsNotNone(self.store.remove(token))
        self.assertTrue(any("failed" in line for line in logged.output))
        self.assertEqual(dev.closed, 1)
        self.assertEqual(self.store.count(), 0)


class BackgroundTouchTests(unittest.TestCase):
    """BE-01 (B-4): a background request checks expiry but never refreshes the idle clock."""

    def setUp(self) -> None:
        self.clock = FakeClock()
        self.store = SessionStore(idle_s=900, absolute_s=3600, max_sessions=4, clock=self.clock)
        self.device = FakeDevice("alice")
        self.token, self.sess = self.store.create(user="alice", backend="netconf", device=self.device, source="s")

    def test_background_get_does_not_extend(self) -> None:
        self.clock.advance(600)
        self.assertIs(self.store.get(self.token, touch=False), self.sess)
        self.assertEqual(self.sess.last_seen, 1000.0)
        self.clock.advance(301)
        self.assertIsNone(self.store.get(self.token, touch=False))
        self.assertEqual(self.device.closed, 1)

    def test_background_get_still_refuses_an_expired_session(self) -> None:
        self.clock.advance(901)
        self.assertIsNone(self.store.get(self.token, touch=False))
        self.assertIsNone(self.store.get(self.token))  # and a foreground request cannot revive it
        self.assertEqual(self.device.closed, 1)

    def test_foreground_get_extends(self) -> None:
        self.clock.advance(600)
        self.assertIs(self.store.get(self.token), self.sess)
        self.assertEqual(self.sess.last_seen, 1600.0)
        self.clock.advance(800)
        self.assertIs(self.store.get(self.token, touch=False), self.sess)
        self.clock.advance(101)
        self.assertIsNone(self.store.get(self.token))

    def test_background_never_outlives_the_absolute_limit(self) -> None:
        for _ in range(4):
            self.clock.advance(800)
            self.assertIsNotNone(self.store.get(self.token))
        self.clock.advance(401)  # 3601 s after sign-in
        self.assertIsNone(self.store.get(self.token, touch=False))


class TombstoneTests(unittest.TestCase):
    """BE-02, BE-03 (B-5): why a session ended, kept briefly and boundedly, never as an authenticator."""

    def setUp(self) -> None:
        self.clock = FakeClock()
        self.wall = FakeClock(1_795_500_000.0)
        self.ended: List[Tuple[str, str]] = []
        self.store = SessionStore(
            idle_s=900, absolute_s=3600, max_sessions=4, max_per_user=1, clock=self.clock, wall_clock=self.wall,
            on_end=lambda sess, reason: self.ended.append((sess.user, reason)),
        )

    def create(self, user: str = "alice", key: Any = "") -> Tuple[str, Any]:
        token, sess = self.store.create(user=user, backend="netconf", device=FakeDevice(user), source="s",
                                        user_key=(user if key == "" else key))
        return token, sess

    def advance(self, seconds: float) -> None:
        self.clock.advance(seconds)
        self.wall.advance(seconds)

    def test_each_end_path_leaves_its_reason(self) -> None:
        replaced, _ = self.create("alice")
        self.create("alice")  # the same person signs in again elsewhere
        idle, _ = self.create("bob")
        signed_out, _ = self.create("carol")
        lost, lost_sess = self.create("dave")
        self.store.remove(signed_out)
        self.store.drop(lost_sess, "device session lost")
        self.advance(901)
        self.assertIsNone(self.store.get(idle))
        got = {name: self.store.ended(token) for name, token in
               (("replaced", replaced), ("idle", idle), ("signed-out", signed_out), ("session-lost", lost))}
        for reason, ended in got.items():
            with self.subTest(reason=reason):
                self.assertIsNotNone(ended)
                assert ended is not None
                self.assertEqual(ended.reason, reason)
        self.assertEqual(got["replaced"].at_wall, 1_795_500_000.0)  # type: ignore[union-attr]
        self.assertEqual(got["idle"].at_wall, 1_795_500_901.0)  # type: ignore[union-attr]

    def test_absolute(self) -> None:
        token, _ = self.create()
        for _ in range(4):
            self.advance(800)
            self.assertIsNotNone(self.store.get(token))
        self.advance(401)
        self.assertIsNone(self.store.get(token))
        ended = self.store.ended(token)
        self.assertEqual(ended.reason if ended else None, "absolute")

    def test_reap_leaves_the_reason_too(self) -> None:
        token, _ = self.create()
        self.advance(901)
        self.assertEqual(len(self.store.reap()), 1)
        ended = self.store.ended(token)
        self.assertEqual(ended.reason if ended else None, "idle")

    def test_new_sign_in_and_shutdown_leave_none(self) -> None:
        mine, _ = self.create("alice")
        self.store.remove(mine, reason="new-sign-in")
        other, _ = self.create("bob")
        self.store.close_all()
        self.assertIsNone(self.store.ended(mine))
        self.assertIsNone(self.store.ended(other))
        self.assertEqual(self.ended, [("alice", "new-sign-in"), ("bob", "shutdown")])

    def test_unknown_token_and_no_token(self) -> None:
        self.create()
        for token in (None, "", "never-issued"):
            with self.subTest(token=token):
                self.assertIsNone(self.store.ended(token))

    def test_a_tombstone_never_authenticates(self) -> None:
        token, _ = self.create()
        self.store.remove(token)
        self.assertIsNotNone(self.store.ended(token))
        self.assertIsNone(self.store.get(token))
        self.assertIsNone(self.store.get(token, touch=False))
        self.assertIsNone(self.store.remove(token))
        self.assertEqual(self.store.count(), 0)

    def test_tombstones_hold_only_a_reason_and_a_time(self) -> None:
        token, sess = self.create("alice")
        self.store.remove(token)
        ended = self.store.ended(token)
        assert ended is not None
        self.assertEqual(set(vars(ended)) if hasattr(ended, "__dict__") else set(ended.__dataclass_fields__),
                         {"reason", "at_wall"})
        dumped = repr(self.store._ended)
        for value in ("alice", "s", token, sess.csrf):
            self.assertNotIn(f"'{value}'", dumped)

    def test_size_stays_capped(self) -> None:
        store = SessionStore(idle_s=900, absolute_s=3600, max_sessions=4, max_per_user=1, clock=self.clock,
                             wall_clock=self.wall)
        first = None
        for _ in range(1000):
            token, _ = store.create(user="alice", backend="netconf", device=FakeDevice("alice"), source="s",
                                    user_key="alice")
            first = first or token
        self.assertEqual(store.tombstones(), 64)  # max(64, 4 * max_sessions)
        self.assertIsNone(store.ended(first))  # the oldest went first
        big = SessionStore(idle_s=900, absolute_s=3600, max_sessions=40, max_per_user=1, clock=self.clock,
                           wall_clock=self.wall)
        for _ in range(1000):
            big.create(user="a", backend="netconf", device=FakeDevice("a"), source="s", user_key="a")
        self.assertEqual(big.tombstones(), 160)

    def test_old_tombstones_are_pruned(self) -> None:
        token, _ = self.create("alice")
        self.store.remove(token)
        self.advance(3601)
        self.assertIsNone(self.store.ended(token))
        other, _ = self.create("bob")
        self.store.remove(other)  # a write prunes what is older than absolute_s
        self.assertEqual(self.store.tombstones(), 1)

    def test_on_end_for_idle_absolute_and_shutdown(self) -> None:
        idle, _ = self.create("alice")
        self.advance(901)
        self.assertIsNone(self.store.get(idle))
        self.assertIsNone(self.store.get(idle))  # already ended: no second call
        busy, _ = self.create("bob")
        for _ in range(4):
            self.advance(800)
            self.store.get(busy)
        self.advance(401)
        self.store.reap()
        self.store.reap()
        self.create("carol")
        self.store.close_all()
        self.assertEqual(self.ended, [("alice", "idle"), ("bob", "absolute"), ("carol", "shutdown")])

    def test_a_failing_hook_does_not_break_the_store(self) -> None:
        def explode(_sess: Any, _reason: str) -> None:
            raise RuntimeError("audit trail unavailable")

        self.store.on_end = explode
        token, _ = self.create()
        with self.assertLogs("jwicket.sessions", level="WARNING"):
            self.assertIsNotNone(self.store.remove(token))
        self.assertEqual(self.store.count(), 0)


class SessionLimitTests(unittest.TestCase):
    """BE-04 (B-7): the refusal at the cap carries bounds computed under the store lock."""

    def test_bounds(self) -> None:
        clock = FakeClock()
        store = SessionStore(idle_s=900, absolute_s=3600, max_sessions=2, clock=clock)
        store.create(user="a", backend="netconf", device=FakeDevice("a"), source="s")
        clock.advance(100)
        token_b, _ = store.create(user="b", backend="netconf", device=FakeDevice("b"), source="s")
        clock.advance(500)
        store.get(token_b)  # b was active just now
        with self.assertRaises(SessionLimit) as ctx:
            store.create(user="c", backend="netconf", device=FakeDevice("c"), source="s")
        refusal = ctx.exception
        self.assertEqual((refusal.open_count, refusal.max_sessions), (2, 2))
        self.assertEqual(refusal.slot_free_by_s, 3000)  # a: 3600 after its sign-in at t=0, now t=600
        self.assertEqual(refusal.slot_may_free_in_s, 300)  # a: idle since t=0, 900 s, now t=600

    def test_refusal_names_no_one(self) -> None:
        clock = FakeClock()
        store = SessionStore(idle_s=900, absolute_s=3600, max_sessions=1, clock=clock)
        store.create(user="alice-secret-name", backend="netconf", device=FakeDevice("a"), source="192.0.2.77")
        with self.assertRaises(SessionLimit) as ctx:
            store.create(user="bob", backend="netconf", device=FakeDevice("b"), source="s")
        refusal = ctx.exception
        self.assertNotIn("alice", str(refusal))
        self.assertNotIn("192.0.2.77", str(refusal))
        for value in (refusal.open_count, refusal.max_sessions, refusal.slot_free_by_s, refusal.slot_may_free_in_s):
            self.assertIsInstance(value, int)


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
