"""junos/errors.classify: PyEZ/ncclient exceptions map to a small, closed set of kinds."""

from __future__ import annotations

import unittest
from typing import Type

from jwicket.junos import errors as E


def fake(name: str) -> Type[Exception]:
    """An exception class named like a PyEZ one, without importing PyEZ."""
    return type(name, (Exception,), {})


class ClassifyTests(unittest.TestCase):
    def check(self, exc: BaseException, cls: Type[E.JunosError], kind: str) -> E.JunosError:
        got = E.classify(exc)
        self.assertIsInstance(got, cls)
        self.assertEqual(got.kind, kind)
        self.assertTrue(got.public)
        self.assertIn(type(exc).__name__, str(got))  # the log text says what failed
        return got

    def test_connect_auth_error_is_rejected(self) -> None:
        self.check(fake("ConnectAuthError")("bad password"), E.LoginRejected, "rejected")

    def test_connect_failures_are_unavailable(self) -> None:
        for name in ("ConnectRefusedError", "ConnectTimeoutError", "ConnectUnknownHostError", "ConnectError"):
            with self.subTest(name=name):
                self.check(fake(name)("127.0.0.1:830"), E.LoginUnavailable, "unavailable")

    def test_connect_closed_is_session_lost(self) -> None:
        self.check(fake("ConnectClosedError")("closed"), E.SessionLost, "session-lost")

    def test_permission_error_class(self) -> None:
        self.check(fake("PermissionError")("nope"), E.RpcDenied, "denied")
        self.check(PermissionError("builtin"), E.RpcDenied, "denied")

    def test_rpc_timeout(self) -> None:
        got = self.check(fake("RpcTimeoutError")("30 s"), E.RpcFailed, "failed")
        self.assertIn("too long", got.public)

    def test_rpc_error_texts(self) -> None:
        rpc_error = fake("RpcError")
        for text, cls, kind in (
            ("error: permission denied", E.RpcDenied, "denied"),
            ("user is not authorized to perform this", E.RpcDenied, "denied"),
            ("chassis cluster is not enabled", E.RpcUnsupported, "unsupported"),
            ("syntax error, expecting <command>", E.RpcUnsupported, "unsupported"),
            ("unknown command", E.RpcUnsupported, "unsupported"),
            ("something unexpected happened", E.RpcFailed, "failed"),
        ):
            with self.subTest(text=text):
                self.check(rpc_error(text), cls, kind)

    def test_generic_exception_is_failed(self) -> None:
        self.check(RuntimeError("boom"), E.RpcFailed, "failed")
        self.check(ValueError(""), E.RpcFailed, "failed")

    def test_junos_errors_pass_through(self) -> None:
        original = E.RpcDenied("already classified", "custom public text")
        self.assertIs(E.classify(original), original)

    def test_public_message_does_not_echo_device_text(self) -> None:
        got = E.classify(fake("RpcError")("internal detail 0xdeadbeef /var/tmp/secret-path"))
        self.assertNotIn("0xdeadbeef", got.public)
        self.assertNotIn("secret-path", got.public)

    def test_kinds_are_the_closed_set(self) -> None:
        kinds = {cls.kind for cls in (E.JunosError, E.RpcDenied, E.RpcUnsupported, E.RpcFailed, E.LoginRejected,
                                      E.LoginUnavailable, E.SessionLost)}
        self.assertEqual(kinds, {"failed", "denied", "unsupported", "rejected", "unavailable", "session-lost"})


if __name__ == "__main__":
    unittest.main()
