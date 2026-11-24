"""junos/session.py: the only code that talks to Junos. Allowlisted RPCs, least data, session loss."""

from __future__ import annotations

import sys
import types
import unittest
from typing import Any, Dict, List, Optional, Tuple
from unittest import mock

from helpers import xml

from jwicket.junos import session as S
from jwicket.junos.errors import LoginRejected, LoginUnavailable, RpcDenied, RpcFailed, RpcUnsupported, SessionLost
from jwicket.junos.xmlutil import child_tags, kid, path


def fake_exc(name: str, text: str = "") -> Exception:
    return type(name, (Exception,), {})(text)


class FakeRpc:
    """Stands in for PyEZ's ``dev.rpc``: any attribute is a callable RPC."""

    def __init__(self, handlers: Optional[Dict[str, Any]] = None) -> None:
        self.handlers: Dict[str, Any] = dict(handlers or {})
        self.calls: List[Tuple[str, Dict[str, Any]]] = []

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)

        def call(**kwargs: Any) -> Any:
            self.calls.append((name, kwargs))
            handler = self.handlers.get(name)
            if isinstance(handler, BaseException):
                raise handler
            return handler if handler is not None else xml("<ok/>")

        return call


class FakeDev:
    def __init__(self, handlers: Optional[Dict[str, Any]] = None, close_error: Optional[Exception] = None) -> None:
        self.rpc = FakeRpc(handlers)
        self.close_calls = 0
        self.close_error = close_error
        self.timeout: Optional[int] = None

    def close(self) -> None:
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error


def fake_pyez(device_cls: Any) -> Dict[str, Any]:
    jnpr = types.ModuleType("jnpr")
    junos = types.ModuleType("jnpr.junos")
    junos.Device = device_cls  # type: ignore[attr-defined]
    jnpr.junos = junos  # type: ignore[attr-defined]
    return {"jnpr": jnpr, "jnpr.junos": junos}


class AllowlistTests(unittest.TestCase):
    def test_allowlist_is_read_only(self) -> None:
        self.assertIsInstance(S.ALLOWED_RPCS, frozenset)
        for name in S.ALLOWED_RPCS:
            with self.subTest(name=name):
                self.assertTrue(name.startswith("get-"), name)
        for name in ("load-configuration", "commit-configuration", "lock-configuration", "request-shell-execute",
                     "request-reboot", "clear-security-flow-session", "get-configuration", "open-configuration"):
            self.assertNotIn(name, S.ALLOWED_RPCS)

    def test_check_rpc(self) -> None:
        S.check_rpc("get-software-information")
        for name in ("commit-configuration", "GET-SOFTWARE-INFORMATION", "get-software-information ", "", "get_log"):
            with self.subTest(name=name), self.assertRaises(RpcFailed):
                S.check_rpc(name)


class FilterTests(unittest.TestCase):
    def test_inventory_filter_is_narrow(self) -> None:
        root = xml(S.INVENTORY_FILTER)
        self.assertEqual(child_tags(root),
                         ["security", "applications", "logical-systems", "tenants", "system", "chassis"])
        system = kid(root, "system")
        self.assertEqual(child_tags(system), ["services"])  # never the whole system tree (login, passwords)
        self.assertEqual(child_tags(path(system, "services")), ["outbound-ssh"])
        self.assertEqual(child_tags(kid(root, "chassis")), ["high-availability"])

    def test_minimal_filter(self) -> None:
        self.assertEqual(child_tags(xml(S.INVENTORY_FILTER_MINIMAL)), ["security", "applications"])

    def test_config_options_committed_with_inheritance(self) -> None:
        self.assertEqual(S.CONFIG_OPTIONS, {"database": "committed", "inherit": "inherit", "groups": "groups"})


class UserSessionTests(unittest.TestCase):
    def test_disallowed_rpc_never_reaches_the_device(self) -> None:
        dev = FakeDev()
        sess = S.PyEzUserSession(dev, "alice")
        for name in ("commit-configuration", "load-configuration", "request-shell-execute"):
            with self.subTest(name=name), self.assertRaises(RpcFailed):
                sess.rpc(name)
        self.assertEqual(dev.rpc.calls, [])

    def test_allowed_rpc_is_sent_with_params(self) -> None:
        reply = xml("<software-information/>")
        dev = FakeDev({"get_software_information": reply})
        sess = S.PyEzUserSession(dev, "alice")
        self.assertIs(sess.rpc("get-software-information"), reply)
        sess.rpc("get-log", filename="messages")
        self.assertEqual(dev.rpc.calls, [("get_software_information", {}), ("get_log", {"filename": "messages"})])
        self.assertEqual((sess.user, sess.backend), ("alice", "netconf"))

    def test_get_configuration_reads_committed_inherited(self) -> None:
        dev = FakeDev({"get_config": xml("<configuration/>")})
        sess = S.PyEzUserSession(dev, "alice")
        sess.get_configuration(S.INVENTORY_FILTER)
        name, kwargs = dev.rpc.calls[0]
        self.assertEqual(name, "get_config")
        self.assertEqual(kwargs["filter_xml"], S.INVENTORY_FILTER)
        self.assertEqual(kwargs["options"], {"database": "committed", "inherit": "inherit", "groups": "groups"})
        self.assertIsNot(kwargs["options"], S.CONFIG_OPTIONS)

    def test_connect_closed_marks_session_lost(self) -> None:
        dev = FakeDev({"get_software_information": fake_exc("ConnectClosedError", "transport closed")})
        sess = S.PyEzUserSession(dev, "alice")
        with self.assertRaises(SessionLost):
            sess.rpc("get-software-information")
        calls_before = len(dev.rpc.calls)
        with self.assertRaises(SessionLost):
            sess.rpc("get-software-information")
        with self.assertRaises(SessionLost):
            sess.get_configuration(S.INVENTORY_FILTER)
        self.assertEqual(len(dev.rpc.calls), calls_before)  # nothing more was sent
        sess.close()
        sess.close()
        self.assertLessEqual(dev.close_calls, 1)

    def test_other_errors_do_not_end_the_session(self) -> None:
        dev = FakeDev({"get_chassis_cluster_status": fake_exc("RpcError", "error: permission denied")})
        sess = S.PyEzUserSession(dev, "alice")
        with self.assertRaises(RpcDenied):
            sess.rpc("get-chassis-cluster-status")
        sess.rpc("get-software-information")
        self.assertEqual(dev.rpc.calls[-1][0], "get_software_information")

    def test_close_is_idempotent_and_never_raises(self) -> None:
        dev = FakeDev(close_error=fake_exc("ConnectClosedError", "already gone"))
        sess = S.PyEzUserSession(dev, "alice")
        sess.close()
        sess.close()
        self.assertEqual(dev.close_calls, 1)
        with self.assertRaises(SessionLost):
            sess.rpc("get-software-information")

    def test_open_passes_credentials_to_pyez_and_classifies_failures(self) -> None:
        created: List[Any] = []

        class Device:
            def __init__(self, **kwargs: Any) -> None:
                self.kwargs = kwargs
                self.opened: Optional[Dict[str, Any]] = None
                self.timeout: Optional[int] = None
                created.append(self)

            def open(self, **kwargs: Any) -> None:
                if self.kwargs["passwd"] == "wrong":
                    raise fake_exc("ConnectAuthError", "auth failed")
                if self.kwargs["passwd"] == "down":
                    raise fake_exc("ConnectRefusedError", "refused")
                self.opened = kwargs

        with mock.patch.dict(sys.modules, fake_pyez(Device)):
            sess = S.PyEzUserSession.open(host="127.0.0.1", port=830, user="alice", password="pw", timeout_s=30)
            self.assertEqual(sess.user, "alice")
            dev = created[-1]
            self.assertEqual(dev.kwargs, {"host": "127.0.0.1", "port": 830, "user": "alice", "passwd": "pw",
                                          "gather_facts": False, "conn_open_timeout": 30})
            self.assertEqual(dev.opened, {"gather_facts": False})
            self.assertEqual(dev.timeout, 30)
            with self.assertRaises(LoginRejected):
                S.PyEzUserSession.open(host="127.0.0.1", port=830, user="alice", password="wrong", timeout_s=30)
            with self.assertRaises(LoginUnavailable):
                S.PyEzUserSession.open(host="127.0.0.1", port=830, user="alice", password="down", timeout_s=30)

    def test_open_without_pyez_is_unavailable(self) -> None:
        with mock.patch.dict(sys.modules, {"jnpr": None, "jnpr.junos": None}), self.assertRaises(LoginUnavailable):
            S.PyEzUserSession.open(host="127.0.0.1", port=830, user="alice", password="pw", timeout_s=30)


class LocalSessionTests(unittest.TestCase):
    def make_device_cls(self, handlers: Optional[Dict[str, Any]] = None) -> Any:
        log: Dict[str, Any] = {"init": [], "enter": 0, "exit": 0, "timeouts": [], "rpc": FakeRpc(handlers)}

        class Device:
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                log["init"].append((args, kwargs))
                self.rpc = log["rpc"]
                self._timeout: Optional[int] = None

            @property
            def timeout(self) -> Optional[int]:
                return self._timeout

            @timeout.setter
            def timeout(self, value: int) -> None:
                log["timeouts"].append(value)
                self._timeout = value

            def __enter__(self) -> Any:
                log["enter"] += 1
                return self

            def __exit__(self, *exc: Any) -> None:
                log["exit"] += 1

        Device.log = log  # type: ignore[attr-defined]
        return Device

    def test_disallowed_rpc_refused_before_pyez_is_touched(self) -> None:
        sess = S.PyEzLocalSession("jwicket", 30)
        with mock.patch.dict(sys.modules, {"jnpr": None, "jnpr.junos": None}), self.assertRaises(RpcFailed):
            sess.rpc("commit-configuration")

    def test_allowed_rpc_runs_on_local_device_as_daemon_account(self) -> None:
        device_cls = self.make_device_cls()
        sess = S.PyEzLocalSession("jwicket", 25)
        with mock.patch.dict(sys.modules, fake_pyez(device_cls)):
            sess.rpc("get-software-information")
            sess.get_configuration(S.INVENTORY_FILTER)
        log = device_cls.log
        self.assertEqual(log["init"], [((), {}), ((), {})])  # Device() with no arguments
        self.assertEqual(log["timeouts"], [25, 25])
        self.assertEqual((log["enter"], log["exit"]), (2, 2))
        self.assertEqual([c[0] for c in log["rpc"].calls], ["get_software_information", "get_config"])
        self.assertEqual(log["rpc"].calls[1][1]["options"], S.CONFIG_OPTIONS)
        self.assertEqual((sess.user, sess.backend), ("jwicket", "lab-token"))
        sess.close()

    def test_errors_are_classified(self) -> None:
        device_cls = self.make_device_cls({"get_software_information": fake_exc("ConnectClosedError", "x"),
                                           "get_chassis_cluster_status": RpcUnsupported("already ours")})
        sess = S.PyEzLocalSession("jwicket", 25)
        with mock.patch.dict(sys.modules, fake_pyez(device_cls)):
            with self.assertRaises(SessionLost):
                sess.rpc("get-software-information")
            with self.assertRaises(RpcUnsupported):
                sess.rpc("get-chassis-cluster-status")


class FakeConfigSession:
    def __init__(self, full: Any) -> None:
        self.full = full
        self.filters: List[str] = []

    def get_configuration(self, filter_xml: str) -> Any:
        self.filters.append(filter_xml)
        if filter_xml == S.INVENTORY_FILTER and isinstance(self.full, BaseException):
            raise self.full
        return xml("<configuration/>")


class OpenConfigTests(unittest.TestCase):
    def test_full_filter_used_first(self) -> None:
        sess = FakeConfigSession(None)
        warnings: List[str] = []
        S.open_config(sess, warnings)  # type: ignore[arg-type]
        self.assertEqual(sess.filters, [S.INVENTORY_FILTER])
        self.assertEqual(warnings, [])

    def test_falls_back_to_minimal_filter_with_a_warning(self) -> None:
        sess = FakeConfigSession(RpcUnsupported("syntax error: tenants"))
        warnings: List[str] = []
        with self.assertLogs("jwicket.junos", level="WARNING"):
            got = S.open_config(sess, warnings)  # type: ignore[arg-type]
        self.assertEqual(got.tag, "configuration")
        self.assertEqual(sess.filters, [S.INVENTORY_FILTER, S.INVENTORY_FILTER_MINIMAL])
        self.assertEqual(len(warnings), 1)
        self.assertIn("logical systems", warnings[0])

    def test_denied_does_not_fall_back(self) -> None:
        sess = FakeConfigSession(RpcDenied("no"))
        warnings: List[str] = []
        with self.assertRaises(RpcDenied):
            S.open_config(sess, warnings)  # type: ignore[arg-type]
        self.assertEqual(sess.filters, [S.INVENTORY_FILTER])
        self.assertEqual(warnings, [])


if __name__ == "__main__":
    unittest.main()
