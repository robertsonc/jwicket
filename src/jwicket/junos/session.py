"""Device sessions: the only code that sends anything to Junos.

Two real implementations and one fake:

* ``PyEzUserSession`` opens a NETCONF session to the device's own loopback address *as the signed-in
  operator*. Junos checks the password (local, RADIUS or TACACS+) and every RPC then runs with that
  operator's login class. This is the least-privilege design from the spike report; whether on-box
  Python can do it is qualification test Q-AUTH-01, not yet run on a device.
* ``PyEzLocalSession`` uses on-box PyEZ ``Device()`` with no arguments, which runs as the account named
  in the extension-service ``username`` statement. That is what the spike proved (T5). It is used only
  by the loopback-only ``lab-token`` backend, and the UI says so on every screen.
* ``jwicket.fixtures.FixtureSession`` (not shipped to devices) replays recorded or synthetic
  replies for development and tests.

Only RPCs in ``ALLOWED_RPCS`` can be sent, with parameters validated by the caller. No code path
builds an RPC name or a configuration filter from request input.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict, FrozenSet, Protocol

from jwicket.junos.errors import (
    JunosError,
    LoginUnavailable,
    RpcFailed,
    RpcUnsupported,
    SessionLost,
    classify,
)
from jwicket.junos.xmlutil import Element

LOG = logging.getLogger("jwicket.junos")

# Read-only RPCs J-Wicket may send. Adding one is a reviewed change (see CONTRIBUTING.md).
ALLOWED_RPCS: FrozenSet[str] = frozenset(
    {
        "get-software-information",
        "get-chassis-cluster-status",
        # Spec 004. Reply formats are confirmed per release by Q-REL-01.
        "get-flow-session-information",  # show security flow session [filters] / summary
        "get-log",  # show log <file>
        "get-security-log-information",  # show security log (event-mode RE buffer)
    }
    | {f"get-sec-log-report-detail-{t}" for t in (
        # show security log report in-detail <type> (on-box reporting database)
        "session-all", "session-close", "session-create", "session-deny",
        "screen", "idp-all", "utm-all", "ipsec-vpn", "threat", "all",
    )}
)

# Committed database, with group inheritance expanded and annotated with the source group.
CONFIG_OPTIONS: Dict[str, str] = {"database": "committed", "inherit": "inherit", "groups": "groups"}

# The narrowest configuration that the policy inventory needs. Never the whole configuration:
# the rest holds password hashes and secrets that J-Wicket has no reason to read.
INVENTORY_FILTER = (
    "<configuration>"
    "<security/>"
    "<applications/>"
    "<logical-systems/>"
    "<tenants/>"
    "<system><services><outbound-ssh/></services></system>"
    "<chassis><high-availability/></chassis>"
    "</configuration>"
)
# Where logs are: syslog files and the security log settings (Spec 004).
LOGS_FILTER = "<configuration><system><syslog/></system><security><log/></security></configuration>"
# Used when a device rejects the full filter (for example a release without tenants).
INVENTORY_FILTER_MINIMAL = "<configuration><security/><applications/></configuration>"


class DeviceSession(Protocol):
    """What the read path needs from a connection to the local device."""

    @property
    def user(self) -> str: ...

    @property
    def backend(self) -> str: ...

    def get_configuration(self, filter_xml: str) -> Element: ...

    def rpc(self, name: str, **params: Any) -> Element: ...

    def close(self) -> None: ...


def _import_pyez() -> Any:
    try:
        from jnpr.junos import Device
    except ImportError as exc:
        raise LoginUnavailable(f"PyEZ is not importable: {exc}", "PyEZ is not available on this system.") from exc
    return Device


def check_rpc(name: str) -> None:
    if name not in ALLOWED_RPCS:
        raise RpcFailed(f"RPC {name!r} is not on the allowlist")


class PyEzUserSession:
    """A NETCONF session held open for one signed-in operator. One RPC at a time."""

    backend = "netconf"

    def __init__(self, dev: Any, user: str) -> None:
        self._dev = dev
        self._user = user
        self._lock = threading.Lock()
        self._closed = False  # no further RPCs will be sent
        self._released = False  # the PyEZ Device has been closed

    @property
    def user(self) -> str:
        return self._user

    @classmethod
    def open(cls, *, host: str, port: int, user: str, password: str, timeout_s: int) -> PyEzUserSession:
        device_cls = _import_pyez()
        try:
            dev = device_cls(
                host=host,
                port=port,
                user=user,
                passwd=password,
                gather_facts=False,
                conn_open_timeout=timeout_s,
            )
            dev.open(gather_facts=False)
            dev.timeout = timeout_s
        except Exception as exc:
            raise classify(exc) from exc
        return cls(dev, user)

    def _call(self, fn: Any) -> Element:
        if self._closed:
            raise SessionLost("session already closed")
        with self._lock:
            try:
                return fn()
            except Exception as exc:
                err = classify(exc)
                if isinstance(err, SessionLost):
                    self._closed = True
                raise err from exc

    def get_configuration(self, filter_xml: str) -> Element:
        return self._call(lambda: self._dev.rpc.get_config(filter_xml=filter_xml, options=dict(CONFIG_OPTIONS)))

    def rpc(self, name: str, **params: Any) -> Element:
        check_rpc(name)
        method = name.replace("-", "_")
        return self._call(lambda: getattr(self._dev.rpc, method)(**params))

    def close(self) -> None:
        self._closed = True
        if self._released:
            return
        self._released = True
        # Close even after a transport loss: the Device may still hold ncclient threads and sockets.
        try:
            self._dev.close()
        except Exception as exc:  # noqa: BLE001 - closing a dead session must not raise
            LOG.debug("closing device session for %s: %r", self._user, exc)


class PyEzLocalSession:
    """On-box ``Device()`` as the daemon's own Junos account. Lab-token backend only."""

    backend = "lab-token"

    def __init__(self, account_label: str, timeout_s: int) -> None:
        self._label = account_label
        self._timeout = timeout_s
        self._lock = threading.Lock()

    @property
    def user(self) -> str:
        return self._label

    def _with_device(self, fn: Any) -> Element:
        device_cls = _import_pyez()
        with self._lock:
            try:
                # No arguments = the local device, as the extension-service account (spike T5).
                with device_cls() as dev:
                    dev.timeout = self._timeout
                    return fn(dev)
            except JunosError:
                raise
            except Exception as exc:
                raise classify(exc) from exc

    def get_configuration(self, filter_xml: str) -> Element:
        return self._with_device(lambda dev: dev.rpc.get_config(filter_xml=filter_xml, options=dict(CONFIG_OPTIONS)))

    def rpc(self, name: str, **params: Any) -> Element:
        check_rpc(name)
        method = name.replace("-", "_")
        return self._with_device(lambda dev: getattr(dev.rpc, method)(**params))

    def close(self) -> None:
        return None


def open_config(session: DeviceSession, warnings: list[str]) -> Element:
    """Read the inventory subtree; fall back to the minimal filter if the device rejects the full one."""
    try:
        return session.get_configuration(INVENTORY_FILTER)
    except RpcUnsupported as exc:
        LOG.warning("full inventory filter rejected (%s); retrying with security and applications only", exc)
        warnings.append(
            "The device rejected J-Wicket's full configuration filter, so logical systems, tenant systems, "
            "central-management connections and Multinode HA settings are not shown."
        )
        return session.get_configuration(INVENTORY_FILTER_MINIMAL)
