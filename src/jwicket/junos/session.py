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

Only RPCs in ``ALLOWED_RPCS`` can be sent, with parameters validated by the caller. No configuration
filter is built from request input. One RPC name is: ``live._read_report`` appends a report type to
``get-sec-log-report-detail-``, but only a type from the fixed ``logs.REPORT_TYPES`` set, and the
result must still be in ``ALLOWED_RPCS``.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import TYPE_CHECKING, Any, Dict, FrozenSet, List, Optional

from jwicket.junos.errors import (
    JunosError,
    LoginUnavailable,
    RpcFailed,
    RpcUnsupported,
    SessionLost,
    classify,
)
from jwicket.junos.xmlutil import Element

if TYPE_CHECKING:
    from typing_extensions import Protocol
else:
    # typing.Protocol is 3.8+; Junos 25.2 and 26.2 ship Python 3.7 (Q-RT-01). At run time nothing
    # checks the protocol, so a plain base class is enough.
    Protocol = object

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
        # Overview health, recorded on SRX4100 25.2R1-S1.4.
        "get-route-engine-information",  # show chassis routing-engine
        "get-performance-summary-information",  # show security monitoring
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
# the rest holds password hashes and secrets that J-Wicket has no reason to read. Within
# [edit security] only the three subtrees the inventory parses are requested, because the rest of it
# holds secrets such as IKE pre-shared keys; within each logical or tenant system only its name and
# the same subtrees, because each one is a whole configuration of its own (protocols, system...).
# That a subtree filter returns "the key plus these children" of every list entry, with the entry's
# inactive attribute, is J-Wicket's reading of RFC 6241 subtree filtering as Junos implements it,
# confirmed per release by qualification Q-REL-01. From [edit system] only two leaves are read: the
# configured time zone (one leaf, owner decision OD-05) and the outbound-ssh clients (central
# management). Reading time-zone uses the same RPC and, inferred, the same system view permission the
# outbound-ssh part already needs; no new RPC.
_SCOPE_SECURITY = "<security><policies/><zones/><address-book/></security>"
INVENTORY_FILTER = (
    "<configuration>"
    f"{_SCOPE_SECURITY}"
    "<applications/>"
    f"<logical-systems><name/>{_SCOPE_SECURITY}<applications/></logical-systems>"
    f"<tenants><name/>{_SCOPE_SECURITY}<applications/></tenants>"
    # Only the client fields the central-management card shows. Asking for the whole client would also
    # fetch its $9$ secret (reversible) and device-id, which J-Wicket never needs (seen on SRX4100
    # 25.2R1-S1.4; Junos honours the narrower filter there).
    "<system><time-zone/>"
    "<services><outbound-ssh><client><name/><services/><servers/></client></outbound-ssh></services></system>"
    "<chassis><high-availability/></chassis>"
    "</configuration>"
)
# Where logs are: syslog files and the security log settings (Spec 004).
LOGS_FILTER = "<configuration><system><syslog/></system><security><log/></security></configuration>"
# Used when a device rejects the full filter (for example a release without tenants).
INVENTORY_FILTER_MINIMAL = f"<configuration>{_SCOPE_SECURITY}<applications/></configuration>"


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
            # Only the password the operator typed may sign them in. By default PyEZ and ncclient
            # first offer every key in the daemon account's ~/.ssh (look_for_keys) and read its
            # ~/.ssh/config, whose Port, HostName, IdentityFile and ProxyCommand would override the
            # validated loopback address and port. Neither is wanted here; no key file is passed, and
            # PyEZ does not use an SSH agent when a password is given. PyEZ 2.8.3 honours both
            # keywords (jnpr/junos/device.py, Device.__init__ and open). Older PyEZ ignores keyword
            # arguments it does not know, so qualification Q-AUTH-01 checks on each on-box PyEZ
            # that a wrong password is refused even when the daemon account holds an accepted key.
            dev = device_cls(
                host=host,
                port=port,
                user=user,
                passwd=password,
                gather_facts=False,
                conn_open_timeout=timeout_s,
                look_for_keys=False,
                ssh_config=os.devnull,
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


def open_config(
    session: DeviceSession, warnings: List[str], *, report: Optional[Dict[str, str]] = None
) -> Element:
    """Read the inventory subtree; fall back to the minimal filter if the device rejects the full one.
    When ``report`` is given, ``report["filter"]`` is set to the filter that was used: "full" or
    "minimal" (the minimal one reads no system or chassis settings)."""
    try:
        found = session.get_configuration(INVENTORY_FILTER)
    except RpcUnsupported as exc:
        LOG.warning("full inventory filter rejected (%s); retrying with security and applications only", exc)
        warnings.append(
            "The device rejected J-Wicket's full configuration filter, so logical systems, tenant systems, "
            "central-management connections, Multinode HA settings and the time zone are not shown."
        )
        found = session.get_configuration(INVENTORY_FILTER_MINIMAL)
        if report is not None:
            report["filter"] = "minimal"
        return found
    if report is not None:
        report["filter"] = "full"
    return found
