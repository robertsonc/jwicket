"""How the workstation installer talks to a device (Spec 006 sections 6.2, 7.5, 8.10 and 12). LAB ONLY.

Three channels to the same device, the first two over SSH and verified against one trusted host key
(INV-09):

* NETCONF, through PyEZ (``junos-eznc`` 2.8.3, imported lazily: nothing here needs it until a device is
  contacted), always with ``hostkey_verify=True`` and, by default, on the SSH port, so no security-zone
  change is needed (NETCONF on the SSH port once ``netconf ssh`` is set: verified, NETCONF guide; that
  it reaches the device wherever SSH does is inferred). Every RPC goes through one choke point that
  accepts only the names and argument names of ``INSTALL_RPCS``.
* The installer's own ``paramiko.SSHClient`` (also lazy) for SCP (``scp`` 0.16.2, the legacy protocol
  ``scp -t`` that the spike verified with OpenSSH ``scp -O``) and the one fixed veriexec read. PyEZ's own
  ``SCP`` and ``StartShell`` are not used: they load only the system known_hosts and connect to port 22
  whenever the NETCONF port is 830 (verified, PyEZ 2.8.3 ``utils/ssh_client.py``). It opens no
  forwarding channel of any kind (revision R3): SSH TCP forwarding was refused on a lab SRX4100 running
  25.2R1-S1.4 ('administratively prohibited', verified, docs/evidence/2026-11-24-srx4100-lab).
* With ``--access tls``, health check C8: one HTTPS ``GET /api/session`` from the workstation to the
  listen address (``https_get``), standard library only, trusting nothing but the certificate whose
  SHA-256 the installer made (the pin stands in for a CA store and the host-name check). The
  certificate and its key are made in memory (``make_tls_pair``, with the ``cryptography`` library that
  paramiko already needs, pinned in requirements-install.txt): the key goes to the device by SCP and is
  never written to the workstation's disk, logged or printed.

Timeouts on every call (SC-17): SSH and NETCONF open 30 s, RPC 60 s, commit 120 s, SCP 30 s, HTTPS 30 s.
Reads are retried up to three times with 1, 2 and 4 s back-off; writes are never retried, and a write
that timed out raises ``OutcomeUnknown`` because it may have happened (PyEZ: "It is possible the commit
was successful", verified). Device replies are returned as XML text for :mod:`jwicket_install.state`,
which caps and parses them; raw replies are never logged (DEBUG records RPC names and sizes only).

This module also runs inside the on-box op script (tools/jwicket_install/build_op.py embeds it), so it
imports on Python 3.7 (Junos 25.2R1-S1.4's Python 3.7.10, verified): the ``Protocol`` classes below are
plain classes at run time. Nothing in this module has run against a device: every device behaviour here
is unverified until lab test Q-INST-06, and the reply shapes until Q-INST-01.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import importlib
import io
import ipaddress
import logging
import socket
import ssl
from dataclasses import dataclass, field
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

from . import plan, state
from .plan import Minutes

if TYPE_CHECKING:
    from typing import Protocol
else:  # Python 3.7 (the SRX's) has no typing.Protocol: the interfaces below are plain classes at run time
    Protocol = object

LOG = logging.getLogger("jwicket_install.transport")

Reply = state.ReplyInput
ArgValue = Union[str, bool]

# ------------------------------------------------------------------------------------------------
# The fixed RPC list (spec 12). AC-006-29 checks every argument name against the junos-es 23.2R1 YANG
# fixture in tests/fixtures/install_rpc/. Two arguments name an enumeration value and are sent as an empty
# element of that name ("detail" for the file-list leaf 'style', "summary" for
# get-flow-session-information's 'level'): PyEZ's FS.ls sends file-list that way (verified, PyEZ 2.8.3
# utils/fs.py); for the flow summary the same convention is inferred (Q-INST-01). Every other enumerated
# leaf is sent as an element with the value as text, as Juniper documents it, e.g. refresh-from's
# <type>extension-service</type> ([refresh-from-cmd], verified); '| display xml rpc' records the real form
# on a device (Q-INST-01).
# ------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class RpcSpec:
    """One RPC the installer may send: its argument names (as sent, with hyphens), whether it is a read
    (retried) or a write (never retried, only after the gate), and where its name comes from."""

    args: FrozenSet[str]
    kind: str  # "read" or "write"
    source: str  # "yang:<module>", "junos-xml-protocol", "pyez" or "j-wicket"
    status: str


INSTALL_RPCS: Mapping[str, RpcSpec] = {
    # Facts and production signs (spec 8.2, 8.3).
    "get-software-information": RpcSpec(
        frozenset(), "read", "j-wicket", "used by the J-Wicket daemon today (fixtures); not in the YANG files read"
    ),
    "get-chassis-cluster-status": RpcSpec(frozenset(), "read", "yang:junos-es-rpc-chassis", "verified (YANG 23.2R1)"),
    "get-chassis-inventory": RpcSpec(
        frozenset(), "read", "yang:junos-es-rpc-chassis", "verified (YANG 23.2R1); serial as its source inferred"
    ),
    "get-flow-session-information": RpcSpec(
        frozenset({"summary"}), "read", "yang:junos-es-rpc-security", "summary as an element inferred"
    ),
    # Commit state, history and committed deltas (spec 8.5, 7.7, 7.9).
    "get-commit-information": RpcSpec(frozenset(), "read", "yang:junos-es-rpc-system", "verified (YANG 23.2R1)"),
    "get-rollback-information": RpcSpec(
        frozenset({"rollback", "compare"}),
        "read",
        "yang:junos-es-rpc-system",
        "verified (YANG 23.2R1); rollback is the base (the older index) and '+' adds to it to give compare "
        "(netconf-pdf, verified); the reply shape is Q-INST-01's",
    ),
    # Files (spec 7.5, 9.2 A3 to A5, 9.5).
    "file-list": RpcSpec(frozenset({"detail", "path"}), "read", "yang:junos-es-rpc-file", "verified (YANG 23.2R1)"),
    "file-show": RpcSpec(frozenset({"filename"}), "read", "yang:junos-es-rpc-file", "verified (YANG 23.2R1)"),
    "get-sha256-checksum-information": RpcSpec(
        frozenset({"path"}), "read", "yang:junos-es-rpc-file", "verified (YANG 23.2R1)"
    ),
    "jet-application-status": RpcSpec(
        frozenset({"application-name"}),
        "read",
        "yang:junos-es-rpc-extension-service",
        "verified to exist (YANG 23.2R1); as 'show extension-service status' inferred",
    ),
    # Files only, never the state directory (revision R4): root makes /var/db/jwicket once, because a
    # super-user-class account's 'file make-directory' was refused there (verified on SRX4100), so no
    # directory RPC is in this list and none can be sent. Never 'recurse' (spec 12) either.
    "file-change-permission": RpcSpec(
        frozenset({"filename", "permission"}), "write", "yang:junos-es-rpc-file", "verified (YANG 23.2R1)"
    ),
    "file-delete": RpcSpec(frozenset({"path"}), "write", "yang:junos-es-rpc-file", "verified (YANG 23.2R1)"),
    "file-copy": RpcSpec(
        frozenset({"source", "destination", "routing-instance"}),
        "write",
        "pyez",
        "known from PyEZ 2.8.3 FS.cp only (not in the SRX YANG); owner after a copy unknown (Q-INST-01); "
        "routing-instance is FS.cp's routing_instance argument as PyEZ sends it, inferred (JFR-05)",
    ),
    "request-script-refresh-from": RpcSpec(
        frozenset({"type", "file", "url", "cert-file", "routing-instance"}),
        "write",
        "yang:junos-es-rpc-request",
        "verified tag and XML form <type>extension-service</type> (refresh-from-cmd); an unconfigured file name "
        "unknown (Q-INST-05); routing-instance a leaf of its YANG input (verified, 23.2R1), its effect inferred",
    ),
    "extension-service-start": RpcSpec(
        frozenset({"application-name"}),
        "write",
        "yang:junos-es-rpc-request",
        "verified tag; the CLI command printed the self-test and probe JSON on SRX4100 25.2R1-S1.4 (verified, "
        "docs/evidence/2026-11-24-srx4100-lab); whether this RPC's output leaf carries it is unknown (Q-INST-05)",
    ),
    "extension-service-stop": RpcSpec(
        frozenset({"application-name"}),
        "write",
        "yang:junos-es-rpc-request",
        "verified tag; effect on a daemonized app unknown (Q-INST-03)",
    ),
    # Junos XML protocol operations, sent by PyEZ's Config and get_config (not in the rpc YANG modules):
    # [xml-confirm], [load-guide], [nc-sessions], [xml-compare] (verified).
    "get-configuration": RpcSpec(frozenset(), "read", "junos-xml-protocol", "verified"),
    "lock-configuration": RpcSpec(frozenset(), "write", "junos-xml-protocol", "verified"),
    "unlock-configuration": RpcSpec(frozenset(), "write", "junos-xml-protocol", "verified"),
    "load-configuration": RpcSpec(frozenset(), "write", "junos-xml-protocol", "verified"),
    "commit-configuration": RpcSpec(
        frozenset(), "write", "junos-xml-protocol", "verified; never a check or validate (INV-02)"
    ),
}

# The only arguments sent as an empty element named after an enumeration value: (RPC, YANG leaf) -> value.
EMPTY_ELEMENT_ARGS: Mapping[Tuple[str, str], str] = {
    ("file-list", "style"): "detail",  # PyEZ 2.8.3 FS.ls (verified)
    ("get-flow-session-information", "level"): "summary",  # inferred (Q-INST-01)
}

READ_RPCS = frozenset(name for name, spec in INSTALL_RPCS.items() if spec.kind == "read")
WRITE_RPCS = frozenset(name for name, spec in INSTALL_RPCS.items() if spec.kind == "write")

# The select-only configuration filter of spec 8.3. A request for an identifier only (<name/>) or for
# named child leaves returns only those (Junos XML "specific child tags"; inferred, Q-INST-01 records the
# reply). Never system login, any secret, a source URL or the whole configuration (INV-08).
#
# Every element path here is in the junos-es 23.2R1 conf YANG (tests/fixtures/install_rpc/
# junos-es-23.2R1-config-paths.json; test_install_autospec checks each one): 'system scripts' has commit,
# op and snmp files but no event container (event scripts are configured under 'event-options
# event-script file', junos-es-conf-event-options); 'system services web-management' has https but no
# http container at 23.2R1, so only its https port is read; 'system management-instance' is an empty leaf
# of 'system' (junos-es-conf-system 23.2R1, verified), read for [server] routing_instance (revision R2).
# 24.4 is inferred (Q-INST-01).
CONFIG_FILTER = (
    "<configuration>"
    "<system>"
    "<management-instance/>"
    "<scripts>"
    "<language/><load-scripts-from-flash/>"
    "<commit><file><name/></file></commit>"
    "<op><file><name/><checksum/></file><allow-url-for-python/></op>"
    "<snmp><file><name/></file></snmp>"
    "</scripts>"
    "<extensions><extension-service><application><file>"
    "<name/><username/><checksum/><daemonize/><respawn-on-normal-exit/>"
    "</file></application></extension-service></extensions>"
    "<services>"
    "<netconf/>"
    "<outbound-ssh><client><name/></client></outbound-ssh>"
    "<web-management><https><port/></https></web-management>"
    "<rest><http><port/></http><https><port/></https></rest>"
    "</services>"
    "<fips/>"
    "</system>"
    "<event-options><event-script><file><name/></file></event-script></event-options>"
    "<chassis><high-availability/></chassis>"
    "<groups><name>jwicket</name></groups>"
    "<apply-groups/>"
    "</configuration>"
)

DATABASES = ("committed", "candidate")
MAX_ROLLBACK = 49  # Junos keeps rollbacks 0..49 (PyEZ's range check, verified source); older is unreadable

# ------------------------------------------------------------------------------------------------
# Errors. Each message says what failed and why; device text in them is sanitised for display.
# ------------------------------------------------------------------------------------------------


class TransportError(Exception):
    """A device or transport step failed. The message names the step."""


class SessionLost(TransportError):
    """The session closed or dropped (the lock goes with it). Junos rolls back a pending confirmed commit
    at its deadline, and possibly at once (documented for kill-session; inferred for a drop, Q-INST-03)."""


class ReadTimeout(TransportError):
    """A read timed out; reads are retried with back-off."""


class DeviceRefused(TransportError):
    """The device answered a write (lock, load, commit, file RPC) with an error."""


class OutcomeUnknown(TransportError):
    """A write timed out: it may or may not have happened. Never retried."""


class NetconfUnavailable(TransportError):
    """NETCONF did not answer on the port (the netconf ssh statement is probably absent): print the
    bootstrap units."""


class AuthFailed(TransportError):
    """SSH authentication failed (agent, key or the typed password)."""


class HostKeyRejected(TransportError):
    """The NETCONF session's host key is not the pinned one (INV-09): nothing was sent. Reported as
    R-HOSTKEY, never as 'NETCONF is off' (PyEZ 2.8.3 turns ncclient's SSHUnknownHostError raised within
    3 s into ConnectRefusedError, verified in jnpr/junos/device.py)."""


class ToolMissing(TransportError):
    """junos-eznc, paramiko or scp is not installed in this Python."""


# ------------------------------------------------------------------------------------------------
# Targets, credentials, clocks
# ------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Target:
    """Where to connect. ``host`` is validated by the CLI (a host name or IPv4 address); it is never a
    path component on the workstation."""

    host: str
    user: str
    ssh_port: int = 22
    netconf_port: Optional[int] = None

    @property
    def nc_port(self) -> int:
        return self.netconf_port if self.netconf_port is not None else self.ssh_port

    @property
    def ports(self) -> Tuple[int, ...]:
        return tuple(sorted({self.ssh_port, self.nc_port}))


@dataclass(frozen=True)
class Credentials:
    """SSH agent and keys by default; a password only when typed at a getpass prompt (INV-08). There is
    no password option, environment variable or file. ``repr`` never shows the password."""

    identity_file: Optional[str] = None
    password: Optional[str] = field(default=None, repr=False)

    def __repr__(self) -> str:
        shown = "set" if self.password else "none"
        return f"Credentials(identity_file={self.identity_file!r}, password={shown})"


class Clock(Protocol):
    def monotonic(self) -> float: ...

    def sleep(self, seconds: float) -> None: ...


class SystemClock:
    def monotonic(self) -> float:
        import time

        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        import time

        time.sleep(seconds)


def retry_read(call: Callable[[], Reply], what: str, sleep: Callable[[float], None]) -> Reply:
    """Run an idempotent read; on a timeout retry after 1, 2 and 4 seconds (SC-17). Writes never come
    here. A lost session is not retried: the lock and any pending state went with it."""
    delays = plan.READ_RETRY_BACKOFF_S
    for attempt in range(len(delays) + 1):
        try:
            return call()
        except ReadTimeout:
            if attempt == len(delays):
                raise
            LOG.info(
                "%s timed out; retrying in %d s (read %d of %d)", what, delays[attempt], attempt + 2, len(delays) + 1
            )
            sleep(delays[attempt])
    raise ReadTimeout(f"{what} timed out")  # pragma: no cover - the loop returns or raises


def check_rpc(name: str, args: Mapping[str, ArgValue], kind: str) -> RpcSpec:
    """The one choke point every executor call passes (also used by the test fakes): the RPC must be in
    INSTALL_RPCS with this kind, and every argument name must be one of its own."""
    spec = INSTALL_RPCS.get(name)
    if spec is None:
        raise ValueError(f"RPC {name!r} is not in INSTALL_RPCS: the installer never sends it")
    if spec.kind != kind:
        raise ValueError(f"RPC {name!r} is a {spec.kind}, not a {kind}")
    extra = set(args) - spec.args
    if extra:
        raise ValueError(f"RPC {name!r} has no argument(s) {', '.join(sorted(extra))}")
    for value in args.values():
        if not isinstance(value, (str, bool)) or (isinstance(value, str) and ("\n" in value or len(value) > 512)):
            raise ValueError(f"RPC {name!r} argument is not a plain string or flag")
    return spec


# ------------------------------------------------------------------------------------------------
# What the executor needs from a session (the real adapters below and tests/fakes_junos.py implement it)
# ------------------------------------------------------------------------------------------------


class Netconf(Protocol):
    def read(self, name: str, **args: ArgValue) -> Reply: ...

    def write(self, name: str, **args: ArgValue) -> Reply: ...

    def get_configuration(self, *, database: str, inherit: bool) -> Reply: ...

    def compare(self, rollback: int) -> Optional[str]: ...

    def lock(self) -> None: ...

    def unlock(self) -> None: ...

    def load_set(self, lines: Sequence[str]) -> None: ...

    def discard(self) -> None: ...

    def load_rollback(self, number: int) -> None: ...

    def commit(self, comment: str, confirm: Optional[Minutes]) -> None: ...

    def close(self) -> None: ...


class Ssh(Protocol):
    """The installer's own SSH client: SCP and the veriexec read. No forwarding channel (revision R3)."""

    def put(self, data: bytes, path: str, mode: int) -> None: ...

    def get(self, path: str, local_path: str) -> None: ...

    def veriexec(self) -> Optional[str]: ...

    def close(self) -> None: ...


# ------------------------------------------------------------------------------------------------
# PyEZ adapter (NETCONF only)
# ------------------------------------------------------------------------------------------------


def _pyez() -> Tuple[Any, Any, Any]:
    """Import PyEZ lazily: unit tests, dry renders and the help text never need it."""
    try:
        from jnpr.junos import Device
        from jnpr.junos import exception as ez_exception
        from jnpr.junos.utils.config import Config
    except ImportError as exc:
        raise ToolMissing(
            "junos-eznc is not installed in this Python: install the hash-pinned requirements "
            "(pip install --require-hashes -r requirements-install.txt), then the installer wheel"
        ) from exc
    return Device, Config, ez_exception


def _reply_text(reply: Any) -> str:
    """PyEZ returns an lxml element (or True for a bare <ok/>); state.py parses text."""
    if isinstance(reply, bool):
        return "<ok/>"
    from lxml import etree

    return str(etree.tostring(reply, encoding="unicode"))


def _message(exc: BaseException) -> str:
    return plan.sanitize_display(str(exc) or type(exc).__name__, 300)


def _host_key_rejected(exc: BaseException) -> bool:
    """Whether ``exc`` or an exception chained to it is ncclient's SSHUnknownHostError (checked by class
    name, so ncclient stays imported lazily by PyEZ alone)."""
    seen: Set[int] = set()
    stack: List[Optional[BaseException]] = [exc]
    while stack:
        current = stack.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        if any(cls.__name__ == "SSHUnknownHostError" for cls in type(current).__mro__):
            return True
        stack.extend((current.__cause__, current.__context__))
    return False


class PyezNetconf:
    """NETCONF through PyEZ: ``Device(..., hostkey_verify=True, ssh_config=<pinned>)`` and PyEZ's Config
    without a mode (lock and unlock are explicit: the lock spans the load, the confirmed commit, the
    health checks and the confirm, SC-07). Never a private or ephemeral database (no confirmed commit
    there, verified)."""

    def __init__(
        self,
        target: Target,
        credentials: Credentials,
        ssh_config: str,
        clock: Clock,
        *,
        device_factory: Optional[Callable[..., Any]] = None,
        config_factory: Optional[Callable[..., Any]] = None,
        errors: Any = None,
    ) -> None:
        self._target = target
        self._credentials = credentials
        self._ssh_config = ssh_config
        self._clock = clock
        if device_factory is None or config_factory is None or errors is None:
            device_cls, config_cls, ez_errors = _pyez()
            device_factory = device_factory or device_cls
            config_factory = config_factory or config_cls
            errors = errors or ez_errors
        self._device_factory = device_factory
        self._config_factory = config_factory
        self._errors = errors
        self._dev: Any = None
        self._cu: Any = None

    def device_kwargs(self) -> Dict[str, Any]:
        """The Device keywords (AC-006-23 checks hostkey_verify; the autospec test checks the names)."""
        kwargs: Dict[str, Any] = {
            "host": self._target.host,
            "user": self._target.user,
            "port": self._target.nc_port,
            "hostkey_verify": True,
            "ssh_config": self._ssh_config,
            "conn_open_timeout": plan.TIMEOUTS["netconf-open"],
            "gather_facts": False,
        }
        if self._credentials.identity_file:
            kwargs["ssh_private_key_file"] = self._credentials.identity_file
        if self._credentials.password:
            kwargs["passwd"] = self._credentials.password
        return kwargs

    def open(self) -> None:
        errors = self._errors
        self._dev = self._device_factory(**self.device_kwargs())
        try:
            self._dev.open()
        except errors.ConnectError as exc:
            port = self._target.nc_port
            if _host_key_rejected(exc):  # before ConnectRefusedError, which PyEZ makes of it (SEC-03)
                raise HostKeyRejected(
                    f"NETCONF on port {port} presented a host key other than the one verified (INV-09); nothing "
                    "was sent"
                ) from exc
            if isinstance(exc, errors.ConnectAuthError):
                raise AuthFailed(f"NETCONF authentication as {self._target.user} failed: {_message(exc)}") from exc
            if isinstance(exc, errors.ConnectRefusedError):
                raise NetconfUnavailable(f"NETCONF on port {port} refused the session: {_message(exc)}") from exc
            raise TransportError(f"NETCONF on port {port} did not open: {_message(exc)}") from exc
        self._dev.timeout = plan.TIMEOUTS["rpc"]
        self._cu = self._config_factory(self._dev)
        LOG.debug("NETCONF open on port %d", self._target.nc_port)

    # -- RPCs ----------------------------------------------------------------------------------------

    def _invoke(self, name: str, args: Mapping[str, ArgValue], kind: str, timeout: int) -> Reply:
        check_rpc(name, args, kind)
        errors = self._errors
        method = getattr(self._dev.rpc, name.replace("-", "_"))
        kwargs = {key.replace("-", "_"): value for key, value in args.items()}
        try:
            reply = method(dev_timeout=timeout, **kwargs)
        except errors.RpcTimeoutError as exc:
            if kind == "read":
                raise ReadTimeout(f"{name} timed out after {timeout} s") from exc
            raise OutcomeUnknown(f"{name} timed out after {timeout} s; it may have run") from exc
        except errors.ConnectClosedError as exc:
            raise SessionLost(f"the NETCONF session closed during {name}") from exc
        except errors.RpcError as exc:
            if kind == "write":
                raise DeviceRefused(f"the device refused {name}: {_message(exc)}") from exc
            return state.RpcErrorReply(str(exc))
        text = _reply_text(reply)
        LOG.debug("%s answered %d bytes", name, len(text))
        return text

    def read(self, name: str, **args: ArgValue) -> Reply:
        return retry_read(lambda: self._invoke(name, args, "read", plan.TIMEOUTS["rpc"]), name, self._clock.sleep)

    def write(self, name: str, **args: ArgValue) -> Reply:
        return self._invoke(name, args, "write", plan.TIMEOUTS["rpc"])

    def get_configuration(self, *, database: str, inherit: bool) -> Reply:
        if database not in DATABASES:
            raise ValueError(f"database {database!r} is not committed or candidate")
        check_rpc("get-configuration", {}, "read")
        from lxml import etree

        options = {"database": database}
        if inherit:
            options["inherit"] = "inherit"
        errors = self._errors

        def call() -> Reply:
            try:
                reply = self._dev.rpc.get_config(
                    filter_xml=etree.XML(CONFIG_FILTER), options=dict(options), dev_timeout=plan.TIMEOUTS["rpc"]
                )
            except errors.RpcTimeoutError as exc:
                raise ReadTimeout("get-configuration timed out") from exc
            except errors.ConnectClosedError as exc:
                raise SessionLost("the NETCONF session closed during get-configuration") from exc
            except errors.RpcError as exc:
                return state.RpcErrorReply(str(exc))
            return _reply_text(reply)

        return retry_read(call, "get-configuration", self._clock.sleep)

    def compare(self, rollback: int) -> Optional[str]:
        """The candidate against rollback ``rollback`` in patch form: '<get-configuration compare="rollback"
        rollback="N" format="text"/>' ([xml-compare], verified for 0; 1 on an unchanged candidate as the
        committed delta is inferred). None when the device returns no text."""
        if not 0 <= rollback <= 1:
            raise ValueError("compare takes rollback 0 or 1")
        check_rpc("get-configuration", {}, "read")
        errors = self._errors

        def call() -> Reply:
            try:
                reply = self._dev.rpc.get_configuration(
                    {"compare": "rollback", "rollback": str(rollback), "format": "text"},
                    dev_timeout=plan.TIMEOUTS["rpc"],
                )
            except errors.RpcTimeoutError as exc:
                raise ReadTimeout("compare timed out") from exc
            except errors.ConnectClosedError as exc:
                raise SessionLost("the NETCONF session closed during compare") from exc
            except errors.RpcError as exc:
                return state.RpcErrorReply(str(exc))
            return _reply_text(reply)

        return output_text(retry_read(call, "compare", self._clock.sleep), ("configuration-output",))

    # -- configuration writes (never retried) ---------------------------------------------------------

    def _config_call(self, what: str, call: Callable[[], Any], *, timeout_is: str = "unknown") -> None:
        errors = self._errors
        try:
            call()
        except errors.RpcTimeoutError as exc:
            raise OutcomeUnknown(f"{what} timed out; it may have happened") from exc
        except errors.ConnectClosedError as exc:
            raise SessionLost(f"the NETCONF session closed during {what}") from exc
        except errors.RpcError as exc:  # LockError, UnlockError, ConfigLoadError, CommitError are RpcErrors
            raise DeviceRefused(f"the device refused {what}: {_message(exc)}") from exc
        except ValueError as exc:  # PyEZ argument checks
            raise DeviceRefused(f"{what}: {_message(exc)}") from exc

    def lock(self) -> None:
        check_rpc("lock-configuration", {}, "write")
        self._config_call("the exclusive lock ('configure exclusive')", self._cu.lock)

    def unlock(self) -> None:
        check_rpc("unlock-configuration", {}, "write")
        self._config_call("unlock", self._cu.unlock)

    def load_set(self, lines: Sequence[str]) -> None:
        check_rpc("load-configuration", {}, "write")
        text = "\n".join(lines)
        self._config_call("the load of the stage's set lines", lambda: self._cu.load(text, format="set"))

    def discard(self) -> None:
        check_rpc("load-configuration", {}, "write")
        self._config_call("rollback 0 (discarding the candidate)", lambda: self._cu.rollback(0))

    def load_rollback(self, number: int) -> None:
        if number != 1:
            raise ValueError("only rollback 1 is ever loaded (--rollback-now)")
        check_rpc("load-configuration", {}, "write")
        self._config_call("loading rollback 1", lambda: self._cu.rollback(1))

    def commit(self, comment: str, confirm: Optional[Minutes]) -> None:
        """'commit confirmed N comment' (confirm set) or the confirming 'commit comment' (confirm None):
        <commit-configuration><confirmed/><confirm-timeout>N</confirm-timeout><log>..</log> or <log>
        alone (PyEZ Config.commit, verified source). Never <check/> (INV-02)."""
        check_rpc("commit-configuration", {}, "write")
        kwargs: Dict[str, Any] = {"comment": comment, "timeout": plan.TIMEOUTS["commit"]}
        if confirm is not None:
            kwargs["confirm"] = int(confirm)
        what = f"commit confirmed {int(confirm)}" if confirm is not None else "the confirming commit"
        self._config_call(what, lambda: self._cu.commit(**kwargs))

    def close(self) -> None:
        if self._dev is None:
            return
        try:
            self._dev.close()
        except Exception as exc:  # noqa: BLE001 - closing is best effort and must never mask the real outcome
            LOG.debug("closing NETCONF failed: %s", type(exc).__name__)


def output_text(reply: Reply, tags: Iterable[str] = ("output", "configuration-output")) -> Optional[str]:
    """The text of the first element named in ``tags`` (a reply's <output> or <configuration-output>),
    or None when the reply has none or failed."""
    if reply is None or isinstance(reply, state.RpcErrorReply):
        return None
    try:
        root = state.parse_xml(reply)
    except state.ReplyError:
        return None
    wanted = tuple(tags)
    for node in root.iter():
        tag = node.tag.rsplit("}", 1)[-1] if isinstance(node.tag, str) else ""
        if tag in wanted:
            return "".join(node.itertext())
    return None


def error_text(reply: Reply) -> Optional[str]:
    """The message of a failed read, for display only."""
    if isinstance(reply, state.RpcErrorReply):
        return plan.sanitize_display(reply.message, 300)
    return None


# ------------------------------------------------------------------------------------------------
# The installer's own SSH client (SCP and the veriexec read)
# ------------------------------------------------------------------------------------------------


def _paramiko() -> Any:
    try:
        import paramiko
    except ImportError as exc:
        raise ToolMissing(
            "paramiko is not installed in this Python: install the hash-pinned requirements "
            "(pip install --require-hashes -r requirements-install.txt)"
        ) from exc
    return paramiko


def _scp_client() -> Any:
    try:
        from scp import SCPClient
    except ImportError as exc:
        raise ToolMissing("scp is not installed in this Python: install requirements-install.txt") from exc
    return SCPClient


def pinned_policy(paramiko: Any, expected: Tuple[str, bytes]) -> Any:
    """paramiko's RejectPolicy, except for the one host key the installer already verified against the
    known_hosts files (INV-09; hostkeys.py looks up both 'host' and '[host]:port', as ncclient does)."""

    class PinnedRejectPolicy(paramiko.RejectPolicy):  # type: ignore[misc]
        def missing_host_key(self, client: Any, hostname: str, key: Any) -> None:
            if (key.get_name(), key.asbytes()) == expected:
                return
            super().missing_host_key(client, hostname, key)

    return PinnedRejectPolicy()


class OwnSsh:
    """paramiko.SSHClient with the pinned reject policy, connect, banner, auth and channel timeouts.

    The veriexec read is the only shell use (P7): 'start shell sh' run as one SSH exec request, fed the
    spike's exact command and 'exit' on standard input. That the Junos CLI runs an exec request this way
    and that sh reads its commands from the channel are inferred (Q-INST-05); the command itself is the
    one the spike ran (verified), and on the lab SRX4100 the state read 'loaded active enforce' (verified
    by hand, docs/evidence/2026-11-24-srx4100-lab)."""

    def __init__(
        self, target: Target, credentials: Credentials, expected_key: Tuple[str, bytes], key_types: Sequence[str]
    ) -> None:
        self._target = target
        self._credentials = credentials
        self._expected = expected_key
        self._key_types = tuple(key_types)
        self._client: Any = None

    def connect_kwargs(self, paramiko: Any) -> Dict[str, Any]:
        timeout = plan.TIMEOUTS["ssh-connect"]
        password = self._credentials.password
        identity = self._credentials.identity_file
        disabled = [t for t in _ALL_KEY_ALGORITHMS if t not in self._key_types]
        kwargs: Dict[str, Any] = {
            "hostname": self._target.host,
            "port": self._target.ssh_port,
            "username": self._target.user,
            "timeout": timeout,
            "banner_timeout": timeout,
            "auth_timeout": timeout,
            "channel_timeout": timeout,
            "allow_agent": password is None and identity is None,
            "look_for_keys": password is None,
            "disabled_algorithms": {"keys": disabled} if disabled and self._key_types else None,
        }
        if password is not None:
            kwargs["password"] = password
        if identity is not None:
            kwargs["key_filename"] = identity
        return kwargs

    def open(self) -> None:
        paramiko = _paramiko()
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(pinned_policy(paramiko, self._expected))
        try:
            client.connect(**self.connect_kwargs(paramiko))
        except paramiko.BadHostKeyException as exc:
            raise TransportError("the device presented another host key than the one verified (INV-09)") from exc
        except paramiko.AuthenticationException as exc:
            raise AuthFailed(f"SSH authentication as {self._target.user} failed: {_message(exc)}") from exc
        except (paramiko.SSHException, OSError) as exc:
            raise TransportError(
                f"SSH to port {self._target.ssh_port} failed: {_message(exc)} (refused by the host-key "
                "policy if the key differs)"
            ) from exc
        self._client = client

    def _transport(self) -> Any:
        if self._client is None:
            raise SessionLost("the SSH connection is not open")
        transport = self._client.get_transport()
        if transport is None or not transport.is_active():
            raise SessionLost("the SSH connection closed")
        return transport

    def put(self, data: bytes, path: str, mode: int) -> None:
        """SCP to a fixed, validated path with an explicit mode (the 'C<mode>' record). The final mode is
        the device's umask's business (unknown); the caller reads it back."""
        scp_client = _scp_client()
        try:
            with scp_client(self._transport(), socket_timeout=plan.TIMEOUTS["scp"]) as scp:
                scp.putfo(io.BytesIO(data), path, mode=f"{mode:04o}")
        except Exception as exc:
            if isinstance(exc, SessionLost):
                raise
            raise DeviceRefused(f"SCP to {path} failed: {_message(exc)}") from exc

    def get(self, path: str, local_path: str) -> None:
        scp_client = _scp_client()
        try:
            with scp_client(self._transport(), socket_timeout=plan.TIMEOUTS["scp"]) as scp:
                scp.get(path, local_path)
        except Exception as exc:
            if isinstance(exc, SessionLost):
                raise
            raise DeviceRefused(f"SCP of {path} failed: {_message(exc)}") from exc

    def veriexec(self) -> Optional[str]:
        paramiko = _paramiko()
        timeout = float(plan.TIMEOUTS["veriexec-read"])
        try:
            channel = self._transport().open_session(timeout=plan.TIMEOUTS["ssh-connect"])
            channel.settimeout(timeout)
            channel.exec_command(plan.SHELL_START)
            channel.sendall(f"{plan.SHELL_VERIEXEC}\n{plan.SHELL_EXIT}\n".encode("ascii"))
            channel.shutdown_write()
            data = _read_channel(channel, 4096)
            channel.close()
        except (paramiko.SSHException, OSError, socket.timeout) as exc:
            LOG.info("veriexec read failed: %s", _message(exc))
            return None
        return data.decode("utf-8", "replace")

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None


def _read_channel(channel: Any, limit: int) -> bytes:
    data = bytearray()
    while len(data) < limit:
        chunk = channel.recv(min(4096, limit - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


# paramiko's host-key algorithm names; a known_hosts key type maps to these (hostkeys.algorithms_for).
_ALL_KEY_ALGORITHMS: Tuple[str, ...] = (
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
)


def fetch_host_key(host: str, port: int, key_types: Sequence[str]) -> Tuple[str, bytes]:
    """The host key a port presents, from a bare paramiko Transport: no authentication, nothing sent but
    the key exchange (INV-09). ``key_types`` restricts the negotiation to the algorithms the known_hosts
    entries name, so the device presents a key of a type the operator recorded."""
    paramiko = _paramiko()
    timeout = plan.TIMEOUTS["ssh-connect"]
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        raise TransportError(f"TCP to {host} port {port} failed: {_message(exc)}") from exc
    transport = paramiko.Transport(sock)
    try:
        transport.banner_timeout = timeout
        if key_types:
            options = transport.get_security_options()
            allowed = [t for t in options.key_types if t in set(key_types)]
            if allowed:
                options.key_types = allowed
        transport.start_client(timeout=timeout)
        key = transport.get_remote_server_key()
        return (str(key.get_name()), bytes(key.asbytes()))
    except (paramiko.SSHException, OSError, EOFError) as exc:
        raise TransportError(f"SSH key exchange with port {port} failed: {_message(exc)}") from exc
    finally:
        transport.close()


def netconf_subsystem_available(ssh: OwnSsh) -> bool:
    """Whether the 'netconf' SSH subsystem answers on the SSH port (a read: it opens and closes a session
    channel, as any NETCONF client does). False means 'netconf ssh' is probably not configured."""
    paramiko = _paramiko()
    try:
        channel = ssh._transport().open_session(timeout=plan.TIMEOUTS["ssh-connect"])
    except (paramiko.SSHException, OSError) as exc:
        raise TransportError(f"SSH session channel failed: {_message(exc)}") from exc
    try:
        channel.settimeout(float(plan.TIMEOUTS["ssh-connect"]))
        channel.invoke_subsystem("netconf")
    except (paramiko.SSHException, OSError, socket.timeout):
        return False
    else:
        return True
    finally:
        channel.close()


# ------------------------------------------------------------------------------------------------
# --access tls: the certificate (made in memory) and C8's pinned HTTPS read (revisions R2, R3)
# ------------------------------------------------------------------------------------------------


@dataclass
class TlsPair:
    """A self-signed certificate and its private key, both PEM, made in memory for one run. ``key_pem``
    is the secret: never written to the workstation's disk, logged, printed or recorded, and dropped
    (``forget_key``) once it is on the device; ``repr`` never shows it. ``cert_sha256`` is the SHA-256
    of the certificate's DER form: the fingerprint a browser shows, the only value printed and recorded,
    and C8's pin. ``not_after`` is the certificate's notAfter as YYYY-MM-DDTHH:MM:SSZ (recorded, so a
    rerun renews the pair before it expires, SEC-R1)."""

    cert_pem: bytes
    key_pem: bytes = field(repr=False)
    cert_sha256: str
    not_after: Optional[str] = None

    def __repr__(self) -> str:
        return f"TlsPair(cert_sha256={self.cert_sha256!r}, key={'held' if self.key_pem else 'dropped'})"

    def forget_key(self) -> None:
        """Drop the reference to the key (best effort: Python cannot wipe the bytes it already copied)."""
        self.key_pem = b""


def _cryptography() -> Tuple[Any, Any, Any, Any, Any]:
    """Import the cryptography library lazily (a paramiko dependency, pinned on its own in
    requirements-install.txt): unit tests, dry runs and the on-box op script never need it."""
    try:
        x509 = importlib.import_module("cryptography.x509")
        oid = importlib.import_module("cryptography.x509.oid")
        hashes = importlib.import_module("cryptography.hazmat.primitives.hashes")
        serialization = importlib.import_module("cryptography.hazmat.primitives.serialization")
        rsa = importlib.import_module("cryptography.hazmat.primitives.asymmetric.rsa")
    except ImportError as exc:
        raise ToolMissing(
            "cryptography is not installed in this Python: --access tls makes its certificate with it; install "
            "the hash-pinned requirements (pip install --require-hashes -r requirements-install.txt)"
        ) from exc
    return x509, oid, hashes, serialization, rsa


def make_tls_pair(
    address: str,
    *,
    days: int = plan.TLS_CERT_DAYS,
    bits: int = plan.TLS_KEY_BITS,
    now: Optional[datetime.datetime] = None,
) -> TlsPair:
    """A self-signed RSA certificate for ``address`` (a canonical IP literal: its subjectAltName is that
    IP address, and its common name the same text), valid ``days`` days from five minutes ago (clock
    skew), serverAuth, not a CA. The lab run's certificate was RSA-2048 from 'openssl req' on the box
    (verified on SRX4100); that the on-box ssl module loads this one is inferred (the same PEM forms:
    PKCS#8 key, X.509 certificate), unverified until Q-INST-06."""
    ip = ipaddress.ip_address(plan.canonical_address(address))
    if not 1 <= days <= 397:
        raise plan.InputError(f"certificate validity {days} days is outside 1..397")
    if bits < 2048:
        raise plan.InputError(f"an RSA key of {bits} bits is too small (2048 at least)")
    x509, oid, hashes, serialization, rsa = _cryptography()
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([x509.NameAttribute(oid.NameOID.COMMON_NAME, str(ip))])
    start = (now or datetime.datetime.now(datetime.timezone.utc)) - datetime.timedelta(minutes=5)
    end = start + datetime.timedelta(days=days, minutes=5)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ip)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    )
    certificate = builder.sign(private_key=key, algorithm=hashes.SHA256())
    encoding = serialization.Encoding
    key_pem = bytes(key.private_bytes(encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    del key
    cert_pem = bytes(certificate.public_bytes(encoding.PEM))
    sha = hashlib.sha256(bytes(certificate.public_bytes(encoding.DER))).hexdigest()
    LOG.debug("made a TLS certificate for %s, SHA-256 %s", ip, sha)
    return TlsPair(cert_pem, key_pem, sha, end.strftime("%Y-%m-%dT%H:%M:%SZ"))


def pem_certificate_sha256(pem: bytes) -> Optional[str]:
    """The SHA-256 of the DER form of the first PEM certificate in ``pem`` (a browser's fingerprint), or
    None when there is none."""
    try:
        text = pem.decode("ascii")
        start = text.index("-----BEGIN CERTIFICATE-----")
        end = text.index("-----END CERTIFICATE-----", start) + len("-----END CERTIFICATE-----")
        der = ssl.PEM_cert_to_DER_cert(text[start:end])
    except (UnicodeDecodeError, ValueError):
        return None
    return hashlib.sha256(der).hexdigest()


@dataclass(frozen=True)
class HttpsResult:
    """One pinned HTTPS exchange. ``connected`` False: no TLS session (refused, timed out, handshake
    failed). ``pinned`` False: a TLS session whose certificate is not the pinned one; nothing was sent.
    ``data`` is the raw HTTP answer (capped), ``reason`` says what failed, ``peer_sha256`` is what the
    peer presented (a fingerprint, for the message)."""

    connected: bool
    pinned: bool = False
    data: bytes = b""
    reason: str = ""
    peer_sha256: Optional[str] = None


def pinned_context() -> ssl.SSLContext:
    """A client context that trusts no CA store and checks no host name: the caller compares the peer
    certificate's SHA-256 with the pin before sending anything (R3). TLS 1.2 at least (the SRX4100's
    daemon answered TLS 1.2 and 1.3, verified)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False  # the pin stands in for the host-name check (ssl requires this order)
    context.verify_mode = ssl.CERT_NONE  # the pin stands in for the CA store; compared before any request
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def https_get(
    address: str,
    port: int,
    path: str,
    host_header: str,
    pin_sha256: str,
    *,
    timeout: float = float(plan.TIMEOUTS["http"]),
    limit: int = 65536,
) -> HttpsResult:
    """``GET <path>`` over TLS to ``address:port``, sent only after the certificate the peer presented
    has SHA-256 ``pin_sha256`` (compared in constant time). ``Host`` is ``host_header`` (the daemon
    answers 421 to any name not in allowed_hosts). A read only: retried by the caller, never here."""
    ip = plan.canonical_address(address)
    plan.validate_sha256(pin_sha256, "certificate pin")
    if not path.startswith("/") or any(c in path + host_header for c in "\r\n "):
        raise ValueError("the HTTPS path and Host header must be plain")
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except OSError as exc:  # refused, unreachable or timed out (socket.timeout is an OSError)
        return HttpsResult(False, reason=f"TCP to {plan.host_port(ip, port)} failed: {_message(exc)}")
    try:
        with pinned_context().wrap_socket(raw) as tls:
            tls.settimeout(timeout)
            der = tls.getpeercert(binary_form=True)
            peer = hashlib.sha256(der).hexdigest() if der else None
            if peer is None or not hmac.compare_digest(peer, pin_sha256):
                return HttpsResult(
                    True,
                    False,
                    reason="the certificate presented is not the one this installer made",
                    peer_sha256=peer,
                )
            request = (
                f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\nAccept: application/json\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            tls.sendall(request)
            data = bytearray()
            while len(data) < limit:
                try:
                    chunk = tls.recv(min(4096, limit - len(data)))
                except OSError as exc:  # a timeout or a TLS error (both are OSErrors)
                    if data:
                        break
                    return HttpsResult(True, True, reason=f"no answer within {timeout:.0f} s: {_message(exc)}")
                if not chunk:
                    break
                data.extend(chunk)
            return HttpsResult(True, True, bytes(data), peer_sha256=peer)
    except OSError as exc:  # the handshake failed or timed out (ssl.SSLError and socket.timeout included)
        return HttpsResult(False, reason=f"TLS with {plan.host_port(ip, port)} failed: {_message(exc)}")
    finally:
        raw.close()


# ------------------------------------------------------------------------------------------------
# The connector: what workstation.py asks for (tests/fakes_junos.py has a fake with the same methods)
# ------------------------------------------------------------------------------------------------


class Connector(Protocol):
    def host_key(self, port: int, key_types: Sequence[str]) -> Tuple[str, bytes]: ...

    def open_ssh(self, key: Tuple[str, bytes], key_types: Sequence[str]) -> Ssh: ...

    def netconf_available(self, ssh: Ssh, key: Tuple[str, bytes]) -> bool: ...

    def open_netconf(self, ssh_config: str) -> Netconf: ...

    def https_get(self, address: str, port: int, path: str, host_header: str, pin_sha256: str) -> HttpsResult: ...


class RealConnector:
    """The production connector: paramiko for host keys and the own client, PyEZ for NETCONF, the
    standard library's ssl for C8."""

    def __init__(self, target: Target, credentials: Credentials, clock: Clock) -> None:
        self._target = target
        self._credentials = credentials
        self._clock = clock

    def host_key(self, port: int, key_types: Sequence[str]) -> Tuple[str, bytes]:
        return fetch_host_key(self._target.host, port, key_types)

    def open_ssh(self, key: Tuple[str, bytes], key_types: Sequence[str]) -> Ssh:
        client = OwnSsh(self._target, self._credentials, key, key_types)
        client.open()
        return client

    def netconf_available(self, ssh: Ssh, key: Tuple[str, bytes]) -> bool:
        if self._target.nc_port != self._target.ssh_port:
            return True  # a dedicated NETCONF port answered the key exchange (it accepts NETCONF only, verified)
        if not isinstance(ssh, OwnSsh):
            raise TypeError("the real connector probes NETCONF through its own SSH client")
        return netconf_subsystem_available(ssh)

    def open_netconf(self, ssh_config: str) -> Netconf:
        session = PyezNetconf(self._target, self._credentials, ssh_config, self._clock)
        session.open()
        return session

    def https_get(self, address: str, port: int, path: str, host_header: str, pin_sha256: str) -> HttpsResult:
        return https_get(address, port, path, host_header, pin_sha256)
