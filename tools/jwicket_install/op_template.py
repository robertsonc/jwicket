"""The on-box op-script installer (Spec 006 sections 6.5 and 6.6: methods M4 and M4U). LAB ONLY.

``tools/jwicket_install/build_op.py`` embeds this module, with ``plan``, ``state``, ``render``, ``health``
and ``transport`` of this package, into ``dist/jwicket-install-op.py``. Junos runs that file as a Python op
script, with the rights of the account that typed the command ([op-cmd], verified: "Op scripts are
executed with the access privileges of the user who invokes the command"):

* M4: ``op jwicket-install-op.py``, the file in ``/var/db/scripts/op`` pinned by ``set system scripts op
  file jwicket-install-op.py checksum sha-256 <hash>`` (statement S14). A local op script whose bytes
  differ from its configured checksum does not run ([op-checksum-local], verified). That ``op`` takes the
  name with its ``.py`` suffix is inferred (research EXT-11).
* M4U: ``op url <per-tag URL> key sha-256 <hash>`` with ``set system scripts op allow-url-for-python``
  ([allow-url-py], verified). How ``op url`` validates HTTPS and whether it follows GitHub's redirect are
  unknown (Q-INST-05), so the typed hash is the integrity control.

Python 3.7 (revision R1): Junos 25.2R1-S1.4 ships Python 3.7.10, and a JET app imported ``jnpr.junos``,
``lxml``, ``ncclient`` and ``paramiko`` there (verified on a lab SRX4100,
docs/evidence/2026-11-24-srx4100-lab). That an op script runs on the same interpreter is inferred. So
this module and every module it embeds stay within Python 3.7 (no assignment expressions, positional-only
parameters, ``f"{x=}"``, run-time ``typing.Protocol``/``Literal``/``Final``/``TypedDict``,
``functools.cached_property``, ``str.removeprefix``, dict union, ``math.prod``); build_op.py's prelude
refuses an older Python before anything is compiled.

One run, in the order of spec 6.5 and 9.2:

1. The prelude checks the Python version; this module then checks that ``jcs`` and on-box PyEZ import
   (``main``), before any read.
2. Reads only (spec 8.3): the local device through PyEZ ``Device()`` with no host ([op-py-config],
   verified: "The script does not supply a host parameter when creating the Device instance, which
   causes the open() method to establish a connection with the local device."), facts, the select-only
   configuration (with ``system management-instance``), the commit state and history, the file listings
   (``/var/db`` and ``/var/db/jwicket`` among them), checksums, the advisory device receipt, and veriexec:
   ``/sbin/sysctl security.mac.veriexec.state`` with an argument list and a 5 s timeout (the path and
   whether an op script may run it are inferred and unknown, Q-INST-05; ``python3`` from the shell was
   refused under veriexec on the SRX4100, verified), else a typed attestation the operator reads in
   another session ("read by hand" in the receipt). The SRX4100 reported 'loaded active enforce'
   (verified).
3. Its own unconfirmed bootstrap is recognised (``plan.recognise_bootstrap``: the newest pending entry,
   by this account, with the comment ``jwicket-bootstrap op`` or ``jwicket-bootstrap op-url``, whose
   committed delta adds exactly the bootstrap's statements); anything else pending is R-PENDING. Cut C5:
   confirming the operator's own bootstrap after the gate is an owner decision open for veto. The
   bootstrap pattern itself is unverified.
4. The bundle source: ``<home>/jwicket.py`` when the operator copied it there (opened with
   ``O_NOFOLLOW``, ``fstat`` must show a regular file owned by the running uid and not group- or
   other-writable, read once and hashed before the gate), else the per-tag release URL this file embeds,
   fetched after the gate by the ``file-copy`` RPC (as ``file copy <url> <dest>``, [file-copy], verified
   to accept HTTPS sources; certificate checking on Junos OS unknown, Q-INST-05). Either way the bytes
   land only in the unconfigured staging name ``/var/db/scripts/jet/jwicket-next.py`` and are checked
   with ``get-sha256-checksum-information`` against the SHA-256 embedded in this file. A fixed name in a
   shared temporary directory is never used.
5. Access (revision R2), typed at a prompt: ``tls`` (the default) or ``tunnel``. With ``tls`` the daemon
   listens with TLS on the device address the operator types, port 9443, in ``mgmt_junos`` when
   ``system management-instance`` is set (the plan's ``[server] routing_instance``). This script does not
   make the key pair: whether an op script may run ``openssl`` under veriexec is unknown, and the key must
   never leave the device. The operator makes ``tls.key`` (0600) and ``tls.crt`` in ``/var/db/jwicket``
   once, in the shell as the daemon account, with ``plan.shell_tls_lines`` (deploy-lab's TLS unit,
   verified on SRX4100 25.2R1-S1.4); until both are there, owned by the account, the run is refused before
   any write and prints that unit. The script reads only the certificate, prints its SHA-256 fingerprint
   for the browser comparison and records it. ``tunnel`` keeps 127.0.0.1 behind 'ssh -L' (refused on the
   SRX4100, ``plan.TUNNEL_WARNING``).
6. The plan, its diff, the warnings and the production signs are printed. The state directory is root's
   (revision R4): a super-user-class account could not create /var/db/jwicket on the SRX4100 ('mkdir' and
   'file make-directory' both refused, verified), so this script never creates or removes it; while it is
   absent or untrusted the plan refuses R-STATEDIR and the run prints the one-time root step
   (``plan.directory_fallback``) and exits 1 before any write. Then the lab gate:
   ``jcs.get_input(LAB_GATE_PROMPT)`` ([op-py-config], verified; under ``op url`` unknown, Q-INST-05). The
   device's host name is never printed before the prompt (INV-05). On hardware (revision R5: R-MODEL
   overridden with ``--lab-hardware``, a physical SRX only) the production signs are shown again and the
   operator must type 'lab only', recorded in the receipt. Enter, a wrong answer or a refusal ends the run
   with nothing written; a pending bootstrap rolls back at its deadline.
7. After the gate: the state directory's trust is read again (a refusal leaves the bootstrap
   unconfirmed); the bootstrap's confirm (K1, K2, C10, C11 first); the files; the stages through
   ``Config(dev, mode="exclusive")`` (the lock is held from the load through the confirming commit; PyEZ
   2.8.3 ``utils/config.py``, verified), each a ``commit confirmed`` with the health checks of spec 7.6
   before its confirm (``commit confirmed 5``, a check, then a confirming commit is the lab run's own
   sequence, and an unconfirmed commit rolled back by itself: verified on SRX4100); the device receipt and
   ``/var/db/jwicket/uninstall-cli.txt`` (mode 0600).
8. Everything after the bootstrap's confirm runs inside ``try``/``finally``: on any other outcome than
   success the revert stage (spec 8.8) removes what this run's confirmed stages added and, when the
   commit history shows this run's bootstrap added them, the bootstrap's own statements. If the revert
   cannot run, the exact paste units are printed.

The same script offers "uninstall" when J-Wicket is installed (spec 6.5); /var/db/jwicket stays for root
to remove (``plan.STATE_DIR_LEFT``).

Health checks without an SSH channel (revision R3): C9 is retired. C8 with ``--access tls`` is an HTTPS
``GET /api/session`` from this script to the listen address, sent only after the peer's certificate
matches the fingerprint read from ``tls.crt`` (``transport.https_get``), and only when the listener is in
the default routing instance: with ``mgmt_junos`` it is recorded not available, because this script
runs in the default instance and ``jcs.set_routing_instance`` is process-wide (on the SRX4100 it stopped
the process's own NETCONF to 127.0.0.1:830, verified). Whether an op script may open that connection at
all is unknown (Q-INST-05): a connection that cannot be made is "not available", not a failure. C8 with
``--access tunnel`` is not available. C8 is never required for the confirm on the box.

Verified on the SRX4100 run (by the manual procedure, not by this script): ``language python3``, the
``daemonize``, ``respawn-on-normal-exit`` and ``username`` statements of the daemon's stanza and the
``username`` statements of the self-test and probe stanzas were committed and worked; ``request
extension-service start`` printed the self-test and probe JSON on the CLI (whether the RPC's reply carries
it is unknown, Q-INST-05). Unverified: ``checksum sha-256`` on JET files (Q-INST-02), every RPC this script
sends, the bootstrap pattern, and the owner and mode a write or an on-device ``file-copy`` produces
(Q-INST-01: every file is read back with ``file-list``).

PyEZ calls are the ones Juniper's op-script example documents (``Device()``, ``open``, ``Config(dev,
mode="exclusive")``, ``load``, ``commit``, ``close``) plus ``dev.rpc.<name>``, ``get_config``,
``rollback`` and the ``commit`` keywords ``confirm``, ``comment`` and ``timeout`` as PyEZ 2.8.3's source
defines them (verified); which PyEZ version Junos ships on the box is unknown (Q-RT-01), so each call is
unverified there. ``Device()`` is built with no arguments, as in the example; its connection-open timeout
is PyEZ's default of 30 s (research PYEZ-03, verified for 2.8.3). Unknown on the box and settled by lab
test Q-INST-05: whether an op script may run ``/sbin/sysctl``, write under ``/var/db/scripts/jet`` and
``/var/db/jwicket`` itself, and open a TCP connection (C8); ``jcs.get_input`` under ``op url``. Unknown,
Q-INST-03: whether removing ``language python3`` or this script's own stanza stops a running op script
(the revert removes both in its commit; the uninstall removes the stanza).

Rules kept by control flow and tested with recording fakes, as in the workstation executor (no run-time
chokepoint checks the gate): nothing written before the gate (INV-01); never
``commit check``, ``<check/>`` or ``<validate>`` (INV-02); the pending state re-read on the locked
session right before every commit and every confirm (INV-03); a confirm only while every check passed at
least 60 s before the deadline (INV-04); no configured path written in place or deleted outside the
plan's steps (INV-06); every RPC through ``transport.check_rpc`` (the names and arguments of
``INSTALL_RPCS``); reads retried, writes never; no shell; no ``subprocess`` but the one fixed veriexec
argument list; the TLS key is never read, written, printed or logged. Every device step is unverified
until lab test Q-INST-06.
"""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import importlib
import json
import logging
import os
import re
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, FrozenSet, Iterator, List, Mapping, Optional, Sequence, Set, TextIO, Tuple

from . import health, plan, render, state, transport
from .health import Result
from .plan import FileStep, InstallPlan, Layout, Method, Stage, StatementSet, UninstallPlan
from .transport import DeviceRefused, OutcomeUnknown, ReadTimeout, SessionLost, TransportError

LOG = logging.getLogger("jwicket_install.op")

# The floor every embedded module is written for (revision R1): Junos 25.2R1-S1.4 ships Python 3.7.10
# (verified on a lab SRX4100). build_op.py's prelude checks it before anything is compiled; main checks
# it again (tests call main directly).
MIN_PYTHON = (3, 7)
HOME_BUNDLE = "jwicket.py"  # the name the operator copies into the home directory (spec 6.5 step 4)
# The spike's exact command (plan.SHELL_VERIEXEC) run without a shell; /sbin is FreeBSD's place for
# sysctl (inferred for Junos), and whether an op script may run it is unknown (Q-INST-05).
SYSCTL_ARGV: Tuple[str, ...] = ("/sbin/sysctl", *plan.SHELL_VERIEXEC.split(" ")[1:])
POLL_S = 5
ROLLBACK_POLL_S = 10
RESULT_POLL_S = 2
STOP_WAIT_S = 10
MAX_ANSWER = 256
MAX_FILE_TEXT = 4 * 1024 * 1024
MAX_CERT_TEXT = 64 * 1024
UNINSTALL_ANSWER = "uninstall"
ROLLBACK_ANSWER = "rollback"
# The overrides an operator may type at this script's prompts (each recorded in the receipt). The
# workstation's transport overrides (host keys, provenance, plain HTTP) have no meaning on the box.
ONBOX_OVERRIDES: FrozenSet[str] = frozenset(
    {"--adopt", plan.LAB_HARDWARE_FLAG, "--ack-managed", "--ack-commit-scripts", "--veriexec-not-enforcing-ok"}
)
BOOTSTRAP_TEXTS: Mapping[str, Method] = {
    plan.bootstrap_comment("op", None): Method.ONBOX_LOCAL,
    plan.bootstrap_comment("op-url", None): Method.ONBOX_URL,
}
OP_STANZA = " ".join(plan.STANZA_KEYS["F-OP"])
OP_CHECKSUM = " ".join(plan.SPEC_BY_KEY["S14"].path)
TLS_CONTENTS = ("tls-key", "tls-cert")

# Revision R2 on the box: the access mode and the listen address are typed (an op script takes no option
# this script declares; jcs.get_input is the documented way to ask, [op-py-config], verified).
ACCESS_PROMPT_HEAD = "How will you reach J-Wicket?"
LISTEN_PROMPT_HEAD = "Type the device address your browser reaches"
LISTEN_ADDRESS_NEEDED = (
    "--access tls needs the device address your browser reaches, as an IP address (fxp0's when you manage "
    "the device through fxp0; 'show interfaces terse' lists its addresses); or choose tunnel"
)
# Why this script never makes the TLS key pair, and where the operator's pair must be.
TLS_NOT_MADE = (
    "This op script does not make the TLS key pair: whether an op script may run 'openssl' under veriexec is "
    "unknown ('python3' from the shell was refused there on a lab SRX4100, verified), and the private key must "
    "never leave the device. It reads only the certificate, never the key."
)
TLS_FILES_NEEDED = (
    "Make the pair once, in a shell on this device as {user} (deploy-lab's TLS unit, verified on SRX4100 "
    "25.2R1-S1.4; the shell openssl's version was not recorded; the shell is outside Juniper support), then "
    "run this script again, or "
    "choose tunnel. The last line prints the certificate's SHA-256 fingerprint: this script prints the same "
    "one, and your browser must show it too."
)
# C8 on the box with --access tls when the listener is in mgmt_junos (revision R3 and the lab's finding 2).
ONBOX_MGMT_C8_REASON = (
    "the listener is in routing instance mgmt_junos and this op script runs in the default instance: "
    "switching is process-wide (jcs.set_routing_instance stopped the process's own NETCONF to 127.0.0.1:830 on "
    "SRX4100, verified), so browse to the URL below and compare the certificate's fingerprint"
)
_FROM_OP_SCRIPT_RE = re.compile(r"^(?P<lead>  )write    (?P<path>\S+) mode (?P<mode>[0-7]{4}) from op-script\Z")


def access_prompt(default: str) -> str:
    return (
        f"{ACCESS_PROMPT_HEAD} Type tls (it listens with TLS on a device address you choose, port "
        f"{plan.DEFAULT_TLS_PORT}; this script needs {plan.TLS_KEY_PATH} and {plan.TLS_CERT_PATH} made by you "
        f"first) or tunnel (127.0.0.1 behind 'ssh -L', which a lab SRX4100 on 25.2R1-S1.4 refused). Press Enter "
        f"for {default}: "
    )


def listen_prompt(default: Optional[str]) -> str:
    tail = f"Press Enter for {default}: " if default else "Press Enter to stop: "
    return (
        f"{LISTEN_PROMPT_HEAD} (an IP address: fxp0's when you manage the device through fxp0; 'show interfaces "
        f"terse' lists them). {tail}"
    )


# ------------------------------------------------------------------------------------------------
# Errors and small types
# ------------------------------------------------------------------------------------------------


class Stop(Exception):
    """End the run with an exit code; the message has been printed."""

    def __init__(self, code: int) -> None:
        super().__init__(f"exit {code}")
        self.code = code


class LockFailed(TransportError):
    """The exclusive lock ('configure exclusive') was refused."""


class LocalFileError(Exception):
    """A local file failed a check or could not be written; the message says which and why."""


@dataclass(frozen=True)
class Payload:
    """What build_op.py embedded: the bundle's identity, its per-tag URL and the release it belongs to."""

    bundle: plan.BundleId
    bundle_url: str
    tag: Optional[str]
    repo: Optional[str]

    @classmethod
    def from_json(cls, text: str) -> Payload:
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise plan.InputError(f"the embedded payload is not JSON: {exc}") from exc
        if not isinstance(data, dict) or data.get("schema") != plan.PLAN_SCHEMA:
            raise plan.InputError("the embedded payload is not plan schema 2")
        raw = data.get("bundle")
        urls = data.get("urls")
        release = data.get("release") or {}
        if not isinstance(raw, dict) or not isinstance(urls, dict) or not isinstance(release, dict):
            raise plan.InputError("the embedded payload has no bundle, urls or release object")
        features = raw.get("features") or []
        if not isinstance(features, list):
            raise plan.InputError("the embedded bundle features are not a list")
        bundle = plan.BundleId(
            file_sha256=str(raw.get("file_sha256")),
            size=int(raw.get("size") or 0),
            version=str(raw.get("version")),
            source_ref=None if raw.get("source_ref") is None else str(raw.get("source_ref")),
            payload_sha256=str(raw.get("payload_sha256")),
            features=frozenset(str(f) for f in features),
        )
        url = plan.validate_url(str(urls.get("bundle")), allow_plain_http=False)
        tag = release.get("tag")
        repo = release.get("repo")
        for value in (tag, repo):
            if value is not None and (not isinstance(value, str) or plan.TOKEN_RE.match(value) is None):
                raise plan.InputError("the embedded release tag or repository is not a token")
        return cls(bundle, url, tag, repo)


@dataclass(frozen=True)
class Account:
    """The account Junos runs this script as (the invoking user). Its name and home directory come from
    the password database (inferred for Junos login accounts; Q-INST-05)."""

    uid: int
    name: str
    home: Optional[str]


def running_account() -> Account:
    import pwd  # Unix only; imported here so the module also imports where pwd is absent

    uid = os.geteuid()
    entry = pwd.getpwuid(uid)
    return Account(uid, entry.pw_name, entry.pw_dir or None)


@dataclass(frozen=True)
class BundleSource:
    """Where the bundle comes from: 'home-copy' (bytes read once, before the gate) or 'url'."""

    kind: str
    location: str
    data: Optional[bytes] = None

    def label(self) -> str:
        if self.kind == "home-copy":
            return f"the copy in your home directory, {self.location} (read once; SHA-256 checked)"
        return f"{self.location}, fetched by the device ('{plan.cli_file_copy(self.location, plan.STAGING_PATH)}')"


@dataclass
class Preflight:
    facts: plan.DeviceFacts
    prior: plan.PriorState
    evidence: plan.OwnershipEvidence
    method: Method


@dataclass
class StageResult:
    code: int
    after_commit: bool = False
    rolled_back: Optional[bool] = None
    session_lost: bool = False
    foreign_pending: bool = False


# ------------------------------------------------------------------------------------------------
# The operator's terminal: print() for output and jcs.get_input for prompts ([op-py-config], verified)
# ------------------------------------------------------------------------------------------------


class Console:
    def __init__(self, get_input: Callable[[str], Any], out: TextIO) -> None:
        self._get_input = get_input
        self._out = out

    def say(self, text: str = "") -> None:
        self._out.write(text + "\n")
        self._out.flush()

    def ask(self, prompt: str) -> Optional[str]:
        """One typed line, or None (no answer, end of input or an interrupt)."""
        try:
            answer = self._get_input(prompt)
        except (EOFError, KeyboardInterrupt):
            return None
        if not isinstance(answer, str):
            return None
        return answer[:MAX_ANSWER]


# ------------------------------------------------------------------------------------------------
# Local files: the home copy, the staging file and the files in /var/db/jwicket
# ------------------------------------------------------------------------------------------------

_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


class LocalFiles:
    """The few files this script reads or writes itself, every one by a fixed, validated path.

    ``root`` prefixes every path (tests point it at a temporary directory; on the device it is empty).
    Whether an op script may write under /var/db/scripts/jet and /var/db/jwicket is unknown (Q-INST-01,
    Q-INST-05); every write is read back by the file RPCs afterwards, so a refused or redirected write is
    caught. ``O_NOFOLLOW`` and ``O_EXCL`` keep another account's link or file from redirecting a write."""

    def __init__(self, root: str = "") -> None:
        self.root = root.rstrip("/")

    def _path(self, path: str) -> str:
        if not path.startswith("/") or "/../" in path + "/" or "\x00" in path:
            raise LocalFileError(f"{plan.sanitize_display(path)}: not a plain absolute path")
        return self.root + path

    def exists(self, path: str) -> bool:
        try:
            os.lstat(self._path(path))
        except FileNotFoundError:
            return False
        return True

    def read_once(self, path: str, uid: int, limit: int) -> bytes:
        """Spec 6.5 step 4: O_NOFOLLOW; fstat must show a regular file owned by ``uid`` and not group- or
        other-writable; the bytes are read once and must match the size fstat reported."""
        try:
            fd = os.open(self._path(path), os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC | _O_NONBLOCK)
        except OSError as exc:
            raise LocalFileError(f"{path} could not be opened without following a link: {exc.strerror}") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise LocalFileError(f"{path} is not a regular file")
            if info.st_uid != uid:
                raise LocalFileError(f"{path} is owned by uid {info.st_uid}, not the account running this script")
            if info.st_mode & 0o022:
                raise LocalFileError(f"{path} is writable by group or others (mode {info.st_mode & 0o777:04o})")
            if info.st_size > limit:
                raise LocalFileError(f"{path} is {info.st_size} bytes, more than {limit}")
            chunks: List[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise LocalFileError(f"{path} grew past {limit} bytes while it was read")
                chunks.append(chunk)
        finally:
            os.close(fd)
        data = b"".join(chunks)
        if len(data) != info.st_size:
            raise LocalFileError(f"{path} changed while it was read")
        return data

    def write_new(self, path: str, data: bytes, mode: int) -> None:
        """Create ``path`` with O_CREAT | O_EXCL | O_NOFOLLOW (an existing file or link refuses), write
        every byte, set ``mode`` exactly (the umask is not trusted), fsync."""
        try:
            fd = os.open(self._path(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC, mode)
        except OSError as exc:
            raise LocalFileError(f"{path} could not be created: {exc.strerror}") from exc
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fchmod(fd, mode)
            os.fsync(fd)
        except OSError as exc:
            raise LocalFileError(f"{path} could not be written: {exc.strerror}") from exc
        finally:
            os.close(fd)

    def state_dir_trusted(self, uid: int) -> bool:
        """The daemon's trust rule on /var/db/jwicket, re-checked before every write into it (lstat: a
        directory, not a link, owned by ``uid``, not group- or other-writable)."""
        try:
            info = os.lstat(self._path(plan.STATE_DIR))
        except OSError:
            return False
        return stat.S_ISDIR(info.st_mode) and info.st_uid == uid and not info.st_mode & 0o022

    def write_private(self, path: str, data: bytes, mode: int, uid: int) -> None:
        """A file in /var/db/jwicket (none of these names is a configured path, INV-06): created with
        O_EXCL, or, when it exists, opened with O_NOFOLLOW and rewritten only if fstat shows a regular
        file owned by ``uid``. The directory's trust rule is checked first."""
        directory, _, name = path.rpartition("/")
        if directory != plan.STATE_DIR or not name:
            raise LocalFileError(f"{path} is not a file in {plan.STATE_DIR}")
        if not self.state_dir_trusted(uid):
            raise LocalFileError(f"{plan.STATE_DIR} is not a directory owned by this account and closed to others")
        flags = os.O_WRONLY | _O_NOFOLLOW | _O_CLOEXEC
        try:
            fd = os.open(self._path(path), flags | os.O_CREAT | os.O_EXCL, mode)
        except FileExistsError:
            try:
                fd = os.open(self._path(path), flags)
            except OSError as exc:
                raise LocalFileError(f"{path} could not be opened without following a link: {exc.strerror}") from exc
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != uid:
                os.close(fd)
                raise LocalFileError(f"{path} exists and is not a regular file owned by this account") from None
            os.ftruncate(fd, 0)
        except OSError as exc:
            raise LocalFileError(f"{path} could not be created: {exc.strerror}") from exc
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fchmod(fd, mode)
            os.fsync(fd)
        except OSError as exc:
            raise LocalFileError(f"{path} could not be written: {exc.strerror}") from exc
        finally:
            os.close(fd)


# ------------------------------------------------------------------------------------------------
# The local device through on-box PyEZ
# ------------------------------------------------------------------------------------------------


def import_pyez() -> Tuple[Any, Any, Any]:
    """jnpr.junos Device, Config and the exception module (on-box PyEZ; its version is unknown, Q-RT-01)."""
    device_module = importlib.import_module("jnpr.junos")
    config_module = importlib.import_module("jnpr.junos.utils.config")
    errors = importlib.import_module("jnpr.junos.exception")
    return device_module.Device, config_module.Config, errors


def _reply_text(reply: Any) -> str:
    """PyEZ returns an lxml element, or True for a bare <ok/>; state.py parses text."""
    if isinstance(reply, str):
        return reply
    if isinstance(reply, bytes):
        return reply.decode("utf-8", "replace")
    if reply is True or reply is None:
        return "<ok/>"
    etree = importlib.import_module("lxml.etree")
    return str(etree.tostring(reply, encoding="unicode"))


def _message(exc: BaseException) -> str:
    return plan.sanitize_display(str(exc) or type(exc).__name__, 300)


class LocalJunos:
    """The local device: ``Device()`` with no host, the RPC timeout set to 60 s, every RPC checked by
    ``transport.check_rpc``; reads retried with back-off, writes never (SC-17)."""

    def __init__(
        self,
        device_factory: Callable[..., Any],
        config_factory: Callable[..., Any],
        errors: Any,
        clock: transport.Clock,
        *,
        xml: Optional[Callable[[str], Any]] = None,
    ) -> None:
        self._device_factory = device_factory
        self._config_factory = config_factory
        self._errors = errors
        self._clock = clock
        self._xml = xml
        self._dev: Any = None

    def open(self) -> None:
        try:
            dev = self._device_factory()
            dev.open()
        except self._errors.ConnectError as exc:
            raise TransportError(f"the local device did not open a session for this script: {_message(exc)}") from exc
        dev.timeout = plan.TIMEOUTS["rpc"]
        self._dev = dev

    def close(self) -> None:
        if self._dev is None:
            return
        try:
            self._dev.close()
        except Exception as exc:  # noqa: BLE001 - closing is best effort and must never mask the run's outcome
            LOG.debug("closing the local session failed: %s", type(exc).__name__)
        self._dev = None

    def _invoke(self, name: str, args: Mapping[str, transport.ArgValue], kind: str) -> transport.Reply:
        transport.check_rpc(name, args, kind)
        errors = self._errors
        method = getattr(self._dev.rpc, name.replace("-", "_"))
        kwargs = {key.replace("-", "_"): value for key, value in args.items()}
        try:
            reply = method(dev_timeout=plan.TIMEOUTS["rpc"], **kwargs)
        except errors.RpcTimeoutError as exc:
            if kind == "read":
                raise ReadTimeout(f"{name} timed out") from exc
            raise OutcomeUnknown(f"{name} timed out; it may have run") from exc
        except errors.ConnectClosedError as exc:
            raise SessionLost(f"the local session closed during {name}") from exc
        except errors.RpcError as exc:
            if kind == "write":
                raise DeviceRefused(f"the device refused {name}: {_message(exc)}") from exc
            return state.RpcErrorReply(str(exc))
        text = _reply_text(reply)
        LOG.debug("%s answered %d bytes", name, len(text))
        return text

    def read(self, name: str, **args: transport.ArgValue) -> transport.Reply:
        return transport.retry_read(lambda: self._invoke(name, args, "read"), name, self._clock.sleep)

    def write(self, name: str, **args: transport.ArgValue) -> transport.Reply:
        return self._invoke(name, args, "write")

    def _filter(self) -> Any:
        if self._xml is not None:
            return self._xml(transport.CONFIG_FILTER)
        etree = importlib.import_module("lxml.etree")
        return etree.XML(transport.CONFIG_FILTER)

    def get_configuration(self, *, database: str, inherit: bool) -> transport.Reply:
        if database not in transport.DATABASES:
            raise ValueError(f"database {database!r} is not committed or candidate")
        transport.check_rpc("get-configuration", {}, "read")
        options = {"database": database}
        if inherit:
            options["inherit"] = "inherit"
        errors = self._errors

        def call() -> transport.Reply:
            try:
                reply = self._dev.rpc.get_config(
                    filter_xml=self._filter(), options=dict(options), dev_timeout=plan.TIMEOUTS["rpc"]
                )
            except errors.RpcTimeoutError as exc:
                raise ReadTimeout("get-configuration timed out") from exc
            except errors.ConnectClosedError as exc:
                raise SessionLost("the local session closed during get-configuration") from exc
            except errors.RpcError as exc:
                return state.RpcErrorReply(str(exc))
            return _reply_text(reply)

        return transport.retry_read(call, "get-configuration", self._clock.sleep)

    def compare(self, rollback: int) -> Optional[str]:
        """The candidate against rollback 0 (Junos's 'show | compare', [xml-compare], verified) or 1 (on an
        unchanged candidate, the committed delta: inferred), in patch form."""
        if rollback not in (0, 1):
            raise ValueError("compare takes rollback 0 or 1")
        transport.check_rpc("get-configuration", {}, "read")
        errors = self._errors

        def call() -> transport.Reply:
            try:
                reply = self._dev.rpc.get_configuration(
                    {"compare": "rollback", "rollback": str(rollback), "format": "text"},
                    dev_timeout=plan.TIMEOUTS["rpc"],
                )
            except errors.RpcTimeoutError as exc:
                raise ReadTimeout("compare timed out") from exc
            except errors.ConnectClosedError as exc:
                raise SessionLost("the local session closed during compare") from exc
            except errors.RpcError as exc:
                return state.RpcErrorReply(str(exc))
            return _reply_text(reply)

        return transport.output_text(
            transport.retry_read(call, "compare", self._clock.sleep), ("configuration-output",)
        )

    @contextlib.contextmanager
    def exclusive(self) -> Iterator[Candidate]:
        """``Config(dev, mode="exclusive")``: it locks the candidate on entry and unlocks it on exit (PyEZ
        2.8.3 ``utils/config.py``, verified; Juniper's op-script example uses the same mode). Never a
        private or ephemeral database, where a confirmed commit is impossible ([xml-confirm], verified)."""
        transport.check_rpc("lock-configuration", {}, "write")
        manager = self._config_factory(self._dev, mode="exclusive")
        errors = self._errors
        try:
            cu = manager.__enter__()
        except errors.ConnectClosedError as exc:
            raise SessionLost("the local session closed at the lock") from exc
        except errors.RpcError as exc:
            raise LockFailed(f"the exclusive lock ('configure exclusive') was refused: {_message(exc)}") from exc
        try:
            yield Candidate(cu, errors)
        finally:
            try:
                transport.check_rpc("unlock-configuration", {}, "write")
                manager.__exit__(None, None, None)
            except Exception as exc:  # noqa: BLE001 - an unlock that fails (session gone) must not mask the outcome
                LOG.info("unlock: %s", _message(exc))


class Candidate:
    """The locked candidate: load, discard, the one rollback the installer loads, and commits. Never
    ``<check/>`` (INV-02): PyEZ's commit sends <confirmed/> and <confirm-timeout> or <log> alone."""

    def __init__(self, cu: Any, errors: Any) -> None:
        self._cu = cu
        self._errors = errors

    def _call(self, what: str, call: Callable[[], Any]) -> None:
        errors = self._errors
        try:
            call()
        except errors.RpcTimeoutError as exc:
            raise OutcomeUnknown(f"{what} timed out; it may have happened") from exc
        except errors.ConnectClosedError as exc:
            raise SessionLost(f"the local session closed during {what}") from exc
        except errors.RpcError as exc:
            raise DeviceRefused(f"the device refused {what}: {_message(exc)}") from exc
        except ValueError as exc:
            raise DeviceRefused(f"{what}: {_message(exc)}") from exc

    def load_set(self, lines: Sequence[str]) -> None:
        transport.check_rpc("load-configuration", {}, "write")
        text = "\n".join(lines)
        self._call("the load of the stage's set lines", lambda: self._cu.load(text, format="set"))

    def discard(self) -> None:
        transport.check_rpc("load-configuration", {}, "write")
        self._call("rollback 0 (discarding the candidate)", lambda: self._cu.rollback(0))

    def load_rollback_1(self) -> None:
        transport.check_rpc("load-configuration", {}, "write")
        self._call("loading rollback 1", lambda: self._cu.rollback(1))

    def commit(self, comment: str, confirm: Optional[plan.Minutes]) -> None:
        transport.check_rpc("commit-configuration", {}, "write")
        kwargs: Dict[str, Any] = {"comment": comment, "timeout": plan.TIMEOUTS["commit"]}
        if confirm is not None:
            kwargs["confirm"] = int(confirm)
        what = f"commit confirmed {int(confirm)}" if confirm is not None else "the confirming commit"
        self._call(what, lambda: self._cu.commit(**kwargs))


HttpsGet = Callable[[str, int, str, str, str], transport.HttpsResult]


def pinned_https(address: str, port: int, path: str, host_header: str, pin_sha256: str) -> transport.HttpsResult:
    """C8 on the box with --access tls: ``transport.https_get`` (standard library ``ssl``, which the
    SRX4100's probe reported ok, verified), which sends nothing until the peer's certificate has the pinned
    SHA-256. Whether an op script may open this connection is unknown (Q-INST-05): a connection that
    cannot be made is "not available" (the plan's if_unavailable), a wrong certificate or answer fails."""
    return transport.https_get(address, port, path, host_header, pin_sha256)


def read_veriexec_sysctl() -> Tuple[Optional[str], str]:
    """The spike's command without a shell: (output or None, why not). A fixed argument list, a 5 s
    timeout, an empty environment; nothing from the device or the operator reaches the argument list."""
    try:
        done = subprocess.run(  # noqa: S603 - a fixed argument list of constants, no shell
            list(SYSCTL_ARGV),
            capture_output=True,
            timeout=plan.TIMEOUTS["veriexec-read"],
            check=False,
            env={},
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return None, _message(exc)
    if done.returncode != 0:
        return None, f"{SYSCTL_ARGV[0]} exited {done.returncode}"
    return done.stdout.decode("utf-8", "replace")[:4096], ""


def _safe_lines(text: Optional[str], limit: int = 200) -> List[str]:
    if not text:
        return []
    return [plan.sanitize_display(line, 300) for line in text.splitlines()[:limit] if line.strip()]


def _described(info: plan.FileInfo) -> str:
    """A listed entry's type, owner and mode, for a message (all from file-list, validated by state.py)."""
    kind = "a symbolic link" if info.is_symlink else ("a directory" if info.is_dir else "a file")
    mode = "unknown" if info.mode is None else f"{info.mode:04o}"
    return f"{kind}, owner {info.owner or 'unknown'}, mode {mode}"


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ------------------------------------------------------------------------------------------------
# The executor
# ------------------------------------------------------------------------------------------------


class OpExecutor:
    """One run of the op script. ``box`` is the local device, ``files`` the script's own file access,
    ``sysctl`` the veriexec read and ``https`` C8's pinned HTTPS read (each injectable for tests)."""

    def __init__(
        self,
        payload: Payload,
        box: LocalJunos,
        console: Console,
        clock: transport.Clock,
        account: Account,
        *,
        files: Optional[LocalFiles] = None,
        sysctl: Callable[[], Tuple[Optional[str], str]] = read_veriexec_sysctl,
        https: HttpsGet = pinned_https,
        now: Callable[[], str] = _utc_now,
    ) -> None:
        self.payload = payload
        self.bundle = payload.bundle
        self.box = box
        self.console = console
        self.clock = clock
        self.account = account
        self.user = account.name
        self.files = files or LocalFiles()
        self.sysctl = sysctl
        self.https = https
        self.now = now
        # The listener of the plan being run (C8) and the certificate's SHA-256 read from tls.crt (--access
        # tls): the fingerprint printed, pinned by C8 and recorded. The key is never read.
        self.options: Optional[plan.Options] = None
        self.routing_instance: Optional[str] = None
        self.cert_sha256: Optional[str] = None
        self.lab_attested = False
        self.layout = Layout.DIRECT
        self.overrides: Set[str] = set()
        self.created: List[str] = []
        self.confirmed: List[str] = []
        self.commits: List[plan.ReceiptCommit] = []
        self.bootstrap_confirmed = False
        self.installed = False
        self.last_result: Optional[StageResult] = None
        self.source: Optional[BundleSource] = None

    def say(self, text: str = "") -> None:
        self.console.say(text)

    # -- the run ----------------------------------------------------------------------------------

    def run(self) -> int:
        try:
            plan.validate_user(self.user)
        except plan.InputError as exc:
            self.say(f"This account cannot run J-Wicket: {exc}")
            return plan.EXIT_INPUT
        if self.user == "root":
            self._refusal("R-ROOT", "this script runs as root")
            return plan.EXIT_REFUSED
        try:
            self.box.open()
        except TransportError as exc:
            self.say(f"{exc}. Nothing was read or written.")
            return plan.EXIT_REFUSED
        try:
            return self._run()
        except Stop as stop:
            return stop.code
        finally:
            self.box.close()

    def _run(self) -> int:
        pre = self.preflight()
        if self._installed(pre.prior):
            answer = self.console.ask(
                "J-Wicket is installed on this device. Type uninstall to plan its removal, or press Enter to plan "
                "an install, upgrade or repair: "
            )
            if answer is not None and answer.strip() == UNINSTALL_ANSWER:
                return self.uninstall(pre)
        self.source = self.bundle_source()
        return self.install(pre, self.source)

    @staticmethod
    def _installed(prior: plan.PriorState) -> bool:
        return any(name in prior.jwicket_stanzas for name in plan.JWICKET_JET_FILES)

    # -- reads (spec 8.3) -------------------------------------------------------------------------

    def _read(self, name: str, **args: transport.ArgValue) -> transport.Reply:
        return self.box.read(name, **args)

    def _config(self, database: str, inherit: bool) -> StatementSet:
        reply = self.box.get_configuration(database=database, inherit=inherit)
        if state._config_root(reply) is None:
            self.say(f"The {database} configuration could not be read: {transport.error_text(reply) or 'no data'}")
            raise Stop(plan.EXIT_REFUSED)
        return state.statements_from_config(reply)

    def _listing(self, directory: str) -> Optional[state.DirListing]:
        return state.file_list_from_reply(self._read("file-list", detail=True, path=directory), directory)

    def _info(self, path: str) -> Optional[plan.FileInfo]:
        listing = self._listing(path.rpartition("/")[0] or "/")
        if listing is None:
            return None
        return next((e for e in listing.entries if e.path == path), None)

    def _checksum(self, path: str) -> Optional[str]:
        return state.checksum_from_reply(self._read("get-sha256-checksum-information", path=path))

    def _file_text(self, path: str) -> Optional[str]:
        return state.file_text_from_reply(self._read("file-show", filename=path), limit=MAX_FILE_TEXT)

    def _commit_state(self) -> state.CommitState:
        return state.commit_state_from_reply(self._read("get-commit-information"))

    def _delta(self, sequence: int) -> Optional[str]:
        if sequence + 1 > transport.MAX_ROLLBACK:
            return None
        # The older configuration (n+1) is the base and the newer (n) is compared with it, so '+' means added
        # by commit n ([netconf-pdf] "Compare Two Previous (Rollback) Configurations Using NETCONF", verified).
        reply = self._read("get-rollback-information", rollback=str(sequence + 1), compare=str(sequence))
        return transport.output_text(reply, ("configuration-output", "output", "rollback-information"))

    def _veriexec(self) -> Tuple[Optional[str], str]:
        text, why = self.sysctl()
        if text is not None and state.parse_veriexec(text) is not None:
            return text, "op script read"
        self.say(
            f"This script could not read the veriexec state itself ({why or 'the output was not recognised'}; "
            "whether an op script may run sysctl is unknown, Q-INST-05)."
        )
        typed = self.console.ask(
            f"In another SSH or console session on this device run '{plan.SHELL_START}', then "
            f"'{plan.SHELL_VERIEXEC}', then '{plan.SHELL_EXIT}' (the shell is outside Juniper support), and type "
            "here exactly what it printed, or press Enter if you cannot: "
        )
        if typed is None or not typed.strip():
            return None, "not read"
        return typed.strip(), "read by hand"

    def preflight(self) -> Preflight:
        try:
            return self._preflight()
        except (ReadTimeout, SessionLost, OutcomeUnknown) as exc:
            self.say(f"The device could not be read: {exc}. Nothing was written.")
            raise Stop(plan.EXIT_REFUSED) from exc

    def _preflight(self) -> Preflight:
        software = self._read("get-software-information")
        cluster = self._read("get-chassis-cluster-status")
        inventory = self._read("get-chassis-inventory")
        flow = self._read("get-flow-session-information", summary=True)
        raw = self.box.get_configuration(database="committed", inherit=False)
        inherited = self.box.get_configuration(database="committed", inherit=True)
        commits = self._read("get-commit-information")
        lists = {d: self._read("file-list", detail=True, path=d) for d in plan.READ_DIRS}
        script_lists = {d: self._read("file-list", detail=True, path=d) for d in plan.S1_SCRIPT_DIRS}
        listed: Set[str] = set()
        for directory, reply in lists.items():
            parsed = state.file_list_from_reply(reply, directory)
            if parsed is not None:
                listed |= {e.path for e in parsed.entries}
        checksums: Dict[str, transport.Reply] = {}
        for path in (*(f"{plan.JET_DIR}/{n}" for n in plan.JWICKET_JET_FILES), plan.SETTINGS_PATH):
            if path in listed:
                checksums[path] = self._read("get-sha256-checksum-information", path=path)
        device_receipt = self._file_text(plan.RECEIPT_PATH) if plan.RECEIPT_PATH in listed else None
        veriexec, source = self._veriexec()
        prior = state.prior_from_replies(
            inherited,
            raw,
            commits,
            lists,
            {"device": device_receipt, "workstation": None},
            veriexec,
            checksums=checksums,
            veriexec_source=source,
            script_lists=script_lists,
        )
        facts = state.facts_from_replies(
            software, cluster, inventory, raw, flow_sessions=state.flow_session_count(flow)
        )
        deltas: Dict[int, str] = {}
        newest = prior.newest
        if prior.pending is plan.Pending.OTHER and newest is not None and newest.sequence == 0:
            kinds = [m for text, m in BOOTSTRAP_TEXTS.items() if text in newest.texts]
            delta = self._delta(0) if kinds else None
            if delta is not None:
                deltas[0] = delta
                for method in kinds:
                    found = plan.recognise_bootstrap(prior, method=method, user=self.user, nonce=None, delta_text=delta)
                    if found is not None:
                        prior = plan.mark_own_bootstrap(prior, found)
                        break
        for entry in prior.history:
            if entry.sequence not in deltas and any(plan.is_installer_comment(t) for t in entry.texts):
                delta = self._delta(entry.sequence)
                if delta is not None:
                    deltas[entry.sequence] = delta
        evidence = plan.ownership_from_history(prior.history, deltas, user=self.user)
        self._note_confirmed_by_others(prior)
        return Preflight(facts, prior, evidence, self._method(prior))

    def _method(self, prior: plan.PriorState) -> Method:
        """M4 or M4U: from the own pending bootstrap's comment; otherwise M4 when the op stanza is configured
        (a local op script must be configured to run; inferred that this run is that script)."""
        if prior.own_bootstrap is not None:
            return prior.own_bootstrap.method
        return Method.ONBOX_LOCAL if prior.effective.under(OP_STANZA) else Method.ONBOX_URL

    def _note_confirmed_by_others(self, prior: plan.PriorState) -> None:
        """Spec 6.5 risks: a 'jwicket-bootstrap op' entry that is not pending, that this script never
        confirmed, and whose statement is still configured: another administrator's commit confirmed it
        (inferred from [commit-cmd]). A bootstrap that Junos rolled back leaves its statement absent."""
        if prior.own_bootstrap is not None or prior.pending is not plan.Pending.NONE:
            return
        marks = {
            plan.bootstrap_comment("op", None): plan.STANZA_KEYS["F-OP"],
            plan.bootstrap_comment("op-url", None): plan.SPEC_BY_KEY["S9"].path,
        }
        entries = sorted(prior.history, key=lambda e: e.sequence)
        for index, entry in enumerate(entries):
            comment = next((t for t in entry.texts if t in BOOTSTRAP_TEXTS), None)
            if comment is None or not prior.effective.under(" ".join(marks[comment])):
                continue
            newer = entries[:index]
            if any(comment + " confirmed" in e.texts for e in newer):
                continue
            self.say(
                f"Note: your bootstrap commit '{comment}' (history entry {entry.sequence}) was confirmed by a later "
                "commit that this script did not make. Its statements stay configured. To remove them, run this "
                "script again and choose uninstall, or remove them by hand."
            )
            return

    # -- the bundle source (spec 6.5 step 4) --------------------------------------------------------

    def bundle_source(self) -> BundleSource:
        home = self.account.home
        if home and home.startswith("/") and "/../" not in home + "/":
            path = home.rstrip("/") + "/" + HOME_BUNDLE
            if self.files.exists(path):
                try:
                    data = self.files.read_once(path, self.account.uid, plan.MAX_BUNDLE_SIZE)
                except LocalFileError as exc:
                    self.say(f"The home-directory copy cannot be used: {exc}. Nothing was written.")
                    raise Stop(plan.EXIT_INTEGRITY) from exc
                actual = hashlib.sha256(data).hexdigest()
                if actual != self.bundle.file_sha256 or len(data) != self.bundle.size:
                    self.say(
                        f"{path} is not the bundle this op script was built for: SHA-256 {actual}, expected "
                        f"{self.bundle.file_sha256}. Nothing was written."
                    )
                    raise Stop(plan.EXIT_INTEGRITY)
                return BundleSource("home-copy", path, data)
        return BundleSource("url", self.payload.bundle_url)

    def _access(self, prior: plan.PriorState) -> Tuple[str, Optional[str]]:
        """Revision R2 on the box: tls (the default) or tunnel, and for tls the listen address. The advisory
        device receipt (INV-11) only suggests the defaults; the operator's answer decides."""
        receipt = prior.device_receipt
        default = receipt.access if receipt is not None else plan.DEFAULT_ACCESS
        typed = self.console.ask(access_prompt(default))
        if typed is None:
            raise plan.InputError("no access mode was typed")
        access = typed.strip() or default
        if access not in plan.ACCESS_MODES:
            raise plan.InputError(f"access {plan.sanitize_display(access)[:40]!r} must be tls or tunnel")
        if access == "tunnel":
            return access, None
        known = receipt.listen_address if receipt is not None and receipt.access == "tls" else None
        typed = self.console.ask(listen_prompt(known))
        address = (typed or "").strip() or known
        if not address:
            raise plan.InputError(LISTEN_ADDRESS_NEEDED)
        return access, plan.canonical_address(address)

    def _options(self, source: BundleSource, access: str, listen_address: Optional[str]) -> plan.Options:
        # For this script, transfer "scp" means "the executor writes the bytes it holds" (the home copy);
        # the plan's "workstation" source then means this script, never a workstation.
        if source.kind == "home-copy":
            return plan.Options(user=self.user, transfer="scp", access=access, listen_address=listen_address)
        return plan.Options(
            user=self.user,
            transfer="file-copy",
            pull_url=source.location,
            access=access,
            listen_address=listen_address,
        )

    def _provenance(self, method: Method) -> plan.Provenance:
        """The trust anchor is the hash the operator pinned for this op script (S14, or op url's key),
        taken from docs/releases/<tag>.sha256sums on main as unit 0 says: an operator-supplied hash (P-E).
        This script cannot tell which channel the operator really used."""
        pinned = "pinned-by:S14" if method is Method.ONBOX_LOCAL else "pinned-by:op-url-key"
        detail = [pinned]
        if self.payload.tag:
            detail.append(f"expected-source:docs/releases/{self.payload.tag}.sha256sums")
        return plan.Provenance("operator-hash", tuple(detail), True)

    # -- install ----------------------------------------------------------------------------------

    def _build(self, pre: Preflight, options: plan.Options) -> InstallPlan:
        op_values = pre.prior.effective.values(OP_CHECKSUM)
        op_sha = op_values[0] if len(op_values) == 1 and plan.SHA256_RE.match(op_values[0]) else None
        built = plan.build_install_plan(
            self.bundle,
            self._provenance(pre.method),
            options,
            pre.facts,
            pre.prior,
            method=pre.method,
            overrides=frozenset(self.overrides),
            evidence=pre.evidence,
            op_sha256=op_sha if pre.method is Method.ONBOX_LOCAL else None,
        )
        self.options = built.options
        self.routing_instance = built.routing_instance
        return built

    def install(self, pre: Preflight, source: BundleSource) -> int:
        try:
            access, listen_address = self._access(pre.prior)
            options = self._options(source, access, listen_address)
        except plan.InputError as exc:
            self.say(f"{exc}. Nothing was written.")
            return plan.EXIT_INPUT
        self.layout = options.layout
        try:
            built = self._build(pre, options)
        except plan.InvariantError as exc:
            self.say(f"The installer built a plan that breaks its own rules (a defect; nothing was sent): {exc}")
            return plan.EXIT_REFUSED
        except plan.InputError as exc:
            self.say(f"The plan cannot be built: {exc}. Nothing was written.")
            return plan.EXIT_INPUT
        try:
            tls_problem = self._tls_pair(pre.prior) if options.tls else None
        except (ReadTimeout, SessionLost, OutcomeUnknown) as exc:
            self.say(f"The device could not be read: {exc}. Nothing was written.")
            return plan.EXIT_REFUSED
        self._show_plan(built, pre.prior, source)
        if tls_problem is None and built.blocked and self._ask_overrides(built.refusals):
            try:
                built = self._build(pre, options)
            except plan.PlanError as exc:
                self.say(f"The plan cannot be built with these overrides: {exc}. Nothing was written.")
                return plan.EXIT_REFUSED
            self.say("Overrides recorded: " + ", ".join(sorted(self.overrides)))
        if built.blocked or tls_problem is not None:
            # R4 first: the root step makes the directory the operator's TLS unit then writes into.
            if any(r.code == "R-STATEDIR" and not r.overridden for r in built.refusals):
                self.say(plan.directory_fallback(self.user))
            if tls_problem is not None:
                self._tls_help(tls_problem, options)
            self.say("Refused before any write. Nothing was changed.")
            if built.bootstrap is not None:
                self.say(self._deadline_text(built.bootstrap))
            return plan.EXIT_REFUSED
        if self._no_change(built):
            self.say("Nothing to change: this bundle is already installed. Read-only checks:")
            return self._status_checks(built)
        self.gate(pre.facts, built.bootstrap, lab_hardware=built.lab_hardware, signs=built.production_signs)
        return self._apply(built, pre)

    @staticmethod
    def _no_change(built: InstallPlan) -> bool:
        """SC-14 on the box: the plan's own no_change, or nothing to do but check the operator's TLS pair (a
        'write' of source op-script, which this script never writes: an idempotent re-run reads it again)."""
        if built.no_change:
            return True
        if built.stages or built.bootstrap is not None:
            return False
        if built.directory is not None and built.directory.action != "keep":
            return False
        return all(f.action == "keep" or (f.content in TLS_CONTENTS and f.source == "op-script") for f in built.files)

    # -- the operator's TLS pair (revision R2 on the box) ---------------------------------------------

    def _tls_pair(self, prior: plan.PriorState) -> Optional[str]:
        """What is wrong with the operator's TLS pair in /var/db/jwicket, or None (then ``cert_sha256`` holds
        the certificate's fingerprint). The key: a regular file owned by this account, mode 0600, never read.
        The certificate: a regular file owned by this account, not group- or other-writable, holding a PEM
        certificate (read with file-show; it is public)."""
        user = self.user
        problems: List[str] = []
        key = prior.files.get(plan.TLS_KEY_PATH)
        cert = prior.files.get(plan.TLS_CERT_PATH)
        if key is None:
            problems.append(f"{plan.TLS_KEY_PATH} is not there")
        elif key.is_dir or key.is_symlink or key.owner != user or key.mode != plan.TLS_KEY_MODE:
            problems.append(
                f"{plan.TLS_KEY_PATH} must be a regular file owned by {user} with mode 0600 ({_described(key)}); a "
                "key others could read is not private any more: make a new pair"
            )
        if cert is None:
            problems.append(f"{plan.TLS_CERT_PATH} is not there")
        elif cert.is_dir or cert.is_symlink or cert.owner != user or cert.mode is None or cert.mode & 0o022:
            problems.append(
                f"{plan.TLS_CERT_PATH} must be a regular file owned by {user}, writable by its owner only "
                f"({_described(cert)})"
            )
        else:
            sha = self._certificate_sha256()
            if sha is None:
                problems.append(f"{plan.TLS_CERT_PATH} holds no PEM certificate this script can read")
            else:
                self.cert_sha256 = sha
        return "; ".join(problems) or None

    def _certificate_sha256(self) -> Optional[str]:
        """The SHA-256 of the DER form of the certificate in tls.crt: the fingerprint a browser shows."""
        text = self._file_text(plan.TLS_CERT_PATH)
        if not text or len(text) > MAX_CERT_TEXT:
            return None
        return transport.pem_certificate_sha256(text.encode("ascii", "replace"))

    def _tls_help(self, problem: str, options: plan.Options) -> None:
        address = options.bind_address
        self.say(f"--access tls on the box needs your TLS key pair in {plan.STATE_DIR} first: {problem}.")
        self.say(TLS_NOT_MADE)
        self.say(TLS_FILES_NEEDED.replace("{user}", self.user))
        unit = render.PasteUnit(
            "T", "the TLS certificate (on the device)", "device-shell", plan.shell_tls_lines(address)
        )
        self.say(render.units_to_text((unit,)).rstrip("\n"))

    def _show_plan(self, built: InstallPlan, prior: plan.PriorState, source: BundleSource) -> None:
        # DEVICE_STATUS was the first line of this run; "workstation" in the plan means this script here,
        # and a TLS file "from op-script" is the operator's own, which this script only checks.
        text = render.render_plan_text(built, prior, status=False).rstrip("\n")
        lines = []
        for line in text.replace(" from workstation", " from this op script").splitlines():
            match = _FROM_OP_SCRIPT_RE.match(line)
            if match is not None:
                line = (
                    f"{match.group('lead')}check    {match.group('path')} mode {match.group('mode')} (yours, made in "
                    "the shell; this script never writes the TLS key pair)"
                )
            lines.append(line)
        self.say("\n".join(lines))
        self.say("")
        self.say(f"Method: {built.method.value} (this op script, running as {self.user}).")
        self.say("Bundle source: " + source.label() + f"; it must have SHA-256 {self.bundle.file_sha256}.")
        if self.cert_sha256 is not None:
            fingerprint = plan.fingerprint_display(self.cert_sha256)
            self.say(
                f"TLS certificate {plan.TLS_CERT_PATH}: SHA-256 fingerprint {fingerprint}. Your browser must show the "
                "same one."
            )
        if built.bootstrap is not None:
            self.say(
                f"Your bootstrap ({built.bootstrap.comment}) is pending and unconfirmed. This script confirms it only "
                "after the gate; otherwise Junos removes it at its deadline."
            )

    def _ask_overrides(self, refusals: Sequence[plan.Refusal]) -> bool:
        """Overridable refusals (spec 8.11) are offered one by one, typed exactly; a refusal without an
        override that applies here blocks the run without a question."""
        open_refusals = [r for r in refusals if not r.overridden]
        if not open_refusals or any(r.override not in ONBOX_OVERRIDES for r in open_refusals):
            return False
        for refusal in open_refusals:
            flag = str(refusal.override)
            if flag in self.overrides:
                continue
            answer = self.console.ask(
                f"{refusal.code} can be overridden: type {flag} to continue (recorded in the receipt), or press "
                "Enter to stop: "
            )
            if answer is None or answer.strip() != flag:
                return False
            self.overrides.add(flag)
        return True

    def _refusal(self, code: str, detail: str = "") -> None:
        message, override = plan.REFUSALS[code]
        self.say(f"{code}: {message}")
        if detail:
            self.say(f"  {plan.sanitize_display(detail)}")
        if override:
            self.say(f"  Override: {override} (recorded).")

    @staticmethod
    def _deadline_text(bootstrap: plan.Bootstrap) -> str:
        return (
            f"Your bootstrap commit ({bootstrap.comment}) stays unconfirmed: Junos removes it at its deadline, "
            f"{bootstrap.deadline_text}."
        )

    def gate(
        self,
        facts: plan.DeviceFacts,
        bootstrap: Optional[plan.Bootstrap],
        *,
        lab_hardware: bool = False,
        signs: Sequence[str] = (),
    ) -> None:
        """Spec 8.2: the typed answer against the device's own host name, which was never printed; then, on
        lab hardware (R5), the production signs again and the typed 'lab only'."""
        typed = self.console.ask(plan.LAB_GATE_PROMPT)
        if not plan.lab_gate_matches(typed, facts):
            self.say("That is not this device's host name (or nothing was typed). Nothing was written.")
            if bootstrap is not None:
                self.say(self._deadline_text(bootstrap))
            raise Stop(plan.EXIT_GATE)
        self.say(f"Lab gate passed for {facts.hostname}.")
        if lab_hardware:
            self._lab_only(bootstrap, signs)

    def _lab_only(self, bootstrap: Optional[plan.Bootstrap], signs: Sequence[str]) -> None:
        """R5: a physical SRX goes on only after the operator types 'lab only' exactly, the production signs
        shown first. The statement is recorded in the receipt; it proves nothing (spec 8.2)."""
        self.say(plan.LAB_HARDWARE_WARNING)
        if signs:
            self.say("Production signs of this device (shown, not judged):")
            for sign in signs:
                self.say(f"  {sign}")
        typed = self.console.ask(plan.LAB_HARDWARE_PROMPT)
        if not plan.lab_hardware_matches(typed):
            self.say(f"'{plan.LAB_HARDWARE_ANSWER}' was not typed. Nothing was written.")
            if bootstrap is not None:
                self.say(self._deadline_text(bootstrap))
            raise Stop(plan.EXIT_GATE)
        self.lab_attested = True
        self.say(f"Recorded: you stated that this device carries only lab traffic ({plan.LAB_HARDWARE_FLAG}).")

    def _apply(self, built: InstallPlan, pre: Preflight) -> int:
        # The state directory's trust again, before the bootstrap's confirm, so a change since the plan's
        # read leaves the bootstrap unconfirmed (R4: this script never creates or repairs it).
        code = self._directory_still_trusted()
        if code:
            return code
        boot = built.stage("bootstrap")
        if boot is not None:
            code = self._confirm_bootstrap(boot, pre.prior)
            if code:
                self._remove_created_files(built)
                return code
        try:
            code = self._install_stages(built)
        finally:
            if not self.installed:
                self._after_failure(built)
        if code:
            return code
        # Installed and confirmed: what follows is reported if it fails, never reverted.
        self._final_files(built)
        self._summary(built)
        return plan.EXIT_OK

    def _install_stages(self, built: InstallPlan) -> int:
        code = self._files(built)
        if code:
            return code
        for stage in built.stages:
            if stage.already_committed:
                continue
            result = self._run_stage(stage)
            self.last_result = result
            if result.code != plan.EXIT_OK:
                return result.code
        self.installed = True
        return plan.EXIT_OK

    # -- A2: the state directory, root's (revision R4) ------------------------------------------------

    def _directory_still_trusted(self) -> int:
        """Read /var/db again: /var/db/jwicket must still be a directory, not a link, owned by this account,
        mode 0700. Otherwise nothing is written and the root step is printed (exit 1)."""
        try:
            listing = self._listing(plan.VAR_DB)
        except TransportError as exc:
            self.say(f"{plan.VAR_DB} could not be listed again: {exc}. Nothing was written.")
            return plan.EXIT_REFUSED
        info = None if listing is None else next((e for e in listing.entries if e.path == plan.STATE_DIR), None)
        if info is not None and plan.state_dir_untrusted(info, self.user) is None:
            return plan.EXIT_OK
        shown = "not listed" if info is None else _described(info)
        self._refusal("R-STATEDIR", f"{plan.STATE_DIR} changed since it was read ({shown})")
        self.say(plan.directory_fallback(self.user))
        return plan.EXIT_REFUSED

    # -- A3: the operator's own bootstrap (cut C5) --------------------------------------------------

    @staticmethod
    def _pending_problem(cs: state.CommitState) -> Optional[str]:
        if cs.pending is plan.Pending.UNREADABLE:
            return "the commit state could not be read"
        if cs.scheduled or cs.prepared:
            return "a 'commit at' or 'commit prepare' is pending"
        if cs.pending is not plan.Pending.NONE:
            return "a 'commit confirmed' is waiting for its confirmation"
        return None

    def _confirm_bootstrap(self, boot: Stage, prior: plan.PriorState) -> int:
        own = prior.own_bootstrap
        if own is None:  # the plan has a bootstrap stage only with an own bootstrap
            return plan.EXIT_REFUSED
        self.say(f"Confirming your bootstrap ({own.comment}): its health check is this script running (K2).")
        try:
            with self.box.exclusive() as candidate:
                cs = self._commit_state()
                newest = cs.entries[0] if cs.entries else None
                exact = (
                    cs.pending is plan.Pending.OTHER
                    and not cs.scheduled
                    and not cs.prepared
                    and newest is not None
                    and newest.pending_confirm
                    and newest.user == own.user
                    and own.comment in newest.texts
                )
                if not exact:  # K1
                    self._refusal("R-PENDING", "the pending commit is no longer exactly your bootstrap")
                    return plan.EXIT_REFUSED
                if self._config("committed", False) != prior.direct:
                    self.say("The committed configuration changed since it was read; the bootstrap stays unconfirmed.")
                    return plan.EXIT_REFUSED
                outside = plan.headers_outside(boot, Layout.DIRECT, self.box.compare(1))
                if outside:  # C10 on the bootstrap's own delta
                    self.say("The bootstrap's committed delta changes something outside it: " + "; ".join(outside))
                    return plan.EXIT_UNEXPECTED_DIFF
                candidate.commit(own.confirm_comment, None)
                # That this script's commit confirms the commit confirmed typed in the operator's CLI session is
                # inferred ([commit-cmd] names no session; Q-INST-03): read back that it is no longer pending.
                after = self._commit_state()
                if after.pending is plan.Pending.UNREADABLE or any(
                    e.pending_confirm and own.comment in e.texts for e in after.entries
                ):
                    self.say(
                        "The confirming commit was accepted, but the bootstrap still shows as pending (or the commit "
                        "state could not be read): it may not be confirmed (Q-INST-03). Nothing more is written."
                    )
                    return plan.EXIT_DEVICE_REFUSED
        except LockFailed as exc:
            self.say(f"{exc}. The bootstrap stays unconfirmed.")
            return plan.EXIT_DEVICE_REFUSED
        except Stop as stop:
            self.say("The bootstrap stays unconfirmed: Junos removes it at its deadline.")
            return stop.code
        except (DeviceRefused, OutcomeUnknown, SessionLost, ReadTimeout) as exc:
            self.say(f"The bootstrap's confirm did not complete: {exc}. It rolls back at its deadline.")
            return plan.EXIT_DEVICE_REFUSED
        self.bootstrap_confirmed = True
        self.confirmed.append("bootstrap")
        self.commits.append(plan.ReceiptCommit("bootstrap", own.confirm_comment, True))
        self.say(f"Bootstrap confirmed (same as '{plan.cli_confirm(own.confirm_comment)}').")
        return plan.EXIT_OK

    # -- A4, A5: files ------------------------------------------------------------------------------

    def _verify_file(self, path: str, sha: Optional[str], mode: int, *, fix_mode: bool = True) -> Optional[str]:
        """None when ``path`` has SHA-256 ``sha`` (if given), owner = this account and ``mode``; otherwise
        what differs. A wrong mode is set once with file-change-permission, then read again."""
        if sha is not None:
            actual = self._checksum(path)
            if actual != sha:
                return f"SHA-256 is {actual or 'unreadable'}, expected {sha}"
        info = self._info(path)
        if info is None:
            return "not listed after it was written"
        if info.owner == "root":
            return "owned by root (R-ROOT: the account maps to uid 0)"
        if info.owner != self.user:
            return f"owned by {info.owner or 'unknown'}, not {self.user}"
        if info.mode != mode and fix_mode:
            self.box.write("file-change-permission", filename=path, permission=f"{mode:o}")
            info = self._info(path)
        if info is None or info.mode != mode:
            return f"mode is {(info.mode or 0) if info else 0:04o}, not {mode:04o}"
        return None

    def _note_created(self, path: str, existed: bool) -> None:
        if not existed and path not in self.created:
            self.created.append(path)

    def _delete(self, path: str) -> bool:
        """file-delete of one exact J-Wicket path; an absent file is fine. Never recursive."""
        try:
            self.box.write("file-delete", path=path)
        except DeviceRefused as exc:
            if state.is_absent_path_error(str(exc)):
                return True
            self.say(f"  could not delete {path}: {exc}")
            return False
        if path in self.created:
            self.created.remove(path)
        return True

    def _files(self, built: InstallPlan) -> int:
        staged = False
        try:
            for step in built.files:
                problem = self._file_step(step, built)
                if step.action == "stage" and problem is None:
                    staged = True
                if problem is not None:
                    self.say(f"{step.path}: {problem}")
                    if staged or step.action == "stage":
                        self._delete(plan.STAGING_PATH)
                    return plan.EXIT_INTEGRITY
        except DeviceRefused as exc:
            self.say(f"The device refused a file step: {exc}")
            if staged:
                self._delete(plan.STAGING_PATH)
            return plan.EXIT_DEVICE_REFUSED
        except (SessionLost, ReadTimeout, OutcomeUnknown) as exc:
            self.say(f"The device stopped answering during the file steps: {exc}. Nothing was committed.")
            return plan.EXIT_REFUSED
        return plan.EXIT_OK

    def _bundle_bytes(self) -> bytes:
        """The verified bundle bytes: the home copy, or the staging file read once (O_NOFOLLOW, fstat)."""
        if self.source is not None and self.source.data is not None:
            return self.source.data
        data = self.files.read_once(plan.STAGING_PATH, self.account.uid, plan.MAX_BUNDLE_SIZE)
        if hashlib.sha256(data).hexdigest() != self.bundle.file_sha256:
            raise LocalFileError(f"{plan.STAGING_PATH} changed after it was checked")
        return data

    def _file_step(self, step: FileStep, built: InstallPlan) -> Optional[str]:
        action = step.action
        if action == "keep":
            return None
        if action == "delete":
            self._delete(step.path)
            return None
        if step.content in TLS_CONTENTS:
            return self._tls_file_step(step)
        existed = self._info(step.path) is not None
        try:
            if action == "stage":
                return self._stage_bundle(step, existed, built.pull_routing_instance)
            if action in ("copy", "backup", "replace", "restore"):
                source = step.source or ""
                self.say(f"  copying {source} to {step.path} (same as '{plan.cli_file_copy(source, step.path)}')")
                self.box.write("file-copy", source=source, destination=step.path)
                self._note_created(step.path, existed)
                problem = self._verify_file(step.path, step.sha256, step.mode)
                if problem is not None and action == "copy" and "owned by" in problem and "root" not in problem:
                    # spec 9.2 A4: an on-device copy with another owner is replaced by one write of that name
                    # (an unconfigured name this run created), from the verified bytes.
                    self.say(f"  {step.path} {problem}; writing it from the verified bundle bytes instead")
                    if not self._delete(step.path):
                        return problem
                    self.files.write_new(step.path, self._bundle_bytes(), step.mode)
                    self._note_created(step.path, False)
                    problem = self._verify_file(step.path, step.sha256, step.mode)
                return problem
            if action == "write":
                data = self._content(step, built)
                self.say(f"  writing {step.path}, mode {step.mode:04o}")
                self.files.write_private(step.path, data, step.mode, self.account.uid)
                del data  # the lab token never outlives this call
                self._note_created(step.path, existed)
                return self._verify_file(step.path, step.sha256, step.mode)
        except LocalFileError as exc:
            return str(exc)
        return f"unknown file action {action}"

    def _stage_bundle(self, step: FileStep, existed: bool, instance: Optional[str] = None) -> Optional[str]:
        """Every transfer lands in the unconfigured staging name (INV-06); a stale one is deleted first. On a
        management-instance device the release URL is fetched in ``instance`` (mgmt_junos, JFR-05: fxp0's
        route is there, verified on SRX4100; that the option routes the download is inferred)."""
        if existed and not self._delete(plan.STAGING_PATH):
            return "a stale staging file could not be deleted"
        source = self.source
        if source is not None and source.data is not None:
            self.say(f"  writing the home copy's bytes to {step.path} (O_CREAT | O_EXCL, mode 0644)")
            self.files.write_new(step.path, source.data, step.mode)
        else:
            url = self.payload.bundle_url
            self.say(f"  the device fetches {url} (same as '{plan.cli_file_copy(url, step.path, instance)}')")
            args: Dict[str, transport.ArgValue] = {"source": url, "destination": step.path}
            if instance is not None:
                args["routing-instance"] = instance
            try:
                self.box.write("file-copy", **args)
            except (DeviceRefused, OutcomeUnknown) as exc:
                return f"the device's download failed: {exc}"
        self._note_created(step.path, False)
        return self._verify_file(step.path, step.sha256, step.mode)

    def _tls_file_step(self, step: FileStep) -> Optional[str]:
        """The plan's TLS 'write' (source op-script) is the operator's pair, checked before the gate and now
        again: never written, and the key never read. The certificate must still be the one whose
        fingerprint was printed; a certificate mode other than 0644 is set to 0644 (it is public)."""
        if step.source not in (None, "op-script"):
            return f"source {step.source} is not one this op script supports (it never makes the TLS pair)"
        self.say(f"  checking {step.path} (yours; this script never writes the TLS key pair)")
        if step.content == "tls-key":
            return self._verify_file(step.path, None, step.mode, fix_mode=False)
        sha = self._certificate_sha256()
        if sha is None or sha != self.cert_sha256:
            return "the certificate changed since its fingerprint was printed, or it cannot be read"
        return self._verify_file(step.path, None, step.mode)

    def _content(self, step: FileStep, built: InstallPlan) -> bytes:
        if step.content == "settings":
            return built.settings_text.encode("utf-8")
        if step.content == "lab-token":
            import secrets

            return (secrets.token_hex(24) + "\n").encode("ascii")  # 48 hex; never stored, printed or logged
        raise plan.InvariantError(f"no content for {step.path}")

    # -- the stage runner (spec 8.6, 8.7) ----------------------------------------------------------

    def _run_stage(self, stage: Stage) -> StageResult:
        layout = plan.stage_layout(stage, self.layout)
        minutes = int(stage.confirm_minutes)
        self.say("")
        self.say(f"Stage {stage.name}: commit confirmed {minutes} (comment: {stage.comment})")
        offsets: Dict[str, int] = {}
        try:
            if stage.name == "runtime":
                offsets = self._offsets()
                self._delete(plan.STARTUP_REFUSED_PATH)  # C6: J-Wicket's own file; a new one means a refusal
            before_raw = self._config("committed", False)
            before_eff = self._config("committed", True) if layout is Layout.GROUP else None
        except (ReadTimeout, SessionLost, OutcomeUnknown, DeviceRefused) as exc:
            self.say(f"Stage {stage.name}: the device could not be read: {exc}")
            return StageResult(plan.EXIT_REFUSED)
        except Stop as stop:
            return StageResult(stop.code)
        confirmed = False
        try:
            with self.box.exclusive() as candidate:
                result = self._in_lock(stage, candidate, layout, before_raw, before_eff, offsets)
                confirmed = result.code == plan.EXIT_OK
        except LockFailed as exc:
            self.say(f"Stage {stage.name}: {exc}")
            return StageResult(plan.EXIT_DEVICE_REFUSED)
        except SessionLost as exc:
            self.say(f"Stage {stage.name}: the session closed at the lock: {exc}")
            return StageResult(plan.EXIT_DEVICE_REFUSED)
        if not confirmed:
            return result
        return self._post_confirm(stage)

    def _in_lock(
        self,
        stage: Stage,
        candidate: Candidate,
        layout: Layout,
        before_raw: StatementSet,
        before_eff: Optional[StatementSet],
        offsets: Mapping[str, int],
    ) -> StageResult:
        minutes = int(stage.confirm_minutes)
        replaced: List[FileStep] = []
        start: Optional[float] = None  # set once the confirmed commit was sent
        try:
            problem = self._pending_problem(self._commit_state())
            if problem is not None:
                self._refusal("R-PENDING", problem)
                return StageResult(plan.EXIT_REFUSED, foreign_pending=True)
            for step in stage.files_before_commit:
                failure = self._pre_commit_file(step)
                if failure is not None:
                    self._restore(stage, replaced)
                    return StageResult(failure)
                if step.action == "replace":
                    replaced.append(step)
            lines = plan.stage_lines(stage, self.layout)
            self.say("  loading: " + "; ".join(lines))
            try:
                candidate.load_set(lines)
            except DeviceRefused as exc:
                self._discard(candidate)
                self._restore(stage, replaced)
                self.say(f"Stage {stage.name}: the device refused the load: {exc}")
                self._checksum_hint(str(exc))
                return StageResult(plan.EXIT_DEVICE_REFUSED)
            unexpected = list(plan.structural_unexpected(stage, layout, before_raw, self._config("candidate", False)))
            if before_eff is not None:
                unexpected += plan.structural_unexpected(
                    stage, layout, before_eff, self._config("candidate", True), view="effective"
                )
            diff = self.box.compare(0)
            outside = list(plan.headers_outside(stage, layout, diff))
            self._show_device_diff(stage.name, diff)
            if unexpected or outside:
                self._discard(candidate)
                self._restore(stage, replaced)
                self.say(
                    f"Stage {stage.name}: the device's candidate differs from the plan; discarded, nothing committed:"
                )
                for line in [*unexpected, *outside]:
                    self.say(f"  {line}")
                return StageResult(plan.EXIT_UNEXPECTED_DIFF)
            problem = self._pending_problem(self._commit_state())  # INV-03, right before the commit
            if problem is not None:
                self._discard(candidate)
                self._restore(stage, replaced)
                self._refusal("R-PENDING", problem)
                return StageResult(plan.EXIT_REFUSED, foreign_pending=True)
            start = self.clock.monotonic()
            try:
                candidate.commit(stage.comment, stage.confirm_minutes)
            except DeviceRefused as exc:
                start = None
                self._discard(candidate)
                self._restore(stage, replaced)
                self.say(f"Stage {stage.name}: the device refused the confirmed commit: {exc}")
                self._checksum_hint(str(exc))
                return StageResult(plan.EXIT_DEVICE_REFUSED)
            except (OutcomeUnknown, SessionLost) as exc:
                return self._not_confirmed(
                    stage,
                    candidate,
                    before_raw,
                    start,
                    f"the commit's outcome is unknown: {exc}",
                    session_ok=not isinstance(exc, SessionLost),
                    replaced=replaced,
                )
            self.commits.append(plan.ReceiptCommit(stage.name, stage.comment, False))
            self.say(
                f"  committed (same as '{plan.cli_commit_confirmed(minutes, stage.comment)}'); Junos rolls it back "
                f"in {minutes} minutes unless the checks pass and this script confirms it."
            )
            results = self._checks(stage, start, offsets, before_raw, before_eff, layout)
            ok, warnings = health.summary(results)
            complete = len(results) == len(stage.checks)
            if not (ok and complete and plan.confirm_allowed(self.clock.monotonic() - start, minutes)):
                failed = next((r for r in results if not r.acceptable), None)
                reason = (
                    f"check {failed.check} failed: {failed.detail}"
                    if failed is not None
                    else "the checks did not finish at least 60 s before the deadline"
                )
                return self._not_confirmed(
                    stage, candidate, before_raw, start, reason, session_ok=True, replaced=replaced
                )
            try:
                candidate.commit(stage.confirm_comment, None)
            except (DeviceRefused, OutcomeUnknown, SessionLost) as exc:
                return self._not_confirmed(
                    stage,
                    candidate,
                    before_raw,
                    start,
                    f"the confirming commit failed: {exc}",
                    session_ok=not isinstance(exc, SessionLost),
                    replaced=replaced,
                )
            for warning in warnings:
                self.say(f"  warning: {warning}")
            self.commits[-1] = plan.ReceiptCommit(stage.name, stage.comment, True)
            self.confirmed.append(stage.name)
            self.say(f"Stage {stage.name} confirmed (same as '{plan.cli_confirm(stage.confirm_comment)}').")
            return StageResult(plan.EXIT_OK)
        except SessionLost as exc:
            if start is None:
                return self._lost_before_commit(stage, replaced, f"the session was lost before the commit: {exc}")
            return self._not_confirmed(
                stage, candidate, before_raw, start, f"the session was lost: {exc}", session_ok=False, replaced=replaced
            )
        except (ReadTimeout, OutcomeUnknown, DeviceRefused, Stop) as exc:
            if start is None:
                self._discard(candidate)
                self._restore(stage, replaced)
                self.say(f"Stage {stage.name}: a step failed before the commit ({exc}); nothing was committed in it.")
                return StageResult(plan.EXIT_REFUSED)
            return self._not_confirmed(
                stage, candidate, before_raw, start, f"a read failed: {exc}", session_ok=True, replaced=replaced
            )

    def _lost_before_commit(self, stage: Stage, replaced: Sequence[FileStep], reason: str) -> StageResult:
        """Nothing of this stage was committed; an upgrade's replaced files get their old bytes back over a
        new session (reads and the restore copy only; no commit, INV-06)."""
        self.say(f"Stage {stage.name}: {reason}. Nothing was committed in this stage.")
        if replaced:
            try:
                self.box.close()
                self.box.open()
                self._restore(stage, replaced)
            except TransportError as exc:
                self.say(f"  could not reconnect to restore the replaced files: {exc}")
        return StageResult(plan.EXIT_DEVICE_REFUSED, session_lost=True)

    def _post_confirm(self, stage: Stage) -> StageResult:
        if stage.post_confirm_checks:
            code = self._process_gone()
            if code:
                return StageResult(code)
        for step in stage.files_after_confirm:  # deletes only: the directory is root's (R4)
            self._delete(step.path)
        return StageResult(plan.EXIT_OK)

    def _discard(self, candidate: Candidate) -> None:
        try:
            candidate.discard()
        except TransportError as exc:
            self.say(f"  could not discard the candidate ('rollback 0'): {exc}; the session's end discards it")

    def _checksum_hint(self, message: str) -> None:
        lowered = message.lower()
        if "checksum" in lowered and any(w in lowered for w in ("unknown", "unsupported", "syntax error")):
            self.say(
                "  Junos does not accept the 'checksum sha-256' statement here (Q-INST-02). This op script always "
                "installs with it; the workstation installer's --no-jet-checksum installs without it (recorded)."
            )

    def _pre_commit_file(self, step: FileStep) -> Optional[int]:
        """An upgrade's backup or replace, inside the stage's lock, right before its commit (INV-06)."""
        source = step.source or ""
        self.say(f"  copying {source} onto {step.path} (same as '{plan.cli_file_copy(source, step.path)}')")
        try:
            self.box.write("file-copy", source=source, destination=step.path)
        except (DeviceRefused, OutcomeUnknown) as exc:
            self.say(
                f"  the device refused to write {step.path}: {exc}. Whether 'file copy' overwrites an existing file "
                "is unknown (Q-INST-01); nothing was deleted. Uninstall, then install, instead."
            )
            return plan.EXIT_DEVICE_REFUSED
        problem = self._verify_file(step.path, step.sha256, step.mode)
        if problem is not None:
            self.say(f"  {step.path}: {problem} (the device may have refused to overwrite it); stopping before commit")
            return plan.EXIT_DEVICE_REFUSED
        return None

    def _restore(self, stage: Stage, replaced: Sequence[FileStep]) -> None:
        """Put back the old bytes of every file this stage replaced, by copy (never by delete, INV-06)."""
        paths = {s.path for s in replaced}
        for step in stage.restore_on_failure:
            if step.path not in paths:
                continue
            source = step.source or ""
            self.say(f"  restoring {step.path} from {source}")
            try:
                self.box.write("file-copy", source=source, destination=step.path)
                problem = self._verify_file(step.path, step.sha256, step.mode)
            except TransportError as exc:
                problem = str(exc)
            if problem is not None:
                self.say(f"  {step.path} was not restored: {problem}")

    def _show_device_diff(self, stage: str, diff: Optional[str]) -> None:
        self.say(f"  Junos's own 'show | compare' for stage {stage}:")
        for line in _safe_lines(diff) or ["(no difference)"]:
            self.say(f"    {line}")

    # -- checks (spec 7.6) ----------------------------------------------------------------------------

    def _offsets(self) -> Dict[str, int]:
        listing = self._listing(plan.STATE_DIR)
        sizes = {e.path: e.size or 0 for e in listing.entries} if listing is not None else {}
        return {plan.LOG_PATH: sizes.get(plan.LOG_PATH, 0), plan.AUDIT_PATH: sizes.get(plan.AUDIT_PATH, 0)}

    def _checks(
        self,
        stage: Stage,
        start: float,
        offsets: Mapping[str, int],
        before_raw: StatementSet,
        before_eff: Optional[StatementSet],
        layout: Layout,
    ) -> List[Result]:
        deadline = start + int(stage.confirm_minutes) * 60
        results: List[Result] = []
        context: Dict[str, Any] = {"offsets": offsets, "since": None}
        for check in stage.checks:
            if deadline - self.clock.monotonic() < plan.CONFIRM_MARGIN_S:
                results.append(Result(check.id, health.FAIL, "out of time before the confirm margin"))
                break
            try:
                result = self._check(check, stage, context, before_raw, before_eff, layout, deadline)
            except (Stop, ReadTimeout, OutcomeUnknown, DeviceRefused) as exc:
                result = Result(check.id, health.FAIL, f"a read failed: {exc}")
            left = int(deadline - self.clock.monotonic())
            self.say(f"  {result.check} {result.status}: {result.detail} ({left} s left before the deadline)")
            results.append(result)
            if not result.acceptable:
                break
        return results

    def _check(
        self,
        check: plan.Check,
        stage: Stage,
        context: Dict[str, Any],
        before_raw: StatementSet,
        before_eff: Optional[StatementSet],
        layout: Layout,
        deadline: float,
    ) -> Result:
        expect = check.expect
        cid = check.id
        if cid in ("C2", "C3"):
            return self._diagnostic(check)
        if cid == "C4":
            return self._start_line(check, context, deadline)
        if cid == "C5":
            data = (self._file_text(plan.AUDIT_PATH) or "").encode("utf-8")
            return health.audit_start(data, int(context["offsets"].get(plan.AUDIT_PATH, 0)), expect)
        if cid == "C6":
            if self._info(plan.STARTUP_REFUSED_PATH) is not None:
                text = plan.sanitize_display(self._file_text(plan.STARTUP_REFUSED_PATH) or "", 200)
                return Result("C6", health.FAIL, f"J-Wicket refused to start: {text}")
            return Result("C6", health.PASS, "no startup-refused.txt")
        if cid == "C7":
            first = health.process_id(self._status_text())
            self.clock.sleep(int(expect.get("interval_s", "30")))
            second = health.process_id(self._status_text())
            result = health.stable(first, second)
            if result.ok and "c4" in context:
                again = self._log_result(context["c4"], context)
                if not again.ok:
                    return Result("C7", health.FAIL, "at the second read: " + again.detail)
            return result
        if cid == "C8":
            return self._c8(check)
        if cid in plan.RETIRED_CHECKS:  # C9 (revision R3): never planned; a plan that has it is a defect
            return Result(cid, health.FAIL, f"check {cid} is retired and never planned")
        if cid == "C10":
            unexpected = list(plan.structural_unexpected(stage, layout, before_raw, self._config("committed", False)))
            if before_eff is not None:
                unexpected += plan.structural_unexpected(
                    stage, layout, before_eff, self._config("committed", True), view="effective"
                )
            outside = plan.headers_outside(stage, layout, self.box.compare(1))
            if unexpected or outside:
                return Result(
                    "C10",
                    health.FAIL,
                    "committed change differs from the plan: " + "; ".join([*unexpected, *outside])[:300],
                )
            return Result("C10", health.PASS, "the committed change equals the plan")
        if cid == "C11":
            cs = self._commit_state()
            newest = cs.entries[0] if cs.entries else None
            if newest is None or expect.get("newest_comment") not in newest.texts:
                return Result("C11", health.FAIL, "the newest commit is not this stage's")
            # INV-03: by this account, for every stage (an uninstall stage's check names no user: it is the
            # account this executor signed in as).
            if newest.user != (expect.get("newest_user") or self.user):
                return Result("C11", health.FAIL, "the newest commit is by another account")
            if cs.scheduled or cs.prepared:
                return Result("C11", health.FAIL, "a 'commit at' or prepared commit appeared")
            return Result("C11", health.PASS, "the newest commit is this stage's, by this account")
        if cid == "C12":
            committed = self._config("committed", False)
            changes = {s.path for s in stage.add}
            left = [
                s.key
                for s in stage.remove
                if s.path not in changes
                and committed.under(s.path_key(layout))
                and not (
                    s.value and s.form(layout)[-1] in plan.LEAF_LISTS and not committed.has(s.path_key(layout), s.value)
                )
            ]
            if left:
                return Result("C12", health.FAIL, "still in the committed configuration: " + ", ".join(left))
            return Result("C12", health.PASS, "the removed statements are absent")
        return Result(cid, health.FAIL, f"check {cid} is not known to this executor")

    def _c8(self, check: plan.Check) -> Result:
        """C8 on the box (revision R3): --access tunnel, not available (no SSH channel); --access tls in
        mgmt_junos, not available (this script stays in the default instance); --access tls in the default
        instance, a pinned HTTPS GET /api/session to the listen address, where a connection that cannot be
        made is not available (whether an op script may open it is unknown, Q-INST-05)."""
        expect = check.expect
        if check.target == "not-available" or expect.get("access") != "tls":
            return health.not_available("C8", expect.get("reason") or plan.TUNNEL_C8_REASON)
        if self.routing_instance is not None:
            return health.not_available("C8", ONBOX_MGMT_C8_REASON)
        options = self.options
        if options is None or not options.tls or options.listen_address is None or self.cert_sha256 is None:
            return Result("C8", health.FAIL, "no listen address or certificate fingerprint to check against")
        host = expect.get("host") or plan.host_port(options.listen_address, options.port)
        answer = self.https(options.listen_address, options.port, "/api/session", host, self.cert_sha256)
        return health.https_session(
            answer.data, expect, connected=answer.connected, pinned=answer.pinned, reason=answer.reason
        )

    def _status_text(self) -> Optional[str]:
        reply = self._read("jet-application-status", **{"application-name": plan.DAEMON_FILE})
        return transport.output_text(reply)

    def _log_result(self, check: plan.Check, context: Dict[str, Any]) -> Result:
        data = (self._file_text(plan.LOG_PATH) or "").encode("utf-8")
        return health.start_line(data, int(context["offsets"].get(plan.LOG_PATH, 0)), check.expect, context["since"])

    def _start_line(self, check: plan.Check, context: Dict[str, Any], deadline: float) -> Result:
        cs = self._commit_state()
        if cs.entries:
            context["since"] = health.commit_time(cs.entries[0].date_time)
        context["c4"] = check
        waited = 0
        while True:
            result = self._log_result(check, context)
            if result.ok or "restarting" in result.detail or "another build" in result.detail:
                return result
            if waited >= check.timeout_s or deadline - self.clock.monotonic() < plan.CONFIRM_MARGIN_S + POLL_S:
                return Result(result.check, result.status, f"{result.detail} (after {waited} s)")
            self.clock.sleep(POLL_S)
            waited += POLL_S

    def _diagnostic(self, check: plan.Check) -> Result:
        expect = check.expect
        app = plan.SELFTEST_FILE if check.id == "C2" else plan.PROBE_FILE
        result_path = plan.SELFTEST_RESULT_PATH if check.id == "C2" else plan.PROBE_RESULT_PATH
        from_file = expect.get("source") == "result-file"
        if from_file and (not self._delete(result_path) or self._info(result_path) is not None):
            return Result(check.id, health.FAIL, f"a stale {result_path} could not be removed before the run")
        self.say(f"  running {app} (same as '{plan.cli_start(app)}')")
        try:
            reply = self.box.write("extension-service-start", **{"application-name": app})
        except (DeviceRefused, OutcomeUnknown) as exc:
            return Result(check.id, health.FAIL, f"the device refused to start {app}: {exc}")
        text: Optional[str]
        if from_file:
            text = None
            waited = 0
            while waited <= check.timeout_s:
                if self._info(result_path) is not None:
                    text = self._file_text(result_path)
                    break
                self.clock.sleep(RESULT_POLL_S)
                waited += RESULT_POLL_S
        else:
            text = transport.output_text(reply)
        judge = health.selftest if check.id == "C2" else health.probe
        result = judge(text, expect)
        if result.status == health.NOT_CHECKED:
            return Result(
                check.id,
                health.FAIL,
                "the start reply carried no output and this bundle writes no result file (no D2); this op script "
                "has no --accept-unchecked-diagnostics: use the workstation installer for such a bundle",
            )
        return result

    def _status_checks(self, built: InstallPlan) -> int:
        """An idempotent re-run (SC-14): the read-only checks against the running daemon."""
        results: List[Result] = []
        stage = Stage("runtime", (), (), (), "x", "x", plan.Minutes(5), ())
        for check in built.status_checks:
            if check.id in ("C4", "C5"):
                continue  # 'exactly one new line' needs a commit
            if check.id == "C7":
                pid = health.process_id(self._status_text())
                result = Result(
                    "C7", health.PASS if pid else health.FAIL, f"process {pid}" if pid else "no J-Wicket process"
                )
            else:
                context: Dict[str, Any] = {"offsets": {}, "since": None}
                result = self._check(
                    check, stage, context, StatementSet(), None, self.layout, self.clock.monotonic() + 3600
                )
            self.say(f"  {result.check} {result.status}: {result.detail}")
            results.append(result)
        ok, warnings = health.summary(results)
        for warning in warnings:
            self.say(f"  warning: {warning}")
        self.say("Healthy." if ok else "Not healthy: nothing was changed; see the checks above.")
        return plan.EXIT_OK if ok else plan.EXIT_REFUSED

    # -- failure handling (spec 8.8) -------------------------------------------------------------------

    def _not_confirmed(
        self,
        stage: Stage,
        candidate: Candidate,
        before_raw: StatementSet,
        start: float,
        reason: str,
        *,
        session_ok: bool,
        replaced: Sequence[FileStep] = (),
    ) -> StageResult:
        minutes = int(stage.confirm_minutes)
        left = max(0, int(start + minutes * 60 - self.clock.monotonic()))
        self.say(f"Stage {stage.name} is NOT confirmed: {reason}.")
        self.say(f"Junos rolls it back at its deadline, in about {left} s ({minutes} minutes after the commit).")
        if not session_ok:
            self.say("The local session was lost: this script reconnects only to read, and never confirms from it.")
            return self._after_drop(stage, before_raw, start)
        self._restore(stage, replaced)
        if stage.name == "runtime":
            self._show_refusal_evidence()
        self._rollback_now(stage, candidate)
        rolled = self._wait_rollback(stage, before_raw, start)
        return StageResult(plan.EXIT_CHECK_FAILED, after_commit=True, rolled_back=rolled)

    def _show_refusal_evidence(self) -> None:
        try:
            refused = self._file_text(plan.STARTUP_REFUSED_PATH) if self._info(plan.STARTUP_REFUSED_PATH) else None
            log = self._file_text(plan.LOG_PATH) if self._info(plan.LOG_PATH) else None
        except TransportError as exc:
            LOG.info("could not read J-Wicket's own files: %s", exc)
            return
        for line in _safe_lines(refused):
            self.say(f"  startup-refused.txt: {line}")
        for line in _safe_lines(log)[-10:]:
            self.say(f"  jwicket.log: {line}")

    def _rollback_now(self, stage: Stage, candidate: Candidate) -> None:
        """Spec 8.6: on a typed 'rollback' only, 'rollback 1' and a commit on the same locked session, after
        the INV-03 re-read; the default is to wait for Junos's own rollback at the deadline."""
        answer = self.console.ask(
            f"Type {ROLLBACK_ANSWER} to restore the previous configuration now, or press Enter to wait for the "
            "deadline: "
        )
        if answer is None or answer.strip() != ROLLBACK_ANSWER:
            return
        try:
            cs = self._commit_state()
            newest = cs.entries[0] if cs.entries else None
            if (
                newest is None
                or stage.comment not in newest.texts
                or not newest.pending_confirm
                or cs.scheduled
                or cs.prepared
            ):
                self.say("The newest commit is no longer this stage's pending commit: not rolling back by hand.")
                return
            comment = plan.rollback_now_comment(self.bundle)
            candidate.load_rollback_1()
            candidate.commit(comment, None)
            self.say(f"Rolled back now (same as 'rollback 1' and '{plan.cli_confirm(comment)}'): a write.")
        except TransportError as exc:
            self.say(f"The rollback by hand failed: {exc}. Junos still rolls back at the deadline.")

    def _wait_rollback(self, stage: Stage, before_raw: StatementSet, start: float) -> bool:
        end = start + int(stage.confirm_minutes) * 60 + 60
        while True:
            try:
                if self._config("committed", False) == before_raw:
                    self.say(f"Junos rolled stage {stage.name} back.")
                    return True
            except (ReadTimeout, SessionLost, OutcomeUnknown, Stop) as exc:
                LOG.info("rollback wait read failed: %s", exc)
                return False
            if self.clock.monotonic() >= end:
                self.say(f"Stage {stage.name} was not rolled back by its deadline: check 'show system commit'.")
                return False
            self.clock.sleep(ROLLBACK_POLL_S)

    def _after_drop(self, stage: Stage, before_raw: StatementSet, start: float) -> StageResult:
        """After a lost session: reconnect only to read (8.6), wait for Junos's rollback, then restore the old
        bytes whose checksum is committed again (9.4 step 5)."""
        try:
            self.box.close()
            self.box.open()
        except TransportError as exc:
            self.say(f"Could not reconnect: {exc}. Junos rolls the stage back at its deadline.")
            return StageResult(plan.EXIT_CHECK_FAILED, after_commit=True, session_lost=True, rolled_back=None)
        rolled = self._wait_rollback(stage, before_raw, start)
        if rolled and stage.restore_on_failure:
            committed = self._config("committed", False)
            keys = {
                plan.DAEMON_PATH: "S13",
                f"{plan.JET_DIR}/{plan.SELFTEST_FILE}": "S3",
                f"{plan.JET_DIR}/{plan.PROBE_FILE}": "S5",
            }
            for step in stage.restore_on_failure:
                key = keys.get(step.path)
                if key is None:
                    continue
                pinned = committed.values(" ".join(plan.SPEC_BY_KEY[key].path))
                if pinned == ((step.sha256,) if step.sha256 else ()):
                    self._restore(stage, [step])
                else:
                    self.say(f"  {step.path}: the committed checksum is not the old one; its bytes are left as is")
        return StageResult(plan.EXIT_CHECK_FAILED, after_commit=True, session_lost=True, rolled_back=rolled)

    def _after_failure(self, built: InstallPlan) -> None:
        """The ``finally`` of spec 6.5: revert this run's confirmed stages, and the bootstrap's statements when
        the commit history shows this run's bootstrap added them; never after a foreign pending commit, a
        lost session or a rollback that did not happen. Best effort: it must never mask the run's outcome."""
        try:
            self._revert(built)
        except (TransportError, plan.PlanError, LocalFileError, Stop) as exc:
            self.say(f"The revert could not run: {exc}.")
            self._print_revert_units(built)

    def _revert(self, built: InstallPlan) -> None:
        result = self.last_result
        if result is not None and result.foreign_pending:
            self.say(
                "Another commit is pending, so this script sends no revert commit (it would confirm that commit "
                "too). When it is settled, run this script again to finish or to uninstall."
            )
            self._partial_report()
            return
        if result is not None and (result.session_lost or (result.after_commit and not result.rolled_back)):
            self.say("The revert stage does not run after a lost session or a missing rollback; nothing more is sent.")
            self._partial_report()
            return
        if built.upgrade and (result is None or not result.after_commit) and "diagnostics" not in self.confirmed:
            self.say("Nothing of the upgrade was committed: the previous build keeps running.")
            self._remove_created_files(built)
            return
        if built.upgrade:
            self.say(
                "The upgrade was rolled back to the previous build. The diagnostic copies may be the new build's, "
                "with their committed checksums; run this script again to check the running daemon."
            )
            return
        # The bootstrap's statements are this run's when it confirmed the bootstrap: recognise_bootstrap read
        # them from that commit's own delta in the history (spec 7.9), so this is history provenance.
        include_bootstrap = self.bootstrap_confirmed and built.bootstrap is not None
        names = [n for n in self.confirmed if n in ("diagnostics", "runtime")]
        names += ["bootstrap"] if include_bootstrap else []
        if not any(s.add for s in built.stages if s.name in names):
            self._remove_created_files(built)
            return
        revert = plan.build_revert_stage(built, names, include_bootstrap=include_bootstrap)
        self.say("Reverting what this run's confirmed stages added (the revert stage):")
        if include_bootstrap:
            self.say(
                "  this includes your bootstrap's statements; whether removing them affects this running script is "
                "unknown (Q-INST-03): if it stops, the units below the next message finish the job."
            )
        outcome = self._run_stage(revert)
        if outcome.code == plan.EXIT_OK:
            self._remove_created_files(built)
            self.say("Reverted: the device's configuration is as it was before this run.")
        else:
            self.say("The revert stage did not complete: the device keeps this run's confirmed stages.")
            self._print_revert_units(built, revert)
            self._partial_report()

    def _print_revert_units(self, built: InstallPlan, revert: Optional[Stage] = None) -> None:
        """Spec 6.5: if the revert cannot run, the exact units (rules of AC-006-09). An upgrade has none."""
        if revert is None and built.upgrade:
            self.say("A failed upgrade is not reverted: run this script again to check the running daemon.")
            return
        if revert is None:
            include_bootstrap = self.bootstrap_confirmed and built.bootstrap is not None
            names = [n for n in self.confirmed if n in ("diagnostics", "runtime")]
            names += ["bootstrap"] if include_bootstrap else []
            if not any(s.add for s in built.stages if s.name in names):
                self._partial_report()
                return
            try:
                revert = plan.build_revert_stage(built, names, include_bootstrap=include_bootstrap)
            except plan.PlanError as exc:
                self.say(f"No revert units could be built: {exc}")
                return
        self.say(render.units_to_text(revert_units(revert, self.layout)))

    def _remove_created_files(self, built: InstallPlan) -> None:
        """Delete the files this run created once a fresh read shows that no configuration names them
        (INV-06). The state directory stays: root made it, and this account cannot remove it (R4). What the
        daemon itself wrote there (its log, audit trail, startup-refused.txt, result files) stays as evidence."""
        if not self.created:
            return
        try:
            committed = self._config("committed", False)
        except Stop:
            self._partial_report()
            return
        configured = plan.PriorState(effective=committed, direct=committed).configured_paths
        for path in list(self.created):
            if path in configured:
                self.say(f"  {path} is configured; left in place")
                continue
            self._delete(path)
        if self.created:
            self.say("Files this run created and left in place: " + ", ".join(self.created))
        else:
            self.say("The files this run created were removed.")

    def _partial_report(self) -> None:
        if self.confirmed:
            self.say("Confirmed so far in this run: " + ", ".join(self.confirmed) + ".")
        if self.created:
            self.say("Files this run created and left in place: " + ", ".join(self.created))
        self.say("Run this script again to finish, or choose uninstall to remove J-Wicket (J-Wicket's names only).")

    # -- the end of an install ----------------------------------------------------------------------

    def _final_files(self, built: InstallPlan) -> None:
        """The advisory device receipt and uninstall-cli.txt, both 0600 (spec 6.5 step 5, 7.10). J-Wicket is
        installed and confirmed by now, so a failure here is reported, never reverted."""
        wrote_cert = any(f.content == "tls-cert" and f.action == "write" for f in built.files)
        try:
            final = plan.receipt_for_run(
                built,
                time=self.now(),
                commits=self.commits,
                bootstrap_confirmed=True if self.bootstrap_confirmed else None,
                tls_cert_sha256=self.cert_sha256 if wrote_cert else None,
                lab_hardware_attested=True if self.lab_attested else None,
            )
            final = dataclasses.replace(final, overrides=tuple(sorted(set(final.overrides) | self.overrides)))
        except plan.PlanError as exc:
            self.say(f"The install record could not be completed: {exc}. Nothing more is written.")
            return
        for step in built.final_files:
            try:
                if step.content == "receipt":
                    data = final.to_json().encode("utf-8")
                elif step.content == "uninstall-cli":
                    data = self._uninstall_text().encode("utf-8")
                else:
                    continue
                self.files.write_private(step.path, data, step.mode, self.account.uid)
                problem = self._verify_file(step.path, hashlib.sha256(data).hexdigest(), step.mode)
            except (LocalFileError, TransportError, plan.PlanError, Stop) as exc:
                problem = str(exc)
            if problem is not None:
                self.say(f"{step.path} was not written: {problem}")
            else:
                self.say(f"Wrote {step.path} (mode {step.mode:04o}).")

    def _uninstall_text(self) -> str:
        """The rendered uninstall units for the device as it is now (a fresh read), so removal needs neither
        a workstation nor the bootstrap again."""
        pre = self._preflight_for_uninstall()
        uplan = plan.build_uninstall_plan(
            pre.evidence,
            pre.facts,
            pre.prior,
            method=pre.method,
            overrides=frozenset(self.overrides),
            layout=self.layout,
            user=self.user,
        )
        header = [
            f"# {plan.UNINSTALL_CLI_PATH}: how to remove J-Wicket {self.bundle.version} from this device by hand,",
            "# written by the on-box installer (lab only). Every step is unverified until lab test Q-INST-06.",
            "# Or run 'op jwicket-install-op.py' again and choose uninstall.",
            "",
        ]
        if uplan.blocked:
            codes = ", ".join(r.code for r in uplan.refusals if not r.overridden)
            return "\n".join([*header, f"The removal is refused right now ({codes}); run the op script for why.", ""])
        return "\n".join(header) + render.units_to_text(render.render_cli_uninstall_units(uplan, prior=pre.prior))

    def _preflight_for_uninstall(self) -> Preflight:
        """The reads an uninstall plan needs (no veriexec, no prompt)."""
        software = self._read("get-software-information")
        cluster = self._read("get-chassis-cluster-status")
        inventory = self._read("get-chassis-inventory")
        raw = self.box.get_configuration(database="committed", inherit=False)
        inherited = self.box.get_configuration(database="committed", inherit=True)
        commits = self._read("get-commit-information")
        lists = {d: self._read("file-list", detail=True, path=d) for d in plan.READ_DIRS}
        script_lists = {d: self._read("file-list", detail=True, path=d) for d in plan.S1_SCRIPT_DIRS}
        receipt_text = self._file_text(plan.RECEIPT_PATH)
        receipts = {"device": receipt_text, "workstation": None}
        prior = state.prior_from_replies(inherited, raw, commits, lists, receipts, None, script_lists=script_lists)
        facts = state.facts_from_replies(software, cluster, inventory, raw)
        deltas: Dict[int, str] = {}
        for entry in prior.history:
            if any(plan.is_installer_comment(t) for t in entry.texts):
                delta = self._delta(entry.sequence)
                if delta is not None:
                    deltas[entry.sequence] = delta
        evidence = plan.ownership_from_history(prior.history, deltas, user=self.user)
        return Preflight(facts, prior, evidence, self._method(prior))

    def _summary(self, built: InstallPlan) -> None:
        """How to reach the UI (render.render_open): --access tls, the URL and the fingerprint to compare;
        --access tunnel, the 'ssh -L' line and TUNNEL_WARNING (forwarding refused on SRX4100 25.2R1-S1.4)."""
        self.say("")
        self.say(f"J-Wicket {built.bundle.version} is installed on {built.facts.hostname} (lab only).")
        opened = render.render_open(built, cert_sha256=self.cert_sha256 if built.options.tls else None)
        if built.options.tls:
            self.say("Open it: " + opened[0])
            self.say(opened[1])
        else:
            self.say("Open it from your workstation: " + opened[0])
            self.say(opened[1])
            self.say(plan.TUNNEL_WARNING)
        self.say("Sign in with a Junos account (the netconf backend).")
        self.say(
            "Remove it later: run 'op jwicket-install-op.py' and choose uninstall, or paste the units in "
            f"'{plan.cli_file_show(plan.UNINSTALL_CLI_PATH)}'."
        )

    # -- uninstall (spec 9.5) -------------------------------------------------------------------------

    def uninstall(self, pre: Preflight) -> int:
        def build() -> UninstallPlan:
            return plan.build_uninstall_plan(
                pre.evidence,
                pre.facts,
                pre.prior,
                method=pre.method,
                overrides=frozenset(self.overrides),
                user=self.user,
            )

        try:
            uplan = build()
            self.layout = uplan.layout
            self._show_uninstall(uplan, pre)
            if uplan.blocked and self._ask_overrides(uplan.refusals):
                uplan = build()
                self.say("Overrides recorded: " + ", ".join(sorted(self.overrides)))
        except plan.PlanError as exc:
            self.say(f"The removal plan cannot be built: {exc}. Nothing was written.")
            return plan.EXIT_REFUSED
        if uplan.blocked:
            self.say("Refused before any write. Nothing was changed.")
            return plan.EXIT_REFUSED
        if uplan.no_change:
            self.say("Nothing of J-Wicket's is on this device. Nothing to remove.")
            return plan.EXIT_OK
        self.say(
            "Before you type the host name: this removes J-Wicket's log and audit files too. To keep them, copy them "
            f"off the device first (for example 'file copy {plan.LOG_PATH} <destination>', deploy-lab step 8)."
        )
        self.gate(
            pre.facts,
            None,
            lab_hardware=uplan.lab_hardware,
            signs=plan._production_signs(pre.facts, pre.prior),  # the plan's own list, as the workstation's
        )
        for stage in uplan.stages:
            if stage.name == "netconf-removal":
                continue  # never offered here: 'netconf ssh' needs --remove-shared and its own confirmation
            result = self._run_stage(stage)
            if result.code != plan.EXIT_OK:
                return result.code
        if not uplan.stages and uplan.files:
            code = self._process_gone()
            if code:
                return code
            for step in uplan.files:  # deletes only: the directory is root's (R4)
                self._delete(step.path)
        self._verify_removed()
        if uplan.state_dir_left:
            self.say(plan.STATE_DIR_LEFT)
        self.say(plan.NOT_REMOVED_BY_TOOL)
        return plan.EXIT_OK

    def _show_uninstall(self, uplan: UninstallPlan, pre: Preflight) -> None:
        """The removal plan, with the production signs shown before the gate's first prompt (spec 8.2)."""
        user = uplan.user or self.user
        self.say(
            f"Device: model {pre.facts.model or 'unknown'}, release {pre.facts.junos_version or 'unknown'}, "
            f"serial {pre.facts.serial or 'unknown'}"
        )
        self.say("Shown, not judged (a production device would show these):")
        for sign in plan._production_signs(pre.facts, pre.prior):
            self.say(f"  {sign}")
        for wid in uplan.warnings:
            if wid not in ("DEVICE_STATUS", "NOT_REMOVED_BY_TOOL", "STATE_DIR_LEFT"):  # the last two at the end
                self.say(plan.warning_text(wid, user))
        for refusal in uplan.refusals:
            self.say(f"{refusal.code} ({'overridden' if refusal.overridden else 'blocks'}): {refusal.message}")
        for stage in uplan.stages:
            self.say(f"Stage {stage.name}: commit confirmed {stage.confirm_minutes}:")
            for line in plan.stage_lines(stage, uplan.layout):
                self.say(f"  {line}")
            for step in stage.files_after_confirm:
                self.say(f"  then {step.action} {step.path}")
        for step in uplan.files:
            self.say(f"  {step.action} {step.path}")
        for kept in uplan.kept:
            self.say(f"Stays: {kept.key}: {kept.reason}")
        for path in uplan.leftovers:
            self.say(f"Left in {plan.STATE_DIR} (not J-Wicket's name): {path}")
        if uplan.state_dir_left:
            self.say(f"Stays: {plan.STATE_DIR} itself, for root to remove once it is empty (printed at the end).")
        for leaf in uplan.unknown_leaves:
            self.say(f"Not known to this tool: {leaf}")
        if any(s.key == "F-OP" for st in uplan.stages for s in st.remove):
            self.say(
                "The uninstall stage also removes this op script's own stanza. Whether Junos stops a running op "
                "script when its stanza goes is unknown (Q-INST-03): if this script stops after that commit, finish "
                f"with the file deletes in {plan.UNINSTALL_CLI_PATH} ('{plan.cli_file_show(plan.UNINSTALL_CLI_PATH)}')."
            )

    def _process_gone(self) -> int:
        """C13 (9.5 step 6): no J-Wicket process before any file is deleted; one stop request, then exit 8."""
        pid = health.process_id(self._status_text())
        if pid is None:
            return plan.EXIT_OK
        self.say(
            f"J-Wicket process {pid} is still listed; asking Junos to stop it (same as 'request extension-service stop "
            f"{plan.DAEMON_FILE}'; its effect on a daemonized app is unknown, Q-INST-03)."
        )
        try:
            self.box.write("extension-service-stop", **{"application-name": plan.DAEMON_FILE})
        except (DeviceRefused, OutcomeUnknown) as exc:
            self.say(f"  the stop request was refused: {exc}")
        self.clock.sleep(STOP_WAIT_S)
        pid = health.process_id(self._status_text())
        if pid is None:
            return plan.EXIT_OK
        self.say(
            f"J-Wicket process {pid} still runs, so its files are kept (exit 8, incomplete). Stop it by hand "
            f"(deploy-lab step 9: in the shell, 'kill {pid}'), then run this script again to remove the files."
        )
        return plan.EXIT_UNINSTALL_INCOMPLETE

    def _verify_removed(self) -> None:
        listing = self._listing(plan.JET_DIR)
        names = (*plan.JWICKET_JET_FILES, plan.STAGING_FILE, plan.BACKUP_FILE)
        left = [e.path for e in (listing.entries if listing else ()) if e.path.rpartition("/")[2] in names]
        if left:
            self.say("Still listed: " + ", ".join(left))
        else:
            self.say("J-Wicket's files are gone from the script directory.")


def revert_units(stage: Stage, layout: Layout) -> Tuple[render.PasteUnit, ...]:
    """The revert stage as paste units, for when this script cannot run it (spec 6.5 'Failure')."""
    lines = plan.stage_lines(stage, layout)
    minutes = int(stage.confirm_minutes)
    return (
        render.PasteUnit(
            "R1",
            "revert: open configuration mode",
            "device-configuration",
            (plan.CLI_CONFIGURE, plan.CLI_SHOW_COMMIT),
            before=(plan.DEVICE_STATUS,),
            after=(f"STOP if {plan.PENDING_SIGNS}: type 'exit' and wait for it to settle.",),
            opens_configuration=True,
        ),
        render.PasteUnit(
            "R2",
            "revert: remove what this run added",
            "device-configuration",
            (*lines, plan.CLI_COMPARE),
            after=render.compare_expectation(lines),  # the device's other levels are not read here (JFR-02)
        ),
        render.PasteUnit(
            "R3",
            "revert: commit confirmed",
            "device-configuration",
            (plan.cli_commit_confirmed(minutes, stage.comment),),
            after=(f"Then '{plan.CLI_SHOW_COMMIT}' must show this commit as the newest; deadline {minutes} minutes.",),
        ),
        render.PasteUnit(
            "R4",
            "revert: confirm, only if the check matched",
            "device-configuration",
            (plan.cli_confirm(stage.confirm_comment), plan.CLI_EXIT),
        ),
    )


# ------------------------------------------------------------------------------------------------
# Entry point (the generated file calls main with its embedded payload)
# ------------------------------------------------------------------------------------------------


def main(
    payload_text: str,
    *,
    jcs_module: Any = None,
    pyez: Optional[Tuple[Any, Any, Any]] = None,
    account: Optional[Account] = None,
    clock: Optional[transport.Clock] = None,
    out: Optional[TextIO] = None,
    files: Optional[LocalFiles] = None,
    sysctl: Optional[Callable[[], Tuple[Optional[str], str]]] = None,
    https: Optional[HttpsGet] = None,
    xml: Optional[Callable[[str], Any]] = None,
    now: Optional[Callable[[], str]] = None,
    version: Optional[Tuple[int, ...]] = None,
) -> int:
    """Run the op script. Every keyword is for tests; on the device all come from the system. The Python
    version and the jcs and PyEZ imports are checked before anything is read (AC-006-32)."""
    stream = out if out is not None else sys.stdout
    console_out = Console(lambda prompt: None, stream)
    console_out.say(plan.DEVICE_STATUS)
    found = tuple(version) if version is not None else tuple(sys.version_info[:3])
    if found < MIN_PYTHON:
        console_out.say(
            f"This op script needs Python {'.'.join(map(str, MIN_PYTHON))} or later; this device runs "
            f"{'.'.join(map(str, found))}. Nothing was read or written."
        )
        return plan.EXIT_REFUSED
    try:
        payload = Payload.from_json(payload_text)
    except plan.PlanError as exc:
        console_out.say(f"This op script's embedded payload is invalid (rebuild it with build_op.py): {exc}")
        return plan.EXIT_INPUT
    try:
        jcs = jcs_module if jcs_module is not None else importlib.import_module("jcs")
    except ImportError:
        console_out.say(
            "The Junos 'jcs' module is not available: run this file on the device with 'op jwicket-install-op.py' "
            "(or 'op url ...'). Nothing was read or written."
        )
        return plan.EXIT_REFUSED
    try:
        device_factory, config_factory, errors = pyez if pyez is not None else import_pyez()
    except ImportError as exc:
        console_out.say(
            f"On-box PyEZ (jnpr.junos) does not import on this device ({type(exc).__name__}: "
            f"{plan.sanitize_display(str(exc), 120)}). A JET app imported it on a lab SRX4100 running 25.2R1-S1.4 "
            "(verified); which version Junos ships is unknown (Q-RT-01). Use the workstation installer instead. "
            "Nothing was read or written."
        )
        return plan.EXIT_REFUSED
    run_clock = clock if clock is not None else transport.SystemClock()
    try:
        who = account if account is not None else running_account()
    except (KeyError, OSError, ImportError) as exc:
        console_out.say(f"The account running this script could not be named: {exc}. Nothing was read or written.")
        return plan.EXIT_REFUSED
    console = Console(jcs.get_input, stream)
    box = LocalJunos(device_factory, config_factory, errors, run_clock, xml=xml)
    executor = OpExecutor(
        payload,
        box,
        console,
        run_clock,
        who,
        files=files,
        sysctl=sysctl or read_veriexec_sysctl,
        https=https or pinned_https,
        now=now or _utc_now,
    )
    return executor.run()


__all__ = [
    "MIN_PYTHON",
    "ONBOX_OVERRIDES",
    "Account",
    "BundleSource",
    "Candidate",
    "Console",
    "LocalFileError",
    "LocalFiles",
    "LocalJunos",
    "OpExecutor",
    "Payload",
    "Stop",
    "access_prompt",
    "listen_prompt",
    "main",
    "pinned_https",
    "revert_units",
]
