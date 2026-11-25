"""The workstation executor (Spec 006 sections 6.2, 8 and 9): M1, and M2 and M3 through it. LAB ONLY.

One run, in the order of spec 9.2: P1 host keys and connections; P2 to P6 reads only, among them the
listings of /var/db and /var/db/jwicket; P7 the plan, printed, and every refusal decided (R-STATEDIR
among them: root makes the state directory once, because a super-user-class account's 'mkdir' and 'file
make-directory' were refused on a lab SRX4100, verified; this executor never creates, changes or removes
the directory, never logs in as root and never asks for the root password); then, only with
``--apply``: A1 the lab gate (the operator types the device's host name, which this module reads from
the device itself and never prints before the prompt, INV-05), and with ``--lab-hardware`` the typed
'lab only' attestation (revision R5); A2 is retired (a re-read of the directory listing only); A3 the
confirm of the operator's own pending bootstrap (cut C5, an owner decision open for veto); A4 and A5 the
files, each verified by SHA-256, owner and mode, with ``--access tls`` a self-signed certificate made in
memory whose key goes to the device by SCP (0600) and nowhere else; the stages, each a ``commit
confirmed`` held under the exclusive lock, compared structurally with the plan before the commit (exit 6)
and before the confirm (C10), confirmed only when every check passed at least 60 s before the deadline
(INV-04), C8 being an HTTPS read from this workstation pinned to that certificate (revision R3: no check
uses an SSH channel); on a failure no confirm, the deadline printed, and the revert stage (8.8) unless
``--keep-partial``; A9 the receipts and the way in.

Rules this module keeps by control flow, tested with recording fakes (no run-time chokepoint checks the
gate): nothing written before the gate (INV-01); no ``commit check``,
``<check/>`` or ``<validate>`` (INV-02); the pending state re-read on the locked session right before
every commit and every confirm (INV-03); never a confirm from a new session after a drop (8.6); no
configured path written in place or deleted outside the plan's steps (INV-06); reads retried, writes
never; the TLS key and the lab token never on the workstation's disk, in a log or on the console. Every
installer step is unverified on a device until lab test Q-INST-06.
"""

from __future__ import annotations

import dataclasses
import hashlib
import logging
import secrets
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, FrozenSet, List, Mapping, Optional, Sequence, Set, TextIO, Tuple

from . import health, hostkeys, plan, receipt, render, state, transport, tunnel
from .health import Result
from .plan import FileStep, InstallPlan, Layout, Method, Stage, StatementSet, UninstallPlan
from .transport import (
    AuthFailed,
    Connector,
    DeviceRefused,
    HostKeyRejected,
    Netconf,
    NetconfUnavailable,
    OutcomeUnknown,
    ReadTimeout,
    SessionLost,
    Ssh,
    Target,
    TransportError,
)

LOG = logging.getLogger("jwicket_install.workstation")

POLL_S = 5
ROLLBACK_POLL_S = 10
RESULT_POLL_S = 2
STOP_WAIT_S = 10
MAX_ANSWER = 256
REMOVE_NETCONF_ANSWER = "remove-netconf"
ACCEPT_KEY_ANSWER = "yes"
ROLLBACK_ANSWER = "rollback"


# ------------------------------------------------------------------------------------------------
# The operator's terminal
# ------------------------------------------------------------------------------------------------


class Console:
    """Program output to standard output (to standard error with --json, where standard output carries
    one JSON document only, UI-006-01); prompts read a line from a terminal only."""

    def __init__(
        self,
        *,
        json_mode: bool = False,
        stdin: Optional[TextIO] = None,
        stdout: Optional[TextIO] = None,
        stderr: Optional[TextIO] = None,
    ) -> None:
        self.json_mode = json_mode
        self.status_shown = False  # DEVICE_STATUS already printed (cli.main prints it first)
        self._stdin = stdin if stdin is not None else sys.stdin
        self._stdout = stdout if stdout is not None else sys.stdout
        self._stderr = stderr if stderr is not None else sys.stderr

    @property
    def interactive(self) -> bool:
        try:
            return bool(self._stdin.isatty())
        except (AttributeError, ValueError):
            return False

    def say(self, text: str = "") -> None:
        stream = self._stderr if self.json_mode else self._stdout
        stream.write(text + "\n")
        stream.flush()

    def prompt(self, text: str) -> Optional[str]:
        """A typed answer, or None without a terminal (never a default)."""
        if not self.interactive:
            return None
        stream = self._stderr if self.json_mode else self._stdout
        stream.write(text)
        stream.flush()
        line = self._stdin.readline(MAX_ANSWER + 1)
        return line[:MAX_ANSWER] if line else None

    def stdin_line(self, what: str = "gate") -> Optional[str]:
        """--gate-from-stdin (M2's play only, spec 6.3): one line from standard input, the host name
        (``what`` 'gate') or, with --lab-hardware, the 'lab only' attestation (``what`` 'lab-only') on the
        next line; empty never matches."""
        line = self._stdin.readline(MAX_ANSWER + 1)
        return line[:MAX_ANSWER] if line else None

    def result(self, text: str) -> None:
        self._stdout.write(text if text.endswith("\n") else text + "\n")
        self._stdout.flush()


@dataclass
class RunOptions:
    """How this run behaves (CLI flags that are not plan Options)."""

    apply: bool = False
    gate_from_stdin: bool = False
    accept_new_host_key: bool = False
    device_diff: bool = False
    rollback_now: bool = False
    remove_shared: bool = False
    no_evidence: bool = False
    evidence_base: Path = field(default_factory=lambda: Path())
    bootstrap_nonce: Optional[str] = None
    follow_up: Tuple[str, ...] = ()
    known_hosts: Tuple[Path, ...] = ()


@dataclass
class Link:
    ssh: Ssh
    nc: Netconf
    key: hostkeys.HostKeyBlob
    fingerprints: Tuple[str, ...]
    ssh_config: str


@dataclass
class Preflight:
    facts: plan.DeviceFacts
    prior: plan.PriorState
    evidence: plan.OwnershipEvidence
    deltas: Dict[int, str]


@dataclass
class StageResult:
    code: int
    after_commit: bool = False  # a confirmed commit was sent (or may have been), then not confirmed
    session_lost: bool = False
    rolled_back: Optional[bool] = None


class Stop(Exception):
    """Ends the run with an exit code; the message was already printed."""

    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code


def _nonce() -> str:
    return "".join(secrets.choice(plan.NONCE_ALPHABET) for _ in range(plan.NONCE_LENGTH))


# ------------------------------------------------------------------------------------------------
# The executor
# ------------------------------------------------------------------------------------------------


class Executor:
    def __init__(
        self,
        target: Target,
        connector: Connector,
        console: Console,
        clock: transport.Clock,
        store: receipt.Store,
        run: RunOptions,
        *,
        tls_maker: Optional[Callable[[str], transport.TlsPair]] = None,
    ) -> None:
        """``tls_maker`` makes the --access tls pair for an address (default ``transport.make_tls_pair``,
        with the cryptography library; the tests' fake device hands in its own)."""
        self.target = target
        self.connector = connector
        self.console = console
        self.clock = clock
        self.store = store
        self.run = run
        self.link: Optional[Link] = None
        self.journal: Optional[receipt.Journal] = None
        self.overrides: Set[str] = set()
        self.confirmed: List[str] = []
        self.created: List[str] = []
        self.commits: List[plan.ReceiptCommit] = []
        self.had_receipt = False
        self.prior_paths: FrozenSet[str] = frozenset()  # every path the preflight listed, before any write
        self.rewritten: Set[str] = set()  # existing files the files phase wrote over (jwicket.ini on an upgrade)
        self.bootstrap_confirmed = False
        self.layout = Layout.DIRECT
        self.user = target.user
        self.json_doc: Dict[str, Any] = {}
        # --access tls: the pair this run made (the key only until it is on the device), and the SHA-256 of
        # its certificate once uploaded and verified: the fingerprint printed, recorded and pinned by C8.
        self.tls_pair: Optional[transport.TlsPair] = None
        self.tls_maker: Callable[[str], transport.TlsPair] = tls_maker or transport.make_tls_pair
        self.tls_cert_sha256: Optional[str] = None
        self.tls_cert_not_after: Optional[str] = None  # its notAfter (SEC-R1)
        self.tls_cert_file_sha256: Optional[str] = None  # the SHA-256 of tls.crt as uploaded (OPX-04)
        self.lab_attested = False  # --lab-hardware: the operator typed 'lab only' after the host name (R5)

    # -- output --------------------------------------------------------------------------------------

    def say(self, text: str = "") -> None:
        self.console.say(text)

    def _device_status(self) -> None:
        """DEVICE_STATUS once per run (UI-006-04): cli.main prints it first and marks the console."""
        if not self.console.status_shown:
            self.say(plan.DEVICE_STATUS)
            self.console.status_shown = True

    def step(self, name: str, outcome: str, **detail: Any) -> None:
        if self.journal is not None:
            self.journal.step(name, outcome, **detail)

    @property
    def nc(self) -> Netconf:
        if self.link is None:
            raise SessionLost("not connected")
        return self.link.nc

    @property
    def ssh(self) -> Ssh:
        if self.link is None:
            raise SessionLost("not connected")
        return self.link.ssh

    # -- P1: host keys, SSH and NETCONF ---------------------------------------------------------------

    def _known_hosts(self) -> List[Path]:
        paths = list(self.run.known_hosts) or [Path.home() / ".ssh" / "known_hosts"]
        paths.append(self.store.known_hosts())
        return paths

    def trusted_key(self, *, bootstrap_options: Optional[plan.Options] = None) -> hostkeys.HostKeyBlob:
        """P1, first half: the key of every port, judged against the known_hosts files, equal on all ports
        (INV-09); unknown only with --accept-new-host-key."""
        host = self.target.host
        failed_port: List[int] = []

        def fetch(port: int, types: Sequence[str]) -> hostkeys.HostKeyBlob:
            try:
                return self.connector.host_key(port, types)
            except TransportError:
                failed_port.append(port)
                raise

        try:
            verdicts = hostkeys.verify_ports(host, self.target.ports, fetch, self._known_hosts())
        except hostkeys.HostKeyError as exc:
            self._refusal("R-HOSTKEY", str(exc))
            raise Stop(plan.EXIT_REFUSED) from exc
        except TransportError as exc:
            if failed_port and failed_port[0] == self.target.nc_port != self.target.ssh_port and bootstrap_options:
                self.say(f"NETCONF port {self.target.nc_port} does not answer: {exc}")
                raise Stop(self._print_bootstrap(bootstrap_options)) from exc
            self.say(f"Cannot reach {host}: {exc}. Nothing was read or written.")
            raise Stop(plan.EXIT_REFUSED) from exc
        key = next(iter(verdicts.values())).key
        unknown = sorted(p for p, v in verdicts.items() if not v.known)
        fp = hostkeys.fingerprint(key)
        if unknown:
            self._accept_new(host, unknown, key, fp)
        self.say(f"Host key {fp} ({key[0]}) verified on port(s) {', '.join(str(p) for p in self.target.ports)}.")
        return key

    def open_ssh(self, key: hostkeys.HostKeyBlob) -> Ssh:
        try:
            return self.connector.open_ssh(key, hostkeys.algorithms_for([key[0]]))
        except AuthFailed as exc:
            self.say(f"{exc}. Use an SSH agent or key (--identity-file), or --password-prompt.")
            raise Stop(plan.EXIT_REFUSED) from exc
        except TransportError as exc:
            self.say(f"SSH to {self.target.host} failed: {exc}")
            raise Stop(plan.EXIT_REFUSED) from exc

    def connect(self, run_dir: Path, *, bootstrap_options: Optional[plan.Options] = None) -> Link:
        """P1: the trusted key, the own SSH client and NETCONF. A NETCONF that does not answer prints the
        bootstrap units (exit 1) when ``bootstrap_options`` is given."""
        host = self.target.host
        key = self.trusted_key(bootstrap_options=bootstrap_options)
        fp = hostkeys.fingerprint(key)
        ssh = self.open_ssh(key)
        try:
            available = self.connector.netconf_available(ssh, key)
        except TransportError as exc:
            ssh.close()
            self.say(f"Cannot check NETCONF on {host}: {exc}")
            raise Stop(plan.EXIT_REFUSED) from exc
        if not available:
            ssh.close()
            self.say(
                "NETCONF does not answer on the SSH port ('set system services netconf ssh' is probably not "
                "configured). Nothing was read or written."
            )
            if bootstrap_options is None:
                raise Stop(plan.EXIT_REFUSED)
            raise Stop(self._print_bootstrap(bootstrap_options))
        try:
            _, config = hostkeys.pinned_files(run_dir, host, [self.target.nc_port], key)
        except hostkeys.HostKeyError as exc:
            ssh.close()
            self.say(str(exc))
            raise Stop(plan.EXIT_REFUSED) from exc
        try:
            nc = self.connector.open_netconf(str(config))
        except HostKeyRejected as exc:
            ssh.close()
            self._refusal("R-HOSTKEY", str(exc))
            raise Stop(plan.EXIT_REFUSED) from exc
        except NetconfUnavailable as exc:
            ssh.close()
            self.say(f"{exc}")
            if bootstrap_options is None:
                raise Stop(plan.EXIT_REFUSED) from exc
            raise Stop(self._print_bootstrap(bootstrap_options)) from exc
        except AuthFailed as exc:
            ssh.close()
            self.say(f"{exc}. Use an SSH agent or key (--identity-file), or --password-prompt.")
            raise Stop(plan.EXIT_REFUSED) from exc
        except TransportError as exc:
            ssh.close()
            self.say(f"NETCONF to {host} failed: {exc}")
            raise Stop(plan.EXIT_REFUSED) from exc
        self.link = Link(ssh, nc, key, (fp,), str(config))
        return self.link

    def _accept_new(self, host: str, ports: Sequence[int], key: hostkeys.HostKeyBlob, fp: str) -> None:
        if not self.run.accept_new_host_key:
            self._refusal("R-HOSTKEY", f"unknown key {fp} ({key[0]}) on port(s) {', '.join(map(str, ports))}")
            raise Stop(plan.EXIT_REFUSED)
        if not self.console.interactive:
            self.say("--accept-new-host-key needs a terminal to compare the fingerprint. Nothing was written.")
            raise Stop(plan.EXIT_REFUSED)
        self.say(
            f"The device's SSH host key is not recorded. Its SHA-256 fingerprint is {fp} ({key[0]}).\n"
            "Compare it with the fingerprint read on the lab console or in the lab platform's own UI (how "
            "to read it from the Junos CLI is not yet recorded, lab test Q-INST-05)."
        )
        answer = self.console.prompt(f"Type {ACCEPT_KEY_ANSWER} if they match, or press Enter to stop: ")
        if answer is None or answer.strip() != ACCEPT_KEY_ANSWER:
            self.say("Host key not accepted. Nothing was written.")
            raise Stop(plan.EXIT_REFUSED)
        self.store.ensure()
        hostkeys.append_private(self.store.known_hosts(), [hostkeys.known_line(host, p, key) for p in ports])
        self.overrides.add("--accept-new-host-key")
        self.say(f"Recorded in {self.store.known_hosts()} (trust on first use, recorded as an override).")

    def _print_bootstrap(self, options: plan.Options, method: Method = Method.WORKSTATION) -> int:
        nonce = _nonce()
        boot = plan.build_bootstrap(method, options, None, nonce)
        if boot is None:  # pragma: no cover - a NETCONF bootstrap with no prior always adds S8
            return plan.EXIT_REFUSED
        follow = [line.replace("<NONCE>", nonce) for line in self.run.follow_up] or [
            f"jwicket-install install --apply --host {self.target.host} --user {options.user} "
            f"--bootstrap-nonce {nonce}"
        ]
        self.say("")
        self.say(render.units_to_text(render.render_bootstrap_units(boot, follow_up=follow)))
        self.say(
            f"Paste units A to D on the lab device (SSH or console), then run the command in unit E within "
            f"{boot.minutes} minutes. The nonce of this bootstrap is {nonce}."
        )
        self.json_doc = {
            "outcome": "bootstrap-needed",
            "bootstrap": {"kind": boot.kind, "nonce": nonce, "minutes": boot.minutes, "keys": list(boot.keys)},
        }
        return plan.EXIT_REFUSED

    def close(self) -> None:
        if self.link is not None:
            for end in (self.link.nc, self.link.ssh):
                try:
                    end.close()
                except Exception as exc:  # noqa: BLE001 - closing is best effort, never masks the outcome
                    LOG.debug("close failed: %s", type(exc).__name__)
            self.link = None

    # -- P2 to P6: reads -----------------------------------------------------------------------------

    def _read(self, name: str, **args: transport.ArgValue) -> transport.Reply:
        return self.nc.read(name, **args)

    def _config(self, database: str, inherit: bool) -> StatementSet:
        reply = self.nc.get_configuration(database=database, inherit=inherit)
        if state._config_root(reply) is None:
            detail = transport.error_text(reply) or "no configuration element"
            self.say(f"The {database} configuration could not be read: {detail}")
            raise Stop(plan.EXIT_REFUSED)
        return state.statements_from_config(reply)

    def _listing(self, directory: str) -> Optional[state.DirListing]:
        return state.file_list_from_reply(self._read("file-list", detail=True, path=directory), directory)

    def _checksum(self, path: str) -> Optional[str]:
        return state.checksum_from_reply(self._read("get-sha256-checksum-information", path=path))

    def _file_text(self, path: str) -> Optional[str]:
        return state.file_text_from_reply(self._read("file-show", filename=path), limit=state.MAX_REPLY_BYTES)

    def _commit_state(self) -> state.CommitState:
        return state.commit_state_from_reply(self._read("get-commit-information"))

    def _delta(self, sequence: int) -> Optional[str]:
        if sequence + 1 > transport.MAX_ROLLBACK:
            return None
        # The older configuration (n+1) is the base and the newer (n) is compared with it, so '+' means added
        # by commit n ([netconf-pdf] "Compare Two Previous (Rollback) Configurations Using NETCONF", verified).
        reply = self._read("get-rollback-information", rollback=str(sequence + 1), compare=str(sequence))
        return transport.output_text(reply, ("configuration-output", "output", "rollback-information"))

    def preflight(self, *, method: Method, nonce: Optional[str]) -> Preflight:
        """P2 to P6: facts, configuration (raw and inherited, select-only), commit state and history,
        file listings, checksums, receipts, veriexec. Reads only."""
        try:
            return self._preflight(method=method, nonce=nonce)
        except (ReadTimeout, SessionLost) as exc:
            self.say(f"The device could not be read: {exc}. Nothing was written.")
            raise Stop(plan.EXIT_REFUSED) from exc

    def _preflight(self, *, method: Method, nonce: Optional[str]) -> Preflight:
        assert self.link is not None  # noqa: S101 - connect() ran first
        software = self._read("get-software-information")
        cluster = self._read("get-chassis-cluster-status")
        inventory = self._read("get-chassis-inventory")
        flow = self._read("get-flow-session-information", summary=True)
        raw = self.nc.get_configuration(database="committed", inherit=False)
        inherited = self.nc.get_configuration(database="committed", inherit=True)
        commits = self._read("get-commit-information")
        lists = {d: self._read("file-list", detail=True, path=d) for d in plan.READ_DIRS}
        script_lists = {d: self._read("file-list", detail=True, path=d) for d in plan.S1_SCRIPT_DIRS}
        listed: Set[str] = set()
        for directory, reply in lists.items():
            parsed = state.file_list_from_reply(reply, directory)
            if parsed is not None:
                listed |= {e.path for e in parsed.entries}
        checksums: Dict[str, transport.Reply] = {}
        # The certificate's checksum too (it is public; the key's is never read): a recorded pair is kept only
        # while tls.crt is still the file this installer uploaded (OPX-04).
        for path in (*(f"{plan.JET_DIR}/{n}" for n in plan.JWICKET_JET_FILES), plan.SETTINGS_PATH, plan.TLS_CERT_PATH):
            if path in listed:
                checksums[path] = self._read("get-sha256-checksum-information", path=path)
        device_receipt = self._file_text(plan.RECEIPT_PATH) if plan.RECEIPT_PATH in listed else None
        fp = self.link.fingerprints[0]
        try:
            ws_receipt = self.store.read_receipt(fp)
        except receipt.StoreError as exc:
            self.say(f"The workstation receipt cannot be used: {exc}")
            raise Stop(plan.EXIT_REFUSED) from exc
        veriexec = self.ssh.veriexec()
        prior = state.prior_from_replies(
            inherited,
            raw,
            commits,
            lists,
            {"device": device_receipt, "workstation": ws_receipt},
            veriexec,
            checksums=checksums,
            script_lists=script_lists,
        )
        facts = state.facts_from_replies(
            software, cluster, inventory, raw, flow_sessions=state.flow_session_count(flow)
        )
        deltas: Dict[int, str] = {}
        newest = prior.newest
        if (
            prior.pending is plan.Pending.OTHER
            and newest is not None
            and newest.sequence == 0
            and any(t.startswith("jwicket-bootstrap") for t in newest.texts)
        ):
            delta = self._delta(0)
            if delta is not None:
                deltas[0] = delta
                found = plan.recognise_bootstrap(prior, method=method, user=self.user, nonce=nonce, delta_text=delta)
                if found is not None:
                    prior = plan.mark_own_bootstrap(prior, found)
        for entry in prior.history:
            if entry.sequence not in deltas and any(plan.is_installer_comment(t) for t in entry.texts):
                delta = self._delta(entry.sequence)
                if delta is not None:
                    deltas[entry.sequence] = delta
        evidence = plan.ownership_from_history(prior.history, deltas, user=self.user)
        return Preflight(facts, prior, evidence, deltas)

    # -- refusals and the gate ------------------------------------------------------------------------

    def _refusal(self, code: str, detail: str = "") -> None:
        message, override = plan.REFUSALS[code]
        self.say(f"{code}: {message}")
        if detail:
            self.say(f"  {plan.sanitize_display(detail)}")
        if override:
            self.say(f"  Override: {override} (recorded).")

    def gate(
        self,
        facts: plan.DeviceFacts,
        prior: Optional[plan.PriorState] = None,
        *,
        lab_hardware: bool = False,
        signs: Sequence[str] = (),
    ) -> None:
        """A1 (spec 8.2): the typed answer against the device's own host name, never shown before; then,
        for lab hardware (R5), the production signs again, LAB_HARDWARE_WARNING and the typed 'lab only'."""
        if self.run.gate_from_stdin:
            typed = self.console.stdin_line("gate")
        elif not self.console.interactive:
            self.say("The lab gate needs a typed host name, and standard input is not a terminal. Nothing was written.")
            raise Stop(plan.EXIT_GATE)
        else:
            typed = self.console.prompt(plan.LAB_GATE_PROMPT)
        if not plan.lab_gate_matches(typed, facts):
            self.say("That is not this device's host name (or nothing was typed). Nothing was written.")
            self._bootstrap_stays(prior)
            raise Stop(plan.EXIT_GATE)
        self.step("gate", "passed")
        self.say(f"Lab gate passed for {facts.hostname}.")
        if lab_hardware:
            self._lab_only(prior, signs)

    def _bootstrap_stays(self, prior: Optional[plan.PriorState]) -> None:
        if prior is not None and prior.own_bootstrap is not None:
            self.say(
                "Your bootstrap commit stays unconfirmed: Junos removes it at its deadline "
                f"({prior.own_bootstrap.deadline_text})."
            )

    def _lab_only(self, prior: Optional[plan.PriorState], signs: Sequence[str]) -> None:
        """R5: a device that is not a vSRX goes on only after the operator types 'lab only' exactly, the
        production signs shown first. The statement is recorded; it proves nothing (spec 8.2)."""
        self.say(plan.LAB_HARDWARE_WARNING)
        if signs:
            self.say("Production signs of this device (shown, not judged):")
            for sign in signs:
                self.say(f"  {sign}")
        if self.run.gate_from_stdin:
            typed = self.console.stdin_line("lab-only")
        else:
            typed = self.console.prompt(plan.LAB_HARDWARE_PROMPT)
        if not plan.lab_hardware_matches(typed):
            self.say(f"'{plan.LAB_HARDWARE_ANSWER}' was not typed. Nothing was written.")
            self._bootstrap_stays(prior)
            raise Stop(plan.EXIT_GATE)
        self.lab_attested = True
        self.step("lab-hardware", "attested")
        self.say("Recorded: you stated that this device carries only lab traffic (--lab-hardware).")

    # -- install --------------------------------------------------------------------------------------

    def install(
        self,
        identity: plan.BundleId,
        bundle_bytes: bytes,
        provenance: plan.Provenance,
        options: plan.Options,
        *,
        method: Method = Method.WORKSTATION,
        overrides: FrozenSet[str] = frozenset(),
    ) -> int:
        self.layout = options.layout
        self.overrides |= set(overrides)
        with self.store.run_dir() as run_dir:
            try:
                code = self._install(run_dir, identity, bundle_bytes, provenance, options, method)
            except Stop as stop:
                code = stop.code
            except TransportError as exc:
                code = self._unexpected_transport_error(exc)
            finally:
                self.close()
        return self._finish(code)

    def _unexpected_transport_error(self, exc: TransportError) -> int:
        """A device step failed where no handler expected it (spec 9.7: exit 4); the journal is finished."""
        self.say(f"The device stopped answering or refused a step: {exc}.")
        self.say("A pending 'commit confirmed' of this run, if any, rolls back at its deadline; run 'status' then.")
        self._list_created()
        return plan.EXIT_DEVICE_REFUSED

    def _finish(self, code: int, outcome: Optional[str] = None) -> int:
        if self.journal is not None:
            self.journal.finish(outcome or ("ok" if code == 0 else f"exit-{code}"), code)
        return code

    def _install(
        self,
        run_dir: Path,
        identity: plan.BundleId,
        bundle_bytes: bytes,
        provenance: plan.Provenance,
        options: plan.Options,
        method: Method,
    ) -> int:
        self.connect(run_dir, bootstrap_options=options)
        assert self.link is not None  # noqa: S101 - connect() returned
        pre = self.preflight(method=method, nonce=self.run.bootstrap_nonce)
        try:
            built = plan.build_install_plan(
                identity,
                provenance,
                options,
                pre.facts,
                pre.prior,
                method=method,
                overrides=frozenset(self.overrides),
                evidence=pre.evidence,
                now=receipt.utc_now(),
            )
        except plan.InvariantError as exc:
            self.say(f"The installer built a plan that breaks its own rules (a defect, nothing was sent): {exc}")
            return plan.EXIT_REFUSED
        self._show_plan(built, pre.prior)
        if built.blocked:
            if any(r.code == "R-STATEDIR" and not r.overridden for r in built.refusals):
                self.say(plan.directory_fallback(self.user))
            self.say("Refused before any write. Nothing was changed.")
            return plan.EXIT_REFUSED
        if not self.run.apply and not self.run.device_diff:
            self.say("Dry run: nothing was written. Run again with --apply to install.")
            return plan.EXIT_OK
        self.journal = self.store.journal("install", self.link.fingerprints)
        self.step("preflight", "read", stages=len(built.stages))
        if built.no_change:
            self.say("Nothing to change: this bundle and these options are already installed. Read-only checks:")
            return self._status_checks(built)
        self.gate(pre.facts, pre.prior, lab_hardware=built.lab_hardware, signs=built.production_signs)
        if self.run.device_diff and not self.run.apply:
            return self._device_diffs(built)
        return self._apply(built, pre, bundle_bytes)

    def _show_plan(self, built: InstallPlan, prior: plan.PriorState) -> None:
        if self.console.json_mode:
            self.json_doc["plan"] = render.plan_to_json(built)
            return
        self.say(render.render_plan_text(built, prior, status=not self.console.status_shown).rstrip("\n"))
        if built.bootstrap is not None:
            self.say(
                f"Your bootstrap ({built.bootstrap.comment}) is pending and unconfirmed. The installer confirms "
                "it only after the gate; otherwise Junos removes it at its deadline."
            )

    def _apply(self, built: InstallPlan, pre: Preflight, bundle_bytes: bytes) -> int:
        self.had_receipt = pre.prior.workstation_receipt is not None
        self.prior_paths = frozenset(pre.prior.files)
        # A2 is retired (revision R4): root made the directory; P7 refused R-STATEDIR otherwise. Its listing
        # is read once more (a read only), so a directory replaced since the dry run stops the run here.
        code = self._recheck_state_dir(pre.prior)
        if code:
            return code
        # A3: the operator's own bootstrap.
        boot = built.stage("bootstrap")
        if boot is not None:
            code = self._confirm_bootstrap(boot, pre.prior)
            if code:
                return code
            self._progress_receipt(built)
        # A4, A5: files (and, with --access tls, the certificate made in memory).
        code = self._files(built, bundle_bytes)
        if code:
            return code
        if self.tls_cert_sha256 is not None:
            self._progress_receipt(built)  # the certificate's fingerprint is on the record before any stage
        # A6 to A8: stages.
        for stage in built.stages:
            if stage.already_committed:
                continue
            result = self._run_stage(stage, built)
            if result.code == plan.EXIT_OK:
                self._progress_receipt(built)
                continue
            if stage.name == "netconf-removal":
                # J-Wicket itself is installed and confirmed; only the removal of NETCONF did not complete.
                self.say("'netconf ssh' stays on the device: remove it later with 'uninstall --apply --remove-shared'.")
                self._write_receipts(built)
                self._summary(built)
                return result.code
            if result.after_commit:
                self._after_failed_install(built, result)
            elif result.code == plan.EXIT_REFUSED and self.confirmed:
                self._partial_report(built)
            return result.code
        # A9: receipts and the summary.
        self._write_receipts(built)
        self._summary(built)
        if "RESTART_NEEDED" in built.warnings:
            # OPX-05: files J-Wicket reads at start were rewritten and nothing restarted it, so the running
            # process still has the old ones. The read checks say what it serves now (C8 pins the new
            # certificate, so it fails until the restart): exit 1 when they fail, as an idempotent rerun.
            self.say("Read-only checks against the running J-Wicket (it has not restarted):")
            return self._status_checks(built, rewritten=True)
        return plan.EXIT_OK

    # -- the state directory (R4: root's; read only here) -----------------------------------------------

    def _state_dir_info(self) -> Optional[plan.FileInfo]:
        listing = self._listing(plan.VAR_DB)
        if listing is None:
            return None
        return next((e for e in listing.entries if e.path == plan.STATE_DIR), None)

    def _recheck_state_dir(self, prior: plan.PriorState) -> int:
        """Not a write and not a step of its own: /var/db listed again right after the gate. The trust rule
        is the daemon's (and R-STATEDIR's): a directory, not a symbolic link, owned by the daemon's account,
        mode 0700. Otherwise R-STATEDIR with the one-time root step, exit 1, nothing written."""
        try:
            info = self._state_dir_info()
        except (ReadTimeout, SessionLost) as exc:
            self.say(f"The device could not be read: {exc}. Nothing was written.")
            self._bootstrap_stays(prior)
            return plan.EXIT_REFUSED
        why = f"{plan.STATE_DIR} is not listed" if info is None else plan.state_dir_untrusted(info, self.user)
        if why is None:
            return plan.EXIT_OK
        if info is None:
            shown = why
        else:
            kind = "a symbolic link" if info.is_symlink else ("a directory" if info.is_dir else "not a directory")
            mode = "unknown" if info.mode is None else f"{info.mode:04o}"
            shown = f"{plan.STATE_DIR} is {kind}, owner {info.owner or 'unknown'}, mode {mode}: {why}"
        root_step = plan.state_dir_root_step(self.user)
        self._refusal("R-STATEDIR", f"{shown} (changed since the dry run); as root, once: {root_step}")
        self.say(plan.directory_fallback(self.user))
        self._bootstrap_stays(prior)
        self.step("state-dir", "refused")
        self.say("Refused before any write. Nothing was changed.")
        return plan.EXIT_REFUSED

    # -- A3 -----------------------------------------------------------------------------------------

    def _pending_problem(self, cs: state.CommitState) -> Optional[str]:
        if cs.pending is plan.Pending.UNREADABLE:
            return "the commit state could not be read"
        if cs.scheduled or cs.prepared:
            return "a 'commit at' or 'commit prepare' is pending"
        if cs.pending is not plan.Pending.NONE:
            return "a 'commit confirmed' is waiting for its confirmation"
        return None

    def _confirm_bootstrap(self, boot: Stage, prior: plan.PriorState) -> int:
        assert prior.own_bootstrap is not None  # noqa: S101 - the plan has a bootstrap stage only then
        own = prior.own_bootstrap
        self.say(f"Confirming your bootstrap ({own.comment}): its health check is this NETCONF session (K2).")
        try:
            self.nc.lock()
        except (DeviceRefused, OutcomeUnknown, SessionLost) as exc:
            self.say(f"The exclusive lock was refused: {exc}. The bootstrap stays unconfirmed.")
            return plan.EXIT_DEVICE_REFUSED
        try:
            return self._confirm_bootstrap_locked(boot, prior, own)
        except (SessionLost, ReadTimeout) as exc:
            self.say(f"The device stopped answering before the bootstrap was confirmed: {exc}. It stays unconfirmed.")
            return plan.EXIT_DEVICE_REFUSED
        finally:
            self._unlock()

    def _confirm_bootstrap_locked(self, boot: Stage, prior: plan.PriorState, own: plan.Bootstrap) -> int:
        cs = self._commit_state()
        newest = cs.entries[0] if cs.entries else None
        ok = (
            cs.pending is plan.Pending.OTHER
            and not cs.scheduled
            and not cs.prepared
            and newest is not None
            and newest.pending_confirm
            and newest.user == own.user
            and own.comment in newest.texts
        )
        if not ok:  # K1
            self._refusal("R-PENDING", "the pending commit is no longer exactly your bootstrap")
            return plan.EXIT_REFUSED
        committed = self._config("committed", False)
        if committed != prior.direct:
            self.say("The committed configuration changed since it was read; the bootstrap stays unconfirmed.")
            return plan.EXIT_REFUSED
        outside = plan.headers_outside(boot, Layout.DIRECT, self.nc.compare(1))
        if outside:  # C10 on the bootstrap's own delta
            self.say("The bootstrap's committed delta changes something outside it: " + "; ".join(outside))
            return plan.EXIT_UNEXPECTED_DIFF
        try:
            self.nc.commit(own.confirm_comment, None)
        except (DeviceRefused, OutcomeUnknown, SessionLost) as exc:
            self.say(f"The bootstrap's confirming commit failed: {exc}. It rolls back at its deadline.")
            return plan.EXIT_DEVICE_REFUSED
        # That a commit on this NETCONF session confirms the commit confirmed typed in the operator's CLI
        # session is inferred ([commit-cmd] names no session or user; Q-INST-03): read back that the
        # bootstrap is no longer pending before counting it as confirmed.
        after = self._commit_state()
        if after.pending is plan.Pending.UNREADABLE or any(
            e.pending_confirm and own.comment in e.texts for e in after.entries
        ):
            self.say(
                "The confirming commit was accepted, but the bootstrap still shows as pending (or the commit state "
                "could not be read): it may not be confirmed (Q-INST-03). Nothing more is written; Junos rolls it "
                "back at its deadline."
            )
            self.step("bootstrap", "still-pending")
            return plan.EXIT_DEVICE_REFUSED
        self.bootstrap_confirmed = True
        self.commits.append(plan.ReceiptCommit("bootstrap", own.confirm_comment, True))
        self.step("bootstrap", "confirmed")
        self.say(f"Bootstrap confirmed (same as '{plan.cli_confirm(own.confirm_comment)}').")
        return plan.EXIT_OK

    def _unlock(self) -> None:
        try:
            self.nc.unlock()
        except TransportError as exc:
            LOG.info("unlock: %s", exc)

    # -- A4, A5: files --------------------------------------------------------------------------------

    def _info(self, path: str) -> Optional[plan.FileInfo]:
        directory = path.rpartition("/")[0]
        listing = self._listing(directory)
        if listing is None:
            return None
        return next((e for e in listing.entries if e.path == path), None)

    def _verify_file(self, path: str, sha: Optional[str], mode: int, *, fix_mode: bool = True) -> Optional[str]:
        """None when ``path`` has SHA-256 ``sha`` (if given), owner = the daemon account, the mode;
        otherwise what differs. A wrong mode is set once with file-change-permission, then re-read."""
        if sha is not None:
            actual = self._checksum(path)
            if actual != sha:
                return f"SHA-256 is {actual or 'unreadable'}, expected {sha}"
        info = self._info(path)
        if info is None:
            return "not listed after the transfer"
        if info.owner == "root":
            return "owned by root (R-ROOT: the account maps to uid 0)"
        if info.owner != self.user:
            return f"owned by {info.owner or 'unknown'}, not {self.user}"
        if info.mode != mode and fix_mode:
            self.nc.write("file-change-permission", filename=path, permission=f"{mode:o}")
            info = self._info(path)
        if info is None or info.mode != mode:
            return f"mode is {(info.mode or 0) if info else 0:04o}, not {mode:04o}"
        return None

    def _files(self, built: InstallPlan, bundle_bytes: bytes) -> int:
        staged = False
        try:
            for step in built.files:
                staged = staged or step.action == "stage"  # never configured: deleted on any failure (INV-06)
                problem = self._file_step(step, bundle_bytes, built)
                if problem is not None:
                    self.say(f"{step.path}: {problem}")
                    if staged:
                        self._delete(plan.STAGING_PATH)
                    self._list_created()
                    self.step("files", "failed", path=step.path)
                    return plan.EXIT_INTEGRITY
        except DeviceRefused as exc:
            self.say(f"The device refused a file step: {exc}")
            if staged:
                self._delete(plan.STAGING_PATH)
            self._list_created()
            return plan.EXIT_DEVICE_REFUSED
        except (SessionLost, ReadTimeout, OutcomeUnknown) as exc:
            # Spec 9.7: a session lost before the stage's commit is exit 4.
            self.say(f"The device stopped answering during the file steps: {exc}. Nothing was committed.")
            self._list_created()
            return plan.EXIT_DEVICE_REFUSED
        self.step("files", "verified", count=len(built.files))
        return plan.EXIT_OK

    def _scp(self, data: bytes, path: str, mode: int) -> Optional[str]:
        """An SCP push; a refused transfer is an integrity failure (exit 7), not a device refusal."""
        try:
            self.ssh.put(data, path, mode)
        except DeviceRefused as exc:
            return f"the transfer failed: {exc}"
        return None

    def _list_created(self) -> None:
        if self.created:
            self.say("Files this run created and left in place: " + ", ".join(self.created))
            self.say("'jwicket-install uninstall --apply' removes them (J-Wicket's names only).")

    def _note_created(self, path: str, existed: bool) -> None:
        if not existed and path not in self.created:
            self.created.append(path)
            if self.journal is not None:
                self.journal.created(path)

    def _file_step(self, step: FileStep, bundle_bytes: bytes, built: InstallPlan) -> Optional[str]:
        """One file action of the plan; returns what failed, or None."""
        action = step.action
        if action == "keep":
            return None
        if action == "delete":
            self._delete(step.path)
            return None
        existed = self._info(step.path) is not None
        if action == "stage":
            failed = self._stage_bundle(step, bundle_bytes, built)
            if failed is not None:
                return failed
            self._note_created(step.path, existed)
            if self._info(step.path) is None:
                return "the device did not create the staging file (refresh-from of an unconfigured name is unknown)"
            return self._verify_file(step.path, step.sha256, step.mode)
        if action in ("copy", "backup", "replace", "restore"):
            source = step.source or ""
            self.say(f"  copying {source} to {step.path} (same as '{plan.cli_file_copy(source, step.path)}')")
            try:
                self.nc.write("file-copy", source=source, destination=step.path)
            except DeviceRefused as exc:
                return f"the device refused the copy: {exc}"  # a refused copy is a transfer failure (9.7: exit 7)
            self._note_created(step.path, existed)
            problem = self._verify_file(step.path, step.sha256, step.mode)
            if problem is not None and action == "copy" and "owned by" in problem and "root" not in problem:
                # spec 9.2 A4: an on-device copy with the wrong owner is replaced by one SCP of that name
                self.say(f"  {step.path} {problem}; sending it by SCP instead")
                # The wrong-owner copy is this run's own and no configuration names it (a 'copy' step is for
                # unconfigured names only, INV-06): delete it, because SCP onto an existing file keeps its owner.
                self._delete(step.path)
                failed = self._scp(bundle_bytes, step.path, step.mode)
                self._note_created(step.path, existed)
                problem = failed or self._verify_file(step.path, step.sha256, step.mode)
            return problem
        if action == "write" and step.content == "tls-key":
            return self._send_tls_key(step, built, existed)
        if action == "write" and step.content == "tls-cert":
            return self._send_tls_cert(step, built, existed)
        if action == "write":
            data = self._content(step, built)
            self.say(f"  sending {step.path} by SCP, mode {step.mode:04o} (same as 'scp -O ... {step.path}')")
            failed = self._scp(data, step.path, step.mode)
            del data  # the lab token never outlives this call
            if failed is not None:
                return failed
            if existed:
                self.rewritten.add(step.path)
            self._note_created(step.path, existed)
            return self._verify_file(step.path, step.sha256, step.mode)
        return f"unknown file action {action}"

    def _content(self, step: FileStep, built: InstallPlan) -> bytes:
        if step.content == "settings":
            return built.settings_text.encode("utf-8")  # the plan's own text: its SHA-256 is in the step
        if step.content == "lab-token":
            return (secrets.token_hex(24) + "\n").encode("ascii")  # 48 hex; never stored, printed or logged
        raise plan.InvariantError(f"no content for {step.path}")

    # -- --access tls: the certificate and key (revision R2) -------------------------------------------

    def _pair(self, built: InstallPlan) -> transport.TlsPair:
        """The run's self-signed pair for the listen address, made once, in memory (never on this disk)."""
        if self.tls_pair is None:
            address = built.options.bind_address
            self.say(
                f"  making a self-signed TLS certificate for {address} (RSA-{plan.TLS_KEY_BITS}, "
                f"{plan.TLS_CERT_DAYS} days) in memory; its key goes to the device only"
            )
            self.tls_pair = self.tls_maker(address)
        return self.tls_pair

    def _send_tls_key(self, step: FileStep, built: InstallPlan, existed: bool) -> Optional[str]:
        pair = self._pair(built)
        info = self._info(step.path) if existed else None
        if info is not None and (info.owner != self.user or info.mode != step.mode or info.is_symlink or info.is_dir):
            # SCP onto an existing file keeps that file's mode (inferred OpenSSH sink behaviour): the old
            # file goes first, so the new key is never in a file that another account can read.
            self.say(f"  removing the old {step.path} (owner {info.owner or 'unknown'}, mode {(info.mode or 0):04o})")
            if not self._delete(step.path):
                return f"the old {step.path} could not be removed, so the new key was not sent"
            existed = False
        self.say(
            f"  sending {step.path} by SCP, mode {step.mode:04o} (the private key: made in memory, never written "
            "on this workstation, never shown)"
        )
        failed = self._scp(pair.key_pem, step.path, step.mode)
        if failed is not None:
            pair.forget_key()
            return failed
        pair.forget_key()
        if existed:
            self.rewritten.add(step.path)
        self._note_created(step.path, existed)
        # Spec 7.5: the key is checked by owner and mode only, never read back (not even its checksum).
        return self._verify_file(step.path, None, step.mode)

    def _send_tls_cert(self, step: FileStep, built: InstallPlan, existed: bool) -> Optional[str]:
        pair = self._pair(built)
        self.say(f"  sending {step.path} by SCP, mode {step.mode:04o} (the certificate: public)")
        failed = self._scp(pair.cert_pem, step.path, step.mode)
        if failed is not None:
            return failed
        if existed:
            self.rewritten.add(step.path)
        self._note_created(step.path, existed)
        file_sha = hashlib.sha256(pair.cert_pem).hexdigest()
        problem = self._verify_file(step.path, file_sha, step.mode)
        if problem is not None:
            return problem
        self.tls_cert_sha256 = pair.cert_sha256
        self.tls_cert_not_after = pair.not_after
        self.tls_cert_file_sha256 = file_sha
        self.step("tls", "certificate", sha256=pair.cert_sha256)
        self.say(
            f"  TLS certificate for {built.options.bind_address}: SHA-256 fingerprint "
            f"{plan.fingerprint_display(pair.cert_sha256)} (compare it in the browser; recorded in the install "
            "record, never the key)"
        )
        return None

    def _pin(self, built: Optional[InstallPlan]) -> Optional[str]:
        """C8's pin: this run's certificate, or the kept one the workstation's record names."""
        if self.tls_cert_sha256 is not None:
            return self.tls_cert_sha256
        if built is not None and built.options.tls:
            return built.receipt.tls_cert_sha256
        return None

    def _stage_bundle(self, step: FileStep, bundle_bytes: bytes, built: InstallPlan) -> Optional[str]:
        transfer = built.options.transfer
        if transfer == "scp":
            self.say(
                f"  sending the bundle to {step.path} by SCP (same as 'scp -O jwicket.py <u>@<device>:{step.path}')"
            )
            return self._scp(bundle_bytes, step.path, step.mode)
        url = str(built.options.pull_url)
        try:
            # JFR-05: on a management-instance device fxp0's route is in mgmt_junos, so the download names it
            # (the option is documented; that it routes the download through fxp0 is inferred).
            instance = built.pull_routing_instance
            if transfer == "file-copy":
                shown = plan.cli_file_copy(url, step.path, instance)
                self.say(f"  the device fetches {url} (same as '{shown}')")
                copy_args: Dict[str, transport.ArgValue] = {"source": url, "destination": step.path}
                if instance is not None:
                    copy_args["routing-instance"] = instance
                self.nc.write("file-copy", **copy_args)
            else:
                args: Dict[str, transport.ArgValue] = {
                    "type": "extension-service",  # <type>extension-service</type> ([refresh-from-cmd], verified)
                    "file": plan.STAGING_FILE,
                    "url": url,
                }
                if built.options.cert_file:
                    args["cert-file"] = built.options.cert_file
                if instance is not None:
                    args["routing-instance"] = instance
                shown = plan.cli_refresh_from(plan.STAGING_FILE, url, built.options.cert_file, instance)
                self.say(f"  {shown} (unverified)")
                self.nc.write("request-script-refresh-from", **args)
        except DeviceRefused as exc:
            return f"the device's download failed: {exc}"
        return None

    def _delete(self, path: str) -> bool:
        """file-delete of one exact J-Wicket path; an absent file is fine. Never recursive."""
        try:
            self.nc.write("file-delete", path=path)
        except DeviceRefused as exc:
            if state.is_absent_path_error(str(exc)):
                return True
            self.say(f"  could not delete {path}: {exc}")
            return False
        if path in self.created:
            self.created.remove(path)
        return True

    # -- the stage runner (8.6, 8.7) ------------------------------------------------------------------

    def _run_stage(self, stage: Stage, built: Optional[InstallPlan]) -> StageResult:
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
            # The inherited view is compared for group-layout stages that add or change statements; a stage
            # that removes the whole group (G-APPLY, G-GROUP) is checked on the raw view only, where its
            # removal is exactly 'delete apply-groups jwicket' and 'delete groups jwicket'.
            whole_group = any(st.key in (plan.APPLY_KEY, plan.GROUP_KEY) for st in stage.remove)
            group_view = layout is Layout.GROUP and not whole_group
            before_eff = self._config("committed", True) if group_view else None
        except (ReadTimeout, SessionLost) as exc:
            self.say(f"Stage {stage.name}: the device could not be read: {exc}")
            return StageResult(plan.EXIT_REFUSED)
        try:
            self.nc.lock()
        except (DeviceRefused, OutcomeUnknown) as exc:
            self.say(f"Stage {stage.name}: the exclusive lock ('configure exclusive') was refused: {exc}")
            return StageResult(plan.EXIT_DEVICE_REFUSED)
        except SessionLost as exc:
            self.say(f"Stage {stage.name}: the session closed: {exc}")
            return StageResult(plan.EXIT_DEVICE_REFUSED)
        locked = True
        sent = False  # a 'commit confirmed' was sent (or may have been): from here on, never a plain return
        replaced: List[FileStep] = []
        start = self.clock.monotonic()
        try:
            problem = self._pending_problem(self._commit_state())
            if problem is not None:
                self._refusal("R-PENDING", problem)
                return StageResult(plan.EXIT_REFUSED)
            for step in stage.files_before_commit:
                failure = self._pre_commit_file(step, built)
                if failure is not None:
                    self._restore(stage, replaced)
                    return StageResult(failure)
                if step.action == "replace":
                    replaced.append(step)
            lines = plan.stage_lines(stage, self.layout)
            self.say("  loading: " + "; ".join(lines))
            try:
                self.nc.load_set(lines)
            except DeviceRefused as exc:
                self._discard()
                self._restore(stage, replaced)
                self.say(f"Stage {stage.name}: the device refused the load: {exc}")
                self._checksum_hint(str(exc))
                return StageResult(plan.EXIT_DEVICE_REFUSED)
            candidate = self._config("candidate", False)
            unexpected = list(plan.structural_unexpected(stage, layout, before_raw, candidate))
            if before_eff is not None:
                candidate_eff = self._config("candidate", True)
                unexpected += plan.structural_unexpected(stage, layout, before_eff, candidate_eff, view="effective")
            diff = self.nc.compare(0)
            outside = list(plan.headers_outside(stage, layout, diff))
            self._show_device_diff(stage.name, diff)
            if unexpected or outside:
                self._discard()
                self._restore(stage, replaced)
                self.say(
                    f"Stage {stage.name}: the device's candidate differs from the plan; discarded, nothing committed:"
                )
                for line in [*unexpected, *outside]:
                    self.say(f"  {line}")
                self.step(stage.name, "unexpected-diff")
                return StageResult(plan.EXIT_UNEXPECTED_DIFF)
            problem = self._pending_problem(self._commit_state())  # INV-03, right before the commit
            if problem is not None:
                self._discard()
                self._restore(stage, replaced)
                self._refusal("R-PENDING", problem)
                return StageResult(plan.EXIT_REFUSED)
            start = self.clock.monotonic()
            sent = True
            try:
                self.nc.commit(stage.comment, stage.confirm_minutes)
            except DeviceRefused as exc:
                sent = False
                self._discard()
                self._restore(stage, replaced)
                self.say(f"Stage {stage.name}: the device refused the confirmed commit: {exc}")
                self._checksum_hint(str(exc))
                return StageResult(plan.EXIT_DEVICE_REFUSED)
            except (OutcomeUnknown, SessionLost) as exc:
                locked = not isinstance(exc, SessionLost)
                return self._not_confirmed(
                    stage,
                    before_raw,
                    start,
                    f"the commit's outcome is unknown: {exc}",
                    session_ok=locked,
                    replaced=replaced,
                )
            self.commits.append(plan.ReceiptCommit(stage.name, stage.comment, False))
            self.step(stage.name, "committed")
            self.say(
                f"  committed (same as '{plan.cli_commit_confirmed(minutes, stage.comment)}'); Junos rolls it back "
                f"in {minutes} minutes unless the checks pass and the installer confirms it."
            )
            results = self._checks(stage, start, offsets, before_raw, before_eff, layout, pin=self._pin(built))
            ok, warnings = health.summary(results)
            complete = len(results) == len(stage.checks)
            if ok and complete and plan.confirm_allowed(self.clock.monotonic() - start, minutes):
                try:
                    self.nc.commit(stage.confirm_comment, None)
                except (DeviceRefused, OutcomeUnknown, SessionLost) as exc:
                    locked = not isinstance(exc, SessionLost)
                    return self._not_confirmed(
                        stage,
                        before_raw,
                        start,
                        f"the confirming commit failed: {exc}",
                        session_ok=locked,
                        replaced=replaced,
                    )
                for warning in warnings:
                    self.say(f"  warning: {warning}")
                self.commits[-1] = plan.ReceiptCommit(stage.name, stage.comment, True)
                self.confirmed.append(stage.name)
                if self.journal is not None:
                    self.journal.confirmed(stage.name)
                self.say(f"Stage {stage.name} confirmed (same as '{plan.cli_confirm(stage.confirm_comment)}').")
            else:
                failed = next((r for r in results if not r.acceptable), None)
                reason = (
                    f"check {failed.check} failed: {failed.detail}"
                    if failed is not None
                    else "the checks did not finish at least 60 s before the deadline"
                )
                return self._not_confirmed(stage, before_raw, start, reason, session_ok=True, replaced=replaced)
        except SessionLost as exc:
            locked = False
            if not sent:
                self.say(
                    f"Stage {stage.name}: the session was lost before the commit ({exc}); nothing was committed in "
                    "this stage, and the session's end discards the candidate."
                )
                if replaced:
                    self.say("  Files replaced for this stage keep the new bytes: run 'install --apply' again.")
                return StageResult(plan.EXIT_DEVICE_REFUSED)
            return self._not_confirmed(
                stage, before_raw, start, f"the session was lost: {exc}", session_ok=False, replaced=replaced
            )
        except ReadTimeout as exc:
            if not sent:
                self._discard()
                self._restore(stage, replaced)
                self.say(f"Stage {stage.name}: a read timed out before the commit ({exc}); nothing was committed.")
                return StageResult(plan.EXIT_REFUSED)
            return self._not_confirmed(
                stage, before_raw, start, f"a read timed out: {exc}", session_ok=True, replaced=replaced
            )
        finally:
            if locked:
                self._unlock()
        return self._post_confirm(stage)

    def _post_confirm(self, stage: Stage) -> StageResult:
        if stage.post_confirm_checks:
            code = self._process_gone(stage)
            if code:
                return StageResult(code)
        for step in stage.files_after_confirm:
            if step.action == "delete":  # files only: the state directory itself is root's (R4)
                self._delete(step.path)
        return StageResult(plan.EXIT_OK)

    def _checksum_hint(self, message: str) -> None:
        lowered = message.lower()
        if "checksum" in lowered and any(w in lowered for w in ("unknown", "unsupported", "syntax error")):
            self.say(
                "  Junos does not accept the 'checksum sha-256' statement here: --no-jet-checksum installs without "
                "it (recorded; upgrades then refuse, R-UPGRADE-NOCHECKSUM)."
            )

    def _discard(self) -> None:
        try:
            self.nc.discard()
        except TransportError as exc:
            self.say(f"  could not discard the candidate ('rollback 0'): {exc}; the session's end discards it")

    def _pre_commit_file(self, step: FileStep, built: Optional[InstallPlan]) -> Optional[int]:
        """An upgrade's backup or replace, inside the stage's lock, right before its commit (INV-06)."""
        source = step.source or ""
        self.say(f"  copying {source} onto {step.path} (same as '{plan.cli_file_copy(source, step.path)}')")
        try:
            self.nc.write("file-copy", source=source, destination=step.path)
        except DeviceRefused as exc:
            self.say(
                f"  the device refused to write {step.path}: {exc}. Whether 'file copy' overwrites an existing "
                "file is unknown (Q-INST-01); nothing was deleted. Uninstall, then install, instead."
            )
            return plan.EXIT_DEVICE_REFUSED
        problem = self._verify_file(step.path, step.sha256, step.mode)
        if problem is not None:
            self.say(
                f"  {step.path}: {problem} (the device may have refused to overwrite it); stopping before the commit"
            )
            return plan.EXIT_DEVICE_REFUSED
        return None

    def _restore(self, stage: Stage, replaced: Sequence[FileStep]) -> None:
        """Put back the old bytes of every file this stage replaced (and of a settings file the files phase
        rewrote), by copy, never by delete (INV-06)."""
        paths = {s.path for s in replaced} | self.rewritten
        for step in stage.restore_on_failure:
            if step.path not in paths:
                continue
            source = step.source or ""
            self.say(f"  restoring {step.path} from {source}")
            try:
                self.nc.write("file-copy", source=source, destination=step.path)
                problem = self._verify_file(step.path, step.sha256, step.mode)
            except TransportError as exc:
                problem = str(exc)
            if problem is not None:
                self.say(f"  {step.path} was not restored: {problem}")

    def _show_device_diff(self, stage: str, diff: Optional[str]) -> None:
        lines = receipt.safe_lines(diff)
        self.say(f"  Junos's own 'show | compare' for stage {stage}:")
        for line in lines or ["(no difference)"]:
            self.say(f"    {line}")
        if self.journal is not None:
            self.journal.diff(stage, diff)

    # -- checks ---------------------------------------------------------------------------------------

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
        *,
        pin: Optional[str] = None,
    ) -> List[Result]:
        deadline = start + int(stage.confirm_minutes) * 60
        results: List[Result] = []
        context: Dict[str, Any] = {"offsets": offsets, "since": None, "pin": pin}
        for check in stage.checks:
            if deadline - self.clock.monotonic() < plan.CONFIRM_MARGIN_S:
                results.append(Result(check.id, health.FAIL, "out of time before the confirm margin"))
                break
            try:
                result = self._check(check, stage, context, before_raw, before_eff, layout, deadline)
            except (Stop, ReadTimeout) as exc:
                result = Result(check.id, health.FAIL, f"a read failed: {exc}")
            left = int(deadline - self.clock.monotonic())
            self.say(f"  {result.check} {result.status}: {result.detail} ({left} s left before the deadline)")
            # SPEC-10: each check's id and status is kept in the run's journal, so 'not-available' (C8 with
            # --access tunnel) is evidence that outlives the console.
            self.step("check", result.status, stage=stage.name, check=result.check)
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
            info = self._info(plan.STARTUP_REFUSED_PATH)
            if info is not None:
                text = receipt.safe_line(self._file_text(plan.STARTUP_REFUSED_PATH) or "")
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
            return self._c8(check, context.get("pin"), deadline)
        if cid in plan.RETIRED_CHECKS:  # C9 (R3): never planned; a plan that names it is a defect
            return Result(cid, health.FAIL, f"check {cid} is retired and never runs")
        if cid == "C10":
            committed = self._config("committed", False)
            unexpected = list(plan.structural_unexpected(stage, layout, before_raw, committed))
            if before_eff is not None:
                unexpected += plan.structural_unexpected(
                    stage, layout, before_eff, self._config("committed", True), view="effective"
                )
            outside = plan.headers_outside(stage, layout, self.nc.compare(1))
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

    def _c8(self, check: plan.Check, pin: Optional[str], deadline: float) -> Result:
        """C8 (R3): with --access tls an HTTPS GET /api/session from this workstation to the listen
        address, trusting only the certificate whose SHA-256 is ``pin``; never through an SSH channel.
        With --access tunnel the plan records it "not available". A read: a connection that does not open
        is tried again after 1, 2 and 4 s while the confirm margin allows; another certificate is not."""
        expect = check.expect
        if expect.get("access") != "tls" or check.target == "not-available":
            return health.not_available("C8", expect.get("reason") or plan.TUNNEL_C8_REASON)
        if expect.get("from") != "workstation":
            return health.not_available("C8", "read by the operator in a browser, not by this executor")
        if pin is None:
            return Result("C8", health.FAIL, "no certificate fingerprint to pin (the TLS pair is not on the record)")
        address, port = _split_host_port(expect.get("host", ""))
        answer = transport.HttpsResult(False, reason="not tried")
        for delay in (0, *plan.READ_RETRY_BACKOFF_S):
            if delay:
                if deadline - self.clock.monotonic() < plan.CONFIRM_MARGIN_S + delay:
                    break
                self.clock.sleep(delay)
            answer = self.connector.https_get(address, port, "/api/session", expect["host"], pin)
            if answer.connected:
                break
            LOG.info("C8: %s", answer.reason)
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
        context["port"] = None
        waited = 0
        limit = check.timeout_s
        result = Result("C4", health.FAIL, "not read")
        while True:
            result = self._log_result(check, context)
            if result.ok or "restarting" in result.detail or "another build" in result.detail:
                return result
            if waited >= limit or deadline - self.clock.monotonic() < plan.CONFIRM_MARGIN_S + POLL_S:
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
            reply = self.nc.write("extension-service-start", **{"application-name": app})
        except DeviceRefused as exc:
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
            if expect.get("unchecked_override") == "yes":
                return Result(check.id, health.NOT_AVAILABLE, "not checked (--accept-unchecked-diagnostics, recorded)")
            return Result(
                check.id,
                health.FAIL,
                "the start reply carried no output and this bundle writes no result file (no D2): pass "
                "--accept-unchecked-diagnostics to continue unchecked (recorded)",
            )
        return result

    # -- failure handling (8.8) -----------------------------------------------------------------------

    def _not_confirmed(
        self,
        stage: Stage,
        before_raw: StatementSet,
        start: float,
        reason: str,
        *,
        session_ok: bool,
        replaced: Sequence[FileStep] = (),
    ) -> StageResult:
        minutes = int(stage.confirm_minutes)
        left = max(0, int(start + minutes * 60 - self.clock.monotonic()))
        self.step(stage.name, "not-confirmed", reason=reason)
        self.say(f"Stage {stage.name} is NOT confirmed: {reason}.")
        self.say(f"Junos rolls it back at its deadline, in about {left} s ({minutes} minutes after the commit).")
        if self.confirmed:
            self.say(
                "After that, the revert stage removes what this run's confirmed stages added: "
                + ", ".join(self.confirmed)
            )
        if not session_ok:
            return self._after_drop(stage, before_raw, start, replaced)
        self._restore(stage, replaced)
        if stage.name == "runtime":
            self._show_refusal_evidence()
        if self.run.rollback_now:
            self._rollback_now(stage)
        # The wait runs under the stage's exclusive lock, so no other user's commit can confirm the failed
        # stage meanwhile. Whether Junos's own rollback at the deadline runs while this session holds the
        # lock is unknown (spec 13.4, Q-INST-03): a wait that ends without it is reported, and the revert
        # stage then does not run.
        rolled = self._wait_rollback(stage, before_raw, start)
        return StageResult(plan.EXIT_CHECK_FAILED, after_commit=True, rolled_back=rolled)

    def _show_refusal_evidence(self) -> None:
        """What J-Wicket itself said, before any revert removes it: startup-refused.txt and the log's tail."""
        try:
            refused = self._file_text(plan.STARTUP_REFUSED_PATH) if self._info(plan.STARTUP_REFUSED_PATH) else None
            log = self._file_text(plan.LOG_PATH) if self._info(plan.LOG_PATH) else None
        except TransportError as exc:
            LOG.info("could not read J-Wicket's own files: %s", exc)
            return
        for line in receipt.safe_lines(refused):
            self.say(f"  startup-refused.txt: {line}")
        for line in receipt.safe_lines(log)[-10:]:
            self.say(f"  jwicket.log: {line}")

    def _rollback_now(self, stage: Stage) -> None:
        if not self.console.interactive:
            return
        answer = self.console.prompt(
            f"Type {ROLLBACK_ANSWER} to restore the previous configuration now, or press Enter to wait for the "
            "deadline: "
        )
        if answer is None or answer.strip() != ROLLBACK_ANSWER:
            return
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
        assert stage.comment.startswith("jwicket ")  # noqa: S101 - install stage comments only
        version_sha = stage.comment.split(" ")[1:3]
        comment = f"jwicket {version_sha[0]} {version_sha[1]} rolled back by installer"
        try:
            self.nc.load_rollback(1)
            self.nc.commit(comment, None)
            self.say(f"Rolled back now (same as 'rollback 1' and '{plan.cli_confirm(comment)}'): a write.")
            self.step(stage.name, "rolled-back-now")
        except TransportError as exc:
            self.say(f"The rollback by hand failed: {exc}. Junos still rolls back at the deadline.")

    def _wait_rollback(self, stage: Stage, before_raw: StatementSet, start: float, *, locked: bool = True) -> bool:
        """Read until the committed configuration is the one before the stage again, or the deadline plus a
        minute passes (reads only). ``locked``: this session still holds the stage's exclusive lock."""
        end = start + int(stage.confirm_minutes) * 60 + 60
        while True:
            try:
                if self._config("committed", False) == before_raw:
                    self.say(f"Junos rolled stage {stage.name} back.")
                    return True
            except (ReadTimeout, SessionLost, Stop) as exc:
                LOG.info("rollback wait read failed: %s", exc)
                return False
            if self.clock.monotonic() >= end:
                if locked:
                    # JF-09: this wait holds the stage's exclusive lock (so no other commit can confirm the failed
                    # stage); whether Junos rolls back while the lock is held is unknown (Q-INST-03).
                    self.say(
                        f"Stage {stage.name} was not rolled back by its deadline while this session held the "
                        "exclusive lock (whether Junos rolls back under a held lock is unknown, Q-INST-03): the "
                        "lock is released now; check 'show system commit'."
                    )
                    self.step(stage.name, "not-rolled-back-while-locked")
                else:
                    self.say(f"Stage {stage.name} was not rolled back by its deadline: check 'show system commit'.")
                return False
            self.clock.sleep(ROLLBACK_POLL_S)

    def _after_drop(
        self, stage: Stage, before_raw: StatementSet, start: float, replaced: Sequence[FileStep]
    ) -> StageResult:
        """After a lost session: reconnect only to read (never a confirm from a new session, 8.6), wait for
        Junos's rollback, then restore the old bytes whose checksum is committed again (9.4 step 5)."""
        self.say("The NETCONF session was lost. Reconnecting only to read the committed configuration.")
        try:
            assert self.link is not None  # noqa: S101 - a stage runs only when connected
            try:
                self.link.nc.close()
            except Exception as exc:  # noqa: BLE001 - the old session is gone; closing is best effort
                LOG.debug("closing the lost session: %s", type(exc).__name__)
            self.link.nc = self.connector.open_netconf(self.link.ssh_config)
        except TransportError as exc:
            self.say(f"Could not reconnect: {exc}. Junos rolls the stage back at its deadline; run 'status' then.")
            return StageResult(plan.EXIT_CHECK_FAILED, after_commit=True, session_lost=True, rolled_back=None)
        rolled = self._wait_rollback(stage, before_raw, start, locked=False)
        touched = {s.path for s in replaced} | self.rewritten
        if rolled and stage.restore_on_failure:
            committed = self._config("committed", False)
            for step in stage.restore_on_failure:
                if step.path not in touched:
                    continue
                key = {
                    plan.DAEMON_PATH: "S13",
                    f"{plan.JET_DIR}/{plan.SELFTEST_FILE}": "S3",
                    f"{plan.JET_DIR}/{plan.PROBE_FILE}": "S5",
                }.get(step.path)
                pinned = committed.values(" ".join(plan.SPEC_BY_KEY[key].path)) if key else None
                if pinned is None or pinned == ((step.sha256,) if step.sha256 else ()):
                    self._restore(stage, [step])
                else:
                    self.say(
                        f"  {step.path}: the committed checksum is not the old one; its bytes are left as they are"
                    )
        return StageResult(plan.EXIT_CHECK_FAILED, after_commit=True, session_lost=True, rolled_back=rolled)

    def _after_failed_install(self, built: InstallPlan, result: StageResult) -> None:
        if built.options.keep_partial:
            self.say("--keep-partial: the revert stage is skipped; the device keeps what the confirmed stages added.")
            self._partial_report(built)
            return
        if result.session_lost or not result.rolled_back:
            self.say(
                "The revert stage does not run after a lost session or a missing rollback; nothing more is written."
            )
            self._partial_report(built)
            return
        if built.upgrade:
            # spec 9.4: a failed upgrade keeps the previous build running; a confirmed diagnostics stage left
            # new diagnostic copies whose checksums are committed, which is consistent. Nothing is reverted.
            self.say(
                "The upgrade was rolled back to the previous build. The diagnostic copies may be the new build's, "
                "with their committed checksums; run 'jwicket-install status' to check the running daemon."
            )
            return
        include_bootstrap = (self.run.remove_shared and self.bootstrap_confirmed and built.bootstrap is not None) or (
            self.bootstrap_confirmed and built.bootstrap is not None and built.bootstrap.kind != "netconf"
        )
        names = [n for n in self.confirmed if n in ("diagnostics", "runtime")]
        names += ["bootstrap"] if include_bootstrap else []
        if not any(s.add for s in built.stages if s.name in names):
            self._remove_created_files(built)
            self._remove_run_results()
            return
        revert = plan.build_revert_stage(built, names, include_bootstrap=include_bootstrap)
        self.say("Reverting what this run's confirmed stages added (the revert stage).")
        outcome = self._run_stage(revert, built)
        if outcome.code == plan.EXIT_OK:
            self._remove_run_results()
            self.say("Reverted: the device's configuration is as it was before this run.")
            if not self.had_receipt and self.link is not None:
                self.store.remove_receipt(self.link.fingerprints[0])
        else:
            self.say("The revert stage did not complete: the device keeps this run's confirmed stages.")
            self._partial_report(built)

    def _remove_created_files(self, built: InstallPlan) -> None:
        """No stage was confirmed: delete the files this run created, once a fresh read shows that no
        configuration names them (INV-06). Never the state directory: root made it (R4)."""
        if not self.created:
            return
        configured = self._configured_paths()
        for path in list(self.created):
            if path in configured:
                self.say(f"  {path} is configured; left in place")
                continue
            self._delete(path)
        if self.created:
            self._list_created()
        else:
            self.say("The files this run created were removed; the device is as it was before this run.")

    def _remove_run_results(self) -> None:
        """After a revert: the result and refusal files the device wrote during this run (its self-test,
        probe and refused start; J-Wicket's own names in the state directory, configured nowhere, INV-06)
        go too, once their content was shown. The state directory itself stays: it is root's (R4). A log
        or audit trail this run's daemon started is kept as evidence; 'uninstall --apply' removes it."""
        for path in (plan.SELFTEST_RESULT_PATH, plan.PROBE_RESULT_PATH, plan.STARTUP_REFUSED_PATH):
            if path not in self.prior_paths:
                self._delete(path)
        listing = self._listing(plan.STATE_DIR)
        kept = [
            e.path
            for e in (listing.entries if listing is not None else ())
            if e.path in (plan.LOG_PATH, plan.AUDIT_PATH) and e.path not in self.prior_paths
        ]
        if kept:
            self.say("Kept as evidence of this run: " + ", ".join(kept) + " ('uninstall --apply' removes them).")

    def _configured_paths(self) -> FrozenSet[str]:
        committed = self._config("committed", False)
        prior = plan.PriorState(effective=committed, direct=committed)
        return prior.configured_paths

    def _partial_report(self, built: InstallPlan) -> None:
        if self.confirmed:
            self.say("Installed and confirmed so far: stage(s) " + ", ".join(self.confirmed) + ".")
        self.say(
            "Finish with 'jwicket-install install --apply' again once the device is settled, or remove with "
            "'jwicket-install uninstall --apply'."
        )
        self._list_created()

    # -- --device-diff ------------------------------------------------------------------------------

    def _device_diffs(self, built: InstallPlan) -> int:
        self.say(
            "--device-diff: loading each stage into the candidate under the lock, then discarding it. "
            "This touches the candidate (a write); nothing is committed or checked."
        )
        for stage in built.stages:
            if stage.already_committed:
                continue
            try:
                self.nc.lock()
            except TransportError as exc:
                self.say(f"The exclusive lock was refused: {exc}")
                return plan.EXIT_DEVICE_REFUSED
            try:
                problem = self._pending_problem(self._commit_state())
                if problem is not None:
                    self._refusal("R-PENDING", problem)
                    return plan.EXIT_REFUSED
                try:
                    self.nc.load_set(plan.stage_lines(stage, self.layout))
                except DeviceRefused as exc:
                    self.say(f"Stage {stage.name}: the device refused the load: {exc}")
                    self._discard()
                    return plan.EXIT_DEVICE_REFUSED
                self._show_device_diff(stage.name, self.nc.compare(0))
                self._discard()
            finally:
                self._unlock()
        return plan.EXIT_OK

    # -- read-only checks of a running install (idempotent re-run, status) ----------------------------

    def _status_checks(self, built: InstallPlan, *, rewritten: bool = False) -> int:
        """The read checks of an idempotent rerun (exit 1 when one fails). ``rewritten``: this run wrote files
        J-Wicket reads at start and nothing restarted it (OPX-05), so a failure says to restart it."""
        results: List[Result] = []
        for check in built.status_checks:
            if check.id in ("C4", "C5"):
                continue  # 'exactly one new line' needs a commit; status shows the last lines instead
            if check.id == "C7":
                pid = health.process_id(self._status_text())
                result = Result(
                    "C7", health.PASS if pid else health.FAIL, f"process {pid}" if pid else "no J-Wicket process"
                )
            else:
                result = self._check(
                    check,
                    Stage("runtime", (), (), (), "x", "x", plan.Minutes(5), ()),
                    {"offsets": {}, "since": None, "pin": self._pin(built)},
                    StatementSet(),
                    None,
                    self.layout,
                    self.clock.monotonic() + 3600,
                )
            self.say(f"  {result.check} {result.status}: {result.detail}")
            results.append(result)
        ok, warnings = health.summary(results)
        for warning in warnings:
            self.say(f"  warning: {warning}")
        if ok:
            self.say("Healthy.")
        elif rewritten:
            self.say(
                "Not healthy until J-Wicket restarts with the new files: see the checks and the restart step above."
            )
        else:
            self.say("Not healthy: nothing was changed; see the checks above.")
        self.json_doc["healthy"] = ok
        return plan.EXIT_OK if ok else plan.EXIT_REFUSED

    def status(self, *, port: Optional[int] = None, identity: Optional[plan.BundleId] = None) -> int:
        """Read-only (9.6). C8 from the workstation's record of the listener: --access tls reads
        /api/session over HTTPS with the recorded certificate pinned; --access tunnel: not available.
        ``port`` overrides the recorded daemon port."""
        with self.store.run_dir() as run_dir:
            try:
                self.connect(run_dir)
                pre = self.preflight(method=Method.WORKSTATION, nonce=None)
                return self._status(pre, port, identity)
            except Stop as stop:
                return stop.code
            finally:
                self.close()

    def _status_c8(self, record: Optional[plan.Receipt], version: str, port: Optional[int] = None) -> Result:
        if record is None:
            return health.not_available("C8", "this workstation has no install record to pin a certificate with")
        if record.access != "tls" or record.listen_address is None:
            return health.not_available("C8", plan.TUNNEL_C8_REASON)
        if record.tls_cert_sha256 is None:
            return Result("C8", health.FAIL, "the install record names no certificate fingerprint to pin")
        daemon_port = port or record.port or plan.DEFAULT_TLS_PORT
        host = plan.host_port(record.listen_address, daemon_port)
        expect = {"access": "tls", "host": host, "status": "200", "version": version, "if_unavailable": "fail"}
        answer = self.connector.https_get(
            record.listen_address, daemon_port, "/api/session", host, record.tls_cert_sha256
        )
        return health.https_session(
            answer.data, expect, connected=answer.connected, pinned=answer.pinned, reason=answer.reason
        )

    def _status(self, pre: Preflight, port: Optional[int], identity: Optional[plan.BundleId]) -> int:
        prior = pre.prior
        facts = pre.facts
        self._device_status()
        self.say(
            f"Device: model {facts.model or 'unknown'}, release {facts.junos_version or 'unknown'}, "
            f"serial {facts.serial or 'unknown'}"
        )
        stanzas = prior.jwicket_stanzas
        self.say("J-Wicket stanzas: " + (", ".join(sorted(stanzas)) or "none"))
        for name in plan.JWICKET_JET_FILES:
            path = f"{plan.JET_DIR}/{name}"
            info = prior.files.get(path)
            if info is None:
                self.say(f"  {path}: absent")
                continue
            sha = prior.checksums.get(path, "unreadable")
            self.say(f"  {path}: owner {info.owner}, mode {(info.mode or 0):04o}, sha256 {sha}")
        receipt_ws = prior.workstation_receipt
        receipt_dev = prior.device_receipt
        self.say(
            f"Workstation receipt: {'bundle ' + receipt_ws.bundle_version if receipt_ws else 'none'}; "
            f"device receipt (advisory): {'bundle ' + receipt_dev.bundle_version if receipt_dev else 'none'}"
        )
        if receipt_ws is not None and pre.evidence.history_available:
            agree = set(receipt_ws.statements_added) <= pre.evidence.keys | set(receipt_ws.statements_present_before)
            self.say(
                f"Commit history and the workstation receipt {'agree' if agree else 'disagree'} about what "
                "this installer added."
            )
        pid = health.process_id(self._status_text())
        self.say(f"Process: {pid if pid else 'not listed'}")
        log = self._file_text(plan.LOG_PATH) if plan.LOG_PATH in prior.files else None
        for line in receipt.safe_lines(log)[-10:]:
            self.say(f"  log: {line}")
        healthy = bool(pid)
        c8 = "not read"
        if pid:
            version = identity.version if identity else (receipt_ws.bundle_version if receipt_ws else "")
            result = self._status_c8(receipt_ws, version, port)
            self.say(f"  C8 {result.status}: {result.detail}")
            healthy = healthy and result.acceptable
            c8 = result.status
        not_after = receipt_ws.tls_cert_not_after if receipt_ws is not None else None
        expiry = plan.certificate_expiry(not_after)
        if expiry is not None:
            # SEC-R1: C8 pins the fingerprint, not the dates, so an expired certificate still passes it; a
            # browser refuses it, so an expired one makes status unhealthy.
            self.say(f"  warning: {expiry}")
            self.json_doc["certificate_expiry"] = expiry
            healthy = healthy and not plan.certificate_expired(not_after)
        if receipt_ws is not None:
            for line in tunnel.reach_lines(
                receipt_ws, user=self.user, host=self.target.host, ssh_port=self.target.ssh_port, port=port
            ):
                self.say(line)
        self.json_doc.update(
            {
                "outcome": "status",
                "healthy": healthy,
                "process": bool(pid),
                "stanzas": sorted(stanzas),
                "access": receipt_ws.access if receipt_ws is not None else "unknown",
                "c8": c8,
            }
        )
        return plan.EXIT_OK

    # -- uninstall (9.5) ------------------------------------------------------------------------------

    def uninstall(self, *, method: Method = Method.WORKSTATION, overrides: FrozenSet[str] = frozenset()) -> int:
        self.overrides |= set(overrides)
        with self.store.run_dir() as run_dir:
            try:
                code = self._uninstall(run_dir, method)
            except Stop as stop:
                code = stop.code
            except TransportError as exc:
                code = self._unexpected_transport_error(exc)
            finally:
                self.close()
        return self._finish(code)

    def _uninstall(self, run_dir: Path, method: Method) -> int:
        self.connect(run_dir)
        assert self.link is not None  # noqa: S101 - connect() returned
        pre = self.preflight(method=method, nonce=None)
        uplan = plan.build_uninstall_plan(
            pre.evidence,
            pre.facts,
            pre.prior,
            method=method,
            remove_shared=self.run.remove_shared,
            overrides=frozenset(self.overrides),
            user=self.user,
        )
        self.layout = uplan.layout
        self._show_uninstall(uplan, pre)
        if uplan.blocked:
            self.say("Refused before any write. Nothing was changed.")
            return plan.EXIT_REFUSED
        if uplan.no_change:
            self.say("Nothing of J-Wicket's is on this device. Nothing to remove.")
            self._state_dir_left(uplan)
            return plan.EXIT_OK
        if not self.run.apply:
            self._state_dir_left(uplan)
            self.say("Dry run: nothing was written. Run again with --apply to remove J-Wicket.")
            return plan.EXIT_OK
        self.journal = self.store.journal("uninstall", self.link.fingerprints)
        self.gate(pre.facts, lab_hardware=uplan.lab_hardware, signs=plan._production_signs(pre.facts, pre.prior))
        if not self.run.no_evidence:
            self._fetch_evidence(pre.prior)
        for stage in uplan.stages:
            if stage.name == "netconf-removal" and not self._confirm_remove_netconf():
                self.say("'netconf ssh' stays.")
                continue
            result = self._run_stage(stage, None)
            if result.code != plan.EXIT_OK:
                if stage.name == "netconf-removal" and result.session_lost:
                    self._netconf_units(stage)
                return result.code
        if not uplan.stages and uplan.files:
            code = self._process_gone(
                Stage("uninstall", (), (), (), "x", "x", plan.Minutes(5), (), post_confirm_checks=uplan.file_checks)
            )
            if code:
                return code
            for step in uplan.files:
                if step.action == "delete":  # files only: the state directory itself is root's (R4)
                    self._delete(step.path)
        self._verify_removed()
        self._state_dir_left(uplan)
        self.say(plan.NOT_REMOVED_BY_TOOL)
        self.store.remove_receipt(self.link.fingerprints[0])
        return plan.EXIT_OK

    def _state_dir_left(self, uplan: UninstallPlan) -> None:
        """R4: the uninstaller leaves /var/db/jwicket for root, who made it (STATE_DIR_LEFT)."""
        if uplan.state_dir_left:
            self.say(plan.STATE_DIR_LEFT)

    def _show_uninstall(self, uplan: UninstallPlan, pre: Preflight) -> None:
        """The removal plan, with the production signs shown before the gate's first prompt (spec 8.2)."""
        signs = plan._production_signs(pre.facts, pre.prior)
        if self.console.json_mode:
            self.json_doc["uninstall"] = {
                "production_signs": list(signs),
                "stages": [{"name": s.name, "lines": list(plan.stage_lines(s, uplan.layout))} for s in uplan.stages],
                "files": [f.path for s in uplan.stages for f in s.files_after_confirm] + [f.path for f in uplan.files],
                "kept": [k.key for k in uplan.kept],
                "refusals": [r.code for r in uplan.refusals],
                "blocked": uplan.blocked,
                "state_dir_left": uplan.state_dir_left,
                "lab_hardware": uplan.lab_hardware,
            }
            return
        user = uplan.user or self.user
        self._device_status()
        self.say(
            f"Device: model {pre.facts.model or 'unknown'}, release {pre.facts.junos_version or 'unknown'}, "
            f"serial {pre.facts.serial or 'unknown'}"
        )
        self.say("Shown, not judged (a production device would show these):")
        for sign in signs:
            self.say(f"  {sign}")
        for wid in uplan.warnings:
            if wid not in ("DEVICE_STATUS", "NOT_REMOVED_BY_TOOL", "STATE_DIR_LEFT"):  # the last two: at the end
                self.say(plan.warning_text(wid, user))
        if uplan.lab_hardware:
            self.say(plan.LAB_HARDWARE_WARNING)
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
        for leaf in uplan.unknown_leaves:
            self.say(f"Not known to this tool: {leaf}")

    def _confirm_remove_netconf(self) -> bool:
        self.say(plan.REMOVE_NETCONF_WARNING)
        if not self.console.interactive:
            self.say("Removing 'netconf ssh' needs its own typed confirmation at a terminal.")
            return False
        answer = self.console.prompt(f"Type {REMOVE_NETCONF_ANSWER} to remove it, or press Enter to keep it: ")
        return answer is not None and answer.strip() == REMOVE_NETCONF_ANSWER

    def _netconf_units(self, stage: Stage) -> None:
        lines = plan.stage_lines(stage, self.layout)
        units = (
            render.PasteUnit(
                "A",
                "remove netconf: open configuration mode",
                "device-configuration",
                (plan.CLI_CONFIGURE, plan.CLI_SHOW_COMMIT),
                opens_configuration=True,
                after=(f"STOP if {plan.PENDING_SIGNS}: type 'exit'.",),
            ),
            render.PasteUnit(
                "B",
                "remove netconf",
                "device-configuration",
                (*lines, plan.CLI_COMPARE),
                after=render.compare_expectation(lines),
            ),
            render.PasteUnit(
                "C",
                "commit confirmed",
                "device-configuration",
                (plan.cli_commit_confirmed(5, plan.uninstall_comment("netconf-removal")),),
                after=(f"Check: {plan.SHOW_NETCONF} shows nothing.",),
            ),
            render.PasteUnit(
                "D",
                "only if the check above matches",
                "device-configuration",
                (
                    plan.SHOW_NETCONF,
                    plan.cli_confirm(plan.uninstall_comment("netconf-removal", confirmed=True)),
                    plan.CLI_EXIT,
                ),
            ),
        )
        self.say("Removing NETCONF ended this session, so Junos restores it. Remove it from an SSH or console session:")
        self.say(render.units_to_text(units))

    def _process_gone(self, stage: Stage) -> int:
        """C13 (9.5 step 6): no J-Wicket process before any file is deleted; one stop request, then exit 8."""
        pid = health.process_id(self._status_text())
        if pid is None:
            return plan.EXIT_OK
        self.say(
            f"J-Wicket process {pid} is still listed; asking Junos to stop it (same as "
            f"'request extension-service stop {plan.DAEMON_FILE}'; its effect on a daemonized app is unknown)."
        )
        try:
            self.nc.write("extension-service-stop", **{"application-name": plan.DAEMON_FILE})
        except DeviceRefused as exc:
            self.say(f"  the stop request was refused: {exc}")
        self.clock.sleep(STOP_WAIT_S)
        pid = health.process_id(self._status_text())
        if pid is None:
            return plan.EXIT_OK
        self.say(
            f"J-Wicket process {pid} still runs, so its files are kept (exit 8, incomplete). Stop it by hand "
            f"(deploy-lab step 9: in the shell, 'kill {pid}'), then run 'jwicket-install uninstall --apply' again "
            "to remove the files."
        )
        return plan.EXIT_UNINSTALL_INCOMPLETE

    def _fetch_evidence(self, prior: plan.PriorState) -> None:
        assert self.link is not None  # noqa: S101 - connected
        names = [
            name
            for name in plan.STATE_DIR_KNOWN_FILES
            if name.startswith(("jwicket.log", "audit.jsonl"))
            or name
            in (
                "startup-refused.txt",
                "selftest-result.json",
                "probe-result.json",
                "setup-result.json",
                "install-receipt.json",
            )
        ]
        present = [n for n in names if f"{plan.STATE_DIR}/{n}" in prior.files]
        if not present:
            return
        try:
            directory = receipt.evidence_dir(self.run.evidence_base, self.link.fingerprints[0])
        except (OSError, receipt.StoreError) as exc:
            # Before any write to the device: say why and stop, so the logs are not removed unfetched.
            self.say(
                f"The evidence directory cannot be created in {self.run.evidence_base}: {exc}. Nothing was written "
                "to the device. Give a writable --evidence-dir, or --no-evidence to remove the logs unfetched."
            )
            raise Stop(plan.EXIT_INPUT) from exc
        for name in present:
            local = directory / name
            try:
                self.ssh.get(f"{plan.STATE_DIR}/{name}", str(local))
                local.chmod(0o600)
            except (TransportError, OSError) as exc:
                self.say(f"  evidence {name} not fetched: {exc}")
        self.say(f"Evidence fetched to {directory} (deploy-lab step 8).")

    def _verify_removed(self) -> None:
        listing = self._listing(plan.JET_DIR)
        left = [
            e.path
            for e in (listing.entries if listing else ())
            if e.path.rpartition("/")[2] in (*plan.JWICKET_JET_FILES, plan.STAGING_FILE, plan.BACKUP_FILE)
        ]
        if left:
            self.say("Still listed: " + ", ".join(left))
        else:
            self.say("J-Wicket's files are gone from the script directory.")

    # -- render --method cli with --host (spec 6.8): reads, refusals, the gate, then the units ----------

    def render_units(
        self,
        identity: Optional[plan.BundleId],
        provenance: Optional[plan.Provenance],
        options: plan.Options,
        *,
        overrides: FrozenSet[str],
        uninstall: bool,
        set_files: bool,
    ) -> Tuple[int, Tuple[render.PasteUnit, ...], Optional[InstallPlan]]:
        """Read-only: connect, read, apply the refusals, print the production signs, ask for the host name,
        and only then return the paste units, stamped with that name and the time."""
        self.overrides |= set(overrides)
        with self.store.run_dir() as run_dir:
            try:
                self.connect(run_dir)
                pre = self.preflight(method=Method.CLI, nonce=None)
                if uninstall:
                    uplan = plan.build_uninstall_plan(
                        pre.evidence,
                        pre.facts,
                        pre.prior,
                        method=Method.CLI,
                        remove_shared=self.run.remove_shared,
                        overrides=frozenset(self.overrides),
                        user=self.user,
                    )
                    self.layout = uplan.layout
                    self._show_uninstall(uplan, pre)
                    if uplan.blocked:
                        self.say("Refused: no units are printed.")
                        return plan.EXIT_REFUSED, (), None
                    self.gate(
                        pre.facts,
                        lab_hardware=uplan.lab_hardware,
                        signs=plan._production_signs(pre.facts, pre.prior),
                    )
                    return plan.EXIT_OK, render.render_cli_uninstall_units(uplan, prior=pre.prior), None
                assert identity is not None and provenance is not None  # noqa: S101 - the CLI passes both
                built = plan.build_install_plan(
                    identity,
                    provenance,
                    options,
                    pre.facts,
                    pre.prior,
                    method=Method.CLI,
                    overrides=frozenset(self.overrides),
                    evidence=pre.evidence,
                )
                self._device_status()
                self.say("Shown, not judged (a production device would show these):")
                for sign in built.production_signs:
                    self.say(f"  {sign}")
                for refusal in built.refusals:
                    self.say(f"{refusal.code} ({'overridden' if refusal.overridden else 'blocks'}): {refusal.message}")
                    if refusal.detail:
                        self.say(f"  {refusal.detail}")
                if built.blocked:
                    if any(r.code == "R-STATEDIR" and not r.overridden for r in built.refusals):
                        self.say(plan.directory_fallback(self.user))
                    self.say("Refused: no units are printed.")
                    return plan.EXIT_REFUSED, (), built
                self.gate(pre.facts, lab_hardware=built.lab_hardware, signs=built.production_signs)
                units = render.render_cli_units(
                    built,
                    prior=pre.prior,
                    set_files=set_files,
                    stamp_host=pre.facts.hostname,
                    stamp_time=receipt.utc_now(),
                )
            except Stop as stop:
                return stop.code, (), None
            else:
                return plan.EXIT_OK, units, built
            finally:
                self.close()

    def reach(self, *, port: Optional[int] = None) -> int:
        """`open` (R3: it forwards nothing): the device's host key verified as for every run (a key
        exchange only, no sign-in), this workstation's record of that device, and the way in it names:
        the URL and the certificate's fingerprint with --access tls, checked with C8's pinned read; the
        'ssh -L' line and TUNNEL_WARNING with --access tunnel."""
        try:
            key = self.trusted_key()
        except Stop as stop:
            return stop.code
        try:
            text = self.store.read_receipt(hostkeys.fingerprint(key))
            record = plan.Receipt.from_json(text) if text is not None else None
        except (receipt.StoreError, plan.PlanError, ValueError) as exc:
            self.say(f"The install record for this device cannot be used: {exc}")
            return plan.EXIT_REFUSED
        for line in tunnel.reach_lines(
            record, user=self.user, host=self.target.host, ssh_port=self.target.ssh_port, port=port
        ):
            self.say(line)
        if record is None:
            return plan.EXIT_REFUSED
        if record.access != "tls":
            return plan.EXIT_OK
        result = self._status_c8(record, record.bundle_version, port)
        self.say(f"  C8 {result.status}: {result.detail}")
        return plan.EXIT_OK if result.ok else plan.EXIT_REFUSED

    # -- A9 -------------------------------------------------------------------------------------------

    def _run_receipt(self, built: InstallPlan) -> plan.Receipt:
        assert self.link is not None  # noqa: S101 - connected
        source = built
        if self.tls_cert_sha256 is None and any(f.content == "tls-cert" and f.action == "write" for f in built.files):
            # The new certificate is not verified on the device yet (a record written after the bootstrap's
            # confirm, or after a failed files phase): this record names no certificate until it is.
            source = dataclasses.replace(
                built,
                files=tuple(
                    dataclasses.replace(f, action="keep") if f.content in ("tls-key", "tls-cert") else f
                    for f in built.files
                ),
            )
        final = plan.receipt_for_run(
            source,
            host_key_sha256=self.link.fingerprints,
            time=receipt.utc_now(),
            commits=self.commits,
            bootstrap_confirmed=True if self.bootstrap_confirmed else None,
            tls_cert_sha256=self.tls_cert_sha256,
            lab_hardware_attested=True if self.lab_attested else None,
            tls_cert_not_after=self.tls_cert_not_after,
            tls_cert_file_sha256=self.tls_cert_file_sha256,
        )
        return dataclasses.replace(
            final, overrides=tuple(sorted(set(final.overrides) | (self.overrides & plan.OVERRIDES)))
        )

    def _progress_receipt(self, built: InstallPlan) -> None:
        """After each confirmed stage, the workstation receipt records the run so far, so that a run that
        stops half-way can still be removed by ownership (spec 7.9 needs the history and this record to
        agree on a shared statement). The device copy is written once, at the end."""
        assert self.link is not None  # noqa: S101 - connected
        try:
            self.store.write_receipt(self.link.fingerprints[0], self._run_receipt(built))
        except (OSError, receipt.StoreError) as exc:
            self.say(f"The workstation receipt was not updated: {exc}")

    def _write_receipts(self, built: InstallPlan) -> None:
        assert self.link is not None  # noqa: S101 - connected
        final = self._run_receipt(built)
        path = self.store.write_receipt(self.link.fingerprints[0], final)
        self.json_doc["receipt"] = "written"
        for step in built.final_files:
            if step.content == "receipt":
                try:
                    self.ssh.put(final.to_json().encode("utf-8"), step.path, step.mode)
                except TransportError as exc:
                    self.say(f"The device receipt (advisory) was not written: {exc}")
        self.step("receipts", "written")
        self.say(f"Workstation receipt: {path}")

    def _summary(self, built: InstallPlan) -> None:
        """A9 and UI-006-06: the host name, the way in (the URL and the certificate's fingerprint with
        --access tls; the 'ssh -L' line and TUNNEL_WARNING with --access tunnel), the backend, the
        uninstall command. The receipt path was printed with the receipts."""
        options = built.options
        user = options.user
        port_flag = f" --port {self.target.ssh_port}" if self.target.ssh_port != 22 else ""
        self.say("")
        self.say(f"J-Wicket {built.bundle.version} is installed on {built.facts.hostname} (lab only).")
        restart = "RESTART_NEEDED" in built.warnings
        if restart:
            self.say(plan.RESTART_NEEDED)
        if options.tls:
            opened = render.render_open(built, cert_sha256=self._pin(built))
            if restart and self.tls_cert_sha256 is not None:
                # The new pair is on the device but the running process still serves the old certificate.
                opened = tuple(f"After that restart: {line}" for line in opened)
            for line in opened:
                self.say(line)
        else:
            line = render.render_tunnel(
                user, options.port, host=tunnel.ssh_host(self.target.host), ssh_port=self.target.ssh_port
            )
            self.say(f"Reach it through an SSH tunnel: {line}")
            self.say(f"Then browse to http://{plan.LOOPBACK}:{options.port}/ while that SSH session stays open.")
            self.say(plan.TUNNEL_WARNING)
        self.say(f"'jwicket-install open --host {self.target.host} --user {user}{port_flag}' prints this again.")
        if options.backend == "lab-token":
            self.say(f"Sign in with the lab token: read it on the device with 'file show {plan.LAB_TOKEN_PATH}'.")
        else:
            self.say("Sign in with a Junos account (the netconf backend).")
        self.say(f"Remove it later: {self._uninstall_command(user)}")

    def _uninstall_command(self, user: str) -> str:
        """OPX-02: the uninstall command with what uninstall needs from this run: the ports, and the refusals
        this run overrode that uninstall applies too (R-MODEL's --lab-hardware, R-MANAGED's --ack-managed,
        R-COMMIT-SCRIPTS' --ack-commit-scripts). --adopt is not needed: the stanzas are on the record now."""
        parts = ["jwicket-install uninstall --apply", f"--host {self.target.host}", f"--user {user}"]
        if self.target.ssh_port != 22:
            parts.append(f"--port {self.target.ssh_port}")
        if self.target.netconf_port is not None:
            parts.append(f"--netconf-port {self.target.netconf_port}")
        parts += sorted(self.overrides & UNINSTALL_NEEDS)
        return " ".join(parts)


# The overrides of a run that its uninstall needs again, because uninstall applies the same refusals.
UNINSTALL_NEEDS = frozenset({plan.LAB_HARDWARE_FLAG, "--ack-managed", "--ack-commit-scripts"})


def _split_host_port(text: str) -> Tuple[str, int]:
    """'<address>:<port>' or '[<v6>]:<port>' (plan.host_port) back to its parts."""
    address, _, port = text.rpartition(":")
    if address.startswith("[") and address.endswith("]"):
        address = address[1:-1]
    if not port.isdigit():
        raise plan.InvariantError(f"C8's host {plan.sanitize_display(text)!r} is not '<address>:<port>'")
    return plan.canonical_address(address), int(port)
