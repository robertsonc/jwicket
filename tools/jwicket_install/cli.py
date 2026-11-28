"""``jwicket-install``: the lab-gated workstation installer's command line (Spec 006 sections 6.2, 6.7,
6.8, 8, 9 and 12). LAB ONLY: J-Wicket has not passed gate G1, and every device step is unverified until
lab test Q-INST-06.

Commands: ``guide`` (interactive lab setup and install), ``install`` (a dry run unless ``--apply``;
an upgrade is ``install --release <newer tag>``),
``uninstall`` (a dry run unless ``--apply``), ``status`` (read-only), ``render`` (``--method cli`` paste
units, ``--set-files``, ``--upgrade``; ``--method cli-uninstall``), ``bootstrap`` (the one-time NETCONF or
op-script bootstrap units), ``fetch`` (download a pre-release and check its provenance) and ``open`` (how
to reach J-Wicket: the URL and certificate fingerprint, or the ``ssh -L`` line; it forwards nothing).
``--json`` prints one JSON document on standard output and nothing else (UI-006-01).

Access (revision R2): ``--access tls`` (the default) listens with TLS on ``--listen-address`` (default:
``--host`` when that is an IP address; required otherwise), port 9443 unless ``--daemon-port``; the
installer makes the certificate in memory and prints only its SHA-256 fingerprint. ``--access tunnel``
keeps 127.0.0.1 behind ``ssh -L`` (refused on a lab SRX4100, ``TUNNEL_WARNING``). ``--port`` is the SSH
port. ``--lab-hardware`` (R5) lets a physical SRX through R-MODEL, with a typed 'lab only' after the
host name.

Exit codes (spec 9.7): 0 done, dry run printed or nothing to change; 1 refused (R-STATEDIR among them:
root makes /var/db/jwicket once), unreadable, or NETCONF off (bootstrap printed); 2 bad arguments; 3 gate
or 'lab only' not passed, or no terminal; 4 the device refused a step before that stage's commit; 5 a
check failed after ``commit confirmed`` (rolled back, reverted unless ``--keep-partial``); 6 the device's
change differed from the plan; 7 transfer, integrity or provenance failure; 8 uninstall incomplete.

Credentials: an SSH agent or key (``--identity-file``), or a password typed at a ``getpass`` prompt
(``--password-prompt``). There is no password option, environment variable or file (INV-08).
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import re
import shlex
import sys
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Sequence, Tuple

from . import __version__, hostkeys, plan, provenance, receipt, render, transport, workstation
from .plan import Layout, Method
from .workstation import Console, Executor, RunOptions

LOG = logging.getLogger("jwicket_install")

HOST_RE = re.compile(r"^(?:[A-Za-z0-9][A-Za-z0-9._-]{0,252}|[0-9]{1,3}(?:\.[0-9]{1,3}){3})\Z")
OVERRIDE_FLAGS: Tuple[str, ...] = (
    "--adopt",
    plan.LAB_HARDWARE_FLAG,
    "--ack-managed",
    "--ack-commit-scripts",
    "--veriexec-not-enforcing-ok",
    "--trust-release-page-only",
    "--accept-unchecked-diagnostics",
)
UNINSTALL_OVERRIDES: Tuple[str, ...] = ("--adopt", plan.LAB_HARDWARE_FLAG, "--ack-managed", "--ack-commit-scripts")
METHODS = {"workstation": Method.WORKSTATION, "ansible": Method.ANSIBLE, "container": Method.CONTAINER}
QUIET_LOGGERS = ("ncclient", "paramiko", "jnpr", "scp")


class CliError(Exception):
    """Bad arguments or inputs (exit 2)."""


class Refused(Exception):
    """A refusal decided from the arguments alone (exit 1), before anything is downloaded or contacted."""


# ------------------------------------------------------------------------------------------------
# Arguments
# ------------------------------------------------------------------------------------------------


def _target_args(parser: argparse.ArgumentParser, *, host_required: bool = True) -> None:
    group = parser.add_argument_group("device")
    group.add_argument("--host", required=host_required, help="the lab device's address or DNS name")
    group.add_argument("--user", required=True, help="the super-user-class account (not root); J-Wicket runs as it")
    group.add_argument(
        "--port",
        "--ssh-port",
        dest="ssh_port",
        type=int,
        default=22,
        help="SSH port; NETCONF uses it too unless --netconf-port (default 22)",
    )
    group.add_argument("--netconf-port", type=int, default=None, help="a NETCONF-only port such as 830 (fallback)")
    group.add_argument("--identity-file", default=None, help="an SSH private key file (else the agent and ~/.ssh keys)")
    group.add_argument(
        "--password-prompt", action="store_true", help="ask for the SSH password at a terminal (never an option)"
    )
    group.add_argument(
        "--accept-new-host-key",
        action="store_true",
        help="trust an unknown host key after comparing its SHA-256 fingerprint (recorded)",
    )
    group.add_argument("--known-hosts", action="append", default=[], help=argparse.SUPPRESS)


def _bundle_args(parser: argparse.ArgumentParser, *, local: bool = True) -> None:
    """``local``: the command also takes a local --bundle (install and render; fetch only downloads)."""
    group = parser.add_argument_group("bundle and provenance (spec 8.9)")
    group.add_argument("--release", default=None, help="the pre-release tag, e.g. v0.1.0.dev1")
    group.add_argument("--repo", default=provenance.DEFAULT_REPO, help="owner/name of the release repository")
    if local:
        group.add_argument("--bundle", default=None, help="a local jwicket.py instead of a download")
    else:
        parser.set_defaults(bundle=None)  # OPX-13: fetch's --help no longer offers an option it refuses
    group.add_argument("--expect-sha256", default=None, help="P-E: the bundle's SHA-256 from a channel you trust")
    group.add_argument("--expect-source", default=None, help="P-E: one word naming that channel")
    group.add_argument("--checkout", default=None, help="a git checkout for P-B ancestry, P-C and P-D")
    group.add_argument("--reproduce", action="store_true", help="P-D: rebuild the bundle in --checkout and compare")
    group.add_argument("--no-gh", action="store_true", help="do not use gh (skips P-A and P-B)")
    group.add_argument("--asset-host", action="append", default=[], help="an extra allowed download host")
    group.add_argument(
        "--trust-release-page-only",
        action="store_true",
        help="no independent source: stamps the record 'not qualification evidence'",
    )
    group.add_argument("--local-self-test", action="store_true", help="run the bundle self-test here first")


def _plan_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("what to install (spec 7.2)")
    group.add_argument("--backend", choices=plan.BACKENDS, default="netconf")
    group.add_argument(
        "--access",
        choices=plan.ACCESS_MODES,
        default=None,
        help="tls (default; lab-token: tunnel): HTTPS on --listen-address; tunnel: 127.0.0.1 behind ssh -L",
    )
    group.add_argument(
        "--listen-address",
        default=None,
        help="--access tls: the device address your browser reaches, e.g. fxp0's (default: --host if an IP address)",
    )
    group.add_argument(
        "--daemon-port",
        type=int,
        default=0,
        help=f"J-Wicket's port (default {plan.DEFAULT_TLS_PORT} with tls, {plan.DEFAULT_PORT} with tunnel)",
    )
    group.add_argument("--layout", choices=[layout.value for layout in Layout], default=Layout.DIRECT.value)
    group.add_argument("--no-jet-checksum", action="store_true", help="leave out 'checksum sha-256' (recorded)")
    group.add_argument("--confirm-minutes", type=int, default=5)
    group.add_argument("--bootstrap-minutes", type=int, default=10)
    group.add_argument("--transfer", choices=plan.TRANSFERS, default="scp", help="M5: scp push, or a device pull")
    group.add_argument("--url", default=None, help="M5: the URL the device pulls the bundle from")
    group.add_argument("--cert-file", default=None, help="M5 refresh-from over https: a PEM under /var/db/jwicket/")
    group.add_argument("--allow-plain-http", action="store_true", help="M5 over http (recorded as consent)")
    group.add_argument("--remove-diagnostics", action="store_true", help="remove the diagnostic copies after install")
    netconf = group.add_mutually_exclusive_group()
    netconf.add_argument("--remove-netconf-after", dest="remove_netconf_after", action="store_true", default=None)
    netconf.add_argument("--keep-netconf", dest="remove_netconf_after", action="store_false")


def _override_args(parser: argparse.ArgumentParser, flags: Sequence[str]) -> None:
    group = parser.add_argument_group("recorded overrides (spec 8.11)")
    for flag in flags:
        if flag == "--trust-release-page-only":
            continue  # with the provenance arguments
        group.add_argument(flag, action="store_true")


def build_parser() -> argparse.ArgumentParser:
    # allow_abbrev=False everywhere: an option is taken only as spelled in full, so no abbreviation can
    # stand for --apply or another option that writes (the container entry point guards them too).
    parser = argparse.ArgumentParser(
        prog="jwicket-install",
        allow_abbrev=False,
        description=(
            f"{plan.DEVICE_STATUS} LAB ONLY: installs, upgrades and removes J-Wicket on a lab vSRX, "
            "dry run by default, gated on the device's typed host name."
        ),
    )
    parser.add_argument("--version", action="version", version=f"jwicket-install {__version__}")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="diagnostics on standard error")
    commands = parser.add_subparsers(dest="command", required=True)

    guide = commands.add_parser(
        "guide", allow_abbrev=False, help="interactive setup, preview and optional install on a lab device"
    )
    guide.add_argument("--release", default=f"v{__version__}", help="the published lab release (default: this version)")
    guide.add_argument("--port", type=int, default=22, help="device SSH port (default: 22)")
    guide.add_argument("--netconf-port", type=int, default=None, help="separate NETCONF port, if already configured")
    guide.add_argument("--lab-hardware", action="store_true", help="allow the existing physical lab SRX gate")

    install = commands.add_parser(
        "install", allow_abbrev=False, help="install, upgrade or repair (dry run unless --apply)"
    )
    _target_args(install)
    _bundle_args(install)
    _plan_args(install)
    _override_args(install, OVERRIDE_FLAGS)
    run = install.add_argument_group("run")
    run.add_argument("--apply", action="store_true", help="write, after the plan, the warnings and the gate")
    run.add_argument(
        "--gate-from-stdin",
        action="store_true",
        help="the typed host name on standard input (M2's play only: refused without --method ansible)",
    )
    run.add_argument("--bootstrap-nonce", default=None, help="the nonce of the bootstrap you pasted")
    run.add_argument("--device-diff", action="store_true", help="after the gate, print Junos's own diff per stage")
    run.add_argument("--rollback-now", action="store_true", help="after a failed check, offer an immediate rollback")
    run.add_argument("--keep-partial", action="store_true", help="skip the revert stage after a failure (debugging)")
    run.add_argument("--remove-shared", action="store_true", help="the revert also removes the NETCONF bootstrap")
    run.add_argument("--method", choices=sorted(METHODS), default="workstation", help=argparse.SUPPRESS)
    run.add_argument("--json", action="store_true", help="one JSON document on standard output")

    uninstall = commands.add_parser(
        "uninstall", allow_abbrev=False, help="remove what this installer added (dry run unless --apply)"
    )
    _target_args(uninstall)
    _override_args(uninstall, UNINSTALL_OVERRIDES)
    urun = uninstall.add_argument_group("run")
    urun.add_argument("--apply", action="store_true")
    urun.add_argument(
        "--gate-from-stdin",
        action="store_true",
        help="the typed host name on standard input (M2's play only: refused without --method ansible)",
    )
    urun.add_argument(
        "--remove-shared", action="store_true", help="also 'netconf ssh', with its own typed confirmation"
    )
    urun.add_argument("--no-evidence", action="store_true", help="do not fetch the logs before removing them")
    urun.add_argument(
        "--evidence-dir",
        default=None,
        help="where evidence-<id>-<time>/ is created (default: the current directory, or the state directory "
        f"when {receipt.STATE_ENV} is set, as in the container)",
    )
    urun.add_argument("--method", choices=sorted(METHODS), default="workstation", help=argparse.SUPPRESS)
    urun.add_argument("--json", action="store_true")

    status = commands.add_parser("status", allow_abbrev=False, help="read-only: what is installed and whether it runs")
    _target_args(status)
    status.add_argument("--daemon-port", type=int, default=None, help="J-Wicket's port (default: the install record's)")
    status.add_argument("--json", action="store_true")

    rend = commands.add_parser("render", allow_abbrev=False, help="M6: paste units for the Junos CLI")
    rend.add_argument("--method", choices=("cli", "cli-uninstall"), required=True)
    _target_args(rend, host_required=False)
    _bundle_args(rend)
    _plan_args(rend)
    _override_args(rend, OVERRIDE_FLAGS)
    rend.add_argument("--set-files", default=None, help="also write each stage's lines to jwicket-<stage>.set here")
    rend.add_argument("--upgrade", action="store_true", help="units for an upgrade (needs --host)")
    rend.add_argument("--remove-shared", action="store_true")

    boot = commands.add_parser(
        "bootstrap", allow_abbrev=False, help="the one-time bootstrap units (NETCONF, or the op script)"
    )
    boot.add_argument("--user", required=True)
    boot.add_argument("--method", choices=("netconf", "op", "op-url"), default="netconf")
    boot.add_argument("--op-sha256", default=None, help="op: the op script's SHA-256 from docs/releases on main")
    boot.add_argument("--bootstrap-minutes", type=int, default=10)
    boot.add_argument("--host", default=None, help="only to print the follow-up command")
    boot.add_argument("--json", action="store_true")

    fetch = commands.add_parser("fetch", allow_abbrev=False, help="download a pre-release and check its provenance")
    _bundle_args(fetch, local=False)
    fetch.add_argument("--out", required=True, help="the directory for jwicket.py and SHA256SUMS")
    fetch.add_argument("--json", action="store_true")

    opener = commands.add_parser(
        "open", allow_abbrev=False, help="how to reach J-Wicket: the URL and fingerprint, or the ssh -L line"
    )
    _target_args(opener)
    opener.add_argument("--daemon-port", type=int, default=None, help="J-Wicket's port (default: the install record's)")
    return parser


# ------------------------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------------------------


def _host(value: Optional[str]) -> str:
    if value is None or HOST_RE.match(value) is None:
        raise CliError("--host must be a plain host name or IPv4 address (no user@, no spaces)")
    return value


def _port(value: Optional[int], what: str) -> Optional[int]:
    if value is not None and not 1 <= value <= 65535:
        raise CliError(f"{what} {value} is outside 1..65535")
    return value


def credentials(args: argparse.Namespace) -> transport.Credentials:
    identity = getattr(args, "identity_file", None)
    if identity is not None:
        path = Path(identity).expanduser()
        if not path.is_file():
            raise CliError(f"--identity-file {identity} is not a file")
        identity = str(path)
    password: Optional[str] = None
    if getattr(args, "password_prompt", False):
        if not sys.stdin.isatty():
            raise CliError("--password-prompt needs a terminal; use an SSH agent or key instead")
        password = getpass.getpass(f"SSH password for {args.user}: ")
    return transport.Credentials(identity, password)


def target_of(args: argparse.Namespace) -> transport.Target:
    plan.validate_user(args.user)
    if args.user == "root":
        message, _ = plan.REFUSALS["R-ROOT"]
        raise Refused(f"R-ROOT: {message}")
    return transport.Target(
        host=_host(args.host),
        user=args.user,
        ssh_port=int(_port(args.ssh_port, "--port") or 22),
        netconf_port=_port(args.netconf_port, "--netconf-port"),
    )


def listen_address_of(args: argparse.Namespace) -> Optional[str]:
    """--listen-address, else --host when that is an IP address and the access mode is tls (R2); None
    for --access tunnel. --access tls without either is exit 2 before anything is contacted."""
    access = args.access or ("tunnel" if args.backend == "lab-token" else plan.DEFAULT_ACCESS)
    given: Optional[str] = args.listen_address
    if access != "tls":
        return given  # a listen address with tunnel is refused by plan.Options (exit 2)
    if given is None and getattr(args, "host", None):
        given = plan.default_listen_address(args.host)
    if given is None:
        raise CliError(plan.LISTEN_ADDRESS_REQUIRED)
    return given


def options_of(args: argparse.Namespace) -> plan.Options:
    return plan.Options(
        user=args.user,
        backend=args.backend,
        access=args.access or "",
        listen_address=listen_address_of(args),
        port=args.daemon_port,
        ssh_port=args.ssh_port,
        netconf_port=args.netconf_port,
        layout=Layout(args.layout),
        jet_checksum=not args.no_jet_checksum,
        confirm_minutes=args.confirm_minutes,
        bootstrap_minutes=args.bootstrap_minutes,
        transfer=args.transfer,
        pull_url=args.url,
        cert_file=args.cert_file,
        allow_plain_http=args.allow_plain_http,
        keep_diagnostics=not args.remove_diagnostics,
        remove_netconf_after=args.remove_netconf_after,
        keep_partial=bool(getattr(args, "keep_partial", False)),
    )


def overrides_of(args: argparse.Namespace, flags: Sequence[str] = OVERRIDE_FLAGS) -> FrozenSet[str]:
    chosen = set()
    for flag in flags:
        if getattr(args, flag[2:].replace("-", "_"), False):
            chosen.add(flag)
    if getattr(args, "no_jet_checksum", False):
        chosen.add("--no-jet-checksum")
    if getattr(args, "allow_plain_http", False):
        chosen.add("--allow-plain-http")
    return frozenset(chosen)


def _state_store() -> receipt.Store:
    store = receipt.Store(receipt.default_state_dir())
    try:
        store.ensure()
    except (receipt.StoreError, OSError) as exc:
        raise CliError(f"the installer's state directory cannot be used: {exc}") from exc
    return store


def _fetcher(args: argparse.Namespace) -> provenance.Fetcher:
    hosts = {provenance.RELEASE_HOST, *provenance.ASSET_HOSTS}
    for host in getattr(args, "asset_host", []):
        hosts.add(provenance.validate_host(host))
    import time

    return provenance.Fetcher(hosts=frozenset(hosts), sleep=time.sleep)


def obtain_bundle(args: argparse.Namespace, console: Console) -> Tuple[bytes, plan.BundleId, plan.Provenance, Path]:
    """P0 (spec 9.2): the bundle (downloaded per tag, or --bundle), its SHA256SUMS line, its header's
    version against the tag, and one provenance source independent of the release page."""
    tag = provenance.validate_tag(args.release) if args.release else None
    repo = provenance.validate_repo(args.repo)
    if args.bundle is None and tag is None:
        raise CliError("give --release <tag> (a published pre-release) or --bundle <jwicket.py>")
    work = Path(receipt.default_state_dir())
    fetcher = _fetcher(args)
    if args.bundle is not None:
        bundle_path = Path(args.bundle)
        data = provenance.read_local_bundle(bundle_path)
        identity = provenance.bundle_id(data, tag=tag)
    else:
        assert tag is not None  # noqa: S101 - checked above
        console.say(f"Downloading {provenance.release_url(repo, tag, provenance.BUNDLE_NAME)} and its SHA256SUMS.")
        download = provenance.fetch_release(fetcher, repo, tag)
        data, identity = download.data, download.identity
        store = _state_store()
        work = store.root
        bundle_path = work / f"bundle-{identity.file_sha256[:16]}.py"
        receipt.write_private(bundle_path, data)
    sources = provenance.Sources(
        repo=repo,
        tag=tag,
        expect_sha256=args.expect_sha256,
        expect_source=args.expect_source,
        checkout=Path(args.checkout) if args.checkout else None,
        reproduce=args.reproduce,
        use_gh=not args.no_gh,
        trust_release_page_only=args.trust_release_page_only,
    )
    prov, attempts = provenance.establish(data, identity, bundle_path, sources, fetcher=fetcher)
    for attempt in attempts:
        console.say(f"Provenance {attempt.source}: {attempt.outcome} ({attempt.detail})")
    console.say(f"Bundle {identity.version}, SHA-256 {identity.file_sha256}, payload {identity.payload_sha256}.")
    if args.local_self_test:
        if not prov.evidence:
            raise provenance.ProvenanceError(
                "--local-self-test runs only after an independent provenance source passed"
            )
        ok, message = provenance.local_self_test(data)
        console.say(message)
        if not ok:
            raise provenance.ProvenanceError(message)
    return data, identity, prov, bundle_path


# Options of 'install' that the printed follow-up leaves out: the dry run's own (it runs with --apply and
# the nonce), the output form, and the M2 play's stdin gate.
_FOLLOW_UP_SKIP = frozenset({"apply", "bootstrap_nonce", "json", "gate_from_stdin", "device_diff", "help"})


# render.render_bootstrap_units shows each unit E line through plan.sanitize_display(line, 400), which cuts a
# longer line and drops control characters, and the executor replaces '<NONCE>' in each line with the nonce.
_FOLLOW_UP_LIMIT = 400
_NONCE_MARK = "<NONCE>"


def _no_follow_up(reason: str) -> str:
    """Unit E's line when no command can be printed whole: a shell comment (harmless if pasted) saying why."""
    return (
        f"# No command here: {reason}, so a copy would not be the command this dry run reviewed. Type "
        f"'jwicket-install install --apply' yourself with this dry run's options and --bootstrap-nonce "
        f"{_NONCE_MARK}."
    )


def _follow_up(args: argparse.Namespace) -> Tuple[str, ...]:
    """The command unit E of the NETCONF bootstrap prints (OPX-03): this run's own command line rebuilt from
    the parsed options, every option that differs from its default echoed (the repository, identity file,
    ports, layout, minutes, transfer, NETCONF removal, provenance options and overrides among them), so the
    run that follows the bootstrap installs what the dry run reviewed. Each word is shell-quoted.

    Never a cut or altered value inside the command. A command longer than a unit shows on one line is
    printed one option to a line, each line but the last ending in ' \\' (a POSIX shell continuation), so
    the unit still pastes as one command. When a value holds characters a unit cannot show (control
    characters, a tab or a line break, which sanitize_display drops or replaces) or the nonce placeholder,
    or one option alone is longer than a unit shows, the unit gets no command, only a shell comment that
    names the option and says to type the command."""
    chunks: List[Tuple[str, List[str]]] = [("", ["jwicket-install", "install", "--apply"])]  # (option, words)
    install = _subparser(build_parser(), "install")
    for action in install._actions:  # argparse exposes no public list of a parser's actions
        dest = action.dest
        if not action.option_strings or dest in _FOLLOW_UP_SKIP:
            continue
        value = getattr(args, dest, action.default)
        if value is None or value == action.default:
            continue
        flag = action.option_strings[0]
        if action.nargs == 0:
            # A flag (store_true, or the NETCONF pair --remove-netconf-after / --keep-netconf, which share one
            # dest): echoed when the parsed value is the one this flag stores.
            if action.const == value:
                chunks.append((flag, [flag]))
        elif isinstance(value, list):
            chunks += [(flag, [flag, str(item)]) for item in value]
        else:
            chunks.append((flag, [flag, str(value)]))
    for flag, words in chunks:
        for word in words:
            if plan.sanitize_display(word, len(word) + 1) != word:
                return (_no_follow_up(f"the value of {flag} holds characters a unit cannot show"),)
            if _NONCE_MARK in word:
                return (_no_follow_up(f"the value of {flag} holds the nonce placeholder, which the unit replaces"),)
    # The nonce placeholder stays unquoted: the executor puts the bootstrap's nonce (6 letters or digits) there.
    quoted = [(flag, " ".join(shlex.quote(word) for word in words)) for flag, words in chunks]
    quoted.append(("--bootstrap-nonce", f"--bootstrap-nonce {_NONCE_MARK}"))
    line = " ".join(text for _, text in quoted)
    if len(line) <= _FOLLOW_UP_LIMIT:
        return (line,)
    last = len(quoted) - 1
    lines = [("  " if i else "") + text + (" \\" if i < last else "") for i, (_, text) in enumerate(quoted)]
    for (flag, _), shown in zip(quoted, lines):
        if len(shown) > _FOLLOW_UP_LIMIT:
            reason = f"the value of {flag} is longer than the {_FOLLOW_UP_LIMIT} characters a unit line shows"
            return (_no_follow_up(reason),)
    return tuple(lines)


def _subparser(parser: argparse.ArgumentParser, name: str) -> argparse.ArgumentParser:
    for action in parser._actions:  # as above
        if isinstance(action, argparse._SubParsersAction):
            found = action.choices.get(name)
            if isinstance(found, argparse.ArgumentParser):
                return found
    raise plan.InvariantError(f"the parser has no {name!r} command")


def _token_doc(value: Any, where: str = "result") -> Any:
    """Every string in a --json result matches the plan JSON's token set (INV-12)."""
    if isinstance(value, str):
        if render.JSON_TOKEN_RE.match(value) is None:
            raise plan.InvariantError(f"result field {where} holds characters outside the token set")
        return value
    if isinstance(value, dict):
        return {_token_doc(k, where): _token_doc(v, f"{where}.{k}") for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_token_doc(v, f"{where}[]") for v in value]
    return value


def _emit(console: Console, document: Dict[str, Any]) -> None:
    console.result(json.dumps(_token_doc(document), indent=2, sort_keys=True))


ExecutorFactory = Callable[[transport.Target, Console, RunOptions], Executor]


def _real_executor(
    target: transport.Target,
    console: Console,
    run: RunOptions,
    args: argparse.Namespace,
    creds: Optional[transport.Credentials] = None,
) -> Executor:
    if creds is None:
        creds = credentials(args)
    clock = transport.SystemClock()
    return Executor(target, transport.RealConnector(target, creds, clock), console, clock, _state_store(), run)


_FACTORY: Optional[ExecutorFactory] = None  # tests inject a fake device here through main(executor_factory=...)


def _executor(
    args: argparse.Namespace, console: Console, run: RunOptions, creds: Optional[transport.Credentials] = None
) -> Executor:
    target = target_of(args)
    if _FACTORY is not None:
        return _FACTORY(target, console, run)
    return _real_executor(target, console, run, args, creds)


# ------------------------------------------------------------------------------------------------
# Commands
# ------------------------------------------------------------------------------------------------


def _gate_source(args: argparse.Namespace) -> None:
    """Spec 6.3 and 8.2: --gate-from-stdin exists only for M2's play, which passes --method ansible; any
    other caller types the host name at a terminal (no terminal: exit 3)."""
    if getattr(args, "gate_from_stdin", False) and getattr(args, "method", None) != "ansible":
        raise CliError("--gate-from-stdin is for the Ansible play only (with --method ansible); type the host name")


def _guide_answer(console: Console, prompt: str) -> str:
    answer = console.prompt(prompt)
    if answer is None:
        raise Refused("guide stopped; no install was applied")
    return answer.strip()


def _guide_account(console: Console, host: str, port: int) -> str:
    user = _guide_answer(console, "SRX non-root super-user account (Enter to set up jwicket): ")
    if user:
        plan.validate_user(user)
        if user.lower() == "root":
            raise Refused("R-ROOT: use a named non-root Junos super-user, not root")
        return user
    console.say(
        "Use a trusted console or an existing administrator session for this one-time setup. "
        "The installer will not log in as root or handle an administrator password.\n"
        "This account is dedicated to J-Wicket, but Junos super-user has full device permissions. "
        "Use it only on an authorized lab device.\n"
        f"On the verified lab SRX {host}:\n"
        "  show configuration system login user jwicket | display inheritance\n"
        "If the account already exists, stop rather than overwrite it. Restart the guide and enter jwicket.\n"
        "  show system commit | no-more\n"
        "If there is a pending commit, stop. Otherwise, enter these at the Junos CLI:\n"
        "  configure exclusive\n"
        "  show | compare\n"
        "Continue only if the candidate is empty:\n"
        "  set system login user jwicket class super-user\n"
        "  set system login user jwicket authentication plain-text-password\n"
        "Type a strong new password at the device's prompt, not here. Check 'show | compare' contains only "
        "this new account before running:\n"
        '  commit confirmed 5 comment "Create dedicated J-Wicket lab installer account"\n'
        f"In a separate terminal, verify the device's SSH host key and test: ssh -p {port} jwicket@{host}\n"
        "Run 'show cli authorization' and verify the super-user class. If it matches, confirm with 'commit' "
        "in the original session; otherwise let the trial commit roll back."
    )
    if _guide_answer(console, "Type ready after creating and verifying jwicket (anything else stops): ") != "ready":
        raise Refused("guide stopped before the install preview")
    return "jwicket"


def cmd_guide(args: argparse.Namespace, console: Console) -> int:
    if not console.interactive:
        console.say("The guide needs a terminal. For automation, use jwicket-install install with explicit options.")
        return plan.EXIT_GATE
    console.say("Guided lab install. No root login, automatic trust, or management overrides.")
    address = _guide_answer(console, "SRX management IPv4 address: ")
    try:
        ip = IPv4Address(address)
    except ValueError:
        raise CliError("enter an IPv4 address reachable on your private management network") from None
    if ip.is_unspecified or ip.is_multicast or ip.is_loopback or ip.is_reserved:
        raise CliError("enter the SRX's usable private management IPv4 address")
    host = str(ip)
    port = _port(args.port, "--port") or 22
    netconf_port = _port(args.netconf_port, "--netconf-port")
    user = _guide_account(console, host, port)
    console.say(
        f"Verify the device's SSH host-key fingerprint using the lab console or provider. Record it by signing "
        f"in with ssh -p {port} {user}@{host}. The device's host key is not a personal login key. "
        "Use 'show cli authorization' to check the account is a Junos super-user.\n"
        "At the Junos > prompt, use 'start shell user root' or open a root shell through your lab's console. "
        "Check 'id -u' returns 0, then check /var/db/jwicket. If absent on a fresh target, run:\n"
        f"  mkdir -m 700 /var/db/jwicket && chown {shlex.quote(user)} /var/db/jwicket\n"
        f"If already present, keep it only if it is a real directory (not a symlink), mode 0700, owned by {user}, "
        "and not part of an existing deployment. Do not change ownership under an existing install."
    )
    if _guide_answer(console, "Type ready when host identity and the state directory are ready: ") != "ready":
        raise Refused("guide stopped before the install preview")
    auth = _guide_answer(console, "Sign in with [p]assword, [k]ey file, or [a]gent (Enter = password): ").lower()
    words = [
        "install",
        "--host", host,
        "--user", user,
        "--port", str(port),
        "--release", args.release,
        "--access", "tls",
        "--listen-address", host,
    ]
    if netconf_port is not None:
        words.extend(("--netconf-port", str(netconf_port)))
    if args.lab_hardware:
        words.append(plan.LAB_HARDWARE_FLAG)
    if auth in ("", "p"):
        words.append("--password-prompt")
    elif auth == "k":
        key = _guide_answer(console, "SSH private key file: ")
        if not key:
            raise CliError("a key file path is required with key-file sign-in")
        words.append(f"--identity-file={key}")
    elif auth != "a":
        raise CliError("choose password (p), key file (k), or agent (a)")

    install = build_parser().parse_args(words)
    options = options_of(install)
    target_of(install)
    # Keep the non-root credential only in memory and only for this invocation. The test factory
    # supplies its own transport; production uses the same getpass/identity-file path as install.
    console.say(
        "Before any apply, including after a NETCONF bootstrap, verify management ingress allows TCP 9443 "
        "only from designated jump hosts or operator prefixes. If you cannot enforce and test it, do not apply."
    )
    creds = credentials(install) if _FACTORY is None else None
    data, identity, prov, bundle_path = obtain_bundle(install, console)
    try:
        console.say("Preview: read-only device checks and plan. No install writes.")
        code = _install(install, console, options, data, identity, prov, creds)
        if code != plan.EXIT_OK:
            console.say(
                "The guide did not apply anything. Resolve the reported refusal without weakening checks. "
                "If NETCONF is disabled and bootstrap instructions were printed, follow those exact units "
                "and inspect the generated apply command before running it. Do not manually confirm its timed commit."
            )
            return code
        if _guide_answer(console, "Type apply if the preview and source filter are correct (Enter stops): ") != "apply":
            console.say("Preview only. No install was applied.")
            return plan.EXIT_OK
        install.apply = True
        code = _install(install, console, options, data, identity, prov, creds)
        if code == plan.EXIT_OK:
            console.say(
                "Verify TCP 9443 from an allowed and a denied source. From the allowed source, compare the displayed "
                "TLS fingerprint before signing in. Use a restricted operator to check one allowed read, "
                "one denied read, and sign-out."
            )
        return code
    finally:
        _drop_download(install, bundle_path)


def cmd_install(args: argparse.Namespace, console: Console) -> int:
    _gate_source(args)
    options = options_of(args)
    target_of(args)
    if args.bootstrap_nonce is not None and plan.NONCE_RE.match(args.bootstrap_nonce) is None:
        raise CliError("--bootstrap-nonce is the 6 lowercase letters or digits in your bootstrap's comment")
    data, identity, prov, bundle_path = obtain_bundle(args, console)
    try:
        return _install(args, console, options, data, identity, prov)
    finally:
        _drop_download(args, bundle_path)


def _drop_download(args: argparse.Namespace, path: Path) -> None:
    """The per-tag download kept in the state directory for 'gh release verify-asset' is not kept."""
    if args.bundle is None and path.name.startswith("bundle-"):
        try:
            path.unlink()
        except OSError:
            LOG.debug("the downloaded bundle copy was not removed")


def _install(
    args: argparse.Namespace,
    console: Console,
    options: plan.Options,
    data: bytes,
    identity: plan.BundleId,
    prov: plan.Provenance,
    creds: Optional[transport.Credentials] = None,
) -> int:
    if (args.apply or args.device_diff) and prov.kind == "none":
        message, override = plan.REFUSALS["R-PROVENANCE"]
        console.say(f"R-PROVENANCE: {message} (override: {override}). Exit 7: nothing was contacted or written.")
        return plan.EXIT_INTEGRITY
    run = RunOptions(
        apply=args.apply,
        gate_from_stdin=args.gate_from_stdin,
        accept_new_host_key=args.accept_new_host_key,
        device_diff=args.device_diff,
        rollback_now=args.rollback_now,
        remove_shared=args.remove_shared,
        bootstrap_nonce=args.bootstrap_nonce,
        follow_up=_follow_up(args),
        known_hosts=tuple(Path(p) for p in args.known_hosts),
    )
    executor = _executor(args, console, run, creds)
    code = executor.install(identity, data, prov, options, method=METHODS[args.method], overrides=overrides_of(args))
    if args.json:
        plan_text = executor.json_doc.get("plan")
        if not args.apply and plan_text is not None:
            console.result(str(plan_text))
            return code
        document: Dict[str, Any] = {
            "schema": plan.PLAN_SCHEMA,
            "command": "install",
            "exit": code,
            "outcome": executor.json_doc.get("outcome", "ok" if code == 0 else f"exit-{code}"),
            "confirmed_stages": list(executor.confirmed),
            "host_key_sha256": list(executor.link.fingerprints) if executor.link else [],
            "receipt": executor.json_doc.get("receipt", "not written"),
            "access": options.access,
            "listen_address": options.listen_address,
            "port": options.port,
            # The certificate this run made and verified on the device: its fingerprint only, never the key.
            "tls_cert_sha256": executor.tls_cert_sha256,
            "lab_hardware_attested": executor.lab_attested,
        }
        if "bootstrap" in executor.json_doc:
            document["bootstrap"] = executor.json_doc["bootstrap"]
        if plan_text is not None:
            document["plan"] = json.loads(str(plan_text))
        if "healthy" in executor.json_doc:
            document["healthy"] = executor.json_doc["healthy"]
        _emit(console, document)
    return code


def _evidence_base(args: argparse.Namespace) -> Path:
    """--evidence-dir, else the state directory when the environment names one (the container's /state:
    its working directory is not writable by the caller's uid), else the current directory."""
    if args.evidence_dir is not None:
        return Path(args.evidence_dir)
    if os.environ.get(receipt.STATE_ENV):
        return receipt.default_state_dir()
    return Path()


def cmd_uninstall(args: argparse.Namespace, console: Console) -> int:
    _gate_source(args)
    target_of(args)
    run = RunOptions(
        apply=args.apply,
        gate_from_stdin=args.gate_from_stdin,
        accept_new_host_key=args.accept_new_host_key,
        remove_shared=args.remove_shared,
        no_evidence=args.no_evidence,
        evidence_base=_evidence_base(args),
        known_hosts=tuple(Path(p) for p in args.known_hosts),
    )
    executor = _executor(args, console, run)
    code = executor.uninstall(method=METHODS[args.method], overrides=overrides_of(args, UNINSTALL_OVERRIDES))
    if args.json:
        _emit(
            console,
            {
                "schema": plan.PLAN_SCHEMA,
                "command": "uninstall",
                "exit": code,
                **{k: v for k, v in executor.json_doc.items() if k in ("uninstall",)},
            },
        )
    return code


def cmd_status(args: argparse.Namespace, console: Console) -> int:
    target_of(args)
    port = _port(args.daemon_port, "--daemon-port")
    run = RunOptions(accept_new_host_key=args.accept_new_host_key, known_hosts=tuple(Path(p) for p in args.known_hosts))
    executor = _executor(args, console, run)
    code = executor.status(port=port)
    if args.json:
        _emit(
            console,
            {
                "schema": plan.PLAN_SCHEMA,
                "command": "status",
                "exit": code,
                **{
                    k: v for k, v in executor.json_doc.items() if k in ("healthy", "process", "stanzas", "access", "c8")
                },
            },
        )
    return code


def cmd_render(args: argparse.Namespace, console: Console) -> int:
    if args.user == "root":
        raise Refused("R-ROOT: " + plan.REFUSALS["R-ROOT"][0])
    # OPX-13: the missing --host is named first; the listen address is only asked once the units can exist.
    if (args.upgrade or args.method == "cli-uninstall") and args.host is None:
        raise CliError(
            f"render {'--upgrade' if args.upgrade else '--method cli-uninstall'} needs --host: the units "
            "depend on what the device has"
        )
    # The removal units need no listener: no --listen-address is asked for them.
    options = options_of(args) if args.method == "cli" else plan.Options(user=args.user, access="tunnel")
    overrides = overrides_of(args)
    identity: Optional[plan.BundleId] = None
    prov: Optional[plan.Provenance] = None
    if args.method == "cli":
        _, identity, prov, _ = obtain_bundle(args, console)
    if args.host is not None:
        run = RunOptions(
            accept_new_host_key=args.accept_new_host_key,
            remove_shared=args.remove_shared,
            known_hosts=tuple(Path(p) for p in args.known_hosts),
        )
        executor = _executor(args, console, run)
        code, units, built = executor.render_units(
            identity,
            prov,
            options,
            overrides=overrides,
            uninstall=args.method == "cli-uninstall",
            set_files=bool(args.set_files),
        )
        if code:
            return code
        if args.upgrade and built is not None and not built.upgrade:
            console.say("Note: no earlier J-Wicket build is installed there, so these are install units.")
    else:
        assert identity is not None and prov is not None  # noqa: S101 - the cli method always has both
        built = plan.build_install_plan(
            identity,
            prov,
            options,
            plan.DeviceFacts.unknown(),
            plan.PriorState.fresh(),
            method=Method.CLI,
            overrides=overrides,
            offline=True,
        )
        if built.blocked:
            for refusal in built.refusals:
                console.say(f"{refusal.code}: {refusal.message}")
            return plan.EXIT_REFUSED
        units = render.render_cli_units(built, prior=plan.PriorState.fresh(), set_files=bool(args.set_files))
    console.say(render.units_to_text(units))
    if args.set_files and built is not None:
        directory = Path(args.set_files)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        for stage in built.stages:
            if stage.already_committed:
                continue
            path = directory / render.set_file_name(stage)
            receipt.write_private(path, render.render_set_file(stage, built.layout).encode("utf-8"))
            console.say(f"wrote {path}")
    return plan.EXIT_OK


def cmd_bootstrap(args: argparse.Namespace, console: Console) -> int:
    user = plan.validate_user(args.user)
    method = {"netconf": Method.WORKSTATION, "op": Method.ONBOX_LOCAL, "op-url": Method.ONBOX_URL}[args.method]
    if args.method == "op" and args.op_sha256 is None:
        raise CliError("bootstrap --method op needs --op-sha256 (the value for this tag in docs/releases on main)")
    nonce = workstation._nonce() if args.method == "netconf" else None
    options = plan.Options(user=user, bootstrap_minutes=args.bootstrap_minutes)
    boot = plan.build_bootstrap(method, options, None, nonce, op_sha256=args.op_sha256)
    if boot is None:  # pragma: no cover - without a prior state every bootstrap adds a statement
        return plan.EXIT_OK
    follow: List[str] = []
    if args.method == "netconf":
        host = _host(args.host) if args.host else "<device>"
        follow.append(
            f"jwicket-install install --apply --host {host} --user {user} --release <tag> --bootstrap-nonce {nonce}"
        )
    console.say(render.units_to_text(render.render_bootstrap_units(boot, follow_up=follow)))
    if args.json:
        _emit(
            console,
            {
                "schema": plan.PLAN_SCHEMA,
                "command": "bootstrap",
                "kind": boot.kind,
                "nonce": nonce,
                "minutes": boot.minutes,
                "keys": list(boot.keys),
                "comment": boot.comment,
            },
        )
    return plan.EXIT_OK


def cmd_fetch(args: argparse.Namespace, console: Console) -> int:
    if args.release is None:
        raise CliError("fetch needs --release <tag>")
    data, identity, prov, path = obtain_bundle(args, console)
    if prov.kind == "none":
        message, override = plan.REFUSALS["R-PROVENANCE"]
        console.say(f"R-PROVENANCE: {message} (override: {override}).")
        return plan.EXIT_INTEGRITY
    out = Path(args.out)
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = out / provenance.BUNDLE_NAME
    receipt.write_private(target, data)
    receipt.write_private(out / provenance.SUMS_NAME, f"{identity.file_sha256}  {provenance.BUNDLE_NAME}\n".encode())
    console.say(
        f"wrote {target} (SHA-256 {identity.file_sha256}, provenance {prov.kind}"
        + ("" if prov.evidence else f", {plan.NOT_EVIDENCE}")
        + ")"
    )
    _drop_download(args, path)
    if args.json:
        _emit(
            console,
            {
                "schema": plan.PLAN_SCHEMA,
                "command": "fetch",
                "exit": 0,
                "file_sha256": identity.file_sha256,
                "version": identity.version,
                "provenance": prov.kind,
                "evidence": prov.evidence,
            },
        )
    return plan.EXIT_OK


def cmd_open(args: argparse.Namespace, console: Console) -> int:
    """How to reach J-Wicket on this device (R3: nothing is forwarded): the device's host key verified,
    this workstation's install record found by it, and what it names (tunnel.reach_lines)."""
    target_of(args)
    port = _port(args.daemon_port, "--daemon-port")
    if port is not None and port < 1024:
        raise CliError("--daemon-port must be 1024..65535")
    run = RunOptions(accept_new_host_key=args.accept_new_host_key, known_hosts=tuple(Path(p) for p in args.known_hosts))
    return _executor(args, console, run).reach(port=port)


COMMANDS = {
    "guide": cmd_guide,
    "install": cmd_install,
    "uninstall": cmd_uninstall,
    "status": cmd_status,
    "render": cmd_render,
    "bootstrap": cmd_bootstrap,
    "fetch": cmd_fetch,
    "open": cmd_open,
}


def setup_logging(verbose: int) -> None:
    level = logging.WARNING if verbose == 0 else logging.INFO if verbose == 1 else logging.DEBUG
    logging.basicConfig(stream=sys.stderr, level=level, format="jwicket-install: %(levelname)s: %(name)s: %(message)s")
    for name in QUIET_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)  # they can log replies and key material (INV-08)


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    executor_factory: Optional[ExecutorFactory] = None,
    console: Optional[Console] = None,
) -> int:
    """The console script. ``executor_factory`` and ``console`` exist for the tests' fake devices only."""
    global _FACTORY  # one injection point for the tests, reset in finally
    parser = build_parser()
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    setup_logging(args.verbose)
    if console is None:
        console = Console(json_mode=bool(getattr(args, "json", False)))
    else:
        console.json_mode = bool(getattr(args, "json", False))
    _FACTORY = executor_factory
    if args.command != "bootstrap":  # the bootstrap units open with it themselves
        console.say(plan.DEVICE_STATUS)  # UI-006-04: every run starts with it (standard error with --json)
        console.status_shown = True
    try:
        return COMMANDS[args.command](args, console)
    except (CliError, plan.InputError) as exc:
        console.say(f"jwicket-install: {exc}")
        return plan.EXIT_INPUT
    except Refused as exc:
        console.say(f"jwicket-install: {exc}")
        return plan.EXIT_REFUSED
    except provenance.ProvenanceError as exc:
        console.say(f"jwicket-install: {exc}. Exit 7: nothing was written to the device.")
        return plan.EXIT_INTEGRITY
    except plan.PlanBlocked as exc:
        console.say(f"jwicket-install: {exc}")
        return plan.EXIT_REFUSED
    except transport.ToolMissing as exc:
        console.say(f"jwicket-install: {exc}")
        return plan.EXIT_REFUSED
    except transport.TransportError as exc:  # after ToolMissing, its subclass; spec 9.7 exit 4
        console.say(
            f"jwicket-install: the device stopped answering or refused a step: {exc}. A pending 'commit confirmed' "
            "of this run, if any, rolls back at its deadline."
        )
        return plan.EXIT_DEVICE_REFUSED
    except hostkeys.HostKeyError as exc:
        console.say(f"jwicket-install: {exc}")
        return plan.EXIT_REFUSED
    except receipt.StoreError as exc:
        console.say(f"jwicket-install: {exc}")
        return plan.EXIT_INPUT
    except KeyboardInterrupt:
        console.say("jwicket-install: interrupted. A pending 'commit confirmed' rolls back at its deadline.")
        return plan.EXIT_REFUSED
    finally:
        _FACTORY = None


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["build_parser", "main"]
