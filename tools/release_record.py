#!/usr/bin/env python3
"""Release notes and the release record for J-Wicket lab pre-releases (Spec 006 sections 11.3 to 11.6).

Three subcommands, standard library only, never run on a device:

``notes``
    In the release workflow's ``build`` job: render ``dist/RELEASE-NOTES.md`` from
    ``.github/release-notes-lab-only.md``. Every value is checked before it is written: the files are
    hashed again and compared with ``SHA256SUMS``, the bundle header must name the tag's version and
    the source commit, and the template must carry the installer's texts verbatim (``PLAN_CONSTANTS``,
    read from ``jwicket_install.plan``: the device status, the posture warning, both access modes'
    warnings and root's one-time step for the state directory) and its M4 bootstrap lines, so the
    notes cannot drift from what the installer prints.

``record``
    After publication, by the owner (``make release-record TAG=<tag> REPO=<owner>/<repo>``):
    download the per-tag assets with ``gh``, check them against ``SHA256SUMS``, verify them with
    ``gh release verify`` and ``gh release verify-asset`` (the immutable release's attestation), or,
    in a private repository without attestations, check the owner's SSH signature of
    ``SHA256SUMS`` (``ssh-keygen -Y verify``), and write ``docs/releases/<tag>.sha256sums``: the
    verified ``SHA256SUMS``, byte for byte, so ``sha256sum -c`` reads it. A reviewed pull request puts
    it on ``main``, where provenance source P-C and the on-box installer's operators read it.

``fetch``
    For ``make container-context``: the same download and verification (or a comparison with the
    record on ``main``), then the installer wheel and ``requirements-install.txt`` are copied into
    an empty directory with a ``SHA256SUMS`` of those two files.

Only network reads happen here (``gh release download``, ``gh release verify``), each with a
timeout and retried with back-off; nothing is uploaded. Credentials stay with ``gh`` (its own login
or ``GH_TOKEN``); this tool never sees a token. Python 3.7 or later. Exit status: 0 done, 1 a check
failed or a tool it needs (gh, git, ssh-keygen) is not on PATH, 2 bad arguments.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

import release_check

LOG = logging.getLogger("jwicket.release_record")

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TEMPLATE = REPO_ROOT / ".github" / "release-notes-lab-only.md"
DEFAULT_RECORD_DIR = REPO_ROOT / "docs" / "releases"
DEFAULT_ALLOWED_SIGNERS = DEFAULT_RECORD_DIR / "allowed_signers"
SUMS_FILE = "SHA256SUMS"
SIGNATURE_FILE = "SHA256SUMS.sig"
BUNDLE_FILE = "jwicket.py"
OP_FILE = "jwicket-install-op.py"
REQUIREMENTS_FILE = "requirements-install.txt"
# The texts of jwicket_install.plan the template must carry verbatim (AC-006-10): the device status, the
# posture warning of 'language python3', the warning of each access mode (Spec 006 revision R2: tls, the
# default, opens an HTTPS listener on the management address; tunnel's SSH forwarding was refused on the
# lab SRX4100) and root's one-time step for /var/db/jwicket (revision R4: a super-user-class account
# cannot create it, verified on that SRX4100).
PLAN_CONSTANTS = (
    "DEVICE_STATUS",
    "POSTURE_WARNING",
    "TLS_POSTURE_WARNING",
    "TUNNEL_WARNING",
    "STATE_DIR_ROOT_STEP",
)

GH_TIMEOUT_S = 120
SSH_KEYGEN_TIMEOUT_S = 30
GIT_TIMEOUT_S = 30
READ_ATTEMPTS = 3
BACKOFF_S = 2.0
MAX_ASSET_BYTES = 16 * 1024 * 1024
HEADER_BYTES = 4096

REPO_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}\Z", re.ASCII)
HEX64 = re.compile(r"^[0-9a-f]{64}\Z", re.ASCII)
SUMS_LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,127})\Z", re.ASCII)
PLACEHOLDER = re.compile(r"@@([A-Z0-9_]+)@@")
# ssh-keygen -Y principals and namespaces: plain tokens only, as the owner writes them.
SIGNER_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._+-]{0,127}\Z", re.ASCII)

_HEADER_VERSION = re.compile(r"^jwicket version: (\S+)$", re.MULTILINE)
_HEADER_SOURCE = re.compile(r"^source ref:      (\S.*)$", re.MULTILINE)
_HEADER_PAYLOAD = re.compile(r"^payload sha256:  ([0-9a-f]{64})$", re.MULTILINE)


class RecordError(Exception):
    """A release check failed. The message says what and why."""


Runner = Callable[[Sequence[str], int, Optional[bytes]], "subprocess.CompletedProcess[bytes]"]


@dataclass(frozen=True)
class Assets:
    directory: Path
    version: str
    sums_text: str
    sums: Mapping[str, str]


# --- small helpers -------------------------------------------------------------------------------


def expected_assets(version: str) -> Tuple[str, ...]:
    """The four files ``SHA256SUMS`` lists, in the order the workflow writes them."""
    return (BUNDLE_FILE, OP_FILE, f"jwicket_install-{version}-py3-none-any.whl", REQUIREMENTS_FILE)


def wheel_file(version: str) -> str:
    return expected_assets(version)[2]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_tag(tag: str) -> str:
    if not release_check.TAG_PATTERN.match(tag):
        raise RecordError(f"tag {tag[:80]!r} does not match {release_check.TAG_PATTERN.pattern}")
    return tag[1:]


def validate_repo(repo: str) -> None:
    if not REPO_PATTERN.match(repo):
        raise RecordError(f"repository {repo[:120]!r} is not in owner/name form")


def parse_sums(text: str, version: str) -> Dict[str, str]:
    """Parse ``SHA256SUMS`` strictly: two-space ``sha256sum`` lines, exactly the expected files."""
    sums: Dict[str, str] = {}
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    for number, line in enumerate(lines, 1):
        match = SUMS_LINE.match(line)
        if not match:
            raise RecordError(f"{SUMS_FILE} line {number} is not '<64 hex>  <file name>'")
        digest, name = match.groups()
        if name in sums:
            raise RecordError(f"{SUMS_FILE} lists {name} twice")
        sums[name] = digest
    expected = set(expected_assets(version))
    if set(sums) != expected:
        missing = sorted(expected - set(sums))
        extra = sorted(set(sums) - expected)
        raise RecordError(f"{SUMS_FILE} must list exactly {sorted(expected)}; missing {missing}, unexpected {extra}")
    return sums


def check_files(directory: Path, sums: Mapping[str, str]) -> None:
    for name, digest in sorted(sums.items()):
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise RecordError(f"{name} is missing or not a regular file in {directory}")
        if path.stat().st_size > MAX_ASSET_BYTES:
            raise RecordError(f"{name} is larger than {MAX_ASSET_BYTES} bytes")
        actual = sha256_file(path)
        if actual != digest:
            raise RecordError(f"{name}: SHA-256 is {actual}, {SUMS_FILE} says {digest}")


def load_assets(directory: Path, version: str) -> Assets:
    sums_path = directory / SUMS_FILE
    try:
        raw = sums_path.read_bytes()
    except OSError as exc:
        raise RecordError(f"cannot read {sums_path}: {exc}") from exc
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise RecordError(f"{sums_path} is not ASCII") from exc
    sums = parse_sums(text, version)
    check_files(directory, sums)
    return Assets(directory, version, text, sums)


def bundle_header(path: Path) -> Tuple[str, str, str]:
    """``(version, source ref, payload sha256)`` from the bundle's generated docstring."""
    try:
        with path.open("rb") as handle:
            head = handle.read(HEADER_BYTES).decode("ascii", errors="replace")
    except OSError as exc:
        raise RecordError(f"cannot read {path}: {exc}") from exc
    version = _HEADER_VERSION.search(head)
    source = _HEADER_SOURCE.search(head)
    payload = _HEADER_PAYLOAD.search(head)
    if not (version and source and payload):
        raise RecordError(f"{path} has no bundle header with version, source ref and payload sha256")
    return version.group(1), source.group(1).strip(), payload.group(1)


def write_text_file(path: Path, data: bytes) -> None:
    """Write in one step, mode 0644: release notes and records are public, so world-readable on purpose."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp_path = Path(tmp)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        tmp_path.chmod(0o644)
        tmp_path.replace(path)
    except BaseException:
        # Not unlink(missing_ok=True): that is Python 3.8+, and the release tools run on 3.7.
        with contextlib.suppress(FileNotFoundError):
            tmp_path.unlink()
        raise


# --- release notes -------------------------------------------------------------------------------


def load_plan() -> Any:
    """The installer's plan module (tools/ is on sys.path when this file runs as a script)."""
    try:
        # Imported by name so this tool loads (and type-checks) without the installer package.
        return importlib.import_module("jwicket_install.plan")
    except ImportError as exc:
        raise RecordError(f"cannot import jwicket_install.plan for the warning texts and units: {exc}") from exc


def plan_constants(plan: Any = None) -> Mapping[str, str]:
    """Each of ``PLAN_CONSTANTS`` from the installer's plan module."""
    plan = load_plan() if plan is None else plan
    values: Dict[str, str] = {}
    for name in PLAN_CONSTANTS:
        value = getattr(plan, name, None)
        if not isinstance(value, str) or not value:
            raise RecordError(f"jwicket_install.plan.{name} is missing or not a string")
        values[name] = value
    return values


def check_template_constants(template: str, constants: Mapping[str, str]) -> None:
    """Each constant must appear verbatim, on one line, in the template (AC-006-10)."""
    for name, value in sorted(constants.items()):
        if value not in template:
            raise RecordError(
                f"the release-notes template does not carry jwicket_install.plan.{name} verbatim; "
                "copy the constant's exact text into .github/release-notes-lab-only.md"
            )


def m4_unit_lines(plan: Any, *, op_sha256: str, tag: str, repo: str) -> List[str]:
    """The Junos lines of the M4 units, as the installer's own plan renders them (P1: one plan).

    The template carries the units so that an operator needs no workstation to read them; this list
    is what each rendered line must equal, so the notes cannot drift from ``plan.py``. The device
    is unknown here, so the language statement is included (the notes say to leave it out when set).
    """
    try:
        bootstrap = plan.build_bootstrap(
            plan.Method.ONBOX_LOCAL, plan.Options(user="lab"), None, None, op_sha256=op_sha256
        )
        url = f"https://github.com/{repo}/releases/download/{tag}/{plan.OP_FILE}"
        lines = [statement.set_line(plan.Layout.DIRECT) for statement in bootstrap.add]
        lines.append(plan.cli_commit_confirmed(bootstrap.minutes, bootstrap.comment))
        lines.append(plan.cli_file_copy(url, plan.OP_PATH))
        lines.append(plan.cli_file_checksum(plan.OP_PATH))
    except (AttributeError, TypeError, ValueError) as exc:
        raise RecordError(f"cannot render the M4 bootstrap with jwicket_install.plan: {exc}") from exc
    return [str(line) for line in lines]


def check_m4_units(rendered: str, expected: Sequence[str]) -> None:
    present = set(rendered.splitlines())
    missing = [line for line in expected if line not in present]
    if missing:
        raise RecordError(
            "the release notes' M4 units differ from jwicket_install.plan; update "
            f".github/release-notes-lab-only.md so these lines appear exactly: {missing}"
        )


def render_template(template: str, values: Mapping[str, str]) -> str:
    """Replace ``@@NAME@@`` placeholders. Unknown or unused placeholders and leftovers are errors."""
    used = set(PLACEHOLDER.findall(template))
    unknown = sorted(used - set(values))
    if unknown:
        raise RecordError(f"the template uses unknown placeholders: {', '.join(unknown)}")
    rendered = PLACEHOLDER.sub(lambda m: values[m.group(1)], template)
    if "@@" in rendered:
        raise RecordError("the rendered notes still contain '@@'")
    return rendered


def notes_values(assets: Assets, *, tag: str, commit: str, repo: str) -> Dict[str, str]:
    version, source_ref, payload = bundle_header(assets.directory / BUNDLE_FILE)
    if version != assets.version:
        raise RecordError(f"the bundle header says jwicket {version}, the tag says {assets.version}")
    if source_ref != commit:
        raise RecordError(f"the bundle header records source ref {source_ref[:60]!r}, not {commit}")
    sums_sha256 = hashlib.sha256(assets.sums_text.encode("ascii")).hexdigest()
    wheel = wheel_file(assets.version)
    values = {
        "TAG": tag,
        "VERSION": assets.version,
        "COMMIT": commit,
        "REPO": repo,
        "PAYLOAD_SHA256": payload,
        "BUNDLE_SHA256": assets.sums[BUNDLE_FILE],
        "OP_SHA256": assets.sums[OP_FILE],
        "WHEEL_NAME": wheel,
        "WHEEL_SHA256": assets.sums[wheel],
        "REQUIREMENTS_SHA256": assets.sums[REQUIREMENTS_FILE],
        "SUMS_SHA256": sums_sha256,
        "SHA256SUMS": assets.sums_text.rstrip("\n"),
    }
    for key, value in values.items():
        if "@@" in value or "\r" in value:
            raise RecordError(f"value for {key} is not allowed in the notes")
    return values


def render_notes(
    template: str,
    assets: Assets,
    *,
    tag: str,
    commit: str,
    repo: str,
    constants: Mapping[str, str],
    m4_lines: Optional[Sequence[str]] = None,
) -> str:
    """The notes; ``m4_lines`` (from :func:`m4_unit_lines`) must each appear as a whole line."""
    check_template_constants(template, constants)
    rendered = render_template(template, notes_values(assets, tag=tag, commit=commit, repo=repo))
    if m4_lines is not None:
        check_m4_units(rendered, m4_lines)
    return rendered


# --- downloading and verifying -------------------------------------------------------------------


def run_tool(argv: Sequence[str], timeout: int, stdin: Optional[bytes] = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603 - argument list, no shell; tags, names and paths are validated
        list(argv), input=stdin, capture_output=True, timeout=timeout, check=False
    )


def _find(tool: str) -> str:
    path = shutil.which(tool)
    if path is None or not Path(path).is_absolute():  # a relative result (an empty or '.' PATH entry) never runs
        raise RecordError(f"{tool} is not on PATH as an absolute path")
    return path


def read_with_retries(argv: Sequence[str], what: str, runner: Runner, timeout: int = GH_TIMEOUT_S) -> bytes:
    """Run a read-only network command, retrying with back-off; never used for a write."""
    last = ""
    for attempt in range(1, READ_ATTEMPTS + 1):
        try:
            proc = runner(argv, timeout, None)
        except subprocess.TimeoutExpired:
            last = f"timed out after {timeout} s"
        except OSError as exc:
            raise RecordError(f"{what}: cannot run {argv[0]}: {exc}") from exc
        else:
            if proc.returncode == 0:
                return proc.stdout
            last = proc.stderr.decode("utf-8", errors="replace").strip()[:400] or f"exit status {proc.returncode}"
        if attempt < READ_ATTEMPTS:
            delay = BACKOFF_S * (2 ** (attempt - 1))
            LOG.warning(
                "%s failed (attempt %d of %d: %s); retrying in %.0f s", what, attempt, READ_ATTEMPTS, last, delay
            )
            time.sleep(delay)
    raise RecordError(f"{what} failed after {READ_ATTEMPTS} attempts: {last}")


def download(tag: str, repo: str, directory: Path, names: Sequence[str], runner: Runner) -> None:
    gh = _find("gh")
    argv = [gh, "release", "download", tag, "--repo", repo, "--dir", str(directory)]
    for name in names:
        argv += ["--pattern", name]
    read_with_retries(argv, f"gh release download {tag}", runner)
    present = sorted(p.name for p in directory.iterdir())
    if present != sorted(names):
        raise RecordError(f"the release {tag} provided {present}, expected {sorted(names)}")


def verify_attestation(tag: str, repo: str, assets: Assets, runner: Runner) -> List[str]:
    """P-A: the immutable release's attestation covers every asset, ``SHA256SUMS`` included."""
    gh = _find("gh")
    read_with_retries([gh, "release", "verify", tag, "--repo", repo], f"gh release verify {tag}", runner)
    checked = []
    for name in [*expected_assets(assets.version), SUMS_FILE]:
        path = assets.directory / name
        read_with_retries(
            [gh, "release", "verify-asset", tag, str(path), "--repo", repo], f"gh release verify-asset {name}", runner
        )
        checked.append(name)
    return checked


def verify_signature(
    assets: Assets, *, allowed_signers: Path, identity: str, namespace: str, runner: Runner
) -> None:
    """The owner's SSH signature of ``SHA256SUMS`` (private repositories without attestations, 11.5)."""
    if not SIGNER_TOKEN.match(identity) or not SIGNER_TOKEN.match(namespace):
        raise RecordError("--identity and --namespace must be plain tokens such as owner@example.org")
    if not allowed_signers.is_file():
        raise RecordError(f"{allowed_signers} does not exist; the owner's public key must be on main first")
    signature = assets.directory / SIGNATURE_FILE
    if not signature.is_file():
        raise RecordError(f"the release has no {SIGNATURE_FILE}")
    keygen = _find("ssh-keygen")
    argv = [keygen, "-Y", "verify", "-f", str(allowed_signers), "-I", identity, "-n", namespace, "-s", str(signature)]
    try:
        proc = runner(argv, SSH_KEYGEN_TIMEOUT_S, (assets.directory / SUMS_FILE).read_bytes())
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RecordError(f"ssh-keygen -Y verify failed to run: {exc}") from exc
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", errors="replace").strip()[:400]
        raise RecordError(f"the signature of {SUMS_FILE} does not verify for {identity}: {detail}")


def record_from_git(ref: str, tag: str, runner: Runner) -> bytes:
    """P-C: ``docs/releases/<tag>.sha256sums`` as committed on ``ref`` (normally origin/main)."""
    if not release_check.REF_PATTERN.match(ref):
        raise RecordError(f"{ref[:80]!r} is not a plain revision name")
    git = _find("git")
    argv = [git, "-C", str(REPO_ROOT), "show", f"{ref}:docs/releases/{tag}.sha256sums"]
    try:
        proc = runner(argv, GIT_TIMEOUT_S, None)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RecordError(f"git show failed to run: {exc}") from exc
    if proc.returncode != 0:
        raise RecordError(f"no release record for {tag} on {ref} (docs/releases/{tag}.sha256sums)")
    return proc.stdout


def fetch_verified(
    tag: str,
    repo: str,
    directory: Path,
    *,
    verify: str,
    runner: Runner,
    allowed_signers: Path = DEFAULT_ALLOWED_SIGNERS,
    identity: Optional[str] = None,
    namespace: Optional[str] = None,
    record_ref: str = "origin/main",
) -> Tuple[Assets, str]:
    version = validate_tag(tag)
    validate_repo(repo)
    if verify not in ("attestation", "signature", "record"):
        raise RecordError(f"unknown verification {verify!r}")
    names = [*expected_assets(version), SUMS_FILE]
    if verify == "signature":
        names.append(SIGNATURE_FILE)
    download(tag, repo, directory, names, runner)
    assets = load_assets(directory, version)
    if verify == "attestation":
        checked = verify_attestation(tag, repo, assets, runner)
        how = f"immutable-release attestation (gh release verify-asset: {', '.join(checked)})"
    elif verify == "signature":
        if identity is None or namespace is None:
            raise RecordError("--verify signature needs --identity and --namespace")
        verify_signature(assets, allowed_signers=allowed_signers, identity=identity, namespace=namespace, runner=runner)
        how = f"owner signature ({identity}, namespace {namespace})"
    elif verify == "record":
        if record_from_git(record_ref, tag, runner) != assets.sums_text.encode("ascii"):
            raise RecordError(f"{SUMS_FILE} differs from docs/releases/{tag}.sha256sums on {record_ref}")
        how = f"release record on {record_ref}"
    else:
        raise RecordError(f"unknown verification {verify!r}")
    return assets, how


def write_record(assets: Assets, tag: str, out_dir: Path) -> Tuple[Path, bool]:
    """Write ``<out_dir>/<tag>.sha256sums``. A record never changes: an existing different one is refused."""
    target = out_dir / f"{tag}.sha256sums"
    data = assets.sums_text.encode("ascii")
    if target.exists():
        if target.is_symlink() or target.read_bytes() != data:
            raise RecordError(f"{target} exists and differs from the verified {SUMS_FILE}; a record never changes")
        return target, False
    write_text_file(target, data)
    return target, True


def copy_container_context(assets: Assets, out_dir: Path) -> List[str]:
    """The installer wheel and requirements, with a SHA256SUMS of the two, into an empty directory."""
    if out_dir.exists() and (out_dir.is_symlink() or not out_dir.is_dir() or any(out_dir.iterdir())):
        raise RecordError(f"{out_dir} must be absent or an empty directory")
    out_dir.mkdir(parents=True, exist_ok=True)
    names = [wheel_file(assets.version), REQUIREMENTS_FILE]
    lines = []
    for name in names:
        shutil.copyfile(assets.directory / name, out_dir / name)
        lines.append(f"{assets.sums[name]}  {name}\n")
    write_text_file(out_dir / SUMS_FILE, "".join(lines).encode("ascii"))
    return names


# --- command line --------------------------------------------------------------------------------


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="release_record.py", description="Release notes and records for lab pre-releases."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    notes = sub.add_parser("notes", help="render the release notes from the template (release workflow)")
    notes.add_argument("--dist", type=Path, required=True, help="directory with the assets and SHA256SUMS")
    notes.add_argument("--tag", required=True)
    notes.add_argument("--commit", required=True, help="the source commit (40 hex)")
    notes.add_argument("--repo", required=True, help="owner/name")
    notes.add_argument("--template", type=Path, default=DEFAULT_TEMPLATE)
    notes.add_argument("--out", type=Path, required=True)

    for name, help_text in (
        ("record", "verify a published release and write docs/releases/<tag>.sha256sums"),
        ("fetch", "verify a published release and copy the wheel and requirements into a directory"),
    ):
        cmd = sub.add_parser(name, help=help_text)
        cmd.add_argument("--tag", required=True)
        cmd.add_argument("--repo", required=True, help="owner/name")
        choices = ["attestation", "signature"] + (["record"] if name == "fetch" else [])
        cmd.add_argument("--verify", choices=choices, default="attestation")
        cmd.add_argument("--allowed-signers", type=Path, default=DEFAULT_ALLOWED_SIGNERS)
        cmd.add_argument("--identity", help="the owner's principal in allowed_signers (--verify signature)")
        cmd.add_argument("--namespace", help="the signature namespace, e.g. jwicket-release@example.org")
        if name == "record":
            cmd.add_argument("--out-dir", type=Path, default=DEFAULT_RECORD_DIR)
        else:
            cmd.add_argument("--out-dir", type=Path, required=True)
            cmd.add_argument(
                "--record-ref", default="origin/main", help="where the release record is read (--verify record)"
            )
    return parser.parse_args(argv)


def _notes(args: argparse.Namespace) -> int:
    version = validate_tag(args.tag)
    validate_repo(args.repo)
    if not release_check.SHA_PATTERN.match(args.commit):
        raise RecordError("--commit must be a 40-character lowercase hexadecimal SHA")
    assets = load_assets(args.dist, version)
    try:
        template = args.template.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RecordError(f"cannot read the template {args.template}: {exc}") from exc
    plan = load_plan()
    m4_lines = m4_unit_lines(plan, op_sha256=assets.sums[OP_FILE], tag=args.tag, repo=args.repo)
    text = render_notes(template, assets, tag=args.tag, commit=args.commit, repo=args.repo,
                        constants=plan_constants(plan), m4_lines=m4_lines)
    write_text_file(args.out, text.encode("utf-8"))
    print(f"{args.out}: release notes for {args.tag} ({len(text)} characters)")
    return 0


def _record_or_fetch(args: argparse.Namespace) -> int:
    with tempfile.TemporaryDirectory(prefix="jwicket-release-") as tmp:
        assets, how = fetch_verified(
            args.tag,
            args.repo,
            Path(tmp),
            verify=args.verify,
            runner=run_tool,
            allowed_signers=args.allowed_signers,
            identity=args.identity,
            namespace=args.namespace,
            record_ref=getattr(args, "record_ref", "origin/main"),
        )
        print(f"{args.tag}: {SUMS_FILE} and every asset verified by {how}")
        if args.command == "record":
            target, written = write_record(assets, args.tag, args.out_dir)
            print(f"{target}: {'written' if written else 'already recorded, identical'}; "
                  "add it to main with a reviewed pull request")
        else:
            names = copy_container_context(assets, args.out_dir)
            print(f"{args.out_dir}: {', '.join(names)} and {SUMS_FILE}")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="release_record: %(levelname)s %(message)s", stream=sys.stderr)
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        return _notes(args) if args.command == "notes" else _record_or_fetch(args)
    except RecordError as exc:
        LOG.error("%s", exc)
        return 1
    except OSError as exc:
        LOG.error("file error: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
