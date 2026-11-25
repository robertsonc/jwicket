"""Downloads and provenance of a pre-release (Spec 006 section 8.9, INV-07). LAB ONLY.

``SHA256SUMS`` from the same release protects against corruption, not against a replaced release, so
``--apply`` and ``fetch`` need one source independent of the release page:

* P-A: the immutable release's attestation, ``gh release verify-asset <tag> <file> --repo <repo>``.
* P-B: the build-provenance attestation, ``gh attestation verify <file> --repo <repo> --signer-workflow
  <repo>/.github/workflows/release.yml --source-ref refs/tags/<tag> --source-digest <commit>``, where
  <commit> is the bundle header's source ref: the attested source commit must be that commit (``gh``'s
  "Enforce that the digest associated with the source repository matches the provided value", gh
  2.89.0 help; that this digest is the commit SHA is inferred). Only then is that commit, now the
  attested one, checked to be an ancestor of ``main``: ``git merge-base --is-ancestor`` in a checkout,
  or the GitHub compare API through ``gh api`` (inferred to answer 'ahead' or 'identical'). The header
  alone is never trusted: the workflow run that built the bundle wrote it.
* P-C: the release record on ``main``, ``docs/releases/<tag>.sha256sums``, from a checkout
  (``git show origin/main:...``) or from raw.githubusercontent.com.
* P-D: a local reproduction in a checkout of the tagged commit (``tools/bundle.py --source-ref``).
* P-E: a hash the operator supplies (``--expect-sha256``) from a channel they name (``--expect-source``).

With none, the run stops with exit 7 unless ``--trust-release-page-only``, which stamps the receipt "not
qualification evidence". ``gh`` and ``git`` run with argument lists and timeouts, never a shell, and
only from an absolute path: a ``which`` result that is relative (an empty or '.' entry in PATH) counts
as not installed, so a ``gh`` planted in the working directory never runs.

Downloads use per-tag URLs only (never ``/releases/latest``, which cannot point at a pre-release,
verified), the default verified TLS context, a 16 MB cap, a 30 s timeout, and a redirect handler that
accepts only https, only github.com and the configured asset hosts, and at most 3 hops (CPython's own
handler follows https to http, verified, so it is not used). The asset host names are inferred: they are
a setting (``ASSET_HOSTS``, ``--asset-host``) with a tested default. GitHub sends a release asset's
download on to a signed URL with a query string (observed: ``release-assets.githubusercontent.com/...
?sp=r&sv=...``), so a query is accepted on a redirect hop, and the final URL, to an asset host only;
the first URL and any URL on github.com or raw.githubusercontent.com must have none, and no URL may carry
user information or a fragment. A signed URL is never printed or logged (only the per-tag URL is).
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple

from . import plan

LOG = logging.getLogger("jwicket_install.provenance")

# -- configuration (kept apart from the logic below) --------------------------------------------------
DEFAULT_REPO = "robertsonc/jwicket"  # the project's repository (its git remote); --repo overrides it
RELEASE_HOST = "github.com"
ASSET_HOSTS: Tuple[str, ...] = ("objects.githubusercontent.com", "release-assets.githubusercontent.com")
RECORD_HOST = "raw.githubusercontent.com"
MAX_REDIRECTS = 3
MAX_DOWNLOAD_BYTES = plan.MAX_BUNDLE_SIZE  # 16 MB
MAX_SUMS_BYTES = 64 * 1024
GH_TIMEOUT_S = 60
GIT_TIMEOUT_S = 60
REPRODUCE_TIMEOUT_S = 300
SELF_TEST_TIMEOUT_S = 60
RELEASE_WORKFLOW = ".github/workflows/release.yml"
BUNDLE_NAME = "jwicket.py"
SUMS_NAME = "SHA256SUMS"

TAG_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+\.dev[0-9]+\Z")  # tools/release_check.py's rule
REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}\Z")
ASSET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}\.)+[a-z]{2,63}\Z")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}\Z")
SOURCE_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+=-]{0,63}\Z")


class ProvenanceError(Exception):
    """A download, integrity or provenance failure (exit 7). The message says which and why."""


# ------------------------------------------------------------------------------------------------
# Validation
# ------------------------------------------------------------------------------------------------


def validate_tag(tag: str) -> str:
    if TAG_RE.match(tag) is None:
        raise plan.InputError(
            f"--release {plan.sanitize_display(tag)[:40]!r} is not a pre-release tag like v0.1.0.dev1 "
            "(only .devN pre-releases exist before G1)"
        )
    return tag


def validate_repo(repo: str) -> str:
    if REPO_RE.match(repo) is None:
        raise plan.InputError(f"--repo {plan.sanitize_display(repo)[:80]!r} is not <owner>/<name>")
    return repo


def validate_host(host: str) -> str:
    lowered = host.lower()
    if HOST_RE.match(lowered) is None:
        raise plan.InputError(f"asset host {plan.sanitize_display(host)[:80]!r} is not a plain DNS name")
    return lowered


def release_url(repo: str, tag: str, name: str) -> str:
    """A per-tag asset URL; never /releases/latest."""
    validate_repo(repo)
    validate_tag(tag)
    if ASSET_RE.match(name) is None:
        raise plan.InputError(f"asset name {name!r} is not plain")
    return f"https://{RELEASE_HOST}/{repo}/releases/download/{tag}/{name}"


def record_url(repo: str, tag: str) -> str:
    validate_repo(repo)
    validate_tag(tag)
    return f"https://{RECORD_HOST}/{repo}/main/docs/releases/{tag}.sha256sums"


def _check_url(
    url: str, hosts: FrozenSet[str], schemes: Tuple[str, ...], query_hosts: FrozenSet[str] = frozenset()
) -> None:
    """``query_hosts``: the hosts whose URL may carry a query (a redirect hop to an asset host only)."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in schemes:
        raise ProvenanceError(f"refused {parts.scheme or 'a'} URL: only {', '.join(schemes)} is fetched")
    if parts.username is not None or parts.password is not None:
        raise ProvenanceError("refused a URL with user information")
    host = (parts.hostname or "").lower()
    if host not in hosts:
        raise ProvenanceError(f"refused host {plan.sanitize_display(host)[:80]!r}: not in the allowed list")
    if parts.fragment:
        raise ProvenanceError("refused a URL with a fragment")
    if parts.query and host not in query_hosts:
        raise ProvenanceError(f"refused a URL with a query on {plan.sanitize_display(host)[:80]!r}")


def query_hosts_of(hosts: FrozenSet[str]) -> FrozenSet[str]:
    """The asset hosts among ``hosts``: every allowed host but github.com and raw.githubusercontent.com."""
    return frozenset(hosts - {RELEASE_HOST, RECORD_HOST})


class StrictRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follows a redirect only to an allowed scheme and host, at most ``max_redirections`` hops."""

    max_redirections = MAX_REDIRECTS  # CPython's own hop counter, lowered from 10

    def __init__(
        self,
        hosts: FrozenSet[str],
        schemes: Tuple[str, ...] = ("https",),
        query_hosts: Optional[FrozenSet[str]] = None,
    ) -> None:
        super().__init__()
        self.hosts = hosts
        self.schemes = schemes
        self.query_hosts = query_hosts_of(hosts) if query_hosts is None else query_hosts

    def redirect_request(
        self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> Optional[urllib.request.Request]:
        _check_url(newurl, self.hosts, self.schemes, self.query_hosts)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@dataclass
class Fetcher:
    """HTTPS downloads with an allowlist, a cap, a timeout and read retries (GET is idempotent)."""

    hosts: FrozenSet[str] = frozenset({RELEASE_HOST, *ASSET_HOSTS})
    schemes: Tuple[str, ...] = ("https",)
    timeout: int = plan.TIMEOUTS["http"]
    sleep: Callable[[float], None] = field(default=lambda s: None)
    context: Optional[ssl.SSLContext] = None

    def get(self, url: str, limit: int = MAX_DOWNLOAD_BYTES, *, extra_hosts: FrozenSet[str] = frozenset()) -> bytes:
        hosts = self.hosts | extra_hosts
        _check_url(url, hosts, self.schemes)  # the first URL: never a query
        delays = plan.READ_RETRY_BACKOFF_S
        last = ""
        for attempt in range(len(delays) + 1):
            try:
                return self._once(url, limit, hosts)
            except urllib.error.HTTPError as exc:
                if 300 <= exc.code < 400:
                    raise ProvenanceError(
                        f"download of {_display(url)} refused: more than {MAX_REDIRECTS} redirects"
                    ) from exc
                if exc.code < 500:
                    raise ProvenanceError(f"download refused: HTTP {exc.code} for {_display(url)}") from exc
                last = f"HTTP {exc.code}"
            except (urllib.error.URLError, socket.timeout, ConnectionError) as exc:
                reason = getattr(exc, "reason", exc)
                if isinstance(reason, ProvenanceError):
                    raise reason from exc
                last = plan.sanitize_display(str(reason), 200)
            if attempt < len(delays):
                LOG.info("download of %s failed (%s); retrying in %d s", _display(url), last, delays[attempt])
                self.sleep(delays[attempt])
        raise ProvenanceError(f"download of {_display(url)} failed after {len(delays) + 1} tries: {last}")

    def _once(self, url: str, limit: int, hosts: FrozenSet[str]) -> bytes:
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self.context or ssl.create_default_context()),
            StrictRedirectHandler(hosts, self.schemes, query_hosts_of(hosts)),
        )
        request = urllib.request.Request(url, headers={"User-Agent": "jwicket-install", "Accept": "*/*"})  # noqa: S310 - scheme checked above
        with opener.open(request, timeout=self.timeout) as response:
            final = response.geturl()  # a signed asset URL: checked, never printed
            _check_url(final, hosts, self.schemes, query_hosts_of(hosts) if final != url else frozenset())
            length = response.headers.get("Content-Length")
            if length is not None and length.isdigit() and int(length) > limit:
                raise ProvenanceError(f"{_display(url)} is {length} bytes, more than the {limit}-byte cap")
            data = bytearray()
            while True:
                chunk = response.read(65536)
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > limit:
                    raise ProvenanceError(f"{_display(url)} is larger than the {limit}-byte cap")
        return bytes(data)


def _display(url: str) -> str:
    return plan.sanitize_display(url, 160)


# ------------------------------------------------------------------------------------------------
# SHA256SUMS and the bundle header
# ------------------------------------------------------------------------------------------------


def parse_sums(text: str) -> Dict[str, str]:
    """'<64 hex>  <name>' (or ' *<name>') lines; anything else is an error, not skipped."""
    sums: Dict[str, str] = {}
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        match = re.match(r"^([0-9a-fA-F]{64}) [ *]([A-Za-z0-9][A-Za-z0-9._+-]{0,127})\Z", line)
        if match is None:
            raise ProvenanceError(f"SHA256SUMS line {number} is not '<sha256>  <file>'")
        name = match.group(2)
        if name in sums:
            raise ProvenanceError(f"SHA256SUMS names {name} twice")
        sums[name] = match.group(1).lower()
    return sums


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def bundle_id(data: bytes, *, tag: Optional[str]) -> plan.BundleId:
    """The BundleId from the bundle's own header; its version must be the tag's (spec 8.9 step 2)."""
    if len(data) > MAX_DOWNLOAD_BYTES or not data:
        raise ProvenanceError("the bundle is empty or larger than 16 MB")
    head = data[:4096].decode("utf-8", "replace")
    try:
        identity = plan.BundleId.from_header(head, sha256_hex(data), len(data))
    except plan.InputError as exc:
        raise ProvenanceError(f"the bundle's header does not parse: {exc}") from exc
    if tag is not None and identity.version != tag[1:]:
        raise ProvenanceError(
            f"the bundle's header says version {identity.version}, the tag says {tag[1:]}: not this release"
        )
    return identity


def check_sums(name: str, data: bytes, sums: Mapping[str, str]) -> None:
    expected = sums.get(name)
    if expected is None:
        raise ProvenanceError(f"SHA256SUMS has no line for {name}")
    actual = sha256_hex(data)
    if actual != expected:
        raise ProvenanceError(f"{name}'s SHA-256 is {actual}, SHA256SUMS says {expected}: refused")


@dataclass(frozen=True)
class Download:
    data: bytes
    identity: plan.BundleId
    sums: Mapping[str, str]


def fetch_release(fetcher: Fetcher, repo: str, tag: str) -> Download:
    """jwicket.py and SHA256SUMS of one tag, checked against each other and against the tag."""
    sums = parse_sums(fetcher.get(release_url(repo, tag, SUMS_NAME), MAX_SUMS_BYTES).decode("utf-8", "replace"))
    data = fetcher.get(release_url(repo, tag, BUNDLE_NAME))
    check_sums(BUNDLE_NAME, data, sums)
    return Download(data, bundle_id(data, tag=tag), sums)


def read_local_bundle(path: Path) -> bytes:
    """A local bundle (--bundle): a regular file, not a link, at most 16 MB, read once."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ProvenanceError(f"cannot open --bundle {path}: {exc.strerror or type(exc).__name__}") from exc
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not (info.st_mode & 0o170000 == 0o100000):
            raise ProvenanceError(f"--bundle {path} is not a regular file")
        data = handle.read(MAX_DOWNLOAD_BYTES + 1)
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise ProvenanceError(f"--bundle {path} is larger than 16 MB")
    return data


# ------------------------------------------------------------------------------------------------
# Independent sources (P-A to P-E)
# ------------------------------------------------------------------------------------------------

Runner = Callable[..., Tuple[int, str]]


def run_command(
    argv: Sequence[str], *, timeout: int, cwd: Optional[str] = None, env: Optional[Mapping[str, str]] = None
) -> Tuple[int, str]:
    """An argument list, no shell, a timeout; returns (exit status, standard output). Standard error is
    logged at DEBUG only (it can hold tool chatter, never shown raw)."""
    try:
        completed = subprocess.run(  # noqa: S603 - an argument list built from validated tokens, shell=False
            list(argv),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            cwd=cwd,
            env=dict(env) if env is not None else None,
        )
    except subprocess.TimeoutExpired:
        return 124, ""
    except OSError as exc:
        return 127, plan.sanitize_display(str(exc), 200)
    LOG.debug("%s exited %d", argv[0], completed.returncode)
    return completed.returncode, completed.stdout


@dataclass(frozen=True)
class Sources:
    """What the operator gave for provenance (all optional)."""

    repo: str = DEFAULT_REPO
    tag: Optional[str] = None
    expect_sha256: Optional[str] = None
    expect_source: Optional[str] = None
    checkout: Optional[Path] = None
    reproduce: bool = False
    use_gh: bool = True
    trust_release_page_only: bool = False


@dataclass
class Attempt:
    source: str
    outcome: str  # "passed", "failed", "skipped"
    detail: str


def absolute_tool(which: Callable[[str], Optional[str]], name: str) -> Optional[str]:
    """``which(name)``, or None when it is not an absolute path (a relative PATH entry found it)."""
    found = which(name)
    return found if found is not None and Path(found).is_absolute() else None


def _minimal_env(home: str) -> Dict[str, str]:
    return {"PATH": os.environ.get("PATH", os.defpath), "HOME": home, "LANG": "C.UTF-8"}


def establish(
    data: bytes,
    identity: plan.BundleId,
    file_path: Path,
    sources: Sources,
    *,
    runner: Runner = run_command,
    fetcher: Optional[Fetcher] = None,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> Tuple[plan.Provenance, List[Attempt]]:
    """Try the independent sources in order (P-E, P-A, P-B, P-C, P-D); the first that passes vouches.
    A P-E hash that differs is fatal (exit 7), not a reason to try the next source."""
    sha = sha256_hex(data)
    attempts: List[Attempt] = []
    tag = sources.tag
    repo = validate_repo(sources.repo)

    if sources.expect_sha256 is not None:
        expected = plan.validate_sha256(sources.expect_sha256.lower(), "--expect-sha256")
        source = sources.expect_source or ""
        if SOURCE_TOKEN_RE.match(source) is None:
            raise plan.InputError("--expect-source must name the channel the hash came from, as one plain word")
        if expected != sha:
            raise ProvenanceError(f"the bundle's SHA-256 is {sha}, --expect-sha256 says {expected}: refused")
        attempts.append(Attempt("P-E", "passed", f"operator hash from {source}"))
        return plan.Provenance("operator-hash", (source,), True), attempts

    gh = absolute_tool(which, "gh") if sources.use_gh else None
    git = absolute_tool(which, "git")
    if tag is not None and gh is not None:
        status, _ = runner([gh, "release", "verify-asset", tag, str(file_path), "--repo", repo], timeout=GH_TIMEOUT_S)
        if status == 0:
            attempts.append(Attempt("P-A", "passed", f"gh release verify-asset {tag}"))
            return plan.Provenance("immutable-release", (tag,), True), attempts
        attempts.append(Attempt("P-A", "failed", f"gh release verify-asset exited {status}"))
        commit = identity.source_ref or ""
        status = 1
        if COMMIT_RE.match(commit) is not None:
            # --source-digest binds the attestation to the header's commit, so the ancestry check below is
            # of the attested commit, not of a claim the building workflow wrote (SEC-02).
            status, _ = runner(
                [
                    gh,
                    "attestation",
                    "verify",
                    str(file_path),
                    "--repo",
                    repo,
                    "--signer-workflow",
                    f"{repo}/{RELEASE_WORKFLOW}",
                    "--source-ref",
                    f"refs/tags/{tag}",
                    "--source-digest",
                    commit,
                ],
                timeout=GH_TIMEOUT_S,
            )
        if COMMIT_RE.match(commit) is None:
            attempts.append(Attempt("P-B", "failed", "the bundle header records no source commit"))
        elif status != 0:
            attempts.append(
                Attempt("P-B", "failed", f"gh attestation verify exited {status} (attested commit {commit[:12]}?)")
            )
        elif _on_main(commit, repo, gh, git, sources.checkout, runner):
            attempts.append(Attempt("P-B", "passed", f"attested at refs/tags/{tag}; {commit[:12]} is on main"))
            return plan.Provenance("attestation", (tag, commit), True), attempts
        else:
            attempts.append(Attempt("P-B", "failed", f"{commit[:12]} is not shown to be an ancestor of main"))
    elif tag is not None:
        attempts.append(Attempt("P-A", "skipped", "gh is not installed (or --no-gh)"))

    if tag is not None:
        record = _release_record(tag, repo, git, sources.checkout, runner, fetcher)
        if record is None:
            attempts.append(Attempt("P-C", "skipped", f"no docs/releases/{tag}.sha256sums on main yet"))
        elif record.get(BUNDLE_NAME) == sha:
            attempts.append(Attempt("P-C", "passed", f"docs/releases/{tag}.sha256sums on main"))
            return plan.Provenance("release-record", (tag,), True), attempts
        else:
            raise ProvenanceError(
                f"the release record on main says {BUNDLE_NAME} is {record.get(BUNDLE_NAME)}, this file is {sha}: "
                "the release page and main disagree; refused"
            )

    if sources.reproduce:
        if sources.checkout is None or git is None:
            attempts.append(Attempt("P-D", "skipped", "--reproduce needs --checkout and git"))
        else:
            reproduced = _reproduce(identity, sources.checkout, git, runner)
            if reproduced == sha:
                attempts.append(Attempt("P-D", "passed", "a local rebuild gives the same SHA-256"))
                detail = (identity.source_ref,) if identity.source_ref else ()
                return plan.Provenance("reproduced", detail, True), attempts
            attempts.append(Attempt("P-D", "failed", f"the local rebuild gives {reproduced or 'nothing'}"))

    if sources.trust_release_page_only:
        attempts.append(Attempt("release page", "passed", "--trust-release-page-only: not qualification evidence"))
        return plan.Provenance("release-page-only", (tag,) if tag else (), False), attempts
    return plan.Provenance("none", (), False), attempts


def _on_main(
    commit: str, repo: str, gh: Optional[str], git: Optional[str], checkout: Optional[Path], runner: Runner
) -> bool:
    if checkout is not None and git is not None:
        status, _ = runner(
            [git, "-C", str(checkout), "merge-base", "--is-ancestor", commit, "origin/main"], timeout=GIT_TIMEOUT_S
        )
        return status == 0
    if gh is None:
        return False
    status, out = runner([gh, "api", f"repos/{repo}/compare/{commit}...main", "--jq", ".status"], timeout=GH_TIMEOUT_S)
    return status == 0 and out.strip() in ("ahead", "identical")


def _release_record(
    tag: str, repo: str, git: Optional[str], checkout: Optional[Path], runner: Runner, fetcher: Optional[Fetcher]
) -> Optional[Dict[str, str]]:
    text: Optional[str] = None
    if checkout is not None and git is not None:
        status, out = runner(
            [git, "-C", str(checkout), "show", f"origin/main:docs/releases/{tag}.sha256sums"], timeout=GIT_TIMEOUT_S
        )
        text = out if status == 0 else None
    elif fetcher is not None:
        try:
            text = fetcher.get(record_url(repo, tag), MAX_SUMS_BYTES, extra_hosts=frozenset({RECORD_HOST})).decode(
                "utf-8", "replace"
            )
        except ProvenanceError as exc:
            LOG.info("release record not read: %s", exc)
            text = None
    if text is None:
        return None
    return parse_sums(text)


def _reproduce(identity: plan.BundleId, checkout: Path, git: str, runner: Runner) -> Optional[str]:
    commit = identity.source_ref or ""
    if COMMIT_RE.match(commit) is None:
        return None
    status, head = runner([git, "-C", str(checkout), "rev-parse", "HEAD"], timeout=GIT_TIMEOUT_S)
    if status != 0 or head.strip() != commit:
        LOG.warning("--checkout is not at the bundle's source commit %s", commit[:12])
        return None
    with tempfile.TemporaryDirectory(prefix="jwicket-reproduce-") as tmp:
        out = Path(tmp) / BUNDLE_NAME
        status, _ = runner(
            [sys.executable, "tools/bundle.py", "--out", str(out), "--source-ref", commit],
            timeout=REPRODUCE_TIMEOUT_S,
            cwd=str(checkout),
            env=_minimal_env(tmp),
        )
        if status != 0 or not out.is_file():
            return None
        return sha256_hex(out.read_bytes())


def local_self_test(data: bytes, runner: Runner = run_command) -> Tuple[bool, str]:
    """--local-self-test (off by default; spec 8.9 step 3): only after a provenance source passed, in a
    fresh temporary directory, with a scrubbed environment (no SSH agent, HOME there), -I and a timeout."""
    with tempfile.TemporaryDirectory(prefix="jwicket-selftest-") as tmp:
        path = Path(tmp) / BUNDLE_NAME
        path.write_bytes(data)
        path.chmod(0o600)
        status, out = runner(
            [sys.executable, "-I", str(path), "--bundle-self-test"],
            timeout=SELF_TEST_TIMEOUT_S,
            cwd=tmp,
            env=_minimal_env(tmp),
        )
    ok = status == 0
    return ok, "the bundle self-test passed on this workstation" if ok else f"the bundle self-test exited {status}"
