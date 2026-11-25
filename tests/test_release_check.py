"""tools/release_check.py and tools/release_record.py (Spec 006 sections 11.1, 11.3 to 11.6; AC-006-40).

release_check is the release workflow's ``verify`` job: it must refuse a non-dev tag, a mismatch
among the three versions, a commit that is not on main, a tag that points elsewhere and a missing
JWICKET_IMMUTABLE_RELEASES assertion. release_record renders the release notes and writes the
release record after verifying a published release; here every ``gh``, ``git`` and ``ssh-keygen``
call goes to a fake runner, so nothing touches the network.
"""

from __future__ import annotations

import hashlib
import importlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from types import ModuleType
from typing import Dict, List, Optional, Sequence
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
TOOLS = REPO / "tools"
TIMEOUT_S = 120


def _load(name: str) -> ModuleType:
    if str(TOOLS) not in sys.path:
        sys.path.append(str(TOOLS))
    return importlib.import_module(name)


release_check = _load("release_check")
release_record = _load("release_record")

GOOD_SHA = "0123456789abcdef0123456789abcdef01234567"


def git(root: Path, *args: str) -> str:
    env = dict(os.environ)
    env.update(
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_NOSYSTEM="1",
        GIT_AUTHOR_NAME="Test",
        GIT_AUTHOR_EMAIL="test@example.invalid",
        GIT_COMMITTER_NAME="Test",
        GIT_COMMITTER_EMAIL="test@example.invalid",
    )
    exe = shutil.which("git")
    assert exe is not None
    proc = subprocess.run(  # noqa: S603 - fixed argument list, no shell
        [exe, "-C", str(root), "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args],
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
        check=False,
        env=env,
    )
    if proc.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {proc.stderr}")
    return proc.stdout.strip()


def write_versions(root: Path, daemon: str, pyproject: str, installer: str) -> None:
    (root / "src" / "jwicket").mkdir(parents=True, exist_ok=True)
    (root / "tools" / "jwicket_install").mkdir(parents=True, exist_ok=True)
    (root / "src" / "jwicket" / "__init__.py").write_text(f'"""x"""\n\n__version__ = "{daemon}"\n', encoding="utf-8")
    (root / "tools" / "jwicket_install" / "__init__.py").write_text(f'__version__ = "{installer}"\n', encoding="utf-8")
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "jwicket"\nversion = "{pyproject}"\n\n[tool.other]\nversion = "9.9.9"\n', encoding="utf-8"
    )


@unittest.skipIf(shutil.which("git") is None, "git is not installed")
class ReleaseCheckRepoTests(unittest.TestCase):
    """Against a throwaway git repository with a main branch, a side branch and tags."""

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="jwicket-release-check-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        git(self.root, "init", "-q")
        git(self.root, "symbolic-ref", "HEAD", "refs/heads/main")
        write_versions(self.root, "0.1.0.dev1", "0.1.0.dev1", "0.1.0.dev1")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "release 0.1.0.dev1")
        self.main_sha = git(self.root, "rev-parse", "HEAD")
        git(self.root, "checkout", "-q", "-b", "side")
        (self.root / "side.txt").write_text("unreviewed\n", encoding="utf-8")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "unreviewed")
        self.side_sha = git(self.root, "rev-parse", "HEAD")
        git(self.root, "checkout", "-q", "main")

    def check(self, **kwargs: object) -> object:
        params: Dict[str, object] = {
            "sha": self.main_sha,
            "event": "push",
            "ref_type": "tag",
            "ref_name": "v0.1.0.dev1",
            "main_ref": "main",
            "immutable": "true",
        }
        params.update(kwargs)
        return release_check.run_checks(self.root, **params)

    def test_a_good_tag_on_main_passes(self) -> None:
        git(self.root, "tag", "v0.1.0.dev1", self.main_sha)
        result = self.check()
        self.assertTrue(result.ok, result.failures)
        self.assertEqual(result.tag, "v0.1.0.dev1")
        self.assertFalse(result.dry_run)

    def test_an_annotated_tag_is_peeled_to_its_commit(self) -> None:
        git(self.root, "tag", "-a", "-m", "lab pre-release", "v0.1.0.dev1", self.main_sha)
        self.assertTrue(self.check().ok)

    def test_a_commit_not_on_main_is_refused(self) -> None:
        git(self.root, "tag", "v0.1.0.dev1", self.side_sha)
        result = self.check(sha=self.side_sha)
        self.assertFalse(result.ok)
        self.assertTrue(any("not reachable from main" in f for f in result.failures), result.failures)

    def test_a_tag_that_points_elsewhere_is_refused(self) -> None:
        git(self.root, "tag", "v0.1.0.dev1", self.side_sha)
        result = self.check(sha=self.main_sha)
        self.assertTrue(any("points to" in f for f in result.failures), result.failures)

    def test_a_push_for_a_missing_tag_is_refused(self) -> None:
        result = self.check()
        self.assertTrue(any("does not exist" in f for f in result.failures), result.failures)

    def test_a_push_for_a_branch_is_refused(self) -> None:
        result = self.check(ref_type="branch", ref_name="main")
        self.assertFalse(result.ok)
        self.assertTrue(any("must be for a tag" in f for f in result.failures), result.failures)

    def test_other_events_are_refused(self) -> None:
        git(self.root, "tag", "v0.1.0.dev1", self.main_sha)
        for event in ("pull_request", "pull_request_target", "workflow_run", "release", ""):
            with self.subTest(event=event):
                result = self.check(event=event)
                self.assertTrue(any("is not one of" in f for f in result.failures), result.failures)

    def test_a_manual_run_on_a_branch_is_a_dry_run_with_the_derived_tag(self) -> None:
        result = self.check(event="workflow_dispatch", ref_type="branch", ref_name="main")
        self.assertTrue(result.ok, result.failures)
        self.assertTrue(result.dry_run)
        self.assertEqual(result.tag, "v0.1.0.dev1")

    def test_a_manual_run_on_a_tag_checks_that_tag(self) -> None:
        git(self.root, "tag", "v0.1.0.dev1", self.main_sha)
        result = self.check(event="workflow_dispatch")
        self.assertTrue(result.ok, result.failures)
        self.assertTrue(result.dry_run)

    def test_a_manual_run_still_needs_main_and_the_assertion(self) -> None:
        result = self.check(
            event="workflow_dispatch", ref_type="branch", ref_name="side", sha=self.side_sha, immutable=None
        )
        self.assertEqual(len(result.failures), 2, result.failures)

    def test_the_immutable_releases_assertion_must_be_exactly_true(self) -> None:
        git(self.root, "tag", "v0.1.0.dev1", self.main_sha)
        for value in (None, "", "false", "TRUE", "True", "true ", "1", "yes"):
            with self.subTest(value=value):
                result = self.check(immutable=value)
                self.assertFalse(result.ok)
                self.assertTrue(any("JWICKET_IMMUTABLE_RELEASES" in f for f in result.failures))

    def test_versions_that_differ_are_refused(self) -> None:
        write_versions(self.root, "0.1.0.dev1", "0.1.0.dev1", "0.1.0.dev2")
        result = self.check(tag="v0.1.0.dev1", event=None)
        self.assertTrue(any("versions differ" in f for f in result.failures), result.failures)

    def test_a_tag_that_differs_from_the_version_is_refused(self) -> None:
        git(self.root, "tag", "v0.1.0.dev2", self.main_sha)
        result = self.check(ref_name="v0.1.0.dev2")
        self.assertTrue(any("does not equal" in f for f in result.failures), result.failures)

    def test_a_final_version_is_refused(self) -> None:
        write_versions(self.root, "0.1.0", "0.1.0", "0.1.0")
        result = self.check(tag="v0.1.0", event=None)
        self.assertFalse(result.ok)
        self.assertTrue(any("not a .devN pre-release" in f for f in result.failures), result.failures)

    def test_bad_revisions_never_reach_git(self) -> None:
        for sha in ("0123", GOOD_SHA.upper(), f"{GOOD_SHA}\n", "--output=/tmp/x", ""):
            with self.subTest(sha=sha):
                result = self.check(sha=sha)
                self.assertTrue(any("40-character" in f for f in result.failures), result.failures)
        result = self.check(main_ref="--upload-pack=touch")
        self.assertTrue(any("main ref" in f for f in result.failures), result.failures)

    def test_main_writes_job_outputs_only_when_every_check_passes(self) -> None:
        git(self.root, "tag", "v0.1.0.dev1", self.main_sha)
        out = self.root / "github-output"
        argv = [
            "--event",
            "push",
            "--ref-type",
            "tag",
            "--ref-name",
            "v0.1.0.dev1",
            "--sha",
            self.main_sha,
            "--main-ref",
            "main",
            "--root",
            str(self.root),
            "--github-output",
            str(out),
        ]
        quiet = mock.patch.object(release_check.logging, "basicConfig")
        with quiet, mock.patch.dict(os.environ, {"JWICKET_IMMUTABLE_RELEASES": "true"}), redirect_stdout(io.StringIO()):
            self.assertEqual(release_check.main(argv), 0)
        self.assertEqual(out.read_text(encoding="utf-8"), "tag=v0.1.0.dev1\nversion=0.1.0.dev1\ndry_run=false\n")
        out.unlink()
        # Not a parenthesized multi-item 'with': that is Python 3.10 syntax, and these tests run on 3.7.
        with ExitStack() as stack:
            stack.enter_context(quiet)
            stack.enter_context(mock.patch.dict(os.environ, {"JWICKET_IMMUTABLE_RELEASES": "no"}))
            stack.enter_context(redirect_stdout(io.StringIO()))
            stack.enter_context(self.assertLogs("jwicket.release_check", "ERROR"))
            self.assertEqual(release_check.main(argv), 1)
        self.assertFalse(out.exists())

    def test_main_needs_a_tag_or_the_event(self) -> None:
        with mock.patch.object(release_check.logging, "basicConfig"), self.assertLogs("jwicket.release_check", "ERROR"):
            self.assertEqual(release_check.main(["--sha", self.main_sha, "--root", str(self.root)]), 2)


class RelativeToolTests(unittest.TestCase):
    """SEC-08: a relative which() result (an empty or '.' PATH entry) is never run."""

    def test_release_check_refuses_a_relative_git(self) -> None:
        with mock.patch.object(release_check.shutil, "which", return_value="git"), self.assertRaises(
            release_check.CheckError
        ):
            release_check._git(REPO, ["rev-parse", "HEAD"])

    def test_release_record_refuses_a_relative_tool(self) -> None:
        with mock.patch.object(release_record.shutil, "which", return_value="gh"), self.assertRaises(
            release_record.RecordError
        ):
            release_record._find("gh")
        with mock.patch.object(release_record.shutil, "which", return_value="/usr/bin/gh"):
            self.assertEqual(release_record._find("gh"), "/usr/bin/gh")

    def test_build_wheel_refuses_a_relative_git(self) -> None:
        build_wheel = _load("build_wheel")
        with mock.patch.object(build_wheel.shutil, "which", return_value="git"), self.assertRaises(
            build_wheel.BuildError
        ):
            build_wheel.commit_epoch(REPO)


class TagPatternTests(unittest.TestCase):
    def test_accepted(self) -> None:
        for tag in ("v0.1.0.dev1", "v0.1.0.dev0", "v10.20.30.dev400"):
            with self.subTest(tag=tag):
                self.assertIsNotNone(release_check.TAG_PATTERN.match(tag))

    def test_refused(self) -> None:
        for tag in (
            "v0.1.0",
            "0.1.0.dev1",
            "v0.1.0-dev.1",
            "v0.1.0.dev1\n",
            "v0.1.0.dev1 ",
            " v0.1.0.dev1",
            "v0.1.0.dev",
            "v0.1.0.dev1a",
            "v0.1.0rc1",
            "v0.1.0.dev1.post1",
            "v0.1.dev1",
            "V0.1.0.dev1",
            "v0.1.0.dev1/x",
            "v" + chr(0x660) + ".1.0.dev1",
            "v0.1.0.dev" + chr(0x661),
            "refs/tags/v0.1.0.dev1",
            "",
        ):
            with self.subTest(tag=tag):
                self.assertIsNone(release_check.TAG_PATTERN.match(tag))


class VersionFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="jwicket-versions-"))
        self.addCleanup(shutil.rmtree, self.root, True)

    def test_the_project_table_alone_is_read(self) -> None:
        write_versions(self.root, "0.1.0.dev1", "0.1.0.dev1", "0.1.0.dev1")
        self.assertEqual(release_check.read_pyproject_version(self.root / "pyproject.toml"), "0.1.0.dev1")

    def test_two_project_versions_are_refused(self) -> None:
        path = self.root / "pyproject.toml"
        path.write_text('[project]\nversion = "0.1.0.dev1"\nversion = "0.1.0.dev2"\n', encoding="utf-8")
        with self.assertRaises(release_check.CheckError):
            release_check.read_pyproject_version(path)

    def test_a_computed_version_is_refused(self) -> None:
        path = self.root / "init.py"
        path.write_text('__version__ = "0.1." + "0"\n', encoding="utf-8")
        with self.assertRaises(release_check.CheckError):
            release_check.read_init_version(path)

    def test_a_missing_file_is_a_failure_not_a_crash(self) -> None:
        result = release_check.run_checks(self.root, sha=GOOD_SHA, tag="v0.1.0.dev1", immutable="true")
        self.assertFalse(result.ok)


# --- release_record -------------------------------------------------------------------------------

VERSION = "0.1.0.dev1"
TAG = "v0.1.0.dev1"
REPO_NAME = "example-owner/jwicket"


def make_dist(directory: Path, bundle_text: Optional[bytes] = None) -> str:
    """Four assets and their SHA256SUMS, as the build job writes them; returns the SHA256SUMS text."""
    directory.mkdir(parents=True, exist_ok=True)
    files = {
        "jwicket.py": bundle_text or b"bundle",
        "jwicket-install-op.py": b"op script",
        f"jwicket_install-{VERSION}-py3-none-any.whl": b"wheel",
        "requirements-install.txt": b"junos-eznc==2.8.3 --hash=sha256:00\n",
    }
    lines = []
    for name, data in files.items():
        (directory / name).write_bytes(data)
        lines.append(f"{hashlib.sha256(data).hexdigest()}  {name}\n")
    text = "".join(lines)
    (directory / "SHA256SUMS").write_text(text, encoding="ascii")
    return text


class FakeRunner:
    """Records every argument list and answers like gh, git or ssh-keygen would."""

    def __init__(
        self,
        source: Path,
        fail: Sequence[str] = (),
        failures_before_success: int = 0,
        git_record: Optional[bytes] = None,
    ) -> None:
        self.source = source
        self.fail = tuple(fail)
        self.failures_left = failures_before_success
        self.git_record = git_record
        self.calls: List[List[str]] = []
        self.stdin: List[Optional[bytes]] = []

    def __call__(self, argv: Sequence[str], timeout: int, stdin: Optional[bytes]) -> subprocess.CompletedProcess[bytes]:
        args = list(argv)
        self.calls.append(args)
        self.stdin.append(stdin)
        assert timeout > 0
        joined = " ".join(args[1:3])
        if any(word in joined for word in self.fail):
            return subprocess.CompletedProcess(args, 1, b"", b"refused by the fake")
        if self.failures_left and joined == "release download":
            self.failures_left -= 1
            return subprocess.CompletedProcess(args, 1, b"", b"transient")
        if joined == "release download":
            target = Path(args[args.index("--dir") + 1])
            patterns = [args[i + 1] for i, a in enumerate(args) if a == "--pattern"]
            for name in patterns:
                shutil.copyfile(self.source / name, target / name)
        if args[1:3] == ["-C", str(release_record.REPO_ROOT)]:
            if self.git_record is None:
                return subprocess.CompletedProcess(args, 128, b"", b"fatal: path not found")
            return subprocess.CompletedProcess(args, 0, self.git_record, b"")
        return subprocess.CompletedProcess(args, 0, b"", b"")


@mock.patch.object(release_record.shutil, "which", lambda name: f"/fake/bin/{name}")
@mock.patch.object(release_record.time, "sleep", lambda _s: None)
class ReleaseRecordTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="jwicket-release-record-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.published = self.tmp / "published"
        self.sums = make_dist(self.published)
        (self.published / "SHA256SUMS.sig").write_bytes(b"-----BEGIN SSH SIGNATURE-----\n")
        self.work = self.tmp / "work"
        self.work.mkdir()

    def fetch(self, runner: FakeRunner, verify: str = "attestation", **kwargs: object) -> object:
        return release_record.fetch_verified(TAG, REPO_NAME, self.work, verify=verify, runner=runner, **kwargs)

    def test_attestation_verifies_every_asset_and_the_sums(self) -> None:
        runner = FakeRunner(self.published)
        assets, how = self.fetch(runner)
        self.assertIn("attestation", how)
        gh = "/fake/bin/gh"
        download = runner.calls[0]
        self.assertEqual(download[:7], [gh, "release", "download", TAG, "--repo", REPO_NAME, "--dir"])
        self.assertEqual(runner.calls[1], [gh, "release", "verify", TAG, "--repo", REPO_NAME])
        verified = [c[4] for c in runner.calls[2:]]
        self.assertEqual(
            [Path(p).name for p in verified],
            [
                "jwicket.py",
                "jwicket-install-op.py",
                f"jwicket_install-{VERSION}-py3-none-any.whl",
                "requirements-install.txt",
                "SHA256SUMS",
            ],
        )
        for call in runner.calls[2:]:
            self.assertEqual(call[:4], [gh, "release", "verify-asset", TAG])
        record_dir = self.tmp / "docs-releases"
        target, written = release_record.write_record(assets, TAG, record_dir)
        self.assertTrue(written)
        self.assertEqual(target.read_bytes(), self.sums.encode("ascii"))
        self.assertEqual(target.name, f"{TAG}.sha256sums")

    def test_a_failed_attestation_writes_nothing(self) -> None:
        with self.assertRaises(release_record.RecordError), self.assertLogs("jwicket.release_record", "WARNING"):
            self.fetch(FakeRunner(self.published, fail=("verify-asset",)))

    def test_reads_are_retried_and_then_give_up(self) -> None:
        runner = FakeRunner(self.published, failures_before_success=2)
        with self.assertLogs("jwicket.release_record", "WARNING") as logs:
            self.fetch(runner)
        self.assertEqual(len(logs.records), 2)
        self.assertEqual([c[1:3] for c in runner.calls[:3]], [["release", "download"]] * 3)
        self.work = self.tmp / "work2"
        self.work.mkdir()
        with self.assertRaises(release_record.RecordError), self.assertLogs("jwicket.release_record", "WARNING"):
            self.fetch(FakeRunner(self.published, failures_before_success=release_record.READ_ATTEMPTS))

    def test_a_tampered_asset_is_refused(self) -> None:
        (self.published / "jwicket.py").write_bytes(b"replaced")
        with self.assertRaises(release_record.RecordError) as ctx:
            self.fetch(FakeRunner(self.published))
        self.assertIn("jwicket.py", str(ctx.exception))

    def test_an_existing_record_never_changes(self) -> None:
        assets, _ = self.fetch(FakeRunner(self.published))
        record_dir = self.tmp / "records"
        record_dir.mkdir()
        (record_dir / f"{TAG}.sha256sums").write_text("something else\n", encoding="ascii")
        with self.assertRaises(release_record.RecordError):
            release_record.write_record(assets, TAG, record_dir)
        (record_dir / f"{TAG}.sha256sums").write_text(self.sums, encoding="ascii")
        self.assertEqual(release_record.write_record(assets, TAG, record_dir)[1], False)

    def test_signature_mode_runs_ssh_keygen_verify_on_the_sums(self) -> None:
        signers = self.tmp / "allowed_signers"
        signers.write_text("owner@example.org ssh-ed25519 AAAA\n", encoding="ascii")
        runner = FakeRunner(self.published)
        self.fetch(
            runner,
            verify="signature",
            allowed_signers=signers,
            identity="owner@example.org",
            namespace="jwicket-release@example.org",
        )
        keygen = runner.calls[-1]
        self.assertEqual(
            keygen,
            [
                "/fake/bin/ssh-keygen",
                "-Y",
                "verify",
                "-f",
                str(signers),
                "-I",
                "owner@example.org",
                "-n",
                "jwicket-release@example.org",
                "-s",
                str(self.work / "SHA256SUMS.sig"),
            ],
        )
        self.assertEqual(runner.stdin[-1], self.sums.encode("ascii"))
        with self.assertRaises(release_record.RecordError):
            release_record.verify_signature(
                release_record.load_assets(self.work, VERSION),
                allowed_signers=signers,
                identity="owner; rm -rf /",
                namespace="ns",
                runner=runner,
            )

    def test_record_mode_compares_with_main(self) -> None:
        self.fetch(FakeRunner(self.published, git_record=self.sums.encode("ascii")), verify="record")
        self.work = self.tmp / "work3"
        self.work.mkdir()
        with self.assertRaises(release_record.RecordError):
            self.fetch(FakeRunner(self.published, git_record=b"other\n"), verify="record")

    def test_container_context_gets_the_wheel_and_requirements_only(self) -> None:
        assets, _ = self.fetch(FakeRunner(self.published))
        out = self.tmp / "context"
        names = release_record.copy_container_context(assets, out)
        self.assertEqual(sorted(p.name for p in out.iterdir()), sorted([*names, "SHA256SUMS"]))
        for line in (out / "SHA256SUMS").read_text(encoding="ascii").splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((out / name).read_bytes()).hexdigest(), digest)
        with self.assertRaises(release_record.RecordError):
            release_record.copy_container_context(assets, out)

    def test_bad_tags_and_repositories_are_refused_before_any_call(self) -> None:
        runner = FakeRunner(self.published)
        for tag, repo in (("v0.1.0", REPO_NAME), (TAG, "owner"), (TAG, "owner/repo --clobber"), (TAG, "-R/x")):
            with self.subTest(tag=tag, repo=repo), self.assertRaises(release_record.RecordError):
                release_record.fetch_verified(tag, repo, self.work, verify="attestation", runner=runner)
        self.assertEqual(runner.calls, [])


class SumsParsingTests(unittest.TestCase):
    def sums(self) -> str:
        return "".join(f"{'ab' * 32}  {name}\n" for name in release_record.expected_assets(VERSION))

    def test_the_build_jobs_format_is_accepted(self) -> None:
        parsed = release_record.parse_sums(self.sums(), VERSION)
        self.assertEqual(set(parsed), set(release_record.expected_assets(VERSION)))

    def test_malformed_sums_are_refused(self) -> None:
        good = self.sums()
        bad = {
            "binary mode": good.replace("  jwicket.py", " *jwicket.py"),
            "one space": good.replace("  jwicket.py", " jwicket.py"),
            "upper case": good.replace("ab" * 32, "AB" * 32, 1),
            "CRLF": good.replace("\n", "\r\n"),
            "duplicate": good + f"{'cd' * 32}  jwicket.py\n",
            "extra file": good + f"{'cd' * 32}  evil.py\n",
            "missing file": "".join(good.splitlines(keepends=True)[1:]),
            "path": good.replace("  jwicket.py", "  ../jwicket.py"),
            "other version": good.replace(VERSION, "0.1.0.dev2"),
        }
        for label, text in bad.items():
            with self.subTest(label), self.assertRaises(release_record.RecordError):
                release_record.parse_sums(text, VERSION)


class ReleaseNotesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="jwicket-notes-"))
        bundle = cls.tmp / "bundle.py"
        proc = subprocess.run(  # noqa: S603 - fixed argument list, no shell, this interpreter
            [sys.executable, str(TOOLS / "bundle.py"), "--out", str(bundle), "--source-ref", GOOD_SHA],
            cwd=str(REPO),
            capture_output=True,
            text=True,
            timeout=TIMEOUT_S,
            check=False,
        )
        if proc.returncode != 0:
            raise AssertionError(f"bundle build failed: {proc.stdout}{proc.stderr}")
        cls.bundle_bytes = bundle.read_bytes()
        cls.version = release_check.read_init_version(REPO / "src" / "jwicket" / "__init__.py")
        cls.template = release_record.DEFAULT_TEMPLATE.read_text(encoding="utf-8")

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def dist(self) -> Path:
        directory = Path(tempfile.mkdtemp(prefix="dist-", dir=self.tmp))
        files = {
            "jwicket.py": self.bundle_bytes,
            "jwicket-install-op.py": b"op",
            f"jwicket_install-{self.version}-py3-none-any.whl": b"wheel",
            "requirements-install.txt": b"req\n",
        }
        lines = []
        for name, data in files.items():
            (directory / name).write_bytes(data)
            lines.append(f"{hashlib.sha256(data).hexdigest()}  {name}\n")
        (directory / "SHA256SUMS").write_text("".join(lines), encoding="ascii")
        return directory

    def constants(self) -> Dict[str, str]:
        try:
            return dict(release_record.plan_constants())
        except release_record.RecordError:
            # Without the installer package, the spec's texts (section 8.4) stand in.
            return {
                "DEVICE_STATUS": "This installer has not yet run on any device. Every device step is unverified "
                "until lab test Q-INST-06 is certified.",
            }

    def test_the_template_renders_with_every_value_checked(self) -> None:
        tag = f"v{self.version}"
        assets = release_record.load_assets(self.dist(), self.version)
        text = release_record.render_notes(
            self.template, assets, tag=tag, commit=GOOD_SHA, repo=REPO_NAME, constants=self.constants()
        )
        self.assertNotIn("@@", text)
        self.assertIn("LAB ONLY", text.splitlines()[0])
        self.assertIn(GOOD_SHA, text)
        for name, digest in assets.sums.items():
            self.assertIn(digest, text, name)
        payload = release_record.bundle_header(assets.directory / "jwicket.py")[2]
        self.assertIn(payload, text)
        self.assertIn(f"docs/releases/{tag}.sha256sums", text)
        self.assertIn(f"/releases/download/{tag}/", text)
        self.assertNotIn("/releases/latest", text.replace("never `/releases/latest`", ""))

    def test_the_template_carries_the_installer_warnings_verbatim(self) -> None:
        try:
            constants = release_record.plan_constants()
        except release_record.RecordError as exc:
            self.skipTest(f"jwicket_install.plan is not importable here: {exc}")
        release_record.check_template_constants(self.template, constants)

    def test_the_m4_section_carries_the_plans_certificate_unit(self) -> None:
        """OPX-09: M4 with tls (the op script's default) needs the operator's TLS pair before unit A; the
        notes show plan.shell_tls_lines' unit, placeholder aside, so it cannot drift from the plan."""
        try:
            plan = release_record.load_plan()
        except release_record.RecordError as exc:
            self.skipTest(f"jwicket_install.plan is not importable here: {exc}")
        address = "192.0.2.10"
        unit = "\n".join(plan.shell_tls_lines(address)).replace(address, "<address>")
        m4 = self.template[self.template.index("### M4:") :]
        self.assertIn("```\n" + unit + "\n```", m4)
        self.assertLess(m4.index(unit), m4.index("**Unit A**"))

    def test_the_m4_units_equal_what_the_plan_renders(self) -> None:
        try:
            plan = release_record.load_plan()
        except release_record.RecordError as exc:
            self.skipTest(f"jwicket_install.plan is not importable here: {exc}")
        tag = f"v{self.version}"
        assets = release_record.load_assets(self.dist(), self.version)
        lines = release_record.m4_unit_lines(
            plan, op_sha256=assets.sums["jwicket-install-op.py"], tag=tag, repo=REPO_NAME
        )
        self.assertTrue(any(line.startswith("set system scripts op file") for line in lines), lines)
        text = release_record.render_notes(
            self.template,
            assets,
            tag=tag,
            commit=GOOD_SHA,
            repo=REPO_NAME,
            constants=release_record.plan_constants(plan),
            m4_lines=lines,
        )
        self.assertIn(lines[-1], text)
        drifted = self.template.replace("commit confirmed 10 comment", "commit confirmed 5 comment")
        with self.assertRaises(release_record.RecordError):
            release_record.render_notes(
                drifted,
                assets,
                tag=tag,
                commit=GOOD_SHA,
                repo=REPO_NAME,
                constants=release_record.plan_constants(plan),
                m4_lines=lines,
            )

    def code_lines(self) -> List[str]:
        """The lines inside the template's ``` blocks: what an operator pastes or runs."""
        lines: List[str] = []
        inside = False
        for line in self.template.splitlines():
            if line.startswith("```"):
                inside = not inside
            elif inside:
                lines.append(line)
        return lines

    def test_the_notes_state_both_access_modes_and_roots_step(self) -> None:
        # Spec 006 revision R2 (--access tls, the default, and --access tunnel) and R4 (the state directory
        # is root's one-time step): the notes carry them in the installer's own words.
        self.assertEqual(
            set(release_record.PLAN_CONSTANTS),
            {"DEVICE_STATUS", "POSTURE_WARNING", "TLS_POSTURE_WARNING", "TUNNEL_WARNING", "STATE_DIR_ROOT_STEP"},
        )
        try:
            constants = release_record.plan_constants()
        except release_record.RecordError as exc:
            self.skipTest(f"jwicket_install.plan is not importable here: {exc}")
        self.assertIn(constants["STATE_DIR_ROOT_STEP"], self.code_lines(), "root's step, on a line of its own")
        for fragment in ("`--access tls`, the default", "`--access tunnel`", "R-STATEDIR", "`--lab-hardware`",
                         "`lab only`", "9443", "SHA-256 fingerprint"):
            self.assertIn(fragment, self.template)

    def test_nothing_to_paste_creates_the_directory_or_asks_for_forwarding(self) -> None:
        # R4: the installers never call make-directory (refused on the SRX4100); R2: tcp-forwarding is a
        # syntax error on 25.2R1-S1.4. Neither may appear in a block an operator pastes.
        for line in self.code_lines():
            with self.subTest(line=line):
                self.assertNotIn("make-directory", line)
                self.assertNotIn("tcp-forwarding", line)
                self.assertNotIn("routing-instance", line)  # the JET statement was ineffective (verified)

    def test_a_compare_mismatch_says_rollback_0_and_exit_before_the_commit(self) -> None:
        # OPD-16: between the expected 'show | compare' output and the commit block, the notes say what to
        # do on a mismatch (rollback 0, then exit), never a bare 'Otherwise:' that reads as "go on".
        commit = self.template.index('commit confirmed 10 comment "jwicket-bootstrap op"')
        compare = self.template.rindex("show | compare", 0, commit)
        between = self.template[compare:commit]
        self.assertIn("If it shows anything else, type `rollback 0` and `exit`.", between)
        self.assertIn("If it matches, paste:", between)
        self.assertNotIn("Otherwise:", between)

    def test_a_bundle_from_another_commit_is_refused(self) -> None:
        assets = release_record.load_assets(self.dist(), self.version)
        with self.assertRaises(release_record.RecordError):
            release_record.notes_values(assets, tag=f"v{self.version}", commit="f" * 40, repo=REPO_NAME)

    def test_unknown_placeholders_and_missing_constants_are_refused(self) -> None:
        with self.assertRaises(release_record.RecordError):
            release_record.render_template("@@NOPE@@", {"TAG": "x"})
        with self.assertRaises(release_record.RecordError):
            release_record.check_template_constants("no warnings here", {"DEVICE_STATUS": "This installer ..."})


if __name__ == "__main__":
    unittest.main()
