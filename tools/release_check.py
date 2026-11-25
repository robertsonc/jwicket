#!/usr/bin/env python3
"""Pre-flight checks for a J-Wicket lab pre-release (Spec 006 section 11.1 and 11.3, job ``verify``).

The release workflow runs the copy of ``release.yml`` in the tagged commit, so whoever can push a
``v*`` tag controls the workflow that runs. These checks are defence in depth: the controls that
matter are repository settings (a tag ruleset, branch protection, immutable releases, the
``lab-prerelease`` environment). What this tool refuses:

* a tag that is not exactly ``v<major>.<minor>.<patch>.dev<N>`` (only lab pre-releases, never a
  final version, until the owner changes the rule);
* a version mismatch among ``src/jwicket/__init__.py``, ``pyproject.toml`` and
  ``tools/jwicket_install/__init__.py``, or between them and the tag;
* a commit that is not reachable from ``origin/main`` (the reviewed branch), or a tag that points
  elsewhere;
* a missing owner assertion that immutable releases are on (``JWICKET_IMMUTABLE_RELEASES=true``;
  the workflow cannot read the setting itself, so ``publish`` also runs ``gh release verify``).

Usage, in the workflow (every value comes from the environment, never from ``${{ }}``)::

    python tools/release_check.py --event "$GITHUB_EVENT_NAME" --ref-type "$GITHUB_REF_TYPE" \\
        --ref-name "$GITHUB_REF_NAME" --sha "$GITHUB_SHA" --github-output "$GITHUB_OUTPUT"

and by hand before the owner pushes a tag::

    JWICKET_IMMUTABLE_RELEASES=true python3 tools/release_check.py --tag v0.1.0.dev1 --sha "$(git rev-parse HEAD)"

A ``workflow_dispatch`` run on a branch is a dry run: the tag is derived from the version
(``v`` + version) and every other check still applies. Exit status: 0 all checks passed, 1 a check
failed (each failure is printed), 2 bad arguments. Standard library only, Python 3.7 or later (the
release workflow's oldest interpreter is the SRX's 3.7); runs on a build machine, never on a device.
"""

from __future__ import annotations

import argparse
import ast
import logging
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Mapping, Optional, Sequence, Tuple

LOG = logging.getLogger("jwicket.release_check")

REPO_ROOT = Path(__file__).resolve().parent.parent

# Where the three copies of the version live (Spec 006 section 11.1). A test requires them equal.
DAEMON_INIT = Path("src") / "jwicket" / "__init__.py"
INSTALLER_INIT = Path("tools") / "jwicket_install" / "__init__.py"
PYPROJECT = Path("pyproject.toml")
VERSION_FILES: Tuple[Path, ...] = (DAEMON_INIT, PYPROJECT, INSTALLER_INIT)

# re.ASCII: without it \d also matches non-ASCII digits such as U+0661.
TAG_PATTERN = re.compile(r"^v\d+\.\d+\.\d+\.dev\d+\Z", re.ASCII)
VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+\.dev\d+\Z", re.ASCII)
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}\Z", re.ASCII)
# A git revision such as origin/main; never starts with "-" so git cannot read it as an option.
REF_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}\Z", re.ASCII)

IMMUTABLE_VARIABLE = "JWICKET_IMMUTABLE_RELEASES"
DEFAULT_MAIN_REF = "origin/main"
EVENTS = ("push", "workflow_dispatch")
REF_TYPES = ("tag", "branch")
GIT_TIMEOUT_S = 30

_PYPROJECT_VERSION = re.compile(r'^version\s*=\s*"([^"\\]*)"\s*(?:#.*)?$')


class CheckError(Exception):
    """A release check could not be carried out (a file is unreadable, git failed)."""


@dataclass(frozen=True)
class Result:
    tag: str
    version: str
    dry_run: bool
    failures: Tuple[str, ...]
    passed: Tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.failures


# --- versions ------------------------------------------------------------------------------------


def read_init_version(path: Path) -> str:
    """``__version__`` from a Python file, parsed with ``ast`` rather than imported."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError, UnicodeDecodeError, ValueError) as exc:
        raise CheckError(f"cannot read __version__ from {path}: {exc}") from exc
    found: List[str] = []
    for node in tree.body:
        targets: List[ast.expr]
        value: Optional[ast.expr]
        if isinstance(node, ast.Assign):
            targets, value = list(node.targets), node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        else:
            continue
        if not any(isinstance(t, ast.Name) and t.id == "__version__" for t in targets):
            continue
        # Python 3.7's parser gives ast.Str for a string literal (its .s); 3.8 and later ast.Constant.
        text = value.value if isinstance(value, ast.Constant) else getattr(value, "s", None)
        if not isinstance(text, str):
            raise CheckError(f"{path}: __version__ must be a plain string literal")
        found.append(text)
    if len(found) != 1:
        raise CheckError(f"{path}: expected exactly one __version__ assignment, found {len(found)}")
    return found[0]


def read_pyproject_version(path: Path) -> str:
    """``[project] version`` from ``pyproject.toml``, without a TOML library (none before Python 3.11)."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise CheckError(f"cannot read {path}: {exc}") from exc
    in_project = False
    found: List[str] = []
    for raw in lines:
        line = raw.strip()
        if line.startswith("["):
            in_project = line == "[project]"
            continue
        if in_project:
            match = _PYPROJECT_VERSION.match(line)
            if match:
                found.append(match.group(1))
    if len(found) != 1:
        raise CheckError(f"{path}: expected exactly one 'version = \"...\"' line in [project], found {len(found)}")
    return found[0]


def read_versions(root: Path) -> Mapping[str, str]:
    """Each version file (relative path, POSIX form) to the version it declares."""
    versions = {}
    for rel in VERSION_FILES:
        path = root / rel
        versions[rel.as_posix()] = read_pyproject_version(path) if rel == PYPROJECT else read_init_version(path)
    return versions


def tag_for_version(version: str) -> str:
    return "v" + version


# --- git -----------------------------------------------------------------------------------------


def _git(root: Path, args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    git = shutil.which("git")
    if git is None or not Path(git).is_absolute():  # a relative result (an empty or '.' PATH entry) never runs
        raise CheckError("git is not on PATH as an absolute path; the ancestry and tag checks need it")
    try:
        return subprocess.run(  # noqa: S603 - argument list, no shell; every argument is validated
            [git, "-C", str(root), *args],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CheckError(f"git {' '.join(args[:2])} failed to run: {exc}") from exc


def is_ancestor(root: Path, sha: str, ref: str) -> bool:
    """True when ``sha`` is reachable from ``ref`` (``git merge-base --is-ancestor``)."""
    if not SHA_PATTERN.match(sha) or not REF_PATTERN.match(ref):
        raise CheckError("refusing to pass an unvalidated revision to git")
    resolved = _git(root, ["rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"])
    if resolved.returncode != 0:
        raise CheckError(f"{ref} does not resolve to a commit in {root} (was the checkout made with fetch-depth 0?)")
    proc = _git(root, ["merge-base", "--is-ancestor", sha, ref])
    if proc.returncode == 0:
        return True
    if proc.returncode == 1:
        return False
    raise CheckError(f"git merge-base --is-ancestor {sha} {ref} failed: {proc.stderr.strip()[:300]}")


def tag_commit(root: Path, tag: str) -> Optional[str]:
    """The commit a local tag points to (peeled), or None when no such tag exists."""
    if not TAG_PATTERN.match(tag):
        raise CheckError("refusing to pass an unvalidated tag to git")
    proc = _git(root, ["rev-parse", "--verify", "--quiet", f"refs/tags/{tag}^{{commit}}"])
    if proc.returncode != 0:
        return None
    value = proc.stdout.strip()
    if not SHA_PATTERN.match(value):
        raise CheckError(f"git rev-parse refs/tags/{tag} printed an unexpected value")
    return value


# --- the checks ----------------------------------------------------------------------------------


def resolve_tag(
    *, tag: Optional[str], event: Optional[str], ref_type: Optional[str], ref_name: Optional[str], version: str
) -> Tuple[str, bool, List[str]]:
    """Which tag this run releases, whether it is a dry run, and any refusals about the trigger."""
    problems: List[str] = []
    if tag is not None:
        return tag, event == "workflow_dispatch", problems
    if event not in EVENTS:
        problems.append(f"event {event!r} is not one of {', '.join(EVENTS)}")
        return tag_for_version(version), True, problems
    if ref_type not in REF_TYPES:
        problems.append(f"ref type {ref_type!r} is not one of {', '.join(REF_TYPES)}")
        return tag_for_version(version), True, problems
    if event == "push":
        if ref_type != "tag":
            problems.append("a push run must be for a tag; this workflow publishes only from tags")
            return tag_for_version(version), True, problems
        return ref_name or "", False, problems
    # workflow_dispatch: always a dry run. On a tag, check that tag; on a branch, the tag the
    # version would get.
    if ref_type == "tag":
        return ref_name or "", True, problems
    return tag_for_version(version), True, problems


def run_checks(
    root: Path,
    *,
    sha: str,
    tag: Optional[str] = None,
    event: Optional[str] = None,
    ref_type: Optional[str] = None,
    ref_name: Optional[str] = None,
    main_ref: str = DEFAULT_MAIN_REF,
    immutable: Optional[str] = None,
) -> Result:
    failures: List[str] = []
    passed: List[str] = []

    try:
        versions = read_versions(root)
    except CheckError as exc:
        return Result(tag or "", "", True, (str(exc),), ())
    distinct = sorted(set(versions.values()))
    version = versions[DAEMON_INIT.as_posix()]
    if len(distinct) != 1:
        listing = ", ".join(f"{name} = {value!r}" for name, value in sorted(versions.items()))
        failures.append(f"the three versions differ: {listing}")
    elif not VERSION_PATTERN.match(version):
        failures.append(f"version {version!r} is not a .devN pre-release (expected e.g. 0.1.0.dev1)")
    else:
        passed.append(f"the three versions are {version}")

    release_tag, dry_run, problems = resolve_tag(
        tag=tag, event=event, ref_type=ref_type, ref_name=ref_name, version=version
    )
    failures.extend(problems)

    if not TAG_PATTERN.match(release_tag):
        failures.append(f"tag {release_tag[:80]!r} does not match {TAG_PATTERN.pattern}")
    elif release_tag != tag_for_version(version):
        failures.append(f"tag {release_tag} does not equal 'v' + the version ({version})")
    else:
        passed.append(f"tag {release_tag} matches the version")

    if not SHA_PATTERN.match(sha):
        failures.append(f"commit {sha[:80]!r} is not a 40-character lowercase hexadecimal SHA")
    elif not REF_PATTERN.match(main_ref):
        failures.append(f"main ref {main_ref[:80]!r} is not a plain revision name")
    else:
        try:
            if is_ancestor(root, sha, main_ref):
                passed.append(f"commit {sha} is reachable from {main_ref}")
            else:
                failures.append(f"commit {sha} is not reachable from {main_ref}; release only reviewed commits on main")
            if TAG_PATTERN.match(release_tag):
                pointed = tag_commit(root, release_tag)
                if pointed is None:
                    if event == "push":
                        failures.append(f"tag {release_tag} does not exist in the checkout")
                elif pointed != sha:
                    failures.append(f"tag {release_tag} points to {pointed}, not to the commit being built ({sha})")
                else:
                    passed.append(f"tag {release_tag} points to {sha}")
        except CheckError as exc:
            failures.append(str(exc))

    if immutable == "true":
        passed.append(f"{IMMUTABLE_VARIABLE} is 'true' (the owner's assertion; publish verifies it)")
    else:
        failures.append(
            f"repository variable {IMMUTABLE_VARIABLE} must be 'true' (got {immutable!r}): enable immutable "
            "releases in the repository settings first, then set the variable (Spec 006 section 11.2)"
        )

    return Result(release_tag, version, dry_run, tuple(failures), tuple(passed))


def write_github_output(path: Path, result: Result) -> None:
    """Append ``tag``, ``version`` and ``dry_run`` for later jobs. Only validated values are written."""
    if not (TAG_PATTERN.match(result.tag) and VERSION_PATTERN.match(result.version)):
        raise CheckError("refusing to write unvalidated outputs")
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"tag={result.tag}\nversion={result.version}\ndry_run={'true' if result.dry_run else 'false'}\n")


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="release_check.py", description="Pre-flight checks for a lab pre-release.")
    parser.add_argument("--sha", required=True, help="the commit being released (40 hex)")
    parser.add_argument("--tag", help="the release tag; omit in the workflow and pass --event/--ref-type/--ref-name")
    parser.add_argument("--event", help="GITHUB_EVENT_NAME (push or workflow_dispatch)")
    parser.add_argument("--ref-type", help="GITHUB_REF_TYPE (tag or branch)")
    parser.add_argument("--ref-name", help="GITHUB_REF_NAME")
    parser.add_argument("--main-ref", default=DEFAULT_MAIN_REF, help="the reviewed branch (default: %(default)s)")
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="repository root (default: this checkout)")
    parser.add_argument("--github-output", type=Path, help="append tag, version and dry_run to this file")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="release_check: %(levelname)s %(message)s", stream=sys.stderr)
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.tag is None and args.event is None:
        LOG.error("give --tag, or --event, --ref-type and --ref-name as the workflow does")
        return 2
    result = run_checks(
        args.root,
        sha=args.sha,
        tag=args.tag,
        event=args.event,
        ref_type=args.ref_type,
        ref_name=args.ref_name,
        main_ref=args.main_ref,
        immutable=os.environ.get(IMMUTABLE_VARIABLE),
    )
    for line in result.passed:
        print(f"ok: {line}")
    for line in result.failures:
        print(f"FAILED: {line}")
    if not result.ok:
        LOG.error("%d release check(s) failed; nothing will be built or published", len(result.failures))
        return 1
    print(f"release {result.tag}{' (dry run: nothing is published)' if result.dry_run else ''}: all checks passed")
    if args.github_output is not None:
        try:
            write_github_output(args.github_output, result)
        except (OSError, CheckError) as exc:
            LOG.error("cannot write the job outputs to %s: %s", args.github_output, exc)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
