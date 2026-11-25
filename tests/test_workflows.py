"""The GitHub Actions workflows keep their safety rules (Spec 006 sections 11.3 and 11.4; AC-006-39).

Two layers. The text checks always run, with no third-party package: every ``uses:`` is pinned to a
40-hex commit SHA with its version as a comment, the same action has the same pin in both files, no
``run:`` script contains ``${{ }}`` (values reach scripts through ``env:``) and every variable a
script expands is inside double quotes, every checkout sets ``persist-credentials: false``, and
release.yml has workflow permissions ``{}`` and no cache. The structural checks parse the YAML and
need PyYAML: they skip without it, and fail instead when ``JWICKET_REQUIRE_YAML=1`` (CI's
install-test job). They pin the release workflow's triggers, per-job grants, job graph, the exact
``attest`` and ``publish`` conditions, the draft-publish-verify-delete sequence, and that a manual
run never publishes; that ``test`` and ``rebuild`` run on Python 3.7 (the SRX's, on ubuntu-22.04), 3.9
and 3.13; and that ci.yml keeps main's jobs (its 3.7 test job included), adds the installer jobs and
reproduces the release assets on the same interpreters.

actionlint itself runs in CI's actionlint job and through ``make actionlint``.
"""

from __future__ import annotations

import itertools
import os
import re
import unittest
from pathlib import Path
from typing import Any, Dict, List, Mapping, Set, Tuple

try:
    import yaml
except ImportError:  # PyYAML is optional here; see JWICKET_REQUIRE_YAML
    yaml = None

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO / ".github" / "workflows"
RELEASE = WORKFLOWS / "release.yml"
CI = WORKFLOWS / "ci.yml"
REQUIRE_YAML = os.environ.get("JWICKET_REQUIRE_YAML") == "1"

USES_LINE = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<value>.*?)\s*$")
PINNED = re.compile(r"^(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@(?P<sha>[0-9a-f]{40}) # v\d+\.\d+\.\d+$")
RUN_LINE = re.compile(r"^(?P<indent>\s*)(?P<dash>-\s+)?run:\s*(?P<rest>.*?)\s*$")
BLOCK_INDICATORS = {"|", "|-", "|+", ">", ">-", ">+"}

ATTEST_IF = "${{ !github.event.repository.private || vars.JWICKET_ATTEST == 'true' }}"
PUBLISH_IF = (
    "${{ !cancelled() && github.event_name == 'push' && needs.build.result == 'success' && "
    "needs.rebuild.result == 'success' && (needs.attest.result == 'success' || "
    "(needs.attest.result == 'skipped' && github.event.repository.private)) }}"
)
RELEASE_PERMISSIONS: Dict[str, Dict[str, str]] = {
    "verify": {"contents": "read"},
    "test": {"contents": "read"},
    "build": {"contents": "read"},
    "rebuild": {"contents": "read"},
    "attest": {"contents": "read", "id-token": "write", "attestations": "write"},
    "publish": {"contents": "write"},
}
RELEASE_NEEDS: Dict[str, Tuple[str, ...]] = {
    "verify": (),
    "test": ("verify",),
    "build": ("verify", "test"),
    "rebuild": ("verify", "build"),
    "attest": ("build", "rebuild"),
    "publish": ("verify", "build", "rebuild", "attest"),
}
CI_EXISTING_JOBS = ("lint", "test", "js", "bundle")
CI_NEW_JOBS = ("install-test", "install-autospec", "ansible", "actionlint", "container", "reproduce")
# (Python, runner) of release.yml's test and rebuild jobs. 3.7 is the SRX's Python (Junos 25.2R1-S1.4,
# verified on a lab SRX4100); setup-python has no 3.7 for ubuntu-24.04, so it runs on ubuntu-22.04.
RELEASE_PYTHONS = {("3.7", "ubuntu-22.04"), ("3.9", "ubuntu-24.04"), ("3.13", "ubuntu-24.04")}
# ci.yml's test job, as main has it (#6).
CI_TEST_PYTHONS = {("3.7", "ubuntu-22.04"), ("3.9", "ubuntu-24.04"), ("3.11", "ubuntu-24.04"), ("3.13", "ubuntu-24.04")}
# The interpreter release.yml's build job uses; reproduce compares every other build with its.
BUILD_PYTHON = "3.12"


# --- text helpers (no YAML library) --------------------------------------------------------------


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def uses_values(text: str) -> List[str]:
    values = []
    for line in text.splitlines():
        match = USES_LINE.match(line)
        if match:
            values.append(match.group("value"))
    return values


def run_blocks(text: str) -> List[Tuple[int, str]]:
    """``(line number, script)`` for every ``run:`` value: block scalars and plain one-line values."""
    lines = text.splitlines()
    blocks: List[Tuple[int, str]] = []
    index = 0
    while index < len(lines):
        match = RUN_LINE.match(lines[index])
        if not match:
            index += 1
            continue
        key_column = len(match.group("indent")) + len(match.group("dash") or "")
        rest = match.group("rest")
        if not rest:  # "defaults: run:", a mapping, not a script
            index += 1
            continue
        if rest in BLOCK_INDICATORS:
            body = []
            following = index + 1
            while following < len(lines):
                line = lines[following]
                if line.strip() and len(line) - len(line.lstrip(" ")) <= key_column:
                    break
                body.append(line)
                following += 1
            blocks.append((index + 1, "\n".join(body).strip("\n")))
            index = following
        else:
            blocks.append((index + 1, rest))
            index += 1
    return blocks


def without_strings(script: str) -> str:
    """The script with its quoted strings emptied, so text inside an echo is not mistaken for a command."""
    return re.sub(r"'[^']*'", "''", re.sub(r'"(?:[^"\\]|\\.)*"', '""', script))


def unquoted_expansions(script: str) -> List[str]:
    """Parameter expansions (``$NAME``, ``${NAME}``) that are not inside double quotes.

    A small shell lexer: single quotes, double quotes, backslashes, comments and ``$( ... )`` (whose
    inside is a fresh quoting context) are followed; ``$?``, ``$#`` and positional parameters are
    ignored. It is deliberately strict: a script that confuses it should be rewritten more plainly.
    """
    found: List[str] = []
    stack: List[List[Any]] = [["code", 0]]  # context, parenthesis depth inside $( )
    i, n = 0, len(script)
    while i < n:
        char = script[i]
        nxt = script[i + 1] if i + 1 < n else ""
        context = stack[-1][0]
        if char == "\\":
            i += 2
            continue
        if context in ("code", "cmd"):
            if char == "#" and (i == 0 or script[i - 1] in " \t\n;"):
                end = script.find("\n", i)
                i = n if end < 0 else end
                continue
            if char == "'":
                end = script.find("'", i + 1)
                i = n if end < 0 else end + 1
                continue
            if char == '"':
                stack.append(["dq", 0])
            elif char == "$" and nxt == "(":
                stack.append(["cmd", 0])
                i += 2
                continue
            elif char == "$" and (nxt.isalpha() or nxt in "_{"):
                match = re.match(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)", script[i:])
                found.append(match.group(1) if match else script[i : i + 10])
            elif context == "cmd" and char == "(":
                stack[-1][1] += 1
            elif context == "cmd" and char == ")":
                if stack[-1][1]:
                    stack[-1][1] -= 1
                else:
                    stack.pop()
        else:  # inside double quotes
            if char == '"':
                stack.pop()
            elif char == "$" and nxt == "(":
                stack.append(["cmd", 0])
                i += 2
                continue
        i += 1
    return found


class ShellLexerTests(unittest.TestCase):
    """The lexer above, on the shapes the workflows use."""

    def test_quoted_expansions_pass(self) -> None:
        for script in (
            'python tools/bundle.py --out "$RUNNER_TEMP/jwicket.py"',
            'epoch=$(git log -1 --format=%ct "$SOURCE_REF")',
            "actual=$(sha256sum SHA256SUMS | cut -d ' ' -f 1)",
            'version="${RELEASE_TAG#v}"',
            "echo '$NOT_EXPANDED'  # $NOR_THIS",
            'if timeout 120 "$@"; then return 0; fi',
            'echo "a $(printf "%s" "$X") b"',
        ):
            with self.subTest(script=script):
                self.assertEqual(unquoted_expansions(script), [])

    def test_unquoted_expansions_are_found(self) -> None:
        self.assertEqual(unquoted_expansions("gh release create $RELEASE_TAG"), ["RELEASE_TAG"])
        self.assertEqual(unquoted_expansions("cd ${RUNNER_TEMP}/x"), ["RUNNER_TEMP"])
        self.assertEqual(unquoted_expansions("x=$(echo $Y)"), ["Y"])


class TextChecks(unittest.TestCase):
    """Run without PyYAML."""

    def test_every_action_is_pinned_by_commit_sha_with_its_version(self) -> None:
        pins: Dict[str, str] = {}
        for path in (RELEASE, CI):
            values = uses_values(read(path))
            self.assertTrue(values, path.name)
            for value in values:
                with self.subTest(workflow=path.name, uses=value):
                    match = PINNED.match(value)
                    self.assertIsNotNone(match, f"{value!r} is not owner/repo@<40 hex> # vX.Y.Z")
                    assert match is not None
                    action, sha = match.group("action"), match.group("sha")
                    self.assertEqual(pins.setdefault(action, sha), sha, f"{action} is pinned to two commits")

    def test_no_run_script_interpolates_an_expression(self) -> None:
        for path in (RELEASE, CI):
            blocks = run_blocks(read(path))
            self.assertTrue(blocks, path.name)
            for line, script in blocks:
                with self.subTest(workflow=path.name, line=line):
                    self.assertNotIn("${{", script)

    def test_every_expansion_in_a_script_is_double_quoted(self) -> None:
        for path in (RELEASE, CI):
            for line, script in run_blocks(read(path)):
                with self.subTest(workflow=path.name, line=line):
                    self.assertEqual(unquoted_expansions(script), [], script)

    def test_every_checkout_drops_its_credentials(self) -> None:
        for path in (RELEASE, CI):
            text = read(path)
            checkouts = sum(1 for v in uses_values(text) if v.startswith("actions/checkout@"))
            dropped = len(re.findall(r"^\s*persist-credentials: false\s*$", text, re.MULTILINE))
            with self.subTest(workflow=path.name):
                self.assertGreater(checkouts, 0)
                self.assertEqual(checkouts, dropped)
                self.assertNotRegex(text, r"persist-credentials:\s*true")

    def test_release_has_no_cache_and_no_workflow_permissions(self) -> None:
        text = read(RELEASE)
        self.assertRegex(text, r"(?m)^permissions: \{\}$")
        self.assertNotRegex(text, r"(?m)^\s*(cache|cache-dependency-path|package-manager-cache):")
        self.assertNotIn("actions/cache", text)

    def test_no_dangerous_trigger_secret_or_floating_reference(self) -> None:
        for path in (RELEASE, CI):
            text = read(path)
            with self.subTest(workflow=path.name):
                for forbidden in (
                    "pull_request_target",
                    "workflow_run",
                    "secrets.",
                    ":latest",
                    "privileged",
                    "docker push",
                    "docker login",
                    "github.head_ref",
                    "github.event.pull_request",
                ):
                    self.assertNotIn(forbidden, text)

    def test_only_publish_writes_a_release(self) -> None:
        text = read(RELEASE)
        publish_line = text.splitlines().index("  publish:") + 1
        writers = [
            line
            for line, script in run_blocks(text)
            if re.search(r"gh api --method (POST|PATCH|DELETE)|curl --disable", without_strings(script))
        ]
        self.assertTrue(writers)
        for line in writers:
            with self.subTest(line=line):
                self.assertGreater(line, publish_line, "a job before publish writes a release")
        self.assertNotRegex(read(CI), r"gh release")


# --- structural checks (PyYAML) ------------------------------------------------------------------


def load_workflow(path: Path) -> Dict[str, Any]:
    if yaml is None:
        if REQUIRE_YAML:
            raise AssertionError("PyYAML is required for the workflow checks (JWICKET_REQUIRE_YAML=1)")
        raise unittest.SkipTest("PyYAML is not installed; the structural workflow checks are skipped")
    data = yaml.safe_load(read(path))
    assert isinstance(data, dict)
    # YAML 1.1 reads the key "on" as the boolean True.
    if True in data:
        data["on"] = data.pop(True)
    return data


def steps(job: Mapping[str, Any]) -> List[Dict[str, Any]]:
    return list(job.get("steps", []))


def step_named(job: Mapping[str, Any], fragment: str) -> Dict[str, Any]:
    for step in steps(job):
        if fragment in str(step.get("name", "")):
            return step
    raise AssertionError(f"no step whose name contains {fragment!r}")


def uses_of(job: Mapping[str, Any], action: str) -> List[Dict[str, Any]]:
    return [s for s in steps(job) if str(s.get("uses", "")).startswith(f"{action}@")]


def needs_of(job: Mapping[str, Any]) -> Tuple[str, ...]:
    needs = job.get("needs", ())
    return (needs,) if isinstance(needs, str) else tuple(needs)


def all_runs(workflow: Mapping[str, Any]) -> List[str]:
    return [str(s["run"]) for job in workflow["jobs"].values() for s in steps(job) if "run" in s]


def matrix_combinations(job: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """The combinations a job's ``strategy.matrix`` runs, by GitHub's rules: the product of the keys, minus
    each ``exclude`` match, then each ``include`` added to every combination whose original values it
    does not overwrite, or appended as a combination of its own when it fits none."""
    matrix = dict((job.get("strategy") or {}).get("matrix") or {})
    keys = [k for k in matrix if k not in ("include", "exclude")]
    combos = [dict(zip(keys, values)) for values in itertools.product(*(matrix[k] for k in keys))]
    for excluded in matrix.get("exclude") or []:
        combos = [c for c in combos if not all(c.get(k) == v for k, v in excluded.items())]
    for included in matrix.get("include") or []:
        fits = [c for c in combos if all(c[k] == v for k, v in included.items() if k in keys)]
        for combo in fits:
            combo.update(included)
        if not fits:
            combos.append(dict(included))
    return combos


def python_runners(job: Mapping[str, Any]) -> Set[Tuple[str, str]]:
    """``{(python, runner)}`` of a job whose ``runs-on`` is ``${{ matrix.os }}``."""
    return {(str(c["python"]), str(c["os"])) for c in matrix_combinations(job)}


class MatrixHelperTests(unittest.TestCase):
    def test_exclude_then_include_adds_a_combination_back_on_another_runner(self) -> None:
        job = {
            "strategy": {
                "matrix": {
                    "python": ["3.7", "3.9"],
                    "os": ["ubuntu-24.04"],
                    "exclude": [{"python": "3.7", "os": "ubuntu-24.04"}],
                    "include": [{"python": "3.7", "os": "ubuntu-22.04"}],
                }
            }
        }
        self.assertEqual(python_runners(job), {("3.7", "ubuntu-22.04"), ("3.9", "ubuntu-24.04")})


class Python37RunnerTests(unittest.TestCase):
    """Every job that sets up Python 3.7 runs on ubuntu-22.04: setup-python has no 3.7 for ubuntu-24.04."""

    def test_python_3_7_only_on_ubuntu_22_04(self) -> None:
        found = 0
        for path in (RELEASE, CI):
            for name, job in load_workflow(path)["jobs"].items():
                for step in uses_of(job, "actions/setup-python"):
                    requested = str(step["with"]["python-version"])
                    if requested == "${{ matrix.python }}":
                        runners = {r for p, r in python_runners(job) if p == "3.7"}
                    elif "3.7" in requested.split():
                        runners = {str(job["runs-on"])}
                    else:
                        continue
                    found += 1
                    with self.subTest(workflow=path.name, job=name):
                        self.assertEqual(runners, {"ubuntu-22.04"})
        self.assertEqual(found, 4, "ci.yml test and reproduce, release.yml test and rebuild")


class ReleaseWorkflowTests(unittest.TestCase):
    workflow: Dict[str, Any]

    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = load_workflow(RELEASE)
        cls.jobs = cls.workflow["jobs"]

    def test_triggers_are_dev_tags_and_a_manual_dry_run(self) -> None:
        self.assertEqual(self.workflow["on"], {"push": {"tags": ["v*.*.*.dev*"]}, "workflow_dispatch": None})

    def test_workflow_permissions_are_empty_and_each_job_grants_its_own(self) -> None:
        self.assertEqual(self.workflow["permissions"], {})
        self.assertEqual(set(self.jobs), set(RELEASE_PERMISSIONS))
        for name, expected in RELEASE_PERMISSIONS.items():
            with self.subTest(job=name):
                self.assertEqual(self.jobs[name]["permissions"], expected)

    def test_the_job_graph(self) -> None:
        for name, expected in RELEASE_NEEDS.items():
            with self.subTest(job=name):
                self.assertEqual(needs_of(self.jobs[name]), expected)

    def test_concurrency_waits_and_never_cancels(self) -> None:
        expected = {"group": "release-${{ github.ref }}", "cancel-in-progress": False}
        self.assertEqual(self.workflow["concurrency"], expected)

    def test_every_job_has_a_timeout(self) -> None:
        for name, job in self.jobs.items():
            with self.subTest(job=name):
                self.assertIsInstance(job.get("timeout-minutes"), int)
                self.assertTrue(1 <= job["timeout-minutes"] <= 60)

    def test_checkouts_build_the_triggering_commit_without_credentials(self) -> None:
        for name, job in self.jobs.items():
            for step in uses_of(job, "actions/checkout"):
                with self.subTest(job=name):
                    self.assertIs(step["with"]["persist-credentials"], False)
                    self.assertEqual(step["with"]["ref"], "${{ github.sha }}")
        self.assertEqual(uses_of(self.jobs["publish"], "actions/checkout"), [])
        self.assertEqual(uses_of(self.jobs["attest"], "actions/checkout"), [])
        self.assertEqual(uses_of(self.jobs["verify"], "actions/checkout")[0]["with"]["fetch-depth"], 0)

    def test_no_cache_anywhere(self) -> None:
        for name, job in self.jobs.items():
            for step in steps(job):
                with self.subTest(job=name, step=step.get("name") or step.get("uses")):
                    self.assertNotIn("actions/cache", str(step.get("uses", "")))
                    self.assertFalse({"cache", "cache-dependency-path"} & set(step.get("with") or {}))

    def test_test_and_rebuild_cover_the_srx_python_and_the_newest(self) -> None:
        # The bundle and the op script run on the box's Python 3.7: the unit tests must pass there and
        # the four assets must rebuild byte for byte there (Spec 006 revision R1).
        for name in ("test", "rebuild"):
            with self.subTest(job=name):
                job = self.jobs[name]
                self.assertEqual(job["runs-on"], "${{ matrix.os }}")
                self.assertEqual(python_runners(job), RELEASE_PYTHONS)
                setup = uses_of(job, "actions/setup-python")[0]["with"]
                self.assertEqual(setup["python-version"], "${{ matrix.python }}")

    def test_build_runs_on_the_python_reproduce_compares_with(self) -> None:
        setup = uses_of(self.jobs["build"], "actions/setup-python")[0]["with"]
        self.assertEqual(setup["python-version"], BUILD_PYTHON)

    def test_the_release_notes_name_the_rebuild_pythons(self) -> None:
        template = (REPO / ".github" / "release-notes-lab-only.md").read_text(encoding="utf-8")
        pythons = sorted(
            {p for p, _ in python_runners(self.jobs["rebuild"])}, key=lambda v: tuple(int(n) for n in v.split("."))
        )
        self.assertEqual(pythons, ["3.7", "3.9", "3.13"])
        self.assertIn("rebuilt byte for byte on Python 3.7 (the SRX's), 3.9 and 3.13", template)
        self.assertIn("Python 3.7 or later, from a clone of the repository", template)

    def test_rebuild_runs_the_builds_of_build(self) -> None:
        rebuild = step_named(self.jobs["rebuild"], "Rebuild the four assets")["run"]
        for fragment in (
            'python tools/bundle.py --out "$out/jwicket.py" --source-ref "$SOURCE_REF"',
            "python -m jwicket_install.build_op",
            'python tools/build_wheel.py --out "$out" --source-date-epoch "$epoch"',
        ):
            self.assertIn(fragment, rebuild)

    def test_verify_runs_release_check_with_the_owner_assertion(self) -> None:
        step = step_named(self.jobs["verify"], "Release checks")
        self.assertEqual(step["env"], {"JWICKET_IMMUTABLE_RELEASES": "${{ vars.JWICKET_IMMUTABLE_RELEASES }}"})
        for fragment in (
            "tools/release_check.py",
            '--ref-name "$GITHUB_REF_NAME"',
            '--sha "$GITHUB_SHA"',
            '--github-output "$GITHUB_OUTPUT"',
        ):
            self.assertIn(fragment, step["run"])
        outputs = self.jobs["verify"]["outputs"]
        self.assertEqual(outputs["tag"], "${{ steps.check.outputs.tag }}")

    def test_build_makes_every_asset_reproducibly(self) -> None:
        runs = "\n".join(str(s.get("run", "")) for s in steps(self.jobs["build"]))
        for fragment in (
            'tools/bundle.py --out dist/jwicket.py --source-ref "$SOURCE_REF"',
            'tools/bundle.py --out dist/jwicket.py --source-ref "$SOURCE_REF" --check',
            'python -I "$GITHUB_WORKSPACE/dist/jwicket.py" --bundle-self-test',
            "jwicket_selftest.py",
            "python -I jwicket_selftest.py",
            "python -m jwicket_install.build_op",
            "--out dist/jwicket-install-op.py",
            'tools/build_wheel.py --out dist --source-date-epoch "$epoch"',
            "cp requirements-install.txt dist/requirements-install.txt",
            "sha256sum jwicket.py jwicket-install-op.py jwicket_install-*.whl requirements-install.txt > SHA256SUMS",
            "tools/release_record.py notes",
        ):
            self.assertIn(fragment, runs)
        upload = uses_of(self.jobs["build"], "actions/upload-artifact")[0]["with"]
        self.assertEqual(upload["retention-days"], 7)
        self.assertEqual(upload["if-no-files-found"], "error")
        self.assertEqual(self.jobs["build"]["env"]["SOURCE_REF"], "${{ github.sha }}")

    def test_rebuild_requires_builds_hashes(self) -> None:
        job = self.jobs["rebuild"]
        self.assertEqual(job["env"]["EXPECTED_SUMS_SHA256"], "${{ needs.build.outputs.sums_sha256 }}")
        compare = step_named(job, "Compare with build")["run"]
        self.assertIn('[ "$actual" != "$EXPECTED_SUMS_SHA256" ]', compare)
        self.assertIn("exit 1", compare)

    def test_attest_runs_whenever_the_repository_is_public(self) -> None:
        job = self.jobs["attest"]
        self.assertEqual(job["if"], ATTEST_IF)
        attest = uses_of(job, "actions/attest")[0]["with"]
        self.assertEqual(attest["subject-checksums"], "dist/SHA256SUMS")
        self.assertIn("sha256sum -c SHA256SUMS", step_named(job, "Check the downloaded assets")["run"])

    def test_publish_has_exactly_the_specified_condition_and_environment(self) -> None:
        job = self.jobs["publish"]
        self.assertEqual(job["if"], PUBLISH_IF)
        self.assertEqual(job["environment"], "lab-prerelease")
        self.assertIn("github.event_name == 'push'", job["if"])

    def test_a_manual_run_never_publishes(self) -> None:
        # publish is the only job that can write, and its condition requires a push event.
        writers = [n for n, j in self.jobs.items() if "write" in (j.get("permissions") or {}).get("contents", "")]
        self.assertEqual(writers, ["publish"])
        self.assertTrue(self.jobs["publish"]["if"].startswith("${{ !cancelled() && github.event_name == 'push' &&"))

    def test_publish_creates_a_draft_then_publishes_verifies_or_deletes_by_id(self) -> None:
        job = self.jobs["publish"]
        check = step_named(job, "Check the tag and the assets")["run"]
        self.assertIn('[ "$RELEASE_TAG" != "$GITHUB_REF_NAME" ]', check)
        self.assertIn("sha256sum -c SHA256SUMS", check)
        create = step_named(job, "Create the pre-release as a draft")
        self.assertNotIn("if", create)
        self.assertEqual(create["id"], "draft")
        script = create["run"]
        self.assertLess(script.index("all(.[][]; .tag_name != $tag)"), script.index("--method POST"))
        self.assertIn('draft: true, prerelease: true, make_latest: "false"', script)
        self.assertIn('printf \'release_id=%s\\n\' "$release_id" >> "$GITHUB_OUTPUT"', script)
        upload = step_named(job, "Upload and check assets")
        self.assertIn("/releases/$RELEASE_ID/assets?name=$asset", upload["run"])
        self.assertIn(".digest == $digest", upload["run"])
        verify = step_named(job, "Publish, then verify")
        self.assertEqual(verify["if"], "${{ needs.attest.result == 'success' }}")
        script = verify["run"]
        order = [
            script.index(s)
            for s in (
                'release="$repo/releases/$RELEASE_ID"',
                '--method PATCH "$release"',
                '[[ "$actual_id" == "$RELEASE_ID" ]]',
                'gh release verify "$RELEASE_TAG"',
                "gh release verify-asset",
            )
        ]
        self.assertEqual(order, sorted(order))
        self.assertIn('[[ "$live_immutable" == true ]]', script)
        cleanup = step_named(job, "Clean up only the release")
        self.assertIn("failure() && steps.draft.outputs.release_id != ''", cleanup["if"])
        self.assertIn('--method DELETE "repos/$GITHUB_REPOSITORY/releases/$RELEASE_ID"', cleanup["run"])
        for step in (upload, verify, cleanup):
            self.assertEqual(step["env"]["RELEASE_ID"], "${{ steps.draft.outputs.release_id }}")
        self.assertNotRegex(read(RELEASE), r"gh release (create|edit|delete|upload)")
        draft = step_named(job, "leave the draft for the owner")
        self.assertEqual(draft["if"], "${{ needs.attest.result == 'skipped' }}")
        self.assertNotIn("gh release", without_strings(draft["run"]))

    def test_the_token_reaches_only_the_steps_that_run_gh(self) -> None:
        for name, job in self.jobs.items():
            self.assertNotIn("GH_TOKEN", job.get("env") or {}, name)
            for step in steps(job):
                script = str(step.get("run", ""))
                uses_gh = "gh release" in without_strings(script) or "gh api" in script or "curl --disable" in script
                token = (step.get("env") or {}).get("GH_TOKEN")
                with self.subTest(job=name, step=step.get("name")):
                    if uses_gh:
                        self.assertEqual(token, "${{ github.token }}")
                    else:
                        self.assertIsNone(token)

    def test_event_fields_never_reach_env_or_inputs(self) -> None:
        for name, job in self.jobs.items():
            values = [str(v) for v in (job.get("env") or {}).values()]
            for step in steps(job):
                values += [str(v) for v in (step.get("env") or {}).values()]
                values += [str(v) for v in (step.get("with") or {}).values()]
            for value in values:
                with self.subTest(job=name, value=value):
                    self.assertNotIn("github.event.", value)
                    self.assertNotIn("github.ref_name", value)

    def test_text_and_yaml_see_the_same_run_scripts(self) -> None:
        def norm(s: str) -> str:
            return " ".join(s.split())

        self.assertEqual([norm(s) for _, s in run_blocks(read(RELEASE))], [norm(s) for s in all_runs(self.workflow)])


class CiWorkflowTests(unittest.TestCase):
    workflow: Dict[str, Any]

    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = load_workflow(CI)
        cls.jobs = cls.workflow["jobs"]

    def test_existing_jobs_are_kept_and_the_installer_jobs_added(self) -> None:
        self.assertEqual(set(self.jobs), set(CI_EXISTING_JOBS) | set(CI_NEW_JOBS))
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        self.assertEqual(self.jobs["test"]["runs-on"], "${{ matrix.os }}")
        self.assertEqual(python_runners(self.jobs["test"]), CI_TEST_PYTHONS)
        self.assertEqual(needs_of(self.jobs["bundle"]), ("lint", "test", "js"))

    def test_reproduce_builds_the_release_assets_on_builds_and_rebuilds_pythons(self) -> None:
        job = self.jobs["reproduce"]
        self.assertEqual(job["runs-on"], "ubuntu-22.04")  # the only runner with setup-python's 3.7
        self.assertEqual(job["env"], {"SOURCE_REF": "${{ github.sha }}"})
        self.assertNotIn("permissions", job)  # the workflow's contents: read
        versions = str(uses_of(job, "actions/setup-python")[0]["with"]["python-version"]).split()
        release = {p for p, _ in RELEASE_PYTHONS}
        self.assertEqual(set(versions), release | {BUILD_PYTHON})
        script = step_named(job, "Build the four assets with each Python")["run"]
        loop = re.search(r"for python in ([^;]+); do", script)
        self.assertIsNotNone(loop, script)
        assert loop is not None
        order = loop.group(1).split()
        self.assertEqual(order[0], f"python{BUILD_PYTHON}", "the reference build is the release build's Python")
        self.assertEqual({name[len("python"):] for name in order}, release | {BUILD_PYTHON})
        for fragment in (
            '"$python" tools/bundle.py --out "$out/jwicket.py" --source-ref "$SOURCE_REF"',
            '"$python" -m jwicket_install.build_op',
            '"$python" tools/build_wheel.py --out "$out" --source-date-epoch "$epoch"',
            "sha256sum jwicket.py jwicket-install-op.py jwicket_install-*.whl requirements-install.txt > SHA256SUMS",
            'cmp -s "$first" "$out/SHA256SUMS"',
            "exit 1",
        ):
            self.assertIn(fragment, script)

    def test_no_job_grants_more(self) -> None:
        for name, job in self.jobs.items():
            with self.subTest(job=name):
                self.assertNotIn("write", str(job.get("permissions", "")))

    def test_every_job_has_a_timeout_and_every_checkout_drops_credentials(self) -> None:
        for name, job in self.jobs.items():
            with self.subTest(job=name):
                self.assertIsInstance(job.get("timeout-minutes"), int)
                for step in uses_of(job, "actions/checkout"):
                    self.assertIs(step["with"]["persist-credentials"], False)

    def test_the_unit_test_command_is_unchanged(self) -> None:
        for name in ("test", "install-test", "install-autospec"):
            with self.subTest(job=name):
                step = step_named(self.jobs[name], "Unit tests")
                self.assertEqual(step["run"], "python -m unittest discover -s tests -v")
                self.assertEqual(step["env"], {"PYTHONPATH": "src"})

    def test_install_test_requires_yaml_installed_by_hash(self) -> None:
        job = self.jobs["install-test"]
        self.assertEqual(job["env"]["JWICKET_REQUIRE_YAML"], "1")
        install = step_named(job, "Install PyYAML")["run"]
        self.assertRegex(install, r"PyYAML==\d+\.\d+\.\d+ --hash=sha256:[0-9a-f]{64}")
        self.assertIn("--require-hashes", install)

    def test_install_autospec_requires_pyez_installed_by_hash(self) -> None:
        job = self.jobs["install-autospec"]
        self.assertEqual(job["env"]["JWICKET_REQUIRE_PYEZ"], "1")
        self.assertIn("--require-hashes -r requirements-install.txt", step_named(job, "hash-pinned")["run"])

    def test_ansible_checks_syntax_with_hash_pinned_tools(self) -> None:
        job = self.jobs["ansible"]
        self.assertIn("--require-hashes -r deploy/ansible/requirements-ansible.txt", step_named(job, "Install")["run"])
        check = step_named(job, "syntax-check")
        self.assertEqual(check["working-directory"], "deploy/ansible")
        self.assertIn("ansible-playbook --syntax-check", check["run"])
        self.assertEqual(job["env"]["JWICKET_REQUIRE_YAML"], "1")

    def test_actionlint_is_pinned_by_version_and_hash(self) -> None:
        job = self.jobs["actionlint"]
        self.assertRegex(job["env"]["ACTIONLINT_VERSION"], r"^\d+\.\d+\.\d+$")
        self.assertRegex(job["env"]["ACTIONLINT_SHA256"], r"^[0-9a-f]{64}$")
        download = step_named(job, "Download actionlint")["run"]
        self.assertIn("sha256sum -c -", download)
        self.assertIn('--proto "=https"', download)
        lint = step_named(job, "actionlint (")["run"]
        self.assertIn(".github/workflows/ci.yml .github/workflows/release.yml", lint)

    def test_the_container_is_built_locally_and_never_pushed(self) -> None:
        job = self.jobs["container"]
        build = step_named(job, "docker build")
        self.assertEqual(build["if"], "${{ steps.present.outputs.build == 'true' }}")
        self.assertNotIn("push", build["run"])
        self.assertIn("make container-context LOCAL=1", step_named(job, "Build context")["run"])

    def test_setup_node_keeps_no_cache(self) -> None:
        node = uses_of(self.jobs["js"], "actions/setup-node")[0]["with"]
        self.assertIs(node["package-manager-cache"], False)

    def test_text_and_yaml_see_the_same_run_scripts(self) -> None:
        def norm(s: str) -> str:
            return " ".join(s.split())

        self.assertEqual([norm(s) for _, s in run_blocks(read(CI))], [norm(s) for s in all_runs(self.workflow)])


if __name__ == "__main__":
    unittest.main()
