"""The container image (M3) keeps its contract (Spec 006 section 6.4; AC-006-34).

These are text and unit checks; they never run Docker (the CI ``container`` job builds the image).

* The Dockerfile: every stage from ``python:3.12-slim`` pinned by one digest, no build argument that
  could change the base, ``pip install --require-hashes`` everywhere (wheels only for the
  dependencies; the installer wheel by the hash in ``SHA256SUMS``, checked first), copies only from
  the allowlisted context files, no ``ADD`` and no ``VOLUME``, a non-root final user, and an
  isolated (``-I``) entry point that is the file this test imports.
* ``.dockerignore``: an allowlist of the Dockerfile, the entry point and the three ``build/`` files.
  Its matching is emulated here with Docker's documented rule (a pattern matches a path or one of
  its parent directories, ``*`` never crosses ``/``, the last matching line decides); the CI image
  build is the real check.
* ``entrypoint.py``: refuses uid 0; refuses ``open``, whose forward the browser cannot reach from
  inside the container; refuses every command that keeps state, and ``--apply`` and the other writing
  options (and their argparse abbreviations), unless ``/state`` is a mount that outlives the container,
  read from a fake ``mountinfo``; then hands every argument to the installer unchanged (the access and
  hardware options among them) with the state directory forced.
* The names agree with the other packages: ``make container-context`` (``tools/release_record.py``,
  the Makefile, ``.gitignore``) and the wheel's console script (``tools/build_wheel.py``).

Nothing here talks to a device or a network, and it passes as root and as an unprivileged user.
Python 3.7 syntax: CI runs the unit tests on 3.7 (so no parenthesized context managers).
"""

from __future__ import annotations

import fnmatch
import importlib.util
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from typing import Dict, List, Mapping, Optional, Sequence, Tuple
from unittest import mock

import install_support  # noqa: F401 - puts tools/ on sys.path

import build_wheel  # tools/ is on sys.path now
import release_record

REPO = Path(__file__).resolve().parent.parent
CONTAINER = REPO / "deploy" / "container"
DOCKERFILE = CONTAINER / "Dockerfile"
DOCKERIGNORE = CONTAINER / ".dockerignore"
ENTRYPOINT = CONTAINER / "entrypoint.py"
README = CONTAINER / "README.md"

VENV = "/opt/jwicket-install"
ENTRYPOINT_PATH = "/opt/jwicket/entrypoint.py"
WHEEL_GLOB = "build/jwicket_install-*-py3-none-any.whl"
CONTEXT_FILES = ("build/SHA256SUMS", "build/requirements-install.txt", WHEEL_GLOB)
BASE = re.compile(
    r"^python:3\.12(?:\.\d+)?-slim(?:-[a-z]+)?@sha256:(?P<digest>[0-9a-f]{64})(?: AS (?P<stage>[a-z]+))?$"
)
TEST_UID = 4242  # owner given to a temporary state directory when the tests run as root


def load_entrypoint() -> ModuleType:
    spec = importlib.util.spec_from_file_location("jwicket_container_entrypoint", ENTRYPOINT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look the module up while the class is built
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True  # no __pycache__ inside the image's build context
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


ep = load_entrypoint()


def instructions(text: str) -> List[Tuple[str, str]]:
    """The Dockerfile's instructions with continuation lines joined and comment lines dropped."""
    out: List[Tuple[str, str]] = []
    pending = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith("#") or (not stripped and not pending):
            continue
        if stripped.endswith("\\"):
            pending += stripped[:-1].rstrip() + " "
            continue
        line = pending + stripped
        pending = ""
        word, _, rest = line.partition(" ")
        out.append((word.upper(), rest.strip()))
    assert not pending, "the Dockerfile ends inside a continuation"
    return out


def args_of(name: str) -> List[str]:
    return [rest for word, rest in instructions(DOCKERFILE.read_text(encoding="utf-8")) if word == name]


def run_commands() -> List[str]:
    """Every shell command of every RUN, split at ';' and '&&'."""
    commands: List[str] = []
    for run in args_of("RUN"):
        commands.extend(c.strip() for c in re.split(r";|&&", run) if c.strip())
    return commands


def go_match(pattern: str, path: str) -> bool:
    """Go's filepath.Match for the patterns used here: '*' and '?' never match '/'."""
    regex = "".join("[^/]*" if c == "*" else "[^/]" if c == "?" else re.escape(c) for c in pattern)
    return re.fullmatch(regex, path) is not None


def dockerignore_patterns() -> List[str]:
    lines = DOCKERIGNORE.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


def excluded(path: str, patterns: Sequence[str]) -> bool:
    """Docker's rule: a pattern matches a path or a parent directory of it; the last match decides."""
    parts = path.split("/")
    candidates = ["/".join(parts[: i + 1]) for i in range(len(parts))]
    result = False
    for pattern in patterns:
        negated = pattern.startswith("!")
        body = os.path.normpath(pattern[1:] if negated else pattern)
        if any(go_match(body, candidate) for candidate in candidates):
            result = not negated
    return result


def escape(path: str) -> str:
    """A path as /proc/self/mountinfo writes it (proc(5): octal escapes for space, tab, newline, backslash)."""
    return "".join(f"\\{ord(c):03o}" if c in " \t\n\\" else c for c in path)


def mount_line(
    mount_point: str,
    *,
    root: str = "/home/alice/.local/state/jwicket-install",
    options: str = "rw,relatime",
    fs_type: str = "ext4",
    optional: str = "",
) -> str:
    fields = ["1020", "1011", "259:2", escape(root), escape(mount_point), options]
    if optional:
        fields.append(optional)
    fields += ["-", fs_type, "/dev/nvme0n1p2", "rw"]
    return " ".join(fields)


# A container's mountinfo as Docker Engine on Linux writes it (synthetic; the shape is proc(5)'s).
BASE_MOUNTINFO = "\n".join(
    [
        "1011 870 0:120 / / rw,relatime master:345 - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/A,"
        "upperdir=/var/lib/docker/overlay2/1/diff,workdir=/var/lib/docker/overlay2/1/work",
        "1012 1011 0:123 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw",
        "1013 1011 0:124 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64",
        "1016 1011 0:122 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro",
        "1021 1011 259:2 /home/alice/.ssh/known_hosts /home/app/.ssh/known_hosts ro,relatime - ext4 /dev/nvme0n1p2 rw",
        "1022 1011 0:26 /user/1000/jwicket-lab-agent/agent.sock /ssh-agent rw,nosuid,nodev,relatime shared:5 - "
        "tmpfs tmpfs rw,size=1601392k,mode=700,uid=1000,gid=1000,inode64",
        "1023 1011 0:125 / /tmp rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=65536k,inode64",
    ]
)


class DockerfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = DOCKERFILE.read_text(encoding="utf-8")
        self.instructions = instructions(self.text)

    def test_every_stage_starts_from_the_same_digest_pinned_python_312_slim(self) -> None:
        froms = args_of("FROM")
        self.assertEqual(len(froms), 2, froms)
        digests = set()
        for value in froms:
            match = BASE.match(value)
            self.assertIsNotNone(match, f"FROM {value} is not python:3.12-slim pinned by digest")
            assert match is not None
            digests.add(match.group("digest"))
        self.assertEqual(len(digests), 1, "the two stages must use the same base image digest")
        self.assertEqual(BASE.match(froms[0]).group("stage"), "build")  # type: ignore[union-attr]
        self.assertIsNone(BASE.match(froms[-1]).group("stage"))  # type: ignore[union-attr]

    def test_no_build_argument_or_floating_tag_can_change_what_is_pulled(self) -> None:
        self.assertNotIn("ARG", [word for word, _ in self.instructions])
        self.assertNotIn(":latest", self.text)
        for value in args_of("FROM"):
            self.assertNotIn("$", value)
        # The BuildKit syntax directive would pull a frontend image by a floating tag.
        self.assertNotRegex(self.text, r"(?im)^#\s*syntax\s*=")

    def test_the_final_user_is_numeric_and_not_root(self) -> None:
        words = [word for word, _ in self.instructions]
        users = args_of("USER")
        self.assertEqual(users, ["10001:10001"])
        self.assertGreater(len(words) - 1 - words[::-1].index("USER"), len(words) - 1 - words[::-1].index("FROM"))
        self.assertTrue(any("useradd" in c and "--uid 10001" in c and "--gid 10001" in c for c in run_commands()))
        self.assertTrue(any("groupadd" in c and "--gid 10001" in c for c in run_commands()))

    def test_every_pip_install_requires_hashes(self) -> None:
        installs = [c for c in run_commands() if re.search(r"\bpip install\b", c)]
        self.assertEqual(len(installs), 2, installs)
        for command in installs:
            self.assertIn("--require-hashes", command)
            self.assertIn("--no-cache-dir", command)
            for banned in ("--index-url", "--extra-index-url", "--trusted-host", "--find-links", "--pre", "--user"):
                self.assertNotIn(banned, command)
            self.assertNotRegex(command, r"(?:^|\s)(?:-e|--editable)(?:\s|=)")
            self.assertTrue(command.startswith(f"{VENV}/bin/python -m pip install"), command)
        dependencies, wheel = installs
        self.assertIn("--only-binary=:all:", dependencies)
        self.assertIn("-r /tmp/build/requirements-install.txt", dependencies)
        self.assertNotIn("--no-deps", dependencies)  # pip must find every dependency pinned in the file
        self.assertIn("--no-deps", wheel)
        self.assertIn("--no-index", wheel)
        self.assertIn("-r /tmp/wheel-requirement.txt", wheel)

    def test_sha256sums_is_checked_before_anything_is_installed(self) -> None:
        commands = run_commands()
        check = commands.index("sha256sum --check --strict SHA256SUMS")
        first_pip = min(i for i, c in enumerate(commands) if "pip install" in c)
        venv = commands.index(f"python -m venv {VENV}")
        self.assertLess(check, venv)
        self.assertLess(venv, first_pip)
        # The wheel's requirement line is built from SHA256SUMS, after the check, and the file named
        # there must be the one file present.
        printf = next(c for c in commands if c.startswith("printf"))
        self.assertLess(check, commands.index(printf))
        self.assertIn("--hash=sha256:", printf)
        self.assertIn('test "${line#*  }" = "$1"', commands)
        self.assertIn('test "$#" -eq 1', commands)
        self.assertIn('test "$(wc -l < SHA256SUMS)" -eq 2', commands)

    def test_copies_come_only_from_the_allowlisted_context_files(self) -> None:
        self.assertNotIn("ADD", [word for word, _ in self.instructions])
        sources: List[str] = []
        for value in args_of("COPY"):
            parts = value.split()
            if parts[0].startswith("--from="):
                self.assertEqual(parts, ["--from=build", VENV, VENV])
                continue
            self.assertFalse(any(p.startswith("--") for p in parts), value)
            sources.extend(parts[:-1])
        self.assertEqual(sorted(sources), sorted(["entrypoint.py", *CONTEXT_FILES]))

    def test_no_volume_instruction(self) -> None:
        # A VOLUME on /state would give every container an anonymous volume there: a mount point
        # that passes for a state directory and that docker run --rm deletes.
        self.assertNotIn("VOLUME", [word for word, _ in self.instructions])

    def test_the_entry_point_is_this_file_run_isolated(self) -> None:
        entry = json.loads(args_of("ENTRYPOINT")[0])
        self.assertEqual(entry, [f"{VENV}/bin/python", "-I", ENTRYPOINT_PATH])
        self.assertIn(f"entrypoint.py {ENTRYPOINT_PATH}", args_of("COPY"))
        self.assertEqual(json.loads(args_of("CMD")[0]), ["--help"])
        self.assertEqual(ep.INSTALLER_ARGV, (f"{VENV}/bin/python", "-I", f"{VENV}/bin/{build_wheel.CONSOLE_SCRIPT}"))
        self.assertIn(f"test -f {VENV}/bin/{build_wheel.CONSOLE_SCRIPT}", run_commands())

    def test_the_image_has_the_paths_the_entry_point_checks(self) -> None:
        self.assertEqual(ep.STATE_DIR, "/state")
        self.assertTrue(
            any(c.startswith("install -d -m 0700 -o 10001 -g 10001") and c.endswith(" /state") for c in run_commands())
        )
        self.assertIn("HOME=/home/app", args_of("ENV")[0])
        self.assertTrue(ep.KNOWN_HOSTS.startswith("/home/app/.ssh/"))

    def test_nothing_is_downloaded_outside_pip_and_no_secret_is_configured(self) -> None:
        for command in run_commands():
            for tool in ("curl", "wget", "git ", "apt-get", "chmod 777", "chmod -R"):
                self.assertNotIn(tool, command)
        for value in args_of("ENV") + args_of("LABEL"):
            self.assertNotRegex(value.upper(), r"PASSWORD|TOKEN|SECRET|PRIVATE|_KEY\b")


class DockerignoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.patterns = dockerignore_patterns()

    def test_it_is_an_allowlist(self) -> None:
        self.assertEqual(self.patterns[0], "*")
        self.assertEqual(
            sorted(self.patterns[1:]),
            sorted(["!Dockerfile", "!entrypoint.py", *(f"!{f}" for f in CONTEXT_FILES)]),
        )
        for pattern in self.patterns:
            self.assertNotIn("**", pattern)

    def test_only_the_allowlisted_files_enter_the_context(self) -> None:
        wheel = "build/" + release_record.wheel_file("0.1.0.dev1")
        for path in ("Dockerfile", "entrypoint.py", "build/SHA256SUMS", "build/requirements-install.txt", wheel):
            self.assertFalse(excluded(path, self.patterns), path)
        for path in (
            "README.md",
            "jwicket.ini",
            "lab-token",
            "build/jwicket.ini",
            "build/lab-token",
            "build/known_hosts",
            "build/sub/SHA256SUMS",
            f"{wheel}.bak",
            "build/jwicket_install-x/evil-py3-none-any.whl",
            "evidence/2026-11-24/receipt.json",
            ".git/config",
            "state/abc.json",
        ):
            self.assertTrue(excluded(path, self.patterns), path)

    def test_every_copy_source_is_let_in(self) -> None:
        wheel = "build/" + release_record.wheel_file("0.1.0.dev1")
        for source in ("entrypoint.py", *CONTEXT_FILES):
            path = wheel if source == WHEEL_GLOB else source
            self.assertFalse(excluded(path, self.patterns), source)


class ContextNamesTests(unittest.TestCase):
    """The file names agree with what `make container-context` writes (RELEASE package)."""

    def test_names_match_release_record_and_the_wheel_builder(self) -> None:
        self.assertEqual(release_record.SUMS_FILE, "SHA256SUMS")
        self.assertEqual(release_record.REQUIREMENTS_FILE, "requirements-install.txt")
        self.assertTrue(fnmatch.fnmatchcase("build/" + release_record.wheel_file("0.1.0.dev1"), WHEEL_GLOB))
        self.assertEqual(build_wheel.PACKAGE, "jwicket_install")
        self.assertEqual(build_wheel.WHEEL_TAG, "py3-none-any")

    def test_the_entry_point_names_the_installers_own_state_variable(self) -> None:
        from jwicket_install import receipt

        self.assertEqual(ep.STATE_ENV, receipt.STATE_ENV)
        self.assertEqual(receipt.default_state_dir({ep.STATE_ENV: ep.STATE_DIR}), Path(ep.STATE_DIR))
        with self.assertRaises(receipt.StoreError):  # a relative value is refused, not taken from the cwd
            receipt.default_state_dir({ep.STATE_ENV: "state"})

    def test_the_makefile_and_gitignore_use_this_directory(self) -> None:
        makefile = (REPO / "Makefile").read_text(encoding="utf-8")
        self.assertRegex(makefile, r"(?m)^CONTAINER_BUILD \?= deploy/container/build$")
        self.assertRegex(makefile, r"(?m)^container-context:")
        gitignore = (REPO / ".gitignore").read_text(encoding="utf-8").splitlines()
        self.assertIn("deploy/container/build/", gitignore)


class ReadmeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = README.read_text(encoding="utf-8")

    def test_it_says_lab_only_and_unverified(self) -> None:
        self.assertIn("LAB ONLY", self.text)
        self.assertIn("Q-INST-06", self.text)
        self.assertIn("unverified", self.text)

    def test_the_run_command_mounts_state_and_runs_as_the_caller(self) -> None:
        blocks = re.findall(r"```sh\n(.*?)```", self.text, flags=re.S)
        runs = [b for b in blocks if re.search(r"(?m)^docker run ", b)]
        self.assertTrue(runs)
        for block in runs:
            self.assertIn("--rm -it", block)
            self.assertIn('--user "$(id -u):$(id -g)"', block)
            self.assertIn('-v "$HOME/.local/state/jwicket-install:/state"', block)
            self.assertIn('-v "$HOME/.ssh/known_hosts:/home/app/.ssh/known_hosts:ro"', block)
            self.assertNotIn("--privileged", block)
            self.assertNotIn(":latest", block)

    def test_it_states_the_access_modes_and_the_devices_state_directory(self) -> None:
        prose = " ".join(self.text.split())
        self.assertIn("--access tls", self.text)
        self.assertIn("--access tunnel", self.text)
        self.assertIn("--listen-address", self.text)
        self.assertIn("--lab-hardware", self.text)
        self.assertIn("administratively prohibited", self.text)
        self.assertIn("reachable by anything that reaches that address", prose)
        self.assertIn("R-STATEDIR", self.text)
        from jwicket_install import plan

        self.assertIn(plan.STATE_DIR_ROOT_STEP.replace(plan.USER_MARKER, "<account>"), self.text)
        self.assertIn("never written to `/state`", prose)
        self.assertIn("refuses `open`", prose)

    def test_it_asks_for_a_dedicated_agent_with_confirmation(self) -> None:
        self.assertIn("ssh-add -c", self.text)
        self.assertIn("ssh-agent -s -a", self.text)
        self.assertIn("ssh-askpass", self.text)
        self.assertIn("every key the agent holds", self.text)
        self.assertRegex(self.text, r"macOS[^.]*\*\*unknown\*\*")


class GuardedOptionTests(unittest.TestCase):
    def test_full_names_abbreviations_and_values(self) -> None:
        cases: Dict[Tuple[str, ...], List[str]] = {
            ("install", "--apply"): ["--apply"],
            ("install", "--app"): ["--apply"],
            ("install", "--apply=yes"): ["--apply"],
            ("uninstall", "--apply", "--host", "lab"): ["--apply"],
            ("install", "--rollback-now"): ["--rollback-now"],
            ("install", "--rollb"): ["--rollback-now"],
            ("install", "--device-diff"): ["--device-diff"],
            ("install", "--dev"): ["--device-diff"],
            ("install", "--accept-new-host-key"): ["--accept-new-host-key"],
            ("install", "--accept-new"): ["--accept-new-host-key"],
            ("install", "--a"): ["--accept-new-host-key", "--apply"],
            ("install", "--", "--apply"): ["--apply"],
        }
        for argv, expected in cases.items():
            self.assertEqual(ep.guarded_options(argv), expected, argv)

    def test_other_options_and_values_are_not_guarded(self) -> None:
        for argv in (
            ("install", "--release", "v0.1.0.dev1", "--host", "lab-vsrx-1", "--user", "labadmin"),
            ("--help",),
            ("status", "--host=--apply"),
            ("install", "--adopt", "--ack-managed", "--accept-unchecked-diagnostics"),
            ("install", "--access", "tls", "--listen-address", "192.0.2.10", "--daemon-port", "9443"),
            ("install", "--lab-hardware", "--access=tunnel"),
            ("install", "--applyx"),
            ("install", "-a", "apply"),
            ("install", "--"),
            (),
        ):
            self.assertEqual(ep.guarded_options(argv), [], argv)


class MountinfoTests(unittest.TestCase):
    def test_fields_are_parsed_and_unescaped(self) -> None:
        text = BASE_MOUNTINFO + "\n" + mount_line("/state x", root="/home/a b/state", optional="shared:1 master:2")
        mounts = ep.parse_mountinfo(text)
        self.assertEqual(len(mounts), 8)
        last = mounts[-1]
        self.assertEqual(last.mount_point, "/state x")
        self.assertEqual(last.root, "/home/a b/state")
        self.assertEqual(last.fs_type, "ext4")
        self.assertIn("rw", last.options)
        self.assertEqual(mounts[0].fs_type, "overlay")
        self.assertEqual(ep.unescape("a\\040b\\011c\\134d"), "a b\tc\\d")

    def test_a_root_that_is_not_a_path_is_accepted(self) -> None:
        line = "1030 1011 0:4 net:[4026531840] /run/netns/lab rw - nsfs nsfs rw"
        mounts = ep.parse_mountinfo(BASE_MOUNTINFO + "\n" + line + "\n" + mount_line("/state"))
        self.assertEqual(mounts[-2].root, "net:[4026531840]")
        self.assertIsNone(ep.mount_refusal(mounts, "/state"))

    def test_an_escaped_near_miss_is_not_the_state_directory(self) -> None:
        mounts = ep.parse_mountinfo(BASE_MOUNTINFO + "\n" + mount_line("/state x"))
        self.assertIn("not a mount point", ep.mount_refusal(mounts, "/state") or "")

    def test_malformed_lines_are_errors(self) -> None:
        for line in (
            "1020 1011 259:2 / /state rw,relatime ext4 /dev/sda rw",  # no separator
            "1020 1011 259:2 / /state rw -",  # nothing after the separator
            "1020 1011 259:2 / state rw - ext4 /dev/sda rw",  # mount point not absolute
            "1020 1011 - ext4 /dev/sda rw",  # too few fields before the separator
        ):
            with self.assertRaises(ep.MountinfoError, msg=line):
                ep.parse_mountinfo(BASE_MOUNTINFO + "\n" + line)

    def test_what_counts_as_a_lasting_mount(self) -> None:
        anonymous = "/var/lib/docker/volumes/" + "ab" * 32 + "/_data"
        cases: List[Tuple[str, Optional[str]]] = [
            (mount_line("/state"), None),
            (mount_line("/state", root="/var/lib/docker/volumes/jwicket-state/_data"), None),  # a named volume
            (mount_line("/state", options="ro,relatime"), "read-only"),
            (mount_line("/state", root="/", fs_type="tmpfs"), "tmpfs"),
            (mount_line("/state", root="/", fs_type="ramfs"), "ramfs"),
            (mount_line("/state", root=anonymous), "anonymous volume"),
            (mount_line("/state") + "\n" + mount_line("/state", root="/", fs_type="tmpfs"), "tmpfs"),
            (mount_line("/state", root="/", fs_type="tmpfs") + "\n" + mount_line("/state"), None),
            ("", "not a mount point"),
        ]
        for extra, expected in cases:
            reason = ep.mount_refusal(ep.parse_mountinfo(BASE_MOUNTINFO + "\n" + extra), "/state")
            if expected is None:
                self.assertIsNone(reason, extra)
            else:
                self.assertIn(expected, reason or "", extra)

    def test_a_too_large_or_unreadable_file_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mountinfo"
            path.write_text(BASE_MOUNTINFO, encoding="utf-8")
            self.assertEqual(len(ep.read_mountinfo(str(path))), 7)
            with mock.patch.object(ep, "MAX_MOUNTINFO_BYTES", 100), self.assertRaises(ep.MountinfoError):
                ep.read_mountinfo(str(path))
            with self.assertRaises(ep.MountinfoError):
                ep.read_mountinfo(str(Path(tmp) / "absent"))


class FakeExec:
    def __init__(self, error: Optional[OSError] = None) -> None:
        self.calls: List[Tuple[str, List[str], Dict[str, str]]] = []
        self.error = error

    def __call__(self, path: str, args: Sequence[str], env: Mapping[str, str]) -> object:
        self.calls.append((path, list(args), dict(env)))
        if self.error is not None:
            raise self.error
        return None


class EntrypointTests(unittest.TestCase):
    """main() with a fake mountinfo, a temporary state directory and a fake execve."""

    def setUp(self) -> None:
        tmp = tempfile.mkdtemp(prefix="jwicket state ")  # a space, to exercise the octal escapes
        self.addCleanup(shutil.rmtree, tmp)
        self.tmp = Path(tmp)
        self.state = self.tmp / "state"
        self.state.mkdir(mode=0o700)
        self.uid = os.geteuid()
        if self.uid == 0:
            os.chown(self.state, TEST_UID, -1)
            self.uid = TEST_UID
        self.mountinfo = self.tmp / "mountinfo"
        self.write_mountinfo(mount_line(str(self.state)))

    def write_mountinfo(self, extra: str) -> None:
        self.mountinfo.write_text(BASE_MOUNTINFO + "\n" + extra + "\n", encoding="utf-8")

    def run_main(
        self,
        argv: Sequence[str],
        *,
        environ: Optional[Mapping[str, str]] = None,
        euid: Optional[int] = None,
        execve: Optional[FakeExec] = None,
    ) -> Tuple[int, FakeExec]:
        fake = execve or FakeExec()
        code = ep.main(
            list(argv),
            environ=dict(environ or {"PATH": "/usr/bin", "HOME": "/home/app"}),
            euid=self.uid if euid is None else euid,
            state_dir=str(self.state),
            mountinfo_path=str(self.mountinfo),
            known_hosts=str(self.tmp / "known_hosts"),
            execve=fake,
        )
        return code, fake

    def assert_refused(self, argv: Sequence[str], fragment: str, **kwargs: object) -> None:
        with self.assertLogs("jwicket.container", "ERROR") as logs:
            code, fake = self.run_main(argv, **kwargs)  # type: ignore[arg-type]
        self.assertEqual(code, 2)
        self.assertEqual(fake.calls, [])
        self.assertIn(fragment, "\n".join(logs.output))

    def test_apply_on_a_private_bind_mount_reaches_the_installer_unchanged(self) -> None:
        argv = ["install", "--apply", "--release", "v0.1.0.dev1", "--host", "lab-vsrx-1", "--user", "labadmin"]
        code, fake = self.run_main(argv, environ={"PATH": "/usr/bin", ep.STATE_ENV: "/tmp/elsewhere"})
        self.assertEqual(code, 0)
        self.assertEqual(len(fake.calls), 1)
        path, args, env = fake.calls[0]
        self.assertEqual(path, ep.INSTALLER_ARGV[0])
        self.assertEqual(args, [*ep.INSTALLER_ARGV, *argv])
        self.assertEqual(env[ep.STATE_ENV], str(self.state))  # an -e value cannot redirect the state
        self.assertEqual(env["PATH"], "/usr/bin")

    def test_apply_without_a_mount_is_refused(self) -> None:
        self.write_mountinfo("")
        self.assert_refused(["install", "--apply", "--host", "lab-vsrx-1"], "is not a mount point")
        self.assert_refused(["install", "--appl"], "--apply")
        for option in ("--rollback-now", "--device-diff", "--accept-new-host-key"):
            self.assert_refused(["install", option], option)

    def test_a_dry_run_needs_the_mount_too(self) -> None:
        """SEC-04: a dry run writes a run directory and the downloaded bundle into the state directory."""
        self.write_mountinfo("")
        for argv in (
            ["install", "--release", "v0.1.0.dev1", "--host", "lab-vsrx-1"],
            ["uninstall", "--host", "lab-vsrx-1"],
            ["status", "--host", "lab-vsrx-1"],
            ["render", "--method", "cli", "--release", "v0.1.0.dev1", "--user", "lab"],
            ["fetch", "--release", "v0.1.0.dev1"],
            ["-v", "install"],
            ["instal"],
        ):
            with self.subTest(argv=argv):
                self.assert_refused(argv, "is not a mount point")

    def test_commands_that_touch_no_state_run_without_a_mount(self) -> None:
        self.write_mountinfo("")
        for argv in (["bootstrap", "--method", "netconf", "--user", "lab"], ["install", "--help"], ["--version"], []):
            with self.subTest(argv=argv):
                code, fake = self.run_main(argv)
                self.assertEqual(code, 0)
                self.assertEqual(len(fake.calls), 1)
                self.assertEqual(fake.calls[0][2][ep.STATE_ENV], str(self.state))
        self.assert_refused(["install", "--apply", "--help"], "--apply")  # what CI's smoke test checks

    def test_the_images_own_state_directory_cannot_serve_the_caller(self) -> None:
        """Why the mount is required: without it /state is the image's, 0700 and owned by uid 10001, and the
        installer's store refuses a directory another uid owns."""
        from jwicket_install import cli

        image_state = self.tmp / "image-state"  # stands for the image's /state, owned by "uid 10001"
        image_state.mkdir(mode=0o700)
        owner = image_state.stat().st_uid
        caller = owner + 1  # the --user uid of the README's docker run, not the directory's owner
        environ = mock.patch.dict(os.environ, {ep.STATE_ENV: str(image_state)})
        euid = mock.patch("os.geteuid", return_value=caller)
        with environ, euid, self.assertRaises(cli.CliError) as caught:  # one line: 3.7 has no (...) form
            cli._state_store()
        self.assertIn(f"owned by uid {owner}", str(caught.exception))

    def test_open_is_refused_with_the_way_that_works(self) -> None:
        """open forwards nothing (R3); its C8 read would test the container's network; tunnel runs ssh -L outside."""
        for mounted in (True, False):
            self.write_mountinfo(mount_line(str(self.state)) if mounted else "")
            for argv in (["open", "--host", "lab-vsrx-1", "--user", "labadmin"], ["-v", "open"], ["open"]):
                with self.subTest(mounted=mounted, argv=argv):
                    self.assert_refused(argv, "refusing 'open' in the container")
        with self.assertLogs("jwicket.container", "ERROR") as logs:
            self.run_main(["open", "--host", "lab-vsrx-1"])
        text = "\n".join(logs.output)
        self.assertIn("https://<listen address>:<port>/", text)
        self.assertIn("ssh -L 127.0.0.1:<port>:127.0.0.1:<port>", text)
        self.assertIn("refused on a lab SRX4100", text)
        code, fake = self.run_main(["open", "--help"])  # help still reaches the installer
        self.assertEqual(code, 0)
        self.assertEqual(len(fake.calls), 1)
        self.assertIsNone(ep.unavailable(["install", "--host", "open"]))  # a value is not the command

    def test_the_access_and_hardware_options_reach_the_installer_unchanged(self) -> None:
        argv = [
            "install",
            "--release",
            "v0.1.0.dev1",
            "--host",
            "lab-vsrx-1.example.net",
            "--user",
            "labadmin",
            "--access",
            "tls",
            "--listen-address",
            "192.0.2.10",
            "--daemon-port",
            "9443",
            "--lab-hardware",
        ]
        self.assertEqual(ep.guarded_options(argv), [])  # none of them writes on its own
        for extra in ([], ["--apply"], ["--access", "tunnel"]):
            with self.subTest(extra=extra):
                code, fake = self.run_main([*argv, *extra])
                self.assertEqual(code, 0)
                self.assertEqual(fake.calls[0][1], [*ep.INSTALLER_ARGV, *argv, *extra])
        self.write_mountinfo("")
        self.assert_refused(argv, "is not a mount point")  # a dry run still needs /state
        self.assert_refused([*argv, "--apply"], "--apply")

    def test_mounts_that_do_not_outlive_the_container_are_refused(self) -> None:
        anonymous = "/var/lib/docker/volumes/" + "0f" * 32 + "/_data"
        for extra, fragment in (
            (mount_line(str(self.state), options="ro,relatime"), "read-only"),
            (mount_line(str(self.state), root="/", fs_type="tmpfs"), "tmpfs"),
            (mount_line(str(self.state), root=anonymous), "anonymous volume"),
        ):
            self.write_mountinfo(extra)
            self.assert_refused(["install", "--apply"], fragment)

    def test_an_unreadable_or_malformed_mountinfo_refuses_apply(self) -> None:
        self.mountinfo.unlink()
        self.assert_refused(["install", "--apply"], "cannot tell whether")
        self.mountinfo.write_text("garbage\n", encoding="utf-8")
        self.assert_refused(["install", "--apply"], "cannot tell whether")

    def test_the_state_directory_must_be_private_to_this_uid(self) -> None:
        self.assert_refused(["install", "--apply"], "belongs to uid", euid=self.uid + 1)
        os.chmod(self.state, 0o770)  # noqa: S103 - the refusal under test
        self.assert_refused(["install", "--apply"], "group or other users can write it")
        os.chmod(self.state, 0o702)  # noqa: S103 - the refusal under test
        self.assert_refused(["install", "--apply"], "group or other users can write it")
        os.chmod(self.state, 0o500)
        self.assert_refused(["install", "--apply"], "cannot read, write and enter it")
        os.chmod(self.state, 0o700)
        code, _ = self.run_main(["install", "--apply"])
        self.assertEqual(code, 0)

    def test_the_state_path_must_be_a_real_directory(self) -> None:
        real = self.tmp / "real"
        real.mkdir(mode=0o700)
        self.state.rmdir()
        self.state.symlink_to(real)
        self.assert_refused(["install", "--apply"], "is not a directory")
        self.state.unlink()
        self.state.write_text("", encoding="utf-8")
        self.assert_refused(["install", "--apply"], "is not a directory")

    def test_uid_0_is_refused_for_every_command(self) -> None:
        for argv in (["--help"], ["install", "--host", "lab-vsrx-1"], ["install", "--apply"]):
            self.assert_refused(argv, "refusing to run as uid 0", euid=0)

    def test_a_missing_installer_is_reported(self) -> None:
        fake = FakeExec(FileNotFoundError(2, "No such file or directory"))
        with self.assertLogs("jwicket.container", "ERROR") as logs:
            code, _ = self.run_main(["--help"], execve=fake)
        self.assertEqual(code, 2)
        self.assertIn("cannot start the installer", "\n".join(logs.output))

    def test_an_agent_variable_that_names_no_socket_is_a_warning(self) -> None:
        not_a_socket = self.tmp / "agent"
        not_a_socket.write_text("", encoding="utf-8")
        with self.assertLogs("jwicket.container", "WARNING") as logs:
            code, fake = self.run_main(["--help"], environ={"SSH_AUTH_SOCK": str(not_a_socket)})
        self.assertEqual(code, 0)
        self.assertEqual(len(fake.calls), 1)
        self.assertIn("is not a socket", "\n".join(logs.output))

    def test_the_entry_point_uses_no_shell_and_no_third_party_module(self) -> None:
        source = ENTRYPOINT.read_text(encoding="utf-8")
        self.assertNotIn("subprocess", source)
        self.assertNotIn("shell=True", source)
        self.assertNotRegex(source, r"(?<![.\w])(eval|exec)\(")
        imports = set(re.findall(r"(?m)^(?:from|import) ([\w.]+)", source))
        self.assertLessEqual(
            imports, {"__future__", "logging", "os", "re", "stat", "sys", "dataclasses", "pathlib", "typing"}
        )


if __name__ == "__main__":
    unittest.main()
