"""M2's Ansible playbooks keep the lab gate's contract (Spec 006 section 6.3; AC-006-31).

Nothing here contacts a device or the network. Four layers:

* Text checks always run, with no third-party package: no password variable, Juniper or netcommon
  collection, ``:latest`` or variable file anywhere in the playbooks, inventory or configuration; every
  requirement in requirements-ansible.txt pinned by version and SHA-256 (and equal to the installer's own
  pins where both name a package); ansible.cfg keeps the typed answers out of logs; the example inventory
  uses documentation addresses and no password; the README carries DEVICE_STATUS; the prompts and
  R-STATEDIR's root step are the plan's own texts.
* Structure checks parse the playbooks with PyYAML: they skip without it, and fail instead when
  ``JWICKET_REQUIRE_YAML=1`` (CI's ansible and install-test jobs). Per play: connection local, serial 1,
  a first task asserting that the gate variables and every name the play registers or derives are
  undefined (extra variables always win), a pause with ``LAB_GATE_PROMPT`` and, with
  ``jwicket_lab_hardware``, a pause with ``LAB_HARDWARE_PROMPT``, before the only ``--apply`` command,
  whose standard input is the pauses' answers, one per line; the plan read only through ``from_json`` of
  a registered result, and only ansible.builtin modules.
* Contract checks against the installer itself: every option a play passes is one the real parser
  accepts, every key the install play reads is one ``render.plan_to_json`` writes, and every key the
  uninstall play reads is in what ``jwicket-install uninstall --json`` prints for the fake device of
  tests/fakes_junos.py.
* Behaviour checks run ansible-playbook against a recording fake jwicket-install. They run only where
  ``ansible-playbook`` (``JWICKET_ANSIBLE_PLAYBOOK``, else the one on ``PATH``, else the one beside this
  interpreter) reports the pinned ansible-core 2.20.0, and fail instead of skipping when
  ``JWICKET_REQUIRE_ANSIBLE=1``. They show that the dry run sends no ``--apply``, that a run without a
  terminal or with a preset gate variable never reaches ``--apply``, that the typed answers reach the
  executor's standard input (the host name, then 'lab only'), that the access and hardware options pass
  through, that a ``tls`` host with no address to listen on stops before anything runs, that an
  uninstall with nothing to remove asks nothing, and that executor output holding Jinja is printed,
  never evaluated.

``ansible-playbook --syntax-check`` itself runs in CI's ansible job and ``make ansible-check``.
Python 3.7 syntax: CI runs the unit tests on 3.7.
"""

from __future__ import annotations

import argparse
import configparser
import ipaddress
import json
import os
import re
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Sequence, Set, Tuple
from unittest import mock

try:
    import yaml
except ImportError:  # PyYAML is optional here; see JWICKET_REQUIRE_YAML
    yaml = None

import install_support as s
import release_check  # tools/ is on sys.path (install_support)
from install_support import plan

from jwicket_install import cli, provenance, receipt, render

REPO = s.REPO
ANSIBLE_DIR = REPO / "deploy" / "ansible"
PLAYBOOKS = ("install.yml", "upgrade.yml", "uninstall.yml", "status.yml")
GATED = ("install.yml", "uninstall.yml")  # plays with a gate; upgrade.yml imports install.yml's play
EXAMPLES = (*PLAYBOOKS, "ansible.cfg", "inventory.example.ini", "requirements-ansible.txt", "requirements-ansible.in")
REQUIRE_YAML = os.environ.get("JWICKET_REQUIRE_YAML") == "1"
REQUIRE_ANSIBLE = os.environ.get("JWICKET_REQUIRE_ANSIBLE") == "1"
ANSIBLE_CORE = "2.20.0"

BANNED = (
    "ansible_password",
    "ansible_ssh_pass",
    "ANSIBLE_NET_PASSWORD",
    "ansible_become_pass",
    "--ask-pass",
    "juniper.device",
    "junipernetworks",
    "ansible.netcommon",
    ":latest",
    "vars_files",
    "vars_prompt",
    "include_vars",
    "-e @",
    "from_yaml",
    "lookup('file",
    "lookup('ansible.builtin.file",
    "lookup('pipe",
    "lookup('ansible.builtin.pipe",
    "ansible.builtin.shell",
    "ansible.builtin.raw",
    "ansible.builtin.script",
    "ansible.builtin.expect",
    "become: true",
    "become: yes",
    "delegate_to",
    "--device-diff",
    "--accept-new-host-key",
    "make-directory",
)
ALLOWED_MODULES = frozenset(
    {
        "ansible.builtin.assert",
        "ansible.builtin.command",
        "ansible.builtin.debug",
        "ansible.builtin.fail",
        "ansible.builtin.file",
        "ansible.builtin.pause",
        "ansible.builtin.stat",
    }
)
TASK_KEYWORDS = frozenset(
    {"name", "vars", "register", "when", "changed_when", "failed_when", "check_mode", "timeout", "no_log"}
)
PLAY_KEYS = frozenset(
    {
        "name",
        "hosts",
        "connection",
        "gather_facts",
        "serial",
        "any_errors_fatal",
        "max_fail_percentage",
        "debugger",
        "vars",
        "tasks",
    }
)
PLAY_VARS = {
    "ansible_connection": "local",
    "ansible_python_interpreter": "{{ ansible_playbook_python }}",
    "ansible_no_target_syslog": True,
}
GATE_NAMES = ("jwicket_gate_typed", "jwicket_lab_typed", "jwicket_device_hostname")
APPLY_WHEN = "jwicket_apply | default(false) | bool"
LAB_WHEN = "jwicket_lab_hardware | default(false) | bool"
LAB_OPTION = "(['--lab-hardware'] if jwicket_lab_hardware | default(false) | bool else [])"
# The apply step's standard input: the typed host name, then (lab hardware) the typed 'lab only', as
# YAML parses it: a real newline between the quotes (Ansible would keep a backslash escape as it is).
TYPED = (
    "{{ jwicket_gate_typed.user_input ~ (('\n' ~ jwicket_lab_typed.user_input) "
    "if jwicket_lab_hardware | default(false) | bool else '') }}"
)
# The canonical dotted-quad form, as the plays spell it (compared with plan.canonical_address below).
IPV4_PLAY = "^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])([.](25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$"
# Overrides a play may pass: never one that needs a terminal (comparing a host key's fingerprint), a
# device pull URL, which M2 does not offer, or --lab-hardware, which comes only with its own pause.
NEVER_IN_M2 = frozenset({"--accept-new-host-key", "--allow-plain-http", plan.LAB_HARDWARE_FLAG})
DOCUMENTATION_NETS = tuple(
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)

_REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[A-Za-z0-9.+!-]+)"
    r"(?: ; (?P<marker>[^;\\]+?))?"
    r"(?P<hashes>(?: --hash=sha256:[0-9a-f]{64})+)$"
)
# The one environment both files are installed into: CI's ansible job and the M2 virtual environment
# (CPython 3.12 on ubuntu-24.04 x86_64). requirements-install.txt selects some pins per interpreter
# and platform with environment markers; its pins are compared as pip would select them here.
CI_MARKER_ENVIRONMENT: Mapping[str, str] = {
    "python_full_version": "3.12.3",
    "python_version": "3.12",
    "platform_python_implementation": "CPython",
    "implementation_name": "cpython",
    "platform_machine": "x86_64",
    "sys_platform": "linux",
}
_MARKER_CLAUSE = re.compile(r"^(?P<variable>[a-z_]+) (?P<op><=|>=|==|!=|<|>) '(?P<value>[^']*)'$")
_VERSION_VARIABLES = frozenset({"python_full_version", "python_version"})


def _version_key(text: str) -> Tuple[int, ...]:
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", text):
        raise AssertionError(f"unsupported version in an environment marker: {text!r}")
    return tuple(int(part) for part in text.split("."))


def _marker_clause(clause: str, environment: Mapping[str, str]) -> bool:
    match = _MARKER_CLAUSE.match(clause)
    if match is None or match.group("variable") not in environment:
        raise AssertionError(f"unsupported environment marker clause: {clause!r}")
    variable, op, value = match.group("variable", "op", "value")
    actual = environment[variable]
    if variable not in _VERSION_VARIABLES:
        if op not in ("==", "!="):
            raise AssertionError(f"unsupported operator for {variable}: {clause!r}")
        return (actual == value) == (op == "==")
    if value.endswith(".*"):
        if op not in ("==", "!="):
            raise AssertionError(f"a wildcard version needs == or !=: {clause!r}")
        prefix = _version_key(value[:-2])
        return (_version_key(actual)[: len(prefix)] == prefix) == (op == "==")
    left, right = _version_key(actual), _version_key(value)
    width = max(len(left), len(right))
    left, right = left + (0,) * (width - len(left)), right + (0,) * (width - len(right))
    return {
        "<": left < right,
        "<=": left <= right,
        ">": left > right,
        ">=": left >= right,
        "==": left == right,
        "!=": left != right,
    }[op]


def marker_applies(marker: str, environment: Mapping[str, str]) -> bool:
    """A PEP 508 marker of ``and``/``or`` clauses without parentheses (what uv writes); anything else fails."""
    if "(" in marker or ")" in marker:
        raise AssertionError(f"unsupported environment marker (parentheses): {marker!r}")
    return any(
        all(_marker_clause(clause.strip(), environment) for clause in alternative.split(" and "))
        for alternative in marker.split(" or ")
    )


def read(name: str) -> str:
    return (ANSIBLE_DIR / name).read_text(encoding="utf-8")


def normal_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def requirement_pins(path: Path, environment: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
    """name -> version for a pip requirements file; every logical line must be ``name==version --hash...``.

    Without ``environment`` an environment marker is refused. With it, ``name==version ; <marker>``
    lines are accepted, a pin whose marker does not hold there is left out, and each name must still
    end up with exactly one pin.
    """
    logical: List[str] = []
    current = ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        current = f"{current} {line}".strip()
        if current.endswith("\\"):
            current = current[:-1].strip()
            continue
        logical.append(current)
        current = ""
    if current:
        logical.append(current)
    pins: Dict[str, str] = {}
    for line in logical:
        match = _REQUIREMENT.match(" ".join(line.split()))
        if match is None:
            raise AssertionError(f"{path.name}: not an exact pin with SHA-256 hashes: {line[:120]!r}")
        marker = match.group("marker")
        if marker is not None:
            if environment is None:
                raise AssertionError(f"{path.name}: an environment marker is not allowed here: {line[:120]!r}")
            if not marker_applies(marker, environment):
                continue
        name = normal_name(match.group("name"))
        if name in pins:
            raise AssertionError(f"{path.name}: more than one pin for {name} applies")
        pins[name] = match.group("version")
    return pins


def input_pins(path: Path) -> Dict[str, str]:
    pins: Dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            name, _, version = line.partition("==")
            pins[normal_name(name)] = version
    return pins


def code_of(text: str) -> str:
    """A playbook without its full-line comments."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def canonical_ipv4(value: str) -> bool:
    """What the installer accepts as a listen address, restricted to IPv4 (--host takes no IPv6 either)."""
    if ":" in value:
        return False
    try:
        plan.canonical_address(value)
    except plan.InputError:
        return False
    return True


# Probes for the input patterns: each playbook pattern must accept exactly what the plan's (or the
# release check's) pattern accepts. Values with a final newline are left out: Python's $ matches before
# one, so the playbooks pair every pattern with a "value == value | trim" clause, checked separately.
PROBES: Mapping[str, Tuple[str, ...]] = {
    "jwicket_user": (
        "labadmin",
        "a",
        "A" + "b" * 31,
        "A" + "b" * 32,
        "lab.admin_1-x",
        "1abc",
        "-x",
        "a b",
        "a/b",
        "",
        "é",
    ),
    "jwicket_bootstrap_nonce": ("k3v9qt", "abcdef", "ABCDEF", "abc", "abcdefg", "abc-ef", "k3v9q"),
    "jwicket_release": (
        "v0.1.0.dev1",
        "v10.20.30.dev400",
        "v0.1.0",
        "0.1.0.dev1",
        "v0.1.0-dev.1",
        "v0.1.0.dev1x",
        "v0.1.0.dev",
        "v0.1.0.dev1 ",
    ),
    "jwicket_listen_address": (
        "192.0.2.10",
        "10.0.0.15",
        "0.0.0.0",  # noqa: S104 - a probe string; nothing binds it
        "255.255.255.255",
        "1.2.3.4",
        "199.249.200.250",
        "192.0.2.010",
        "01.2.3.4",
        "256.1.1.1",
        "1.2.3",
        "1.2.3.4.5",
        "a.b.c.d",
        "lab-a.example.net",
        "2001:db8::1",
        " 192.0.2.10",
        "192.0.2.10 ",
        "",
    ),
}
HOST_EXPRESSION = "ansible_host | default(inventory_hostname)"
HOST_PROBES = (
    "lab-a",
    "192.0.2.10",
    "lab-vsrx-1.example.net",
    "a" * 253,
    "a" * 254,
    "2001:db8::1",
    "[2001:db8::1]",
    "-x",
    ".x",
    "a b",
    "a/b",
    "",
    "é",
)
REFERENCE: Mapping[str, Callable[[str], bool]] = {
    "jwicket_user": lambda v: plan.USER_RE.match(v) is not None,
    "jwicket_bootstrap_nonce": lambda v: plan.NONCE_RE.match(v) is not None,
    "jwicket_release": lambda v: release_check.TAG_PATTERN.match(v) is not None,
    "jwicket_listen_address": canonical_ipv4,
}
PORT_PROBES = ("1024", "8443", "9443", "65535", "1023", "443", "0", "65536", "99999", "08443", "9443x", "")


def clause_pattern(clauses: Sequence[str], variable: str) -> str:
    found = [
        m.group(1) for c in clauses for m in [re.search(rf"\b{re.escape(variable)} is match\('([^']*)'\)", c)] if m
    ]
    if len(found) != 1:
        raise AssertionError(f"expected one pattern for {variable}, found {found}")
    return found[0]


# --- text checks (no third-party package) ------------------------------------------------------


class TextTests(unittest.TestCase):
    def test_the_package_files_exist(self) -> None:
        for name in (*EXAMPLES, "README.md"):
            with self.subTest(file=name):
                self.assertTrue((ANSIBLE_DIR / name).is_file())

    def test_no_banned_name_in_the_examples(self) -> None:
        for name in EXAMPLES:
            text = read(name)
            for banned in BANNED:
                with self.subTest(file=name, banned=banned):
                    self.assertNotIn(banned.lower(), text.lower())

    def test_the_plays_source_check_is_the_installers_own(self) -> None:
        """SEC-10: a value the play accepts for jwicket_expect_source must not be refused by jwicket-install."""
        text = read("install.yml")
        found = re.findall(r"jwicket_expect_source is match\('([^']+)'\)", text)
        self.assertEqual(len(found), 1)
        play = found[0]
        self.assertTrue(play.endswith("$"))
        self.assertEqual(play[:-1] + "\\Z", provenance.SOURCE_TOKEN_RE.pattern)
        for value in ("local-build", "slack:#lab", "a" * 64, "with space", "a" * 65, "-x"):
            with self.subTest(value=value):
                self.assertEqual(re.match(play, value) is not None, provenance.SOURCE_TOKEN_RE.match(value) is not None)

    def test_requirements_are_exact_pins_with_hashes(self) -> None:
        pins = requirement_pins(ANSIBLE_DIR / "requirements-ansible.txt")
        self.assertEqual(pins["ansible-core"], ANSIBLE_CORE)
        self.assertEqual(pins["junos-eznc"], "2.8.3")
        self.assertEqual(pins["scp"], "0.16.2")
        for name in ("paramiko", "ncclient", "lxml", "jinja2", "pyyaml", "cryptography"):
            with self.subTest(dependency=name):
                self.assertIn(name, pins)  # transitive dependencies are pinned too
        text = read("requirements-ansible.txt")
        for option in ("--index-url", "--extra-index-url", "--find-links", "--trusted-host", "git+", "http://"):
            with self.subTest(option=option):
                self.assertNotIn(option, text)
        self.assertIn("pip-compile", text)  # the command that produced it is recorded in its header

    def test_the_inputs_file_names_exactly_the_pinned_top_level_versions(self) -> None:
        pins = requirement_pins(ANSIBLE_DIR / "requirements-ansible.txt")
        inputs = input_pins(ANSIBLE_DIR / "requirements-ansible.in")
        # cryptography explicitly, not only through paramiko: it makes the --access tls certificate.
        self.assertEqual(set(inputs), {"ansible-core", "junos-eznc", "scp", "cryptography"})
        for name, version in inputs.items():
            with self.subTest(package=name):
                self.assertEqual(pins[name], version)

    def test_shared_pins_equal_the_installers_own(self) -> None:
        install_requirements = REPO / "requirements-install.txt"
        if not install_requirements.is_file():
            self.skipTest("requirements-install.txt is not in this checkout yet")
        ours = requirement_pins(ANSIBLE_DIR / "requirements-ansible.txt")
        theirs = requirement_pins(install_requirements, CI_MARKER_ENVIRONMENT)
        self.assertIn("junos-eznc", theirs)
        self.assertIn("cryptography", theirs)
        for name, version in theirs.items():
            with self.subTest(package=name):
                # One virtual environment runs both ansible-playbook and the installer.
                self.assertEqual(ours.get(name), version)

    def test_environment_markers_are_evaluated_strictly(self) -> None:
        env = CI_MARKER_ENVIRONMENT
        cases = {
            "python_full_version < '3.10' and platform_python_implementation != 'PyPy'": False,
            "python_full_version >= '3.10' and platform_python_implementation != 'PyPy'": True,
            "python_full_version == '3.10.*' and implementation_name != 'PyPy'": False,
            "python_full_version == '3.12.*'": True,
            "python_full_version < '3.11'": False,
            "platform_machine == 'x86_64' and sys_platform == 'darwin'": False,
            "platform_machine != 'x86_64' or sys_platform != 'darwin'": True,
        }
        for marker, expected in cases.items():
            with self.subTest(marker=marker):
                self.assertIs(marker_applies(marker, env), expected)
        for unsupported in ("(sys_platform == 'linux')", "os_name == 'posix'", "sys_platform < 'linux'"):
            with self.subTest(unsupported=unsupported), self.assertRaises(AssertionError):
                marker_applies(unsupported, env)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "requirements.txt"
            hashed = " --hash=sha256:" + "0" * 64
            path.write_text(f"six==1.17.0 ; sys_platform == 'linux'{hashed}\n", encoding="utf-8")
            with self.assertRaises(AssertionError):  # markers only where an environment is given
                requirement_pins(path)
            self.assertEqual(requirement_pins(path, env), {"six": "1.17.0"})
            path.write_text(f"six==1.17.0{hashed}\nsix==1.16.0 ; sys_platform == 'linux'{hashed}\n", encoding="utf-8")
            with self.assertRaises(AssertionError):  # two applicable pins for one name
                requirement_pins(path, env)

    def test_ansible_cfg_keeps_the_typed_answer_out_of_logs(self) -> None:
        config = configparser.ConfigParser(interpolation=None)
        config.read_string(read("ansible.cfg"))
        defaults = config["defaults"]
        self.assertTrue(defaults.getboolean("no_target_syslog"))
        self.assertFalse(defaults.getboolean("display_args_to_stdout"))
        self.assertFalse(defaults.getboolean("ask_pass"))
        self.assertTrue(defaults.getboolean("host_key_checking"))
        self.assertEqual(defaults["callback_result_format"], "yaml")  # paste units print unescaped
        self.assertEqual(defaults["gathering"], "explicit")
        self.assertNotIn("log_path", defaults)
        self.assertNotIn("vault_password_file", defaults)
        self.assertFalse(config["privilege_escalation"].getboolean("become"))
        self.assertTrue(config["connection"].getboolean("pipelining"))

    def test_the_example_inventory_has_documentation_addresses_and_no_password(self) -> None:
        group = ""
        hosts: Dict[str, Dict[str, str]] = {}
        group_vars: Dict[str, str] = {}
        for raw in read("inventory.example.ini").splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith("["):
                group = line.strip("[]")
                continue
            fields = line.split()
            if group == "jwicket_lab":
                hosts[fields[0]] = dict(f.split("=", 1) for f in fields[1:])
            elif group == "jwicket_lab:vars":
                key, _, value = line.partition("=")
                group_vars[key.strip()] = value.strip()
            else:
                self.fail(f"unexpected inventory section {group!r}")
        self.assertGreaterEqual(len(hosts), 1)
        for name, values in hosts.items():
            with self.subTest(host=name):
                address = ipaddress.ip_address(values["ansible_host"])
                self.assertTrue(any(address in net for net in DOCUMENTATION_NETS))
                self.assertNotIn("ansible_connection", values)
                self.assertNotIn("jwicket_lab_typed", values)
        user = group_vars["jwicket_user"]
        self.assertRegex(user, plan.USER_RE)
        self.assertNotEqual(user, "root")
        for key in (*group_vars, *(k for v in hosts.values() for k in v)):
            with self.subTest(variable=key):
                self.assertNotIn("pass", key.lower())
                self.assertNotIn("secret", key.lower())
                self.assertNotIn("typed", key.lower())
        # The commented examples use documentation addresses and names too (RFC 5737, RFC 2606).
        for address in re.findall(r"=([0-9]+(?:\.[0-9]+){3})\b", read("inventory.example.ini")):
            with self.subTest(address=address):
                self.assertTrue(any(ipaddress.ip_address(address) in net for net in DOCUMENTATION_NETS))
        for name in re.findall(r"ansible_host=([A-Za-z][A-Za-z0-9.-]*)", read("inventory.example.ini")):
            with self.subTest(name=name):
                self.assertTrue(name.endswith(".example.net"), name)

    def test_the_readme_says_lab_only_and_unverified(self) -> None:
        text = read("README.md")
        prose = " ".join(line.lstrip("> ").strip() for line in text.splitlines())  # block quotes unwrapped
        self.assertIn(plan.DEVICE_STATUS, prose)
        self.assertIn("LAB ONLY", text)
        self.assertIn("unverified", text)
        self.assertIn("Q-SEC-01", text)
        self.assertNotIn(":latest", text)

    def test_the_readme_states_the_revisions_facts(self) -> None:
        text = read("README.md")
        prose = " ".join(text.split())
        self.assertIn("R-STATEDIR", text)
        self.assertIn(plan.STATE_DIR_ROOT_STEP.replace(plan.USER_MARKER, "<jwicket_user>"), text)
        self.assertIn("never logs in as root", prose)
        self.assertIn("administratively prohibited", text)
        self.assertIn("reachable by anything that reaches that address", prose)
        self.assertIn(f"`{plan.LAB_HARDWARE_ANSWER}`", text)
        self.assertIn("docs/evidence/2026-11-24-srx4100-lab/README.md", text)
        for variable in ("jwicket_access", "jwicket_listen_address", "jwicket_daemon_port", "jwicket_lab_hardware"):
            with self.subTest(variable=variable):
                self.assertIn(f"| `{variable}` |", text)

    def test_r_statedirs_root_step_is_the_plans(self) -> None:
        # The play names the account it knows; the command is plan.py's (principle P1).
        step = plan.STATE_DIR_ROOT_STEP.replace(plan.USER_MARKER, "{{ jwicket_user }}")
        self.assertIn(f"'{step}'", " ".join(read("install.yml").split()))
        for name in PLAYBOOKS:
            with self.subTest(playbook=name):
                self.assertNotIn("make-directory", read(name))  # the installer never creates the directory

    def test_every_option_a_play_passes_is_one_its_subcommand_accepts(self) -> None:
        # The real parser of jwicket_install.cli, not a list copied from the spec: an option the CLI does
        # not define would make every run of that play exit 2.
        parser = cli.build_parser()
        subcommands = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction)).choices
        expected = {"install.yml": "install", "uninstall.yml": "uninstall", "status.yml": "status"}
        for name, subcommand in expected.items():
            accepted = subcommands[subcommand]._option_string_actions
            passed = set(re.findall(r"'(--[a-z][a-z0-9-]*)'", code_of(read(name))))
            self.assertIn("--host", passed)
            for option in sorted(passed):
                with self.subTest(playbook=name, option=option):
                    self.assertIn(option, accepted)
        install = set(re.findall(r"'(--[a-z][a-z0-9-]*)'", code_of(read("install.yml"))))
        self.assertLessEqual({"--access", "--listen-address", "--daemon-port", plan.LAB_HARDWARE_FLAG}, install)
        self.assertIn(plan.LAB_HARDWARE_FLAG, set(re.findall(r"'(--[a-z][a-z0-9-]*)'", code_of(read("uninstall.yml")))))
        # The pin: uninstall takes no bootstrap, so the uninstall play must pass no --bootstrap-nonce.
        self.assertNotIn("--bootstrap-nonce", subcommands["uninstall"]._option_string_actions)
        self.assertIn("--bootstrap-nonce", subcommands["install"]._option_string_actions)

    def test_the_access_choices_are_the_plans(self) -> None:
        text = code_of(read("install.yml"))
        self.assertIn("jwicket_access in ['tls', 'tunnel']", text)
        self.assertEqual(plan.ACCESS_MODES, ("tls", "tunnel"))
        self.assertEqual(plan.DEFAULT_ACCESS, "tls")
        self.assertIn("jwicket_access | default('tls')", text)
        self.assertEqual(text.count(IPV4_PLAY), 2)  # the input check and the listen-address check
        for probe in PROBES["jwicket_listen_address"]:
            with self.subTest(probe=probe):
                self.assertEqual(re.match(IPV4_PLAY, probe) is not None, canonical_ipv4(probe))
        # --daemon-port: what the play accepts, the installer accepts (plan.Options' port rule).
        that = [line.strip()[2:] for line in text.splitlines() if line.strip().startswith("- jwicket_daemon_port ")]
        found = [
            m.group(1)
            for c in that
            for m in [re.search(r"jwicket_daemon_port \| string is match\('([^']*)'\)", c)]
            if m
        ]
        self.assertEqual(len(found), 1, found)
        pattern = found[0]
        self.assertIn("jwicket_daemon_port is not defined or jwicket_daemon_port | int >= 1024", that)
        self.assertIn("jwicket_daemon_port is not defined or jwicket_daemon_port | int <= 65535", that)
        for probe in PORT_PROBES:
            with self.subTest(port=probe):
                by_play = re.match(pattern, probe) is not None and 1024 <= int(probe) <= 65535
                expected = probe.isdigit() and not probe.startswith("0") and 1024 <= int(probe) <= 65535
                self.assertEqual(by_play, expected)
                if by_play:
                    plan.Options(user=s.USER, access="tunnel", port=int(probe))  # raises if the plan refuses

    def test_every_plan_key_the_install_play_reads_is_written_by_plan_to_json(self) -> None:
        document = json.loads(render.plan_to_json(s.plan_for("own-bootstrap", method=plan.Method.ANSIBLE)))
        self.assertIsInstance(document["bootstrap"], dict)
        text = read("install.yml")
        references = re.findall(r"\bjwicket_plan\.([a-z][a-z0-9_]*)(?:\.([a-z][a-z0-9_]*))?", text)
        self.assertGreater(len(references), 10)
        for top, sub in references:
            with self.subTest(key=f"{top}.{sub}" if sub else top):
                self.assertIn(top, document)
                if sub:
                    self.assertIsInstance(document[top], dict)
                    self.assertIn(sub, document[top])
        for loop_name, key in (("stage", "stages"), ("file", "files")):
            for field in set(re.findall(rf"\b{loop_name}\.([a-z][a-z0-9_]*)", text)):
                with self.subTest(key=f"{key}[].{field}"):
                    self.assertIn(field, document[key][0])
        for key in ("access", "listen_address", "port", "routing_instance", "lab_hardware"):
            with self.subTest(key=key):
                self.assertIn(f"jwicket_plan.{key}", text)
        self.assertIn(document["access"], plan.ACCESS_MODES)
        self.assertIs(document["lab_hardware"], False)

    def test_the_prompt_texts_are_the_plans(self) -> None:
        # The structure check compares the parsed prompts; this one needs no YAML library.
        for name in GATED:
            text = " ".join(read(name).split())
            for constant, register in (
                (plan.LAB_GATE_PROMPT, "jwicket_gate_typed"),
                (plan.LAB_HARDWARE_PROMPT, "jwicket_lab_typed"),
            ):
                with self.subTest(playbook=name, register=register):
                    expected = constant.rstrip()
                    self.assertTrue(expected.endswith(":"))
                    self.assertIn("prompt: >- " + expected[:-1] + " register: " + register, text)


class UninstallDocumentTests(unittest.TestCase):
    """The uninstall play reads ``jwicket-install uninstall --json`` as the real CLI prints it (the fake
    device of tests/fakes_junos.py, through ``cli.main(executor_factory=...)``): an earlier version of the
    play read top-level keys the document does not have, and defaulted past them."""

    def test_every_key_the_uninstall_play_reads_is_in_the_executors_document(self) -> None:
        import fakes_junos as f  # the fake device; nothing here reaches a network

        with tempfile.TemporaryDirectory() as tmp:
            harness = f.Harness(f.FakeDevice(), Path(tmp))
            # Root made the state directory once (R-STATEDIR, verified on SRX4100); the installer never does.
            harness.device.files[plan.STATE_DIR] = f.FakeFile(owner=f.USER, mode=0o700, is_dir=True)
            console = f.FakeConsole(harness.device, f.gate_answers())
            code, _ = f.install(harness, f.make_bundle(), console, opts=f.options(access="tunnel"))
            self.assertEqual(code, 0, console.out.getvalue()[-2000:])
            console = f.FakeConsole(harness.device, [])
            argv = ["uninstall", "--host", f.ADDRESS, "--user", f.USER, "--method", "ansible", "--json"]
            with mock.patch.object(receipt, "default_state_dir", return_value=harness.store.root):
                code = cli.main(argv, executor_factory=harness.factory(), console=console)
            self.assertEqual(code, 0, console.out.getvalue()[-2000:])
            document = json.loads(console.out.getvalue())
        text = code_of(read("uninstall.yml"))
        top = set(re.findall(r"\bjwicket_plan\.([a-z][a-z0-9_]*)", text))
        self.assertEqual(top, {"command", "uninstall"})
        self.assertEqual(document["command"], "uninstall")
        body = document["uninstall"]
        self.assertIsInstance(body, dict)
        read_keys = set(re.findall(r"\bjwicket_plan\.uninstall\.([a-z][a-z0-9_]*)", text))
        read_keys |= set(re.findall(r"\(jwicket_dry_json\.stdout \| from_json\)\.uninstall\.([a-z][a-z0-9_]*)", text))
        self.assertEqual(read_keys, {"blocked", "stages", "files", "kept", "lab_hardware", "production_signs"})
        for key in sorted(read_keys):
            with self.subTest(key=key):
                self.assertIn(key, body)
        self.assertIs(body["blocked"], False)
        self.assertTrue(body["stages"], "an installed device has something to remove")
        for stage in body["stages"]:
            self.assertLessEqual(set(re.findall(r"\bstage\.([a-z][a-z0-9_]*)", text)), set(stage))
            self.assertTrue(all(isinstance(line, str) for line in stage["lines"]))
        self.assertTrue(all(isinstance(path, str) for path in body["files"]))
        self.assertTrue(all(isinstance(key, str) for key in body["kept"]))


# --- structure checks (PyYAML) ------------------------------------------------------------------


def as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def flatten(
    tasks: Sequence[Mapping[str, Any]], inherited: Tuple[str, ...] = ()
) -> Iterator[Tuple[Mapping[str, Any], Tuple[str, ...]]]:
    """Every task with the ``when`` conditions it inherits from enclosing blocks."""
    for task in tasks:
        conditions = inherited + tuple(as_list(task.get("when")))
        if "block" in task:
            if not set(task) <= {"name", "when", "block"}:
                raise AssertionError(f"block {task.get('name')!r} has keys beyond name, when and block: {sorted(task)}")
            yield from flatten(task["block"], conditions)
        else:
            yield task, conditions


def module_of(task: Mapping[str, Any]) -> str:
    modules = [k for k in task if k not in TASK_KEYWORDS]
    if len(modules) != 1:
        raise AssertionError(f"task {task.get('name')!r} has unexpected keys {sorted(modules)}")
    return modules[0]


def args_of(task: Mapping[str, Any]) -> Mapping[str, Any]:
    value = task[module_of(task)]
    if not isinstance(value, dict):
        raise TypeError(f"task {task.get('name')!r}: module arguments must be a mapping")
    return value


@unittest.skipIf(yaml is None and not REQUIRE_YAML, "PyYAML is not installed (JWICKET_REQUIRE_YAML=1 makes this fail)")
class StructureTests(unittest.TestCase):
    plays: Dict[str, Mapping[str, Any]]

    def setUp(self) -> None:
        if yaml is None:
            self.fail("PyYAML is required (JWICKET_REQUIRE_YAML=1)")
        self.plays = {}
        for name in PLAYBOOKS:
            data = yaml.safe_load(read(name))
            self.assertIsInstance(data, list, name)
            if name == "upgrade.yml":
                continue
            self.assertEqual(len(data), 1, f"{name} has one play")
            self.plays[name] = data[0]

    def tasks(self, name: str) -> List[Tuple[Mapping[str, Any], Tuple[str, ...]]]:
        return list(flatten(self.plays[name]["tasks"]))

    def test_upgrade_is_the_install_play_with_the_upgrade_check(self) -> None:
        data = yaml.safe_load(read("upgrade.yml"))
        self.assertEqual(len(data), 1)
        entry = data[0]
        self.assertEqual(set(entry), {"name", "ansible.builtin.import_playbook", "vars"})
        self.assertEqual(entry["ansible.builtin.import_playbook"], "install.yml")
        self.assertEqual(entry["vars"], {"jwicket_upgrade_only": True})
        guard = [t for t, _ in self.tasks("install.yml") if "jwicket_upgrade_only" in str(t.get("when"))]
        self.assertEqual(len(guard), 1)
        self.assertEqual(module_of(guard[0]), "ansible.builtin.assert")
        self.assertIn("jwicket_plan.upgrade is true", str(args_of(guard[0])["that"]))

    def test_play_keywords(self) -> None:
        for name, play in self.plays.items():
            with self.subTest(playbook=name):
                self.assertLessEqual(set(play), PLAY_KEYS)
                self.assertEqual(play["hosts"], "jwicket_lab")
                self.assertEqual(play["connection"], "local")
                self.assertIs(play["gather_facts"], False)
                self.assertEqual(play["serial"], 1)
                self.assertIs(play["any_errors_fatal"], True)
                self.assertEqual(play["max_fail_percentage"], 0)
                self.assertEqual(play["debugger"], "never")
                self.assertEqual(play["vars"], PLAY_VARS)

    def test_only_ansible_builtin_modules_and_known_task_keywords(self) -> None:
        for name in self.plays:
            for task, _ in self.tasks(name):
                with self.subTest(playbook=name, task=task.get("name")):
                    self.assertIn(module_of(task), ALLOWED_MODULES)
                    self.assertNotIn("{{", str(task.get("name", "")))
                    self.assertNotIn("{%", str(task.get("name", "")))

    def test_the_first_task_refuses_preset_gate_and_internal_variables(self) -> None:
        for name in self.plays:
            tasks = self.tasks(name)
            first, conditions = tasks[0]
            with self.subTest(playbook=name):
                self.assertEqual(module_of(first), "ansible.builtin.assert")
                self.assertEqual(conditions, ())
                asserted = set(as_list(args_of(first)["that"]))
                derived: Set[str] = set(GATE_NAMES)
                for task, _ in tasks:
                    if "register" in task:
                        derived.add(task["register"])
                    derived.update(task.get("vars") or {})
                for variable in sorted(derived):
                    self.assertIn(f"{variable} is not defined", asserted)

    def test_the_inputs_are_checked_with_the_plans_patterns_before_anything_runs(self) -> None:
        for name in self.plays:
            task, _ = self.tasks(name)[1]
            that = as_list(args_of(task)["that"])
            with self.subTest(playbook=name):
                self.assertEqual(module_of(task), "ansible.builtin.assert")
                self.assertIn("ansible_connection == 'local'", that)
                self.assertIn("jwicket_user != 'root'", that)
                variables = ["jwicket_user"]
                if name in GATED:
                    self.assertIn("not (ansible_check_mode and jwicket_apply | default(false) | bool)", that)
                    self.assertIn(
                        "jwicket_lab_hardware | default(false) | string | lower in ['true', 'false', 'yes', 'no']",
                        that,
                    )
                if name == "install.yml":
                    variables += ["jwicket_bootstrap_nonce", "jwicket_release", "jwicket_listen_address"]
                    self.assertIn(
                        "jwicket_listen_address is not defined or jwicket_access | default('tls') == 'tls'", that
                    )
                if name == "uninstall.yml":
                    self.assertIn("jwicket_bootstrap_nonce is not defined", that)  # uninstall takes no bootstrap
                for variable in variables:
                    pattern = re.compile(clause_pattern(that, variable))
                    self.assertTrue(any(f"{variable} == {variable} | trim" in c for c in that), variable)
                    for probe in PROBES[variable]:
                        with self.subTest(variable=variable, probe=probe):
                            self.assertEqual(bool(pattern.match(probe)), REFERENCE[variable](probe))
                # --host: the play accepts exactly what jwicket-install's own --host check accepts.
                host = re.escape(HOST_EXPRESSION)
                found = [m.group(1) for c in that for m in [re.search(rf"{host} is match\('([^']*)'\)", c)] if m]
                self.assertEqual(len(found), 1, found)
                for probe in HOST_PROBES:
                    with self.subTest(variable="ansible_host", probe=probe):
                        self.assertEqual(bool(re.match(found[0], probe)), bool(cli.HOST_RE.match(probe)))

    def test_tls_needs_an_address_before_anything_runs(self) -> None:
        tasks = self.tasks("install.yml")
        task, conditions = tasks[2]
        self.assertEqual(module_of(task), "ansible.builtin.assert")
        self.assertEqual(conditions, ())
        (clause,) = as_list(args_of(task)["that"])
        clause = " ".join(clause.split())
        self.assertTrue(
            clause.startswith("jwicket_access | default('tls') == 'tunnel' or jwicket_listen_address is defined or ")
        )
        self.assertIn(f"{HOST_EXPRESSION} is match('{IPV4_PLAY}')", clause)
        # Before the first command: nothing has run when it fails.
        first_command = min(i for i, (t, _) in enumerate(tasks) if module_of(t) == "ansible.builtin.command")
        self.assertLess(2, first_command)

    def test_overrides_are_an_allowlist_of_the_plans_override_flags(self) -> None:
        for name in GATED:
            task, _ = self.tasks(name)[1]
            clauses = [c for c in as_list(args_of(task)["that"]) if "difference(" in c]
            with self.subTest(playbook=name):
                self.assertEqual(len(clauses), 1)
                listed = set(re.findall(r"'(--[a-z-]+)'", clauses[0]))
                self.assertTrue(listed)
                self.assertLessEqual(listed, set(plan.OVERRIDES))
                self.assertFalse(listed & NEVER_IN_M2)

    def test_lab_hardware_is_passed_only_with_its_pause(self) -> None:
        for name in GATED:
            options = [
                str(t["vars"]["jwicket_argv"]["options"])
                for t, _ in self.tasks(name)
                if "jwicket_argv" in (t.get("vars") or {})
            ]
            with self.subTest(playbook=name):
                self.assertTrue(options)
                for value in options:
                    self.assertIn(LAB_OPTION, " ".join(value.split()))
                self.assertEqual(code_of(read(name)).count("'--lab-hardware'"), 1)

    def test_the_pauses_show_the_plans_prompts_and_register_the_answers(self) -> None:
        for name in GATED:
            pauses = [(t, c) for t, c in self.tasks(name) if module_of(t) == "ansible.builtin.pause"]
            with self.subTest(playbook=name):
                self.assertEqual(len(pauses), 2)
                (gate, gate_when), (lab, lab_when) = pauses  # in this order: the host name first
                for pause, constant, register in (
                    (gate, plan.LAB_GATE_PROMPT, "jwicket_gate_typed"),
                    (lab, plan.LAB_HARDWARE_PROMPT, "jwicket_lab_typed"),
                ):
                    args = args_of(pause)
                    self.assertEqual(set(args), {"prompt"})  # no seconds or minutes: it waits; echo stays on
                    self.assertEqual(args["prompt"] + ":", constant.rstrip())  # Ansible adds the colon
                    self.assertNotIn("{{", args["prompt"])
                    self.assertEqual(pause["register"], register)
                    self.assertIs(pause["no_log"], True)
                self.assertIn(APPLY_WHEN, gate_when)
                self.assertNotIn(LAB_WHEN, gate_when)
                self.assertIn(APPLY_WHEN, lab_when)
                self.assertIn(LAB_WHEN, lab_when)
        pauses = [t for t, _ in self.tasks("status.yml") if module_of(t) == "ansible.builtin.pause"]
        self.assertEqual(pauses, [])

    def test_nothing_before_the_gate_can_write(self) -> None:
        for name in self.plays:
            tasks = self.tasks(name)
            modules = [module_of(t) for t, _ in tasks]
            end = modules.index("ansible.builtin.pause") if "ansible.builtin.pause" in modules else len(tasks)
            for task, _ in tasks[:end]:
                with self.subTest(playbook=name, task=task.get("name")):
                    self.assertNotEqual(module_of(task), "ansible.builtin.file")
                    if module_of(task) != "ansible.builtin.command":
                        continue
                    args = args_of(task)
                    self.assertEqual(set(args), {"argv"})
                    for flag in ("'--apply'", "'--gate-from-stdin'", "rollback"):
                        self.assertNotIn(flag, args["argv"])
                    self.assertIs(task["check_mode"], False)  # the reads also run under --check
                    self.assertIs(task["changed_when"], False)

    def test_the_only_apply_comes_after_the_gates_and_reads_the_pauses_answers(self) -> None:
        for name in GATED:
            tasks = self.tasks(name)
            modules = [module_of(t) for t, _ in tasks]
            pause = modules.index("ansible.builtin.pause")
            applies = [i for i, (t, _) in enumerate(tasks) if "'--apply'" in str(t.get("ansible.builtin.command", {}))]
            with self.subTest(playbook=name):
                self.assertEqual(len(applies), 1)
                index = applies[0]
                self.assertGreater(index, pause)
                task, conditions = tasks[index]
                args = args_of(task)
                self.assertLessEqual(set(args), {"argv", "stdin", "chdir"})
                for flag in ("'--apply'", "'--gate-from-stdin'", "'--json'"):
                    self.assertIn(flag, args["argv"])
                self.assertEqual(args["stdin"], TYPED)
                self.assertIs(task["no_log"], True)
                self.assertIn(APPLY_WHEN, conditions)
                self.assertNotIn(LAB_WHEN, conditions)
                # Between the gate and the apply: the empty-answer check, the 'lab only' pause and its
                # empty-answer check (lab hardware only), then at most the controller-side evidence
                # directory (uninstall).
                between = list(tasks[pause + 1 : index])
                (gate_check, _), (lab_pause, _), (lab_check, lab_check_when) = between[:3]
                self.assertEqual(module_of(gate_check), "ansible.builtin.assert")
                self.assertIn("jwicket_gate_typed.user_input | trim | length > 0", as_list(args_of(gate_check)["that"]))
                self.assertEqual(module_of(lab_pause), "ansible.builtin.pause")
                self.assertEqual(module_of(lab_check), "ansible.builtin.assert")
                self.assertIn("jwicket_lab_typed.user_input | trim | length > 0", as_list(args_of(lab_check)["that"]))
                self.assertIn(LAB_WHEN, lab_check_when)
                self.assertLessEqual({module_of(t) for t, _ in between[3:]}, {"ansible.builtin.file"})
            for task, _ in tasks:
                if task is not tasks[applies[0]][0]:
                    self.assertNotIn("--gate-from-stdin", str(task))
                    self.assertNotIn("_typed.user_input", str(task.get("ansible.builtin.command", "")))

    def test_every_command_is_an_argument_list_with_a_timeout(self) -> None:
        for name in self.plays:
            for task, _ in self.tasks(name):
                if module_of(task) != "ansible.builtin.command":
                    continue
                with self.subTest(playbook=name, task=task.get("name")):
                    argv = args_of(task)["argv"]
                    self.assertIsInstance(argv, str)
                    self.assertTrue(argv.strip().startswith("{{ [jwicket_argv.executable, '"))
                    self.assertTrue(argv.strip().endswith("}}"))
                    self.assertIsInstance(task["timeout"], int)
                    self.assertTrue(0 < task["timeout"] <= 3600)
                    self.assertIs(task["failed_when"], False)  # the exit code is reported by the next tasks

    def test_the_plan_is_read_only_through_from_json_of_a_registered_result(self) -> None:
        for name in self.plays:
            text = code_of(read(name))
            registered = {t["register"] for t, _ in self.tasks(name) if "register" in t}
            uses = re.findall(r"([A-Za-z_][A-Za-z0-9_.]*)\s*\|\s*from_json", text)
            with self.subTest(playbook=name):
                self.assertTrue(uses)
                self.assertEqual(text.count("from_json"), len(uses))
                for use in uses:
                    variable, _, field = use.partition(".")
                    self.assertIn(variable, registered)
                    self.assertEqual(field, "stdout")
                commands = [t for t, _ in self.tasks(name) if module_of(t) == "ansible.builtin.command"]
                json_runs = [
                    t for t in commands if "'--json'" in args_of(t)["argv"] and "'--apply'" not in args_of(t)["argv"]
                ]
                self.assertEqual(len(json_runs), 1)
                self.assertIn(f"{json_runs[0]['register']}.stdout | from_json", text)

    def test_the_executor_is_called_with_its_own_subcommand(self) -> None:
        expected = {"install.yml": "install", "uninstall.yml": "uninstall", "status.yml": "status"}
        for name, subcommand in expected.items():
            for task, _ in self.tasks(name):
                if module_of(task) == "ansible.builtin.command":
                    with self.subTest(playbook=name, task=task.get("name")):
                        prefix = f"{{{{ [jwicket_argv.executable, '{subcommand}'"
                        self.assertTrue(args_of(task)["argv"].startswith(prefix))

    def test_exit_code_tables_cover_the_specs_codes(self) -> None:
        for name in self.plays:
            task_vars = [t.get("vars") or {} for t, _ in self.tasks(name)]
            tables = [v["jwicket_exit_codes"] for v in task_vars if "jwicket_exit_codes" in v]
            with self.subTest(playbook=name):
                self.assertTrue(tables)
                for table in tables:
                    self.assertLessEqual(set(table), set(range(9)))
                    self.assertIn(0, table)
                    if name in GATED:
                        self.assertEqual(set(table), set(range(9)))
                        self.assertIn("lab only", table[plan.EXIT_GATE])
                if name == "install.yml":
                    self.assertIn("R-STATEDIR", tables[0][plan.EXIT_REFUSED])


# --- behaviour checks (ansible-playbook and a fake jwicket-install) -----------------------------

FAKE_EXECUTOR = """
import json
import sys

CONFIG = {config!r}
args = sys.argv[1:]
entry = {{"argv": args, "stdin": None, "cwd": None}}
if "--gate-from-stdin" in args:
    entry["stdin"] = sys.stdin.read()
    import os
    entry["cwd"] = os.getcwd()
with open(CONFIG["log"], "a", encoding="utf-8") as log:
    log.write(json.dumps(entry) + "\\n")
key = args[0] + (":apply" if "--apply" in args else "") + (":json" if "--json" in args else "")
rc, out, err = CONFIG["outputs"].get(key, [2, "", "fake: nothing configured for " + key])
sys.stdout.write(out)
sys.stderr.write(err)
sys.exit(rc)
"""

INVENTORY = "[jwicket_lab]\nlab-a ansible_host=192.0.2.10\n\n[jwicket_lab:vars]\njwicket_user=labadmin\n"
TARGET = ["--host", "192.0.2.10", "--user", "labadmin"]
M2 = ["--method", "ansible"]  # every install and uninstall call: the only method that may take --gate-from-stdin
RELEASE = "v0.1.0.dev1"
INJECTED = "{{ 7 * 191 }}"
PROMPT_END = b"Press Enter to stop:"  # both prompts end so


def find_ansible_playbook() -> Optional[str]:
    named = os.environ.get("JWICKET_ANSIBLE_PLAYBOOK")
    if named:
        return named
    found = shutil.which("ansible-playbook")
    if found:
        return found
    beside = Path(sys.executable).parent / "ansible-playbook"
    return str(beside) if beside.is_file() else None


def ansible_core_version(executable: str) -> Optional[str]:
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argument list, no shell
            [executable, "--version"], capture_output=True, text=True, timeout=60, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"\[core ([0-9][^\]]*)\]", proc.stdout)
    return match.group(1) if match else None


def exit_code(status: int) -> int:
    """os.waitstatus_to_exitcode (Python 3.9+), spelled for 3.7."""
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    return -os.WTERMSIG(status) if os.WIFSIGNALED(status) else status


class Run:
    def __init__(self, rc: int, output: str, calls: List[Dict[str, Any]], marker: Path, work: Path) -> None:
        self.rc = rc
        self.output = output
        self.calls = calls
        self.marker = marker
        self.work = work


class AnsibleRunTests(unittest.TestCase):
    playbook_bin: str = ""

    @classmethod
    def setUpClass(cls) -> None:
        found = find_ansible_playbook()
        version = ansible_core_version(found) if found else None
        if version != ANSIBLE_CORE:
            reason = f"no ansible-playbook of ansible-core {ANSIBLE_CORE} (found {found!r}, version {version!r})"
            if REQUIRE_ANSIBLE:
                raise AssertionError(reason + "; JWICKET_REQUIRE_ANSIBLE=1")
            raise unittest.SkipTest(reason + "; JWICKET_REQUIRE_ANSIBLE=1 makes this fail")
        assert found is not None
        cls.playbook_bin = found

    def run_playbook(
        self,
        playbook: str,
        variables: Mapping[str, Any],
        outputs: Mapping[str, Sequence[Any]],
        answers: Optional[Sequence[str]] = None,
    ) -> Run:
        work = Path(tempfile.mkdtemp(prefix="jwicket-ansible-"))
        self.addCleanup(shutil.rmtree, work, True)
        marker = work / "template-was-evaluated"
        log = work / "calls.jsonl"
        config = {"log": str(log), "outputs": {k: list(v) for k, v in outputs.items()}}
        fake = work / "jwicket-install"
        fake.write_text(f"#!{sys.executable} -I\n" + FAKE_EXECUTOR.format(config=config), encoding="utf-8")
        fake.chmod(0o700)
        inventory = work / "inventory.ini"
        inventory.write_text(INVENTORY, encoding="utf-8")
        extra = dict(variables)
        extra["jwicket_install_executable"] = str(fake)
        if playbook == "uninstall.yml":
            extra.setdefault("jwicket_evidence_dir", str(work / "evidence"))  # never the real ~/.local/state
        argv = [self.playbook_bin, "-i", str(inventory), playbook, "-e", json.dumps(extra)]
        env = {k: v for k, v in os.environ.items() if not k.startswith("ANSIBLE_")}
        env.update(
            {
                "ANSIBLE_CONFIG": str(ANSIBLE_DIR / "ansible.cfg"),
                "ANSIBLE_HOME": str(work / "ansible-home"),
                "ANSIBLE_LOCAL_TEMP": str(work / "ansible-home" / "tmp"),
                "ANSIBLE_NOCOLOR": "1",
                "MARKER": str(marker),
            }
        )
        if sys.platform.startswith("linux"):
            env["LC_ALL"] = "C.UTF-8"  # ansible-core refuses a locale whose encoding is not UTF-8
        if answers is None:
            proc = subprocess.run(  # noqa: S603 - fixed argument list, no shell
                argv,
                cwd=ANSIBLE_DIR,
                env=env,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
            rc, output = proc.returncode, proc.stdout + proc.stderr
        else:
            rc, output = self._run_on_a_terminal(argv, env, answers)
        calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []
        return Run(rc, output, calls, marker, work)

    def _run_on_a_terminal(self, argv: List[str], env: Mapping[str, str], answers: Sequence[str]) -> Tuple[int, str]:
        import pty  # Linux and macOS only; the caller skips elsewhere

        pid, fd = pty.fork()
        if pid == 0:  # the child: ansible-playbook with the pty as its terminal
            try:
                os.chdir(ANSIBLE_DIR)
                os.execve(argv[0], argv, dict(env))  # noqa: S606 - fixed argument list, no shell
            finally:
                os._exit(127)
        # Ansible prints a prompt and only then flushes the terminal's input (utils/display.py,
        # prompt_until: tcflush TCIFLUSH), so an answer typed at once can be discarded. Type the answer to
        # the n-th prompt after a short wait, and again while nothing after that prompt shows it was read.
        # A prompt beyond the answers given gets Enter alone, which stops the play.
        buffer = b""
        answered = 0  # prompts an answer has been typed for
        typed_at = 0.0
        attempts = 0
        deadline = time.monotonic() + 300
        try:
            while time.monotonic() < deadline:
                ready, _, _ = select.select([fd], [], [], 0.25)
                if ready:
                    try:
                        data = os.read(fd, 65536)
                    except OSError:  # EIO: the child closed the terminal
                        break
                    if not data:
                        break
                    buffer += data
                seen = buffer.count(PROMPT_END)
                if seen == 0:
                    continue
                after = buffer.rsplit(PROMPT_END, 1)[1]
                read_back = any(mark in after for mark in (b"TASK [", b"fatal:", b"PLAY RECAP"))
                now = time.monotonic()
                if seen > answered:
                    answered, attempts, typed_at = seen, 0, 0.0
                if not read_back and attempts < 10 and (attempts == 0 or now - typed_at > 3):
                    answer = answers[answered - 1] if answered <= len(answers) else ""
                    time.sleep(0.5)
                    os.write(fd, answer.encode("utf-8") + b"\r")
                    typed_at = time.monotonic()
                    attempts += 1
            else:
                os.kill(pid, signal.SIGKILL)
                self.fail("ansible-playbook did not finish within 300 s")
        finally:
            os.close(fd)
        _, status = os.waitpid(pid, 0)
        return exit_code(status), buffer.decode("utf-8", "replace")

    def outputs(
        self, scenario: str = "fresh-vsrx", *, lab_hardware: bool = False, **extra: Sequence[Any]
    ) -> Dict[str, Sequence[Any]]:
        document = json.loads(render.plan_to_json(s.plan_for(scenario, method=plan.Method.ANSIBLE)))
        document["lab_hardware"] = lab_hardware
        # Device text that reached the JSON (it cannot through plan_to_json) must still never be evaluated.
        document["production_signs"].append("outbound-ssh client: " + INJECTED)
        touch = "{{ lookup('ansible.builtin.pipe', 'touch ' ~ lookup('ansible.builtin.env', 'MARKER')) }}"
        text = f"{plan.DEVICE_STATUS}\nsimulated plan text\n  {INJECTED} {touch}\n"
        result: Dict[str, Sequence[Any]] = {
            "install": [0, text, "INFO simulated diagnostics\n"],
            "install:json": [0, json.dumps(document), ""],
            "install:apply:json": [0, json.dumps({"result": "installed"}), ""],
        }
        result.update(extra)
        return result

    @staticmethod
    def uninstall_outputs(stages: Sequence[Mapping[str, Any]], files: Sequence[str]) -> Dict[str, Sequence[Any]]:
        """What jwicket-install uninstall prints (cli.cmd_uninstall's document; UninstallDocumentTests)."""
        body = {"stages": list(stages), "files": list(files), "kept": [], "refusals": [], "blocked": False}
        document = {"schema": plan.PLAN_SCHEMA, "command": "uninstall", "exit": 0, "uninstall": body}
        return {
            "uninstall": [0, "simulated uninstall plan\n" + INJECTED + "\n", ""],
            "uninstall:json": [0, json.dumps(document), ""],
            "uninstall:apply:json": [0, json.dumps({"command": "uninstall", "exit": 0}), ""],
        }

    def test_a_dry_run_reads_twice_and_prints_device_text_without_evaluating_it(self) -> None:
        run = self.run_playbook("install.yml", {"jwicket_release": RELEASE}, self.outputs())
        self.assertEqual(run.rc, 0, run.output[-3000:])
        self.assertEqual(
            [c["argv"] for c in run.calls],
            [
                ["install", "--release", RELEASE, *TARGET, *M2],
                ["install", "--release", RELEASE, *TARGET, *M2, "--json"],
            ],
        )
        self.assertFalse(run.marker.exists())
        self.assertIn(INJECTED, run.output)
        self.assertNotIn(str(7 * 191), run.output)
        self.assertIn(plan.DEVICE_STATUS, " ".join(run.output.split()))
        self.assertIn("Dry run only: nothing was written", " ".join(run.output.split()))
        self.assertIn("access: tls on " + s.LISTEN + ":9443", run.output)

    def test_the_access_and_hardware_options_reach_the_executor(self) -> None:
        values = {
            "jwicket_release": RELEASE,
            "jwicket_access": "tls",
            "jwicket_listen_address": "192.0.2.20",
            "jwicket_daemon_port": 9444,
            "jwicket_lab_hardware": True,
        }
        run = self.run_playbook("install.yml", values, self.outputs(lab_hardware=True))
        self.assertEqual(run.rc, 0, run.output[-3000:])
        options = [*M2, "--access", "tls", "--listen-address", "192.0.2.20", "--daemon-port", "9444", "--lab-hardware"]
        self.assertEqual(
            [c["argv"] for c in run.calls],
            [
                ["install", "--release", RELEASE, *TARGET, *options],
                ["install", "--release", RELEASE, *TARGET, *options, "--json"],
            ],
        )
        tunnel = self.run_playbook(
            "install.yml", {"jwicket_release": RELEASE, "jwicket_access": "tunnel"}, self.outputs()
        )
        self.assertEqual(tunnel.rc, 0, tunnel.output[-3000:])
        self.assertEqual(tunnel.calls[0]["argv"], ["install", "--release", RELEASE, *TARGET, *M2, "--access", "tunnel"])

    def test_bad_access_inputs_stop_before_anything_runs(self) -> None:
        cases: Sequence[Tuple[Mapping[str, Any], str]] = (
            # A DNS name cannot stand for the listen address (plan.default_listen_address).
            ({"ansible_host": "lab-a.example.net"}, "Set jwicket_listen_address"),
            ({"jwicket_access": "tunnel", "jwicket_listen_address": "192.0.2.20"}, "not in the expected form"),
            ({"jwicket_listen_address": "192.0.2.010"}, "not in the expected form"),
            ({"jwicket_access": "https"}, "not in the expected form"),
            ({"jwicket_daemon_port": 1023}, "not in the expected form"),
            ({"jwicket_overrides": [plan.LAB_HARDWARE_FLAG]}, "not in the expected form"),
        )
        for extra, message in cases:
            with self.subTest(extra=extra):
                values = {"jwicket_release": RELEASE, **extra}
                run = self.run_playbook("install.yml", values, self.outputs())
                self.assertNotEqual(run.rc, 0)
                self.assertEqual(run.calls, [])
                self.assertIn(message, " ".join(run.output.split()))
        named = self.run_playbook(
            "install.yml",
            {"jwicket_release": RELEASE, "ansible_host": "lab-a.example.net", "jwicket_listen_address": "192.0.2.20"},
            self.outputs(),
        )
        self.assertEqual(named.rc, 0, named.output[-3000:])
        self.assertEqual(named.calls[0]["argv"][3:5], ["--host", "lab-a.example.net"])

    def test_apply_without_a_terminal_never_reaches_apply(self) -> None:
        for extra in ({}, {"jwicket_lab_hardware": True}):
            with self.subTest(extra=extra):
                values = {"jwicket_release": RELEASE, "jwicket_apply": True, **extra}
                run = self.run_playbook("install.yml", values, self.outputs(lab_hardware=bool(extra)))
                self.assertNotEqual(run.rc, 0)
                self.assertEqual(len(run.calls), 2)
                self.assertFalse(any("--apply" in c["argv"] for c in run.calls))
                self.assertIn("The lab gate got no answer", " ".join(run.output.split()))

    def test_gate_and_internal_variables_from_outside_are_refused_before_anything_runs(self) -> None:
        for variable in ("jwicket_gate_typed", "jwicket_lab_typed", "jwicket_device_hostname", "jwicket_dry_json"):
            with self.subTest(variable=variable):
                values = {
                    "jwicket_release": RELEASE,
                    "jwicket_apply": True,
                    "jwicket_lab_hardware": True,
                    variable: {"user_input": plan.LAB_HARDWARE_ANSWER}
                    if variable == "jwicket_lab_typed"
                    else "lab-vsrx-1",
                }
                run = self.run_playbook("install.yml", values, self.outputs(lab_hardware=True))
                self.assertNotEqual(run.rc, 0)
                self.assertEqual(run.calls, [])
                self.assertIn("was given from outside", " ".join(run.output.split()))

    @unittest.skipUnless(sys.platform.startswith("linux"), "needs a Linux pseudo-terminal")
    def test_the_typed_answer_reaches_the_executor_on_standard_input(self) -> None:
        values = {
            "jwicket_release": RELEASE,
            "jwicket_apply": True,
            "jwicket_ssh_port": 2222,
            "jwicket_bootstrap_nonce": s.NONCE,
            "jwicket_overrides": ["--adopt"],
        }
        run = self.run_playbook("install.yml", values, self.outputs(), answers=[s.HOST])
        self.assertEqual(run.rc, 0, run.output[-3000:])
        options = [*TARGET, "--port", "2222", *M2, "--bootstrap-nonce", s.NONCE, "--adopt"]
        self.assertEqual(
            [c["argv"] for c in run.calls],
            [
                ["install", "--release", RELEASE, *options],
                ["install", "--release", RELEASE, *options, "--json"],
                ["install", "--apply", "--release", RELEASE, *options, "--gate-from-stdin", "--json"],
            ],
        )
        self.assertEqual(run.calls[2]["stdin"], s.HOST + "\n")
        self.assertIn(plan.LAB_GATE_PROMPT.rstrip(), " ".join(run.output.split()))
        self.assertNotIn(" ".join(plan.LAB_HARDWARE_PROMPT.split())[:40], " ".join(run.output.split()))
        self.assertFalse(run.marker.exists())

    @unittest.skipUnless(sys.platform.startswith("linux"), "needs a Linux pseudo-terminal")
    def test_lab_hardware_asks_for_lab_only_after_the_host_name(self) -> None:
        values = {"jwicket_release": RELEASE, "jwicket_apply": True, "jwicket_lab_hardware": True}
        run = self.run_playbook(
            "install.yml", values, self.outputs(lab_hardware=True), answers=[s.HOST, plan.LAB_HARDWARE_ANSWER]
        )
        self.assertEqual(run.rc, 0, run.output[-3000:])
        options = [*TARGET, *M2, plan.LAB_HARDWARE_FLAG]
        self.assertEqual(
            [c["argv"] for c in run.calls][2],
            ["install", "--apply", "--release", RELEASE, *options, "--gate-from-stdin", "--json"],
        )
        self.assertEqual(run.calls[2]["stdin"], s.HOST + "\n" + plan.LAB_HARDWARE_ANSWER + "\n")
        output = " ".join(run.output.split())
        gate = output.index(" ".join(plan.LAB_GATE_PROMPT.split()))
        lab = output.index(" ".join(plan.LAB_HARDWARE_PROMPT.split()))
        signs = output.index("production sign: outbound-ssh client")
        self.assertLess(signs, gate)  # the production signs come before both prompts
        self.assertLess(gate, lab)
        # Enter alone at the second prompt stops the play before --apply.
        stopped = self.run_playbook("install.yml", values, self.outputs(lab_hardware=True), answers=[s.HOST])
        self.assertNotEqual(stopped.rc, 0)
        self.assertEqual(len(stopped.calls), 2)
        self.assertIn("The lab-hardware attestation got no answer", " ".join(stopped.output.split()))

    def test_netconf_off_stops_after_the_first_dry_run_with_pasteable_units(self) -> None:
        unit = 'commit confirmed 10 comment "jwicket-bootstrap netconf ' + s.NONCE + '"'
        outputs = self.outputs(install=[1, "NETCONF is off. Paste unit A:\n  " + unit + "\n", ""])
        run = self.run_playbook("install.yml", {"jwicket_release": RELEASE, "jwicket_apply": True}, outputs)
        self.assertNotEqual(run.rc, 0)
        self.assertEqual(len(run.calls), 1)
        self.assertIn(unit, run.output)  # printed as a YAML block: the quotes are not escaped
        self.assertIn("-e jwicket_bootstrap_nonce=", run.output)

    def test_a_refused_dry_run_names_roots_one_time_step(self) -> None:
        outputs = self.outputs(install=[1, "R-STATEDIR: /var/db/jwicket is absent.\n", ""])
        run = self.run_playbook("install.yml", {"jwicket_release": RELEASE}, outputs)
        self.assertNotEqual(run.rc, 0)
        self.assertEqual(len(run.calls), 1)
        self.assertIn(plan.state_dir_root_step("labadmin"), " ".join(run.output.split()))

    def test_upgrade_refuses_a_first_install(self) -> None:
        run = self.run_playbook("upgrade.yml", {"jwicket_release": RELEASE, "jwicket_apply": True}, self.outputs())
        self.assertNotEqual(run.rc, 0)
        self.assertEqual(len(run.calls), 2)
        self.assertIn("upgrade.yml changes an existing J-Wicket install only", " ".join(run.output.split()))

    def test_status_and_the_uninstall_dry_run_send_only_their_reads(self) -> None:
        status = self.run_playbook(
            "status.yml", {}, {"status:json": [0, json.dumps({"installed": True, "log": [INJECTED]}), ""]}
        )
        self.assertEqual(status.rc, 0, status.output[-3000:])
        self.assertEqual([c["argv"] for c in status.calls], [["status", *TARGET, "--json"]])
        self.assertIn(INJECTED, status.output)
        stages = [
            {"name": "uninstall", "lines": ["delete system extensions extension-service application file jwicket.py"]}
        ]
        uninstall = self.run_playbook(
            "uninstall.yml", {}, self.uninstall_outputs(stages, ["/var/db/jwicket/jwicket.ini"])
        )
        self.assertEqual(uninstall.rc, 0, uninstall.output[-3000:])
        calls = [c["argv"] for c in uninstall.calls]
        self.assertEqual(calls, [["uninstall", *TARGET, *M2], ["uninstall", *TARGET, *M2, "--json"]])
        self.assertIn("file /var/db/jwicket/jwicket.ini", uninstall.output)
        self.assertIn("nothing to remove: False", uninstall.output)
        self.assertFalse(uninstall.marker.exists())

    def test_an_uninstall_with_nothing_to_remove_asks_nothing(self) -> None:
        run = self.run_playbook("uninstall.yml", {"jwicket_apply": True}, self.uninstall_outputs([], []))
        self.assertEqual(run.rc, 0, run.output[-3000:])
        self.assertEqual(len(run.calls), 2)
        self.assertIn("J-Wicket is not installed on this host", " ".join(run.output.split()))
        self.assertNotIn("Press Enter to stop", run.output)

    @unittest.skipUnless(sys.platform.startswith("linux"), "needs a Linux pseudo-terminal")
    def test_the_uninstall_gate_feeds_the_executor_in_the_evidence_directory(self) -> None:
        stages = [
            {"name": "uninstall", "lines": ["delete system extensions extension-service application file jwicket.py"]}
        ]
        values = {"jwicket_apply": True, "jwicket_lab_hardware": True}
        run = self.run_playbook(
            "uninstall.yml", values, self.uninstall_outputs(stages, []), answers=[s.HOST, plan.LAB_HARDWARE_ANSWER]
        )
        self.assertEqual(run.rc, 0, run.output[-3000:])
        options = [*TARGET, *M2, plan.LAB_HARDWARE_FLAG]
        self.assertEqual(run.calls[2]["argv"], ["uninstall", "--apply", *options, "--gate-from-stdin", "--json"])
        self.assertEqual(run.calls[2]["stdin"], s.HOST + "\n" + plan.LAB_HARDWARE_ANSWER + "\n")
        evidence = run.work / "evidence"
        self.assertEqual(run.calls[2]["cwd"], str(evidence))
        self.assertEqual(evidence.stat().st_mode & 0o777, 0o700)


if __name__ == "__main__":
    unittest.main()
