"""The containerlab topology (M8) keeps its contract (Spec 006 section 6.9; AC-006-35).

One ``juniper_vsrx`` node; the image comes from the variable the Makefile's ``lab-up`` sets
(``JWICKET_VSRX_IMAGE``), with a local vrnetlab tag as its default and ``image-pull-policy: Never``;
and nothing that would configure the box at boot: no ``startup-config``, ``exec`` or ``binds``, no
other file in the directory, and no word of any J-Wicket statement (taken from the installer's own
statement table, so a new statement is covered without editing this test). The README gives root's
one-time state-directory step (R-STATEDIR), install commands that sign in and choose an access mode a
named host allows, and the lab's reachability caveats.

Two layers, as in ``test_workflows.py``: the text checks always run; the structural checks parse the
YAML with PyYAML, skip without it, and fail instead when ``JWICKET_REQUIRE_YAML=1`` (CI's
install-test job). Nothing here runs containerlab (there is none in CI or here). Python 3.7 syntax.
"""

from __future__ import annotations

import os
import re
import unittest
from pathlib import Path
from typing import Any, Dict, List, Mapping, Set

import install_support  # noqa: F401 - puts tools/ on sys.path

from jwicket_install import plan

try:
    import yaml
except ImportError:  # PyYAML is optional here; see JWICKET_REQUIRE_YAML
    yaml = None

REPO = Path(__file__).resolve().parent.parent
LAB = REPO / "deploy" / "containerlab"
TOPOLOGY = LAB / "jwicket-lab.clab.yml"
README = LAB / "README.md"
REQUIRE_YAML = os.environ.get("JWICKET_REQUIRE_YAML") == "1"

IMAGE_VARIABLE = "JWICKET_VSRX_IMAGE"
IMAGE_LINE = re.compile(r"^\s*image:\s*\$\{(?P<var>[A-Z_]+)(?::=(?P<default>[^}]+))?\}\s*$")
LOCAL_VRNETLAB_IMAGE = re.compile(r"^vrnetlab/juniper_vsrx:[0-9A-Za-z][0-9A-Za-z._-]*$")
# Node properties that load configuration or run commands at boot (containerlab nodes reference).
BOOT_KEYS = ("startup-config", "startup-delay", "exec", "binds", "ports", "env", "env-files", "stages", "config")
VRNETLAB_COMMIT = re.compile(r"git checkout --detach (?P<sha>[0-9a-f]{40})")


def yaml_lines() -> List[str]:
    """The topology's lines without comments (a '#' starts a comment here; no value contains one)."""
    out: List[str] = []
    for raw in TOPOLOGY.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if line.strip():
            out.append(line)
    return out


def expand(value: str, environ: Mapping[str, str]) -> str:
    """containerlab's ``${var:=default}`` and ``${var}``, as its topology-file page documents them."""

    def one(match: re.Match[str]) -> str:
        name, default = match.group(1), match.group(3)
        current = environ.get(name, "")
        if match.group(2) is not None:
            return current or (default or "")
        return current

    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(:=([^}]*))?\}", one, value)


def statement_words() -> Set[str]:
    """Every path word and fixed value of every J-Wicket statement in the installer's plan."""
    words: Set[str] = set()
    for spec in plan.STATEMENT_TABLE:
        words.update(spec.path)
        if spec.fixed_value:
            words.add(spec.fixed_value)
    for path in plan.STANZA_KEYS.values():
        words.update(path)
    return words


class TopologyTextTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lines = yaml_lines()
        self.text = "\n".join(self.lines)

    def test_the_directory_holds_no_configuration_file(self) -> None:
        # Generated, never committed: tool caches, and the clab-<lab> directory containerlab writes
        # next to the topology on deploy.
        generated = re.compile(r"^(?:__pycache__|\.mypy_cache|\.ruff_cache|clab-jwicket)$")
        names = sorted(p.name for p in LAB.iterdir() if not generated.match(p.name))
        self.assertEqual(names, ["README.md", "jwicket-lab.clab.yml"])

    def test_one_juniper_vsrx_node(self) -> None:
        kinds = [line.split(":", 1)[1].strip() for line in self.lines if line.strip().startswith("kind:")]
        self.assertEqual(kinds, ["juniper_vsrx"])

    def test_nothing_configures_the_box_at_boot(self) -> None:
        for key in BOOT_KEYS:
            self.assertNotRegex(self.text, rf"(?m)^\s*-?\s*{re.escape(key)}\s*:", key)

    def test_no_word_of_any_jwicket_statement(self) -> None:
        words = statement_words()
        self.assertIn("extension-service", words)
        self.assertIn(plan.DAEMON_FILE, words)
        for word in sorted(words):
            pattern = rf"(?<![\w.-]){re.escape(word)}(?![\w.-])"
            self.assertNotRegex(self.text, pattern, f"the topology contains {word!r}")
        for fragment in ("set system", "/var/db", "jwicket.ini", "commit"):
            self.assertNotIn(fragment, self.text)

    def test_the_image_is_the_makefile_variable_with_a_local_default(self) -> None:
        images = [m for m in (IMAGE_LINE.match(line) for line in self.lines) if m]
        self.assertEqual(len(images), 1)
        self.assertEqual(len([line for line in self.lines if line.strip().startswith("image:")]), 1)
        self.assertEqual(images[0].group("var"), IMAGE_VARIABLE)
        default = images[0].group("default") or ""
        self.assertRegex(default, LOCAL_VRNETLAB_IMAGE)
        self.assertNotIn("latest", default)
        makefile = (REPO / "Makefile").read_text(encoding="utf-8")
        self.assertIn(f"{IMAGE_VARIABLE}='$(VSRX_IMAGE)' $(CLAB) deploy -t $(CLAB_TOPOLOGY)", makefile)
        self.assertRegex(makefile, r"(?m)^CLAB_TOPOLOGY \?= deploy/containerlab/jwicket-lab\.clab\.yml$")
        self.assertIn("$(CLAB) destroy -t $(CLAB_TOPOLOGY)", makefile)

    def test_the_variable_expands_as_containerlab_documents(self) -> None:
        line = next(line for line in self.lines if line.strip().startswith("image:"))
        value = line.split(":", 1)[1].strip()
        built = "vrnetlab/juniper_vsrx:23.4R2-S5.7"
        self.assertEqual(expand(value, {IMAGE_VARIABLE: built}), built)
        match = IMAGE_LINE.match(line)
        assert match is not None
        default = match.group("default")
        self.assertEqual(expand(value, {}), default)
        self.assertEqual(expand(value, {IMAGE_VARIABLE: ""}), default)

    def test_the_image_is_never_pulled(self) -> None:
        policies = [
            line.split(":", 1)[1].strip() for line in self.lines if line.strip().startswith("image-pull-policy:")
        ]
        self.assertEqual(policies, ["Never"])

    def test_no_other_variable_or_magic_value(self) -> None:
        raw = TOPOLOGY.read_text(encoding="utf-8")
        self.assertEqual(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)", raw), [IMAGE_VARIABLE])
        self.assertNotIn("__clab", raw)


@unittest.skipIf(yaml is None and not REQUIRE_YAML, "PyYAML is not installed (JWICKET_REQUIRE_YAML=1 makes this fail)")
class TopologyStructureTests(unittest.TestCase):
    def setUp(self) -> None:
        if yaml is None:
            self.fail("PyYAML is required (JWICKET_REQUIRE_YAML=1)")
        data = yaml.safe_load(TOPOLOGY.read_text(encoding="utf-8"))
        self.assertIsInstance(data, dict)
        self.data: Dict[str, Any] = data

    def test_the_shape_is_one_node_and_nothing_else(self) -> None:
        self.assertEqual(set(self.data), {"name", "topology"})
        self.assertEqual(self.data["name"], "jwicket")
        topology = self.data["topology"]
        self.assertEqual(set(topology), {"nodes"})  # no kinds, defaults, groups or links
        nodes = topology["nodes"]
        self.assertEqual(list(nodes), ["lab-vsrx1"])
        node = nodes["lab-vsrx1"]
        self.assertEqual(set(node), {"kind", "image", "image-pull-policy"})
        self.assertEqual(node["kind"], "juniper_vsrx")
        self.assertEqual(node["image-pull-policy"], "Never")
        self.assertIsNotNone(IMAGE_LINE.match(f"image: {node['image']}"))

    def test_the_readme_names_the_container_containerlab_makes(self) -> None:
        # clab-${lab-name}-${node-name} (containerlab topology-file page)
        container = f"clab-{self.data['name']}-{next(iter(self.data['topology']['nodes']))}"
        self.assertEqual(container, "clab-jwicket-lab-vsrx1")
        self.assertIn(container, README.read_text(encoding="utf-8"))


class ReadmeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = README.read_text(encoding="utf-8")

    def test_it_warns_about_the_lab_only_default_credentials(self) -> None:
        self.assertIn("LAB ONLY", self.text)
        self.assertIn("admin@123", self.text)
        self.assertIn("root-login allow", self.text)
        self.assertIn("same password for root", self.text)
        self.assertIn("never run it where", self.text)

    def test_it_states_the_management_instance_caveat(self) -> None:
        self.assertIn("system management-instance", self.text)
        self.assertIn("mgmt_junos", self.text)
        self.assertIn("Q-INST-05", self.text)
        self.assertIn("127.0.0.1:830", self.text)

    def test_it_builds_the_image_from_a_pinned_vrnetlab_commit(self) -> None:
        match = VRNETLAB_COMMIT.search(self.text)
        assert match is not None, "the README pins no vrnetlab commit"
        sha = match.group("sha")
        self.assertIn("https://github.com/srl-labs/vrnetlab.git", self.text)
        self.assertIn(f"srl-labs/vrnetlab/blob/{sha}/", self.text)
        self.assertIn("make lab-up VSRX_IMAGE=vrnetlab/juniper_vsrx:", self.text)
        self.assertIn("image-pull-policy: Never", self.text)

    def test_it_gives_roots_one_time_state_directory_step(self) -> None:
        """R-STATEDIR (revision R4): the account cannot create /var/db/jwicket; root does it once, by hand."""
        prose = " ".join(self.text.split())
        self.assertIn("R-STATEDIR", self.text)
        self.assertIn(plan.state_dir_root_step("admin"), self.text)
        self.assertIn("never logs in as root", prose)
        self.assertIn("Permission denied", self.text)
        self.assertNotIn("file make-directory /var/db/jwicket", self.text)

    def test_every_install_command_works_with_a_named_host(self) -> None:
        """OPD-04 and revision R2: vrnetlab's admin has a password only, and a DNS-named --host cannot be the
        default --listen-address, so each command says how to sign in and how J-Wicket is reached."""
        blocks = re.findall(r"```sh\n(.*?)```", self.text, flags=re.S)
        commands = [
            line.strip() for b in blocks for line in b.splitlines() if line.strip().startswith("jwicket-install ")
        ]
        self.assertTrue(commands)
        for command in commands:
            with self.subTest(command=command):
                self.assertIn("--host clab-jwicket-lab-vsrx1", command)
                self.assertIn("--user admin", command)
                self.assertIn("--password-prompt", command)
                self.assertTrue("--access tunnel" in command or "--listen-address" in command)

    def test_it_states_why_tls_may_not_reach_this_lab(self) -> None:
        prose = " ".join(self.text.split())
        self.assertIn("mgmt_passthrough=False", self.text)
        self.assertIn("10.0.0.15", self.text)
        self.assertIn("administratively prohibited", self.text)
        self.assertIn("CLAB_MGMT_PASSTHROUGH", self.text)
        self.assertIn("this topology does not set it", prose)
        self.assertIn("C9", self.text)
        self.assertIn("is retired", prose)
        self.assertIn("docs/evidence/2026-11-24-srx4100-lab/README.md", self.text)

    def test_it_says_nothing_has_run(self) -> None:
        self.assertIn("Q-INST-06", self.text)
        self.assertIn("unverified", self.text)
        self.assertIn("Nothing here has been deployed", self.text)


if __name__ == "__main__":
    unittest.main()
