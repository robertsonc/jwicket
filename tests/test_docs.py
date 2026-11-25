"""The documentation set holds together: links resolve, test and spec IDs exist, ledger cells are marked.

Stdlib only, Python 3.7 syntax, no network. What each check covers:

* every relative Markdown link in README.md, CONTRIBUTING.md, SECURITY.md and docs/**/*.md (the spike
  evidence in docs/evidence/ is kept unedited and is not checked as a source) points at a file or
  directory that exists, and every ``#anchor`` on such a link names a heading in the target file;
* every qualification test ID (``Q-AREA-NN``) used in docs/ or src/ is defined in docs/governance.md;
* every spec named as ``Spec NNN`` (or ``Specs NNN and MMM``) has a file in docs/specs/;
* the README's "Start here" table links only to files that exist, and the README links to every
  document in the project's document set;
* every HTML ``<img src>`` and ``<source srcset>`` path in the README exists, every file in
  docs/images/readme/ is used by the README, and those images stay within a size budget (each file
  is kept forever in the public history, so an unused or oversized image is a permanent cost);
* every ``junos_hierarchy`` cell of the parity ledger carries a marker (docs/parity/README.md, section 4),
  and the cells the ledger summary copies from the CSV (status, priority, spec, reason) still match it;
* the install guide (docs/install.md, Spec 006 AC-006-41) opens with the installer's ``DEVICE_STATUS``
  banner, quotes its warnings verbatim, marks every built method's section "Unverified on a device",
  and every ``jwicket-install`` and ``make`` command in it, in docs/releases/README.md and in Spec 006
  names a subcommand, option or target that exists (the parser of tools/jwicket_install/cli.py, which
  imports no device library, and the Makefile).
"""

from __future__ import annotations

import argparse
import csv
import importlib
import re
import shlex
import sys
import unittest
from pathlib import Path
from types import ModuleType
from typing import Dict, Iterator, List, Set, Tuple
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
EVIDENCE = DOCS / "evidence"
SPECS = DOCS / "specs"
GOVERNANCE = DOCS / "governance.md"
README = ROOT / "README.md"
LEDGER = DOCS / "parity" / "jweb-24.4.csv"
README_IMAGES = DOCS / "images" / "readme"
# Size budget for the README's images: one animated hero, the rest stills.
MAX_IMAGE_BYTES = 2 * 1024 * 1024
MAX_IMAGES_TOTAL_BYTES = 5 * 1024 * 1024

# The documents the README must link to (the project's document set).
DOCUMENT_SET = (
    "docs/charter.md",
    "docs/parity/README.md",
    "docs/parity/jweb-24.4.csv",
    "docs/parity/jweb-24.4.md",
    "docs/catalog.md",
    "docs/architecture.md",
    "docs/specs/000-template.md",
    "docs/specs/001-policy-inventory.md",
    "docs/specs/002-change-protocol.md",
    "docs/specs/003-firewall-policy-builder.md",
    "docs/specs/004-live-sessions-and-logs.md",
    "docs/specs/006-installation.md",
    "docs/install.md",
    "docs/releases/README.md",
    "docs/governance.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "docs/brand/README.md",
)

# The install guide (Spec 006 AC-006-41) and the documents whose commands must match the built tools.
INSTALL_GUIDE = DOCS / "install.md"
COMMAND_DOCS = (
    INSTALL_GUIDE,
    DOCS / "releases" / "README.md",
    SPECS / "006-installation.md",
    ROOT / "README.md",
    ROOT / "CONTRIBUTING.md",
    *sorted((ROOT / "deploy").glob("*/README.md")),
    ROOT / ".github" / "release-notes-lab-only.md",
)
MAKEFILE = ROOT / "Makefile"
TOOLS = ROOT / "tools"
# The methods Spec 006 builds (section 6.1); each has a "## <ID>: ..." section in the install guide.
BUILT_METHODS = ("M1", "M2", "M3", "M4", "M4U", "M5", "M6")
UNVERIFIED_MARK = "Unverified on a device"
# plan.py constants the guide quotes word for word, in a blockquote.
QUOTED_CONSTANTS = (
    "POSTURE_WARNING",
    "TLS_POSTURE_WARNING",
    "TUNNEL_WARNING",
    "ROOT_BLAST_RADIUS",
    "NETCONF_NOT_CHECKED",
    "KEEP_SESSION_OPEN",
    "DIRECTORY_FALLBACK",
    "STATE_DIR_LEFT",
    "LAB_HARDWARE_WARNING",
    "NOT_REMOVED_BY_TOOL",
    "ALLOW_URL_WARNING",
    "REMOVE_NETCONF_WARNING",
)
# plan.py prompts the guide quotes, without the trailing space the prompt keeps for the typed answer.
QUOTED_PROMPTS = ("LAB_GATE_PROMPT", "LAB_HARDWARE_PROMPT")
# The documents that must never tell an operator to create /var/db/jwicket with a Junos file command
# (revision R4: refused on the lab SRX4100; root makes it once).
NO_MAKE_DIRECTORY_DOCS = (INSTALL_GUIDE, DOCS / "deploy-lab.md", ROOT / "README.md")

SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
FENCE = re.compile(r"^\s*(```+|~~~+)")
CODE_SPAN = re.compile(r"(`+)(.+?)\1")
REF_DEF = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*(\S+)")
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
HTML_ANCHOR = re.compile(r"<a\s+(?:id|name)=\"([^\"]+)\"")
HTML_IMAGE_SOURCE = re.compile(r"<(?:img|source)\b[^>]*?\b(?:src|srcset)=\"([^\"]+)\"", re.IGNORECASE)
Q_ID = re.compile(r"\bQ-[A-Z]+-[0-9]{2}\b")
SPEC_REF = re.compile(r"\bSpecs? ([0-9]{3}(?:(?:,\s*|\s+and\s+|\s+to\s+|\s+or\s+)[0-9]{3})*)\b")
THREE_DIGITS = re.compile(r"[0-9]{3}")
MARKER_WORD = re.compile(r"\b(verified|inferred|unknown|exists?|doc)\b")
NA_FORM = re.compile(r"n/a \(.+\)")
AS_FORM = re.compile(r"as ([A-Z]+(?:-[A-Z0-9]+)+)")


def markdown_sources() -> List[Path]:
    files = [ROOT / "README.md", ROOT / "CONTRIBUTING.md", ROOT / "SECURITY.md"]
    files += sorted(p for p in DOCS.rglob("*.md") if EVIDENCE not in p.parents)
    return files


def prose_lines(path: Path) -> Iterator[Tuple[int, str]]:
    """Lines outside fenced code blocks, with inline code spans blanked out."""
    fence = ""
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        match = FENCE.match(line)
        if match:
            marker = match.group(1)[0] * 3
            if not fence:
                fence = marker
                continue
            if line.strip().startswith(fence):
                fence = ""
                continue
        if fence:
            continue
        yield number, CODE_SPAN.sub(lambda m: " " * len(m.group(0)), line)


def inline_targets(line: str) -> Iterator[str]:
    """Targets of ``[text](target)`` and ``![alt](target)`` links, allowing nested parentheses."""
    i = 0
    while True:
        i = line.find("](", i)
        if i < 0:
            return
        j = i + 2
        depth = 1
        while j < len(line) and depth:
            if line[j] == "(":
                depth += 1
            elif line[j] == ")":
                depth -= 1
            j += 1
        if depth == 0:
            inner = line[i + 2 : j - 1].strip()
            if inner.startswith("<") and ">" in inner:
                inner = inner[1 : inner.index(">")]
            elif inner:
                inner = inner.split()[0]
            if inner:
                yield inner
        i = j


def links(path: Path) -> Iterator[Tuple[int, str]]:
    for number, line in prose_lines(path):
        for target in inline_targets(line):
            yield number, target
        match = REF_DEF.match(line)
        if match:
            yield number, match.group(1)


def relative(target: str) -> bool:
    return not (SCHEME.match(target) or target.startswith("//"))


def split_target(source: Path, target: str) -> Tuple[Path, str]:
    """The file a relative link points at, and its anchor ('' when it has none)."""
    path_part, _, anchor = target.partition("#")
    path_part = path_part.split("?", 1)[0]
    resolved = source if not path_part else (source.parent / unquote(path_part)).resolve()
    return resolved, unquote(anchor)


def slug(heading: str) -> str:
    """GitHub's heading anchor: rendered text, lower case, punctuation dropped, spaces to hyphens."""
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", heading)  # links and images keep their text
    text = re.sub(r"<[^>]+>", "", text)  # inline HTML
    text = text.replace("`", "").replace("*", "")
    text = text.strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


_ANCHORS: Dict[Path, Set[str]] = {}


def anchors(path: Path) -> Set[str]:
    if path not in _ANCHORS:
        found: Set[str] = set()
        seen: Dict[str, int] = {}
        fence = ""
        for line in path.read_text(encoding="utf-8").splitlines():
            match = FENCE.match(line)
            if match:
                marker = match.group(1)[0] * 3
                if not fence:
                    fence = marker
                elif line.strip().startswith(fence):
                    fence = ""
                continue
            if fence:
                continue
            found.update(HTML_ANCHOR.findall(line))
            heading = HEADING.match(line)
            if heading:
                base = slug(heading.group(2))
                count = seen.get(base, 0)
                seen[base] = count + 1
                found.add(base if count == 0 else f"{base}-{count}")
        _ANCHORS[path] = found
    return _ANCHORS[path]


def defined_test_ids() -> Set[str]:
    """IDs that governance.md defines: a ``#### Q-...`` heading, or the first cell of a table row."""
    ids: Set[str] = set()
    for line in GOVERNANCE.read_text(encoding="utf-8").splitlines():
        heading = re.match(r"^#{2,6}\s+(Q-[A-Z]+-[0-9]{2})\b", line)
        if heading:
            ids.add(heading.group(1))
        row = re.match(r"^\|\s*(Q-[A-Z]+-[0-9]{2})\s*\|", line)
        if row:
            ids.add(row.group(1))
    return ids


def id_sources() -> List[Path]:
    files = [p for p in DOCS.rglob("*") if p.is_file() and p.suffix in (".md", ".csv")]
    files += [p for p in (ROOT / "src").rglob("*") if p.is_file() and p.suffix in (".py", ".js", ".html", ".css")]
    files += [ROOT / "README.md", ROOT / "CONTRIBUTING.md", ROOT / "SECURITY.md"]
    return sorted(files)


def start_here_targets() -> List[str]:
    lines = README.read_text(encoding="utf-8").splitlines()
    start = lines.index("## Start here")
    targets: List[str] = []
    for line in lines[start + 1 :]:
        if line.startswith("## "):
            break
        if line.startswith("|"):
            targets.extend(t for t in inline_targets(line) if relative(t))
    return targets


class RelativeLinkTests(unittest.TestCase):
    def test_every_relative_link_points_at_an_existing_path(self) -> None:
        broken = []
        for source in markdown_sources():
            for number, target in links(source):
                if not relative(target) or target.startswith("#"):
                    continue
                path, _ = split_target(source, target)
                if not path.exists():
                    broken.append(f"{source.relative_to(ROOT)}:{number}: {target}")
        self.assertEqual(broken, [], "relative links to files that do not exist")

    def test_every_anchor_names_a_heading(self) -> None:
        broken = []
        for source in markdown_sources():
            for number, target in links(source):
                if not relative(target):
                    continue
                path, anchor = split_target(source, target)
                if not anchor or not path.is_file() or path.suffix != ".md":
                    continue
                if anchor not in anchors(path):
                    broken.append(f"{source.relative_to(ROOT)}:{number}: {target}")
        self.assertEqual(broken, [], "links whose #anchor matches no heading in the target")

    def test_links_are_found_at_all(self) -> None:
        # Guards the parser: the README alone links to a dozen documents.
        self.assertGreater(len([t for _, t in links(README) if relative(t)]), 10)


class IdentifierTests(unittest.TestCase):
    def test_every_qualification_test_id_is_defined_in_governance(self) -> None:
        defined = defined_test_ids()
        self.assertGreaterEqual(len(defined), 25, "governance.md should define at least the 25 Q-tests")
        undefined = []
        for path in id_sources():
            text = path.read_text(encoding="utf-8", errors="replace")
            for found in sorted(set(Q_ID.findall(text)) - defined):
                undefined.append(f"{path.relative_to(ROOT)}: {found}")
        self.assertEqual(undefined, [], "Q-IDs used but not defined in docs/governance.md")

    def test_every_spec_named_exists(self) -> None:
        missing = []
        for path in id_sources():
            text = path.read_text(encoding="utf-8", errors="replace")
            for match in SPEC_REF.finditer(text):
                for number in THREE_DIGITS.findall(match.group(1)):
                    if len(list(SPECS.glob(f"{number}-*.md"))) != 1:
                        missing.append(f"{path.relative_to(ROOT)}: Spec {number}")
        self.assertEqual(sorted(set(missing)), [], "specs named that have no single file in docs/specs/")


class ReadmeTests(unittest.TestCase):
    def test_start_here_links_exist(self) -> None:
        targets = start_here_targets()
        self.assertGreater(len(targets), 5, "the Start here table should link the main documents")
        missing = [t for t in targets if not split_target(README, t)[0].exists()]
        self.assertEqual(missing, [])

    def test_readme_links_every_document_in_the_set(self) -> None:
        linked = {
            split_target(README, t)[0]
            for _, t in links(README)
            if relative(t) and not t.startswith("#")
        }
        missing = [doc for doc in DOCUMENT_SET if (ROOT / doc).resolve() not in linked]
        self.assertEqual(missing, [], "documents the README does not link to")

    def html_image_sources(self) -> List[Tuple[int, str]]:
        found = []
        for number, line in prose_lines(README):
            for match in HTML_IMAGE_SOURCE.finditer(line):
                # A srcset may list several candidates ("a.webp 1x, b.webp 2x"): check each URL.
                for candidate in match.group(1).split(","):
                    url = candidate.strip().split()[0] if candidate.strip() else ""
                    if url and relative(url):
                        found.append((number, url))
        return found

    def test_html_image_sources_exist(self) -> None:
        sources = self.html_image_sources()
        self.assertTrue(sources, "no <img> or <source> found in the README; is the pattern still right?")
        missing = [
            f"README.md:{number}: {url}"
            for number, url in sources
            if not split_target(README, url)[0].is_file()
        ]
        self.assertEqual(missing, [], "README image paths that do not exist")

    def test_every_readme_image_is_used_and_within_budget(self) -> None:
        used = {split_target(README, url)[0] for _, url in self.html_image_sources()}
        used |= {split_target(README, t)[0] for _, t in links(README) if relative(t)}
        files = sorted(p for p in README_IMAGES.rglob("*") if p.is_file())
        unused = [str(p.relative_to(ROOT)) for p in files if p.resolve() not in used]
        self.assertEqual(unused, [], "files in docs/images/readme/ the README does not use")
        oversized = [
            f"{p.relative_to(ROOT)}: {p.stat().st_size} bytes" for p in files if p.stat().st_size > MAX_IMAGE_BYTES
        ]
        self.assertEqual(oversized, [], f"README images over {MAX_IMAGE_BYTES} bytes")
        total = sum(p.stat().st_size for p in files)
        self.assertLessEqual(total, MAX_IMAGES_TOTAL_BYTES, "README images over the total budget")


def ledger_rows() -> List[Dict[str, str]]:
    with LEDGER.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def summary_row_lists() -> Dict[str, Tuple[List[str], List[List[str]]]]:
    """Each ``<!-- ledger-rows: key -->`` table of the summary: its header and its rows, cells cleaned."""
    lines = (DOCS / "parity" / "jweb-24.4.md").read_text(encoding="utf-8").splitlines()
    tables: Dict[str, Tuple[List[str], List[List[str]]]] = {}
    for i, line in enumerate(lines):
        match = re.fullmatch(r"<!-- ledger-rows: (\S+) -->", line.strip())
        if not match:
            continue
        j = i + 1
        while j < len(lines) and not lines[j].strip():
            j += 1
        table = []
        while j < len(lines) and lines[j].startswith("|"):
            cells = re.split(r"(?<!\\)\|", lines[j].strip()[1:-1])
            table.append([c.strip().replace("**", "").strip("`").strip().replace("\\|", "|") for c in cells])
            j += 1
        tables[match.group(1)] = (table[0], table[2:])
    return tables


class LedgerTests(unittest.TestCase):
    def test_summary_row_lists_copy_the_csv(self) -> None:
        # test_parity_ledger.py checks which ids each list holds; this checks the copied cells.
        rows = {r["id"]: r for r in ledger_rows()}
        columns = {"Status": "jwicket_status", "Priority": "priority", "Spec": "spec"}
        stale = []
        for key, (header, body) in summary_row_lists().items():
            for line in body:
                row = rows[line[0]]
                for name, column in columns.items():
                    if name in header and line[header.index(name)] != row[column]:
                        stale.append(f"{key} {line[0]} {name}: {line[header.index(name)]!r} != {row[column]!r}")
                if header[-1] in ("What replaces it", "Reason") and line[-1] != row["jwicket_notes"].strip():
                    stale.append(f"{key} {line[0]} {header[-1]}")
        self.assertEqual(stale, [], "summary cells that no longer match jweb-24.4.csv")

    def test_every_junos_hierarchy_cell_carries_a_marker(self) -> None:
        rows = ledger_rows()
        ids = {r["id"] for r in rows}
        unmarked = []
        for r in rows:
            cell = r["junos_hierarchy"].strip()
            if MARKER_WORD.search(cell) or NA_FORM.fullmatch(cell):
                continue
            as_row = AS_FORM.fullmatch(cell)
            if as_row and as_row.group(1) in ids:
                continue
            unmarked.append((r["id"], cell))
        self.assertEqual(unmarked, [], "junos_hierarchy cells with no marker (docs/parity/README.md, section 4)")


def installer_module(name: str) -> ModuleType:
    """``jwicket_install.<name>`` from tools/ (stdlib only at import: PyEZ and paramiko load lazily)."""
    if str(TOOLS) not in sys.path:
        sys.path.insert(0, str(TOOLS))
    return importlib.import_module(f"jwicket_install.{name}")


def blockquotes(text: str) -> List[str]:
    """Each blockquote outside fenced code, its lines joined; Markdown escapes such as ``\\<`` undone."""
    quotes: List[str] = []
    current: List[str] = []
    fence = ""
    for line in [*text.splitlines(), ""]:
        match = FENCE.match(line)
        if match and (not fence or line.strip().startswith(fence)):
            fence = "" if fence else match.group(1)[0] * 3
            continue
        stripped = line.strip()
        if not fence and stripped.startswith(">"):
            current.append(stripped[1:].strip())
            continue
        if current:
            quotes.append(re.sub(r"\\([<>*_`])", r"\1", " ".join(current)).replace("**", "").strip())
            current = []
    return quotes


def sections(text: str, level: int) -> Dict[str, str]:
    """Heading text to the body under it, up to the next heading of the same or a higher level."""
    found: Dict[str, str] = {}
    heading = ""
    body: List[str] = []
    fence = ""
    for line in text.splitlines():
        match = FENCE.match(line)
        if match and (not fence or line.strip().startswith(fence)):
            fence = "" if fence else match.group(1)[0] * 3
        elif not fence:
            head = HEADING.match(line)
            if head and len(head.group(1)) <= level:
                if heading:
                    found[heading] = "\n".join(body)
                heading = head.group(2) if len(head.group(1)) == level else ""
                body = []
                continue
        body.append(line)
    if heading:
        found[heading] = "\n".join(body)
    return found


def fenced_lines(text: str) -> List[str]:
    """Lines inside fenced code blocks, with backslash continuations joined."""
    lines: List[str] = []
    fence = ""
    pending = ""
    for line in text.splitlines():
        match = FENCE.match(line)
        if match and (not fence or line.strip().startswith(fence)):
            fence = "" if fence else match.group(1)[0] * 3
            continue
        if not fence:
            continue
        if line.rstrip().endswith("\\"):
            pending += line.rstrip()[:-1] + " "
            continue
        lines.append(pending + line)
        pending = ""
    return lines


def fenced_blocks(text: str) -> List[List[str]]:
    """Each fenced code block's lines, as written (no continuation joining)."""
    blocks: List[List[str]] = []
    current: List[str] = []
    fence = ""
    for line in text.splitlines():
        match = FENCE.match(line)
        if match and (not fence or line.strip().startswith(fence)):
            if fence:
                blocks.append(current)
            fence, current = ("" if fence else match.group(1)[0] * 3), []
        elif fence:
            current.append(line)
    return blocks


def inline_code(text: str) -> List[str]:
    """Inline code spans outside fenced blocks; a span may wrap across lines of one paragraph."""
    outside: List[str] = []
    fence = ""
    for line in text.splitlines():
        match = FENCE.match(line)
        if match and (not fence or line.strip().startswith(fence)):
            fence = "" if fence else match.group(1)[0] * 3
            outside.append("")
            continue
        outside.append("" if fence else line)
    joined = "\n".join(outside)
    return [" ".join(m.group(2).split()) for m in re.finditer(r"(`+)([^`].*?)\1", joined, re.DOTALL)]


def makefile_targets() -> Set[str]:
    return set(re.findall(r"^([a-z][a-z0-9-]*):", MAKEFILE.read_text(encoding="utf-8"), re.MULTILINE))


def command_words(command: str) -> List[str]:
    """The shell words of one documented command line; optional ``[...]`` brackets dropped."""
    try:
        return shlex.split(command.replace("[", " ").replace("]", " "))
    except ValueError:
        return command.split()


class InstallGuideTests(unittest.TestCase):
    """Spec 006 AC-006-41: the install guide's banner, warnings, unverified marks and commands."""

    plan: ModuleType

    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = installer_module("plan")

    def guide(self) -> str:
        return INSTALL_GUIDE.read_text(encoding="utf-8")

    def test_opens_with_the_device_status_banner(self) -> None:
        lines = [line for line in self.guide().splitlines() if line.strip()]
        self.assertTrue(lines[0].startswith("# "), "the guide starts with its title")
        self.assertTrue(lines[1].startswith(">"), "the line after the title is the DEVICE_STATUS banner")
        self.assertEqual(blockquotes(self.guide())[0], self.plan.DEVICE_STATUS)

    def test_quotes_the_installer_warnings_verbatim(self) -> None:
        quotes = blockquotes(self.guide())
        missing = [name for name in QUOTED_CONSTANTS if getattr(self.plan, name) not in quotes]
        self.assertEqual(missing, [], "plan.py texts not quoted word for word in docs/install.md")
        prompts = [name for name in QUOTED_PROMPTS if getattr(self.plan, name).rstrip() not in quotes]
        self.assertEqual(prompts, [], "plan.py prompts not quoted word for word in docs/install.md")

    def test_root_step_and_tls_unit_are_the_plans(self) -> None:
        # Revision R4 and R2: the one-time root step and the on-box certificate unit (M4, M6) the guide
        # shows are plan.py's own lines, placeholders aside, so a change to either cannot leave it stale.
        blocks = {"\n".join(block) for block in fenced_blocks(self.guide())}
        root_step = self.plan.state_dir_root_step("labuser").replace("labuser", "<user>")
        self.assertEqual(root_step, self.plan.STATE_DIR_ROOT_STEP)
        self.assertIn(root_step, blocks, "docs/install.md does not show root's directory step on its own")
        address = "192.0.2.10"
        tls_unit = "\n".join(self.plan.shell_tls_lines(address)).replace(address, "<address>")
        self.assertIn(tls_unit, blocks, "docs/install.md's on-box certificate unit differs from plan.shell_tls_lines")

    def test_states_the_workstation_floor_the_wheel_declares(self) -> None:
        # R1: the guide names the installer wheel's Requires-Python, which is the pinned PyEZ's floor.
        source = (TOOLS / "build_wheel.py").read_text(encoding="utf-8")
        match = re.search(r'^REQUIRES_PYTHON = "([^"]+)"$', source, re.MULTILINE)
        self.assertIsNotNone(match, "tools/build_wheel.py has no REQUIRES_PYTHON")
        assert match is not None  # for mypy
        self.assertIn(f"`Requires-Python: {match.group(1)}`", self.guide())
        self.assertIn("CPython 3.9.2 or later", self.guide())

    def test_no_document_tells_the_operator_to_make_the_state_directory(self) -> None:
        # R4: 'file make-directory /var/db/jwicket' was refused on the lab SRX4100; no installer sends it,
        # and no document may give it as a step to run.
        found = []
        for path in NO_MAKE_DIRECTORY_DOCS:
            for line in fenced_lines(path.read_text(encoding="utf-8")):
                if re.search(r"\bfile make-directory\b", line):
                    found.append(f"{path.name}: {line.strip()}")
        self.assertEqual(found, [], "fenced 'file make-directory' steps (root makes /var/db/jwicket once)")

    def test_no_stop_rule_looks_for_rollback_pending(self) -> None:
        # JFR-01 (and JF-03): '<rollback pending>' is only the name of a 'show system commit' output field;
        # Juniper's sample of a pending confirmed commit reads 'commit confirmed, rollback in <n>mins'. A STOP
        # rule that waits for the words 'rollback pending' never fires. Multiline: a line break can split it.
        found = []
        for path in (SPECS / "006-installation.md", INSTALL_GUIDE, DOCS / "deploy-lab.md"):
            text = path.read_text(encoding="utf-8")
            for match in re.finditer(r"rollback\s+pending", text, re.IGNORECASE):
                if text[match.start() - 1 : match.start()] == "<":
                    continue  # `<rollback pending>`: the field's name, said to be only that
                before = text[max(0, match.start() - 200) : match.start()]
                sentence = re.split(r"(?<=[.!?])\s|\n\s*\n", before)[-1]
                if re.search(r"\bSTOP\b|\bstop if\b|\bif it shows\b", sentence, re.IGNORECASE):
                    found.append(f"{path.name}: ...{' '.join((sentence + match.group(0)).split())[-120:]}")
        self.assertEqual(found, [], "a STOP rule names 'rollback pending' (use plan.PENDING_SIGNS' wording)")

    def test_spec_quotes_the_installer_texts_verbatim(self) -> None:
        # Spec 006 quotes some plan.py texts as `NAME`: "..."; a quote that drifts from the code misleads.
        text = " ".join((SPECS / "006-installation.md").read_text(encoding="utf-8").split())
        quoted = re.findall(r'`([A-Z][A-Z_]+)`(?:\*\*)?:(?:\*\*)? "([^"]+)"', text)
        self.assertGreaterEqual(len(quoted), 5, "Spec 006 quotes fewer plan.py texts than expected")
        drifted = [name for name, words in quoted if words != getattr(self.plan, name).rstrip()]
        self.assertEqual(drifted, [], "Spec 006 quotes that differ from tools/jwicket_install/plan.py")

    def test_bootstrap_units_match_the_renderer(self) -> None:
        # The Junos units the guide shows for M1, M4 and M4U are the renderer's, placeholders aside.
        render = installer_module("render")
        method = self.plan.Method
        options = self.plan.Options(user="labuser")
        nonce, op_hash = "k3v9qt", "a" * 64
        cases = (
            (method.WORKSTATION, nonce, None),
            (method.ONBOX_LOCAL, None, op_hash),
            (method.ONBOX_URL, None, None),
        )
        blocks = set()
        lines: List[str] = []
        fence = ""
        for line in self.guide().splitlines():
            match = FENCE.match(line)
            if match and (not fence or line.strip().startswith(fence)):
                if fence:
                    blocks.add("\n".join(lines))
                fence, lines = ("" if fence else match.group(1)[0] * 3), []
            elif fence:
                lines.append(line)
        missing = []
        checked = 0
        for kind, boot_nonce, sha in cases:
            boot = self.plan.build_bootstrap(kind, options, None, boot_nonce, op_sha256=sha)
            for unit in render.render_bootstrap_units(boot):
                shown = "\n".join(unit.lines).replace(nonce, "<nonce>").replace(op_hash, "<hash>")
                shown = shown.replace("labuser", "<user>")
                checked += 1
                # M4U's one-line unit C is given inline, in prose: its text must still appear verbatim.
                inline = kind is method.ONBOX_URL and unit.number == "C" and f"`{shown}`" in self.guide()
                if shown not in blocks and not inline:
                    missing.append(f"{kind.value} unit {unit.number}: {shown!r}")
        self.assertGreaterEqual(checked, 12, "fewer bootstrap units than the three kinds' A to D")
        self.assertEqual(missing, [], "bootstrap units in docs/install.md that differ from render.py")

    def test_every_built_method_has_a_section_marked_unverified(self) -> None:
        by_method: Dict[str, str] = {}
        for heading, body in sections(self.guide(), 2).items():
            match = re.match(r"^(M[0-9]+U?):", heading)
            if match:
                by_method[match.group(1)] = body
        self.assertEqual(sorted(set(BUILT_METHODS) - set(by_method)), [], "built methods with no section")
        unmarked = [m for m in BUILT_METHODS if UNVERIFIED_MARK not in by_method.get(m, "")]
        self.assertEqual(unmarked, [], f"built-method sections without '{UNVERIFIED_MARK}'")

    def installer_parsers(self) -> Dict[str, argparse.ArgumentParser]:
        parser = installer_module("cli").build_parser()
        for action in parser._actions:  # argparse keeps its subparsers among its actions
            if isinstance(action, argparse._SubParsersAction):
                return dict(action.choices)
        raise AssertionError("the installer's parser has no subcommands")

    def test_every_installer_command_uses_options_that_exist(self) -> None:
        parsers = self.installer_parsers()
        wrong = []
        checked = 0
        for path in COMMAND_DOCS:
            text = path.read_text(encoding="utf-8")
            for command in fenced_lines(text) + inline_code(text):
                words = command_words(command)
                if len(words) < 2 or words[0] != "jwicket-install" or words[1].startswith("-"):
                    continue
                checked += 1
                sub = parsers.get(words[1])
                if sub is None:
                    wrong.append(f"{path.name}: no subcommand {words[1]!r}: {command}")
                    continue
                known = set(sub._option_string_actions)  # every option string of the subcommand, long and short
                for word in words[2:]:
                    flag = word.split("=", 1)[0]
                    if flag.startswith("--") and flag not in known:
                        wrong.append(f"{path.name}: {words[1]} has no option {flag}: {command}")
        self.assertGreater(checked, 20, "no jwicket-install command found; is the pattern still right?")
        self.assertEqual(wrong, [], "documented commands that the built CLI does not accept")

    def test_every_fenced_installer_command_parses(self) -> None:
        parser = installer_module("cli").build_parser()
        refused = []
        for path in COMMAND_DOCS:
            for command in fenced_lines(path.read_text(encoding="utf-8")):
                words = command_words(command)
                if not words or words[0] != "jwicket-install":
                    continue
                try:
                    parser.parse_args(words[1:])
                except SystemExit:
                    refused.append(f"{path.name}: {command}")
        self.assertEqual(refused, [], "fenced jwicket-install commands that argparse refuses")

    def test_every_make_command_names_a_target(self) -> None:
        targets = makefile_targets()
        self.assertIn("release-record", targets)
        missing = []
        for path in COMMAND_DOCS:
            text = path.read_text(encoding="utf-8")
            for command in fenced_lines(text) + inline_code(text):
                words = [w for w in command_words(command) if not re.match(r"^[A-Z_][A-Z0-9_]*=", w)]
                if len(words) >= 2 and words[0] == "make" and words[1] not in targets:
                    missing.append(f"{path.name}: {command}")
        self.assertEqual(missing, [], "make commands naming no Makefile target")


if __name__ == "__main__":
    unittest.main()
