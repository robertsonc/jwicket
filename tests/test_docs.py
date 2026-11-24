"""The documentation set holds together: links resolve, test and spec IDs exist, ledger cells are marked.

Stdlib only, Python 3.9 syntax, no network. What each check covers:

* every relative Markdown link in README.md, CONTRIBUTING.md, SECURITY.md and docs/**/*.md (the spike
  evidence in docs/evidence/ is kept unedited and is not checked as a source) points at a file or
  directory that exists, and every ``#anchor`` on such a link names a heading in the target file;
* every qualification test ID (``Q-AREA-NN``) used in docs/ or src/ is defined in docs/governance.md;
* every spec named as ``Spec NNN`` (or ``Specs NNN and MMM``) has a file in docs/specs/;
* the README's "Start here" table links only to files that exist, and the README links to every
  document in the project's document set;
* every ``junos_hierarchy`` cell of the parity ledger carries a marker (docs/parity/README.md, section 4),
  and the cells the ledger summary copies from the CSV (status, priority, spec, reason) still match it.
"""

from __future__ import annotations

import csv
import re
import unittest
from pathlib import Path
from typing import Dict, Iterator, List, Set, Tuple
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
EVIDENCE = DOCS / "evidence"
SPECS = DOCS / "specs"
GOVERNANCE = DOCS / "governance.md"
README = ROOT / "README.md"
LEDGER = DOCS / "parity" / "jweb-24.4.csv"

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
    "docs/governance.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
)

SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
FENCE = re.compile(r"^\s*(```+|~~~+)")
CODE_SPAN = re.compile(r"(`+)(.+?)\1")
REF_DEF = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*(\S+)")
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
HTML_ANCHOR = re.compile(r"<a\s+(?:id|name)=\"([^\"]+)\"")
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


if __name__ == "__main__":
    unittest.main()
