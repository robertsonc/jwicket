"""The parity ledger (docs/parity/jweb-24.4.csv) is well formed, and its summary matches it.

Stdlib only, Python 3.7 syntax, no network. The method, the columns and the vocabularies are in
docs/parity/README.md. These tests check the shape of the ledger, not whether a status is true:
reviewers check that against each spec's acceptance table and the code.
"""

from __future__ import annotations

import collections
import csv
import re
import unittest
from pathlib import Path
from typing import Callable, Dict, List, Sequence, Tuple
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
PARITY = ROOT / "docs" / "parity"
LEDGER = PARITY / "jweb-24.4.csv"
SUMMARY = PARITY / "jweb-24.4.md"
SPECS = ROOT / "docs" / "specs"

HEADER = [
    "id", "menu_path", "page", "operation", "junos_hierarchy", "source_url", "source_status",
    "platform_notes", "jwicket_status", "priority", "spec", "jwicket_notes",
]
REQUIRED = ("id", "menu_path", "page", "operation", "source_url", "source_status", "jwicket_status", "priority")

# Ledger order: the six menus, then the cross-cutting areas. id prefix -> first element of menu_path.
MENUS: Tuple[Tuple[str, str], ...] = (
    ("DASH", "Dashboard"),
    ("MON", "Monitor"),
    ("DA", "Device Administration"),
    ("NET", "Network"),
    ("SPO", "Security Policies & Objects"),
    ("SVC", "Security Services"),
    ("GS", "Getting Started"),
    ("SDC", "Add SRX Series Firewall to Security Director Cloud"),
    ("BAN", "Banner (top pane)"),
)
MENU_NAMES = [name for _, name in MENUS]
PREFIX_MENU = dict(MENUS)

STATUSES = ("implemented", "qualified", "specified", "planned", "replace", "out-of-scope", "unassessed")
NEEDS_SPEC = ("implemented", "qualified", "specified")
NEEDS_REASON = ("replace", "out-of-scope")
PRIORITIES = ("P0", "P1", "P2", "P3", "P4")
SOURCE_STATUSES = ("verified", "inferred", "unknown")

SOURCE_HOSTS = ("networkingdocs.hpe.com", "www.juniper.net", "juniper.net")
REFERENCE_GUIDE_PATH = "/documentation/us/en/software/jweb-srx24.4/jweb-srx/"
LOCAL_PDF = re.compile(r"local:jweb-srx\.pdf#page=[1-9][0-9]*")
ID_PATTERN = re.compile(r"[A-Z]+(?:-[A-Z0-9]+)+")
SPEC_PATTERN = re.compile(r"[0-9]{3}")
APPROVAL = re.compile(r"owner approval pending|owner approved", re.IGNORECASE)
CELL_SPLIT = re.compile(r"(?<!\\)\|")

Row = Dict[str, str]
Table = Tuple[List[str], List[List[str]]]


def menu_of(row: Row) -> str:
    return row["menu_path"].split(" > ")[0]


def spec_files(spec: str) -> List[Path]:
    return sorted(SPECS.glob(f"{spec}-*.md"))


# --- expected summary content, computed from the CSV -------------------------------------------------


def _by(
    rows: Sequence[Row], label_name: str, label_of: Callable[[Row], str], labels: Sequence[str],
    column: str, values: Sequence[str],
) -> Table:
    body = []
    for label in labels:
        subset = [r for r in rows if label_of(r) == label]
        counts = collections.Counter(r[column] for r in subset)
        body.append([label, str(len(subset)), *[str(counts[v]) for v in values]])
    counts = collections.Counter(r[column] for r in rows)
    body.append(["Total", str(len(rows)), *[str(counts[v]) for v in values]])
    return [label_name, "Rows", *values], body


def expected_tables(rows: Sequence[Row]) -> Dict[str, Table]:
    specs = sorted({r["spec"] for r in rows if r["spec"]})
    return {
        "menu-status": _by(rows, "Menu", menu_of, MENU_NAMES, "jwicket_status", STATUSES),
        "priority-status": _by(rows, "Priority", lambda r: r["priority"], PRIORITIES, "jwicket_status", STATUSES),
        "menu-priority": _by(rows, "Menu", menu_of, MENU_NAMES, "priority", PRIORITIES),
        "spec-status": _by(
            rows, "Spec", lambda r: r["spec"] or "(none)", [*specs, "(none)"], "jwicket_status", STATUSES
        ),
        "source-status": _by(rows, "Source status", lambda r: r["source_status"], SOURCE_STATUSES, "priority", ()),
    }


def expected_row_lists(rows: Sequence[Row]) -> Dict[str, List[str]]:
    return {
        "P0": [r["id"] for r in rows if r["priority"] == "P0"],
        "P1": [r["id"] for r in rows if r["priority"] == "P1"],
        "replace": [r["id"] for r in rows if r["jwicket_status"] == "replace"],
        "out-of-scope": [r["id"] for r in rows if r["jwicket_status"] == "out-of-scope"],
    }


def render(table: Table) -> str:
    header, body = table
    lines = ["| " + " | ".join(header) + " |", "| " + " | ".join("---" for _ in header) + " |"]
    for line in body:
        cells = ["**Total**" if i == 0 and c == "Total" else c for i, c in enumerate(line)]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


# --- parsing the summary -----------------------------------------------------------------------------


def _clean(cell: str) -> str:
    return cell.strip().replace("**", "").strip("`").strip()


def marked_table(text: str, kind: str, key: str) -> Tuple[List[List[str]], int]:
    """The Markdown table after ``<!-- ledger-<kind>: <key> -->``: its rows of cleaned cells, and the
    line number of the marker."""
    lines = text.splitlines()
    marker = f"<!-- ledger-{kind}: {key} -->"
    found = [i for i, line in enumerate(lines) if line.strip() == marker]
    if len(found) != 1:
        raise AssertionError(f"{SUMMARY.name}: expected one {marker!r}, found {len(found)}")
    i = found[0] + 1
    while i < len(lines) and not lines[i].strip():
        i += 1
    table = []
    while i < len(lines) and lines[i].startswith("|"):
        inner = lines[i].strip()[1:-1]
        table.append([_clean(c) for c in CELL_SPLIT.split(inner)])
        i += 1
    if len(table) < 2:
        raise AssertionError(f"{SUMMARY.name}: no table after {marker!r}")
    return [table[0], *table[2:]], found[0]


def heading_count(text: str, line_no: int) -> int:
    """The ``(N)`` in the last ``##`` heading above a line, or -1 when it has none."""
    for line in reversed(text.splitlines()[:line_no]):
        if line.startswith("## "):
            match = re.search(r"\(([0-9]+)\)", line)
            return int(match.group(1)) if match else -1
    return -1


class ParityLedgerTests(unittest.TestCase):
    raw: List[List[str]]
    rows: List[Row]

    @classmethod
    def setUpClass(cls) -> None:
        with LEDGER.open(newline="", encoding="utf-8") as fh:
            cls.raw = list(csv.reader(fh, strict=True))
        header = cls.raw[0] if cls.raw else []
        cls.rows = [dict(zip(header, line)) for line in cls.raw[1:]]

    def test_header(self) -> None:
        self.assertEqual(self.raw[0], HEADER)

    def test_every_row_has_every_column(self) -> None:
        bad = [(n, len(line)) for n, line in enumerate(self.raw[1:], start=2) if len(line) != len(HEADER)]
        self.assertEqual(bad, [], "CSV line numbers with the wrong number of fields")

    def test_rows_exist(self) -> None:
        self.assertGreater(len(self.rows), 0)

    def test_required_fields_are_filled(self) -> None:
        bad = [(r["id"], f) for r in self.rows for f in REQUIRED if not r[f].strip()]
        self.assertEqual(bad, [])

    def test_ids_are_unique_and_well_formed(self) -> None:
        ids = [r["id"] for r in self.rows]
        duplicates = sorted(i for i, n in collections.Counter(ids).items() if n > 1)
        self.assertEqual(duplicates, [])
        malformed = [i for i in ids if not ID_PATTERN.fullmatch(i)]
        self.assertEqual(malformed, [])

    def test_id_prefix_matches_menu(self) -> None:
        bad = [
            (r["id"], menu_of(r)) for r in self.rows
            if PREFIX_MENU.get(r["id"].split("-", 1)[0]) != menu_of(r)
        ]
        self.assertEqual(bad, [])

    def test_rows_are_sorted_by_menu(self) -> None:
        unknown = sorted({menu_of(r) for r in self.rows} - set(MENU_NAMES))
        self.assertEqual(unknown, [], "menus outside the ledger order")
        order = [MENU_NAMES.index(menu_of(r)) for r in self.rows]
        out_of_order = [self.rows[i]["id"] for i in range(1, len(order)) if order[i] < order[i - 1]]
        self.assertEqual(out_of_order, [], "rows that come before an earlier menu's rows")

    def test_statuses_and_priorities_are_in_the_vocabulary(self) -> None:
        for column, vocabulary in (
            ("jwicket_status", STATUSES), ("priority", PRIORITIES), ("source_status", SOURCE_STATUSES),
        ):
            with self.subTest(column=column):
                bad = [(r["id"], r[column]) for r in self.rows if r[column] not in vocabulary]
                self.assertEqual(bad, [])

    def test_source_urls_are_juniper_documentation(self) -> None:
        bad = []
        for r in self.rows:
            url = r["source_url"]
            if url.startswith("local:"):
                if not LOCAL_PDF.fullmatch(url):
                    bad.append((r["id"], url))
                continue
            parts = urlsplit(url)
            if parts.scheme != "https" or parts.hostname not in SOURCE_HOSTS or any(c.isspace() for c in url):
                bad.append((r["id"], url))
        self.assertEqual(bad, [])

    def test_verified_rows_cite_the_reference_release(self) -> None:
        bad = [
            (r["id"], r["source_url"]) for r in self.rows
            if r["source_status"] == "verified"
            and not r["source_url"].startswith("local:")
            and REFERENCE_GUIDE_PATH not in urlsplit(r["source_url"]).path
        ]
        self.assertEqual(bad, [], "a verified row must cite the J-Web 24.4 guide")

    def test_every_spec_named_exists(self) -> None:
        bad = [
            (r["id"], r["spec"]) for r in self.rows
            if r["spec"] and not (SPEC_PATTERN.fullmatch(r["spec"]) and len(spec_files(r["spec"])) == 1)
        ]
        self.assertEqual(bad, [], f"spec must be three digits naming one file in {SPECS}")

    def test_implemented_specified_and_qualified_rows_name_a_spec(self) -> None:
        bad = [(r["id"], r["jwicket_status"]) for r in self.rows if r["jwicket_status"] in NEEDS_SPEC and not r["spec"]]
        self.assertEqual(bad, [])

    def test_replace_and_out_of_scope_rows_give_a_reason_and_its_approval_state(self) -> None:
        bad = [
            r["id"] for r in self.rows
            if r["jwicket_status"] in NEEDS_REASON
            and not (r["jwicket_notes"].strip() and APPROVAL.search(r["jwicket_notes"]))
        ]
        self.assertEqual(bad, [], "notes must say what replaces it or why, and 'Owner approval pending' or 'approved'")

    def test_summary_tables_match_the_csv(self) -> None:
        text = SUMMARY.read_text(encoding="utf-8")
        for key, expected in expected_tables(self.rows).items():
            with self.subTest(table=key):
                actual, _ = marked_table(text, "table", key)
                header, body = expected
                self.assertEqual(actual, [header, *body], f"\nExpected table '{key}':\n{render(expected)}\n")

    def test_summary_row_lists_match_the_csv(self) -> None:
        text = SUMMARY.read_text(encoding="utf-8")
        for key, expected in expected_row_lists(self.rows).items():
            with self.subTest(rows=key):
                table, line_no = marked_table(text, "rows", key)
                self.assertEqual([line[0] for line in table[1:]], expected)
                count = heading_count(text, line_no)
                if count >= 0:
                    self.assertEqual(count, len(expected), f"the heading above the {key} rows")


if __name__ == "__main__":
    unittest.main()
