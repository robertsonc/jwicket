"""Static UI assets obey the strict CSP and the offline rule (no external URLs, no HTML injection APIs)."""

from __future__ import annotations

import re
import unittest
from html.parser import HTMLParser
from typing import List, Optional, Tuple

from jwicket.resources import STATIC_DIR

URL = re.compile(r"https?://", re.IGNORECASE)
# XML namespace identifiers are not fetched; createElementNS needs the SVG one.
ALLOWED_URLS = ("http://www.w3.org/2000/svg",)


def external_urls(text: str) -> List[str]:
    found = []
    for match in URL.finditer(text):
        rest = text[match.start():]
        if not any(rest.startswith(ok) for ok in ALLOWED_URLS):
            found.append(rest[:60])
    return found


def assets(suffix: str) -> List[str]:
    return sorted(p.relative_to(STATIC_DIR).as_posix() for p in STATIC_DIR.rglob(f"*{suffix}"))
# DOM APIs that parse strings as HTML or code. Trusted Types would block them at run time anyway; the
# UI must not depend on that.
FORBIDDEN_JS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("innerHTML", re.compile(r"\.\s*innerHTML\b")),
    ("outerHTML", re.compile(r"\.\s*outerHTML\b")),
    ("insertAdjacentHTML", re.compile(r"\binsertAdjacentHTML\b")),
    ("document.write", re.compile(r"\bdocument\s*\.\s*write(ln)?\b")),
    ("eval", re.compile(r"(?<![\w$.])eval\s*\(")),
    ("new Function", re.compile(r"\bnew\s+Function\b")),
    ("Function(", re.compile(r"(?<![\w$.])Function\s*\(")),
    ("string setTimeout", re.compile(r"\bset(Timeout|Interval)\s*\(\s*['\"`]")),
    ("setAttribute style", re.compile(r"setAttribute\s*\(\s*['\"`]style['\"`]")),
    ("setAttribute on*", re.compile(r"setAttribute\s*\(\s*['\"`]on[a-z]+['\"`]", re.IGNORECASE)),
    ("createContextualFragment", re.compile(r"\bcreateContextualFragment\b")),
    ("srcdoc", re.compile(r"\.\s*srcdoc\b")),
    ("DOMParser", re.compile(r"\bDOMParser\b")),
)


def read(name: str) -> str:
    return (STATIC_DIR / name).read_text(encoding="utf-8")


def strip_js_comments(source: str) -> str:
    """Remove // and /* */ comments, leaving string and template literals alone (best effort)."""
    out: List[str] = []
    i, n = 0, len(source)
    quote: Optional[str] = None
    while i < n:
        ch = source[i]
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(source[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if source.startswith("/*", i):
            end = source.find("*/", i + 2)
            i = n if end < 0 else end + 2
            out.append(" ")
            continue
        if source.startswith("//", i):
            end = source.find("\n", i)
            i = n if end < 0 else end
            continue
        out.append(ch)
        i += 1
    return "".join(out)


class IndexParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: List[Tuple[str, List[Tuple[str, Optional[str]]]]] = []
        self.script_bodies: List[str] = []
        self._in_script = False
        self._script_text: List[str] = []
        self.style_elements = 0

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        self.tags.append((tag, attrs))
        if tag == "script":
            self._in_script = True
            self._script_text = []
        if tag == "style":
            self.style_elements += 1

    def handle_startendtag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        self.tags.append((tag, attrs))

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._in_script:
            self.script_bodies.append("".join(self._script_text))
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._script_text.append(data)


class IndexHtmlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = read("index.html")
        cls.parsed = IndexParser()
        cls.parsed.feed(cls.text)
        cls.parsed.close()

    def test_scripts_are_external_with_no_inline_body(self) -> None:
        scripts = [attrs for tag, attrs in self.parsed.tags if tag == "script"]
        self.assertTrue(scripts, "index.html loads no script")
        for attrs in scripts:
            src = dict(attrs).get("src")
            self.assertIsNotNone(src, f"inline script element: {attrs}")
            self.assertTrue(str(src).startswith("/static/"), src)
        for body in self.parsed.script_bodies:
            self.assertEqual(body.strip(), "", f"inline script body: {body[:80]!r}")

    def test_no_inline_style_or_event_handlers(self) -> None:
        self.assertEqual(self.parsed.style_elements, 0, "<style> element present")
        for tag, attrs in self.parsed.tags:
            for name, value in attrs:
                with self.subTest(tag=tag, attr=name):
                    self.assertNotEqual(name.lower(), "style", f"<{tag} style={value!r}>")
                    self.assertFalse(name.lower().startswith("on"), f"<{tag} {name}={value!r}>")
                    if value is not None:
                        self.assertNotIn("javascript:", value.lower())

    def test_references_only_static_paths(self) -> None:
        for tag, attrs in self.parsed.tags:
            for name, value in attrs:
                if value is None or name not in ("src", "href", "srcset", "poster", "data", "action", "formaction"):
                    continue
                with self.subTest(tag=tag, attr=name, value=value):
                    if tag == "a" and name == "href":
                        # Navigation stays on this origin: an in-page fragment or a same-origin path.
                        self.assertTrue(value.startswith("#") or (value.startswith("/") and not value.startswith("//")),
                                        value)
                    else:
                        self.assertTrue(value.startswith("/static/"), value)

    def test_stylesheets_are_static(self) -> None:
        links = [dict(attrs) for tag, attrs in self.parsed.tags if tag == "link"]
        sheets = [link for link in links if "stylesheet" in str(link.get("rel", ""))]
        self.assertTrue(sheets)
        for link in sheets:
            self.assertTrue(str(link.get("href")).startswith("/static/"))

    def test_no_external_urls(self) -> None:
        self.assertEqual(external_urls(self.text), [])


class ScriptTests(unittest.TestCase):
    """Every JavaScript file under static/, however the UI is split into modules."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.files = {name: read(name) for name in assets(".js")}

    def test_there_is_script(self) -> None:
        self.assertTrue(self.files)

    def test_no_external_urls(self) -> None:
        for name, raw in self.files.items():
            with self.subTest(file=name):
                self.assertEqual(external_urls(raw), [])

    def test_no_html_or_code_injection_apis(self) -> None:
        for name, raw in self.files.items():
            code = strip_js_comments(raw)
            for label, pattern in FORBIDDEN_JS:
                with self.subTest(file=name, api=label):
                    match = pattern.search(code)
                    context = code[max(0, match.start() - 60): match.end() + 60] if match else ""
                    self.assertIsNone(match, f"{label} used in {name}: ...{context}...")

    def test_comment_stripper(self) -> None:
        src = "a(); // x.innerHTML = 1\n/* eval( */ b('// not a comment'); c(`/* nor this */`);"
        stripped = strip_js_comments(src)
        self.assertNotIn("innerHTML", stripped)
        self.assertNotIn("eval", stripped)
        self.assertIn("'// not a comment'", stripped)
        self.assertIn("`/* nor this */`", stripped)

    def test_no_device_data_in_browser_storage(self) -> None:
        # localStorage is allowed for UI preferences only (ADR 0007); these have no such use.
        for name, raw in self.files.items():
            code = strip_js_comments(raw)
            for api in ("sessionStorage", "indexedDB", "caches.open", "serviceWorker"):
                with self.subTest(file=name, api=api):
                    self.assertNotIn(api, code)


class StyleTests(unittest.TestCase):
    def test_no_external_urls_or_imports(self) -> None:
        names = assets(".css")
        self.assertTrue(names)
        for name in names:
            css = read(name)
            with self.subTest(file=name):
                self.assertEqual(external_urls(css), [])
                self.assertNotIn("@import", css)
                self.assertIsNone(re.search(r"url\(\s*['\"]?//", css))
                self.assertNotIn("expression(", css)


if __name__ == "__main__":
    unittest.main()
