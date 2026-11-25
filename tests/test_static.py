"""Static UI assets obey the strict CSP and the offline rule (no external URLs, no HTML injection APIs)."""

from __future__ import annotations

import re
import unittest
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from jwicket.resources import STATIC_DIR

ROOT = Path(__file__).resolve().parent.parent
BRAND_DIR = ROOT / "docs" / "brand"
PREVIEW_DIR = ROOT / "docs" / "images" / "brand"

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


IMPORT = re.compile(
    r"""(?:\bimport\s*\(\s*|\bimport\s[^'"`;]*?\bfrom\s*|\bimport\s*|\bexport\s[^'"`;]*?\bfrom\s*)"""
    r"""['"]([^'"]+)['"]"""
)
SERVABLE = re.compile(r"^[a-z0-9][a-z0-9_\-]*(/[a-z0-9][a-z0-9_\-]*)*\.(html|js|css|svg)\Z")


def module_imports(name: str) -> List[str]:
    """Static and dynamic import specifiers of one module, resolved to paths under static/."""
    base = name.rsplit("/", 1)[0] if "/" in name else ""
    out = []
    for spec in IMPORT.findall(strip_js_comments(read(name))):
        if spec.startswith("/static/"):
            out.append(spec[len("/static/"):])
            continue
        parts = [p for p in base.split("/") if p]
        for piece in spec.split("/"):
            if piece in ("", "."):
                continue
            if piece == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(piece)
        out.append("/".join(parts))
    return out


class AssetGraphTests(unittest.TestCase):
    """index.html and the module graph reference only files that exist, and every file is used."""

    @classmethod
    def setUpClass(cls) -> None:
        parsed = IndexParser()
        parsed.feed(read("index.html"))
        parsed.close()
        cls.refs = []
        for _tag, attrs in parsed.tags:
            for name, value in attrs:
                if name in ("src", "href") and value and value.startswith("/static/"):
                    cls.refs.append(value[len("/static/"):])
        cls.files = set(assets(".js")) | set(assets(".css")) | set(assets(".svg")) | set(assets(".html"))

    def test_index_references_exist_and_are_servable(self) -> None:
        self.assertIn("js/main.js", self.refs)
        for ref in self.refs:
            with self.subTest(ref=ref):
                self.assertRegex(ref, SERVABLE)
                self.assertTrue((STATIC_DIR / ref).is_file(), f"index.html references missing /static/{ref}")

    def test_stylesheets_in_contract_order(self) -> None:
        sheets = [r for r in self.refs if r.endswith(".css")]
        self.assertEqual(
            sheets, ["css/app.css", "css/querybar.css", "css/sessions.css", "css/logs.css", "css/policies.css"]
        )

    def test_every_import_resolves(self) -> None:
        for name in assets(".js"):
            for target in module_imports(name):
                with self.subTest(module=name, imports=target):
                    self.assertRegex(target, SERVABLE)
                    self.assertTrue((STATIC_DIR / target).is_file(), f"{name} imports missing {target}")

    def test_no_unused_assets(self) -> None:
        reached = {"index.html"}
        todo = list(self.refs)
        while todo:
            name = todo.pop()
            if name in reached:
                continue
            reached.add(name)
            if name.endswith(".js") and (STATIC_DIR / name).is_file():
                todo.extend(module_imports(name))
        self.assertEqual(sorted(self.files - reached), [], "static files nothing loads")

    def test_v1_files_are_gone(self) -> None:
        for name in ("app.js", "app.css"):
            with self.subTest(name=name):
                self.assertFalse((STATIC_DIR / name).exists(), f"superseded v1 file static/{name} still present")

    def test_every_file_is_servable(self) -> None:
        for p in STATIC_DIR.rglob("*"):
            if p.is_file():
                rel = p.relative_to(STATIC_DIR).as_posix()
                with self.subTest(file=rel):
                    self.assertRegex(rel, SERVABLE, "the server would not serve this file")


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



# ---- the brand: the Sentinel Gate emblem, the favicon, the wordmark, the default colour scheme ---------

SVG_NS = "{http://www.w3.org/2000/svg}"
SHAPES = ("polygon", "rect", "polyline")
# What makes the emblem's shape; colours are compared separately (CSS classes in the UI, fixed in the favicon).
GEOMETRY = ("points", "x", "y", "width", "height", "rx", "stroke-width", "stroke-linejoin", "stroke-miterlimit")
DATA_URI = re.compile(r"\bdata:[a-z-]+/[a-z0-9.+-]+[;,]", re.IGNORECASE)
OLD_MARK = re.compile(r"lg-stump|lg-bail|lg-ground|_stumps|stumps and (two )?bails", re.IGNORECASE)

Shape = Tuple[str, Tuple[Tuple[str, str], ...]]
# The brand colours (docs/brand/README.md, "Colours"): frame, J and wordmark ink, mint.
INKS = {
    "dark": ("#475d68", "#ecf2f6", "#1ff3c3"),
    "light": ("#0c141d", "#0c141d", "#08d496"),
    "mono-black": ("#000", "#000", "#000"),
    "mono-white": ("#fff", "#fff", "#fff"),
}
# Inter's cap height (1490 of 2048 units), and the emblem's brackets (y 60 to 202 of its 236-unit box).
CAP_PER_EM = 1490 / 2048
BRACKETS_PER_BOX = 142 / 236


def number(value: str) -> str:
    """'4' and '4.0', '99,37 171,37' and '99, 37  171, 37' compare equal."""
    nums = re.findall(r"-?[0-9]*\.?[0-9]+", value)
    if not nums or re.sub(r"[-0-9., ]", "", value):
        return value.strip()
    return " ".join(format(float(n), "g") for n in nums)


def shape(tag: str, attrs: Dict[str, str]) -> Shape:
    return tag, tuple((k, number(attrs[k])) for k in GEOMETRY if k in attrs)


class MarkParser(HTMLParser):
    """The shapes of every <svg class="logo-mark"> in index.html (HTMLParser lowercases names)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.marks: List[List[Shape]] = []
        self.svg_attrs: List[Dict[str, str]] = []
        self.shape_attrs: List[Dict[str, Optional[str]]] = []
        self._in = False

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        a = {k: v or "" for k, v in attrs}
        if tag == "svg" and "logo-mark" in a.get("class", "").split():
            self._in = True
            self.marks.append([])
            self.svg_attrs.append(a)
        elif self._in and tag in SHAPES:
            self.marks[-1].append(shape(tag, a))
            self.shape_attrs.append(dict(attrs))

    def handle_startendtag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag == "svg":
            self._in = False


class TextParser(HTMLParser):
    """The text of one element by id, as a screen reader gets it (aria-hidden left out) and as it is
    seen (.sr-only left out), and the text of its .wm-dash."""

    def __init__(self, element_id: str) -> None:
        super().__init__(convert_charrefs=True)
        self.element_id = element_id
        self.spoken: List[str] = []
        self.seen: List[str] = []
        self.dash: List[str] = []
        self._stack: List[Tuple[str, bool, bool, bool]] = []  # tag, hidden, sr-only, dash

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        a = {k: v or "" for k, v in attrs}
        if not self._stack and a.get("id") != self.element_id:
            return
        hidden, sr, dash = self._stack[-1][1:] if self._stack else (False, False, False)
        classes = a.get("class", "").split()
        self._stack.append((tag, hidden or a.get("aria-hidden") == "true", sr or "sr-only" in classes,
                            dash or "wm-dash" in classes))

    def handle_endtag(self, tag: str) -> None:
        if self._stack:
            self._stack.pop()

    def handle_data(self, data: str) -> None:
        if not self._stack:
            return
        _tag, hidden, sr, dash = self._stack[-1]
        if not hidden:
            self.spoken.append(data)
        if not sr:
            self.seen.append(data)
        if dash:
            self.dash.append(data)


def drawn_shapes(root: ET.Element) -> List[Tuple[ET.Element, Dict[str, str]]]:
    """The emblem's shapes in an SVG file, in paint order, each with its fill and stroke as painted
    (inherited from an enclosing <g>). A <mask> is not painted, so its shapes are left out."""
    out: List[Tuple[ET.Element, Dict[str, str]]] = []

    def walk(el: ET.Element, paint: Dict[str, str]) -> None:
        tag = el.tag[len(SVG_NS):]
        if tag == "mask":
            return
        here = dict(paint)
        for k in ("fill", "stroke"):
            if k in el.attrib:
                here[k] = el.attrib[k].lower()
        if tag in SHAPES:
            out.append((el, here))
        for child in el:
            walk(child, here)

    walk(root, {})
    return out


def without_frame_stroke(parts: List[Shape]) -> List[Shape]:
    """The parts with the frame's stroke-width left out (the small and the one-colour icons thicken it)."""
    tag, attrs = parts[0]
    return [(tag, tuple(a for a in attrs if a[0] != "stroke-width"))] + parts[1:]


def css_px(css: str, selector: str, prop: str) -> float:
    """A px value of `prop` in the rule for exactly `selector` (comments left out)."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)
    rule = re.search(r"(?:^|\})\s*" + re.escape(selector) + r"\s*\{([^}]*)\}", css)
    assert rule, selector
    value = re.search(r"(?:^|;)\s*" + re.escape(prop) + r"\s*:\s*([^;]+);", rule.group(1))
    assert value, (selector, prop)
    raw = value.group(1).strip()
    token = re.fullmatch(r"var\((--[\w-]+)\)", raw)
    if token:
        defined = re.search(re.escape(token.group(1)) + r"\s*:\s*([^;]+);", css)
        assert defined, token.group(1)
        raw = defined.group(1).strip()
    return float(raw[:-2]) if raw.endswith("px") else float("nan")


def brand_js_parts() -> List[Shape]:
    """EMBLEM_PARTS in js/brand.js: [tag, { key: value, ... }] entries."""
    source = strip_js_comments(read("js/brand.js"))
    body = source[source.index("EMBLEM_PARTS") :]
    body = body[: body.index("];")]
    parts = []
    for tag, attrs in re.findall(r"\[\s*'(\w+)',\s*\{([^}]*)\}\s*\]", body):
        pairs = re.findall(r"""(?:'([\w-]+)'|([\w]+)):\s*(?:'([^']*)'|([0-9.]+))""", attrs)
        parts.append(shape(tag, {(q or b): (sv or nv) for q, b, sv, nv in pairs}))
    return parts


def css_declarations(css: str, prop: str) -> List[Tuple[str, str]]:
    """(selector, value) of every declaration of `prop`; the selector is the innermost rule's."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)
    out = []
    for match in re.finditer(re.escape(prop) + r"\s*:\s*([^;]+);", css):
        open_at = css.rfind("{", 0, match.start())
        start = max(css.rfind("{", 0, open_at), css.rfind("}", 0, open_at)) + 1
        out.append((" ".join(css[start:open_at].split()), match.group(1).strip()))
    return out


class BrandTests(unittest.TestCase):
    """The Sentinel Gate emblem replaced the cricket-wicket mark everywhere; Obsidian & Phosphor is the
    default colour scheme from the first paint (docs/brand/ has the guide)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.index = read("index.html")
        cls.marks = MarkParser()
        cls.marks.feed(cls.index)
        cls.marks.close()
        cls.css = read("css/app.css")
        cls.brand_js = strip_js_comments(read("js/brand.js"))

    def test_the_old_mark_is_gone(self) -> None:
        for p in sorted(STATIC_DIR.rglob("*")):
            if p.is_file():
                rel = p.relative_to(STATIC_DIR).as_posix()
                with self.subTest(file=rel):
                    self.assertIsNone(OLD_MARK.search(p.read_text(encoding="utf-8")), "the cricket-wicket mark")

    def test_one_emblem_in_index_brand_js_and_the_favicon(self) -> None:
        parts = brand_js_parts()
        self.assertEqual([t for t, _ in parts], ["polygon", "polygon", "rect", "rect", "rect", "polygon", "polygon",
                                                 "polyline"])
        self.assertEqual(len(self.marks.marks), 2, "the boot screen and the sign-in card each draw the emblem")
        for i, mark in enumerate(self.marks.marks):
            with self.subTest(index_mark=i):
                self.assertEqual(mark, parts)
                self.assertEqual(self.marks.svg_attrs[i].get("viewbox"), "15 13 236 236")
                self.assertEqual(self.marks.svg_attrs[i].get("aria-hidden"), "true")
        root = ET.fromstring(read("logo.svg"))
        drawn = drawn_shapes(root)
        tile, emblem = drawn[0][0], drawn[1:]
        self.assertEqual(tile.tag, f"{SVG_NS}rect", "the favicon starts with its tile")
        favicon = [shape(el.tag[len(SVG_NS):], dict(el.attrib)) for el, _ in emblem]
        self.assertEqual(without_frame_stroke(favicon), without_frame_stroke(parts))
        self.assertEqual(emblem[0][0].get("stroke-width"), "12", "the heavier frame of app-icon-small.svg")

    def test_favicon_is_app_icon_small(self) -> None:
        """Below 32 px only app-icon-small.svg is used (docs/brand/README.md, "Rules"): the favicon is it."""
        brand = (BRAND_DIR / "app-icon-small.svg").read_text(encoding="utf-8")
        self.assertEqual(read("logo.svg"), re.sub(r"#[0-9A-Fa-f]{6}\b", lambda m: m.group(0).lower(), brand))

    def test_favicon_colours_part_by_part(self) -> None:
        drawn = drawn_shapes(ET.fromstring(read("logo.svg")))
        frame, j, mint = INKS["dark"]
        expected = [{"fill": "#0b0e14", "stroke": frame}, {"fill": "none", "stroke": frame}, {"fill": j}]
        expected += [{"fill": mint}] * 5 + [{"fill": "none", "stroke": mint}]
        self.assertEqual([paint for _, paint in drawn], expected)

    def test_brand_files_draw_the_same_emblem_in_the_brand_colours(self) -> None:
        parts = without_frame_stroke(brand_js_parts())
        files = sorted(BRAND_DIR.glob("*.svg")) + sorted(PREVIEW_DIR.glob("*.svg"))
        self.assertEqual(len(files), 12, "10 brand files and the guide's 2 previews")
        for path in files:
            name = path.stem
            with self.subTest(file=name):
                root = ET.fromstring(path.read_text(encoding="utf-8"))
                drawn = drawn_shapes(root)
                if name.startswith(("app-icon", "preview-")):
                    drawn = drawn[1:]  # the tile or the preview's background
                kind = next(k for k in ("mono-black", "mono-white", "light", "dark") if k in name or
                            (k == "dark" and name.startswith("app-icon")))
                frame, ink, mint = INKS[kind]
                found = [shape(el.tag[len(SVG_NS):], dict(el.attrib)) for el, _ in drawn]
                self.assertEqual(without_frame_stroke(found), parts)
                width = {"app-icon-small": "12"}.get(name, "6" if kind.startswith("mono") else "4")
                self.assertEqual(drawn[0][0].get("stroke-width"), width, "the frame")
                paints = [paint for _, paint in drawn]
                self.assertEqual(paints[0], {"fill": "none", "stroke": frame})
                self.assertEqual(paints[1].get("fill"), ink, "the J")
                self.assertEqual({p.get("fill") for p in paints[2:7]}, {mint}, "the line, the dot and the brackets")
                self.assertEqual(paints[7].get("stroke"), mint, "the arrow")
                words = [(el.get("d", ""), (el.get("fill") or "").lower()) for el in root.iter(f"{SVG_NS}path")]
                if name.startswith(("lockup", "preview")):
                    if kind.startswith("mono"):
                        self.assertEqual([fill for _, fill in words], [ink], "one colour, the hyphen included")
                    else:
                        self.assertEqual([fill for _, fill in words], [ink, mint], "the ink and the mint hyphen")
                else:
                    self.assertEqual(words, [], "an emblem has no wordmark")

    def test_one_wordmark_drawing_in_every_lockup(self) -> None:
        drawings = set()
        for path in sorted(BRAND_DIR.glob("lockup-*.svg")) + sorted(PREVIEW_DIR.glob("preview-*.svg")):
            root = ET.fromstring(path.read_text(encoding="utf-8"))
            drawings.add("".join(el.get("d", "") for el in root.iter(f"{SVG_NS}path")))
        self.assertEqual(len(drawings), 1, "the same outlines and hyphen in the colour, one-colour and preview lockups")
        hyphen = "M400 119.9H365V139.6H400Z"
        self.assertTrue(drawings.pop().endswith(hyphen), "the redrawn hyphen, 0.40 x 0.22 of the cap height")

    def test_index_marks_take_their_colours_from_css(self) -> None:
        for attrs in self.marks.shape_attrs:
            with self.subTest(shape=attrs.get("class")):
                self.assertIn(attrs.get("class"), ("lg-frame", "lg-j", "lg-acc", "lg-acc-stroke"))
                self.assertIn(attrs.get("fill"), (None, "none"))
                self.assertIsNone(attrs.get("stroke"))
                self.assertIsNone(attrs.get("style"))
        for cls_name in ("lg-frame", "lg-j", "lg-acc", "lg-acc-stroke"):
            with self.subTest(rule=cls_name):
                self.assertRegex(self.css, r"\.logo-mark \." + cls_name + r" \{[^}]*var\(--logo-")

    def test_the_logo_keeps_the_brand_colours_in_every_scheme(self) -> None:
        night, day = INKS["dark"], INKS["light"]
        for i, prop in enumerate(("--logo-frame", "--logo-j", "--logo-mint")):
            with self.subTest(token=prop):
                self.assertEqual(sorted(css_declarations(self.css, prop)), sorted([
                    (":root", night[i]),
                    (':root:not([data-theme="dark"])', day[i]),
                    (':root[data-theme="light"]', day[i]),
                ]), "one value by night and one by day, and no scheme overrides it")
        self.assertRegex(self.css, r"\.wordmark \{[^}]*color: var\(--logo-j\)")
        self.assertRegex(self.css, r"\.wordmark \.wm-dash \{[^}]*color: var\(--logo-mint\)")

    def test_ui_lockups_keep_the_lockup_proportions(self) -> None:
        """Emblem and wordmark sized as in docs/brand/lockup-dark.svg: the cap height 0.6 of the brackets'
        height (0.53 to 0.65 on the boards), and the lockup at least the brand's 120 px wide."""
        for mark, word, gap in ((".tb-brand .logo-mark", ".tb-brand .wordmark", ".tb-brand"),
                                (".signin-brand .logo-mark", ".signin-brand h1", ".signin-lockup")):
            with self.subTest(lockup=gap):
                box = css_px(self.css, mark, "width")
                self.assertEqual(box, css_px(self.css, mark, "height"))
                size = css_px(self.css, word, "font-size") if word.endswith(".wordmark") else 40.0
                ratio = size * CAP_PER_EM / (box * BRACKETS_PER_BOX)
                self.assertTrue(0.55 <= ratio <= 0.65, f"cap height / brackets {ratio:.2f}")
                # lockup-dark.svg is 797 units wide, the emblem's box 236: at 120 px the box is 35.5 px.
                self.assertGreaterEqual(box, 236 * 120 / 797, "no smaller than the lockup at its minimum width")
                self.assertGreater(css_px(self.css, gap, "gap"), 0)
        self.assertRegex(self.css, r"--fs-brand: 40px;")
        self.assertIn('<div class="signin-lockup">', self.index, "the sign-in shows the horizontal lockup")

    def test_favicon_is_referenced_and_self_contained(self) -> None:
        icons = [dict(a) for t, a in index_tags(self.index) if t == "link" and dict(a).get("rel") == "icon"]
        self.assertEqual(icons, [{"rel": "icon", "href": "/static/logo.svg", "type": "image/svg+xml"}])
        text = read("logo.svg")
        root = ET.fromstring(text)
        self.assertEqual(root.tag, f"{SVG_NS}svg")
        self.assertEqual(root.get("aria-label"), "J-Wicket")
        title = root.find(f"{SVG_NS}title")
        self.assertIsNotNone(title)
        self.assertEqual(title.text if title is not None else None, "J-Wicket")
        _x, _y, w, h = (float(v) for v in str(root.get("viewBox")).split())
        self.assertEqual(w, h, "a square icon")
        for el in root.iter():
            with self.subTest(element=el.tag):
                self.assertNotIn(el.tag[len(SVG_NS):], ("script", "style", "image", "use", "foreignObject"))
                for name in el.attrib:
                    self.assertNotIn(name, ("style", "class"), "colours live in the file, not in a stylesheet")
                    self.assertFalse(name.endswith("href"), name)
                    self.assertFalse(name.lower().startswith("on"), name)
        self.assertNotIn("var(", text)
        self.assertIsNone(DATA_URI.search(text))
        for colour in ("#0b0e14", "#475d68", "#ecf2f6", "#1ff3c3"):
            self.assertIn(colour, text.lower(), "the emblem on the Obsidian tile, in the brand colours")
        self.assertLess(len(text.encode("utf-8")), 2048, "the favicon stays small (it ships in the bundle)")

    def test_no_data_uris(self) -> None:
        for name in assets(".html") + assets(".css") + assets(".svg") + assets(".js"):
            text = strip_js_comments(read(name)) if name.endswith(".js") else read(name)
            with self.subTest(file=name):
                self.assertIsNone(DATA_URI.search(text), "img-src 'self' blocks data: URIs")

    def test_signin_wordmark_reads_as_one_word(self) -> None:
        parser = TextParser("signin-title")
        parser.feed(self.index)
        parser.close()
        self.assertEqual("".join(parser.spoken).strip(), "J-Wicket", "the accessible name of the sign-in heading")
        self.assertEqual("".join(parser.seen).strip(), "J-Wicket", "what is seen")
        self.assertEqual("".join(parser.dash), "-", "the hyphen is the mint .wm-dash")
        heading = re.search(r'<h1 id="signin-title"[^>]*>(.*?)</h1>', self.index)
        self.assertIsNotNone(heading)
        self.assertEqual(heading.group(1) if heading else None, 'J<span class="wm-dash">-</span>Wicket',
                         "the name once: copied or found, it reads J-Wicket")

    def test_topbar_wordmark_has_no_hidden_copy(self) -> None:
        main = strip_js_comments(read("js/main.js"))
        body = main[main.index("function wordmark()"):]
        body = body[: body.index("\n}\n")]
        self.assertNotIn("sr-only", body, "the link's aria-label names it; a hidden copy doubles copied text")
        self.assertNotIn("aria-hidden", body)
        self.assertIn("'wm-dash'", body)

    def test_default_scheme_is_set_before_any_script(self) -> None:
        default = re.search(r"SCHEMES = \[\s*\{ id: '(\w+)'", self.brand_js)
        self.assertIsNotNone(default)
        self.assertEqual(default.group(1) if default else None, "obsidian", "the first scheme is the default")
        html = [dict(a) for t, a in index_tags(self.index) if t == "html"]
        self.assertEqual(html[0].get("data-scheme"), "obsidian", "the first paint has the default")
        main = strip_js_comments(read("js/main.js"))
        self.assertIn("from './brand.js'", main)
        self.assertIsNone(re.search(r"const SCHEMES\b", main), "one list of schemes, in brand.js")
        self.assertIsNone(re.search(r"delete [\w.]*dataset\.scheme", main), "data-scheme always names a scheme")

    def test_every_scheme_rule_resolves(self) -> None:
        ids = re.findall(r"\{ id: '(\w+)', label:", self.brand_js)
        self.assertEqual(ids, ["obsidian", "hpe", "nordic"])
        css = re.sub(r"/\*.*?\*/", "", self.css, flags=re.DOTALL)
        named = set(re.findall(r'data-scheme="(\w+)"', css))
        # HPE is the bare :root rules, so data-scheme="hpe" (or none, or an unknown value) gets it.
        self.assertEqual(named, {"obsidian", "nordic"})
        self.assertNotIn(":not([data-scheme", css)
        light = css.index("@media (prefers-color-scheme: light)")
        for scheme in ("obsidian", "nordic"):
            with self.subTest(scheme=scheme):
                night = css.find(f':root[data-scheme="{scheme}"] {{')
                media = css.find(f':root[data-scheme="{scheme}"]:not([data-theme="dark"]) {{')
                day = css.find(f':root[data-scheme="{scheme}"][data-theme="light"] {{')
                self.assertTrue(night >= 0 and media > light and day > media, "night, system day and day blocks")
        bg = {selector for selector, _ in css_declarations(self.css, "--bg")}
        for selector in (":root", ':root:not([data-theme="dark"])', ':root[data-theme="light"]'):
            with self.subTest(hpe=selector):
                self.assertIn(selector, bg, "HPE's night, system day and day tokens stay the bare :root rules")


def index_tags(text: str) -> List[Tuple[str, List[Tuple[str, Optional[str]]]]]:
    parsed = IndexParser()
    parsed.feed(text)
    parsed.close()
    return parsed.tags


if __name__ == "__main__":
    unittest.main()
