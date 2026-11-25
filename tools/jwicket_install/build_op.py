"""Build ``dist/jwicket-install-op.py``: the on-box op-script installer (Spec 006 sections 6.5 and 6.6).

The output is one Python file that Junos runs as an op script (M4: ``op jwicket-install-op.py`` with
its ``checksum sha-256`` pinned under ``system scripts op file``; M4U: ``op url <per-tag URL> key sha-256
<hash>``). It carries, as source text, the modules of this package the executor needs (``plan``,
``state``, ``render``, ``health``, ``transport`` and ``op_template``, plus the package ``__init__``), and
the constants of ``render.op_payload``: the bundle's SHA-256, size, version and payload SHA-256, and the
bundle's per-tag release URL. Nothing of the installer goes into ``dist/jwicket.py``.

Deterministic: modules are sorted, literals are written with ``ascii()``, the payload is JSON with sorted
keys, and nothing depends on the time, the machine or the Python version that runs this tool, so two
builds from the same tree and bundle are byte-identical (``--check`` proves it). The generated file
starts with a prelude in plain syntax that checks the Python version before anything is compiled and
removes the script's own directory from ``sys.path`` (``/var/db/scripts/op`` may hold other operators'
scripts; a ``json.py`` there must not stand in for the standard library).

Python 3.7 (revision R1): Junos 25.2R1-S1.4 ships Python 3.7.10 (verified on a lab SRX4100,
docs/evidence/2026-11-24-srx4100-lab), so ``MIN_PYTHON`` is (3, 7). Every embedded module must parse with
Python 3.7's grammar (``ast.parse(feature_version=(3, 7))`` where the running Python offers it, 3.8 and
later; on 3.7 its own grammar is the floor) and import at module level only standard-library modules that
Python 3.7 has (``STDLIB_37``). This tool itself runs on Python 3.7 too.

Usage::

    PYTHONPATH=tools python3 -m jwicket_install.build_op --bundle dist/jwicket.py --tag v0.1.0.dev1 \\
        --repo <owner>/<repo> --out dist/jwicket-install-op.py [--check]

Standard library only; it runs on a build machine, never on a device. Every device step of the
generated script is unverified until lab test Q-INST-06.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import hashlib
import json
import logging
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, FrozenSet, List, Optional, Sequence, Tuple

from . import __version__, plan, render

LOG = logging.getLogger("jwicket_install.build_op")

PACKAGE = "jwicket_install"
PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_OUT = Path("dist") / plan.OP_FILE
# The modules the op script embeds, in the package; nothing else of it is shipped to a device.
EMBEDDED: Tuple[str, ...] = ("__init__", "health", "op_template", "plan", "render", "state", "transport")
FILENAME_PREFIX = "jwicket-install-op/"
MIN_PYTHON = (3, 7)
_TAG_RE = re.compile(r"^v[0-9][0-9A-Za-z.+_-]{0,62}\Z")
_REPO_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}\Z")
# Imports an embedded module may make besides the standard library and the embedded modules themselves:
# PyEZ, lxml, paramiko and scp are imported lazily inside functions, never at module level.
_LAZY_TOP_LEVEL: Tuple[str, ...] = ()
# The standard-library modules an embedded module may import at module level, each of which Python 3.7 (the
# box's) has: a newer one (graphlib, zoneinfo, tomllib) fails the build here rather than the run on a device.
# Newer submodules of older packages are refused by name. On 3.10 and later the list is also checked
# against sys.stdlib_module_names (a test).
STDLIB_37: FrozenSet[str] = frozenset(
    {
        "__future__",
        "abc",
        "argparse",
        "ast",
        "base64",
        "binascii",
        "collections",
        "contextlib",
        "copy",
        "dataclasses",
        "datetime",
        "enum",
        "errno",
        "functools",
        "hashlib",
        "hmac",
        "html",
        "http",
        "importlib",
        "io",
        "ipaddress",
        "itertools",
        "json",
        "logging",
        "math",
        "os",
        "posix",
        "pwd",
        "re",
        "secrets",
        "select",
        "socket",
        "ssl",
        "stat",
        "string",
        "struct",
        "subprocess",
        "sys",
        "tempfile",
        "textwrap",
        "threading",
        "time",
        "types",
        "typing",
        "unicodedata",
        "urllib",
        "uuid",
        "warnings",
        "weakref",
        "xml",
        "zlib",
    }
)
# Submodules of a 3.7 package that are newer than 3.7.
_NEWER_SUBMODULES: FrozenSet[str] = frozenset({"importlib.metadata", "importlib.resources.abc"})


class BuildError(Exception):
    """The op script cannot be built; the message names the input and the reason."""


@dataclass(frozen=True)
class Module:
    name: str
    relpath: str
    source: str

    @property
    def is_package(self) -> bool:
        return self.name == PACKAGE


@dataclass(frozen=True)
class OpScript:
    bundle: plan.BundleId
    tag: str
    repo: str
    url: str
    modules: Tuple[Module, ...]
    modules_sha256: str
    text: str


def read_bundle(path: Path) -> plan.BundleId:
    """The bundle's identity from its bytes and its tools/bundle.py header."""
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise BuildError(f"cannot read the bundle {path}: {exc.strerror or exc}") from exc
    if not data or len(data) > plan.MAX_BUNDLE_SIZE:
        raise BuildError(f"{path} is {len(data)} bytes; a bundle is 1 to {plan.MAX_BUNDLE_SIZE} bytes")
    try:
        head = data[:4096].decode("ascii")
    except UnicodeDecodeError as exc:
        raise BuildError(f"{path} does not start with tools/bundle.py's ASCII header") from exc
    try:
        return plan.BundleId.from_header(head, hashlib.sha256(data).hexdigest(), len(data))
    except plan.InputError as exc:
        raise BuildError(f"{path}: {exc}") from exc


# The f-string '=' specifier (f"{x=}", Python 3.8): a name or expression, '=', then '}', '!' or ':'.
_SELF_DOCUMENTING = re.compile(r"(?<!\{)\{\s*[^{}'\"!:=<>]+?\s*=\s*[}!:]")


def _segments(source: str) -> Callable[[ast.AST], str]:
    """A node's source text from its positions (Python 3.8+ records end positions; on 3.7 there are none,
    and its own parser already refuses 3.8 syntax). ``ast.get_source_segment`` re-splits the whole source
    on every call, character by character on 3.8, which is far too slow for a module of this size; column
    offsets are UTF-8 byte offsets, equal to character offsets for the ASCII sources embedded here."""
    lines = source.splitlines(keepends=True)
    ascii_only = source.isascii()

    def segment(node: ast.AST) -> str:
        end_line: Optional[int] = getattr(node, "end_lineno", None)
        end_col: Optional[int] = getattr(node, "end_col_offset", None)
        if end_line is None or end_col is None:
            return ""
        if not ascii_only:
            return ast.get_source_segment(source, node) or ""
        first: int = getattr(node, "lineno", 1) - 1
        start_col: int = getattr(node, "col_offset", 0)
        if first == end_line - 1:
            return lines[first][start_col:end_col]
        return lines[first][start_col:] + "".join(lines[first + 1 : end_line - 1]) + lines[end_line - 1][:end_col]

    return segment


def parse_37(source: str, filename: str) -> ast.Module:
    """``ast.parse`` with Python 3.7's grammar where this Python can apply it (``feature_version`` exists
    from 3.8), then the 3.8 forms that ``feature_version`` lets through on some interpreters (3.8 and 3.9
    accept ':=' and '/', 3.13 accepts f"{x=}"), refused as a SyntaxError. On 3.7 its own grammar is the
    floor. Best effort: CI also runs the unit tests on 3.7."""
    if sys.version_info >= (3, 8):
        tree = ast.parse(source, filename=filename, feature_version=MIN_PYTHON)
    else:
        tree = ast.parse(source, filename=filename)
    named = getattr(ast, "NamedExpr", None)
    segment = _segments(source)
    # A format spec is a JoinedStr inside the f-string; 3.8 gives such inner nodes unreliable positions.
    specs = {id(n.format_spec) for n in ast.walk(tree) if isinstance(n, ast.FormattedValue) and n.format_spec}
    for node in ast.walk(tree):
        what = ""
        if named is not None and isinstance(node, named):
            what = "an assignment expression (Python 3.8)"
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)) and getattr(
            node.args, "posonlyargs", None
        ):
            what = "positional-only parameters (Python 3.8)"
        elif isinstance(node, ast.JoinedStr) and id(node) not in specs and _SELF_DOCUMENTING.search(segment(node)):
            what = "the f-string '=' specifier (Python 3.8)"
        if what:
            error = SyntaxError(f"{what} is not Python 3.7")
            error.filename, error.lineno = filename, getattr(node, "lineno", 0)
            raise error
    return tree


def _imported(tree: ast.AST) -> List[Tuple[int, str]]:
    """(level, module) of every module-level import (relative imports keep their level)."""
    found: List[Tuple[int, str]] = []
    for node in getattr(tree, "body", []):
        if isinstance(node, ast.Import):
            found.extend((0, alias.name) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.module is None:
                found.extend((node.level, alias.name) for alias in node.names)
            else:
                found.append((node.level, node.module or ""))
    return found


def collect_modules(package_dir: Path = PACKAGE_DIR) -> Tuple[Module, ...]:
    """The embedded modules, each checked to compile for Python 3.7 and to import at module level only
    Python 3.7's standard library (``STDLIB_37``) and other embedded modules."""
    modules: List[Module] = []
    for stem in sorted(EMBEDDED):
        path = package_dir / f"{stem}.py"
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise BuildError(f"cannot read {path}: {exc.strerror or exc}") from exc
        if not source.isascii():
            raise BuildError(f"{path} is not ASCII: the op script embeds ASCII source only")
        relpath = f"{PACKAGE}/{stem}.py"
        try:
            tree = parse_37(source, relpath)
            compile(source, relpath, "exec", dont_inherit=True)
        except SyntaxError as exc:
            raise BuildError(f"{relpath} does not compile for Python 3.7 (line {exc.lineno}): {exc.msg}") from exc
        for level, name in _imported(tree):
            if level:
                if name.split(".")[0] not in EMBEDDED:
                    raise BuildError(f"{relpath} imports .{name}, which the op script does not embed")
                continue
            top = name.split(".")[0]
            if top == PACKAGE:
                inner = name.split(".")[1] if "." in name else "__init__"
                if inner not in EMBEDDED:
                    raise BuildError(f"{relpath} imports {name}, which the op script does not embed")
                continue
            if top not in STDLIB_37 and top not in _LAZY_TOP_LEVEL:
                raise BuildError(
                    f"{relpath} imports {name} at module level: only Python 3.7's standard library is allowed "
                    "(build_op.STDLIB_37)"
                )
            if name in _NEWER_SUBMODULES:
                raise BuildError(f"{relpath} imports {name}, which Python 3.7 does not have")
        name = PACKAGE if stem == "__init__" else f"{PACKAGE}.{stem}"
        modules.append(Module(name, relpath, source))
    return tuple(sorted(modules, key=lambda m: m.name))


def modules_sha256(modules: Sequence[Module]) -> str:
    digest = hashlib.sha256()
    for module in sorted(modules, key=lambda m: m.name):
        data = module.source.encode("ascii")
        digest.update(b"module\0%s\0%d\0" % (module.name.encode("ascii"), len(data)))
        digest.update(data)
    return digest.hexdigest()


def bundle_url(repo: str, tag: str) -> str:
    """The per-tag release URL (never /releases/latest, which cannot point at a pre-release: verified)."""
    return f"https://github.com/{repo}/releases/download/{tag}/{plan.DAEMON_FILE}"


def _literal_tuple(items: Sequence[str], indent: int) -> str:
    if not items:
        return "()"
    pad = " " * (indent + 4)
    inner = "".join(f"{pad}{item!a},\n" for item in items)
    return "(\n" + inner + " " * indent + ")"


def _header(bundle: plan.BundleId, tag: str, repo: str, url: str, digest: str, modules: Sequence[Module]) -> str:
    names = ", ".join(m.name for m in modules)
    return f'''#!/usr/bin/env python3
"""J-Wicket on-box installer (op script). GENERATED by tools/jwicket_install/build_op.py: DO NOT EDIT.

LAB ONLY. {plan.DEVICE_STATUS}

installer version: {__version__}
release tag:       {tag}
repository:        {repo}
bundle url:        {url}
bundle sha256:     {bundle.file_sha256}
bundle size:       {bundle.size}
bundle version:    {bundle.version}
bundle payload:    {bundle.payload_sha256}
bundle source ref: {bundle.source_ref or "not recorded"}
bundle features:   {",".join(sorted(bundle.features)) or "none"}
modules sha256:    {digest}
modules:           {names}

M4 (Spec 006 section 6.5): copy this file to /var/db/scripts/op/{plan.OP_FILE}, check its SHA-256 with
'file checksum sha-256' against docs/releases/{tag}.sha256sums on main (never the release page alone),
paste the bootstrap units (they pin that SHA-256 with 'set system scripts op file {plan.OP_FILE}
checksum sha-256 <hash>' and end at an unconfirmed 'commit confirmed 10'), then run
'op {plan.OP_FILE}'. M4U (6.6): 'op url <this file's per-tag URL> key sha-256 <hash>' after the
op-url bootstrap. The script reads the device, asks how you reach J-Wicket (tls, the default, or
tunnel), prints the plan and the warnings, asks for the device's host name (and 'lab only' on a physical
SRX with --lab-hardware), and writes nothing unless the typed answers match; every write is a 'commit
confirmed' that it confirms only after its health checks. It never creates {plan.STATE_DIR}; root
does that once, in the shell:
    {plan.STATE_DIR_ROOT_STEP}
It never makes the TLS key pair either: you do, in the shell as <user> (the script prints the unit).
"""
'''


# The prelude runs before anything else and must parse and run on any Python 3 (the version check has to
# be reachable on the old ones), so it uses no annotations and no f-strings, and only built-in modules
# until the script's own directory is off sys.path.
_PRELUDE = r'''
# --- prelude (fixed text from build_op.py): the Python version, then this file's directory off sys.path
import sys

if sys.version_info < _MIN_PYTHON:
    sys.stdout.write(_DEVICE_STATUS + "\n")
    sys.stdout.write(
        "This op script needs Python %d.%d or later; this device runs %d.%d. Nothing was read or written.\n"
        % (_MIN_PYTHON[0], _MIN_PYTHON[1], sys.version_info[0], sys.version_info[1])
    )
    sys.exit(1)


def _script_dirs():
    """This file's directory and the directory of the file a symbolic link to it points at."""
    import posix  # built into the interpreter: never read from a directory on sys.path

    here = globals().get("__file__") or (sys.argv[0] if sys.argv else "")
    if not here:
        return []
    if not here.startswith("/"):
        here = posix.getcwd() + "/" + here
    dirs = [here.rpartition("/")[0] or "/"]
    target = here
    for _hop in range(40):
        try:
            link = posix.readlink(target)
        except (OSError, ValueError):
            break
        target = link if link.startswith("/") else (target.rpartition("/")[0] or "/") + "/" + link
        dirs.append(target.rpartition("/")[0] or "/")
    return dirs


def _scrub_path(dirs):
    """Remove every sys.path entry that is one of ``dirs`` (by device and inode) and "" and "."."""
    import posix

    def identity(entry):
        try:
            st = posix.stat(entry)
        except (OSError, TypeError, ValueError):
            return None
        return (st.st_dev, st.st_ino)

    unsafe = set(identity(d) for d in dirs) - set([None])
    sys.path[:] = [
        entry
        for entry in sys.path
        if not (entry in ("", ".") or (isinstance(entry, str) and identity(entry) in unsafe))
    ]


_scrub_path(_script_dirs())
'''

_RUNTIME = r'''

# --- runtime (fixed text from build_op.py) ------------------------------------------------------
import importlib.abc
import importlib.machinery
import importlib.util


class _OpImporter(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Serves the embedded jwicket_install modules from memory, first on sys.meta_path, so no
    jwicket_install directory anywhere on sys.path can stand in for the code that was built and pinned by
    its SHA-256. The package gets an empty __path__: a module that is not embedded cannot load from disk."""

    def find_spec(self, fullname, path, target=None):
        entry = _MODULES.get(fullname)
        if entry is None:
            return None
        return importlib.util.spec_from_loader(
            fullname, self, origin=_FILENAME_PREFIX + entry[1], is_package=entry[0]
        )

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        is_package, relpath, lines = _MODULES[module.__name__]
        filename = _FILENAME_PREFIX + relpath
        module.__file__ = filename
        if is_package:
            module.__path__ = []
        code = compile("".join(lines), filename, "exec", dont_inherit=True)
        # The embedded source is text build_op.py copied into this very file from the reviewed tree; Junos
        # runs this file only when its SHA-256 matches the one the operator pinned, so the source carries
        # exactly this file's trust. Nothing here executes any input.
        exec(code, module.__dict__)

    def get_source(self, fullname):
        entry = _MODULES.get(fullname)
        return None if entry is None else "".join(entry[2])

    def is_package(self, fullname):
        entry = _MODULES.get(fullname)
        if entry is None:
            raise ImportError(fullname + " is not in this op script", name=fullname)
        return entry[0]


def _run():
    for finder in sys.meta_path:
        if isinstance(finder, _OpImporter):
            break
    else:
        sys.meta_path.insert(0, _OpImporter())
    from jwicket_install import op_template

    return op_template.main(PAYLOAD_JSON)


if __name__ == "__main__":
    sys.exit(_run())
'''


def payload_json(bundle: plan.BundleId, url: str, tag: str, repo: str) -> str:
    payload = render.op_payload(bundle, {"bundle": url})
    payload["release"] = {"tag": tag, "repo": repo}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def render_op(bundle: plan.BundleId, tag: str, repo: str, modules: Sequence[Module]) -> Tuple[str, str, str]:
    """(text, url, modules digest) of the op script."""
    if _TAG_RE.match(tag) is None:
        raise BuildError(f"--tag {tag[:80]!r} must be 'v' followed by a version (letters, digits and ._+-)")
    if _REPO_RE.match(repo) is None:
        raise BuildError(f"--repo {repo[:120]!r} must be <owner>/<repository>")
    if tag != "v" + bundle.version:
        raise BuildError(
            f"--tag {tag} does not name this bundle's version ({bundle.version}): the op script would fetch "
            "another release's bundle and refuse it"
        )
    url = bundle_url(repo, tag)
    try:
        payload = payload_json(bundle, url, tag, repo)
    except plan.PlanError as exc:
        raise BuildError(f"the payload cannot be built: {exc}") from exc
    digest = modules_sha256(modules)
    parts = [_header(bundle, tag, repo, url, digest, modules)]
    parts.append(f"\n_DEVICE_STATUS = {plan.DEVICE_STATUS!a}\n")
    parts.append(f"_MIN_PYTHON = {MIN_PYTHON!a}\n")
    parts.append(_PRELUDE)
    parts.append("\n")
    parts.append(f"INSTALLER_VERSION = {__version__!a}\n")
    parts.append(f"BUNDLE_SHA256 = {bundle.file_sha256!a}\n")
    parts.append(f"MODULES_SHA256 = {digest!a}\n")
    parts.append(f"_FILENAME_PREFIX = {FILENAME_PREFIX!a}\n")
    parts.append(f"PAYLOAD_JSON = {payload!a}\n\n")
    parts.append("# name -> (is_package, file name inside the op script, source lines)\n")
    parts.append("_MODULES = {\n")
    for module in sorted(modules, key=lambda m: m.name):
        lines = module.source.splitlines(keepends=True)
        parts.append(f"    {module.name!a}: ({module.is_package}, {module.relpath!a}, {_literal_tuple(lines, 4)}),\n")
    parts.append("}\n")
    parts.append(_RUNTIME)
    return "".join(parts), url, digest


def build(bundle_path: Path, tag: str, repo: str, package_dir: Path = PACKAGE_DIR) -> OpScript:
    bundle = read_bundle(bundle_path)
    modules = collect_modules(package_dir)
    text, url, digest = render_op(bundle, tag, repo, modules)
    try:
        compile(text, plan.OP_FILE, "exec", dont_inherit=True)
        parse_37(text, plan.OP_FILE)
    except SyntaxError as exc:  # a defect in this tool, not in the inputs
        raise BuildError(f"the generated op script does not compile (line {exc.lineno}): {exc.msg}") from exc
    if not text.isascii():
        raise BuildError("the generated op script is not ASCII")
    return OpScript(bundle, tag, repo, url, modules, digest, text)


def write_atomic(path: Path, data: bytes) -> None:
    """Replace ``path`` in one step, mode 0644 (Junos wants owner-only write on an unsigned script)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp_path = Path(tmp)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        tmp_path.chmod(0o644)
        tmp_path.replace(path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):  # Path.unlink(missing_ok=) is Python 3.8+
            tmp_path.unlink()
        raise


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="build_op", description="Build the on-box op-script installer (M4, M4U).")
    parser.add_argument("--bundle", type=Path, required=True, help="the bundle built by tools/bundle.py")
    parser.add_argument("--tag", required=True, help="the release tag, 'v' + the bundle's version")
    parser.add_argument("--repo", required=True, help="<owner>/<repository> on github.com")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output file (default: %(default)s)")
    parser.add_argument("--check", action="store_true", help="exit 1 if --out differs from a fresh build")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="build_op: %(levelname)s %(message)s", stream=sys.stderr)
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        script = build(args.bundle, args.tag, args.repo)
    except BuildError as exc:
        LOG.error("build failed: %s", exc)
        return 2
    data = script.text.encode("ascii")
    out: Path = args.out
    if args.check:
        try:
            existing = out.read_bytes()
        except OSError as exc:
            LOG.error("cannot read %s (%s); build it first", out, exc.strerror or exc)
            return 1
        if existing != data:
            LOG.error("%s differs from a fresh build; rebuild it, and never edit it by hand", out)
            return 1
        LOG.info("%s matches a fresh build", out)
        return 0
    write_atomic(out, data)
    summary: Dict[str, object] = {
        "out": str(out),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "bundle_sha256": script.bundle.file_sha256,
        "modules_sha256": script.modules_sha256,
        "url": script.url,
    }
    LOG.info("%s", json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
