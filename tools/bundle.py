#!/usr/bin/env python3
"""Build ``dist/jwicket.py``: J-Wicket as one self-contained file that Junos can run as a JET app.

Why one file: Junos runs unsigned Python from ``/var/db/scripts/jet/``, and whether such a script
may import sibling modules is unverified, so the bundle carries the whole package with it:

* every module under ``src/jwicket`` as source text, except the development-only modules
  (``devserver``, ``fixtures``) and ``__main__`` (importing it starts the daemon; the bundle has its
  own entry point);
* every file under ``src/jwicket/static``, base64-encoded, served to ``jwicket.resources`` through a
  generated module, ``jwicket._embedded``.

The output is deterministic: entries are sorted, nothing depends on the time, the build machine or
the Python version that runs this tool (literals are written with ``ascii()``), so two builds of the
same tree with the same ``--source-ref`` are byte-identical, and ``--check`` proves it.

Usage::

    python3 tools/bundle.py [--out dist/jwicket.py] [--source-ref REF] [--check]

Standard library only. This tool runs on a build machine, never on a device.
"""

from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import logging
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

LOG = logging.getLogger("jwicket.bundle")

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "jwicket"
PACKAGE_DIR = REPO_ROOT / "src" / PACKAGE
DEFAULT_OUT = Path("dist") / "jwicket.py"
STATIC_DIR = "static"

# Never shipped to a device. devserver and fixtures replay synthetic data for development and tests;
# __main__ is "python -m jwicket", and importing it would start the daemon.
EXCLUDED_MODULES: Tuple[str, ...] = ("jwicket.__main__", "jwicket.devserver", "jwicket.fixtures")
EMBEDDED_MODULE = "jwicket._embedded"
BUNDLE_FILENAME_PREFIX = "jwicket-bundle/"

# The on-box Python version is unverified (qualification Q-RT-01); 3.9 is the floor we build for.
MIN_PYTHON = (3, 9)
B64_LINE = 76

# Both end up in the generated docstring, so only plain characters are accepted.
_SOURCE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/+@-]{0,127}$")
_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+!_-]{0,63}$")


class BuildError(Exception):
    """The source tree cannot be bundled. The message names the file and the reason."""


@dataclass(frozen=True)
class Module:
    name: str  # dotted module name, e.g. "jwicket.web.http"
    relpath: str  # "jwicket/web/http.py": the file name tracebacks show, under BUNDLE_FILENAME_PREFIX
    is_package: bool
    source: str


@dataclass(frozen=True)
class Resource:
    name: str  # "static/app.js": the key jwicket.resources looks up
    data: bytes


@dataclass(frozen=True)
class Bundle:
    version: str
    source_ref: Optional[str]
    modules: Tuple[Module, ...]
    resources: Tuple[Resource, ...]
    payload_sha256: str
    text: str


# --- reading the source tree ----------------------------------------------------------------------


def _walk(root: Path) -> List[Path]:
    """Every regular file under ``root`` (skipping __pycache__), refusing symbolic links."""
    found: List[Path] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        for entry in directory.iterdir():
            if entry.is_symlink():
                raise BuildError(f"{entry} is a symbolic link; the bundle takes regular files only")
            if entry.is_dir():
                if entry.name != "__pycache__":
                    pending.append(entry)
            elif entry.is_file():
                found.append(entry)
            else:
                raise BuildError(f"{entry} is not a regular file")
    return sorted(found, key=lambda p: p.relative_to(root).as_posix())


def read_version(package_dir: Path) -> str:
    """``__version__`` from the package's ``__init__.py``, parsed rather than imported."""
    init = package_dir / "__init__.py"
    try:
        tree = ast.parse(init.read_text(encoding="utf-8"), filename=str(init))
    except (OSError, SyntaxError, UnicodeDecodeError) as exc:
        raise BuildError(f"cannot read the version from {init}: {exc}") from exc
    for node in tree.body:
        targets: List[ast.expr]
        value: Optional[ast.expr]
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        else:
            continue
        if any(isinstance(t, ast.Name) and t.id == "__version__" for t in targets):
            if isinstance(value, ast.Constant) and isinstance(value.value, str) and _VERSION.match(value.value):
                return value.value
            raise BuildError(f"{init}: __version__ must be a plain string literal such as '0.1.0'")
    raise BuildError(f"{init} does not assign __version__")


def _module_name(rel: Path) -> Tuple[str, bool]:
    parts = list(rel.with_suffix("").parts)
    is_package = parts[-1] == "__init__"
    if is_package:
        parts = parts[:-1]
    return ".".join([PACKAGE, *parts]), is_package


def _is_excluded(name: str) -> bool:
    return any(name == ex or name.startswith(ex + ".") for ex in EXCLUDED_MODULES)


def _imported_names(module: Module, tree: ast.AST) -> List[str]:
    """Every module name an import statement in ``tree`` could load, relative imports resolved."""
    package = module.name if module.is_package else module.name.rpartition(".")[0]
    out: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base_parts = package.split(".")
                base_parts = base_parts[: len(base_parts) - (node.level - 1)]
                base = ".".join(p for p in [*base_parts, node.module or ""] if p)
            else:
                base = node.module or ""
            out.append(base)
            out.extend(f"{base}.{alias.name}" for alias in node.names if alias.name != "*")
    return out


def _check_module(module: Module) -> None:
    filename = BUNDLE_FILENAME_PREFIX + module.relpath
    try:
        # feature_version is best-effort (it catches e.g. match statements); the CI test matrix on
        # the oldest supported Python is what really proves compatibility.
        tree = ast.parse(module.source, filename=filename, feature_version=MIN_PYTHON)
        compile(module.source, filename, "exec", dont_inherit=True)
    except SyntaxError as exc:
        raise BuildError(
            f"src/{module.relpath} line {exc.lineno}: not valid Python "
            f"{MIN_PYTHON[0]}.{MIN_PYTHON[1]} syntax: {exc.msg}"
        ) from exc
    for name in _imported_names(module, tree):
        if _is_excluded(name):
            raise BuildError(
                f"src/{module.relpath} imports {name}, which is development-only and is not shipped to devices"
            )


def collect_modules(package_dir: Path) -> List[Module]:
    if not (package_dir / "__init__.py").is_file():
        raise BuildError(f"{package_dir} is not a Python package (no __init__.py)")
    modules: List[Module] = []
    for path in _walk(package_dir):
        rel = path.relative_to(package_dir)
        if rel.parts[0] == STATIC_DIR:
            continue  # embedded as resources, below
        if path.suffix != ".py":
            if not path.name.endswith((".pyc", ".pyo")):
                LOG.warning("not bundled (not a module and not under %s/): %s", STATIC_DIR, rel.as_posix())
            continue
        name, is_package = _module_name(rel)
        if _is_excluded(name):
            LOG.debug("excluded: %s", name)
            continue
        if name == EMBEDDED_MODULE:
            raise BuildError(f"{path}: {EMBEDDED_MODULE} is reserved for the generated resource module")
        try:
            source = path.read_bytes().decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BuildError(f"{path} is not UTF-8: {exc}") from exc
        module = Module(name, f"{PACKAGE}/{rel.as_posix()}", is_package, source)
        _check_module(module)
        modules.append(module)
    modules.sort(key=lambda m: m.name)
    packages = {m.name for m in modules if m.is_package}
    for module in modules:
        parent = module.name.rpartition(".")[0]
        if parent and parent not in packages:
            raise BuildError(
                f"src/{module.relpath}: package {parent} has no __init__.py (namespace packages are not bundled)"
            )
    return modules


def collect_resources(package_dir: Path) -> List[Resource]:
    static = package_dir / STATIC_DIR
    if static.is_symlink() or not static.is_dir():
        raise BuildError(f"{static} is missing or not a directory")
    resources: List[Resource] = []
    for path in _walk(static):
        rel = path.relative_to(static).as_posix()
        if any(part.startswith(".") for part in rel.split("/")):
            LOG.warning("not bundled (hidden file): %s/%s", STATIC_DIR, rel)
            continue
        resources.append(Resource(f"{STATIC_DIR}/{rel}", path.read_bytes()))
    return resources


# --- payload and rendering ------------------------------------------------------------------------


def payload_sha256(modules: Sequence[Module], resources: Sequence[Resource]) -> str:
    """SHA-256 over every embedded module and file, length-prefixed so the framing is unambiguous.

    The generated file recomputes this in its self-test (``_payload_sha256``); keep the two in step.
    """
    digest = hashlib.sha256()
    for module in sorted(modules, key=lambda m: m.name):
        data = module.source.encode("utf-8")
        digest.update(b"module\0%s\0%d\0%d\0" % (module.name.encode("utf-8"), module.is_package, len(data)))
        digest.update(data)
    for resource in sorted(resources, key=lambda r: r.name):
        digest.update(b"resource\0%s\0%d\0" % (resource.name.encode("utf-8"), len(resource.data)))
        digest.update(resource.data)
    return digest.hexdigest()


def _literal_tuple(items: Sequence[str], indent: int) -> str:
    if not items:
        return "()"
    pad = " " * indent
    body = "".join(f"{pad}    {item!a},\n" for item in items)
    return f"(\n{body}{pad})"


def _header(version: str, source_ref: Optional[str], digest: str, modules: int, resources: int) -> str:
    return f'''#!/usr/bin/env python3
"""J-Wicket single-file bundle. GENERATED by tools/bundle.py: DO NOT EDIT; rebuild instead.

jwicket version: {version}
source ref:      {source_ref or "not recorded"}
payload sha256:  {digest}
contents:        {modules} modules, {resources} static files
not shipped:     {", ".join(EXCLUDED_MODULES)}

Foundation stage. Not installable on a production SRX: lab qualification only (docs/deploy-lab.md).

Under Junos this file is started with no arguments (Junos cannot pass --flag options to a JET
application) and reads /var/db/jwicket/jwicket.ini. A copy saved as jwicket_selftest.py or
jwicket_probe.py runs the bundle self-test or the interpreter probe instead, then exits.
Off the device, "--bundle-self-test" does the same as the jwicket_selftest.py name.

Before anything else is imported, this file's own directory is removed from sys.path, so nothing
placed beside it can stand in for a standard-library or PyEZ module. The self-test fails, and the
daemon refuses to start, if any loaded module still comes from that directory.
"""
'''


# Runs before every other import in the generated file (and so it may use built-in modules only, and
# no annotations: the generated file has no "from __future__ import annotations", because even that
# statement imports a module, __future__, through sys.path).
_SCRUB = r'''
# --- first: keep this file's own directory off the import path (fixed text from tools/bundle.py) ----
# Run as a script, this file's directory is sys.path[0], so a json.py or hashlib.py placed beside it
# would replace the standard library inside the daemon. Only built-in modules (sys, posix) are used
# until that directory is removed; everything else is imported after.
import sys


def _script_dirs():
    """This file's directory, and the directory of the file a symbolic link to it points at
    (CPython puts the resolved one on sys.path)."""
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
    """Remove every sys.path entry that is one of ``dirs`` (compared by device and inode, so any
    spelling of the directory matches), and the current-directory entries "" and "."."""
    import posix

    def identity(entry):
        try:
            st = posix.stat(entry)
        except (OSError, TypeError, ValueError):
            return None
        return (st.st_dev, st.st_ino)

    unsafe = {identity(d) for d in dirs} - {None}
    kept, removed = [], []
    for entry in sys.path:
        if entry in ("", ".") or (isinstance(entry, str) and identity(entry) in unsafe):
            removed.append(entry)
        else:
            kept.append(entry)
    sys.path[:] = kept
    return removed


_SCRIPT_DIRS = _script_dirs()
_PATH_REMOVED = _scrub_path(_SCRIPT_DIRS)
'''


_RUNTIME = r'''

# --- runtime (fixed template text from tools/bundle.py) -------------------------------------------

EMBEDDED_MODULE = "jwicket._embedded"
FILENAME_PREFIX = "jwicket-bundle/"
SELF_TEST_FLAG = "--bundle-self-test"
# Junos cannot pass --flag options to a JET application (spike finding F1). A copy of this file
# saved under one of these names runs that diagnostic instead of the daemon; both read and exit.
ALIASES = {"jwicket_selftest.py": "self-test", "jwicket_probe.py": "probe"}


def _resources() -> Dict[str, bytes]:
    return {
        name: base64.b64decode("".join(chunks), validate=True)
        for name, chunks in sorted(_RESOURCES_B64.items())
    }


def _payload_sha256() -> str:
    """Recompute the payload digest exactly as tools/bundle.py payload_sha256() does."""
    digest = hashlib.sha256()
    for name in sorted(_MODULES):
        is_package, _relpath, lines = _MODULES[name]
        data = "".join(lines).encode("utf-8")
        digest.update(b"module\0%s\0%d\0%d\0" % (name.encode("utf-8"), is_package, len(data)))
        digest.update(data)
    for name, data in sorted(_resources().items()):
        digest.update(b"resource\0%s\0%d\0" % (name.encode("utf-8"), len(data)))
        digest.update(data)
    return digest.hexdigest()


class _BundleImporter(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Serves the embedded jwicket package from memory.

    It goes first on sys.meta_path, for two reasons: when this file runs as a script its own
    directory is sys.path[0] and the file is named jwicket.py, so the ordinary path finder would
    import this very file as "jwicket"; and a jwicket directory anywhere on sys.path must never
    stand in for the code that was built and checksummed. Packages get an empty __path__, so a
    module that is not embedded (devserver, fixtures) cannot be imported from disk either.
    """

    def find_spec(
        self,
        fullname: str,
        path: Optional[Sequence[str]],
        target: Optional[types.ModuleType] = None,
    ) -> Optional[importlib.machinery.ModuleSpec]:
        if fullname == EMBEDDED_MODULE:
            return importlib.util.spec_from_loader(
                fullname, self, origin=FILENAME_PREFIX + "jwicket/_embedded", is_package=False
            )
        entry = _MODULES.get(fullname)
        if entry is None:
            return None
        return importlib.util.spec_from_loader(
            fullname, self, origin=FILENAME_PREFIX + entry[1], is_package=entry[0]
        )

    def create_module(self, spec: importlib.machinery.ModuleSpec) -> Optional[types.ModuleType]:
        return None  # the default module object

    def exec_module(self, module: types.ModuleType) -> None:
        name = module.__name__
        if name == EMBEDDED_MODULE:
            module.RESOURCES = _resources()  # type: ignore[attr-defined]
            return
        is_package, relpath, lines = _MODULES[name]
        filename = FILENAME_PREFIX + relpath
        module.__file__ = filename
        # dont_inherit: each module gets only its own __future__ imports, as it would from source.
        code = compile("".join(lines), filename, "exec", dont_inherit=True)
        # Executing embedded source is acceptable here: it is text tools/bundle.py copied into this
        # very file at build time from the reviewed source tree, so it carries exactly the trust of
        # the file Junos is executing (anyone able to change it could change this file directly),
        # and PAYLOAD_SHA256 covers it. Nothing here ever executes a request, a settings value or
        # any other input.
        exec(code, module.__dict__)  # noqa: S102

    def get_source(self, fullname: str) -> Optional[str]:
        """Lets tracebacks show the embedded source lines (linecache asks the loader)."""
        entry = _MODULES.get(fullname)
        return None if entry is None else "".join(entry[2])

    def is_package(self, fullname: str) -> bool:
        if fullname == EMBEDDED_MODULE:
            return False
        entry = _MODULES.get(fullname)
        if entry is None:
            raise ImportError(f"{fullname} is not in this bundle", name=fullname)
        return entry[0]


def _foreign_modules() -> List[str]:
    """Loaded modules whose file lies in this file's directory, which must supply no code at all."""
    prefixes: List[str] = []
    for directory in [*_SCRIPT_DIRS, *_PATH_REMOVED]:
        if directory in ("", "."):
            directory = os.getcwd()
        for form in {directory, os.path.realpath(directory)}:
            if form not in ("", "/"):
                prefixes.append(form.rstrip("/") + "/")
    own = os.path.realpath(str(globals().get("__file__") or "")) if globals().get("__file__") else None
    found: List[str] = []
    for name, module in list(sys.modules.items()):
        filename = getattr(module, "__file__", None)
        if name == "__main__" or not isinstance(filename, str) or not filename.startswith("/"):
            continue
        real = os.path.realpath(filename)
        if real == own:
            continue  # this bundle itself
        if any(filename.startswith(p) or real.startswith(p) for p in prefixes):
            found.append(f"{name} ({filename})")
    return sorted(found)


def _install() -> _BundleImporter:
    for finder in sys.meta_path:
        if isinstance(finder, _BundleImporter):
            return finder
    importer = _BundleImporter()
    sys.meta_path.insert(0, importer)
    return importer


def _self_test() -> int:
    """Import every embedded module, resolve every allowlisted asset, check the payload digest."""
    importer = _install()
    failures: List[str] = []
    imported = 0
    for name in [*sorted(_MODULES), EMBEDDED_MODULE]:
        try:
            module = importlib.import_module(name)
        except Exception as exc:  # noqa: BLE001 - report every module, not only the first failure
            failures.append(f"import {name}: {type(exc).__name__}: {exc}")
            continue
        spec = getattr(module, "__spec__", None)
        if spec is None or spec.loader is not importer:
            failures.append(f"{name} was not loaded from this bundle (origin {getattr(spec, 'origin', None)})")
        elif name != EMBEDDED_MODULE:
            imported += 1

    for name in EXCLUDED_MODULES:
        try:
            found = importlib.util.find_spec(name)
        except (ImportError, ValueError):
            found = None
        if found is not None:
            failures.append(f"{name} is development-only but importable from {found.origin}")

    version = getattr(sys.modules.get("jwicket"), "__version__", None)
    if version != BUNDLE_VERSION:
        failures.append(f"jwicket.__version__ is {version!r}, the bundle header says {BUNDLE_VERSION!r}")

    assets: Dict[str, str] = {}
    try:
        resources = importlib.import_module("jwicket.resources")
        embedded = sys.modules[EMBEDDED_MODULE].RESOURCES
        # The servable set: an explicit allowlist where resources.py has one, else its manifest
        # (names matching its strict pattern). Either way the UI entry page must be among them.
        servable = getattr(resources, "STATIC_ASSETS", None)
        if servable is None:
            servable = resources.manifest()
        names = sorted(servable)
        if "index.html" not in names:
            failures.append("assets: index.html is not servable from this bundle")
        for asset_name in names:
            found_asset = resources.asset(asset_name)
            if found_asset is None:
                assets[asset_name] = "missing"
            elif found_asset[0] != embedded.get(f"static/{asset_name}"):
                assets[asset_name] = "not served from the bundle"
            else:
                assets[asset_name] = f"ok ({len(found_asset[0])} bytes)"
                continue
            failures.append(f"asset {asset_name}: {assets[asset_name]}")
    except Exception as exc:  # noqa: BLE001 - the summary must still be printed
        failures.append(f"assets: {type(exc).__name__}: {exc}")

    actual = _payload_sha256()
    if actual != PAYLOAD_SHA256:
        failures.append(f"payload sha256 is {actual}, the bundle header says {PAYLOAD_SHA256}")

    foreign = _foreign_modules()
    if foreign:
        failures.append("loaded from this file's directory: " + ", ".join(foreign))

    summary = {
        "bundle": "jwicket",
        "version": BUNDLE_VERSION,
        "source_ref": SOURCE_REF,
        "python": sys.version.split()[0],
        "payload_sha256": PAYLOAD_SHA256,
        "payload_ok": actual == PAYLOAD_SHA256,
        "modules": len(_MODULES),
        "modules_imported": imported,
        "static_files": len(_RESOURCES_B64),
        "assets": assets,
        "not_shipped": list(EXCLUDED_MODULES),
        "path_removed": list(_PATH_REMOVED),
        "foreign_modules": foreign,
        "failures": failures,
        "ok": not failures,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if not failures else 1


def _main(argv: List[str]) -> int:
    args = argv[1:]
    if SELF_TEST_FLAG in args:
        if len(args) != 1:
            print(f"{SELF_TEST_FLAG} takes no other arguments", file=sys.stderr)
            return 2
        return _self_test()
    mode = ALIASES.get(os.path.basename(str(globals().get("__file__") or argv[0] or "")))
    if mode is not None and not args:
        if mode == "self-test":
            return _self_test()
        _install()
        return int(importlib.import_module("jwicket.app").main(["--probe"]))
    _install()
    app = importlib.import_module("jwicket.app")
    foreign = _foreign_modules()
    if foreign:
        print("jwicket: refusing to start: code was loaded from this file's directory: " + ", ".join(foreign),
              file=sys.stderr)
        return 2
    return int(app.main())


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
'''

_IMPORTS = """
import base64
import hashlib
import importlib
import importlib.abc
import importlib.machinery
import importlib.util
import json
import os
import sys
import types
from typing import Dict, List, Optional, Sequence, Tuple
"""


def render(
    version: str, source_ref: Optional[str], modules: Sequence[Module], resources: Sequence[Resource], digest: str
) -> str:
    parts = [_header(version, source_ref, digest, len(modules), len(resources)), _SCRUB, _IMPORTS, "\n"]
    parts.append(f"BUNDLE_VERSION = {version!a}\n")
    parts.append(f"SOURCE_REF = {source_ref!a}\n")
    parts.append(f"PAYLOAD_SHA256 = {digest!a}\n")
    parts.append(f"EXCLUDED_MODULES = {tuple(EXCLUDED_MODULES)!a}\n\n")
    parts.append("# name -> (is_package, file name inside the bundle, source lines)\n")
    parts.append("_MODULES: Dict[str, Tuple[bool, str, Tuple[str, ...]]] = {\n")
    for module in sorted(modules, key=lambda m: m.name):
        lines = module.source.splitlines(keepends=True)
        parts.append(
            f"    {module.name!a}: ({module.is_package}, {module.relpath!a}, {_literal_tuple(lines, 4)}),\n"
        )
    parts.append("}\n\n")
    parts.append('# "static/<name>" -> base64 of the file\n')
    parts.append("_RESOURCES_B64: Dict[str, Tuple[str, ...]] = {\n")
    for resource in sorted(resources, key=lambda r: r.name):
        encoded = base64.b64encode(resource.data).decode("ascii")
        chunks = [encoded[i : i + B64_LINE] for i in range(0, len(encoded), B64_LINE)]
        parts.append(f"    {resource.name!a}: {_literal_tuple(chunks, 4)},\n")
    parts.append("}\n")
    parts.append(_RUNTIME)
    return "".join(parts)


def build(package_dir: Path = PACKAGE_DIR, source_ref: Optional[str] = None) -> Bundle:
    if source_ref is not None and not _SOURCE_REF.match(source_ref):
        raise BuildError(f"--source-ref {source_ref[:80]!r} must be 1-128 letters, digits and ._/+@- characters")
    version = read_version(package_dir)
    modules = tuple(collect_modules(package_dir))
    resources = tuple(collect_resources(package_dir))
    digest = payload_sha256(modules, resources)
    text = render(version, source_ref, modules, resources, digest)
    filename = str(DEFAULT_OUT)
    try:
        compile(text, filename, "exec", dont_inherit=True)
        ast.parse(text, filename=filename, feature_version=MIN_PYTHON)
    except SyntaxError as exc:  # a defect in this tool, not in the source tree
        raise BuildError(f"the generated bundle does not compile (line {exc.lineno}): {exc.msg}") from exc
    return Bundle(version, source_ref, modules, resources, digest, text)


def write_atomic(path: Path, data: bytes) -> None:
    """Replace ``path`` in one step, mode 0644 (Junos wants owner-only write on JET scripts)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp_path = Path(tmp)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        tmp_path.chmod(0o644)
        tmp_path.replace(path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def _summary(out: Path, bundle: Bundle, data: bytes) -> str:
    ref = f" ({bundle.source_ref})" if bundle.source_ref else ""
    return (
        f"{out}: jwicket {bundle.version}{ref}, {len(bundle.modules)} modules, {len(bundle.resources)} static "
        f"files, {len(data)} bytes, file sha256 {hashlib.sha256(data).hexdigest()}, "
        f"payload sha256 {bundle.payload_sha256}"
    )


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="bundle.py", description="Build the single-file J-Wicket bundle.")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output file (default: %(default)s)")
    parser.add_argument("--source-ref", help="source revision to record in the header, e.g. a git commit")
    parser.add_argument(
        "--check", action="store_true", help="rebuild in memory and exit 1 if --out differs from it"
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="bundle: %(levelname)s %(message)s", stream=sys.stderr)
    args = parse_args(sys.argv[1:] if argv is None else argv)
    out: Path = args.out
    try:
        bundle = build(PACKAGE_DIR, args.source_ref)
    except BuildError as exc:
        LOG.error("build failed: %s", exc)
        return 2
    data = bundle.text.encode("ascii")
    if args.check:
        try:
            existing = out.read_bytes()
        except OSError as exc:
            LOG.error("cannot read %s (%s); build it first", out, exc.strerror or exc)
            return 1
        if existing != data:
            LOG.error(
                "%s differs from a fresh build of %s (fresh payload sha256 %s); rebuild it, and never edit it by hand",
                out, PACKAGE_DIR, bundle.payload_sha256,
            )
            return 1
        print(_summary(out, bundle, data) + ", up to date")
        return 0
    try:
        write_atomic(out, data)
    except OSError as exc:
        LOG.error("cannot write %s: %s", out, exc.strerror or exc)
        return 2
    print(_summary(out, bundle, data))
    return 0


if __name__ == "__main__":
    sys.exit(main())
