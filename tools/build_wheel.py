#!/usr/bin/env python3
"""Build ``jwicket_install-<version>-py3-none-any.whl``: the workstation installer as a wheel.

Spec 006 sections 6.2 and 11.3: each lab pre-release carries the installer (``tools/jwicket_install``)
as a wheel, so an operator installs it without a clone. The wheel is built here, without a build
backend, so that two builds of the same tree are byte-identical on any machine and any Python 3.7+
(the release's ``rebuild`` job requires that on 3.7, the SRX's Python, and on 3.9 and 3.13):

* entries are sorted; the ``.dist-info`` files come last, ``RECORD`` the very last;
* every timestamp is ``--source-date-epoch`` (in CI and in the reproduce command, the commit time:
  ``git log -1 --format=%ct <commit>``), clamped to the ZIP minimum of 1980-01-01;
* entries are stored, not deflated: deflate output depends on the zlib build (zlib, zlib-ng), which
  differs between machines, and the installer is small;
* file modes are fixed (0644), the creator system is fixed (Unix), and no extra fields are written.

The wheel declares no ``Requires-Dist``: its dependencies are installed from the release's
hash-pinned ``requirements-install.txt`` (``pip install --require-hashes -r``), then the wheel with
``--no-deps``, so nothing is ever resolved from an index without a hash. Every module must parse with
Python 3.7's grammar (Spec 006 revision 4: the on-box op script embeds the plan modules, and the unit
tests run on 3.7), which the build checks where the running Python can (``feature_version``, 3.8+).

Usage::

    python3 tools/build_wheel.py --out dist/ [--source-date-epoch N] [--package-dir tools/jwicket_install]

Without ``--source-date-epoch`` the ``SOURCE_DATE_EPOCH`` environment variable is used, then the
commit time of ``HEAD`` (git, with a timeout). Standard library only; runs on a build machine, never
on a device. Exit status: 0 built (the path and SHA-256 are printed), 2 the tree cannot be built.
"""

from __future__ import annotations

import argparse
import ast
import base64
import contextlib
import hashlib
import io
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

LOG = logging.getLogger("jwicket.build_wheel")

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "jwicket_install"
DEFAULT_PACKAGE_DIR = REPO_ROOT / "tools" / PACKAGE
DISTRIBUTION = "jwicket-install"  # the project name pip shows; the file names use jwicket_install
CONSOLE_SCRIPT = "jwicket-install"
ENTRY_MODULE = "cli"  # jwicket_install.cli
ENTRY_FUNCTION = "main"
SUMMARY = (
    "Lab-gated installer for J-Wicket on a lab vSRX. LAB ONLY: pre-release, unsupported, and not yet run "
    "on any device"
)
# The workstation installer's floor (Spec 006 section 6.2, revision R1): what the pinned junos-eznc 2.8.3
# declares, 'Requires-Python: >=3.8' (PyPI metadata, checked 2026-11-25). The modules themselves run on
# 3.7 (MIN_PYTHON). The hash-pinned requirements-install.txt as a whole needs more: paramiko 5.1.0
# declares >=3.9 and cryptography 48.0.1 and 50.0.2 declare '>=3.9, !=3.9.0, !=3.9.1', so its first
# 'pip install --require-hashes' step refuses an older interpreter before this wheel is installed.
REQUIRES_PYTHON = ">=3.8"
# The grammar every module of the package must parse with (the SRX's Python 3.7, Q-RT-01).
MIN_PYTHON = (3, 7)
WHEEL_TAG = "py3-none-any"
GENERATOR = "jwicket tools/build_wheel.py"

# A ZIP timestamp cannot be earlier than 1980-01-01 00:00:00 UTC.
ZIP_EPOCH_MIN = 315532800
# 2107-12-31, the last date a ZIP (DOS) timestamp can hold.
ZIP_EPOCH_MAX = 4354819199
FILE_MODE = 0o100644  # regular file, rw-r--r--
UNIX = 3
GIT_TIMEOUT_S = 30

# PEP 440 subset accepted for the installer: X.Y.Z or X.Y.Z.devN.
_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:\.dev\d+)?\Z", re.ASCII)
# Files the wheel may carry: plain names, nothing hidden.
_PART = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*\Z", re.ASCII)
_SKIP_DIRS = frozenset({"__pycache__"})
_SKIP_SUFFIXES = (".pyc", ".pyo")
# Top-level packages the wheel does not contain. A module-level import of one would make the
# installed console script fail at start (the daemon package lives in src/, the bundle tool in tools/).
_FOREIGN_TOP_LEVEL = frozenset({"jwicket", "bundle", "release_check", "release_record", "build_wheel"})


class BuildError(Exception):
    """The package cannot be built into a wheel. The message names the file and the reason."""


@dataclass(frozen=True)
class Wheel:
    name: str
    version: str
    data: bytes
    entries: Tuple[str, ...]

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


# --- reading the package -------------------------------------------------------------------------


def _string_literal(node: Optional[ast.expr]) -> Optional[str]:
    """The value of a plain string literal, or None. Python 3.7's parser gives ``ast.Str`` (its ``s``);
    3.8 and later give ``ast.Constant`` (its ``value``)."""
    text = node.value if isinstance(node, ast.Constant) else getattr(node, "s", None)
    return text if isinstance(text, str) else None


def _parse(source: bytes, filename: str) -> ast.Module:
    """``ast.parse`` with Python 3.7's grammar where this Python can apply it (``feature_version`` is
    3.8+, and best-effort); on 3.7 its own parser is that grammar."""
    if sys.version_info >= (3, 8):
        return ast.parse(source, filename=filename, feature_version=MIN_PYTHON)
    return ast.parse(source, filename=filename)  # type: ignore[unreachable]  # mypy checks as 3.8


def read_version(package_dir: Path) -> str:
    init = package_dir / "__init__.py"
    try:
        tree = ast.parse(init.read_text(encoding="utf-8"), filename=str(init))
    except (OSError, SyntaxError, UnicodeDecodeError, ValueError) as exc:
        raise BuildError(f"cannot read __version__ from {init}: {exc}") from exc
    for node in tree.body:
        targets: List[ast.expr]
        value: Optional[ast.expr]
        if isinstance(node, ast.Assign):
            targets, value = list(node.targets), node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        else:
            continue
        if any(isinstance(t, ast.Name) and t.id == "__version__" for t in targets):
            text = _string_literal(value)
            if text is not None and _VERSION.match(text):
                return text
            raise BuildError(f"{init}: __version__ must be a string literal such as '0.1.0.dev1'")
    raise BuildError(f"{init} does not assign __version__")


def package_files(package_dir: Path) -> List[Tuple[str, Path]]:
    """``(archive name, path)`` for every file of the package, sorted, refusing links and odd names."""
    if not package_dir.is_dir() or package_dir.is_symlink():
        raise BuildError(f"{package_dir} is not a directory")
    found: List[Tuple[str, Path]] = []
    pending = [package_dir]
    while pending:
        directory = pending.pop()
        for entry in directory.iterdir():
            if entry.is_symlink():
                raise BuildError(f"{entry} is a symbolic link; the wheel takes regular files only")
            if entry.is_dir():
                if entry.name in _SKIP_DIRS:
                    continue
                if not _PART.match(entry.name):
                    raise BuildError(f"{entry}: directory name not allowed in the wheel")
                pending.append(entry)
            elif entry.is_file():
                if entry.name.endswith(_SKIP_SUFFIXES):
                    continue
                if not _PART.match(entry.name):
                    raise BuildError(f"{entry}: file name not allowed in the wheel (hidden or unusual characters)")
                rel = entry.relative_to(package_dir).as_posix()
                found.append((f"{PACKAGE}/{rel}", entry))
            else:
                raise BuildError(f"{entry} is not a regular file")
    found.sort(key=lambda item: item[0])
    if not any(name == f"{PACKAGE}/__init__.py" for name, _ in found):
        raise BuildError(f"{package_dir} has no __init__.py")
    return found


def _module_level_imports(tree: ast.Module) -> List[str]:
    names: List[str] = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            names.extend(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.append(node.module.split(".")[0])
    return names


def check_sources(files: Sequence[Tuple[str, Path]]) -> None:
    """Every module parses with Python 3.7's grammar, none imports a package the wheel lacks, and the
    entry point exists."""
    entry_found = False
    for name, path in files:
        if not name.endswith(".py"):
            continue
        try:
            tree = _parse(path.read_bytes(), str(path))
        except SyntaxError as exc:
            raise BuildError(
                f"{path} line {exc.lineno}: not valid Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} syntax: {exc.msg}"
            ) from exc
        except (OSError, ValueError) as exc:
            raise BuildError(f"{path} does not parse: {exc}") from exc
        foreign = sorted(set(_module_level_imports(tree)) & _FOREIGN_TOP_LEVEL)
        if foreign:
            raise BuildError(
                f"{path} imports {', '.join(foreign)} at module level, which the wheel does not contain; "
                "the installed jwicket-install would fail at start"
            )
        if name == f"{PACKAGE}/{ENTRY_MODULE}.py":
            entry_found = any(
                isinstance(node, ast.FunctionDef) and node.name == ENTRY_FUNCTION for node in tree.body
            )
    if not entry_found:
        raise BuildError(
            f"{PACKAGE}/{ENTRY_MODULE}.py must define a module-level {ENTRY_FUNCTION}() for the "
            f"{CONSOLE_SCRIPT} console script"
        )


# --- writing the wheel ---------------------------------------------------------------------------


def _record_hash(data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
    return f"sha256={digest}"


def _zip_time(epoch: int) -> Tuple[int, int, int, int, int, int]:
    clamped = min(max(epoch, ZIP_EPOCH_MIN), ZIP_EPOCH_MAX)
    t = time.gmtime(clamped)
    return (t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec)


def _metadata(version: str) -> bytes:
    lines = [
        "Metadata-Version: 2.1",
        f"Name: {DISTRIBUTION}",
        f"Version: {version}",
        f"Summary: {SUMMARY}",
        f"Requires-Python: {REQUIRES_PYTHON}",
        "",
        "Install the dependencies first, from the same release: pip install --require-hashes -r "
        "requirements-install.txt; then this wheel with pip install --no-deps. See docs/install.md.",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def _wheel_file() -> bytes:
    return (
        f"Wheel-Version: 1.0\nGenerator: {GENERATOR}\nRoot-Is-Purelib: true\nTag: {WHEEL_TAG}\n"
    ).encode("ascii")


def _entry_points() -> bytes:
    return f"[console_scripts]\n{CONSOLE_SCRIPT} = {PACKAGE}.{ENTRY_MODULE}:{ENTRY_FUNCTION}\n".encode("ascii")


def wheel_name(version: str) -> str:
    return f"{PACKAGE}-{version}-{WHEEL_TAG}.whl"


def build(package_dir: Path = DEFAULT_PACKAGE_DIR, *, source_date_epoch: int) -> Wheel:
    version = read_version(package_dir)
    files = package_files(package_dir)
    check_sources(files)
    dist_info = f"{PACKAGE}-{version}.dist-info"
    contents: List[Tuple[str, bytes]] = []
    for name, path in files:
        try:
            contents.append((name, path.read_bytes()))
        except OSError as exc:
            raise BuildError(f"cannot read {path}: {exc}") from exc
    contents.append((f"{dist_info}/METADATA", _metadata(version)))
    contents.append((f"{dist_info}/WHEEL", _wheel_file()))
    contents.append((f"{dist_info}/entry_points.txt", _entry_points()))
    contents.append((f"{dist_info}/top_level.txt", f"{PACKAGE}\n".encode("ascii")))
    record_lines = [f"{name},{_record_hash(data)},{len(data)}" for name, data in contents]
    record_lines.append(f"{dist_info}/RECORD,,")
    contents.append((f"{dist_info}/RECORD", ("\n".join(record_lines) + "\n").encode("ascii")))

    date_time = _zip_time(source_date_epoch)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in contents:
            info = zipfile.ZipInfo(name, date_time=date_time)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = UNIX
            info.external_attr = FILE_MODE << 16
            archive.writestr(info, data)
    return Wheel(wheel_name(version), version, buffer.getvalue(), tuple(name for name, _ in contents))


def write_atomic(path: Path, data: bytes) -> None:
    """Replace ``path`` in one step, mode 0644 (a public release asset, so world-readable on purpose)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp_path = Path(tmp)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        tmp_path.chmod(0o644)
        tmp_path.replace(path)
    except BaseException:
        # Not unlink(missing_ok=True): that is Python 3.8+, and this tool runs on 3.7 (rebuild job).
        with contextlib.suppress(FileNotFoundError):
            tmp_path.unlink()
        raise


def commit_epoch(root: Path) -> int:
    """The commit time of ``HEAD`` in ``root``, for a default ``--source-date-epoch``."""
    git = shutil.which("git")
    if git is None or not Path(git).is_absolute():  # a relative result (an empty or '.' PATH entry) never runs
        raise BuildError("no --source-date-epoch, no SOURCE_DATE_EPOCH, and git is not on PATH as an absolute path")
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argument list, no shell
            [git, "-C", str(root), "log", "-1", "--format=%ct", "HEAD"],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BuildError(f"git log failed to run: {exc}") from exc
    value = proc.stdout.strip()
    if proc.returncode != 0 or not value.isdigit():
        raise BuildError(f"cannot read the commit time of HEAD in {root}; pass --source-date-epoch")
    return int(value)


def parse_epoch(text: str) -> int:
    if not re.match(r"^[0-9]{1,12}\Z", text, re.ASCII):
        raise BuildError(f"source date epoch {text[:40]!r} must be a non-negative integer (seconds since 1970)")
    return int(text)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="build_wheel.py", description="Build the jwicket-install wheel.")
    parser.add_argument("--out", type=Path, required=True, help="output directory")
    parser.add_argument("--source-date-epoch", help="timestamp for every entry (default: SOURCE_DATE_EPOCH, then HEAD)")
    parser.add_argument("--package-dir", type=Path, default=DEFAULT_PACKAGE_DIR, help="default: %(default)s")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="build_wheel: %(levelname)s %(message)s", stream=sys.stderr)
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        raw = args.source_date_epoch or os.environ.get("SOURCE_DATE_EPOCH")
        epoch = parse_epoch(raw) if raw else commit_epoch(REPO_ROOT)
        wheel = build(args.package_dir, source_date_epoch=epoch)
        out_dir: Path = args.out
        target = out_dir / wheel.name
        write_atomic(target, wheel.data)
    except BuildError as exc:
        LOG.error("wheel build failed: %s", exc)
        return 2
    except OSError as exc:
        LOG.error("cannot write the wheel into %s: %s", args.out, exc)
        return 2
    print(f"{target}: {DISTRIBUTION} {wheel.version}, {len(wheel.entries)} entries, {len(wheel.data)} bytes, "
          f"sha256 {wheel.sha256}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
