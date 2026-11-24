"""Static assets, read from the package directory or from the single-file bundle.

tools/bundle.py embeds every file under ``jwicket/static`` into a generated module named
``jwicket._embedded``. When that module exists (on a device), assets come from it; otherwise
(development, tests) they come from disk.

What can be served is decided once, from the asset set itself: a request path must match a strict
pattern *and* be a key in the manifest. There is no filesystem path built from request input.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Dict, Optional, Tuple

STATIC_DIR = Path(__file__).resolve().parent / "static"

CONTENT_TYPES: Dict[str, str] = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
}
_NAME = re.compile(r"^[a-z0-9][a-z0-9_\-]*(/[a-z0-9][a-z0-9_\-]*)*\.(html|js|css|svg)\Z")

_manifest: Optional[Dict[str, bytes]] = None
_etags: Dict[str, str] = {}


def _embedded() -> Optional[Dict[str, bytes]]:
    try:
        from jwicket import _embedded as emb  # type: ignore[attr-defined]  # generated in the bundle only
    except ImportError:
        return None
    resources: Dict[str, bytes] = emb.RESOURCES
    return resources


def manifest() -> Dict[str, bytes]:
    """Every servable asset, keyed by its path under static/ (for example ``js/logs.js``).

    From the bundle it is built once. From disk (development) it is rebuilt on every call so asset
    edits show without restarting the development server.
    """
    global _manifest
    emb = _embedded()
    if _manifest is None or emb is None:
        _etags.clear()
        if emb is not None:
            found = {k[len("static/"):]: v for k, v in emb.items() if k.startswith("static/")}
        else:
            found = {
                p.relative_to(STATIC_DIR).as_posix(): p.read_bytes()
                for p in sorted(STATIC_DIR.rglob("*"))
                if p.is_file() and not p.is_symlink()
            }
        _manifest = {k: v for k, v in found.items() if _NAME.match(k)}
    return _manifest


def asset(name: str) -> Optional[Tuple[bytes, str, str]]:
    """Return (body, content_type, etag) for a servable asset, or None."""
    if not _NAME.match(name):
        return None
    body = manifest().get(name)
    if body is None:
        return None
    suffix = name[name.rfind("."):]
    if name not in _etags:
        _etags[name] = hashlib.sha256(body).hexdigest()[:16]
    return body, CONTENT_TYPES[suffix], _etags[name]


def reset_cache() -> None:
    """Tests and the development server call this after assets change on disk."""
    global _manifest
    _manifest = None
    _etags.clear()
