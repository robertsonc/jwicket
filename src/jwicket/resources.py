"""Static assets, read from the package directory or from the single-file bundle.

tools/bundle.py embeds every file under ``jwicket/static`` into a generated module named
``jwicket._embedded``. When that module exists (on a device), assets come from it; otherwise
(development, tests) they come from disk. Only names in the allowlist are ever served.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, Optional, Tuple

STATIC_DIR = Path(__file__).resolve().parent / "static"

# name -> content type. Anything else is a 404, whatever exists on disk.
STATIC_ASSETS: Dict[str, str] = {
    "index.html": "text/html; charset=utf-8",
    "app.js": "text/javascript; charset=utf-8",
    "app.css": "text/css; charset=utf-8",
    "logo.svg": "image/svg+xml",
}

_cache: Dict[str, Tuple[bytes, str]] = {}


def _embedded() -> Optional[Dict[str, bytes]]:
    try:
        from jwicket import _embedded as emb  # type: ignore[attr-defined]  # generated in the bundle only
    except ImportError:
        return None
    resources: Dict[str, bytes] = emb.RESOURCES
    return resources


def asset(name: str) -> Optional[Tuple[bytes, str, str]]:
    """Return (body, content_type, etag) for an allowlisted asset, or None."""
    content_type = STATIC_ASSETS.get(name)
    if content_type is None:
        return None
    if name not in _cache:
        emb = _embedded()
        body = emb[f"static/{name}"] if emb is not None else (STATIC_DIR / name).read_bytes()
        _cache[name] = (body, hashlib.sha256(body).hexdigest()[:16])
    body, etag = _cache[name]
    return body, content_type, etag
