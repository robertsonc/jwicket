"""Fixture replay for development and tests. Excluded from the device bundle by tools/bundle.py."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict
from xml.etree import ElementTree

from jwicket.junos.errors import RpcDenied, RpcFailed, RpcUnsupported
from jwicket.junos.session import check_rpc
from jwicket.junos.xmlutil import Element


class FixtureSession:
    """Replays files from a fixture directory. Development and tests only; never on a device.

    Layout: ``config.xml`` (a <configuration> element), ``<rpc-name>.xml`` per operational RPC, and
    an optional ``errors.json`` mapping ``"<user>:<rpc-name>"`` or ``"*:<rpc-name>"`` to one of
    ``denied``, ``unsupported``, ``failed`` so that login-class and platform differences can be shown.
    ``get-configuration`` is the RPC name used for config reads.
    """

    backend = "fixture"

    def __init__(self, directory: Path, user: str) -> None:
        self._dir = directory
        self._user = user
        errors_file = directory / "errors.json"
        self._errors: Dict[str, str] = {}
        if errors_file.is_file():
            loaded = json.loads(errors_file.read_text(encoding="utf-8"))
            self._errors = {str(k): str(v) for k, v in loaded.items()}
        self.closed = False

    @property
    def user(self) -> str:
        return self._user

    def _maybe_fail(self, name: str) -> None:
        kind = self._errors.get(f"{self._user}:{name}") or self._errors.get(f"*:{name}")
        if kind == "denied":
            raise RpcDenied(f"fixture: {name} denied for {self._user}")
        if kind == "unsupported":
            raise RpcUnsupported(f"fixture: {name} unsupported")
        if kind == "failed":
            raise RpcFailed(f"fixture: {name} failed")

    def _load(self, filename: str) -> Element:
        target = self._dir / filename
        if not target.is_file():
            raise RpcUnsupported(f"fixture has no {filename}")
        return ElementTree.parse(target).getroot()  # noqa: S314 - repository fixtures, not network input

    def get_configuration(self, filter_xml: str) -> Element:
        self._maybe_fail("get-configuration")
        return self._load("config.xml")

    def rpc(self, name: str, **params: Any) -> Element:
        check_rpc(name)
        self._maybe_fail(name)
        return self._load(f"{name}.xml")

    def close(self) -> None:
        self.closed = True
