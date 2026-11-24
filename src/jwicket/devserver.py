"""Development server: the real J-Wicket server and UI, fed from a fixture directory.

    python -m jwicket.devserver --fixture tests/fixtures/branch --port 8080

Loopback only, plain HTTP, and every page carries a "fixture data" banner. Fixture users (listed in
the fixture's users.json) sign in with any non-empty password: this is a demonstration harness for
the UI and the read path, not an authentication test, and it must never face a network.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import sys
from pathlib import Path
from typing import List, Optional

from jwicket.app import build_app, serve
from jwicket.auth.backends import validate_secret, validate_username
from jwicket.junos.errors import LoginRejected
from jwicket.fixtures import FixtureSession
from jwicket.junos.session import DeviceSession
from jwicket.logs import setup_logging
from jwicket.settings import AuthSettings, ConfigError, LogSettings, ServerSettings, Settings, validate

LOG = logging.getLogger("jwicket.devserver")


class FixtureBackend:
    name = "fixture"
    credential = "password"

    def __init__(self, directory: Path) -> None:
        self._dir = directory
        users_file = directory / "users.json"
        users = json.loads(users_file.read_text(encoding="utf-8"))["users"] if users_file.is_file() else ["admin"]
        self.users = [str(u) for u in users]

    def authenticate(self, username: str, secret: str) -> DeviceSession:
        user = validate_username(username)
        validate_secret(secret)
        if user not in self.users:
            raise LoginRejected(f"fixture has no user {user!r}")
        return FixtureSession(self._dir, user)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="jwicket.devserver", description=__doc__.splitlines()[0])
    parser.add_argument("--fixture", type=Path, default=Path("tests/fixtures/branch"))
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    if not ipaddress.ip_address(args.bind).is_loopback:
        print("the development server binds to loopback only", file=sys.stderr)
        return 2
    if not (args.fixture / "config.xml").is_file():
        print(f"{args.fixture} is not a fixture directory (no config.xml)", file=sys.stderr)
        return 2

    settings = Settings(
        server=ServerSettings(bind=args.bind, port=args.port),
        auth=AuthSettings(backend="netconf"),
        log=LogSettings(level="INFO"),
    )
    try:
        validate(settings)
    except ConfigError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    setup_logging(settings.log)
    backend = FixtureBackend(args.fixture)
    LOG.warning("FIXTURE MODE: %s; users %s accept any non-empty password", args.fixture, ", ".join(backend.users))
    app = build_app(
        settings,
        backend,
        fixture=True,
        warnings=[f"Fixture data from {args.fixture.name}: synthetic, not read from a device."],
    )
    return serve(settings, app)


if __name__ == "__main__":
    sys.exit(main())
