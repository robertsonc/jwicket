"""``python -m jwicket_install``: the same command line as the ``jwicket-install`` console script."""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
