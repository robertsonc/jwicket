# ADR 0001: On-box, pure-Python runtime shipped as one generated file

Status: Proposed (written 2026-11-24; owner acceptance not recorded, governance D11)

## Context

Veriexec blocks unsigned binaries on the SRX. The only on-box runtime open to unsigned code is
Python 3 under `set system scripts language python3`, started by the JET extension-service from
`/var/db/scripts/jet/` (spike T0, T1). The spike ran as one file. Whether an unsigned script may
import other `.py` files from that directory has not been tested, and C extensions are out.

## Decision

- Runtime: the Python standard library plus the PyEZ (and its lxml/ncclient) that Junos ships. No
  third-party packages, no C extensions, no build step on the device.
- Source is an ordinary multi-module package (`src/jwicket`). `tools/bundle.py` generates
  `dist/jwicket.py`: one deterministic file that embeds every shipped module and static asset and
  imports them from memory. Development-only modules (`devserver.py`, `fixtures.py`) are excluded.
- Code stays Python 3.9-compatible until Q-RT-01 records the on-box version for each target release.

## Consequences

- Deployment matches what the spike proved: one file, no arguments, settings in a fixed file.
- The bundle is reproducible, so a SHA-256 can be published per build and checked on the device.
- A signed JET package (roadmap phase 6, Production, [governance section 7](../governance.md#7-roadmap))
  would remove these limits; until then, no websockets library, no fast JSON, no async framework.

## Would be proven wrong by

- Q-RT-03 showing sibling imports work (the bundle would become optional, not wrong).
- Q-RT-01 showing a target release ships Python older than 3.9.
