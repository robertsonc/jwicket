# ADR 0001: On-box, pure-Python runtime shipped as one generated file

Status: Proposed (written 2026-11-24; owner acceptance not recorded, governance D11). Revised
2026-11-24: the Python floor is 3.7, after Q-RT-01 on an SRX4100 (see "Revision").

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
- Code stays Python 3.7-compatible: Junos 25.2R1-S1.4 ships Python 3.7.10, and the 26.2R1-S2.3
  image carries 3.7 too (Q-RT-01). CI tests 3.7 as the floor.
- Where a Junos routing instance holds the address to listen on (`mgmt_junos` with
  `system management-instance`), only the listening socket is created there, through
  `jcs.set_routing_instance()`; everything else stays in the default instance
  (`[server] routing_instance`).

## Consequences

- Deployment matches what the spike proved: one file, no arguments, settings in a fixed file.
- The bundle is reproducible, so a SHA-256 can be published per build and checked on the device.
- A signed JET package (roadmap phase 6, Production, [governance section 7](../governance.md#7-roadmap))
  would remove these limits; until then, no websockets library, no fast JSON, no async framework.

## Would be proven wrong by

- Q-RT-03 showing sibling imports work (the bundle would become optional, not wrong).
- Q-RT-01 showing a target release ships Python older than 3.7.

## Revision

The first version of this ADR set a 3.9 floor and named "a target release ships Python older than
3.9" as what would prove it wrong. Q-RT-01 found exactly that on the first device run: Junos
25.2R1-S1.4 on an SRX4100 ships Python 3.7.10, and the bundle failed to import `typing.Protocol`
([evidence](../evidence/2026-11-24-srx4100-lab/README.md)). The decision stands; only the floor
moved. What 3.7 costs: no `typing.Protocol`, `Literal` or `TypedDict` at run time (they are
imported for type checking only), no `Path.readlink`, no walrus operator or positional-only
parameters, and mypy checks as 3.8, the oldest target the pinned mypy accepts, so the CI job on
3.7 is the real check.
