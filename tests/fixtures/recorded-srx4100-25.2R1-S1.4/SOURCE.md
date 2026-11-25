# Recorded replies: SRX4100, Junos 25.2R1-S1.4

Recorded on 24 November 2026 from the project owner's lab SRX4100 (standalone, veriexec
enforcing), the device of [the lab record](../../../docs/evidence/2026-11-24-srx4100-lab/README.md).
Captured by the project's agent over SSH as a super-user-class account, with the CLI's XML output:

| File | Command |
| --- | --- |
| `get-route-engine-information.xml` | `show chassis routing-engine \| display xml` |
| `get-performance-summary-information.xml` | `show security monitoring \| display xml` |

The RPC names were read from the same commands with `| display xml rpc`. Redaction: none was
needed (the routing engine's serial number reads `BUILTIN`); the CLI's trailing `<cli><banner/></cli>`
element was removed, because it is not part of the RPC reply. Values are as read: 72 % idle CPU,
48 % memory, 76 flow sessions at the time.

These are the first recorded replies in the repository (Q-REL-01, partial: one platform, one
release, two RPCs). `tests/test_health.py` parses them.
