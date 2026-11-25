# Recorded replies: SRX4100, Junos 25.2R1-S1.4

Recorded on 25 November 2026 (UTC; 24 November on the device's CST clock) from the project owner's lab SRX4100 (standalone, veriexec
enforcing, Security Director Cloud attached), the device of
[the lab record](../../../docs/evidence/2026-11-24-srx4100-lab/README.md). Captured over NETCONF
(`ssh -s <user>@<device> netconf`, base 1.0 framing) as a super-user-class account, sending exactly
the requests J-Wicket sends: the same RPC names, and for configuration the same filters and options
(`INVENTORY_FILTER`, `LOGS_FILTER` and `CONFIG_OPTIONS` imported from `jwicket.junos.session`).
Each file is the whole `<nc:rpc-reply>`.

| File | Request |
| --- | --- |
| `get-software-information.xml` | `<get-software-information/>` |
| `get-chassis-cluster-status.xml` | `<get-chassis-cluster-status/>` (an error reply: not a cluster) |
| `get-flow-session-information-summary.xml` | `<get-flow-session-information><summary/>` |
| `get-flow-session-information.xml` | `<get-flow-session-information/>` (25 sessions) |
| `get-route-engine-information.xml` | `<get-route-engine-information/>` |
| `get-performance-summary-information.xml` | `<get-performance-summary-information/>` |
| `get-configuration-inventory.xml` | `<get-configuration database="committed" inherit="inherit" groups="groups">` + `INVENTORY_FILTER` |
| `get-configuration-logs.xml` | the same options + `LOGS_FILTER` |
| `get-security-log-information.xml` | `<get-security-log-information/>` (logs disabled in this mode) |

Redaction: none. The owner stated the lab data is not secret. The inventory filter used here is the
narrowed one, which no longer fetches the outbound-SSH client's `secret` or `device-id`, so neither
is in the file. Addresses, host names and policy names are the lab's own.

What these replies showed (they are the first recorded replies, Q-REL-01 partial: one platform, one
release):

- Text values are padded with newlines (`<active-sessions>\n63\n</active-sessions>`); the parsers
  strip them.
- `active-sessions` counts invalidated sessions too: here 43 active = 21 valid + 22 invalidated,
  and the list, read a moment later, held 25. An earlier capture had 63 active = 37 valid + 26
  invalidated with 37 listed. Whether the list leaves invalidated sessions out is therefore likely
  but not established: the table changes between the two reads.
- The outbound-SSH client's `services` is a leaf-list text value (`<services>netconf</services>`),
  not the child elements the synthetic fixture had.
- A standalone device answers `get-chassis-cluster-status` with an `xnm:error` from `jsrpd`:
  "error: Chassis cluster is not enabled".

`tests/test_recorded.py` and `tests/test_health.py` parse these files.
