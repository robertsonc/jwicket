# Fixtures

**Everything in this directory is synthetic except `log-samples/juniper-docs.txt` and the `recorded-*` directories**. `recorded-srx4100-25.2R1-S1.4/` holds two health replies read from a lab SRX4100 (its `SOURCE.md` says how). `log-samples/juniper-docs.txt` is a parser corpus of
log lines copied verbatim from Juniper documentation (see [its README](log-samples/README.md)), which
also carries addresses outside the ranges below. The XML follows the Junos configuration and RPC
reply structure as documented for Junos 24.4, but none of it was captured from a device. Addresses
use RFC 1918 and documentation ranges (RFC 5737); secrets are obvious placeholders.

Recorded replies from real releases replace these as qualification test Q-REL-01 runs (see
`docs/governance.md`). A recorded fixture lives in its own directory named after the release and
platform, for example `recorded-vsrx-24.4R2-S3.5/`, with a `SOURCE.md` saying who captured it, when,
with which command, and what was redacted.

| Directory | Shows |
| --- | --- |
| `branch/` | A standalone branch firewall with brownfield traits: a policy and addresses inherited from a configuration group, an inactive policy, nested address sets, a zone-attached address book, a global policy, a policy with settings J-Wicket does not model, and an outbound-SSH central-management client. User `auditor` is denied the configuration read, to show login-class enforcement. |
| `branch-edge/` | A copy of `branch/` with the edge cases J-Wicket must show honestly: deactivated statements (the default policy, policy-rematch, pre-ID, an address, an application, set members, a nested set, a screen, a port, an interface, an attach and a book), a logical system `LS-OFF` whose `[edit security policies]` is deactivated, a logical system `LS-EMPTY` with no security section, configuration comments (annotate) on rules, pairs, the default policy and objects, unified policies, an outbound-SSH client that is deactivated next to one that is not, an application with an ALG and an inactivity timeout, a `functional-zone management`, the time zone `Europe/Paris`, and hidden or direction-changing characters (U+200B, U+0085, U+202E) in names, descriptions and comments. Whether Junos accepts every one of these names is not verified. |
| `log-states/` | Every log-source state: a deactivated syslog file, no `messages` file (so it is assumed), `security log mode stream-event`, four streams (a remote host, a RADIUS server, a local stream file and a deactivated one; their tags are J-Wicket's inferred reading), on-box reporting on a release without the report queries (SRX550M on 22.4R3), `security log disable` and `security log format binary`. It has no session table: `/api/sessions` answers "This fixture has no session table." |
| `cluster-lsys/` | A chassis cluster (two nodes, two redundancy groups) with a logical system and a tenant system, each with its own zones and policies. Its `live.json` serves a synthetic two-node session table that follows the root policies: every session is listed on both nodes under the same session id, the node1 copy has zero counters and no role field, and node1 reports a slightly smaller active count. Whether a real cluster reports equal ids on both nodes is unknown. |
| `recorded-srx4100-25.2R1-S1.4/` | Recorded, not synthetic: `get-route-engine-information` and `get-performance-summary-information` from an SRX4100 on Junos 25.2R1-S1.4, parsed by `tests/test_health.py`. |

Layout of a fixture directory (read by `jwicket.junos.session.FixtureSession`):

- `config.xml`: the `<configuration>` returned by the inventory read
- `<rpc-name>.xml`: one reply per operational RPC
- `errors.json`: optional, maps `"<user>:<rpc>"` or `"*:<rpc>"` to `denied`, `unsupported` or `failed`
- `users.json`: optional, the user names the development server accepts
- `live.json`: optional, drives the development server's time-based sessions and log lines
  (`jwicket.fixtures.LiveModel`; synthetic, and its filter and reply emulation is inferred device
  behaviour). A fixture with neither `live.json` nor `get-flow-session-information.xml` has no session
  table, and says so.
- `logs/<file>.log`: optional, the text `show log <file>` returns
