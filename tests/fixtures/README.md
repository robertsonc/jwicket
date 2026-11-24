# Fixtures

**Everything in this directory is synthetic except `log-samples/juniper-docs.txt`**, a parser corpus of
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
| `cluster-lsys/` | A chassis cluster (two nodes, two redundancy groups) with a logical system and a tenant system, each with its own zones and policies. |

Layout of a fixture directory (read by `jwicket.junos.session.FixtureSession`):

- `config.xml`: the `<configuration>` returned by the inventory read
- `<rpc-name>.xml`: one reply per operational RPC
- `errors.json`: optional, maps `"<user>:<rpc>"` or `"*:<rpc>"` to `denied`, `unsupported` or `failed`
- `users.json`: optional, the user names the development server accepts
