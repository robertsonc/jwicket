# Architecture decision records

One decision per file. A record is short: the context that forced a choice, the choice, what it
costs, and which qualification test would prove it wrong. Records are not edited after acceptance;
a later record supersedes an earlier one and says so.

| ADR | Decision | Status |
| --- | --- | --- |
| [0001](0001-on-box-pure-python-single-file.md) | On-box, pure-Python runtime shipped as one generated file | Accepted |
| [0002](0002-junos-delegated-sign-in.md) | Sign-in is delegated to Junos through a per-operator NETCONF session | Accepted, pending Q-AUTH-01 |
| [0003](0003-tls-off-loopback.md) | TLS for any non-loopback listener; SSH tunnel for lab access | Accepted |
| [0004](0004-no-sample-data.md) | No sample data: every panel is device data or an explicit state | Accepted |
| [0005](0005-committed-config-with-provenance.md) | Read the committed configuration with inheritance and group provenance | Accepted |
| [0006](0006-device-explains-policy-decisions.md) | The device explains policy decisions; J-Wicket does not reimplement the matcher | Accepted |
| [0007](0007-offline-capable-meaning.md) | "Offline-capable" means no runtime internet dependency, not browser caching of device data | Accepted |
| [0008](0008-release-scoped-parity.md) | Parity is measured against one named J-Web release, in a ledger | Accepted |
| [0009](0009-central-management-coexistence.md) | Detect central management and treat it as a co-owner of the configuration | Accepted |
