# Architecture decision records

One decision per file. A record is short: the context that forced a choice, the choice, what it
costs, and which qualification test would prove it wrong. Records are not edited after acceptance;
a later record supersedes an earlier one and says so.

**Status of these records.** ADRs 0001 to 0009 were written and committed by a contributor on
2026-11-24 with the status "Accepted". No owner acceptance is recorded in the repository, and
[governance section 2.1](../governance.md#21-architecture-decision-records) says an ADR opens as
Proposed and only the owner accepts it. So all nine read **Proposed** until the owner accepts each
one in a pull request, which then sets `Status: Accepted (YYYY-MM-DD)` and links the pull request
here (decision D11 in [governance section 2.5](../governance.md#25-decisions-pending)). Until then
they may still be corrected in place.

| ADR | Decision | Status |
| --- | --- | --- |
| [0001](0001-on-box-pure-python-single-file.md) | On-box, pure-Python runtime shipped as one generated file | Proposed |
| [0002](0002-junos-delegated-sign-in.md) | Sign-in is delegated to Junos through a per-operator NETCONF session | Proposed; unproven until Q-AUTH-01 |
| [0003](0003-tls-off-loopback.md) | TLS for any non-loopback listener; SSH tunnel for lab access | Proposed |
| [0004](0004-no-sample-data.md) | No sample data: every panel is device data or an explicit state | Proposed |
| [0005](0005-committed-config-with-provenance.md) | Read the committed configuration with inheritance and group provenance | Proposed |
| [0006](0006-device-explains-policy-decisions.md) | The device explains policy decisions; J-Wicket does not reimplement the matcher | Proposed |
| [0007](0007-offline-capable-meaning.md) | "Offline-capable" means no runtime internet dependency, not browser caching of device data. `localStorage` holds UI preferences and operator-saved query text, never device replies (widened 2026-11-24 for Spec 004's saved queries; Spec 004 open question 14) | Proposed |
| [0008](0008-release-scoped-parity.md) | Parity is measured against one named J-Web release, in a ledger | Proposed |
| [0009](0009-central-management-coexistence.md) | Detect central management and treat it as a co-owner of the configuration | Proposed |

Corrections made in place on 2026-11-24, while the records are Proposed: ADR 0001 names the roadmap
phase that would bring a signed package (phase 6, Production); ADR 0002 points its multi-factor
question at a future sign-in spec instead of "Spec 00x"; ADR 0007 records the saved-query widening
above; ADR 0008 uses the ledger statuses `replace` and `out-of-scope`.
