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
they may still be corrected in place. ADR 0010 records an owner decision made on 2026-11-24, so it
starts as Accepted, and so does ADR 0011, which holds only the owner's installation decisions of the
same day and, as its decision 4, the installer defaults the owner accepted on 2026-11-25. ADR 0012
holds the installer design that [Spec 006](../specs/006-installation.md) proposes to carry them out,
and reads Proposed until the owner accepts it, with the security reviewer (D11), except its decisions
4 and 11 and the R-MODEL part of its decision 8, which ADR 0011 decision 4 accepted. ADR 0013 records an owner decision made on 2026-11-25, so it also starts as Accepted.

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
| [0010](0010-usable-without-knowing-junos.md) | Every screen is usable without knowing Junos: concepts explained in place, the command alongside; reads stay first; an SE or administrator installs | Accepted (2026-11-24, owner decision; confirmed by the merge of its pull request) |
| [0011](0011-owner-decisions-lab-gated-install.md) | Installation: every installer lab-gated until G1 (dry run, diff, posture warning, `commit confirmed` with a health check, the typed host name); CI pre-releases with SHA-256, the first tag the owner's; spec and installers built together, every device step unverified. Decision 4 (2026-11-25): the installer defaults from the SRX4100 run (TLS on the management address, the root step printed and checked but never run, lab hardware only with a typed `lab only`) | Accepted (2026-11-24, decision 4 on 2026-11-25; owner decisions; confirmed when the owner merges the pull request that adds them) |
| [0012](0012-installer-design.md) | Installer design: one shared plan, twelve security invariants, the gated bootstrap and its R-PENDING exception, provenance independent of the release page, no installer code in the bundle, the release repository settings. Revised on 2026-11-25 from the lab SRX4100 run: the state directory made once by root, never by an installer; TLS on the management address by default, with `--access tunnel` kept; health checks without SSH channels; Python 3.7 for everything the op script embeds; lab hardware only with a typed `lab only` | Proposed; unproven until Q-INST-06. Decisions 4 and 11 and the R-MODEL part of decision 8 accepted by the owner on 2026-11-25 (ADR 0011, decision 4) |
| [0013](0013-user-regexes-run-in-a-linear-time-matcher.md) | User regular expressions run in J-Wicket's own linear-time matcher (a Pike VM) with the browser's character semantics; lookaround and back-references are refused; the Logs time budget stays | Accepted (2026-11-25, owner decision; confirmed by the merge of its pull request) |
| [0015](0015-verified-installer-profiles.md) | Verify installer profiles on the target SRX | Proposed |

Corrections made in place on 2026-11-24, while the records are Proposed: ADR 0001 names the roadmap
phase that would bring a signed package (phase 6, Production); ADR 0002 points its multi-factor
question at a future sign-in spec instead of "Spec 00x"; ADR 0007 records the saved-query widening
above; ADR 0008 uses the ledger statuses `replace` and `out-of-scope`.
