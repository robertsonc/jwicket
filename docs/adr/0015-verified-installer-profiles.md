# ADR 0015: Verify installer profiles on the target SRX

Status: Proposed. Requires owner and security review before implementation.

## Context

The [SRX4100 lab](../evidence/2026-11-24-srx4100-lab/README.md) had working operator
NETCONF on loopback and TLS on fxp0. In the [vSRX lab](../evidence/2026-11-26-vsrx-vlab/README.md),
the same logical roles were available only through different paths. Binding, management
reachability, and the SSH library's ability to verify the device were distinct checks.
The temporary compatibility code is not suitable as an installer default.

## Decision proposed

Keep existing defaults and treat alternate state, listener, and operator NETCONF paths
as independent candidates. Use read-only discovery to explain choices; gate active
probes and configuration behind an exact approved plan. Prefer working operator
NETCONF on IP loopback. An alternative may use only an address verified on the same
device through the trusted management session, with its complete independently verified
SSH host key and an approved signature algorithm. Require that identity check before
sending operator credentials. A missing capability can lead to a new proposed plan.
An identity or authentication failure cannot lead to automatic fallback.

Pin the chosen characteristics in the install receipt, lock and recheck before
configuration changes, and confirm only after verification through the actual runtime
and intended client. No silent migration at startup. Hold the existing installer and
production gates, including the MNHA refusal. The full checks and negative cases are
in [Spec 006 section 7.12](../specs/006-installation.md#712-adaptive-preflight-proposed).

## Alternatives

- **Make this vSRX path the default.** Rejected: it would encode a particular platform,
  address, and old SSH library's behavior and change devices with working loopback.
- **Allow arbitrary NETCONF targets.** Rejected: it would send operator credentials
  outside the device trust boundary.
- **Keep loopback as the only option forever.** Preserves the current rule, but leaves
  otherwise usable SRXs without delegated reads. Keep it as the rule until the proposed
  alternative is independently qualified.

## Qualification

Require one run that preserves the existing SRX4100 loopback path and one that selects
the reviewed fallback on a vSRX, plus pin, signature, ingress and rollback refusals.
Qualification is release- and platform-specific. The current lab result is not installer
qualification or production approval.
