# ADR 0009: Detect central management and treat it as a co-owner of the configuration

Status: Accepted (2026-11-24)

## Context

Many SRX devices are also managed from Security Director, Security Director Cloud or Mist. A
change made on the box is an out-of-band change to those systems: it may be overwritten, flagged
as drift, or conflict with a pending deployment. J-Web 24.4 itself includes a flow to add the
device to Security Director Cloud.

## Decision

- Spec 001 reads `system services outbound-ssh` clients and shows them in the scope banner as
  "also managed from", with the client name and targets, never the secret.
- Spec 002 treats a detected manager as a co-owner: a write flow must show the warning, require an
  explicit acknowledgement recorded in the audit trail and the commit comment, and may be blocked
  by policy (setting) on managed devices.
- Detection is a heuristic. Management over plain inbound NETCONF leaves no trace in the
  configuration; the banner says "detected", not "not managed".

## Consequences

The exact signatures for each manager need confirmation (Q-MGMT-01). J-Wicket never manages more
than the one device it runs on.
