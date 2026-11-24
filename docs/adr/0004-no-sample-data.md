# ADR 0004: No sample data: every panel is device data or an explicit state

Status: Proposed (written 2026-11-24; owner acceptance not recorded, governance D11)

## Context

The spike UI filled any panel it could not read with rows tagged "sample data". On a firewall, a
plausible table that is not the device's is worse than an empty one: someone will act on it.

## Decision

A panel shows device data, or one of: `denied` (the operator's login class does not allow the
read), `unsupported` (the device lacks or has not enabled the feature), `failed` (timeout,
transport, malformed reply), `session-lost` (sign in again). Each carries an operator-safe message.
Development fixtures are allowed only through the development server, which marks every page with
a "fixture data" banner and labels the snapshot `fixture: true`.

## Consequences

The UI must design for partial data from day one, which is also what least-privilege operators
will see. Tests assert that a denied configuration read produces no policy rows.
