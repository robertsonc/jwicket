# ADR 0008: Parity is measured against one named J-Web release, in a ledger

Status: Accepted (2026-11-24)

## Context

The spike report argued for "a branch admin's normal week" instead of screen-for-screen parity.
The charter now sets the bar at parity: an authorized operator can complete the same tasks as on
the reference J-Web release. "Parity" without a named release and an itemised list cannot be
tested and will drift.

## Decision

- The reference is **J-Web for SRX Series 24.4** (the release line the spike ran on, 24.4R2-S3.5),
  as documented in the J-Web User Guide for SRX Series Firewalls, release 24.4.
- `docs/parity/` holds a ledger: one row per J-Web page or operation, with its menu path, source
  URL, the Junos hierarchy it touches, J-Wicket status, the spec that covers it, and a priority.
- A row counts as done only when its acceptance test passes on a qualified platform.
- Moving the reference release is a governance decision recorded with a diff of the two ledgers.

## Consequences

The spike's narrower "normal week" scope survives as **priority** within the ledger, not as the
definition of done. Some J-Web pages will be marked "replace with better" or "out of scope", each
with a reason the project owner approved.
