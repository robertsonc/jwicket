# ADR 0007: "Offline-capable" means no runtime internet dependency

Status: Accepted (2026-11-24)

## Context

Firewalls are often managed from isolated management networks with no internet path. Browser
"offline" features (service workers, IndexedDB caches) would also keep firewall configuration on
whatever workstation the operator used, often a shared jump host.

## Decision

- Every asset is served by the device. No CDN, no web fonts, no external URLs; the Content Security
  Policy allows only `'self'`, and a test fails the build if an asset contains an external URL.
- Review away from the device uses explicit exports (JSON snapshot, CSV), each stamped with device,
  scope, user and read time.
- Device data is never written to browser storage. `localStorage` holds UI preferences only.

## Consequences

The UI does not work when the device is unreachable, and says so. An "offline review" mode that
opens an exported snapshot locally is a possible later feature; it would read a file the operator
chose, not a cache.
