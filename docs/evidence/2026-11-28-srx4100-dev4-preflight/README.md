# SRX4100 dev4 installer preflight, 2026-11-28

**Result: blocked before device discovery.** The published M1 workstation installer rejected the supplied root installer identity. This demonstrates the expected `R-ROOT` refusal only; it is not a completed installation or a Q-INST-06 pass.

## Build and lab baseline

- Release: [v0.1.0.dev4](https://github.com/robertsonc/jwicket/releases/tag/v0.1.0.dev4), source commit `12b733d0c41e70da1fee7ee620ecbb5346a9a4a1`. The workstation reported `jwicket-install 0.1.0.dev4`. All four listed files matched the previously verified release's `SHA256SUMS` when rechecked for this run.
- Installer wheel SHA-256: `5e6de92cf9a5df5f67acc98508fc77a5cc5bd269ab8dd086dd9ef25623bab95a`.
- On-box bundle SHA-256: `d70416f6d2e0b5102dd34682dc0706ab6e5270ba686eadad126e690be4ef979e`.
- Target: physical lab SRX4100, Junos `25.2R1-S1.4`, reached over private management from macOS. A separate operator SSH check used strict host-key validation and confirmed a root shell (UID 0). That check was not part of M1.
- The device was not clean: an enabled JET entry pointed to an existing dev3 bundle. Its on-device SHA-256 matched the [published dev3 checksum record](../../releases/v0.1.0.dev3.sha256sums). The state directory already existed with mode `0700`, owned by a named non-root Junos `super-user`. NETCONF over SSH and outbound SSH were configured; this run did not establish their operability for the installer account or determine the outbound SSH management owner.

## Exact checkpoint

Ran the stock preview (address redacted), without `--apply` or a credential argument:

```sh
jwicket-install install --release v0.1.0.dev4 --host LAB_MGMT_IP --user root --lab-hardware
```

The CLI returned exit status `1` and `R-ROOT: J-Wicket must not run as root.` It stopped at username validation. It did not connect to NETCONF, upload files, change JET configuration, or replace dev3. No independent installer authentication was attempted for the existing non-root account.

| Check | Result |
| --- | --- |
| Release checksum recheck and workstation version | Passed |
| Lab reachability and root shell via independently verified SSH | Demonstrated |
| M1 refuses root as the installer user | Demonstrated |
| M1 device discovery, preview, apply, and startup | Not run beyond the local identity refusal |
| Daemon restart recovery, restricted-operator allowed/denied reads and sign-out, and removal or rollback | Not run |

The lab owner separately requested a root credential rotation. It was committed after a successful fresh password-authenticated root SSH login and reverified after permanent confirmation. This was administrative work, not an M1 action or installer rollback. No credential values, private addresses, or raw configuration are included.

## Next run

Prefer a clean isolated lab target for install and removal evidence. If reusing this SRX4100, agree in advance how to preserve and restore the existing dev3 deployment and verify the role of outbound management; do not pass adoption or management overrides just to get through preflight. Authenticate M1 with the named non-root Junos `super-user` through its own password prompt or a verified accepted key. Proceed only if the stock preview produces an agreed plan. Record startup and restart recovery, restricted sign-in, one allowed read, one denied read, and sign-out over verified private TLS, then verify rollback or removal. This record does not close G1 or authorize a read-only alpha.
