# SRX4100 dev4 installer preflight, 2026-11-28

**Result: authenticated device preview completed and refused to apply.** The first run demonstrated the expected local `R-ROOT` refusal. A second run using a dedicated non-root account authenticated and reached the device planner. Neither run applied changes or passed Q-INST-06.

## Build and lab baseline

- Release: [v0.1.0.dev4](https://github.com/robertsonc/jwicket/releases/tag/v0.1.0.dev4), source commit `12b733d0c41e70da1fee7ee620ecbb5346a9a4a1`. The workstation reported `jwicket-install 0.1.0.dev4`. All four listed files matched the previously verified release's `SHA256SUMS` when rechecked for this run.
- Installer wheel SHA-256: `5e6de92cf9a5df5f67acc98508fc77a5cc5bd269ab8dd086dd9ef25623bab95a`.
- On-box bundle SHA-256: `d70416f6d2e0b5102dd34682dc0706ab6e5270ba686eadad126e690be4ef979e`.
- Target: physical lab SRX4100, Junos `25.2R1-S1.4`, reached over private management from macOS. A separate operator SSH check used strict host-key validation and confirmed a root shell (UID 0). That check was not part of M1.
- The device was not clean: an enabled JET entry pointed to an existing dev3 bundle. Its on-device SHA-256 matched the [published dev3 checksum record](../../releases/v0.1.0.dev3.sha256sums). The state directory already existed with mode `0700`, owned by a named non-root Junos `super-user`. NETCONF over SSH and outbound SSH were configured; this run did not establish their operability for the installer account or determine the outbound SSH management owner.

## Run 1: root identity refusal

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

## Run 2: authenticated non-root device preview

The lab owner authorized a dedicated non-root Junos `super-user` account. A confirmed commit added only that account and its ED25519 public key, with a nonzero Junos-assigned UID. A fresh SSH session verified the effective `super-user` class before permanent confirmation and again afterward. The dedicated private key stayed on the workstation with mode `0600`.

The stock dev4 M1 preview used the same release and physical-lab flag as run 1, with the dedicated account and an explicit identity file. It accepted release provenance (`P-A`), verified the management SSH host key on port 22, authenticated NETCONF, read the device model and Junos version, and reached the planner. It reported:

| Check | Observation |
| --- | --- |
| `R-MODEL` | Shown; acknowledged for preview by the documented `--lab-hardware` flag. |
| `R-UNREADABLE`, `R-STATEDIR` | The state directory was not readable by the new account and was owned by the existing dev3 account. |
| `R-USER`, `R-FOREIGN` | Existing JET entries/files belong to the earlier account; installer ownership evidence did not cover the reported stanzas. |
| `R-MANAGED` | One outbound SSH client was configured; an active manager session was not established by this preview. |

Exit status `1`: `Refused before any write. Nothing was changed.` No `--apply`, adoption or management override was passed. The prior deployment and its files were left intact. Startup, restricted operator tests, restart and removal remain untested for dev4. The account-creation commit is separate from the installer.

## Run 3: dev3 removed, stock preview rerun

The lab owner authorized removal of the manual dev3 deployment. A root-private rollback archive on the lab device was verified before changes; it preserves the prior JET stanzas, four exact J-Wicket scripts, and the old state directory. A Junos confirmed commit removed only those four J-Wicket application stanzas. After verifying the old process was stopped, the operator moved the old files out of their live paths and prepared an empty, real `0700` state directory owned by the new non-root installer account. Port 9443 no longer accepted a TCP connection from the workstation. Shared NETCONF, system script settings, and outbound management were not changed.

The stock dev4 preview authenticated, passed release provenance, and no longer reported the earlier state or ownership refusals. The remaining blocking refusal was `R-MANAGED` for a configured outbound SSH client. `R-MODEL` was shown with the documented physical lab flag. Preview returned exit 1 and stopped before any write. The manual cleanup is not evidence for the installer uninstall method, and the preview is not evidence of startup or a completed dev4 install.

## Next run

Use the [pinned install guide](https://github.com/robertsonc/jwicket/blob/v0.1.0.dev4/docs/install.md). For this physical lab SRX, review the owner-approved handling of the configured manager before any out-of-band apply. A fresh, standalone lab vSRX without a configured manager does not exercise that coexistence case. On either target, record the final stock plan, startup and restart recovery, restricted sign-in, one allowed read, one denied read, and sign-out over verified private TLS, then verify removal or restoration. This record does not close G1 or authorize a read-only alpha.
