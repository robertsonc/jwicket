# Lab evidence: two standalone vSRXs, 26 November 2026

A temporary dev3-derived build served certificate-verified HTTPS to an internal lab
client and signed in a restricted Junos operator through a pinned device-local NETCONF
connection. The working path is evidence for an installer design, not a supported
installation mode. No gate was closed.

## Platform and build

| Item | Observed |
| --- | --- |
| Lab | Two standalone vSRXs on Junos 24.4R2-S3.5; same platform and release, not two qualification cells |
| Runtime | Veriexec `loaded active enforce` on both; Python 3.7.10 observed in the vSRX1 JET diagnostic |
| Operator | Dot, with lab owner Corey Robertson's authorization |
| Release source | [dev3](https://github.com/robertsonc/jwicket/releases/tag/v0.1.0.dev3), `c62321ad860b7ab3ad9412c73dbc779c6b12cd33` |
| Final lab-only bundle SHA-256 | `b5ff7500f248662313c041c021614b120b7feb744eec516c3b541e653df0d5eb` |
| Final lab-only payload SHA-256 | `18208dbfc1f8fdb961fedd020162b9a8606cd512e2f3eebf38cc576228ea6218` |

The published diagnostics staged on both devices matched the published bundle checksum.
Their initial registration attempt was discarded before commit. The later vSRX1 runs
used distinct proof builds with an account-owned settings path, a HelperVM-only HTTPS
listener, a single provisioned ECDSA pin, and compatibility code for the on-box SSH and
NETCONF libraries. These changes were not in the dev3 release. The final proof bundle
passed its workstation self-test and matched its on-box SHA-256.

## Test results

| Check | Observation | Limit |
| --- | --- | --- |
| State directory (Spec 006) | The Junos super-user-class account lacked a root shell and could not create `/var/db/jwicket`. With Veriexec unchanged, JET read its settings and opened owner-only logs in a private directory under the account's home. | One account and filesystem layout; installer and reboot persistence untested. |
| Listener (Q-NET-01, Q-TLS-01) | JET's bind-only diagnostic refused `127.0.0.1` but could bind `::1`, the address on `lo0.0`, and the address on `fxp0.0`. The HelperVM got HTTP 200 from both `/` and `/api/session` on fxp0 TCP 9443, with the certificate and IP SAN checked. | IPv6 HTTP and other ingress paths were not tested. The proof's source check is not a Junos ingress filter or production control. No public 9443 forward or REST change. |
| SSH forwarding (Q-NET-03) | SSH authenticated and the workstation opened its local socket, but vSRX1 rejected the forwarding channel as `administratively prohibited`. The remote target was an existing device service, not J-Wicket's failed listener. | Default settings of this device only; no change to SSH policy. |
| Operator NETCONF (Q-AUTH-01) | TCP 830 did not answer on either IP loopback in the JET diagnostic. The same device's interface addresses answered. The compatible proof compared the full provisioned ECDSA host key before password authentication, signed in, performed bounded reads and signed out. A wrong password was rejected in an earlier pinned trial; a nonmatching key and a SHA-1 host signature stopped other trials before password authentication. | Does not qualify new production trust rules, NETCONF sign-in on other builds, or the wrong-password case with a usable daemon account key. |
| Restricted reads (Q-AUTH-03, AC-004-06) | A temporary class with `interface security system trace view` signed in via the pinned path. The root configuration and log sources reported `ok`; the `messages` source was listed but its contents returned `denied` and zero lines. Sign-out was HTTP 200; the next inventory request was 401. Junos attributed the committed reads, `get-log`, and `close-session` to that user. | A custom class on one release; not a minimum privilege recipe, write denial, full class matrix or browser rendering check. |
| Reply compatibility (Q-REL-01) | Baseline NETCONF reads on both devices showed that the full inventory filter was rejected at `tenants`; the minimal filter was accepted. The final application run used that fallback. | The second round added five fixtures, below. The two vSRXs do not add two releases. |
| MNHA baseline (Q-HA-03) | The direct data link was up on both nodes and carried the lab's established IKEv1/IPsec tunnel. Both reported HA mode not configured; the native CLI maps to `get-chassis-high-availability-information`. Both ran `kmd`; no mounted optional IKE package or running unified `iked` was observed. | No MNHA was configured during baseline capture. See the staged trial and the later successful SRG0 peer retest below. |

No NETCONF credentials or traffic contents are included. Device and lab addresses,
passwords and hashes, certificates and keys, raw syslog and VPN details are omitted. The
temporary operator accounts and non-HA configuration proofs used timed confirmed commits
without confirmation. The published installer did not run. The paired HA trial required an
explicitly restored regular commit to persist through reboot.

See [Spec 006's proposed preflight](../../specs/006-installation.md#712-adaptive-preflight-proposed)
and the [qualification matrix](../../governance.md#5-qualification-matrix).

## Restoration

Confirmed rollback removed the restricted user and class and the temporary JET
registration. The original scripts language and REST configuration were restored or
unchanged. The HelperVM could no longer reach the listener. The test state and
certificate files were removed, and Veriexec still reported `loaded active enforce`.

## Paired MNHA configuration trial

With the lab owner's approval, the trial temporarily deactivated the existing lab VPN
and its IKE gateway, then configured reciprocal MNHA peers and SRG0 on the direct link.
The exact candidate diff was checked under a configuration lock on both devices.
No management, filter, peer-commit, firmware or package changes were made. The follow-up
exercised only SRG0 over the direct lab data link. No test application traffic was
generated, and configuration synchronization was not enabled. It did not test an
encrypted or production HA deployment.

Both confirmed commits succeeded with Junos's HA mode change reboot warning. Without
a reboot, both native peer and SRG0 status commands still reported HA mode not
configured. The trial did not verify service roles, state synchronization, encryption,
or failover. Encrypted qualification still requires a lab image with the supported IKE stack.
[Juniper 24.4 MNHA example](https://www.juniper.net/documentation/stage/us/en/software/junos2024.4/high-availability/topics/example/mnha-configuration-example.html) ·
[Juniper 24.4 ICL encryption prerequisites](https://www.juniper.net/documentation/us/en/software/ccfips24.4/cc_security/cc-security5k/topics/concept/configuring-multinode-ha-link-encryption.html)

A separate narrow committed read found `chassis high-availability` on both nodes.
The unchanged J-Wicket inventory logic, exercised off-box against the live replies,
returned `standalone` with a warning that the MNHA settings had not been read. Junos
rejected the full inventory filter at `tenants`, and the fallback does not request the
chassis subtree. This is a detection gap, not evidence of peer health or a live browser
UI test. A future narrow HA read should distinguish absent configuration from denied
or unreadable configuration; it must not infer that a peer is up. The installer still
refuses `R-MNHA`.

Neither timed commit was confirmed. After rollback, the scoped committed configuration
digests (HA, IKE and IPsec) matched both pre-trial baselines, SSH management was still
reachable, and each device again showed one active IPsec tunnel.

### Reboot follow-up

A fresh confirmed commit rolled back on vSRX1 during its first reboot; after SSH
returned, neither the MNHA stanza nor a pending rollback remained. The second node
was held until its own pending change was explicitly restored. The lab owner
authorized rebooting both nodes. After verifying the original scope and exact
candidate on each device, the same lab-only configuration was committed without a
timer. The nodes were rebooted one at a time and the change was verified to persist.

| Observation after both nodes rebooted | vSRX1 | vSRX2 |
| --- | --- | --- |
| MNHA and peer configured, per Junos | Yes | Yes |
| Local SRG0 | ONLINE | ONLINE |
| Peer connection / BFD | DOWN / DOWN | DOWN / DOWN |
| J-Wicket dev3 inventory against live replies, off-box | `standalone` with incomplete-read warning | `standalone` with incomplete-read warning |

The two local SRG0s activated, but they did not form an operational peer pair in
this trial. Cold sync showed `IN PROGRESS`, with no SRG status messages exchanged
in the captured counters. The cause of the down peer was not isolated. No on-box
J-Wicket, successful state sync, encrypted ICL, or failover was demonstrated.
Q-HA-03 remains partial, and the installer still refuses `R-MNHA`.

The scoped restore matched the pretrial HA, IKE and IPsec configuration digests
on both nodes. Because native HA state persisted after restoring the
configuration, each node was rebooted once more. After that, Junos reported HA
mode not configured on both and each again showed one active original IPsec
tunnel. Management access was verified after every reboot.


## Native description-only rollback

On vSRX1, a read of the lab-owned VPN policy established its original four statements.
Under an exclusive candidate lock, the only addition was a synthetic description.
NETCONF committed it on a 90-second timer, and the committed reread showed exactly
the original policy plus that description. No confirm, extend, or manual rollback
was sent. Junos logged `UI_COMMIT_NOT_CONFIRMED` and automatic rollback completion.
An exact committed comparison of the policy found no difference, and the shared
candidate was clean. This is the native timeout and scoped-restore portion of
Q-CHG-03. It did not cut management access (Q-CHG-02), test the other undo modes,
or use a J-Wicket write path.

## Synthetic policy and log reply capture

Two vMX lab hosts sent ICMP across the restored lab VPN. The trace used an exact
host-to-host permit for ICMP before the existing lab VPN permit; no other source,
destination or application matched the new rule. All 20 test packets received
replies, and Junos showed nonzero hits on the temporary rule. The temporary log
held one synthetic marker. The lab operator could read it and a restricted
operator received Junos's file-open permission denial for the same file.

J-Wicket's live flow and file-read code, called off-box under the same lab
operator against live NETCONF, matched the native CLI on policy/protocol and on
the synthetic log marker. In a separate capture, the filtered NETCONF list and
summary returned four matching ICMP sessions, and the unfiltered gauge showed
six active sessions. CLI and NETCONF were sampled sequentially, so table
counts were not compared as simultaneous readings.

[Five sanitized fixtures and their provenance](../../../tests/fixtures/recorded-vsrx-24.4R2-S3.5/SOURCE.md)
cover the list, both summaries, allowed log content and actual denied log
reply. The regression tests replay them directly. The vSRX reply uses `sess-state`;
the current parser preserves it as an extra rather than returning it in the
main state field. This adds partial Q-REL-01 evidence on a second platform
and release, not cell qualification.

## Ten-minute idle and JET supervisor recovery

The same verified dev3-derived proof bundle started without arguments on vSRX1
and answered the HelperVM over certificate-verified HTTPS. No browser or
operator session was signed in during the measurement. Process samples taken
through the management CLI showed one PID for the entire idle window.

| Observation | Result |
| --- | --- |
| First pinned HTTPS response | HTTP 200; expected version and payload prefix |
| First process sample | 30,924 KiB resident; 48,600 KiB virtual |
| 60 seconds through 600.16 seconds | 30,624 KiB resident; 54,032 KiB virtual at each one-minute sample |
| SIGTERM | New supervised PID and pinned HTTPS 200 in 1.62 s |
| SIGKILL | New supervised PID and pinned HTTPS 200 in 6.28 s |

Neither recovery used a manual start. Veriexec remained enabled. This is
partial Q-RT-02 evidence for the lab-derived build, not the released bundle:
the stock installer and reboot persistence were not tested. Timings include
the verification poll.


The temporary JET configuration rolled back. The scoped baseline, REST on
TCP 3000, Veriexec state, and removal of the app files and HelperVM certificate
were verified.


### One signed-in operator

The same payload was staged again with a fresh, pinned TLS certificate. A
scripted HTTPS client on the HelperVM used one real Junos-backed operator
session, read inventory, and refreshed Sessions and the system-log tail nine
times over 81 seconds. All refreshes returned HTTP 200 and status `ok`;
sign-out returned 200 and the next inventory request returned 401. The audit
events confirmed inventory, session and log reads during the single sign-in.

Five process samples taken during that signed-in window were 48,984–52,168 KiB
resident and 79,484–81,688 KiB virtual. This is one operator with bounded
read refreshes, not a sustained multi-operator or browser benchmark.

## MNHA peer and cold-sync retest

The direct link had connected routes and bidirectional ARP, but the baseline
zone admitted only IKE; direct ICMP got no replies in either direction. The
retest preserved IKE and the existing screen and allowed BFD, the HA service,
and diagnostic ICMP only on the two direct-link interfaces. No filters, SSH
services or packages were changed. Direct ICMP then passed 4/4 each way before
the sequential reboots. See
[Juniper's interchassis-link example](https://www.juniper.net/documentation/us/en/software/junos/high-availability/topics/concept/mnha-asymmetric-route-support.html).

| Observation after both reboots | vSRX1 | vSRX2 |
| --- | --- | --- |
| BFD peer | Up | Up |
| Junos peer connection | UP | UP |
| Cold sync | COMPLETE | COMPLETE |
| Local SRG0 | ONLINE | ONLINE |
| Attribute messages sent / received | 1 / 1 | 2 / 1 |
| Attribute acknowledgments sent / received | 1 / 1 | 1 / 1 |
| Encryption | NO | NO |
| J-Wicket dev3 inventory, off-box against live NETCONF | `standalone` with warning | `standalone` with warning |

The scoped permissions resolved peering in this retest; their individual
effects were not isolated. The captured counters had no send or receive
errors and no SRG status messages or acknowledgments. These observations
demonstrate native, unencrypted SRG0 peering and reported cold-sync
completion, not traffic survival, SRG1, failover or encrypted ICL. The
contemporaneous J-Wicket responses confirm the inventory detection gap
even with an operational peer. No on-box HA UI was exercised.

The original configuration, including the untrust zone and VPN, matched
the saved scope on each vSRX after the restore. After sequential cleanup
reboots, both had working management access, reported HA not configured
and showed one active original IPsec tunnel each. Q-HA-03 remains partial.
