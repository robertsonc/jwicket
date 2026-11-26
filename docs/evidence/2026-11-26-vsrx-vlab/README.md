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
| Reply compatibility (Q-REL-01) | Baseline NETCONF reads on both devices showed that the full inventory filter was rejected at `tenants`; the minimal filter was accepted. The final application run used that fallback. | Same-release repeatability only. No recorded-reply fixtures are added by this record. |
| MNHA baseline (Q-HA-03) | The direct data link was up on both nodes and carried the lab's established IKEv1/IPsec tunnel. Both reported HA mode not configured; the native CLI maps to `get-chassis-high-availability-information`. Both ran `kmd`; no mounted optional IKE package or running unified `iked` was observed. | No MNHA configuration, encrypted peer formation, J-Wicket live detection, or failover test. Preserve the existing VPN and use a lab image with the supported encrypted ICL stack. |

No NETCONF credentials or traffic contents are included. Device and lab addresses,
passwords and hashes, certificates and keys, raw syslog and VPN details are omitted. The
restricted account and all active test configuration used timed confirmed commits without
confirmation. The project did not run the released installer, measure ten-minute idle RAM,
or test stable daemon respawn in this run.

See [Spec 006's proposed preflight](../../specs/006-installation.md#712-adaptive-preflight-proposed)
and the [qualification matrix](../../governance.md#5-qualification-matrix).

## Restoration

Confirmed rollback removed the restricted user and class and the temporary JET
registration. The original scripts language and REST configuration were restored or
unchanged. The HelperVM could no longer reach the listener. The test state and
certificate files were removed, and Veriexec still reported `loaded active enforce`.

The MNHA prerequisite check did not change either vSRX. Juniper documents an encrypted
ICL for supported MNHA and the unified IKE package for that encryption on this release.
The existing VPN was not interrupted. J-Wicket's installer still refuses `R-MNHA`;
the application can label MNHA from committed configuration but does not report live
peer health or failover. Neither was exercised on an actual pair here.
[Juniper MNHA overview](https://networkingdocs.hpe.com/documentation/us/en/software/junos/high-availability/topics/concept/mnha-overview.html) ·
[Juniper 24.4 ICL encryption prerequisites](https://www.juniper.net/documentation/us/en/software/ccfips24.4/cc_security/cc-security5k/topics/concept/configuring-multinode-ha-link-encryption.html)
