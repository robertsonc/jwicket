# Lab evidence: dev3 on an SRX4100, 26 November 2026

On this device, a restricted Junos user could read root-system policies through J-Wicket
without gaining access to the contents of the `messages` log. The source was listed, and the
tail returned an explicit `denied` state with no lines. This is a partial Q-AUTH-03 result
and a device observation for the file-source denial case in AC-004-06. It is not certified.

## Platform and build

| Item | Value |
| --- | --- |
| Operator | Dot, with lab owner Corey Robertson's authorization |
| Hardware | One standalone lab SRX4100, Junos 25.2R1-S1.4 |
| Runtime baseline | The [previous run on this device](../2026-11-24-srx4100-lab/README.md) recorded Veriexec as `loaded active enforce`. Veriexec and memory were not measured again in these trials. |
| Access | Certificate-validated HTTPS on fxp0 in `mgmt_junos`; the web app authenticated the operator over local NETCONF |
| Release | [`v0.1.0.dev3`](https://github.com/robertsonc/jwicket/releases/tag/v0.1.0.dev3), commit `c62321ad860b7ab3ad9412c73dbc779c6b12cd33` |
| Bundle SHA-256 | `e76f0a11a7eacb5a86b73245370efc69e078c2e0835046f5bc34bb1e5b6e0370` |
| `payload_sha256` | `3387bf3978d21501df1b1f1e9137d359b03fafe6da3873cd5571271ab5281b5a` |

The released bundle was installed by hand and checked against the published SHA-256. The
cutover reused the existing TLS configuration; it did not exercise a Spec 006 installer,
upgrade method, certificate provisioning, or the device ingress-filter test.

## Two restricted-class trials

For each trial, the lab operator checked for a clean candidate and no pending confirmed
commit. The reviewed diff added only a temporary Junos user and class. The operator used a
120-second confirmed commit and let it expire; there was no J-Wicket configuration write.
Neither trial granted `configure`, any `*-control` permission, `secret`, or `maintenance`.
No write was attempted as the restricted user. Tests exercised the actual HTTPS API, not
browser rendering.

| | Trial 1 | Trial 2 |
| --- | --- | --- |
| Junos permissions | `security system trace view` | Same, plus `interface` |
| Sign-in | HTTP 200 | HTTP 200, NETCONF backend |
| Committed root inventory | Configuration `denied`; Junos audit identified `chassis` as the denied hierarchy | Configuration and policies `ok`; three policy inventory rows returned |
| Log sources | `ok`; `messages` listed | `ok`; `messages` listed |
| Log tail | HTTP 200, panel state `denied`, zero lines | HTTP 200, panel state `denied`, zero lines |
| Sign-out | HTTP 200; subsequent inventory request HTTP 401 | HTTP 200; subsequent inventory request HTTP 401 |

Junos recorded the committed configuration reads, `get-log filename=messages`, and
`close-session` under the temporary identity in Trial 2. The `messages` stanza had no
world-readable override. The denial despite `trace` is consistent with Junos's documented
[default file access for root and users with `maintenance`](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/world-readable-edit-system.html).
No log permissions or logging configuration were changed. The tested permission sets
are observations for this device and build, not a recommended class or a minimum.

Both rollbacks removed the user and class. The device recorded the second rollback at
14:47:04 UTC (08:47:04 CST on its clock). Pinned HTTPS still reported dev3 and the same
payload build afterward.

## What remains open

- **Q-AUTH-03:** This tests two variants of one custom class on one device. The full
  per-class endpoint and CLI comparison, raw RPC replies, regexp-limited classes,
  logical-system and tenant classes, and other release/platform cells remain open.
- **AC-004-06:** The API returned `denied` after sources were read successfully. This does
  not establish a successful restricted log tail, report or buffer denial after source
  discovery, or browser rendering. It does not add a recorded-reply fixture.
- **Gates:** G0 remains the only passed gate. No gate or parity row advances on this record.
  This does not demonstrate the preview builder or any live configuration change by J-Wicket.

This record summarizes the observed API states and Junos audit events. Raw responses,
device transcripts, credentials, identifiers and policy or log contents are not included.
See the [qualification matrix](../../governance.md#5-qualification-matrix) for remaining work.
