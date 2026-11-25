# Installer fixtures (Spec 006, section 17.1)

**Everything in this directory is synthetic.** No file was captured from a device. The XML replies are
shaped from the junos-es 23.2R1 YANG modules (`get-commit-information`, `file-list`,
`get-sha256-checksum-information`) and from PyEZ 2.8.3's parsers (`file-permissions` with a `format`
attribute; a standalone SRX's cluster-status `<error>`), as Spec 006 cites them. Wherever a real
reply's shape or wording is unknown (the absent-path errors, the `commit-confirmed` text, where a commit
comment lands, the flow-session summary), the file says so in a comment, and lab test **Q-INST-01**
records the real replies; recorded fixtures will then live beside these in their own directory, as
`tests/fixtures/README.md` describes for the daemon's fixtures. A passing test shows what the plan does
with these replies; it proves nothing about what a device sends or does (Q-INST-06).

Two scenarios borrow values that **were** recorded: `lab-srx4100` takes the model, release, bundle
SHA-256 and the shape of what was left on the box from
[`docs/evidence/2026-11-24-srx4100-lab/`](../../../docs/evidence/2026-11-24-srx4100-lab/README.md) (every
reply in it is still synthetic, and its host name, serial and addresses are placeholders), and every
fixture's `/var/db/jwicket` follows that run's finding that root, not the daemon's account, makes the
directory (revision R4).

Secrets are obvious placeholders (`$9$FIXTURE-PLACEHOLDER-NOT-A-SECRET`, `$6$FIXTURE-PLACEHOLDER-HASH`,
`fixture-user:fixture-pass`); the tests require that none of them survives parsing or reaches any output.

## Layout

| Path | What it holds |
| --- | --- |
| `base/` | A fresh lab vSRX (host `lab-vsrx-1`, model `vsrx`, 24.4R2-S3.5, serial `FIXTURE-SN-0001`): no J-Wicket, NETCONF off, nothing pending, `/var/db/jwicket` made once by root and given to `labadmin` (`drwx------`, empty; R4), veriexec enforcing |
| `scenarios/<name>/` | Only the files that differ from `base/`, plus `scenario.json` |
| `golden/` | Reviewed renderings (paste units, bootstrap units, plan JSON, plan diff, `.set` files, `jwicket.ini`). Refresh with `JWICKET_UPDATE_GOLDEN=1` and review the diff |

File names in a fixture directory (`tests/install_support.py` reads them):

| File | Reply of |
| --- | --- |
| `software-information.xml` | `get-software-information` |
| `chassis-cluster-status.xml` | `get-chassis-cluster-status` |
| `chassis-inventory.xml` | `get-chassis-inventory` |
| `flow-session-summary.xml` | `get-flow-session-information` summary (shape inferred) |
| `config-raw.xml` (`config-inherited.xml` when it differs) | the select-only `<get-configuration>` read of spec 8.3 |
| `commit-information.xml` | `get-commit-information` |
| `file-list-var-db*.xml` | `file-list detail` of `/var/db/scripts/jet`, `/var/db/scripts/op`, `/var/db`, `/var/db/jwicket` |
| `sha256-<name>.xml` | `get-sha256-checksum-information` of a J-Wicket file, `jwicket.ini` or `tls.crt` (`6a...`; never `tls.key`) |
| `rollback-delta-<n>.txt` | the committed delta of history entry `n` in patch form, `+` meaning added by entry `n`: `get-rollback-information` with `rollback` n+1 (the base) and `compare` n (Juniper's NETCONF guide, "Compare Two Previous (Rollback) Configurations", **verified**); the reply shape is Q-INST-01's |
| `workstation-receipt.json`, `device-receipt.json` | receipts, schema 3 (installs with `--access tls` on `192.0.2.10:9443`, certificate SHA-256 `5b...`, its `tls.crt` file SHA-256 `6a...`, notAfter `2099-01-01T00:00:00Z` so that no test depends on today's date) |
| `device-receipt-show.xml` | `file-show` of the device receipt |
| `veriexec.txt` | the output of `sysctl security.mac.veriexec.state` |

`scenario.json` fields: `description`; `refusals` (the codes of spec 8.11 the scenario must produce);
`needs` (the overrides that let it proceed); `rpc_errors` (a reply that raised, with its message);
`bootstrap` (the own pending bootstrap's method and nonce); `inverse_removed_prefixes`,
`inverse_added` and `inverse_note` (what an install followed by an uninstall cannot or must not give
back, and why: an adopted stanza, a pending own bootstrap, an install that was already there, a
`language python3` another Python script relies on).

## Scenarios

The 17.1 list: a fresh vSRX; a vSRX with `system management-instance` (`management-instance`: the plan
renders `routing_instance = mgmt_junos`); the lab SRX4100 reference case of `--lab-hardware`
(`lab-srx4100`: Security Director Cloud over outbound-ssh, `management-instance`, the lab run's manual
install to adopt); an absent `/var/db/jwicket` (`absent-paths`: R-STATEDIR and the root step);
`language python3` and `netconf ssh` already set; a deploy-lab manual install (stanzas, no receipt); a
foreign `groups jwicket`; a chassis cluster; a standalone SRX's cluster-status `<error>` (in `base/`) and
a cluster-status RPC that raised; MNHA; a physical model (`srx345`, which `--lab-hardware` lets through
R-MODEL); no host name; a pending confirmed commit by another user; the installer's own pending
bootstrap and three near misses (another user, another nonce, an extra line in its delta); a
`prepared-commit` and a scheduled `commit at`; an unreadable commit state; `language python`;
`load-scripts-from-flash`; `system fips level 2`; outbound-SSH clients with a `secret` leaf, a login
hash and a source URL with user information that a failed filter returned; commit scripts; other Python
op and event scripts and another `.py` in the JET directory; `web-management` on 9443 and `rest` on 8443
(the two access modes' default ports);
absent-path errors for `file-list` and `file-show`; a running install with history and receipts; the
same install of an earlier build (upgrade); a device receipt that disagrees with the history; a
half-finished install (files, no stanzas); commit comments containing `{{ lookup('pipe', 'id') }}`,
quotes, a newline and a URL with user information.
