# J-Wicket @@TAG@@: LAB ONLY, pre-release, unsupported

**LAB ONLY. Pre-release. Unsupported.** J-Wicket is at its foundation stage and is not qualified for, or installable on, a production SRX: gate G1 has not passed ([governance](https://github.com/@@REPO@@/blob/main/docs/governance.md)), and neither has the security review (Q-SEC-01). Use it only on a lab device you are allowed to change: a disposable vSRX, or, with `--lab-hardware`, a physical SRX that carries only lab traffic.

> This installer has not yet run on any device. Every device step is unverified until lab test Q-INST-06 is certified.

J-Wicket itself has run once, installed by hand, on a lab SRX4100 (Junos 25.2R1-S1.4, Python 3.7.10): [the evidence](https://github.com/@@REPO@@/blob/@@COMMIT@@/docs/evidence/2026-11-24-srx4100-lab/README.md). No installer step has run on any device; [`docs/install.md`](https://github.com/@@REPO@@/blob/@@COMMIT@@/docs/install.md) labels each fact it relies on verified (by Juniper's documentation or by that run), inferred or unknown.

- Version: `@@VERSION@@`
- Source commit: `@@COMMIT@@`
- Built by `.github/workflows/release.yml` at that commit, and rebuilt byte for byte on Python 3.7 (the SRX's), 3.9 and 3.13 before publication.

## Assets

| Asset | SHA-256 |
| --- | --- |
| `jwicket.py` (the daemon bundle) | `@@BUNDLE_SHA256@@` |
| `jwicket-install-op.py` (the on-box op-script installer, M4) | `@@OP_SHA256@@` |
| `@@WHEEL_NAME@@` (the workstation installer, M1) | `@@WHEEL_SHA256@@` |
| `requirements-install.txt` (the installer's hash-pinned dependencies) | `@@REQUIREMENTS_SHA256@@` |

The bundle's payload SHA-256, which its header and J-Wicket's start log line carry: `@@PAYLOAD_SHA256@@`.

`SHA256SUMS` (its own SHA-256 is `@@SUMS_SHA256@@`):

```
@@SHA256SUMS@@
```

## Check where it came from before you use it

`SHA256SUMS` on this page protects against a corrupted download, **not** against a replaced release: whoever could replace the assets could replace `SHA256SUMS` with them. Check at least one source that is independent of this page (Spec 006 section 8.9), then `sha256sum -c SHA256SUMS` in the download directory:

1. P-A, the immutable release's attestation: `gh release verify-asset @@TAG@@ <file> --repo @@REPO@@`
2. P-B, the build-provenance attestation: `gh attestation verify <file> --repo @@REPO@@ --signer-workflow @@REPO@@/.github/workflows/release.yml --source-ref refs/tags/@@TAG@@ --source-digest <commit>`, where `<commit>` is the `source ref:` line of the bundle's header, and that commit is on `main`.
3. P-C, the release record on `main`: compare with [`docs/releases/@@TAG@@.sha256sums`](https://github.com/@@REPO@@/blob/main/docs/releases/@@TAG@@.sha256sums), added by a reviewed pull request after publication. It is byte-identical to `SHA256SUMS`.
4. P-D, a local reproduction (below).

Download by hand: `gh release download @@TAG@@ --repo @@REPO@@ --pattern jwicket.py --pattern SHA256SUMS`. Always use this tag's URLs (`https://github.com/@@REPO@@/releases/download/@@TAG@@/<file>`), never `/releases/latest`: a pre-release is never "latest".

## Reproduce (P-D)

Python 3.7 or later, from a clone of the repository:

```
git checkout @@COMMIT@@
python3 tools/bundle.py --out dist/jwicket.py --source-ref @@COMMIT@@
PYTHONPATH=tools python3 -m jwicket_install.build_op --bundle dist/jwicket.py --tag @@TAG@@ --repo @@REPO@@ --out dist/jwicket-install-op.py
python3 tools/build_wheel.py --out dist --source-date-epoch "$(git log -1 --format=%ct @@COMMIT@@)"
cp requirements-install.txt dist/
cd dist && sha256sum jwicket.py jwicket-install-op.py @@WHEEL_NAME@@ requirements-install.txt
```

The four lines must equal `SHA256SUMS` above.

## Before you install

### The state directory: one step as root, once per device

J-Wicket keeps its settings, its TLS certificate and key, its log and its audit trail in `/var/db/jwicket`, which must be a real directory (not a symbolic link) owned by the account J-Wicket runs as (`--user`, written `<user>` below), mode 700. That account cannot create it: on the lab SRX4100, a super-user-class account's `mkdir /var/db/jwicket` and `file make-directory` were both refused with `Permission denied` (verified). The installers never create it, never log in as root and never ask for the root password. Their dry run lists `/var/db` and `/var/db/jwicket` and reports R-STATEDIR while the directory is absent or not as described, and `--apply` then writes nothing. Once, in a shell on the lab device as root (outside Juniper support; how you become root is your lab's own procedure), run the command root ran on that SRX4100 (verified there), with `<user>` replaced:

```
mkdir -m 700 /var/db/jwicket && chown <user> /var/db/jwicket
```

`file list /var/db detail` should then show `jwicket` as `drwx------`, owned by `<user>`. Then run the installer again.

### How you reach J-Wicket: `--access`

`--access tls`, the default: J-Wicket listens with TLS on the device address your browser reaches (`--listen-address`, which defaults to `--host` when that is an IP address and is required otherwise), port 9443 unless `--daemon-port` says otherwise; a port that J-Web or the REST API is configured on is refused (R-PORT). The installer generates a self-signed RSA-2048 certificate for that address in memory, copies the key (mode 0600) and the certificate to `/var/db/jwicket` over SCP (the owner and mode they get there are unverified until lab test Q-INST-01), never writes the key to your workstation, and prints only the certificate's SHA-256 fingerprint. When the device has `system management-instance`, the settings carry `routing_instance = mgmt_junos`, as on the SRX4100 run (verified there). The health check before each confirm includes an HTTPS request to `/api/session` that trusts only that certificate.

> LAB ONLY. With --access tls the runtime commit opens a new HTTPS listener on this device's management address: the --listen-address, by default --host, which the installer does not check is the management address (an address of a revenue interface would put the listener there; in the mgmt_junos routing instance when 'system management-instance' is set). It is reachable by anything that reaches that address: J-Wicket's sign-in page becomes one more way into this device, beside SSH and NETCONF. Its certificate is self-signed; compare its SHA-256 fingerprint in the browser with the one the installer prints. J-Wicket has not passed gate G1 or a security review (Q-SEC-01). Continue only on a lab device whose management network you control.

`--access tunnel`: J-Wicket listens on `127.0.0.1` only, without TLS, and the installer prints the `ssh -L` line that reaches it.

> With --access tunnel, J-Wicket listens on 127.0.0.1 only and is reached through 'ssh -L', which needs SSH TCP forwarding on the device. On a lab SRX4100 running Junos 25.2R1-S1.4 the tunnel was refused ('administratively prohibited') and 'set system services ssh tcp-forwarding' is a syntax error there (verified, docs/evidence/2026-11-24-srx4100-lab). The SRX configuration schema at 23.2R1 marks tcp-forwarding deprecated and names 'set system services ssh allow-tcp-forwarding'; that statement was not tried (unverified, Q-NET-03). Health check C8 is not available with this mode. --access tls is the alternative.

### Which devices

A vSRX by default; anything else is refused (R-MODEL). On a physical SRX that carries only lab traffic, `--lab-hardware` shows the production signs first (the central manager's `outbound-ssh` client names, the flow-session count, the committers and the last commit time, model, release and serial) and, after the host name, asks you to type `lab only`; the install record keeps that statement. A device managed over `outbound-ssh` still needs `--ack-managed`, and chassis clusters, MNHA and dual routing engines are refused.

## Install (every device step unverified)

The full procedure, every method and its verified, inferred and unknown steps are in [`docs/install.md`](https://github.com/@@REPO@@/blob/@@COMMIT@@/docs/install.md) at this commit. Every installer is a dry run by default, shows the plan's diff and the posture warning, asks you to type the lab device's host name (and, with `--lab-hardware`, `lab only`), and makes every change a `commit confirmed` that it confirms only after a health check.

### M1: workstation installer

On a workstation with Python 3.9.2 or later: the hash-pinned requirements need it (paramiko 5.1.0 and cryptography; cryptography refuses 3.9.0 and 3.9.1), although `junos-eznc` 2.8.3 itself declares 3.8. After checking provenance and `sha256sum -c SHA256SUMS`:

```
python3 -m venv ~/.local/share/jwicket-install
~/.local/share/jwicket-install/bin/pip install --require-hashes -r requirements-install.txt
~/.local/share/jwicket-install/bin/pip install --no-deps ./@@WHEEL_NAME@@
~/.local/share/jwicket-install/bin/jwicket-install install --release @@TAG@@ --host <device> --user <u>
```

The last line is the dry run: it reads the device and prints the plan. When `<device>` is a name rather than an IP address, add `--listen-address <the device address your browser reaches>`. Add `--apply` to install. Then, with `--access tls`, open `https://<listen address>:9443/` (or your `--daemon-port`) and, before you sign in, compare the certificate's SHA-256 fingerprint with the one the installer printed.

### M4: on-box op-script installer, from the Junos CLI only

> LAB ONLY. This adds 'set system scripts language python3'. That lets any unsigned Python script owned by a super-user-class account run on this device's routing engine, not only J-Wicket: a change to the device's security posture. J-Wicket is not qualified for production (gate G1 has not passed). Continue only on a disposable lab device you are allowed to change.

Check that your CLI prompt shows `<u>@<the lab device you intend>` before each unit. These units mirror the installer's M4 bootstrap (Spec 006 sections 6.5 and 7.7); `docs/install.md` has the same units. Make the state directory first ([above](#the-state-directory-one-step-as-root-once-per-device)): the op script refuses (R-STATEDIR) before its prompt while it is not right.

**Unit 0**, operational mode. Whether `file copy https://` checks the server certificate and follows GitHub's redirect on Junos OS is unknown (Q-INST-05); `scp -O` from any machine is the alternative.

```
file copy https://github.com/@@REPO@@/releases/download/@@TAG@@/jwicket-install-op.py /var/db/scripts/op/jwicket-install-op.py
file checksum sha-256 /var/db/scripts/op/jwicket-install-op.py
```

STOP unless the checksum is `@@OP_SHA256@@` **and** that value is the one for `jwicket-install-op.py` in [`docs/releases/@@TAG@@.sha256sums`](https://github.com/@@REPO@@/blob/main/docs/releases/@@TAG@@.sha256sums) on `main`, or in a verified attestation. A match with this page alone is not enough.

**The certificate, once** (with `tls`, the op script's default access; skip it for `tunnel`). The op script never makes the TLS key pair, and the key never leaves the device: make it yourself before unit A, in a shell on the device as `<u>` (not root), with your listen address (the device address your browser reaches, fxp0's on a box managed through fxp0) in place of `<address>`. This is deploy-lab's TLS unit, verified on SRX4100 25.2R1-S1.4, outside Juniper support:

```
start shell sh
cd /var/db/jwicket
umask 077
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 90 -keyout tls.key -out tls.crt -subj /CN=<address> -addext subjectAltName=IP:<address>
chmod 600 tls.key
chmod 644 tls.crt
openssl x509 -in tls.crt -noout -fingerprint -sha256
exit
```

Write down the `SHA256 Fingerprint=` line. Until both files are there, owned by `<u>`, the op script refuses `tls` before any write, and the pasted bootstrap would only roll back. The certificate is valid for 90 days: run this unit again before then and restart J-Wicket.

**Unit A**, the op bootstrap. Paste:

```
configure exclusive
run show system commit | no-more
```

STOP if the newest entry (`0`) ends with `commit confirmed, rollback in <n>mins`, or the output starts with `commit requested by` (someone's commit is pending): type `exit`. Otherwise paste the lines below, leaving out the first one when `language python3` is already set:

```
set system scripts language python3
set system scripts op file jwicket-install-op.py checksum sha-256 @@OP_SHA256@@
show | compare | no-more
```

STOP unless `show | compare` shows these statements and nothing else (the `language python3` block is absent if it was already set). Junos prints each change under the deepest level that already exists, and a new level as a braced block of `+` lines under that header, so the same statements may appear grouped that way, for example `[edit system scripts]` then `+    op {` ... `+    }` (illustrative; real samples are recorded by lab test Q-INST-01):

```
[edit system scripts]
+    language python3;
[edit system scripts op file jwicket-install-op.py checksum]
+    sha-256 @@OP_SHA256@@;
```

If it shows anything else, type `rollback 0` and `exit`. If it matches, paste:

```
commit confirmed 10 comment "jwicket-bootstrap op"
```

Wait for the commit to finish, then paste this on its own (nothing follows `commit confirmed` in one paste):

```
exit
```

Do not confirm it yourself. Keep this CLI session open: whether closing it rolls the pending commit back early is unknown (Q-INST-03). Then run `op jwicket-install-op.py` (that `op` takes the name with its `.py` suffix is inferred). The script prints the plan and the warnings, asks for the host name, and confirms the bootstrap only after a match. Enter, a wrong name or any refusal leaves the bootstrap unconfirmed, and Junos rolls it back within ten minutes. What the op script sets up (its backend, access mode and port) and every prompt it may show are in `docs/install.md` at this commit.
