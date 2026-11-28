# J-Wicket dev4 quickstart: fresh lab vSRX

Install the read-only lab prerelease on a **fresh, standalone vSRX** over private management. This is not an upgrade or a production procedure. For a physical SRX, an existing deployment, a managed target, or a different access profile, use the [full dev4 guide](https://github.com/robertsonc/jwicket/blob/v0.1.0.dev4/docs/install.md).

Before starting, have a verified management SSH host key, root shell access, a named non-root Junos `super-user` account for the installer, and a restricted Junos account for browser verification. The workstation needs an up-to-date GitHub CLI (`gh` 2.93.0 or newer) and Python 3.9.2–3.13, the range covered by the dev4 dependency lock. Replace `LAB_USER` and `MGMT_IP` below; use the device's private management IPv4 address, not a public forwarding address.

## 1. SSH to the vSRX and prepare its state directory

On the workstation:

```sh
ssh LAB_USER@MGMT_IP
```

If you need to accept a new host key, compare its fingerprint against a trusted source first. At the Junos operational prompt (`>`), enter `start shell user root`. If you are already in a root shell, skip that command. Confirm `id -u` prints `0`, then run on the vSRX:

```sh
mkdir -m 700 /var/db/jwicket && chown LAB_USER /var/db/jwicket
```

If the directory already exists, stop and check the target. For an otherwise fresh target, continue only if it is a real directory, not a symlink, with mode `0700` and the installer account as owner. Do not change ownership under an existing deployment. Exit the shell and return to the workstation.

## 2. Download and verify the workstation installer

Run `gh --version` before continuing. If it is older than 2.93.0, update it before verifying assets. See [GitHub's token-handling advisory](https://github.com/cli/cli/security/advisories/GHSA-8xvp-7hj6-mcj9).

In a new empty **workstation** directory:

```sh
repo=robertsonc/jwicket
tag=v0.1.0.dev4
wheel=jwicket_install-0.1.0.dev4-py3-none-any.whl

gh release download "$tag" -R "$repo" -p "$wheel" -p requirements-install.txt &&
gh release verify-asset "$tag" "$wheel" -R "$repo" &&
gh release verify-asset "$tag" requirements-install.txt -R "$repo" &&
python3 -m venv .venv &&
.venv/bin/python -m pip install --require-hashes -r requirements-install.txt &&
.venv/bin/python -m pip install --no-deps "./$wheel"
```

Stop if any command fails. Check `.venv/bin/jwicket-install --version` reports `0.1.0.dev4`.

## 3. Preview with the named Junos account

**You do not need a personal SSH key.** The command below uses your named Junos account's password. The SRX's SSH **host key** is separate: it verifies the device's identity, and the installer checks it whether you sign in with a password or a key.

```sh
.venv/bin/jwicket-install install --release v0.1.0.dev4 \
  --host MGMT_IP --user LAB_USER --password-prompt \
  --access tls --listen-address MGMT_IP
```

Enter the named account's password at the terminal prompt. For key authentication, replace `--password-prompt` with `--identity-file /path/to/key` or use an accepted SSH agent key. Root is only for step 1; M1 rejects `--user root`.

Read the whole preview, especially the management address, the listener port, and any refusal. If NETCONF is disabled and the installer prints bootstrap units, follow the [NETCONF bootstrap instructions](https://github.com/robertsonc/jwicket/blob/v0.1.0.dev4/docs/install.md#netconf-off-the-bootstrap-units) and use the exact command with the nonce that the installer supplies. Do not manually confirm its temporary bootstrap commit. An authentication or host-key error is not a reason to bootstrap or weaken checks.

## 4. Apply and verify

Before applying, verify the management ingress filter permits TCP 9443 only from designated jump hosts or operator source prefixes. If you cannot enforce and test that filter, do not enable the non-loopback listener. See the [dev4 management filter requirement](https://github.com/robertsonc/jwicket/blob/v0.1.0.dev4/docs/install.md#L79-L86).

If the preview has no blocking refusal, repeat the command with `--apply` and type the device's hostname when prompted. If you followed the bootstrap path, use its generated apply command instead.

Once the listener starts, verify that an allowed management source can connect to TCP 9443 and that a denied source cannot. From the allowed source, open `https://MGMT_IP:9443/`. Compare the presented certificate's SHA-256 fingerprint with the fingerprint printed by the installer **before** entering credentials. Sign in with a restricted operator account, verify an allowed read and a denied read, and sign out. Do not expose the listener publicly.

If you need to remove the install, start with the [uninstall preview](https://github.com/robertsonc/jwicket/blob/v0.1.0.dev4/docs/install.md#uninstall); verify the removal restores your baseline.
