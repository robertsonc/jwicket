# A disposable lab vSRX with containerlab (M8)

> **LAB ONLY.** This topology starts one throwaway vSRX on a Linux host, for installing, testing and
> removing J-Wicket pre-releases. Its default credentials are public (below): never run it where
> anyone but you can reach its management address. **Nothing here has been deployed** (the
> environment it was written in had no containerlab, KVM or vSRX image), and **no J-Wicket installer
> step has run on a device: every device step is unverified until lab test Q-INST-06.**

[Spec 006](../../docs/specs/006-installation.md) section 6.9 is the design. The topology,
`jwicket-lab.clab.yml`, has one `juniper_vsrx` node and nothing else: no `startup-config`, no
`exec`, no `binds`. The node boots with vrnetlab's own base configuration, and J-Wicket goes on it
only through an installer (M1, M2 or M3), so that nothing committed at boot can bypass the lab gate,
the plan's diff or `commit confirmed`. `tests/test_lab_contract.py` keeps it that way.

## What you need

| Need | Source |
| --- | --- |
| A Linux host with KVM; on a VM, nested virtualization turned on | containerlab, [vrnetlab page][clab-vrnetlab]: "Ensure that the VM that containerlab runs on has Nested virtualization enabled" (**verified**) |
| Docker and containerlab 0.41.0 or later (the release that added the `juniper_vsrx` kind) | [clab-vrnetlab] compatibility table (**verified**) |
| A vSRX 3.0 `.qcow2` image (a Juniper account is required to download the evaluation image), 2 cores and 4 GB of RAM for the VM | [vrnetlab vSRX README][vrnetlab-readme] (**verified**) |
| The srl-labs fork of vrnetlab, not upstream vrnetlab | [clab-vrnetlab]: "You will not be able to build a compatible container with the upstream vrnetlab project" (**verified**) |

## 1. Build the vSRX image

vrnetlab packages the qcow2 into a container image that runs the VM under QEMU. The commands below
pin vrnetlab to the commit that was read for this guide (`master` on 2026-11-24); review it before
you run its `make`, which runs `docker build` with vrnetlab's own Dockerfile.

```sh
git clone https://github.com/srl-labs/vrnetlab.git
cd vrnetlab
git checkout --detach 5af59cf917659e3a1b905ea3ffb404c000f83683
cd juniper/vsrx
cp ~/Downloads/junos-vsrx3-x86-64-24.4R2-S3.5.qcow2 .
make
docker image ls vrnetlab/juniper_vsrx
```

- The image tag comes from the file name: vrnetlab's `juniper/vsrx/Makefile` at that commit strips
  `junos-vsrx3-x86-64-` and `.qcow2` from it (**verified**, source), so the file above becomes
  `vrnetlab/juniper_vsrx:24.4R2-S3.5`. Its README says "Tested with versions: `22.3R1.11`,
  `21.3R1.9`"; 24.4 is **not** among them.
- vrnetlab's `juniper/vsrx/docker/Dockerfile` starts `FROM ghcr.io/srl-labs/vrnetlab-base:0.3.0`, a
  tag, not a digest. On 2026-11-24 that tag's manifest digest was
  `sha256:57f36ae1cf44a78a6b2cad35a6276565c56edfd28e8160ae9a772929db28fd6d` (read from ghcr.io, body
  hash equal to `Docker-Content-Digest`). To pin it, change that line in your checkout to
  `FROM ghcr.io/srl-labs/vrnetlab-base:0.3.0@sha256:57f36ae1cf44a78a6b2cad35a6276565c56edfd28e8160ae9a772929db28fd6d`
  before `make`.

## 2. Start and stop it

From the J-Wicket repository root:

```sh
make lab-up VSRX_IMAGE=vrnetlab/juniper_vsrx:24.4R2-S3.5
docker logs -f clab-jwicket-lab-vsrx1     # about 7 minutes until the VM has booted
make lab-down
```

- `make lab-up` passes the image to the topology as `JWICKET_VSRX_IMAGE`; the topology falls back to
  `vrnetlab/juniper_vsrx:24.4R2-S3.5` when it is unset (containerlab expands `${VAR:=default}` as
  bash does, [topology file][clab-topo], **verified**).
- `image-pull-policy: Never`: containerlab stops with an error instead of pulling an image of that
  name from a registry ([nodes][clab-nodes], **verified**: "Do not at all try to pull the image from
  a registry"). The only vSRX image this lab runs is the one you built.
- Containerlab names the container `clab-jwicket-lab-vsrx1` (`clab-${lab-name}-${node-name}`), puts
  it on the Docker network `clab` (172.20.20.0/24 by default) and adds the name to the host's
  `/etc/hosts` ([topology file][clab-topo], [network][clab-network], **verified**).
- vrnetlab re-renders the base configuration on every start of the container and attaches it to the
  VM as a configuration disk (**verified**, `launch.py` at the pinned commit). Whether the vSRX
  applies it again when the container restarts, undoing what was committed since, is **unknown**:
  after any restart, run `jwicket-install status` before you trust what you see.
- Containerlab keeps the lab's working files in a `clab-jwicket/` directory next to the topology
  (**inferred** from the `__clabDir__` examples on the [topology file][clab-topo] page). It is
  generated; never commit it.
- `make lab-down` destroys the VM. The next `make lab-up` is a new box with a new SSH host key
  (**inferred**); remove the old key first:
  `ssh-keygen -R clab-jwicket-lab-vsrx1` ([ssh-keygen(1)][ssh-keygen]: "Removes all keys belonging to
  the specified hostname").

## 3. Lab-only default credentials

vrnetlab's base configuration (`juniper/vsrx/docker/init.conf` at the pinned commit, **verified**)
sets:

- a `super-user` account `admin`, and the **same password for root** (`root-authentication`);
- `system services ssh root-login allow`, so **root can log in over SSH with that password**;
- `system services netconf ssh`, `host-name` and `system management-instance`.

The password containerlab gives it is **`admin@123`**, published in the containerlab documentation
([vSRX kind][clab-vsrx]: "Default user credentials: admin:admin@123", **verified**). Treat the box
as reachable by anyone who can reach 172.20.20.0/24:

- keep that network on this host only: add no `ports:` to the topology, do not route the subnet from
  other machines, and do not run the lab on a shared host;
- after the first boot, change both passwords by hand on the device, and consider
  `set system services ssh root-login deny` (the `root-login` values `allow`, `deny` and
  `deny-password` are in the SRX configuration schema, junos-es 23.2R1, **verified**; **inferred**
  for 24.4). The J-Wicket installers never touch `system login` or root authentication
  (Spec 006 section 4); account changes are yours;
- destroy the lab when you are done (`make lab-down`).

## 4. Install J-Wicket on it

The installer refuses root (R-ROOT); `admin` is a super-user-class account, so it can install and
becomes the account the daemon runs as (Spec 006 section 7.5). NETCONF is already on, so no
bootstrap is needed. Two things come first.

**The state directory, once, as root (R-STATEDIR).** J-Wicket keeps its settings in
`/var/db/jwicket`, and a super-user-class account cannot create it: on a lab SRX4100 running
25.2R1-S1.4, `mkdir` and `file make-directory` were both refused (`Permission denied`), and root made
it and gave it to the account (**verified**, [lab evidence][srx4100]; on this vSRX **unverified**).
The installer never creates it, never logs in as root and never asks for the root password: until the
directory is there, its dry run reports R-STATEDIR and `--apply` writes nothing. On this lab, root may
log in over SSH with the lab's public password (`root-login allow`, section 3); that root's login
opens a shell rather than the Junos CLI is **inferred**. In root's shell on the vSRX:

```
mkdir -m 700 /var/db/jwicket && chown admin /var/db/jwicket
```

That is the step the installer prints for `--user admin` (`plan.STATE_DIR_ROOT_STEP`). Then, if you
follow section 3's advice, set `root-login deny`.

**The access mode.** `--host clab-jwicket-lab-vsrx1` is a name, so the default `--access tls` needs
`--listen-address`: the address J-Wicket binds, which is fxp0's. On this lab that address is very
likely not one the host can reach (**inferred**): vrnetlab's vSRX launcher passes
`mgmt_passthrough=False` (`launch.py` at the pinned commit, **verified**), and in that mode the
guest's management address is a fixed `10.0.0.15` behind the launcher container, which the host
reaches only on the ports vrnetlab forwards ([clab-vrnetlab], **verified** for vrnetlab in general; its
example is not a vSRX). The image exposes 22 and 830 (its Dockerfile, **verified**); whether it
forwards 9443 is not researched. Even then, the browser's `Host` header and the certificate would name
the container's address, not the one J-Wicket listens on, and J-Wicket answers a foreign `Host` with
421 (**verified** on the SRX4100). The installer's HTTPS check C8 would fail, and Junos would roll the
runtime stage back by itself. So this guide uses `--access tunnel`: J-Wicket on the vSRX's
`127.0.0.1`, reached through `ssh -L`. Whether this vSRX allows SSH forwarding is **unknown**; the
SRX4100 refused it (`administratively prohibited`, [lab evidence][srx4100]). containerlab documents a
Transparent Management mode (`CLAB_MGMT_PASSTHROUGH: "true"`, which gives the guest the address
containerlab assigns, [clab-vrnetlab], **verified** as documented); whether this vSRX image honours it
is **unknown**, and this topology does not set it.

vrnetlab's base configuration gives `admin` a password and no SSH key (`init.conf` at the pinned
commit, **verified**), and the installer uses a password only when you pass `--password-prompt`
(it then asks with `getpass`; it never takes one on the command line). So either add
`--password-prompt`:

```sh
ssh admin@clab-jwicket-lab-vsrx1          # once: records the host key in ~/.ssh/known_hosts
jwicket-install install --release v0.1.0.dev1 --host clab-jwicket-lab-vsrx1 --user admin --access tunnel --password-prompt
jwicket-install install --apply --release v0.1.0.dev1 --host clab-jwicket-lab-vsrx1 --user admin --access tunnel --password-prompt
```

or give `admin` your public key first, which M2 (Ansible, keys only; `jwicket_access=tunnel` in its
inventory) needs. In a CLI session on the lab device (**unverified** on a device; the `ssh-ed25519`
list of `system login user <name> authentication` is in the SRX configuration schema, junos-es
23.2R1, **verified**):

```
configure exclusive
set system login user admin authentication ssh-ed25519 "<your public key line>"
commit confirmed 5 comment "lab key for admin"
```

then, from a second terminal, check that `ssh admin@clab-jwicket-lab-vsrx1` signs in with the key,
and only then `commit comment "lab key for admin confirmed"` and `exit`. The J-Wicket installers
themselves never touch `system login`.

- NETCONF goes over the SSH port by default; `--netconf-port 830` is the fallback
  (Spec 006 section 6.2). vrnetlab's image exposes 22 and 830 (its Dockerfile, **verified**); that
  both reach the VM is **inferred**.
- How to read the vSRX's SSH host-key fingerprint on the Junos CLI, to compare with the one `ssh`
  shows, is **unknown** (Q-INST-05). On a host-only lab network the first-use risk is small, but it
  is still trust on first use.
- The gate asks for the host name of the lab device you intend to change. You named this node
  `lab-vsrx1`; that vrnetlab's `host-name` is that node name is **inferred** (vrnetlab takes it from
  its `--hostname` argument). If the gate does not match, read the name on the device's own
  `show version`, never from the installer.
- From the M3 container, add `--network clab` to `docker run` (see
  [../container/README.md](../container/README.md)).
- `containerlab exec` and `docker exec` run in the launcher container, not in the vSRX
  ([clab-vrnetlab], **verified**), so they cannot place files on the box: the installers copy them
  over SSH.

## 5. The management-instance caveat

The base configuration sets `system management-instance`, which moves `fxp0` and its default route
into the `mgmt_junos` routing instance (**verified**, `init.conf`). The lab SRX4100 had it too, and its
run settled what that means for J-Wicket there ([lab evidence][srx4100], **verified** on that box,
**unverified** on this vSRX, Q-INST-05):

- fxp0's address cannot be bound from the default instance, so with `--access tls` the installer
  writes `routing_instance = mgmt_junos` in `jwicket.ini` whenever the configuration has
  `system management-instance`; J-Wicket then creates only its listener in that instance;
- the J-Wicket daemon's own NETCONF session to `127.0.0.1:830` (the `netconf` backend) worked from the
  default instance; inside `mgmt_junos` it timed out, which is why only the listener moves;
- the extension-service statement `routing-instance mgmt_junos` did not move the listener, so the
  installer never writes it.

No installer check opens an SSH forwarding (`direct-tcpip`) channel: check C9, which read the
`SSH-2.0` banner from `127.0.0.1:830` through one, is retired, and the `netconf` backend's readiness rests on the probe's
module check (C3), "not checked end to end". Check C8 is an HTTPS read of `/api/session` from the
workstation with `--access tls`, and "not available" with `--access tunnel`. Sign in once through the
tunnel to prove the backend. If something fails here, record it against Q-INST-05 rather than
changing the box's routing instances to make it pass.

[clab-vsrx]: https://containerlab.dev/manual/kinds/vr-vsrx/
[clab-vrnetlab]: https://containerlab.dev/manual/vrnetlab/
[clab-topo]: https://containerlab.dev/manual/topo-def-file/
[clab-nodes]: https://containerlab.dev/manual/nodes/
[clab-network]: https://containerlab.dev/manual/network/
[vrnetlab-readme]: https://github.com/srl-labs/vrnetlab/blob/5af59cf917659e3a1b905ea3ffb404c000f83683/juniper/vsrx/README.md
[ssh-keygen]: https://man.openbsd.org/ssh-keygen.1
[srx4100]: ../../docs/evidence/2026-11-24-srx4100-lab/README.md
