# J-Wicket packet

A proof of concept: a read-only web UI that runs on a Juniper SRX itself, as an unsigned
Python app supervised by Junos. Built and tested on 23 November 2026 (24 November UTC) on a
vLabs vSRX running Junos 24.4R2-S3.5.

This is a spike, not a product. It has no real authentication and has never run on SRX
hardware. Do not install it on a firewall that carries traffic you care about.

## What is in here

| Path | What it is |
| --- | --- |
| `wicket_spike.py` | The daemon and the embedded single-page UI. Standard library plus on-box PyEZ. |
| `docs/J-Wicket-spike-report-and-product-plan.md` | The write-up: results, findings, limits, scope and roadmap. |
| `docs/Wicket-concept-brief-and-spike-plan.md` | The concept brief and lab notebook, with every test as it ran. |
| `junos/baseline.set` | The four config lines that run the daemon. |
| `junos/zone-access.set` | The one line that admits it through a security zone on TCP 8443. |
| `junos/wicket.args.example` | Example options file for `/var/tmp/wicket.args`. |
| `images/roadmap.png` | Roadmap diagram from the report. |
| `images/spike-architecture.png` | Architecture diagram from the concept brief. |
| `images/ui-preview-mock-data.png` | UI preview rendered against stand-in data. Not a screenshot of a real device. |

The markdown files are copies made when this packet was built. The live documents are linked at
the top of each one.

## Run it on a vSRX

1. Copy the script to the device. macOS needs `-O` because SFTP is off by default on Junos:

   ```
   scp -O wicket_spike.py <user>@<device>:/var/db/scripts/jet/wicket_spike.py
   ```

   The file must be owned by a user in the super-user class, with write permission for the
   owner only (mode 644).

2. From the Junos shell, create a token and the options file:

   ```
   openssl rand -hex 24 > /var/tmp/wicket_token
   chmod 600 /var/tmp/wicket_token
   echo "--bind 0.0.0.0 --port 8443 --allow-plaintext --token-file /var/tmp/wicket_token --log-file /var/tmp/wicket-spike.log" > /var/tmp/wicket.args
   ```

   Junos cannot pass `--flag` options to a JET app, which is why they live in a file.
   `--allow-plaintext` is for a lab only. For anything else, supply `--cert` and `--key`.

3. Load `junos/baseline.set` (replace `<user>`), then `commit confirmed 5` and `commit`.

4. Check it started: `file show /var/tmp/wicket-spike.log` should end with `listening on 0.0.0.0:8443`.

5. If you reach it through a revenue interface, load `junos/zone-access.set` for that zone.

6. Open `http://<device>:8443/` and paste the token.

To debug a start failure, remove the `daemonize` statement, commit, and run
`request extension-service start wicket_spike.py`. Errors print to the terminal.

## Endpoints

| Path | Auth | Purpose |
| --- | --- | --- |
| `/` | none | The UI. It asks for the token. |
| `/healthz` | none | Liveness check. |
| `/api/version` | bearer token | Hostname, model and Junos version from local mgd. |
| `/api/dashboard` | bearer token | Read-only device state for the UI. |

## Known limits

- One shared token, and every request runs with the rights of the configured `username`.
- TLS is supported by the script but was never exercised on a device.
- Tested on one Junos release, on a virtual SRX only.
- UI panels fall back to rows tagged "sample data" when they cannot read their source.
- Not tested: load, reboot, Junos upgrade, chassis cluster.
