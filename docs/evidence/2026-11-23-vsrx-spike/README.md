# Evidence: vSRX spike, 23–24 November 2026

This directory is the spike packet **as delivered**, unedited, so later readers can check every
claim in the charter against the original record. Do not edit these files; correct them by adding
a dated note to `docs/charter.md` instead.

| File | What it is |
| --- | --- |
| `PACKET-README.md` | The packet's own README: run steps, endpoints, known limits |
| `docs/J-Wicket-spike-report-and-product-plan.md` | Spike report: results, findings, limits, the original scope and roadmap |
| `docs/Wicket-concept-brief-and-spike-plan.md` | Concept brief and lab notebook, with each test as it ran |
| `wicket_spike.py` | The spike daemon and embedded UI (superseded by `src/jwicket`; kept as evidence) |
| `junos/baseline.set`, `junos/zone-access.set`, `junos/wicket.args.example` | The Junos lines the spike verified |
| `images/` | Roadmap and architecture diagrams; `ui-preview-mock-data.png` is rendered against stand-in data and is **not** a device screenshot |

Lab: Juniper vLabs sandbox, one vSRX, Junos 24.4R2-S3.5, veriexec enforcing. The lab token used
during the spike crossed the internet in clear text and is treated as burned.

Where the product deliberately departs from the spike (for example: no plaintext listener off
loopback, no shared token off loopback, no "sample data" fallback, no `--flag` arguments), the
reason is recorded in `docs/architecture.md` and the ADRs under `docs/adr/`.
