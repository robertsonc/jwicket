"""jwicket_install: J-Wicket's lab-gated installer tooling (Spec 006). Never shipped inside dist/jwicket.py.

Every installer is LAB-GATED until G1 (owner decision, 2026-11-24): dry run by default, the plan's
diff and the posture warning shown first, every write a ``commit confirmed`` with a health check
before it is confirmed, and nothing written until the operator types the host name of the lab device
(and, with ``--lab-hardware``, 'lab only'). No installer step has run on a device yet: every installer
step is unverified until lab test Q-INST-06. J-Wicket itself ran once on a lab SRX4100 by the manual
procedure (docs/evidence/2026-11-24-srx4100-lab), which verified some of the facts the plan uses.

Every module of this package must import on Python 3.7, the floor of Junos 25.2R1-S1.4 (Python 3.7.10,
verified on that SRX4100); the CI test job runs the unit tests there, and a test parses each module with
``feature_version=(3, 7)``. The workstation installer's own floor is higher once PyEZ is involved:
the pinned junos-eznc 2.8.3 declares ``Requires-Python: >=3.8`` (its wheel's METADATA).

Modules (the shared plan, stdlib only, no I/O, no ``jnpr`` import, Python 3.7-compatible, because the
on-box op script embeds them):

* :mod:`jwicket_install.plan`: constants, warning texts, statement set S1..S14, stages, checks,
  refusals, the bootstrap, ownership, the uninstall inverse, the receipt, ``render_settings``,
  ``lab_gate_matches``, the structural and header checks, ``check_invariants``. All Junos statement
  and command text lives there.
* :mod:`jwicket_install.state`: device replies (XML text) to ``DeviceFacts`` and ``PriorState`` with
  explicit parse rules, a 4 MB cap and secret stripping.
* :mod:`jwicket_install.render`: paste units (M6), bootstrap units, set and ``.set`` files, the plan
  diff in patch form, token-only plan JSON, the op-script payload, the SSH tunnel line (--access tunnel)
  and the URL and certificate fingerprint to open (--access tls).

``render`` and ``state`` import ``plan`` relatively (``from . import plan``): an embedder (the on-box
op script) must keep the three as modules of one package.
"""

__version__ = "0.1.0.dev1"
