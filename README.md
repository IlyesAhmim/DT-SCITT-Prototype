# DT evidence checkpoint prototype

Code and saved experimental artifacts accompanying **Verifiable Evidence for
Digital Twin Behavior Across Organizations: An Overlay on the ETSI TS 103 846
Architecture**.

This repository contains the local Python prototype, synthetic event simulator,
fault-injection campaign, reference data, and a small executable example vector.
The event-level implementation used for the paper is in
`src/dt_trust_checkpoints/overlay/`. It uses Ed25519 signatures, a local
time-stamping service, and a Merkle log with locally co-signing witness processes.

The proposed DT evidence semantics can be profiled over
[SCITT (RFC 9943)](https://www.rfc-editor.org/rfc/rfc9943.html). This prototype uses
its own JSON objects and local receipts; SCITT COSE message interoperability,
JCS encoding, DTD content digests, and independently authenticated fresh per-DT
heads are proposed extensions, rather than implemented claims.

## Contents

| Path | Purpose |
| --- | --- |
| `src/dt_trust_checkpoints/overlay/` | Event-level proof production, policy, checkpoints, Merkle registry, witnesses, verification, and fault injection |
| `src/dt_trust_checkpoints/simulation/` | Synthetic DT event generator used by the workload builder |
| `configs/default.json` | Application and checkpoint policy configuration |
| `tests/` | Existing automated tests, including signatures, Merkle proofs, clean runs, faults, and pending-tail rewrites |
| `examples/prototype-test-vector.json` | Six saved objects under a witnessed checkpoint, including a DTD update followed by a validated AF output |
| `scripts/verify_example.py` | Verifies the vector using the prototype verifier and checks a modified-record negative case |
| `scripts/check_paper_numbers.py` | Recalculates paper counts, category statistics, fault counts, and pending-tail counts from the CSV files |
| `scripts/verify_saved_artifacts.py` | Independent cryptographic checks of all saved runs |
| `data/event_level/` | Unmodified reference data for all 15 runs, summaries, receipts, public trust data, and figures |
| `docs/REPRODUCIBILITY.md` | Reproduction commands, timing definitions, and limits |
| `docs/PROVENANCE.md` | Source provenance and packaging changes |
| `docs/original-development-notes.md` | Original development README, retained for historical context |

The older `core/`, `storage/`, and `verification/` pipeline includes deterministic
mock signatures. Use the `overlay/` implementation and the **event-level** CLI
commands below for the experiment discussed in the article.

## Installation

Requires Python 3.11 or later. From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

On Windows, activate with `.venv\Scripts\activate`.
The package declares `cryptography`, `numpy`, and `matplotlib` as dependencies.

## Quick verification

```bash
python scripts/verify_example.py
python scripts/check_paper_numbers.py
python scripts/verify_saved_artifacts.py
python -m unittest discover -s tests -v
```

The first command verifies the small frozen vector and confirms detection of a
source-record modification. The next two validate the saved data, without
rerunning event generation or making new performance measurements. Verification
reports are written to `checks/`, which is excluded from Git.

The saved data contain 5,000 input events per mode, 4,421 ordinary proof objects
per mode, 111 rejection records across the three modes, 13,374 anchored objects
in total, and 2,200 reported fault cases. The 179 pending objects in the
tail-rewrite experiment describe the state before the final flush.

## Run the simulator and fault campaign

The CLI runs the synthetic workload, proof production, witness processes,
verification, and the fault campaign together. New outputs go to a separate
directory from the reference data:

```bash
python -m dt_trust_checkpoints.cli run-event-level-study \
  --output-dir outputs/reproduced_event_level \
  --twins 2 --events-per-twin 500 --seed 42 \
  --members 4 --quorum 3 --faults-per-cell 10

python -m dt_trust_checkpoints.cli summarize-event-level-study \
  --input-dir outputs/reproduced_event_level

python -m dt_trust_checkpoints.cli plot-event-level-study \
  --input-dir outputs/reproduced_event_level
```

The defaults select all five scenarios and all three modes; the fault seed is 7
in `overlay/study.py`. The command refuses to overwrite a nonempty output
directory unless `--force` is supplied. See `docs/REPRODUCIBILITY.md` for a small
smoke run and the precise scope of the saved results.

## Interpretation

The study uses synthetic events and local processes on one machine. It does not
measure network transfer, deployed consensus, or independently acquired history
freshness. The local time-stamp token binds the **source-record digest**, and is
included in the signed proof object. It does not date the complete signed
envelope proposed in the revised evidence profile. The vector documents this
implemented format and is not an ETSI or SCITT conformance vector.

The original data and timing environment are preserved in
`data/event_level/study_config.json`. Fresh keys, salts, times, process scheduling,
and hardware mean new runs will not produce byte-identical proofs or identical
latency measurements.
