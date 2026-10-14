# dt_trust_checkpoints

`dt_trust_checkpoints` is a research-oriented Python prototype skeleton for an ETSI-aligned Digital Twin trust architecture. The long-term goal is to study how critical Digital Twin events can be detected, converted into verifiable evidence, selectively anchored to a blockchain, and later verified without anchoring every observation.

The prototype is being built incrementally. Step 1 created the package skeleton. Step 2 added the local proof-construction pipeline. Step 3 added a deterministic local trust-gate controller for async anchoring, synchronous checkpoints, and reject/block decisions. Step 4 added local verification and tampering/rollback detection. Step 5 added a reusable deterministic Digital Twin event simulator. Step 6 added experiment runners for comparing async and sync behavior across scenarios. Step 7 added publication-oriented figure and table generation from saved experiment outputs. Step 8 adds a publication bundle layer for collecting figures, tables, aggregate metrics, and cautious drafting notes into one auditable artifact pack.

## Architecture Idea

The prototype is organized around a trust checkpoint pipeline:

1. Digital Twin events are observed during a lifecycle state.
2. A critical event classifier decides whether an event requires a trust checkpoint.
3. Evidence is canonicalized, hashed, signed, and assembled into a proof envelope.
4. A checkpoint controller chooses synchronous or asynchronous anchoring.
5. Selected proof digests are anchored externally while full evidence remains off-chain.
6. A verifier reconstructs and checks the proof chain later.

The current codebase now implements local proof construction, local checkpoint decisions, a mock anchor registry, and a verifier for forensic checks over the generated artifacts.

## Project Structure

```text
dt_trust_checkpoints/
├── configs/
│   └── default.json
├── experiments/
│   └── .gitkeep
├── outputs/
│   └── .gitkeep
├── src/
│   └── dt_trust_checkpoints/
│       ├── cli.py
│       ├── config.py
│       ├── core/
│       ├── experiments/
│       ├── models/
│       ├── publication/
│       ├── reporting/
│       ├── simulation/
│       ├── storage/
│       └── verification/
├── tests/
├── pyproject.toml
└── requirements.txt
```

## Implemented In Step 1

- Python 3.11+ package using a `src/` layout.
- Core dataclass models:
  - `Event`
  - `ProofEnvelope`
  - `AnchorRecord`
  - `VerificationResult`
  - `PolicyDecision`
  - `TwinContext`
- Core enums:
  - `EventType`
  - `ProofType`
  - `CheckpointMode`
  - `VerificationStatus`
  - `LifecycleState`
- Lightweight JSON configuration loader.
- Minimal CLI commands:
  - `init-demo`
  - `run-simulation`
  - `verify`
- Placeholder modules for later implementation.
- Minimal unit tests for imports, enums, configuration, CLI behavior, and model instantiation.

## Implemented In Step 2

- Deterministic canonicalization for dictionaries, lists, dataclasses, enums, datetimes, paths, bytes, and primitive values.
- SHA-256 hashing over canonical UTF-8 JSON bytes.
- Local deterministic mock signatures for research experiments.
- Per-`twin_id` proof sequence tracking and previous-anchor linking.
- Local JSON proof storage under `outputs/evidence/<twin_id>/<proof_id>.json`.
- Evidence orchestration from `Event` plus optional `TwinContext` into a persisted `ProofEnvelope`.
- Demo proof generation command:

```bash
PYTHONPATH=src python -m dt_trust_checkpoints.cli build-demo-proofs --count 4
```

## Implemented In Step 3

- Policy-driven `CheckpointController` for local trust-gate decisions.
- Deterministic rules for DTD updates, DTS transitions, AF validated outputs, management actions, lifecycle events, and malformed events.
- `CheckpointMode.REJECT` for blocked events that should not be anchored.
- Local append-only mock anchor registry under `outputs/anchors/anchors.jsonl`.
- High-level `CheckpointProcessor` that runs:
  proof construction -> policy decision -> local anchor submission.
- Demo command:

```bash
PYTHONPATH=src python -m dt_trust_checkpoints.cli run-checkpoint-demo
```

## Implemented In Step 4

- Local `ProofVerifier` for proof envelopes and mock anchor records.
- Verification result categories for payload, signature, anchor, sequence, previous-anchor, order-index, missing-anchor, and policy-claim failures.
- Per-twin verification summaries with passed/failed counts and failure categories.
- Lightweight lifecycle/fidelity semantic check for synchronized lifecycle claims.
- Experimental tampering helpers for local attack simulations.
- Verification demo command:

```bash
PYTHONPATH=src python -m dt_trust_checkpoints.cli run-verification-demo
```

## Implemented In Step 5

- Reusable `EventSimulator` for deterministic synthetic Digital Twin event streams.
- Multi-twin generation with configurable event counts and random seed.
- Minimal per-twin simulation state:
  DTD version, lifecycle state, state version/label, fidelity score, management mode, and AF risk level.
- ETSI-aligned event families:
  DTD updates, DTS transitions, AF validated outputs, management actions, lifecycle claims, and benign sensor readings.
- Scenario presets:
  `nominal`, `high_risk`, `management_heavy`, `lifecycle_instability`, and `mixed`.
- Compact simulator summaries for checkpoint-relevant characteristics.
- Simulator demo command:

```bash
PYTHONPATH=src python -m dt_trust_checkpoints.cli run-event-simulator-demo --scenario mixed --twins 2 --events-per-twin 8 --seed 42
```

## Implemented In Step 6

- Reusable `ExperimentRunner` for local checkpoint comparison studies.
- Experimental modes:
  `policy-driven`, `forced-async`, and `forced-sync`.
- Scenario and mode sweeps across simulator presets.
- Optional verification after each run.
- Per-run artifacts:
  `summary.json`, `event_metrics.csv`, `proof_metrics.csv`, `anchors_metrics.csv`, and optional `verification_summary.json`.
- Aggregate CSV output for figure generation:
  `outputs/experiments/aggregate_results.csv`.
- Experiment CLI commands:

```bash
PYTHONPATH=src python -m dt_trust_checkpoints.cli run-experiments --scenario mixed --mode policy-driven --twins 2 --events-per-twin 20 --seed 42
PYTHONPATH=src python -m dt_trust_checkpoints.cli run-default-experiment-suite
```

## Implemented In Step 7

- Reporting package for generating figures and tables from saved experiment outputs.
- Matplotlib-backed PNG figure generation.
- Summary tables in CSV and Markdown.
- Robust artifact generation that skips unavailable optional figures instead of failing the whole run.
- Report CLI command:

```bash
PYTHONPATH=src python -m dt_trust_checkpoints.cli generate-report-artifacts --input-dir outputs/experiments --output-dir outputs
```

Figures are written under `outputs/figures/`:

- `figure_mode_latency.png`
- `figure_scenario_checkpoint_mix.png`
- `figure_storage_footprint.png`
- `figure_verification_detection.png` when verification failure data is available
- `figure_event_type_timing.png` when per-run event metrics are available
- `figure_scaling_trend.png` when experiment sizes vary

Tables are written under `outputs/tables/`:

- `table_mode_comparison.csv` and `.md`
- `table_scenario_comparison.csv` and `.md`
- `table_verification_failure_summary.csv` and `.md` when failure data is available

## Implemented In Step 8

- Publication bundle package for collecting existing experiment/report artifacts without rerunning experiments.
- Bundle manifest with source paths, destination paths, artifact type, descriptions, and missing optional components.
- Machine-readable `results_summary.json` derived from `aggregate_results.csv`.
- Concise Markdown outputs for paper drafting and slide preparation:
  - `report/mini_report.md`
  - `methodology_summary.md`
  - `paper_snippets.md`
  - `figure_captions.md`
  - `table_captions.md`
- CLI command:

```bash
PYTHONPATH=src python -m dt_trust_checkpoints.cli build-publication-bundle --input-dir outputs --output-dir outputs/publication_bundle --force
```

The bundle is written under `outputs/publication_bundle/` with subfolders for copied figures, copied tables, and report-oriented Markdown files. It is intended as a local prototype artifact pack for paper writing, slide preparation, and reviewer-response traceability; it is not a final publication workflow.

## Proof Construction Flow

For each event, the `EvidenceOrchestrator`:

1. Builds a proof-relevant evidence document from the event and optional twin context.
2. Canonicalizes that document to stable JSON.
3. Computes a SHA-256 payload hash.
4. Creates a deterministic local mock signature over the payload hash.
5. Assigns the next sequence number for the event's `twin_id`.
6. Links the proof to the previous local anchor digest for that `twin_id`.
7. Builds a `ProofEnvelope`.
8. Computes an anchor digest over stable proof anchor material.
9. Stores the proof envelope in the local off-chain JSON store.
10. Updates the local chain state with the new anchor digest.

## Local Prototype Limitations

- Signatures are mock deterministic hashes, not real cryptographic signatures or PKI.
- Evidence storage is a local JSON file store, not a tamper-resistant evidence backend.
- Anchor digests are submitted only to a local append-only JSONL mock registry, not a real blockchain.
- Verification is local and deterministic; it does not prove consensus finality or external timestamping.
- Lifecycle/fidelity semantics are intentionally minimal and should be expanded for real experiments.
- The event simulator is synthetic and scenario-driven. It is not a physics model or full industrial Digital Twin runtime.
- Experiment timing metrics are local prototype elapsed times measured with `time.perf_counter`; they should be used for relative comparisons, not deployment-grade latency claims.
- Reporting figures are generated from local prototype experiment outputs and are intended for paper drafting and slides, not as final empirical claims without validation.

## Simulator Semantics

The simulator is designed for controlled checkpoint experiments rather than physical realism:

- DTD update events increment a per-twin DTD version.
- DTS transition events update a per-twin state label/version and may be critical.
- AF validated outputs include confidence, score, criticality, fidelity, and risk-level metadata.
- Management actions may be sensitive or benign.
- Lifecycle events emit synchronized or out-of-sync claims influenced by fidelity and scenario settings.
- Fidelity drifts over time according to the scenario preset.

## Verification Checks

The verifier currently checks:

- proof file existence;
- expected anchor record existence;
- canonical payload hash recomputation;
- deterministic mock signature metadata and value;
- anchor digest recomputation from proof anchor material;
- proof/anchor `twin_id`, `proof_id`, sequence, payload hash, previous anchor, and off-chain reference consistency;
- monotonic per-twin proof sequence;
- previous-anchor linkage across each twin chain;
- local anchor registry order-index consistency;
- synchronized lifecycle claims with insufficient fidelity evidence.

The local tampering helpers can simulate:

- payload tampering;
- previous-anchor tampering;
- sequence rollback/inconsistency;
- fake synchronized lifecycle claims;
- missing or altered local anchor records.

## Checkpoint Decision Modes

- `async`: the proof is allowed and a local anchor record is submitted immediately while marked as asynchronous. A later implementation can replace this with a queue or scheduler.
- `sync`: the proof is allowed and a local anchor record is submitted before the processing result is returned, modeling a synchronous trust checkpoint.
- `reject`: the event/proof pair is blocked by policy. The proof artifact may exist locally for auditability, but no anchor record is submitted.

## Experiment Metrics

Each experiment records:

- processing counts:
  total events, processed events, anchored events, rejected events, async count, sync count, and per-event-type counts;
- local timing:
  total, average, p50, p95, and p99 event processing time, plus averages by event type and checkpoint mode;
- storage footprint:
  proof JSON bytes, mock anchor bytes, averages, and off-chain/on-chain ratio;
- policy characteristics:
  async/sync/reject ratios, critical events, sensitive management actions, synchronized claims, and out-of-sync claims;
- verification totals when enabled:
  proofs checked, passed/failed counts, and failure categories.

## Running Locally

Install the package in editable mode:

```bash
python -m pip install -e .
```

Then run:

```bash
python -m dt_trust_checkpoints.cli --help
dt-trust-checkpoints --help
```

Without installation, use:

```bash
PYTHONPATH=src python -m dt_trust_checkpoints.cli --help
```

Run tests with:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Figure generation requires the package dependencies, including `matplotlib`. A standard editable install is enough:

```bash
python -m pip install -e .
python -m dt_trust_checkpoints.cli generate-report-artifacts
python -m dt_trust_checkpoints.cli build-publication-bundle --force
```

## TODO

- Refine critical event classification policies.
- Refine canonical evidence schemas for ETSI-aligned experiments.
- Replace mock signatures with a real signing abstraction when needed.
- Add real async scheduling if experiments need delayed/batched anchoring.
- Add stronger storage adapters for off-chain evidence.
- Replace the local mock anchor registry with a real blockchain adapter when appropriate.
- Add real verifier support for external chain proofs and stronger signatures.
- Expand lifecycle and policy semantics for larger experiments.
- Add richer paper-specific plotting presets once the final experiment matrix is fixed.
- Add optional paper-template exporters only after the artifact bundle format stabilizes.

## Event-level study (2026-10-07)

`src/dt_trust_checkpoints/overlay/` implements the evidence overlay as the article
defines it: Ed25519 signatures over the whole proof object (link and salt included),
a local time-stamping service, an RFC 9162 Merkle log whose tree heads 3 of 4
consortium member processes co-sign after a consistency check, and a verifier with
the article's six checks. The original mock pipeline is unchanged.

```bash
PYTHONPATH=src .venv/bin/python -m dt_trust_checkpoints.cli run-event-level-study      # ~2 min, outputs/event_level
PYTHONPATH=src .venv/bin/python -m dt_trust_checkpoints.cli summarize-event-level-study # tables + paper_numbers.json from raw CSVs
PYTHONPATH=src .venv/bin/python -m dt_trust_checkpoints.cli plot-event-level-study      # CCDF figures
```

5 scenarios x 3 modes x 1,000 events (2 twins). Every number quoted in the article's
Prototype Illustration comes from `outputs/event_level/paper_numbers.json`, and
Table II from `table_per_category.tex`. Times are local (one machine): no network
transfer, no consensus.
