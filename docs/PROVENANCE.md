# Package provenance

Prepared on 14 October 2026 for the manuscript revision.

## Existing material

- Source, configuration, tests, and development notes were recovered from the
  local `etsiEvidence` project.
- Reference data came from the manuscript workspace's `event_level/` folder.
- All 152 reference-data files were compared by SHA-256 against the recovered
  project's `outputs/event_level/`: every file was identical.
- The independent cryptographic audit originated in
  `verification_revision/audit_preuves.py` in the manuscript workspace.

## Packaging additions

- Kept the prototype source and existing tests unchanged.
- Added the required `numpy` and `cryptography` dependencies alongside
  `matplotlib` in the package metadata and requirements.
- Added an English README, reproduction instructions, and this provenance note.
- Adapted the independent audit's input/output paths to the repository layout,
  and made cryptographic failures produce a nonzero exit status.
- Extracted a six-object example from the saved nominal policy-driven run,
  preserving original records, proof objects, receipts, and signed checkpoints.
- Added a script that loads and verifies the frozen example with the prototype
  verifier, and an independent script that recalculates the paper statistics.

`scripts/SHA256SUMS` records the hashes of the retained reference data, copied
source, tests, configuration, and frozen example. To check them on Linux, run
`sha256sum -c scripts/SHA256SUMS` from the repository root.

No performance result was regenerated during extraction of the example. Any
functional smoke-run results are reported separately in `checks/` and in the
local preparation note accompanying this folder.
