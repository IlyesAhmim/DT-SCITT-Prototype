# Reproducing the local study

## Reference configuration

The saved dataset was generated on 7 October 2026. Its recorded environment is
Python 3.14.4, cryptography 50.0.2, and an Intel Core i9-13950HX on Linux. The
recorded environment is descriptive; the package supports Python 3.11 or later.

`data/event_level/study_config.json` records the study settings:

- Five scenarios: nominal, mixed, management-heavy, life-cycle instability, and high-risk.
- Three modes: policy-driven, forced-sync, and forced-async.
- Two twins with 500 input events each in each scenario.
- Workload seed 42 and fault seed 7.
- Four local witnesses, with a quorum of three.
- Asynchronous batching threshold of 64 commitments and maximum age of 300 input events.
- Ten fault cases per eligible fault/category cell; some combinations are inapplicable.
- Key rotation defaults to halfway through each twin's event stream.

The simulator is in `simulation/event_simulator.py`; its study-specific workload
builder is `overlay/workload.py`. The study runner and summary calculations are
in `overlay/study.py`. `overlay/faults.py` implements the nine fault classes and
the separate pre-flush pending-tail rewrite experiment.

## Small run

After installation, run from the repository root:

```bash
python -m dt_trust_checkpoints.cli run-event-level-study \
  --output-dir outputs/smoke_event_level \
  --scenarios nominal --modes policy-driven forced-sync forced-async \
  --twins 2 --events-per-twin 30 --seed 42 \
  --members 4 --quorum 3 --faults-per-cell 2
```

This exercises actual local witness processes and fault injection. It is a
functional check with fewer events, not the population used in the paper.

## Full study

Use the full command in the README. It processes 15,000 input events over 15
runs and performs faults on the five policy-driven runs. Rerun summary and
plotting commands against the generated output directory.

The original data remain in `data/event_level/`. The CSV files and JSON Lines
proof files are retained unmodified, so their signatures and digests remain
verifiable. The public trust data describe the local experiment's key history;
their inclusion does not establish an independent real-world identity binding.

## Timing boundaries

See `overlay/pipeline.py`, `overlay/proof_objects.py`, and `overlay/study.py` for
the exact measured operations. The CSV column names include their units:

- `production_us` measures elapsed time from the start of classification to the
  end of local storage (`t4 - t0`). It includes classification, any key
  registration, record construction, digest computation, local timestamping,
  encoding/signing, commitment computation, and local storage.
- `reliance_us` is release to a consumer under the configured mode. A synchronous
  outcome waits for a witnessed receipt; asynchronous release occurs while
  anchoring is pending. These states have different assurance.
- `verify_us` measures the implemented local checks using supplied registry and
  trust data. It excludes acquisition of a remote, sufficiently recent DT head.
- Exposure and queue-age counts use input events, rather than elapsed wall time.

For paper tables, raw microsecond timing samples are divided by 1,000 to obtain
milliseconds. Percentiles use linear interpolation between ordered observations.

## Reference totals and limits

The independent CSV check expects 5,000 input events per mode: 542 routine
readings, 37 rejected candidates, and 4,421 ordinary proof objects. Final
verification covers 13,374 anchored objects, including 111 rejection records.
The saved fault campaign reports 2,200 detected cases. The pending-tail test
rewrote 179 pre-flush objects without detection.

The example vector is a **frozen prefix** of the nominal policy-driven run at a
tree size of six. It proves inclusion relative to supplied signed checkpoints.
The full reference run contains later objects; neither this example nor a global
Merkle inclusion receipt establishes a current or complete DT history.

The proposed `dt-evidence-1` profile in the revised manuscript differs from the
saved implementation: JCS/COSE interoperability, DTD content binding, timestamping
of the full signed envelope, and independent per-DT head freshness are not
implemented by the saved format.
