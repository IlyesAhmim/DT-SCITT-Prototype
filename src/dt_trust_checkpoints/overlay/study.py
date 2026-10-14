"""Event-level study: per-event measurements of the evidence overlay.

For each scenario, the same 1,000-event stream (two twins, 500 events each) is
processed in policy-driven, forced-sync, and forced-async modes. Each run uses
fresh keys, a fresh time-stamping service, and a fresh consortium of member
processes. Every proof object is then verified, faults are injected into the
policy-driven runs, and the entries still pending at the end of each run are
rewritten to confirm that the unanchored tail is not protected.

All numbers quoted in the article are written to ``paper_numbers.json`` and the
per-category table to ``table_per_category.tex``, both generated from the raw
per-event files so that nothing is transcribed by hand.
"""

from __future__ import annotations

import csv
import json
import platform
import shutil
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import numpy

from dt_trust_checkpoints.config import AppConfig
from dt_trust_checkpoints.core.checkpoint_controller import CheckpointController
from dt_trust_checkpoints.overlay.consortium import Consortium
from dt_trust_checkpoints.overlay.crypto import KeyRegistry, TimeStampService
from dt_trust_checkpoints.overlay.faults import (
    FaultContext,
    rewrite_pending_tail,
    run_fault_campaign,
)
from dt_trust_checkpoints.overlay.pipeline import EvidenceOverlay, EvidenceWorld
from dt_trust_checkpoints.overlay.policy import EVIDENCE_CATEGORIES, EvidenceClassifier
from dt_trust_checkpoints.overlay.proof_objects import ProofProducer
from dt_trust_checkpoints.overlay.registry import EvidenceLog
from dt_trust_checkpoints.overlay.verifier import OverlayVerifier, TrustAnchors
from dt_trust_checkpoints.overlay.workload import build_workload


SCENARIOS = ("nominal", "mixed", "management_heavy", "lifecycle_instability", "high_risk")
MODES = ("policy-driven", "forced-sync", "forced-async")
CATEGORY_LABELS = {
    "dtd_update": "DTD update",
    "dts_transition": "DTS transition",
    "af_validated_output": "AF output",
    "management_action": "Management action",
    "lifecycle_event": "Life-cycle event",
}


@dataclass(slots=True)
class StudyConfig:
    """Parameters of the event-level study."""

    scenarios: tuple[str, ...] = SCENARIOS
    modes: tuple[str, ...] = MODES
    twins: int = 2
    events_per_twin: int = 500
    seed: int = 42
    reference_events_per_twin: int = 20
    malformed_probability: float = 0.01
    members: int = 4
    quorum: int = 3
    async_max_batch: int = 64
    async_max_age_events: int = 300
    rotate_key_at_event: int | None = None  # default: halfway through each twin's events
    faults_per_cell: int = 10
    fault_seed: int = 7
    log_id: str = "dt-evidence-log"


@dataclass(slots=True)
class RunOutcome:
    """Rows produced by one run."""

    scenario: str
    mode: str
    events: list[dict[str, Any]] = field(default_factory=list)
    verification: list[dict[str, Any]] = field(default_factory=list)
    seals: list[dict[str, Any]] = field(default_factory=list)
    faults: list[dict[str, Any]] = field(default_factory=list)
    tail: dict[str, Any] = field(default_factory=dict)


def run_study(
    app_config: AppConfig, output_dir: Path, study: StudyConfig, *, force: bool = False
) -> dict[str, Any]:
    """Run the whole study and write every artifact under ``output_dir``.

    An existing, non-empty ``output_dir`` is never overwritten unless ``force``.
    """
    output_dir = Path(output_dir)
    if output_dir.exists() and any(output_dir.iterdir()):
        if not force:
            raise FileExistsError(f"{output_dir} is not empty; choose another directory or use force.")
        shutil.rmtree(output_dir)
    (output_dir / "runs").mkdir(parents=True)
    started = time.time()
    outcomes: list[RunOutcome] = []
    for scenario in study.scenarios:
        events = build_workload(
            app_config,
            scenario,
            twins=study.twins,
            events_per_twin=study.events_per_twin,
            seed=study.seed,
            reference_events_per_twin=study.reference_events_per_twin,
            malformed_probability=study.malformed_probability,
        )
        for mode in study.modes:
            outcome = _run_one(app_config, study, scenario, mode, events, output_dir)
            outcomes.append(outcome)
            print(
                f"[{scenario:22s} {mode:13s}] events={len(outcome.events)} "
                f"verified={len(outcome.verification)} faults={len(outcome.faults)}",
                flush=True,
            )
    _write_outputs(output_dir, study, outcomes, elapsed_s=time.time() - started)
    return summarize_study(output_dir)


def _run_one(
    app_config: AppConfig,
    study: StudyConfig,
    scenario: str,
    mode: str,
    events: list[Any],
    output_dir: Path,
) -> RunOutcome:
    run_dir = output_dir / "runs" / f"{scenario}_{mode}"
    run_dir.mkdir(parents=True)
    forced = {"policy-driven": None, "forced-sync": "sync", "forced-async": "async"}[mode]
    keys = KeyRegistry()
    time_stamps = TimeStampService()
    producer = ProofProducer(keys, time_stamps)
    outcome = RunOutcome(scenario=scenario, mode=mode)
    with Consortium(study.members, study.quorum, study.log_id) as consortium:
        log = EvidenceLog(consortium)
        overlay = EvidenceOverlay(
            classifier=EvidenceClassifier(CheckpointController(app_config.checkpoint_policy), forced),
            producer=producer,
            log=log,
            store_dir=run_dir / "evidence",
            async_max_batch=study.async_max_batch,
            async_max_age_events=study.async_max_age_events,
        )
        rotate_at = study.rotate_key_at_event or max(2, study.events_per_twin // 2)
        per_twin: dict[str, int] = {}
        for index, event in enumerate(events):
            per_twin[event.twin_id] = per_twin.get(event.twin_id, 0) + 1
            if per_twin[event.twin_id] == rotate_at and event.twin_id in producer._chains:
                producer.rotate_key(event.twin_id)
            row = overlay.process(event, index)
            row.update({"scenario": scenario, "mode": mode})
            outcome.events.append(row)
        snapshot: EvidenceWorld = overlay.world()
        pending = overlay.pending()
        overlay.finish(len(events))
        outcome.seals = overlay.seals
        trust = TrustAnchors(
            keys=keys,
            time_stamp_key=time_stamps.public_key,
            member_keys=dict(consortium.public_keys),
            quorum=study.quorum,
            log_id=study.log_id,
        )
    world = overlay.world()
    verdicts = OverlayVerifier(trust).verify_world(world)
    for twin_id, verdict in verdicts.items():
        if verdict.chain_failures:
            raise RuntimeError(f"Clean chain of {twin_id} failed: {verdict.chain_failures}")
        for item in verdict.objects:
            outcome.verification.append(
                {
                    "scenario": scenario,
                    "mode": mode,
                    "twin_id": twin_id,
                    "position": item.position,
                    "category": item.category,
                    "anchored": item.anchored,
                    "passed": not item.failed,
                    "failed_checks": "+".join(sorted(item.failed)),
                    "verify_us": item.verify_us,
                }
            )
    context = FaultContext(producer, time_stamps, trust, study.log_id, study.quorum, study.members)
    if mode == "policy-driven":
        run_fault_campaign(
            world,
            context,
            EVIDENCE_CATEGORIES,
            per_cell=study.faults_per_cell,
            seed=study.fault_seed,
            on_case=lambda case: outcome.faults.append({"scenario": scenario, **case}),
        )
    if pending:
        faulty, targets = rewrite_pending_tail(snapshot, pending, context)
        tail_verdicts = OverlayVerifier(trust).verify_world(faulty)
        detected = any(verdict.detected for verdict in tail_verdicts.values())
    else:
        targets, detected = [], False
    outcome.tail = {
        "scenario": scenario,
        "mode": mode,
        "pending_at_end": len(pending),
        "rewritten": len(targets),
        "detected": detected,
    }
    _write_run(run_dir, outcome, world, trust, study)
    return outcome


def _write_run(
    run_dir: Path, outcome: RunOutcome, world: EvidenceWorld, trust: TrustAnchors, study: StudyConfig
) -> None:
    _write_csv(run_dir / "events.csv", outcome.events)
    _write_csv(run_dir / "verification.csv", outcome.verification)
    _write_csv(run_dir / "seals.csv", outcome.seals)
    with (run_dir / "log.jsonl").open("w", encoding="utf-8") as handle:
        for anchor in world.anchors:
            handle.write(anchor.decode("utf-8") + "\n")
    (run_dir / "heads.json").write_text(
        json.dumps([head.export() for head in world.heads], indent=1) + "\n", encoding="utf-8"
    )
    with (run_dir / "receipts.jsonl").open("w", encoding="utf-8") as handle:
        for (twin_id, seq), receipt in sorted(world.receipts.items()):
            handle.write(json.dumps({"dt": twin_id, "seq": seq, **receipt.export()}) + "\n")
    (run_dir / "trust_anchors.json").write_text(
        json.dumps(
            {
                "keys": trust.keys.export(),
                "time_stamp_key": trust.time_stamp_key.hex(),
                "member_keys": {member: key.hex() for member, key in trust.member_keys.items()},
                "quorum": trust.quorum,
                "log_id": trust.log_id,
                "initial_dtd": world.initial_dtd,
            },
            indent=1,
        )
        + "\n",
        encoding="utf-8",
    )


# --------------------------------------------------------------------------- outputs


def _write_outputs(
    output_dir: Path, study: StudyConfig, outcomes: list[RunOutcome], *, elapsed_s: float
) -> None:
    events = [row for outcome in outcomes for row in outcome.events]
    verification = [row for outcome in outcomes for row in outcome.verification]
    seals = [
        {"scenario": outcome.scenario, "mode": outcome.mode, **seal}
        for outcome in outcomes
        for seal in outcome.seals
    ]
    faults = [row for outcome in outcomes for row in outcome.faults]
    tails = [outcome.tail for outcome in outcomes]
    _write_csv(output_dir / "events.csv", events)
    _write_csv(output_dir / "verification.csv", verification)
    _write_csv(output_dir / "seals.csv", seals)
    _write_csv(output_dir / "faults.csv", faults)
    _write_csv(output_dir / "tail_rewrites.csv", tails)
    (output_dir / "study_config.json").write_text(
        json.dumps(
            {
                "study": asdict(study),
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "elapsed_s": round(elapsed_s, 1),
                "environment": _environment(),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def _typed(value: str) -> Any:
    if value == "":
        return None
    if value in {"True", "False"}:
        return value == "True"
    for cast in (int, float):
        try:
            return cast(value)
        except ValueError:
            pass
    return value


def _read_csv(path: Path) -> list[dict[str, Any]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return [{key: _typed(value) for key, value in row.items()} for row in csv.DictReader(handle)]


def summarize_study(output_dir: Path) -> dict[str, Any]:
    """Recompute every summary of a study from its saved raw files.

    Writes ``per_category.csv``, ``per_mode.csv``, ``faults_summary.csv``,
    ``paper_numbers.json``, and ``table_per_category.tex``; nothing is measured
    again, so summaries can be regenerated without re-running the study.
    """
    output_dir = Path(output_dir)
    config = json.loads((output_dir / "study_config.json").read_text(encoding="utf-8"))["study"]
    events = _read_csv(output_dir / "events.csv")
    verification = _read_csv(output_dir / "verification.csv")
    seals = _read_csv(output_dir / "seals.csv")
    faults = _read_csv(output_dir / "faults.csv")
    tails = _read_csv(output_dir / "tail_rewrites.csv")
    per_category = _per_category(events, verification)
    per_mode = _per_mode(events, seals)
    _write_csv(output_dir / "per_category.csv", per_category)
    _write_csv(output_dir / "per_mode.csv", per_mode)
    _write_csv(output_dir / "faults_summary.csv", _fault_summary(faults))
    numbers = _paper_numbers(config, events, verification, per_category, per_mode, faults, tails)
    (output_dir / "paper_numbers.json").write_text(
        json.dumps(numbers, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "table_per_category.tex").write_text(_latex_rows(per_category), encoding="utf-8")
    return numbers


def _environment() -> dict[str, str]:
    import cryptography

    cpu = ""
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    return {
        "python": sys.version.split()[0],
        "cryptography": cryptography.__version__,
        "platform": platform.platform(),
        "cpu": cpu,
    }


def _pct(values: Iterable[float], q: float) -> float | None:
    data = [value for value in values if value is not None]
    return float(numpy.percentile(data, q)) if data else None


def _ms(value: float | None) -> float | None:
    return None if value is None else value / 1000.0


def _per_category(events: list[dict[str, Any]], verification: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    policy = [row for row in events if row["mode"] == "policy-driven"]
    for category in EVIDENCE_CATEGORIES:
        selected = [row for row in policy if row["category"] == category]
        kept = [row for row in selected if row["decision"] in {"sync", "async"}]
        sync = [row for row in kept if row["decision"] == "sync"]
        asynchronous = [row for row in kept if row["decision"] == "async"]
        checked = [
            row["verify_us"]
            for row in verification
            if row["mode"] == "policy-driven" and row["category"] == category
        ]
        rows.append(
            {
                "category": category,
                "label": CATEGORY_LABELS[category],
                "events": len(selected),
                "kept": len(kept),
                "rejected": len(selected) - len(kept),
                "sync_share": len(sync) / len(kept) if kept else None,
                "record_bytes_p50": _pct((row["record_bytes"] for row in kept), 50),
                "object_bytes_p50": _pct((row["object_bytes"] for row in kept), 50),
                "anchor_bytes_p50": _pct((row["anchor_bytes"] for row in kept), 50),
                "production_ms_p50": _ms(_pct((row["production_us"] for row in kept), 50)),
                "production_ms_p99": _ms(_pct((row["production_us"] for row in kept), 99)),
                "reliance_ms_p50": _ms(_pct((row["reliance_us"] for row in kept), 50)),
                "reliance_ms_p99": _ms(_pct((row["reliance_us"] for row in kept), 99)),
                "sync_reliance_ms_p50": _ms(_pct((row["reliance_us"] for row in sync), 50)),
                "async_reliance_ms_p50": _ms(_pct((row["reliance_us"] for row in asynchronous), 50)),
                "sync_reliance_ms_p99": _ms(_pct((row["reliance_us"] for row in sync), 99)),
                "verify_ms_p50": _ms(_pct(checked, 50)),
                "async_exposure_events_p50": _pct((row["exposure_events"] for row in asynchronous), 50),
                "async_exposure_events_max": max((row["exposure_events"] for row in asynchronous), default=None),
            }
        )
    return rows


def _per_mode(events: list[dict[str, Any]], seals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for mode in MODES:
        selected = [row for row in events if row["mode"] == mode]
        if not selected:
            continue
        kept = [row for row in selected if row["decision"] in {"sync", "async"}]
        queued = [row for row in selected if row["decision"] in {"async", "reject"}]
        mode_seals = [seal for seal in seals if seal["mode"] == mode]
        rows.append(
            {
                "mode": mode,
                "events": len(selected),
                "evidence_events": sum(1 for row in selected if row["evidence"]),
                "not_evidence": sum(1 for row in selected if not row["evidence"]),
                "rejected": sum(1 for row in selected if row["decision"] == "reject"),
                "sync_share": sum(1 for row in kept if row["decision"] == "sync") / len(kept),
                "production_ms_p50": _ms(_pct((row["production_us"] for row in kept), 50)),
                "reliance_ms_p50": _ms(_pct((row["reliance_us"] for row in kept), 50)),
                "reliance_ms_p95": _ms(_pct((row["reliance_us"] for row in kept), 95)),
                "reliance_ms_p99": _ms(_pct((row["reliance_us"] for row in kept), 99)),
                "seals": len(mode_seals),
                "anchors_per_seal_mean": (
                    sum(seal["queued_anchors"] for seal in mode_seals) / len(mode_seals)
                    + sum(1 for row in kept if row["decision"] == "sync") / len(mode_seals)
                    if mode_seals
                    else None
                ),
                "quorum_ms_p50": _ms(_pct((seal["quorum_us"] for seal in mode_seals), 50)),
                "quorum_ms_p99": _ms(_pct((seal["quorum_us"] for seal in mode_seals), 99)),
                "queued_exposure_events_p50": _pct((row["exposure_events"] for row in queued), 50),
                "queued_exposure_events_max": max((row["exposure_events"] for row in queued), default=None),
            }
        )
    return rows


def _fault_summary(faults: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for name in sorted({case["fault"] for case in faults}):
        cases = [case for case in faults if case["fault"] == name]
        fired: dict[str, int] = {}
        for case in cases:
            fired[case["checks_fired"]] = fired.get(case["checks_fired"], 0) + 1
        rows.append(
            {
                "fault": name,
                "cases": len(cases),
                "detected": sum(1 for case in cases if case["detected"]),
                "target_check": cases[0]["target_check"],
                "target_check_fired": sum(1 for case in cases if case["target_check_fired"]),
                "check_sets": "; ".join(f"{key or '-'}:{value}" for key, value in sorted(fired.items())),
            }
        )
    return rows


def _paper_numbers(
    study: dict[str, Any],
    events: list[dict[str, Any]],
    verification: list[dict[str, Any]],
    per_category: list[dict[str, Any]],
    per_mode: list[dict[str, Any]],
    faults: list[dict[str, Any]],
    tails: list[dict[str, Any]],
) -> dict[str, Any]:
    policy = [row for row in events if row["mode"] == "policy-driven"]
    kept = [row for row in policy if row["decision"] in {"sync", "async"}]
    sync = [row for row in kept if row["decision"] == "sync"]
    asynchronous = [row for row in kept if row["decision"] == "async"]
    modes = {row["mode"]: row for row in per_mode}
    tail_rewritten = sum(tail["rewritten"] for tail in tails)
    return {
        "runs": len({(row["scenario"], row["mode"]) for row in events}),
        "events_per_run": study["twins"] * study["events_per_twin"],
        "policy_events": len(policy),
        "policy_not_evidence": sum(1 for row in policy if not row["evidence"]),
        "policy_rejected": sum(1 for row in policy if row["decision"] == "reject"),
        "policy_evidence_kept": len(kept),
        "policy_sync_share": len(sync) / len(kept),
        "policy_async_reliance_ms_p50": _ms(_pct((row["reliance_us"] for row in asynchronous), 50)),
        "policy_async_reliance_ms_p99": _ms(_pct((row["reliance_us"] for row in asynchronous), 99)),
        "policy_sync_reliance_ms_p50": _ms(_pct((row["reliance_us"] for row in sync), 50)),
        "policy_sync_reliance_ms_p99": _ms(_pct((row["reliance_us"] for row in sync), 99)),
        "policy_sync_wait_ms_p50": _ms(
            _pct((row["reliance_us"] - row["production_us"] for row in sync), 50)
        ),
        "policy_quorum_ms_p50": modes["policy-driven"]["quorum_ms_p50"],
        "policy_anchor_bytes_p50": _pct((row["anchor_bytes"] for row in kept), 50),
        "policy_object_bytes_p50": _pct((row["object_bytes"] for row in kept), 50),
        "policy_async_exposure_events_p50": _pct((row["exposure_events"] for row in asynchronous), 50),
        "policy_async_exposure_events_max": max(row["exposure_events"] for row in asynchronous),
        "forced_sync_reliance_ms_p50": modes.get("forced-sync", {}).get("reliance_ms_p50"),
        "forced_async_reliance_ms_p50": modes.get("forced-async", {}).get("reliance_ms_p50"),
        "policy_reliance_ms_p50": modes["policy-driven"]["reliance_ms_p50"],
        "forced_async_exposure_events_max": modes.get("forced-async", {}).get("queued_exposure_events_max"),
        "verified_objects": len(verification),
        "verified_passed": sum(1 for row in verification if row["passed"]),
        "verify_ms_p50": _ms(_pct((row["verify_us"] for row in verification), 50)),
        "fault_cases": len(faults),
        "fault_classes": len({case["fault"] for case in faults}),
        "fault_detected": sum(1 for case in faults if case["detected"]),
        "fault_target_check_fired": sum(1 for case in faults if case["target_check_fired"]),
        "dtd_misbinding_only_vi": all(
            case["checks_fired"] == "vi" for case in faults if case["fault"] == "dtd_misbinding"
        ),
        "tail_rewritten": tail_rewritten,
        "tail_detected_runs": sum(1 for tail in tails if tail["detected"]),
        "per_category": {row["category"]: row for row in per_category},
    }


def _fmt(value: float | None, digits: int) -> str:
    return "--" if value is None else f"{value:.{digits}f}"


def _latex_rows(per_category: list[dict[str, Any]]) -> str:
    """Rows of the per-category table: medians unless the column says otherwise."""
    lines = []
    for row in per_category:
        lines.append(
            " & ".join(
                [
                    row["label"],
                    f"{row['kept']:,}".replace(",", "{,}"),
                    _fmt(row["sync_share"], 2),
                    _fmt(row["record_bytes_p50"] / 1000.0, 1),
                    _fmt(row["production_ms_p50"], 2),
                    _fmt(row["async_reliance_ms_p50"], 2),
                    _fmt(row["sync_reliance_ms_p50"], 2),
                    _fmt(row["reliance_ms_p99"], 2),
                    _fmt(row["verify_ms_p50"], 2),
                ]
            )
            + " \\\\"
        )
    return "\n".join(lines) + "\n"


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames: list[str] = []
    for row in rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
