"""Local experiment runner for checkpoint-mode comparisons.

The timings produced here are local prototype measurements taken with
``time.perf_counter``. They are useful for relative comparisons inside this
research prototype, but they are not deployment-grade latency measurements.
"""

from __future__ import annotations

import csv
import json
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dt_trust_checkpoints.config import AppConfig
from dt_trust_checkpoints.core.canonicalization_service import to_json_compatible
from dt_trust_checkpoints.core.checkpoint_controller import CheckpointController
from dt_trust_checkpoints.core.checkpoint_processor import CheckpointProcessor
from dt_trust_checkpoints.core.evidence_orchestrator import EvidenceOrchestrator
from dt_trust_checkpoints.core.proof_chain_builder import ProofChainBuilder
from dt_trust_checkpoints.models import (
    CheckpointMode,
    Event,
    EventType,
    PolicyDecision,
    ProofEnvelope,
    TwinContext,
)
from dt_trust_checkpoints.simulation import EventSimulator, summarize_events
from dt_trust_checkpoints.storage.blockchain_anchor_adapter import BlockchainAnchorAdapter
from dt_trust_checkpoints.storage.offchain_evidence_store import OffchainEvidenceStore
from dt_trust_checkpoints.verification.proof_verifier import ProofVerifier


VALID_EXPERIMENT_MODES = {"policy-driven", "forced-async", "forced-sync"}


@dataclass(frozen=True, slots=True)
class ExperimentRunConfig:
    """Configuration for one local checkpoint experiment run."""

    scenario: str
    mode: str
    twins: int
    events_per_twin: int
    seed: int
    output_dir: str | Path
    with_verification: bool = False
    run_id: str | None = None


@dataclass(frozen=True, slots=True)
class ExperimentRunResult:
    """Paths and summary for a completed experiment run."""

    run_id: str
    run_dir: Path
    summary: dict[str, Any]


class ExperimentRunner:
    """Run local experiment batches across simulator scenarios and policies."""

    def __init__(self, app_config: AppConfig) -> None:
        self.app_config = app_config

    def run_one(self, run_config: ExperimentRunConfig) -> ExperimentRunResult:
        """Run one experiment and persist summary/metric artifacts."""
        if run_config.mode not in VALID_EXPERIMENT_MODES:
            raise ValueError(f"Unsupported experiment mode: {run_config.mode}")

        output_dir = Path(run_config.output_dir)
        run_id = run_config.run_id or _default_run_id(run_config)
        run_dir = output_dir / run_id
        shutil.rmtree(run_dir, ignore_errors=True)
        run_dir.mkdir(parents=True, exist_ok=True)

        evidence_dir = run_dir / "evidence"
        chain_state_dir = run_dir / "chain_state"
        anchor_dir = run_dir / "anchors"
        event_metrics_path = run_dir / "event_metrics.csv"
        proof_metrics_path = run_dir / "proof_metrics.csv"
        anchor_metrics_path = run_dir / "anchors_metrics.csv"

        simulator = EventSimulator.from_config(
            self.app_config.simulation,
            scenario=run_config.scenario,
            twin_count=run_config.twins,
            events_per_twin=run_config.events_per_twin,
            seed=run_config.seed,
        )
        events = simulator.generate_events()
        processor = self._build_processor(
            mode=run_config.mode,
            evidence_dir=evidence_dir,
            chain_state_dir=chain_state_dir,
            anchor_dir=anchor_dir,
        )

        event_rows: list[dict[str, Any]] = []
        proof_rows: list[dict[str, Any]] = []
        anchor_rows: list[dict[str, Any]] = []
        durations: list[float] = []

        run_start = time.perf_counter()
        for event in events:
            context = _context_for_event(event)
            event_start = time.perf_counter()
            result = processor.process_event(event, context)
            duration = time.perf_counter() - event_start
            durations.append(duration)

            proof = result.proof
            anchor = result.anchor
            checkpoint_mode = result.decision.checkpoint_mode.value
            proof_path = Path(result.offchain_ref)
            proof_bytes = proof_path.stat().st_size if proof_path.exists() else 0
            anchor_bytes = _serialized_size(anchor) if anchor is not None else 0

            event_rows.append(
                {
                    "run_id": run_id,
                    "event_id": event.event_id,
                    "twin_id": event.twin_id,
                    "event_type": event.event_type.value,
                    "checkpoint_mode": checkpoint_mode,
                    "allowed": result.decision.allowed,
                    "blocked": result.decision.blocked,
                    "anchored": anchor is not None,
                    "processing_time_sec": duration,
                    "proof_id": proof.proof_id,
                    "anchor_digest": proof.anchor_digest or "",
                    "tx_ref": anchor.tx_ref if anchor is not None else "",
                    "criticality": float(event.metadata.get("criticality", 0.0)),
                    "fidelity_score": float(event.metadata.get("fidelity_score", 0.0)),
                    "management_sensitive": bool(
                        event.metadata.get("management_sensitive", False)
                    ),
                    "claim": event.metadata.get("claim", ""),
                }
            )
            proof_rows.append(
                {
                    "run_id": run_id,
                    "proof_id": proof.proof_id,
                    "twin_id": proof.twin_id,
                    "seq": proof.seq,
                    "event_type": (proof.event_type.value if proof.event_type else ""),
                    "checkpoint_mode": checkpoint_mode,
                    "proof_file": str(proof_path),
                    "proof_bytes": proof_bytes,
                    "payload_hash": proof.payload_hash or "",
                    "anchor_digest": proof.anchor_digest or "",
                }
            )
            if anchor is not None:
                anchor_rows.append(
                    {
                        "run_id": run_id,
                        "proof_id": anchor.proof_id,
                        "twin_id": anchor.twin_id,
                        "event_type": (
                            anchor.event_type.value if anchor.event_type else ""
                        ),
                        "checkpoint_mode": anchor.checkpoint_mode.value,
                        "anchor_digest": anchor.anchor_digest,
                        "tx_ref": anchor.tx_ref or "",
                        "order_index": anchor.order_index,
                        "anchor_bytes": anchor_bytes,
                    }
                )

        total_processing_time = time.perf_counter() - run_start
        verification_summary = (
            self._verify_run(events, evidence_dir, anchor_dir)
            if run_config.with_verification
            else None
        )

        summary = self._build_summary(
            run_config=run_config,
            run_id=run_id,
            events=events,
            event_rows=event_rows,
            proof_rows=proof_rows,
            anchor_rows=anchor_rows,
            durations=durations,
            total_processing_time=total_processing_time,
            verification_summary=verification_summary,
        )

        _write_csv(event_metrics_path, event_rows)
        _write_csv(proof_metrics_path, proof_rows)
        _write_csv(anchor_metrics_path, anchor_rows)
        _write_json(run_dir / "summary.json", summary)
        if verification_summary is not None:
            _write_json(run_dir / "verification_summary.json", verification_summary)
        self._append_aggregate(output_dir / "aggregate_results.csv", summary)

        return ExperimentRunResult(run_id=run_id, run_dir=run_dir, summary=summary)

    def run_sweep(
        self,
        *,
        scenarios: list[str],
        modes: list[str],
        twins: int,
        events_per_twin: int,
        seed: int,
        output_dir: str | Path,
        with_verification: bool = False,
    ) -> list[ExperimentRunResult]:
        """Run a scenario/mode sweep with deterministic run identifiers."""
        results: list[ExperimentRunResult] = []
        for scenario in scenarios:
            for mode in modes:
                results.append(
                    self.run_one(
                        ExperimentRunConfig(
                            scenario=scenario,
                            mode=mode,
                            twins=twins,
                            events_per_twin=events_per_twin,
                            seed=seed,
                            output_dir=output_dir,
                            with_verification=with_verification,
                        )
                    )
                )
        return results

    def run_default_suite(
        self,
        *,
        output_dir: str | Path | None = None,
        twins: int | None = None,
        events_per_twin: int | None = None,
        seed: int | None = None,
        with_verification: bool | None = None,
    ) -> list[ExperimentRunResult]:
        """Run the configured scenario/mode sweep."""
        experiments = self.app_config.experiments
        return self.run_sweep(
            scenarios=experiments.default_scenarios,
            modes=experiments.default_modes,
            twins=twins if twins is not None else experiments.default_twins,
            events_per_twin=(
                events_per_twin
                if events_per_twin is not None
                else experiments.default_events_per_twin
            ),
            seed=seed if seed is not None else experiments.default_seed,
            output_dir=output_dir or experiments.output_dir,
            with_verification=(
                with_verification
                if with_verification is not None
                else experiments.with_verification
            ),
        )

    def _build_processor(
        self,
        *,
        mode: str,
        evidence_dir: Path,
        chain_state_dir: Path,
        anchor_dir: Path,
    ) -> CheckpointProcessor:
        forced_mode = None
        if mode == "forced-async":
            forced_mode = CheckpointMode.ASYNC
        elif mode == "forced-sync":
            forced_mode = CheckpointMode.SYNC

        controller = _ExperimentCheckpointController(
            self.app_config,
            forced_mode=forced_mode,
        )
        return CheckpointProcessor(
            evidence_orchestrator=EvidenceOrchestrator(
                evidence_store=OffchainEvidenceStore(evidence_dir),
                chain_builder=ProofChainBuilder(chain_state_dir),
                proof_type=self.app_config.proof.default_proof_type,
                signer_id=self.app_config.proof.default_signer_id,
                canonicalization_version=(
                    self.app_config.proof.canonicalization_version
                ),
            ),
            checkpoint_controller=controller,
            anchor_adapter=BlockchainAnchorAdapter(anchor_dir),
        )

    def _verify_run(
        self,
        events: list[Event],
        evidence_dir: Path,
        anchor_dir: Path,
    ) -> dict[str, Any]:
        verifier = ProofVerifier(
            evidence_store=OffchainEvidenceStore(evidence_dir),
            anchor_adapter=BlockchainAnchorAdapter(anchor_dir),
            synchronized_fidelity_threshold=(
                self.app_config.verification.synchronized_fidelity_threshold
            ),
            strict_mode=self.app_config.verification.verification_strict_mode,
        )
        totals = {
            "proofs_checked": 0,
            "passed_count": 0,
            "failed_count": 0,
            "failure_categories": {},
            "twins": {},
        }
        for twin_id in sorted({event.twin_id for event in events}):
            summary = verifier.verify_all_for_twin(twin_id)
            totals["proofs_checked"] += summary.total_proofs_checked
            totals["passed_count"] += summary.passed_count
            totals["failed_count"] += summary.failed_count
            for category, count in summary.failure_categories.items():
                totals["failure_categories"][category] = (
                    totals["failure_categories"].get(category, 0) + count
                )
            totals["twins"][twin_id] = {
                "total_proofs_checked": summary.total_proofs_checked,
                "passed_count": summary.passed_count,
                "failed_count": summary.failed_count,
                "failure_categories": summary.failure_categories,
            }
        return totals

    def _build_summary(
        self,
        *,
        run_config: ExperimentRunConfig,
        run_id: str,
        events: list[Event],
        event_rows: list[dict[str, Any]],
        proof_rows: list[dict[str, Any]],
        anchor_rows: list[dict[str, Any]],
        durations: list[float],
        total_processing_time: float,
        verification_summary: dict[str, Any] | None,
    ) -> dict[str, Any]:
        event_summary = summarize_events(events)
        total_events = len(events)
        processed_events = len(event_rows)
        anchored_events = len(anchor_rows)
        rejected_events = sum(1 for row in event_rows if row["checkpoint_mode"] == "reject")
        async_count = sum(1 for row in event_rows if row["checkpoint_mode"] == "async")
        sync_count = sum(1 for row in event_rows if row["checkpoint_mode"] == "sync")
        total_proof_bytes = sum(int(row["proof_bytes"]) for row in proof_rows)
        total_anchor_bytes = sum(int(row["anchor_bytes"]) for row in anchor_rows)

        timing = {
            "total_processing_time_sec": total_processing_time,
            "avg_processing_time_sec": _average(durations),
            "p50_processing_time_sec": _percentile(durations, 50),
            "p95_processing_time_sec": _percentile(durations, 95),
            "p99_processing_time_sec": _percentile(durations, 99),
            "avg_processing_time_by_event_type": _averages_by_key(
                event_rows, "event_type", "processing_time_sec"
            ),
            "avg_processing_time_by_checkpoint_mode": _averages_by_key(
                event_rows, "checkpoint_mode", "processing_time_sec"
            ),
        }

        storage = {
            "total_offchain_proof_bytes": total_proof_bytes,
            "avg_offchain_proof_bytes_per_event": (
                total_proof_bytes / processed_events if processed_events else 0.0
            ),
            "total_mock_onchain_anchor_bytes": total_anchor_bytes,
            "avg_mock_anchor_bytes_per_anchored_event": (
                total_anchor_bytes / anchored_events if anchored_events else 0.0
            ),
            "offchain_onchain_ratio": (
                total_proof_bytes / total_anchor_bytes if total_anchor_bytes else None
            ),
        }

        summary = {
            "run_id": run_id,
            "scenario": run_config.scenario,
            "mode": run_config.mode,
            "twins": run_config.twins,
            "events_per_twin": run_config.events_per_twin,
            "seed": run_config.seed,
            "with_verification": run_config.with_verification,
            "total_events": total_events,
            "processed_events": processed_events,
            "anchored_events": anchored_events,
            "rejected_events": rejected_events,
            "async_count": async_count,
            "sync_count": sync_count,
            "per_event_type_counts": event_summary["event_type_counts"],
            "timing": timing,
            "storage": storage,
            "verification": verification_summary or {},
            "policy": {
                "async_ratio": async_count / processed_events if processed_events else 0.0,
                "sync_ratio": sync_count / processed_events if processed_events else 0.0,
                "reject_ratio": rejected_events / processed_events if processed_events else 0.0,
                "critical_event_count": sum(
                    1 for row in event_rows if float(row["criticality"]) >= 0.75
                ),
                "sensitive_management_count": event_summary[
                    "sensitive_management_actions"
                ],
                "synchronized_claims_count": event_summary["synchronized_claims"],
                "out_of_sync_claims_count": event_summary["out_of_sync_claims"],
            },
        }
        return summary

    def _append_aggregate(self, aggregate_path: Path, summary: dict[str, Any]) -> None:
        row = _aggregate_row(summary)
        aggregate_path.parent.mkdir(parents=True, exist_ok=True)
        write_header = not aggregate_path.exists()
        with aggregate_path.open("a", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=list(row.keys()))
            if write_header:
                writer.writeheader()
            writer.writerow(row)


class _ExperimentCheckpointController(CheckpointController):
    """Checkpoint controller wrapper for forced-mode experiment variants."""

    def __init__(
        self,
        app_config: AppConfig,
        *,
        forced_mode: CheckpointMode | None,
    ) -> None:
        super().__init__(app_config.checkpoint_policy)
        self.forced_mode = forced_mode

    def decide(
        self,
        event: Event,
        proof: ProofEnvelope,
        twin_context: TwinContext | None = None,
    ) -> PolicyDecision:
        decision = super().decide(event, proof, twin_context)
        if self.forced_mode is None or decision.blocked:
            return decision

        decision.checkpoint_mode = self.forced_mode
        decision.is_critical = self.forced_mode is CheckpointMode.SYNC
        decision.allowed = True
        decision.blocked = False
        decision.requires_anchor = True
        decision.policy_rule_id = f"experiment.{self.forced_mode.value}"
        decision.reason = f"Experiment forced {self.forced_mode.value} checkpoint mode."
        decision.rationale = decision.reason
        decision.metadata["experiment_forced_mode"] = self.forced_mode.value
        return decision


def _context_for_event(event: Event) -> TwinContext:
    return TwinContext(
        twin_id=event.twin_id,
        lifecycle_state=event.lifecycle_state,
        domain="simulation",
        asset_type="synthetic-digital-twin",
        trust_domain="experiment-local",
        metadata={
            "scenario_name": str(event.metadata.get("scenario_name", "")),
            "dtd_version": str(event.metadata.get("dtd_version", "")),
            "state_version": str(event.metadata.get("state_version", "")),
            "state_label": str(event.metadata.get("state_label", "")),
            "fidelity_score": str(event.metadata.get("fidelity_score", "")),
        },
    )


def _default_run_id(config: ExperimentRunConfig) -> str:
    return (
        f"{config.scenario}_{config.mode}_tw{config.twins}_"
        f"ev{config.events_per_twin}_seed{config.seed}"
    )


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(to_json_compatible(payload), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return

    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _serialized_size(value: Any) -> int:
    if value is None:
        return 0
    return len(json.dumps(to_json_compatible(value), sort_keys=True).encode("utf-8"))


def _average(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _percentile(values: list[float], percentile: int) -> float:
    if not values:
        return 0.0
    sorted_values = sorted(values)
    index = round((percentile / 100) * (len(sorted_values) - 1))
    return sorted_values[index]


def _averages_by_key(
    rows: list[dict[str, Any]], key_field: str, value_field: str
) -> dict[str, float]:
    buckets: dict[str, list[float]] = {}
    for row in rows:
        buckets.setdefault(str(row[key_field]), []).append(float(row[value_field]))
    return {key: _average(values) for key, values in sorted(buckets.items())}


def _aggregate_row(summary: dict[str, Any]) -> dict[str, Any]:
    verification = summary.get("verification", {})
    return {
        "run_id": summary["run_id"],
        "scenario": summary["scenario"],
        "mode": summary["mode"],
        "twins": summary["twins"],
        "events_per_twin": summary["events_per_twin"],
        "seed": summary["seed"],
        "total_events": summary["total_events"],
        "processed_events": summary["processed_events"],
        "anchored_events": summary["anchored_events"],
        "rejected_events": summary["rejected_events"],
        "async_count": summary["async_count"],
        "sync_count": summary["sync_count"],
        "async_ratio": summary["policy"]["async_ratio"],
        "sync_ratio": summary["policy"]["sync_ratio"],
        "reject_ratio": summary["policy"]["reject_ratio"],
        "critical_event_count": summary["policy"]["critical_event_count"],
        "sensitive_management_count": summary["policy"][
            "sensitive_management_count"
        ],
        "synchronized_claims_count": summary["policy"][
            "synchronized_claims_count"
        ],
        "out_of_sync_claims_count": summary["policy"]["out_of_sync_claims_count"],
        "total_processing_time_sec": summary["timing"][
            "total_processing_time_sec"
        ],
        "avg_processing_time_sec": summary["timing"]["avg_processing_time_sec"],
        "p50_processing_time_sec": summary["timing"]["p50_processing_time_sec"],
        "p95_processing_time_sec": summary["timing"]["p95_processing_time_sec"],
        "p99_processing_time_sec": summary["timing"]["p99_processing_time_sec"],
        "total_offchain_proof_bytes": summary["storage"][
            "total_offchain_proof_bytes"
        ],
        "total_mock_onchain_anchor_bytes": summary["storage"][
            "total_mock_onchain_anchor_bytes"
        ],
        "offchain_onchain_ratio": summary["storage"]["offchain_onchain_ratio"],
        "verification_proofs_checked": verification.get("proofs_checked", ""),
        "verification_passed_count": verification.get("passed_count", ""),
        "verification_failed_count": verification.get("failed_count", ""),
    }
