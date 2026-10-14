"""Command-line interface for the Digital Twin trust checkpoint prototype."""

from __future__ import annotations

import argparse
import json
import shutil
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Sequence

from dt_trust_checkpoints.config import AppConfig, load_config
from dt_trust_checkpoints.core.checkpoint_controller import CheckpointController
from dt_trust_checkpoints.core.checkpoint_processor import CheckpointProcessor
from dt_trust_checkpoints.core.evidence_orchestrator import EvidenceOrchestrator
from dt_trust_checkpoints.core.proof_chain_builder import ProofChainBuilder
from dt_trust_checkpoints.experiments import ExperimentRunConfig, ExperimentRunner
from dt_trust_checkpoints.models import (
    Event,
    EventType,
    LifecycleState,
    TwinContext,
    VerificationResult,
    VerificationStatus,
)
from dt_trust_checkpoints.publication import build_publication_bundle
from dt_trust_checkpoints.reporting import generate_report_artifacts
from dt_trust_checkpoints.simulation.event_simulator import (
    EventSimulator,
    summarize_events,
)
from dt_trust_checkpoints.storage.blockchain_anchor_adapter import BlockchainAnchorAdapter
from dt_trust_checkpoints.storage.offchain_evidence_store import OffchainEvidenceStore
from dt_trust_checkpoints.verification.proof_verifier import ProofVerifier
from dt_trust_checkpoints.verification.tampering import (
    tamper_lifecycle_claim,
    tamper_prev_anchor,
    tamper_proof_payload,
    tamper_sequence,
)


def _json_default(value: Any) -> str:
    """Serialize model values used by placeholder CLI commands."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    return str(value)


def _load_cli_config(config_path: str | None) -> AppConfig:
    return load_config(Path(config_path) if config_path else None)


def handle_init_demo(args: argparse.Namespace) -> int:
    """Create local demo folders and a small demo context artifact."""
    config = _load_cli_config(args.config)
    config.storage.ensure_directories()

    context = TwinContext(
        twin_id=config.simulation.default_twin_id,
        lifecycle_state=LifecycleState.OPERATION,
        domain="demo",
        asset_type="research-digital-twin",
    )
    event = Event(
        twin_id=context.twin_id,
        event_type=EventType.LIFECYCLE_EVENT,
        source="init-demo",
        payload={"message": "Demo context initialized."},
        lifecycle_state=context.lifecycle_state,
    )

    output_path = Path(config.storage.outputs_dir) / "demo_context.json"
    output_path.write_text(
        json.dumps(
            {"context": asdict(context), "event": asdict(event)},
            default=_json_default,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"Initialized demo context at {output_path}")
    return 0


def handle_run_simulation(args: argparse.Namespace) -> int:
    """Placeholder simulation command."""
    config = _load_cli_config(args.config)
    config.storage.ensure_directories()

    print(
        "Simulation placeholder: "
        f"{config.simulation.event_count} events would be generated for "
        f"{config.simulation.default_twin_id}."
    )
    return 0


def _build_evidence_orchestrator(config: AppConfig) -> EvidenceOrchestrator:
    return EvidenceOrchestrator(
        evidence_store=OffchainEvidenceStore(config.storage.evidence_dir),
        chain_builder=ProofChainBuilder(config.storage.chain_state_dir),
        proof_type=config.proof.default_proof_type,
        signer_id=config.proof.default_signer_id,
        canonicalization_version=config.proof.canonicalization_version,
    )


def _build_checkpoint_processor(config: AppConfig) -> CheckpointProcessor:
    return CheckpointProcessor(
        evidence_orchestrator=_build_evidence_orchestrator(config),
        checkpoint_controller=CheckpointController(config.checkpoint_policy),
        anchor_adapter=BlockchainAnchorAdapter(config.storage.anchor_dir),
    )


def _build_checkpoint_processor_for_paths(
    config: AppConfig,
    evidence_dir: Path,
    chain_state_dir: Path,
    anchor_dir: Path,
) -> CheckpointProcessor:
    return CheckpointProcessor(
        evidence_orchestrator=EvidenceOrchestrator(
            evidence_store=OffchainEvidenceStore(evidence_dir),
            chain_builder=ProofChainBuilder(chain_state_dir),
            proof_type=config.proof.default_proof_type,
            signer_id=config.proof.default_signer_id,
            canonicalization_version=config.proof.canonicalization_version,
        ),
        checkpoint_controller=CheckpointController(config.checkpoint_policy),
        anchor_adapter=BlockchainAnchorAdapter(anchor_dir),
    )


def _build_verifier_for_paths(
    config: AppConfig,
    evidence_dir: Path,
    anchor_dir: Path,
) -> ProofVerifier:
    return ProofVerifier(
        evidence_store=OffchainEvidenceStore(evidence_dir),
        anchor_adapter=BlockchainAnchorAdapter(anchor_dir),
        synchronized_fidelity_threshold=(
            config.verification.synchronized_fidelity_threshold
        ),
        strict_mode=config.verification.verification_strict_mode,
    )


def _build_demo_events(config: AppConfig, count: int) -> list[Event]:
    event_types = [
        EventType.SENSOR_READING,
        EventType.STATE_TRANSITION,
        EventType.ANOMALY,
        EventType.CONTROL_ACTION,
        EventType.SECURITY_INCIDENT,
    ]
    twin_ids = [
        config.simulation.default_twin_id,
        f"{config.simulation.default_twin_id}-secondary",
    ]
    base_time = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)

    events: list[Event] = []
    for index in range(count):
        event_type = event_types[index % len(event_types)]
        twin_id = twin_ids[index % len(twin_ids)]
        events.append(
            Event(
                twin_id=twin_id,
                event_type=event_type,
                source="build-demo-proofs",
                payload={
                    "sample_index": index + 1,
                    "measurement": round(20.0 + index * 1.75, 2),
                    "unit": "demo-unit",
                },
                lifecycle_state=LifecycleState.OPERATION,
                severity=0.2 + index * 0.15,
                observed_at=base_time + timedelta(seconds=index),
                event_id=f"demo-event-{index + 1:03d}",
            )
        )

    return events


def _build_checkpoint_demo_events(config: AppConfig) -> list[Event]:
    twin_id = config.simulation.default_twin_id
    secondary_twin_id = f"{twin_id}-mgmt"
    base_time = datetime(2026, 1, 2, 9, 0, tzinfo=timezone.utc)

    return [
        Event(
            twin_id=twin_id,
            event_type=EventType.DTD_UPDATE,
            source="checkpoint-demo",
            payload={"component": "dtd", "version": "2.0.0"},
            observed_at=base_time,
            event_id="checkpoint-demo-001",
        ),
        Event(
            twin_id=twin_id,
            event_type=EventType.DTS_TRANSITION,
            source="checkpoint-demo",
            payload={"from": "standby", "to": "active"},
            metadata={"criticality": 0.95},
            observed_at=base_time + timedelta(seconds=1),
            event_id="checkpoint-demo-002",
        ),
        Event(
            twin_id=twin_id,
            event_type=EventType.AF_VALIDATED_OUTPUT,
            source="checkpoint-demo",
            payload={"prediction": "nominal", "confidence": 0.93},
            metadata={"criticality": 0.2, "fidelity_score": 0.91},
            observed_at=base_time + timedelta(seconds=2),
            event_id="checkpoint-demo-003",
        ),
        Event(
            twin_id=twin_id,
            event_type=EventType.AF_VALIDATED_OUTPUT,
            source="checkpoint-demo",
            payload={"prediction": "unsafe-drift", "confidence": 0.88},
            metadata={"criticality": 0.92, "fidelity_score": 0.87},
            observed_at=base_time + timedelta(seconds=3),
            event_id="checkpoint-demo-004",
        ),
        Event(
            twin_id=secondary_twin_id,
            event_type=EventType.MANAGEMENT_ACTION,
            source="checkpoint-demo",
            payload={"action": "rotate-operator-role"},
            metadata={"management_sensitive": True},
            observed_at=base_time + timedelta(seconds=4),
            event_id="checkpoint-demo-005",
        ),
        Event(
            twin_id=secondary_twin_id,
            event_type=EventType.MANAGEMENT_ACTION,
            source="checkpoint-demo",
            payload={"action": "refresh-dashboard-cache"},
            metadata={"management_sensitive": False},
            observed_at=base_time + timedelta(seconds=5),
            event_id="checkpoint-demo-006",
        ),
        Event(
            twin_id=twin_id,
            event_type=EventType.LIFECYCLE_EVENT,
            source="checkpoint-demo",
            payload={"claim": "synchronized"},
            metadata={"claim": "synchronized", "fidelity_score": 0.95},
            observed_at=base_time + timedelta(seconds=6),
            event_id="checkpoint-demo-007",
        ),
        Event(
            twin_id=twin_id,
            event_type=EventType.LIFECYCLE_EVENT,
            source="checkpoint-demo",
            payload={"status": "out_of_sync"},
            lifecycle_state=LifecycleState.OUT_OF_SYNC,
            observed_at=base_time + timedelta(seconds=7),
            event_id="checkpoint-demo-008",
        ),
        Event(
            twin_id=twin_id,
            event_type=EventType.SENSOR_READING,
            source="checkpoint-demo",
            payload={"temperature": None},
            metadata={"malformed": True},
            observed_at=base_time + timedelta(seconds=8),
            event_id="checkpoint-demo-009",
        ),
    ]


def _build_verification_demo_events(config: AppConfig) -> list[Event]:
    twin_id = config.simulation.default_twin_id
    base_time = datetime(2026, 1, 3, 10, 0, tzinfo=timezone.utc)
    return [
        Event(
            twin_id=twin_id,
            event_type=EventType.DTD_UPDATE,
            source="verification-demo",
            payload={"component": "dtd", "version": "3.0.0"},
            observed_at=base_time,
            event_id="verification-demo-001",
        ),
        Event(
            twin_id=twin_id,
            event_type=EventType.AF_VALIDATED_OUTPUT,
            source="verification-demo",
            payload={"prediction": "nominal", "confidence": 0.94},
            metadata={"criticality": 0.2, "fidelity_score": 0.92},
            observed_at=base_time + timedelta(seconds=1),
            event_id="verification-demo-002",
        ),
        Event(
            twin_id=twin_id,
            event_type=EventType.LIFECYCLE_EVENT,
            source="verification-demo",
            payload={"claim": "synchronized"},
            metadata={"claim": "synchronized", "fidelity_score": 0.95},
            observed_at=base_time + timedelta(seconds=2),
            event_id="verification-demo-003",
        ),
        Event(
            twin_id=twin_id,
            event_type=EventType.MANAGEMENT_ACTION,
            source="verification-demo",
            payload={"action": "refresh-calibration-note"},
            metadata={"management_sensitive": False},
            observed_at=base_time + timedelta(seconds=3),
            event_id="verification-demo-004",
        ),
    ]


def _process_verification_dataset(
    config: AppConfig,
    dataset_root: Path,
) -> tuple[str, list[str], ProofVerifier]:
    evidence_dir = dataset_root / "evidence"
    chain_state_dir = dataset_root / "chain_state"
    anchor_dir = dataset_root / "anchors"
    processor = _build_checkpoint_processor_for_paths(
        config, evidence_dir, chain_state_dir, anchor_dir
    )
    events = _build_verification_demo_events(config)
    proof_ids: list[str] = []

    for event in events:
        context = TwinContext(
            twin_id=event.twin_id,
            lifecycle_state=event.lifecycle_state,
            domain="demo",
            asset_type="research-digital-twin",
            trust_domain="local-prototype",
        )
        result = processor.process_event(event, context)
        proof_ids.append(result.proof.proof_id)

    verifier = _build_verifier_for_paths(config, evidence_dir, anchor_dir)
    return events[0].twin_id, proof_ids, verifier


def _pick_detection(
    results: list[VerificationResult],
    proof_id: str,
    expected_status: VerificationStatus,
) -> VerificationResult:
    for result in results:
        if result.proof_id == proof_id and result.status is expected_status:
            return result
    for result in results:
        if result.proof_id == proof_id and not result.ok:
            return result
    for result in results:
        if not result.ok:
            return result
    return results[0]


def handle_build_demo_proofs(args: argparse.Namespace) -> int:
    """Build and persist a small set of local demo proof envelopes."""
    config = _load_cli_config(args.config)
    config.storage.ensure_directories()

    orchestrator = _build_evidence_orchestrator(config)
    events = _build_demo_events(config, args.count)

    print("Built demo proofs:")
    print("proof_id                             twin_id                       seq  hashes")
    for event in events:
        context = TwinContext(
            twin_id=event.twin_id,
            lifecycle_state=event.lifecycle_state,
            domain="demo",
            asset_type="research-digital-twin",
            trust_domain="local-prototype",
        )
        result = orchestrator.create_proof(event, context)
        proof = result.proof
        print(
            f"{proof.proof_id}  {proof.twin_id:<28} "
            f"{proof.seq:<4} payload={proof.payload_hash[:12]} "
            f"anchor={proof.anchor_digest[:12]} file={result.offchain_ref}"
        )

    return 0


def handle_run_checkpoint_demo(args: argparse.Namespace) -> int:
    """Run local proof construction plus trust checkpoint decisions."""
    config = _load_cli_config(args.config)
    config.storage.ensure_directories()

    processor = _build_checkpoint_processor(config)
    events = _build_checkpoint_demo_events(config)

    print("Checkpoint demo results:")
    print(
        "event_type           twin_id                 proof_id                             mode    allowed  tx_ref           anchor        reason"
    )
    for event in events:
        context = TwinContext(
            twin_id=event.twin_id,
            lifecycle_state=event.lifecycle_state,
            domain="demo",
            asset_type="research-digital-twin",
            trust_domain="local-prototype",
        )
        result = processor.process_event(event, context)
        proof = result.proof
        decision = result.decision
        anchor = result.anchor
        tx_ref = anchor.tx_ref if anchor is not None else "-"
        anchor_digest = proof.anchor_digest[:12] if proof.anchor_digest else "-"
        reason = decision.reason or decision.rationale

        print(
            f"{event.event_type.value:<20} {event.twin_id:<23} "
            f"{proof.proof_id}  "
            f"{decision.checkpoint_mode.value:<7} {str(decision.allowed):<8} "
            f"{tx_ref:<16} {anchor_digest:<13} {reason}"
        )

    return 0


def handle_run_verification_demo(args: argparse.Namespace) -> int:
    """Run clean verification and controlled tampering scenarios."""
    config = _load_cli_config(args.config)
    demo_root = Path(config.storage.outputs_dir) / "verification_demo"
    shutil.rmtree(demo_root, ignore_errors=True)
    demo_root.mkdir(parents=True, exist_ok=True)

    clean_root = demo_root / "clean"
    twin_id, proof_ids, clean_verifier = _process_verification_dataset(
        config, clean_root
    )
    clean_summary = clean_verifier.verify_all_for_twin(twin_id)
    print("Verification demo:")
    print(
        f"clean twin={clean_summary.twin_id} total={clean_summary.total_proofs_checked} "
        f"passed={clean_summary.passed_count} failed={clean_summary.failed_count} "
        f"failures={clean_summary.failure_categories}"
    )
    print("scenario                       proof_id                             expected                         detected                         message")

    scenarios = [
        (
            "payload tampering",
            VerificationStatus.PAYLOAD_HASH_MISMATCH,
            lambda root, pid: tamper_proof_payload(root / "evidence", twin_id, pid),
            1,
        ),
        (
            "prev_anchor tampering",
            VerificationStatus.PREV_ANCHOR_MISMATCH,
            lambda root, pid: tamper_prev_anchor(root / "evidence", twin_id, pid),
            2,
        ),
        (
            "sequence rollback",
            VerificationStatus.CHAIN_SEQUENCE_ERROR,
            lambda root, pid: tamper_sequence(root / "evidence", twin_id, pid, 1),
            2,
        ),
        (
            "fake synchronized claim",
            VerificationStatus.POLICY_CLAIM_INCONSISTENCY,
            lambda root, pid: tamper_lifecycle_claim(root / "evidence", twin_id, pid),
            2,
        ),
    ]

    for index, (name, expected, tamper, proof_index) in enumerate(scenarios, start=1):
        scenario_root = demo_root / f"scenario_{index}"
        scenario_twin_id, scenario_proof_ids, verifier = _process_verification_dataset(
            config, scenario_root
        )
        proof_id = scenario_proof_ids[proof_index]
        tamper(scenario_root, proof_id)
        summary = verifier.verify_all_for_twin(scenario_twin_id)
        detected = _pick_detection(summary.results, proof_id, expected)
        message = detected.message or detected.reason
        print(
            f"{name:<30} {proof_id}  {expected.value:<32} "
            f"{detected.status.value:<32} {message}"
        )

    return 0


def handle_run_event_simulator_demo(args: argparse.Namespace) -> int:
    """Generate a deterministic synthetic Digital Twin event stream."""
    config = _load_cli_config(args.config)
    simulator = EventSimulator.from_config(
        config.simulation,
        scenario=args.scenario,
        twin_count=args.twins,
        events_per_twin=args.events_per_twin,
        seed=args.seed,
    )
    events = simulator.generate_events()
    summary = summarize_events(events)

    print("Event simulator demo:")
    print(
        f"scenario={args.scenario or config.simulation.default_scenario} "
        f"seed={args.seed if args.seed is not None else config.simulation.random_seed} "
        f"twins={summary['twin_count']} total_events={summary['total_events']}"
    )
    print(f"event_type_counts={summary['event_type_counts']}")
    print(
        "checkpoint_relevant="
        f"critical_af={summary['critical_af_outputs']} "
        f"critical_dts={summary['critical_state_transitions']} "
        f"sensitive_management={summary['sensitive_management_actions']} "
        f"synchronized={summary['synchronized_claims']} "
        f"out_of_sync={summary['out_of_sync_claims']}"
    )
    print("sample_events:")
    for event in events[: args.show]:
        print(
            f"{event.observed_at.isoformat()} {event.twin_id:<18} "
            f"{event.event_type.value:<20} "
            f"crit={float(event.metadata.get('criticality', 0.0)):.2f} "
            f"fid={float(event.metadata.get('fidelity_score', 0.0)):.2f} "
            f"payload={event.payload}"
        )

    return 0


def handle_run_experiments(args: argparse.Namespace) -> int:
    """Run one local checkpoint comparison experiment or a configured sweep."""
    config = _load_cli_config(args.config)
    runner = ExperimentRunner(config)
    output_dir = args.output_dir or config.experiments.output_dir

    if args.sweep_defaults:
        results = runner.run_default_suite(
            output_dir=output_dir,
            twins=args.twins,
            events_per_twin=args.events_per_twin,
            seed=args.seed,
            with_verification=args.with_verification,
        )
        print(
            f"Experiment suite complete: runs={len(results)} output_dir={output_dir} "
            f"aggregate={Path(output_dir) / 'aggregate_results.csv'}"
        )
        return 0

    run_config = ExperimentRunConfig(
        scenario=args.scenario or config.simulation.default_scenario,
        mode=args.mode,
        twins=args.twins or config.experiments.default_twins,
        events_per_twin=args.events_per_twin
        or config.experiments.default_events_per_twin,
        seed=args.seed if args.seed is not None else config.experiments.default_seed,
        output_dir=output_dir,
        with_verification=args.with_verification,
    )
    result = runner.run_one(run_config)
    summary = result.summary
    print("Experiment run complete:")
    print(f"run_id={result.run_id}")
    print(f"run_dir={result.run_dir}")
    print(
        f"events={summary['total_events']} anchored={summary['anchored_events']} "
        f"async={summary['async_count']} sync={summary['sync_count']} "
        f"rejected={summary['rejected_events']}"
    )
    print(
        "timing="
        f"avg={summary['timing']['avg_processing_time_sec']:.6f}s "
        f"p95={summary['timing']['p95_processing_time_sec']:.6f}s"
    )
    print(f"aggregate={Path(output_dir) / 'aggregate_results.csv'}")
    return 0


def handle_run_default_experiment_suite(args: argparse.Namespace) -> int:
    """Run the configured scenario/mode experiment suite."""
    config = _load_cli_config(args.config)
    output_dir = args.output_dir or config.experiments.output_dir
    results = ExperimentRunner(config).run_default_suite(
        output_dir=output_dir,
        twins=args.twins,
        events_per_twin=args.events_per_twin,
        seed=args.seed,
        with_verification=args.with_verification,
    )
    print("Default experiment suite complete:")
    print(f"runs={len(results)}")
    print(f"output_dir={output_dir}")
    print(f"aggregate={Path(output_dir) / 'aggregate_results.csv'}")
    return 0


def handle_generate_report_artifacts(args: argparse.Namespace) -> int:
    """Generate figures and summary tables from experiment outputs."""
    result = generate_report_artifacts(
        input_dir=args.input_dir,
        output_dir=args.output_dir,
        aggregate_csv=args.aggregate_csv,
    )

    if not args.quiet:
        print("Report artifact generation complete:")
        print(f"figures={len(result.figures)}")
        for path in result.figures:
            print(f"  figure: {path}")
        print(f"tables={len(result.tables)}")
        for path in result.tables:
            print(f"  table: {path}")
        if result.skipped:
            print(f"skipped={len(result.skipped)}")
            for item in result.skipped:
                print(f"  skipped: {item}")

    return 0


def handle_build_publication_bundle(args: argparse.Namespace) -> int:
    """Collect existing experiment/report artifacts into a publication bundle."""
    result = build_publication_bundle(
        input_dir=args.input_dir,
        output_dir=args.output_dir,
        force=args.force,
    )

    if not args.quiet:
        print("Publication bundle complete:")
        print(f"output_dir={result.output_dir}")
        print(f"manifest={result.manifest_path}")
        print(f"results_summary={result.results_summary_path}")
        print(f"copied={len(result.copied_files)} generated={len(result.generated_files)}")
        if result.missing_required:
            print(f"missing_required={len(result.missing_required)}")
            for item in result.missing_required:
                print(f"  required: {item}")
        if result.missing_optional:
            print(f"missing_optional={len(result.missing_optional)}")
            for item in result.missing_optional:
                print(f"  optional: {item}")

    return 1 if result.missing_required else 0


def handle_run_event_level_study(args: argparse.Namespace) -> int:
    """Run the per-event evaluation of the evidence overlay."""
    from dt_trust_checkpoints.overlay.study import MODES, SCENARIOS, StudyConfig, run_study

    config = _load_cli_config(args.config)
    study = StudyConfig(
        scenarios=tuple(args.scenarios or SCENARIOS),
        modes=tuple(args.modes or MODES),
        twins=args.twins,
        events_per_twin=args.events_per_twin,
        seed=args.seed,
        members=args.members,
        quorum=args.quorum,
        faults_per_cell=args.faults_per_cell,
    )
    numbers = run_study(config, Path(args.output_dir), study, force=args.force)
    print("Event-level study complete:")
    print(f"output_dir={args.output_dir}")
    print(f"runs={numbers['runs']} events_per_run={numbers['events_per_run']}")
    print(f"verified={numbers['verified_passed']}/{numbers['verified_objects']}")
    print(f"faults_detected={numbers['fault_detected']}/{numbers['fault_cases']}")
    return 0


def handle_plot_event_level_study(args: argparse.Namespace) -> int:
    """Draw the figures of the event-level study from its saved outputs."""
    from dt_trust_checkpoints.overlay.figures import plot_study

    input_dir = Path(args.input_dir)
    paths = plot_study(input_dir, Path(args.output_dir) if args.output_dir else input_dir / "figures")
    for path in paths:
        print(f"figure: {path}")
    return 0


def handle_summarize_event_level_study(args: argparse.Namespace) -> int:
    """Recompute the summaries of the event-level study from its raw files."""
    from dt_trust_checkpoints.overlay.study import summarize_study

    numbers = summarize_study(Path(args.input_dir))
    print(f"summaries rewritten in {args.input_dir} ({numbers['runs']} runs)")
    return 0


def handle_verify(args: argparse.Namespace) -> int:
    """Placeholder verification command."""
    _load_cli_config(args.config)

    if args.proof_path is None:
        print("Verification placeholder: no proof envelope path provided.")
        return 0

    proof_path = Path(args.proof_path)
    if not proof_path.exists():
        print(f"Verification placeholder: proof file not found at {proof_path}")
        return 0

    print(f"Verification placeholder: proof file discovered at {proof_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="dt-trust-checkpoints",
        description="Research prototype for trustworthy Digital Twin checkpoints.",
    )
    parser.add_argument(
        "--config",
        help="Path to a JSON configuration file. Defaults to configs/default.json.",
    )

    subparsers = parser.add_subparsers(dest="command")

    init_demo = subparsers.add_parser(
        "init-demo",
        help="Initialize local demo folders and a demo context artifact.",
    )
    init_demo.set_defaults(func=handle_init_demo)

    run_simulation = subparsers.add_parser(
        "run-simulation",
        help="Run the event simulation placeholder.",
    )
    run_simulation.set_defaults(func=handle_run_simulation)

    build_demo_proofs = subparsers.add_parser(
        "build-demo-proofs",
        help="Build and store local demo proof envelopes.",
    )
    build_demo_proofs.add_argument(
        "--count",
        type=int,
        default=4,
        help="Number of synthetic demo events to convert into proofs.",
    )
    build_demo_proofs.set_defaults(func=handle_build_demo_proofs)

    run_checkpoint_demo = subparsers.add_parser(
        "run-checkpoint-demo",
        help="Run proof construction, checkpoint decisions, and local anchoring.",
    )
    run_checkpoint_demo.set_defaults(func=handle_run_checkpoint_demo)

    run_verification_demo = subparsers.add_parser(
        "run-verification-demo",
        help="Run clean verification and controlled tampering scenarios.",
    )
    run_verification_demo.set_defaults(func=handle_run_verification_demo)

    run_event_simulator_demo = subparsers.add_parser(
        "run-event-simulator-demo",
        help="Generate deterministic synthetic Digital Twin events.",
    )
    run_event_simulator_demo.add_argument(
        "--scenario",
        choices=[
            "nominal",
            "high_risk",
            "management_heavy",
            "lifecycle_instability",
            "mixed",
        ],
        help="Scenario preset to generate. Defaults to config.",
    )
    run_event_simulator_demo.add_argument(
        "--twins",
        type=int,
        help="Number of twins to simulate. Defaults to config.",
    )
    run_event_simulator_demo.add_argument(
        "--events-per-twin",
        type=int,
        help="Number of events per twin. Defaults to config.",
    )
    run_event_simulator_demo.add_argument(
        "--seed",
        type=int,
        help="Deterministic random seed. Defaults to config.",
    )
    run_event_simulator_demo.add_argument(
        "--show",
        type=int,
        default=6,
        help="Number of sample events to print.",
    )
    run_event_simulator_demo.set_defaults(func=handle_run_event_simulator_demo)

    run_experiments = subparsers.add_parser(
        "run-experiments",
        help="Run local checkpoint comparison experiments.",
    )
    run_experiments.add_argument(
        "--scenario",
        choices=[
            "nominal",
            "high_risk",
            "management_heavy",
            "lifecycle_instability",
            "mixed",
        ],
        help="Scenario preset for a single run. Defaults to config.",
    )
    run_experiments.add_argument(
        "--mode",
        choices=["policy-driven", "forced-async", "forced-sync"],
        default="policy-driven",
        help="Checkpoint comparison mode for a single run.",
    )
    run_experiments.add_argument(
        "--twins",
        type=int,
        help="Number of twins. Defaults to experiment config.",
    )
    run_experiments.add_argument(
        "--events-per-twin",
        type=int,
        help="Number of events per twin. Defaults to experiment config.",
    )
    run_experiments.add_argument(
        "--seed",
        type=int,
        help="Deterministic random seed. Defaults to experiment config.",
    )
    run_experiments.add_argument(
        "--output-dir",
        help="Directory for experiment outputs. Defaults to config.",
    )
    run_experiments.add_argument(
        "--with-verification",
        action="store_true",
        help="Run verifier summaries after processing.",
    )
    run_experiments.add_argument(
        "--sweep-defaults",
        action="store_true",
        help="Run the configured scenario/mode suite instead of one run.",
    )
    run_experiments.set_defaults(func=handle_run_experiments)

    run_default_experiment_suite = subparsers.add_parser(
        "run-default-experiment-suite",
        help="Run all configured scenarios across all configured modes.",
    )
    run_default_experiment_suite.add_argument(
        "--twins",
        type=int,
        help="Override configured number of twins.",
    )
    run_default_experiment_suite.add_argument(
        "--events-per-twin",
        type=int,
        help="Override configured events per twin.",
    )
    run_default_experiment_suite.add_argument(
        "--seed",
        type=int,
        help="Override configured seed.",
    )
    run_default_experiment_suite.add_argument(
        "--output-dir",
        help="Directory for experiment outputs. Defaults to config.",
    )
    run_default_experiment_suite.add_argument(
        "--with-verification",
        action="store_true",
        help="Run verifier summaries after processing.",
    )
    run_default_experiment_suite.set_defaults(
        func=handle_run_default_experiment_suite
    )

    generate_report_parser = subparsers.add_parser(
        "generate-report-artifacts",
        help="Generate figures and summary tables from experiment outputs.",
    )
    generate_report_parser.add_argument(
        "--input-dir",
        default="outputs/experiments",
        help="Directory containing aggregate_results.csv and per-run outputs.",
    )
    generate_report_parser.add_argument(
        "--output-dir",
        default="outputs",
        help="Directory where figures/ and tables/ will be written.",
    )
    generate_report_parser.add_argument(
        "--aggregate-csv",
        help="Optional explicit path to aggregate_results.csv.",
    )
    generate_report_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress generated/skipped artifact details.",
    )
    generate_report_parser.set_defaults(func=handle_generate_report_artifacts)

    publication_bundle_parser = subparsers.add_parser(
        "build-publication-bundle",
        help="Collect existing outputs into a paper/slides artifact bundle.",
    )
    publication_bundle_parser.add_argument(
        "--input-dir",
        default="outputs",
        help="Root output directory containing experiments/, figures/, and tables/.",
    )
    publication_bundle_parser.add_argument(
        "--output-dir",
        default="outputs/publication_bundle",
        help="Directory where the publication bundle will be written.",
    )
    publication_bundle_parser.add_argument(
        "--force",
        action="store_true",
        help="Remove an existing bundle directory before writing the new bundle.",
    )
    publication_bundle_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress generated/copied/missing artifact details.",
    )
    publication_bundle_parser.set_defaults(func=handle_build_publication_bundle)

    event_level = subparsers.add_parser(
        "run-event-level-study",
        help="Run the per-event evaluation of the evidence overlay.",
    )
    event_level.add_argument("--output-dir", default="outputs/event_level")
    event_level.add_argument("--scenarios", nargs="*", help="Scenarios to run (default: all five).")
    event_level.add_argument(
        "--modes",
        nargs="*",
        choices=["policy-driven", "forced-sync", "forced-async"],
        help="Modes to run (default: all three).",
    )
    event_level.add_argument("--twins", type=int, default=2)
    event_level.add_argument("--events-per-twin", type=int, default=500)
    event_level.add_argument("--seed", type=int, default=42)
    event_level.add_argument("--members", type=int, default=4)
    event_level.add_argument("--quorum", type=int, default=3)
    event_level.add_argument("--faults-per-cell", type=int, default=10)
    event_level.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing output directory (otherwise the study refuses to start).",
    )
    event_level.set_defaults(func=handle_run_event_level_study)

    event_level_plot = subparsers.add_parser(
        "plot-event-level-study",
        help="Draw the figures of the event-level study.",
    )
    event_level_plot.add_argument("--input-dir", default="outputs/event_level")
    event_level_plot.add_argument("--output-dir")
    event_level_plot.set_defaults(func=handle_plot_event_level_study)

    event_level_summary = subparsers.add_parser(
        "summarize-event-level-study",
        help="Recompute the tables and quoted numbers of the event-level study from its raw files.",
    )
    event_level_summary.add_argument("--input-dir", default="outputs/event_level")
    event_level_summary.set_defaults(func=handle_summarize_event_level_study)

    verify = subparsers.add_parser(
        "verify",
        help="Run the proof verification placeholder.",
    )
    verify.add_argument(
        "proof_path",
        nargs="?",
        help="Optional path to a proof envelope artifact.",
    )
    verify.set_defaults(func=handle_verify)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line interface."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not hasattr(args, "func"):
        parser.print_help()
        return 0

    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
