"""Tests for deterministic Digital Twin event simulation."""

from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from dt_trust_checkpoints.cli import main
from dt_trust_checkpoints.core.canonicalization_service import canonicalize_to_json
from dt_trust_checkpoints.core.checkpoint_controller import CheckpointController
from dt_trust_checkpoints.core.checkpoint_processor import CheckpointProcessor
from dt_trust_checkpoints.core.evidence_orchestrator import EvidenceOrchestrator
from dt_trust_checkpoints.core.proof_chain_builder import ProofChainBuilder
from dt_trust_checkpoints.models import EventType
from dt_trust_checkpoints.simulation import EventSimulator, summarize_events
from dt_trust_checkpoints.storage.blockchain_anchor_adapter import BlockchainAnchorAdapter
from dt_trust_checkpoints.storage.offchain_evidence_store import OffchainEvidenceStore


class EventSimulatorTests(TestCase):
    """Simulator behavior and pipeline compatibility tests."""

    def test_fixed_seed_is_deterministic(self):
        first = EventSimulator(
            twin_ids=["twin-a", "twin-b"],
            events_per_twin=8,
            seed=77,
            scenario_name="mixed",
        ).generate_events()
        second = EventSimulator(
            twin_ids=["twin-a", "twin-b"],
            events_per_twin=8,
            seed=77,
            scenario_name="mixed",
        ).generate_events()

        self.assertEqual(canonicalize_to_json(first), canonicalize_to_json(second))

    def test_event_count_and_multi_twin_generation(self):
        events = EventSimulator(
            twin_ids=["twin-a", "twin-b", "twin-c"],
            events_per_twin=4,
            seed=1,
            scenario_name="nominal",
        ).generate_events()

        summary = summarize_events(events)
        self.assertEqual(len(events), 12)
        self.assertEqual(summary["twin_count"], 3)
        self.assertEqual(set(summary["twin_ids"]), {"twin-a", "twin-b", "twin-c"})

    def test_scenario_presets_have_distinguishable_behavior(self):
        nominal = summarize_events(
            EventSimulator(
                twin_ids=["twin-a"],
                events_per_twin=200,
                seed=123,
                scenario_name="nominal",
            ).generate_events()
        )
        high_risk = summarize_events(
            EventSimulator(
                twin_ids=["twin-a"],
                events_per_twin=200,
                seed=123,
                scenario_name="high_risk",
            ).generate_events()
        )
        management_heavy = summarize_events(
            EventSimulator(
                twin_ids=["twin-a"],
                events_per_twin=200,
                seed=123,
                scenario_name="management_heavy",
            ).generate_events()
        )
        lifecycle_instability = summarize_events(
            EventSimulator(
                twin_ids=["twin-a"],
                events_per_twin=200,
                seed=123,
                scenario_name="lifecycle_instability",
            ).generate_events()
        )

        nominal_critical = (
            nominal["critical_af_outputs"] + nominal["critical_state_transitions"]
        )
        high_risk_critical = (
            high_risk["critical_af_outputs"] + high_risk["critical_state_transitions"]
        )

        self.assertGreater(high_risk_critical, nominal_critical)
        self.assertGreater(
            management_heavy["event_type_counts"][EventType.MANAGEMENT_ACTION.value],
            nominal["event_type_counts"][EventType.MANAGEMENT_ACTION.value],
        )
        self.assertGreater(
            lifecycle_instability["out_of_sync_claims"],
            nominal["out_of_sync_claims"],
        )

    def test_generated_events_are_checkpoint_processor_compatible(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            simulator = EventSimulator(
                twin_ids=["twin-a", "twin-b"],
                events_per_twin=5,
                seed=11,
                scenario_name="mixed",
            )
            events = simulator.generate_events()
            processor = CheckpointProcessor(
                evidence_orchestrator=EvidenceOrchestrator(
                    evidence_store=OffchainEvidenceStore(root / "evidence"),
                    chain_builder=ProofChainBuilder(root / "chain"),
                    signer_id="sim-test-signer",
                ),
                checkpoint_controller=CheckpointController(),
                anchor_adapter=BlockchainAnchorAdapter(root / "anchors"),
            )

            results = [
                processor.process_event(event, simulator.context_for_twin(event.twin_id))
                for event in events
            ]

            self.assertEqual(len(results), len(events))
            self.assertTrue(all(result.proof.proof_id for result in results))
            self.assertTrue(all(result.anchor is not None for result in results))

    def test_cli_run_event_simulator_demo_runs(self):
        stream = StringIO()

        with redirect_stdout(stream):
            exit_code = main(
                [
                    "run-event-simulator-demo",
                    "--scenario",
                    "mixed",
                    "--twins",
                    "2",
                    "--events-per-twin",
                    "4",
                    "--seed",
                    "5",
                ]
            )

        output = stream.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("Event simulator demo:", output)
        self.assertIn("total_events=8", output)
        self.assertIn("event_type_counts=", output)
