"""Tests for checkpoint policy decisions, anchoring, and processing."""

import json
from contextlib import redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from dt_trust_checkpoints.cli import main
from dt_trust_checkpoints.config import load_config
from dt_trust_checkpoints.core.checkpoint_controller import CheckpointController
from dt_trust_checkpoints.core.checkpoint_processor import CheckpointProcessor
from dt_trust_checkpoints.core.evidence_orchestrator import EvidenceOrchestrator
from dt_trust_checkpoints.core.proof_chain_builder import ProofChainBuilder
from dt_trust_checkpoints.models import (
    AnchorRecord,
    CheckpointMode,
    Event,
    EventType,
    LifecycleState,
    ProofEnvelope,
    ProofType,
    TwinContext,
)
from dt_trust_checkpoints.storage.blockchain_anchor_adapter import BlockchainAnchorAdapter
from dt_trust_checkpoints.storage.offchain_evidence_store import OffchainEvidenceStore


class CheckpointPipelineTests(TestCase):
    """Trust checkpoint layer tests."""

    def _proof(self, event: Event) -> ProofEnvelope:
        return ProofEnvelope(
            proof_type=ProofType.CANONICAL_HASH,
            subject_event_id=event.event_id,
            twin_id=event.twin_id,
            canonical_hash="payload-hash",
            event_type=event.event_type,
            seq=1,
            payload_hash="payload-hash",
            canonical_payload="{}",
            anchor_digest="anchor-digest",
        )

    def _event(
        self,
        event_type: EventType,
        *,
        metadata: dict[str, object] | None = None,
        lifecycle_state: LifecycleState = LifecycleState.OPERATION,
    ) -> Event:
        return Event(
            twin_id="twin-001",
            event_type=event_type,
            source="unit-test",
            payload={"value": 1},
            lifecycle_state=lifecycle_state,
            observed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            event_id=f"event-{event_type.value}",
            metadata=metadata or {},
        )

    def test_checkpoint_controller_policy_decisions(self):
        controller = CheckpointController()

        cases = [
            (self._event(EventType.DTD_UPDATE), CheckpointMode.SYNC),
            (
                self._event(EventType.DTS_TRANSITION, metadata={"criticality": 0.9}),
                CheckpointMode.SYNC,
            ),
            (
                self._event(
                    EventType.AF_VALIDATED_OUTPUT,
                    metadata={"criticality": 0.2, "fidelity_score": 0.9},
                ),
                CheckpointMode.ASYNC,
            ),
            (
                self._event(
                    EventType.AF_VALIDATED_OUTPUT,
                    metadata={"criticality": 0.9, "fidelity_score": 0.9},
                ),
                CheckpointMode.SYNC,
            ),
            (
                self._event(
                    EventType.MANAGEMENT_ACTION,
                    metadata={"management_sensitive": True},
                ),
                CheckpointMode.SYNC,
            ),
            (
                self._event(
                    EventType.MANAGEMENT_ACTION,
                    metadata={"management_sensitive": False},
                ),
                CheckpointMode.ASYNC,
            ),
        ]

        for event, expected_mode in cases:
            with self.subTest(event_type=event.event_type):
                decision = controller.decide(event, self._proof(event))
                self.assertEqual(decision.checkpoint_mode, expected_mode)
                self.assertTrue(decision.allowed)
                self.assertFalse(decision.blocked)

    def test_checkpoint_controller_rejects_malformed_event(self):
        event = self._event(EventType.SENSOR_READING, metadata={"malformed": True})
        decision = CheckpointController().decide(event, self._proof(event))

        self.assertEqual(decision.checkpoint_mode, CheckpointMode.REJECT)
        self.assertFalse(decision.allowed)
        self.assertTrue(decision.blocked)
        self.assertFalse(decision.requires_anchor)

    def test_blockchain_anchor_adapter_submit_list_and_load(self):
        with TemporaryDirectory() as tmpdir:
            adapter = BlockchainAnchorAdapter(tmpdir)
            record = AnchorRecord(
                proof_id="proof-001",
                twin_id="twin-001",
                checkpoint_mode=CheckpointMode.SYNC,
                anchor_digest="anchor-001",
                proof_type=ProofType.CANONICAL_HASH,
                event_type=EventType.DTD_UPDATE,
                seq=1,
                payload_hash="payload-001",
                offchain_ref="outputs/evidence/twin-001/proof-001.json",
            )

            anchored = adapter.submit_anchor(record)
            listed = adapter.list_anchors("twin-001")
            loaded = adapter.load_anchor("anchor-001", "twin-001")

            self.assertEqual(anchored.tx_ref, "local-tx-000001")
            self.assertEqual(len(listed), 1)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.tx_ref, "local-tx-000001")

    def test_end_to_end_processing_anchors_allowed_and_skips_rejected(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            processor = CheckpointProcessor(
                evidence_orchestrator=EvidenceOrchestrator(
                    evidence_store=OffchainEvidenceStore(root / "evidence"),
                    chain_builder=ProofChainBuilder(root / "chain"),
                    signer_id="test-signer",
                ),
                checkpoint_controller=CheckpointController(),
                anchor_adapter=BlockchainAnchorAdapter(root / "anchors"),
            )
            context = TwinContext(
                twin_id="twin-001",
                lifecycle_state=LifecycleState.OPERATION,
                domain="test",
                asset_type="demo-asset",
            )

            sync_result = processor.process_event(
                self._event(EventType.DTD_UPDATE), context
            )
            async_result = processor.process_event(
                self._event(
                    EventType.AF_VALIDATED_OUTPUT,
                    metadata={"criticality": 0.1, "fidelity_score": 0.95},
                ),
                context,
            )
            rejected_result = processor.process_event(
                self._event(EventType.SENSOR_READING, metadata={"malformed": True}),
                context,
            )

            self.assertEqual(sync_result.decision.checkpoint_mode, CheckpointMode.SYNC)
            self.assertIsNotNone(sync_result.anchor)
            self.assertEqual(sync_result.anchor.tx_ref, "local-tx-000001")
            self.assertEqual(async_result.decision.checkpoint_mode, CheckpointMode.ASYNC)
            self.assertIsNotNone(async_result.anchor)
            self.assertEqual(async_result.anchor.tx_ref, "local-tx-000002")
            self.assertEqual(rejected_result.decision.checkpoint_mode, CheckpointMode.REJECT)
            self.assertIsNone(rejected_result.anchor)

            anchors = processor.anchor_adapter.list_anchors("twin-001")
            self.assertEqual(len(anchors), 2)

    def test_cli_run_checkpoint_demo_runs(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "proof": {
                            "default_proof_type": "canonical_hash",
                            "hash_algorithm": "sha256",
                            "canonicalization_version": "v0.1-test",
                            "include_signatures": True,
                            "default_signer_id": "checkpoint-cli-signer",
                            "signature_scheme": "local-mock-sha256-v1",
                        },
                        "checkpoint_policy": {
                            "default_mode": "async",
                            "critical_event_mode": "sync",
                            "anchor_only_critical_events": True,
                            "max_async_delay_seconds": 300,
                            "thresholds": {
                                "criticality_sync_threshold": 0.75,
                                "fidelity_sync_threshold": 0.5,
                            },
                            "rules": {
                                "reject_malformed_events": True,
                                "event_type_default_modes": {
                                    "dtd_update": "sync",
                                    "dts_transition": "sync",
                                    "af_validated_output": "async",
                                    "management_action": "async",
                                    "lifecycle_event": "async",
                                },
                                "lifecycle_sync_claims": [
                                    "synchronized",
                                    "out_of_sync",
                                ],
                            },
                        },
                        "simulation": {
                            "default_twin_id": "checkpoint-demo-twin",
                            "event_count": 3,
                            "random_seed": 42,
                            "critical_event_probability": 0.2,
                        },
                        "storage": {
                            "outputs_dir": str(root / "outputs"),
                            "experiments_dir": str(root / "experiments"),
                            "evidence_dir": str(root / "outputs" / "evidence"),
                            "offchain_evidence_dir": str(root / "outputs" / "evidence"),
                            "chain_state_dir": str(root / "outputs" / "chain_state"),
                            "anchor_dir": str(root / "outputs" / "anchors"),
                            "anchor_records_file": str(
                                root / "outputs" / "anchor_records.jsonl"
                            ),
                        },
                    }
                ),
                encoding="utf-8",
            )
            stream = StringIO()

            with redirect_stdout(stream):
                exit_code = main(
                    ["--config", str(config_path), "run-checkpoint-demo"]
                )

            output = stream.getvalue()
            self.assertEqual(exit_code, 0)
            self.assertIn("Checkpoint demo results:", output)
            self.assertIn("dtd_update", output)
            self.assertIn("reject", output)

            config = load_config(config_path)
            self.assertTrue((Path(config.storage.anchor_dir) / "anchors.jsonl").exists())
