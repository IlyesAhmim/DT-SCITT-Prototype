"""Tests for local proof verification and tampering detection."""

import json
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from dt_trust_checkpoints.cli import main
from dt_trust_checkpoints.core.checkpoint_controller import CheckpointController
from dt_trust_checkpoints.core.checkpoint_processor import CheckpointProcessor
from dt_trust_checkpoints.core.evidence_orchestrator import EvidenceOrchestrator
from dt_trust_checkpoints.core.proof_chain_builder import ProofChainBuilder
from dt_trust_checkpoints.models import (
    Event,
    EventType,
    LifecycleState,
    TwinContext,
    VerificationStatus,
)
from dt_trust_checkpoints.storage.blockchain_anchor_adapter import BlockchainAnchorAdapter
from dt_trust_checkpoints.storage.offchain_evidence_store import OffchainEvidenceStore
from dt_trust_checkpoints.verification.proof_verifier import ProofVerifier
from dt_trust_checkpoints.verification.tampering import (
    remove_anchor_record,
    tamper_lifecycle_claim,
    tamper_prev_anchor,
    tamper_proof_payload,
    tamper_sequence,
)


class VerificationTests(TestCase):
    """Verification and attack-detection tests."""

    def _event(
        self,
        event_type: EventType,
        index: int,
        *,
        metadata: dict[str, object] | None = None,
        payload: dict[str, object] | None = None,
        lifecycle_state: LifecycleState = LifecycleState.OPERATION,
    ) -> Event:
        return Event(
            twin_id="twin-verify",
            event_type=event_type,
            source="verification-test",
            payload=payload or {"value": index},
            lifecycle_state=lifecycle_state,
            observed_at=datetime(2026, 1, 1, tzinfo=timezone.utc)
            + timedelta(seconds=index),
            event_id=f"verify-event-{index:03d}",
            metadata=metadata or {},
        )

    def _dataset(self, root: Path) -> tuple[list[str], ProofVerifier, Path, Path]:
        evidence_dir = root / "evidence"
        chain_dir = root / "chain"
        anchor_dir = root / "anchors"
        processor = CheckpointProcessor(
            evidence_orchestrator=EvidenceOrchestrator(
                evidence_store=OffchainEvidenceStore(evidence_dir),
                chain_builder=ProofChainBuilder(chain_dir),
                signer_id="verification-test-signer",
            ),
            checkpoint_controller=CheckpointController(),
            anchor_adapter=BlockchainAnchorAdapter(anchor_dir),
        )
        events = [
            self._event(EventType.DTD_UPDATE, 1, payload={"component": "dtd"}),
            self._event(
                EventType.AF_VALIDATED_OUTPUT,
                2,
                metadata={"criticality": 0.1, "fidelity_score": 0.9},
                payload={"prediction": "nominal"},
            ),
            self._event(
                EventType.LIFECYCLE_EVENT,
                3,
                metadata={"claim": "synchronized", "fidelity_score": 0.95},
                payload={"claim": "synchronized"},
            ),
        ]
        context = TwinContext(
            twin_id="twin-verify",
            lifecycle_state=LifecycleState.OPERATION,
            domain="test",
            asset_type="demo-asset",
        )

        proof_ids = [
            processor.process_event(event, context).proof.proof_id
            for event in events
        ]
        verifier = ProofVerifier(
            evidence_store=OffchainEvidenceStore(evidence_dir),
            anchor_adapter=BlockchainAnchorAdapter(anchor_dir),
            synchronized_fidelity_threshold=0.8,
        )
        return proof_ids, verifier, evidence_dir, anchor_dir

    def test_clean_single_proof_verification_passes(self):
        with TemporaryDirectory() as tmpdir:
            proof_ids, verifier, _, _ = self._dataset(Path(tmpdir))

            result = verifier.verify_single_proof("twin-verify", proof_ids[0])

            self.assertEqual(result.status, VerificationStatus.OK)
            self.assertTrue(result.ok)

    def test_clean_chain_verification_passes(self):
        with TemporaryDirectory() as tmpdir:
            _, verifier, _, _ = self._dataset(Path(tmpdir))

            summary = verifier.verify_all_for_twin("twin-verify")

            self.assertEqual(summary.total_proofs_checked, 3)
            self.assertEqual(summary.failed_count, 0)
            self.assertEqual(summary.passed_count, 3)

    def test_tampered_payload_is_detected(self):
        with TemporaryDirectory() as tmpdir:
            proof_ids, verifier, evidence_dir, _ = self._dataset(Path(tmpdir))
            tamper_proof_payload(evidence_dir, "twin-verify", proof_ids[0])

            result = verifier.verify_single_proof("twin-verify", proof_ids[0])

            self.assertEqual(result.status, VerificationStatus.PAYLOAD_HASH_MISMATCH)

    def test_tampered_prev_anchor_is_detected(self):
        with TemporaryDirectory() as tmpdir:
            proof_ids, verifier, evidence_dir, _ = self._dataset(Path(tmpdir))
            tamper_prev_anchor(evidence_dir, "twin-verify", proof_ids[2])

            results = verifier.verify_twin_chain("twin-verify")

            self.assertIn(
                VerificationStatus.PREV_ANCHOR_MISMATCH,
                {result.status for result in results if result.proof_id == proof_ids[2]},
            )

    def test_tampered_sequence_is_detected(self):
        with TemporaryDirectory() as tmpdir:
            proof_ids, verifier, evidence_dir, _ = self._dataset(Path(tmpdir))
            tamper_sequence(evidence_dir, "twin-verify", proof_ids[2], 1)

            results = verifier.verify_twin_chain("twin-verify")

            self.assertIn(
                VerificationStatus.CHAIN_SEQUENCE_ERROR,
                {result.status for result in results if result.proof_id == proof_ids[2]},
            )

    def test_fake_synchronized_claim_is_detected(self):
        with TemporaryDirectory() as tmpdir:
            proof_ids, verifier, evidence_dir, _ = self._dataset(Path(tmpdir))
            tamper_lifecycle_claim(evidence_dir, "twin-verify", proof_ids[2], 0.1)

            result = verifier.verify_single_proof("twin-verify", proof_ids[2])

            self.assertEqual(
                result.status,
                VerificationStatus.POLICY_CLAIM_INCONSISTENCY,
            )

    def test_missing_anchor_is_detected(self):
        with TemporaryDirectory() as tmpdir:
            proof_ids, verifier, _, anchor_dir = self._dataset(Path(tmpdir))
            proof = verifier.evidence_store.load_proof(proof_ids[0], "twin-verify")
            remove_anchor_record(anchor_dir, "twin-verify", proof.anchor_digest)

            result = verifier.verify_single_proof("twin-verify", proof_ids[0])

            self.assertEqual(result.status, VerificationStatus.ANCHOR_NOT_FOUND)

    def test_cli_run_verification_demo_runs(self):
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
                            "default_signer_id": "verification-cli-signer",
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
                            "default_twin_id": "verification-demo-twin",
                            "event_count": 3,
                            "random_seed": 42,
                            "critical_event_probability": 0.2,
                        },
                        "verification": {
                            "synchronized_fidelity_threshold": 0.8,
                            "verification_strict_mode": True,
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
                    ["--config", str(config_path), "run-verification-demo"]
                )

            output = stream.getvalue()
            self.assertEqual(exit_code, 0)
            self.assertIn("Verification demo:", output)
            self.assertIn("payload_hash_mismatch", output)
            self.assertIn("policy_claim_inconsistency", output)
