"""Minimal tests for core dataclass models."""

from unittest import TestCase

from dt_trust_checkpoints.models import (
    AnchorRecord,
    CheckpointMode,
    Event,
    EventType,
    LifecycleState,
    PolicyDecision,
    ProofEnvelope,
    ProofType,
    TwinContext,
    VerificationResult,
    VerificationStatus,
)


class ModelTests(TestCase):
    """Model instantiation tests."""

    def test_basic_model_instantiation(self):
        context = TwinContext(
            twin_id="twin-001",
            lifecycle_state=LifecycleState.OPERATION,
            domain="manufacturing",
            asset_type="robot-cell",
        )
        event = Event(
            twin_id=context.twin_id,
            event_type=EventType.SENSOR_READING,
            source="simulator",
            payload={"temperature": 42.0},
        )
        decision = PolicyDecision(
            event_id=event.event_id,
            twin_id=event.twin_id,
            is_critical=True,
            checkpoint_mode=CheckpointMode.SYNC,
            rationale="Synthetic critical event for smoke testing.",
            required_proof_types=[ProofType.CANONICAL_HASH],
        )
        proof = ProofEnvelope(
            proof_type=ProofType.CANONICAL_HASH,
            subject_event_id=event.event_id,
            twin_id=event.twin_id,
            canonical_hash="abc123",
            evidence_refs=["offchain://evidence/abc123"],
        )
        anchor = AnchorRecord(
            proof_id=proof.proof_id,
            twin_id=proof.twin_id,
            checkpoint_mode=decision.checkpoint_mode,
            anchor_digest=proof.canonical_hash,
        )
        result = VerificationResult(
            proof_id=proof.proof_id,
            status=VerificationStatus.INCONCLUSIVE,
            reason="Verifier not implemented in step 1.",
        )

        self.assertEqual(event.twin_id, "twin-001")
        self.assertTrue(decision.is_critical)
        self.assertEqual(proof.subject_event_id, event.event_id)
        self.assertEqual(anchor.anchor_digest, "abc123")
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
