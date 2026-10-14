"""High-level local trust checkpoint processing flow."""

from __future__ import annotations

from dataclasses import dataclass

from dt_trust_checkpoints.core.checkpoint_controller import CheckpointController
from dt_trust_checkpoints.core.evidence_orchestrator import EvidenceOrchestrator
from dt_trust_checkpoints.models import (
    AnchorRecord,
    CheckpointMode,
    Event,
    PolicyDecision,
    ProofEnvelope,
    TwinContext,
)
from dt_trust_checkpoints.storage.blockchain_anchor_adapter import BlockchainAnchorAdapter


@dataclass(frozen=True, slots=True)
class CheckpointProcessingResult:
    """Result of proof construction plus local trust checkpoint processing."""

    proof: ProofEnvelope
    decision: PolicyDecision
    anchor: AnchorRecord | None
    offchain_ref: str
    status: str


class CheckpointProcessor:
    """Coordinate proof construction, trust-gate decisions, and local anchoring."""

    def __init__(
        self,
        evidence_orchestrator: EvidenceOrchestrator,
        checkpoint_controller: CheckpointController,
        anchor_adapter: BlockchainAnchorAdapter,
    ) -> None:
        self.evidence_orchestrator = evidence_orchestrator
        self.checkpoint_controller = checkpoint_controller
        self.anchor_adapter = anchor_adapter

    def process_event(
        self, event: Event, twin_context: TwinContext | None = None
    ) -> CheckpointProcessingResult:
        """Build a proof, decide checkpoint mode, and anchor when allowed."""
        proof_result = self.evidence_orchestrator.create_proof(event, twin_context)
        proof = proof_result.proof
        decision = self.checkpoint_controller.decide(event, proof, twin_context)
        proof.metadata.update(
            {
                "checkpoint_mode": decision.checkpoint_mode.value,
                "policy_allowed": str(decision.allowed).lower(),
                "policy_blocked": str(decision.blocked).lower(),
                "requires_anchor": str(decision.requires_anchor).lower(),
                "policy_rule_id": decision.policy_rule_id or "",
            }
        )
        self.evidence_orchestrator.evidence_store.save_proof(proof)

        if decision.blocked or decision.checkpoint_mode is CheckpointMode.REJECT:
            return CheckpointProcessingResult(
                proof=proof,
                decision=decision,
                anchor=None,
                offchain_ref=proof_result.offchain_ref,
                status="rejected",
            )

        if not decision.requires_anchor:
            return CheckpointProcessingResult(
                proof=proof,
                decision=decision,
                anchor=None,
                offchain_ref=proof_result.offchain_ref,
                status="no_anchor_required",
            )

        anchor = self.anchor_adapter.submit_anchor(
            AnchorRecord(
                proof_id=proof.proof_id,
                twin_id=proof.twin_id,
                checkpoint_mode=decision.checkpoint_mode,
                anchor_digest=proof.anchor_digest or proof.canonical_hash,
                proof_type=proof.proof_type,
                event_type=proof.event_type,
                seq=proof.seq,
                timestamp=proof.timestamp,
                payload_hash=proof.payload_hash,
                prev_anchor=proof.prev_anchor,
                offchain_ref=proof.offchain_ref,
                metadata={
                    "policy_rule_id": decision.policy_rule_id or "",
                    "policy_reason": decision.reason or decision.rationale,
                },
            )
        )

        status = (
            "sync_attested"
            if decision.checkpoint_mode is CheckpointMode.SYNC
            else "async_anchor_submitted"
        )
        return CheckpointProcessingResult(
            proof=proof,
            decision=decision,
            anchor=anchor,
            offchain_ref=proof_result.offchain_ref,
            status=status,
        )
