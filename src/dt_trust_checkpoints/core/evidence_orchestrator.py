"""Evidence orchestration for local proof construction."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from dt_trust_checkpoints.core.canonicalization_service import (
    CanonicalizationService,
    canonicalize_to_bytes,
    canonicalize_to_json,
)
from dt_trust_checkpoints.core.hashing_signature_service import HashingSignatureService
from dt_trust_checkpoints.core.proof_chain_builder import ProofChainBuilder
from dt_trust_checkpoints.models import Event, ProofEnvelope, ProofType, TwinContext
from dt_trust_checkpoints.storage.offchain_evidence_store import OffchainEvidenceStore


@dataclass(frozen=True, slots=True)
class ProofConstructionResult:
    """Result returned by the proof construction orchestration step."""

    proof: ProofEnvelope
    offchain_ref: str


class EvidenceOrchestrator:
    """Coordinate canonicalization, hashing, signing, proof building, and storage."""

    def __init__(
        self,
        evidence_store: OffchainEvidenceStore | None = None,
        chain_builder: ProofChainBuilder | None = None,
        canonicalizer: CanonicalizationService | None = None,
        hashing_service: HashingSignatureService | None = None,
        proof_type: ProofType = ProofType.CANONICAL_HASH,
        signer_id: str = "local-demo-signer",
        canonicalization_version: str = "v0.1",
    ) -> None:
        self.evidence_store = evidence_store or OffchainEvidenceStore()
        self.chain_builder = chain_builder or ProofChainBuilder()
        self.canonicalizer = canonicalizer or CanonicalizationService()
        self.hashing_service = hashing_service or HashingSignatureService()
        self.proof_type = proof_type
        self.signer_id = signer_id
        self.canonicalization_version = canonicalization_version

    def _evidence_document(
        self, event: Event, context: TwinContext | None
    ) -> dict[str, Any]:
        return {
            "canonicalization_version": self.canonicalization_version,
            "event": event,
            "twin_context": context,
        }

    def _anchor_material(self, proof: ProofEnvelope) -> dict[str, Any]:
        return {
            "anchor_material_version": "v0.1",
            "proof_id": proof.proof_id,
            "proof_type": proof.proof_type,
            "twin_id": proof.twin_id,
            "subject_event_id": proof.subject_event_id,
            "event_type": proof.event_type,
            "seq": proof.seq,
            "payload_hash": proof.payload_hash,
            "prev_anchor": proof.prev_anchor,
            "signer_id": proof.signer_id,
            "signature": proof.signature,
        }

    def create_proof(
        self, event: Event, context: TwinContext | None = None
    ) -> ProofConstructionResult:
        """Create, persist, and locally chain a proof envelope for an event."""
        canonical_payload = canonicalize_to_json(self._evidence_document(event, context))
        payload_hash = self.hashing_service.sha256_hex(canonical_payload)
        signature = self.hashing_service.sign_digest(payload_hash, self.signer_id)
        prev_anchor = self.chain_builder.previous_anchor(event.twin_id)
        seq = self.chain_builder.next_sequence(event.twin_id)

        proof = self.chain_builder.build_proof(
            event=event,
            proof_type=self.proof_type,
            seq=seq,
            payload_hash=payload_hash,
            canonical_payload=canonical_payload,
            signer_id=self.signer_id,
            signature=signature,
            signature_metadata=self.hashing_service.signature_metadata(self.signer_id),
            prev_anchor=prev_anchor,
            metadata={
                "canonicalization_version": self.canonicalization_version,
                "payload_scope": "event-plus-optional-twin-context",
            },
        )

        proof.anchor_digest = self.hashing_service.sha256_hex(
            canonicalize_to_bytes(self._anchor_material(proof))
        )
        offchain_ref = self.evidence_store.save_proof(proof)
        proof.evidence_refs.append(offchain_ref)
        self.evidence_store.save_proof(proof)
        self.chain_builder.update_chain(event.twin_id, proof.anchor_digest)

        return ProofConstructionResult(proof=proof, offchain_ref=offchain_ref)

    def collect(
        self, event: Event, context: TwinContext | None = None
    ) -> ProofConstructionResult:
        """Compatibility alias for creating proof evidence from an event."""
        return self.create_proof(event, context)
