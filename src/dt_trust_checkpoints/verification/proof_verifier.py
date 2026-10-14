"""Local proof verifier for trust checkpoint artifacts.

The verifier is deterministic and filesystem-local. It checks the relationship
between stored proof envelopes, canonical payloads, mock signatures, local anchor
records, and per-twin chain linkage. It does not contact a real blockchain.
"""

from __future__ import annotations

import json
from typing import Any

from dt_trust_checkpoints.core.canonicalization_service import canonicalize_to_bytes
from dt_trust_checkpoints.core.hashing_signature_service import (
    MOCK_SIGNATURE_SCHEME,
    sha256_hex,
    sign_digest,
)
from dt_trust_checkpoints.models import (
    AnchorRecord,
    EventType,
    LifecycleState,
    ProofEnvelope,
    VerificationResult,
    VerificationStatus,
    VerificationSummary,
)
from dt_trust_checkpoints.storage.blockchain_anchor_adapter import BlockchainAnchorAdapter
from dt_trust_checkpoints.storage.offchain_evidence_store import OffchainEvidenceStore


def build_anchor_material(proof: ProofEnvelope) -> dict[str, Any]:
    """Return the canonical anchor material used by proof construction."""
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


class ProofVerifier:
    """Verify locally stored proof envelopes and mock anchor records."""

    def __init__(
        self,
        evidence_store: OffchainEvidenceStore | None = None,
        anchor_adapter: BlockchainAnchorAdapter | None = None,
        *,
        synchronized_fidelity_threshold: float = 0.8,
        strict_mode: bool = True,
    ) -> None:
        self.evidence_store = evidence_store or OffchainEvidenceStore()
        self.anchor_adapter = anchor_adapter or BlockchainAnchorAdapter()
        self.synchronized_fidelity_threshold = synchronized_fidelity_threshold
        self.strict_mode = strict_mode

    def verify_single_proof(self, twin_id: str, proof_id: str) -> VerificationResult:
        """Verify one stored proof envelope and its expected anchor record."""
        proof = self._load_proof_or_none(twin_id, proof_id)
        if proof is None:
            return self._result(
                VerificationStatus.PROOF_NOT_FOUND,
                proof_id=proof_id,
                twin_id=twin_id,
                message="Proof file was not found in the local evidence store.",
            )

        material_result = self._verify_proof_material(proof)
        if not material_result.ok:
            return material_result

        semantic_result = self._verify_lifecycle_claim_consistency(proof)
        if not semantic_result.ok:
            return semantic_result

        anchor_result = self.verify_anchor_consistency(twin_id, proof_id)
        if not anchor_result.ok:
            return anchor_result

        return self._result(
            VerificationStatus.OK,
            proof_id=proof.proof_id,
            twin_id=proof.twin_id,
            anchor_digest=proof.anchor_digest,
            message="Proof, signature, anchor digest, and anchor record are consistent.",
            checks={
                "proof_found": True,
                "payload_hash": True,
                "signature": True,
                "anchor_digest": True,
                "anchor_record": True,
            },
        )

    def verify_anchor_consistency(
        self, twin_id: str, proof_id: str
    ) -> VerificationResult:
        """Verify that the expected local anchor record matches a proof."""
        proof = self._load_proof_or_none(twin_id, proof_id)
        if proof is None:
            return self._result(
                VerificationStatus.PROOF_NOT_FOUND,
                proof_id=proof_id,
                twin_id=twin_id,
                message="Proof file was not found before anchor consistency check.",
            )

        if not self._anchor_expected(proof):
            return self._result(
                VerificationStatus.OK,
                proof_id=proof.proof_id,
                twin_id=proof.twin_id,
                anchor_digest=proof.anchor_digest,
                message="No anchor is expected for this proof according to policy metadata.",
                checks={"anchor_expected": False},
            )

        if proof.anchor_digest is None:
            return self._result(
                VerificationStatus.ANCHOR_DIGEST_MISMATCH,
                proof_id=proof.proof_id,
                twin_id=proof.twin_id,
                message="Proof does not contain an anchor digest.",
            )

        anchor = self.anchor_adapter.load_anchor(proof.anchor_digest, twin_id)
        if anchor is None:
            return self._result(
                VerificationStatus.ANCHOR_NOT_FOUND,
                proof_id=proof.proof_id,
                twin_id=proof.twin_id,
                anchor_digest=proof.anchor_digest,
                message="Expected local anchor record was not found.",
            )

        mismatches = self._anchor_mismatches(proof, anchor)
        if mismatches:
            return self._result(
                VerificationStatus.ANCHOR_DIGEST_MISMATCH,
                proof_id=proof.proof_id,
                twin_id=proof.twin_id,
                anchor_digest=proof.anchor_digest,
                message="Local anchor record does not match the proof envelope.",
                details={"mismatches": mismatches},
            )

        if anchor.order_index <= 0 or not anchor.tx_ref:
            return self._result(
                VerificationStatus.ORDER_INDEX_ERROR,
                proof_id=proof.proof_id,
                twin_id=proof.twin_id,
                anchor_digest=proof.anchor_digest,
                message="Local anchor record has invalid ordering metadata.",
                details={"order_index": anchor.order_index, "tx_ref": anchor.tx_ref},
            )

        return self._result(
            VerificationStatus.OK,
            proof_id=proof.proof_id,
            twin_id=proof.twin_id,
            anchor_digest=proof.anchor_digest,
            message="Local anchor record matches the proof envelope.",
            checks={"anchor_record": True, "order_index": True},
        )

    def verify_twin_chain(self, twin_id: str) -> list[VerificationResult]:
        """Verify all proofs for a twin plus sequence and prev-anchor linkage."""
        proofs = self._load_proofs_for_twin(twin_id)
        results = [
            self.verify_single_proof(twin_id, proof.proof_id)
            for proof in proofs
        ]

        sorted_proofs = sorted(proofs, key=lambda proof: (proof.seq, proof.timestamp))
        previous_anchor: str | None = None
        expected_seq = 1
        for proof in sorted_proofs:
            if proof.seq != expected_seq:
                results.append(
                    self._result(
                        VerificationStatus.CHAIN_SEQUENCE_ERROR,
                        proof_id=proof.proof_id,
                        twin_id=proof.twin_id,
                        anchor_digest=proof.anchor_digest,
                        message=(
                            f"Expected sequence {expected_seq}, found {proof.seq}."
                        ),
                        details={
                            "expected_seq": expected_seq,
                            "observed_seq": proof.seq,
                        },
                    )
                )

            if proof.prev_anchor != previous_anchor:
                results.append(
                    self._result(
                        VerificationStatus.PREV_ANCHOR_MISMATCH,
                        proof_id=proof.proof_id,
                        twin_id=proof.twin_id,
                        anchor_digest=proof.anchor_digest,
                        message="Previous-anchor linkage is inconsistent.",
                        details={
                            "expected_prev_anchor": previous_anchor,
                            "observed_prev_anchor": proof.prev_anchor,
                        },
                    )
                )

            previous_anchor = proof.anchor_digest
            expected_seq += 1

        results.extend(self._verify_anchor_ordering(twin_id))
        return results

    def verify_all_for_twin(self, twin_id: str) -> VerificationSummary:
        """Return an aggregate verification summary for one twin."""
        proof_ids = self.evidence_store.list_proofs(twin_id)
        results = self.verify_twin_chain(twin_id)
        failed_proof_ids = {
            result.proof_id
            for result in results
            if not result.ok and result.proof_id
        }
        failure_categories: dict[str, int] = {}
        proof_ids_by_status: dict[str, list[str]] = {}

        for result in results:
            status = result.status.value
            proof_ids_by_status.setdefault(status, []).append(result.proof_id)
            if not result.ok:
                failure_categories[status] = failure_categories.get(status, 0) + 1

        return VerificationSummary(
            twin_id=twin_id,
            total_proofs_checked=len(proof_ids),
            passed_count=len(proof_ids) - len(failed_proof_ids),
            failed_count=len(failed_proof_ids),
            failure_categories=failure_categories,
            proof_ids_by_status=proof_ids_by_status,
            results=results,
        )

    def verify(self, proof: ProofEnvelope) -> VerificationResult:
        """Verify an in-memory proof envelope without requiring local storage."""
        material_result = self._verify_proof_material(proof)
        if not material_result.ok:
            return material_result
        return self._verify_lifecycle_claim_consistency(proof)

    def _verify_proof_material(self, proof: ProofEnvelope) -> VerificationResult:
        expected_payload_hash = sha256_hex(proof.canonical_payload or "")
        if proof.payload_hash != expected_payload_hash or proof.canonical_hash != proof.payload_hash:
            return self._result(
                VerificationStatus.PAYLOAD_HASH_MISMATCH,
                proof_id=proof.proof_id,
                twin_id=proof.twin_id,
                anchor_digest=proof.anchor_digest,
                message="Canonical payload hash does not match stored payload_hash.",
                details={
                    "expected_payload_hash": expected_payload_hash,
                    "observed_payload_hash": proof.payload_hash,
                    "canonical_hash": proof.canonical_hash,
                },
            )

        signer_id = proof.signer_id
        signature_scheme = proof.signature_metadata.get("signature_scheme")
        metadata_signer = proof.signature_metadata.get("signer_id")
        expected_signature = (
            sign_digest(proof.payload_hash, signer_id)
            if proof.payload_hash and signer_id
            else None
        )
        if (
            not signer_id
            or metadata_signer != signer_id
            or signature_scheme != MOCK_SIGNATURE_SCHEME
            or proof.signature != expected_signature
        ):
            return self._result(
                VerificationStatus.SIGNATURE_MISMATCH,
                proof_id=proof.proof_id,
                twin_id=proof.twin_id,
                anchor_digest=proof.anchor_digest,
                message="Mock signature or signature metadata does not match.",
                details={
                    "expected_signature": expected_signature,
                    "observed_signature": proof.signature,
                    "expected_scheme": MOCK_SIGNATURE_SCHEME,
                    "observed_scheme": signature_scheme,
                    "expected_signer_id": signer_id,
                    "metadata_signer_id": metadata_signer,
                },
            )

        expected_anchor_digest = sha256_hex(
            canonicalize_to_bytes(build_anchor_material(proof))
        )
        if proof.anchor_digest != expected_anchor_digest:
            return self._result(
                VerificationStatus.ANCHOR_DIGEST_MISMATCH,
                proof_id=proof.proof_id,
                twin_id=proof.twin_id,
                anchor_digest=proof.anchor_digest,
                message="Anchor digest does not match recomputed proof anchor material.",
                details={
                    "expected_anchor_digest": expected_anchor_digest,
                    "observed_anchor_digest": proof.anchor_digest,
                },
            )

        return self._result(
            VerificationStatus.OK,
            proof_id=proof.proof_id,
            twin_id=proof.twin_id,
            anchor_digest=proof.anchor_digest,
            message="Proof material is internally consistent.",
            checks={"payload_hash": True, "signature": True, "anchor_digest": True},
        )

    def _verify_lifecycle_claim_consistency(
        self, proof: ProofEnvelope
    ) -> VerificationResult:
        document = self._canonical_payload_document(proof)
        event = document.get("event", {}) if isinstance(document, dict) else {}
        twin_context = (
            document.get("twin_context", {}) if isinstance(document, dict) else {}
        )
        if not isinstance(event, dict):
            event = {}
        if not isinstance(twin_context, dict):
            twin_context = {}

        if proof.event_type is not EventType.LIFECYCLE_EVENT:
            return self._ok_policy_result(proof)

        event_state = str(event.get("lifecycle_state", "")).lower()
        context_state = str(twin_context.get("lifecycle_state", "")).lower()
        if LifecycleState.OUT_OF_SYNC.value in {event_state, context_state}:
            return self._ok_policy_result(proof)

        claim = self._lifecycle_claim(event, twin_context)
        if claim != LifecycleState.SYNCHRONIZED.value:
            return self._ok_policy_result(proof)

        fidelity = self._fidelity_score(event, proof)
        if fidelity is None or fidelity < self.synchronized_fidelity_threshold:
            return self._result(
                VerificationStatus.POLICY_CLAIM_INCONSISTENCY,
                proof_id=proof.proof_id,
                twin_id=proof.twin_id,
                anchor_digest=proof.anchor_digest,
                message=(
                    "Synchronized lifecycle claim lacks sufficient fidelity evidence."
                ),
                details={
                    "claim": claim,
                    "fidelity_score": fidelity,
                    "threshold": self.synchronized_fidelity_threshold,
                },
            )

        return self._ok_policy_result(proof)

    def _ok_policy_result(self, proof: ProofEnvelope) -> VerificationResult:
        return self._result(
            VerificationStatus.OK,
            proof_id=proof.proof_id,
            twin_id=proof.twin_id,
            anchor_digest=proof.anchor_digest,
            message="Lifecycle policy claim check passed.",
            checks={"policy_claim": True},
        )

    def _verify_anchor_ordering(self, twin_id: str) -> list[VerificationResult]:
        anchors = self.anchor_adapter.list_anchors(twin_id)
        results: list[VerificationResult] = []
        previous_order = 0
        for anchor in anchors:
            if anchor.order_index <= previous_order or anchor.order_index <= 0:
                results.append(
                    self._result(
                        VerificationStatus.ORDER_INDEX_ERROR,
                        proof_id=anchor.proof_id,
                        twin_id=anchor.twin_id,
                        anchor_digest=anchor.anchor_digest,
                        message="Anchor registry order_index is not strictly increasing.",
                        details={
                            "previous_order_index": previous_order,
                            "observed_order_index": anchor.order_index,
                        },
                    )
                )
            previous_order = anchor.order_index
        return results

    def _load_proof_or_none(
        self, twin_id: str, proof_id: str
    ) -> ProofEnvelope | None:
        try:
            return self.evidence_store.load_proof(proof_id, twin_id)
        except FileNotFoundError:
            return None

    def _load_proofs_for_twin(self, twin_id: str) -> list[ProofEnvelope]:
        proofs: list[ProofEnvelope] = []
        for proof_id in self.evidence_store.list_proofs(twin_id):
            proof = self._load_proof_or_none(twin_id, proof_id)
            if proof is not None:
                proofs.append(proof)
        return proofs

    def _anchor_expected(self, proof: ProofEnvelope) -> bool:
        requires_anchor = proof.metadata.get("requires_anchor")
        if isinstance(requires_anchor, str):
            return requires_anchor.lower() == "true"
        if requires_anchor is not None:
            return bool(requires_anchor)

        checkpoint_mode = str(proof.metadata.get("checkpoint_mode", "")).lower()
        if checkpoint_mode == "reject":
            return False
        return self.strict_mode

    def _anchor_mismatches(
        self, proof: ProofEnvelope, anchor: AnchorRecord
    ) -> dict[str, dict[str, Any]]:
        pairs = {
            "proof_id": (proof.proof_id, anchor.proof_id),
            "twin_id": (proof.twin_id, anchor.twin_id),
            "anchor_digest": (proof.anchor_digest, anchor.anchor_digest),
            "proof_type": (proof.proof_type, anchor.proof_type),
            "event_type": (proof.event_type, anchor.event_type),
            "seq": (proof.seq, anchor.seq),
            "payload_hash": (proof.payload_hash, anchor.payload_hash),
            "prev_anchor": (proof.prev_anchor, anchor.prev_anchor),
            "offchain_ref": (proof.offchain_ref, anchor.offchain_ref),
        }
        return {
            field: {"proof": proof_value, "anchor": anchor_value}
            for field, (proof_value, anchor_value) in pairs.items()
            if proof_value != anchor_value
        }

    def _canonical_payload_document(self, proof: ProofEnvelope) -> dict[str, Any]:
        if not proof.canonical_payload:
            return {}
        try:
            document = json.loads(proof.canonical_payload)
        except json.JSONDecodeError:
            return {}
        return document if isinstance(document, dict) else {}

    def _lifecycle_claim(
        self, event: dict[str, Any], twin_context: dict[str, Any]
    ) -> str:
        metadata = event.get("metadata", {})
        payload = event.get("payload", {})
        if not isinstance(metadata, dict):
            metadata = {}
        if not isinstance(payload, dict):
            payload = {}

        claim = (
            metadata.get("lifecycle_claim")
            or metadata.get("claim")
            or payload.get("claim")
            or payload.get("status")
            or event.get("lifecycle_state")
            or twin_context.get("lifecycle_state")
            or ""
        )
        return str(claim).lower()

    def _fidelity_score(
        self, event: dict[str, Any], proof: ProofEnvelope
    ) -> float | None:
        metadata = event.get("metadata", {})
        payload = event.get("payload", {})
        if not isinstance(metadata, dict):
            metadata = {}
        if not isinstance(payload, dict):
            payload = {}

        value = (
            metadata.get("fidelity_score")
            if metadata.get("fidelity_score") is not None
            else payload.get("fidelity_score", proof.metadata.get("fidelity_score"))
        )
        if value is None:
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _result(
        self,
        status: VerificationStatus,
        *,
        proof_id: str,
        message: str,
        twin_id: str | None = None,
        anchor_digest: str | None = None,
        checks: dict[str, bool] | None = None,
        details: dict[str, Any] | None = None,
    ) -> VerificationResult:
        ok = status is VerificationStatus.OK or status is VerificationStatus.VALID
        return VerificationResult(
            proof_id=proof_id,
            status=status,
            reason=message,
            ok=ok,
            twin_id=twin_id,
            anchor_digest=anchor_digest,
            message=message,
            error_code=None if ok else status.value,
            checks=checks or {},
            details=details or {},
        )
