"""Local JSON off-chain evidence storage."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from dt_trust_checkpoints.core.canonicalization_service import to_json_compatible
from dt_trust_checkpoints.models import EventType, ProofEnvelope, ProofType


class OffchainEvidenceStore:
    """File-based store for proof envelopes.

    Proofs are stored as JSON under ``<evidence_dir>/<twin_id>/<proof_id>.json``.
    This local store is intentionally simple and should later be replaced or
    wrapped by a stronger evidence-retention backend.
    """

    def __init__(self, evidence_dir: str | Path = "outputs/evidence") -> None:
        self.evidence_dir = Path(evidence_dir)

    def _proof_path(self, proof_id: str, twin_id: str) -> Path:
        return self.evidence_dir / twin_id / f"{proof_id}.json"

    def proof_path(self, proof: ProofEnvelope) -> Path:
        """Return the filesystem path for a proof envelope."""
        return self._proof_path(proof.proof_id, proof.twin_id)

    def reference_for(self, proof: ProofEnvelope) -> str:
        """Return the local off-chain reference for a proof envelope."""
        return str(self.proof_path(proof))

    def save_proof(self, proof: ProofEnvelope) -> str:
        """Persist a proof envelope and return its local off-chain reference."""
        path = self.proof_path(proof)
        path.parent.mkdir(parents=True, exist_ok=True)

        if proof.offchain_ref is None:
            proof.offchain_ref = str(path)

        path.write_text(
            json.dumps(to_json_compatible(proof), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return str(path)

    def load_proof(self, proof_id: str, twin_id: str) -> ProofEnvelope:
        """Load a proof envelope from local JSON storage."""
        path = self._proof_path(proof_id, twin_id)
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("Stored proof must be a JSON object.")

        return _proof_from_dict(raw)

    def list_proofs(self, twin_id: str) -> list[str]:
        """List proof identifiers stored for a twin."""
        twin_dir = self.evidence_dir / twin_id
        if not twin_dir.exists():
            return []
        return sorted(path.stem for path in twin_dir.glob("*.json"))

    def put(self, evidence: Mapping[str, Any]) -> str:
        """Persist evidence and return an evidence reference."""
        proof = evidence.get("proof")
        if isinstance(proof, ProofEnvelope):
            return self.save_proof(proof)

        raise TypeError("OffchainEvidenceStore.put currently expects {'proof': ProofEnvelope}.")


def _parse_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value))


def _proof_from_dict(data: dict[str, Any]) -> ProofEnvelope:
    proof = ProofEnvelope(
        proof_type=ProofType(str(data["proof_type"])),
        subject_event_id=str(data["subject_event_id"]),
        twin_id=str(data["twin_id"]),
        canonical_hash=str(data["canonical_hash"]),
        event_type=(
            EventType(str(data["event_type"]))
            if data.get("event_type") is not None
            else None
        ),
        seq=int(data.get("seq", 0)),
        timestamp=_parse_datetime(data["timestamp"]),
        payload_hash=data.get("payload_hash"),
        canonical_payload=data.get("canonical_payload"),
        evidence_refs=list(data.get("evidence_refs", [])),
        previous_proof_id=data.get("previous_proof_id"),
        prev_anchor=data.get("prev_anchor"),
        signer_id=data.get("signer_id"),
        signature=data.get("signature"),
        signature_metadata=dict(data.get("signature_metadata", {})),
        anchor_digest=data.get("anchor_digest"),
        offchain_ref=data.get("offchain_ref"),
        anchor_id=data.get("anchor_id"),
        created_at=_parse_datetime(data["created_at"]),
        proof_id=str(data["proof_id"]),
        metadata=dict(data.get("metadata", {})),
    )
    return proof
