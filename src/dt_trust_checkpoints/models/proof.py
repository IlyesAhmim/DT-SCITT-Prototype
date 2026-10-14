"""Data model for proof envelopes."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4

from dt_trust_checkpoints.models.enums import EventType, ProofType


@dataclass(slots=True)
class ProofEnvelope:
    """A portable envelope containing proof metadata and evidence references."""

    proof_type: ProofType
    subject_event_id: str
    twin_id: str
    canonical_hash: str
    event_type: EventType | None = None
    seq: int = 0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    payload_hash: str | None = None
    canonical_payload: str | None = None
    evidence_refs: list[str] = field(default_factory=list)
    previous_proof_id: str | None = None
    prev_anchor: str | None = None
    signer_id: str | None = None
    signature: str | None = None
    signature_metadata: dict[str, str] = field(default_factory=dict)
    anchor_digest: str | None = None
    offchain_ref: str | None = None
    anchor_id: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    proof_id: str = field(default_factory=lambda: str(uuid4()))
    metadata: dict[str, str] = field(default_factory=dict)
