"""Data model for selective blockchain anchor records."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4

from dt_trust_checkpoints.models.enums import CheckpointMode, EventType, ProofType


@dataclass(slots=True)
class AnchorRecord:
    """A record describing a selectively anchored proof digest."""

    proof_id: str
    twin_id: str
    checkpoint_mode: CheckpointMode
    anchor_digest: str
    proof_type: ProofType | None = None
    event_type: EventType | None = None
    seq: int = 0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    payload_hash: str | None = None
    prev_anchor: str | None = None
    offchain_ref: str | None = None
    tx_ref: str | None = None
    order_index: int = 0
    backend: str = "unconfigured"
    transaction_ref: str | None = None
    anchored_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    anchor_id: str = field(default_factory=lambda: str(uuid4()))
    metadata: dict[str, str] = field(default_factory=dict)
