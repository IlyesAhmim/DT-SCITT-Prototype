"""Data model for event checkpoint policy decisions."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from dt_trust_checkpoints.models.enums import CheckpointMode, ProofType


@dataclass(slots=True)
class PolicyDecision:
    """Decision produced by the critical event policy layer."""

    event_id: str
    twin_id: str
    is_critical: bool
    checkpoint_mode: CheckpointMode
    rationale: str
    allowed: bool = True
    blocked: bool = False
    requires_anchor: bool = True
    reason: str | None = None
    policy_rule_id: str | None = None
    policy_source: str = "local-default-policy"
    required_proof_types: list[ProofType] = field(default_factory=list)
    decided_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, str] = field(default_factory=dict)
