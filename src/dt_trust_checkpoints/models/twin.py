"""Data model for Digital Twin context."""

from __future__ import annotations

from dataclasses import dataclass, field

from dt_trust_checkpoints.models.enums import LifecycleState


@dataclass(slots=True)
class TwinContext:
    """Context needed to evaluate trust decisions for a Digital Twin."""

    twin_id: str
    lifecycle_state: LifecycleState
    domain: str
    asset_type: str
    owner: str | None = None
    trust_domain: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)
