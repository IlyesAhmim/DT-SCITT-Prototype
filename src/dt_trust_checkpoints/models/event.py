"""Data model for Digital Twin events."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from dt_trust_checkpoints.models.enums import EventType, LifecycleState


@dataclass(slots=True)
class Event:
    """An observed event emitted by or about a Digital Twin."""

    twin_id: str
    event_type: EventType
    source: str
    payload: dict[str, Any] = field(default_factory=dict)
    lifecycle_state: LifecycleState = LifecycleState.OPERATION
    severity: float = 0.0
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_id: str = field(default_factory=lambda: str(uuid4()))
    metadata: dict[str, Any] = field(default_factory=dict)
