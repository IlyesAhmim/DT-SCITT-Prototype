"""Data model for proof verification results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from dt_trust_checkpoints.models.enums import VerificationStatus


@dataclass(slots=True)
class VerificationResult:
    """Outcome of verifying a proof envelope and related evidence."""

    proof_id: str
    status: VerificationStatus
    reason: str
    ok: bool = False
    twin_id: str | None = None
    anchor_digest: str | None = None
    message: str | None = None
    error_code: str | None = None
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    checks: dict[str, bool] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class VerificationSummary:
    """Aggregate verification report for all proofs of a twin."""

    twin_id: str
    total_proofs_checked: int
    passed_count: int
    failed_count: int
    failure_categories: dict[str, int] = field(default_factory=dict)
    proof_ids_by_status: dict[str, list[str]] = field(default_factory=dict)
    results: list[VerificationResult] = field(default_factory=list)
