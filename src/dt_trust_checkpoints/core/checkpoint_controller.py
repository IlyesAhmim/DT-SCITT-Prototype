"""Policy-driven trust checkpoint decisions.

This module implements a deliberately small and deterministic local policy
layer. It decides whether a proof should be anchored asynchronously, handled as
a synchronous checkpoint, or rejected before anchoring.
"""

from __future__ import annotations

from typing import Any, Mapping

from dt_trust_checkpoints.config import CheckpointPolicyDefaults
from dt_trust_checkpoints.models import (
    CheckpointMode,
    Event,
    EventType,
    LifecycleState,
    PolicyDecision,
    ProofEnvelope,
    ProofType,
    TwinContext,
)


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return False


def _as_float(value: Any, default: float = 0.0) -> float:
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


class CheckpointController:
    """Apply local trust-gate policy rules to events and proof envelopes."""

    def __init__(
        self,
        policy: CheckpointPolicyDefaults | None = None,
        *,
        default_mode: CheckpointMode = CheckpointMode.ASYNC,
        critical_event_mode: CheckpointMode = CheckpointMode.SYNC,
        criticality_sync_threshold: float = 0.75,
        fidelity_sync_threshold: float = 0.5,
        reject_malformed_events: bool = True,
        event_type_default_modes: Mapping[str, CheckpointMode] | None = None,
        lifecycle_sync_claims: list[str] | None = None,
    ) -> None:
        if policy is not None:
            default_mode = policy.default_mode
            critical_event_mode = policy.critical_event_mode
            criticality_sync_threshold = policy.criticality_sync_threshold
            fidelity_sync_threshold = policy.fidelity_sync_threshold
            reject_malformed_events = policy.reject_malformed_events
            event_type_default_modes = policy.event_type_default_modes
            lifecycle_sync_claims = policy.lifecycle_sync_claims

        self.default_mode = default_mode
        self.critical_event_mode = critical_event_mode
        self.criticality_sync_threshold = criticality_sync_threshold
        self.fidelity_sync_threshold = fidelity_sync_threshold
        self.reject_malformed_events = reject_malformed_events
        self.event_type_default_modes = dict(event_type_default_modes or {})
        self.lifecycle_sync_claims = {
            value.lower() for value in (lifecycle_sync_claims or ["synchronized"])
        }

    def decide(
        self,
        event: Event,
        proof: ProofEnvelope,
        twin_context: TwinContext | None = None,
    ) -> PolicyDecision:
        """Return the checkpoint decision for an event/proof pair."""
        if self.is_rejected(event, proof):
            return self._decision(
                event=event,
                proof=proof,
                mode=CheckpointMode.REJECT,
                allowed=False,
                blocked=True,
                requires_anchor=False,
                reason="Rejected by malformed-event policy.",
                rule_id="reject.malformed",
            )

        mode, rule_id, reason = self._select_mode(event, proof, twin_context)
        return self._decision(
            event=event,
            proof=proof,
            mode=mode,
            allowed=mode is not CheckpointMode.REJECT,
            blocked=mode is CheckpointMode.REJECT,
            requires_anchor=mode in {CheckpointMode.ASYNC, CheckpointMode.SYNC},
            reason=reason,
            rule_id=rule_id,
        )

    def is_rejected(self, event: Event, proof: ProofEnvelope) -> bool:
        """Return whether an event/proof pair should be blocked before anchoring."""
        if not self.reject_malformed_events:
            return False

        metadata = event.metadata
        malformed_flag = _as_bool(metadata.get("malformed")) or _as_bool(
            metadata.get("reject")
        )
        invalid_flag = "valid" in metadata and not _as_bool(metadata.get("valid"))

        return bool(
            malformed_flag
            or invalid_flag
            or not event.twin_id
            or not event.event_id
            or proof.twin_id != event.twin_id
            or proof.subject_event_id != event.event_id
            or not proof.anchor_digest
        )

    def is_sync_required(
        self,
        event: Event,
        proof: ProofEnvelope,
        twin_context: TwinContext | None = None,
    ) -> bool:
        """Return whether the policy requires a synchronous checkpoint."""
        if self.is_rejected(event, proof):
            return False
        mode, _, _ = self._select_mode(event, proof, twin_context)
        return mode is CheckpointMode.SYNC

    def submit(self, decision: PolicyDecision) -> None:
        """Compatibility hook for later asynchronous scheduling implementations."""
        return None

    def select_mode(
        self, event: Event, twin_context: TwinContext | None = None
    ) -> tuple[CheckpointMode, str, str]:
        """Return the mode, rule identifier, and reason the policy assigns to an event.

        The rules only read the event, so no proof envelope is needed; this lets
        the evidence overlay decide the rule before building the proof object.
        """
        return self._select_mode(event, None, twin_context)  # type: ignore[arg-type]

    def _select_mode(
        self,
        event: Event,
        proof: ProofEnvelope,
        twin_context: TwinContext | None,
    ) -> tuple[CheckpointMode, str, str]:
        metadata = event.metadata
        criticality = self._criticality(metadata)
        fidelity = _as_float(metadata.get("fidelity_score"), default=1.0)

        if event.event_type is EventType.DTD_UPDATE:
            return (
                CheckpointMode.SYNC,
                "event.dtd_update.sync",
                "DTD update requires a synchronous trust checkpoint.",
            )

        if event.event_type in {EventType.DTS_TRANSITION, EventType.STATE_TRANSITION}:
            if (
                event.event_type is EventType.DTS_TRANSITION
                or _as_bool(metadata.get("critical_transition"))
                or criticality >= self.criticality_sync_threshold
            ):
                return (
                    CheckpointMode.SYNC,
                    "event.dts_transition.critical_sync",
                    "Critical DTS transition requires synchronous anchoring.",
                )

        if event.event_type is EventType.AF_VALIDATED_OUTPUT:
            if criticality >= self.criticality_sync_threshold:
                return (
                    CheckpointMode.SYNC,
                    "event.af_output.criticality_sync",
                    "AF validated output exceeds the criticality threshold.",
                )
            if fidelity < self.fidelity_sync_threshold:
                return (
                    CheckpointMode.SYNC,
                    "event.af_output.low_fidelity_sync",
                    "AF validated output is below the fidelity threshold.",
                )
            return (
                CheckpointMode.ASYNC,
                "event.af_output.default_async",
                "AF validated output is below synchronous risk thresholds.",
            )

        if event.event_type is EventType.MANAGEMENT_ACTION:
            if _as_bool(metadata.get("management_sensitive")):
                return (
                    CheckpointMode.SYNC,
                    "event.management.sensitive_sync",
                    "Sensitive management action requires synchronous anchoring.",
                )
            return (
                CheckpointMode.ASYNC,
                "event.management.default_async",
                "Management action is not marked sensitive.",
            )

        if event.event_type is EventType.LIFECYCLE_EVENT:
            if self._lifecycle_requires_sync(event, twin_context):
                return (
                    CheckpointMode.SYNC,
                    "event.lifecycle.sync_claim",
                    "Lifecycle state or synchronization claim requires sync.",
                )
            return (
                CheckpointMode.ASYNC,
                "event.lifecycle.default_async",
                "Lifecycle event does not require synchronous handling.",
            )

        if criticality >= self.criticality_sync_threshold:
            return (
                self.critical_event_mode,
                "event.generic.criticality_sync",
                "Event exceeds the configured criticality threshold.",
            )

        configured_mode = self.event_type_default_modes.get(
            event.event_type.value, self.default_mode
        )
        return (
            configured_mode,
            "event.default_mode",
            "Event follows the configured default checkpoint mode.",
        )

    def _lifecycle_requires_sync(
        self, event: Event, twin_context: TwinContext | None
    ) -> bool:
        if event.lifecycle_state in {
            LifecycleState.OUT_OF_SYNC,
            LifecycleState.SYNCHRONIZED,
        }:
            return True

        if twin_context is not None and twin_context.lifecycle_state in {
            LifecycleState.OUT_OF_SYNC,
            LifecycleState.SYNCHRONIZED,
        }:
            return True

        claim = str(
            event.metadata.get("lifecycle_claim", event.metadata.get("claim", ""))
        ).lower()
        return claim in self.lifecycle_sync_claims

    def _criticality(self, metadata: Mapping[str, Any]) -> float:
        return max(
            _as_float(metadata.get("criticality"), default=0.0),
            _as_float(metadata.get("criticality_level"), default=0.0),
            1.0 if _as_bool(metadata.get("critical")) else 0.0,
        )

    def _decision(
        self,
        *,
        event: Event,
        proof: ProofEnvelope,
        mode: CheckpointMode,
        allowed: bool,
        blocked: bool,
        requires_anchor: bool,
        reason: str,
        rule_id: str,
    ) -> PolicyDecision:
        return PolicyDecision(
            event_id=event.event_id,
            twin_id=event.twin_id,
            is_critical=mode is CheckpointMode.SYNC,
            checkpoint_mode=mode,
            rationale=reason,
            allowed=allowed,
            blocked=blocked,
            requires_anchor=requires_anchor,
            reason=reason,
            policy_rule_id=rule_id,
            required_proof_types=[proof.proof_type or ProofType.CANONICAL_HASH],
            metadata={
                "event_type": event.event_type.value,
                "proof_id": proof.proof_id,
            },
        )
