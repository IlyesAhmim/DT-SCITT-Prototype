"""Classification of events: evidence relevance, well-formedness, checkpoint rule.

Routine sensor readings are not evidence-relevant. Every other event is checked
against the fields its category requires; a malformed event is rejected, which
leaves a rejection record in the chain. Well-formed events receive the mode and
rule of the existing :class:`CheckpointController` policy, so the overlay
applies exactly the policy described for the original prototype.
"""

from __future__ import annotations

from dataclasses import dataclass

from dt_trust_checkpoints.core.checkpoint_controller import CheckpointController
from dt_trust_checkpoints.models import Event


REQUIRED_PAYLOAD_FIELDS: dict[str, tuple[str, ...]] = {
    "dtd_update": ("component", "version", "change", "description"),
    "dts_transition": ("from", "to", "state_version", "state"),
    "af_validated_output": ("prediction", "confidence", "af_score", "validation"),
    "management_action": ("action", "mode", "actor"),
    "lifecycle_event": ("claim", "fidelity_score", "metrics"),
}
EVIDENCE_CATEGORIES = tuple(REQUIRED_PAYLOAD_FIELDS)
REJECTION_CATEGORY = "rejection"


@dataclass(frozen=True, slots=True)
class Classification:
    """Outcome of classifying one event."""

    relevant: bool
    mode: str
    rule: str
    reason: str


class EvidenceClassifier:
    """Decide whether an event becomes evidence and under which checkpoint."""

    def __init__(self, controller: CheckpointController, forced_mode: str | None = None) -> None:
        if forced_mode not in {None, "sync", "async"}:
            raise ValueError("forced_mode must be None, 'sync', or 'async'.")
        self.controller = controller
        self.forced_mode = forced_mode

    def classify(self, event: Event) -> Classification:
        """Return the classification of ``event``."""
        category = event.event_type.value
        required = REQUIRED_PAYLOAD_FIELDS.get(category)
        if required is None:
            return Classification(False, "none", "classifier.not_evidence", "Routine event.")
        missing = [name for name in required if name not in event.payload]
        if missing:
            return Classification(
                True, "reject", "reject.malformed", f"Missing required field '{missing[0]}'."
            )
        if self.forced_mode is not None:
            return Classification(
                True,
                self.forced_mode,
                f"experiment.forced_{self.forced_mode}",
                f"Experiment forces {self.forced_mode} checkpoints.",
            )
        mode, rule, reason = self.controller.select_mode(event)
        return Classification(True, mode.value, rule, reason)
