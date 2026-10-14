"""Shared enumerations for the Digital Twin trust checkpoint prototype."""

from __future__ import annotations

from enum import Enum


class EventType(str, Enum):
    """Kinds of Digital Twin events considered by the prototype."""

    SENSOR_READING = "sensor_reading"
    STATE_TRANSITION = "state_transition"
    CONTROL_ACTION = "control_action"
    ANOMALY = "anomaly"
    SECURITY_INCIDENT = "security_incident"
    POLICY_VIOLATION = "policy_violation"
    LIFECYCLE_EVENT = "lifecycle_event"
    DTD_UPDATE = "dtd_update"
    DTS_TRANSITION = "dts_transition"
    AF_VALIDATED_OUTPUT = "af_validated_output"
    MANAGEMENT_ACTION = "management_action"


class ProofType(str, Enum):
    """Proof construction strategies supported by the architecture."""

    CANONICAL_HASH = "canonical_hash"
    MERKLE_PROOF = "merkle_proof"
    SIGNED_ATTESTATION = "signed_attestation"
    COMPOSITE = "composite"


class CheckpointMode(str, Enum):
    """Checkpoint execution modes."""

    SYNC = "sync"
    ASYNC = "async"
    HYBRID = "hybrid"
    DISABLED = "disabled"
    REJECT = "reject"


class VerificationStatus(str, Enum):
    """Possible verification outcomes."""

    OK = "ok"
    VALID = "valid"
    INVALID = "invalid"
    INCONCLUSIVE = "inconclusive"
    UNSUPPORTED = "unsupported"
    PROOF_NOT_FOUND = "proof_not_found"
    ANCHOR_NOT_FOUND = "anchor_not_found"
    PAYLOAD_HASH_MISMATCH = "payload_hash_mismatch"
    SIGNATURE_MISMATCH = "signature_mismatch"
    ANCHOR_DIGEST_MISMATCH = "anchor_digest_mismatch"
    CHAIN_SEQUENCE_ERROR = "chain_sequence_error"
    PREV_ANCHOR_MISMATCH = "prev_anchor_mismatch"
    ORDER_INDEX_ERROR = "order_index_error"
    POLICY_CLAIM_INCONSISTENCY = "policy_claim_inconsistency"


class LifecycleState(str, Enum):
    """Digital Twin lifecycle states relevant to trust decisions."""

    DESIGN = "design"
    COMMISSIONING = "commissioning"
    OPERATION = "operation"
    MAINTENANCE = "maintenance"
    OUT_OF_SYNC = "out_of_sync"
    SYNCHRONIZED = "synchronized"
    DECOMMISSIONED = "decommissioned"
