"""Proof chain builder and local per-twin chain state management."""

from __future__ import annotations

import json
from pathlib import Path

from dt_trust_checkpoints.models import Event, PolicyDecision, ProofEnvelope, ProofType


class ProofChainBuilder:
    """Build proof envelopes and track local sequence/anchor state.

    The state manager is intentionally local and lightweight. It gives each
    ``twin_id`` a monotonically increasing proof sequence and remembers the last
    anchor digest so new proofs can link to the previous checkpoint material.
    """

    def __init__(self, state_dir: str | Path | None = None) -> None:
        self.state_dir = Path(state_dir) if state_dir is not None else None
        self.state_file = (
            self.state_dir / "chain_state.json" if self.state_dir is not None else None
        )
        self._state: dict[str, dict[str, int | str | None]] = {}
        self._load_state()

    def _load_state(self) -> None:
        if self.state_file is None or not self.state_file.exists():
            return

        raw = json.loads(self.state_file.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("Chain state file must contain a JSON object.")

        for twin_id, state in raw.items():
            if not isinstance(state, dict):
                continue
            self._state[str(twin_id)] = {
                "seq": int(state.get("seq", 0)),
                "last_anchor_digest": state.get("last_anchor_digest"),
            }

    def _persist_state(self) -> None:
        if self.state_file is None:
            return

        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(
            json.dumps(self._state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def _state_for(self, twin_id: str) -> dict[str, int | str | None]:
        if twin_id not in self._state:
            self._state[twin_id] = {"seq": 0, "last_anchor_digest": None}
        return self._state[twin_id]

    def next_sequence(self, twin_id: str) -> int:
        """Increment and return the next sequence number for a twin."""
        state = self._state_for(twin_id)
        next_seq = int(state["seq"]) + 1
        state["seq"] = next_seq
        self._persist_state()
        return next_seq

    def previous_anchor(self, twin_id: str) -> str | None:
        """Return the last anchor digest known for a twin."""
        value = self._state_for(twin_id).get("last_anchor_digest")
        return str(value) if value is not None else None

    def update_chain(self, twin_id: str, new_anchor_digest: str) -> None:
        """Record the newest anchor digest for a twin."""
        state = self._state_for(twin_id)
        state["last_anchor_digest"] = new_anchor_digest
        self._persist_state()

    def build_proof(
        self,
        event: Event,
        proof_type: ProofType,
        seq: int,
        payload_hash: str,
        canonical_payload: str,
        signer_id: str,
        signature: str,
        signature_metadata: dict[str, str],
        prev_anchor: str | None,
        metadata: dict[str, str] | None = None,
    ) -> ProofEnvelope:
        """Build a proof envelope from canonical event evidence."""
        return ProofEnvelope(
            proof_type=proof_type,
            subject_event_id=event.event_id,
            twin_id=event.twin_id,
            canonical_hash=payload_hash,
            event_type=event.event_type,
            seq=seq,
            timestamp=event.observed_at,
            payload_hash=payload_hash,
            canonical_payload=canonical_payload,
            prev_anchor=prev_anchor,
            signer_id=signer_id,
            signature=signature,
            signature_metadata=signature_metadata,
            metadata=metadata or {},
        )

    def build(self, event: Event, decision: PolicyDecision) -> ProofEnvelope:
        """Build a minimal proof envelope for compatibility with step-1 API.

        Full proof construction is performed by ``EvidenceOrchestrator`` because
        it has access to canonicalization, hashing, signing, and storage.
        """
        seq = self.next_sequence(event.twin_id)
        return ProofEnvelope(
            proof_type=(
                decision.required_proof_types[0]
                if decision.required_proof_types
                else ProofType.CANONICAL_HASH
            ),
            subject_event_id=event.event_id,
            twin_id=event.twin_id,
            canonical_hash="",
            event_type=event.event_type,
            seq=seq,
            prev_anchor=self.previous_anchor(event.twin_id),
            metadata={"policy_rationale": decision.rationale},
        )
