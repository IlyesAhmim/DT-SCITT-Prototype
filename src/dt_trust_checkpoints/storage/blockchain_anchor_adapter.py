"""Local mock blockchain anchor adapter.

This adapter is not a blockchain client. It is an append-only local JSONL
registry that gives experiments blockchain-shaped anchoring metadata without
introducing external infrastructure or consensus assumptions.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from dt_trust_checkpoints.core.canonicalization_service import to_json_compatible
from dt_trust_checkpoints.models import (
    AnchorRecord,
    CheckpointMode,
    EventType,
    ProofEnvelope,
    ProofType,
)


LOCAL_ANCHOR_BACKEND = "local-jsonl-anchor-registry"


class BlockchainAnchorAdapter:
    """Append-only local registry for anchor records."""

    def __init__(self, anchor_dir: str | Path = "outputs/anchors") -> None:
        self.anchor_dir = Path(anchor_dir)
        self.records_file = self.anchor_dir / "anchors.jsonl"

    def submit_anchor(self, anchor: AnchorRecord) -> AnchorRecord:
        """Append an anchor record and return it with local transaction metadata."""
        self.anchor_dir.mkdir(parents=True, exist_ok=True)
        next_index = self._next_order_index()

        anchor.backend = LOCAL_ANCHOR_BACKEND
        anchor.order_index = next_index
        if anchor.tx_ref is None:
            anchor.tx_ref = f"local-tx-{next_index:06d}"
        if anchor.transaction_ref is None:
            anchor.transaction_ref = anchor.tx_ref

        with self.records_file.open("a", encoding="utf-8") as file:
            file.write(json.dumps(to_json_compatible(anchor), sort_keys=True) + "\n")

        return anchor

    def list_anchors(self, twin_id: str) -> list[AnchorRecord]:
        """Return all anchor records for a twin in append order."""
        return [
            anchor
            for anchor in self._read_all()
            if anchor.twin_id == twin_id
        ]

    def load_anchor(self, anchor_digest: str, twin_id: str) -> AnchorRecord | None:
        """Return the first matching anchor record for a digest and twin."""
        for anchor in self._read_all():
            if anchor.twin_id == twin_id and anchor.anchor_digest == anchor_digest:
                return anchor
        return None

    def anchor(self, proof: ProofEnvelope) -> AnchorRecord:
        """Compatibility helper to anchor a proof envelope asynchronously."""
        record = AnchorRecord(
            proof_id=proof.proof_id,
            twin_id=proof.twin_id,
            checkpoint_mode=CheckpointMode.ASYNC,
            anchor_digest=proof.anchor_digest or proof.canonical_hash,
            proof_type=proof.proof_type,
            event_type=proof.event_type,
            seq=proof.seq,
            timestamp=proof.timestamp,
            payload_hash=proof.payload_hash,
            prev_anchor=proof.prev_anchor,
            offchain_ref=proof.offchain_ref,
        )
        return self.submit_anchor(record)

    def _next_order_index(self) -> int:
        if not self.records_file.exists():
            return 1
        with self.records_file.open("r", encoding="utf-8") as file:
            return sum(1 for line in file if line.strip()) + 1

    def _read_all(self) -> list[AnchorRecord]:
        if not self.records_file.exists():
            return []

        anchors: list[AnchorRecord] = []
        with self.records_file.open("r", encoding="utf-8") as file:
            for line in file:
                if line.strip():
                    anchors.append(_anchor_from_dict(json.loads(line)))
        return anchors


def _parse_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value))


def _optional_proof_type(value: Any) -> ProofType | None:
    return ProofType(str(value)) if value is not None else None


def _optional_event_type(value: Any) -> EventType | None:
    return EventType(str(value)) if value is not None else None


def _anchor_from_dict(data: dict[str, Any]) -> AnchorRecord:
    return AnchorRecord(
        proof_id=str(data["proof_id"]),
        twin_id=str(data["twin_id"]),
        checkpoint_mode=CheckpointMode(str(data["checkpoint_mode"])),
        anchor_digest=str(data["anchor_digest"]),
        proof_type=_optional_proof_type(data.get("proof_type")),
        event_type=_optional_event_type(data.get("event_type")),
        seq=int(data.get("seq", 0)),
        timestamp=_parse_datetime(data["timestamp"]),
        payload_hash=data.get("payload_hash"),
        prev_anchor=data.get("prev_anchor"),
        offchain_ref=data.get("offchain_ref"),
        tx_ref=data.get("tx_ref"),
        order_index=int(data.get("order_index", 0)),
        backend=str(data.get("backend", LOCAL_ANCHOR_BACKEND)),
        transaction_ref=data.get("transaction_ref", data.get("tx_ref")),
        anchored_at=_parse_datetime(data["anchored_at"]),
        anchor_id=str(data["anchor_id"]),
        metadata=dict(data.get("metadata", {})),
    )
