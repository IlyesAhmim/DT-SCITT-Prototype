"""Experimental local tampering helpers for verification experiments.

These helpers intentionally rewrite local proof and anchor JSON artifacts. They
are only for tests, demos, and attack simulations inside the research prototype.
Do not use them as production data-management utilities.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from dt_trust_checkpoints.core.canonicalization_service import canonicalize_to_json
from dt_trust_checkpoints.core.hashing_signature_service import sha256_hex, sign_digest
from dt_trust_checkpoints.verification.proof_verifier import build_anchor_material
from dt_trust_checkpoints.storage.offchain_evidence_store import _proof_from_dict


def tamper_proof_payload(
    evidence_dir: str | Path,
    twin_id: str,
    proof_id: str,
    marker: str = "tampered-payload",
) -> None:
    """Modify a stored proof's canonical payload without updating its hash."""
    proof_data = _load_proof_data(evidence_dir, twin_id, proof_id)
    document = _load_canonical_payload(proof_data)
    document["tamper_marker"] = marker
    proof_data["canonical_payload"] = canonicalize_to_json(document)
    _write_proof_data(evidence_dir, twin_id, proof_id, proof_data)


def tamper_prev_anchor(
    evidence_dir: str | Path,
    twin_id: str,
    proof_id: str,
    new_prev_anchor: str = "tampered-prev-anchor",
) -> None:
    """Alter a stored proof's previous-anchor linkage."""
    proof_data = _load_proof_data(evidence_dir, twin_id, proof_id)
    proof_data["prev_anchor"] = new_prev_anchor
    _write_proof_data(evidence_dir, twin_id, proof_id, proof_data)


def tamper_sequence(
    evidence_dir: str | Path,
    twin_id: str,
    proof_id: str,
    new_seq: int,
) -> None:
    """Alter a stored proof's sequence number."""
    proof_data = _load_proof_data(evidence_dir, twin_id, proof_id)
    proof_data["seq"] = new_seq
    _write_proof_data(evidence_dir, twin_id, proof_id, proof_data)


def tamper_lifecycle_claim(
    evidence_dir: str | Path,
    twin_id: str,
    proof_id: str,
    fidelity_score: float = 0.1,
) -> None:
    """Make a synchronized lifecycle claim semantically inconsistent.

    The proof is rewritten so payload hash, mock signature, and anchor digest are
    internally self-consistent. The verifier should still reject it because the
    synchronized claim carries insufficient fidelity evidence.
    """
    proof_data = _load_proof_data(evidence_dir, twin_id, proof_id)
    document = _load_canonical_payload(proof_data)
    event = document.setdefault("event", {})
    if not isinstance(event, dict):
        event = {}
        document["event"] = event
    metadata = event.setdefault("metadata", {})
    payload = event.setdefault("payload", {})
    if not isinstance(metadata, dict):
        metadata = {}
        event["metadata"] = metadata
    if not isinstance(payload, dict):
        payload = {}
        event["payload"] = payload

    metadata["claim"] = "synchronized"
    metadata["fidelity_score"] = fidelity_score
    payload["claim"] = "synchronized"
    event["event_type"] = "lifecycle_event"
    event["lifecycle_state"] = "operation"
    proof_data["event_type"] = "lifecycle_event"
    proof_data["canonical_payload"] = canonicalize_to_json(document)

    payload_hash = sha256_hex(proof_data["canonical_payload"])
    signer_id = str(proof_data.get("signer_id", "local-demo-signer"))
    proof_data["payload_hash"] = payload_hash
    proof_data["canonical_hash"] = payload_hash
    proof_data["signature"] = sign_digest(payload_hash, signer_id)
    signature_metadata = dict(proof_data.get("signature_metadata", {}))
    signature_metadata["signer_id"] = signer_id
    signature_metadata["signature_scheme"] = "local-mock-sha256-v1"
    proof_data["signature_metadata"] = signature_metadata

    proof = _proof_from_dict(proof_data)
    proof_data["anchor_digest"] = sha256_hex(
        canonicalize_to_json(build_anchor_material(proof))
    )
    _write_proof_data(evidence_dir, twin_id, proof_id, proof_data)


def tamper_anchor_record(
    anchor_dir: str | Path,
    twin_id: str,
    anchor_digest: str,
    field: str = "proof_id",
    value: Any = "tampered-proof-id",
) -> None:
    """Modify one local anchor registry entry."""
    _rewrite_anchor_records(
        anchor_dir,
        lambda record: _set_field_if_match(record, twin_id, anchor_digest, field, value),
    )


def remove_anchor_record(
    anchor_dir: str | Path,
    twin_id: str,
    anchor_digest: str,
) -> None:
    """Remove one local anchor registry entry to simulate missing anchoring."""
    _rewrite_anchor_records(
        anchor_dir,
        lambda record: None
        if record.get("twin_id") == twin_id and record.get("anchor_digest") == anchor_digest
        else record,
    )


def _load_proof_data(
    evidence_dir: str | Path, twin_id: str, proof_id: str
) -> dict[str, Any]:
    path = _proof_path(evidence_dir, twin_id, proof_id)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Proof file must contain a JSON object.")
    return data


def _write_proof_data(
    evidence_dir: str | Path,
    twin_id: str,
    proof_id: str,
    data: dict[str, Any],
) -> None:
    _proof_path(evidence_dir, twin_id, proof_id).write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _proof_path(evidence_dir: str | Path, twin_id: str, proof_id: str) -> Path:
    return Path(evidence_dir) / twin_id / f"{proof_id}.json"


def _load_canonical_payload(proof_data: dict[str, Any]) -> dict[str, Any]:
    raw = proof_data.get("canonical_payload", "{}")
    document = json.loads(raw)
    if not isinstance(document, dict):
        raise ValueError("Canonical payload must contain a JSON object.")
    return document


def _rewrite_anchor_records(anchor_dir: str | Path, transform: Any) -> None:
    records_file = Path(anchor_dir) / "anchors.jsonl"
    if not records_file.exists():
        return

    rewritten: list[dict[str, Any]] = []
    for line in records_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        transformed = transform(record)
        if transformed is not None:
            rewritten.append(transformed)

    records_file.write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in rewritten),
        encoding="utf-8",
    )


def _set_field_if_match(
    record: dict[str, Any],
    twin_id: str,
    anchor_digest: str,
    field: str,
    value: Any,
) -> dict[str, Any]:
    if record.get("twin_id") == twin_id and record.get("anchor_digest") == anchor_digest:
        record[field] = value
    return record
