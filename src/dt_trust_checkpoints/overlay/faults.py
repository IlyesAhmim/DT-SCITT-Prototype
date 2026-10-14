"""Fault injection: functional tests of the verifier's checks.

Each fault modifies a copy of a completed run's evidence, never the original,
and the verifier then checks the affected DT chain. These are tests that each
check fires on the fault it targets; they are not an attack evaluation.

Faults on anchored history:

* ``record_alteration``  - the stored record is changed;
* ``object_alteration``  - a signed field (DTD version) is changed, no re-signing;
* ``rewrite_resign``     - the operator rewrites a record and re-signs it and all
  its successors with its current key and fresh time-stamps;
* ``reorder``            - two consecutive entries are swapped;
* ``deletion``           - one entry is removed;
* ``truncation``         - the chain is cut from one entry onwards;
* ``replay``             - an earlier entry is appended again;
* ``revoked_key``        - an object is re-signed with the operator's revoked key;
* ``dtd_misbinding``     - the producer asserts a wrong DTD version *before*
  anchoring: the object is signed, chained, and anchored normally, in a
  rebuilt log.

``tail_rewrite`` rewrites, with valid keys, entries that are still pending, i.e.
after the latest anchored chain head; the trust model says this is undetectable.
"""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass
from typing import Any, Callable

from dt_trust_checkpoints.core.canonicalization_service import canonicalize_to_bytes
from dt_trust_checkpoints.overlay.consortium import InProcessConsortium
from dt_trust_checkpoints.overlay.crypto import TimeStampService
from dt_trust_checkpoints.overlay.pipeline import EvidenceWorld, StoredEntry
from dt_trust_checkpoints.overlay.proof_objects import (
    ProofProducer,
    commitment_of,
    sign_object,
    unsigned_part,
)
from dt_trust_checkpoints.overlay.registry import EvidenceLog, anchor_bytes
from dt_trust_checkpoints.overlay.verifier import OverlayVerifier, TrustAnchors


ANCHORED_FAULTS = (
    "record_alteration",
    "object_alteration",
    "rewrite_resign",
    "reorder",
    "deletion",
    "truncation",
    "replay",
    "revoked_key",
    "dtd_misbinding",
)
TARGET_CHECK = {
    "record_alteration": "iii",
    "object_alteration": "i",
    "rewrite_resign": "v",
    "reorder": "iv",
    "deletion": "iv",
    "truncation": "iv",
    "replay": "iv",
    "revoked_key": "i",
    "dtd_misbinding": "vi",
}


@dataclass(slots=True)
class FaultContext:
    """What a misbehaving operator holds, plus the run's trust anchors."""

    producer: ProofProducer
    time_stamps: TimeStampService
    trust: TrustAnchors
    log_id: str
    quorum: int
    members: int


def _altered_record(record: bytes) -> bytes:
    document = json.loads(record)
    payload = document.get("payload") if isinstance(document.get("payload"), dict) else document
    payload["altered"] = True
    return canonicalize_to_bytes(document)


def _resign(
    context: FaultContext,
    proof: dict[str, Any],
    *,
    prev: str | None,
    key_id: str | None = None,
    record: bytes | None = None,
    fresh_token: bool = False,
) -> dict[str, Any]:
    unsigned = dict(unsigned_part(proof))
    unsigned["prev"] = prev
    if record is not None:
        unsigned["pd"] = hashlib.sha256(record).hexdigest()
    if fresh_token or record is not None:
        unsigned["tst"] = context.time_stamps.issue(unsigned["pd"])
    twin_id = unsigned["dt"]
    unsigned["kid"] = key_id or context.producer.current_key_id(twin_id)
    return sign_object(unsigned, context.producer.private_key(twin_id, unsigned["kid"]))


def _relink_from(
    context: FaultContext,
    chain: list[StoredEntry],
    start: int,
    *,
    fresh_tokens: bool,
    keep_keys: bool,
) -> None:
    """Re-sign entries from ``start`` onwards so that their links match again."""
    for position in range(start, len(chain)):
        prev = commitment_of(chain[position - 1].proof_object) if position else None
        proof = chain[position].proof_object
        key_id = proof["kid"] if keep_keys else None
        chain[position] = StoredEntry(
            _resign(context, proof, prev=prev, key_id=key_id, fresh_token=fresh_tokens),
            chain[position].record,
        )


def apply_fault(
    name: str, world: EvidenceWorld, twin_id: str, position: int, context: FaultContext
) -> tuple[EvidenceWorld, TrustAnchors]:
    """Return a modified copy of ``world`` and the trust anchors to verify it with."""
    faulty = world.copy()
    chain = faulty.chains[twin_id]
    entry = chain[position]
    proof = entry.proof_object
    trust = context.trust
    if name == "record_alteration":
        chain[position] = StoredEntry(proof, _altered_record(entry.record))
    elif name == "object_alteration":
        chain[position] = StoredEntry({**proof, "dtd": proof["dtd"] + 1}, entry.record)
    elif name == "rewrite_resign":
        record = _altered_record(entry.record)
        prev = commitment_of(chain[position - 1].proof_object) if position else None
        chain[position] = StoredEntry(_resign(context, proof, prev=prev, record=record), record)
        _relink_from(context, chain, position + 1, fresh_tokens=True, keep_keys=False)
    elif name == "reorder":
        chain[position], chain[position + 1] = chain[position + 1], chain[position]
    elif name == "deletion":
        del chain[position]
    elif name == "truncation":
        del chain[position:]
    elif name == "replay":
        chain.append(entry)
    elif name == "revoked_key":
        old_key = f"{twin_id}/k1"
        prev = commitment_of(chain[position - 1].proof_object) if position else None
        chain[position] = StoredEntry(_resign(context, proof, prev=prev, key_id=old_key), entry.record)
        _relink_from(context, chain, position + 1, fresh_tokens=False, keep_keys=True)
    elif name == "dtd_misbinding":
        prev = commitment_of(chain[position - 1].proof_object) if position else None
        lied = {**unsigned_part(proof), "dtd": proof["dtd"] + 1}
        chain[position] = StoredEntry(
            _resign(context, lied, prev=prev, key_id=proof["kid"]), entry.record
        )
        _relink_from(context, chain, position + 1, fresh_tokens=False, keep_keys=True)
        faulty, trust = _reanchor(faulty, context)
    else:
        raise ValueError(f"Unknown fault {name}.")
    return faulty, trust


def _reanchor(world: EvidenceWorld, context: FaultContext) -> tuple[EvidenceWorld, TrustAnchors]:
    """Rebuild the log as if the modified chains had been anchored originally."""
    cosigner = InProcessConsortium(context.members, context.quorum, context.log_id)
    log = EvidenceLog(cosigner)
    commitments = {
        (twin, entry.proof_object["seq"]): commitment_of(entry.proof_object)
        for twin, chain in world.chains.items()
        for entry in chain
    }
    order: list[tuple[str, int]] = []
    for anchor in world.anchors[: world.sealed_size]:
        content = json.loads(anchor)
        key = (content["dt"], int(content["seq"]))
        order.append(key)
        log.append(anchor_bytes(key[0], key[1], commitments[key]))
    head = log.seal()
    assert head is not None
    receipts = {key: log.receipt(index, head) for index, key in enumerate(order)}
    rebuilt = EvidenceWorld(
        chains=world.chains,
        anchors=list(log.anchors),
        heads=[head],
        receipts=receipts,
        sealed_size=log.sealed_size,
        initial_dtd=world.initial_dtd,
    )
    trust = TrustAnchors(
        keys=context.trust.keys,
        time_stamp_key=context.trust.time_stamp_key,
        member_keys=cosigner.public_keys,
        quorum=context.quorum,
        log_id=context.log_id,
    )
    return rebuilt, trust


def eligible_positions(name: str, chain: list[StoredEntry], category: str) -> list[int]:
    """Return the positions of ``category`` entries a fault can target."""
    positions = [
        position
        for position, entry in enumerate(chain)
        if entry.proof_object["cat"] == category
    ]
    if name == "reorder":
        positions = [position for position in positions if position + 1 < len(chain)]
    if name == "revoked_key":
        positions = [
            position for position in positions if not chain[position].proof_object["kid"].endswith("/k1")
        ]
    if name == "dtd_misbinding":
        positions = [] if category == "dtd_update" else positions
    return positions


def run_fault_campaign(
    world: EvidenceWorld,
    context: FaultContext,
    categories: tuple[str, ...],
    *,
    per_cell: int,
    seed: int,
    on_case: Callable[[dict[str, Any]], None],
) -> None:
    """Inject every anchored fault into up to ``per_cell`` objects per category."""
    rng = random.Random(seed)
    base_verifier = OverlayVerifier(context.trust)
    for name in ANCHORED_FAULTS:
        for category in categories:
            candidates = [
                (twin_id, position)
                for twin_id, chain in sorted(world.chains.items())
                for position in eligible_positions(name, chain, category)
            ]
            for twin_id, position in rng.sample(candidates, min(per_cell, len(candidates))):
                faulty, trust = apply_fault(name, world, twin_id, position, context)
                # A rebuilt log has its own members, hence its own verifier.
                verifier = base_verifier if trust is context.trust else OverlayVerifier(trust)
                verdict = verifier.verify_twin(faulty, twin_id)
                failed = verdict.failed_checks
                on_case(
                    {
                        "fault": name,
                        "category": category,
                        "twin_id": twin_id,
                        "position": position,
                        "detected": verdict.detected,
                        "target_check": TARGET_CHECK[name],
                        "target_check_fired": TARGET_CHECK[name] in failed,
                        "checks_fired": "+".join(sorted(failed)),
                    }
                )


def rewrite_pending_tail(
    world: EvidenceWorld, pending: list[tuple[str, int]], context: FaultContext
) -> tuple[EvidenceWorld, list[tuple[str, int]]]:
    """Rewrite, with valid keys, every pending entry; return the copy and targets."""
    faulty = world.copy()
    targets: list[tuple[str, int]] = []
    for twin_id in sorted({twin for twin, _ in pending}):
        chain = faulty.chains[twin_id]
        seqs = sorted(seq for twin, seq in pending if twin == twin_id)
        first = seqs[0] - 1
        for position in range(first, len(chain)):
            entry = chain[position]
            record = _altered_record(entry.record)
            prev = commitment_of(chain[position - 1].proof_object) if position else None
            chain[position] = StoredEntry(
                _resign(context, entry.proof_object, prev=prev, record=record), record
            )
            targets.append((twin_id, position + 1))
    return faulty, targets
