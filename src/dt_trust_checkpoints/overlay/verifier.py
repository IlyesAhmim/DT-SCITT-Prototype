"""Verifier outside the DT runtime, implementing the article's six checks.

(i)   signature, against a key of the DT's operator that was valid and
      unrevoked at the time-stamp of the object;
(ii)  time-stamp: token signature, token digest equal to the payload digest,
      and strictly increasing evidence time along the chain;
(iii) digest: the payload digest is recomputed from the stored record, and the
      commitment from the canonical encoding of the signed object;
(iv)  chain continuity and consecutive sequence numbers, and presence of the
      latest anchored chain head (no truncation of anchored history);
(v)   inclusion: the anchor (DT, sequence number, commitment) is in the log
      under a head co-signed by a quorum, and matches the object;
(vi)  DTD consistency: the object's DTD version is the one set by the latest
      DTD update recorded before it in the chain.

Objects after the latest anchored chain head of their DT are *pending*: checks
(i)-(iv) and (vi) apply, but nothing external constrains their content yet.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field

from dt_trust_checkpoints.core.canonicalization_service import canonicalize_to_bytes
from dt_trust_checkpoints.overlay.consortium import CosignedHead, verify_head
from dt_trust_checkpoints.overlay.crypto import KeyRegistry, verify_signature, verify_token
from dt_trust_checkpoints.overlay.pipeline import EvidenceWorld, StoredEntry
from dt_trust_checkpoints.overlay.proof_objects import unsigned_part
from dt_trust_checkpoints.overlay.registry import Receipt, anchor_bytes, verify_receipt


CHECKS = ("i", "ii", "iii", "iv", "v", "vi")


@dataclass(slots=True)
class TrustAnchors:
    """What the verifier trusts: key records, time-stamp key, members, quorum."""

    keys: KeyRegistry
    time_stamp_key: bytes
    member_keys: dict[str, bytes]
    quorum: int
    log_id: str


@dataclass(slots=True)
class ObjectVerdict:
    """Result of verifying one stored entry."""

    position: int
    category: str
    anchored: bool
    failed: set[str]
    verify_us: float


@dataclass(slots=True)
class TwinVerdict:
    """Result of verifying the chain of one DT."""

    twin_id: str
    objects: list[ObjectVerdict] = field(default_factory=list)
    chain_failures: set[str] = field(default_factory=set)

    @property
    def failed_checks(self) -> set[str]:
        failed = set(self.chain_failures)
        for verdict in self.objects:
            failed |= verdict.failed
        return failed

    @property
    def detected(self) -> bool:
        return bool(self.failed_checks)


@dataclass(slots=True)
class AnchoredView:
    """Anchors covered by the latest co-signed head, indexed by (DT, seq)."""

    commitments: dict[tuple[str, int], str]
    max_seq: dict[str, int]
    heads_by_size: dict[int, CosignedHead]


def anchored_view(world: EvidenceWorld) -> AnchoredView:
    """Parse the sealed part of the log."""
    commitments: dict[tuple[str, int], str] = {}
    max_seq: dict[str, int] = {}
    for anchor in world.anchors[: world.sealed_size]:
        content = json.loads(anchor)
        key = (content["dt"], int(content["seq"]))
        commitments[key] = content["c"]
        max_seq[key[0]] = max(max_seq.get(key[0], 0), key[1])
    return AnchoredView(commitments, max_seq, {head.size: head for head in world.heads})


class OverlayVerifier:
    """Checks stored evidence against the shared log and the trust anchors."""

    def __init__(self, trust: TrustAnchors) -> None:
        self.trust = trust
        self._object_cache: dict[tuple[str, str], tuple[int, frozenset[str]]] = {}
        self._head_cache: dict[tuple[int, bytes, tuple[tuple[str, bytes], ...]], bool] = {}

    def verify_world(self, world: EvidenceWorld) -> dict[str, TwinVerdict]:
        """Verify every DT chain of ``world``."""
        view = anchored_view(world)
        twins = sorted(set(world.chains) | set(view.max_seq))
        return {twin: self.verify_twin(world, twin, view) for twin in twins}

    def verify_twin(
        self, world: EvidenceWorld, twin_id: str, view: AnchoredView | None = None
    ) -> TwinVerdict:
        """Verify the chain of one DT."""
        view = view or anchored_view(world)
        verdict = TwinVerdict(twin_id)
        chain = world.chains.get(twin_id, [])
        anchored_max = view.max_seq.get(twin_id, 0)
        expected_seq = 1
        previous: str | None = None
        last_time = -1
        current_dtd = world.initial_dtd.get(twin_id, 0)
        for position, entry in enumerate(chain):
            started = time.perf_counter_ns()
            commitment, token_time, failed = self._object_checks(entry)
            proof = entry.proof_object
            if proof.get("dt") != twin_id or proof.get("seq") != expected_seq:
                failed.add("iv")
            if proof.get("prev") != previous:
                failed.add("iv")
            if token_time <= last_time:
                failed.add("ii")
            dtd = proof.get("dtd")
            if proof.get("cat") == "dtd_update":
                if not isinstance(dtd, int) or dtd <= current_dtd:
                    failed.add("vi")
                if isinstance(dtd, int):
                    current_dtd = dtd
            elif dtd != current_dtd:
                failed.add("vi")
            anchored = expected_seq <= anchored_max
            if anchored and not self._included(world, view, twin_id, expected_seq, commitment):
                failed.add("v")
            verdict.objects.append(
                ObjectVerdict(
                    position=position,
                    category=str(proof.get("cat")),
                    anchored=anchored,
                    failed=failed,
                    verify_us=(time.perf_counter_ns() - started) / 1000.0,
                )
            )
            expected_seq += 1
            previous = commitment
            last_time = max(last_time, token_time)
        if len(chain) < anchored_max:
            verdict.chain_failures.add("iv")
        return verdict

    def _object_checks(self, entry: StoredEntry) -> tuple[str, int, set[str]]:
        proof = entry.proof_object
        encoded = canonicalize_to_bytes(proof)
        commitment = hashlib.sha256(encoded).hexdigest()
        record_digest = hashlib.sha256(entry.record).hexdigest()
        cached = self._object_cache.get((commitment, record_digest))
        if cached is not None:
            return commitment, cached[0], set(cached[1])
        failed: set[str] = set()
        if record_digest != proof.get("pd"):
            failed.add("iii")
        token = proof.get("tst") if isinstance(proof.get("tst"), dict) else {}
        token_time = int(token.get("t", -1)) if isinstance(token.get("t"), int) else -1
        if not verify_token(token, self.trust.time_stamp_key) or token.get("d") != proof.get("pd"):
            failed.add("ii")
        key = self.trust.keys.get(str(proof.get("kid")))
        try:
            unsigned = canonicalize_to_bytes(unsigned_part(proof))
            signature = bytes.fromhex(str(proof.get("sig")))
        except (KeyError, ValueError):
            failed.add("i")
        else:
            if (
                key is None
                or key.owner != f"operator-of-{proof.get('dt')}"
                or not key.is_valid_at(token_time)
                or not verify_signature(key.public_key, signature, unsigned)
            ):
                failed.add("i")
        self._object_cache[(commitment, record_digest)] = (token_time, frozenset(failed))
        return commitment, token_time, failed

    def _included(
        self, world: EvidenceWorld, view: AnchoredView, twin_id: str, seq: int, commitment: str
    ) -> bool:
        if view.commitments.get((twin_id, seq)) != commitment:
            return False
        receipt: Receipt | None = world.receipts.get((twin_id, seq))
        if receipt is None:
            return False
        head = view.heads_by_size.get(receipt.size)
        if head is None:
            return False
        return verify_receipt(
            anchor_bytes(twin_id, seq, commitment),
            receipt,
            head,
            self.trust.member_keys,
            self.trust.quorum,
            self.trust.log_id,
            head_already_verified=self._head_ok(head),
        ) and self._head_ok(head)

    def _head_ok(self, head: CosignedHead) -> bool:
        key = (head.size, head.root, tuple(sorted(head.signatures.items())))
        cached = self._head_cache.get(key)
        if cached is None:
            cached = verify_head(head, self.trust.member_keys, self.trust.quorum, self.trust.log_id)
            self._head_cache[key] = cached
        return cached
