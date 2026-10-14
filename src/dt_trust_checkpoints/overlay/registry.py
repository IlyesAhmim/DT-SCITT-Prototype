"""Shared append-only evidence log with co-signed tree heads and receipts.

The log stores anchors, i.e. commitments with minimal metadata (DT identifier
and sequence number). Sealing computes the new tree head and the consistency
proof from the last co-signed head, and asks the consortium to co-sign it. A
receipt is an RFC 9162 inclusion path under a co-signed head, which a party can
check offline with the members' public keys.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from dt_trust_checkpoints.core.canonicalization_service import canonicalize_to_bytes
from dt_trust_checkpoints.overlay.consortium import CosignedHead, verify_head
from dt_trust_checkpoints.overlay.merkle import (
    EMPTY_ROOT,
    MerkleTree,
    leaf_hash,
    verify_inclusion,
)


class CoSigner(Protocol):
    """Interface shared by process-based and in-process consortia."""

    quorum: int
    log_id: str
    public_keys: dict[str, bytes]

    def cosign(
        self, old_size: int, old_root: bytes, new_size: int, new_root: bytes, proof: list[bytes]
    ) -> CosignedHead: ...


def anchor_bytes(twin_id: str, seq: int, commitment: str) -> bytes:
    """Return the canonical bytes of an anchor (commitment plus minimal metadata)."""
    return canonicalize_to_bytes({"dt": twin_id, "seq": seq, "c": commitment})


@dataclass(slots=True)
class Receipt:
    """Inclusion path of one anchor under a co-signed tree head."""

    index: int
    size: int
    path: list[bytes]

    def export(self) -> dict[str, Any]:
        """Return a JSON-compatible view of the receipt."""
        return {"index": self.index, "size": self.size, "path": [h.hex() for h in self.path]}


class EvidenceLog:
    """Operator side of the shared append-only log."""

    def __init__(self, cosigner: CoSigner) -> None:
        self.cosigner = cosigner
        self.tree = MerkleTree()
        self.anchors: list[bytes] = []
        self.heads: list[CosignedHead] = []
        self._heads_by_size: dict[int, CosignedHead] = {}

    @property
    def size(self) -> int:
        """Return the number of anchors appended so far."""
        return self.tree.size

    @property
    def sealed_size(self) -> int:
        """Return the size covered by the latest co-signed head."""
        return self.heads[-1].size if self.heads else 0

    def append(self, anchor: bytes) -> int:
        """Append one anchor and return its index (not yet covered by a head)."""
        self.anchors.append(anchor)
        return self.tree.append(leaf_hash(anchor))

    def seal(self) -> CosignedHead | None:
        """Have the consortium co-sign a head covering every appended anchor."""
        new_size = self.tree.size
        old_size = self.sealed_size
        if new_size == old_size:
            return self.heads[-1] if self.heads else None
        old_root = self.heads[-1].root if self.heads else EMPTY_ROOT
        new_root = self.tree.root(new_size)
        proof = self.tree.consistency_proof(old_size, new_size)
        head = self.cosigner.cosign(old_size, old_root, new_size, new_root, proof)
        self.heads.append(head)
        self._heads_by_size[new_size] = head
        return head

    def receipt(self, index: int, head: CosignedHead) -> Receipt:
        """Return the receipt of anchor ``index`` under ``head``."""
        return Receipt(index=index, size=head.size, path=self.tree.inclusion_proof(index, head.size))

    def head_for_size(self, size: int) -> CosignedHead | None:
        """Return the co-signed head of a given size, if any."""
        return self._heads_by_size.get(size)


def verify_receipt(
    anchor: bytes,
    receipt: Receipt,
    head: CosignedHead,
    public_keys: dict[str, bytes],
    quorum: int,
    log_id: str,
    *,
    head_already_verified: bool = False,
) -> bool:
    """Check that ``anchor`` is included under a head co-signed by a quorum."""
    if receipt.size != head.size:
        return False
    if not head_already_verified and not verify_head(head, public_keys, quorum, log_id):
        return False
    return verify_inclusion(receipt.index, receipt.size, leaf_hash(anchor), receipt.path, head.root)
