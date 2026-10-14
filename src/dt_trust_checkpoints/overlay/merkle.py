"""Merkle tree with RFC 9162 hashing, inclusion proofs, and consistency proofs.

The tree keeps every complete, aligned subtree hash so that roots, inclusion
paths, and consistency proofs cost O(log n) hash look-ups instead of a full
recomputation. Hashing follows RFC 9162, Section 2.1: leaves are hashed as
``SHA-256(0x00 || data)`` and interior nodes as ``SHA-256(0x01 || left || right)``.
"""

from __future__ import annotations

import hashlib


EMPTY_ROOT = hashlib.sha256(b"").digest()


def leaf_hash(data: bytes) -> bytes:
    """Return the RFC 9162 hash of one leaf."""
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """Return the RFC 9162 hash of one interior node."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_power_of_two_below(n: int) -> int:
    """Return the largest power of two strictly smaller than ``n`` (n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


class MerkleTree:
    """Append-only Merkle tree storing complete aligned subtree hashes."""

    def __init__(self) -> None:
        self._levels: list[list[bytes]] = [[]]

    @property
    def size(self) -> int:
        """Return the number of leaves."""
        return len(self._levels[0])

    def append(self, hashed_leaf: bytes) -> int:
        """Append an already hashed leaf and return its index."""
        index = self.size
        self._levels[0].append(hashed_leaf)
        level = 0
        while len(self._levels[level]) % 2 == 0:
            nodes = self._levels[level]
            if len(self._levels) == level + 1:
                self._levels.append([])
            self._levels[level + 1].append(node_hash(nodes[-2], nodes[-1]))
            level += 1
        return index

    def root(self, size: int | None = None) -> bytes:
        """Return the tree head hash for the first ``size`` leaves."""
        size = self.size if size is None else size
        if size > self.size:
            raise ValueError("Requested tree size exceeds the number of leaves.")
        return self._subtree(0, size)

    def inclusion_proof(self, index: int, size: int | None = None) -> list[bytes]:
        """Return the RFC 9162 inclusion path of leaf ``index`` in a tree of ``size``."""
        size = self.size if size is None else size
        if not 0 <= index < size <= self.size:
            raise ValueError("Leaf index outside the requested tree.")
        return self._path(index, 0, size)

    def consistency_proof(self, old_size: int, new_size: int | None = None) -> list[bytes]:
        """Return the RFC 9162 consistency proof between two tree sizes."""
        new_size = self.size if new_size is None else new_size
        if not 0 <= old_size <= new_size <= self.size:
            raise ValueError("Invalid tree sizes for a consistency proof.")
        if old_size == 0 or old_size == new_size:
            return []
        return self._subproof(old_size, 0, new_size, True)

    def _subtree(self, start: int, end: int) -> bytes:
        count = end - start
        if count == 0:
            return EMPTY_ROOT
        if count & (count - 1) == 0 and start % count == 0:
            level = count.bit_length() - 1
            return self._levels[level][start >> level]
        split = _largest_power_of_two_below(count)
        return node_hash(self._subtree(start, start + split), self._subtree(start + split, end))

    def _path(self, index: int, start: int, end: int) -> list[bytes]:
        count = end - start
        if count <= 1:
            return []
        split = _largest_power_of_two_below(count)
        if index - start < split:
            return self._path(index, start, start + split) + [self._subtree(start + split, end)]
        return self._path(index, start + split, end) + [self._subtree(start, start + split)]

    def _subproof(self, old_size: int, start: int, end: int, complete: bool) -> list[bytes]:
        count = end - start
        if old_size == count:
            return [] if complete else [self._subtree(start, end)]
        split = _largest_power_of_two_below(count)
        if old_size <= split:
            return self._subproof(old_size, start, start + split, complete) + [
                self._subtree(start + split, end)
            ]
        return self._subproof(old_size - split, start + split, end, False) + [
            self._subtree(start, start + split)
        ]


def verify_inclusion(
    index: int, size: int, hashed_leaf: bytes, path: list[bytes], root: bytes
) -> bool:
    """Verify an inclusion path (RFC 9162, Section 2.1.3.2)."""
    if index >= size:
        return False
    fn, sn = index, size - 1
    result = hashed_leaf
    for sibling in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            result = node_hash(sibling, result)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            result = node_hash(result, sibling)
        fn >>= 1
        sn >>= 1
    return sn == 0 and result == root


def verify_consistency(
    old_size: int, new_size: int, old_root: bytes, new_root: bytes, proof: list[bytes]
) -> bool:
    """Verify a consistency proof (RFC 9162, Section 2.1.4.2)."""
    if old_size > new_size:
        return False
    if old_size == new_size:
        return old_root == new_root and not proof
    if old_size == 0:
        return not proof
    if not proof:
        return False
    path = list(proof)
    if old_size & (old_size - 1) == 0:
        path.insert(0, old_root)
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    first = second = path[0]
    for value in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            first = node_hash(value, first)
            second = node_hash(value, second)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            second = node_hash(second, value)
        fn >>= 1
        sn >>= 1
    return sn == 0 and first == old_root and second == new_root
