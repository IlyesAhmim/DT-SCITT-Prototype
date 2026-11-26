"""Merkle tree of RFC 9162 (Certificate Transparency 2.0), Section 2.1.

Implements tree hashes, inclusion and consistency proofs and their
verification algorithms, and the compact range used by witnesses to recompute
the root of an append-only log from the appended entries alone.
"""
import hashlib


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(entry: bytes) -> bytes:
    return _h(b"\x00" + entry)


def node_hash(left: bytes, right: bytes) -> bytes:
    return _h(b"\x01" + left + right)


def _split(n: int) -> int:
    """Largest power of two strictly smaller than n (n > 1)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


class MerkleLog:
    """Append-only list of entries with RFC 9162 tree hashes and proofs."""

    def __init__(self):
        self.leaves = []          # leaf hashes
        self._perfect = {}        # (start, size) -> hash, for complete power-of-two subtrees

    def __len__(self):
        return len(self.leaves)

    def append(self, entry: bytes) -> int:
        self.leaves.append(leaf_hash(entry))
        return len(self.leaves) - 1

    def _mth(self, start: int, size: int) -> bytes:
        if size == 0:
            return _h(b"")
        if size == 1:
            return self.leaves[start]
        perfect = size & (size - 1) == 0
        if perfect:
            key = (start, size)
            cached = self._perfect.get(key)
            if cached is not None:
                return cached
        k = _split(size)
        value = node_hash(self._mth(start, k), self._mth(start + k, size - k))
        if perfect:
            self._perfect[(start, size)] = value
        return value

    def root(self, size=None) -> bytes:
        size = len(self.leaves) if size is None else size
        return self._mth(0, size)

    def inclusion_path(self, index: int, size=None):
        size = len(self.leaves) if size is None else size
        if not 0 <= index < size:
            raise ValueError("index out of range")

        def path(m, start, n):
            if n == 1:
                return []
            k = _split(n)
            if m < k:
                return path(m, start, k) + [self._mth(start + k, n - k)]
            return path(m - k, start + k, n - k) + [self._mth(start, k)]

        return path(index, 0, size)

    def consistency_path(self, first: int, second=None):
        second = len(self.leaves) if second is None else second
        if not 0 < first <= second:
            raise ValueError("invalid sizes")

        def subproof(m, start, n, b):
            if m == n:
                return [] if b else [self._mth(start, n)]
            k = _split(n)
            if m <= k:
                return subproof(m, start, k, b) + [self._mth(start + k, n - k)]
            return subproof(m - k, start + k, n - k, False) + [self._mth(start, k)]

        return subproof(first, 0, second, True)


def root_from_inclusion(entry_hash: bytes, index: int, size: int, path):
    """Run RFC 9162, Section 2.1.3.2, and return the computed root (None on failure).

    RFC 9942 receipts carry no root: the verifier computes it from the inclusion
    proof and then checks the receipt signature over that root.
    """
    if index >= size:
        return None
    fn, sn = index, size - 1
    r = entry_hash
    for p in path:
        if sn == 0:
            return None
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return r if sn == 0 else None


def verify_inclusion(entry_hash: bytes, index: int, size: int, path, root: bytes) -> bool:
    """RFC 9162, Section 2.1.3.2, with entry_hash = leaf_hash(entry)."""
    return root_from_inclusion(entry_hash, index, size, path) == root


def verify_consistency(first: int, second: int, first_hash: bytes, second_hash: bytes, path) -> bool:
    """RFC 9162, Section 2.1.4.2."""
    if first == second:
        return not path and first_hash == second_hash
    if first == 0 or first > second or not path:
        return False
    path = list(path)
    if first & (first - 1) == 0:
        path = [first_hash] + path
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_hash and sr == second_hash and sn == 0


class CompactRange:
    """Right frontier of an RFC 9162 tree: enough state to append and get the root."""

    def __init__(self):
        self.size = 0
        self.nodes = []            # list of (height, hash), heights strictly decreasing

    def append_entry(self, entry: bytes):
        self.size += 1
        self.nodes.append((0, leaf_hash(entry)))
        while len(self.nodes) >= 2 and self.nodes[-1][0] == self.nodes[-2][0]:
            (h, right), (_, left) = self.nodes.pop(), self.nodes.pop()
            self.nodes.append((h + 1, node_hash(left, right)))

    def root(self) -> bytes:
        if not self.nodes:
            return _h(b"")
        r = self.nodes[-1][1]
        for _, h in reversed(self.nodes[:-1]):
            r = node_hash(h, r)
        return r

    def copy(self):
        c = CompactRange()
        c.size, c.nodes = self.size, list(self.nodes)
        return c


def tree_root(entries) -> bytes:
    """Root of the RFC 9162 tree over a list of entries (used for the head map)."""
    log = MerkleLog()
    for e in entries:
        log.append(e)
    return log.root()
