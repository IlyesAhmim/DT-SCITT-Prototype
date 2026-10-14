import unittest

from dt_trust_checkpoints.overlay.merkle import (
    EMPTY_ROOT,
    MerkleTree,
    leaf_hash,
    node_hash,
    verify_consistency,
    verify_inclusion,
)


def _k(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _mth(leaves: list[bytes]) -> bytes:
    """Reference RFC 9162 tree hash computed directly from the definition."""
    if not leaves:
        return EMPTY_ROOT
    if len(leaves) == 1:
        return leaf_hash(leaves[0])
    k = _k(len(leaves))
    return node_hash(_mth(leaves[:k]), _mth(leaves[k:]))


def _path(m: int, leaves: list[bytes]) -> list[bytes]:
    if len(leaves) <= 1:
        return []
    k = _k(len(leaves))
    if m < k:
        return _path(m, leaves[:k]) + [_mth(leaves[k:])]
    return _path(m - k, leaves[k:]) + [_mth(leaves[:k])]


def _subproof(m: int, leaves: list[bytes], complete: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if complete else [_mth(leaves)]
    k = _k(n)
    if m <= k:
        return _subproof(m, leaves[:k], complete) + [_mth(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [_mth(leaves[:k])]


class MerkleTreeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.leaves = [f"leaf-{i}".encode() for i in range(70)]
        self.tree = MerkleTree()
        for leaf in self.leaves:
            self.tree.append(leaf_hash(leaf))

    def test_roots_match_reference(self) -> None:
        for size in range(0, 71):
            self.assertEqual(self.tree.root(size), _mth(self.leaves[:size]))

    def test_inclusion_paths_match_reference_and_verify(self) -> None:
        for size in range(1, 71):
            root = self.tree.root(size)
            for index in range(size):
                path = self.tree.inclusion_proof(index, size)
                self.assertEqual(path, _path(index, self.leaves[:size]))
                self.assertTrue(
                    verify_inclusion(index, size, leaf_hash(self.leaves[index]), path, root)
                )

    def test_inclusion_rejects_wrong_leaf(self) -> None:
        path = self.tree.inclusion_proof(5, 40)
        self.assertFalse(
            verify_inclusion(5, 40, leaf_hash(b"forged"), path, self.tree.root(40))
        )

    def test_consistency_proofs_match_reference_and_verify(self) -> None:
        for new_size in range(1, 71):
            for old_size in range(1, new_size + 1):
                proof = self.tree.consistency_proof(old_size, new_size)
                if old_size < new_size:
                    self.assertEqual(
                        proof, _subproof(old_size, self.leaves[:new_size], True)
                    )
                self.assertTrue(
                    verify_consistency(
                        old_size,
                        new_size,
                        self.tree.root(old_size),
                        self.tree.root(new_size),
                        proof,
                    )
                )

    def test_consistency_rejects_rewritten_history(self) -> None:
        forged = MerkleTree()
        for i, leaf in enumerate(self.leaves[:30]):
            forged.append(leaf_hash(b"rewritten" if i == 3 else leaf))
        proof = forged.consistency_proof(10, 30)
        self.assertFalse(
            verify_consistency(10, 30, self.tree.root(10), forged.root(30), proof)
        )


if __name__ == "__main__":
    unittest.main()
