"""Unit and end-to-end tests: python3 -m unittest discover -s tests"""
import os
import random
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "experiments"))

from dt_evidence import jcs, merkle, profile          # noqa: E402
from common import World, build_history, T0           # noqa: E402


class TestJCS(unittest.TestCase):
    def test_rfc8785_property_sorting(self):
        # RFC 8785, Section 3.2.3: sorting by UTF-16 code units
        obj = {"€": "Euro Sign", "\r": "Carriage Return", "דּ": "Hebrew Letter Dalet With Dagesh",
               "1": "One", "\U0001F600": "Emoji: Grinning Face", "\u0080": "Control", "ö": "Latin Small Letter O With Diaeresis"}
        out = jcs.canonicalize(obj).decode("utf-8")
        order = [k for k in ["\r", "1", "\u0080", "ö", "€", "\U0001F600", "דּ"]]
        positions = [out.index(jcs.canonicalize(k).decode("utf-8") + ":") for k in order]
        self.assertEqual(positions, sorted(positions))

    def test_no_whitespace_and_escapes(self):
        self.assertEqual(jcs.canonicalize({"b": [1, None, True], "a": "x\ny\"z"}),
                         b'{"a":"x\\ny\\"z","b":[1,null,true]}')

    def test_rejects_floats_and_duplicates(self):
        with self.assertRaises(ValueError):
            jcs.canonicalize({"a": 1.5})
        with self.assertRaises(ValueError):
            jcs.parse_strict(b'{"a":1,"a":2}')


class TestMerkle(unittest.TestCase):
    def test_proofs_all_sizes(self):
        log = merkle.MerkleLog()
        rng = merkle.CompactRange()
        roots = {}
        for n in range(1, 70):
            e = f"entry {n}".encode()
            log.append(e)
            rng.append_entry(e)
            roots[n] = log.root()
            self.assertEqual(rng.root(), roots[n])
            for m in range(n):
                path = log.inclusion_path(m, n)
                self.assertTrue(merkle.verify_inclusion(log.leaves[m], m, n, path, roots[n]))
                self.assertFalse(merkle.verify_inclusion(log.leaves[m], m, n, path, roots[n][::-1]))
        for n in range(1, 70):
            for m in range(1, n + 1):
                path = log.consistency_path(m, n)
                self.assertTrue(merkle.verify_consistency(m, n, roots[m], roots[n], path), (m, n))
                if m < n:
                    self.assertFalse(merkle.verify_consistency(m, n, roots[m], roots[n][::-1], path))


class TestEndToEnd(unittest.TestCase):
    def test_honest_history_verifies_in_all_modes(self):
        for config in ("chain", "scitt", "profile"):
            w = build_history(World(config, seed=3), 40, random.Random(3))
            self.assertEqual(w.verify()[0], "verified", config)

    def test_pending_tail(self):
        w = build_history(World("profile", seed=4), 20, random.Random(4))
        it = w.emit("af-validated", w.now)
        w.stamp(it, w.now + 2)
        self.assertEqual(w.verify()[0], "pending")

    def test_body_tamper_detected(self):
        w = build_history(World("profile", seed=5), 20, random.Random(5))
        w.items[7]["body"] = dict(w.items[7]["body"], phase="out-of-sync")
        self.assertEqual(w.verify()[0], "invalid")

    def test_statement_size_and_fields(self):
        w = build_history(World("profile", seed=6), 5, random.Random(6))
        h = profile.header(w.items[2]["statement"])
        self.assertEqual(h["sub"], "urn:dt:pump:7")
        self.assertEqual(h["seq"], 3)
        self.assertEqual(len(h["payload"]), 32)


if __name__ == "__main__":
    unittest.main()
