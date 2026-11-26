"""Transparency Service (registry) and witnesses.

mode="profile": the registration policy of dt-evidence-1. For each DT (CWT
subject) the service accepts only the successor of the current head
(seq = head.seq + 1 and prev = head commitment), rejects a conflicting
statement for an occupied sequence number, treats identical resubmissions as
idempotent, and publishes a per-DT head map in every checkpoint. Witnesses
recompute the log root and the head map from the appended statements and
re-check these rules before cosigning.

mode="generic": a SCITT-style service without DT-specific rules. It verifies
issuer signatures and key status, appends every statement, and its witnesses
only check that the log is append-only.
"""
from . import cose, merkle, profile
from .trust import key_from_seed

CHECKPOINT_CONTEXT = b"dt-evidence checkpoint v1\n"


def _head_entry(sub: str, seq: int, c: bytes) -> bytes:
    return cose.dumps([sub, seq, c])


def head_entries(heads: dict):
    return [_head_entry(sub, seq, c) for sub, (seq, c) in sorted(heads.items())]


def _successor_ok(heads: dict, h: dict, c: bytes):
    head = heads.get(h["sub"])
    if head is None:
        return h["seq"] == 1 and h["prev"] is None
    return h["seq"] == head[0] + 1 and h["prev"] == head[1]


class TransparencyService:
    def __init__(self, seed: bytes, keydir, mode: str = "profile", log_id: str = "ts.example",
                 kid: bytes = b"ts-1"):
        self.key = key_from_seed(seed)
        self.public = self.key.public_key()
        self.kid, self.log_id, self.mode, self.keydir = kid, log_id, mode, keydir
        self.log = merkle.MerkleLog()
        self.statements, self.index_of = [], {}
        self.heads = {}                         # sub -> (seq, commitment)
        self.pending_from = 0
        self.checkpoints = {}
        self.latest, self.latest_entries = None, []

    # ---- registration ------------------------------------------------------------
    def register(self, statement: bytes, now: int):
        try:
            h = profile.header(statement)
        except Exception:
            return "rejected", "malformed"
        if h["alg"] != cose.ED25519 or h["profile"] != profile.PROFILE or not h["iss"] or not h["sub"]:
            return "rejected", "header"
        if h["unprotected"]:
            return "rejected", "unprotected header must be empty"
        if not self.keydir.valid_at(h["kid"], h["iss"], now):
            return "rejected", "key not valid at registration time"
        if not cose.verify1(statement, self.keydir.public(h["kid"])):
            return "rejected", "signature"
        c = profile.commitment(statement)
        if c in self.index_of:
            return "registered", self.index_of[c]            # idempotent resubmission
        if self.mode == "profile" and not _successor_ok(self.heads, h, c):
            return "rejected", "not the successor of the current per-DT head"
        idx = self.log.append(c)
        self.statements.append(statement)
        self.index_of[c] = idx
        if self.mode == "profile":
            self.heads[h["sub"]] = (h["seq"], c)
        return "registered", idx

    # ---- checkpoints, receipts, head proofs -----------------------------------------
    def checkpoint(self, witnesses, quorum: int, now: int):
        size = len(self.log)
        entries = head_entries(self.heads) if self.mode == "profile" else []
        body = {"log": self.log_id, "size": size, "root": self.log.root(),
                "time": now, "heads": merkle.tree_root(entries) if self.mode == "profile" else None}
        body_bytes = cose.dumps(body)
        ts_sig = self.key.sign(CHECKPOINT_CONTEXT + body_bytes)
        new = self.statements[self.pending_from:size]
        cosigs = {}
        for w in witnesses:
            sig = w.cosign(body_bytes, ts_sig, new)
            if sig is not None:
                cosigs[w.kid] = sig
        if len(cosigs) < quorum:
            return None
        cp = {"body": body_bytes, "ts_sig": ts_sig, "cosigs": cosigs}
        # receipts refer to the first checkpoint of their tree size (registration time);
        # the most recent checkpoint, possibly of the same size, carries the fresh heads
        self.checkpoints.setdefault(size, cp)
        self.latest, self.latest_entries = cp, entries
        self.pending_from = size
        return cp

    def fork(self):
        """Copy of the service state sharing its key (used to test split views)."""
        other = TransparencyService.__new__(TransparencyService)
        other.__dict__.update(self.__dict__)
        other.log = merkle.MerkleLog()
        other.log.leaves = list(self.log.leaves)
        other.log._perfect = dict(self.log._perfect)
        other.statements, other.index_of = list(self.statements), dict(self.index_of)
        other.heads = dict(self.heads)
        other.checkpoints = dict(self.checkpoints)
        other.latest_entries = list(self.latest_entries)
        return other

    def receipt(self, index: int, size: int) -> bytes:
        return cose.make_receipt(self.log.root(size), size, index,
                                 self.log.inclusion_path(index, size), self.key, self.kid)

    def head_proof(self, sub: str):
        """Proof of the per-DT head under the most recent cosigned checkpoint."""
        if self.latest is None:
            return None
        entries = self.latest_entries
        tree = merkle.MerkleLog()
        found = None
        for i, e in enumerate(entries):
            tree.append(e)
            if cose.loads(e)[0] == sub:
                found = i
        if found is None:
            return None
        return {"checkpoint": self.latest, "index": found, "count": len(entries),
                "entry": entries[found], "path": tree.inclusion_path(found)}


class Witness:
    def __init__(self, seed: bytes, kid: bytes, ts_public, keydir, mode: str = "profile",
                 honest: bool = True):
        self.key = key_from_seed(seed)
        self.public = self.key.public_key()
        self.kid, self.ts_public, self.keydir, self.mode, self.honest = kid, ts_public, keydir, mode, honest
        self.range = merkle.CompactRange()
        self.heads = {}

    def cosign(self, body_bytes: bytes, ts_sig: bytes, new_statements):
        try:
            self.ts_public.verify(ts_sig, CHECKPOINT_CONTEXT + body_bytes)
        except Exception:
            return None
        if not self.honest:
            return self.key.sign(CHECKPOINT_CONTEXT + body_bytes)
        body = cose.loads(body_bytes)
        if body["size"] != self.range.size + len(new_statements):
            return None                                  # not an extension of what we signed
        rng, heads = self.range.copy(), dict(self.heads)
        for st in new_statements:
            h = profile.header(st)
            pub = self.keydir.public(h["kid"])
            if pub is None or not cose.verify1(st, pub):
                return None
            c = profile.commitment(st)
            if self.mode == "profile":
                if not _successor_ok(heads, h, c):
                    return None
                heads[h["sub"]] = (h["seq"], c)
            rng.append_entry(c)
        if rng.root() != body["root"]:
            return None
        if self.mode == "profile" and merkle.tree_root(head_entries(heads)) != body["heads"]:
            return None
        self.range, self.heads = rng, heads
        return self.key.sign(CHECKPOINT_CONTEXT + body_bytes)
