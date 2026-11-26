"""Verifier for disclosed DT histories, with three levels of checking.

mode="chain"   (B0) signed hash chain: signatures, body digests, sequence and
               predecessor links; key validity judged at the claimed eventTime.
mode="scitt"   (B1) generic SCITT: B0 plus receipts (RFC 9942) under checkpoints
               cosigned by a witness quorum; key validity judged at the
               registration (checkpoint) time.
mode="profile" (B2) dt-evidence-1: B1 plus time-stamp tokens, DTD and policy
               binding rules, and an authenticated, sufficiently fresh per-DT head.

Outcomes: "verified" (anchored and every required check passed), "pending"
(no contradiction, but some records are not yet anchored or time-stamped),
"invalid" (a demonstrated contradiction), "indeterminate" (required evidence,
key status, or a fresh head is unavailable).
"""
from . import cose, jcs, merkle, profile
from .registry import CHECKPOINT_CONTEXT
from .trust import verify_token

MODES = ("chain", "scitt", "profile")


def _ms_from_time(s: str) -> int:
    import datetime
    t = datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=datetime.timezone.utc)
    return int(round(t.timestamp() * 1000))


class Verifier:
    def __init__(self, mode, keydir, ts_public=None, tsa_public=None, witness_keys=None,
                 quorum=3, max_age=60_000):
        assert mode in MODES
        self.mode, self.keydir = mode, keydir
        self.ts_public, self.tsa_public = ts_public, tsa_public
        self.witness_keys, self.quorum, self.max_age = witness_keys or {}, quorum, max_age

    def checkpoint_body(self, cp):
        """Decoded checkpoint if signed by the service and a witness quorum, else None.

        Results are cached per checkpoint, as a verifier checks each checkpoint once.
        """
        if cp is None:
            return None
        key = (cp["body"], cp["ts_sig"], tuple(sorted(cp["cosigs"].items())))
        cache = self.__dict__.setdefault("_cp_cache", {})
        if key in cache:
            return cache[key]
        cache[key] = self._checkpoint_body(cp)
        return cache[key]

    def _checkpoint_body(self, cp):
        msg = CHECKPOINT_CONTEXT + cp["body"]
        try:
            self.ts_public.verify(cp["ts_sig"], msg)
        except Exception:
            return None
        good = 0
        for kid, sig in cp["cosigs"].items():
            pub = self.witness_keys.get(kid)
            if pub is None:
                continue
            try:
                pub.verify(sig, msg)
                good += 1
            except Exception:
                pass
        return cose.loads(cp["body"]) if good >= self.quorum else None

    def verify(self, disclosure, now: int):
        sub, items = disclosure["sub"], disclosure["items"]
        cps = disclosure.get("checkpoints", {})
        pending = False
        prev_c, eff_dtd, eff_policy, last_anchored = None, None, None, 0
        commits = []
        if not items:
            return "indeterminate", "empty disclosure", 0
        for seq, it in enumerate(items, start=1):
            st, body = it["statement"], it["body"]
            try:
                h = profile.header(st)
            except Exception:
                return "invalid", "malformed statement", seq
            if (h["alg"] != cose.ED25519 or h["profile"] != profile.PROFILE or h["sub"] != sub
                    or h["unprotected"]):
                return "invalid", "header", seq
            pub = self.keydir.public(h["kid"])
            if pub is None:
                return "indeterminate", "unknown key", seq
            if not cose.verify1(st, pub):
                return "invalid", "signature", seq
            try:
                profile.check_body(body)
                digest = profile.sha256(jcs.canonicalize(body))
            except Exception:
                return "invalid", "body", seq
            if digest != h["payload"]:
                return "invalid", "body digest", seq
            if h["seq"] != seq:
                return "invalid", "sequence", seq
            if h["prev"] != prev_c:
                return "invalid", "predecessor", seq
            c = profile.commitment(st)

            # time evidence used to judge key status
            t = None
            if self.mode == "chain":
                t = _ms_from_time(body["eventTime"])
            reg_time = None
            if self.mode in ("scitt", "profile"):
                rc = it.get("receipt")
                if rc is None:
                    pending = True
                else:
                    try:
                        size, idx, path, _ = cose.receipt_proof(rc)
                    except Exception:
                        return "invalid", "receipt", seq
                    root = merkle.root_from_inclusion(merkle.leaf_hash(c), idx, size, path)
                    if root is None or not cose.verify1(rc, self.ts_public, detached_payload=root):
                        return "invalid", "receipt", seq
                    cpb = self.checkpoint_body(cps.get(size))
                    if cpb is None:
                        return "indeterminate", "no cosigned checkpoint for receipt", seq
                    if cpb["root"] != root:
                        return "invalid", "receipt root differs from cosigned checkpoint", seq
                    reg_time = cpb["time"]
                    last_anchored = seq
                if self.mode == "scitt":
                    t = reg_time
            if self.mode == "profile":
                tok = it.get("tsa")
                t = verify_token(tok, c, self.tsa_public) if tok is not None else None
                if t is None:
                    pending = True
                elif reg_time is not None and t > reg_time:
                    return "invalid", "time-stamp later than registration", seq
            if t is not None and not self.keydir.valid_at(h["kid"], h["iss"], t):
                return "invalid", "key not valid at the evidenced time", seq

            # DT-specific binding rules
            if self.mode == "profile":
                ev = body["event"]
                if (ev == "init") != (seq == 1):
                    return "invalid", "initialization", seq
                if ev == "init":
                    eff_dtd, eff_policy = (body["dtdVersion"], body["dtdDigest"]), body["policy"]
                elif ev == "dtd-update":
                    if body["dtdDigest"] != body["payloadDigest"] or body["dtdVersion"] == eff_dtd[0]:
                        return "invalid", "DTD update", seq
                    eff_dtd = (body["dtdVersion"], body["dtdDigest"])
                    if body["policy"] != eff_policy:
                        return "invalid", "policy binding", seq
                elif ev == "policy-update":
                    if body["policy"] != body["payloadDigest"]:
                        return "invalid", "policy update", seq
                    eff_policy = body["policy"]
                    if (body["dtdVersion"], body["dtdDigest"]) != eff_dtd:
                        return "invalid", "DTD binding", seq
                else:
                    if (body["dtdVersion"], body["dtdDigest"]) != eff_dtd:
                        return "invalid", "DTD binding", seq
                    if body["policy"] != eff_policy:
                        return "invalid", "policy binding", seq
            commits.append(c)
            prev_c = c

        if self.mode == "profile":
            hp = disclosure.get("head")
            if hp is None:
                return "indeterminate", "no per-DT head", len(items)
            cpb = self.checkpoint_body(hp["checkpoint"])
            if cpb is None:
                return "indeterminate", "head checkpoint not cosigned", len(items)
            if now - cpb["time"] > self.max_age:
                return "indeterminate", "no sufficiently fresh head", len(items)
            root = merkle.root_from_inclusion(merkle.leaf_hash(hp["entry"]), hp["index"],
                                              hp["count"], hp["path"])
            if root is None or root != cpb["heads"]:
                return "invalid", "head proof", len(items)
            hsub, hseq, hc = cose.loads(hp["entry"])
            if hsub != sub:
                return "invalid", "head subject", len(items)
            if hseq > len(items):
                return "invalid", "withheld suffix", len(items)
            if commits[hseq - 1] != hc:
                return "invalid", "history differs from registered head", hseq
            if hseq < last_anchored:
                return "indeterminate", "head older than the receipts", hseq
        if pending:
            return "pending", "not yet anchored", last_anchored
        return "verified", "", len(items)
