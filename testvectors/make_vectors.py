#!/usr/bin/env python3
"""Deterministic test vectors for dt-evidence-1 (pump twin urn:dt:pump:7).

The history has 18 records: event 1 initializes the chain under DTD version 2,
event 17 records a DTD update to version 3, and event 18 records a validated
AF output under version 3 (the example of the article). All keys are derived
from fixed seeds, so the vectors are reproducible byte for byte.

Run:  python3 testvectors/make_vectors.py   -> testvectors/dt-evidence-1-vectors.json
"""
import json
import os
import sys

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", "experiments"))

from common import ISS, SUB, World            # noqa: E402
from dt_evidence import cose, jcs, profile    # noqa: E402

T = 1_790_841_600_000      # 2026-10-01T08:00:00.000Z


def hexs(b):
    return b.hex() if isinstance(b, (bytes, bytearray)) else b


def honest_world(seed=2026):
    w = World("profile", seed=seed, max_age=600_000)
    kinds = ["dts-transition", "af-validated", "mgmt-action", "lifecycle"]
    w.emit("init", T)
    for i in range(2, 17):
        w.emit(kinds[i % 4], T + 1_000 * i, record=f"pump 7 record {i}".encode())
    w.emit("dtd-update", T + 17_000, version="3")
    w.emit("af-validated", T + 18_000, record=b"AF output: bearing wear index 0.42, validated by the DTM")
    return w


def anchor(w, upto_first=16):
    t = T + 20_000
    for i, it in enumerate(w.items, start=1):
        w.stamp(it, t + i)
        w.register(it, t + i)
        if i == upto_first:
            w.checkpoint(t + 100)
    w.checkpoint(t + 200)
    w.now = t + 1_000


def export_item(it):
    return {"body": it["body"], "body_jcs": jcs.canonicalize(it["body"]).decode(),
            "body_digest": profile.sha256(jcs.canonicalize(it["body"])).hex(),
            "statement": it["statement"].hex(),
            "commitment": profile.commitment(it["statement"]).hex(),
            "tsa_token": hexs(it["tsa"]), "receipt": hexs(it["receipt"])}


def export_cp(cp):
    return {"body": cp["body"].hex(), "ts_sig": cp["ts_sig"].hex(),
            "cosigs": {k.decode(): v.hex() for k, v in cp["cosigs"].items()}}


def export_disclosure(w, items, head=True):
    d = {"sub": SUB, "items": [export_item(it) for it in items],
         "checkpoints": {str(k): export_cp(v) for k, v in w.ts.checkpoints.items()}}
    if head:
        hp = w.ts.head_proof(SUB)
        d["head"] = {"checkpoint": export_cp(hp["checkpoint"]), "index": hp["index"], "count": hp["count"],
                     "entry": hp["entry"].hex(), "path": [p.hex() for p in hp["path"]]}
    return d


def trust(w):
    return {"issuer": ISS, "operator_keys": {k.decode(): {"public": rec.public.public_bytes_raw().hex(),
                                                          "valid_from": rec.valid_from,
                                                          "revoked_at": rec.revoked_at}
                                             for k, rec in w.keydir.keys.items()},
            "tsa_public": w.tsa.public.public_bytes_raw().hex(),
            "ts_public": w.ts.public.public_bytes_raw().hex(),
            "witness_publics": {x.kid.decode(): x.public.public_bytes_raw().hex() for x in w.witnesses},
            "quorum": 3, "max_age_ms": 600_000}


def main():
    vectors = {"profile": profile.PROFILE,
               "header_labels": {"alg": cose.ALG, "kid": cose.KID, "cwt_claims": cose.CWT_CLAIMS,
                                 "dt_profile": profile.H_PROFILE, "dt_seq": profile.H_SEQ,
                                 "dt_prev": profile.H_PREV, "receipts": cose.RECEIPTS, "vds": cose.VDS,
                                 "vdp": cose.VDP},
               "checkpoint_context": "dt-evidence checkpoint v1\\n", "cases": []}

    w = honest_world()
    anchor(w)
    vectors["trust"] = trust(w)
    vectors["now"] = w.now
    vectors["cases"].append({"name": "valid-history", "expected": "verified",
                             "disclosure": export_disclosure(w, w.items)})
    out = w.verify()
    assert out[0] == "verified", out
    print("python verifier:", out)

    # body of event 18 altered after the fact
    items = [dict(it) for it in w.items]
    items[17]["body"] = dict(items[17]["body"], phase="out-of-sync")
    vectors["cases"].append({"name": "altered-body", "expected": "invalid",
                             "disclosure": export_disclosure(w, items)})
    assert w.verify(items=items)[0] == "invalid"

    # the latest record is withheld
    vectors["cases"].append({"name": "withheld-suffix", "expected": "invalid",
                             "disclosure": export_disclosure(w, w.items[:17])})
    assert w.verify(items=w.items[:17])[0] == "invalid"

    # event 18 re-signed by the operator with another output; the registry refuses it
    items = [dict(it) for it in w.items[:17]]
    body = dict(w.items[17]["body"], payloadDigest=profile.sha256(b"another AF output").hex())
    st = profile.make_statement(body, ISS, SUB, 18, profile.commitment(items[16]["statement"]),
                                w.op_key, b"pump7-k1")
    forged = {"statement": st, "body": body, "receipt": None, "tsa": None, "index": None}
    w.stamp(forged, w.now)
    status, _ = w.ts.register(st, w.now)
    assert status == "rejected"
    items.append(forged)
    vectors["cases"].append({"name": "rewritten-record", "expected": "invalid",
                             "disclosure": export_disclosure(w, items)})
    assert w.verify(items=items)[0] == "invalid"

    # event 18 declares DTD version 2 although event 17 recorded version 3
    w2 = honest_world()
    w2.items.pop()
    w2.producer.seq, w2.producer.prev = 17, profile.commitment(w2.items[-1]["statement"])
    old = ("2", profile.sha256(b"DTD v2 of pump 7").hex())
    st, body = w2.producer._emit("af-validated", profile.sha256(b"decision under the old DTD").hex(),
                                 "synchronized", T + 18_000, dtd=old)
    w2.items.append({"statement": st, "body": body, "receipt": None, "tsa": None, "index": None})
    anchor(w2)
    vectors["cases"].append({"name": "dtd-misbinding", "expected": "invalid",
                             "disclosure": export_disclosure(w2, w2.items),
                             "note": "anchored in a separate log with the same keys"})
    assert w2.verify()[:2] == ("invalid", "DTD binding"), w2.verify()

    path = os.path.join(HERE, "dt-evidence-1-vectors.json")
    with open(path, "w") as f:
        json.dump(vectors, f, indent=1)
    print("wrote", path, "with", len(vectors["cases"]), "cases")
    ex = vectors["cases"][0]["disclosure"]["items"][17]
    print("event 18 body:", ex["body_jcs"])
    print("event 18 statement bytes:", len(bytes.fromhex(ex["statement"])))


if __name__ == "__main__":
    main()
