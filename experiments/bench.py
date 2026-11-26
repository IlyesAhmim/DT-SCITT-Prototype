#!/usr/bin/env python3
"""Processing costs and sizes of dt-evidence-1 on the local machine.

Measures, per record: production (JCS body, SHA-256, COSE_Sign1 with Ed25519,
commitment), time-stamping, registration under the per-DT policy, checkpoint
cosigning by four witnesses (per batch), receipt generation, and verification;
and the sizes of every evidence object. Also runs the complete synchronous
pipeline locally, without network delay.

Run:  python3 experiments/bench.py      -> results/bench.json
"""
import importlib.metadata as md
import json
import os
import platform
import random
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from common import SUB, World, build_history                     # noqa: E402
from dt_evidence import cose, jcs, merkle, profile               # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), "..", "results")


def stats(samples_s):
    xs = sorted(s * 1000 for s in samples_s)                    # ms
    p99 = xs[min(len(xs) - 1, int(round(0.99 * (len(xs) - 1))))]
    return {"median_ms": statistics.median(xs), "p99_ms": p99, "n": len(xs)}


def timed(fn, n):
    out = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        out.append(time.perf_counter() - t)
    return out


def cpu_model():
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor()


def main(n=2000):
    os.makedirs(OUT, exist_ok=True)
    rng = random.Random(1)
    res = {"environment": {"python": platform.python_version(), "cpu": cpu_model(),
                           "cores": os.cpu_count(), "cryptography": md.version("cryptography"),
                           "cbor2": md.version("cbor2")}}

    # ---- production ------------------------------------------------------------------
    w = World("profile", seed=11)
    w.emit("init", 1_790_812_801_000)
    t0 = 1_790_812_802_000
    samples = []
    for i in range(n):
        t = time.perf_counter()
        w.emit(rng.choice(("dts-transition", "af-validated", "mgmt-action", "lifecycle")), t0 + i)
        samples.append(time.perf_counter() - t)
    res["produce"] = stats(samples)
    items = w.items

    # ---- time-stamping -----------------------------------------------------------------
    cs = [profile.commitment(it["statement"]) for it in items]
    res["timestamp"] = stats(timed(lambda: w.tsa.stamp(cs[0], t0), n))
    for it in items:
        w.stamp(it, t0 + 5)

    # ---- registration ------------------------------------------------------------------
    samples = []
    for it in items:
        t = time.perf_counter()
        w.register(it, t0 + 10)
        samples.append(time.perf_counter() - t)
    res["register"] = stats(samples)

    # ---- checkpoint with four witnesses, per batch size -----------------------------------
    res["checkpoint"] = {}
    for batch in (1, 8, 64):
        wb = World("profile", seed=12)
        wb.emit("init", t0)
        for i in range(batch * 30 - 1):
            wb.emit("af-validated", t0 + i + 1)
        samples = []
        for i, it in enumerate(wb.items):
            wb.ts.register(it["statement"], t0 + 10)
            if (i + 1) % batch == 0:
                t = time.perf_counter()
                cp = wb.ts.checkpoint(wb.witnesses, 3, t0 + 20)
                samples.append(time.perf_counter() - t)
                assert cp is not None
        st = stats(samples)
        st["per_record_ms"] = st["median_ms"] / batch
        res["checkpoint"][str(batch)] = st
    w.checkpoint(t0 + 100)

    # ---- receipts -------------------------------------------------------------------------
    size = len(w.ts.log)
    res["receipt"] = stats(timed(lambda: w.ts.receipt(rng.randrange(size), size), n))

    # ---- verification -----------------------------------------------------------------------
    w.now = t0 + 1_000
    d = w.disclosure()
    t = time.perf_counter()
    outcome = w.verifier.verify(d, w.now)
    total = time.perf_counter() - t
    res["verify_history"] = {"records": len(items), "outcome": outcome[0],
                             "total_ms": total * 1000, "per_record_ms": total * 1000 / len(items)}
    # one record, including the checkpoint checks (no caching)
    small = World("profile", seed=13)
    build_history(small, 2, random.Random(13), batch=1)
    def cold_verify():
        small.verifier.__dict__.pop("_cp_cache", None)      # no cached checkpoint checks
        return small.verify()
    res["verify_record"] = stats(timed(cold_verify, 500))
    res["verify_record"]["note"] = "two-record history: signatures, digests, time-stamps, receipts, checkpoints, head proof"

    # ---- sizes ------------------------------------------------------------------------------
    it = items[10]
    tok = it["tsa"]
    sizes = {"body_jcs": len(jcs.canonicalize(it["body"])), "statement": len(it["statement"]),
             "timestamp_token": len(tok), "receipt_at_size": {}, "checkpoint": None, "head_proof": None}
    for exp in (10, 20):
        nleaf = 2 ** exp
        log = merkle.MerkleLog()
        for j in range(nleaf):
            log.append(j.to_bytes(32, "big"))
        rc = cose.make_receipt(log.root(), nleaf, nleaf // 3, log.inclusion_path(nleaf // 3),
                               w.ts.key, w.ts.kid)
        sizes["receipt_at_size"][str(nleaf)] = len(rc)
    cp = w.ts.latest
    sizes["checkpoint"] = len(cp["body"]) + len(cp["ts_sig"]) + sum(len(s) + 2 for s in cp["cosigs"].values())
    hp = w.ts.head_proof(SUB)
    sizes["head_proof_1_dt"] = len(hp["entry"]) + sum(len(x) for x in hp["path"]) + 8
    sizes["per_record_stored"] = sizes["body_jcs"] + sizes["statement"] + sizes["timestamp_token"] + \
        sizes["receipt_at_size"]["1048576"]
    res["sizes_bytes"] = sizes

    # ---- complete synchronous pipeline without network delay ------------------------------
    wl = World("profile", seed=14)
    wl.emit("init", t0)
    first = wl.items[0]
    wl.stamp(first, t0)
    wl.register(first, t0)
    wl.checkpoint(t0)
    samples = []
    for i in range(300):
        t = time.perf_counter()
        item = wl.emit("af-validated", t0 + i + 1)
        wl.stamp(item, t0 + i + 1)
        wl.register(item, t0 + i + 1)
        wl.checkpoint(t0 + i + 1)
        samples.append(time.perf_counter() - t)
    res["sync_pipeline_local"] = stats(samples)
    res["sync_pipeline_local"]["note"] = "produce + time-stamp + register + checkpoint (4 witnesses), no network"

    for k in ("produce", "register", "verify_record"):
        res[k]["throughput_per_s"] = 1000.0 / res[k]["median_ms"]
    with open(os.path.join(OUT, "bench.json"), "w") as f:
        json.dump(res, f, indent=1)
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
