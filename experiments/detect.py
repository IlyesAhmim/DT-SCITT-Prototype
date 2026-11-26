#!/usr/bin/env python3
"""Manipulation campaign: which manipulations does each level of evidence expose?

Configurations: B0 signed hash chain ("chain"), B1 generic SCITT ("scitt"),
B2 dt-evidence-1 ("profile"). Each manipulation is run on N random honest
histories of 20-60 events per configuration. A manipulation counts as exposed
when the verifier does not return "verified" for the manipulated history
(including the case where the registry refused to register it).

Run:  python3 experiments/detect.py [N]      -> results/detection.json, detection.tex
"""
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(__file__))
from common import ISS, ORDINARY, SUB, World, anchor, build_history, event_plan  # noqa: E402
from dt_evidence import profile                                              # noqa: E402
from dt_evidence.producer import Producer                                    # noqa: E402
from dt_evidence.verifier import _ms_from_time as profile_time                 # noqa: E402

CONFIGS = ("chain", "scitt", "profile")
OUT = os.path.join(os.path.dirname(__file__), "..", "results")


def _replay_state(items):
    """Producer bindings (DTD, policy) after a prefix of items."""
    dtd = policy = None
    for it in items:
        b = it["body"]
        if b["event"] in ("init", "dtd-update"):
            dtd = (b["dtdVersion"], b["dtdDigest"])
        if b["event"] in ("init", "policy-update"):
            policy = b["policy"]
    return dtd, policy


def _resign_from(w, k, modify, salt_seed):
    """Operator rewrites event k (1-based) with modify(body) and re-chains the suffix."""
    p = Producer(ISS, SUB, w.op_key, b"pump7-k1", seed=salt_seed)
    prefix = w.items[:k - 1]
    p.seq, p.prev = k - 1, profile.commitment(prefix[-1]["statement"])
    new = []
    for j, it in enumerate(w.items[k - 1:], start=k):
        body = dict(it["body"])
        if j == k:
            body = modify(body)
        st = profile.make_statement(body, ISS, SUB, j, p.prev, w.op_key, b"pump7-k1")
        p.seq, p.prev = j, profile.commitment(st)
        new.append({"statement": st, "body": body, "receipt": None, "tsa": None, "index": None})
    return prefix, new


def _ordinary_position(w, rng, lo=2):
    cands = [i for i, it in enumerate(w.items, start=1) if it["body"]["event"] in ORDINARY and i >= lo]
    return rng.choice(cands)


def _new_digest(body):
    return dict(body, payloadDigest=profile.sha256(b"rewritten:" + body["payloadDigest"].encode()).hex())


# ---- manipulations: each returns (verifier outcome, registration refused?) ----------------

def m_rewrite(config, seed):
    rng = random.Random(seed)
    w = build_history(World(config, seed), rng.randint(20, 60), rng)
    k = _ordinary_position(w, rng)
    prefix, new = _resign_from(w, k, _new_digest, seed + 10_000)
    refused = False
    if config != "chain":
        t = anchor(w, [], w.now, final_checkpoint=False)
        w.items = prefix + new
        for it in new:
            t += 5
            w.stamp(it, t)
            status, _ = w.register(it, t)
            refused |= status != "registered"
        w.checkpoint(t + 100)
        w.now = t + 1_000
    else:
        w.items = prefix + new
    return w.verify()[0], refused


def m_truncate(config, seed):
    rng = random.Random(seed)
    w = build_history(World(config, seed), rng.randint(20, 60), rng)
    cut = rng.randint(1, 5)
    return w.verify(items=w.items[:-cut])[0], False


def m_dtd_misbinding(config, seed):
    rng = random.Random(seed)
    length = rng.randint(20, 60)
    w = World(config, seed)
    plan = event_plan(length, rng, force_dtd_update_at=length // 3)
    t = 1_790_812_801_000
    old = None
    j_bad = rng.randint(length // 3 + 2, length - 1)
    for i, (kind, kw) in enumerate(plan, start=1):
        if kind == "dtd-update" and i >= length // 3 and old is None:
            old = w.producer.dtd
        if i == j_bad and old is not None and kind in ORDINARY:
            # the event declares the previous DTD although an update was recorded
            st, body = w.producer._emit(kind, profile.sha256(b"decision").hex(), "synchronized", t, dtd=old)
            w.items.append({"statement": st, "body": body, "receipt": None, "tsa": None, "index": None})
        elif i == j_bad and old is not None:
            st, body = w.producer._emit("af-validated", profile.sha256(b"decision").hex(), "synchronized",
                                        t, dtd=old)
            w.items.append({"statement": st, "body": body, "receipt": None, "tsa": None, "index": None})
        else:
            w.emit(kind, t, **kw)
        t += 1_000
    w.now = anchor(w, w.items, t) + 1_000
    return w.verify()[0], False


def m_backdate(config, seed):
    rng = random.Random(seed)
    w = build_history(World(config, seed), rng.randint(20, 60), rng)
    revoked = w.now
    w.keydir.revoke(b"pump7-k1", revoked)
    last = max(profile_time(it["body"]["eventTime"]) for it in w.items)
    t_claim = last + 1                                  # claims to predate the revocation
    t_now = revoked + 60_000
    it = w.emit("mgmt-action", t_claim, record=b"backdated set-point change")
    refused = False
    if config != "chain":
        w.stamp(it, t_now)
        status, _ = w.register(it, t_now)
        refused = status != "registered"
        w.checkpoint(t_now + 100)
    w.now = t_now + 1_000
    return w.verify()[0], refused


def m_pending_rewrite(config, seed):
    rng = random.Random(seed)
    w = build_history(World(config, seed), rng.randint(20, 60), rng)
    # an asynchronous record released to a consumer, then replaced before anchoring
    p = w.producer
    seq, prev = p.seq, p.prev
    it = w.emit("af-validated", w.now, record=b"AF output as released")
    p.seq, p.prev = seq, prev                           # the operator rewinds its chain state
    w.items.pop()
    it2 = w.emit("af-validated", w.now, record=b"AF output as later claimed")
    if config != "chain":
        w.stamp(it2, w.now + 10)
        w.register(it2, w.now + 10)
        w.checkpoint(w.now + 100)
    w.now += 1_000
    return w.verify()[0], False


def m_false_reading(config, seed):
    rng = random.Random(seed)
    w = build_history(World(config, seed), rng.randint(20, 60), rng)
    it = w.emit("dts-transition", w.now, record=b"vibration 2.0 mm/s (sensor actually reads 7.5)")
    w.now = anchor(w, [it], w.now) + 1_000
    return w.verify()[0], False


def m_omitted(config, seed):
    rng = random.Random(seed)
    length = rng.randint(20, 60)
    plan = event_plan(length, rng)
    drop = rng.choice([i for i, (k, _) in enumerate(plan) if k in ORDINARY and i > 0])
    w = build_history(World(config, seed), length, rng, plan=plan[:drop] + plan[drop + 1:])
    return w.verify()[0], False


def m_alter_stored(config, seed):
    rng = random.Random(seed)
    w = build_history(World(config, seed), rng.randint(20, 60), rng)
    k = _ordinary_position(w, rng)
    w.items[k - 1]["body"] = _new_digest(w.items[k - 1]["body"])
    return w.verify()[0], False


def m_delete_middle(config, seed):
    rng = random.Random(seed)
    w = build_history(World(config, seed), rng.randint(20, 60), rng)
    k = rng.randint(2, len(w.items) - 1)
    return w.verify(items=w.items[:k - 1] + w.items[k:])[0], False


def _split_view(config, seed, colluding):
    if config == "chain":
        return None, False
    rng = random.Random(seed)
    w = build_history(World(config, seed, colluding=colluding), rng.randint(20, 60), rng)
    ts_b = w.ts.fork()                                  # the service forks its log
    seq, prev = w.producer.seq, w.producer.prev
    honest = [x for x in w.witnesses if x.honest]
    bad = [x for x in w.witnesses if not x.honest]
    # view A: the record shown to the asset owner
    a = w.emit("mgmt-action", w.now, record=b"set-point change as shown to A")
    w.stamp(a, w.now + 5)
    w.register(a, w.now + 5)
    view_a_witnesses = bad + honest[:max(1, len(honest) - 2)] if colluding >= 2 else w.witnesses
    w.checkpoint(w.now + 50, witnesses=view_a_witnesses)
    # view B: a conflicting record shown to the insurer
    items_a = list(w.items)
    w.items.pop()
    w.producer.seq, w.producer.prev = seq, prev
    b = w.emit("mgmt-action", w.now, record=b"set-point change as shown to B")
    w.stamp(b, w.now + 6)
    ts_a, w.ts = w.ts, ts_b
    w.register(b, w.now + 6)
    view_b_witnesses = bad + honest[-1:] if colluding >= 2 else w.witnesses
    w.checkpoint(w.now + 60, witnesses=view_b_witnesses)
    w.now += 1_000
    outcome_b = w.verify()[0]
    w.ts, w.items = ts_a, items_a
    return outcome_b, False


def m_split_view(config, seed):
    return _split_view(config, seed, colluding=1)


def m_split_view_two(config, seed):
    return _split_view(config, seed, colluding=2)


MANIPULATIONS = [
    ("alter_stored", "Alter a stored record without the signing key", m_alter_stored),
    ("delete_middle", "Delete a record inside the disclosed history", m_delete_middle),
    ("backdate", "Backdate a record with a key compromised after revocation", m_backdate),
    ("rewrite", "Operator re-signs an anchored record and re-chains the suffix", m_rewrite),
    ("truncate", "Withhold the latest records", m_truncate),
    ("dtd_misbinding", "Declare a DTD version other than the recorded one", m_dtd_misbinding),
    ("split_view", "Registry forks its log, one witness colludes", m_split_view),
    ("split_view_two", "Registry forks its log, two witnesses collude", m_split_view_two),
    ("pending_rewrite", "Replace a released record before it is anchored", m_pending_rewrite),
    ("omitted", "Never record an event", m_omitted),
    ("false_reading", "Sign a false reading at recording time", m_false_reading),
]


def main(n=100):
    os.makedirs(OUT, exist_ok=True)
    results = {}
    for key, label, fn in MANIPULATIONS:
        results[key] = {"label": label}
        for config in CONFIGS:
            outcomes, exposed, refused, applicable = {}, 0, 0, 0
            for s in range(n):
                outcome, ref = fn(config, 1_000 * (MANIPULATIONS.index((key, label, fn)) + 1) + s)
                if outcome is None:
                    continue
                applicable += 1
                outcomes[outcome] = outcomes.get(outcome, 0) + 1
                exposed += outcome != "verified"
                refused += ref
            results[key][config] = {"trials": applicable, "exposed": exposed, "refused": refused,
                                    "outcomes": outcomes}
        row = "  ".join(f"{c}:{results[key][c]['exposed']}/{results[key][c]['trials']}" for c in CONFIGS)
        print(f"{label:70s} {row}")
    with open(os.path.join(OUT, "detection.json"), "w") as f:
        json.dump(results, f, indent=1)
    return results


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 100)
