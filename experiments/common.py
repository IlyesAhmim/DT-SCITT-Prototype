"""Shared set-up for the tests, the manipulation campaign, and the benchmarks."""
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dt_evidence import profile                                  # noqa: E402
from dt_evidence.producer import Producer                         # noqa: E402
from dt_evidence.registry import TransparencyService, Witness     # noqa: E402
from dt_evidence.trust import KeyDirectory, TimeStampAuthority, key_from_seed  # noqa: E402
from dt_evidence.verifier import Verifier                         # noqa: E402

ISS = "https://operator.example/dt-platform"
SUB = "urn:dt:pump:7"
T0 = 1_790_812_800_000            # 2026-10-01T00:00:00.000Z in ms
CONFIG_TS_MODE = {"chain": None, "scitt": "generic", "profile": "profile"}


def seed_bytes(label: str, seed: int = 0) -> bytes:
    return profile.sha256(f"{label}/{seed}".encode())


class World:
    """Keys, TSA, Transparency Service, witnesses and one producer for one DT."""

    def __init__(self, config: str = "profile", seed: int = 0, n_witnesses: int = 4, quorum: int = 3,
                 colluding: int = 0, max_age: int = 60_000):
        self.config, self.seed, self.quorum = config, seed, quorum
        self.keydir = KeyDirectory()
        self.op_key = key_from_seed(seed_bytes("operator-key-1", seed))
        self.keydir.add(b"pump7-k1", self.op_key.public_key(), ISS, T0)
        self.tsa = TimeStampAuthority(seed_bytes("tsa", seed))
        mode = CONFIG_TS_MODE[config] or "generic"
        self.ts = TransparencyService(seed_bytes("ts", seed), self.keydir, mode=mode)
        self.witnesses = [Witness(seed_bytes(f"witness-{i}", seed), f"w{i}".encode(), self.ts.public,
                                  self.keydir, mode=mode, honest=(i >= colluding))
                          for i in range(n_witnesses)]
        self.producer = Producer(ISS, SUB, self.op_key, b"pump7-k1", seed=seed)
        self.verifier = Verifier(config, self.keydir, self.ts.public, self.tsa.public,
                                 {w.kid: w.public for w in self.witnesses}, quorum, max_age)
        self.items = []
        self.now = T0

    # ---- producing and anchoring ---------------------------------------------------------
    def emit(self, kind: str, t: int, **kw):
        p = self.producer
        if kind == "init":
            st, body = p.init("2", b"DTD v2 of pump 7", b"selection policy v1", t)
        elif kind == "dtd-update":
            st, body = p.dtd_update(kw["version"], f"DTD v{kw['version']} of pump 7".encode(), t)
        elif kind == "policy-update":
            st, body = p.policy_update(f"selection policy {kw['tag']}".encode(), t)
        else:
            st, body = p.record(kind, kw.get("record", f"{kind}@{t}".encode()), t,
                                phase=kw.get("phase", "synchronized"))
        item = {"statement": st, "body": body, "receipt": None, "tsa": None, "index": None}
        self.items.append(item)
        return item

    def stamp(self, item, t: int):
        item["tsa"] = self.tsa.stamp(profile.commitment(item["statement"]), t)

    def register(self, item, t: int):
        status, info = self.ts.register(item["statement"], t)
        if status == "registered":
            item["index"] = info
        return status, info

    def checkpoint(self, t: int, witnesses=None):
        cp = self.ts.checkpoint(witnesses or self.witnesses, self.quorum, t)
        if cp is None:
            return None
        size = len(self.ts.log)
        for it in self.items:
            if it["index"] is not None and it["receipt"] is None and it["index"] < size:
                it["receipt"] = self.ts.receipt(it["index"], size)
        return cp

    def disclosure(self, items=None):
        items = self.items if items is None else items
        d = {"sub": SUB, "items": [dict(it) for it in items],
             "checkpoints": dict(self.ts.checkpoints)}
        d["head"] = self.ts.head_proof(SUB) if self.ts.mode == "profile" else None
        return d

    def verify(self, items=None, now=None):
        return self.verifier.verify(self.disclosure(items), self.now if now is None else now)


ORDINARY = ("dts-transition", "af-validated", "mgmt-action", "lifecycle")


def event_plan(length: int, rng: random.Random, force_dtd_update_at=None):
    """Event kinds for an honest history: init, ordinary events, occasional updates."""
    plan, version = [("init", {})], 2
    for i in range(1, length):
        r = rng.random()
        if i == force_dtd_update_at or r < 0.06:
            version += 1
            plan.append(("dtd-update", {"version": str(version)}))
        elif r < 0.09:
            plan.append(("policy-update", {"tag": f"v{rng.randrange(10**6)}"}))
        else:
            plan.append((rng.choice(ORDINARY), {}))
    return plan


def anchor(world: World, items, t: int, batch: int = 8, final_checkpoint: bool = True):
    """Time-stamp, register and checkpoint items; return the last time used."""
    for i, it in enumerate(items):
        t += 5
        world.stamp(it, t)
        if world.config != "chain":
            world.register(it, t)
            if (i + 1) % batch == 0:
                world.checkpoint(t + 50)
    if world.config != "chain" and final_checkpoint:
        world.checkpoint(t + 100)
    return t + 100


def build_history(world: World, length: int, rng: random.Random, batch: int = 8,
                  anchor_all: bool = True, step: int = 1_000, plan=None):
    """Honest history, anchored in batches, with world.now set after the last checkpoint."""
    t = T0 + 1_000
    for kind, kw in plan or event_plan(length, rng):
        world.emit(kind, t, **kw)
        t += step
    t = anchor(world, world.items, t, batch, final_checkpoint=anchor_all)
    world.now = t + 1_000
    return world
