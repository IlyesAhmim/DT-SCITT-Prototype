"""Verify a frozen saved-format example and a modified-record negative case."""

from __future__ import annotations

import json
from pathlib import Path

from dt_trust_checkpoints.overlay.consortium import CosignedHead, verify_head
from dt_trust_checkpoints.overlay.crypto import KeyRegistry
from dt_trust_checkpoints.overlay.merkle import MerkleTree, leaf_hash
from dt_trust_checkpoints.overlay.pipeline import EvidenceWorld, StoredEntry
from dt_trust_checkpoints.overlay.proof_objects import commitment_of
from dt_trust_checkpoints.overlay.registry import Receipt
from dt_trust_checkpoints.overlay.verifier import OverlayVerifier, TrustAnchors

ROOT = Path(__file__).resolve().parents[1]


def load_example(path: Path) -> tuple[dict, EvidenceWorld, TrustAnchors]:
    vector = json.loads(path.read_text(encoding="utf-8"))
    public = vector["trust_anchors"]
    keys = KeyRegistry()
    for item in public["keys"]:
        keys.register(item["key_id"], item["owner"],
                      bytes.fromhex(item["public_key"]), item["valid_from_ns"])
        if item["revoked_at_ns"] is not None:
            keys.revoke(item["key_id"], item["revoked_at_ns"])
    trust = TrustAnchors(
        keys, bytes.fromhex(public["time_stamp_key"]),
        {k: bytes.fromhex(v) for k, v in public["member_keys"].items()},
        public["quorum"], public["log_id"],
    )
    saved = vector["world"]
    heads = [CosignedHead(h["size"], bytes.fromhex(h["root"]),
                         {k: bytes.fromhex(v) for k, v in h["signatures"].items()})
             for h in saved["heads"]]
    receipts = {(r["dt"], r["seq"]): Receipt(
        r["index"], r["size"], [bytes.fromhex(x) for x in r["path"]])
        for r in saved["receipts"]}
    chains = {dt: [StoredEntry(e["proof_object"], e["record"].encode("utf-8"))
                   for e in entries] for dt, entries in saved["chains"].items()}
    world = EvidenceWorld(chains, [x.encode("utf-8") for x in saved["anchors"]],
                          heads, receipts, saved["sealed_size"],
                          public["initial_dtd"])
    return vector, world, trust


def main() -> int:
    vector, world, trust = load_example(ROOT / "examples" / "prototype-test-vector.json")
    tree = MerkleTree()
    for anchor in world.anchors:
        tree.append(leaf_hash(anchor))
    for head in world.heads:
        if tree.root(head.size) != head.root:
            raise ValueError("Saved head does not match the example's log prefix")
        if not verify_head(head, trust.member_keys, trust.quorum, trust.log_id):
            raise ValueError("Saved head does not have the required valid witness signatures")
    actual = {f"{dt}:{e.proof_object['seq']}": commitment_of(e.proof_object)
              for dt, entries in world.chains.items() for e in entries}
    if actual != vector["expected"]["commitments"]:
        raise ValueError("Commitments disagree with the frozen expected values")
    verdicts = OverlayVerifier(trust).verify_world(world)
    objects = [o for v in verdicts.values() for o in v.objects]
    if any(v.detected for v in verdicts.values()) or not all(o.anchored for o in objects):
        raise ValueError("Clean example did not verify as anchored")
    if len(objects) != vector["expected"]["objects"]:
        raise ValueError("Unexpected example object count")

    modified = world.copy()
    dt = sorted(modified.chains)[0]
    first = modified.chains[dt][0]
    modified.chains[dt][0] = StoredEntry(dict(first.proof_object), first.record + b" ")
    negative = OverlayVerifier(trust).verify_world(modified)[dt]
    if "iii" not in negative.objects[0].failed:
        raise ValueError("Modified source record was not detected by digest check iii")
    report = {
        "scope": "Saved prototype JSON format; inclusion relative to supplied checkpoints",
        "objects": len(objects), "anchored": sum(o.anchored for o in objects),
        "signed_heads": len(world.heads), "failures": [],
        "modified_record_detected_by_check": "iii",
        "current_head_freshness_tested": False,
        "scitt_or_etsi_conformance_tested": False,
    }
    (ROOT / "checks").mkdir(exist_ok=True)
    (ROOT / "checks" / "example_verification.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
