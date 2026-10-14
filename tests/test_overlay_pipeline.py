import tempfile
import unittest
from pathlib import Path

from dt_trust_checkpoints.config import load_config
from dt_trust_checkpoints.core.checkpoint_controller import CheckpointController
from dt_trust_checkpoints.overlay.consortium import Consortium, InProcessConsortium
from dt_trust_checkpoints.overlay.crypto import KeyRegistry, TimeStampService
from dt_trust_checkpoints.overlay.faults import (
    FaultContext,
    rewrite_pending_tail,
    run_fault_campaign,
)
from dt_trust_checkpoints.overlay.pipeline import EvidenceOverlay
from dt_trust_checkpoints.overlay.policy import EVIDENCE_CATEGORIES, EvidenceClassifier
from dt_trust_checkpoints.overlay.proof_objects import ProofProducer
from dt_trust_checkpoints.overlay.registry import EvidenceLog
from dt_trust_checkpoints.overlay.verifier import OverlayVerifier, TrustAnchors
from dt_trust_checkpoints.overlay.workload import build_workload

ROOT = Path(__file__).resolve().parents[1]


def _run(cosigner, events, store_dir, forced_mode=None, finish=True):
    config = load_config(ROOT / "configs" / "default.json")
    keys = KeyRegistry()
    time_stamps = TimeStampService()
    producer = ProofProducer(keys, time_stamps)
    log = EvidenceLog(cosigner)
    overlay = EvidenceOverlay(
        classifier=EvidenceClassifier(CheckpointController(config.checkpoint_policy), forced_mode),
        producer=producer,
        log=log,
        store_dir=store_dir,
        async_max_batch=8,
    )
    halfway = {}
    rows = []
    for index, event in enumerate(events):
        count = halfway.get(event.twin_id, 0) + 1
        halfway[event.twin_id] = count
        if count == 15 and event.twin_id in producer._chains:
            producer.rotate_key(event.twin_id)
        rows.append(overlay.process(event, index))
    snapshot, pending = overlay.world(), overlay.pending()
    if finish:
        overlay.finish(len(events))
    trust = TrustAnchors(keys, time_stamps.public_key, cosigner.public_keys, cosigner.quorum, cosigner.log_id)
    context = FaultContext(producer, time_stamps, trust, cosigner.log_id, cosigner.quorum, cosigner.members)
    return rows, overlay, snapshot, pending, trust, context


class OverlayPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        config = load_config(ROOT / "configs" / "default.json")
        self.events = build_workload(
            config, "mixed", twins=2, events_per_twin=30, seed=3, malformed_probability=0.05
        )
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_clean_run_verifies_with_process_members(self) -> None:
        with Consortium(4, 3) as consortium:
            rows, overlay, _, _, trust, _ = _run(consortium, self.events, Path(self.tmp.name))
        verdicts = OverlayVerifier(trust).verify_world(overlay.world())
        for verdict in verdicts.values():
            self.assertFalse(verdict.detected, verdict.failed_checks)
        decisions = {row["decision"] for row in rows}
        self.assertTrue({"sync", "async"} <= decisions)
        sync_rows = [row for row in rows if row["decision"] == "sync"]
        self.assertTrue(all(row["reliance_us"] > row["production_us"] for row in sync_rows))

    def test_every_fault_is_detected_by_its_target_check(self) -> None:
        cosigner = InProcessConsortium(4, 3)
        _, overlay, _, _, _, context = _run(cosigner, self.events, Path(self.tmp.name))
        cases = []
        run_fault_campaign(
            overlay.world(), context, EVIDENCE_CATEGORIES, per_cell=2, seed=1, on_case=cases.append
        )
        self.assertTrue(cases)
        for case in cases:
            self.assertTrue(case["detected"], case)
            self.assertTrue(case["target_check_fired"], case)
        misbinding = [case for case in cases if case["fault"] == "dtd_misbinding"]
        self.assertTrue(misbinding)
        self.assertTrue(all(case["checks_fired"] == "vi" for case in misbinding))
        rewrite = [case for case in cases if case["fault"] == "rewrite_resign"]
        self.assertTrue(all(case["checks_fired"] == "v" for case in rewrite))

    def test_rewriting_the_pending_tail_is_not_detected(self) -> None:
        cosigner = InProcessConsortium(4, 3)
        _, _, snapshot, pending, trust, context = _run(
            cosigner, self.events, Path(self.tmp.name), forced_mode="async", finish=False
        )
        self.assertTrue(pending)
        faulty, targets = rewrite_pending_tail(snapshot, pending, context)
        self.assertEqual(len(targets), len(pending))
        verdicts = OverlayVerifier(trust).verify_world(faulty)
        self.assertFalse(any(verdict.detected for verdict in verdicts.values()))


if __name__ == "__main__":
    unittest.main()
