"""Tests for proof chain, evidence storage, and orchestration."""

import json
from contextlib import redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from dt_trust_checkpoints.cli import main
from dt_trust_checkpoints.core.evidence_orchestrator import EvidenceOrchestrator
from dt_trust_checkpoints.core.proof_chain_builder import ProofChainBuilder
from dt_trust_checkpoints.models import (
    Event,
    EventType,
    LifecycleState,
    ProofEnvelope,
    ProofType,
    TwinContext,
)
from dt_trust_checkpoints.storage.offchain_evidence_store import OffchainEvidenceStore


class EvidencePipelineTests(TestCase):
    """Local proof construction pipeline tests."""

    def _event(self, event_id: str = "event-001") -> Event:
        return Event(
            twin_id="twin-001",
            event_type=EventType.SENSOR_READING,
            source="unit-test",
            payload={"temperature": 41.5, "unit": "celsius"},
            lifecycle_state=LifecycleState.OPERATION,
            observed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            event_id=event_id,
        )

    def test_proof_chain_sequence_and_previous_anchor(self):
        with TemporaryDirectory() as tmpdir:
            chain = ProofChainBuilder(tmpdir)

            self.assertIsNone(chain.previous_anchor("twin-001"))
            self.assertEqual(chain.next_sequence("twin-001"), 1)
            chain.update_chain("twin-001", "anchor-001")
            self.assertEqual(chain.previous_anchor("twin-001"), "anchor-001")
            self.assertEqual(chain.next_sequence("twin-001"), 2)

            reloaded = ProofChainBuilder(tmpdir)
            self.assertEqual(reloaded.previous_anchor("twin-001"), "anchor-001")
            self.assertEqual(reloaded.next_sequence("twin-001"), 3)

    def test_evidence_store_save_load_and_list(self):
        with TemporaryDirectory() as tmpdir:
            store = OffchainEvidenceStore(tmpdir)
            proof = ProofEnvelope(
                proof_type=ProofType.CANONICAL_HASH,
                subject_event_id="event-001",
                twin_id="twin-001",
                canonical_hash="hash-001",
                event_type=EventType.SENSOR_READING,
                seq=1,
                payload_hash="hash-001",
                canonical_payload="{\"value\":1}",
                anchor_digest="anchor-001",
            )

            ref = store.save_proof(proof)
            loaded = store.load_proof(proof.proof_id, proof.twin_id)

            self.assertTrue(Path(ref).exists())
            self.assertEqual(loaded.proof_id, proof.proof_id)
            self.assertEqual(loaded.anchor_digest, "anchor-001")
            self.assertEqual(store.list_proofs("twin-001"), [proof.proof_id])

    def test_orchestrator_creates_stores_and_chains_proofs(self):
        with TemporaryDirectory() as tmpdir:
            evidence_dir = Path(tmpdir) / "evidence"
            chain_dir = Path(tmpdir) / "chain"
            orchestrator = EvidenceOrchestrator(
                evidence_store=OffchainEvidenceStore(evidence_dir),
                chain_builder=ProofChainBuilder(chain_dir),
                signer_id="unit-test-signer",
            )
            context = TwinContext(
                twin_id="twin-001",
                lifecycle_state=LifecycleState.OPERATION,
                domain="test",
                asset_type="demo-asset",
            )

            first = orchestrator.create_proof(self._event("event-001"), context)
            second = orchestrator.create_proof(self._event("event-002"), context)

            self.assertEqual(first.proof.seq, 1)
            self.assertEqual(second.proof.seq, 2)
            self.assertIsNotNone(first.proof.anchor_digest)
            self.assertEqual(second.proof.prev_anchor, first.proof.anchor_digest)
            self.assertTrue(Path(first.offchain_ref).exists())

            loaded = orchestrator.evidence_store.load_proof(
                first.proof.proof_id, first.proof.twin_id
            )
            self.assertEqual(loaded.anchor_digest, first.proof.anchor_digest)

    def test_cli_build_demo_proofs_runs(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "proof": {
                            "default_proof_type": "canonical_hash",
                            "hash_algorithm": "sha256",
                            "canonicalization_version": "v0.1-test",
                            "include_signatures": True,
                            "default_signer_id": "cli-test-signer",
                            "signature_scheme": "local-mock-sha256-v1",
                        },
                        "checkpoint_policy": {
                            "default_mode": "async",
                            "critical_event_mode": "sync",
                            "anchor_only_critical_events": True,
                            "max_async_delay_seconds": 300,
                        },
                        "simulation": {
                            "default_twin_id": "cli-demo-twin",
                            "event_count": 3,
                            "random_seed": 42,
                            "critical_event_probability": 0.2,
                        },
                        "storage": {
                            "outputs_dir": str(root / "outputs"),
                            "experiments_dir": str(root / "experiments"),
                            "evidence_dir": str(root / "outputs" / "evidence"),
                            "offchain_evidence_dir": str(root / "outputs" / "evidence"),
                            "chain_state_dir": str(root / "outputs" / "chain_state"),
                            "anchor_records_file": str(
                                root / "outputs" / "anchor_records.jsonl"
                            ),
                        },
                    }
                ),
                encoding="utf-8",
            )
            stream = StringIO()

            with redirect_stdout(stream):
                exit_code = main(
                    [
                        "--config",
                        str(config_path),
                        "build-demo-proofs",
                        "--count",
                        "3",
                    ]
                )

            output = stream.getvalue()
            self.assertEqual(exit_code, 0)
            self.assertIn("Built demo proofs:", output)
            self.assertIn("payload=", output)
            self.assertIn("anchor=", output)
