"""Tests for configuration loading."""

from pathlib import Path
from unittest import TestCase

from dt_trust_checkpoints.config import load_config
from dt_trust_checkpoints.models import CheckpointMode, ProofType


class ConfigTests(TestCase):
    """Configuration loader tests."""

    def test_load_default_config(self):
        config = load_config(Path("configs/default.json"))

        self.assertEqual(config.proof.default_proof_type, ProofType.CANONICAL_HASH)
        self.assertEqual(config.checkpoint_policy.default_mode, CheckpointMode.ASYNC)
        self.assertEqual(config.proof.default_signer_id, "local-demo-signer")
        self.assertEqual(config.proof.signature_scheme, "local-mock-sha256-v1")
        self.assertEqual(config.storage.evidence_dir, "outputs/evidence")
        self.assertEqual(config.storage.chain_state_dir, "outputs/chain_state")
        self.assertEqual(config.storage.anchor_dir, "outputs/anchors")
        self.assertEqual(config.checkpoint_policy.criticality_sync_threshold, 0.75)
        self.assertTrue(config.checkpoint_policy.reject_malformed_events)
        self.assertEqual(config.verification.synchronized_fidelity_threshold, 0.8)
        self.assertTrue(config.verification.verification_strict_mode)
        self.assertEqual(config.simulation.default_twin_count, 2)
        self.assertEqual(config.simulation.events_per_twin, 12)
        self.assertEqual(config.simulation.default_scenario, "mixed")
        self.assertIn("high_risk", config.simulation.scenario_presets)
        self.assertGreater(config.simulation.event_count, 0)
