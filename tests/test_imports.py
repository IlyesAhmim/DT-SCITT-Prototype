"""Import smoke tests for the public package API."""

from unittest import TestCase

import dt_trust_checkpoints as dt


class ImportTests(TestCase):
    """Public package API import tests."""

    def test_public_api_imports(self):
        self.assertEqual(dt.EventType.SENSOR_READING.value, "sensor_reading")
        self.assertEqual(dt.ProofType.CANONICAL_HASH.value, "canonical_hash")
        self.assertEqual(dt.CheckpointMode.SYNC.value, "sync")
        self.assertEqual(dt.CheckpointMode.REJECT.value, "reject")
        self.assertEqual(dt.VerificationStatus.VALID.value, "valid")
        self.assertEqual(dt.VerificationStatus.OK.value, "ok")
        self.assertEqual(dt.LifecycleState.OPERATION.value, "operation")
