"""Tests for deterministic canonicalization and hashing."""

from datetime import datetime, timezone
from unittest import TestCase

from dt_trust_checkpoints.core.canonicalization_service import canonicalize_to_json
from dt_trust_checkpoints.core.hashing_signature_service import sha256_hex, sign_digest
from dt_trust_checkpoints.models import EventType


class CanonicalizationHashingTests(TestCase):
    """Proof-material determinism tests."""

    def test_canonicalization_is_key_order_independent(self):
        first = {
            "z": [3, 2, 1],
            "a": {"event_type": EventType.ANOMALY, "value": 7},
            "timestamp": datetime(2026, 1, 1, tzinfo=timezone.utc),
        }
        second = {
            "timestamp": datetime(2026, 1, 1, tzinfo=timezone.utc),
            "a": {"value": 7, "event_type": EventType.ANOMALY},
            "z": [3, 2, 1],
        }

        self.assertEqual(canonicalize_to_json(first), canonicalize_to_json(second))

    def test_sha256_and_mock_signature_are_deterministic(self):
        digest = sha256_hex("trust-checkpoint")

        self.assertEqual(digest, sha256_hex("trust-checkpoint"))
        self.assertEqual(
            sign_digest(digest, "test-signer"),
            sign_digest(digest, "test-signer"),
        )
        self.assertNotEqual(
            sign_digest(digest, "test-signer"),
            sign_digest(digest, "other-signer"),
        )
