"""Hashing and local mock signature service for proof material.

The signature helper in this module is deliberately a deterministic prototype
placeholder. It is not PKI, not asymmetric cryptography, and not suitable for
production use. It exists so research experiments can carry signature-shaped
metadata before a real key-management design is selected.
"""

from __future__ import annotations

import hashlib


MOCK_SIGNATURE_SCHEME = "local-mock-sha256-v1"


def sha256_hex(data: bytes | str) -> str:
    """Return the SHA-256 hex digest for bytes or UTF-8 text."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sign_digest(digest: str, signer_id: str) -> str:
    """Return a deterministic local mock signature for a digest.

    This is a research placeholder only. It hashes ``signer_id`` and ``digest``
    together so tests and demos have stable signature-like values without
    introducing a real cryptographic signing dependency.
    """
    return sha256_hex(f"{MOCK_SIGNATURE_SCHEME}:{signer_id}:{digest}")


class HashingSignatureService:
    """Service for hashing canonical bytes and producing mock signatures."""

    def digest(self, canonical_bytes: bytes) -> str:
        """Return a digest for canonical bytes."""
        return sha256_hex(canonical_bytes)

    def sha256_hex(self, data: bytes | str) -> str:
        """Return the SHA-256 hex digest for bytes or UTF-8 text."""
        return sha256_hex(data)

    def sign_digest(self, digest: str, signer_id: str) -> str:
        """Return a deterministic local mock signature for a digest."""
        return sign_digest(digest, signer_id)

    def signature_metadata(self, signer_id: str) -> dict[str, str]:
        """Return metadata describing the local mock signature scheme."""
        return {
            "signer_id": signer_id,
            "signature_scheme": MOCK_SIGNATURE_SCHEME,
            "signature_warning": "prototype-only-not-production-pki",
        }
