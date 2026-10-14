"""Ed25519 signing, key validity records, and a local time-stamping service.

Unlike ``core.hashing_signature_service`` (a deterministic placeholder), this
module uses real Ed25519 signatures from ``cryptography``. Key validity is
recorded explicitly so that a verifier can check that a key was valid and
unrevoked at the time-stamp of an object. The time-stamping service is local:
it signs ``(digest, time)`` tokens with its own key and stands in for an
ETSI EN 319 422 time-stamping authority, without being one.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from dt_trust_checkpoints.core.canonicalization_service import canonicalize_to_bytes


_PUBLIC_KEY_CACHE: dict[bytes, Ed25519PublicKey] = {}


def generate_keypair() -> tuple[Ed25519PrivateKey, bytes]:
    """Return a new Ed25519 private key and its raw 32-byte public key."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private_key, public_key


def verify_signature(public_key: bytes, signature: bytes, data: bytes) -> bool:
    """Return whether ``signature`` is a valid Ed25519 signature of ``data``."""
    key = _PUBLIC_KEY_CACHE.get(public_key)
    if key is None:
        key = Ed25519PublicKey.from_public_bytes(public_key)
        _PUBLIC_KEY_CACHE[public_key] = key
    try:
        key.verify(signature, data)
    except InvalidSignature:
        return False
    return True


@dataclass(slots=True)
class KeyRecord:
    """Public validity record of one signing key."""

    key_id: str
    owner: str
    public_key: bytes
    valid_from_ns: int
    revoked_at_ns: int | None = None

    def is_valid_at(self, instant_ns: int) -> bool:
        """Return whether the key was valid and unrevoked at ``instant_ns``."""
        if instant_ns < self.valid_from_ns:
            return False
        return self.revoked_at_ns is None or instant_ns < self.revoked_at_ns


class KeyRegistry:
    """Record of signing keys, their owners, rotations, and revocations."""

    def __init__(self) -> None:
        self._records: dict[str, KeyRecord] = {}

    def register(self, key_id: str, owner: str, public_key: bytes, valid_from_ns: int) -> None:
        """Record a new key, valid from ``valid_from_ns``."""
        if key_id in self._records:
            raise ValueError(f"Key {key_id} is already registered.")
        self._records[key_id] = KeyRecord(key_id, owner, public_key, valid_from_ns)

    def revoke(self, key_id: str, revoked_at_ns: int) -> None:
        """Record the revocation of a key."""
        self._records[key_id].revoked_at_ns = revoked_at_ns

    def get(self, key_id: str) -> KeyRecord | None:
        """Return the record of a key, if any."""
        return self._records.get(key_id)

    def export(self) -> list[dict[str, Any]]:
        """Return a JSON-compatible view of all key records."""
        return [
            {
                "key_id": record.key_id,
                "owner": record.owner,
                "public_key": record.public_key.hex(),
                "valid_from_ns": record.valid_from_ns,
                "revoked_at_ns": record.revoked_at_ns,
            }
            for record in self._records.values()
        ]


class TimeStampService:
    """Local service issuing signed ``(digest, time)`` tokens."""

    def __init__(self, service_id: str = "local-tss") -> None:
        self.service_id = service_id
        self._private_key, self.public_key = generate_keypair()
        self._serial = 0
        self._last_ns = 0

    @property
    def last_issued_ns(self) -> int:
        """Return the time of the latest token issued."""
        return self._last_ns

    def issue(self, digest_hex: str) -> dict[str, Any]:
        """Return a signed token binding ``digest_hex`` to the current time."""
        self._serial += 1
        now_ns = max(time.time_ns(), self._last_ns + 1)
        self._last_ns = now_ns
        body = {"tss": self.service_id, "serial": self._serial, "t": now_ns, "d": digest_hex}
        signature = self._private_key.sign(canonicalize_to_bytes(body))
        return {**body, "sig": signature.hex()}


def token_body(token: dict[str, Any]) -> dict[str, Any]:
    """Return the signed part of a time-stamp token."""
    return {key: token[key] for key in ("tss", "serial", "t", "d")}


def verify_token(token: dict[str, Any], service_public_key: bytes) -> bool:
    """Verify the signature of a time-stamp token."""
    try:
        body = token_body(token)
        signature = bytes.fromhex(token["sig"])
    except (KeyError, ValueError, TypeError):
        return False
    return verify_signature(service_public_key, signature, canonicalize_to_bytes(body))
