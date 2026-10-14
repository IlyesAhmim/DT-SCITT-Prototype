"""Construction of signed, chained proof objects.

A proof object follows the definition of the article: DT identifier, per-DT
sequence number, event category, payload digest, DTD version in force,
life-cycle phase, time-stamp, and a link to the previous proof object of the
same DT, plus the applied policy rule, a random salt, and the signing key
identifier. The link is part of the signed bytes. The commitment is the
SHA-256 digest of the canonical encoding of the signed object, which includes
the salt.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dt_trust_checkpoints.core.canonicalization_service import canonicalize_to_bytes
from dt_trust_checkpoints.overlay.crypto import KeyRegistry, TimeStampService, generate_keypair


PROOF_OBJECT_VERSION = 1
SIGNED_FIELDS = ("v", "dt", "seq", "cat", "pd", "dtd", "phase", "tst", "salt", "prev", "rule", "kid")


def unsigned_part(proof_object: dict[str, Any]) -> dict[str, Any]:
    """Return the part of a proof object covered by its signature."""
    return {key: proof_object[key] for key in SIGNED_FIELDS}


def commitment_of(proof_object: dict[str, Any]) -> str:
    """Return the commitment (salted digest) of a signed proof object."""
    return hashlib.sha256(canonicalize_to_bytes(proof_object)).hexdigest()


def sign_object(unsigned: dict[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    """Return ``unsigned`` with an Ed25519 signature over its canonical bytes."""
    signature = private_key.sign(canonicalize_to_bytes(unsigned))
    return {**unsigned, "sig": signature.hex()}


@dataclass(slots=True)
class ProofBuild:
    """A freshly built proof object with the measured cost of each step."""

    proof_object: dict[str, Any]
    commitment: str
    size_bytes: int
    timings_ns: dict[str, int]


@dataclass(slots=True)
class _ChainState:
    seq: int = 0
    prev: str | None = None
    key_id: str = ""
    key_counter: int = 0
    private_keys: dict[str, Ed25519PrivateKey] = field(default_factory=dict)


class ProofProducer:
    """Builds proof objects for each DT, keeping its chain state and keys."""

    def __init__(self, keys: KeyRegistry, time_stamps: TimeStampService) -> None:
        self.keys = keys
        self.time_stamps = time_stamps
        self._chains: dict[str, _ChainState] = {}

    def register_twin(self, twin_id: str) -> None:
        """Create the chain state and the first signing key of a DT."""
        if twin_id in self._chains:
            return
        self._chains[twin_id] = _ChainState()
        self._new_key(twin_id)

    def rotate_key(self, twin_id: str) -> str:
        """Replace the signing key of a DT, recording the old key's revocation."""
        chain = self._chains[twin_id]
        old_key_id = chain.key_id
        now_ns = max(time.time_ns(), self.time_stamps.last_issued_ns + 1)
        self.keys.revoke(old_key_id, now_ns)
        return self._new_key(twin_id, valid_from_ns=now_ns)

    def private_key(self, twin_id: str, key_id: str) -> Ed25519PrivateKey:
        """Return a signing key held by the DT operator (used by fault injection)."""
        return self._chains[twin_id].private_keys[key_id]

    def current_key_id(self, twin_id: str) -> str:
        """Return the identifier of the key currently used by a DT."""
        return self._chains[twin_id].key_id

    def next_seq(self, twin_id: str) -> int:
        """Return the sequence number the next proof object of a DT will carry."""
        return self._chains[twin_id].seq + 1

    def build(
        self,
        *,
        twin_id: str,
        category: str,
        record_bytes: bytes,
        dtd_version: int,
        phase: str,
        rule: str,
    ) -> ProofBuild:
        """Time-stamp, link, encode, sign, and commit one proof object."""
        chain = self._chains[twin_id]
        t0 = time.perf_counter_ns()
        payload_digest = hashlib.sha256(record_bytes).hexdigest()
        t1 = time.perf_counter_ns()
        token = self.time_stamps.issue(payload_digest)
        t2 = time.perf_counter_ns()
        unsigned = {
            "v": PROOF_OBJECT_VERSION,
            "dt": twin_id,
            "seq": chain.seq + 1,
            "cat": category,
            "pd": payload_digest,
            "dtd": dtd_version,
            "phase": phase,
            "tst": token,
            "salt": secrets.token_hex(16),
            "prev": chain.prev,
            "rule": rule,
            "kid": chain.key_id,
        }
        signed = sign_object(unsigned, chain.private_keys[chain.key_id])
        t3 = time.perf_counter_ns()
        encoded = canonicalize_to_bytes(signed)
        commitment = hashlib.sha256(encoded).hexdigest()
        t4 = time.perf_counter_ns()
        chain.seq += 1
        chain.prev = commitment
        return ProofBuild(
            proof_object=signed,
            commitment=commitment,
            size_bytes=len(encoded),
            timings_ns={
                "payload_digest": t1 - t0,
                "time_stamp": t2 - t1,
                "encode_sign": t3 - t2,
                "commit": t4 - t3,
            },
        )

    def _new_key(self, twin_id: str, valid_from_ns: int | None = None) -> str:
        chain = self._chains[twin_id]
        chain.key_counter += 1
        key_id = f"{twin_id}/k{chain.key_counter}"
        private_key, public_key = generate_keypair()
        chain.private_keys[key_id] = private_key
        chain.key_id = key_id
        self.keys.register(
            key_id, f"operator-of-{twin_id}", public_key, valid_from_ns or time.time_ns()
        )
        return key_id
