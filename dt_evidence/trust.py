"""Trust data shared by registries and verifiers: key status history and a TSA.

The time-stamping authority is emulated: its tokens are COSE_Sign1 objects over
(commitment, generation time). A deployment would use RFC 3161 tokens profiled
by ETSI EN 319 422; the verification logic (token binds the commitment, the
generation time is compared with key validity) is the same.
"""
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import cose


def key_from_seed(seed: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(seed)


@dataclass
class KeyRecord:
    public: object
    iss: str
    valid_from: int                   # ms since the epoch
    revoked_at: int = None            # ms since the epoch, or None


@dataclass
class KeyDirectory:
    """Issuer keys with their validity intervals (historical key status)."""
    keys: dict = field(default_factory=dict)          # kid -> KeyRecord

    def add(self, kid: bytes, public, iss: str, valid_from: int):
        self.keys[kid] = KeyRecord(public, iss, valid_from)

    def revoke(self, kid: bytes, at: int):
        self.keys[kid].revoked_at = at

    def valid_at(self, kid: bytes, iss: str, t: int) -> bool:
        rec = self.keys.get(kid)
        if rec is None or rec.iss != iss or t < rec.valid_from:
            return False
        return rec.revoked_at is None or t < rec.revoked_at

    def public(self, kid: bytes):
        rec = self.keys.get(kid)
        return rec.public if rec else None


class TimeStampAuthority:
    def __init__(self, seed: bytes, kid: bytes = b"tsa-1"):
        self.key = key_from_seed(seed)
        self.kid = kid
        self.public = self.key.public_key()

    def stamp(self, commitment: bytes, gen_time: int) -> bytes:
        payload = cose.dumps({1: commitment, 2: gen_time})
        return cose.sign1({cose.ALG: cose.ED25519, cose.KID: self.kid}, payload, self.key)


def verify_token(token: bytes, commitment: bytes, tsa_public):
    """Return the generation time if the token is valid for commitment, else None."""
    try:
        if not cose.verify1(token, tsa_public):
            return None
        _, _, _, payload, _ = cose.decode_sign1(token)
        content = cose.loads(payload)
        return content[2] if content.get(1) == commitment else None
    except Exception:
        return None
