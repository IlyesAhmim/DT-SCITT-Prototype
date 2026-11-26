"""Minimal COSE_Sign1 (RFC 9052) with Ed25519 (alg -19, RFC 9864), and COSE Receipts (RFC 9942).

Only what the profile needs: tagged COSE_Sign1 messages with attached or
detached payloads, and receipts for the RFC9162_SHA256 verifiable data
structure (inclusion proofs).
"""
import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

# COSE header parameters
ALG, CONTENT_TYPE, KID, CWT_CLAIMS = 1, 3, 4, 15
RECEIPTS, VDS, VDP = 394, 395, 396          # RFC 9942
ED25519 = -19                                # RFC 9864 fully specified (EdDSA -8 is deprecated)
RFC9162_SHA256 = 1                           # RFC 9942, VDS algorithm registry
INCLUSION_PROOFS = -1                        # RFC 9942, VDP label
CWT_ISS, CWT_SUB = 1, 2
COSE_SIGN1_TAG = 18


def dumps(obj) -> bytes:
    return cbor2.dumps(obj, canonical=True)


def loads(data: bytes):
    return cbor2.loads(data)


def _sig_structure(protected_bstr: bytes, payload: bytes, external_aad: bytes = b"") -> bytes:
    return dumps(["Signature1", protected_bstr, external_aad, payload])


def sign1(protected: dict, payload: bytes, key: Ed25519PrivateKey, unprotected=None,
          detached: bool = False) -> bytes:
    protected_bstr = dumps(protected)
    signature = key.sign(_sig_structure(protected_bstr, payload))
    body = [protected_bstr, unprotected or {}, None if detached else payload, signature]
    return dumps(cbor2.CBORTag(COSE_SIGN1_TAG, body))


def decode_sign1(message: bytes):
    """Return (protected_bstr, protected, unprotected, payload_or_None, signature)."""
    obj = loads(message)
    if not isinstance(obj, cbor2.CBORTag) or obj.tag != COSE_SIGN1_TAG or len(obj.value) != 4:
        raise ValueError("not a tagged COSE_Sign1")
    protected_bstr, unprotected, payload, signature = obj.value
    protected = loads(protected_bstr) if protected_bstr else {}
    return protected_bstr, protected, unprotected, payload, signature


def verify1(message: bytes, public_key: Ed25519PublicKey, detached_payload: bytes = None) -> bool:
    protected_bstr, protected, _, payload, signature = decode_sign1(message)
    if protected.get(ALG) != ED25519:
        return False
    if payload is None:
        if detached_payload is None:
            return False
        payload = detached_payload
    try:
        public_key.verify(signature, _sig_structure(protected_bstr, payload))
        return True
    except InvalidSignature:
        return False


def with_unprotected(message: bytes, unprotected: dict) -> bytes:
    """Re-emit a COSE_Sign1 with a new unprotected header (signature unchanged)."""
    protected_bstr, _, _, payload, signature = decode_sign1(message)
    return dumps(cbor2.CBORTag(COSE_SIGN1_TAG, [protected_bstr, unprotected, payload, signature]))


# ---- COSE Receipts (RFC 9942) for RFC9162_SHA256 ------------------------------------

def make_receipt(root: bytes, tree_size: int, leaf_index: int, path, key: Ed25519PrivateKey,
                 kid: bytes) -> bytes:
    proof = dumps([tree_size, leaf_index, list(path)])
    protected = {ALG: ED25519, KID: kid, VDS: RFC9162_SHA256}
    return sign1(protected, root, key, unprotected={VDP: {INCLUSION_PROOFS: [proof]}}, detached=True)


def receipt_proof(receipt: bytes):
    _, protected, unprotected, _, _ = decode_sign1(receipt)
    if protected.get(VDS) != RFC9162_SHA256:
        raise ValueError("unsupported verifiable data structure")
    proofs = unprotected[VDP][INCLUSION_PROOFS]
    tree_size, leaf_index, path = loads(proofs[0])
    return tree_size, leaf_index, path, protected.get(KID)
