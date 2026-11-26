"""The dt-evidence-1 profile: event bodies, SCITT Signed Statements, commitments.

An event record has two parts:
  * the event body, a JSON object canonicalized with JCS (RFC 8785) and kept in
    the evidence store of the operator;
  * a SCITT Signed Statement (COSE_Sign1, RFC 9052/RFC 9943) whose payload is the
    SHA-256 digest of the canonical body, so a Transparency Service can register
    it without seeing the body.

The protected header carries the issuer and the DT identifier as CWT claims
(iss, sub) and three profile parameters: the profile identifier, the per-DT
sequence number and the predecessor commitment. The prototype uses private-use
labels for these parameters; a published profile would register them.
"""
import hashlib
import re

from . import cose, jcs

PROFILE = "dt-evidence-1"
H_PROFILE, H_SEQ, H_PREV = -65537, -65538, -65539     # private-use COSE header labels

EVENTS = ("init", "dtd-update", "policy-update", "dts-transition", "af-validated",
          "mgmt-action", "lifecycle", "rejection")
PHASES = ("unbound", "bound", "synchronized", "out-of-sync", "done")   # TS 103 846, clause 5.7
BODY_FIELDS = ("profile", "event", "payloadDigest", "dtdVersion", "dtdDigest", "phase",
               "eventTime", "policy", "salt")

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
MAX_SEQ = 2 ** 53 - 1


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def check_body(body: dict):
    """Raise ValueError unless body is a well-formed dt-evidence-1 event body."""
    if set(body) != set(BODY_FIELDS):
        raise ValueError("unknown or missing body fields")
    for k in BODY_FIELDS:
        if not isinstance(body[k], str):
            raise ValueError(f"{k} must be a string")
    if body["profile"] != PROFILE:
        raise ValueError("unsupported profile")
    if body["event"] not in EVENTS:
        raise ValueError("unsupported event code")
    if body["phase"] not in PHASES:
        raise ValueError("unsupported phase code")
    for k in ("payloadDigest", "dtdDigest", "policy"):
        if not _HEX64.match(body[k]):
            raise ValueError(f"{k} must be 64 lowercase hexadecimal characters")
    if not _HEX32.match(body["salt"]):
        raise ValueError("salt must be 32 lowercase hexadecimal characters")
    if not _TIME.match(body["eventTime"]):
        raise ValueError("eventTime must be UTC with three fractional digits and Z")
    if not body["dtdVersion"]:
        raise ValueError("empty dtdVersion")


def body_bytes(body: dict) -> bytes:
    check_body(body)
    return jcs.canonicalize(body)


def make_statement(body: dict, iss: str, sub: str, seq: int, prev, key, kid: bytes) -> bytes:
    if not 1 <= seq <= MAX_SEQ:
        raise ValueError("sequence number out of range")
    if (seq == 1) != (prev is None):
        raise ValueError("prev is null exactly at initialization")
    protected = {
        cose.ALG: cose.ED25519,
        cose.KID: kid,
        cose.CWT_CLAIMS: {cose.CWT_ISS: iss, cose.CWT_SUB: sub},
        H_PROFILE: PROFILE,
        H_SEQ: seq,
        H_PREV: prev,
    }
    return cose.sign1(protected, sha256(body_bytes(body)), key)


def commitment(statement: bytes) -> bytes:
    """Log entry for a statement: SHA-256 of the Signed Statement as registered."""
    return sha256(statement)


def header(statement: bytes) -> dict:
    """Decode the profile-relevant protected header fields of a statement."""
    _, protected, unprotected, payload, _ = cose.decode_sign1(statement)
    claims = protected.get(cose.CWT_CLAIMS, {})
    return {
        "alg": protected.get(cose.ALG),
        "kid": protected.get(cose.KID),
        "iss": claims.get(cose.CWT_ISS),
        "sub": claims.get(cose.CWT_SUB),
        "profile": protected.get(H_PROFILE),
        "seq": protected.get(H_SEQ),
        "prev": protected.get(H_PREV),
        "payload": payload,
        "unprotected": unprotected,
    }


def time_str(ms: int) -> str:
    """Format milliseconds since the epoch as eventTime."""
    import datetime
    t = datetime.datetime.fromtimestamp(ms / 1000, tz=datetime.timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms % 1000:03d}Z"
