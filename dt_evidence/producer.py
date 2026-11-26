"""Evidence producer attached to the ETSI interfaces of one digital twin.

It keeps the per-DT chain state (sequence number, predecessor commitment) and
the effective DTD and selection-policy bindings, and turns selected events
into (Signed Statement, event body) pairs.
"""
import random

from .profile import PROFILE, commitment, make_statement, sha256, time_str


class Producer:
    def __init__(self, iss: str, sub: str, key, kid: bytes, seed: int = 0):
        self.iss, self.sub, self.key, self.kid = iss, sub, key, kid
        self.rng = random.Random(seed)
        self.seq, self.prev = 0, None
        self.dtd = None          # (version, digest hex)
        self.policy = None       # digest hex

    def rotate_key(self, key, kid: bytes):
        self.key, self.kid = key, kid

    def _salt(self) -> str:
        return "%032x" % self.rng.getrandbits(128)

    def _emit(self, event: str, payload_digest: str, phase: str, t_ms: int, dtd=None, policy=None):
        dtd = dtd or self.dtd
        body = {
            "profile": PROFILE, "event": event, "payloadDigest": payload_digest,
            "dtdVersion": dtd[0], "dtdDigest": dtd[1], "phase": phase,
            "eventTime": time_str(t_ms), "policy": policy or self.policy, "salt": self._salt(),
        }
        st = make_statement(body, self.iss, self.sub, self.seq + 1, self.prev, self.key, self.kid)
        self.seq += 1
        self.prev = commitment(st)
        return st, body

    def init(self, dtd_version: str, dtd_doc: bytes, policy_doc: bytes, t_ms: int, phase="bound"):
        self.dtd = (dtd_version, sha256(dtd_doc).hex())
        self.policy = sha256(policy_doc).hex()
        return self._emit("init", self.dtd[1], phase, t_ms)

    def dtd_update(self, version: str, dtd_doc: bytes, t_ms: int, phase="synchronized"):
        self.dtd = (version, sha256(dtd_doc).hex())
        return self._emit("dtd-update", self.dtd[1], phase, t_ms)

    def policy_update(self, policy_doc: bytes, t_ms: int, phase="synchronized"):
        self.policy = sha256(policy_doc).hex()
        return self._emit("policy-update", self.policy, phase, t_ms)

    def record(self, event: str, record: bytes, t_ms: int, phase="synchronized"):
        return self._emit(event, sha256(record).hex(), phase, t_ms)
