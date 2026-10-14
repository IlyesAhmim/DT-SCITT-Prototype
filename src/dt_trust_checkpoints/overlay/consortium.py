"""Consortium members that co-sign tree heads of the shared evidence log.

Each member runs in its own operating-system process, holds its own Ed25519
key, and remembers the last tree head it co-signed. Before co-signing a new
head it checks the RFC 9162 consistency proof from that last head, so a member
never signs a history that rewrites what it already signed. A tree head is
accepted once ``quorum`` members have co-signed it. Everything runs on one
machine: there is no network transfer and no consensus protocol beyond this
k-of-n co-signature.
"""

from __future__ import annotations

import multiprocessing
import time
from dataclasses import dataclass, field
from multiprocessing.connection import Connection, wait
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dt_trust_checkpoints.core.canonicalization_service import canonicalize_to_bytes
from dt_trust_checkpoints.overlay.crypto import generate_keypair, verify_signature
from dt_trust_checkpoints.overlay.merkle import EMPTY_ROOT, verify_consistency


def tree_head_bytes(log_id: str, size: int, root: bytes) -> bytes:
    """Return the canonical bytes that members sign for a tree head."""
    return canonicalize_to_bytes({"log": log_id, "size": size, "root": root.hex()})


@dataclass(slots=True)
class CosignedHead:
    """A tree head with the co-signatures collected for it."""

    size: int
    root: bytes
    signatures: dict[str, bytes] = field(default_factory=dict)
    quorum_ns: int = 0

    def export(self) -> dict[str, Any]:
        """Return a JSON-compatible view of the head."""
        return {
            "size": self.size,
            "root": self.root.hex(),
            "signatures": {member: sig.hex() for member, sig in sorted(self.signatures.items())},
        }


def verify_head(
    head: CosignedHead, public_keys: dict[str, bytes], quorum: int, log_id: str
) -> bool:
    """Return whether at least ``quorum`` distinct members validly co-signed ``head``."""
    data = tree_head_bytes(log_id, head.size, head.root)
    valid = sum(
        1
        for member, signature in head.signatures.items()
        if member in public_keys and verify_signature(public_keys[member], signature, data)
    )
    return valid >= quorum


class _MemberState:
    """Logic shared by process-based and in-process members."""

    def __init__(self, member_id: str, log_id: str) -> None:
        self.member_id = member_id
        self.log_id = log_id
        self.private_key, self.public_key = generate_keypair()
        self.last_size = 0
        self.last_root = EMPTY_ROOT

    def cosign(
        self, old_size: int, old_root: bytes, new_size: int, new_root: bytes, proof: list[bytes]
    ) -> bytes | None:
        if old_size != self.last_size or old_root != self.last_root:
            return None
        if not verify_consistency(old_size, new_size, old_root, new_root, proof):
            return None
        signature = self.private_key.sign(tree_head_bytes(self.log_id, new_size, new_root))
        self.last_size, self.last_root = new_size, new_root
        return signature


def _member_main(conn: Connection, member_id: str, log_id: str) -> None:
    """Event loop of one member process."""
    state = _MemberState(member_id, log_id)
    # Warm up the signing path so the first measured round is not a cold start.
    Ed25519PrivateKey.generate().sign(b"warm-up")
    conn.send(("ready", member_id, state.public_key))
    while True:
        message = conn.recv()
        if message[0] == "stop":
            break
        _, round_id, old_size, old_root, new_size, new_root, proof = message
        signature = state.cosign(old_size, old_root, new_size, new_root, proof)
        conn.send(("sig", round_id, member_id, signature))
    conn.close()


class QuorumError(RuntimeError):
    """Raised when fewer than ``quorum`` members co-sign a tree head."""


class Consortium:
    """A set of member processes co-signing tree heads with a k-of-n quorum."""

    def __init__(self, members: int = 4, quorum: int = 3, log_id: str = "dt-evidence-log") -> None:
        if not 1 <= quorum <= members:
            raise ValueError("Quorum must be between 1 and the number of members.")
        self.members = members
        self.quorum = quorum
        self.log_id = log_id
        self.public_keys: dict[str, bytes] = {}
        self._connections: dict[str, Connection] = {}
        self._processes: list[multiprocessing.Process] = []
        self._round = 0

    def __enter__(self) -> "Consortium":
        self.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.stop()

    def start(self) -> None:
        """Start the member processes and collect their public keys."""
        context = multiprocessing.get_context()
        for index in range(self.members):
            member_id = f"member-{index + 1}"
            parent_conn, child_conn = context.Pipe()
            process = context.Process(
                target=_member_main, args=(child_conn, member_id, self.log_id), daemon=True
            )
            process.start()
            child_conn.close()
            self._connections[member_id] = parent_conn
            self._processes.append(process)
        for member_id, conn in self._connections.items():
            kind, reported_id, public_key = conn.recv()
            if kind != "ready" or reported_id != member_id:
                raise RuntimeError(f"Unexpected start message from {member_id}.")
            self.public_keys[member_id] = public_key
        # Warm-up rounds on the empty tree head: they exercise the message path
        # and the members' checks without adding anything to the log.
        for _ in range(3):
            self.cosign(0, EMPTY_ROOT, 0, EMPTY_ROOT, [])

    def stop(self) -> None:
        """Stop the member processes."""
        for conn in self._connections.values():
            try:
                conn.send(("stop",))
            except (BrokenPipeError, OSError):
                pass
        for process in self._processes:
            process.join(timeout=5)
        self._connections.clear()
        self._processes.clear()

    def cosign(
        self, old_size: int, old_root: bytes, new_size: int, new_root: bytes, proof: list[bytes]
    ) -> CosignedHead:
        """Ask every member to co-sign a head and return once a quorum signed it."""
        self._round += 1
        round_id = self._round
        started = time.perf_counter_ns()
        message = ("cosign", round_id, old_size, old_root, new_size, new_root, proof)
        for conn in self._connections.values():
            conn.send(message)
        head = CosignedHead(size=new_size, root=new_root)
        pending = set(self._connections.values())
        data = tree_head_bytes(self.log_id, new_size, new_root)
        while len(head.signatures) < self.quorum:
            if not pending:
                raise QuorumError(f"Only {len(head.signatures)} co-signatures for size {new_size}.")
            for conn in wait(list(pending)):
                _, reply_round, member_id, signature = conn.recv()
                if reply_round != round_id:
                    continue  # late reply to an earlier round
                pending.discard(conn)
                if signature is not None and verify_signature(
                    self.public_keys[member_id], signature, data
                ):
                    head.signatures[member_id] = signature
        head.quorum_ns = time.perf_counter_ns() - started
        return head


class InProcessConsortium:
    """Same interface as :class:`Consortium`, with members in the calling process.

    Used only to rebuild alternative histories during fault injection, where
    co-signing latency is irrelevant.
    """

    def __init__(self, members: int = 4, quorum: int = 3, log_id: str = "dt-evidence-log") -> None:
        self.members = members
        self.quorum = quorum
        self.log_id = log_id
        self._states = [_MemberState(f"member-{i + 1}", log_id) for i in range(members)]
        self.public_keys = {state.member_id: state.public_key for state in self._states}

    def __enter__(self) -> "InProcessConsortium":
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None

    def cosign(
        self, old_size: int, old_root: bytes, new_size: int, new_root: bytes, proof: list[bytes]
    ) -> CosignedHead:
        """Co-sign with the first ``quorum`` members that accept the head."""
        head = CosignedHead(size=new_size, root=new_root)
        for state in self._states:
            signature = state.cosign(old_size, old_root, new_size, new_root, proof)
            if signature is not None:
                head.signatures[state.member_id] = signature
        if len(head.signatures) < self.quorum:
            raise QuorumError(f"Only {len(head.signatures)} co-signatures for size {new_size}.")
        return head
