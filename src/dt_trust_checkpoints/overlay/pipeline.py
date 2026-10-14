"""Evidence overlay pipeline: classification, proof construction, checkpoints.

For each event the overlay measures, with ``time.perf_counter_ns``:

* production: classification, canonical encoding of the full record, payload
  digest, time-stamp token, Ed25519 signature, commitment, and the append to
  the evidence store;
* for a synchronous checkpoint: appending the anchor (after any queued
  asynchronous anchors), co-signing a new tree head by a quorum of consortium
  members, building the receipt, and verifying it on the DT side;
* the time to reliance: production for an asynchronous outcome, which is usable
  at once, and production plus the receipt for a synchronous one, which is
  relied on only once its receipt verifies.

Asynchronous anchors are queued on the DT side and appended to the shared log
in batches: at the next synchronous checkpoint, when the queue holds
``async_max_batch`` anchors, or when its oldest anchor is
``async_max_age_events`` events old. A rejected event is not anchored; a
signed rejection record takes its place in the chain and is anchored
asynchronously.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

from dt_trust_checkpoints.core.canonicalization_service import (
    canonicalize_to_bytes,
    to_json_compatible,
)
from dt_trust_checkpoints.models import Event
from dt_trust_checkpoints.overlay.consortium import CosignedHead
from dt_trust_checkpoints.overlay.policy import REJECTION_CATEGORY, EvidenceClassifier
from dt_trust_checkpoints.overlay.proof_objects import ProofProducer
from dt_trust_checkpoints.overlay.registry import (
    EvidenceLog,
    Receipt,
    anchor_bytes,
    verify_receipt,
)


@dataclass(slots=True)
class StoredEntry:
    """One entry of the evidence store: a signed proof object and its full record."""

    proof_object: dict[str, Any]
    record: bytes


@dataclass(slots=True)
class EvidenceWorld:
    """Everything a verifier outside the runtime can obtain."""

    chains: dict[str, list[StoredEntry]]
    anchors: list[bytes]
    heads: list[CosignedHead]
    receipts: dict[tuple[str, int], Receipt]
    sealed_size: int
    initial_dtd: dict[str, int]

    def copy(self) -> "EvidenceWorld":
        """Return a shallow copy whose containers can be modified independently."""
        return EvidenceWorld(
            chains={twin: list(entries) for twin, entries in self.chains.items()},
            anchors=list(self.anchors),
            heads=list(self.heads),
            receipts=dict(self.receipts),
            sealed_size=self.sealed_size,
            initial_dtd=dict(self.initial_dtd),
        )


@dataclass(slots=True)
class _Queued:
    twin_id: str
    seq: int
    anchor: bytes
    event_index: int
    stored_ns: int
    row: dict[str, Any]
    log_index: int = -1


class EvidenceStore:
    """Append-only JSON Lines store, one file per DT, flushed after each entry."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self._files: dict[str, TextIO] = {}

    def append(self, twin_id: str, proof_object: dict[str, Any], record: bytes) -> None:
        handle = self._files.get(twin_id)
        if handle is None:
            handle = (self.directory / f"{twin_id}.jsonl").open("w", encoding="utf-8")
            self._files[twin_id] = handle
        handle.write(
            json.dumps({"proof_object": proof_object, "record": record.decode("utf-8")},
                       sort_keys=True, separators=(",", ":"))
            + "\n"
        )
        handle.flush()

    def close(self) -> None:
        for handle in self._files.values():
            handle.close()
        self._files.clear()


def _us(nanoseconds: int) -> float:
    return nanoseconds / 1000.0


class EvidenceOverlay:
    """Turns events into proof objects and applies checkpoint semantics."""

    def __init__(
        self,
        *,
        classifier: EvidenceClassifier,
        producer: ProofProducer,
        log: EvidenceLog,
        store_dir: Path,
        async_max_batch: int = 64,
        async_max_age_events: int = 300,
    ) -> None:
        self.classifier = classifier
        self.producer = producer
        self.log = log
        self.store = EvidenceStore(store_dir)
        self.async_max_batch = async_max_batch
        self.async_max_age_events = async_max_age_events
        self.chains: dict[str, list[StoredEntry]] = {}
        self.receipts: dict[tuple[str, int], Receipt] = {}
        self.initial_dtd: dict[str, int] = {}
        self.seals: list[dict[str, Any]] = []
        self._queue: list[_Queued] = []

    def process(self, event: Event, index: int) -> dict[str, Any]:
        """Process one event and return its measurements."""
        t0 = time.perf_counter_ns()
        decision = self.classifier.classify(event)
        t1 = time.perf_counter_ns()
        twin_id = event.twin_id
        category = event.event_type.value
        dtd_version = int(event.metadata.get("dtd_version", 0))
        if twin_id not in self.initial_dtd:
            self.initial_dtd[twin_id] = dtd_version - 1 if category == "dtd_update" else dtd_version
        row: dict[str, Any] = {
            "index": index,
            "event_id": event.event_id,
            "twin_id": twin_id,
            "category": category,
            "evidence": decision.relevant,
            "decision": decision.mode,
            "rule": decision.rule,
            "classify_us": _us(t1 - t0),
        }
        if not decision.relevant:
            return row

        self.producer.register_twin(twin_id)
        record = to_json_compatible(event)
        object_category = category
        if decision.mode == "reject":
            object_category = REJECTION_CATEGORY
            record = {
                "rejection_of": event.event_id,
                "rejected_category": category,
                "reason": decision.reason,
                "rejected_record_digest": hashlib.sha256(canonicalize_to_bytes(record)).hexdigest(),
            }
        record_bytes = canonicalize_to_bytes(record)
        t2 = time.perf_counter_ns()
        build = self.producer.build(
            twin_id=twin_id,
            category=object_category,
            record_bytes=record_bytes,
            dtd_version=dtd_version,
            phase=event.lifecycle_state.value,
            rule=decision.rule,
        )
        t3 = time.perf_counter_ns()
        self.store.append(twin_id, build.proof_object, record_bytes)
        self.chains.setdefault(twin_id, []).append(StoredEntry(build.proof_object, record_bytes))
        t4 = time.perf_counter_ns()
        seq = build.proof_object["seq"]
        anchor = anchor_bytes(twin_id, seq, build.commitment)
        row.update(
            {
                "seq": seq,
                "record_bytes": len(record_bytes),
                "object_bytes": build.size_bytes,
                "anchor_bytes": len(anchor),
                "record_us": _us(t2 - t1),
                "digest_us": _us(build.timings_ns["payload_digest"]),
                "time_stamp_us": _us(build.timings_ns["time_stamp"]),
                "encode_sign_us": _us(build.timings_ns["encode_sign"]),
                "commit_us": _us(build.timings_ns["commit"]),
                "store_us": _us(t4 - t3),
                "production_us": _us(t4 - t0),
            }
        )

        if decision.mode == "sync":
            flushed = self._append_queue()
            log_index = self.log.append(anchor)
            head = self.log.seal()
            assert head is not None
            t5 = time.perf_counter_ns()
            receipt = self.log.receipt(log_index, head)
            if not verify_receipt(
                anchor,
                receipt,
                head,
                self.log.cosigner.public_keys,
                self.log.cosigner.quorum,
                self.log.cosigner.log_id,
            ):
                raise RuntimeError(f"Receipt of {twin_id}#{seq} does not verify.")
            t6 = time.perf_counter_ns()
            self.receipts[(twin_id, seq)] = receipt
            self._settle(flushed, head, index, t6, trigger="sync")
            row.update(
                {
                    "seal_us": _us(t5 - t4),
                    "quorum_us": _us(head.quorum_ns),
                    "receipt_us": _us(t6 - t5),
                    "reliance_us": _us(t6 - t0),
                    "batch_size": len(flushed) + 1,
                    "exposure_events": 0,
                    "exposure_us": 0.0,
                }
            )
            return row

        if decision.mode == "async":
            row["reliance_us"] = _us(t4 - t0)
        self._queue.append(_Queued(twin_id, seq, anchor, index, t4, row))
        if (
            len(self._queue) >= self.async_max_batch
            or index - self._queue[0].event_index >= self.async_max_age_events
        ):
            self._background_seal(index, trigger="async-bound")
        return row

    def pending(self) -> list[tuple[str, int]]:
        """Return the (DT, seq) pairs whose anchors are still queued."""
        return [(queued.twin_id, queued.seq) for queued in self._queue]

    def world(self) -> EvidenceWorld:
        """Return the verifier's view of the evidence produced so far."""
        return EvidenceWorld(
            chains={twin: list(entries) for twin, entries in self.chains.items()},
            anchors=list(self.log.anchors),
            heads=list(self.log.heads),
            receipts=dict(self.receipts),
            sealed_size=self.log.sealed_size,
            initial_dtd=dict(self.initial_dtd),
        )

    def finish(self, index: int) -> None:
        """Anchor every queued commitment and close the evidence store."""
        if self._queue:
            self._background_seal(index, trigger="end")
        self.store.close()

    def _append_queue(self) -> list[_Queued]:
        flushed = self._queue
        self._queue = []
        for queued in flushed:
            queued.log_index = self.log.append(queued.anchor)
        return flushed

    def _background_seal(self, index: int, trigger: str) -> None:
        flushed = self._append_queue()
        head = self.log.seal()
        assert head is not None
        self._settle(flushed, head, index, time.perf_counter_ns(), trigger=trigger)

    def _settle(
        self, flushed: list[_Queued], head: CosignedHead, index: int, sealed_ns: int, trigger: str
    ) -> None:
        for queued in flushed:
            self.receipts[(queued.twin_id, queued.seq)] = self.log.receipt(queued.log_index, head)
            queued.row["batch_size"] = len(flushed)
            queued.row["exposure_events"] = index - queued.event_index
            queued.row["exposure_us"] = _us(sealed_ns - queued.stored_ns)
        self.seals.append(
            {
                "size": head.size,
                "trigger": trigger,
                "queued_anchors": len(flushed),
                "quorum_us": _us(head.quorum_ns),
                "event_index": index,
            }
        )
