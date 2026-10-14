"""Canonicalization service for deterministic evidence representation.

The functions in this module convert proof-relevant Python objects into stable
JSON. The output is suitable for hashing because it uses sorted object keys,
compact separators, and explicit conversion for dataclasses, enums, and
datetimes.
"""

from __future__ import annotations

import json
from dataclasses import fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Mapping


JsonCompatible = Any


def _normalize_key(key: Any) -> str:
    if isinstance(key, Enum):
        return str(key.value)
    if isinstance(key, datetime):
        return _normalize_datetime(key)
    return str(key)


def _normalize_datetime(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def to_json_compatible(obj: Any) -> JsonCompatible:
    """Convert an object into deterministic JSON-compatible content."""
    if obj is None or isinstance(obj, bool | int | float | str):
        return obj

    if isinstance(obj, Enum):
        return str(obj.value)

    if isinstance(obj, datetime):
        return _normalize_datetime(obj)

    if isinstance(obj, Path):
        return str(obj)

    if isinstance(obj, bytes):
        return obj.hex()

    if is_dataclass(obj) and not isinstance(obj, type):
        return {
            field.name: to_json_compatible(getattr(obj, field.name))
            for field in fields(obj)
        }

    if isinstance(obj, Mapping):
        return {
            _normalize_key(key): to_json_compatible(value)
            for key, value in sorted(obj.items(), key=lambda item: _normalize_key(item[0]))
        }

    if isinstance(obj, list | tuple):
        return [to_json_compatible(value) for value in obj]

    if isinstance(obj, frozenset | set):
        normalized_values = [to_json_compatible(value) for value in obj]
        return sorted(
            normalized_values,
            key=lambda value: json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ),
        )

    raise TypeError(f"Object of type {type(obj).__name__} is not canonicalizable.")


def canonicalize_to_json(obj: Any) -> str:
    """Return stable JSON text for proof-relevant content."""
    return json.dumps(
        to_json_compatible(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonicalize_to_bytes(obj: Any) -> bytes:
    """Return stable UTF-8 JSON bytes for proof-relevant content."""
    return canonicalize_to_json(obj).encode("utf-8")


class CanonicalizationService:
    """Service wrapper around deterministic canonicalization functions."""

    def canonicalize(self, evidence: Mapping[str, Any]) -> bytes:
        """Return canonical bytes for evidence."""
        return canonicalize_to_bytes(evidence)

    def canonicalize_to_json(self, obj: Any) -> str:
        """Return stable JSON text for any supported object."""
        return canonicalize_to_json(obj)

    def canonicalize_to_bytes(self, obj: Any) -> bytes:
        """Return stable UTF-8 JSON bytes for any supported object."""
        return canonicalize_to_bytes(obj)
