"""Document validation and deterministic serialization."""

from __future__ import annotations

import json
from collections.abc import Mapping

FIELDS = ("record_id", "publisher", "heading", "body", "reference", "kind")
KINDS = {"guidance", "advisory"}


def validate_record(value: object) -> dict[str, str]:
    """Return a detached record with exactly the supported fields."""
    if not isinstance(value, Mapping) or set(value) != set(FIELDS):
        raise ValueError(f"record must have exactly these fields: {', '.join(FIELDS)}")
    record = {}
    for field in FIELDS:
        item = value[field]
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"{field} must be a non-empty string")
        record[field] = item
    if record["kind"] not in KINDS:
        raise ValueError("kind must be guidance or advisory")
    return record


def canonical_bytes(value: object) -> bytes:
    record = validate_record(value)
    return b"rag-sec-record-v1\0" + json.dumps(
        record, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
