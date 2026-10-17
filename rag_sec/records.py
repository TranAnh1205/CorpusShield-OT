"""Document validation and deterministic serialization."""

from __future__ import annotations

import json
from collections.abc import Mapping

FIELDS = ("record_id", "publisher", "heading", "body", "reference", "kind")
KINDS = {"guidance", "advisory"}
MAX_RECORD_BYTES = 1_048_576
MAX_QUERY_CHARS = 16_384


def validate_record(value: object) -> dict[str, str]:
    """Return a detached record with exactly the supported fields."""
    if not isinstance(value, Mapping) or set(value) != set(FIELDS):
        raise ValueError(f"record must have exactly these fields: {', '.join(FIELDS)}")
    record = {}
    size = 0
    for field in FIELDS:
        item = value[field]
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"{field} must be a non-empty string")
        if len(item) > MAX_RECORD_BYTES:
            raise ValueError("record exceeds size limit")
        size += len(item.encode("utf-8"))
        if size > MAX_RECORD_BYTES:
            raise ValueError("record exceeds size limit")
        if field == "record_id" and (len(item) > 512 or any(ord(c) < 32 or ord(c) == 127 for c in item)):
            raise ValueError("invalid record_id")
        record[field] = item
    if record["kind"] not in KINDS:
        raise ValueError("kind must be guidance or advisory")
    return record


def validate_search(query: str, top_k: int) -> None:
    if not isinstance(query, str) or len(query) > MAX_QUERY_CHARS:
        raise ValueError("query must be a string of at most 16384 characters")
    if type(top_k) is not int or top_k < 1:
        raise ValueError("top_k must be a positive integer")


def canonical_bytes(value: object) -> bytes:
    record = validate_record(value)
    return b"rag-sec-record-v1\0" + json.dumps(
        record, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
