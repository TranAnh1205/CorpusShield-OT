"""Two independent ingestion checks for a fixed, reviewed corpus."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterable, Mapping

from .records import canonical_bytes, validate_record


def _key_bytes(key: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("signing key must contain at least 32 bytes")
    return key


def sign(record: object, key: bytes) -> str:
    return hmac.new(_key_bytes(key), canonical_bytes(record), hashlib.sha256).hexdigest()


def verify(record: object, signature: object, key: bytes) -> bool:
    if not isinstance(signature, str) or len(signature) != 64:
        return False
    try:
        return hmac.compare_digest(sign(record, key), signature)
    except (TypeError, ValueError):
        return False


def snapshot(records: Iterable[object]) -> dict[str, object]:
    """Pin IDs and content hashes from a reviewed corpus."""
    pins: dict[str, str] = {}
    for value in records:
        record = validate_record(value)
        name = record["record_id"]
        if name in pins:
            raise ValueError(f"duplicate record_id in baseline: {name}")
        pins[name] = hashlib.sha256(canonical_bytes(record)).hexdigest()
    if not pins:
        raise ValueError("baseline must not be empty")
    return {"version": 1, "sha256_by_id": pins}


def ingest(
    envelopes: Iterable[object],
    key: bytes,
    approved: Mapping[str, object] | None = None,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Accept detached records; return (accepted, rejected reasons)."""
    _key_bytes(key)
    if approved is not None:
        pins = approved.get("sha256_by_id")
        if approved.get("version") != 1 or not isinstance(pins, dict):
            raise ValueError("invalid snapshot")
    else:
        pins = None
    accepted: list[dict[str, str]] = []
    rejected: list[dict[str, str]] = []
    seen: set[str] = set()
    for envelope in envelopes:
        record_id = "<invalid>"
        try:
            if not isinstance(envelope, Mapping) or set(envelope) != {"record", "signature"}:
                raise ValueError("invalid envelope")
            record = validate_record(envelope["record"])
            record_id = record["record_id"]
            if record_id in seen:
                raise ValueError("duplicate record_id")
            if not verify(record, envelope["signature"], key):
                raise ValueError("invalid signature")
            digest = hashlib.sha256(canonical_bytes(record)).hexdigest()
            if pins is not None and pins.get(record_id) != digest:
                raise ValueError("not in approved snapshot")
            seen.add(record_id)
            accepted.append(record)
        except (TypeError, ValueError) as error:
            rejected.append({"record_id": record_id, "reason": str(error)})
    return accepted, rejected
