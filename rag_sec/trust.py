"""Two independent ingestion checks for a fixed, reviewed corpus."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path

from .records import canonical_bytes, validate_record
from .io_utils import read_file


def _key_bytes(key: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("signing key must contain at least 32 bytes")
    return key


def sign(record: object, key: bytes) -> str:
    return hmac.new(_key_bytes(key), canonical_bytes(record), hashlib.sha256).hexdigest()


def verify(record: object, signature: object, key: bytes) -> bool:
    if not isinstance(signature, str) or re.fullmatch(r"[0-9a-f]{64}", signature) is None:
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


def validate_snapshot(value: object) -> dict[str, object]:
    """Copy the trust anchor before processing any caller-controlled iterator."""
    if not isinstance(value, Mapping) or set(value) != {"version", "sha256_by_id"}:
        raise ValueError("invalid snapshot")
    pins = value["sha256_by_id"]
    if type(value["version"]) is not int or value["version"] != 1 or not isinstance(pins, dict) or not pins:
        raise ValueError("invalid snapshot")
    detached = dict(pins)
    for name, digest in detached.items():
        if (not isinstance(name, str) or not name.strip() or len(name) > 512
                or any(ord(c) < 32 or ord(c) == 127 for c in name)
                or not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None):
            raise ValueError("invalid snapshot entry")
    return {"version": 1, "sha256_by_id": detached}


def load_snapshot(path: Path, expected_sha256: str) -> dict[str, object]:
    """Require a digest supplied through a separately trusted configuration."""
    if not isinstance(expected_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise ValueError("snapshot SHA-256 must be 64 lowercase hexadecimal characters")
    raw = read_file(path, 16 * 1024 * 1024)
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256):
        raise ValueError("approved snapshot SHA-256 mismatch")
    return validate_snapshot(json.loads(raw))


def ingest(
    envelopes: Iterable[object],
    key: bytes,
    approved: Mapping[str, object] | None = None,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Accept detached records; return (accepted, rejected reasons)."""
    _key_bytes(key)
    if approved is not None:
        pins = validate_snapshot(approved)["sha256_by_id"]
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
