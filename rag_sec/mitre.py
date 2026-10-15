"""Independent MITRE ATT&CK STIX loader with pinned input hashes."""

from __future__ import annotations

import hashlib
import json
import re
import urllib.request
from pathlib import Path

from .records import validate_record

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"
COMMIT = "c2494b29dd268c46a5d0ea0990553e4327cd2253"
VERSION = "20.0"
FILES = {
    "enterprise": ("enterprise-attack-20.0.json", "81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352"),
    "ics": ("ics-attack-20.0.json", "c9ca0ce523a1b5e512060a390415e8aefe8f6d32c5f82d7de81264960c1e1183"),
}


def _verified_bytes(path: Path, expected: str) -> bytes:
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError(f"SHA-256 mismatch: {path}")
    return raw


def fetch_mitre() -> list[Path]:
    """Download missing pinned source files; refuse modified local copies."""
    RAW.mkdir(parents=True, exist_ok=True)
    paths = []
    for domain, (filename, expected) in FILES.items():
        path = RAW / filename
        if not path.exists():
            url = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
                   f"{COMMIT}/{domain}-attack/{filename}")
            with urllib.request.urlopen(url, timeout=120) as response:
                raw = response.read()
            if hashlib.sha256(raw).hexdigest() != expected:
                raise ValueError(f"downloaded MITRE data hash mismatch: {domain}")
            path.write_bytes(raw)
        _verified_bytes(path, expected)
        paths.append(path)
    return paths


def _compact(value: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"\(Citation: [^)]*\)", "", value)).strip()


def _active(item: dict[str, object]) -> bool:
    return not item.get("revoked") and not item.get("x_mitre_deprecated")


def load_mitre() -> list[dict[str, object]]:
    """Return record plus selection metadata for active, mitigated techniques."""
    results: list[dict[str, object]] = []
    for domain, (filename, expected) in FILES.items():
        objects = json.loads(_verified_bytes(RAW / filename, expected))["objects"]
        by_stix = {item["id"]: item for item in objects if _active(item)}
        mitigation_by_tech: dict[str, list[str]] = {}
        for item in objects:
            if item.get("type") != "relationship" or item.get("relationship_type") != "mitigates" or not _active(item):
                continue
            mitigation = by_stix.get(item.get("source_ref"))
            if not mitigation or mitigation.get("type") != "course-of-action":
                continue
            detail = _compact(str(item.get("description", "")))
            mitigation_by_tech.setdefault(item["target_ref"], []).append(
                f"{mitigation['name']}: {detail}" if detail else str(mitigation["name"])
            )
        for item in objects:
            if item.get("type") != "attack-pattern" or not _active(item) or item["id"] not in mitigation_by_tech:
                continue
            references = [ref for ref in item.get("external_references", [])
                          if ref.get("source_name") == "mitre-attack" and ref.get("external_id")]
            if not references:
                continue
            ref = references[0]
            identifier = ref["external_id"]
            record = validate_record({
                "record_id": f"attack:{domain}:{identifier}",
                "publisher": f"MITRE ATT&CK {domain}",
                "heading": f"{identifier} {item['name']}",
                "body": _compact(str(item.get("description", ""))) + " Mitigations: " + "; ".join(sorted(set(mitigation_by_tech[item["id"]]))),
                "reference": ref.get("url") or f"https://attack.mitre.org/techniques/{identifier}/",
                "kind": "guidance",
            })
            results.append({"record": record, "source_type": domain, "name": item["name"], "external_id": identifier})
    ids = [entry["record"]["record_id"] for entry in results]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate MITRE technique ID")
    return results
