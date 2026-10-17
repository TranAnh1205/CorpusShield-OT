"""Pinned, locally rebuilt CISA OT advisory corpus.

Only the manifest is versioned. Advisory content stays in data/raw because
some entries republish third-party text with their own terms.
"""

from __future__ import annotations

import hashlib
import json
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .records import validate_record
from .io_utils import atomic_write, read_file
from .network import download

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "data" / "csaf-manifest.json"
RAW = ROOT / "data" / "raw" / "csaf"
MANIFEST_SHA256 = "a80f112a5def02e2481c452b15a0fa83f1245e33bd35b8b096f350cbbb7c5792"
MAX_ADVISORY_BYTES = 16 * 1024 * 1024


def _manifest() -> dict[str, object]:
    # Git checkouts can convert line endings on Windows; pin canonical LF bytes.
    raw = read_file(MANIFEST, 1024 * 1024).replace(b"\r\n", b"\n")
    if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA256:
        raise ValueError("CSAF manifest SHA-256 mismatch")
    manifest = json.loads(raw)
    if manifest.get("source") != "cisagov/CSAF" or len(manifest.get("files", [])) != 300:
        raise ValueError("invalid CSAF manifest")
    if not re.fullmatch(r"[0-9a-f]{40}", manifest.get("commit", "")):
        raise ValueError("invalid CSAF commit")
    seen = set()
    for item in manifest["files"]:
        path = item["path"]
        if not re.fullmatch(r"csaf_files/OT/white/20(?:23|24|25|26)/[a-z0-9-]+\.json", path):
            raise ValueError("invalid CSAF path in manifest")
        if not re.fullmatch(r"[0-9a-f]{40}", item["git_blob_sha1"]):
            raise ValueError("invalid Git blob digest in manifest")
        if path in seen:
            raise ValueError("duplicate CSAF path")
        seen.add(path)
    return manifest


def _checked_bytes(path: Path, blob_sha: str) -> bytes:
    data = read_file(path, MAX_ADVISORY_BYTES)
    actual = hashlib.sha1(f"blob {len(data)}\0".encode() + data, usedforsecurity=False).hexdigest()
    if actual != blob_sha:
        raise ValueError(f"Git blob hash mismatch: {path}")
    return data


def fetch_csaf(workers: int = 12) -> list[Path]:
    """Fetch the 300 selected files from one commit, verifying each Git blob."""
    if type(workers) is not int or workers < 1 or workers > 32:
        raise ValueError("workers must be between 1 and 32")
    manifest = _manifest()
    commit = manifest["commit"]

    def fetch_one(item: dict[str, str]) -> Path:
        relative = item["path"]
        path = RAW / relative
        if not path.resolve().is_relative_to(RAW.resolve()):
            raise ValueError("CSAF destination escapes data directory")
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            url = f"https://raw.githubusercontent.com/cisagov/CSAF/{commit}/{relative}"
            data = download(url, limit=MAX_ADVISORY_BYTES)
            actual = hashlib.sha1(f"blob {len(data)}\0".encode() + data, usedforsecurity=False).hexdigest()
            if actual != item["git_blob_sha1"]:
                raise ValueError("downloaded CSAF Git blob hash mismatch")
            atomic_write(path, data)
        _checked_bytes(path, item["git_blob_sha1"])
        return path

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(fetch_one, manifest["files"]))


def _compact(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def load_csaf() -> list[dict[str, object]]:
    """Parse local advisories into searchable records and case metadata."""
    manifest = _manifest()
    entries = []
    for item in manifest["files"]:
        relative = item["path"]
        raw = _checked_bytes(RAW / relative, item["git_blob_sha1"])
        source = json.loads(raw)
        document = source["document"]
        advisory_id = str(document["tracking"]["id"])
        title = _compact(str(document["title"]))
        note_text = " ".join(str(note.get("text", "")) for note in document.get("notes", [])
                             if note.get("category") in {"summary", "general"})
        remedies = []
        for vulnerability in source.get("vulnerabilities", []):
            remedies.extend(str(remedy.get("details", ""))
                            for remedy in vulnerability.get("remediations", [])
                            if remedy.get("category") in {"vendor_fix", "workaround", "mitigation"})
        body = (_compact(note_text)[:2000] + " Remediation: " + _compact(" ".join(remedies))[:3000]).strip()
        if not body:
            body = title
        record = validate_record({
            "record_id": f"advisory:{advisory_id}",
            "publisher": "CISA CSAF OT",
            "heading": f"{advisory_id} {title}",
            "body": body,
            "reference": f"https://github.com/cisagov/CSAF/blob/{manifest['commit']}/{relative}",
            "kind": "advisory",
        })
        cves = sorted({str(vulnerability["cve"]) for vulnerability in source.get("vulnerabilities", [])
                       if vulnerability.get("cve")})
        entries.append({"record": record, "advisory_id": advisory_id, "title": title,
                        "cves": cves})
    ids = [entry["record"]["record_id"] for entry in entries]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate CSAF advisory ID")
    return entries
