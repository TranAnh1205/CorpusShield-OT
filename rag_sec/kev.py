"""Load a pinned, public-domain CISA KEV catalog into the local record format."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .records import validate_record
from .io_utils import read_file

DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "known_exploited_vulnerabilities.json"
DATA_SHA256 = "47b463a136b8e0956756cfbcdbc2e4b4ccb60c96b4ca7a1ca9f507817cc83045"
SOURCE_COMMIT = "7606917390b43dc02b251d88dbceed6296a919fc"
REQUIRED = ("cveID", "vendorProject", "product", "vulnerabilityName", "shortDescription", "requiredAction")


def load_kev(path: Path = DATA_PATH) -> list[dict[str, str]]:
    catalog = load_catalog(path)
    entries = catalog["vulnerabilities"]
    records: list[dict[str, str]] = []
    for entry in entries:
        cve = entry["cveID"]
        records.append(validate_record({
            "record_id": cve,
            "publisher": "CISA KEV",
            "heading": f"{cve} {entry['vendorProject']} {entry['product']} {entry['vulnerabilityName']}",
            "body": f"{entry['shortDescription']} Required action: {entry['requiredAction']}",
            "reference": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "kind": "advisory",
        }))
    return records


def load_catalog(path: Path = DATA_PATH) -> dict[str, object]:
    """Parse the same bytes that were verified; never re-read after validation."""
    raw = read_file(path, 16 * 1024 * 1024)
    if hashlib.sha256(raw).hexdigest() != DATA_SHA256:
        raise ValueError("CISA KEV file does not match the pinned SHA-256")
    catalog = json.loads(raw)
    entries = catalog["vulnerabilities"]
    if not isinstance(entries, list) or len(entries) != catalog["count"]:
        raise ValueError("invalid CISA KEV catalog count")
    seen: set[str] = set()
    for entry in entries:
        if not all(isinstance(entry.get(key), str) and entry[key].strip() for key in REQUIRED):
            raise ValueError("incomplete CISA KEV entry")
        cve = entry["cveID"]
        if cve in seen:
            raise ValueError(f"duplicate CISA KEV ID: {cve}")
        seen.add(cve)
    return catalog
