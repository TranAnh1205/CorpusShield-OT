"""Run provenance without secrets or copies of upstream document bodies."""

from __future__ import annotations

import hashlib
import json
import platform
import shutil
# Used only for fixed, read-only Git commands with a resolved executable and no shell.
import subprocess  # nosec B404
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from .csaf import MANIFEST_SHA256, _manifest
from .kev import DATA_SHA256, SOURCE_COMMIT
from .mitre import COMMIT, FILES

ROOT = Path(__file__).resolve().parent.parent


def digest_json(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()


def source_metadata() -> dict[str, object]:
    return {
        "source_commits": {"cisa_kev": SOURCE_COMMIT, "mitre_attack": COMMIT,
                           "cisa_csaf": _manifest()["commit"]},
        "source_hashes": {"cisa_kev": DATA_SHA256, "cisa_csaf_manifest": MANIFEST_SHA256,
                          **{domain: digest for domain, (_, digest) in FILES.items()}},
    }


def run_metadata(started: str, elapsed: float, records: list, cases: list) -> dict[str, object]:
    files = sorted((ROOT / "rag_sec").glob("*.py")) + [ROOT / "pyproject.toml", ROOT / "uv.lock"]
    hashes = {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in files if path.is_file()}
    executable = shutil.which("git")

    def git(*args: str) -> str | None:
        if not executable:
            return None
        try:
            # Arguments are fixed by this module, the executable is resolved, and no shell is used.
            result = subprocess.run([executable, *args], cwd=ROOT, capture_output=True,
                                    text=True, timeout=10, check=False)  # nosec B603
            return result.stdout.strip() if result.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired):
            return None

    packages = {}
    for package in ("sentence-transformers", "torch", "transformers", "numpy", "scikit-learn"):
        try:
            packages[package] = version(package)
        except PackageNotFoundError:
            packages[package] = None
    status = git("status", "--porcelain")
    return {"started_utc": started, "runtime_seconds": round(elapsed, 6),
            "python": platform.python_version(), "platform": platform.platform(),
            "git_commit": git("rev-parse", "HEAD"),
            "git_worktree_dirty": bool(status) if status is not None else None,
            "source_files_sha256": hashes, "source_tree_sha256": digest_json(hashes),
            "packages": packages, "corpus_sha256": digest_json(records), "cases_sha256": digest_json(cases)}
