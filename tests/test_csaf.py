import tempfile
import unittest
from pathlib import Path

from rag_sec.csaf import _checked_bytes, _manifest, load_csaf


class CSAFTests(unittest.TestCase):
    def test_manifest_and_documents_are_pinned(self):
        manifest = _manifest()
        self.assertEqual(len(manifest["files"]), 300)
        entries = load_csaf()
        self.assertEqual(len(entries), 300)
        self.assertEqual(len({entry["advisory_id"] for entry in entries}), 300)
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / "changed.json"
            changed.write_bytes(b"{}")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                _checked_bytes(changed, manifest["files"][0]["git_blob_sha1"])


if __name__ == "__main__":
    unittest.main()
