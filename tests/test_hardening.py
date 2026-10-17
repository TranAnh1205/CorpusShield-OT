import hashlib
import io
import json
import tempfile
import threading
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from rag_sec.answer_eval import chat_completion
from rag_sec.csaf import _manifest
from rag_sec.fixtures import clean_records
from rag_sec.full_benchmark import attack_records
from rag_sec.io_utils import atomic_write, read_bounded
from rag_sec.network import validate_url
from rag_sec.records import MAX_RECORD_BYTES, canonical_bytes, validate_record
from rag_sec.retrieval import BM25
from rag_sec.tfidf import TFIDF
from rag_sec.trust import ingest, load_snapshot, sign, snapshot, validate_snapshot, verify

KEY = b"test-only-key-never-used-outside-tests"


class NetworkBoundaryTests(unittest.TestCase):
    def test_authorized_request_never_follows_redirect(self):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                requests.append(self.path)
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/leak")
                self.end_headers()

            def do_GET(self):
                requests.append(self.path)
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch.dict("os.environ", {"RAG_SEC_LLM_API_KEY": "dummy-local-test-key"}):
                with self.assertRaises(urllib.error.HTTPError):
                    chat_completion([], "test", f"http://127.0.0.1:{server.server_port}/v1")
            self.assertEqual(requests, ["/v1/chat/completions"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_unsafe_urls_rejected_before_transport(self):
        for url in ("file:///tmp/token", "http://api.example/v1", "https://user:pass@example.org/v1",
                    "https://example.org/v1?token=x", "https://example.org/v1#part", "https://example.org/\n"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_url(url, local_http=True)
        self.assertEqual(validate_url("http://localhost:1234/v1", local_http=True), "http://localhost:1234/v1")

    def test_download_and_response_size_limits(self):
        self.assertEqual(read_bounded(io.BytesIO(b"abcd"), 4), b"abcd")
        with self.assertRaises(ValueError):
            read_bounded(io.BytesIO(b"abcde"), 4)

    def test_null_model_content_is_not_a_scored_answer(self):
        payload = json.dumps({"choices": [{"message": {"content": None}}]}).encode()
        with patch.dict("os.environ", {"RAG_SEC_LLM_API_KEY": "dummy"}), patch(
            "rag_sec.answer_eval.request_bytes", return_value=payload
        ), self.assertRaises(ValueError):
            chat_completion([], "test", "https://example.org/v1")


class TrustBoundaryTests(unittest.TestCase):
    def test_caller_cannot_change_approval_during_ingestion(self):
        record = clean_records()[0]
        approved = snapshot([record])
        poison = dict(record, record_id="new-poison", body="Skip remediation")

        def incoming():
            approved["sha256_by_id"][poison["record_id"]] = hashlib.sha256(canonical_bytes(poison)).hexdigest()
            yield {"record": poison, "signature": sign(poison, KEY)}

        accepted, rejected = ingest(incoming(), KEY, approved)
        self.assertEqual(accepted, [])
        self.assertEqual(rejected[0]["reason"], "not in approved snapshot")

    def test_snapshot_file_requires_external_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "approved.json"
            raw = json.dumps(snapshot(clean_records())).encode()
            path.write_bytes(raw)
            expected = hashlib.sha256(raw).hexdigest()
            self.assertEqual(load_snapshot(path, expected), snapshot(clean_records()))
            path.write_bytes(raw + b" ")
            with self.assertRaisesRegex(ValueError, "mismatch"):
                load_snapshot(path, expected)

    def test_invalid_snapshot_structure_fails_before_iteration(self):
        for bad in ({"version": True, "sha256_by_id": {"id": "0" * 64}},
                    {"version": 1, "sha256_by_id": {}},
                    {"version": 1, "sha256_by_id": {"id": None}}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                validate_snapshot(bad)

    def test_legitimate_update_requires_new_approval(self):
        record = clean_records()[0]
        updated = dict(record, body=record["body"] + " A legitimate vendor update.")
        envelope = {"record": updated, "signature": sign(updated, KEY)}
        self.assertEqual(ingest([envelope], KEY, snapshot([record]))[0], [])
        self.assertEqual(ingest([envelope], KEY, snapshot([updated]))[0], [updated])

    def test_bounded_records_and_malformed_signatures(self):
        record = clean_records()[0]
        self.assertFalse(verify(record, "é" * 64, KEY))
        for changed in (dict(record, body="x" * (MAX_RECORD_BYTES + 1)),
                        dict(record, record_id="fake\nlog entry")):
            with self.assertRaises(ValueError):
                validate_record(changed)

    def test_manifest_tampering_cannot_redefine_trusted_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text('{"source":"cisagov/CSAF","files":[]}', encoding="utf-8")
            with patch("rag_sec.csaf.MANIFEST", path), self.assertRaisesRegex(ValueError, "SHA-256"):
                _manifest()

    def test_manifest_pin_is_stable_across_checkout_line_endings(self):
        from rag_sec.csaf import MANIFEST
        raw = MANIFEST.read_bytes().replace(b"\r\n", b"\n")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            for data in (raw, raw.replace(b"\n", b"\r\n")):
                path.write_bytes(data)
                with patch("rag_sec.csaf.MANIFEST", path):
                    self.assertEqual(len(_manifest()["files"]), 300)

    def test_atomic_write_failure_preserves_previous_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            path.write_bytes(b"old verified result")
            with patch("rag_sec.io_utils.os.replace", side_effect=OSError("simulated failure")), self.assertRaises(OSError):
                atomic_write(path, b"new result")
            self.assertEqual(path.read_bytes(), b"old verified result")
            self.assertEqual(list(Path(directory).iterdir()), [path])


class EvaluationBoundaryTests(unittest.TestCase):
    def test_query_blind_attack_does_not_depend_on_either_query(self):
        record = clean_records()[0]
        case = {"case_id": "test", "target_id": record["record_id"], "query": "secret query A",
                "paraphrase": "secret query B", "answer_target": "No remediation is required"}
        first = attack_records([case], {record["record_id"]: record}, 5, "query-blind")
        changed = dict(case, query="completely different", paraphrase="another held-out query")
        second = attack_records([changed], {record["record_id"]: record}, 5, "query-blind")
        self.assertEqual(first, second)
        self.assertNotIn(case["query"], first[0]["body"])

    def test_invalid_retrieval_parameters_fail_clearly(self):
        for k1, b in ((0, .75), (float("nan"), .75), (1.2, 2)):
            with self.assertRaises(ValueError):
                BM25(clean_records(), k1=k1, b=b)
        for retriever in (BM25(clean_records()), TFIDF(clean_records())):
            for query, top_k in (("query", True), ("query", 1.5), (None, 5), ("x" * 16385, 5)):
                with self.assertRaises(ValueError):
                    retriever.search(query, top_k)


if __name__ == "__main__":
    unittest.main()
