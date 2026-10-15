import tempfile
import unittest
from pathlib import Path

from rag_sec.benchmark import CASE_COUNT, attack_records, build_corpora, cluster_interval, select_cases
from rag_sec.kev import load_catalog, load_kev
from rag_sec.tfidf import TFIDF


class KEVBenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = load_kev()
        cls.catalog = load_catalog()

    def test_pinned_corpus_has_unique_ids_and_rejects_tampering(self):
        self.assertEqual(len(self.records), 1745)
        self.assertEqual(len({record["record_id"] for record in self.records}), len(self.records))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tampered.json"
            path.write_bytes(b"{}")
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                load_kev(path)

    def test_case_selection_is_stable_under_source_order(self):
        first = select_cases(self.catalog)
        reversed_catalog = dict(self.catalog, vulnerabilities=list(reversed(self.catalog["vulnerabilities"])))
        self.assertEqual(first, select_cases(reversed_catalog))
        self.assertEqual(len(first), CASE_COUNT * 2)
        self.assertEqual(len({case["query_id"] for case in first}), len(first))
        self.assertTrue(all(case["target_id"] in {record["record_id"] for record in self.records}
                            for case in first))

    def test_signed_poison_needs_independent_snapshot(self):
        cases = select_cases(self.catalog)
        attacks = attack_records(cases)
        corpora, rejected = build_corpora(self.records, attacks)
        self.assertEqual(len(attacks), CASE_COUNT)
        self.assertEqual(len(corpora["signature_forged"]), len(self.records))
        self.assertEqual(len(corpora["signature_compromised"]), len(self.records) + CASE_COUNT)
        self.assertEqual(len(corpora["layered_compromised"]), len(self.records))
        self.assertEqual(rejected["signature_forged"], CASE_COUNT)
        self.assertEqual(rejected["signature_compromised"], 0)
        self.assertEqual(rejected["layered_compromised"], CASE_COUNT)

    def test_tfidf_finds_record_and_cluster_interval_is_stable(self):
        subset = self.records[:10]
        query = subset[3]["record_id"]
        self.assertEqual(TFIDF(subset).search(query, 1)[0][0]["record_id"], query)
        rows = [
            {"target_id": "A", "poison_at_1": 1},
            {"target_id": "A", "poison_at_1": 0},
            {"target_id": "B", "poison_at_1": 0},
            {"target_id": "B", "poison_at_1": 0},
        ]
        interval = cluster_interval(rows, "poison_at_1")
        self.assertEqual(interval, cluster_interval(rows, "poison_at_1"))
        self.assertTrue(0 <= interval[0] <= interval[1] <= 1)
        with self.assertRaises(ValueError):
            cluster_interval(rows[:1], "poison_at_1")


if __name__ == "__main__":
    unittest.main()
