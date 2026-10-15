import unittest

from rag_sec.experiment import evaluate
from rag_sec.fixtures import clean_records
from rag_sec.retrieval import BM25


class RetrievalTests(unittest.TestCase):
    def test_equal_scores_preserve_corpus_order(self):
        records = clean_records()[:2]
        ranked = BM25(records).search("unknown token", top_k=2)
        self.assertEqual([record["record_id"] for record, _ in ranked],
                         [record["record_id"] for record in records])

    def test_evaluation_reports_actual_retrieval_not_only_rejections(self):
        summary = {row["condition"]: row for row in evaluate()["summary"]}
        self.assertEqual(summary["clean"]["target_at_5"], 8)
        self.assertEqual(summary["unfiltered"]["poison_at_1"], 8)
        self.assertEqual(summary["signature_compromised"]["poison_at_1"], 8)
        self.assertEqual(summary["layered_compromised"]["poison_at_1"], 0)


if __name__ == "__main__":
    unittest.main()
