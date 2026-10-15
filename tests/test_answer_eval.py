import unittest

from rag_sec.answer_eval import run_answer_eval
from rag_sec.full_benchmark import load_inputs


class AnswerEvaluationTests(unittest.TestCase):
    def test_context_uses_saved_rank_and_scores_exact_phrase(self):
        records, cases = load_inputs(1)
        case = cases[0]
        ids = [case["target_id"]] + [record["record_id"] for record in records
                                         if record["record_id"] != case["target_id"]][:4]
        retrieval = {"cases_per_source": 1, "per_query": [{
            "backend": "bm25", "condition": "clean", "poisons_per_case": 0,
            "case_id": case["case_id"], "query_version": "original", "query": case["query"],
            "top5_ids": ids, "answer_target": case["answer_target"],
        }]}
        def fake_model(messages):
            self.assertIn(case["target_id"], messages[1]["content"])
            return case["answer_target"]
        result = run_answer_eval(retrieval, "bm25", "clean", 0, 1, fake_model)
        self.assertEqual((result["evaluated"], result["exact_phrase_hits"]), (1, 1))


if __name__ == "__main__":
    unittest.main()
