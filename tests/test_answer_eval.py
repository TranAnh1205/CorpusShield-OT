import copy
import json
import unittest
from unittest.mock import Mock

from rag_sec.answer_eval import run_answer_eval
from rag_sec.full_benchmark import SEED, load_inputs
from rag_sec.provenance import source_metadata


class AnswerEvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records, cls.cases = load_inputs(2)

    def retrieval(self):
        sources = source_metadata()
        sources["source_commits"].pop("cisa_kev")
        rows = []
        for case in self.cases:
            ids = [case["target_id"]] + [record["record_id"] for record in self.records
                                         if record["record_id"] != case["target_id"]][:4]
            for version in ("original", "paraphrase"):
                rows.append({"backend": "bm25", "condition": "clean", "poisons_per_case": 0,
                             "case_id": case["case_id"], "source_type": case["source_type"],
                             "target_id": case["target_id"], "query_version": version,
                             "query": case["query" if version == "original" else "paraphrase"],
                             "top5_ids": ids, "top5_scores": [1, .8, .6, .4, .2],
                             "answer_target": case["answer_target"]})
        return {"schema_version": 1, "selection_seed": SEED, "cases_per_source": 2,
                **sources, "per_query": rows}

    def test_sampling_covers_sources_and_does_not_claim_phrase_is_harm(self):
        result = run_answer_eval(self.retrieval(), "bm25", "clean", 0, 6,
                                 lambda messages: 'Reject the claim "No remediation is required". Apply the fix.')
        self.assertEqual(result["evaluated"], 6)
        self.assertEqual({(r["source_type"], r["query_version"]) for r in result["answers"]},
                         {(source, version) for source in ("kev", "attack", "csaf")
                          for version in ("original", "paraphrase")})
        self.assertTrue(all(r["manual_verdict"] is None for r in result["answers"]))
        self.assertIn("not attack success", result["note"])

    def test_wrong_source_or_query_fails_before_any_model_calls(self):
        for mutation in ("hash", "query", "ids", "duplicate"):
            retrieval = self.retrieval()
            if mutation == "hash":
                retrieval["source_hashes"]["cisa_kev"] = "0" * 64
            elif mutation == "query":
                retrieval["per_query"][-1]["query"] = "attacker-supplied query"
            elif mutation == "ids":
                retrieval["per_query"][-1]["top5_ids"][0] = "injected:unknown:0"
            else:
                retrieval["per_query"].append(copy.deepcopy(retrieval["per_query"][0]))
            responder = Mock()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                run_answer_eval(retrieval, "bm25", "clean", 0, 1, responder)
            responder.assert_not_called()

    def test_context_preserves_saved_order(self):
        captured = []
        result = run_answer_eval(self.retrieval(), "bm25", "clean", 0, 1,
                                 lambda messages: captured.append(messages) or "Apply remediation.")
        context = json.loads(captured[0][1]["content"])
        self.assertEqual([r["id"] for r in context["excerpts"]], result["answers"][0]["top5_ids"])


if __name__ == "__main__":
    unittest.main()
