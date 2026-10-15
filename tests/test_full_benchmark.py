import unittest

from rag_sec.full_benchmark import attack_records, condition_corpora, load_inputs, run_full
from rag_sec.mitre import load_mitre


class FullBenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records, cls.cases = load_inputs(2)

    def test_three_independent_source_groups_have_valid_targets(self):
        entries = load_mitre()
        self.assertGreaterEqual(sum(e["source_type"] == "enterprise" for e in entries), 20)
        self.assertGreaterEqual(sum(e["source_type"] == "ics" for e in entries), 20)
        self.assertEqual(len(self.cases), 6)
        self.assertEqual({case["source_type"] for case in self.cases}, {"kev", "attack", "csaf"})
        ids = {record["record_id"] for record in self.records}
        self.assertEqual(len(ids), len(self.records))
        self.assertTrue(all(case["target_id"] in ids and case["query"] != case["paraphrase"]
                            for case in self.cases))
        self.assertTrue(all(set(case["related_ids"]).issubset(ids) for case in self.cases))

    def test_forgery_replay_and_compromise_have_distinct_outcomes(self):
        by_id = {record["record_id"]: record for record in self.records}
        for count in (1, 5):
            poison = attack_records(self.cases, by_id, count)
            self.assertEqual(len(poison), len(self.cases) * count)
            corpora, rejected = condition_corpora(self.records, poison, self.cases)
            self.assertEqual(len(corpora["clean"]), len(self.records))
            self.assertEqual(len(corpora["unfiltered"]), len(self.records) + len(poison))
            self.assertEqual(len(corpora["signature_compromised"]), len(self.records) + len(poison))
            for condition in ("signature_forged", "signature_replayed", "layered_compromised"):
                self.assertEqual(len(corpora[condition]), len(self.records))
                self.assertEqual(rejected[condition], len(poison))

    def test_small_run_reports_every_condition_and_query(self):
        result = run_full(("bm25",), 1)
        self.assertEqual(len(result["per_query"]), 3 * 2 * 11)
        self.assertEqual({row["condition"] for row in result["per_query"]},
                         {"clean", "unfiltered", "signature_forged", "signature_replayed",
                          "signature_compromised", "layered_compromised"})
        self.assertTrue(all(len(row["top5_ids"]) == 5 for row in result["per_query"]))
        baseline = [row for row in result["per_query"] if row["condition"] == "clean"]
        self.assertTrue(all(row["poison_at_5"] == 0 for row in baseline))
        def tops(condition, count):
            return [row["top5_ids"] for row in result["per_query"]
                    if row["condition"] == condition and row["poisons_per_case"] == count]
        for count in (1, 5):
            self.assertEqual(tops("signature_forged", count), tops("clean", 0))
            self.assertEqual(tops("signature_replayed", count), tops("clean", 0))
            self.assertEqual(tops("layered_compromised", count), tops("clean", 0))
            self.assertEqual(tops("signature_compromised", count), tops("unfiltered", count))


if __name__ == "__main__":
    unittest.main()
