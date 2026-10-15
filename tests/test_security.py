import unittest

from rag_sec.experiment import build_conditions, poisoned_records
from rag_sec.fixtures import clean_records
from rag_sec.trust import ingest, sign, snapshot, verify

KEY = b"independent-test-key-material-32-bytes"


class IngestionTests(unittest.TestCase):
    def test_every_record_field_is_authenticated(self):
        record = clean_records()[0]
        signature = sign(record, KEY)
        for field in record:
            with self.subTest(field=field):
                changed = dict(record)
                changed[field] = changed[field] + " changed"
                self.assertFalse(verify(changed, signature, KEY))

    def test_compromised_signer_needs_separate_approval(self):
        clean = clean_records()
        poison = poisoned_records()[0]
        envelopes = [{"record": item, "signature": sign(item, KEY)} for item in clean + [poison]]
        signed_only, _ = ingest(envelopes, KEY)
        layered, rejected = ingest(envelopes, KEY, snapshot(clean))
        self.assertEqual(len(signed_only), len(clean) + 1)
        self.assertEqual(len(layered), len(clean))
        self.assertEqual(rejected, [{"record_id": poison["record_id"], "reason": "not in approved snapshot"}])

    def test_bad_first_envelope_cannot_shadow_valid_record(self):
        record = clean_records()[0]
        bad = {"record": record, "signature": "0" * 64}
        good = {"record": record, "signature": sign(record, KEY)}
        accepted, rejected = ingest([bad, good], KEY, snapshot([record]))
        self.assertEqual(accepted, [record])
        self.assertEqual(len(rejected), 1)

    def test_accepted_records_do_not_alias_caller_data(self):
        record = clean_records()[0]
        envelope = {"record": record, "signature": sign(record, KEY)}
        accepted, _ = ingest([envelope], KEY)
        record["body"] = "changed after ingestion"
        self.assertNotEqual(accepted[0]["body"], record["body"])

    def test_duplicate_baseline_ids_are_rejected(self):
        record = clean_records()[0]
        with self.assertRaises(ValueError):
            snapshot([record, dict(record)])

    def test_fixture_attack_conditions_are_distinct(self):
        corpora, rejected = build_conditions(KEY)
        self.assertEqual(len(corpora["clean"]), 8)
        self.assertEqual(len(corpora["unfiltered"]), 16)
        self.assertEqual(len(corpora["signature_forged"]), 8)
        self.assertEqual(len(corpora["signature_compromised"]), 16)
        self.assertEqual(len(corpora["layered_compromised"]), 8)
        self.assertEqual(rejected["layered_compromised"], 8)


if __name__ == "__main__":
    unittest.main()
