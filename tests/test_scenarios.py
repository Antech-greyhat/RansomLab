import copy
import unittest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from ransomlab import scenarios
from ransomlab.core.errors import ValidationError


class ScenarioTests(unittest.TestCase):
    def setUp(self):
        self.lab = {"lab_id": str(uuid4()), "baseline_id": str(uuid4()), "fixtures": [{"id": str(uuid4())} for _ in range(3)]}

    def test_roundtrip_and_bounded_selection(self):
        value = scenarios.create(self.lab, "encrypt_generated", 2)
        self.assertEqual(len(value["fixture_ids"]), 2)
        self.assertEqual(scenarios.validate(scenarios.parse_json(scenarios.canonical(value)), self.lab), value)

    def test_unknown_fields_actions_ids_and_stale_generation(self):
        valid = scenarios.create(self.lab, "modify_generated")
        changes = [{"command": "anything"}, {"scenario": "run_shell"}, {"baseline_id": str(uuid4())},
                   {"lab_id": str(uuid4())}, {"fixture_ids": [str(uuid4())]}, {"schema_version": True},
                   {"fixture_ids": [valid["fixture_ids"][0]] * 2}, {"fixture_ids": ["../outside"]}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValidationError):
                scenarios.validate({**valid, **change}, self.lab)

    def test_expiry_future_and_excess_lifetime(self):
        valid = scenarios.create(self.lab, "modify_generated")
        now = datetime.now(timezone.utc)
        for issued, expires in ((now - timedelta(hours=1), now - timedelta(minutes=50)),
                                (now + timedelta(minutes=2), now + timedelta(minutes=10)),
                                (now, now + timedelta(hours=1))):
            with self.assertRaises(ValidationError):
                scenarios.validate({**valid, "issued_at": issued.isoformat(), "expires_at": expires.isoformat()}, self.lab)

    def test_parser_rejects_duplicate_nonfinite_and_large_documents(self):
        for data in (b'{"x":1,"x":2}', b'{"x":NaN}', b'\xff', b'[]' * 10000):
            with self.subTest(data=data[:20]), self.assertRaises(ValidationError):
                scenarios.parse_json(data)


if __name__ == "__main__":
    unittest.main()
