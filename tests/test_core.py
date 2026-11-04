"""Contract tests for the dependency-free core; all inputs are synthetic."""

import json
import unittest
from dataclasses import FrozenInstanceError
from uuid import uuid4

from ransomlab.core.config import Policy
from ransomlab.core.errors import ValidationError
from ransomlab.core.events import Event
from ransomlab.core.hashing import digest_matches, hash_bytes, hash_chunks, validate_digest


class PolicyTests(unittest.TestCase):
    def test_defaults_round_trip_without_mutability(self):
        policy = Policy()
        self.assertEqual(policy, Policy.from_dict(policy.to_dict()))
        self.assertEqual(100, policy.max_files)
        with self.assertRaises(FrozenInstanceError):
            policy.max_files = 1

    def test_wrong_missing_unknown_and_unsafe_limits_rejected(self):
        for value in (True, 0, -1, 1.5, "100", float("inf")):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                Policy(max_files=value)
        for data in ({}, {**Policy().to_dict(), "unsafe": True}):
            with self.assertRaises(ValidationError):
                Policy.from_dict(data)
        with self.assertRaises(ValidationError):
            Policy(max_file_bytes=1024, max_total_bytes=512)
        with self.assertRaises(ValidationError):
            Policy(max_files=101)


class HashTests(unittest.TestCase):
    def test_known_answers(self):
        self.assertEqual("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash_bytes(b""))
        self.assertEqual("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", hash_bytes(b"abc"))
        self.assertEqual("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", hash_bytes(b"\x00"))

    def test_chunking_and_byte_ceiling(self):
        self.assertEqual(hash_bytes(b"abcdef"), hash_chunks([b"ab", b"", b"c", b"def"], max_bytes=6))
        with self.assertRaises(ValidationError):
            hash_chunks([b"ab", b"c"], max_bytes=2)
        with self.assertRaises(ValidationError):
            hash_chunks(["secret input"])
        with self.assertRaises(ValidationError):
            hash_chunks([b"a"], max_bytes=True)

    def test_digests_have_explicit_invalid_and_mismatch_results(self):
        self.assertTrue(digest_matches(hash_bytes(b"abc"), hash_bytes(b"abc")))
        self.assertFalse(digest_matches(hash_bytes(b"a"), hash_bytes(b"b")))
        for value in ("x" * 64, "A" * 64, "0" * 63, None):
            with self.assertRaises(ValidationError):
                validate_digest(value)


class EventTests(unittest.TestCase):
    def setUp(self):
        self.lab_id = str(uuid4())

    def event(self, **kwargs):
        return Event.create(self.lab_id, "lab.created", details={"count": 1, "generator": "sample-v1"}, **kwargs)

    def test_serialization_and_immutable_details(self):
        details = {"count": 2}
        event = Event.create(self.lab_id, "lab.created", details=details)
        details["count"] = 99
        self.assertEqual(2, event.details["count"])
        with self.assertRaises(TypeError):
            event.details["count"] = 3
        with self.assertRaises(FrozenInstanceError):
            event.kind = "run.started"
        encoded = json.dumps(event.to_dict())
        self.assertEqual(event, Event.from_dict(json.loads(encoded)))
        self.assertEqual(event.id, event.event_id)

    def test_invalid_identifiers_enums_versions_and_extra_fields(self):
        base = self.event().to_dict()
        for field, value in (("id", "../outside"), ("lab_id", "x"), ("kind", "shell.execute"),
                             ("source", "untrusted"), ("severity", "urgent"), ("outcome", "maybe"),
                             ("schema_version", True), ("sequence", True), ("sequence", 0),
                             ("created_at", "2026-11-04T12:00:00")):
            with self.subTest(field=field), self.assertRaises(ValidationError):
                Event.from_dict({**base, field: value})
        with self.assertRaises(ValidationError):
            Event.from_dict({**base, "command": "forbidden"})
        with self.assertRaises(ValidationError):
            Event.from_dict({key: value for key, value in base.items() if key != "source"})

    def test_details_are_closed_and_do_not_echo_bad_input(self):
        invalid = ({"count": True}, {"count": -1}, {"command": "secret-marker"},
                   {"count": {"nested": 1}}, {"generator": ["nested"]},
                   {"generator": "x" * 257}, {"generator": "C:\\personal\\secret-marker"},
                   {"generator": "new\nrecord"}, {"generator": "\ud800"})
        for details in invalid:
            with self.subTest(details=details), self.assertRaises(ValidationError) as caught:
                Event.create(self.lab_id, "lab.created", details=details)
            self.assertNotIn("secret-marker", str(caught.exception))

    def test_per_kind_fields_and_utc(self):
        with self.assertRaises(ValidationError):
            Event.create(self.lab_id, "lab.created", details={"evidence_id": str(uuid4())})
        data = self.event().to_dict()
        self.assertTrue(data["created_at"].endswith("Z"))
        with self.assertRaises(ValidationError):
            Event.from_dict({**data, "created_at": "2026-11-04T12:00:00+03:00"})

    def test_evidence_started_records_a_bounded_attempt_reservation(self):
        event = Event.create(self.lab_id, "evidence.started", source="response", outcome="pending",
                             details={"evidence_id": str(uuid4()), "count": 4, "bytes": 16384,
                                      "state": "collecting", "status": "reserved"})
        self.assertEqual(event, Event.from_dict(json.loads(event.to_json())))
        with self.assertRaises(ValidationError):
            Event.create(self.lab_id, "evidence.started", details={"sha256": "0" * 64})


if __name__ == "__main__":
    unittest.main()
