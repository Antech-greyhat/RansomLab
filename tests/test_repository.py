"""Durability/rollback tests using generated temporary SQLite databases only."""

import sqlite3
import tempfile
import unittest
from pathlib import Path
from uuid import uuid4

from ransomlab.core.config import Policy
from ransomlab.core.errors import StateError, ValidationError
from ransomlab.core.events import Event
from ransomlab.core.repository import EventStore


class EventStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ransomlab-core-test-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "state.db"
        self.lab_id = str(uuid4())

    def event(self, **kwargs):
        return Event.create(self.lab_id, "lab.created", details={"count": 1}, **kwargs)

    def test_event_state_transaction_survives_reopen(self):
        event = self.event()
        with EventStore(self.path) as store:
            result = store.append(event, updates={"lab": {"id": self.lab_id, "ready": False}})
            self.assertEqual(1, result.sequence)
            self.assertIsNone(event.sequence)
            self.assertEqual(1, store.count())
        with EventStore(self.path, readonly=True) as reader:
            self.assertEqual(result, reader.events()[0])
            self.assertEqual(self.lab_id, reader.get_state("lab")["id"])

    def test_duplicate_or_limit_failure_rolls_back_state(self):
        with EventStore(self.path, policy=Policy(max_events=2)) as store:
            event = self.event()
            store.append(event, updates={"status": "ready"})
            with self.assertRaises(StateError):
                store.append(event, updates={"status": "incorrect"})
            self.assertEqual("ready", store.get_state("status"))
            store.append(self.event())
            with self.assertRaises(StateError):
                store.append(self.event(), updates={"status": "also-incorrect"})
            self.assertEqual("ready", store.get_state("status"))
            self.assertEqual(2, store.count())

    def test_invalid_updates_do_not_commit_event(self):
        with EventStore(self.path) as store:
            for updates in ({"state": float("nan")}, {"../path": "value"}, {"state": object()}):
                with self.assertRaises(ValidationError):
                    store.append(self.event(), updates=updates)
            self.assertEqual(0, store.count())

    def test_control_compare_and_swap_cannot_clear_a_later_stop(self):
        with EventStore(self.path) as store:
            store.append(self.event(), updates={"stop_requested": False})
            old = store.get_state("stop_requested")
            with EventStore(self.path) as controller:
                controller.append(self.event(), updates={"stop_requested": True})
            with self.assertRaises(StateError):
                store.append(self.event(), updates={"stop_requested": False}, expected={"stop_requested": old})
            self.assertTrue(store.get_state("stop_requested"))
            self.assertEqual(store.count(), 2)

    def test_locked_database_reports_failure_without_event(self):
        with EventStore(self.path) as store:
            other = sqlite3.connect(self.path, isolation_level=None)
            try:
                other.execute("BEGIN IMMEDIATE")
                with self.assertRaises(StateError):
                    store.append(self.event(), updates={"status": "wrong"})
            finally:
                other.rollback()
                other.close()
            self.assertEqual(0, store.count())
            self.assertIsNone(store.get_state("status"))

    def test_readonly_rejects_mutation_and_does_not_create_missing_db(self):
        with self.assertRaises(StateError):
            EventStore(self.path, readonly=True)
        self.assertFalse(self.path.exists())
        with EventStore(self.path) as store:
            store.append(self.event())
        with EventStore(self.path, readonly=True) as reader:
            with self.assertRaises(StateError):
                reader.append(self.event())
            self.assertEqual(1, reader.count())

    def test_sequence_filters_and_bounded_queries(self):
        run_id = str(uuid4())
        with EventStore(self.path) as store:
            store.append(self.event())
            second = store.append(self.event(run_id=run_id))
            store.append(self.event())
            self.assertEqual([2, 3], [event.sequence for event in store.events(after=1)])
            self.assertEqual([second], store.events(run_id=run_id))
            for kwargs in ({"limit": True}, {"limit": 0}, {"limit": 1001}, {"after": -1}, {"run_id": "bad"}):
                with self.assertRaises(ValidationError):
                    store.events(**kwargs)

    def test_corrupt_database_and_invalid_stored_event_fail_explicitly(self):
        self.path.write_bytes(b"not a SQLite database")
        with self.assertRaises(StateError):
            EventStore(self.path)
        self.path.unlink()
        with EventStore(self.path) as store:
            store.append(self.event())
        other = sqlite3.connect(self.path)
        other.execute("UPDATE events SET json = '{}' WHERE seq = 1")
        other.commit()
        other.close()
        with EventStore(self.path, readonly=True) as store:
            with self.assertRaises(StateError):
                store.events()

    def test_wrong_schema_and_database_quota(self):
        with EventStore(self.path):
            pass
        other = sqlite3.connect(self.path)
        other.execute("PRAGMA user_version = 99")
        other.close()
        with self.assertRaises(StateError):
            EventStore(self.path, readonly=True)
        other = sqlite3.connect(self.path)
        other.execute("PRAGMA user_version = 1")
        other.close()
        with self.assertRaises(StateError):
            EventStore(self.path, policy=Policy(max_database_bytes=4096))

    def test_sqlite_full_rolls_back_both_event_and_state(self):
        # A SQLite page quota simulates exhaustion without filling a real disk.
        with EventStore(self.path, policy=Policy(max_database_bytes=32768)) as store:
            store.append(self.event(), updates={"status": "ready"})
            with self.assertRaises(StateError):
                store.append(self.event(), updates={"status": "x" * 50_000})
            self.assertEqual(1, store.count())
            self.assertEqual("ready", store.get_state("status"))
        self.assertLessEqual(self.path.stat().st_size, 32768)

    def test_failure_after_event_insert_rolls_back_the_transaction(self):
        with EventStore(self.path) as store:
            other = sqlite3.connect(self.path)
            other.execute("CREATE TRIGGER fail_state BEFORE INSERT ON state BEGIN SELECT RAISE(ABORT, 'synthetic fault'); END")
            other.commit()
            other.close()
            with self.assertRaises(StateError):
                store.append(self.event(), updates={"status": "wrong"})
            self.assertEqual(0, store.count())
            self.assertIsNone(store.get_state("status"))

    def test_configured_event_limit_rejects_before_state_mutation(self):
        with EventStore(self.path, policy=Policy(max_event_bytes=128)) as store:
            with self.assertRaises(ValidationError):
                store.append(self.event(), updates={"status": "wrong"})
            self.assertEqual(0, store.count())


if __name__ == "__main__":
    unittest.main()
