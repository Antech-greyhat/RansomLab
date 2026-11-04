"""Service regressions with in-memory fixtures and disposable SQLite metadata.

The imported test module supplies setup helpers only; this TestCase does not
inherit its tests or expose a filesystem-impact bypass in application code.
"""

import unittest
from unittest.mock import patch

import test_services as service_cases
from memory_fixtures import MemoryDirectory
from ransomlab.core.config import Policy
from ransomlab.core.errors import StateError


class WorkflowRegressionTests(unittest.TestCase):
    setUp = service_cases.ServiceTests.setUp
    stage = service_cases.ServiceTests.stage

    def test_nonessential_events_cannot_consume_recovery_reserve(self):
        self.service.policy = Policy(max_events=128)
        request = self.stage()
        self.service.simulate(self.lab_id, request["request_id"])
        with self.service._open(self.lab_id, lease=True) as (lab, store, _):
            before = store.count()
            for _ in range(self.service.policy.max_events):
                try:
                    self.service._event(store, lab, "file.observed", source="monitor",
                                        details={"operation": "synthetic_reserve_test", "status": "test"})
                except StateError as error:
                    self.assertIn("reserved", str(error))
                    break
            else:
                self.fail("Nonessential events never stopped at the audit reserve")
            self.assertGreater(store.count(), before)
            self.assertLess(store.count(), self.service.policy.max_events)

        evidence = self.service.preserve(self.lab_id)
        self.assertEqual("complete", evidence["state"])
        self.assertTrue(self.service.recover(self.lab_id)["verified"])
        status = self.service.status(self.lab_id)
        self.assertEqual("verified", status["state"])
        self.assertLessEqual(status["event_count"], self.service.policy.max_events)

    def test_containment_interrupts_recovery_between_fixture_operations(self):
        request = self.stage()
        run = self.service.simulate(self.lab_id, request["request_id"])
        self.assertEqual("completed", run["state"])
        self.service.preserve(self.lab_id)
        original = self.service._mutate
        restored = []

        def restore_then_contain(*args, **kwargs):
            result = original(*args, **kwargs)
            if kwargs.get("recovery"):
                restored.append(True)
                if len(restored) == 1:
                    self.service.contain(self.lab_id)
            return result

        with patch.object(self.service, "_mutate", side_effect=restore_then_contain):
            with self.assertRaisesRegex(StateError, "stopped"):
                self.service.recover(self.lab_id)
        self.assertEqual(1, len(restored))
        status = self.service.status(self.lab_id)
        self.assertEqual("completed", status["last_run"]["state"])
        self.assertEqual("recovery_failed", status["state"])
        self.assertFalse(status["recovery"]["verified"])
        self.assertEqual(1, sum(item["status"] == "intact" for item in status["fixtures"]))
        self.assertEqual(3, sum(item["status"] == "changed" for item in status["fixtures"]))
        kinds = [item["kind"] for item in status["events"]]
        self.assertIn("containment.requested", kinds)
        self.assertIn("recovery.failed", kinds)
        self.assertNotIn("recovery.verified", kinds)

    def test_expired_run_budget_prevents_the_first_fixture_action(self):
        request = self.stage()
        with patch("ransomlab.services.time.monotonic", side_effect=[0.0, 301.0]):
            run = self.service.simulate(self.lab_id, request["request_id"])
        self.assertEqual("contained", run["state"])
        self.assertEqual([], run["affected"])
        status = self.service.status(self.lab_id)
        self.assertEqual({"intact"}, {item["status"] for item in status["fixtures"]})
        self.assertFalse(any(item["kind"] in {"file.intent", "file.changed"} for item in status["events"]))
        self.assertTrue(self.service.simulate(self.lab_id, request["request_id"])["duplicate"])

    def test_existing_sqlite_sidecars_are_rejected_before_repository_open(self):
        with MemoryDirectory(self.service.root / self.lab_id) as directory:
            for suffix in ("-journal", "-wal", "-shm"):
                name = "state.db" + suffix
                with self.subTest(sidecar=name):
                    directory.create(name, b"synthetic sidecar")
                    try:
                        with patch("ransomlab.services.EventStore") as repository:
                            with self.assertRaisesRegex(StateError, "sidecar"):
                                self.service.status(self.lab_id)
                            repository.assert_not_called()
                    finally:
                        # Remove only the synthetic in-memory entry.
                        del directory.entries[directory.key][name]

    def test_post_recovery_change_loses_current_verification_everywhere(self):
        request = self.stage()
        self.service.simulate(self.lab_id, request["request_id"])
        self.service.preserve(self.lab_id)
        self.service.recover(self.lab_id)
        self.assertEqual("verified", self.service.status(self.lab_id)["state"])
        fixture = self.lab["fixtures"][0]
        with MemoryDirectory(self.service.root / self.lab_id / "work") as work:
            work.replace(fixture["name"], b"Synthetic content changed after recovery")

        status = self.service.status(self.lab_id)
        report = self.service.report(self.lab_id)
        listed = next(item for item in self.service.list_labs() if item["lab_id"] == self.lab_id)
        self.assertEqual("verification_lost", status["state"])
        self.assertEqual("verification_lost", report["state"])
        self.assertEqual("verification_lost", listed["state"])
        self.assertFalse(status["recovery"]["verified"])
        self.assertTrue(status["recovery"]["historical_verified"])
        self.assertFalse(report["findings"]["recovery_verified"])
        self.assertEqual(1, report["findings"]["changed"])
        with self.service._open(self.lab_id, readonly=True) as (_, store, __):
            self.assertTrue(store.get_state("recovery")["verified"])
        # The historical result is retained; no false current success is shown.


if __name__ == "__main__":
    unittest.main()
