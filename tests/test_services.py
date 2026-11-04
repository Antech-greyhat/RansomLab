"""Workflow tests: in-memory fixture impact, real disposable SQLite journal."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ransomlab.core.errors import LabError, SafetyError, StateError
from ransomlab.services import LabService
from memory_fixtures import MemoryDirectory, MemoryLease


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ransomlab-metadata-")
        self.addCleanup(self.temp.cleanup)
        MemoryDirectory.entries.clear()
        MemoryLease.locks.clear()
        for name, value in (("SafeDirectory", MemoryDirectory), ("LabLease", MemoryLease)):
            task_patch = patch("ransomlab.services." + name, value)
            task_patch.start()
            self.addCleanup(task_patch.stop)
        vm = patch("ransomlab.environment.vmware_guest", return_value=True)
        vm.start()
        self.addCleanup(vm.stop)
        identity = patch("ransomlab.environment.unprivileged_process", return_value=True)
        identity.start()
        self.addCleanup(identity.stop)
        self.service = LabService(Path(self.temp.name) / "lab-data")
        self.lab = self.service.create_lab("Generated test", count=4, size=128)
        self.lab_id = self.lab["lab_id"]

    def stage(self, scenario="modify_generated"):
        request = self.service.create_scenario(self.lab_id, scenario)
        self.service.import_scenario(request)
        self.service.arm(self.lab_id, "test-snapshot", True, True)
        return request

    def test_generated_inventory_and_readonly_status(self):
        self.assertEqual(self.lab["state"], "prepared")
        self.assertEqual({item["status"] for item in self.lab["fixtures"]}, {"intact"})
        before = self.service.report(self.lab_id)["event_count"]
        self.service.status(self.lab_id)
        self.assertEqual(self.service.report(self.lab_id)["event_count"], before)
        self.assertEqual(self.service.list_labs()[0]["lab_id"], self.lab_id)

    def test_import_stages_deduplicates_and_never_executes(self):
        request = self.service.create_scenario(self.lab_id, "modify_generated")
        self.assertEqual(self.service.import_scenario(request)["status"], "staged")
        self.assertTrue(self.service.import_scenario(request)["duplicate"])
        self.assertEqual(self.service.status(self.lab_id)["state"], "prepared")
        request["scenario"] = "encrypt_generated"
        with self.assertRaises(SafetyError):
            self.service.import_scenario(request)

    def test_arm_requires_verified_environment_and_explicit_confirmations(self):
        with patch("ransomlab.environment.vmware_guest", return_value=False), self.assertRaises(SafetyError):
            self.service.arm(self.lab_id, "snapshot", True, True)
        with self.assertRaises(SafetyError):
            self.service.arm(self.lab_id, "snapshot", False, True)
        request = self.service.create_scenario(self.lab_id, "modify_generated")
        self.service.import_scenario(request)
        with self.assertRaises(SafetyError):
            self.service.simulate(self.lab_id, request["request_id"])

    def test_full_modify_detection_evidence_recovery_workflow(self):
        request = self.stage()
        run = self.service.simulate(self.lab_id, request["request_id"])
        self.assertEqual(run["state"], "completed")
        self.assertTrue(self.service.simulate(self.lab_id, request["request_id"])["duplicate"])
        report = self.service.report(self.lab_id)
        self.assertEqual(report["findings"]["changed"], 4)
        self.assertIn("burst_integrity_change", {item["rule"] for item in report["alerts"]})
        with self.assertRaises(StateError):
            self.service.recover(self.lab_id)
        evidence = self.service.preserve(self.lab_id)
        self.assertGreater(evidence["bytes"], 0)
        recovered = self.service.recover(self.lab_id)
        self.assertTrue(recovered["verified"])
        self.assertEqual(recovered["count"], 4)
        self.assertEqual(self.service.status(self.lab_id)["state"], "verified")
        self.service.arm(self.lab_id, "new-test-snapshot", True, True)
        self.assertEqual(self.service.status(self.lab_id)["state"], "armed")

    @unittest.skipUnless(os.name == "nt", "Native CNG byte provider requires Windows")
    def test_encryption_and_authenticated_decrypt_recovery(self):
        request = self.stage("encrypt_generated")
        self.service.simulate(self.lab_id, request["request_id"])
        self.service.preserve(self.lab_id)
        self.assertTrue(self.service.recover(self.lab_id, mode="decrypt")["verified"])
        # Fixture ciphertext exists only in the memory adapter, not in these dirs.
        self.assertEqual(list((self.service.root / self.lab_id / "work").iterdir()), [])

    def test_tampered_clean_copy_blocks_arming(self):
        filename = self.lab["fixtures"][0]["name"]
        with MemoryDirectory(self.service.root / self.lab_id / "clean") as directory:
            directory.replace(filename, b"bad clean copy")
        with self.assertRaises(SafetyError):
            self.service.arm(self.lab_id, "snapshot", True, True)

    def test_new_objects_and_replaced_identity_fail_closed(self):
        with MemoryDirectory(self.service.root / self.lab_id / "work") as directory:
            directory.create("unknown.bin", b"unregistered")
        with self.assertRaises(SafetyError):
            self.service.status(self.lab_id)

    def test_journal_failure_before_intent_leaves_fixture_intact(self):
        request = self.stage()
        original = self.service._event

        def fail_intent(store, lab, kind, **kwargs):
            if kind == "file.intent":
                raise StateError("Synthetic journal failure")
            return original(store, lab, kind, **kwargs)

        with patch.object(self.service, "_event", side_effect=fail_intent), self.assertRaises(StateError):
            self.service.simulate(self.lab_id, request["request_id"])
        self.assertEqual({item["status"] for item in self.service.status(self.lab_id)["fixtures"]}, {"intact"})

    def test_failure_after_write_requires_reconciliation(self):
        request = self.stage()
        original = self.service._event

        def fail_result(store, lab, kind, **kwargs):
            if kind == "file.changed":
                raise StateError("Synthetic result failure")
            return original(store, lab, kind, **kwargs)

        with patch.object(self.service, "_event", side_effect=fail_result), self.assertRaises(StateError):
            self.service.simulate(self.lab_id, request["request_id"])
        self.assertEqual(self.service.status(self.lab_id)["state"], "reconciliation_required")
        self.assertEqual(self.service.reconcile(self.lab_id)["finding"], "applied")
        self.service.preserve(self.lab_id)
        self.assertTrue(self.service.recover(self.lab_id)["verified"])

    def test_evidence_tamper_blocks_recovery(self):
        request = self.stage()
        self.service.simulate(self.lab_id, request["request_id"])
        evidence = self.service.preserve(self.lab_id)
        filename = self.lab["fixtures"][0]["name"]
        with MemoryDirectory(self.service.root / self.lab_id / "evidence" / evidence["id"]) as directory:
            directory.replace(filename, b"tampered")
        with self.assertRaises(SafetyError):
            self.service.recover(self.lab_id)

    def test_historical_recovery_is_not_current_verification(self):
        request = self.stage()
        self.service.simulate(self.lab_id, request["request_id"])
        self.service.preserve(self.lab_id)
        self.service.recover(self.lab_id)
        filename = self.lab["fixtures"][0]["name"]
        with MemoryDirectory(self.service.root / self.lab_id / "work") as directory:
            directory.replace(filename, b"later change")
        report = self.service.report(self.lab_id)
        self.assertEqual(report["state"], "verification_lost")
        self.assertTrue(report["recovery"]["historical_verified"])
        self.assertFalse(report["findings"]["recovery_verified"])

    def test_idle_monitor_does_not_consume_recovery_reserve(self):
        request = self.stage()
        self.service.simulate(self.lab_id, request["request_id"])
        count = self.service.report(self.lab_id)["event_count"]
        for _ in range(8):
            self.service.monitor(self.lab_id)
        self.assertEqual(count, self.service.report(self.lab_id)["event_count"])
        self.service.preserve(self.lab_id)
        self.assertTrue(self.service.recover(self.lab_id)["verified"])

    def test_failed_evidence_commit_retains_quota_reservation(self):
        request = self.stage()
        self.service.simulate(self.lab_id, request["request_id"])
        original = self.service._event

        def fail_evidence(store, lab, kind, **kwargs):
            if kind == "evidence.preserved":
                raise StateError("Synthetic evidence commit failure")
            return original(store, lab, kind, **kwargs)

        with patch.object(self.service, "_event", side_effect=fail_evidence), self.assertRaises(StateError):
            self.service.preserve(self.lab_id)
        records = self.service.report(self.lab_id)["evidence"]
        self.assertEqual(records[-1]["state"], "incomplete")
        self.assertGreater(records[-1]["bytes"], 0)
        with self.assertRaises(StateError):
            self.service.recover(self.lab_id)

    def test_missing_fixture_preserves_available_evidence_as_partial(self):
        request = self.stage()
        self.service.simulate(self.lab_id, request["request_id"])
        filename = self.lab["fixtures"][0]["name"]
        del MemoryDirectory.entries[str(self.service.root / self.lab_id / "work")][filename]
        evidence = self.service.preserve(self.lab_id)
        self.assertEqual(evidence["state"], "partial")
        self.assertEqual(self.service.report(self.lab_id)["findings"]["missing"], 1)
        with self.assertRaises(StateError):
            self.service.recover(self.lab_id)


if __name__ == "__main__":
    unittest.main()
