"""Multistage effects stay in generated memory fixtures; journals use disposable SQLite."""
import contextlib
import copy
from datetime import datetime, timedelta, timezone
import io
import json
import unittest
from unittest.mock import patch
from uuid import uuid4

import test_services as service_cases
from memory_fixtures import MemoryDirectory
from ransomlab import scenarios, simulation
from ransomlab.cli import main, markdown_report
from ransomlab.core.config import Policy
from ransomlab.core.errors import SafetyError, StateError, ValidationError
from ransomlab.core.hashing import hash_bytes


class ScenarioPlanTests(unittest.TestCase):
    def setUp(self):
        self.lab = {"lab_id": str(uuid4()), "baseline_id": str(uuid4()), "fixtures": [{"id": str(uuid4())} for _ in range(4)]}

    def test_v1_compatibility_and_v2_closed_pacing_and_copy_plans(self):
        legacy = scenarios.create(self.lab, "modify_generated")
        self.assertEqual(legacy["schema_version"], 1)
        self.assertEqual(scenarios.configuration(legacy), {"interval_ms": 0})
        paced = scenarios.create(self.lab, "modify_generated", interval_ms=50)
        self.assertEqual(paced["schema_version"], 2)
        self.assertEqual(scenarios.action_count(paced), 4)
        plan = scenarios.create(self.lab, "double_extortion_generated", stage_count=3, receive_count=2)
        self.assertEqual(scenarios.action_count(plan), 14)
        self.assertEqual(scenarios.validate(scenarios.parse_json(scenarios.canonical(plan)), self.lab), plan)

    def test_path_url_script_counts_versions_and_malformed_configuration_rejected(self):
        plan = scenarios.create(self.lab, "double_extortion_generated")
        for changes in ({"destination": "https://example.invalid"}, {"path": "../outside"}, {"script": "anything"},
                        {"interval_ms": True}, {"interval_ms": -1}, {"interval_ms": 2001}, {"interval_ms": 0.5},
                        {"stage_count": 5}, {"stage_count": -1}, {"receive_count": 5}, {"receive_count": False}):
            invalid = {**plan, "configuration": {**plan["configuration"], **changes}}
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                scenarios.validate(invalid, self.lab)
        for changes in ({"configuration": []}, {"configuration": {}}, {"scenario_version": True},
                        {"scenario_version": 2}, {"replay_of": "../bad"}, {"schema_version": 3}):
            with self.assertRaises(ValidationError):
                scenarios.validate({**plan, **changes}, self.lab)
        with self.assertRaises(ValidationError):
            scenarios.create(self.lab, "modify_generated", stage_count=1)
        for action in ([], {}, None, "shell"):
            with self.assertRaises(ValidationError):
                scenarios.create(self.lab, action)
        invalid = {key: value for key, value in plan.items() if key in scenarios.FIELDS}
        invalid["schema_version"] = 1
        with self.assertRaises(ValidationError):
            scenarios.validate(invalid, self.lab)

    def test_replay_keeps_order_and_plan_digest_with_fresh_identity_and_lifetime(self):
        original = scenarios.create(self.lab, "double_extortion_generated", stage_count=2, receive_count=1)
        original["fixture_ids"].reverse()
        replay = scenarios.replay(original, self.lab)
        self.assertNotEqual(replay["request_id"], original["request_id"])
        self.assertEqual(replay["replay_of"], original["request_id"])
        self.assertEqual(replay["fixture_ids"], original["fixture_ids"])
        self.assertEqual(scenarios.plan_digest(replay), scenarios.plan_digest(original))
        now = datetime.now(timezone.utc)
        original.update(issued_at=(now - timedelta(hours=2)).isoformat(), expires_at=(now - timedelta(minutes=110)).isoformat())
        self.assertGreater(datetime.fromisoformat(scenarios.replay(original, self.lab)["expires_at"]), now)
        changed = copy.deepcopy(replay)
        changed["configuration"]["interval_ms"] = 0
        self.assertNotEqual(scenarios.plan_digest(changed), scenarios.plan_digest(replay))

    def test_pacing_delays_have_bounded_stop_checkpoints(self):
        checkpoint = unittest.mock.Mock()
        with patch("ransomlab.simulation.time.sleep") as sleep:
            simulation.pace(200, checkpoint)
        self.assertAlmostEqual(sum(call.args[0] for call in sleep.call_args_list), 0.2)
        self.assertTrue(all(call.args[0] <= 0.05 for call in sleep.call_args_list))
        self.assertGreaterEqual(checkpoint.call_count, 5)
        with patch("ransomlab.simulation.time.sleep") as sleep:
            with self.assertRaises(simulation.SimulationStopped):
                simulation.pace(2000, lambda: (_ for _ in ()).throw(simulation.SimulationStopped("stopped")))
            sleep.assert_not_called()


class BehaviourServiceTests(unittest.TestCase):
    setUp = service_cases.ServiceTests.setUp

    def stage(self, scenario="double_extortion_generated", count=3, **options):
        request = self.service.create_scenario(self.lab_id, scenario, count, interval_ms=0, **options)
        self.service.import_scenario(request)
        self.service.arm(self.lab_id, "generated-snapshot", True, True)
        return request

    def artifact_directory(self, run):
        return MemoryDirectory(self.service.root / self.lab_id / "artifacts" / run["run_id"])

    def test_multistage_run_verifiable_artifacts_evidence_recovery_and_unchanged_controls(self):
        protected = {key: copy.deepcopy(files) for key, files in MemoryDirectory.entries.items() if key.endswith(("clean", "keys"))}
        request = self.stage(stage_count=2, receive_count=1)
        with patch("socket.socket", side_effect=AssertionError("Scenario opened a socket")):
            run = self.service.simulate(self.lab_id, request["request_id"])
        self.assertEqual(run["state"], "completed")
        self.assertEqual(run["affected"], request["fixture_ids"])
        self.assertEqual([item["synthetic_class"] for item in run["discovered"]], ["public", "finance", "project"])
        with self.artifact_directory(run) as directory:
            for item in run["artifacts"]:
                self.assertEqual(item["sha256"], hash_bytes(directory.read(item["name"], item["size"])))
            self.assertEqual(len(directory.names()), 4)
        report = self.service.report(self.lab_id)
        self.assertEqual(report["simulation"]["staged_bytes"], 256)
        self.assertEqual(report["simulation"]["mock_received_bytes"], 128)
        self.assertFalse(report["simulation"]["external_transfer"])
        self.assertEqual(report["fixtures"][3]["status"], "intact")
        kinds = [event["kind"] for event in report["events"]]
        self.assertLess(kinds.index("file.discovered"), kinds.index("artifact.created"))
        self.assertLess(kinds.index("artifact.created"), kinds.index("file.changed"))
        self.assertEqual(self.service.run_history(self.lab_id), [run])
        self.assertIn("Local mock receipts", markdown_report(report))
        evidence = self.service.preserve(self.lab_id)
        with self.service._open(self.lab_id, readonly=True) as (_, __, path):
            manifest = self.service._verify_evidence(path, evidence)
        preserved = [item for item in manifest["files"] if "artifact_kind" in item]
        self.assertEqual(len(preserved), 4)
        self.assertTrue(all("fixture_id" not in item for item in preserved))
        self.assertTrue(self.service.recover(self.lab_id)["verified"])
        self.service.close_experiment(self.lab_id)
        for key, files in protected.items():
            self.assertEqual(files, MemoryDirectory.entries[key])

    def test_benign_control_copies_without_impact_note_or_integrity_alerts(self):
        request = self.stage("benign_copy_generated", stage_count=2, receive_count=1)
        run = self.service.simulate(self.lab_id, request["request_id"])
        self.assertEqual(run["affected"], [])
        self.assertEqual([item["kind"] for item in run["artifacts"]], ["staged", "staged", "received"])
        report = self.service.report(self.lab_id)
        self.assertEqual(report["findings"]["changed"], 0)
        self.assertEqual(report["alerts"], [])
        self.service.preserve(self.lab_id)
        self.assertTrue(self.service.recover(self.lab_id)["verified"])

    def test_zero_copy_limits_prevent_staging_and_receipts(self):
        request = self.stage(stage_count=0, receive_count=0)
        run = self.service.simulate(self.lab_id, request["request_id"])
        self.assertEqual([item["kind"] for item in run["artifacts"]], ["note"])
        self.assertEqual(self.service.report(self.lab_id)["simulation"]["mock_received_bytes"], 0)

    def test_unarmed_wrong_guest_and_changed_request_do_not_create_artifacts(self):
        request = self.service.create_scenario(self.lab_id, "double_extortion_generated", 1)
        self.service.import_scenario(request)
        with self.assertRaises(SafetyError):
            self.service.simulate(self.lab_id, request["request_id"])
        self.service.arm(self.lab_id, "snapshot", True, True)
        with patch("ransomlab.environment.vmware_guest", return_value=False), self.assertRaises(SafetyError):
            self.service.simulate(self.lab_id, request["request_id"])
        with self.service._open(self.lab_id) as (lab, store, _):
            saved = store.get_state("request:" + request["request_id"])
            saved["envelope"]["configuration"]["interval_ms"] = 100
            self.service._event(store, lab, "scenario.imported", updates={"request:" + request["request_id"]: saved})
        with self.assertRaises(SafetyError):
            self.service.simulate(self.lab_id, request["request_id"])
        self.assertEqual(self.service.run_history(self.lab_id), [])

    def test_action_audit_pacing_and_artifact_quotas_reject_before_consuming_arming(self):
        request = self.stage()
        for policy in (Policy(max_actions=5), Policy(max_events=20), Policy(max_evidence_bytes=1024)):
            self.service.policy = policy
            with self.assertRaises(SafetyError):
                self.service.simulate(self.lab_id, request["request_id"])
        self.service.policy = Policy()
        with self.service._open(self.lab_id) as (lab, store, _):
            self.service._event(store, lab, "file.observed", updates={"artifact_reserved_bytes": self.service.policy.max_total_bytes * 2})
        with self.assertRaises(SafetyError):
            self.service.simulate(self.lab_id, request["request_id"])
        self.assertEqual(self.service.status(self.lab_id)["state"], "armed")
        self.assertEqual(self.service.run_history(self.lab_id), [])

    def test_containment_after_staging_retains_verified_copies_without_receipts_or_impact(self):
        request = self.stage(stage_count=2, receive_count=2)
        original = self.service._write_artifact

        def write_then_stop(*args, **kwargs):
            original(*args, **kwargs)
            self.service.contain(self.lab_id)

        with patch.object(self.service, "_write_artifact", side_effect=write_then_stop):
            run = self.service.simulate(self.lab_id, request["request_id"])
        self.assertEqual(run["state"], "contained")
        self.assertEqual(run["reason"], "operator_requested")
        self.assertEqual([item["kind"] for item in run["artifacts"]], ["staged"])
        self.assertEqual(run["affected"], [])
        self.assertEqual(self.service.report(self.lab_id)["simulation"]["mock_received_files"], 0)
        self.service.preserve(self.lab_id)
        self.assertTrue(self.service.recover(self.lab_id)["verified"])

    def test_artifact_intent_failure_does_not_write_or_report_a_copy(self):
        request = self.stage()
        original = self.service._event

        def fail_intent(store, lab, kind, **kwargs):
            if kind == "artifact.intent":
                raise StateError("Synthetic intent failure")
            return original(store, lab, kind, **kwargs)

        with patch.object(self.service, "_event", side_effect=fail_intent), self.assertRaises(StateError):
            self.service.simulate(self.lab_id, request["request_id"])
        run = self.service.run_history(self.lab_id)[0]
        self.assertEqual(run["state"], "interrupted")
        self.assertEqual(run["artifacts"], [])
        with self.artifact_directory(run) as directory:
            self.assertEqual(directory.names(), [])

    def test_failed_receipt_commit_counts_only_verified_reconciliation(self):
        request = self.stage(stage_count=1, receive_count=1)
        original = self.service._event

        def fail_receipt(store, lab, kind, **kwargs):
            if kind == "artifact.created" and kwargs["details"]["operation"] == "received":
                raise StateError("Synthetic receipt commit failure")
            return original(store, lab, kind, **kwargs)

        with patch.object(self.service, "_event", side_effect=fail_receipt), self.assertRaises(StateError):
            self.service.simulate(self.lab_id, request["request_id"])
        self.assertEqual(self.service.status(self.lab_id)["state"], "reconciliation_required")
        self.assertEqual(self.service.report(self.lab_id)["simulation"]["mock_received_files"], 0)
        with self.assertRaises(StateError):
            self.service.preserve(self.lab_id)
        self.assertEqual(self.service.reconcile(self.lab_id)["finding"], "applied")
        run = self.service.run_history(self.lab_id)[0]
        self.assertTrue(run["artifacts"][-1]["reconciled"])
        self.assertEqual(self.service.report(self.lab_id)["simulation"]["mock_received_files"], 1)
        self.service.preserve(self.lab_id)
        self.assertTrue(self.service.recover(self.lab_id)["verified"])

    def test_corrupt_interrupted_artifact_keeps_pending_state_and_fails_closed(self):
        request = self.stage()
        original = self.service._event

        def fail_created(store, lab, kind, **kwargs):
            if kind == "artifact.created":
                raise StateError("Synthetic artifact commit failure")
            return original(store, lab, kind, **kwargs)

        with patch.object(self.service, "_event", side_effect=fail_created), self.assertRaises(StateError):
            self.service.simulate(self.lab_id, request["request_id"])
        run = self.service.run_history(self.lab_id)[0]
        with self.artifact_directory(run) as directory:
            directory.replace("stage-" + request["fixture_ids"][0] + ".bin", b"synthetic corruption")
        with self.assertRaises(SafetyError):
            self.service.reconcile(self.lab_id)
        self.assertEqual(self.service.status(self.lab_id)["state"], "reconciliation_required")
        self.assertEqual(run["artifacts"], [])

    def test_changed_stage_hash_blocks_transfer(self):
        request = self.stage(stage_count=1, receive_count=1)
        original = self.service._write_artifact

        def corrupt_stage(lab, store, path, run, directory, kind, fixture, data):
            original(lab, store, path, run, directory, kind, fixture, data)
            if kind == "staged":
                directory.replace("stage-" + fixture["id"] + ".bin", b"synthetic corruption")

        with patch.object(self.service, "_write_artifact", side_effect=corrupt_stage), self.assertRaises(SafetyError):
            self.service.simulate(self.lab_id, request["request_id"])
        self.assertEqual(self.service.report(self.lab_id)["simulation"]["mock_received_files"], 0)
        self.assertEqual(self.service.report(self.lab_id)["findings"]["changed"], 0)

    def test_changed_artifact_identity_and_unregistered_objects_block_preservation(self):
        request = self.stage("benign_copy_generated", stage_count=1, receive_count=0)
        run = self.service.simulate(self.lab_id, request["request_id"])
        with self.artifact_directory(run) as directory:
            name = run["artifacts"][0]["name"]
            identity = copy.deepcopy(directory.entries[directory.key][name][1])
            directory.entries[directory.key][name][1]["inode"] += 1
            with self.assertRaises(SafetyError):
                self.service.preserve(self.lab_id)
            directory.entries[directory.key][name][1] = identity
            directory.create("unknown.bin", b"generated unregistered decoy")
            with self.assertRaises(SafetyError):
                self.service.preserve(self.lab_id)

    def test_pacing_budget_and_retained_file_quota_preserve_arming(self):
        request = self.service.create_scenario(self.lab_id, "double_extortion_generated", 3, interval_ms=2000)
        self.service.import_scenario(request)
        self.service.arm(self.lab_id, "snapshot", True, True)
        self.service.policy = Policy(max_run_seconds=1)
        with self.assertRaises(SafetyError):
            self.service.simulate(self.lab_id, request["request_id"])
        self.service.policy = Policy()
        with self.service._open(self.lab_id) as (lab, store, _):
            self.service._event(store, lab, "file.observed", updates={"artifact_reserved_files": 220})
        with self.assertRaises(SafetyError):
            self.service.simulate(self.lab_id, request["request_id"])
        self.assertEqual(self.service.status(self.lab_id)["state"], "armed")

    def test_disk_write_failure_keeps_unapplied_intent_without_optimistic_copy(self):
        request = self.stage(stage_count=1, receive_count=1)
        original = MemoryDirectory.create

        def fail_copy(directory, name, data):
            if name.startswith("stage-"):
                raise OSError("Synthetic full disk")
            return original(directory, name, data)

        with patch.object(MemoryDirectory, "create", fail_copy), self.assertRaises(OSError):
            self.service.simulate(self.lab_id, request["request_id"])
        self.assertEqual(self.service.reconcile(self.lab_id)["finding"], "not_applied")
        self.assertEqual(self.service.report(self.lab_id)["simulation"]["staged_files"], 0)
        self.service.preserve(self.lab_id)
        self.assertTrue(self.service.recover(self.lab_id)["verified"])

    def test_terminal_failure_preserves_committed_impact_and_reconciles_running_state(self):
        request = self.stage(stage_count=1, receive_count=1)
        original = self.service._event

        def fail_terminal(store, lab, kind, **kwargs):
            if kind in {"run.completed", "run.interrupted"}:
                raise StateError("Synthetic terminal write failure")
            return original(store, lab, kind, **kwargs)

        with patch.object(self.service, "_event", side_effect=fail_terminal), self.assertRaises(StateError):
            self.service.simulate(self.lab_id, request["request_id"])
        run = self.service.run_history(self.lab_id)[0]
        self.assertEqual(run["state"], "running")
        self.assertEqual(len(run["affected"]), 3)
        self.assertEqual(len(run["artifacts"]), 3)
        self.service.reconcile(self.lab_id)
        self.assertEqual(self.service.run_history(self.lab_id)[0]["state"], "interrupted")

    def test_area_creation_result_failure_is_reconciled_without_inventing_files(self):
        request = self.stage()
        original = self.service._event

        def fail_area(store, lab, kind, **kwargs):
            if kind == "artifact.area_ready":
                raise StateError("Synthetic area result failure")
            return original(store, lab, kind, **kwargs)

        with patch.object(self.service, "_event", side_effect=fail_area), self.assertRaises(StateError):
            self.service.simulate(self.lab_id, request["request_id"])
        self.assertEqual(self.service.reconcile(self.lab_id)["finding"], "empty_area_prepared")
        self.assertEqual(self.service.report(self.lab_id)["simulation"]["staged_files"], 0)
        self.service.preserve(self.lab_id)
        self.assertTrue(self.service.recover(self.lab_id)["verified"])

    def test_replay_is_fresh_staged_once_and_repeats_normalized_results(self):
        request = self.stage(stage_count=1, receive_count=1)
        first = self.service.simulate(self.lab_id, request["request_id"])
        self.service.preserve(self.lab_id)
        self.service.recover(self.lab_id)
        replay = self.service.replay_scenario(self.lab_id, request["request_id"])
        self.service.import_scenario(replay)
        with self.assertRaises(SafetyError):
            self.service.simulate(self.lab_id, replay["request_id"])
        self.service.arm(self.lab_id, "new-snapshot", True, True)
        second = self.service.simulate(self.lab_id, replay["request_id"])
        self.assertNotEqual(first["run_id"], second["run_id"])
        self.assertEqual(first["plan_sha256"], second["plan_sha256"])
        self.assertEqual(first["discovered"], second["discovered"])
        self.assertEqual(first["affected"], second["affected"])
        self.assertTrue(self.service.simulate(self.lab_id, replay["request_id"])["duplicate"])
        with self.assertRaises(ValidationError):
            self.service.replay_scenario(self.lab_id, str(uuid4()))

    def test_replay_import_rejects_unknown_parent_and_changed_parent_plan(self):
        request = self.stage(stage_count=1, receive_count=1)
        replay = self.service.replay_scenario(self.lab_id, request["request_id"])
        with self.assertRaises(ValidationError):
            self.service.import_scenario({**replay, "replay_of": str(uuid4())})
        replay["configuration"]["receive_count"] = 0
        with self.assertRaises(ValidationError):
            self.service.import_scenario(replay)

    def test_cli_options_history_replay_and_reports_use_shared_services(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["scenario", "create", self.lab_id, "double_extortion_generated", "--count", "2",
                         "--interval-ms", "0", "--stage-count", "1", "--receive-count", "0"], self.service)
        self.assertEqual(code, 0)
        request = json.loads(output.getvalue())
        self.service.import_scenario(request)
        self.service.arm(self.lab_id, "snapshot", True, True)
        self.service.simulate(self.lab_id, request["request_id"])
        for command in (["scenario", "history", self.lab_id], ["scenario", "replay", self.lab_id, request["request_id"]]):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(command, self.service), 0)
