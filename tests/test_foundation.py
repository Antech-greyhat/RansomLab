"""Configuration, lifecycle and boundary regression tests using synthetic data."""
from dataclasses import FrozenInstanceError
import io
import json
import logging
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from ransomlab.cli import main
from ransomlab.core.config import AppConfig, Policy
from ransomlab.core.errors import SafetyError, StateError, ValidationError
from ransomlab.core.events import Event
from ransomlab.core.hashing import hash_bytes
from ransomlab.core.logging import EventFormatter
from ransomlab.core.models import ExperimentRecord, ExperimentState
from ransomlab.core.repository import EventStore
from ransomlab.core.safety import validate_manifest
from ransomlab.services import LabService
from ransomlab.storage import SafeDirectory
from memory_fixtures import MemoryDirectory
import test_services as service_cases


class ConfigurationTests(unittest.TestCase):
    def test_defaults_and_partial_policy_expand_to_explicit_snapshot(self):
        config = AppConfig.from_dict({"schema_version": 1, "policy": {"max_files": 20}, "logging": {"level": "INFO"}})
        self.assertEqual(20, config.policy.max_files)
        self.assertEqual(Policy().max_total_bytes, config.policy.max_total_bytes)
        self.assertEqual(config, AppConfig.from_dict(config.to_dict()))
        with self.assertRaises(FrozenInstanceError):
            config.log_level = "ERROR"

    def test_unknown_types_roots_and_relaxed_limits_are_rejected(self):
        values = [{}, {"schema_version": True}, {"schema_version": 2},
                  {"schema_version": 1, "root": "private-marker"},
                  {"schema_version": 1, "policy": {"max_files": 101}},
                  {"schema_version": 1, "policy": {"max_files": True}},
                  {"schema_version": 1, "policy": {"min_free_bytes": 1}},
                  {"schema_version": 1, "policy": None},
                  {"schema_version": 1, "logging": {"level": "private-marker"}},
                  {"schema_version": 1, "logging": {"file": "private-marker"}}]
        for value in values:
            with self.subTest(value=value), self.assertRaises(ValidationError) as caught:
                AppConfig.from_dict(value)
            self.assertNotIn("private-marker", str(caught.exception))

    def test_toml_size_encoding_and_duplicate_field_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "generated-config.toml"
            for content in (b"schema_version=1\nschema_version=1", b"\xff", b"#" * 16_385):
                path.write_bytes(content)
                with self.subTest(content_length=len(content)), self.assertRaises(ValidationError):
                    AppConfig.load(path)
            path.write_text('schema_version=1\n[logging]\nlevel="INFO"\n', encoding="utf-8")
            self.assertEqual("INFO", AppConfig.load(path).log_level)

    def test_missing_config_blocks_cli_before_service_dispatch(self):
        service = Mock()
        with tempfile.TemporaryDirectory() as temporary, patch("sys.stderr", new_callable=io.StringIO) as error:
            result = main(["--config", str(Path(temporary) / "missing.toml"), "experiment", "create"], service)
        self.assertEqual(2, result)
        self.assertFalse(service.mock_calls)
        self.assertNotIn(temporary, error.getvalue())

    def test_unreadable_default_configuration_never_falls_back(self):
        with patch.object(Path, "lstat", side_effect=PermissionError("private-marker")):
            with self.assertRaisesRegex(ValidationError, "inspected"):
                AppConfig.discover()

    def test_cli_configuration_and_experiment_dispatch(self):
        service = Mock()
        service.create_experiment.return_value = {"experiment_id": str(uuid4()), "state": "draft"}
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(0, main(["experiment", "create", "--name", "Study"], service))
            self.assertEqual("draft", json.loads(output.getvalue())["state"])
        service.create_experiment.assert_called_once_with("Study")
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(0, main(["config", "check"]))
            self.assertEqual(1, json.loads(output.getvalue())["schema_version"])


class ModelTests(unittest.TestCase):
    def record(self):
        return ExperimentRecord(str(uuid4()), str(uuid4()), hash_bytes(b"generated manifest"))

    def test_lifecycle_round_trip_and_terminal_closure(self):
        draft = self.record()
        ready = draft.validate()
        closed = ready.close()
        self.assertEqual(ExperimentState.DRAFT, draft.state)
        self.assertEqual(2, ready.revision)
        self.assertEqual(closed, ExperimentRecord.from_dict(closed.to_dict()))
        self.assertIs(closed, closed.close())
        with self.assertRaises(StateError):
            closed.validate()
        with self.assertRaises(FrozenInstanceError):
            closed.state = ExperimentState.READY

    def test_invalid_state_versions_and_inconsistent_timestamps(self):
        original = self.record().to_dict()
        for change in ({"schema_version": True}, {"state": "running"}, {"state": []},
                       {"revision": True}, {"revision": 0}, {"state": "closed"},
                       {"state": "ready"}, {"closed_at": "2026-01-01T00:00:00Z"},
                       {"experiment_id": "../private-marker"}, {"unknown": 1}):
            with self.subTest(change=change), self.assertRaises(ValidationError):
                ExperimentRecord.from_dict({**original, **change})


class ExperimentTests(unittest.TestCase):
    setUp = service_cases.ServiceTests.setUp
    stage = service_cases.ServiceTests.stage

    def test_metadata_only_create_validate_reopen_inspect_close(self):
        draft = self.service.create_experiment("Metadata study")
        identifier = draft["experiment_id"]
        self.assertEqual("draft", draft["state"])
        self.assertEqual(0, draft["fixture_count"])
        with MemoryDirectory(self.service.root / identifier / "work") as work:
            self.assertEqual([], work.names())
        ready = self.service.validate_experiment(identifier)
        self.assertEqual("ready", ready["state"])
        reopened = LabService(self.service.root)
        self.assertEqual(ready, reopened.inspect_experiment(identifier))
        closed = reopened.close_experiment(identifier)
        self.assertEqual("closed", closed["state"])
        self.assertEqual(closed, reopened.close_experiment(identifier))
        self.assertEqual(closed, next(item for item in reopened.list_experiments() if item["experiment_id"] == identifier))
        kinds = [item["kind"] for item in reopened.status(identifier)["events"]]
        self.assertEqual(["experiment.created", "experiment.validated", "experiment.closed"], kinds)

    def test_empty_experiment_cannot_be_armed_even_after_validation(self):
        identifier = self.service.create_experiment()["experiment_id"]
        self.service.validate_experiment(identifier)
        with self.assertRaisesRegex(StateError, "generated fixtures"):
            self.service.arm(identifier, "snapshot", True, True)

    def test_draft_can_close_without_validation_or_data(self):
        identifier = self.service.create_experiment()["experiment_id"]
        result = self.service.close_experiment(identifier)
        self.assertIsNone(result["validated_at"])
        self.assertIsNotNone(result["closed_at"])

    def test_closed_experiment_blocks_every_existing_mutation_path(self):
        request = self.stage()
        self.service.close_experiment(self.lab_id)
        operations = [lambda: self.service.arm(self.lab_id, "snapshot", True, True),
                      lambda: self.service.simulate(self.lab_id, request["request_id"]),
                      lambda: self.service.import_scenario(request),
                      lambda: self.service.monitor(self.lab_id), lambda: self.service.contain(self.lab_id),
                      lambda: self.service.reconcile(self.lab_id), lambda: self.service.preserve(self.lab_id),
                      lambda: self.service.recover(self.lab_id), lambda: self.service.validate_experiment(self.lab_id)]
        before = self.service.report(self.lab_id)["event_count"]
        for operation in operations:
            with self.subTest(operation=operation), self.assertRaisesRegex(StateError, "Closed"):
                operation()
        self.assertEqual(before, self.service.report(self.lab_id)["event_count"])
        self.assertEqual("closed", self.service.list_labs()[0]["state"])

    def test_validation_revokes_unused_arm_and_persists_atomically(self):
        request = self.stage()
        self.service.validate_experiment(self.lab_id)
        with self.assertRaises(SafetyError):
            self.service.simulate(self.lab_id, request["request_id"])
        with self.service._open(self.lab_id, readonly=True) as (_, store, __):
            self.assertIsNone(store.get_state("arm"))
            self.assertEqual("ready", store.get_state("experiment")["state"])

    def test_pending_work_blocks_validation_and_closure(self):
        with self.service._open(self.lab_id, lease=True) as (lab, store, _):
            self.service._event(store, lab, "operation.failed", details={"status": "pending"},
                                updates={"pending": {"operation": "generated-test"}})
        for action in (self.service.validate_experiment, self.service.close_experiment):
            with self.assertRaisesRegex(StateError, "reconcile"):
                action(self.lab_id)

    def test_closure_failure_does_not_revoke_authority_or_mark_closed(self):
        self.stage()
        original = EventStore.append

        def fail_close(store, event, **kwargs):
            if event.kind == "experiment.closed":
                raise StateError("Generated commit failure")
            return original(store, event, **kwargs)

        with patch.object(EventStore, "append", fail_close), self.assertRaises(StateError):
            self.service.close_experiment(self.lab_id)
        self.assertEqual("armed", self.service.status(self.lab_id)["state"])
        self.assertEqual("ready", self.service.inspect_experiment(self.lab_id)["state"])

    def test_damage_requires_recovery_and_evidence_before_closure(self):
        request = self.stage()
        self.service.simulate(self.lab_id, request["request_id"])
        with self.assertRaises(SafetyError):
            self.service.close_experiment(self.lab_id)
        self.service.preserve(self.lab_id)
        self.service.recover(self.lab_id)
        self.assertEqual("closed", self.service.close_experiment(self.lab_id)["state"])

    def test_corrupt_or_missing_lifecycle_fails_closed(self):
        with self.service._open(self.lab_id, lease=True) as (_, store, __):
            original = store.get_state("experiment")
            store._db().execute("UPDATE state SET json=? WHERE key='experiment'", (json.dumps({**original, "schema_version": 99}),))
        with self.assertRaisesRegex(StateError, "lifecycle"):
            self.service.inspect_experiment(self.lab_id)
        with EventStore(self.service.root / self.lab_id / "state.db") as store:
            store._db().execute("DELETE FROM state WHERE key='experiment'")
        with self.assertRaisesRegex(StateError, "missing"):
            self.service.inspect_experiment(self.lab_id)

    def test_legacy_lab_is_read_without_implicit_migration(self):
        with self.service._open(self.lab_id, lease=True) as (_, store, __):
            first = store.events(limit=1)[0].to_dict()
            first["kind"] = "lab.created"
            store._db().execute("UPDATE events SET json=? WHERE seq=1", (Event.from_dict(first).to_json(),))
            store._db().execute("DELETE FROM state WHERE key='experiment'")
            before = store.count()
        self.assertEqual("ready", self.service.inspect_experiment(self.lab_id)["state"])
        with self.service._open(self.lab_id, readonly=True) as (_, store, __):
            self.assertIsNone(store.get_state("experiment"))
            self.assertEqual(before, store.count())
        self.service.validate_experiment(self.lab_id)
        with self.service._open(self.lab_id, readonly=True) as (_, store, __):
            self.assertIsNotNone(store.get_state("experiment"))

    def test_invalid_name_or_foreign_id_has_no_creation_side_effect(self):
        before = self.service.list_labs()
        with self.assertRaises(ValidationError):
            self.service.create_experiment("../private-marker")
        with self.assertRaises(ValidationError):
            self.service.inspect_experiment(str(uuid4()))
        self.assertEqual(before, self.service.list_labs())

    def test_cli_and_dashboard_report_same_closed_experiment(self):
        from ransomlab.dashboard import create_app
        identifier = self.service.create_experiment("Shared service study")["experiment_id"]
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(0, main(["experiment", "close", identifier], self.service))
            closed = json.loads(output.getvalue())
        token = "generated-test-token-0123456789abcdef0123456789"
        app = create_app(self.service, access_token=token)
        app.config["TESTING"] = True
        response = app.test_client().get(f"/api/labs/{identifier}/status", headers={"Authorization": "Bearer " + token})
        self.assertEqual(200, response.status_code)
        self.assertEqual(closed["state"], response.json["state"])
        self.assertEqual(closed["revision"], response.json["experiment"]["revision"])

    def test_partial_creation_is_not_registered_or_resumed(self):
        before = self.service.list_labs()
        original = EventStore.append

        def fail_create(store, event, **kwargs):
            if event.kind == "experiment.created":
                raise StateError("Generated create failure")
            return original(store, event, **kwargs)

        with patch.object(EventStore, "append", fail_create), self.assertRaises(StateError):
            self.service.create_experiment()
        self.assertEqual(before, self.service.list_labs())
        self.assertGreater(len(list(self.service.root.iterdir())), len(before))
        with self.assertRaisesRegex(StateError, "Interrupted experiment preparation"):
            self.service.create_experiment()

    def test_manifest_shape_totals_aliases_and_policy_relaxation_rejected(self):
        with self.service._open(self.lab_id, readonly=True) as (manifest, _, __):
            base = json.loads(json.dumps(manifest))
        variants = [{**base, "schema_version": True}, {**base, "bytes_total": base["bytes_total"] + 1},
                    {**base, "fixture_count": True}, {**base, "extra": "private-marker"}]
        for field, value in (("id", "../private-marker"), ("name", "other.bin"),
                             ("size", True), ("sample_index", -1), ("sha256", "x" * 64),
                             ("identity", base["fixtures"][0]["clean_identity"])):
            altered = json.loads(json.dumps(base))
            altered["fixtures"][0][field] = value
            variants.append(altered)
        for value in variants:
            with self.subTest(value=value), self.assertRaises(SafetyError) as caught:
                validate_manifest(value, self.service.policy)
            self.assertNotIn("private-marker", str(caught.exception))
        tighter = Policy(max_files=10)
        base["policy"] = tighter.to_dict()
        with self.assertRaises(SafetyError):
            validate_manifest(base, Policy())
        validate_manifest(base, tighter)


class LoggingTests(unittest.TestCase):
    def test_formatter_never_echoes_unstructured_messages_or_exception_text(self):
        record = logging.LogRecord("ransomlab.audit", logging.ERROR, __file__, 1, "private-marker", (), None)
        encoded = EventFormatter().format(record)
        self.assertNotIn("private-marker", encoded)
        self.assertIsNone(json.loads(encoded)["event"])

    def test_only_committed_events_are_logged_with_durable_sequence(self):
        with tempfile.TemporaryDirectory() as temporary, EventStore(Path(temporary) / "events.db") as store:
            event = Event.create(str(uuid4()), "experiment.created", details={"state": "draft", "count": 0})
            with self.assertLogs("ransomlab.audit", level="INFO") as captured:
                committed = store.append(event)
                with self.assertRaises(StateError):
                    store.append(event)
            self.assertEqual(1, len(captured.records))
            payload = json.loads(EventFormatter().format(captured.records[0]))
            self.assertEqual(committed.sequence, payload["event"]["sequence"])
            self.assertEqual(1, store.count())


class NativeMetadataTests(unittest.TestCase):
    def test_native_metadata_lifecycle_preserves_generated_outside_decoy(self):
        with tempfile.TemporaryDirectory(prefix="ransomlab-foundation-") as temporary:
            root = Path(temporary)
            try:
                with SafeDirectory(root):
                    pass
            except SafetyError as error:
                if os.name == "nt" and "Windows error 5" in str(error):
                    self.skipTest("BLOCKED: Windows token cannot pin a metadata storage ancestor")
                raise
            decoy = root / "outside-generated-decoy.bin"
            decoy.write_bytes(b"Generated negative-test data")
            before = hash_bytes(decoy.read_bytes())
            service = LabService(root / "generated-experiments")
            draft = service.create_experiment("Native metadata")
            identifier = draft["experiment_id"]
            self.assertEqual("ready", service.validate_experiment(identifier)["state"])
            reopened = LabService(service.root)
            self.assertEqual("closed", reopened.close_experiment(identifier)["state"])
            self.assertEqual([], list((service.root / identifier / "work").iterdir()))
            self.assertEqual(before, hash_bytes(decoy.read_bytes()))
