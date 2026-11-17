"""Shared lab services for the CLI and read-only dashboard.

Every exercise uses an installed fixed scenario and a signed generated inventory.
Filesystem safety is delegated to checked object access, never caller paths.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager, nullcontext
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import shutil
import time
from uuid import uuid4, uuid5, UUID

from . import crypto, environment, research, scenarios, simulation
from .core.config import AppConfig, Policy
from .core.errors import LabError, SafetyError, StateError, ValidationError
from .core.events import Event, utc_now, validate_id
from .core.hashing import hash_bytes
from .core.logging import configure_logging
from .core.models import ExperimentRecord, ExperimentState, validate_label
from .core.repository import EventStore
from .core.safety import validate_manifest
from .storage import LabLease, SafeDirectory

MAX_LABS = 8
MAX_RUNS = 20
MAGIC = b"RANSOMLAB1\x00"
MAX_EVIDENCE_MANIFEST = 262144


def _label(value):
    return validate_label(value)


def _sample(index, size):
    header = f"RansomLab generated fixture v1 | sample {index:03d}\n".encode("ascii")
    block = header + hashlib.sha256(header).digest()
    return (block * (size // len(block) + 1))[:size]


class LabService:
    """Internal root injection is for test harnesses; no user-facing root option."""

    def __init__(self, root=None, policy=None):
        self.root = Path(root) if root is not None else Path(__file__).resolve().parent.parent / ".ransomlab"
        self.root = self.root.absolute()
        if policy is not None and not isinstance(policy, Policy):
            raise ValidationError("Service requires a validated resource policy")
        self.policy = policy if policy is not None else Policy()

    @classmethod
    def default(cls, config: AppConfig | None = None):
        config = config if config is not None else AppConfig.discover()
        configure_logging(config.log_level)
        return cls(policy=config.policy)

    def _initialize(self):
        if self.root.exists():
            with SafeDirectory(self.root) as directory:
                self._catalog(directory)
            return
        with SafeDirectory(self.root, create=True) as directory:
            directory.create("registry.key", secrets.token_bytes(32))
            directory.create("catalog.json", scenarios.canonical({"schema_version": 1, "labs": []}))

    def _catalog(self, root):
        if len(root.read("registry.key", 32)) != 32:
            raise SafetyError("The generated registry is invalid")
        catalog = scenarios.parse_json(root.read("catalog.json", 8192), 8192)
        if (type(catalog) is not dict or set(catalog) != {"schema_version", "labs"}
                or type(catalog["schema_version"]) is not int or catalog["schema_version"] != 1):
            raise SafetyError("The generated registry is invalid")
        if type(catalog["labs"]) is not list or len(catalog["labs"]) > MAX_LABS:
            raise SafetyError("The generated registry exceeds its bounds")
        for lab_id in catalog["labs"]:
            validate_id(lab_id)
        if len(catalog["labs"]) != len(set(catalog["labs"])):
            raise SafetyError("The generated registry contains duplicates")
        return catalog

    def _space(self, extra=0):
        if shutil.disk_usage(self.root).free < self.policy.min_free_bytes + extra:
            raise SafetyError("Insufficient free space for the operation and recovery reserve")

    def _manifest(self, directory, registry):
        signed = scenarios.parse_json(directory.read("manifest.json", 262144), 262144)
        if type(signed) is not dict or set(signed) != {"manifest", "mac"}:
            raise SafetyError("Fixture manifest is invalid")
        expected = hmac.new(registry.read("registry.key", 32), scenarios.canonical(signed["manifest"]), hashlib.sha256).hexdigest()
        if type(signed["mac"]) is not str or not hmac.compare_digest(signed["mac"], expected):
            raise SafetyError("Fixture manifest does not match the local registry")
        return validate_manifest(signed["manifest"], self.policy)

    @contextmanager
    def _open(self, lab_id, *, readonly=False, lease=False, allow_closed=False):
        validate_id(lab_id)
        if not self.root.exists():
            raise StateError("No generated lab registry exists")
        with ExitStack() as stack:
            registry = stack.enter_context(SafeDirectory(self.root))
            if lab_id not in self._catalog(registry)["labs"]:
                raise ValidationError("Lab ID is not registered")
            path = self.root / lab_id
            directory = stack.enter_context(SafeDirectory(path))
            lab = self._manifest(directory, registry)
            if lab["lab_id"] != lab_id:
                raise SafetyError("Manifest lab identity mismatch")
            if lease:
                stack.enter_context(LabLease(path / "lease.flag"))
            for suffix in ("-journal", "-wal", "-shm"):
                if directory.exists("state.db" + suffix):
                    raise StateError("An existing SQLite sidecar requires offline journal review before this lab can open")
            stack.enter_context(directory.pin("state.db"))
            store = stack.enter_context(EventStore(path / "state.db", readonly=readonly, policy=self.policy))
            record = self._experiment_record(lab, store)
            if not readonly and not allow_closed and record.state == ExperimentState.CLOSED:
                raise StateError("Closed experiments are read-only")
            yield lab, store, path

    @staticmethod
    def _experiment_record(lab, store) -> ExperimentRecord:
        digest = hash_bytes(scenarios.canonical(lab))
        raw = store.get_state("experiment")
        if raw is None:
            # Reading legacy journals does not migrate their lifecycle metadata.
            after = 0
            while True:
                events = store.events(limit=1000, after=after)
                if any(event.kind.startswith("experiment.") for event in events):
                    raise StateError("Experiment lifecycle metadata is missing")
                if not events:
                    break
                after = events[-1].sequence
            if lab["generator"] != "fixture-v1":
                raise StateError("Experiment lifecycle metadata is missing")
            return ExperimentRecord(lab["lab_id"], lab["baseline_id"], digest,
                                    ExperimentState.READY, validated_at=lab["created_at"])
        try:
            record = ExperimentRecord.from_dict(raw)
        except ValidationError:
            raise StateError("Stored experiment lifecycle failed validation") from None
        if (record.experiment_id != lab["lab_id"] or record.baseline_id != lab["baseline_id"]
                or record.manifest_sha256 != digest):
            raise SafetyError("Experiment lifecycle belongs to a different generated inventory")
        return record

    def _event(self, store, lab, kind, *, updates=None, expected=None, **values):
        protected = {"file.intent", "file.changed", "file.restored", "run.completed", "run.contained", "run.interrupted",
                     "recovery.started", "recovery.verified", "recovery.failed", "evidence.started", "evidence.preserved", "containment.requested", "experiment.closed",
                     "crypto.completed", "crypto.contained", "crypto.interrupted", "artifact.created", "artifact.area_ready"}
        reserve = len(lab["fixtures"]) * 3 + 16
        if kind not in protected and store.count() + reserve + 1 > self.policy.max_events:
            raise StateError("Audit capacity is reserved for containment, evidence and recovery")
        return store.append(Event.create(lab["lab_id"], kind, **values), updates=updates, expected=expected)

    def create_lab(self, name="Training lab", count=12, size=4096):
        _label(name)
        if type(count) is not int or not 1 <= count <= self.policy.max_files:
            raise ValidationError("Fixture count exceeds the training ceiling")
        if type(size) is not int or not 64 <= size <= self.policy.max_file_bytes or size * count > self.policy.max_total_bytes:
            raise ValidationError("Fixture bytes exceed the training ceiling")
        return self._create(name, count, size)

    def create_experiment(self, name: str = "Research experiment") -> dict:
        """Create an owned metadata-only draft without running a scenario."""
        _label(name)
        created = self._create(name, 0, 0)
        return self.inspect_experiment(created["lab_id"])

    def _create(self, name, count, size):
        self._initialize()
        self._space(size * count * 3 + self.policy.max_evidence_bytes + self.policy.max_database_bytes)
        with LabLease(self.root / "lease.flag"), SafeDirectory(self.root) as registry:
            catalog = self._catalog(registry)
            if registry.exists("creation.json"):
                pending = scenarios.parse_json(registry.read("creation.json", 128), 128)
                if type(pending) is not dict or set(pending) != {"lab_id"}:
                    raise SafetyError("Experiment creation reservation is invalid")
                validate_id(pending["lab_id"])
                if pending["lab_id"] not in catalog["labs"]:
                    raise StateError("Interrupted experiment preparation requires offline review")
            if len(catalog["labs"]) >= MAX_LABS:
                raise SafetyError("The maximum number of disposable labs has been reached")
            lab_id = str(uuid4())
            reservation = scenarios.canonical({"lab_id": lab_id})
            if registry.exists("creation.json"):
                registry.replace("creation.json", reservation, expected=registry.identity("creation.json"))
            else:
                registry.create("creation.json", reservation)
            path = self.root / lab_id
            with ExitStack() as stack:
                directory = stack.enter_context(SafeDirectory(path, create=True))
                work = stack.enter_context(SafeDirectory(path / "work", create=True))
                clean = stack.enter_context(SafeDirectory(path / "clean", create=True))
                stack.enter_context(SafeDirectory(path / "keys", create=True))
                stack.enter_context(SafeDirectory(path / "evidence", create=True))
                stack.enter_context(SafeDirectory(path / "artifacts", create=True))
                fixtures = []
                for index in range(count):
                    fixture_id = str(uuid4())
                    filename = f"fixture-{fixture_id}.bin"
                    data = _sample(index, size)
                    clean_identity = clean.create(filename, data)
                    identity = work.create(filename, data)
                    digest = hash_bytes(data)
                    if hash_bytes(clean.read(filename, size)) != digest:
                        raise SafetyError("Generated recovery copy did not verify")
                    fixtures.append({"id": fixture_id, "name": filename, "size": size, "sha256": digest,
                                     "identity": identity, "clean_identity": clean_identity, "sample_index": index})
                lab = {"schema_version": 1, "lab_id": lab_id, "baseline_id": str(uuid4()), "name": name,
                       "created_at": utc_now(), "generator": "fixture-v1" if count else "empty-v1", "fixtures": fixtures,
                       "policy": self.policy.to_dict(), "fixture_count": count, "bytes_total": count * size}
                validate_manifest(lab, self.policy)
                record = ExperimentRecord(lab_id, lab["baseline_id"], hash_bytes(scenarios.canonical(lab)),
                                          ExperimentState.READY if count else ExperimentState.DRAFT,
                                          validated_at=lab["created_at"] if count else None)
                mac = hmac.new(registry.read("registry.key", 32), scenarios.canonical(lab), hashlib.sha256).hexdigest()
                directory.create("manifest.json", scenarios.canonical({"manifest": lab, "mac": mac}))
                with EventStore(path / "state.db", policy=self.policy) as store:
                    self._event(store, lab, "experiment.created", details={"count": count, "bytes": count * size, "generator": lab["generator"], "state": record.state.value},
                                updates={"requests": [], "runs": [], "alerts": [], "evidence": [], "recovery": None,
                                         "arm": None, "pending": None, "active_run": None, "stop_requested": False,
                                         "experiment": record.to_dict()})
                catalog["labs"].append(lab_id)
                registry.replace("catalog.json", scenarios.canonical(catalog), expected=registry.identity("catalog.json"))
        return self.status(lab_id)

    def list_labs(self):
        if not self.root.exists():
            return []
        with SafeDirectory(self.root) as registry:
            ids = self._catalog(registry)["labs"]
        result = []
        for lab_id in ids:
            with self._open(lab_id, readonly=True) as (lab, store, path):
                run_id = store.get_state("active_run")
                run = store.get_state("run:" + run_id) if run_id else None
                recovery = store.get_state("recovery")
                state = self._state(store, run, recovery)
                if state != "closed" and recovery and recovery.get("verified") and any(item["status"] != "intact" for item in self._snapshot(lab, path)):
                    state = "verification_lost"
                result.append({"lab_id": lab_id, "name": lab["name"], "fixture_count": lab["fixture_count"],
                               "bytes_total": lab["bytes_total"], "created_at": lab["created_at"],
                               "state": state, "alerts": len(store.get_state("alerts", []))})
        return result

    @staticmethod
    def _state(store, run, recovery):
        record = store.get_state("experiment")
        if record and record["state"] in {"closed", "draft"}:
            return record["state"]
        if store.get_state("pending"):
            return "reconciliation_required"
        if store.get_state("active_study"):
            return "crypto_running"
        if store.get_state("arm"):
            return "armed"
        if run and recovery and recovery.get("run_id") == run["run_id"] and recovery.get("verified"):
            return "verified"
        if run and recovery and recovery.get("run_id") == run["run_id"] and recovery.get("state") in {"failed", "recovering"}:
            return "recovery_failed" if recovery["state"] == "failed" else "recovering"
        if run:
            return run["state"]
        return "prepared"

    def _snapshot(self, lab, path):
        result = []
        with SafeDirectory(path / "work") as work:
            expected_names = {item["name"] for item in lab["fixtures"]}
            names = set(work.names())
            if names - expected_names:
                raise SafetyError("Unregistered objects exist in the fixture area")
            for fixture in lab["fixtures"]:
                item = {k: fixture[k] for k in ("id", "name", "size", "sha256")}
                if fixture["name"] not in names:
                    item.update(current_sha256=None, status="missing")
                else:
                    if work.identity(fixture["name"]) != fixture["identity"]:
                        raise SafetyError("Generated fixture object identity has changed")
                    data = work.read(fixture["name"], self.policy.max_file_bytes + 64)
                    actual = hash_bytes(data)
                    item.update(current_sha256=actual, status="intact" if actual == fixture["sha256"] else "changed")
                result.append(item)
        return result

    def status(self, lab_id):
        with self._open(lab_id, readonly=True) as (lab, store, path):
            run_id = store.get_state("active_run")
            run = store.get_state("run:" + run_id) if run_id else None
            recovery = store.get_state("recovery")
            total = store.count()
            result = {"schema_version": 1, "lab_id": lab_id, "name": lab["name"], "created_at": lab["created_at"],
                    "state": self._state(store, run, recovery), "fixture_count": lab["fixture_count"], "bytes_total": lab["bytes_total"],
                    "experiment": self._experiment_record(lab, store).to_dict(),
                    "last_run": run, "recovery": recovery, "alerts": store.get_state("alerts", []),
                    "active_study": store.get_state("active_study"),
                    "events": [event.to_dict() for event in store.events(limit=200, after=max(0, total - 200))],
                    "event_count": total, "fixtures": self._snapshot(lab, path),
                    "machines": [{"name": "Windows 11", "role": "Fixture execution and defence", "status": "declared"},
                                 {"name": "Kali Linux", "role": "Scenario preparation and analysis", "status": "declared"},
                                 {"name": "Windows 10", "role": "Optional forensic workstation", "status": "optional"}],
                    "limitations": ["Machine roles are declared inventory, not live network probes.",
                                    "Run state is the last durable observation; crashes require explicit reconciliation."]}
            if recovery:
                current_verified = bool(recovery.get("verified") and all(item["status"] == "intact" for item in result["fixtures"]))
                result["recovery"] = {**recovery, "historical_verified": bool(recovery.get("verified")), "verified": current_verified}
                if recovery.get("verified") and not current_verified:
                    result["recovery"]["state"] = "verification_lost"
                    if result["state"] != "closed":
                        result["state"] = "verification_lost"
            return result

    def inspect_experiment(self, experiment_id: str) -> dict:
        snapshot = self.status(experiment_id)
        return {**snapshot["experiment"], "name": snapshot["name"], "created_at": snapshot["created_at"],
                "execution_state": snapshot["state"], "fixture_count": snapshot["fixture_count"],
                "bytes_total": snapshot["bytes_total"], "event_count": snapshot["event_count"]}

    def list_experiments(self) -> list[dict]:
        return [self.inspect_experiment(item["lab_id"]) for item in self.list_labs()]

    @staticmethod
    def _require_idle(store) -> None:
        run_id = store.get_state("active_run")
        run = store.get_state("run:" + run_id) if run_id else None
        recovery = store.get_state("recovery")
        if (store.get_state("pending") or store.get_state("active_study") or run and run["state"] == "running"
                or recovery and recovery.get("state") == "recovering"):
            raise StateError("Contain or reconcile active work before changing the experiment lifecycle")

    def validate_experiment(self, experiment_id: str) -> dict:
        with self._open(experiment_id, lease=True) as (lab, store, path):
            self._require_idle(store)
            self._verify_baseline(lab, path)
            record = self._experiment_record(lab, store).validate()
            self._event(store, lab, "experiment.validated", source="operator",
                        details={"state": record.state.value, "count": len(lab["fixtures"]), "sha256": record.manifest_sha256},
                        updates={"experiment": record.to_dict(), "arm": None},
                        expected={"experiment": store.get_state("experiment"), "arm": store.get_state("arm")})
        return self.inspect_experiment(experiment_id)

    def close_experiment(self, experiment_id: str) -> dict:
        with self._open(experiment_id, lease=True, allow_closed=True) as (lab, store, path):
            record = self._experiment_record(lab, store)
            if record.state != ExperimentState.CLOSED:
                self._require_idle(store)
                # Keep closure conservative: damage must be recovered before freezing history.
                self._verify_baseline(lab, path)
                run_id = store.get_state("active_run")
                if run_id:
                    evidence = [item for item in store.get_state("evidence", []) if item["run_id"] == run_id and item["state"] == "complete"]
                    if not evidence:
                        raise StateError("Preserve evidence before closing a completed run")
                    self._verify_evidence(path, evidence[-1])
                closed = record.close()
                self._event(store, lab, "experiment.closed", source="operator",
                            details={"state": "closed", "status": "baseline_verified", "count": len(lab["fixtures"])},
                            updates={"experiment": closed.to_dict(), "arm": None, "stop_requested": True},
                            expected={"experiment": store.get_state("experiment"), "arm": store.get_state("arm")})
        return self.inspect_experiment(experiment_id)

    def descriptor(self, lab_id):
        with self._open(lab_id, readonly=True) as (lab, _, __):
            return {"schema_version": 1, "lab_id": lab_id, "baseline_id": lab["baseline_id"],
                    "fixtures": [{"id": item["id"]} for item in lab["fixtures"]]}

    def create_scenario(self, lab_id, scenario, count=None, **configuration):
        with self._open(lab_id, readonly=True) as (lab, _, __):
            return scenarios.create(lab, scenario, count, **configuration)

    def replay_scenario(self, lab_id, request_id):
        validate_id(request_id)
        with self._open(lab_id, readonly=True) as (lab, store, _):
            request = store.get_state("request:" + request_id)
            if not request or hash_bytes(scenarios.canonical(request["envelope"])) != request["digest"]:
                raise ValidationError("A verified imported scenario request is required for replay")
            return scenarios.replay(request["envelope"], lab)

    def run_history(self, lab_id):
        with self._open(lab_id, readonly=True) as (_, store, __):
            return [store.get_state("run:" + run_id) for run_id in store.get_state("runs", [])]

    def import_scenario(self, envelope):
        if type(envelope) is not dict:
            raise ValidationError("A scenario object is required")
        lab_id = validate_id(envelope.get("lab_id"))
        with self._open(lab_id, lease=True) as (lab, store, _):
            scenarios.validate(envelope, lab)
            parent_id = envelope.get("replay_of")
            if parent_id:
                parent = store.get_state("request:" + parent_id)
                if (not parent or hash_bytes(scenarios.canonical(parent["envelope"])) != parent["digest"]
                        or scenarios.plan_digest(parent["envelope"]) != scenarios.plan_digest(envelope)):
                    raise ValidationError("Replay lineage must reference the same verified imported plan")
            request_id = envelope["request_id"]
            digest = hash_bytes(scenarios.canonical(envelope))
            existing = store.get_state("request:" + request_id)
            if existing:
                if existing["digest"] != digest:
                    raise SafetyError("Request ID was reused with different content")
                return {"request_id": request_id, "status": existing["status"], "duplicate": True}
            ids = store.get_state("requests", [])
            if len(ids) >= MAX_RUNS:
                raise SafetyError("Scenario retention ceiling reached for this disposable lab")
            ids.append(request_id)
            request = {"envelope": envelope, "digest": digest, "status": "staged"}
            self._event(store, lab, "scenario.imported", source="operator", details={"scenario": envelope["scenario"], "request_id": request_id,
                        "count": len(envelope["fixture_ids"]), "status": "staged"}, updates={"requests": ids, "request:" + request_id: request})
            return {"request_id": request_id, "status": "staged", "duplicate": False}

    def arm(self, lab_id, snapshot, isolated, disposable):
        attestation = environment.validate_attestation(snapshot, isolated, disposable)
        with self._open(lab_id, lease=True) as (lab, store, path):
            stop_before = store.get_state("stop_requested")
            self._ready(lab, store, path)
            arm = {"baseline_id": lab["baseline_id"], "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
                   "attestation": attestation}
            self._event(store, lab, "run.armed", source="operator", details={"state": "armed", "count": len(lab["fixtures"])}, updates={"arm": arm, "stop_requested": False}, expected={"stop_requested": stop_before})
            return {"lab_id": lab_id, "state": "armed", "expires_at": arm["expires_at"]}

    def _ready(self, lab, store, path):
        self._require_idle(store)
        record = self._experiment_record(lab, store)
        if record.state != ExperimentState.READY or not lab["fixtures"]:
            raise StateError("A validated experiment with generated fixtures is required")
        if store.get_state("pending"):
            raise StateError("An uncertain operation requires reconciliation")
        run_id = store.get_state("active_run")
        if run_id:
            recovery = store.get_state("recovery")
            if not recovery or not recovery.get("verified") or recovery.get("run_id") != run_id:
                raise StateError("The previous run must be recovered and verified first")
        self._verify_baseline(lab, path)

    def _verify_baseline(self, lab, path):
        self._space(self.policy.max_total_bytes * 2)
        if any(item["status"] != "intact" for item in self._snapshot(lab, path)):
            raise SafetyError("Working fixtures do not match their generated baseline")
        with SafeDirectory(path / "clean") as clean:
            if set(clean.names()) != {fixture["name"] for fixture in lab["fixtures"]}:
                raise SafetyError("Clean-copy inventory differs from the generated baseline")
            for fixture in lab["fixtures"]:
                if clean.identity(fixture["name"]) != fixture["clean_identity"] or hash_bytes(clean.read(fixture["name"], fixture["size"])) != fixture["sha256"]:
                    raise SafetyError("A clean recovery copy failed verification")

    def crypto_study(self, lab_id: str, count: int = 3, repetitions: int = 3,
                     sizes: tuple[int, ...] = ()) -> dict:
        """Measure RAM copies of registered fixtures using one locally armed session."""
        plan = research.StudyPlan(count, repetitions, sizes)
        with self._open(lab_id, lease=True) as (lab, store, path):
            self._ready(lab, store, path)
            if count > len(lab["fixtures"]) or plan.sample_count > self.policy.max_actions:
                raise ValidationError("Study exceeds the available fixtures or action ceiling")
            fixtures = lab["fixtures"][:count]
            if sizes and any(sizes[-1] > item["size"] for item in fixtures):
                raise ValidationError("Study payload sizes must fit every selected generated fixture")
            studies = store.get_state("studies", [])
            if len(studies) >= MAX_RUNS:
                raise SafetyError("Cryptography study retention ceiling reached")
            if store.count() + plan.sample_count + len(lab["fixtures"]) * 3 + 50 > self.policy.max_events:
                raise SafetyError("Insufficient audit capacity for the study and recovery reserve")
            arm = store.get_state("arm")
            if not arm or arm["baseline_id"] != lab["baseline_id"] or datetime.fromisoformat(arm["expires_at"]) <= datetime.now(timezone.utc):
                raise SafetyError("A current locally armed session is required")
            environment.require_guest(arm["attestation"])
            provider = research.providers()
            study_id = str(uuid4())
            study = {"schema_version": 1, "study_id": study_id, "lab_id": lab_id,
                     "baseline_id": lab["baseline_id"], "generator": lab["generator"],
                     "state": "running", "started_at": utc_now(), "ended_at": None,
                     "providers": provider, "attestation": arm["attestation"],
                     "policy": self.policy.to_dict(),
                     "configuration": {"fixture_ids": [item["id"] for item in fixtures],
                                       "repetitions": repetitions, "sizes": list(sizes),
                                       "planned_samples": plan.sample_count},
                     "public_keys": None, "samples": [], "summary": research.summarize([])}
            self._event(store, lab, "crypto.started", source="operator", outcome="pending",
                        details={"study_id": study_id, "count": plan.sample_count, "state": "running"},
                        updates={"study:" + study_id: study, "studies": studies + [study_id],
                                 "active_study": study_id, "arm": None},
                        expected={"arm": arm, "stop_requested": False, "active_study": None})
            started = time.monotonic()

            def checkpoint():
                if store.get_state("stop_requested"):
                    raise research.StudyStopped("operator_requested")
                if time.monotonic() - started >= self.policy.max_run_seconds:
                    raise research.StudyStopped("deadline_reached")

            session = None
            try:
                session = research.CryptoSession(checkpoint)
                study["public_keys"] = session.public
                self._event(store, lab, "crypto.keys_ready", details={"study_id": study_id, "state": "running"},
                            updates={"study:" + study_id: study}, expected={"stop_requested": False})
                with SafeDirectory(path / "work") as work:
                    for fixture in fixtures:
                        for size in sizes or (fixture["size"],):
                            for repetition in range(1, repetitions + 1):
                                checkpoint()
                                if work.identity(fixture["name"]) != fixture["identity"]:
                                    raise SafetyError("Generated fixture object identity has changed")
                                data = work.read(fixture["name"], fixture["size"])
                                if hash_bytes(data) != fixture["sha256"]:
                                    raise SafetyError("Study fixture no longer matches its baseline")
                                payload = data[:size]
                                context = {"schema_version": 1, "lab_id": lab_id, "baseline_id": lab["baseline_id"],
                                           "study_id": study_id, "fixture_id": fixture["id"],
                                           "repetition": repetition, "plaintext_bytes": size,
                                           "baseline_sha256": fixture["sha256"], "plaintext_sha256": hash_bytes(payload)}
                                sample = session.sample(payload, scenarios.canonical(context))
                                sample["signed_context"] = context
                                candidate = {**study, "samples": study["samples"] + [sample]}
                                candidate["summary"] = research.summarize(candidate["samples"])
                                checkpoint()
                                self._event(store, lab, "crypto.sample", fixture_id=fixture["id"],
                                            details={"study_id": study_id, "count": len(candidate["samples"]),
                                                     "bytes": size, "sha256": hash_bytes(scenarios.canonical(sample))},
                                            updates={"study:" + study_id: candidate}, expected={"stop_requested": False})
                                study = candidate
                self._verify_baseline(lab, path)
                checkpoint()
                return self._finish_study(lab, store, study_id, "completed")
            except research.StudyStopped as exc:
                return self._finish_study(lab, store, study_id, "contained", str(exc))
            except (Exception, KeyboardInterrupt) as exc:
                if isinstance(exc, StateError) and store.get_state("stop_requested"):
                    return self._finish_study(lab, store, study_id, "contained", "operator_requested")
                # Reload committed samples: a failed sample transaction is never a result.
                try:
                    self._finish_study(lab, store, study_id, "interrupted", "operation_failed")
                except (LabError, OSError):
                    pass
                raise
            finally:
                if session is not None:
                    session.close()
                session = None

    def _finish_study(self, lab, store, study_id, state, reason=None):
        study = store.get_state("study:" + study_id)
        study.update(state=state, ended_at=utc_now())
        details = {"study_id": study_id, "count": len(study["samples"]), "state": state}
        if reason:
            study["reason"] = reason
            details["reason"] = reason
        self._event(store, lab, "crypto." + state,
                    outcome="success" if state == "completed" else "partial" if state == "contained" else "unknown",
                    details=details, updates={"study:" + study_id: study, "active_study": None},
                    expected={"active_study": study_id, **({"stop_requested": False} if state == "completed" else {})})
        return study

    def crypto_studies(self, lab_id: str) -> list[dict]:
        with self._open(lab_id, readonly=True) as (_, store, __):
            return [store.get_state("study:" + study_id) for study_id in store.get_state("studies", [])]

    def simulate(self, lab_id, request_id):
        validate_id(request_id)
        with self._open(lab_id, lease=True) as (lab, store, path):
            request = store.get_state("request:" + request_id)
            if not request:
                raise ValidationError("Scenario request is not staged")
            if request["status"] != "staged":
                return {"request_id": request_id, "status": request["status"], "duplicate": True}
            if hash_bytes(scenarios.canonical(request["envelope"])) != request["digest"]:
                raise SafetyError("Staged scenario content changed after import")
            envelope = scenarios.validate(request["envelope"], lab)
            self._ready(lab, store, path)
            arm = store.get_state("arm")
            if not arm or arm["baseline_id"] != lab["baseline_id"] or datetime.fromisoformat(arm["expires_at"]) <= datetime.now(timezone.utc):
                raise SafetyError("A current locally armed session is required")
            environment.require_guest(arm["attestation"])
            ids = envelope["fixture_ids"]
            config = scenarios.configuration(envelope)
            actions = scenarios.action_count(envelope)
            if (actions > self.policy.max_actions or actions * config["interval_ms"] > self.policy.max_run_seconds * 1000
                    or store.count() + actions * 5 + len(lab["fixtures"]) * 3 + 50 > self.policy.max_events):
                raise SafetyError("Insufficient action or audit capacity including recovery reserve")
            runs = store.get_state("runs", [])
            if len(runs) >= MAX_RUNS:
                raise SafetyError("Run retention ceiling reached")
            scenario = envelope["scenario"]
            if scenario == "encrypt_generated":
                crypto.provider_name()
            run_id = str(uuid4())
            run = {"run_id": run_id, "request_id": request_id, "scenario": scenario, "state": "running", "started_at": utc_now(),
                   "ended_at": None, "affected": [], "attestation": arm["attestation"], "lab_id": lab_id,
                   "baseline_id": lab["baseline_id"], "generator": lab["generator"], "policy": self.policy.to_dict(),
                   "scenario_version": envelope.get("scenario_version", 1), "configuration": config,
                   "fixture_ids": list(ids), "plan_sha256": scenarios.plan_digest(envelope),
                   "replay_of": envelope.get("replay_of"), "planned_actions": actions,
                   "discovered": [], "artifacts": [], "artifacts_initialized": False}
            bundle = scenario in scenarios.MULTISTAGE
            reservation = {}
            if bundle:
                with SafeDirectory(path / "artifacts"):
                    pass
                fixtures = {item["id"]: item for item in lab["fixtures"]}
                artifact_bytes = (sum(fixtures[item]["size"] for item in ids[:config["stage_count"]])
                                  + sum(fixtures[item]["size"] for item in ids[:config["receive_count"]])
                                  + (len(simulation.note(lab_id, run_id)) if scenario == "double_extortion_generated" else 0))
                artifact_count = config["stage_count"] + config["receive_count"] + (1 if scenario == "double_extortion_generated" else 0)
                reserved_bytes = store.get_state("artifact_reserved_bytes", 0) + artifact_bytes
                reserved_files = store.get_state("artifact_reserved_files", 0) + artifact_count
                if reserved_bytes > self.policy.max_total_bytes * 2 or reserved_files > self.policy.max_files * 2 + MAX_RUNS:
                    raise SafetyError("Generated staging and mock receipt retention ceiling reached")
                evidence_required = (sum(item["size"] + 64 for item in lab["fixtures"]) + artifact_bytes
                                     + len(scenarios.canonical(self._all_events(store)))
                                     + actions * 5 * self.policy.max_event_bytes + MAX_EVIDENCE_MANIFEST)
                if sum(item["bytes"] for item in store.get_state("evidence", [])) + evidence_required > self.policy.max_evidence_bytes:
                    raise SafetyError("Insufficient evidence retention capacity for the planned scenario")
                self._space(artifact_bytes + self.policy.max_evidence_bytes)
                reservation = {"artifact_reserved_bytes": reserved_bytes, "artifact_reserved_files": reserved_files,
                               "pending": {"kind": "artifact_area", "run_id": run_id}}
                run["artifact_reservation"] = {"bytes": artifact_bytes, "files": artifact_count}
            request["status"] = "consumed"
            runs.append(run_id)
            self._event(store, lab, "run.started", source="simulator", run_id=run_id, details={"scenario": scenario, "request_id": request_id, "count": len(ids), "action_count": actions, "sha256": run["plan_sha256"], "state": "running"},
                        updates={"active_run": run_id, "run:" + run_id: run, "request:" + request_id: request, "runs": runs,
                                 "arm": None, "recovery": None, **reservation}, expected={"arm": arm, "stop_requested": False})
            key = secrets.token_bytes(32) if scenario == "encrypt_generated" else None
            nonce_prefix = secrets.token_bytes(4)
            started = time.monotonic()

            def checkpoint():
                if store.get_state("stop_requested"):
                    raise simulation.SimulationStopped("operator_requested")
                if time.monotonic() - started >= self.policy.max_run_seconds:
                    raise simulation.SimulationStopped("deadline_reached")

            try:
                if key:
                    self._event(store, lab, "key.created", run_id=run_id, outcome="pending", details={"operation": "create_run_key"})
                    with SafeDirectory(path / "keys") as keys:
                        keys.create(f"run-{run_id}.key", key)
                with SafeDirectory(path / "work") as work:
                    fixtures = {item["id"]: item for item in lab["fixtures"]}

                    def read_fixture(fixture):
                        if work.identity(fixture["name"]) != fixture["identity"]:
                            raise SafetyError("Generated fixture object identity changed")
                        data = work.read(fixture["name"], fixture["size"])
                        if hash_bytes(data) != fixture["sha256"]:
                            raise SafetyError("Fixture changed since preparation")
                        return data

                    def impact(fixture, number=0):
                        checkpoint()
                        self._space(self.policy.max_file_bytes * 2)
                        before = read_fixture(fixture)
                        if key:
                            nonce = nonce_prefix + number.to_bytes(8, "big")
                            after = MAGIC + nonce + crypto.encrypt(before, key, nonce, self._aad(lab, run, fixture))
                        else:
                            marker = b"RANSOMLAB SIMULATED CHANGE\n"
                            after = marker + before[len(marker):]
                        checkpoint()
                        self._mutate(store, lab, work, fixture, before, after, run_id, scenario, run=run)
                        self._scan(lab, store, path, run_id, updates={"run:" + run_id: run})

                    if bundle:
                        # The admitted start is also the durable intent for exclusive area creation.
                        with SafeDirectory(path / "artifacts" / run_id, create=True) as artifacts:
                            run["artifacts_initialized"] = True
                            self._event(store, lab, "artifact.area_ready", source="simulator", run_id=run_id,
                                        details={"state": "ready"}, updates={"pending": None, "run:" + run_id: run})

                            def emit(kind, **kwargs):
                                return self._event(store, lab, kind, source="simulator", run_id=run_id, **kwargs)

                            def write_artifact(kind, fixture, data):
                                checkpoint()
                                self._write_artifact(lab, store, path, run, artifacts, kind, fixture, data)

                            def read_staged(fixture):
                                self._artifact_snapshot(lab, path, run)
                                return artifacts.read("stage-" + fixture["id"] + ".bin", fixture["size"])

                            simulation.BehaviourRunner([fixtures[item] for item in ids], run, config, read_fixture,
                                                      write_artifact, read_staged, impact, emit, checkpoint).execute()
                    else:
                        for number, fixture_id in enumerate(ids):
                            if number:
                                simulation.pace(config["interval_ms"], checkpoint)
                            impact(fixtures[fixture_id], number)
                checkpoint()
                self._finish_run(lab, store, run_id, "completed")
            except simulation.SimulationStopped as exc:
                self._finish_run(lab, store, run_id, "contained", str(exc))
            except (LabError, OSError, KeyboardInterrupt) as exc:
                if isinstance(exc, StateError) and store.get_state("stop_requested") and not store.get_state("pending"):
                    return self._finish_run(lab, store, run_id, "contained", "operator_requested")
                # A failed journal leaves the last durable intent for reconciliation.
                try:
                    self._finish_run(lab, store, run_id, "interrupted", "operation_failed")
                except LabError:
                    pass
                raise
            finally:
                key = None
            return store.get_state("run:" + run_id)

    def _finish_run(self, lab, store, run_id, state, reason=None):
        run = store.get_state("run:" + run_id)
        run.update(state=state, ended_at=utc_now())
        details = {"state": state, "count": len(run["affected"])}
        if reason:
            run["reason"] = reason
            details["reason"] = reason
        self._event(store, lab, "run." + state, source="simulator", run_id=run_id,
                    outcome="success" if state == "completed" else "partial" if state == "contained" else "unknown",
                    details=details, updates={"run:" + run_id: run},
                    expected={"stop_requested": False} if state == "completed" else None)
        return run

    @staticmethod
    def _artifact_name(kind, fixture_id=None):
        if kind == "note" and fixture_id is None:
            return "simulation-note.txt"
        if kind not in {"staged", "received"}:
            raise SafetyError("Unsupported generated artifact purpose")
        validate_id(fixture_id)
        return ("stage-" if kind == "staged" else "mock-") + fixture_id + ".bin"

    def _artifact_snapshot(self, lab, path, run, pending=None):
        if not run:
            return []
        records = run.get("artifacts", [])
        if not run.get("artifacts_initialized"):
            if records or pending:
                raise SafetyError("Artifact records require a verified generated area")
            return []
        names = set()
        with SafeDirectory(path / "artifacts" / validate_id(run["run_id"])) as directory:
            for item in records:
                expected_name = self._validate_artifact(lab, run, item)
                if expected_name != item["name"] or expected_name in names:
                    raise SafetyError("Generated artifact inventory is invalid")
                names.add(expected_name)
                if directory.identity(item["name"]) != item["identity"]:
                    raise SafetyError("Generated artifact object identity changed")
                data = directory.read(item["name"], item["size"])
                if (len(data) != item["size"] or hash_bytes(data) != item["sha256"]
                        or directory.identity(item["name"]) != item["identity"]):
                    raise SafetyError("Generated artifact hash verification failed")
            if pending:
                record = pending["record"]
                if record["name"] != self._validate_artifact(lab, run, record):
                    raise SafetyError("Pending artifact name is outside its generated purpose")
                names.add(record["name"])
            if set(directory.names()) - names or not {item["name"] for item in records} <= set(directory.names()):
                raise SafetyError("Unexpected objects exist in the generated artifact area")
        return list(records)

    def _validate_artifact(self, lab, run, item):
        name = self._artifact_name(item["kind"], item["fixture_id"])
        if run.get("lab_id") != lab["lab_id"] or run.get("baseline_id") != lab["baseline_id"]:
            raise SafetyError("Artifact area belongs to a different experiment generation")
        if item["kind"] == "note":
            if run["scenario"] != "double_extortion_generated":
                raise SafetyError("This scenario cannot create a simulation note")
            data = simulation.note(lab["lab_id"], run["run_id"])
            digest, size = hash_bytes(data), len(data)
        else:
            count = run["configuration"]["stage_count" if item["kind"] == "staged" else "receive_count"]
            if item["fixture_id"] not in run["fixture_ids"][:count]:
                raise SafetyError("Artifact source is outside the admitted copy selection")
            fixture = next((row for row in lab["fixtures"] if row["id"] == item["fixture_id"]), None)
            if fixture is None:
                raise SafetyError("Artifact source is not a generated fixture")
            digest, size = fixture["sha256"], fixture["size"]
        if item["name"] != name or item["sha256"] != digest or type(item["size"]) is not int or item["size"] != size:
            raise SafetyError("Artifact provenance differs from its generated source")
        return name

    def _write_artifact(self, lab, store, path, run, directory, kind, fixture, data):
        self._artifact_snapshot(lab, path, run)
        self._space(len(data) * 2)
        record = {"kind": kind, "fixture_id": fixture["id"] if fixture else None,
                  "name": self._artifact_name(kind, fixture["id"] if fixture else None),
                  "size": len(data), "sha256": hash_bytes(data)}
        self._validate_artifact(lab, run, record)
        pending = {"kind": "artifact", "run_id": run["run_id"], "record": record}
        self._event(store, lab, "artifact.intent", source="simulator", run_id=run["run_id"],
                    fixture_id=record["fixture_id"], outcome="pending",
                    details={"operation": kind, "bytes": len(data), "sha256": record["sha256"]},
                    updates={"pending": pending}, expected={"stop_requested": False})
        identity = directory.create(record["name"], data)
        if (hash_bytes(directory.read(record["name"], len(data))) != record["sha256"]
                or directory.identity(record["name"]) != identity):
            raise SafetyError("Generated artifact write did not verify")
        completed = {**record, "identity": identity}
        candidate = {**run, "artifacts": run["artifacts"] + [completed]}
        self._event(store, lab, "artifact.created", source="simulator", run_id=run["run_id"], fixture_id=record["fixture_id"],
                    details={"operation": kind, "bytes": len(data), "sha256": record["sha256"]},
                    updates={"pending": None, "run:" + run["run_id"]: candidate})
        run.update(candidate)

    @staticmethod
    def _aad(lab, run, fixture):
        return scenarios.canonical({"version": 1, "lab_id": lab["lab_id"], "run_id": run["run_id"],
                                    "fixture_id": fixture["id"], "baseline_sha256": fixture["sha256"]})

    def _mutate(self, store, lab, work, fixture, before, after, run_id, operation, *, recovery=False, run=None):
        pending = {"fixture_id": fixture["id"], "run_id": run_id, "operation": operation,
                   "before_sha256": hash_bytes(before), "after_sha256": hash_bytes(after)}
        self._event(store, lab, "file.intent", source="response" if recovery else "simulator", outcome="pending", run_id=run_id,
                    fixture_id=fixture["id"], details={"operation": operation, "before_sha256": pending["before_sha256"], "after_sha256": pending["after_sha256"]},
                    updates={"pending": pending})
        work.replace(fixture["name"], after, expected=fixture["identity"])
        if hash_bytes(work.read(fixture["name"], self.policy.max_file_bytes + 64)) != pending["after_sha256"]:
            raise SafetyError("Post-write verification failed")
        updates = {"pending": None}
        if run is not None:
            candidate = {**run, "affected": run["affected"] + [fixture["id"]]}
            updates["run:" + run_id] = candidate
        self._event(store, lab, "file.restored" if recovery else "file.changed", source="response" if recovery else "simulator", run_id=run_id, fixture_id=fixture["id"],
                    details={"before_sha256": pending["before_sha256"], "after_sha256": pending["after_sha256"], "bytes": len(after)}, updates=updates)
        if run is not None:
            run.update(candidate)

    def _scan(self, lab, store, path, run_id=None, updates=None):
        observations = self._snapshot(lab, path)
        previous = store.get_state("observations", {})
        new = {item["id"]: item["current_sha256"] for item in observations}
        for item in observations:
            old = previous.get(item["id"], item["sha256"])
            if old != item["current_sha256"]:
                details = {"status": item["status"], "baseline_sha256": item["sha256"]}
                if item["current_sha256"]:
                    details["sha256"] = item["current_sha256"]
                self._event(store, lab, "file.observed", source="monitor", outcome="detected", run_id=run_id, fixture_id=item["id"], details=details)
        changed = sum(item["status"] == "changed" for item in observations)
        missing = sum(item["status"] == "missing" for item in observations)
        alerts = store.get_state("alerts", [])
        rule = "burst_integrity_change" if changed + missing >= 3 else "integrity_change"
        if changed or missing:
            identity = str(uuid5(UUID(lab["lab_id"]), str(run_id) + rule))
            if not any(item["id"] == identity for item in alerts):
                alert = {"id": identity, "incident_id": str(uuid5(UUID(lab["lab_id"]), str(run_id) + "incident")),
                         "rule": rule, "severity": "high" if changed + missing >= 3 else "warning",
                         "created_at": utc_now(), "run_id": run_id, "changed": changed, "missing": missing,
                         "summary": "Registered fixture content differs from the trusted baseline", "status": "open"}
                alerts.append(alert)
                self._event(store, lab, "alert.raised", source="monitor", severity=alert["severity"], outcome="detected", run_id=run_id,
                            details={"rule": rule, "changed": changed, "missing": missing}, updates={"alerts": alerts})
        if previous != new or updates:
            self._event(store, lab, "file.observed", source="monitor", run_id=run_id, details={"operation": "scan_complete", "status": "changed" if changed or missing else "intact"},
                        updates={"observations": new, **(updates or {})})
        return {"changed": changed, "missing": missing, "intact": len(observations) - changed - missing, "alerts": alerts}

    def monitor(self, lab_id):
        with self._open(lab_id, lease=True) as (lab, store, path):
            return self._scan(lab, store, path, store.get_state("active_run"))

    def contain(self, lab_id):
        # This control intentionally does not take the mutation lease: it signals its owner.
        with self._open(lab_id) as (lab, store, _):
            run_id = store.get_state("active_run")
            if not store.get_state("stop_requested") or store.get_state("arm"):
                self._event(store, lab, "containment.requested", source="operator", outcome="requested", run_id=run_id,
                            details={"reason": "operator_requested", "state": "stop_requested"}, updates={"stop_requested": True, "arm": None})
            return {"lab_id": lab_id, "state": "stop_requested", "note": "The coordinator acknowledges containment after the current bounded operation."}

    def reconcile(self, lab_id):
        with self._open(lab_id, lease=True) as (lab, store, path):
            study_id = store.get_state("active_study")
            if study_id:
                return self._finish_study(lab, store, study_id, "interrupted", "worker_ended")
            pending = store.get_state("pending")
            run_id = store.get_state("active_run")
            run = store.get_state("run:" + run_id) if run_id else None
            if pending and pending.get("kind") in {"artifact", "artifact_area"}:
                return self._reconcile_artifact(lab, store, path, run, pending)
            if not pending and (not run or run["state"] != "running"):
                return {"state": "no_pending_operation"}
            snapshot = {item["id"]: item for item in self._snapshot(lab, path)}
            finding = "no_pending_file"
            if pending:
                digest = snapshot[pending["fixture_id"]]["current_sha256"]
                finding = "applied" if digest == pending["after_sha256"] else "not_applied" if digest == pending["before_sha256"] else "partial_or_changed"
            updates = {"pending": None, "arm": None}
            recovering = pending and pending["operation"].startswith("recover_")
            if recovering:
                updates["recovery"] = {"run_id": run_id, "verified": False, "state": "failed"}
            elif run:
                if pending and finding == "applied" and pending["fixture_id"] not in run["affected"]:
                    run["affected"].append(pending["fixture_id"])
                run["state"], run["ended_at"] = "interrupted", utc_now()
                updates["run:" + run_id] = run
            self._event(store, lab, "recovery.failed" if recovering else "run.interrupted", source="response", outcome="unknown", run_id=run_id,
                        details={"reason": finding, "state": "recovery_failed" if recovering else "interrupted"}, updates=updates)
            return {"state": "recovery_failed" if recovering else "interrupted", "finding": finding, "next": "preserve_evidence_then_recover"}

    def _reconcile_artifact(self, lab, store, path, run, pending):
        if not run or pending["run_id"] != run["run_id"]:
            raise SafetyError("Pending artifact belongs to a different run")
        location = path / "artifacts" / validate_id(run["run_id"])
        finding = "not_applied"
        with SafeDirectory(path / "artifacts"):
            if pending["kind"] == "artifact_area":
                if location.exists():
                    with SafeDirectory(location) as directory:
                        if directory.names():
                            raise SafetyError("Uncommitted artifact preparation contains unexpected files")
                    run["artifacts_initialized"] = True
                    finding = "empty_area_prepared"
            else:
                self._artifact_snapshot(lab, path, run, pending=pending)
                record = pending["record"]
                with SafeDirectory(location) as directory:
                    if record["name"] in directory.names():
                        data = directory.read(record["name"], record["size"])
                        if len(data) != record["size"] or hash_bytes(data) != record["sha256"]:
                            raise SafetyError("Interrupted artifact contents require offline review")
                        run["artifacts"].append({**record, "identity": directory.identity(record["name"]), "reconciled": True})
                        finding = "applied"
        run.update(state="interrupted", ended_at=utc_now(), reason="artifact_" + finding)
        self._event(store, lab, "run.interrupted", source="response", run_id=run["run_id"], outcome="unknown",
                    details={"state": "interrupted", "reason": run["reason"]},
                    updates={"pending": None, "arm": None, "run:" + run["run_id"]: run})
        return {"state": "interrupted", "finding": finding, "next": "preserve_evidence_then_recover"}

    @staticmethod
    def _all_events(store):
        result, after = [], 0
        while True:
            batch = store.events(limit=1000, after=after)
            if not batch:
                return result
            result.extend(event.to_dict() for event in batch)
            after = batch[-1].sequence

    def preserve(self, lab_id):
        with self._open(lab_id, lease=True) as (lab, store, path):
            run_id = store.get_state("active_run")
            run = store.get_state("run:" + run_id) if run_id else None
            if store.get_state("pending") or store.get_state("active_study") or run and run["state"] == "running":
                raise StateError("Contain or reconcile the run before preserving evidence")
            items = self._snapshot(lab, path)
            artifacts = self._artifact_snapshot(lab, path, run)
            missing = [item["id"] for item in items if item["status"] == "missing"]
            events = scenarios.canonical(self._all_events(store))
            evidence = store.get_state("evidence", [])
            if store.count() + len(lab["fixtures"]) * 2 + 12 > self.policy.max_events:
                raise StateError("Insufficient audit capacity for evidence and recovery")
            required = sum(item["size"] + 64 for item in items) + sum(item["size"] for item in artifacts) + len(events) + MAX_EVIDENCE_MANIFEST
            if sum(item["bytes"] for item in evidence) + required > self.policy.max_evidence_bytes:
                raise SafetyError("Evidence retention ceiling reached; preserve the lab for review")
            self._space(required)
            evidence_id = str(uuid4())
            reservation = {"id": evidence_id, "run_id": run_id, "bytes": required, "sha256": None, "state": "incomplete", "created_at": utc_now()}
            evidence.append(reservation)
            self._event(store, lab, "evidence.started", source="response", outcome="pending", run_id=run_id,
                        details={"evidence_id": evidence_id, "bytes": required, "count": len(items), "state": "incomplete"}, updates={"evidence": evidence})
            files, total = [], 0
            with SafeDirectory(path / "evidence" / evidence_id, create=True) as target, SafeDirectory(path / "work") as work:
                for item in items:
                    if item["status"] == "missing":
                        continue
                    data = work.read(item["name"], self.policy.max_file_bytes + 64)
                    digest = hash_bytes(data)
                    if digest != item["current_sha256"]:
                        raise SafetyError("Fixture changed during evidence acquisition")
                    target.create(item["name"], data)
                    files.append({"name": item["name"], "fixture_id": item["id"], "sha256": digest, "size": len(data)})
                    total += len(data)
                if artifacts:
                    with SafeDirectory(path / "artifacts" / run_id) as source:
                        for item in artifacts:
                            if source.identity(item["name"]) != item["identity"]:
                                raise SafetyError("Artifact identity changed during evidence acquisition")
                            data = source.read(item["name"], item["size"])
                            if hash_bytes(data) != item["sha256"]:
                                raise SafetyError("Artifact changed during evidence acquisition")
                            target.create(item["name"], data)
                            files.append({"name": item["name"], "artifact_kind": item["kind"],
                                          "source_fixture_id": item["fixture_id"], "sha256": item["sha256"], "size": len(data)})
                            total += len(data)
                target.create("events.json", events)
                files.append({"name": "events.json", "sha256": hashlib.sha256(events).hexdigest(), "size": len(events)})
                total += len(events)
                manifest = {"schema_version": 1, "evidence_id": evidence_id, "lab_id": lab_id, "run_id": run_id,
                            "collected_at": utc_now(), "collector": "local_operator", "files": files,
                            "event_count": len(scenarios.parse_json(events, self.policy.max_evidence_bytes)), "complete": not missing,
                            "missing_fixture_ids": missing, "authenticity": "Local hashes require independent trust; not tamperproof."}
                encoded = scenarios.canonical(manifest)
                if len(encoded) > MAX_EVIDENCE_MANIFEST:
                    raise SafetyError("Evidence manifest exceeds its bounded inventory ceiling")
                target.create("manifest.json", encoded)
                total += len(encoded)
            record = {"id": evidence_id, "run_id": run_id, "bytes": total, "sha256": hash_bytes(encoded), "created_at": manifest["collected_at"], "state": "partial" if missing else "complete"}
            evidence[-1] = record
            self._event(store, lab, "evidence.preserved", source="response", run_id=run_id, outcome="partial" if missing else "success",
                        details={"evidence_id": evidence_id, "count": len(files), "bytes": total, "sha256": record["sha256"], "status": record["state"]}, updates={"evidence": evidence})
            return record

    def _verify_evidence(self, path, record):
        with SafeDirectory(path / "evidence" / record["id"]) as directory:
            encoded = directory.read("manifest.json", MAX_EVIDENCE_MANIFEST)
            if hash_bytes(encoded) != record["sha256"]:
                raise SafetyError("Evidence manifest integrity failed")
            manifest = scenarios.parse_json(encoded, MAX_EVIDENCE_MANIFEST)
            if set(directory.names()) != {item["name"] for item in manifest["files"]} | {"manifest.json"}:
                raise SafetyError("Evidence inventory differs from its manifest")
            for item in manifest["files"]:
                data = directory.read(item["name"], item["size"])
                if len(data) != item["size"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
                    raise SafetyError("Evidence content integrity failed")
            return manifest

    def recover(self, lab_id, mode="clean"):
        if mode not in {"clean", "decrypt"}:
            raise ValidationError("Recovery mode must be clean or decrypt")
        with self._open(lab_id, lease=True) as (lab, store, path):
            stop_before = store.get_state("stop_requested")
            run_id = store.get_state("active_run")
            run = store.get_state("run:" + run_id) if run_id else None
            if not run or run["state"] == "running" or store.get_state("pending") or store.get_state("active_study"):
                raise StateError("A completed, contained or reconciled run is required for recovery")
            environment.require_guest(run["attestation"])
            historical = store.get_state("recovery")
            if historical and historical.get("verified") and historical.get("run_id") == run_id and all(item["status"] == "intact" for item in self._snapshot(lab, path)):
                return historical
            evidence = [item for item in store.get_state("evidence", []) if item["run_id"] == run_id and item.get("state") == "complete"]
            if not evidence:
                raise StateError("Preserve evidence for this run before recovery")
            manifest = self._verify_evidence(path, evidence[-1])
            captured = {item.get("fixture_id"): item["sha256"] for item in manifest["files"] if "fixture_id" in item}
            current = self._snapshot(lab, path)
            if any(item["status"] == "missing" or item["current_sha256"] != captured.get(item["id"]) for item in current):
                raise SafetyError("Current fixtures differ from preserved evidence; acquire new evidence first")
            key = None
            if mode == "decrypt":
                if run["scenario"] != "encrypt_generated":
                    raise ValidationError("This run did not use authenticated encryption")
                with SafeDirectory(path / "keys") as keys:
                    key = keys.read(f"run-{run_id}.key", 32)
            if store.count() + len(lab["fixtures"]) * 2 + 3 > self.policy.max_events:
                raise StateError("Insufficient durable audit capacity for recovery")
            self._event(store, lab, "recovery.started", source="response", run_id=run_id, details={"count": len(lab["fixtures"]), "state": "recovering"}, updates={"recovery": {"run_id": run_id, "verified": False, "state": "recovering"}, "stop_requested": False}, expected={"stop_requested": stop_before})
            verified = 0
            started = time.monotonic()
            try:
                with SafeDirectory(path / "clean") as clean, SafeDirectory(path / "work") as work:
                    for fixture in lab["fixtures"]:
                        if store.get_state("stop_requested") or time.monotonic() - started >= self.policy.max_run_seconds:
                            raise StateError("Recovery stopped at a bounded operation boundary")
                        self._space(self.policy.max_file_bytes * 2)
                        if clean.identity(fixture["name"]) != fixture["clean_identity"]:
                            raise SafetyError("Clean-copy object identity changed")
                        original = clean.read(fixture["name"], fixture["size"])
                        if hash_bytes(original) != fixture["sha256"]:
                            raise SafetyError("Clean-copy baseline hash mismatch")
                        before = work.read(fixture["name"], self.policy.max_file_bytes + 64)
                        after = original
                        if hash_bytes(before) != fixture["sha256"]:
                            if key:
                                if not before.startswith(MAGIC):
                                    raise SafetyError("Ciphertext fixture header is invalid")
                                offset = len(MAGIC)
                                nonce = before[offset:offset + 12]
                                after = crypto.decrypt(before[offset + 12:], key, nonce, self._aad(lab, run, fixture))
                                if hash_bytes(after) != fixture["sha256"]:
                                    raise SafetyError("Decrypted fixture differs from its trusted baseline")
                            self._mutate(store, lab, work, fixture, before, after, run_id, "recover_" + mode, recovery=True)
                        verified += 1
                final = self._snapshot(lab, path)
                if any(item["status"] != "intact" for item in final):
                    raise SafetyError("Final recovery inventory verification failed")
                result = {"run_id": run_id, "verified": True, "state": "verified", "count": verified, "mode": mode, "verified_at": utc_now()}
                self._event(store, lab, "recovery.verified", source="response", run_id=run_id, details={"verified": verified, "failed": 0, "state": "verified"}, updates={"recovery": result, "pending": None, "observations": {item["id"]: item["sha256"] for item in lab["fixtures"]}})
                return result
            except (LabError, OSError, KeyboardInterrupt):
                try:
                    self._event(store, lab, "recovery.failed", source="response", outcome="failure", severity="high", run_id=run_id,
                                details={"verified": verified, "failed": len(lab["fixtures"]) - verified, "reason": "verification_or_operation_failed"},
                                updates={"recovery": {"run_id": run_id, "verified": False, "state": "failed", "count": verified}})
                except LabError:
                    pass
                raise
            finally:
                key = None

    def report(self, lab_id):
        result = self.status(lab_id)
        with self._open(lab_id, readonly=True) as (lab, store, path):
            result["events"] = self._all_events(store)
            result["evidence"] = store.get_state("evidence", [])
            result["crypto_studies"] = [store.get_state("study:" + study_id) for study_id in store.get_state("studies", [])]
            result["runs"] = [store.get_state("run:" + run_id) for run_id in store.get_state("runs", [])]
            run = result["last_run"]
            if run:
                result["simulation"] = {"plan_sha256": run.get("plan_sha256"), "discovered_files": len(run.get("discovered", [])),
                                        "staged_files": sum(item["kind"] == "staged" for item in run.get("artifacts", [])),
                                        "staged_bytes": sum(item["size"] for item in run.get("artifacts", []) if item["kind"] == "staged"),
                                        "mock_received_files": sum(item["kind"] == "received" for item in run.get("artifacts", [])),
                                        "mock_received_bytes": sum(item["size"] for item in run.get("artifacts", []) if item["kind"] == "received"),
                                        "modified_files": len(run["affected"]), "external_transfer": False}
            result["schema_version"] = 1
            result["report_created_at"] = utc_now()
            result["indicators"] = [{"type": "generated_fixture_sha256", "value": item["current_sha256"], "fixture_id": item["id"], "synthetic": True}
                                    for item in result["fixtures"] if item["status"] == "changed"]
            result["recommendations"] = ["Retain isolated snapshots and verified clean copies.", "Review independent integrity observations alongside simulation events.",
                                         "Reconcile interrupted operations before recovery.", "Do not infer evidence authenticity from hashes alone."]
            result["findings"] = {"changed": sum(item["status"] == "changed" for item in result["fixtures"]),
                                  "missing": sum(item["status"] == "missing" for item in result["fixtures"]),
                                  "alerts": len(result["alerts"]), "recovery_verified": bool(result["recovery"] and result["recovery"].get("verified"))}
            run = result["last_run"]
            result["incident"] = {"id": str(uuid5(UUID(lab_id), str(run["run_id"]) + "incident")), "run_id": run["run_id"],
                                  "status": "recovered" if result["findings"]["recovery_verified"] else "investigation_required",
                                  "affected_fixture_ids": run["affected"], "evidence_ids": [item["id"] for item in result["evidence"] if item["run_id"] == run["run_id"]]} if run else None
        return result

    def investigate(self, lab_id):
        report = self.report(lab_id)
        return {key: report[key] for key in ("schema_version", "lab_id", "incident", "findings", "alerts", "evidence", "recommendations", "limitations")}
