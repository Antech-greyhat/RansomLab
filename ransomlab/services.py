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
import re
import secrets
import shutil
import time
from uuid import uuid4, uuid5, UUID

from . import crypto, environment, scenarios
from .core.config import Policy
from .core.errors import LabError, SafetyError, StateError, ValidationError
from .core.events import Event, utc_now, validate_id
from .core.hashing import hash_bytes
from .core.repository import EventStore
from .storage import LabLease, SafeDirectory

MAX_LABS = 8
MAX_RUNS = 20
MAGIC = b"RANSOMLAB1\x00"


def _label(value):
    if type(value) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _-]{0,39}", value) is None:
        raise ValidationError("Lab name must be 1 to 40 letters, digits, spaces, underscores or hyphens")
    return value


def _sample(index, size):
    header = f"RansomLab generated fixture v1 | sample {index:03d}\n".encode("ascii")
    block = header + hashlib.sha256(header).digest()
    return (block * (size // len(block) + 1))[:size]


class LabService:
    """Internal root injection is for test harnesses; no user-facing root option."""

    def __init__(self, root=None, policy=None):
        self.root = Path(root) if root is not None else Path(__file__).resolve().parent.parent / ".ransomlab"
        self.root = self.root.absolute()
        self.policy = policy or Policy()

    @classmethod
    def default(cls):
        return cls()

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
        if type(catalog) is not dict or set(catalog) != {"schema_version", "labs"} or catalog["schema_version"] != 1:
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
        manifest = signed["manifest"]
        validate_id(manifest["lab_id"])
        validate_id(manifest["baseline_id"])
        Policy.from_dict(manifest["policy"])
        if not 1 <= len(manifest["fixtures"]) <= self.policy.max_files:
            raise SafetyError("Fixture manifest exceeds its bounds")
        for fixture in manifest["fixtures"]:
            validate_id(fixture["id"])
            if fixture["name"] != f"fixture-{fixture['id']}.bin":
                raise SafetyError("Fixture name is not generated from its identity")
        return manifest

    @contextmanager
    def _open(self, lab_id, *, readonly=False, lease=False):
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
            yield lab, store, path

    def _event(self, store, lab, kind, *, updates=None, expected=None, **values):
        protected = {"file.intent", "file.changed", "file.restored", "run.completed", "run.contained", "run.interrupted",
                     "recovery.started", "recovery.verified", "recovery.failed", "evidence.started", "evidence.preserved", "containment.requested"}
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
        self._initialize()
        self._space(size * count * 3 + self.policy.max_evidence_bytes + self.policy.max_database_bytes)
        with LabLease(self.root / "lease.flag"), SafeDirectory(self.root) as registry:
            catalog = self._catalog(registry)
            if len(catalog["labs"]) >= MAX_LABS:
                raise SafetyError("The maximum number of disposable labs has been reached")
            lab_id = str(uuid4())
            path = self.root / lab_id
            with ExitStack() as stack:
                directory = stack.enter_context(SafeDirectory(path, create=True))
                work = stack.enter_context(SafeDirectory(path / "work", create=True))
                clean = stack.enter_context(SafeDirectory(path / "clean", create=True))
                stack.enter_context(SafeDirectory(path / "keys", create=True))
                stack.enter_context(SafeDirectory(path / "evidence", create=True))
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
                       "created_at": utc_now(), "generator": "fixture-v1", "fixtures": fixtures,
                       "policy": self.policy.to_dict(), "fixture_count": count, "bytes_total": count * size}
                mac = hmac.new(registry.read("registry.key", 32), scenarios.canonical(lab), hashlib.sha256).hexdigest()
                directory.create("manifest.json", scenarios.canonical({"manifest": lab, "mac": mac}))
                with EventStore(path / "state.db", policy=self.policy) as store:
                    self._event(store, lab, "lab.created", details={"count": count, "bytes": count * size, "generator": "fixture-v1", "state": "prepared"},
                                updates={"requests": [], "runs": [], "alerts": [], "evidence": [], "recovery": None,
                                         "arm": None, "pending": None, "active_run": None, "stop_requested": False})
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
                if recovery and recovery.get("verified") and any(item["status"] != "intact" for item in self._snapshot(lab, path)):
                    state = "verification_lost"
                result.append({"lab_id": lab_id, "name": lab["name"], "fixture_count": lab["fixture_count"],
                               "bytes_total": lab["bytes_total"], "created_at": lab["created_at"],
                               "state": state, "alerts": len(store.get_state("alerts", []))})
        return result

    @staticmethod
    def _state(store, run, recovery):
        if store.get_state("pending"):
            return "reconciliation_required"
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
                    "last_run": run, "recovery": recovery, "alerts": store.get_state("alerts", []),
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
                    result["state"] = "verification_lost"
            return result

    def descriptor(self, lab_id):
        with self._open(lab_id, readonly=True) as (lab, _, __):
            return {"schema_version": 1, "lab_id": lab_id, "baseline_id": lab["baseline_id"],
                    "fixtures": [{"id": item["id"]} for item in lab["fixtures"]]}

    def create_scenario(self, lab_id, scenario, count=None):
        with self._open(lab_id, readonly=True) as (lab, _, __):
            return scenarios.create(lab, scenario, count)

    def import_scenario(self, envelope):
        if type(envelope) is not dict:
            raise ValidationError("A scenario object is required")
        lab_id = validate_id(envelope.get("lab_id"))
        with self._open(lab_id, lease=True) as (lab, store, _):
            scenarios.validate(envelope, lab)
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
        if store.get_state("pending"):
            raise StateError("An uncertain operation requires reconciliation")
        run_id = store.get_state("active_run")
        if run_id:
            recovery = store.get_state("recovery")
            if not recovery or not recovery.get("verified") or recovery.get("run_id") != run_id:
                raise StateError("The previous run must be recovered and verified first")
        self._space(self.policy.max_total_bytes * 2)
        if any(item["status"] != "intact" for item in self._snapshot(lab, path)):
            raise SafetyError("Working fixtures do not match their generated baseline")
        with SafeDirectory(path / "clean") as clean:
            for fixture in lab["fixtures"]:
                if clean.identity(fixture["name"]) != fixture["clean_identity"] or hash_bytes(clean.read(fixture["name"], fixture["size"])) != fixture["sha256"]:
                    raise SafetyError("A clean recovery copy failed verification")

    def simulate(self, lab_id, request_id):
        validate_id(request_id)
        with self._open(lab_id, lease=True) as (lab, store, path):
            request = store.get_state("request:" + request_id)
            if not request:
                raise ValidationError("Scenario request is not staged")
            if request["status"] != "staged":
                return {"request_id": request_id, "status": request["status"], "duplicate": True}
            envelope = scenarios.validate(request["envelope"], lab)
            self._ready(lab, store, path)
            arm = store.get_state("arm")
            if not arm or arm["baseline_id"] != lab["baseline_id"] or datetime.fromisoformat(arm["expires_at"]) <= datetime.now(timezone.utc):
                raise SafetyError("A current locally armed session is required")
            environment.require_guest(arm["attestation"])
            ids = envelope["fixture_ids"]
            if len(ids) > self.policy.max_actions or store.count() + len(ids) * 5 + len(lab["fixtures"]) * 3 + 50 > self.policy.max_events:
                raise SafetyError("Insufficient action or audit capacity including recovery reserve")
            runs = store.get_state("runs", [])
            if len(runs) >= MAX_RUNS:
                raise SafetyError("Run retention ceiling reached")
            scenario = envelope["scenario"]
            if scenario == "encrypt_generated":
                crypto.provider_name()
            run_id = str(uuid4())
            run = {"run_id": run_id, "request_id": request_id, "scenario": scenario, "state": "running", "started_at": utc_now(),
                   "ended_at": None, "affected": [], "attestation": arm["attestation"]}
            request["status"] = "consumed"
            runs.append(run_id)
            self._event(store, lab, "run.started", source="simulator", run_id=run_id, details={"scenario": scenario, "request_id": request_id, "count": len(ids), "state": "running"},
                        updates={"active_run": run_id, "run:" + run_id: run, "request:" + request_id: request, "runs": runs,
                                 "arm": None, "recovery": None}, expected={"arm": arm, "stop_requested": False})
            key = secrets.token_bytes(32) if scenario == "encrypt_generated" else None
            nonce_prefix = secrets.token_bytes(4)
            started = time.monotonic()
            try:
                if key:
                    self._event(store, lab, "key.created", run_id=run_id, outcome="pending", details={"operation": "create_run_key"})
                    with SafeDirectory(path / "keys") as keys:
                        keys.create(f"run-{run_id}.key", key)
                with SafeDirectory(path / "work") as work:
                    fixtures = {item["id"]: item for item in lab["fixtures"]}
                    for number, fixture_id in enumerate(ids):
                        if store.get_state("stop_requested") or time.monotonic() - started >= self.policy.max_run_seconds:
                            run["state"] = "contained"
                            break
                        fixture = fixtures[fixture_id]
                        self._space(self.policy.max_file_bytes * 2)
                        before = work.read(fixture["name"], self.policy.max_file_bytes)
                        if hash_bytes(before) != fixture["sha256"]:
                            raise SafetyError("Fixture changed since preparation")
                        if key:
                            nonce = nonce_prefix + number.to_bytes(8, "big")
                            after = MAGIC + nonce + crypto.encrypt(before, key, nonce, self._aad(lab, run, fixture))
                        else:
                            marker = b"RANSOMLAB SIMULATED CHANGE\n"
                            after = marker + before[len(marker):]
                        self._mutate(store, lab, work, fixture, before, after, run_id, scenario)
                        run["affected"].append(fixture_id)
                        self._scan(lab, store, path, run_id, updates={"run:" + run_id: run})
                if run["state"] == "running":
                    run["state"] = "completed"
                run["ended_at"] = utc_now()
                self._event(store, lab, "run.contained" if run["state"] == "contained" else "run.completed", source="simulator", run_id=run_id,
                            details={"state": run["state"], "count": len(run["affected"])}, updates={"run:" + run_id: run})
            except (LabError, OSError, KeyboardInterrupt):
                run["state"], run["ended_at"] = "interrupted", utc_now()
                # A failed journal leaves the last durable intent for reconciliation.
                try:
                    self._event(store, lab, "run.interrupted", source="simulator", severity="high", outcome="unknown", run_id=run_id,
                                details={"state": "interrupted", "reason": "operation_failed"}, updates={"run:" + run_id: run})
                except LabError:
                    pass
                raise
            finally:
                key = None
            return run

    @staticmethod
    def _aad(lab, run, fixture):
        return scenarios.canonical({"version": 1, "lab_id": lab["lab_id"], "run_id": run["run_id"],
                                    "fixture_id": fixture["id"], "baseline_sha256": fixture["sha256"]})

    def _mutate(self, store, lab, work, fixture, before, after, run_id, operation, *, recovery=False):
        pending = {"fixture_id": fixture["id"], "run_id": run_id, "operation": operation,
                   "before_sha256": hash_bytes(before), "after_sha256": hash_bytes(after)}
        self._event(store, lab, "file.intent", source="response" if recovery else "simulator", outcome="pending", run_id=run_id,
                    fixture_id=fixture["id"], details={"operation": operation, "before_sha256": pending["before_sha256"], "after_sha256": pending["after_sha256"]},
                    updates={"pending": pending})
        work.replace(fixture["name"], after, expected=fixture["identity"])
        if hash_bytes(work.read(fixture["name"], self.policy.max_file_bytes + 64)) != pending["after_sha256"]:
            raise SafetyError("Post-write verification failed")
        self._event(store, lab, "file.restored" if recovery else "file.changed", source="response" if recovery else "simulator", run_id=run_id, fixture_id=fixture["id"],
                    details={"before_sha256": pending["before_sha256"], "after_sha256": pending["after_sha256"], "bytes": len(after)}, updates={"pending": None})

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
            pending = store.get_state("pending")
            run_id = store.get_state("active_run")
            run = store.get_state("run:" + run_id) if run_id else None
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
                run["state"], run["ended_at"] = "interrupted", utc_now()
                updates["run:" + run_id] = run
            self._event(store, lab, "recovery.failed" if recovering else "run.interrupted", source="response", outcome="unknown", run_id=run_id,
                        details={"reason": finding, "state": "recovery_failed" if recovering else "interrupted"}, updates=updates)
            return {"state": "recovery_failed" if recovering else "interrupted", "finding": finding, "next": "preserve_evidence_then_recover"}

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
            if store.get_state("pending") or run and run["state"] == "running":
                raise StateError("Contain or reconcile the run before preserving evidence")
            items = self._snapshot(lab, path)
            missing = [item["id"] for item in items if item["status"] == "missing"]
            events = scenarios.canonical(self._all_events(store))
            evidence = store.get_state("evidence", [])
            if store.count() + len(lab["fixtures"]) * 2 + 12 > self.policy.max_events:
                raise StateError("Insufficient audit capacity for evidence and recovery")
            required = sum(item["size"] + 64 for item in items) + len(events) + 65536
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
                target.create("events.json", events)
                files.append({"name": "events.json", "sha256": hashlib.sha256(events).hexdigest(), "size": len(events)})
                total += len(events)
                manifest = {"schema_version": 1, "evidence_id": evidence_id, "lab_id": lab_id, "run_id": run_id,
                            "collected_at": utc_now(), "collector": "local_operator", "files": files,
                            "event_count": len(scenarios.parse_json(events, self.policy.max_evidence_bytes)), "complete": not missing,
                            "missing_fixture_ids": missing, "authenticity": "Local hashes require independent trust; not tamperproof."}
                encoded = scenarios.canonical(manifest)
                target.create("manifest.json", encoded)
                total += len(encoded)
            record = {"id": evidence_id, "run_id": run_id, "bytes": total, "sha256": hash_bytes(encoded), "created_at": manifest["collected_at"], "state": "partial" if missing else "complete"}
            evidence[-1] = record
            self._event(store, lab, "evidence.preserved", source="response", run_id=run_id, outcome="partial" if missing else "success",
                        details={"evidence_id": evidence_id, "count": len(files), "bytes": total, "sha256": record["sha256"], "status": record["state"]}, updates={"evidence": evidence})
            return record

    def _verify_evidence(self, path, record):
        with SafeDirectory(path / "evidence" / record["id"]) as directory:
            encoded = directory.read("manifest.json", 65536)
            if hash_bytes(encoded) != record["sha256"]:
                raise SafetyError("Evidence manifest integrity failed")
            manifest = scenarios.parse_json(encoded, 65536)
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
            if not run or run["state"] == "running" or store.get_state("pending"):
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
