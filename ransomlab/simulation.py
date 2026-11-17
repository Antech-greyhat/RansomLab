"""Finite generated-data behaviour stages; filesystem admission belongs to services."""
import time

from .core.errors import SafetyError, StateError
from .core.hashing import hash_bytes


class SimulationStopped(StateError):
    """The operator or operation budget stopped scheduling further actions."""


def pace(interval_ms, checkpoint):
    """Check containment at most 50 ms apart during an intentional pacing delay."""
    remaining = interval_ms / 1000
    while remaining > 0:
        checkpoint()
        duration = min(remaining, 0.05)
        time.sleep(duration)
        remaining -= duration
    checkpoint()


def note(lab_id, run_id):
    return ("RANSOMLAB SIMULATION NOTE\nGenerated disposable data exercise.\n"
            "No payment, contact or external upload is requested.\n"
            f"Lab: {lab_id}\nRun: {run_id}\n").encode("ascii")


class BehaviourRunner:
    """Only registered fixtures and three fixed artifact purposes are scheduled."""

    def __init__(self, fixtures, run, config, read_fixture, write_artifact, read_staged, impact, emit, checkpoint):
        self.fixtures = fixtures
        self.run = run
        self.config = config
        self.read_fixture = read_fixture
        self.write_artifact = write_artifact
        self.read_staged = read_staged
        self.impact = impact
        self.emit = emit
        self.checkpoint = checkpoint
        self.actions = 0

    def before_action(self):
        if self.actions:
            pace(self.config["interval_ms"], self.checkpoint)
        else:
            self.checkpoint()
        self.actions += 1

    def execute(self):
        for fixture in self.fixtures:
            self.before_action()
            data = self.read_fixture(fixture)
            item = {"fixture_id": fixture["id"], "synthetic_class": ("public", "finance", "project")[fixture["sample_index"] % 3],
                    "size": len(data), "sha256": hash_bytes(data)}
            candidate = {**self.run, "discovered": self.run["discovered"] + [item]}
            self.emit("file.discovered", fixture_id=fixture["id"],
                      details={"classification": item["synthetic_class"], "bytes": item["size"], "sha256": item["sha256"]},
                      updates={"run:" + self.run["run_id"]: candidate}, expected={"stop_requested": False})
            self.run.update(candidate)
        for fixture in self.fixtures[:self.config["stage_count"]]:
            self.before_action()
            self.write_artifact("staged", fixture, self.read_fixture(fixture))
        for fixture in self.fixtures[:self.config["receive_count"]]:
            self.before_action()
            data = self.read_staged(fixture)
            if hash_bytes(data) != fixture["sha256"]:
                raise SafetyError("Staged synthetic data no longer matches its baseline")
            self.write_artifact("received", fixture, data)
        if self.run["scenario"] == "double_extortion_generated":
            for fixture in self.fixtures:
                self.before_action()
                self.impact(fixture)
            self.before_action()
            self.write_artifact("note", None, note(self.run["lab_id"], self.run["run_id"]))
