"""Immutable resource limits; configuration validation is not a sandbox."""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from pathlib import Path
import tomllib
from typing import ClassVar

from .errors import ValidationError


@dataclass(frozen=True, slots=True)
class Policy:
    """Small training ceilings that callers may tighten, never enlarge.

    The minimum free-space reserve can be increased. Limits are explicit in
    persisted configurations: ``from_dict`` does not fill missing fields.
    """

    max_files: int = 100
    max_file_bytes: int = 1_048_576
    max_total_bytes: int = 20_971_520
    max_actions: int = 100
    max_run_seconds: int = 300
    max_event_bytes: int = 8192
    max_events: int = 10_000
    max_database_bytes: int = 33_554_432
    max_evidence_bytes: int = 67_108_864
    min_free_bytes: int = 134_217_728

    SCHEMA_VERSION: ClassVar[int] = 1

    def __post_init__(self):
        for item in fields(self):
            value = getattr(self, item.name)
            if type(value) is not int or value <= 0:
                raise ValidationError("resource limits must be positive integers")
            if item.name == "min_free_bytes":
                if not item.default <= value <= 1_099_511_627_776:
                    raise ValidationError("free-space reserve is outside supported bounds")
            elif value > item.default:
                raise ValidationError("resource limit exceeds the training ceiling")
        if self.max_file_bytes > self.max_total_bytes:
            raise ValidationError("per-file ceiling exceeds the total byte ceiling")
        if self.max_database_bytes < 4096:
            raise ValidationError("database ceiling is smaller than one storage page")

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, values):
        names = {item.name for item in fields(cls)}
        if type(values) is not dict or set(values) != names:
            raise ValidationError("configuration fields are missing or unsupported")
        return cls(**values)


@dataclass(frozen=True, slots=True)
class AppConfig:
    policy: Policy = Policy()
    log_level: str = "WARNING"
    schema_version: int = 1

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ValidationError("Unsupported configuration schema")
        if not isinstance(self.policy, Policy):
            raise ValidationError("Configuration requires a validated policy")
        if type(self.log_level) is not str or self.log_level not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
            raise ValidationError("Unsupported logging level")

    def to_dict(self) -> dict:
        return {"schema_version": self.schema_version, "policy": self.policy.to_dict(),
                "logging": {"level": self.log_level}}

    @classmethod
    def from_dict(cls, value: dict) -> AppConfig:
        if type(value) is not dict or not {"schema_version"} <= value.keys() <= {"schema_version", "policy", "logging"}:
            raise ValidationError("Configuration fields are missing or unsupported")
        policy = value.get("policy", {})
        log = value.get("logging", {})
        if type(policy) is not dict or not policy.keys() <= Policy().to_dict().keys():
            raise ValidationError("Unsupported policy configuration")
        if type(log) is not dict or not log.keys() <= {"level"}:
            raise ValidationError("Unsupported logging configuration")
        return cls(Policy.from_dict({**Policy().to_dict(), **policy}), log.get("level", "WARNING"),
                   value["schema_version"])

    @classmethod
    def load(cls, path: Path | str) -> AppConfig:
        try:
            with Path(path).open("rb") as source:
                data = source.read(16_385)
            if len(data) > 16_384:
                raise ValidationError("Configuration exceeds its byte ceiling")
            return cls.from_dict(tomllib.loads(data.decode("utf-8")))
        except (OSError, ValueError, UnicodeError, RecursionError):
            raise ValidationError("Configuration could not be read as supported TOML") from None

    @classmethod
    def discover(cls) -> AppConfig:
        path = Path(__file__).resolve().parents[2] / "ransomlab.toml"
        try:
            path.lstat()
        except FileNotFoundError:
            return cls()
        except OSError:
            raise ValidationError("Default configuration could not be inspected") from None
        return cls.load(path)

