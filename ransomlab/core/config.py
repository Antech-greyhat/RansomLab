"""Immutable resource limits; configuration validation is not a sandbox."""

from dataclasses import asdict, dataclass, fields
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

