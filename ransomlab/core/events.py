"""Closed, immutable event contracts shared by all application interfaces."""

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from uuid import UUID, uuid4

from .errors import ValidationError
from .hashing import validate_digest

MAX_EVENT_BYTES = 8192
SOURCES = frozenset({"core", "simulator", "monitor", "response", "operator"})
SEVERITIES = frozenset({"info", "warning", "high", "critical"})
OUTCOMES = frozenset({"success", "failure", "pending", "unknown", "detected", "blocked", "requested", "partial"})

_DETAILS_BY_KIND = {
    "experiment.created": {"state", "count", "bytes", "generator"},
    "experiment.validated": {"state", "count", "sha256"},
    "experiment.closed": {"state", "status", "count"},
    "lab.created": {"count", "bytes", "generator", "state", "status"},
    "run.armed": {"scenario", "request_id", "count", "action_count", "state", "reason"},
    "run.started": {"scenario", "request_id", "count", "action_count", "state"},
    "file.intent": {"operation", "before_sha256", "after_sha256", "sha256", "baseline_sha256", "bytes", "size", "state"},
    "file.changed": {"operation", "before_sha256", "after_sha256", "sha256", "baseline_sha256", "bytes", "size", "state", "status"},
    "file.observed": {"operation", "before_sha256", "after_sha256", "sha256", "baseline_sha256", "bytes", "size", "state", "status", "reason"},
    "run.completed": {"scenario", "count", "action_count", "state", "status", "changed", "failed", "reason"},
    "run.contained": {"count", "action_count", "state", "reason"},
    "run.interrupted": {"count", "action_count", "state", "reason"},
    "alert.raised": {"rule", "count", "changed", "missing", "failed", "reason", "state", "status"},
    "evidence.started": {"evidence_id", "count", "bytes", "state", "status"},
    "evidence.preserved": {"evidence_id", "count", "bytes", "sha256", "state", "status"},
    "recovery.started": {"count", "state"},
    "file.restored": {"sha256", "before_sha256", "after_sha256", "baseline_sha256", "bytes", "size", "state", "status"},
    "recovery.verified": {"verified", "failed", "count", "changed", "missing", "state", "status"},
    "recovery.failed": {"verified", "failed", "count", "changed", "missing", "state", "status", "reason"},
    "operation.failed": {"operation", "state", "reason", "status"},
    "scenario.imported": {"scenario", "request_id", "count", "action_count", "status", "state"},
    "containment.requested": {"reason", "state"},
    "key.created": {"operation", "state", "status"},
}
KINDS = frozenset(_DETAILS_BY_KIND)
_INTEGER_DETAILS = frozenset({"count", "bytes", "changed", "missing", "verified", "failed", "action_count", "size"})
_HASH_DETAILS = frozenset({"sha256", "baseline_sha256", "before_sha256", "after_sha256"})
_UUID_DETAILS = frozenset({"request_id", "evidence_id"})


def validate_id(value):
    """Accept only canonical lowercase UUID text, never path-shaped identifiers."""
    if type(value) is not str or len(value) != 36:
        raise ValidationError("identifier must be a canonical UUID")
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError):
        raise ValidationError("identifier must be a canonical UUID") from None
    if str(parsed) != value:
        raise ValidationError("identifier must be a canonical UUID")
    return value


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _utc_timestamp(value):
    if type(value) is not str or len(value) > 40:
        raise ValidationError("event timestamp must be UTC ISO text")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise ValidationError("event timestamp must be UTC ISO text") from None
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        raise ValidationError("event timestamp must have a UTC offset")
    return parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _validate_details(kind, details):
    if not isinstance(details, Mapping) or len(details) > 16:
        raise ValidationError("event details must be a bounded field mapping")
    result = {}
    for key, value in details.items():
        if type(key) is not str or key not in _DETAILS_BY_KIND[kind]:
            raise ValidationError("event detail field is unsupported for this event type")
        if key in _INTEGER_DETAILS:
            if type(value) is not int or not 0 <= value <= 1_099_511_627_776:
                raise ValidationError("event count or size is outside supported bounds")
        elif key in _HASH_DETAILS:
            validate_digest(value)
        elif key in _UUID_DETAILS:
            validate_id(value)
        elif (type(value) is not str or not 1 <= len(value) <= 256
              or any(ord(char) < 32 or ord(char) == 127 for char in value)
              or "/" in value or "\\" in value):
            raise ValidationError("event text must be bounded and free of paths and control characters")
        if type(value) is str:
            try:
                value.encode("utf-8")
            except UnicodeError:
                raise ValidationError("event text must be valid Unicode") from None
        result[key] = value
    return MappingProxyType(result)


@dataclass(frozen=True, slots=True)
class Event:
    id: str
    lab_id: str
    kind: str
    source: str = "core"
    severity: str = "info"
    outcome: str = "success"
    run_id: str | None = None
    fixture_id: str | None = None
    details: Mapping = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)
    sequence: int | None = None
    schema_version: int = 1

    def __post_init__(self):
        validate_id(self.id)
        validate_id(self.lab_id)
        for value in (self.run_id, self.fixture_id):
            if value is not None:
                validate_id(value)
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ValidationError("event schema version is unsupported")
        for value, allowed in ((self.kind, KINDS), (self.source, SOURCES),
                               (self.severity, SEVERITIES), (self.outcome, OUTCOMES)):
            if type(value) is not str or value not in allowed:
                raise ValidationError("event type, source, severity or outcome is unsupported")
        if self.sequence is not None and (type(self.sequence) is not int or not 1 <= self.sequence <= 9_223_372_036_854_775_807):
            raise ValidationError("event sequence must be a positive storage integer")
        object.__setattr__(self, "details", _validate_details(self.kind, self.details))
        object.__setattr__(self, "created_at", _utc_timestamp(self.created_at))
        if len(self.to_json().encode("utf-8")) > MAX_EVENT_BYTES:
            raise ValidationError("event exceeds its serialized byte ceiling")

    @classmethod
    def create(cls, lab_id, kind, source="core", severity="info", outcome="success",
               run_id=None, fixture_id=None, details=None):
        return cls(id=str(uuid4()), lab_id=lab_id, kind=kind, source=source,
                   severity=severity, outcome=outcome, run_id=run_id,
                   fixture_id=fixture_id, details={} if details is None else details)

    @property
    def event_id(self):
        return self.id

    def to_dict(self):
        return {"schema_version": self.schema_version, "id": self.id,
                "lab_id": self.lab_id, "run_id": self.run_id,
                "fixture_id": self.fixture_id, "kind": self.kind,
                "source": self.source, "severity": self.severity,
                "outcome": self.outcome, "details": dict(self.details),
                "created_at": self.created_at, "sequence": self.sequence}

    def to_json(self):
        return json.dumps(self.to_dict(), ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True)

    @classmethod
    def from_dict(cls, value):
        names = {"schema_version", "id", "lab_id", "run_id", "fixture_id", "kind",
                 "source", "severity", "outcome", "details", "created_at", "sequence"}
        if type(value) is not dict or set(value) != names:
            raise ValidationError("event fields are missing or unsupported")
        return cls(**value)

