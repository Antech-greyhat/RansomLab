"""Typed lifecycle metadata stored alongside the existing v1 event journal."""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime
from enum import StrEnum
import re

from .errors import StateError, ValidationError
from .events import utc_now, validate_id
from .hashing import validate_digest


def validate_label(value: str) -> str:
    if type(value) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _-]{0,39}", value) is None:
        raise ValidationError("Experiment name must be 1 to 40 letters, digits, spaces, underscores or hyphens")
    return value


def validate_timestamp(value: str) -> str:
    if type(value) is not str or len(value) > 40:
        raise ValidationError("A bounded UTC timestamp is required")
    try:
        stamp = datetime.fromisoformat(value)
    except ValueError:
        raise ValidationError("A UTC timestamp is required") from None
    if stamp.utcoffset() is None or stamp.utcoffset().total_seconds() != 0:
        raise ValidationError("A UTC timestamp is required")
    return value


class ExperimentState(StrEnum):
    DRAFT = "draft"
    READY = "ready"
    CLOSED = "closed"


@dataclass(frozen=True, slots=True)
class ExperimentRecord:
    experiment_id: str
    baseline_id: str
    manifest_sha256: str
    state: ExperimentState = ExperimentState.DRAFT
    revision: int = 1
    validated_at: str | None = None
    closed_at: str | None = None
    schema_version: int = 1

    def __post_init__(self) -> None:
        validate_id(self.experiment_id)
        validate_id(self.baseline_id)
        validate_digest(self.manifest_sha256)
        if not isinstance(self.state, ExperimentState):
            raise ValidationError("Unsupported experiment state")
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ValidationError("Unsupported experiment schema")
        if type(self.revision) is not int or not 1 <= self.revision <= 1_000_000:
            raise ValidationError("Invalid experiment revision")
        for stamp in (self.validated_at, self.closed_at):
            if stamp is not None:
                validate_timestamp(stamp)
        if (self.state == ExperimentState.DRAFT and self.validated_at is not None
                or self.state == ExperimentState.READY and self.validated_at is None
                or (self.state == ExperimentState.CLOSED) != (self.closed_at is not None)):
            raise ValidationError("Experiment timestamps do not match its state")
        if (self.validated_at is not None and self.closed_at is not None
                and datetime.fromisoformat(self.closed_at) < datetime.fromisoformat(self.validated_at)):
            raise ValidationError("Experiment closure cannot precede validation")

    def to_dict(self) -> dict:
        value = asdict(self)
        value["state"] = self.state.value
        return value

    @classmethod
    def from_dict(cls, value: dict) -> ExperimentRecord:
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            raise ValidationError("Experiment fields are missing or unsupported")
        try:
            return cls(**{**value, "state": ExperimentState(value["state"])})
        except (TypeError, ValueError):
            raise ValidationError("Unsupported experiment state") from None

    def validate(self) -> ExperimentRecord:
        if self.state == ExperimentState.CLOSED:
            raise StateError("Closed experiments cannot be validated")
        return replace(self, state=ExperimentState.READY, revision=self.revision + 1,
                       validated_at=utc_now())

    def close(self) -> ExperimentRecord:
        if self.state == ExperimentState.CLOSED:
            return self
        return replace(self, state=ExperimentState.CLOSED, revision=self.revision + 1,
                       closed_at=utc_now())
