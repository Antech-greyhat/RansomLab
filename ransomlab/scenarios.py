"""Finite, data-only local scenario envelopes. Import never executes a run."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from .core.errors import ValidationError
from .core.events import validate_id

SCENARIOS = {
    "encrypt_generated": "Authenticated encryption of generated working fixtures",
    "modify_generated": "A fixed, same-size content change to generated working fixtures",
}
FIELDS = {"schema_version", "request_id", "lab_id", "baseline_id", "scenario",
          "fixture_ids", "issued_at", "expires_at"}
MAX_ENVELOPE_BYTES = 16_384


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def parse_json(data: bytes, max_bytes: int = MAX_ENVELOPE_BYTES):
    if type(data) is not bytes or len(data) > max_bytes:
        raise ValidationError("JSON input exceeds its byte ceiling")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate field")
            result[key] = value
        return result

    def nonfinite(_):
        raise ValueError("nonfinite value")

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=nonfinite)
    except (ValueError, UnicodeError, RecursionError):
        raise ValidationError("Input is not a supported JSON document") from None


def _time(value):
    if type(value) is not str or len(value) > 40:
        raise ValidationError("Scenario timestamps must be UTC ISO values")
    try:
        result = datetime.fromisoformat(value)
        if result.utcoffset() != timedelta(0):
            raise ValueError("not UTC")
        return result
    except (ValueError, TypeError):
        raise ValidationError("Scenario timestamps must be UTC ISO values") from None


def validate(envelope, lab, *, now=None):
    if type(envelope) is not dict or set(envelope) != FIELDS:
        raise ValidationError("Scenario fields are missing or unsupported")
    if type(envelope["schema_version"]) is not int or envelope["schema_version"] != 1:
        raise ValidationError("Unsupported scenario schema")
    for name in ("request_id", "lab_id", "baseline_id"):
        validate_id(envelope[name])
    if envelope["lab_id"] != lab["lab_id"] or envelope["baseline_id"] != lab["baseline_id"]:
        raise ValidationError("Scenario targets a different lab or fixture generation")
    if type(envelope["scenario"]) is not str or envelope["scenario"] not in SCENARIOS:
        raise ValidationError("Scenario action is not allowlisted")
    ids = envelope["fixture_ids"]
    if type(ids) is not list or not 1 <= len(ids) <= 100:
        raise ValidationError("Scenario fixture count is outside its bounds")
    for value in ids:
        validate_id(value)
    if len(set(ids)) != len(ids) or not set(ids).issubset({item["id"] for item in lab["fixtures"]}):
        raise ValidationError("Scenario fixture IDs are duplicate or unregistered")
    issued, expires = _time(envelope["issued_at"]), _time(envelope["expires_at"])
    now = now or datetime.now(timezone.utc)
    if not timedelta(0) < expires - issued <= timedelta(minutes=15):
        raise ValidationError("Scenario lifetime exceeds its bound")
    if issued > now + timedelta(seconds=30) or expires <= now:
        raise ValidationError("Scenario is future-dated or expired")
    if len(canonical(envelope)) > MAX_ENVELOPE_BYTES:
        raise ValidationError("Scenario exceeds its byte ceiling")
    return envelope


def create(lab, scenario, count=None):
    if count is None:
        count = len(lab["fixtures"])
    if type(count) is not int or not 1 <= count <= len(lab["fixtures"]):
        raise ValidationError("Fixture selection count is invalid")
    now = datetime.now(timezone.utc)
    envelope = {"schema_version": 1, "request_id": str(uuid4()), "lab_id": lab["lab_id"],
                "baseline_id": lab["baseline_id"], "scenario": scenario,
                "fixture_ids": [item["id"] for item in lab["fixtures"][:count]],
                "issued_at": now.isoformat(), "expires_at": (now + timedelta(minutes=10)).isoformat()}
    return validate(envelope, lab, now=now)


def descriptor(value):
    """Validate the bounded public authoring contract used offline on Kali."""
    if type(value) is not dict or set(value) != {"schema_version", "lab_id", "baseline_id", "fixtures"}:
        raise ValidationError("Unsupported lab authoring descriptor")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValidationError("Unsupported descriptor schema")
    validate_id(value["lab_id"])
    validate_id(value["baseline_id"])
    if type(value["fixtures"]) is not list or not 1 <= len(value["fixtures"]) <= 100:
        raise ValidationError("Descriptor fixture count exceeds its bound")
    ids = []
    for item in value["fixtures"]:
        if type(item) is not dict or set(item) != {"id"}:
            raise ValidationError("Unsupported descriptor fixture record")
        ids.append(validate_id(item["id"]))
    if len(set(ids)) != len(ids):
        raise ValidationError("Duplicate descriptor fixture IDs")
    return value
