"""Validate generated inventory contracts before opening experiment state."""
from __future__ import annotations

from .config import Policy
from .errors import SafetyError, ValidationError
from .events import validate_id
from .hashing import validate_digest
from .models import validate_label, validate_timestamp

MANIFEST_FIELDS = {"schema_version", "lab_id", "baseline_id", "name", "created_at", "generator",
                   "fixtures", "policy", "fixture_count", "bytes_total"}
FIXTURE_FIELDS = {"id", "name", "size", "sha256", "identity", "clean_identity", "sample_index"}


def _integer(value: object, minimum: int, maximum: int) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _identity(value: object) -> bool:
    return (type(value) is dict and set(value) == {"device", "inode"}
            and all(_integer(item, 0, 2**128 - 1) for item in value.values()))


def validate_manifest(value: dict, policy: Policy) -> dict:
    """Retain the v1 wire format; reject malformed, foreign or oversized inventories."""
    try:
        if type(value) is not dict or set(value) != MANIFEST_FIELDS:
            raise ValidationError("Unsupported manifest fields")
        if type(value["schema_version"]) is not int or value["schema_version"] != 1:
            raise ValidationError("Unsupported manifest schema")
        validate_id(value["lab_id"])
        validate_id(value["baseline_id"])
        validate_label(value["name"])
        validate_timestamp(value["created_at"])
        stored = Policy.from_dict(value["policy"])
        for name, limit in stored.to_dict().items():
            current = getattr(policy, name)
            relaxes = current < limit if name == "min_free_bytes" else current > limit
            if relaxes:
                raise ValidationError("Active configuration would relax the experiment policy")
        fixtures = value["fixtures"]
        if type(fixtures) is not list or not _integer(len(fixtures), 0, policy.max_files):
            raise ValidationError("Invalid fixture inventory")
        if value["generator"] not in ("fixture-v1", "empty-v1"):
            raise ValidationError("Unsupported synthetic generator")
        if (value["generator"] == "empty-v1") != (len(fixtures) == 0):
            raise ValidationError("Generator and fixture inventory disagree")
        ids, identities, clean_identities, total = set(), set(), set(), 0
        for index, fixture in enumerate(fixtures):
            if type(fixture) is not dict or set(fixture) != FIXTURE_FIELDS:
                raise ValidationError("Unsupported fixture fields")
            validate_id(fixture["id"])
            validate_digest(fixture["sha256"])
            if (fixture["id"] in ids or fixture["name"] != f"fixture-{fixture['id']}.bin"
                    or not _integer(fixture["size"], 64, policy.max_file_bytes)
                    or not _integer(fixture["sample_index"], 0, policy.max_files - 1)
                    or fixture["sample_index"] != index):
                raise ValidationError("Invalid generated fixture")
            ids.add(fixture["id"])
            for key, seen in (("identity", identities), ("clean_identity", clean_identities)):
                identity = fixture[key]
                if not _identity(identity) or tuple(identity[k] for k in ("device", "inode")) in seen:
                    raise ValidationError("Invalid or duplicate object identity")
                seen.add(tuple(identity[k] for k in ("device", "inode")))
            total += fixture["size"]
        if identities & clean_identities:
            raise ValidationError("Working objects alias clean copies")
        if (not _integer(value["fixture_count"], 0, policy.max_files) or value["fixture_count"] != len(fixtures)
                or not _integer(value["bytes_total"], 0, policy.max_total_bytes) or value["bytes_total"] != total):
            raise ValidationError("Manifest totals exceed policy or disagree with inventory")
        return value
    except (ValidationError, TypeError, KeyError, ValueError):
        raise SafetyError("Generated manifest or active policy failed validation") from None
