"""SHA-256 primitives over supplied bytes; no pathname or file access."""

import hashlib
import hmac
import re

from .errors import ValidationError

MAX_HASH_BYTES = 20_971_520
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def validate_digest(value):
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ValidationError("SHA-256 digest must be 64 lowercase hexadecimal characters")
    return value


def hash_bytes(data):
    if type(data) is not bytes:
        raise ValidationError("hash input must be bytes")
    if len(data) > MAX_HASH_BYTES:
        raise ValidationError("hash input exceeds its byte ceiling")
    return hashlib.sha256(data).hexdigest()


def hash_chunks(chunks, max_bytes=MAX_HASH_BYTES):
    if type(max_bytes) is not int or not 0 <= max_bytes <= MAX_HASH_BYTES:
        raise ValidationError("hash byte ceiling is invalid")
    if isinstance(chunks, (bytes, bytearray, str)):
        raise ValidationError("chunk input must be an iterable of byte strings")
    try:
        iterator = iter(chunks)
    except TypeError:
        raise ValidationError("chunk input is not iterable") from None
    digest = hashlib.sha256()
    total = 0
    # Empty chunks also consume a bound so a source cannot keep hashing forever.
    for count, chunk in enumerate(iterator, start=1):
        if count > 100_000:
            raise ValidationError("hash chunk count exceeds its ceiling")
        if type(chunk) is not bytes:
            raise ValidationError("hash chunks must be bytes")
        total += len(chunk)
        if total > max_bytes:
            raise ValidationError("hash input exceeds its byte ceiling")
        digest.update(chunk)
    return digest.hexdigest()


def digest_matches(expected, actual):
    return hmac.compare_digest(validate_digest(expected), validate_digest(actual))

