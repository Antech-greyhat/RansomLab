"""Bounded cryptography measurements over bytes admitted by the shared service."""
from __future__ import annotations

import platform
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass

from . import __version__, crypto
from .core.errors import DependencyError, SafetyError, StateError, ValidationError
from .core.hashing import digest_matches, hash_bytes


class StudyStopped(StateError):
    """A stop request or measurement deadline was reached at a checkpoint."""


@dataclass(frozen=True)
class StudyPlan:
    count: int = 3
    repetitions: int = 3
    sizes: tuple[int, ...] = ()

    def __post_init__(self):
        if (type(self.count) is not int or not 1 <= self.count <= 100
                or type(self.repetitions) is not int or not 1 <= self.repetitions <= 10
                or type(self.sizes) is not tuple or len(self.sizes) > 8
                or any(type(size) is not int or not 1 <= size <= crypto.MAX_PLAINTEXT for size in self.sizes)
                or tuple(sorted(set(self.sizes))) != self.sizes):
            raise ValidationError("Study requires 1-100 files, 1-10 repetitions and up to 8 increasing payload sizes")

    @property
    def sample_count(self) -> int:
        return self.count * self.repetitions * max(1, len(self.sizes))


def providers() -> dict:
    try:
        import cryptography
        from cryptography.hazmat.backends.openssl.backend import backend
    except ImportError:
        raise DependencyError("Install the reviewed cryptography requirements to run this study") from None
    return {"application": __version__, "python": platform.python_version(),
            "platform": platform.platform(), "cryptography": cryptography.__version__,
            "openssl": backend.openssl_version_text(), "symmetric": crypto.provider_name(),
            "asymmetric": "RSA-2048-OAEP-SHA256", "signature": "Ed25519"}


def _bounded_bytes(value: bytes, maximum: int, *, size: int | None = None) -> None:
    if type(value) is not bytes or len(value) > maximum or size is not None and len(value) != size:
        raise ValidationError("Cryptography study input has an invalid type or length")


def verify_signature(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Verify a bounded public Ed25519 result; malformed inputs are errors."""
    _bounded_bytes(public_key, 32, size=32)
    _bounded_bytes(signature, 64, size=64)
    _bounded_bytes(message, 8192)
    providers()
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except InvalidSignature:
        return False
    except UnsupportedAlgorithm:
        raise DependencyError("The cryptography provider does not support Ed25519") from None
    return True


class CryptoSession:
    """Ephemeral study keys. Private keys and wrapped session keys are never exported."""

    def __init__(self, checkpoint: Callable[[], None]):
        providers()
        from cryptography.exceptions import UnsupportedAlgorithm
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

        self.checkpoint = checkpoint
        try:
            self._wrapping_key, rsa_ns = self._measure(lambda: rsa.generate_private_key(65537, 2048))
            self._signing_key, ed_ns = self._measure(ed25519.Ed25519PrivateKey.generate)
        except UnsupportedAlgorithm:
            raise DependencyError("Required asymmetric cryptography is unavailable") from None
        public = self._wrapping_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self._verify_key = self._signing_key.public_key()
        self.public = {"rsa_public_sha256": hash_bytes(public),
                       "ed25519_public_hex": self._verify_key.public_bytes_raw().hex(),
                       "key_generation_ns": {"rsa": rsa_ns, "ed25519": ed_ns}}

    def close(self) -> None:
        """Release private-key references; Python/provider memory erasure is not guaranteed."""
        self._wrapping_key = self._signing_key = None

    def _measure(self, action: Callable):
        self.checkpoint()
        started = time.perf_counter_ns()
        result = action()
        elapsed = time.perf_counter_ns() - started
        self.checkpoint()
        return result, elapsed

    @staticmethod
    def _padding(context: bytes):
        _bounded_bytes(context, 8192)
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=context)

    def wrap_key(self, key: bytes, context: bytes) -> bytes:
        _bounded_bytes(key, 32, size=32)
        return self._wrapping_key.public_key().encrypt(key, self._padding(context))

    def unwrap_key(self, wrapped: bytes, context: bytes) -> bytes:
        _bounded_bytes(wrapped, 256, size=256)
        try:
            result = self._wrapping_key.decrypt(wrapped, self._padding(context))
        except ValueError:
            raise SafetyError("Wrapped study key authentication failed") from None
        _bounded_bytes(result, 32, size=32)
        return result

    def sample(self, data: bytes, context: bytes) -> dict:
        _bounded_bytes(data, crypto.MAX_PLAINTEXT)
        _bounded_bytes(context, 8191)
        key, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
        timings = {}
        digest, timings["sha256"] = self._measure(lambda: hash_bytes(data))
        wrapped, timings["rsa_wrap"] = self._measure(lambda: self.wrap_key(key, context))
        unwrapped, timings["rsa_unwrap"] = self._measure(lambda: self.unwrap_key(wrapped, context))
        if not secrets.compare_digest(key, unwrapped):
            raise SafetyError("Key wrapping round trip failed")
        ciphertext, timings["aes_encrypt"] = self._measure(lambda: crypto.encrypt(data, key, nonce, context))
        restored, timings["aes_decrypt"] = self._measure(lambda: crypto.decrypt(ciphertext, unwrapped, nonce, context))
        if not digest_matches(digest, hash_bytes(restored)):
            raise SafetyError("Study plaintext failed baseline verification")
        signature, timings["ed25519_sign"] = self._measure(lambda: self._signing_key.sign(context))
        from cryptography.exceptions import InvalidSignature
        try:
            _, timings["ed25519_verify"] = self._measure(lambda: self._verify_key.verify(signature, context))
        except InvalidSignature:
            raise SafetyError("Study signature verification failed") from None

        # Negative checks affect RAM copies only and are excluded from operation timings.
        self.checkpoint()
        try:
            crypto.decrypt(ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]), unwrapped, nonce, context)
        except SafetyError:
            pass
        else:
            raise SafetyError("Tampered ciphertext was accepted")
        self.checkpoint()
        try:
            self.unwrap_key(wrapped, context + b"!")
        except SafetyError:
            pass
        else:
            raise SafetyError("Foreign wrapping context was accepted")
        self.checkpoint()
        if verify_signature(bytes.fromhex(self.public["ed25519_public_hex"]), signature, context + b"!"):
            raise SafetyError("Tampered signed context was accepted")
        self.checkpoint()
        return {"plaintext_bytes": len(data), "ciphertext_bytes": len(ciphertext),
                "plaintext_sha256": digest, "ciphertext_sha256": hash_bytes(ciphertext),
                "signature_hex": signature.hex(), "timings_ns": timings,
                "round_trip_verified": True, "signature_verified": True,
                "negative_checks_passed": 3}


def summarize(samples: list[dict]) -> dict:
    """Aggregate only committed samples; zero-duration clocks yield unknown rates."""
    operations = {}
    for operation in ("sha256", "rsa_wrap", "rsa_unwrap", "aes_encrypt", "aes_decrypt", "ed25519_sign", "ed25519_verify"):
        durations = sorted(item["timings_ns"][operation] for item in samples)
        if not durations:
            continue
        total = sum(durations)
        item = {"samples": len(durations), "total_ns": total, "min_ns": durations[0], "max_ns": durations[-1]}
        middle = len(durations) // 2
        item["median_ns"] = durations[middle] if len(durations) % 2 else (durations[middle - 1] + durations[middle]) / 2
        if operation in {"sha256", "aes_encrypt", "aes_decrypt"}:
            count = sum(row["plaintext_bytes"] for row in samples)
            item.update(plaintext_bytes=count, bytes_per_second=count * 1_000_000_000 / total if total else None)
        operations[operation] = item
    return {"completed_samples": len(samples), "operations": operations}
