"""Authenticated encryption using established providers, not a custom cipher.

Windows uses the installed Microsoft CNG AES-GCM implementation. Other platforms
require an approved installation of cryptography. This module only handles bytes.
The services layer controls generated provenance, key custody and unique nonces.
"""
from __future__ import annotations

import ctypes
import os

from .core.errors import DependencyError, SafetyError, ValidationError

MAX_PLAINTEXT = 1024 * 1024


def provider_name() -> str:
    if os.name == "nt":
        return "Microsoft CNG AES-256-GCM"
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
    except ImportError as exc:
        raise DependencyError("An approved cryptography installation is required on this platform") from exc
    return "cryptography AES-256-GCM"


def _validate(data: bytes, key: bytes, nonce: bytes, aad: bytes, decrypting: bool) -> None:
    if any(type(item) is not bytes for item in (data, key, nonce, aad)):
        raise ValidationError("Cryptographic input must be bytes")
    if len(key) != 32 or len(nonce) != 12 or len(aad) > 8192:
        raise ValidationError("Invalid AES-256-GCM key, nonce or metadata length")
    if len(data) > MAX_PLAINTEXT + (16 if decrypting else 0) or (decrypting and len(data) < 16):
        raise ValidationError("Cryptographic payload length is outside the fixture limit")


def encrypt(data: bytes, key: bytes, nonce: bytes, aad: bytes) -> bytes:
    _validate(data, key, nonce, aad, False)
    return _crypt(data, key, nonce, aad, False)


def decrypt(data: bytes, key: bytes, nonce: bytes, aad: bytes) -> bytes:
    _validate(data, key, nonce, aad, True)
    return _crypt(data, key, nonce, aad, True)


def _crypt(data: bytes, key: bytes, nonce: bytes, aad: bytes, decrypting: bool) -> bytes:
    if os.name == "nt":
        return _windows_gcm(data, key, nonce, aad, decrypting)
    provider_name()
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        cipher = AESGCM(key)
        return (cipher.decrypt if decrypting else cipher.encrypt)(nonce, data, aad)
    except InvalidTag as exc:
        raise SafetyError("Ciphertext authentication failed; no plaintext released") from exc


def _windows_gcm(data: bytes, key: bytes, nonce: bytes, aad: bytes, decrypting: bool) -> bytes:
    # Fixed-width types are essential: Windows ULONG is 32 bits on Win64.
    u32, u64, ptr = ctypes.c_uint32, ctypes.c_uint64, ctypes.c_void_p

    class AuthInfo(ctypes.Structure):
        _fields_ = [("cbSize", u32), ("dwInfoVersion", u32),
                    ("pbNonce", ptr), ("cbNonce", u32),
                    ("pbAuthData", ptr), ("cbAuthData", u32),
                    ("pbTag", ptr), ("cbTag", u32),
                    ("pbMacContext", ptr), ("cbMacContext", u32),
                    ("cbAAD", u32), ("cbData", u64), ("dwFlags", u32)]

    try:
        # LOAD_LIBRARY_SEARCH_SYSTEM32 prevents local DLL search-path hijacking.
        bcrypt = ctypes.WinDLL("bcrypt.dll", winmode=0x00000800)
    except OSError:
        raise DependencyError("The Windows cryptography provider is unavailable") from None
    signatures = {
        "BCryptOpenAlgorithmProvider": [ctypes.POINTER(ptr), ctypes.c_wchar_p, ctypes.c_wchar_p, u32],
        "BCryptSetProperty": [ptr, ctypes.c_wchar_p, ptr, u32, u32],
        "BCryptGetProperty": [ptr, ctypes.c_wchar_p, ptr, u32, ctypes.POINTER(u32), u32],
        "BCryptGenerateSymmetricKey": [ptr, ctypes.POINTER(ptr), ptr, u32, ptr, u32, u32],
        "BCryptEncrypt": [ptr, ptr, u32, ptr, ptr, u32, ptr, u32, ctypes.POINTER(u32), u32],
        "BCryptDecrypt": [ptr, ptr, u32, ptr, ptr, u32, ptr, u32, ctypes.POINTER(u32), u32],
        "BCryptDestroyKey": [ptr],
        "BCryptCloseAlgorithmProvider": [ptr, u32],
    }
    try:
        for name, signature in signatures.items():
            fn = getattr(bcrypt, name)
            fn.argtypes, fn.restype = signature, ctypes.c_int32
    except AttributeError:
        raise DependencyError("The Windows cryptography provider API is unavailable") from None

    def check(status: int) -> None:
        if status != 0:
            if decrypting and status & 0xFFFFFFFF == 0xC000A002:
                raise SafetyError("Ciphertext authentication failed; no plaintext released")
            raise SafetyError("The Windows authenticated-encryption provider rejected the operation")

    algorithm, handle = ptr(), ptr()
    key_buffer = ctypes.create_string_buffer(key)
    key_object = None
    output = source = nonce_buffer = aad_buffer = tag_buffer = None
    operation_succeeded = False
    try:
        check(bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(algorithm), "AES", "Microsoft Primitive Provider", 0))
        mode = ctypes.create_unicode_buffer("ChainingModeGCM")
        check(bcrypt.BCryptSetProperty(algorithm, "ChainingMode", mode, ctypes.sizeof(mode), 0))
        object_size, returned = u32(), u32()
        check(bcrypt.BCryptGetProperty(algorithm, "ObjectLength", ctypes.byref(object_size), 4, ctypes.byref(returned), 0))
        if returned.value != ctypes.sizeof(u32) or not 1 <= object_size.value <= 65536:
            raise SafetyError("Unexpected native key allocation")
        key_object = ctypes.create_string_buffer(object_size.value)
        check(bcrypt.BCryptGenerateSymmetricKey(algorithm, ctypes.byref(handle), key_object, object_size, key_buffer, len(key), 0))
        payload, tag_value = (data[:-16], data[-16:]) if decrypting else (data, bytes(16))
        source = ctypes.create_string_buffer(payload)
        nonce_buffer = ctypes.create_string_buffer(nonce)
        aad_buffer = ctypes.create_string_buffer(aad)
        tag_buffer = ctypes.create_string_buffer(tag_value, 16)
        output = ctypes.create_string_buffer(max(1, len(payload)))
        info = AuthInfo()
        info.cbSize, info.dwInfoVersion = ctypes.sizeof(AuthInfo), 1
        info.pbNonce, info.cbNonce = ctypes.cast(nonce_buffer, ptr), len(nonce)
        info.pbAuthData, info.cbAuthData = ctypes.cast(aad_buffer, ptr), len(aad)
        info.pbTag, info.cbTag = ctypes.cast(tag_buffer, ptr), 16
        written = u32()
        operation = bcrypt.BCryptDecrypt if decrypting else bcrypt.BCryptEncrypt
        check(operation(handle, source, len(payload), ctypes.byref(info), None, 0,
                        output, len(payload), ctypes.byref(written), 0))
        if written.value != len(payload):
            raise SafetyError("Unexpected authenticated-encryption output length")
        result = bytes(output.raw[:written.value])
        operation_succeeded = True
        return result if decrypting else result + bytes(tag_buffer.raw)
    finally:
        cleanup_failed = False
        for function, arguments in (
            (bcrypt.BCryptDestroyKey, (handle,)) if handle.value else (None, ()),
            (bcrypt.BCryptCloseAlgorithmProvider, (algorithm, 0)) if algorithm.value else (None, ()),
        ):
            if function is not None:
                try:
                    cleanup_failed |= function(*arguments) != 0
                except (OSError, ValueError, ctypes.ArgumentError):
                    cleanup_failed = True
        for buffer in (key_buffer, key_object, output, source, nonce_buffer, aad_buffer, tag_buffer):
            if buffer is not None:
                ctypes.memset(buffer, 0, ctypes.sizeof(buffer))
        # Preserve an existing failure (especially authentication failure), but
        # never report success when native resource cleanup itself failed.
        if cleanup_failed and operation_succeeded:
            raise SafetyError("Native cryptography resource cleanup failed")
