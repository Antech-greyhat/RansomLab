"""Known-answer tests use synthetic bytes, never filesystem impact."""
import os
import unittest
import ctypes
from unittest.mock import patch

from ransomlab.crypto import MAX_PLAINTEXT, decrypt, encrypt, provider_name
from ransomlab.core.errors import DependencyError, LabError, SafetyError, ValidationError


class _NativeFunction:
    """Delegate real ABI calls, overriding only the selected fault result."""

    def __init__(self, name, native, hook):
        self.name = name
        self.native = native
        self.hook = hook

    @property
    def argtypes(self):
        return self.native.argtypes

    @argtypes.setter
    def argtypes(self, value):
        self.native.argtypes = value

    @property
    def restype(self):
        return self.native.restype

    @restype.setter
    def restype(self, value):
        self.native.restype = value

    def __call__(self, *args):
        status = self.native(*args)
        return self.hook(self.name, args, status)


class _NativeProvider:
    def __init__(self, native, hook):
        self.native = native
        self.hook = hook

    def __getattr__(self, name):
        return _NativeFunction(name, getattr(self.native, name), self.hook)


@unittest.skipUnless(os.name == "nt", "Native CNG test requires Windows")
class CryptoTests(unittest.TestCase):
    def test_nist_aes256_gcm_vector(self):
        ciphertext = encrypt(bytes(16), bytes(32), bytes(12), b"")
        self.assertEqual(ciphertext.hex(),
                         "cea7403d4d606b6e074ec5d3baf39d18"
                         "d0d1c8a799996bf0265b98b5d48ab919")
        self.assertEqual(decrypt(ciphertext, bytes(32), bytes(12), b""), bytes(16))

    def test_aes256_gcm_known_answer_with_aad_and_partial_block(self):
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308" * 2)
        nonce = bytes.fromhex("cafebabefacedbaddecaf888")
        aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        plaintext = bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b39")
        expected = bytes.fromhex(
            "522dc1f099567d07f47f37a32a84427d"
            "643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838"
            "c5f61e6393ba7a0abcc9f662"
            "76fc6ece0f4e1768cddf8853bb2d551b")
        self.assertEqual(expected, encrypt(plaintext, key, nonce, aad))
        self.assertEqual(plaintext, decrypt(expected, key, nonce, aad))

    def test_empty_and_binary_roundtrip(self):
        for value in (b"", bytes(range(256))):
            encrypted = encrypt(value, bytes(range(32)), bytes(range(12)), b"fixture:1")
            self.assertEqual(decrypt(encrypted, bytes(range(32)), bytes(range(12)), b"fixture:1"), value)
        self.assertIn("CNG", provider_name())

    def test_tampering_key_nonce_and_associated_data(self):
        result = encrypt(b"generated fixture", bytes(32), bytes(12), b"run:1")
        for data, key, nonce, aad in (
            (bytes([result[0] ^ 1]) + result[1:], bytes(32), bytes(12), b"run:1"),
            (result[:-1] + bytes([result[-1] ^ 1]), bytes(32), bytes(12), b"run:1"),
            (result[:-1], bytes(32), bytes(12), b"run:1"),
            (result, bytes([1]) * 32, bytes(12), b"run:1"),
            (result, bytes(32), bytes([1]) * 12, b"run:1"),
            (result, bytes(32), bytes(12), b"run:2"),
        ):
            with self.assertRaises(LabError):
                decrypt(data, key, nonce, aad)

    def test_payload_and_aad_boundaries(self):
        value, aad = b"x" * MAX_PLAINTEXT, b"a" * 8192
        result = encrypt(value, bytes(32), bytes(12), aad)
        self.assertEqual(len(value) + 16, len(result))
        self.assertEqual(value, decrypt(result, bytes(32), bytes(12), aad))
        for data, supplied_aad in ((value + b"x", b""), (b"", aad + b"a")):
            with patch("ransomlab.crypto.ctypes.WinDLL") as provider:
                with self.assertRaises(ValidationError):
                    encrypt(data, bytes(32), bytes(12), supplied_aad)
                provider.assert_not_called()

    def test_missing_provider_is_a_dependency_error(self):
        with patch("ransomlab.crypto.ctypes.WinDLL", side_effect=OSError("private-path-marker")):
            with self.assertRaises(DependencyError) as caught:
                encrypt(b"sample", bytes(32), bytes(12), b"")
        self.assertNotIn("private-path-marker", str(caught.exception))

    def test_invalid_native_property_size_fails_and_closes_algorithm(self):
        for bad_size, bad_returned in ((0, 4), (65537, 4), (64, 0), (64, 8)):
            closed = []

            def hook(name, args, status):
                if name == "BCryptGetProperty":
                    ctypes.cast(args[2], ctypes.POINTER(ctypes.c_uint32))[0] = bad_size
                    ctypes.cast(args[4], ctypes.POINTER(ctypes.c_uint32))[0] = bad_returned
                if name == "BCryptCloseAlgorithmProvider":
                    closed.append(True)
                return status

            native = ctypes.WinDLL("bcrypt.dll", winmode=0x00000800)
            with self.subTest(size=bad_size, returned=bad_returned), patch(
                    "ransomlab.crypto.ctypes.WinDLL", return_value=_NativeProvider(native, hook)):
                with self.assertRaises(SafetyError):
                    encrypt(b"sample", bytes(32), bytes(12), b"")
            self.assertEqual([True], closed)

    def test_owned_native_buffers_are_wiped_after_authentication_failure(self):
        original = ctypes.create_string_buffer
        buffers = []

        def capture(*args, **kwargs):
            result = original(*args, **kwargs)
            buffers.append(result)
            return result

        ciphertext = encrypt(b"generated secret fixture", bytes(32), bytes(12), b"lab")
        with patch("ransomlab.crypto.ctypes.create_string_buffer", side_effect=capture):
            with self.assertRaises(SafetyError):
                decrypt(ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]), bytes(32), bytes(12), b"lab")
        self.assertGreaterEqual(len(buffers), 7)
        self.assertTrue(all(bytes(buffer) == bytes(ctypes.sizeof(buffer)) for buffer in buffers))

    def test_cleanup_failure_prevents_success_but_preserves_auth_failure(self):
        for failing_function in ("BCryptDestroyKey", "BCryptCloseAlgorithmProvider"):
            def hook(name, args, status):
                # The actual resource was released; inject the failure status only.
                return -1073741823 if name == failing_function else status

            native = ctypes.WinDLL("bcrypt.dll", winmode=0x00000800)
            ciphertext = encrypt(b"sample", bytes(32), bytes(12), b"")
            with patch("ransomlab.crypto.ctypes.WinDLL", return_value=_NativeProvider(native, hook)):
                with self.assertRaisesRegex(SafetyError, "cleanup"):
                    encrypt(b"sample", bytes(32), bytes(12), b"")
                with self.assertRaisesRegex(SafetyError, "authentication"):
                    decrypt(ciphertext, bytes([1]) * 32, bytes(12), b"")

    def test_invalid_input_rejected(self):
        for key, nonce in ((b"short", bytes(12)), (bytes(32), b"bad")):
            with self.assertRaises(LabError):
                encrypt(b"sample", key, nonce, b"")
        with self.assertRaises(LabError):
            decrypt(b"short", bytes(32), bytes(12), b"")
        for args in (("sample", bytes(32), bytes(12), b""),
                     (b"sample", bytearray(32), bytes(12), b""),
                     (b"sample", bytes(32), bytes(12), None)):
            with self.assertRaises(ValidationError):
                encrypt(*args)


if __name__ == "__main__":
    unittest.main()
