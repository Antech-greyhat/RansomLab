"""Environment gates with mocked identity providers; no fixture impact."""

import ctypes
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from ransomlab import environment
from ransomlab.core.errors import SafetyError, ValidationError


class _Function:
    def __init__(self, callback):
        self.callback = callback
        self.calls = 0

    def __call__(self, *arguments):
        self.calls += 1
        return self.callback(*arguments)


class WindowsIdentityTests(unittest.TestCase):
    def provider(self, *, admin=0, thread_token=False, last_error=1008,
                 open_process=1, token_information=1, elevated=0, returned=4, close=1):
        def open_thread(thread, access, open_as_self, target):
            if thread_token:
                target._obj.value = 123
            return int(thread_token)

        def open_primary(process, access, target):
            if open_process:
                target._obj.value = 456
            return open_process

        def query(token, information_class, value, length, size):
            self.assertEqual(20, information_class)
            self.assertEqual(4, length)
            value._obj.value = elevated
            size._obj.value = returned
            return token_information

        kernel = SimpleNamespace(GetCurrentThread=_Function(lambda: 2),
                                 GetCurrentProcess=_Function(lambda: 1),
                                 CloseHandle=_Function(lambda token: close))
        security = SimpleNamespace(OpenThreadToken=_Function(open_thread),
                                   OpenProcessToken=_Function(open_primary),
                                   GetTokenInformation=_Function(query))
        shell = SimpleNamespace(IsUserAnAdmin=_Function(lambda: admin))
        libraries = {"kernel32.dll": kernel, "advapi32.dll": security, "shell32.dll": shell}

        def load(name, **options):
            self.assertEqual(0x00000800, options["winmode"])
            return libraries[name]

        patches = (patch("ctypes.WinDLL", side_effect=load, create=True),
                   patch("ctypes.set_last_error", create=True),
                   patch("ctypes.get_last_error", return_value=last_error, create=True))
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        return kernel, security, shell

    def test_standard_process_token_must_be_verified_and_closed(self):
        kernel, security, _ = self.provider()
        self.assertTrue(environment._windows_unprivileged())
        self.assertEqual(1, security.OpenProcessToken.calls)
        self.assertEqual(1, kernel.CloseHandle.calls)

    def test_effective_thread_token_takes_precedence(self):
        kernel, security, _ = self.provider(thread_token=True, elevated=1)
        self.assertFalse(environment._windows_unprivileged())
        self.assertEqual(0, security.OpenProcessToken.calls)
        self.assertEqual(1, kernel.CloseHandle.calls)

    def test_admin_membership_rejected_before_token_queries(self):
        kernel, security, _ = self.provider(admin=1)
        self.assertFalse(environment._windows_unprivileged())
        self.assertEqual(0, security.OpenThreadToken.calls)
        self.assertEqual(0, kernel.CloseHandle.calls)

    def test_unexpected_thread_query_error_does_not_fall_back(self):
        _, security, _ = self.provider(last_error=5)
        self.assertFalse(environment._windows_unprivileged())
        self.assertEqual(0, security.OpenProcessToken.calls)

    def test_process_open_failure_is_not_unprivileged(self):
        self.provider(open_process=0)
        self.assertFalse(environment._windows_unprivileged())

    def test_token_query_failure_is_not_unprivileged(self):
        kernel, _, _ = self.provider(token_information=0)
        self.assertFalse(environment._windows_unprivileged())
        self.assertEqual(1, kernel.CloseHandle.calls)

    def test_invalid_token_information_size_rejected(self):
        self.provider(returned=0)
        self.assertFalse(environment._windows_unprivileged())

    def test_cleanup_failure_prevents_acceptance(self):
        self.provider(close=0)
        self.assertFalse(environment._windows_unprivileged())

    def test_unavailable_native_provider_fails_closed(self):
        with patch("ctypes.WinDLL", side_effect=OSError("native failure"), create=True):
            self.assertFalse(environment._windows_unprivileged())


class EnvironmentTests(unittest.TestCase):
    def test_posix_effective_uid(self):
        for identity, expected in ((0, False), (1000, True), (-1, False), (True, False)):
            with self.subTest(identity=identity), patch.object(environment.os, "name", "posix"), patch.object(
                    environment.os, "geteuid", return_value=identity, create=True):
                self.assertEqual(expected, environment.unprivileged_process())
        with patch.object(environment.os, "name", "posix"), patch.object(
                environment.os, "geteuid", side_effect=OSError("query failed"), create=True):
            self.assertFalse(environment.unprivileged_process())

    def test_attestation_requires_guest_and_non_elevation(self):
        with patch.object(environment, "vmware_guest", return_value=True), patch.object(
                environment, "unprivileged_process", return_value=False):
            with self.assertRaisesRegex(SafetyError, "non-elevated"):
                environment.validate_attestation("synthetic-snapshot", True, True)
        with patch.object(environment, "vmware_guest", return_value=False), patch.object(
                environment, "unprivileged_process", return_value=True):
            with self.assertRaises(SafetyError):
                environment.validate_attestation("synthetic-snapshot", True, True)

    def test_arm_and_execution_both_recheck_the_gate(self):
        with patch.object(environment, "vmware_guest", return_value=True), patch.object(
                environment, "unprivileged_process", return_value=True):
            attestation = environment.validate_attestation("synthetic-snapshot", True, True)
        with patch.object(environment, "vmware_guest", return_value=True), patch.object(
                environment, "unprivileged_process", return_value=False):
            with self.assertRaises(SafetyError):
                environment.require_guest(attestation)

    def test_snapshot_and_confirmation_contracts(self):
        with self.assertRaises(ValidationError):
            environment.validate_attestation("../unsafe", True, True)
        with self.assertRaises(SafetyError):
            environment.validate_attestation("snapshot", 1, True)
        with self.assertRaises(SafetyError):
            environment.require_guest(None)


if __name__ == "__main__":
    unittest.main()
