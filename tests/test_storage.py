"""Non-impact checks using newly generated disposable filesystem resources.

Replacement, crash and adversarial race exercises need an approved disposable
VM and remain a separate platform acceptance gate.
"""

from pathlib import Path
import os
import tempfile
import unittest

from ransomlab.core.errors import SafetyError, StateError, ValidationError
from ransomlab.storage import LabLease, SafeDirectory, _check_name


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="ransomlab-storage-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)

    def require_native_directory(self):
        try:
            with SafeDirectory(self.root):
                pass
        except SafetyError as error:
            if os.name == "nt" and "Windows error 5" in str(error):
                self.skipTest("BLOCKED: this Windows token cannot pin a storage ancestor; requires a supported disposable VM")
            raise

    def test_new_directory_creates_and_reads_generated_bytes(self):
        self.require_native_directory()
        with SafeDirectory(self.root / "generated", create=True) as directory:
            identity = directory.create("sample.bin", b"synthetic training data")
            self.assertEqual(directory.read("sample.bin", 100), b"synthetic training data")
            self.assertEqual(identity, directory.identity("sample.bin"))
            self.assertEqual(set(identity), {"device", "inode"})
            self.assertEqual(directory.names(), ["sample.bin"])
            self.assertTrue(directory.exists("sample.bin"))
            self.assertFalse(directory.exists("missing.bin"))

    def test_existing_directory_cannot_be_adopted_as_new(self):
        self.require_native_directory()
        with self.assertRaises(SafetyError):
            SafeDirectory(self.root, create=True)

    def test_creation_never_overwrites_an_existing_object(self):
        self.require_native_directory()
        with SafeDirectory(self.root) as directory:
            directory.create("sample.bin", b"original")
            with self.assertRaises(SafetyError):
                directory.create("sample.bin", b"replacement")
            self.assertEqual(directory.read("sample.bin", 100), b"original")

    def test_read_limit_is_enforced_before_returning_content(self):
        self.require_native_directory()
        with SafeDirectory(self.root) as directory:
            directory.create("sample.bin", b"12345")
            with self.assertRaises(SafetyError):
                directory.read("sample.bin", 4)
            for value in [True, -1, 0, "10"]:
                with self.subTest(value=value), self.assertRaises(ValidationError):
                    directory.read("sample.bin", value)

    def test_names_cannot_address_other_objects(self):
        self.require_native_directory()
        rejected = ["../outside.bin", "C:\\outside.bin", "sample.bin:secret", "\\\\host\\sample.bin",
                    "/sample.bin", "sample.bin.", "sample.bin ", "CON.txt", "COM1.bin",
                    "sample", "sample.exe", "a/b.bin", "a\\b.bin", "", ".bin"]
        with SafeDirectory(self.root) as directory:
            for name in rejected:
                with self.subTest(name=name), self.assertRaises(ValidationError):
                    directory.exists(name)

    def test_path_requires_an_absolute_normal_local_directory(self):
        with self.assertRaises(SafetyError):
            SafeDirectory(Path("relative"))

    def test_unexpected_directory_entry_fails_inventory(self):
        self.require_native_directory()
        (self.root / "unexpected").mkdir()
        with SafeDirectory(self.root) as directory:
            with self.assertRaises(SafetyError):
                directory.names()

    def test_hard_link_is_not_an_approved_regular_object(self):
        self.require_native_directory()
        with SafeDirectory(self.root) as directory:
            directory.create("sample.bin", b"synthetic")
        os.link(self.root / "sample.bin", self.root / "alias.bin")
        with SafeDirectory(self.root) as directory:
            with self.assertRaises(SafetyError):
                directory.read("sample.bin", 100)
        self.assertEqual((self.root / "alias.bin").read_bytes(), b"synthetic")

    def test_closed_directory_rejects_operations(self):
        self.require_native_directory()
        directory = SafeDirectory(self.root)
        directory.close()
        directory.close()
        with self.assertRaises(StateError):
            directory.exists("sample.bin")

    def test_lease_prevents_concurrent_entry_and_can_be_reacquired(self):
        self.require_native_directory()
        lease_path = self.root / "lease.flag"
        with LabLease(lease_path):
            with self.assertRaises(StateError):
                with LabLease(lease_path):
                    self.fail("A second mutation lease was granted")
        with LabLease(lease_path):
            pass

    def test_lease_cannot_be_renamed_to_an_arbitrary_file(self):
        with self.assertRaises(ValidationError):
            LabLease(self.root / "arbitrary.bin")

    def test_database_pin_preserves_regular_object_identity(self):
        self.require_native_directory()
        with SafeDirectory(self.root) as directory:
            expected = directory.create("state.db", b"synthetic metadata placeholder")
            with directory.pin("state.db") as actual:
                self.assertEqual(actual, expected)


class FilenameValidationTests(unittest.TestCase):
    def test_rejects_paths_streams_reserved_names_and_executable_suffixes(self):
        for value in ("../outside.bin", "/outside.bin", "a\\b.bin", "a/b.bin",
                      "C:\\outside.bin", "sample.bin:stream", "sample.bin.",
                      "sample.bin ", "CON.txt", "COM1.bin", "sample.exe", "", None):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                _check_name(value)

    def test_accepts_only_generated_flat_object_name_shapes(self):
        for value in ("fixture-a1.bin", "manifest.json", "registry.key", "lease.flag",
                      "report.txt", "state.db", "state.db-journal", "state.db-wal", "state.db-shm"):
            with self.subTest(value=value):
                _check_name(value)


if __name__ == "__main__":
    unittest.main()
