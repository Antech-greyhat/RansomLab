"""Native VM acceptance; default discovery skips the explicit execution gate.

Only tests/run_vm_acceptance.py supplies an attestation. Every test rechecks
the production environment gate and uses actual SafeDirectory/EventStore APIs.
No production guard is patched, and no in-memory fixture substitute is used.
"""

import hashlib
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest

from ransomlab import environment
from ransomlab.core.errors import SafetyError
from ransomlab.services import LabService
from ransomlab.storage import SafeDirectory


class VmCapabilityBlocked(RuntimeError):
    """A required VM capability is unavailable; acceptance cannot pass."""


class NativeVmAcceptanceTests(unittest.TestCase):
    attestation = None

    @classmethod
    def setUpClass(cls):
        if cls.attestation is None:
            raise unittest.SkipTest(
                "VM acceptance pending: invoke the explicit VMware runner with snapshot/isolation attestations")
        environment.require_guest(cls.attestation)

    def setUp(self):
        environment.require_guest(type(self).attestation)
        self._temp_base = Path(tempfile.gettempdir()).resolve(strict=True)
        # Explicit cleanup avoids an automatic finalizer deleting a path after
        # our containment check has refused it.
        self._temp_root = Path(tempfile.mkdtemp(prefix="ransomlab-vm-", dir=self._temp_base)).resolve(strict=True)
        self.addCleanup(self._cleanup_owned_directory)
        if self._temp_root.parent != self._temp_base:
            raise SafetyError("Generated VM test directory escaped the expected temporary base")
        self.service = LabService(self._temp_root / "generated-labs")

    def _cleanup_owned_directory(self):
        """Verify the exact resolved target before the only recursive removal."""
        target = self._temp_root
        if not target.exists():
            raise SafetyError("VM test cleanup target disappeared; manual review is required")
        attributes = target.lstat()
        is_reparse = bool(getattr(attributes, "st_file_attributes", 0)
                          & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        resolved = target.resolve(strict=True)
        if (target.is_symlink() or is_reparse or resolved != target
                or resolved.parent != self._temp_base
                or not resolved.name.startswith("ransomlab-vm-")):
            raise SafetyError("Refusing cleanup of a changed or out-of-scope VM test directory")
        shutil.rmtree(resolved)

    def _owned_path(self, name):
        """Resolve both sides of any directory rename inside the owned root."""
        target = self._temp_root / name
        resolved = target.resolve(strict=False)
        if resolved.parent != self._temp_root or target != resolved:
            raise SafetyError("VM test operation is outside its generated directory")
        return target

    def _create_and_stage(self, scenario):
        lab = self.service.create_lab("Native VM acceptance", count=4, size=1024)
        envelope = self.service.create_scenario(lab["lab_id"], scenario)
        self.service.import_scenario(envelope)
        attestation = type(self).attestation
        self.service.arm(lab["lab_id"], attestation["snapshot"],
                         attestation["isolated"], attestation["disposable"])
        return lab, envelope

    def _decoy(self):
        path = self._owned_path("outside-fixture-decoy.bin")
        content = b"Generated sacrificial VM test data; not an application fixture.\n"
        path.write_bytes(content)
        return path, hashlib.sha256(content).hexdigest()

    def test_native_modify_detection_evidence_and_clean_recovery(self):
        decoy, baseline = self._decoy()
        lab, request = self._create_and_stage("modify_generated")
        run = self.service.simulate(lab["lab_id"], request["request_id"])
        self.assertEqual("completed", run["state"])
        impacted = self.service.report(lab["lab_id"])
        self.assertEqual(4, impacted["findings"]["changed"])
        self.assertIn("burst_integrity_change", {item["rule"] for item in impacted["alerts"]})
        evidence = self.service.preserve(lab["lab_id"])
        self.assertEqual("complete", evidence["state"])
        recovered = self.service.recover(lab["lab_id"], mode="clean")
        self.assertTrue(recovered["verified"])
        self.assertEqual(4, recovered["count"])
        result = self.service.report(lab["lab_id"])
        self.assertTrue(result["findings"]["recovery_verified"])
        self.assertEqual({"intact"}, {item["status"] for item in result["fixtures"]})
        self.assertEqual(baseline, hashlib.sha256(decoy.read_bytes()).hexdigest())

    @unittest.skipUnless(os.name == "nt", "Native Microsoft CNG exercise is Windows-only")
    def test_native_authenticated_encryption_and_decrypt_recovery(self):
        decoy, baseline = self._decoy()
        lab, request = self._create_and_stage("encrypt_generated")
        run = self.service.simulate(lab["lab_id"], request["request_id"])
        self.assertEqual("completed", run["state"])
        self.assertEqual(4, self.service.report(lab["lab_id"])["findings"]["changed"])
        evidence = self.service.preserve(lab["lab_id"])
        with self.service._open(lab["lab_id"], readonly=True) as (_, __, path):
            manifest = self.service._verify_evidence(path, evidence)
            self.assertFalse(any(item["name"].endswith(".key") for item in manifest["files"]))
        self.assertTrue(self.service.recover(lab["lab_id"], mode="decrypt")["verified"])
        self.assertEqual("verified", self.service.status(lab["lab_id"])["state"])
        self.assertEqual(baseline, hashlib.sha256(decoy.read_bytes()).hexdigest())

    def test_hardlink_to_generated_external_decoy_is_rejected(self):
        decoy, baseline = self._decoy()
        guarded_path = self._owned_path("hardlink-guard")
        with SafeDirectory(guarded_path, create=True) as guarded:
            try:
                os.link(decoy, guarded_path / "fixture-link.bin", follow_symlinks=False)
            except (OSError, NotImplementedError) as error:
                raise VmCapabilityBlocked(
                    "BLOCKED: required hardlink test could not be prepared on this supported VM filesystem") from error
            self.assertGreater(decoy.stat().st_nlink, 1)
            with self.assertRaises(SafetyError):
                guarded.read("fixture-link.bin", 1024)
            with self.assertRaises(SafetyError):
                guarded.replace("fixture-link.bin", b"This must never replace the decoy")
        self.assertEqual(baseline, hashlib.sha256(decoy.read_bytes()).hexdigest())

    @unittest.skipUnless(os.name == "nt", "Directory share-denial contract is Windows-only")
    def test_held_windows_directory_rejects_rename_and_preserves_identity(self):
        source = self._owned_path("rename-guard")
        destination = self._owned_path("rename-destination")
        content = b"Generated directory-handle protection test.\n"
        with SafeDirectory(source, create=True) as guarded:
            fixture_identity = guarded.create("fixture.bin", content)
            directory_inode = source.stat().st_ino
            try:
                os.rename(source, destination)
            except OSError as error:
                if getattr(error, "winerror", None) not in (5, 32, 33):
                    raise VmCapabilityBlocked(
                        "BLOCKED: rename failed for a reason other than the expected Windows sharing protection") from error
            else:
                self.fail("A held Windows storage directory was renamed")
            self.assertTrue(source.exists())
            self.assertFalse(destination.exists())
            self.assertEqual(directory_inode, source.stat().st_ino)
            self.assertEqual(fixture_identity, guarded.identity("fixture.bin"))
            self.assertEqual(content, guarded.read("fixture.bin", 1024))

        # Verify ordinary rename permission once the protective handles close;
        # otherwise a blanket permission denial could make the first check pass.
        source, destination = self._owned_path("rename-guard"), self._owned_path("rename-destination")
        try:
            os.rename(source, destination)
        except OSError as error:
            raise VmCapabilityBlocked(
                "BLOCKED: ordinary rename permission must be available after guard handles close") from error
        self.assertEqual(directory_inode, destination.stat().st_ino)
        with SafeDirectory(destination) as moved:
            self.assertEqual(fixture_identity, moved.identity("fixture.bin"))
            self.assertEqual(content, moved.read("fixture.bin", 1024))


if __name__ == "__main__":
    unittest.main()
