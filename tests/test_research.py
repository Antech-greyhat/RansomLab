"""Cryptography studies use generated memory fixtures and disposable SQLite records."""
import builtins
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ransomlab import crypto, research, scenarios
from ransomlab.cli import main, markdown_report
from ransomlab.core.config import Policy
from ransomlab.core.errors import DependencyError, SafetyError, StateError, ValidationError
from ransomlab.core.hashing import hash_bytes
from ransomlab.services import LabService
from memory_fixtures import MemoryDirectory, MemoryLease


HAS_CRYPTOGRAPHY = importlib.util.find_spec("cryptography") is not None


class StudyContractTests(unittest.TestCase):
    def test_invalid_plans_rejected_before_any_fixture_access(self):
        for values in ((True, 1, ()), (0, 1, ()), (101, 1, ()), (1, False, ()),
                       (1, 11, ()), (1, 1, [64]), (1, 1, (64, 64)),
                       (1, 1, (128, 64)), (1, 1, (0,)), (1, 1, (True,)),
                       (1, 1, (crypto.MAX_PLAINTEXT + 1,)), (1, 1, tuple(range(1, 10)))):
            with self.subTest(values=values), self.assertRaises(ValidationError):
                research.StudyPlan(*values)
        self.assertEqual(research.StudyPlan(2, 3, (64, 128)).sample_count, 12)

    def test_missing_dependency_has_a_redacted_error(self):
        original = builtins.__import__

        def without_provider(name, *args, **kwargs):
            if name == "cryptography" or name.startswith("cryptography."):
                raise ImportError("private dependency marker")
            return original(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=without_provider):
            with self.assertRaises(DependencyError) as caught:
                research.providers()
        self.assertNotIn("private dependency marker", str(caught.exception))

    def test_summary_uses_measured_durations_and_unknown_zero_clock_rate(self):
        names = ("sha256", "rsa_wrap", "rsa_unwrap", "aes_encrypt", "aes_decrypt", "ed25519_sign", "ed25519_verify")
        samples = [{"plaintext_bytes": 64, "timings_ns": dict.fromkeys(names, duration)} for duration in (10, 30)]
        summary = research.summarize(samples)
        self.assertEqual(summary["completed_samples"], 2)
        self.assertEqual(summary["operations"]["aes_encrypt"]["median_ns"], 20)
        self.assertEqual(summary["operations"]["aes_encrypt"]["bytes_per_second"], 128 * 1e9 / 40)
        self.assertNotIn("bytes_per_second", summary["operations"]["rsa_wrap"])
        samples[0]["timings_ns"] = dict.fromkeys(names, 0)
        self.assertIsNone(research.summarize(samples[:1])["operations"]["sha256"]["bytes_per_second"])
        self.assertEqual(research.summarize([]), {"completed_samples": 0, "operations": {}})


@unittest.skipUnless(HAS_CRYPTOGRAPHY, "Install requirements-crypto.txt for asymmetric study tests")
class AsymmetricTests(unittest.TestCase):
    def setUp(self):
        self.session = research.CryptoSession(lambda: None)
        self.addCleanup(self.session.close)

    def test_rfc8032_ed25519_empty_message_vector_and_tampering(self):
        public = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        signature = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
                                  "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        self.assertTrue(research.verify_signature(public, signature, b""))
        self.assertFalse(research.verify_signature(public, signature, b"changed"))
        self.assertFalse(research.verify_signature(bytes(32), signature, b""))
        for args in ((public[:-1], signature, b""), (public, signature[:-1], b""),
                     (public, signature, b"a" * 8193), (bytearray(public), signature, b"")):
            with self.assertRaises(ValidationError):
                research.verify_signature(*args)

    def test_rsa_wrap_rejects_tampering_foreign_context_and_foreign_key(self):
        key, context = bytes(range(32)), b"generated-fixture-context"
        wrapped = self.session.wrap_key(key, context)
        self.assertEqual(self.session.unwrap_key(wrapped, context), key)
        for value, label in ((wrapped[:-1] + bytes([wrapped[-1] ^ 1]), context), (wrapped, context + b"!")):
            with self.assertRaises(SafetyError):
                self.session.unwrap_key(value, label)
        other = research.CryptoSession(lambda: None)
        try:
            with self.assertRaises(SafetyError):
                other.unwrap_key(wrapped, context)
        finally:
            other.close()
        for value in (b"short", bytearray(32)):
            with self.assertRaises(ValidationError):
                self.session.wrap_key(value, context)
        with self.assertRaises(ValidationError):
            self.session.unwrap_key(wrapped[:-1], context)

    def test_sample_has_verified_results_and_fresh_ciphertext_without_secret_exports(self):
        data, context = b"generated synthetic payload", b"study-context"
        first = self.session.sample(data, context)
        second = self.session.sample(data, context)
        self.assertEqual(first["plaintext_sha256"], hash_bytes(data))
        self.assertNotEqual(first["ciphertext_sha256"], second["ciphertext_sha256"])
        self.assertTrue(first["round_trip_verified"])
        self.assertEqual(first["negative_checks_passed"], 3)
        self.assertTrue(research.verify_signature(bytes.fromhex(self.session.public["ed25519_public_hex"]),
                                                 bytes.fromhex(first["signature_hex"]), context))
        self.assertEqual(set(first), {"plaintext_bytes", "ciphertext_bytes", "plaintext_sha256", "ciphertext_sha256",
                                     "signature_hex", "timings_ns", "round_trip_verified", "signature_verified", "negative_checks_passed"})
        self.assertTrue(all(value >= 0 for value in first["timings_ns"].values()))
        self.session.close()
        self.assertIsNone(self.session._wrapping_key)
        self.assertIsNone(self.session._signing_key)


@unittest.skipUnless(HAS_CRYPTOGRAPHY, "Install requirements-crypto.txt for study workflows")
class StudyServiceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ransomlab-study-")
        self.addCleanup(temporary.cleanup)
        MemoryDirectory.entries.clear()
        MemoryLease.locks.clear()
        for target, value in (("ransomlab.services.SafeDirectory", MemoryDirectory),
                              ("ransomlab.services.LabLease", MemoryLease),
                              ("ransomlab.environment.vmware_guest", lambda: True),
                              ("ransomlab.environment.unprivileged_process", lambda: True)):
            task_patch = patch(target, value)
            task_patch.start()
            self.addCleanup(task_patch.stop)
        self.service = LabService(Path(temporary.name) / "lab-data")
        self.lab = self.service.create_lab("Cryptography study", 4, 128)
        self.lab_id = self.lab["lab_id"]

    def arm(self):
        return self.service.arm(self.lab_id, "generated-test-snapshot", True, True)

    def test_completed_study_persists_verified_samples_and_leaves_inventory_unchanged(self):
        before = {path: {name: bytes(value[0]) for name, value in files.items()}
                  for path, files in MemoryDirectory.entries.items() if path.endswith(("work", "clean", "keys"))}
        self.arm()
        study = self.service.crypto_study(self.lab_id, 2, 2, (64, 128))
        self.assertEqual(study["state"], "completed")
        self.assertEqual(study["summary"]["completed_samples"], 8)
        self.assertEqual(study["policy"], Policy().to_dict())
        for sample in study["samples"]:
            self.assertTrue(research.verify_signature(bytes.fromhex(study["public_keys"]["ed25519_public_hex"]),
                                                     bytes.fromhex(sample["signature_hex"]), scenarios.canonical(sample["signed_context"])))
        history = self.service.crypto_studies(self.lab_id)
        self.assertEqual(history, [study])
        self.assertEqual(self.service.report(self.lab_id)["crypto_studies"], history)
        self.assertEqual(self.service.status(self.lab_id)["state"], "prepared")
        for path, files in before.items():
            self.assertEqual(files, {name: bytes(value[0]) for name, value in MemoryDirectory.entries[path].items()})
        events = self.service.report(self.lab_id)["events"]
        samples = [event for event in events if event["kind"] == "crypto.sample"]
        self.assertEqual(len(samples), 8)
        self.assertEqual(samples[0]["details"]["sha256"], hash_bytes(scenarios.canonical(study["samples"][0])))
        with self.assertRaises(SafetyError):
            self.service.crypto_study(self.lab_id, 1, 1)

    def test_arming_expiry_and_environment_checked_again_at_admission(self):
        with self.assertRaises(SafetyError):
            self.service.crypto_study(self.lab_id, 1, 1)
        self.arm()
        with self.service._open(self.lab_id) as (lab, store, __):
            arm = store.get_state("arm")
            arm["expires_at"] = "2000-01-01T00:00:00+00:00"
            self.service._event(store, lab, "run.armed", updates={"arm": arm})
        with self.assertRaises(SafetyError):
            self.service.crypto_study(self.lab_id, 1, 1)
        self.arm()
        with patch("ransomlab.environment.vmware_guest", return_value=False), self.assertRaises(SafetyError):
            self.service.crypto_study(self.lab_id, 1, 1)
        self.assertEqual(self.service.crypto_studies(self.lab_id), [])

    def test_invalid_counts_sizes_and_resource_limits_do_not_consume_arming(self):
        self.arm()
        for args in ((5, 1, ()), (4, 10, (32, 64, 128)), (1, 1, (129,)), (True, 1, ())):
            with self.subTest(args=args), self.assertRaises(ValidationError):
                self.service.crypto_study(self.lab_id, *args)
        self.assertEqual(self.service.status(self.lab_id)["state"], "armed")
        self.service.policy = Policy(max_events=10)
        with self.assertRaises(SafetyError):
            self.service.crypto_study(self.lab_id, 1, 1)
        self.assertEqual(self.service.crypto_studies(self.lab_id), [])

    def test_retention_ceiling_preserves_authorization(self):
        self.arm()
        with self.service._open(self.lab_id) as (lab, store, __):
            self.service._event(store, lab, "run.armed", updates={"studies": ["retained"] * 20})
        with self.assertRaises(SafetyError):
            self.service.crypto_study(self.lab_id, 1, 1)
        self.assertEqual(self.service.status(self.lab_id)["state"], "armed")

    def test_empty_and_closed_experiments_cannot_run_studies(self):
        draft = self.service.create_experiment("Empty")
        with self.assertRaises(StateError):
            self.service.crypto_study(draft["experiment_id"], 1, 1)
        self.service.close_experiment(self.lab_id)
        with self.assertRaises(StateError):
            self.service.crypto_study(self.lab_id, 1, 1)

    def test_changed_fixture_clean_copy_and_foreign_identity_fail_closed(self):
        name = self.lab["fixtures"][0]["name"]
        for area in ("work", "clean"):
            self.arm()
            with MemoryDirectory(self.service.root / self.lab_id / area) as directory:
                original = directory.read(name, 128)
                directory.replace(name, b"synthetic corruption")
                with self.assertRaises(SafetyError):
                    self.service.crypto_study(self.lab_id, 1, 1)
                directory.replace(name, original)
        self.arm()
        work = str(self.service.root / self.lab_id / "work")
        MemoryDirectory.entries[work][name][1]["inode"] += 1
        with self.assertRaises(SafetyError):
            self.service.crypto_study(self.lab_id, 1, 1)
        self.assertEqual(self.service.crypto_studies(self.lab_id), [])

    def test_containment_keeps_only_committed_samples(self):
        self.arm()
        original = research.CryptoSession.sample
        count = 0

        def stop_after_second(session, *args):
            nonlocal count
            result = original(session, *args)
            count += 1
            if count == 2:
                self.service.contain(self.lab_id)
            return result

        with patch.object(research.CryptoSession, "sample", stop_after_second):
            result = self.service.crypto_study(self.lab_id, 1, 3)
        self.assertEqual(result["state"], "contained")
        self.assertEqual(result["reason"], "operator_requested")
        self.assertEqual(result["summary"]["completed_samples"], 1)
        self.assertIsNone(self.service.status(self.lab_id)["active_study"])
        self.service.close_experiment(self.lab_id)

    def test_stop_racing_sample_commit_is_contained_without_uncommitted_results(self):
        self.arm()
        original = self.service._event

        def signal_stop(store, lab, kind, **kwargs):
            if kind == "crypto.sample":
                self.service.contain(self.lab_id)
            return original(store, lab, kind, **kwargs)

        with patch.object(self.service, "_event", side_effect=signal_stop):
            result = self.service.crypto_study(self.lab_id, 1, 1)
        self.assertEqual(result["state"], "contained")
        self.assertEqual(result["samples"], [])

    def test_deadline_is_checked_before_key_generation(self):
        self.arm()
        with patch("ransomlab.services.time.monotonic", side_effect=[0, 301]):
            result = self.service.crypto_study(self.lab_id, 1, 1)
        self.assertEqual(result["state"], "contained")
        self.assertEqual(result["reason"], "deadline_reached")
        self.assertIsNone(result["public_keys"])

    def test_interruption_and_failed_sample_transaction_record_no_fabricated_result(self):
        self.arm()
        original = self.service._event

        def fail_sample(store, lab, kind, **kwargs):
            if kind == "crypto.sample":
                raise StateError("Synthetic sample commit failure")
            return original(store, lab, kind, **kwargs)

        with patch.object(self.service, "_event", side_effect=fail_sample), self.assertRaises(StateError):
            self.service.crypto_study(self.lab_id, 1, 1)
        result = self.service.crypto_studies(self.lab_id)[0]
        self.assertEqual(result["state"], "interrupted")
        self.assertEqual(result["samples"], [])
        self.arm()
        with patch.object(research.CryptoSession, "sample", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self.service.crypto_study(self.lab_id, 1, 1)
        self.assertEqual(self.service.crypto_studies(self.lab_id)[1]["state"], "interrupted")

    def test_failed_terminal_write_requires_reconciliation_and_blocks_other_mutators(self):
        request = self.service.create_scenario(self.lab_id, "modify_generated", 1)
        self.service.import_scenario(request)
        self.arm()
        self.service.simulate(self.lab_id, request["request_id"])
        self.service.preserve(self.lab_id)
        self.service.recover(self.lab_id)
        self.arm()
        original = self.service._event

        def fail_end(store, lab, kind, **kwargs):
            if kind in {"crypto.completed", "crypto.interrupted"}:
                raise StateError("Synthetic terminal write failure")
            return original(store, lab, kind, **kwargs)

        with patch.object(self.service, "_event", side_effect=fail_end), self.assertRaises(StateError):
            self.service.crypto_study(self.lab_id, 1, 1)
        self.assertEqual(self.service.status(self.lab_id)["state"], "crypto_running")
        for operation in (lambda: self.service.close_experiment(self.lab_id), self.arm,
                          lambda: self.service.validate_experiment(self.lab_id),
                          lambda: self.service.preserve(self.lab_id),
                          lambda: self.service.recover(self.lab_id)):
            with self.assertRaises(StateError):
                operation()
        result = self.service.reconcile(self.lab_id)
        self.assertEqual(result["state"], "interrupted")
        self.assertEqual(result["summary"]["completed_samples"], 1)
        self.assertIsNone(self.service.status(self.lab_id)["active_study"])

    def test_cli_study_history_and_markdown_share_persisted_results(self):
        self.arm()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["crypto", "study", self.lab_id, "--count", "1", "--repetitions", "1", "--sizes", "64", "128"], self.service)
        self.assertEqual(code, 0)
        study = json.loads(output.getvalue())
        self.assertEqual(study["summary"]["completed_samples"], 2)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["crypto", "list", self.lab_id], self.service), 0)
        self.assertEqual(json.loads(output.getvalue()), [study])
        report = markdown_report(self.service.report(self.lab_id))
        self.assertIn(study["study_id"], report)
        self.assertIn("aes_encrypt", report)
        self.assertIn("2 / 2", report)
