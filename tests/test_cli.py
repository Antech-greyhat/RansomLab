import contextlib
import io
import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from ransomlab.cli import main, parser
from ransomlab.core.errors import SafetyError
from ransomlab import scenarios


class CLITests(unittest.TestCase):
    def invoke(self, argv, service=None):
        output, error = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            status = main(argv, service=service)
        return status, output.getvalue(), error.getvalue()

    def test_cli_delegates_and_emits_json(self):
        service = Mock()
        service.create_lab.return_value = {"lab_id": str(uuid4()), "state": "prepared"}
        status, output, error = self.invoke(["lab", "create", "--count", "4", "--size", "128"], service)
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output)["state"], "prepared")
        service.create_lab.assert_called_once_with("Training lab", 4, 128)
        self.assertEqual(error, "")

    def test_safety_failure_has_nonzero_json_error(self):
        service = Mock()
        service.arm.side_effect = SafetyError("Verified disposable guest required")
        status, output, error = self.invoke(["lab", "arm", str(uuid4()), "--snapshot", "clean", "--isolated", "--disposable"], service)
        self.assertEqual(status, 3)
        self.assertEqual(json.loads(error)["error"]["type"], "SafetyError")
        self.assertEqual(output, "")

    def test_offline_kali_composition_needs_no_service(self):
        descriptor = {"schema_version": 1, "lab_id": str(uuid4()), "baseline_id": str(uuid4()), "fixtures": [{"id": str(uuid4())}]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "generated-descriptor.json"
            path.write_bytes(scenarios.canonical(descriptor))
            service = Mock()
            status, output, _ = self.invoke(["scenario", "compose", str(path), "modify_generated"], service)
        self.assertEqual(status, 0)
        value = json.loads(output)
        self.assertEqual(value["lab_id"], descriptor["lab_id"])
        self.assertFalse(service.mock_calls)

    def test_monitor_bounds_fail_before_service_call(self):
        service = Mock()
        status, _, _ = self.invoke(["monitor", str(uuid4()), "--interval", "nan"], service)
        self.assertEqual(status, 2)
        service.monitor.assert_not_called()

    def test_doctor_is_structured_and_does_not_create_a_lab(self):
        status, output, error = self.invoke(["doctor"])
        self.assertEqual(status, 0, error)
        value = json.loads(output)
        self.assertIn("python", value)
        self.assertIn(value["filesystem_gate"], {"blocked", "available_for_preparation"})

    def test_help_documents_fixed_actions(self):
        text = parser().format_help()
        self.assertIn("scenario", text)
        self.assertIn("recover", text)
        self.assertNotIn("--root", text)


if __name__ == "__main__":
    unittest.main()
