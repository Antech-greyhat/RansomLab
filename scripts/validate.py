"""Run the ordinary suite and record successes separately from blocked suites."""
from pathlib import Path
import json
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.success_ids = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.success_ids.append(test.id())


def main():
    started = time.perf_counter()
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    result = unittest.TextTestRunner(verbosity=2, resultclass=RecordedResult).run(suite)
    report = {"tests_run": result.testsRun, "passed": len(result.success_ids),
              "failures": len(result.failures), "errors": len(result.errors),
              "skipped_entries": [{"test": str(test), "reason": reason} for test, reason in result.skipped],
              "elapsed_seconds": round(time.perf_counter() - started, 3),
              "native_vm_suite_executed": False,
              "note": "A setUpClass VM-gate skip is a suite entry, not an executed passing test."}
    output = ROOT / "output" / "validation"
    output.mkdir(parents=True, exist_ok=True)
    (output / "tests.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
