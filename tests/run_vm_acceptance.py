"""Explicit native acceptance runner; no environment-variable or force bypass."""

import argparse
import ctypes
import json
import os
from pathlib import Path
import platform
import sys
import unittest

# Running a script by pathname puts tests/, rather than the project, first.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ransomlab import environment
from ransomlab.core.errors import LabError
from test_vm_acceptance import NativeVmAcceptanceTests


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run native RansomLab acceptance inside a disposable VMware guest")
    parser.add_argument("--snapshot", required=True, help="Existing clean snapshot label, checked by the operator")
    parser.add_argument("--isolated", action="store_true", help="Confirm the guest network and host integrations are isolated")
    parser.add_argument("--disposable", action="store_true", help="Confirm the guest and generated exercise data are disposable")
    options = parser.parse_args(argv)
    try:
        attestation = environment.validate_attestation(options.snapshot, options.isolated, options.disposable)
    except LabError as error:
        print(json.dumps({"status": "blocked", "reason": str(error), "tests_started": False}), file=sys.stderr)
        return 2

    NativeVmAcceptanceTests.attestation = attestation
    try:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(NativeVmAcceptanceTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    finally:
        NativeVmAcceptanceTests.attestation = None
    blocked = sum("VmCapabilityBlocked" in detail for _, detail in result.errors)
    if result.failures or len(result.errors) > blocked:
        status = "failed"
    elif blocked:
        status = "blocked"
    else:
        status = "passed" if result.wasSuccessful() and result.testsRun else "blocked"
    summary = {"status": status,
               "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
               "blocked_capabilities": blocked, "skipped": len(result.skipped),
               "python": platform.python_version(), "os": platform.system(), "os_version": platform.version(),
               "pointer_bits": ctypes.sizeof(ctypes.c_void_p) * 8, "snapshot": attestation["snapshot"],
               "scope": "Windows native acceptance" if os.name == "nt" else "Linux storage and modify workflow only"}
    print(json.dumps(summary, sort_keys=True))
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
