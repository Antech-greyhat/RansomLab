# Native VM acceptance plan

This is a retained future acceptance procedure, not a Phase 0 execution step.
The current [test strategy](../requirements.md#test-strategy) separates approved
native test runners from Phase 11 home-lab deployment. Do not configure the user's
VMware or Kali environment during earlier phases.

Status: authored, **not executed on a VM**. Default discovery intentionally skips the explicit VM acceptance gate. Neither that skip nor the in-memory service tests establish native filesystem, VM isolation or end-to-end deployment acceptance.

## Preconditions

The initial complete target is a supported Windows 11 VMware guest using local NTFS storage and a non-elevated dedicated account. The operator must first verify a clean snapshot, a disposable dataset/guest, isolated networking, disabled writable host shares and inappropriate clipboard/drag-and-drop integrations, and enough free space for the application's configured reserve. Guest manufacturer detection does not prove those external settings; the snapshot/isolation/disposable flags record the operator's confirmation.

Use the repository and existing approved runtime in the guest. No package installation is performed by this runner. Windows cryptography uses the reviewed Microsoft CNG provider. Kali's runner scope covers its supported native storage and modify/clean-recovery workflow; Windows-specific tests are outside that scope, and Linux authenticated encryption remains dependent on a separately approved provider installation and equivalent validation.

## Execute explicitly in the prepared guest

From the repository root:

```text
python tests/run_vm_acceptance.py --snapshot clean-ransomlab-baseline --isolated --disposable
```

Use the label of the snapshot that actually exists. The runner validates the production VMware and non-elevated-identity gates before starting any test. It supplies the accepted attestation to the test class only in the current process; each test and each service arming/execution path rechecks the production environment gate. There is no environment-variable, `--force`, mock-provider or arbitrary-workspace override.

Default discovery is safe to run without requesting native impact:

```text
python -m unittest discover -s tests -p "test_vm_acceptance.py" -v
```

That command reports an explicit skip because no runner attestation was supplied, even if executed in a VM. Do not count the skipped class as passed VM acceptance.

## Required native cases

| Case | Actual operations | Required outcome |
| --- | --- | --- |
| Modify → detect → preserve → recover | Real generated fixture files, real guarded writes, SQLite intents/results, alerts, evidence and clean-copy recovery | All expected hashes restored; generated external decoy unchanged; report truthfully verifies recovery |
| Encrypt → preserve → decrypt on Windows | Real CNG encryption of generated fixture files; verified evidence and authenticated decryption recovery | Complete round trip; key files absent from evidence inventory; external decoy unchanged |
| Hardlink boundary | Hardlink under a generated guarded directory to a sacrificial decoy elsewhere in the enclosing test directory | Read and write through the alias rejected before impact; decoy hash unchanged |
| Windows held-directory rename | Rename attempt while guarded ancestor handles are open, followed by an ordinary rename after close | Held rename denied; bytes and identities remain stable; post-close rename succeeds to rule out a blanket permission failure |

The decoy is outside the application's fixture area but remains inside the newly generated disposable test directory. Tests must never use a personal, system, incident or pre-existing host file as a decoy. No test imports a memory fixture adapter or patches production safety guards.

Each case owns a newly created `ransomlab-vm-...` directory under the guest's resolved temporary base. Explicit cleanup checks that the exact resolved target is still that owned direct child, with no symlink/reparse replacement, before recursively removing it. There is no automatic cleanup finalizer that can bypass refusal. Both sides of directory renames remain inside the owned test directory. A changed cleanup target is retained for manual review and fails acceptance.

## Results and blocked capabilities

The runner prints verbose test results plus a JSON summary containing scope, runtime/OS versions, pointer width, snapshot label and pass/failure/error/skip counts. Capture this output with the milestone's test evidence and record the repository revision or uncommitted working-tree identity used. Do not commit the runtime workspaces, keys or raw private evidence.

- Exit `0`: all executed cases passed for the reported scope. Check skip reasons before claiming wider platform support.
- Exit `1`: a test failed or a required capability was blocked. A `VmCapabilityBlocked` error is a blocked acceptance gate, not a skip or successful test.
- Exit `2`: arguments or the actual VMware/non-elevated/attestation gate prevented tests from starting.

For supported Windows execution, hardlink or ordinary-rename permission failures must remain blocked/errors; do not change expectations or skip those cases to get a green result. Fix the disposable test environment or narrow support through explicit owner review. A Windows-only test skipped on Linux does not establish Windows acceptance.

Before declaring home-lab deployment complete, attach the actual run output, independently checked isolation/snapshot evidence, and recovery results. These four cases complement rather than replace the broader unit, fault-injection, regression and operating-system boundary suites. They do not prove freedom from all races, power-loss failures, provider defects or same-account/admin tampering.
