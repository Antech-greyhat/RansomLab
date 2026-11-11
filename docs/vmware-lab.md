# VMware home-lab runbook

**Deferred to Phase 11.** This inherited plan does not authorize VM configuration
or Kali preparation during Phase 0 or other earlier phases. Consult the current
[phase acceptance criteria](requirements.md#phase-acceptance-criteria) before using it.

This is a deployment plan, not a record of deployment. The VMware product/version,
VM allocations, guest builds, isolation rules and competition deadline remain
unknown. Do not fill those fields with assumed facts or mark the lab validated
because its manufacturer string contains VMware.

## Record the environment before execution

| Item | Value to record |
| --- | --- |
| VMware product and version | Pending owner/environment facts |
| Windows 11 guest build, architecture and patch level | Pending |
| Kali release and Python interpreter | Pending |
| Optional Windows 10 forensic guest | Pending; support/security status must be reviewed |
| CPU, RAM, local disk and filesystem per guest | Pending |
| Isolated virtual network type/name and attached adapters | Pending |
| Snapshot labels and restore procedure | Pending |
| Reviewed source revision/artifact identification | Record the reviewed release revision at deployment; Phase 0 baseline is d326a74 |
| Challenge rules, demo duration and date | Pending |

Windows 11 hosts generated fixtures and defence/response services. Kali composes
bounded scenario documents and analyses reviewed synthetic exports. Optional
Windows 10 receives evidence copies for forensic review; it is not another
simulation target by default.

## Isolation and baseline

1. Prepare dedicated disposable guests and non-administrative accounts with no
   personal documents, production credentials or mounted host data.
2. Select a private isolated LAN segment or equivalent where the chosen VMware
   product supports it. Verify that no bridged/NAT adapter or unintended route
   remains attached. A host-only adapter can still reach the host; do not treat
   that name as proof of complete isolation.
3. Disable shared folders, clipboard sharing, drag-and-drop and unnecessary
   integration channels for the exercise. Do not disable antivirus, endpoint
   protection, host firewalls or monitoring products.
4. Establish the reviewed local NTFS storage/account configuration on Windows.
   Run native boundary checks and resolve their failures before file impact.
   Keep generated lab data under its fixed checkout-local root.
5. Create a clean snapshot, record its exact label and rehearse restore before
   the demonstration. Confirm enough disk space for fixtures, clean copies,
   database journals, evidence and the operating system.
6. Document an explicit offline transfer procedure for descriptor/scenario files
   and reviewed evidence. Temporary removable media or another reviewed method
   must not introduce a continuously writable host share. Eject/disconnect it
   before execution where applicable.

The initial delivery design has no listener between Kali and Windows. Manual
scenario import is not permission to open SSH, WinRM, RDP command bridges or a
general upload/execution endpoint.

## Read-only helper scripts

The supplied helpers print a small prerequisite report:

```powershell
.\scripts\windows\lab-preflight.ps1
```

```bash
bash scripts/kali/lab-preflight.sh
```

They inspect Python availability, a VMware manufacturer indicator and effective
elevation. They do not install software, configure networking, alter ACLs or
security tools, create snapshots, run scans or arm the lab. Their successful
exit means only that the Python version command was available; manual checks
remain outstanding. If PowerShell policy blocks the script, follow the guest's
approved policy rather than adding an execution-policy bypass command.

## Execution and recovery rehearsal

Follow [the operator guide](usage.md) using a small generated profile first.
Record the lab/baseline/request/run identifiers, snapshot label, fixture count,
scenario, observed alerts, containment outcome, evidence completeness and final
recovery hashes. Check that the dashboard shows the same committed state as the
CLI. Use synthetic decoys within the disposable validation environment to test
boundary rejection; never use a real external file as a sacrificial target.

The runtime checks the VMware indicator and requires explicit snapshot/isolation/
disposable flags before arming. These assertions are not independently verified
by the runtime. A dishonest assertion, spoofed guest indicator or compromised
administrator is outside the claimed protection model.

After a failed or interrupted exercise, stop scheduling, reconcile uncertain
actions and preserve available evidence. Never force a verified result. If
clean-copy recovery is blocked, retain the failure record and use the previously
tested snapshot rollback. A restored snapshot is operational recovery of the VM,
not proof that application-level recovery succeeded.

## Exit evidence required

A deployment is ready for acceptance only after the supported native filesystem
suite, full guest lifecycle, clean/decrypt recovery paths, interrupted-run path,
isolation observations and snapshot rollback have recorded results. Include
unknowns and failures. The current in-memory fixture workflow tests and local
browser preview do not satisfy this deployment gate.
