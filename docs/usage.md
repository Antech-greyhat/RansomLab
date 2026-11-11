# Operator guide

The [README](../README.md) is the current entry point. This reference documents
inherited commands, not acceptance of the new research scenarios. Phase 0 runs
read-only diagnostics and existing tests only; no VM preparation or file-impact
exercise is performed. Home-lab deployment remains Phase 11.

Run commands from the checkout root. This guide describes the implemented
workflow for an approved disposable lab; it is not evidence that a VM exercise
has already passed. Use `python3` instead of `python` where appropriate on Kali.

Successful data commands emit JSON on stdout; operational errors emit a redacted
JSON error on stderr. Exit codes are 0 for successful command completion, 2 for
invalid input, 3 for a safety rejection, 4 for state/storage failure, 5 for a
missing dependency, and 130 for interruption. Read-only diagnostic commands can
complete successfully while reporting an unavailable gate; inspect their fields.

## Inspect the application

```text
python -m ransomlab --help
python -m ransomlab doctor
python -m ransomlab lab list
python -m ransomlab serve --port 8765
```

The dashboard binds to loopback. Open the token-bearing local URL printed by
the launcher on that machine; treat it as a temporary access credential and do
not put it in screenshots, shell transcripts or reports. The dashboard displays
shared service data and cannot start a simulation, recover files or administer
the host. Stop the local server with Ctrl+C.

Machine roles shown in the dashboard are declared inventory, not live network
discovery or proof that the VMs are reachable. Run status is the latest durable
observation. A crash requires explicit reconciliation; there is no hidden worker
automatically resuming impact.

## Prepare generated fixtures on Windows 11

Complete the [VM preflight](vmware-lab.md) first. Use a normal dedicated guest
account and the validated NTFS storage boundary:

```text
python -m ransomlab lab create --name "Dooms Day exercise" --count 12 --size 4096
python -m ransomlab lab list
python -m ransomlab lab status LAB_ID
```

Replace `LAB_ID` with the generated identifier returned by `lab create`. That
command generates working samples, clean copies and a local signed manifest.
It does not adopt an existing directory or ingest user data.

The policy caps a lab at 100 fixtures, 1 MiB per fixture and 20 MiB total plaintext.
It also bounds actions, event/database/evidence storage and free-space reserves.
The default example is deliberately smaller. Policy limits cannot be enlarged
through a scenario document or CLI override.

If a directory ancestor cannot be pinned, the command fails closed. Do not run
as administrator, alter unrelated ACLs or remove link checks to make a demo pass.
Resolve the supported guest account/filesystem configuration and rerun its
platform validation. The current managed development token has this limitation.

## Compose a local fixed-action scenario

For a Windows-only exercise, create a scenario for the registered lab:

```powershell
$labId = 'REPLACE_WITH_LAB_ID'
python -m ransomlab scenario create $labId encrypt_generated --count 3 |
    Set-Content -LiteralPath scenario.json -Encoding ascii
python -m ransomlab scenario import scenario.json
```

The generated envelope contains ASCII identifiers, action names and timestamps.
The explicit encoding avoids Windows PowerShell 5.1's UTF-16 redirection default.
Keep the `request_id` from the import receipt for the next command. Import only
stages validated data; it does not execute an action.

For the Kali/Windows demonstration, first export a bounded descriptor on Windows:

```powershell
python -m ransomlab scenario describe $labId |
    Set-Content -LiteralPath lab-descriptor.json -Encoding ascii
```

Transfer that descriptor through the reviewed offline process. On Kali:

```bash
python3 -m ransomlab scenario compose lab-descriptor.json encrypt_generated --count 3 > scenario.json
```

Return only the scenario document through that same controlled process, then
import it locally on Windows. The descriptor contains the identifiers needed to
bind the request to the prepared fixture generation; it is not a general remote
execution credential. Do not transfer registry keys, run keys, clean-copy stores
or the complete live lab database to enable scenario composition.

Available scenarios are `encrypt_generated` and `modify_generated`. The latter
applies a fixed same-size content marker to generated working copies. Unknown
actions, extra fields, caller paths, stale generations and expired requests are
rejected. Requests normally expire after ten minutes; compose/import close to
the exercise. Reusing a consumed request does not repeat impact.

## Arm and execute

Only after checking the actual snapshot, disposable guest and isolated network:

```text
python -m ransomlab lab arm LAB_ID --snapshot clean-baseline --isolated --disposable
python -m ransomlab simulate LAB_ID REQUEST_ID
python -m ransomlab lab status LAB_ID
```

Arming requires a VMware guest indicator and a verified non-elevated process,
and records the operator's assertions;
the application does not query VMware to prove that the snapshot exists or that
network isolation is correct. The armed session expires and is consumed by the
run. A previous run must be recovered and verified before another is armed.

Run keys are generated per run. File actions have durable intents and verified
outcomes. Simulation events and observed integrity changes have different
sources. The application performs its own bounded observations as the scenario
progresses; it does not disable or replace external security tooling.

## Monitor, contain and reconcile

```text
python -m ransomlab monitor LAB_ID
python -m ransomlab monitor LAB_ID --watch --interval 2 --samples 10
python -m ransomlab contain LAB_ID
python -m ransomlab reconcile LAB_ID
python -m ransomlab investigate LAB_ID
```

Use a second local terminal for a containment request while a run is active.
Containment requests stop admission and scheduling; the coordinator acknowledges
the stop after the current bounded action. This is not host isolation or
termination of unrelated processes. Small scenarios may finish before a human
can request containment.

The file monitor uses bounded polling. The rule named `burst_integrity_change`
currently reflects three or more changed/missing fixtures, not a measured rate
over a statistical time window. Intentional modifications can therefore alert.
It is an explainable training rule, not a production ransomware classifier.

If a process stops or an outcome is uncertain, inspect status and run `reconcile`
after the prior process has stopped. Reconciliation records the observed pending
file outcome and marks the run interrupted; it does not resume the scenario.
Do not delete lock, journal or pending-state files to force a new run.

## Preserve evidence and recover

```text
python -m ransomlab evidence preserve LAB_ID
python -m ransomlab recover LAB_ID --mode clean
python -m ransomlab report LAB_ID --format json
python -m ransomlab report LAB_ID --format markdown
python -m ransomlab report LAB_ID --format jsonl
```

Evidence is written into a new bounded directory under the managed lab. Review
the receipt and completeness status. Recovery requires preserved evidence and
matching current artifacts so that restoring working copies does not silently
discard unpreserved changes.

For an encryption run with an intact run key, `--mode decrypt` demonstrates
authenticated decryption instead of clean-copy restoration. Both modes require
the complete expected inventory to match its trusted baseline before reporting
verified recovery. Clean copies remain the independent recovery path if a key
is unavailable or ciphertext authentication fails.

Missing fixture objects are an explicit limitation: restoration of a deleted
object is not implemented as an unchecked create operation. Preserve available
evidence, record the failure and use the reviewed VM rollback procedure. A
partial evidence bundle or successful copy of some files is not a verified
recovery result.

Reports contain synthetic indicators, findings, timelines, evidence references
and recovery results. SHA-256 values prove equality only against a trusted
comparison source; they do not make the local bundle tamperproof. Export only
reviewed synthetic material, and keep keys and access tokens out of reports.
The `jsonl` format emits the event timeline as a derivative export; SQLite remains
the authority for local event/state records.
