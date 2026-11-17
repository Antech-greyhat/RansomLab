# Operator guide

The [README](../README.md) is the quick start. This reference covers configuration,
experiment records, and the generated-data workflow in an approved disposable lab.

## Cryptography studies

Install [the cryptography requirements](installation.md#cryptography-dependencies).
Create generated fixtures and arm the lab using an existing clean snapshot and
verified isolated, disposable VMware guest. Study execution repeats the guest and
non-elevated identity checks and consumes the arming atomically with its start event.

```bash
ransomlab lab create --name "Cryptography study" --count 3 --size 4096
ransomlab lab arm LAB_ID --snapshot clean-baseline --isolated --disposable
ransomlab crypto study LAB_ID --count 3 --repetitions 3 --sizes 64 1024 4096
ransomlab crypto list LAB_ID
ransomlab report LAB_ID --format json
ransomlab report LAB_ID --format markdown
```

The study reads only registered generated fixture objects after checking the
manifest, complete working baseline and clean copies. Each payload is a prefix
of its fixture; omitting `--sizes` uses the full fixture. Working files and clean
copies remain intact. The separate `encrypt_generated` scenario demonstrates
bounded disk ciphertext and authenticated restoration through the existing workflow.

Plans allow 1–100 files, 1–10 repetitions and up to eight strictly increasing
positive payload sizes that fit every selected fixture. The saved resource policy
still applies: at most 100 samples by default, 300 seconds checked between bounded
operations, available audit capacity with recovery reserve, and 20 retained studies.
Re-arm before each new study. No arbitrary paths, algorithms or keys are accepted.

Each verified sample measures SHA-256, RSA-2048-OAEP-SHA256 wrapping/unwrapping of
a fresh 256-bit AES key, AES-256-GCM encryption/decryption with a fresh 96-bit nonce,
and Ed25519 signing/verification. The context binds the lab, baseline, study,
fixture, repetition, payload size and hashes. Negative checks reject modified
ciphertext, a foreign OAEP context and a modified signed context using RAM copies.

JSON results include individual nanosecond timings, total/minimum/maximum/median
durations, and plaintext bytes per second for hashing and AES. Timings exclude
fixture I/O, persistence and negative checks; they include adapter overhead and
are local observations, not production throughput estimates. Zero-duration clocks
produce a null rate. Key-generation timings are separate. Provider/runtime versions,
platform, policy, selected fixtures and baseline identifiers support repeatable
inputs; random ciphertext, signature keys and timings differ between studies.

Only public signature material, hashes, counts and timings are persisted. Private
RSA/Ed25519 keys, AES keys, nonces, wrapped keys, plaintext and ciphertext are not
included in study results. Python/provider memory cannot be guaranteed erased.
The public Ed25519 signature verifies each canonical `signed_context`:

```python
from ransomlab import research, scenarios

public = bytes.fromhex(study["public_keys"]["ed25519_public_hex"])
sample = study["samples"][0]
assert research.verify_signature(
    public, bytes.fromhex(sample["signature_hex"]),
    scenarios.canonical(sample["signed_context"]),
)
```

This is an educational context signature. It does not authenticate all timings or
prove authorship, and a public key supplied in the same report needs independent
trust. Audit sample hashes bind the complete recorded sample to its journal event.

`contain LAB_ID` stops a study at checkpoints; `contained` results retain only
committed samples. Operational failures record `interrupted` when the journal is
available. A failed terminal write leaves `active_study` set and blocks arming,
validation, closure, evidence preservation, recovery and execution until the
stopped worker is reconciled with
`reconcile LAB_ID`. Reconciliation preserves committed samples and marks the study
interrupted; it does not resume keys or fabricate missing measurements. Command
success means a result was returned; inspect its `state` for completion.

## Multistage scenarios and replay

New generated labs include an `artifacts` area. Existing labs from earlier phases
remain valid for their original operations; create a new lab for multistage runs.
Every run owns an exclusively created `<lab>/artifacts/<run-id>` flat directory.
Only the service creates fixed `stage-<fixture-id>.bin`, `mock-<fixture-id>.bin`
and `simulation-note.txt` objects there. No arbitrary source paths, destination
URLs, sockets, upload protocols, note text, scripts or shell actions are accepted.

```bash
ransomlab lab create --name "Multistage study" --count 12 --size 4096
ransomlab scenario create LAB_ID double_extortion_generated --count 12 --stage-count 6 --receive-count 4 --interval-ms 50 > scenario.json
ransomlab scenario import scenario.json
ransomlab lab arm LAB_ID --snapshot clean-baseline --isolated --disposable
ransomlab simulate LAB_ID REQUEST_ID
ransomlab scenario history LAB_ID
ransomlab evidence preserve LAB_ID
ransomlab recover LAB_ID --mode clean
ransomlab report LAB_ID --format markdown
```

`double_extortion_generated` reads only selected manifest IDs and verifies their
actual generated bytes. Synthetic classes are deterministic public/finance/project
labels derived from generator sample indices, not classifications of personal
documents. It then stages the configured prefix of that selection, copies the
configured staged prefix into the local mock destination, applies the existing
fixed content marker to selected working files, and creates a labelled inert note.
The note contains no payment or contact instructions. `benign_copy_generated`
uses discovery, staging and mock copying without modifications or a note; run it
with the same selection/copy limits as a control. Detection evaluation remains
subject to the later monitoring/rule phases.

Scenario schema v1 remains supported for original fixed actions. V2 adds an exact
configuration mapping, scenario implementation version 1 and optional verified
replay parent. `--interval-ms` accepts integer values from 0 to 2000; paced waits
check stop requests in slices no longer than 50 ms. Pacing applies between stages'
individual actions. Original actions omit pacing unless explicitly configured.
Use a 50 ms `modify_generated` trial and a 2000 ms trial to compare actual change
timestamps; the inherited three-file alert remains a count rule, not a rate detector.

Copy counts satisfy `0 <= receive_count <= stage_count <= selected files`. Zero
copy limits model prevented staging/receipts. Default multistage pacing is 50 ms;
default copy counts match the selection. Admission counts each discovery, stage,
receipt, impact and note as a logical action, so a full double-extortion plan with
N selected files costs `4*N+1` actions. The default 100-action limit admits at most
24 files with all stages enabled. Smaller copy limits reduce the cost; all plans
must also fit the saved run-time and audit budget with recovery reserve.
Admission also checks retained evidence capacity for the planned work/artifacts
and a conservative event/manifest allowance before consuming arming.

The application reserves planned artifact bytes/files at run admission. Across
retained runs in one lab, artifact reservations cannot exceed twice the saved
total plaintext limit or `2*max_files + 20` artifact files. Interrupted attempts
keep their reservations. Actual file writes recheck free space. Retention has no
automatic deletion or quota-reset command in this phase; use a fresh disposable
experiment when its ceiling is reached. Clean copies, keys and evidence have
separate capabilities and are never staging destinations.

The run records selected order, configuration, implementation/generator version,
baseline, policy, plan hash and verified discoveries/artifacts. Each artifact has
size, SHA-256, object identity and source fixture ID; receipts mean actual local
copies verified against the generated source. Reports count committed results,
including explicitly marked verified reconciliation results. These are synthetic
exposure observations, not claims of external transfer or measured detector recall.
Evidence preservation includes stage/mock copies and the note in the same verified
bundle as working files and events. Recovery restores working copies and retains
the stage/mock/note evidence and sources.

Use `contain LAB_ID` to stop scheduling. `reconcile LAB_ID` after the worker stops
checks a pending artifact intent against actual names and hashes. A matching copy
becomes a marked reconciliation result; absent copies stay uncounted. Corrupted or
unexpected objects fail closed and keep the pending state for offline review.
Incomplete empty-area preparation can be reconciled without inventing file results.
Preservation, recovery, arming and closure require resolution of pending work.

After preserving and recovering the first run, reissue its imported plan:

```bash
ransomlab scenario replay LAB_ID REQUEST_ID > replay.json
ransomlab scenario import replay.json
ransomlab lab arm LAB_ID --snapshot clean-baseline --isolated --disposable
ransomlab simulate LAB_ID NEW_REQUEST_ID
```

Replay preserves the selected IDs/order and configuration, including an expired
original plan, but creates a fresh expiring request with a verified parent. Import
rejects an unknown parent or changed plan. Execution still needs fresh single-use
arming and a verified working baseline. Compare normalized discoveries, artifacts
and plan hashes; run/request IDs, note hashes, object identities and timestamps
will differ. `scenario history` and JSON `report.runs` expose the durable run history.

## Configuration and experiment records

Use `ransomlab` after installing the package, or `python -m ransomlab` from the
checkout. Both dispatch to the same services as the dashboard.

```bash
ransomlab --config ransomlab.example.toml config check
ransomlab experiment create --name "Integrity study"
ransomlab experiment inspect EXPERIMENT_ID
ransomlab experiment validate EXPERIMENT_ID
ransomlab experiment close EXPERIMENT_ID
```

Create makes an owned metadata-only draft with no dataset. Validation records a
successful workspace/inventory check; it does not authorize execution. Closing
revokes unused arming, preserves metadata, and rejects later mutations. Active or
uncertain work must be reconciled. Affected working files must match the baseline
again and completed runs must have preserved evidence before closure.

Configuration defaults are loaded from `ransomlab.toml` in the source checkout;
an explicit `--config` selects another bounded TOML document. No configuration
can redirect file impact. Reopen with the same or stricter resource policy;
attempts to relax an experiment's saved limits fail. INFO diagnostics are JSON
on stderr; command results remain JSON on stdout.

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

Original scenarios are `encrypt_generated` and `modify_generated`. The latter
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
