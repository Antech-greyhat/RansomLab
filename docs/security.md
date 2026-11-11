# Threat model and safety specification

Phase 0, 2026-11-11. This is the required target contract, not a claim that every
control is implemented or platform-validated. Current evidence is recorded in the
[audit](phase-00-audit.md). No simulations or VM changes are performed in Phase 0.

## Scope, assets and trust

Protect unrelated host/user files, clean recovery data, experiment ownership,
keys, audit records, evidence, and the correctness of research conclusions.
Inputs include local CLI/configuration, data-only scenario documents, filesystem
objects, stored records, and browser requests. Treat each as untrusted until
validated. A marker file, user-supplied path, or VMware manufacturer string is
not sufficient authority.

The trusted computing base is the reviewed application, Python/crypto/SQLite
providers, operating system, dedicated non-elevated account, approved local
filesystem, and operator. Assume no hostile administrator, compromised kernel,
hypervisor, executable, or equally privileged process actively replacing trusted
state. Same-account compromise defeats local keys, manifests, and logical backup
separation; this application is not a security sandbox against that threat.

Even within those assumptions, reject malicious scenario inputs, unexpected files,
symlinks, junctions, aliases, hard links, stale identifiers, replayed requests and
concurrent application mutations. If the platform cannot establish a required
boundary, fail closed. Dedicated disposable storage and reviewed permissions are
prerequisites, not checks to bypass for a demonstration.

## Prohibited functionality

Never implement propagation, persistence, evasion, antivirus/EDR disabling,
credential harvesting, unauthorized data collection, external command-and-control,
arbitrary remote commands, real exfiltration, or unrestricted file encryption.
No scenario scripts, shell expressions, uploaded executables, real malware or
arbitrary directory imports. No production/user files, including negative-test
decoys. No destructive operations beyond generated disposable data.

## Threats, controls and acceptance evidence

| Threat | Required control | Verification / current gap |
| --- | --- | --- |
| Traversal, path-prefix collision, UNC/device/stream aliases | Canonical containment plus component/handle validation; generated object IDs only | Existing storage tests; positive Windows native gate blocked |
| Symlink, junction, hard-link or ancestor replacement | No-follow opens, regular-file and single-link checks, retained identities/handles, revalidation | Native races and all supported filesystems still require acceptance |
| Foreign workspace adoption or manifest replacement | Exclusive generated directory creation; registry ownership and generation; authenticated manifest | Existing HMAC/inventory checks; same-account key replacement outside trust guarantee |
| Replay, stale approval or cross-experiment targeting | Single-use expiring authority bound to experiment, baseline, scenario/config and policy | Existing request expiry/consumption; stronger authorization binding is Phase 1 work |
| Disk, event or staging exhaustion | Admission and per-operation quotas, recovery reserve, bounded parsing | Existing partial quotas; staging/mock/global aggregate budgets planned |
| Crash between file and database changes | Durable intent before I/O, verified result after, explicit interrupted state/reconciliation | Memory failure tests exist; native crash/sidecar recovery unresolved |
| Backup/key/evidence modification by scenario | Capability separation; no scenario write handle to those stores; baseline verification | Current logical separation; narrow capabilities and native permission tests planned |
| Covert real upload through mock transfer | Filesystem-only internal sink, no address or networking configuration | No sink exists yet; reject URL/path/socket options and verify no network access in Phase 3 |
| Fabricated detection or optimistic recovery | Observations separate from intents/labels; attributable alerts; full hash verification | Existing hashes/count rules; measured evaluation and missing-file restoration incomplete |
| Browser access or credential leakage | Loopback, session/token access, Host/Origin checks, escaping, bounded read-only routes | Existing tests pass; fresh server/dependency assurance pending |
| Evidence tampering | Bounded manifest, hashes, provenance, trusted comparison source and explicit partial status | Local hashes are not authenticity or legal admissibility proof |

## Workspace and operation admission

Before any effectful operation, the shared service must:

1. Validate the canonical root against the configured fixed allowlist and approved
   workspace identity. Reject unresolved, network, device, drive-relative and
   ambiguous paths. Creation checks the trusted parent and exclusively creates
   a generated child; it never adopts an existing user directory.
2. Validate registry membership, experiment ID, manifest authenticity, dataset
   generation, policy/config version and caller authority. Unknown schemas fail.
3. Check every ancestor and opened object, rejecting links/reparse points,
   multiple hard links, unsupported mounts, unexpected object types, or identity
   changes. Operate through guarded handles/descriptors, not a later unchecked path.
4. Confirm the object is in the correct capability inventory. Only generated work
   data may be modified; stage/mock operations use separately registered objects.
   Register anticipated notes/renames before execution; unexpected entries halt.
5. Recheck authorization, state, lease, cancellation, time, byte/file/event budgets
   and recovery capacity before each bounded operation.
6. Commit intent, perform bounded I/O, verify actual result, then commit outcome.
   A failure to validate or journal prevents further impact.

Existing Windows storage requires local NTFS and retained ancestor handles.
Current managed-token access fails with Windows error 5; do not elevate, change
unrelated ACLs, or remove checks. Linux uses descriptor-relative no-follow access,
but cannot prevent a hostile same-user actor moving an ancestor between checks.
Unsupported native guarantees block the relevant release scope. See the retained
[filesystem review](implementation/filesystem-boundary.md).

## Resource ceilings

These are upper bounds, not workload targets. Values marked proposed require
implementation and tests before the associated feature runs.

| Resource | Ceiling / floor | Status |
| --- | --- | --- |
| Working inventory | 100 files, 1 MiB/file, 20 MiB plaintext | Existing Policy |
| Run | 100 actions, 300 seconds checked between actions | Existing Policy |
| Audit | 8 KiB/event, 10,000 events, 32 MiB database | Existing Policy |
| Evidence | 64 MiB including reserved incomplete attempts | Existing Policy/service |
| Free storage | At least 128 MiB after admitted allocations | Existing reserve; aggregate accounting to extend |
| Retention | 8 labs; 20 requests/runs per lab | Existing service bounds |
| Staging and mock copies | 20 MiB each/run; at most 100 entries each, counted across retained runs | Proposed Phase 3 |
| Aggregate managed storage | 1 GiB including all retained data, keys, journals, backups and temporary reservations | Proposed; fail admission before exceeding |
| Canary/note/rename plan | Counts against approved inventory and action/byte ceilings | Proposed |

Runtime file framing overhead, duplicate stage/mock copies, temporary bytes and
failed attempts count toward the aggregate budget. A rename or note does not
grant a fresh unbounded allocation. Reserve enough audit and storage capacity
for containment, evidence and recovery before simulation. Do not delete prior
evidence to free space automatically. Time limits are checked at bounded operation
boundaries; they cannot interrupt a blocked kernel I/O call reliably.

## Authorization and interruption

An operator approves the displayed experiment ID, canonical root, generation,
scenario/config hash, policy hash and finite lifetime. One authorization admits
one run. Expiry, cancellation or changed inputs invalidate it; consumption and
run admission are atomic. Import, dashboard startup and prior approval of a
different experiment confer no authority. Existing VMware/non-elevation checks
remain until their replacement is explicitly reviewed.

One mutation lease serializes cooperating services. Containment records a stop
request without waiting for the active run's lease; the coordinator stops new
operations and records acknowledgement. It never kills unrelated processes or
changes network/security settings.

A pending intent or stale active run requires explicit reconciliation. Startup
must not resume work, manufacture success, remove journals, or reuse crypto
nonces. Preserve incomplete artifacts and failure records. If audit/storage is
unavailable, stop impact and issue a bounded redacted diagnostic; do not claim
that an audit record was durably stored. Existing sidecars require offline review.

## Clean copies, crypto and evidence

Generate and hash clean copies before authorizing impact. The simulator receives
no clean/key/evidence write capability. Only trusted preparation/recovery services
may access these stores as needed. In-process capability separation prevents
application mistakes; it is not immutable/offline backup protection against the
same account. Do not advertise ransomware-proof backups without independently
tested access controls.

Use established authenticated crypto providers, fresh per-run keys and unique
nonces, metadata-bound associated data and authentication-before-plaintext.
Asymmetric/key/signature teaching operates on synthetic material only. Keys and
tokens stay outside reports, telemetry and Git. Python/provider memory cannot
guarantee complete zeroization.

Preserve affected data before recovery, recording source revision, capture time,
event cutoff, artifact IDs, sizes, digests and omissions. Retain a trusted manifest
digest separately for independent comparison; a bundle hash stored beside a
tampered bundle is insufficient authenticity evidence. Unknown/unexpected entries,
path-shaped artifact names and mismatched hashes fail verification.

Restoration may write only approved working objects. Verify source hashes first
and the complete baseline after restoration, including missing/corrupt files.
Creating a missing baseline object requires safe exclusive creation and a new
verified identity through the guard; it is not implemented in the current service.
A partial restore or old success is never current full recovery.

## Local double-extortion model

Discovery enumerates the manifest, not the host filesystem. Classification uses
synthetic generator labels/content, never personal data, credentials or scanners.
Staging performs bounded real reads and registered copy writes. The local mock
sink receives those bytes, checks hashes and emits receipts inside the experiment.
No archives need extracting, no socket is opened, and no caller selects a URL,
remote host, upload handler or arbitrary local destination.

Record requested, staged, received and rejected byte/file counts separately.
A request/intention is not evidence of received bytes. Detection may use measured
adapter events and integrity observations, not the scenario's expected labels.
This design supports local transfer-like research; it does not validate network
DLP, cloud egress controls, real exfiltration or remote server security.

## Release and disclosure gates

Unresolved critical/high safety findings, unexplained test failures, or unsupported
boundary claims block the affected release. A skipped native test is incomplete
evidence. Report minimal synthetic reproducers privately to the owner through an
owner-selected channel; do not publish credentials, victim files or private paths.
No public security inbox or disclosure process has been established.

The owner authorized this repository to remain public and the Phase 0 documentation
push on 2026-11-11. No visibility change, public release, deployment, or broader
publication is implied. One reviewed phase at a time remains mandatory.
