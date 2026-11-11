# Requirements and phase acceptance

Phase 0 baseline, 2026-11-11. This replaces the earlier competition-specific phase
mapping. Existing implementation is preserved but does not waive review of the
new phased requirements. [README](../README.md) is the main laboratory guide.

## Research requirements

| ID | Required outcome | Primary phase / evidence |
| --- | --- | --- |
| R-01 | Create, validate, persist, inspect and close an owned experiment safely | 1; lifecycle/state, reopen and negative-boundary tests |
| R-02 | Hashing, authenticated symmetric and asymmetric crypto, signatures and key-management demonstrations | 2; established provider vectors, tamper rejection, synthetic round trips and timings |
| R-03 | Repeatable bounded discovery, modification, note, staging and filesystem-only mock transfer | 3; actual artifacts/receipts, no external access, replay provenance |
| R-04 | Baseline/metadata, changes, missing/new files, rename attribution, canaries and observer health | 4; independently induced synthetic changes, loss/unknown states |
| R-05 | Configurable rules, correlation, severity, time windows, measured latency and classification | 5; labelled positive/negative trials, precision/recall/FPR/F1 and coverage |
| R-06 | Verifiable evidence, provenance, incident timelines and investigation records | 6; independent manifest checks, tamper/missing tests |
| R-07 | Protected clean copies, restoration and complete recovery validation | 7; restored baseline hashes including safe missing-file restoration and failures |
| R-08 | Shared-core CLI and functional local dashboard, JSON and human-readable reports | 8; consistent service results, authentication and empty/unavailable states |
| R-09 | Experiment comparison, reproducibility, prevention/control evaluation | 3–9; compatible versioned trials, blocked actions separate from missed detections |
| R-10 | Startup preflight, bounded services and clean shutdown without auto-simulation | 8; Bash/Python integration and failure tests |
| R-11 | Unit/integration/end-to-end, security, interruption, regression and dependency assurance | 9; no unresolved critical/high release issues |
| R-12 | Installation, operating guide, troubleshooting, license review and release preparation | 10; commands tested against implemented entry points, explicit release approval |
| R-13 | Previously planned VMware home laboratory | 11 only; owner-approved environment after implementation, review, merge and release preparation |

All operations use generated synthetic data. The mandatory safety requirements
and attack/verification matrix are in [security](security.md). The six scenario
contracts, including benign controls, are in [research scenarios](research-scenarios.md).

## Engineering requirements

Use a shared Python core with typed versioned records, explicit exceptions,
bounded structured logs and SQLite persistence. CLI/dashboard must not duplicate
business logic. Bash serves Linux startup/preparation; PowerShell is limited to
justified Windows-specific tasks. No React or separate frontend build without
explicit approval. No automatic dependency downloads or VM configuration.

Preserve valid source/tests. Refactor by reviewed phase, avoiding empty placeholder
implementations, fake metrics, fabricated results, swallowed errors or removed
safety gates. README remains central; supplementary documents must serve an actual
architecture, safety, research or evidence purpose.

## Phase acceptance criteria

| Phase | Reviewable acceptance |
| --- | --- |
| 0 | Repository/history/config audit; current-versus-target architecture, data/lifecycle contracts, threat model, technology decisions, six scenarios, test strategy and README; documentation checks; correctly attributed commit and PR; no application changes |
| 1 | Package/configuration, typed core models, experiment create/validate/store/inspect/close, shared storage/logging and safety framework pass unit/integration/boundary tests |
| 2 | Established crypto providers and integrity/signature/key demonstrations are bounded, reversible, measured, reproducible and tested on synthetic data |
| 3 | Researcher can run a bounded multistage scenario with actual discovery/stage/mock receipts and durable interruption outcomes; no arbitrary files or external destinations |
| 4 | Real changes to approved generated objects produce normalized observations; canary, rename/missing/new and monitor-health tests establish supported semantics |
| 5 | Versioned rules detect labelled behaviours; positive/negative windows produce auditable metrics, latency and coverage without truth-label leakage |
| 6 | Independent reader can verify evidence and reconstruct the incident; missing, tampered or partial bundles stay explicit |
| 7 | Complete restore matches baseline or identifies every unsuccessful restoration; simulator cannot obtain backup write capability |
| 8 | CLI/dashboard query the same core; real history, alerts, timelines, evidence, recovery and metrics agree; safe startup/shutdown works |
| 9 | Critical tests pass across supported platforms; interrupted/disk-full/concurrency cases pass; no unresolved critical/high security issues |
| 10 | README commands, installation and dependency/license inventories, release notes and limitations are verified; owner explicitly approves release |
| 11 | Approved VMware instructions match supplied environment and demonstrate isolated startup, experiment, investigation and recovery |

Every phase requires its own feature branch, tests, full diff/artifact review,
co-author-verified commit, push and PR against main. Never merge the PR or start
the next phase while review/merge is pending. An unavailable GitHub operation is
a blocker to report, not a reason to claim completion.

## Phase 0 review checklist

- [ ] P0-01: Audit ties findings to the existing main revision, branches, files,
  visibility, protections and actual fresh validation.
- [ ] P0-02: Architecture separates existing behaviour from proposed modules,
  dependencies, records, lifecycle, migrations and interface contracts.
- [ ] P0-03: Safety specifies synthetic provenance, ownership, path/link controls,
  budgets, authorization, backup separation, interruption and mock-destination limits.
- [ ] P0-04: Six scenario specifications include all research/operational fields;
  metric definitions separate truth, telemetry, controls and unavailable evidence.
- [ ] P0-05: README contains only implemented command syntax and clearly gates
  file-impact workflows; setup/startup gaps are disclosed.
- [ ] P0-06: Existing suite and documentation/repository checks are recorded,
  including skipped/blocked native checks and limitations.
- [ ] P0-07: Diff is documentation-only, reviewed for secrets/generated artifacts;
  commit trailer is verified; branch/PR links are supplied.
- [ ] P0-08: Owner reviews and merges; Phase 1 remains unstarted.

Checkboxes are owner acceptance, not automatic claims of signoff. The audit and
PR carry execution results.

## Test strategy

Retain unittest initially: the repository already has useful tests and a structured
runner. Introduce pytest/property-testing only if a later concrete need justifies
dependencies. Distinguish memory adapters from actual native I/O.

| Layer | Meaningful tests and failure cases | Execution boundary |
| --- | --- | --- |
| Documentation/repository | UTF-8, local links/anchors, fences, command parser agreement, diff whitespace, secret/artifact checks, trailer and branch/PR base | Phase 0; no runtime writes beyond validation artifacts |
| Core/lifecycle | Missing/unknown fields, bool-versus-int, invalid IDs, transitions, expired/revoked approval, closure, reopened persistence | Generated metadata and SQLite only |
| Filesystem/security | Traversal/prefix collision, symlink/junction/hard-link, aliases/streams, foreign ownership, inventory replacement, ancestor races, quota edges | Owned disposable fixtures/decoys; native platform required |
| Crypto | Published known answers, wrong key/nonce/AAD/tag, signed-message tamper, size edges, provider failure, nonces across interruption | Synthetic RAM bytes, then guarded synthetic files |
| Simulation | Stage order, fixed operations, real digests/receipts, replay, cancellation, denied paths/destinations, socket/DNS attempts absent | No user data, external service or live malware |
| Telemetry/detection | Independently change/create/rename/delete generated objects, canary touches, benign bursts, slow positives, event loss, duplicate/out-of-order events | Labels hidden from detectors; windows fixed in advance |
| Forensics/recovery | Tampered/missing artifacts, partial preservation, corrupted backup/key, missing working file, post-restore changes, complete hash comparison | Preserve before restoration; never erase failed evidence |
| Failure/concurrency | Before/after intent crash, partial write, result commit failure, disk/journal full, locks, competing containment, stale worker, sidecar substitution | Inject faults in tests; no production safety bypass |
| Interface/integration | CLI/service/dashboard consistency, empty history, errors, auth, Host/Origin, escaping, bounds, startup signals, no auto-run | Loopback/local only |
| Reproducibility | Same generator/config yields same baseline and normalized action plan; fresh IDs/keys/nonces; version incompatibility explicit | Compare semantics with declared timing tolerances |
| Dependency/release | Maintained versions, source/artifact hashes, licenses, advisories, clean environment install and supported OS/Python matrix | Later phase; record review date and unresolved advisories |

Use existing prepared disposable test runners for native acceptance only when
their ownership and environment are approved; do not configure the user's VMware
or Kali during earlier phases. Test scripts must fail closed if prerequisites are
missing. Python 3.13/3.14, Windows/NTFS, and selected Linux filesystems are proposed
targets, not an established support matrix.

Record revision, environment, command, passed/failed/skipped counts and skip
reasons. No blocked/skipped test is a pass. A green ordinary suite does not certify
native containment. Do not rerun with elevated privileges or mocks to turn a
native prerequisite failure into a claimed success.

Existing commands are `python scripts/validate.py` (also emits ignored JSON)
or `python -m unittest discover -s tests -v`. Native acceptance remains a separate
explicit runner described in the retained [VM test plan](implementation/vm-test-plan.md).
No new application tests or runtime code are added in Phase 0.
