# Phase 0 repository audit

Audit date: 2026-11-11. Repository:
[Antech-greyhat/RansomLab](https://github.com/Antech-greyhat/RansomLab).
Baseline main: `d326a744e8e959401ea200c124611a3242b65dba`.
Scope: repository and source inspection, existing tests, architecture and
documentation only. This is not an independent penetration test or release audit.

## Repository and Git findings

The working tree was clean on main at entry. Origin fetch/push both target the
existing repository; refreshed origin/main and GitHub main match the baseline.
There were 58 tracked files, a zero-byte README, a Python package, tests, scripts,
dashboard assets and substantial documentation. No applicable AGENTS.md was found
in the checkout or ancestor directories.

| Item | Observation |
| --- | --- |
| Default branch | main |
| Local and corresponding remote branches | main, feat/docs, feat/scripts, ransomlab, tests |
| New phase branch | phase-00-architecture; name was unused |
| Main history | Script PR #1, documentation PR #2, test PR #3, application PR #4 |
| Main tip | `d326a74`, application import via PR #4, 2026-11-05 |
| Prior application branch | ransomlab at `2bd0cb9`; preserved |
| Open PRs at audit | None |
| GitHub visibility | PUBLIC, confirmed through authenticated repository metadata |
| Main protected flag | false; no protection settings changed |
| Package/build/CI/license | No pyproject.toml, installable packaging metadata, CI workflow or LICENSE file |
| Local hooks | No active hook files observed; no custom core.hooksPath configured |

GitHub metadata was initially blocked by the workspace network sandbox. Retrying
with approved network access succeeded; authentication was usable. Git writes
require approved access because the sandbox exposes .git read-only.

The public visibility conflicted with the initial private-development directive.
The owner explicitly answered **“Keep it public; authorize the Phase 0 documentation
push”** on 2026-11-11. Preserve that scope: no visibility change, release/tag,
deployment, main commit, protection modification or self-merge is authorized.
Main being unprotected does not waive owner review.

## Existing capabilities and technical debt

| Area / evidence | Existing value to preserve | Gap and disposition |
| --- | --- | --- |
| core/config.py, events.py, errors.py | Immutable bounded policy, closed events, explicit failures, canonical UUIDs | General experiment/lifecycle records still use dictionaries; add typed models and explicit validation/closure in Phase 1 |
| core/repository.py | SQLite event/state transactions, read-only opens, conditional controls, quotas | No migration framework; schema v1 only; design offline verified upgrades |
| storage.py | Guarded object access, identities, no-follow native checks and mutation leases | Positive Windows native acceptance blocked; Linux hostile same-user ancestor race documented; do not weaken checks |
| services.py | Coherent shared workflow, intent/result durability, clean copies, evidence and current recovery status | Broad service owns generation, simulation, detection and response; extract incrementally with compatibility tests |
| crypto.py | Established Windows CNG AES-GCM, byte-only interface, known-answer/failure tests | ctypes maintenance burden; portable package absent; no asymmetric/signature research or persisted experiment benchmarks |
| scenarios.py | Strict data-only envelopes, generated IDs, expiry and duplicate handling | Only encrypt_generated and modify_generated; no discovery/classification, staging/mock transfer, canary or note study |
| services.py observation code | Actual file hashes, changed/missing records and simple explainable alerts | burst_integrity_change is a count of at least three changed/missing files, not a rate; no independent watcher health or precision/recall/F1 |
| services.py evidence/recovery | Bounded evidence attempts, manifests, provenance primitives, baseline checks | Missing fixture recreation absent; native crash/recovery not certified; logical backup separation is not OS-enforced immutability |
| cli.py, dashboard.py, server.py | Shared services, JSON/error output, local authenticated read-only views and bounded requests | Deprecated Uvicorn WSGI path; full experiment/research metrics and startup wrapper missing |
| scripts and tests | Existing validation, benchmark and explicit native runner; synthetic memory fixtures | No CI or clean-install matrix; native tests cannot be counted as passed; no Bash start_lab.sh |
| Documentation | Useful operator, provider, filesystem and VM design details | Empty README; stale no-commit/cross-phase directives and unborn-main claims; earlier phase map conflicts with current mandate |
| constraints-dashboard.txt | Exact observed dashboard package inventory | Not a fresh-install lock, source/hash manifest or current advisory/license audit |

## Risk register

Priorities below are engineering/release gates, not invented CVSS scores or proof
of an exploited vulnerability.

| ID | Priority | Finding / required disposition | Phase |
| --- | --- | --- | --- |
| A-01 | High release gate | Native storage positives blocked; adversarial races/crashes and supported filesystem guarantees unverified | 1 safety foundation; native checks through 9 |
| A-02 | High release gate | Same-account trust and logical clean-copy separation do not establish immutable backups | 1 capability design; 7/9 tests |
| A-03 | High correctness gate | Missing working files cannot currently be restored; report failure until safe recreation exists | 7 |
| A-04 | High assurance gate | Dependency provenance/current advisories, non-Windows crypto and clean installation unverified | 2/8/9/10 |
| A-05 | Medium | Broad service/dictionary state, no explicit experiment close or migrations | 1 and incremental later extraction |
| A-06 | Medium | No measured time-window detection or evaluation; current count rule can mislead if called rate detection | 4/5 |
| A-07 | Medium | No new research stage/mock/crypto/signature capabilities; dashboard must not imply them | 2–8 |
| A-08 | Medium | SQLite sidecars require offline review; native interruption/recovery remains unresolved | 1/7/9 |
| A-09 | Medium governance | Empty/stale docs and conflicting phase permissions | Corrected in Phase 0 documentation |
| A-10 | Owner decision | Main currently unprotected; no license selected | Owner manages governance; license before release |

No application defect is silently fixed during this documentation phase. Preserve
existing good code and defer behaviour changes to their reviewed phases.

## Fresh validation

Executed against unchanged application/tests on Windows, Python 3.14.3,
SQLite 3.50.4. Existing Flask 3.1.3 and Uvicorn 0.41.0 were available; cryptography
was not installed. No dependencies were installed.

| Check | Result and limitation |
| --- | --- |
| `python scripts/validate.py` | 101 passed, 0 failures, 0 errors; 111 entered cases, 11 skip entries; runner elapsed 16.308 seconds |
| Storage skips | 10 cases blocked because the Windows token cannot pin an ancestor (Windows error 5) |
| Native VM suite | One class-level skip before four native cases ran; not executed and not passed |
| `python -m ransomlab --help` | Existing subcommands verified |
| `python -m ransomlab doctor` | Completed read-only diagnostics; blocked filesystem, non-elevated identity, no VMware guest, CNG selected |
| `python -m ransomlab serve --help` and `report --help` | Current port and JSON/Markdown/JSONL options confirmed |
| Documentation checker | 18 Markdown files decoded; fences balanced; 65 local links/anchors resolved; 17 README command lines accepted by the existing CLI parser |
| Source syntax and artifact scan | 33 Python files parsed as AST; 60 candidate source files scanned; no matching secret patterns or tracked runtime/secret filenames |
| Diff review | Complete documentation diff reviewed; `git diff --check` passed; application, tests, scripts, assets and dependency pins unchanged |

The ordinary runner stores ignored output/validation/tests.json. Memory fixture
tests use real disposable SQLite metadata but do not prove native file containment.
CNG tests use synthetic RAM data. No file-impact scenario, dashboard server, VM
acceptance runner, VMware/Kali setup or preflight workflow was executed.

The existing [2026-11-04 report](implementation/validation-report.md) is retained
as historical context. Its benchmarks/browser assertions were not rerun in this
phase and are not fresh evidence. The disposable documentation checker and JSON
summary remain under ignored output/validation; they are not new application or
test-suite files. The secret scan is heuristic, not a full history/advisory audit.
CLI parsing does not execute scenarios; Mermaid rendering was not browser-tested.
Commit/PR verification is recorded in the Phase 0 PR and handoff.

## Architecture and migration recommendation

Retain the Python package, shared services, SQLite authority, argparse CLI and
Flask/Jinja views. Extract narrowly scoped storage, simulation, telemetry,
detection, forensics, recovery and reporting services over time. Prefer reviewed
portable cryptography and dedicated WSGI serving at the relevant phase; do not
install or switch providers now. Version configuration, records and scenarios;
make experiment authorization/closure explicit.

The [architecture specification](architecture.md) defines module contracts,
ownership, data models, lifecycle, interruption, metrics and compatibility.
The [safety specification](security.md) defines admission and the filesystem-only
mock destination. The [research catalogue](research-scenarios.md) defines six
reproducible studies. [Requirements](requirements.md) gives acceptance and tests.

Phase 1 must inventory callers, retain existing v1 data and interface behaviour
through explicit adapters, and reject unsupported migration/execution states.
No destructive migration, wholesale rewrite, packaging change or placeholder
implementation is justified by this audit.

## Deliverables and review decisions

Phase 0 supplies the central README, updated architecture/security/requirements,
technology recommendations, contribution workflow, this audit and the research
catalogue. Historical documents receive scope corrections so they cannot authorize
later phases. Application source, tests, scripts, assets and constraints stay intact.

Owner review is required for Phase 0 acceptance and merge before Phase 1.
The proposal recommends portable cryptography, dedicated WSGI serving, explicit
lifecycle/configuration and capability separation; these are reviewable design
decisions, not installed or irreversible changes. License choice remains open
before release. Exact guest/runtime/filesystem support and home-lab details remain
to be supplied and tested in their phases, not configured here.

The public-repository documentation push is already authorized. Do not request it
again. Branch protection remains owner-managed. Stop after the Phase 0 PR;
do not implement Phase 1 while awaiting review.
