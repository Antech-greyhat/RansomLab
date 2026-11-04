# Development build validation report

Prepared 2026-11-04 for Antech-greyhat. Application version: 0.1.0. Source is uncommitted at the owner's direction. This report describes the current local build; it is not a claim that every deployment/release phase is complete.

## Result

**101 test cases passed, with no failures or errors.** The runner entered 111 test cases: 10 native-storage cases were blocked by an unreadable Windows ancestor. A separate VM acceptance class was skipped before its four native cases ran. Consequently unittest reports 11 skipped entries, one of which is a whole-suite gate. These are not 11 successful safety tests.

Executed `python scripts/validate.py`; the run took about 20 seconds. Its generated JSON output was removed during workspace cleanup; rerunning the script recreates `output/validation/tests.json`. The ordinary command `python -m unittest discover -s tests -v` exercises the same discovery suite. Native replacement, power-loss, race and real-guest recovery guarantees remain unverified.

## Delivered files by capability

| Phase / capability | Main created or updated files | Acceptance status |
| --- | --- | --- |
| Foundation | `docs/requirements.md`, `docs/architecture.md`, security/dependency/contribution documentation | Technical references retained; historical planning and approval records removed |
| 1 — Core | `ransomlab/core/{config,errors,events,hashing,repository}.py`, `storage.py`, `crypto.py`, fixture preparation in `services.py`; core/repository/crypto/storage tests | Pure core, journal and CNG byte contracts passed; native filesystem acceptance blocked |
| 2 — Simulation | `scenarios.py`, arming/execution in `services.py`, `environment.py`; scenario/service/environment tests | Data-only import, generated IDs, duplicate handling, environment gates and RAM-fixture execution tested; real VM exercise pending |
| 3 — Defence | Shared observation/correlation services and service/regression tests | Explainable integrity and count-threshold alerts tested; no production detection or latency claim |
| 4 — Response | Shared containment/reconciliation/evidence/recovery/investigation/report services and workflow regressions | RAM-fixture recovery, failed-intent/result, evidence tampering/reservations and stop behaviour tested; native recovery pending |
| 5 — CLI | `cli.py`, `__main__.py`, `tests/test_cli.py` | Help, dispatch, JSON errors, offline Kali composition and diagnostics passed |
| 6 — Dashboard | `dashboard.py`, `server.py`, `templates/*`, `static/*`, dashboard/server tests, `docs/assets/dashboard-preview.png` | Browser preview and real empty-workspace CLI/server integration passed; actual VM telemetry remains pending |
| 7 — QA | `scripts/validate.py`, `scripts/benchmark_core.py`, test suites, guarded native acceptance runner | Available checks passed with explicitly blocked native cases; full supported-platform signoff incomplete |
| 8 — Release preparation | `README.md`, `.gitignore`, `constraints-dashboard.txt`, installation/security/contribution/release docs, `scripts/prepare_review_bundle.py` | Private review preparation only; source/advisory audit, license and public release remain pending |
| 9 — Lab preparation | `scripts/windows/lab-preflight.ps1`, `scripts/kali/lab-preflight.sh`, `docs/vmware-lab.md` | Scripts syntax-checked, not executed; no VM configuration or deployment performed |
| 10 — Competition | `docs/competition.md`, diagrams and synthetic UI preview | Report/demo/presentation/Q&A drafts exist; actual competition rehearsal and exercise evidence await the lab |

Generated review archives are not the current source of truth after documentation cleanup. `python scripts/prepare_review_bundle.py` can create a fresh archive and SHA-256 source inventory when needed. Runtime datasets, keys, databases, browser credentials and VM images are excluded.

## Checks executed

- Core tests cover immutable/closed schemas, integer/boolean ambiguity, hashing vectors, bounded parsing, event serialization and safe error handling.
- Repository tests cover atomic event/metadata writes, rollback, disk-page quotas, event limits, duplicate IDs, locked/corrupt databases, actual read-only opens and atomic control-state checks that prevent overwriting a later stop request.
- CNG tests use published AES-256-GCM vectors, associated data, empty/partial/max-size payloads, wrong keys/nonces/tags, native API failures, cleanup failures and owned-buffer wiping. Inputs stay in RAM.
- Service/regression tests keep all fixture, key and evidence bytes in a test-only memory adapter; only empty directory scaffolding and temporary SQLite metadata touch disk. They cover import/staging, arming, simulation, independent hash observations, alerts, evidence, clean/decrypt recovery, interrupted intents, quota reserves, containment and current-versus-historical verification.
- Dashboard tests cover authentication, Host/Origin/client checks, escaping, cookie/header settings, read-only routes, bounded pagination and actual recovery-state rendering. Request-wrapper tests reject excess headers and oversized chunked bodies before WSGI buffering.
- `python -m compileall -q ransomlab tests scripts` and `node --check ransomlab/static/dashboard.js` passed.
- PowerShell preflight parsing and Bash `-n` syntax checks passed without executing their workflows.
- The original build's documentation passed structural/link checks, including balanced fences and valid decoded text. Source inspection found no shell-execution or recursive-deletion call in application or operational scripts; the separate native test runner confines its cleanup to checked generated temporary paths.
- CLI help and `doctor` completed. Diagnostics reported Python 3.14.3, SQLite 3.50.4, CNG selected, a non-elevated process, no VMware guest detected, and a blocked filesystem gate (Windows error 5).

## Browser and actual server integration

Existing Playwright Core 1.56.1 and cached Chromium revision 1194 exercised a labelled synthetic dashboard at desktop and mobile widths. Authentication, fragment removal, polling, recovery-state transitions and report download worked without page overflow or console errors. The [reviewed screenshot](../assets/dashboard-preview.png) contains synthetic UI data, not a real Windows incident.

The actual `python -m ransomlab serve` launcher was also tested against its empty real workspace. Observed results: locked shell available, unauthenticated API 401, token exchange 204, authenticated lab list 200 with an empty list, forged Host 400, forged Origin 403, oversized body 413 and mutation attempts 405. The runtime lab directory remained absent. All owned servers/browsers were stopped and their listeners closed. No access token was persisted in results or screenshots.

Temporary browser scripts, snapshots and JSON results were removed during workspace cleanup. The reviewed documentation screenshot and the results summarized here are retained.

## Small core performance assessment

Executed `python scripts/benchmark_core.py` with generated RAM data. Median values on this development process were:

| Operation | Workload | Median |
| --- | --- | --- |
| SHA-256 | 1 MiB bytes | 1.204 ms |
| CNG authenticated encryption | 1 MiB, unique nonce per encryption | 3.357 ms |
| CNG authenticated decryption | 1 MiB authenticated ciphertext | 3.467 ms |
| Durable SQLite append | One generated event, FULL synchronous mode | 13.930 ms |

These are a small concurrent-development sample, not a performance SLA. They do not measure fixture disk I/O, multi-VM detection latency, native containment delay, dashboard load or target-guest recovery duration. The target environment and competition budget remain unknown.

## Security review findings and disposition

| Finding | Disposition |
| --- | --- |
| Native ancestor handle access is denied in this managed workspace | **Open operational gate.** Guard remains enabled; 10 native cases blocked. Verify the dedicated guest/storage contract rather than disabling checks |
| A historical recovery result could be shown as current after later changes | Fixed: current snapshot controls status/list/report verification; regression tests cover it |
| Nonessential events could exhaust journal capacity needed for recovery | Fixed: protected event reserve, unchanged-monitor deduplication and recovery capacity preflight; regression passed |
| Evidence-copy failures could leave uncounted orphan storage | Fixed: durable attempt record reserves bytes before copying; incomplete attempts count toward quota |
| Containment could race operation admission or fail to stop recovery | Fixed: atomic expected-state check at admission and bounded-operation checks in recovery; transaction and workflow regressions passed |
| SQLite opens sidecars outside the Python file adapter | Existing sidecars are rejected before connection. Hot-journal recovery requires offline review; native crash handling remains a gate |
| Windows native crypto ABI, loader and cleanup need scrutiny | Typed widths/signatures, System32-only loading, bounded native properties, authentication-before-return and cleanup tests implemented; no independent crypto certification claimed |
| Missing fixture objects cannot be safely recreated by the current recovery service | Explicit limitation: available evidence can be partial, recovery fails, reviewed VM rollback is the fallback |
| Local manifests/evidence/key stores can be altered by the same account or an administrator | Documented trust limit; deployment ACLs/account isolation still need validation. Hashes are not authenticity proof |
| Dependency source/advisory review could not reach PyPI | No package installed; current provenance/advisory assessment remains required before distribution |

## Outstanding work

Supply actual VMware/guest/runtime/filesystem details, verify isolation/snapshots and run [native acceptance](vm-test-plan.md) in the disposable guest. Complete adversarial native/crash testing, target-VM performance, verified artifact custody and competition rehearsal. Review exact dependency artifacts, license choice and public release content. No phase approval needs repeating, but missing evidence cannot be replaced by broad build authorization.

No commits, tags, pushes, installs, network receiver, public exposure, deployment changes or real file-impact exercises were performed during this build. The repository remains on its unborn main branch because the attempted feature-branch update was denied by workspace permissions.
