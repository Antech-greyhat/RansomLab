# Technology decisions and dependency inventory

## Phase 0 decisions — 2026-11-11

These are recommendations for the reviewed phase plan, not dependency changes.
No package, runtime or browser was installed in Phase 0. Preserve existing working
providers until their relevant phase has tested a replacement. The new
[architecture](../architecture.md) supersedes earlier cross-phase authorization.

| Concern | Decision and justification | Alternatives / implementation phase |
| --- | --- | --- |
| Runtime | Propose Python 3.13–3.14; audit uses 3.14.3. Test each supported platform before claiming compatibility | No downgrade/install now; packaging and matrix begin Phase 1 |
| Models/configuration | Standard-library dataclasses, enums, strict versioned JSON, tomllib for proposed TOML configuration | Pydantic adds a dependency without a demonstrated validation need; Phase 1 |
| Persistence | Keep sqlite3, transactions, bounded records and explicit migrations | SQLAlchemy, Postgres and external brokers add lifecycle/deployment overhead for one local operator; Phase 1 |
| CLI | Keep argparse and structured errors | Click/Typer provide conveniences but no necessary new capability; Phase 8 completes existing interface |
| Dashboard | Keep Flask/Jinja and existing small JavaScript/CSS assets | Streamlit is quick for analysis but less suited to the existing bounded read-only routes; FastAPI adds an unnecessary ASGI/API rewrite; no React |
| HTTP server | Recommend maintained Waitress for dedicated cross-platform WSGI serving; retain all request/Host/Origin/auth limits | Existing Uvicorn WSGI adapter is deprecated. Review Waitress limits/versions and rerun server tests in Phase 8 before switching |
| Cryptography | Recommend established cryptography package for portable AES-GCM, RSA-OAEP key-wrap and Ed25519 signature demonstrations | Existing Windows CNG is established crypto but ctypes raises ABI/maintenance cost; preserve vectors/provider until Phase 2 review; no invented algorithms |
| Integrity/telemetry | hashlib and bounded polling plus scoped operation observations first | watchdog native notifications may help latency but add platform/loss semantics; add only if justified by Phase 4 measurements |
| Tests | Retain unittest and current structured runner | pytest/Hypothesis may help later generative tests; not necessary for Phase 0 |
| Reports | Standard-library JSON/JSONL and generated Markdown over common records | No pandas, plotting framework or separate frontend needed for basic measured results |
| Startup | Bash orchestrates shared Python preflight/entry points in Phase 8 | No Bash duplication of safety logic, implicit downloads or system configuration; Windows-specific diagnostics may remain PowerShell |

Runtime dependencies should be minimal and separated from an optional dashboard
extra in Phase 1 packaging. Add crypto dependencies only with Phase 2 work. A
reviewed platform lock must include transitive versions, sources, artifact hashes,
license notices and dated advisory findings; do not invent exact future pins here.
Online advisory/provenance assessment and clean installation remain outstanding.

## Historical implementation inventory — 2026-11-04

The following records describe the inherited build, not the new target's approval
or a verified-source installation manifest. Its observed Python/SQLite and direct
Flask/Uvicorn versions were corroborated by Phase 0 diagnostics; original package
provenance and full transitive inventory were not independently re-established.

## Implemented choices

The shared core uses the Python standard library. The observed runtime is Python 3.14.3 with SQLite 3.50.4. Earlier 3.13 language in the Phase 0 packet described a candidate. Full target-guest compatibility and patch/advisory assessment remain release gates.

The previously compared Flask option is selected for the read-only dashboard. Existing Uvicorn serves the WSGI application with explicit asyncio/h11, loopback binding, no proxy trust, no WebSockets and bounded request/body/concurrency limits. This replaces the uninstalled Waitress candidate. `BoundedRequest` checks the body before the WSGI adapter buffers it. Uvicorn's WSGI adapter is deprecated upstream; assess migration to a reviewed dedicated WSGI server before a stable release, without silently adding a dependency now.

Windows encryption uses the existing Microsoft CNG AES-256-GCM implementation through typed `ctypes` bindings. This explicit refinement replaces the proposed pip dependency for the primary execution path. [The provider review](crypto-provider.md) covers vectors, ABI, failure handling, limits and maintenance. RansomLab contains no homemade cipher. The optional non-Windows `cryptography` path remains unvalidated and requires an exact approved dependency/source manifest before deployment.

## Existing package inventory

All constraints below are exact observed versions, also recorded in [the constraints file](../../constraints-dashboard.txt). Files came from the pre-existing local Python environment. Their original distribution source and artifact hashes were not independently established; no new installation source has been approved. A fresh deployment must complete that review rather than treating this table as download permission.

| Package / exact constraint | Purpose and justification | Preliminary security assessment |
| --- | --- | --- |
| Flask == 3.1.3 | Selected local view adapter; core remains framework-independent | Host/origin/session, escaping and debug-disabled checks passed; current advisories not checked online |
| Werkzeug == 3.1.7 | Flask request/response dependency | Parser/request and exception boundaries exercised; development server is not used |
| Jinja2 == 3.1.6 | Server-rendered templates | HTML autoescaping and malicious-name tests; no uploaded templates |
| MarkupSafe == 3.0.3 | Template escaping dependency | Untrusted values remain escaped; native wheel provenance review pending |
| itsdangerous == 2.2.0 | Flask session signing | Fresh application secret, local session, HttpOnly/SameSite cookie; account compromise excluded |
| click == 8.3.1 | Existing Flask/Uvicorn dependency | Operational CLI uses argparse; no shell command bridge |
| blinker == 1.9.0 | Flask signal dependency | No uploaded signal handlers or dynamic plugins |
| uvicorn == 0.41.0 | Existing bounded local HTTP server | Protocol/body/connection limits, proxy headers disabled; deprecated WSGI adapter needs future review |
| h11 == 0.16.0 | Explicit HTTP/1.1 parser | Header/event-size and application request limits; no reverse-proxy deployment claim |
| colorama == 0.4.6 on Windows | Click transitive terminal support | No privileged project use; conditional Windows pin |

The attempt to retrieve PyPI release/advisory metadata failed with an unreachable endpoint. No current-source audit or vulnerability scan is claimed. Before release, verify advisories, support lifecycle, licenses, artifacts and hashes against approved upstream sources. Versions may differ from these observed pins by then; updates require review and relevant regressions.

## Browser verification tools

Browser QA reused installed Playwright Core 1.56.1 and cached Chromium revision 1194. No `npx`, package or browser download was performed. These are existing validation tools, not application dependencies. Preview screenshots use synthetic data and contain no access token. Owned browser/server processes were closed after checks.

## Resource policy

The reviewed initial ceiling profile is implemented with explicit storage limits: 100 files, 1 MiB per file, 20 MiB plaintext, 100 actions, a 300-second run budget checked between bounded operations, 8 KiB per event, 10,000 events, 32 MiB database, 64 MiB evidence and a 128 MiB free-space reserve. At most eight labs and twenty staged requests/runs are allowed per lab. Internal policy may tighten limits; the CLI cannot enlarge them.

Nonessential events cannot spend the protected recovery audit reserve. Evidence attempts reserve bytes before copying; incomplete attempts still count. File and database writes remain separate transactions, with pending-intent reconciliation handling uncertainty. Kernel I/O completion and physical disk exhaustion are not proven hard-real-time guarantees.
