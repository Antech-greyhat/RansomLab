# Dependency and implementation decisions

Recorded 2026-11-04. No package, browser or runtime installation occurred. The owner's cross-phase implementation authorization permits use of the existing development environment; it is not a verified-source installation manifest for a fresh guest.

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

The reviewed initial ceiling profile is implemented with explicit storage limits: 100 files, 1 MiB per file, 20 MiB plaintext, 100 actions, 300 seconds between bounded-operation checks, 8 KiB per event, 10,000 events, 32 MiB database, 64 MiB evidence and a 128 MiB free-space reserve. At most eight labs and twenty staged requests/runs are allowed per lab. Internal policy may tighten limits; the CLI cannot enlarge them.

Nonessential events cannot spend the protected recovery audit reserve. Evidence attempts reserve bytes before copying; incomplete attempts still count. File and database writes remain separate transactions, with pending-intent reconciliation handling uncertainty. Kernel I/O completion and physical disk exhaustion are not proven hard-real-time guarantees.
