# Local investigation dashboard

The dashboard is a read-only Flask adapter over `ransomlab.services.LabService`. It displays real service snapshots: registered exercises, current exercise state, generated fixture hashes, recent events, detection alerts, declared machines, recovery results, and report data. It contains no simulation, containment, file mutation or recovery business logic.

## Files and integration

- `ransomlab/dashboard.py`: `create_app(service=None, access_token=None)` WSGI factory and request boundary.
- `ransomlab/templates/dashboard.html`: escaped server-rendered views and private-session shell.
- `ransomlab/static/dashboard.css`: responsive dark investigation interface; local system fonts and reduced-motion support.
- `ransomlab/static/dashboard.js`: fragment-based session bootstrap and bounded periodic snapshot refresh using DOM text nodes.
- `ransomlab/static/favicon.svg`: local vector favicon.
- `tests/test_dashboard.py`: synthetic-service Flask boundary and rendering tests.

The launcher provides an existing supported local server and binds it to `127.0.0.1`. The factory does not bind sockets or use Flask's development/debug server. It lazily creates `LabService.default()` only if no service is supplied. The server/CLI owns startup, socket concurrency/body limits and shutdown.

Expected shared methods are `list_labs()`, `status(lab_id)` and `report(lab_id)`. Each must perform read-only queries when invoked by the dashboard. Data stays governed by the core service models; no second detection or integrity engine is implemented here.

## Session and browser boundary

The launcher supplies a random token of at least 32 ASCII characters and prints a launch link in this format:

```text
http://127.0.0.1:PORT/#token=TOKEN
```

The token is in the fragment, which the browser does not send in HTTP request URLs. The external bootstrap script removes it from browser history before making a request, then sends it as a Bearer credential to `POST /session`. Successful authentication returns an HttpOnly, SameSite=Strict signed session cookie; the token is not placed in the response. The browser reloads the same path without the fragment. The cookie is deliberately not marked Secure because this application serves local HTTP; external exposure is forbidden. Session signatures expire after eight hours, and a process restart invalidates old cookies because the signing secret is generated per factory instance.

The initial unauthenticated `/` response is a generic shell and never queries the service. Static assets are public but contain no lab data or credentials. Data routes require a valid session or Bearer credential. Query-string credentials are rejected. A fresh token and cookie signing key must be used for each launch.

Every request checks the exact loopback Host form, a loopback client address, same-origin Origin where present, and rejects browser requests marked cross-site. Host values containing user information, unrelated names or invalid ports fail. Unknown or duplicate query parameters fail. Lab identifiers must be canonical UUIDs, never filesystem paths. Application exceptions return a fixed error code without reflecting internal paths.

Responses disable caching and use a Content Security Policy restricting scripts, styles, fonts and connections to the same origin. Inline scripts/styles, embedding, object content and form submission are disallowed. Additional headers deny framing, MIME sniffing, referrers, camera, microphone and geolocation. The dashboard has no lab-changing routes; the sole POST endpoint exchanges a credential for a browser session.

## Read routes and limits

| Route | Result |
| --- | --- |
| `GET /` | Private shell or exercise list |
| `GET /labs/<UUID>` | Investigation snapshot |
| `GET /api/labs` | Shared exercise list |
| `GET /api/labs/<UUID>/status` | Shared status snapshot |
| `GET /api/labs/<UUID>/report` | JSON report download with a generated filename |
| `GET /api/labs/<UUID>/events?after=N&limit=N` | Bounded page within the shared recent-event window; `limit` 1–200 |

The HTML timeline displays the latest 40 returned events and labels that limit. It is not a complete historical export. Event pagination also explicitly reports `window: recent`; the authoritative event history and complete report/export remain service responsibilities. Refresh requests are sequential, pause in hidden tabs, time out after five seconds and display stale status after errors. A session-expiry response stops polling. Machine labels describe declared inventory rather than claiming a live network probe.

## Dependencies and verification

Implementation uses the already installed Flask 3.1.3 and its existing dependencies. No package, frontend framework, CDN font, chart library or browser binary was installed for this work. The root dependency inventory governs version/source review and deployment constraints; this document does not claim a current vulnerability audit.

Tests use Flask's test client and direct WSGI calls with generated synthetic records. They cover unauthenticated data denial, fragment-session exchange contract, cookie flags, token rejection, Host/Origin/client-address checks, malformed authority handling, read-only methods, UUID validation, unknown queries, HTML escaping, headers, bounded event pagination, upload rejection and error redaction. JavaScript is checked with the existing Node runtime's syntax checker.

Browser rendering was verified with the existing Playwright Core 1.56.1 and cached Chromium 1194, without installing tools. A temporary loopback Uvicorn preview served clearly labelled synthetic UI records, not application-generated exercise evidence. Desktop (1440 × 1100 viewport) and mobile (390 × 844 viewport) screenshots were visually inspected. The checks confirmed no page overflow or console errors; unauthenticated data stayed hidden; fragment credentials were removed; polling changed recovery and the sidebar state from recovering to verified; and the report download contained the expected synthetic marker.

Browser QA found and corrected two issues: a token fragment added to an already open locked page did not trigger authentication, and the sidebar exercise state did not update with the selected exercise snapshot. The file table also gained keyboard focus and a mobile horizontal-scroll hint. The final browser run passed. All 19 server-side tests and the JavaScript syntax check passed after these changes.

The reviewed [desktop preview](../assets/dashboard-preview.png) is retained as documentation. Temporary preview scripts, browser snapshots and JSON results were removed during cleanup. Duplicate preview images are disposable generated output. The synthetic preview does not establish a real VM exercise, cryptographic recovery result or deployment acceptance. Browser and preview server were closed after verification.

The actual `python -m ransomlab serve --port PORT` command was subsequently tested on an available loopback port with the real service and an empty workspace. The launcher token was captured privately in memory. The locked page disclosed no lab data; unauthenticated API access returned 401; session exchange returned 204 with private cookie flags; authenticated lab listing returned `[]`; forged Host/Origin requests returned 400/403; a 2 KiB body returned 413; and POST requests to data routes returned 405. No `.ransomlab` directory or fixtures were created. The exact child process was stopped and its listener was confirmed closed. These results remain summarized here after the temporary JSON artifact was removed.

The integration review aligned recovery rendering with the real service's `recovery.state`, including `verification_lost`, and recognized the core's `intact` fixture state. A regression test confirms historical recovery success is not displayed as current verification after it is lost. The dashboard suite now contains **20 passing tests**; the JavaScript syntax check also passes. A populated real-lab workflow still needs the approved target-VM integration tests.

Unit/browser tests do not demonstrate resistance to a compromised local operating-system account or browser extension. Loopback and the token protect the application boundary under the approved local-operator threat model; they are not an OS sandbox.
