# Product requirements

RansomLab is an educational and defensive cybersecurity platform for the Halloween Dooms Day challenge. It teaches cryptography, ransomware-related behaviour, file integrity, detection, investigation, containment, recovery and evidence reporting using generated disposable data.

The application serves a single local operator. Learner, investigator and competition reviewer are workflow roles, not separate authenticated user accounts. Windows 11 is the intended exercise guest, Kali prepares fixed-action scenarios and analyses exports, and Windows 10 is an optional forensic workstation.

## Functional requirements

| ID | Capability | Acceptance evidence |
| --- | --- | --- |
| PR-01 | Reversible cryptographic demonstrations over generated samples | Authenticated round trip, tampering/wrong-key rejection and recoverable originals |
| PR-02 | Controlled sample generation and SHA-256 integrity | Bounded registered fixtures; known baseline hashes; changed/missing results |
| PR-03 | Configuration validation, audit events and change primitives | Invalid configuration rejected; ordered journal and failure tests |
| PR-04 | Explicit lab inventory, bounded scenarios and attack timelines | Data-only local import; no general execution, scanning or autonomous target selection |
| PR-05 | Monitoring, suspicious activity detection, correlation and alerts | Explainable synthetic cases with documented false positives and polling limits |
| PR-06 | Investigation and application-managed containment | Incident reconstruction and bounded stop behaviour |
| PR-07 | Evidence preservation and verified clean-copy recovery | Provenance/manifest checks and restored bytes matching the baseline |
| PR-08 | CLI with help, validation, structured output and errors | Shared-service delegation and documented exit behaviour |
| PR-09 | Local dashboard with status, timeline, changes, alerts, findings and reports | Loopback access controls; shared models; browser verification |
| PR-10 | Incident reports, synthetic indicators and recovery recommendations | Report data linked to run and evidence identifiers |
| PR-11 | Integration, security, regression, performance and recovery assessment | Recorded results with supported-platform safety gates |
| PR-12 | Installation, architecture, security, contribution and release documentation | Reviewed release candidate and explicit publication authorization |
| PR-13 | Isolated VMware exercise | Isolation, snapshots, generated data and rollback verified before execution |
| PR-14 | Competition report, demonstration and presentation materials | Rehearsed narrative and evidence traceable to a real exercise |

## Safety requirements

| ID | Boundary | Required outcome |
| --- | --- | --- |
| SAF-01 | Generated disposable fixtures only | Every impact operation checks the registered generated objects; no arbitrary directory targeting |
| SAF-02 | Reversible and recoverable operations | Verified clean copies before impact; successful recovery requires complete baseline matches |
| SAF-03 | No propagation or general execution | No spreading, uploaded executable scenarios, shell commands or arbitrary target paths |
| SAF-04 | No host compromise features | No evasion, security-tool disabling, persistence or credential theft |
| SAF-05 | No unrelated collection or exfiltration | Evidence is limited to generated data and application events; transfers are explicit and bounded |
| SAF-06 | Fail-closed enforcement | Invalid inputs, unsafe links, missing protections, quota failures and uncertain state stop impact |
| SAF-07 | Auditability | Durable intent/result records; visible interruptions; secrets excluded from logs |
| SAF-08 | Scoped containment | Stop application-managed work without killing unrelated processes or changing host security policy |
| SAF-09 | Controlled lab and local management | Isolated disposable guests; no external administrative dashboard exposure |

## Engineering requirements

| ID | Requirement |
| --- | --- |
| ENG-01 | Modular Python core; narrow PowerShell/Bash helpers without duplicated safety decisions |
| ENG-02 | Shared application services and versioned event/data contracts for both interfaces |
| ENG-03 | Incremental changes, meaningful tests, explicit errors and documented limits |
| ENG-04 | Prefer standard library; document and review each dependency, constraint and installation source |
| ENG-05 | Reproducible fixtures and metadata; wall clocks alone do not establish event order |
| ENG-06 | Private development, reviewed changes and controlled versioning; commits remain subject to owner instruction |
| ENG-07 | No credentials, personal data, malware samples, sensitive evidence or runtime keys in Git |
| ENG-08 | Keep architecture/dependency changes visible and obtain explicit authorization before publication |

## Exercise flow

1. Generate a bounded dataset and verify clean copies and baseline hashes.
2. Export the generated IDs, compose a fixed-action scenario on Kali and import it locally on Windows.
3. Validate the guest, isolation/snapshot assertions, scenario and working fixture inventory before arming.
4. Record controlled actions separately from observed file changes and detector findings.
5. Contain or reconcile interrupted work, preserve evidence and recover registered objects.
6. Verify the complete inventory and report both successful and incomplete outcomes.

Production endpoint protection, real victim recovery, actual malware, internet-facing services, network scanning and claims of forensic admissibility are outside scope. Live VMware facts and competition rules remain to be supplied; missing-object restoration and native validation are recorded limitations, not completed capabilities.

See [architecture](architecture.md), [security](security.md), [dependencies](implementation/dependencies.md) and [validation results](implementation/validation-report.md) for implementation details and remaining acceptance work.
