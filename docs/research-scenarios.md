# Research scenario catalogue

Phase 0 design, 2026-11-11. All six specifications below are proposed studies,
not newly available commands. The existing engine accepts only
`encrypt_generated` and `modify_generated`; [README](../README.md) documents them.

## Shared study protocol

Every study uses an owned generated dataset, trusted baseline, verified clean
copies, explicit single-run authorization, a fixed resource policy and versioned
scenario configuration. Record generator seed/version, source revision, fixture
classes, operation order/pacing, provider/runtime, rule versions, observation
settings and evaluation windows. Repeat in a new experiment; keys/nonces remain
fresh rather than deterministic.

Start with environment/configuration validation; prepare synthetic data and clean
copies; start healthy observation; authorize; run bounded stages; contain;
reconcile interrupted work; preserve evidence; recover and verify; export results;
close. Collect actual measurements. Unavailable telemetry yields unscorable
evaluation, not a fabricated alert or zero loss. No entry exploit is performed:
the local operator's admitted scenario start represents incident initiation.

Use a paired benign control and predeclared detection thresholds. Control variants
may change rules, pacing, simulated staging quotas or application stop policy;
they must never disable path, ownership, authorization, backup or host-security
safeguards. Compare affected/staged/received bytes, prevented actions, detection
latency and recovery. [Architecture](architecture.md#telemetry-metrics-and-reproducibility)
defines scoring and [security](security.md) applies to every step.

## S1 — Baseline cryptographic behaviour

| Field | Specification |
| --- | --- |
| Objective | Measure hashing and authenticated encryption/decryption; demonstrate asymmetric key wrapping and signatures without touching real data |
| Prerequisites | Phase 2 provider/vector tests, approved workspace/baseline/clean copies; later monitoring for detection evaluation |
| Configuration | Generator seed/version; 12 files of 4 KiB; bounded payload-size series; provider/version; repetition count; selected fixed demonstration |
| Execution | Generate and hash; authorize; encrypt synthetic working samples; authenticate/decrypt; demonstrate wrapping a generated session key and verifying a synthetic manifest signature; record timings |
| Expected observations | Known baseline, changed ciphertext hashes, authentication/tag failures for controlled RAM tampering, verified round trips and measured durations |
| Detection opportunities | Integrity changes and bulk-write pattern; benign control hashes/reads only. Crypto alone is not evidence of malice |
| Recovery | Restore from verified clean copies independent of the run key; compare every baseline hash |
| Evaluation metrics | Bytes/time and per-operation samples; round-trip/signature outcomes; detector results only if observers/rules are available |
| Safety boundaries | Established providers, bounded bytes, no arbitrary paths, no hardcoded operational keys/nonces, no private keys in reports |

Existing CNG/SHA-256 vectors are reusable; asymmetric/signature studies and
persisted experiment timings are not implemented.

## S2 — Suspicious bulk file modification

| Field | Specification |
| --- | --- |
| Objective | Compare burst detection with benign maintenance and slow modifications; measure damage before containment |
| Prerequisites | Phase 3 bounded runner, Phase 4 independent observations, Phase 5 windowed rules |
| Configuration | 24 generated files of 4 KiB; 12 selected IDs; fixed marker; burst interval 50 ms versus paced 2 s; initial candidate rule 5 changed distinct files/2 s |
| Execution | Baseline; start observer; authorize; modify selected objects at configured cadence; observe/alert; request bounded containment in a paired trial |
| Expected observations | Actual changed hashes and times, admitted/completed counts, untouched controls, stop acknowledgement |
| Detection opportunities | Unique-file rate and correlated modifications; benign sparse edits and benign bursts test false positives |
| Recovery | Preserve affected artifacts, restore selected/affected working objects, verify complete inventory |
| Evaluation metrics | TP/FP/FN/TN, coverage, first-alert delay, affected bytes/files before stop, completion/containment duration |
| Safety boundaries | Fixed markers on generated IDs only; bounded iterations/time; no unrelated process termination or encryption outside the work inventory |

Existing `modify_generated` provides a primitive; its current three-file count
alert does not implement the proposed timing rule. Thresholds are study inputs,
not efficacy claims.

## S3 — Canary-file detection

| Field | Specification |
| --- | --- |
| Objective | Determine whether access/change to an enrolled synthetic canary is attributable and supports early containment |
| Prerequisites | Generated canary enrollment, Phase 4 observation/health, Phase 5 rules |
| Configuration | 20 generated files including 2 canaries; explicit selected ID order; separate read-only and modification trials |
| Execution | Baseline; enroll canaries; authorize finite steps; touch selected canary through guarded adapter; observe; alert and optionally stop scheduling |
| Expected observations | Canary identity, actual access/write event, hash changes when modified, observer health and stop event |
| Detection opportunities | Any observed canary write; read access only when the scoped adapter actually records it. Polling alone cannot establish reads |
| Recovery | Preserve observations/canary artifact; restore and verify all baseline files before reenrollment in a new run |
| Evaluation metrics | Detection/delay per touch type, missed touches, false alerts in no-touch trials, files affected before stop |
| Safety boundaries | Canaries count toward inventory/byte limits, stay inside the experiment, contain no real credentials or executable traps |

## S4 — Local double-extortion behaviour

| Field | Specification |
| --- | --- |
| Objective | Reconstruct synthetic discovery, classification, staging, mock receipt and subsequent impact; evaluate exposure and containment controls |
| Prerequisites | Phase 3 registry-bound staging/mock sink and receipts; telemetry in Phase 4; rules/evaluation in Phase 5 |
| Configuration | 30 generated files of 4 KiB, synthetic finance/project/public labels, selected synthetic class IDs, 10-file stage limit, 8-file mock-receipt limit, bounded pace |
| Execution | Record admitted local start; enumerate manifest IDs; read/classify generated content; stage selected copies; perform local copy-and-receipt steps; apply approved working-file modifications and create a preregistered inert simulation note; contain and preserve |
| Expected observations | Discovery/read counts, stage hashes/sizes, requested versus verified received counts, rejected/prevented steps, impact hashes, inert note and complete stage timeline |
| Detection opportunities | Unusual read concentration, staging bytes/rate, mock write/receipt pattern and correlation with impact; no truth-label input to rules |
| Recovery | Preserve work/stage/mock receipts and note; restore working baseline; retain stage/mock evidence until an explicit retention action |
| Evaluation metrics | Synthetic bytes selected/staged/mock-received, stage-level detection/delay, stopped transfers, coverage, integrity and recovery results |
| Safety boundaries | No filesystem walk outside inventory, personal data, credentials, archives requiring extraction, sockets, HTTP, URL, DNS, proxy or configurable upload destination |

The mock destination is a generated filesystem compartment owned by the experiment.
Receipt means bytes actually copied and hash-verified there. It is not a network
service. A benign control performs approved generated backup-like copies; detection
must explain any false positives. Preventive trials lower the staging budget or
stop on alert; they never weaken mandatory safety gates. Partial transfers retain
partial status and cannot be counted as full exposure.

## S5 — Backup and recovery resilience

| Field | Specification |
| --- | --- |
| Objective | Verify recovery from changed/missing synthetic data and distinguish clean-copy protection from restoration success |
| Prerequisites | Phase 7 guarded restoration including missing-object creation, preserved evidence and clean-copy verification |
| Configuration | 12 generated files of 4 KiB; fixed damage subset; clean-copy versus decrypt mode; declared synthetic failure injection |
| Execution | Verify clean sources; authorize bounded working-data damage; observe; preserve; restore; independently hash the full inventory; repeat controlled failure cases |
| Expected observations | Before/after digests, protected-source access rejection, per-file restored/missing/corrupt results and measured recovery time |
| Detection opportunities | Modification/missing-file alerts; attempted forbidden backup access rejected before I/O and audited |
| Recovery | The restoration itself; on failure preserve partial outcomes, prevent new impact, require reviewed reconciliation or disposable environment reset |
| Evaluation metrics | All-baseline file/byte verification ratio, duration, missing/corrupt counts, prevented backup writes, present versus historical integrity |
| Safety boundaries | Scenario never corrupts backups; backup corruption/provider-failure tests use separately generated test copies or injected adapters, never protected originals or real backups |

Missing-file restoration is a known gap in existing code. Do not execute or claim
that variant until its guarded creation and identity tests pass.

## S6 — Incident investigation

| Field | Specification |
| --- | --- |
| Objective | Enable another researcher to explain incident start, effects, detections, exposure, containment, recovery and prevention using verifiable evidence |
| Prerequisites | Completed/contained or reconciled experiment; Phase 6 evidence/provenance and bounded export verification |
| Configuration | Source experiment/run, event cutoff sequence, artifact scope, rule/evaluation versions; optional generated incomplete-evidence trial |
| Execution | Freeze mutation; preserve evidence; hash/verify manifest; reconstruct ordered timeline; correlate alerts to observations; distinguish unknown gaps; generate JSON and Markdown findings |
| Expected observations | Actual event sequence, generated affected/staged/received inventory, matching or failed evidence digests, explicit gaps and recovery result |
| Detection opportunities | Assess which controls fired and which eligible behaviours were missed; report tampered/missing evidence separately |
| Recovery | Preserve before any restore; reference an existing verified attempt or run the approved recovery service, then record current integrity |
| Evaluation metrics | Artifact verification coverage, attributable finding count, unresolved timeline gaps, classification/latency where scorable, recovery ratio |
| Safety boundaries | Generated artifacts only, no keys/tokens, bounded manifest paths, no real host collection or unsupported admissibility claim |

## Report questions and evidence

| Question | Required evidence |
| --- | --- |
| How did it begin? | Explicit local run admission, scenario/config and authorization reference; no invented entry exploit |
| What occurred and was detected? | Action intents/results, independent observations, alert event references and observation health |
| What was at risk or exposed? | Baseline inventory, classification, stage records and verified local mock receipts |
| How was it contained? | Stop request/acknowledgement, admission counts and subsequent observed changes |
| Did recovery work? | Clean-source checks, per-file outcomes and current full-baseline verification |
| How can it be prevented? | Supported control comparisons, documented false positives/misses and uncertainty |

Do not claim all controls are effective merely because a scenario completed.
