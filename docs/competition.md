# Competition preparation draft

Project: **RansomLab**. Owner: **Antech-greyhat**. Event: **Halloween Dooms Day**.
This material is a rehearsal draft. Deadline, judging rules and allocated demo
time remain unknown; no guest evidence or competition result is fabricated here.

## Demonstration story

Show one small generated dataset through preparation, a fixed ransomware-like
file-impact scenario, independent integrity observations, containment semantics,
evidence preservation and verified recovery. Explain the boundaries before
showing outcomes. Distinguish declared machine roles, synthetic scenario events,
observed file changes and analyst conclusions.

| Step | Operator action | Evidence to capture after the real rehearsal |
| --- | --- | --- |
| 1 | Show approved VM isolation and clean snapshot record | Reviewed topology and snapshot label; no credentials |
| 2 | Run `doctor`, create a small lab and inspect status | Runtime versions, generated IDs, intact SHA-256 baseline |
| 3 | Describe the Windows lab, compose a fixed scenario on Kali and import it locally | Reviewed descriptor/envelope, request ID and staged receipt |
| 4 | Arm the guest using the verified snapshot label, then run the request | Run ID, action intents/results and bounded affected-file count |
| 5 | Inspect monitor findings and the local dashboard timeline | Observed hash changes and explainable rule/alert references |
| 6 | Explain or exercise containment and an interrupted-run reconciliation | Requested versus acknowledged stop; actual pending-state outcome |
| 7 | Preserve evidence before recovery | Collection time, manifest hash, completeness and item references |
| 8 | Restore clean copies, or use authenticated decryption for the crypto lesson | Final complete baseline comparison; failure remains visible if any |
| 9 | Show the report and discuss limitations | Findings, synthetic indicators, recovery result and recommendations |

Default fixtures can execute faster than a human containment action. Rehearse
that timing and explain the observed result; do not slow the run with an
unreviewed arbitrary-action feature or pretend containment caused a completed
run to stop. Keep a reviewed failure demonstration available without changing
actual security controls.

## Technical report template

1. **Objective and scope:** learning goals, approved scenario and generated-data
   boundary; explicitly identify excluded behaviours.
2. **Environment:** actual VMware/guest/runtime versions, local filesystem,
   resource allocation, isolation checks and snapshot references.
3. **Architecture:** use the [component and data-flow diagrams](architecture.md),
   then describe implemented changes such as the Windows CNG provider.
4. **Method:** fixture profile, trusted baseline, fixed-action request, execution
   preconditions, observation method and evidence collection procedure.
5. **Timeline:** sequence, UTC time, source, run/fixture ID, action/outcome and
   supporting artifact. Sequence orders one repository; wall clocks do not
   prove total ordering across machines.
6. **Findings:** affected/unchanged/missing objects, detector explanation,
   containment outcome, evidence completeness and recovery verification.
7. **Security assessment:** observed boundary results, residual risks, failed or
   blocked tests, and how those limit claims.
8. **Lessons and recommendations:** what the measured exercise showed, how it
   differed from expectations, and the next engineering improvements.

Use this evidence register for the actual rehearsal:

| Artifact ID | Run ID | Source | UTC collection time | SHA-256 | Reviewed for release |
| --- | --- | --- | --- | --- | --- |
| Pending actual artifact | Pending | Pending | Pending | Pending | No |

Screenshots should show the generated baseline, timeline/alert, evidence receipt
and recovery result. Exclude launch tokens, keys, usernames/private paths,
credentials, unrelated applications and personal information. No VM evidence
screenshots have been produced by this document.

## Presentation outline

- Problem and learning objectives.
- Architecture and enforced fixture boundaries.
- Kali-to-Windows data-only scenario workflow.
- Short demonstration of observed impact and detection.
- Evidence, containment and recovery results.
- Test evidence, limitations and lessons learned.

Allocate time only after the competition duration is known. Prefer a complete
small scenario over an unfinished large one.

## Likely judges' questions

| Question | Supported answer |
| --- | --- |
| Can this encrypt arbitrary folders? | Public actions select generated fixture IDs; services validate the signed local inventory and guarded storage objects. There is no target-directory command. Native boundary validation is still a release gate |
| Does Kali remotely execute code on Windows? | No. Kali composes a bounded scenario document; the Windows operator imports and arms it locally. The build has no general remote command receiver |
| Is the encryption real? | Windows uses Microsoft CNG AES-256-GCM, with fixed key/nonce/tag lengths and known-answer tests. RansomLab does not implement the cipher itself |
| What if the key is lost? | Verified clean copies are independent of run keys. Clean recovery still requires intact copies and the complete expected inventory |
| Does an alert prove ransomware? | No. The training rules flag baseline differences and affected-file counts; legitimate changes can trigger them |
| Is the evidence tamperproof? | No. Hashes and provenance support verification against a trusted baseline; a same-account attacker or administrator can undermine local trust |
| Does the VM check guarantee isolation? | No. It observes a VMware manufacturer indicator. Isolation and snapshot assertions require actual operator verification |
| What passed in development? | Cite the current test report. In-memory workflow and CNG byte tests are separate from blocked native boundary tests and pending VMware end-to-end evidence |
| How is recovery success established? | The complete expected working inventory must match trusted SHA-256 baselines. Partial copies or a snapshot rollback alone are not application recovery proof |
| What remains before release? | Supported-guest native safety tests, complete VM rehearsal, current dependency/runtime review, approved release contents/license and explicit publication authorization |

## Lessons currently supported by engineering work

Path strings alone do not establish containment. A denied ancestor must stop
operations instead of being silently skipped. SQLite state and file writes need
durable intent/outcome reconciliation because they cannot commit atomically.
Provider vectors, application workflow tests and real filesystem tests answer
different questions. Add operational lessons only after a recorded VM rehearsal.
