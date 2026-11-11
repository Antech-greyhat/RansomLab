# Contributing to Antech-RansomLab

Read the [README](../README.md), [architecture](architecture.md),
[requirements](requirements.md) and [safety boundaries](security.md).
The active workflow is one phase at a time. Historical documents cannot authorize
cross-phase work or override the owner's current instructions.

## Branch, commit and review workflow

1. Inspect the working tree, branches, history and repository instructions.
   Preserve existing valid work and use the existing Antech-greyhat/RansomLab repo.
2. Create one feature branch per phase, starting with phase-00-architecture.
   Never commit directly to main.
3. Complete only the phase's scope and acceptance checks. Phase 0 changes
   documentation only; no new application/simulation code, installs or VM setup.
4. Run relevant tests and inspect the complete diff for defects, secrets and
   generated artifacts. Record failed, skipped and environment-blocked checks.
5. Commit with a meaningful feat/fix/docs/test/refactor/security/chore prefix.
   Every assistant-authored commit, including documentation-only commits, must
   contain the exact trailer below; verify the stored commit message.
6. Push the phase branch and open a PR against main with the required structure.
   Report the commit hash, PR URL, validation and limitations.
7. Stop for owner review and merge. Never self-merge, bypass review, change branch
   protections, or begin the next phase while its predecessor awaits review.

```text
Co-authored-by: technorant <223033055+technorant@users.noreply.github.com>
```

Example commit and verification after staging only reviewed phase files:

```bash
git commit -m "docs: establish Phase 0 architecture and safety baseline" -m "Co-authored-by: technorant <223033055+technorant@users.noreply.github.com>"
git log -1 --format=%B
git diff --check
```

If authentication, network, push or PR creation fails, finish safe local work and
report the exact blocker. Do not claim remote completion.

The owner explicitly authorized keeping the existing repository public and pushing
Phase 0 documentation on 2026-11-11. This is not release/tag/deployment approval.
Do not change visibility. Main protection is owner-managed.

## Pull request format

Title: **[Phase XX] Short description**

- Objective.
- Implemented features (documentation deliverables for Phase 0).
- Architectural decisions.
- Files added or modified.
- Tests executed and results.
- Security considerations.
- Acceptance criteria.
- Known limitations.
- Recommended next phase.

Link relevant requirements/tests and identify unanswered decisions. Describe the
final change for a reviewer who has not read the development conversation.

## Engineering and validation

Keep business logic and safety decisions in shared Python services. Prefer
standard-library components where suitable; justify dependencies and review
versions, artifacts, advisories and licenses before installation. No custom cipher,
React or separate frontend pipeline. Use concise types/docstrings and meaningful
failure tests instead of placeholder features or fake data presented as results.

The existing suite runs with:

```bash
python scripts/validate.py
```

The ordinary suite uses memory fixtures for service impact. Native boundary
acceptance is distinct and required for platform claims. Do not change tests or
remove protections merely to hide a failing prerequisite. Test decoys must also
be generated disposable data. Do not modify VMware/Kali in earlier phases.

## Artifact hygiene and licensing

Never commit credentials, access tokens, runtime keys, live .ransomlab stores,
real malware, user documents, private incident evidence, VM images or unreviewed
browser traces. Scan staged content and inspect the diff before every commit.
Deleting a secret later does not erase it from history.

No license is currently selected. MIT remains a recommendation for owner review,
not a granted license. Review third-party notices and the final release content
before choosing and publishing licensing. Public visibility is not a substitute.
