# Unreleased development status

## Application foundation

- Add installable package metadata and the ransomlab console entry point, with an
  optional dashboard extra and included templates/static assets.
- Add immutable TOML configuration and lifecycle records, strict inventory and
  saved-policy validation, and post-commit structured JSON diagnostics.
- Add shared-service metadata-only experiment creation, validation, inspection,
  listing and closure. Preserve legacy v1 data without implicit migration.
- Reject mutations after closure, prevent empty experiments from arming, and keep
  interrupted/affected experiments from closing before safe reconciliation/recovery.
- Add lifecycle, failure, configuration, manifest and interface regression tests
  and a Windows/Linux Python 3.13–3.14 CI matrix.
- Rewrite README around project capabilities, installation, commands and safety;
  keep audit history and phase governance in their dedicated documents.

This does not add cryptography, simulation scenarios, VM configuration or new
dashboard functionality. Native boundary checks remain distinct from memory tests.

## Phase 0 — architecture and repository audit

The 2026-11-11 Phase 0 change documents the existing RansomLab repository and
proposes the phased plan for Antech-RansomLab for owner review. It adds no application
functionality and does not complete later implementation phases.

- Establish the central README, current capability/gap inventory and repository audit.
- Specify shared services, versioned data/lifecycle contracts and technology decisions.
- Define safety admission, synthetic provenance, interruption, protected clean copies
  and a filesystem-only mock destination.
- Specify six reproducible research scenarios and auditable evaluation metrics.
- Replace obsolete no-commit/cross-phase instructions with one branch and reviewed
  PR per phase, including the required co-author trailer.
- Preserve application source, tests, scripts, dashboard assets and dependency pins.

The owner explicitly authorized keeping the repository public and pushing Phase 0
documentation. No release, tag, deployment, visibility change or Phase 1 work is
authorized by that exception. Stop for Phase 0 review and merge.

## Inherited implementation

The existing development build contains shared Python services, bounded SQLite
events/state, generated fixture controls, two fixed-action scenarios, CNG crypto,
integrity observations/count alerts, evidence/recovery/report services, CLI and a
loopback read-only Flask dashboard. Windows/Kali preflight helpers and VM planning
documents are retained; their presence is not deployment acceptance.

The [Phase 0 audit](phase-00-audit.md) records fresh validation: 101 passing tests,
zero failures/errors, ten blocked native storage cases and a separately skipped
VM class. Existing memory workflows do not establish native filesystem safety.
The [older report](implementation/validation-report.md) is historical evidence only.

## Known limitations and release gates

Native filesystem races/crashes and full recovery need supported-platform evidence.
Missing fixture restoration, multistage discovery/staging/mock transfer, canaries,
asymmetric/signature studies and measured detector evaluation remain incomplete.
Current count alerts are not rate measurements. Local hashes are not tamperproof
evidence; logical clean-copy separation is not immutable backup security.

Fresh installation, packaging/CI, dependency provenance/advisories, portable crypto,
WSGI server maintenance and license selection remain open. Resolve critical/high
security issues, complete phase-specific acceptance and obtain explicit owner
release approval before publishing a release. Home deployment remains Phase 11.

See [requirements](requirements.md), [security](security.md) and
[contributing](contributing.md) for the current gates.
