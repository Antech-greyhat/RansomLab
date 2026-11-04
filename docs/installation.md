# Installation and development setup

RansomLab currently runs from a reviewed source checkout. There is no published
release, signed installer or verified fresh-VM installation package. All changes
remain uncommitted at the owner's instruction.

## Current runtime and dependencies

The development environment has Python **3.14.3**, SQLite **3.50.4** through the
standard library, and the dashboard packages below. These are observed existing
versions; the project did not install them. Python 3.13 was an earlier candidate,
and the complete target-VM support matrix still needs verification.

| Existing package | Version | Purpose |
| --- | --- | --- |
| Flask | 3.1.3 | Local read-only dashboard application |
| Werkzeug | 3.1.7 | Flask request/response and WSGI support |
| Jinja2 | 3.1.6 | Escaped dashboard templates |
| MarkupSafe | 3.0.3 | Template escaping support |
| itsdangerous | 2.2.0 | Flask session signing |
| click | 8.3.1 | Flask transitive command support; the RansomLab CLI uses argparse |
| blinker | 1.9.0 | Flask signal support |
| Uvicorn | 0.41.0 | Bounded loopback server using its WSGI adapter for Flask |
| h11 | 0.16.0 | Selected HTTP parser for the local Uvicorn server |
| colorama | 0.4.6 | Click's existing Windows transitive terminal support |

Windows encryption uses the installed Microsoft CNG AES-256-GCM provider through
Python's standard-library `ctypes`. It does not need a cryptography pip package.
The [provider review](implementation/crypto-provider.md) records that explicit
change from the Phase 0 proposal, tests and native-binding limitations.

On non-Windows platforms, encryption requires a separately approved exact
`cryptography` package and dependency/source review. The fallback is not an
approved installation manifest. Offline scenario composition and core parsing
do not require that encryption fallback. Missing optional packages fail explicitly.

## Open an existing prepared checkout

From its root, use the existing Python interpreter:

```text
python --version
python -m ransomlab --help
python -m ransomlab doctor
```

On Kali, substitute `python3` when that is the installed interpreter's command.
Do not substitute a different version silently; record it with validation results.
Do not install packages, invoke unpinned `npx` commands or download browser binaries
as a side effect of opening the project.

Run relevant automated checks with:

```text
python -m unittest discover -s tests -v
```

The current workflow tests substitute in-memory fixtures while using real
disposable SQLite metadata. Native filesystem cases may report **BLOCKED** skips
when the operating-system boundary cannot be established. This is incomplete
platform validation, not a passing end-to-end VM exercise.

## Fresh guest preparation

Before copying the reviewed source to a new guest, identify the exact supported
Windows 11/Kali/Python versions, selected VMware product, local filesystem,
resource allocation and approved package source. Follow the [VMware runbook](vmware-lab.md).
Prepare a project-specific environment only after its exact runtime/package
manifest and installation source are approved. There is no approved automatic
bootstrap command in this build.

The dashboard needs the Flask/Uvicorn stack above or a newly reviewed compatible pin set.
Existing package metadata is not a current advisory audit or supply-chain proof.
Record transitive pins, artifact hashes, source/provenance, licenses and review
dates before preparing a distributable environment.

The launcher selects asyncio/h11 and disables WebSocket/lifespan support,
proxy-header trust and access logging. It bounds connections, request size and
timeouts. Optional Uvicorn “standard” extras are not requirements of this build.

The local data directory is fixed at `<checkout>/.ransomlab`. The CLI has no
arbitrary target-root option. Do not copy personal documents, host folders,
real malware, credentials or production data into it. Runtime data and keys
must remain outside version control and public release artifacts.

See [usage](usage.md) for commands and [security](security.md) for current boundaries.
