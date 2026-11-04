# RansomLab

Owner: **Antech-greyhat**. Educational cybersecurity platform for the **Halloween Dooms Day** challenge.

RansomLab demonstrates ransomware-related behaviour and the defensive workflow from file-integrity monitoring to investigation, containment, evidence preservation and verified recovery. All file-impact demonstrations are restricted to generated disposable fixtures in approved lab environments.

**Current status: local development build implemented; all changes uncommitted.** The owner authorized implementation across phases and requested no commits. Native fixture-impact validation and actual VMware deployment remain pending: this environment cannot pin a required filesystem ancestor and is not a verified VMware guest. Safety checks remain enabled and refuse file-impact execution here.

Read the [requirements](docs/requirements.md), [architecture](docs/architecture.md) and [validation report](docs/implementation/validation-report.md) for the design, results and remaining work.

The application uses locally imported fixed-action scenarios, shared Python services/models, a CLI and a read-only Flask dashboard. Windows authenticated encryption uses the existing Microsoft CNG AES-256-GCM provider. No packages were installed; the optional non-Windows `cryptography` dependency still needs an exact installation/source review.

The platform must never implement spreading, persistence, stealth/evasion, security-tool disabling, credential theft, unauthorized data collection, arbitrary remote execution or encryption of arbitrary directories. These boundaries must be enforced and tested in later approved implementation phases.

Development remains private. Cross-phase implementation is authorized; dependency installation, public release and actual VM configuration retain their separate constraints. No commits, tags, pushes or publication have occurred.

## Start locally

Use the existing prepared Python environment from the checkout root:

```text
python -m ransomlab --help
python -m ransomlab doctor
python -m ransomlab serve --port 8765
```

The dashboard listens on `127.0.0.1` only. Open the private access URL printed by the launcher. Its token is exchanged for a local session and removed from the address bar. The dashboard has no simulation or host-administration controls.

The current environment uses Python 3.14.3, Flask 3.1.3 and Uvicorn 0.41.0. [Installation notes](docs/installation.md) and the [dependency record](docs/implementation/dependencies.md) describe observed versions and outstanding source/advisory review. Do not run an automatic installer merely to open this project.

View the [dashboard preview](docs/assets/dashboard-preview.png). Its data is explicitly synthetic UI test data, not evidence from a Windows victim exercise.

## Implemented capabilities

- Generated inventories, signed local manifests, clean copies, SHA-256 checks and guarded filesystem access.
- Authenticated encryption using an established Windows provider, tested against published byte-level vectors.
- Fixed-action JSON scenarios with expiry, generation binding, duplicate handling and local arming; offline Kali composition from an ID-only descriptor.
- Durable mutation intents/results, ordered events, independent content observations and explainable integrity alerts.
- Containment requests, interrupted-operation reconciliation, incident summaries, bounded evidence and verified clean-copy or decryption recovery.
- JSON, Markdown and JSONL reports; responsive dashboard with local authentication and request-boundary controls.
- PowerShell/Bash preflight helpers, VMware isolation/rollback runbooks and competition material drafts.

## Tests and operational limits

```text
python -m unittest discover -s tests -v
```

Workflow tests keep fixture bytes in memory while exercising real temporary SQLite transactions. CNG tests use generated in-memory bytes. Native checks marked `BLOCKED` or pending VM attestation are not passing platform safety evidence. The [native acceptance plan](docs/implementation/vm-test-plan.md) defines real-VM verification.

Impact and recovery require a VMware guest indicator, a verified non-elevated process, local arming and operator confirmation of the disposable guest, isolation and snapshot. Guest detection cannot prove snapshot or network state. Follow the [VMware runbook](docs/vmware-lab.md).

Recovery success requires a fresh complete baseline comparison. Missing fixture objects remain an explicit failed-recovery condition; available evidence can be preserved as partial before reviewed VM rollback. Local hashes do not make evidence tamperproof against the operator account or an administrator.

## Documentation

| Topic | Guide |
| --- | --- |
| Commands and offline Kali workflow | [Operator guide](docs/usage.md) |
| Enforced controls and limitations | [Security](docs/security.md) |
| Windows filesystem constraints | [Filesystem boundary](docs/implementation/filesystem-boundary.md) |
| Cryptographic provider decision | [CNG review](docs/implementation/crypto-provider.md) |
| Demonstration and presentation | [Competition materials](docs/competition.md) |
| Review and collaboration | [Contributing](docs/contributing.md) |
| Development build changes | [Release notes](docs/release-notes.md) |

This is a private development build, not an approved public release or a completed VM exercise. No license has been granted yet; MIT is recommended for release review. Runtime keys, databases, generated fixtures, browser traces and VM images are excluded from source control.
