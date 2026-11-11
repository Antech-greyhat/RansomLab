# Antech-RansomLab

A Python laboratory for studying ransomware behaviour, detecting suspicious file
activity, preserving evidence, and testing recovery with generated synthetic data.

Antech-RansomLab connects controlled experiments, file-integrity observations,
alerts, investigation timelines, and recovery reports through one application.
Use the command line to manage experiments and a local dashboard to explore results.

## What you can do

- Create, validate, inspect, and close persistent experiment records.
- Generate bounded synthetic datasets with SHA-256 baselines and clean recovery copies.
- Run controlled file-modification and authenticated-encryption scenarios.
- Observe changed or missing files and investigate integrity alerts.
- Preserve evidence and export incident timelines as JSON, JSONL, or Markdown.
- Restore working files and verify their contents against the original baseline.

All file-impact operations are limited to registered generated data. The application
does not spread, collect personal files, disable security tools, or transfer data
to external destinations.

## Getting started

Use Python **3.13 or 3.14**. File-impact scenarios require an isolated, disposable
VMware guest, a non-elevated account, and a filesystem that passes the application's
safety checks. On Windows, use local NTFS storage.

```bash
git clone https://github.com/Antech-greyhat/RansomLab.git
cd RansomLab
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
ransomlab doctor
```

On Windows, activate the environment with `.venv\Scripts\Activate.ps1` in
PowerShell. You can use `python -m ransomlab` in place of `ransomlab`.

For the dashboard, install the optional dependencies:

```bash
python -m pip install -e ".[dashboard]" -c constraints-dashboard.txt
```

Run commands from the source checkout. Managed experiment data lives in
`.ransomlab/` inside that checkout. `doctor` reports dependency availability,
identity checks, and filesystem readiness; inspect its fields before creating data.

## Manage experiments

Create a record without generating files or starting a scenario:

```bash
ransomlab experiment create --name "Integrity study"
ransomlab experiment list
ransomlab experiment inspect EXPERIMENT_ID
ransomlab experiment validate EXPERIMENT_ID
ransomlab experiment close EXPERIMENT_ID
```

Replace `EXPERIMENT_ID` with the generated identifier. Validation checks the owned
workspace and its inventory. Closing revokes unused authorization and makes the
record read-only; it does not delete data. Active or uncertain operations must be
reconciled first. Experiments with affected files must be restored, and completed
runs must have preserved evidence, before they can close.

A metadata-only record contains no dataset and cannot run a scenario. Use the
dataset workflow below to create a separate experiment with working files.

## Run a synthetic-data experiment

In an approved disposable guest, generate working files and verified clean copies:

```bash
ransomlab lab create --name "Bulk modification study" --count 12 --size 4096
ransomlab lab status LAB_ID
```

Use the returned `LAB_ID` to prepare a scenario:

```bash
ransomlab scenario create LAB_ID modify_generated --count 3 > scenario.json
ransomlab scenario import scenario.json
ransomlab lab arm LAB_ID --snapshot clean-baseline --isolated --disposable
ransomlab simulate LAB_ID REQUEST_ID
```

Replace `REQUEST_ID` with the import receipt's identifier. The snapshot must already
exist and its isolation must be verified by the operator. Requests expire; import
only stages a request and execution consumes its authorization once.

| Scenario | Behaviour |
| --- | --- |
| `modify_generated` | Applies a fixed content change to selected generated working files |
| `encrypt_generated` | Applies authenticated AES-256-GCM encryption to selected generated working files |

These examples use Bash redirection. For Windows PowerShell 5.1, use explicit
ASCII encoding when saving scenario JSON; see the [operator guide](docs/usage.md).

## Observe, investigate, and recover

```bash
ransomlab monitor LAB_ID
ransomlab investigate LAB_ID
ransomlab evidence preserve LAB_ID
ransomlab recover LAB_ID --mode clean
ransomlab report LAB_ID --format json
ransomlab report LAB_ID --format markdown
ransomlab experiment close LAB_ID
```

The monitor compares actual file hashes with the baseline. Integrity alerts identify
changed or missing fixtures; the current bulk-change rule triggers at three affected
files. It is a count-based training rule, not a measured rate or a production detector.

Preserve evidence before recovery. Clean-copy restoration is independent of the
encryption key; `--mode decrypt` is also available for authenticated encryption
experiments. Recovery is verified only when the complete working inventory matches
the baseline. Missing fixture objects cannot currently be recreated.

To stop application-managed activity or inspect an interrupted operation:

```bash
ransomlab contain LAB_ID
ransomlab reconcile LAB_ID
```

Containment stops new operations at bounded checkpoints. Reconcile only after the
previous process has stopped. Neither command terminates unrelated host processes.

## Open the dashboard

```bash
ransomlab serve --port 8765
```

Open the local URL printed by the launcher. Keep its access token private.
The dashboard shows experiment history, file-integrity findings, alerts, timelines,
evidence, and recovery results from the same services used by the CLI.
It is read-only and does not start simulations. Press Ctrl+C to stop it.

## Configuration

Defaults limit each dataset to 100 files, 1 MiB per file, and 20 MiB total plaintext.
Runs are bounded to 100 actions and 300 seconds, with separate audit, evidence,
database, and free-space limits.

Use [ransomlab.example.toml](ransomlab.example.toml) to set smaller limits and
structured logging:

```bash
ransomlab --config ransomlab.example.toml config check
ransomlab --config ransomlab.example.toml experiment create --name "Bounded study"
```

The application also loads `ransomlab.toml` from the checkout when present.
Use the same configuration for subsequent commands. Saved experiment limits cannot
be relaxed by reopening with a more permissive configuration. Configuration cannot
change the file-impact root. JSON audit diagnostics go to stderr when INFO logging
is enabled; command results remain on stdout.

## Troubleshooting and safety

| Problem | Action |
| --- | --- |
| Filesystem check is blocked | Use a validated local filesystem/account. Do not elevate or remove path checks |
| Guest or identity check fails | Verify the disposable VMware guest and non-elevated account |
| Scenario request expired | Create and import a fresh request for the current dataset |
| Operation requires reconciliation | Stop the previous worker, inspect state, then reconcile |
| Experiment preparation was interrupted | Preserve the workspace for offline review; new creation stays blocked rather than resuming partial initialization |
| SQLite sidecar is present | Preserve the workspace for offline review; do not delete journals to force access |
| Recovery reports missing files | Preserve available evidence and record incomplete recovery |
| Dashboard dependency is missing | Install the dashboard extra in the active environment |

Use generated disposable data only. Native filesystem support must be validated
for the environment; the application is not a sandbox against a compromised OS
or another process with the same account authority. See the
[safety guide](docs/security.md) for the boundary and recovery limitations.

## Documentation

- [Operator guide](docs/usage.md)
- [Installation reference](docs/installation.md)
- [Architecture](docs/architecture.md)
- [Research scenario catalogue](docs/research-scenarios.md)
- [Contributing and tests](docs/contributing.md)
