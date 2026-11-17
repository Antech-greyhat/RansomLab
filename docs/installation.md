# Installation reference

The [README](../README.md#getting-started) contains the quick start. Use Python
3.13 or 3.14 and run from a source checkout.

## Create an environment

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
ransomlab --help
ransomlab doctor
```

On Windows, use `.venv\Scripts\Activate.ps1` to activate the environment.
Editable installation keeps package resources and the managed workspace anchored
to the checkout. The core has no third-party runtime dependencies. Its pinned
setuptools build backend is downloaded by pip during installation.

## Dashboard dependencies

```bash
python -m pip install -e ".[dashboard]" -c constraints-dashboard.txt
ransomlab serve --port 8765
```

The dashboard uses Flask/Jinja with the existing bounded Uvicorn WSGI adapter.
The constraints file fixes the inherited dependency set; it is not a current
vulnerability or artifact-provenance attestation. See
[dependency decisions](implementation/dependencies.md) for maintenance limits.

## Cryptography dependencies

```bash
python -m pip install --require-hashes -r requirements-crypto.txt
python -m pip install -e ".[crypto]"
```

The wheel-only requirements pin cryptography 50.0.2, cffi 2.1.1 and pycparser 3.12
with official PyPI artifact hashes for CPython 3.13/3.14 on Windows x64 and glibc
Linux x86_64. Other architectures and source builds require a separate reviewed
manifest. See [dependency decisions](implementation/dependencies.md#phase-2-cryptography-dependencies--2026-11-17).

Windows AES-GCM retains the operating-system CNG provider; non-Windows AES-GCM
uses cryptography. RSA-OAEP and Ed25519 studies need cryptography on both platforms.
Missing providers fail explicitly. Metadata management, configuration and offline
scenario composition remain available without the extra.

## Configuration and workspace

`ransomlab.toml` in the source checkout is the default optional configuration.
Use `--config` before the subcommand to select another bounded TOML file.
`ransomlab.example.toml` demonstrates tighter limits and JSON diagnostics.

```bash
ransomlab --config ransomlab.example.toml config check
```

Workspace paths are not configurable. Generated data, clean copies, keys and
SQLite records stay under `<checkout>/.ransomlab`. Never copy user files there.
Use the same or tighter policy when reopening a saved experiment.

File-impact execution requires an independently approved disposable VMware guest
and non-elevated account. On Windows, storage must be local NTFS and permit the
required ancestor handles. A blocked filesystem check is not resolved by elevation
or removing protections. See [safety](security.md) and [usage](usage.md).

## Test the checkout

```bash
python scripts/validate.py
```

The runner writes `output/validation/tests.json` and distinguishes passes from
blocked/skipped cases. Service tests use synthetic memory fixtures and temporary
SQLite records. Native metadata/storage checks use generated disposable paths;
VM file-impact acceptance is a separate explicit procedure. See
[test strategy](requirements.md#test-strategy).
