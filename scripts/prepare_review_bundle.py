"""Build a local, unsigned source-review archive; never publishes or commits."""
from pathlib import Path
import hashlib
import json
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ransomlab import __version__

ALLOWED = {".py", ".md", ".ps1", ".sh", ".txt", ".html", ".css", ".js", ".svg", ".png"}


def main():
    selected = [ROOT / "README.md", ROOT / ".gitignore", ROOT / "constraints-dashboard.txt"]
    for name in ("ransomlab", "tests", "scripts", "docs"):
        for path in (ROOT / name).rglob("*"):
            if "__pycache__" in path.parts or not path.is_file() or path.suffix not in ALLOWED:
                continue
            if path.is_symlink() or not path.resolve().is_relative_to(ROOT):
                raise RuntimeError("Review input must remain inside the source workspace")
            selected.append(path)
    selected = sorted(set(selected))
    inventory = {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in selected}
    manifest = {"version": __version__, "kind": "unsigned-private-review", "commit": None,
                "native_vm_validation": "pending", "files_sha256": inventory}
    output = ROOT / "output" / "review"
    output.mkdir(parents=True, exist_ok=True)
    archive = output / f"RansomLab-{__version__}-review.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in selected:
            bundle.write(path, arcname=path.relative_to(ROOT).as_posix())
        bundle.writestr("review-manifest.json", json.dumps(manifest, indent=2) + "\n")
    # Read back every member: the digest manifest is evidence of what was bundled,
    # not a signature or proof of trusted source provenance.
    with zipfile.ZipFile(archive) as bundle:
        assert bundle.testzip() is None
        assert set(bundle.namelist()) == set(inventory) | {"review-manifest.json"}
        for name, digest in inventory.items():
            if hashlib.sha256(bundle.read(name)).hexdigest() != digest:
                raise RuntimeError("Review archive verification failed")
    result = {"artifact": archive.relative_to(ROOT).as_posix(), "source_files": len(selected),
              "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(), "verified": True}
    (output / "bundle-result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
