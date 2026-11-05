"""Operational CLI: shared services, finite actions, JSON output by default."""
from __future__ import annotations

import argparse
import importlib.metadata
import json
from pathlib import Path
import platform
import sqlite3
import sys
import time

from . import __version__, crypto, environment, scenarios
from .core.errors import DependencyError, LabError, SafetyError, StateError, ValidationError


def parser():
    root = argparse.ArgumentParser(prog="ransomlab", description="Generated-fixture cybersecurity training. No arbitrary file targets.")
    root.add_argument("--version", action="version", version=__version__)
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="Read-only runtime and safety-gate diagnostics")
    lab = commands.add_parser("lab", help="Manage generated disposable labs").add_subparsers(dest="action", required=True)
    create = lab.add_parser("create", help="Generate original samples and verified clean copies")
    create.add_argument("--name", default="Training lab")
    create.add_argument("--count", type=int, default=12)
    create.add_argument("--size", type=int, default=4096, help="Bytes per generated sample")
    lab.add_parser("list")
    status = lab.add_parser("status")
    status.add_argument("lab_id")
    arm = lab.add_parser("arm", help="One-use arming in a disposable VMware guest")
    arm.add_argument("lab_id")
    arm.add_argument("--snapshot", required=True, help="Previously created clean snapshot label")
    arm.add_argument("--isolated", action="store_true", help="Confirm host-only isolation and disabled host integration")
    arm.add_argument("--disposable", action="store_true", help="Confirm dedicated non-sensitive disposable guest")
    scenario = commands.add_parser("scenario", help="Prepare or import data-only fixed actions").add_subparsers(dest="action", required=True)
    describe = scenario.add_parser("describe", help="Export generated IDs for offline Kali authoring")
    describe.add_argument("lab_id")
    for name, target in (("create", "lab_id"), ("compose", "descriptor_file")):
        command = scenario.add_parser(name)
        command.add_argument(target)
        command.add_argument("scenario", choices=tuple(scenarios.SCENARIOS))
        command.add_argument("--count", type=int)
    importing = scenario.add_parser("import", help="Validate and stage only; never execute on import")
    importing.add_argument("file")
    sim = commands.add_parser("simulate", help="Run a staged fixed action on generated fixtures in an armed VM")
    sim.add_argument("lab_id")
    sim.add_argument("request_id")
    mon = commands.add_parser("monitor", help="Hash approved fixture inventory and correlate changes")
    mon.add_argument("lab_id")
    mon.add_argument("--watch", action="store_true")
    mon.add_argument("--interval", type=float, default=2)
    mon.add_argument("--samples", type=int, default=10)
    for name in ("contain", "reconcile", "investigate"):
        command = commands.add_parser(name)
        command.add_argument("lab_id")
    evidence = commands.add_parser("evidence").add_subparsers(dest="action", required=True)
    preserve = evidence.add_parser("preserve")
    preserve.add_argument("lab_id")
    recovery = commands.add_parser("recover")
    recovery.add_argument("lab_id")
    recovery.add_argument("--mode", choices=("clean", "decrypt"), default="clean")
    report = commands.add_parser("report")
    report.add_argument("lab_id")
    report.add_argument("--format", choices=("json", "markdown", "jsonl"), default="json")
    server = commands.add_parser("serve", help="Authenticated read-only dashboard on 127.0.0.1")
    server.add_argument("--port", type=int, default=8765)
    return root


def _read_document(path):
    # A user-selected document is an explicit local import, never a target path.
    try:
        with Path(path).open("rb") as source:
            data = source.read(scenarios.MAX_ENVELOPE_BYTES + 1)
    except OSError:
        raise ValidationError("The selected local import document could not be read") from None
    return scenarios.parse_json(data)


def doctor():
    from .storage import SafeDirectory
    result = {"version": __version__, "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
              "vmware_guest_detected": environment.vmware_guest(), "unprivileged_process": environment.unprivileged_process(),
              "snapshot_and_isolation": "requires_operator_verification", "packages": {}}
    for package in ("Flask", "uvicorn", "cryptography"):
        try:
            result["packages"][package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            result["packages"][package] = "not_installed"
    try:
        with SafeDirectory(Path(__file__).resolve().parent.parent):
            result["filesystem_gate"] = "available_for_preparation"
    except LabError as exc:
        result["filesystem_gate"] = "blocked"
        result["filesystem_reason"] = str(exc)
    try:
        result["crypto_provider"] = crypto.provider_name()
    except DependencyError:
        result["crypto_provider"] = "unavailable"
    return result


def markdown_report(report):
    rows = [f"# RansomLab incident report: {report['name']}", "", f"Lab: {report['lab_id']}",
            f"State: {report['state']}", f"Generated: {report['report_created_at']}", "", "## Findings", "",
            f"Changed fixtures: {report['findings']['changed']}; missing: {report['findings']['missing']}; alerts: {report['findings']['alerts']}.",
            f"Current recovery verified: {str(report['findings']['recovery_verified']).lower()}.", "", "## Timeline", "",
            "| Sequence | UTC time | Source | Event | Outcome |", "| --- | --- | --- | --- | --- |"]
    for event in report["events"]:
        rows.append(f"| {event['sequence']} | {event['created_at']} | {event['source']} | {event['kind']} | {event['outcome']} |")
    rows += ["", "## Recommendations", ""] + ["- " + text for text in report["recommendations"]]
    rows += ["", "## Limits", "", "Generated exercise artifacts only. Hashes require a trusted baseline and do not establish authorship."]
    return "\n".join(rows)


def main(argv=None, service=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "doctor":
            value = doctor()
        elif args.command == "serve":
            from .server import serve
            serve(args.port, service=service)
            return 0
        elif args.command == "scenario" and args.action == "compose":
            value = scenarios.create(scenarios.descriptor(_read_document(args.descriptor_file)), args.scenario, args.count)
        else:
            if service is None:
                from .services import LabService
                service = LabService.default()
            if args.command == "lab":
                if args.action == "create":
                    value = service.create_lab(args.name, args.count, args.size)
                elif args.action == "list":
                    value = service.list_labs()
                elif args.action == "status":
                    value = service.status(args.lab_id)
                else:
                    value = service.arm(args.lab_id, args.snapshot, args.isolated, args.disposable)
            elif args.command == "scenario":
                if args.action == "create":
                    value = service.create_scenario(args.lab_id, args.scenario, args.count)
                elif args.action == "describe":
                    value = service.descriptor(args.lab_id)
                else:
                    value = service.import_scenario(_read_document(args.file))
            elif args.command == "simulate":
                value = service.simulate(args.lab_id, args.request_id)
            elif args.command == "monitor":
                if not 0.2 <= args.interval <= 60 or not 1 <= args.samples <= 150 or args.interval * args.samples > 300:
                    raise ValidationError("Monitoring must fit within 300 seconds, 150 samples and a 0.2 to 60 second interval")
                if args.watch:
                    for number in range(args.samples):
                        print(json.dumps(service.monitor(args.lab_id), sort_keys=True), flush=True)
                        if number + 1 < args.samples:
                            time.sleep(args.interval)
                    return 0
                value = service.monitor(args.lab_id)
            elif args.command in ("contain", "reconcile", "investigate"):
                value = getattr(service, args.command)(args.lab_id)
            elif args.command == "evidence":
                value = service.preserve(args.lab_id)
            elif args.command == "recover":
                value = service.recover(args.lab_id, args.mode)
            elif args.command == "report":
                value = service.report(args.lab_id)
                if args.format == "markdown":
                    print(markdown_report(value))
                    return 0
                if args.format == "jsonl":
                    for event in value["events"]:
                        print(json.dumps(event, sort_keys=True, allow_nan=False))
                    return 0
            else:
                raise ValidationError("Unsupported operation")
        print(json.dumps(value, indent=2, sort_keys=True, allow_nan=False))
        return 0
    except LabError as exc:
        print(json.dumps({"error": {"type": type(exc).__name__, "message": str(exc)}}), file=sys.stderr)
        return 2 if isinstance(exc, ValidationError) else 3 if isinstance(exc, SafetyError) else 5 if isinstance(exc, DependencyError) else 4
    except OSError:
        print(json.dumps({"error": {"type": "StorageError", "message": "The requested local resource is unavailable"}}), file=sys.stderr)
        return 4
    except KeyboardInterrupt:
        print(json.dumps({"error": {"type": "Interrupted", "message": "Operation interrupted; reconcile any active lab"}}), file=sys.stderr)
        return 130
