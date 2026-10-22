"""Command line interface for Proofpacket."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .core import (ValidationError, assess_packet, atomic_write, capture_check,
                   fingerprint_files, packet_bytes, render_report, validate_packet)


def _protect_inputs(output, sources):
    if output is None:
        return
    destination = Path(output).resolve()
    for source in sources:
        if source is not None and destination == Path(source).resolve():
            raise ValidationError("output must not overwrite an input file; choose a separate report path")


def _json_file(path: Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"cannot read JSON file {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"JSON file must contain an object: {path}")
    return value


def _read_text(path: Path, label: str) -> str:
    try:
        value = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValidationError(f"cannot read {label} {path}: {exc}") from exc
    if not value.strip():
        raise ValidationError(f"{label} must not be empty: {path}")
    return value


def _load_packet(path: Path) -> dict:
    packet = _json_file(path)
    validate_packet(packet)
    return packet


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="proofpacket", description="Capture local command evidence and check whether it remains current.")
    parser.add_argument("--version", action="version", version=f"proofpacket {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="create a packet from task, claims, and selected files")
    init.add_argument("--task", required=True, type=Path)
    init.add_argument("--claims", required=True, type=Path)
    init.add_argument("--root", type=Path, default=Path.cwd())
    init.add_argument("--path", action="append", required=True, help="selected relative source path; repeat for each file")
    init.add_argument("--out", required=True, type=Path)

    run = commands.add_parser("run", help="record an explicitly supplied command")
    run.add_argument("packet", type=Path)
    run.add_argument("--root", type=Path, default=Path.cwd())
    run.add_argument("--id", required=True)
    run.add_argument("--timeout", type=float, default=60)

    link = commands.add_parser("link", help="link a recorded check to a claim")
    link.add_argument("packet", type=Path)
    link.add_argument("--claim", required=True)
    link.add_argument("--check", required=True)

    verify = commands.add_parser("verify", help="assess freshness and execution outcomes")
    verify.add_argument("packet", type=Path)
    verify.add_argument("--root", type=Path, default=Path.cwd())
    verify.add_argument("--out", type=Path, required=True)

    report = commands.add_parser("report", help="write a static Markdown review report")
    report.add_argument("packet", type=Path)
    report.add_argument("--root", type=Path, default=Path.cwd())
    report.add_argument("--out", type=Path, required=True)
    return parser


def _execute(args: argparse.Namespace) -> int:
    if args.command == "init":
        _protect_inputs(args.out, [args.task, args.claims, *[args.root / name for name in args.path]])
        task = _read_text(args.task, "task")
        source = _json_file(args.claims)
        if type(source.get("schema_version")) is not int or source.get("schema_version") != 1:
            raise ValidationError("claims schema_version must be integer 1")
        claims, assumptions = source.get("claims"), source.get("assumptions")
        if not isinstance(claims, list) or not isinstance(assumptions, list):
            raise ValidationError("claims.json must contain claims and assumptions arrays")
        if any(not isinstance(c, dict) or c.get("check_ids") != [] for c in claims):
            raise ValidationError("initial claim check_ids must all be empty arrays")
        hashes = fingerprint_files(args.root, args.path)
        packet = {"schema_version": 1, "task": task,
                  "selected_paths": [{"path": p, "sha256": digest} for p, digest in hashes.items()],
                  "claims": claims, "assumptions": assumptions, "checks": []}
        validate_packet(packet)
        atomic_write(args.out, packet_bytes(packet))
        return 0
    if args.command == "run":
        packet = _load_packet(args.packet)
        if any(check["id"] == args.id for check in packet["checks"]):
            raise ValidationError(f"duplicate check id: {args.id!r}")
        argv = list(args.command_argv)
        if not argv or not argv[0]:
            raise ValidationError("supply a command after --")
        if args.timeout <= 0:
            raise ValidationError("timeout must be a positive number")
        # Validate root and all selected source files before executing the command.
        root = args.root.resolve(strict=True)
        if not root.is_dir():
            raise ValidationError(f"root is not a directory: {root}")
        paths = [item["path"] for item in packet["selected_paths"]]
        fingerprint_files(root, paths)
        check = capture_check(root, paths, args.id, argv, args.timeout)
        packet["checks"].append(check)
        # Existing references were validated before execution; this validates the complete mutation.
        validate_packet(packet)
        atomic_write(args.packet, packet_bytes(packet))
        return 0 if check["status"] == "completed" and check["exit_code"] == 0 else 1
    if args.command == "link":
        packet = _load_packet(args.packet)
        claims = {claim["id"]: claim for claim in packet["claims"]}
        checks = {check["id"] for check in packet["checks"]}
        if args.claim not in claims:
            raise ValidationError(f"unknown claim id: {args.claim!r}")
        if args.check not in checks:
            raise ValidationError(f"unknown check id: {args.check!r}")
        if args.check in claims[args.claim]["check_ids"]:
            raise ValidationError(f"claim {args.claim!r} already links check {args.check!r}")
        claims[args.claim]["check_ids"].append(args.check)
        validate_packet(packet)
        atomic_write(args.packet, packet_bytes(packet))
        return 0
    if args.command == "verify":
        packet = _load_packet(args.packet)
        _protect_inputs(args.out, [args.packet, *[args.root / item["path"] for item in packet["selected_paths"]]])
        assessment = assess_packet(packet, args.root)
        atomic_write(args.out, (json.dumps(assessment, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        return 1 if assessment["adverse"] else 0
    if args.command == "report":
        packet = _load_packet(args.packet)
        _protect_inputs(args.out, [args.packet, *[args.root / item["path"] for item in packet["selected_paths"]]])
        assessment = assess_packet(packet, args.root)
        atomic_write(args.out, render_report(packet, assessment).encode("utf-8"))
        return 0
    raise AssertionError("unreachable command")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    try:
        incoming = list(sys.argv[1:] if argv is None else argv)
        command_argv: list[str] = []
        if incoming and incoming[0] == "run":
            if "--" not in incoming:
                raise ValidationError("supply a command after --")
            split_at = incoming.index("--")
            command_argv = incoming[split_at + 1:]
            incoming = incoming[:split_at]
        args = parser.parse_args(incoming)
        if args.command == "run":
            args.command_argv = command_argv
        return _execute(args)
    except ValidationError as exc:
        print(f"proofpacket: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"proofpacket: I/O error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
