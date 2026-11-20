"""Command line entry point.

Subcommands:

``fetch``   query providers and emit JSON (stdout, or one file per provider)
``render``  turn saved JSON documents into the plain-text report
``report``  fetch the local providers and render them in one step (debugging)

The cron runner uses ``fetch --out DIR`` then ``render DIR`` so that the
output can be reproduced from saved documents without touching the network.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from . import keys
from .alert import render_alert
from .contract import UsageReport
from .providers import PROVIDERS
from .render import render_message

DEFAULT_PROVIDERS = ("zai", "kimi", "minimax", "deepseek")


def collect(providers: Sequence[str], explicit: dict[str, str] | None = None) -> list[UsageReport]:
    """Fetch each provider, turning any failure into an unavailable report."""
    explicit = explicit or {}
    reports: list[UsageReport] = []
    for name in providers:
        module = PROVIDERS[name]
        api_key = keys.resolve(name, explicit.get(name))
        if not api_key:
            reports.append(UsageReport.unavailable(name, "no credential configured"))
            continue
        try:
            reports.append(module.fetch(api_key))
        except Exception as exc:  # one provider must never abort the run
            reason = str(exc).strip() or type(exc).__name__
            reports.append(UsageReport.unavailable(name, reason[:80]))
    return reports


def load_documents(paths: list[str]) -> list[UsageReport]:
    """Read report documents from files and directories (``*.json``)."""
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            files.extend(sorted(path.glob("*.json")))
        elif path.is_file():
            files.append(path)
        else:
            print(f"aiusage: not found: {raw}", file=sys.stderr)
    reports: list[UsageReport] = []
    for path in files:
        try:
            doc = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            print(f"aiusage: skipping {path}: {exc}", file=sys.stderr)
            continue
        # A snapshot file holds a JSON array; a provider document is a single
        # object. Raw provider payloads in the same directory are ignored.
        for candidate in doc if isinstance(doc, list) else [doc]:
            if not isinstance(candidate, dict) or "provider" not in candidate:
                print(f"aiusage: skipping {path}: not a usage report", file=sys.stderr)
                continue
            reports.append(UsageReport.from_document(candidate))
    return reports


def write_documents(reports: list[UsageReport], out_dir: Path) -> None:
    """Write one ``<provider>.json`` per report into ``out_dir``."""
    out_dir.mkdir(parents=True, exist_ok=True)
    for report in reports:
        (out_dir / f"{report.provider}.json").write_text(
            json.dumps(report.to_document(), indent=2) + "\n"
        )


def cmd_fetch(args: argparse.Namespace) -> int:
    """Implement ``fetch``: collect, then emit JSON or files."""
    providers = args.provider or list(DEFAULT_PROVIDERS)
    reports = collect(providers)
    if args.out:
        write_documents(reports, Path(args.out))
    if args.json or not args.out:
        print(json.dumps([report.to_document() for report in reports], indent=2))
    return 0 if any(report.available for report in reports) else 1


def cmd_render(args: argparse.Namespace) -> int:
    """Implement ``render``: print the message for saved documents."""
    reports = load_documents(args.paths)
    if not reports:
        print("aiusage: no readable report documents", file=sys.stderr)
        return 1
    now = datetime.now(timezone.utc) if args.now is None else _parse_now(args.now)
    previous = load_documents([args.previous]) if args.previous else None
    print(render_message(reports, now, previous=previous))
    return 0


def cmd_snapshot(args: argparse.Namespace) -> int:
    """Implement ``snapshot``: save the current documents for the next run."""
    reports = load_documents([args.path])
    if not reports:
        print("aiusage: no readable report documents", file=sys.stderr)
        return 1
    payload = [report.to_document() for report in reports]
    Path(args.out).write_text(json.dumps(payload, indent=2) + "\n")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Implement ``report``: fetch and render in one step."""
    reports = collect(args.provider or list(DEFAULT_PROVIDERS))
    now = datetime.now(timezone.utc) if args.now is None else _parse_now(args.now)
    print(render_message(reports, now))
    return 0 if any(report.available for report in reports) else 1


def cmd_alert(args: argparse.Namespace) -> int:
    """Implement ``alert``: render only the weekly windows resetting soon."""
    reports = load_documents(args.paths)
    if not reports:
        print("aiusage: no readable report documents", file=sys.stderr)
        return 1
    now = datetime.now(timezone.utc) if args.now is None else _parse_now(args.now)
    within = tuple(sorted({int(part) for part in args.within.split(",") if part}))
    message = render_alert(reports, now, within=within)
    if message:
        print(message)
    return 0


def _parse_now(value: str) -> datetime:
    """Parse an ISO-8601 instant supplied on the command line."""
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(prog="aiusage", description="AI subscription usage report")
    sub = parser.add_subparsers(dest="command", required=True)

    fetch = sub.add_parser("fetch", help="query providers and emit JSON")
    fetch.add_argument("--provider", action="append", choices=sorted(PROVIDERS))
    fetch.add_argument("--json", action="store_true", help="print JSON to stdout")
    fetch.add_argument("--out", help="write one <provider>.json per provider into this directory")
    fetch.set_defaults(func=cmd_fetch)

    render = sub.add_parser("render", help="render saved JSON documents")
    render.add_argument("paths", nargs="+", help="JSON files or directories")
    render.add_argument("--previous", help="previous run's snapshot (JSON file or directory)")
    render.add_argument("--now", help="override the report time (ISO-8601, for testing)")
    render.set_defaults(func=cmd_render)

    snapshot = sub.add_parser("snapshot", help="save documents for the next run's comparison")
    snapshot.add_argument("path", help="directory of saved documents")
    snapshot.add_argument("--out", required=True, help="file to write the snapshot to")
    snapshot.set_defaults(func=cmd_snapshot)

    report = sub.add_parser("report", help="fetch and render in one step")
    report.add_argument("--provider", action="append", choices=sorted(PROVIDERS))
    report.add_argument("--now", help="override the report time (ISO-8601, for testing)")
    report.set_defaults(func=cmd_report)

    alert = sub.add_parser("alert", help="render weekly windows resetting in 1-2 days")
    alert.add_argument("paths", nargs="+", help="JSON files or directories")
    alert.add_argument("--within", default="1,2", help="comma-separated day offsets")
    alert.add_argument("--now", help="override the report time (ISO-8601, for testing)")
    alert.set_defaults(func=cmd_alert)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and dispatch; returns the process exit code."""
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
