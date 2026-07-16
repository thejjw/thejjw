#!/usr/bin/env python3
"""Export a Codex rollout JSONL file as a chronological Markdown transcript."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import unicodedata
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from typing import Any, Iterable, TextIO

try:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
except ImportError:  # pragma: no cover - Python 3.9+ always has zoneinfo.
    ZoneInfo = None  # type: ignore[assignment]
    ZoneInfoNotFoundError = KeyError  # type: ignore[assignment]


SECRET_PATTERNS = (
    re.compile(r"\b(?:sk|sess|pat)-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\b(?:gh[opusr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(
        r"(?i)(\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|token|password|passwd|secret)\b"
        r"\s*[:=]\s*)([^\s,;\"']{6,})"
    ),
)


class Redactor:
    """Redact common credential forms while tracking replacements."""

    def __init__(self, enabled: bool) -> None:
        """Create a redactor that may be disabled for explicit raw exports."""
        self.enabled = enabled
        self.count = 0

    def text(self, value: str) -> str:
        """Return text with common secret patterns replaced."""
        if not self.enabled:
            return value
        result = value
        for pattern in SECRET_PATTERNS:
            if pattern.groups:
                result, count = pattern.subn(r"\1[REDACTED]", result)
            else:
                result, count = pattern.subn("[REDACTED]", result)
            self.count += count
        return result

    def value(self, value: Any) -> Any:
        """Recursively redact strings in JSON-compatible values."""
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.value(item) for item in value]
        if isinstance(value, dict):
            return {key: self.value(item) for key, item in value.items()}
        return value


class Exporter:
    """Render rollout records to Markdown without loading the full log."""

    def __init__(self, args: argparse.Namespace, output: TextIO) -> None:
        """Initialize counters, rendering settings, and output state."""
        self.args = args
        self.output = output
        self.zone = parse_timezone(args.timezone)
        self.redactor = Redactor(args.redact)
        self.records = 0
        self.events = 0
        self.malformed = 0
        self.sidecars = 0
        self.tool_calls: dict[str, str] = {}
        self.tool_outputs: set[str] = set()
        self.assets_dir = args.output.with_suffix(".assets")

    def write(self, value: str = "") -> None:
        """Write one Markdown line."""
        self.output.write(value + "\n")

    def heading(self, timestamp: Any, title: str) -> None:
        """Write a timestamped event heading."""
        self.write("---")
        self.write()
        self.write(f"## {format_timestamp(timestamp, self.zone)} -- {title}")
        self.write()

    def fenced(self, value: Any, language: str = "text") -> None:
        """Write a fenced block using a fence longer than any content fence."""
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=2)
        text = self.redactor.text(text)
        longest = max((len(match.group(0)) for match in re.finditer(r"`+", text)), default=0)
        fence = "`" * max(3, longest + 1)
        self.write(f"{fence}{language}")
        self.write(text.rstrip())
        self.write(fence)
        self.write()

    def render(self, record: dict[str, Any], line_number: int) -> None:
        """Render one parsed rollout record according to the detail level."""
        self.records += 1
        record_type = record.get("type", "unknown")
        payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
        payload_type = payload.get("type")

        if record_type == "response_item" and payload_type == "message":
            self.render_message(record, payload)
            return

        if self.args.detail == "messages":
            return

        if record_type == "response_item" and payload_type in {
            "custom_tool_call",
            "function_call",
        }:
            self.render_tool_call(record, payload)
            return
        if record_type == "response_item" and payload_type in {
            "custom_tool_call_output",
            "function_call_output",
        }:
            self.render_tool_output(record, payload)
            return

        if self.args.detail == "tools":
            return

        if record_type == "session_meta":
            self.render_json_event(record, "Session metadata", payload)
        elif record_type == "turn_context":
            self.render_json_event(record, "Turn context", payload)
        elif record_type == "response_item" and payload_type == "reasoning":
            self.render_reasoning(record, payload)
        elif record_type == "event_msg":
            # user_message and agent_message duplicate response_item messages.
            if payload_type not in {"user_message", "agent_message"}:
                self.render_json_event(record, f"Event: {payload_type or 'unknown'}", payload)
        else:
            self.render_json_event(record, f"Unrecognized record at line {line_number}", record)

    def render_message(self, record: dict[str, Any], payload: dict[str, Any]) -> None:
        """Render a visible message, plus developer messages in full mode."""
        role = str(payload.get("role", "unknown"))
        if role not in {"user", "assistant"} and self.args.detail != "full":
            return
        parts = []
        for item in payload.get("content", []):
            if not isinstance(item, dict):
                continue
            text = item.get("text")
            if isinstance(text, str):
                parts.append(text)
        if not parts:
            return
        self.events += 1
        self.heading(record.get("timestamp"), role.title())
        self.write(self.redactor.text("\n\n".join(parts)).rstrip())
        self.write()

    def render_tool_call(self, record: dict[str, Any], payload: dict[str, Any]) -> None:
        """Render a tool request and remember it for output pairing."""
        name = str(payload.get("name", "unknown"))
        call_id = str(payload.get("call_id") or payload.get("id") or "unknown")
        self.tool_calls[call_id] = name
        self.events += 1
        self.heading(record.get("timestamp"), f"Tool call: `{name}`")
        self.write(f"- Call ID: `{markdown_inline(call_id)}`")
        if payload.get("status") is not None:
            self.write(f"- Status: `{markdown_inline(str(payload['status']))}`")
        self.write()
        value = payload.get("input", payload.get("arguments", {}))
        self.render_large_value(value, call_id, "input")

    def render_tool_output(self, record: dict[str, Any], payload: dict[str, Any]) -> None:
        """Render a tool result and associate it with its request."""
        call_id = str(payload.get("call_id") or "unknown")
        self.tool_outputs.add(call_id)
        name = self.tool_calls.get(call_id, "unmatched")
        self.events += 1
        self.heading(record.get("timestamp"), f"Tool result: `{name}`")
        self.write(f"- Call ID: `{markdown_inline(call_id)}`")
        if call_id not in self.tool_calls:
            self.write("- Pairing: **No preceding tool call found**")
        self.write()
        self.render_large_value(payload.get("output", {}), call_id, "output")

    def render_large_value(self, value: Any, call_id: str, suffix: str) -> None:
        """Render a tool value inline or place oversized content in a sidecar."""
        normalized = maybe_parse_json(value)
        text = normalized if isinstance(normalized, str) else json.dumps(normalized, ensure_ascii=False, indent=2)
        text = self.redactor.text(text)
        if len(text) <= self.args.max_tool_output or self.args.large_output == "inline":
            self.fenced(text, "json" if not isinstance(normalized, str) else "text")
            return

        self.assets_dir.mkdir(parents=True, exist_ok=True)
        safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", call_id)[:80] or "unknown"
        sidecar = self.assets_dir / f"tool-{safe_id}-{suffix}.txt"
        sidecar.write_text(text, encoding="utf-8")
        relative = os.path.relpath(sidecar, self.args.output.parent).replace(os.sep, "/")
        self.sidecars += 1
        self.write(f"Output moved to [{sidecar.name}]({relative}) ({len(text)} characters).")
        self.write()

    def render_reasoning(self, record: dict[str, Any], payload: dict[str, Any]) -> None:
        """Render only explicit reasoning summaries, never encrypted or raw reasoning."""
        safe: dict[str, Any] = {"type": "reasoning"}
        if payload.get("summary"):
            safe["summary"] = payload["summary"]
        if payload.get("status"):
            safe["status"] = payload["status"]
        self.render_json_event(record, "Reasoning metadata", safe)

    def render_json_event(self, record: dict[str, Any], title: str, value: Any) -> None:
        """Render a generic full-detail event as redacted JSON."""
        self.events += 1
        self.heading(record.get("timestamp"), title)
        self.fenced(self.redactor.value(value), "json")

    def finish(self) -> None:
        """Write pairing diagnostics at the end of the transcript."""
        if self.args.detail == "messages":
            return
        missing_outputs = sorted(set(self.tool_calls) - self.tool_outputs)
        unmatched_outputs = sorted(self.tool_outputs - set(self.tool_calls))
        self.write("---")
        self.write()
        self.write("## Export diagnostics")
        self.write()
        self.write(f"- Tool calls without results: {len(missing_outputs)}")
        self.write(f"- Tool results without calls: {len(unmatched_outputs)}")
        if missing_outputs:
            self.write(f"- Missing result call IDs: {', '.join(f'`{markdown_inline(x)}`' for x in missing_outputs)}")
        if unmatched_outputs:
            self.write(f"- Unmatched result call IDs: {', '.join(f'`{markdown_inline(x)}`' for x in unmatched_outputs)}")
        self.write()


def parse_timezone(value: str) -> tzinfo:
    """Parse local, UTC, a fixed offset, or an IANA timezone name."""
    lowered = value.lower()
    if lowered == "local":
        return datetime.now().astimezone().tzinfo or timezone.utc
    if lowered in {"utc", "z"}:
        return timezone.utc
    match = re.fullmatch(r"([+-])(\d{2}):(\d{2})", value)
    if match:
        hours, minutes = int(match.group(2)), int(match.group(3))
        if hours > 23 or minutes > 59:
            raise ValueError(f"Invalid fixed timezone offset: {value}")
        delta = timedelta(hours=hours, minutes=minutes)
        return timezone(delta if match.group(1) == "+" else -delta)
    if ZoneInfo is not None:
        try:
            return ZoneInfo(value)
        except ZoneInfoNotFoundError as error:
            raise ValueError(
                f"Timezone '{value}' is unavailable; use local, UTC, or a fixed offset such as +09:00"
            ) from error
    raise ValueError(f"Unsupported timezone: {value}")


def format_timestamp(value: Any, zone: tzinfo) -> str:
    """Convert an ISO timestamp to the requested timezone."""
    if not isinstance(value, str):
        return "timestamp unavailable"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(zone).isoformat(timespec="milliseconds")
    except ValueError:
        return value


def markdown_inline(value: str) -> str:
    """Make short values safe inside a Markdown code span."""
    return value.replace("`", "'")


def maybe_parse_json(value: Any) -> Any:
    """Pretty-print stringified JSON inputs when possible."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def slugify_title(value: str, limit: int = 20) -> str:
    """Convert a semantic title to a short, portable ASCII filename slug."""
    normalized = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    slug = re.sub(r"[^a-z0-9]+", "-", normalized.lower()).strip("-")
    if len(slug) <= limit:
        return slug or "session"
    shortened = slug[:limit].rstrip("-")
    if slug[limit] != "-" and "-" in shortened:
        shortened = shortened.rsplit("-", 1)[0]
    return shortened or slug[:limit] or "session"


def session_date(path: Path, zone: tzinfo) -> str:
    """Return the local date of the first timestamped rollout record."""
    for _, record, error in read_records(path):
        if error is not None or record is None:
            continue
        value = record.get("timestamp")
        if not isinstance(value, str):
            continue
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(zone).strftime("%Y%m%d")
        except ValueError:
            continue
    return datetime.now(zone).strftime("%Y%m%d")


def available_output(directory: Path, filename: str) -> Path:
    """Return a collision-free output path without overwriting existing files."""
    candidate = directory / filename
    if not candidate.exists():
        return candidate
    stem, suffix = candidate.stem, candidate.suffix
    number = 2
    while True:
        candidate = directory / f"{stem}-{number}{suffix}"
        if not candidate.exists():
            return candidate
        number += 1


def read_records(path: Path) -> Iterable[tuple[int, dict[str, Any] | None, str | None]]:
    """Yield parsed records and malformed-line errors from a JSONL file."""
    with path.open("r", encoding="utf-8-sig") as source:
        for line_number, line in enumerate(source, start=1):
            try:
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise ValueError("record is not a JSON object")
                yield line_number, record, None
            except (json.JSONDecodeError, ValueError) as error:
                yield line_number, None, str(error)


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session", type=Path, required=True, help="Codex rollout JSONL path")
    parser.add_argument("--output", type=Path, help="Explicit Markdown output path")
    parser.add_argument("--output-dir", type=Path, default=Path.cwd(), help="Directory for a generated filename")
    parser.add_argument("--title", default="session", help="Semantic title; sanitized to at most 20 characters")
    parser.add_argument("--detail", choices=("messages", "tools", "full"), default="full")
    parser.add_argument("--timezone", default="local", help="local, UTC, +HH:MM, or IANA name")
    parser.add_argument("--redact", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--max-tool-output", type=int, default=100_000)
    parser.add_argument("--large-output", choices=("sidecar", "inline"), default="sidecar")
    parser.add_argument("--overwrite", action="store_true")
    return parser


def main() -> int:
    """Run the exporter and return a process exit code."""
    args = build_parser().parse_args()
    args.session = args.session.expanduser().resolve()
    args.output_dir = args.output_dir.expanduser().resolve()

    if not args.session.is_file():
        print(f"error: session file not found: {args.session}", file=sys.stderr)
        return 2
    if args.max_tool_output < 1:
        print("error: --max-tool-output must be positive", file=sys.stderr)
        return 2
    try:
        zone = parse_timezone(args.timezone)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    if args.output is not None:
        args.output = args.output.expanduser().resolve()
        if args.output.exists() and not args.overwrite:
            print(f"error: output already exists (use --overwrite): {args.output}", file=sys.stderr)
            return 2
    else:
        slug = slugify_title(args.title)
        date = session_date(args.session, zone)
        filename = f"codex-{date}-{slug}-{args.detail}.md"
        args.output = available_output(args.output_dir, filename)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(args.output.name + ".tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as output:
            exporter = Exporter(args, output)
            exporter.write("# Codex Session Export")
            exporter.write()
            exporter.write(f"- Source: `{markdown_inline(str(args.session))}`")
            exporter.write(f"- Exported: {datetime.now().astimezone().isoformat(timespec='seconds')}")
            exporter.write(f"- Timezone: `{markdown_inline(args.timezone)}`")
            exporter.write(f"- Detail: `{args.detail}`")
            exporter.write(f"- Redaction: `{'enabled' if args.redact else 'disabled'}`")
            exporter.write()

            for line_number, record, error in read_records(args.session):
                if error is not None:
                    exporter.malformed += 1
                    if args.detail == "full":
                        exporter.events += 1
                        exporter.heading(None, f"Malformed JSONL line {line_number}")
                        exporter.write(exporter.redactor.text(error))
                        exporter.write()
                    continue
                assert record is not None
                exporter.render(record, line_number)
            exporter.finish()

        temporary.replace(args.output)
    except OSError as error:
        temporary.unlink(missing_ok=True)
        print(f"error: {error}", file=sys.stderr)
        return 1

    print(f"output={args.output}")
    print(f"records={exporter.records}")
    print(f"events={exporter.events}")
    print(f"malformed={exporter.malformed}")
    print(f"redactions={exporter.redactor.count}")
    print(f"sidecars={exporter.sidecars}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
