---
name: export-chat-codex
description: Export the current or a specified Codex conversation as a chronological Markdown transcript from Codex rollout JSONL, with timestamps, messages, commentary, tool calls and results, web activity, patches, lifecycle events, usage data, and session settings. Use when the user asks to export, save, archive, inspect, or serialize a Codex chat, conversation, session, transcript, or execution trace. Do not use for conversations from other AI agents.
---

# Export Codex Chat

Use `scripts/export_codex_chat.py` to export a Codex rollout JSONL file. Treat the rollout as sensitive because it can contain prompts, private file contents, commands, tool output, and credentials.

## Locate the session

1. Prefer a rollout path explicitly supplied by the user.
2. Otherwise search `$CODEX_HOME/sessions`; fall back to `~/.codex/sessions`.
3. Match the active rollout using a distinctive recent user message from the current conversation. Use file recency only to narrow candidates, not as the sole selector when multiple live sessions exist.
4. Ask the user to choose when exactly one session cannot be established.
5. Never modify the source rollout.

## Run the exporter

Find Python in this order: `python3`, `python`, then Windows `py -3`.

```text
<python> scripts/export_codex_chat.py --session <rollout.jsonl> --output-dir <workspace> --title <summary> --detail full --timezone local
```

Use an explicitly requested output path with `--output`. Otherwise infer a concise semantic summary from the existing conversation context without making another model call. Pass it through `--title` using at most 20 characters, preferably two to four descriptive words. The script sanitizes the title and writes this pattern in the workspace:

```text
codex-YYYYMMDD-<summary>-<detail>.md
```

For example: `codex-20260716-chat-export-skill-full.md`. Avoid generic summaries such as `conversation` when the topic is clear. The script uses `session` when the title is empty and adds `-2`, `-3`, and so on rather than overwriting a collision.

Detail levels:

- `messages`: visible user and assistant messages.
- `tools`: messages plus tool calls and tool outputs.
- `full`: all records in source order, including session metadata, settings, lifecycle and usage events, with unrecognized records preserved as JSON.

Use `full` unless the user requests a smaller export. Redaction is enabled by default. Pass `--no-redact` only when the user explicitly requests an unredacted export after being warned that rollout logs may contain secrets. Oversized tool outputs go to a sibling `.assets` directory by default; use `--large-output inline` only when the user requires one physical file.

Timezone values may be `local`, `utc`, a fixed offset such as `+09:00`, or an IANA name such as `Asia/Seoul` when the Python installation has timezone data.

## Verify

Confirm that the exporter exits successfully and reports its record, event, malformed-line, redaction, and sidecar counts. Check that the output:

- declares its timezone and detail level;
- keeps events chronological and in source order;
- pairs tool calls and outputs by `call_id` and reports unmatched records;
- retains Unicode text and paths as UTF-8;
- reports malformed JSONL lines instead of silently discarding them;
- does not expose hidden reasoning; reasoning records include only safe metadata or explicit summaries.

Return the output path and a concise count summary. Do not claim Codex has a built-in `/export` command.
