# Changelog

## 0.1.0

- Initial local copy, based on `@u007/opencode-advisor` 1.2.3 behavior.
- No hardcoded default model: with no advisor model configured, the tool
  reuses the calling session's active model.
- New `advisor_ctl` tool: /advisor parsing, validation, and config edits
  run in code; the `/advisor` command template only relays the tool
  result. (A command-output hook was tried first; hook output is ignored
  for TUI-invoked commands on current opencode, so the hook was removed.)
- `configure model=` fuzzy-matches ids and display names; unambiguous
  match applies, else a pick list. `/advisor models` is model-executed
  (shell dump plus recommendation), not code. No hardcoded default model.
- Settings re-read from disk on every tool call; control changes apply
  with no restart.
- Installer rewritten as plain Node.js (no bun), minimal scope.
- Dropped: `/btw` command, mempalace, bundled prompt templates.
