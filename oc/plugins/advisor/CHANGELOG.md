# Changelog

## 0.1.0

- Initial local copy, based on `@u007/opencode-advisor` 1.2.3 behavior.
- No hardcoded default model: with no advisor model configured, the tool
  reuses the calling session's active model.
- New `advisor_ctl` tool: /advisor parsing, validation, config edits, and
  the models listing run in code; the `/advisor` command template is a thin
  relay of the tool result (it follows a recommendation request for
  `models`). (A command-output hook was tried first; hook output is ignored
  for TUI-invoked commands on current opencode, so the hook was removed.)
- `configure model=` fuzzy-matches ids and display names; unambiguous
  match applies, else a pick list. No hardcoded default model.
- `/advisor models` is tool-handled: writes the dump file itself
  (`models_<timestamp>.txt` in the workspace, per-call session directory
  first) and returns only a compact summary (path, per-provider counts,
  executor baseline, criteria) asking the model to read the file back and
  recommend 4-5. Detail stays in the file for the user to investigate, not
  in the transcript. Falls back to a model-run `opencode models` dump when
  the API is unreachable or the write fails.
- Model candidates carry free/reasoning/context/status flags for the pick.
- Added `models_*.txt` to `.gitignore`.
- Settings re-read from disk on every tool call; control changes apply
  with no restart.
- Installer rewritten as plain Node.js (no bun), minimal scope.
- Dropped: `/btw` command, mempalace, bundled prompt templates.
