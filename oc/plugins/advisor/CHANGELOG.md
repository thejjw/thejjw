# Changelog

## 0.1.1

- Removed command-output interception: hook-set output is ignored for
  TUI-invoked commands, so `/advisor` is now a plain model-executed
  template that reads/edits our tuple directly.
- The tool re-reads settings from disk on every call; `/advisor` changes
  apply with no restart.

## 0.1.0

- Initial local copy. Behavior matches `@u007/opencode-advisor` 1.2.3 except:
- No hardcoded default model: with no advisor model configured, the tool
  reuses the calling session's active model.
- New `/advisor [on|off|status|configure]` command; settings persist in the
  existing user opencode config, no extra files.
- Installer rewritten as plain Node.js (no bun), minimal scope.
- Dropped: `/btw` command, mempalace, bundled prompt templates.
