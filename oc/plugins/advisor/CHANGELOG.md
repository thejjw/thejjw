# Changelog

## 0.1.0

- Initial local copy. Behavior matches `@u007/opencode-advisor` 1.2.3 except:
- No hardcoded default model: with no advisor model configured, the tool
  reuses the calling session's active model.
- New `/advisor [on|off|status|configure]` command; settings persist in the
  existing user opencode config, no extra files.
- Installer rewritten as plain Node.js (no bun), minimal scope.
- Dropped: `/btw` command, mempalace, bundled prompt templates.
