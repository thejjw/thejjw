# Changelog

## 0.2.0

- Port to the OpenCode v2 plugin API (`@opencode/plugin`,
  `Plugin.define` with `id: "advisor"`). V1 implementations do not run on
  v2 hosts. The v1 implementation is preserved in git history.
- Tools registered via `ctx.tool.transform` with JSON Schema inputs;
  executors return `{ content }`.
- Settings moved from hand-edited `opencode.json(c)` plugin-tuple options
  to plugin storage (`ctx.storage`), seeded once from plugin options.
  `/advisor configure` is the source of truth afterwards.
- Session model/variant read directly from the session (`session.get`),
  replacing the v1 transcript scan. Thinking `auto` mirrors the session
  variant when the model is also followed.
- New `thinking` setting: per-model catalog variant, default `auto`.
  `/advisor thinking` lists valid variant ids for the advisor model;
  `configure thinking=` validates against the catalog and rejects unknown
  ids with the valid list. `configure model=` accepts a `#variant`
  shorthand. Per-call tool args gain `variant`.
- Call-time validation: a stale configured model or variant is a hard
  error naming the fix (no silent fallback). Session/default lookup
  failures still fall through gracefully.
- Advisor subcall uses transient `session.generate` (no history) with the
  model+variant set at `session.create`; server failures return an
  `Error:` message instead of propagating an exception.
- New `watch` mode: automatic turn-boundary reviews via execution-end
  events (transcript delta → ephemeral sidecar → severity-tagged
  delivery: nits record-only, concerns/blockers as new turns).
  `configure watch=` / `reviewInterval=`, cursor reseeds on enable and
  compaction, cascade guard via delivery marker.
- Watch sidecars run an investigative tool loop (read/grep/glob under
  deny-by-default session permissions) before verdicting; a bounded
  wait with interrupt caps runaway loops, and execution failures
  advance the cursor instead of retry-storming.
- Emission guard (omp-inspired): finding sections split by severity
  tag, noise-phrase filter, rank-aware dedupe with escalation,
  budget of 4 non-blockers per review (blockers exempt).
- Post-steer cooldown: concerns ride record-only for 3 turns
  (blockers exempt).
- `/advisor status` reports the last auto-review delivery (time,
  severity, first-line preview) from plugin storage.
- A literal per-call `variant=auto` normalizes to omitted (catalog
  default) instead of reaching the request as an unknown variant id.
- Reviewer-only `WATCHDOG.md` guidance (session dir up to git root plus
  user level, `<attention>` blocks, executor never sees it).
- Model `fallback` chain for stale configured models (ordered,
  thinking kept when valid, else catalog default; exhausted chain
  stays a hard error). Stale-result eviction is N/A by design: every
  review runs in a fresh sidecar that is removed afterwards.
- New `SYSTEM_PROMPT`: silence-first (`NO_CONCERNS`), severity tags,
  anti-nag and evidence rules.
- Catalog reads unwrap the `{ location, data }` envelope returned by
  `model.list()`/`model.default()` (a bare array is also tolerated).
  The `models` listing is location-scoped to the calling session.
- Installer defaults to copy mode (snapshot into the global discovery
  dir, no config entry, repo need not stay cloned) with `--reference`
  for a live dev loop via a `plugins` entry; the two are mutually
  exclusive. A root `index.ts` re-exports `src/advisor.ts` because v2
  rejects file-path entries ("configured plugin path must be a
  directory") and ignores `package.json` `main` for local dirs. Migrates
  a legacy v1 `plugin` tuple automatically.
- Dev: `@types/node` so `tsc` is clean.

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
