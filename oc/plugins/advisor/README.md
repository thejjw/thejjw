# oc advisor plugin

Local OpenCode plugin that adds two tools: `advisor`, a second model the
executor can consult for a concise plan or course correction, and
`advisor_ctl`, which manages the plugin itself
(status/on/off/models/thinking/watch/configure).

Based on `@u007/opencode-advisor` (https://github.com/u007/opencode-advisor).
Everything below describes this copy.

## How it works

The plugin registers two tools, `advisor` and `advisor_ctl`, alongside
the built-in tools. The executor decides on its own when to call
`advisor`, following the timing rules in the tool description: before
substantive work, when stuck, when changing approach, and before
declaring done. `advisor_ctl` backs the `/advisor` command.

Each pull call creates an ephemeral `advisor-subcall` session, prompts
the advisor model with a short reviewer system prompt plus the
caller-supplied context, returns the text answer as the tool result,
then deletes the session. A recursion guard stops the advisor model
from calling back into the tool.

Separately, watch mode reviews primary turn boundaries on its own
(see Watch mode below): execution-end events snapshot the transcript
delta into an ephemeral investigative sidecar, which reports back as
severity-tagged notes. Pull and push share the model resolution,
thinking, fallback, and guidance machinery.

There are no hardcoded agent names and no dependency on the routing
config in `oc/opencode-routing`.

## Layout

```
package.json          Local package (private, never published)
index.ts              V2 package entrypoint (re-exports src/advisor.ts;
                      local dirs resolve at the package root)
src/advisor.ts        The whole plugin: tools, watch loop, settings
commands/advisor.md   /advisor command template (installed globally)
scripts/install.mjs   Minimal installer (plain Node.js)
README.md / CHANGELOG.md
PLAN.md               Design/planning notes (working doc, not a spec)
```

## Model selection

With no advisor model configured, the tool reuses the calling session's
active model (read directly from the session, so a mid-session `/models`
switch is honored). There is no advisor-specific default model; the last
resort is the global default model.

`/advisor configure model=` accepts an exact `provider/model` id, a
display name as shown in `/models`, a substring of either, or `auto`.
A `provider/model#variant` shorthand sets thinking too. Matching runs in
code against the model catalog: an unambiguous match applies, multiple
matches return a pick list, and no match names `/advisor models` for
exact ids. `thinking=` accepts a variant id valid for the resolved model
(see `/advisor thinking`), or `auto`. `enabled=` accepts `on`/`off`.
Options may appear in any order.

A stale configured model (no longer in the catalog) is a hard error, not
a silent fallback — reconfigure via `/advisor models` + `configure`.

Precedence for one call, lowest to highest:

1. Calling session's active model (plus its variant when thinking is
   `auto`), else the global default model.
2. Advisor settings (`/advisor configure model=... thinking=...`); a
   stale configured model walks `fallback` in order before failing.
3. Environment (`OPENCODE_ADVISOR_MODEL` as `provider/model[#variant]`,
   or `OPENCODE_ADVISOR_PROVIDER` plus `OPENCODE_ADVISOR_MODEL`, plus
   optional `OPENCODE_ADVISOR_VARIANT`).
4. Per-call tool args `providerID` / `modelID` / `variant`.

## Thinking level

Thinking effort is a per-model catalog variant (`provider/model#variant`
in OpenCode terms). The advisor stores it separately as `thinking` so
`auto` keeps a distinct meaning: mirror the calling session's variant
when the model is also followed, otherwise use the catalog default.

- `/advisor thinking` — lists the valid variant ids for the current
  advisor model, plus the current setting.
- `/advisor configure thinking=<variant|auto>` — validated against the
  resolved model; unknown ids are rejected with the valid list.

`auto` never reaches the model request: it is resolved per call and the
variant field is omitted for the catalog default — except when the model
is also followed (`model: auto`), in which case your session's variant is
mirrored. A session variant is never carried onto a different model.

## /advisor command

`/advisor` is a thin template (`commands/advisor.md`): it tells the model
to call the `advisor_ctl` tool with the words after `/advisor` and relay
the result verbatim (unless the result itself asks for a recommendation,
as `models` does). All logic (parsing, validation, settings, model
listing) runs in code inside the tool — the model only relays or, for
`models`, recommends per the returned criteria.

- `/advisor` or `/advisor status` — report enabled/disabled, model,
  thinking, watch state, and the last auto-review delivery (time,
  severity, preview) when watch has delivered at least once.
- `/advisor models` — handled by the tool: writes available models to
  `models_<timestamp>.txt` in the workspace via the model catalog (falling
  back to an `opencode models` dump run by the model when unreachable),
  then reads the file back and recommends 4-5. You browse the file and
  decide; the recommendation is input, not the decision.
- `/advisor thinking` — lists valid thinking variants for the advisor model.
- `/advisor on` / `/advisor off` — set `"enabled"`. While disabled the
  advisor tool stays registered but answers with a disabled notice
  instead of calling a model (no cost). Watch reviews are also gated
  on `enabled`.
- `/advisor configure [model=<...>] [thinking=<...>] [enabled=on|off] [watch=on|off] [reviewInterval=N] [fallback=<id>,...|none]` —
  invalid input is rejected with usage and changes nothing.

`advisor_ctl` is a regular plugin tool, so it also works wherever tools
work.

## Settings

Settings live in plugin storage (durable, scoped to this plugin), seeded
once from the plugin options on first run. Afterwards `/advisor configure`
is the source of truth; editing config options directly has no effect
until storage is cleared. No settings are written into `opencode.json(c)`
beyond the plugin entry itself. Watch cursors, cooldowns, and the last
delivery record live in the same storage.

## Watch mode (automatic reviews)

The pull-style `advisor` tool waits to be called. Watch mode instead
reviews primary turn boundaries on its own: when a turn ends, the plugin
snapshots the new transcript delta into an ephemeral investigative
sidecar — a short tool loop with read/grep/glob under deny-by-default
session permissions, so findings are verified against the workspace —
then delivers severity-tagged notes back: `[nit]` findings as
record-only notes that never wake the agent, `[concern]`/`[blocker]`
as new turns — except on user-interrupted turns, where everything
stays record-only (never re-wake a user who just stopped the agent).
Silence (`NO_CONCERNS`) delivers nothing.

An emission guard (normalization, noise-phrase filter, rank-aware
dedupe where escalations re-admit, budget of 4 non-blocker findings per
review with blockers exempt) keeps repeat runs quiet. After a steered
delivery, new concerns ride record-only for 3 turns (blockers exempt).
Deliveries carry an `[advisor-note]` marker so they are captured but
never re-scheduled (no advisor→primary→advisor loops); sidecar sessions
are ignored by the watcher, and a rewritten transcript (e.g. compaction)
reseeds the cursor instead of replaying.

- `/advisor configure watch=on|off` — enabling seeds the cursor at the
  current transcript length, so the first review covers only new turns.
  Default `off`.
- `/advisor configure reviewInterval=N` — review every Nth turn (default
  1); skipped turns accumulate into the next scheduled review.

Watch multiplies model calls (one per reviewed turn): prefer a
subscription provider, and keep `reviewInterval` above 1 on edit-heavy
sessions if cost matters.

## Reviewer guidance (WATCHDOG.md)

A `WATCHDOG.md` file is advisor-only guidance: review priorities,
project traps, and quality bars too noisy for the main executor. The
plugin walks from the session directory up to the git root (stopping at
the git root or home, checking both `WATCHDOG.md` and
`.opencode/WATCHDOG.md` at each level; plus a
user-level `~/.config/opencode/WATCHDOG.md`), appending what it finds
to the advisor prompt as `<attention>` blocks. It never enters the
executor's context. Files over 8KB are skipped (at most 6 files);
`@`-imports are not expanded.

## Model fallback chain

When the configured advisor model goes stale (removed from the
catalog), each call first walks `fallback` in order instead of failing:
the first listed model still in the catalog wins, keeping the
configured thinking when valid for it, else the catalog default. Only
the settings tier falls back; environment and per-call values stay
loud on error, and an exhausted chain is still a hard error telling
you to reconfigure.

- `/advisor configure fallback=<id>,...` — validated like `model=`;
  `fallback=none` clears the chain.

## Install

Requirements: OpenCode 2.x, Node.js 18 or newer for the installer.

```bash
npm install          # plugin runtime deps (@opencode/plugin), inside this dir
node scripts/install.mjs --dry-run   # inspect what would change
node scripts/install.mjs             # write global entry + command file
```

The installer defaults to copy mode: it snapshots `index.ts` and
`src/advisor.ts` into the global discovery dir
(`<config>/plugins/advisor/`), which the host loads with no config entry,
so the repo need not stay cloned. It re-copies on every run (drift shows
in `--status`), removes any config entry for mutual exclusion, and copies
`commands/advisor.md` into the global commands dir.

`--reference` instead writes a config `plugins` entry pointing at this
repo for a live dev loop (repo edits go live via hot reload or restart,
no reinstall). A legacy v1 `plugin` tuple is migrated automatically in
either mode.

A v2 config entry must be a directory: local dirs resolve at the package
root, so the package ships a root `index.ts` that re-exports
`src/advisor.ts` (a `package.json` `main` is ignored, and a file-path
entry is rejected by the server).

Then restart opencode and try `/advisor status` in a session.

`node scripts/install.mjs --remove` reverses the install.
`--status` only reports. A timestamped backup of the user config is made
before every write.

## Versioning

See `CHANGELOG.md`. Version `0.2.0` ports the plugin to the OpenCode v2
plugin API (`@opencode/plugin`, `Plugin.define`), adds thinking-level
support via catalog variants, and adds push-style watch-mode reviews
alongside the pull-style tool. The v1 implementation (OpenCode 1.x,
`@opencode-ai/*`) is preserved in git history.

## License
See [LICENSE](LICENSE).

## Attribution

This plugin is a local port of `@u007/opencode-advisor` (u007, [opencode-advisor on GitHub](https://github.com/u007/opencode-advisor)), reworked for local-only use with no hardcoded models.

---

## Author
- Jaewoo Jeon [@thejjw](https://github.com/thejjw)

If you find this plugin helpful, consider supporting its development via GitHub Sponsors (one-time or monthly), or Buy Me a Coffee:

[![Buy Me A Coffee](https://cdn.buymeacoffee.com/buttons/default-yellow.png)](https://www.buymeacoffee.com/thejjw) 
