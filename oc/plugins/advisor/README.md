# oc advisor plugin

Local OpenCode plugin that adds an `advisor` tool: a second model the
executor can consult for a concise plan or course correction.

Based on `@u007/opencode-advisor` (https://github.com/u007/opencode-advisor).
Everything below describes this copy.

## How it works

The plugin registers one tool, `advisor`, alongside the built-in tools. The
executor decides on its own when to call it, following the timing rules in
the tool description: before substantive work, when stuck, when changing
approach, and before declaring done.

Each call creates an ephemeral `advisor-subcall` session, prompts the
advisor model with a short reviewer system prompt plus the caller-supplied
context, returns the text answer as the tool result, then deletes the
session. A recursion guard stops the advisor model from calling back into
the tool.

Nothing watches in the background. There are no hardcoded agent names and
no dependency on the routing config in `oc/opencode-routing`.

## Layout

```
package.json          Local package (private, never published)
src/advisor.ts        The whole plugin: tool, /advisor command, settings
commands/advisor.md   /advisor command template (installed globally)
scripts/install.mjs   Minimal installer (plain Node.js)
README.md / CHANGELOG.md
```

## Model selection

With no advisor model configured, the tool reuses the calling session's
active model (read from the newest message carrying model info, so a
mid-session `/models` switch is honored). There is no built-in default
model.

`/advisor configure model=` accepts an exact `provider/model` id, a
display name as shown in `/models` (e.g. `DeepSeek V4.1 Flash`), a
substring of either, or `auto`. Matching runs in code against every
configured provider: an unambiguous match applies, multiple matches
return a pick list, and no match names `opencode models` for exact ids.
`enabled=` accepts `on`/`off` in any order relative to `model=`.

Precedence for one call, lowest to highest:

1. Calling session's active model, else the global default model.
2. Advisor settings (`/advisor configure model=<provider/model|auto>`).
3. Environment (`OPENCODE_ADVISOR_MODEL` as `provider/model`, or
   `OPENCODE_ADVISOR_PROVIDER` plus `OPENCODE_ADVISOR_MODEL`).
4. Per-call tool args `providerID` / `modelID`.

## /advisor command

`/advisor` is a thin template (`commands/advisor.md`): it tells the model
to call the `advisor_ctl` tool with the words after `/advisor` and relay
the result verbatim. All logic (parsing, validation, config edit) runs in
code inside the tool — the model only relays. (An earlier revision tried
intercepting the command from the plugin, but hook-set command output is
ignored for TUI-invoked commands, so the interception was removed.)

- `/advisor` or `/advisor status` — report enabled/disabled and model.
- `/advisor on` / `/advisor off` — set `"enabled"`. While disabled the
  advisor tool stays registered but answers with a disabled notice
  instead of calling a model (no cost).
- `/advisor configure [model=<provider/model|auto>] [enabled=on|off]` —
  invalid input is rejected with usage and changes nothing.

`advisor_ctl` is a regular plugin tool, so it also works wherever tools
work. The advisor tool re-reads settings from disk on every call, so
command changes apply immediately with no restart.

Settings persist as the options object of our own plugin tuple in the
user's existing `opencode.json(c)` — for example
`["file:///.../oc/plugins/advisor/src/advisor.ts", { "enabled": true,
"model": "auto" }]`. Writes are surgical: only that options object is
replaced, so comments and formatting elsewhere in the file survive. No
separate settings file is created.

## Install

Requirements: OpenCode 1.x, Node.js 18 or newer for the installer.

```bash
npm install          # plugin runtime deps (@opencode-ai/*), inside this dir
node scripts/install.mjs --dry-run   # inspect what would change
node scripts/install.mjs             # write global entry + command file
```

Then restart opencode (config loads once at startup) and verify:

```bash
opencode debug config            # shows the local plugin entry
```

In a session, ask the model to list its tools and quote the advisor
description, then try `/advisor status`.

`node scripts/install.mjs --remove` reverses the install.
`--status` only reports. A timestamped backup of the user config is made
before every write.

## Versioning

See `CHANGELOG.md`. Version `0.1.0` matches upstream advisor behavior plus
the follow-session default and the `/advisor` command.
