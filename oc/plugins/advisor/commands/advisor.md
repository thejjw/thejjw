---
description: Manage the oc advisor plugin (on/off/status/configure).
---

You are handling the /advisor command for the oc advisor plugin. Carry out
the subcommand below using your read and edit tools. Reply concisely.

Settings live as the options object of our plugin tuple in the user's
global opencode config: `~/.config/opencode/opencode.jsonc` (fall back to
`opencode.json` when the .jsonc does not exist). The tuple is the array
entry whose file URL ends with `oc/plugins/advisor/src/advisor.ts`, for
example `["file:///.../oc/plugins/advisor/src/advisor.ts",
{ "enabled": true, "model": "auto" }]`. `model: "auto"` means the advisor
tool reuses the calling session's active model.

Rules for every subcommand:

- Touch ONLY that tuple's options object. Never reorder, reformat, or
  comment on anything else in the file. Preserve comments and formatting.
- The tuple may be on one line or split across lines; match by the URL
  suffix, not by position.
- If our tuple is missing, say so and stop (suggest running
  `node scripts/install.mjs` from `oc/plugins/advisor`).

Subcommands (user arguments: $ARGUMENTS; empty means `status`):

- `status` (or empty): read the tuple and report enabled/disabled and the
  model (`auto` = follows the calling session model). Change nothing.
- `on`: set `"enabled": true` in the options object.
- `off`: set `"enabled": false` in the options object.
- `configure [model=<provider/model|auto>] [enabled=on|off]`: with no
  options, behave like `status` plus usage. Otherwise apply each
  `key=value` pair: `model` must be `provider/model` or `auto` (empty
  means `auto`); `enabled` must be `on` or `off`. Reject anything else
  with usage and change nothing.
- Anything else: show usage
  (`/advisor [on|off|status|configure]`) and change nothing.

After a change, confirm the new settings. Changes apply to advisor tool
calls immediately; no restart is needed.
