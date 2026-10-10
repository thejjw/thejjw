---
description: Manage the oc advisor plugin (on/off/status/configure).
---

Call the advisor_ctl tool with the words after /advisor as its action
(empty means status): $ARGUMENTS

Relay the tool result back verbatim and add nothing, unless the action
starts with "models" — then do it yourself instead of calling the tool:
run `opencode models > models_<timestamp>.txt` in the workspace root
(timestamp like 20261010-201500 from the current date and time), read
the file back, and recommend 4-5 as the advisor model. Prefer
opencode-go and opencode-zen providers (compatibility-tested); present
your picks with one-line reasons and exact ids ready for
`/advisor configure model=<id>`.
