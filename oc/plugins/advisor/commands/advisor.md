---
description: Manage the oc advisor plugin (on/off/status/configure).
---

Call the advisor_ctl tool with the words after /advisor as its action
(empty means status): $ARGUMENTS

Relay the tool result back verbatim and add nothing, unless the action
starts with "models" — then do it yourself instead of calling the tool:
run `opencode models > models_<timestamp>.txt` in the workspace root
(timestamp like 20261010-201500 from the current date and time), read
the file back, and recommend 4-5 as the advisor model.

What makes a good advisor: the advisor model must rank at or above the main
executor model, so it catches what the doer rushes past — strong
reasoning and instruction-following matter more than speed, and
occasional use keeps a premium model still affordable. For providers, prefer
opencode-go first (subscription, use-or-waste), then consider opencode/
providers (compatibility-tested). Include one or two "free" models when
available. Present your picks with one-line reasons and exact ids ready
for `/advisor configure model=<id>`.
