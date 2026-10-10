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

What makes a good advisor: a model at least as capable as the executor,
one that catches what the doer rushes past — strong reasoning and
instruction-following matter more than speed, and occasional use keeps a
premium model affordable. Prefer opencode-go providers first
(subscription, use-or-waste), then opencode/ providers
(compatibility-tested; note "Zen" models use opencode/ ids). Present
your picks with one-line reasons and exact ids ready for
`/advisor configure model=<id>`.
