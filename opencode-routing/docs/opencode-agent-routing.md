# OpenCode Agent Routing

This bundle installs a reusable OpenCode configuration for multi-model agent routing. It keeps two primary heads and adds alternate profiles with `alt_` prefixes.

Last updated: 2026-05-10.

## Requirements

- OpenCode installed and available as `opencode`
- Node.js 18 or newer
- Provider credentials already configured for the referenced models

## Install

From this repository:

```powershell
node scripts\install-opencode-routing.mjs
```

On macOS or Linux:

```bash
node scripts/install-opencode-routing.mjs
```

Use a different default head:

```bash
node scripts/install-opencode-routing.mjs --default-agent head-glm
```

Preview without writing:

```bash
node scripts/install-opencode-routing.mjs --dry-run
```

The installer writes to `~/.config/opencode/opencode.json` by default, creates a timestamped backup first, and preserves unrelated config keys such as existing `permission.skill` settings.

This bundle manages agent definitions and `default_agent`. It intentionally does not set or override the top-level OpenCode `model`; model routing is handled inside each managed agent definition.

The reusable fragment is `config/opencode-agent-routing.json`. It intentionally omits agent-level `temperature` settings so OpenCode uses model-specific defaults. Add `temperature` to individual agents only when you want to pin deterministic, conversational, or creative behavior.

## Main Heads

| Agent | Model | Purpose |
| --- | --- | --- |
| `head-gpt` | `openai/gpt-5.5` | Main premium orchestrator |
| `head-glm` | `zai-coding-plan/glm-5.1` | Main GLM orchestrator |

## Alternate Heads

| Agent | Model | Purpose |
| --- | --- | --- |
| `alt_premium` | `openai/gpt-5.5-pro` | Highest-quality orchestration and review-heavy work |
| `alt_openai` | `openai/gpt-5.5` | All-OpenAI workflow |
| `alt_glm_stack` | `zai-coding-plan/glm-5.1` | All-GLM workflow |
| `alt_budget` | `zai-coding-plan/glm-4.7` | Cheap and fast routine workflow |
| `alt_review_heavy` | `openai/gpt-5.5` | GLM implementation plus premium review |

## Subagents

| Agent | Model | Purpose |
| --- | --- | --- |
| `fast-discovery-m3` | `minimax-coding-plan/MiniMax-M3` | Fast read-only discovery |
| `fast-openai-gpt5.4-mini` | `openai/gpt-5.4-mini` | OpenAI read-only discovery |
| `fast-glm-4.5-air` | `zai-coding-plan/glm-4.5-air` | GLM read-only discovery |
| `hard-impl-glm51` | `zai-coding-plan/glm-5.1` | Main implementation work |
| `hard-impl-glm47` | `zai-coding-plan/glm-4.7` | Alternate implementation work |
| `hard-impl-openai` | `openai/gpt-5.3-codex` | OpenAI implementation work |
| `premium-reviewer-gpt-5.5-pro` | `openai/gpt-5.5-pro` | Read-only final review and risk analysis |

## Routing

| Head | Allowed Subagents |
| --- | --- |
| `head-gpt` | `fast-discovery-m3`, `hard-impl-glm51` |
| `head-glm` | `fast-discovery-m3`, `hard-impl-glm47` |
| `alt_premium` | `fast-discovery-m3`, `hard-impl-openai`, `premium-reviewer-gpt-5.5-pro` |
| `alt_openai` | `fast-openai-gpt5.4-mini`, `hard-impl-openai`, `premium-reviewer-gpt-5.5-pro` |
| `alt_glm_stack` | `fast-glm-4.5-air`, `hard-impl-glm47` |
| `alt_budget` | `fast-discovery-m3`, `hard-impl-glm47` |
| `alt_review_heavy` | `fast-discovery-m3`, `hard-impl-glm51`, `premium-reviewer-gpt-5.5-pro` |

## Validation

After installation:

```bash
opencode debug config
opencode debug agent head-gpt
opencode debug agent head-glm
opencode debug agent fast-discovery-m3
```

## Notes

- Discovery agents are read-only, cannot run bash, and cannot manage todos.
- Implementation agents can edit files and ask before running bash.
- Reviewer agents are read-only, cannot manage todos, and only allow safe git inspection commands.
- The installer replaces managed agent definitions by name on each run, but preserves unrelated agents and settings.

## Temperature Tuning

The source fragment is strict JSON, so tuning guidance lives here instead of inline comments. By default, all managed agents omit `temperature` and inherit OpenCode's model-specific defaults.

Suggested overrides if you want explicit behavior:

| Agent Group | Suggested Temperature | Use When |
| --- | ---: | --- |
| Head agents | `0.2` | You want a slightly more conversational orchestrator |
| Budget or review-heavy heads | `0.1` | You want conservative decisions and less variance |
| Discovery agents | `0` | You want deterministic search and summarization |
| Implementation agents | `0.1` | You want conservative code edits |
| Reviewer agents | `0` | You want deterministic audits and findings |

Example agent override:

```json
"head-gpt": {
  "description": "Primary premium orchestration head using GPT 5.5.",
  "mode": "primary",
  "model": "openai/gpt-5.5",
  "variant": "high",
  "temperature": 0.2
}
```

## Maintenance

Review this configuration whenever OpenCode changes agent or permission behavior, provider model IDs change, or any referenced model is renamed, removed, deprecated, or replaced.

To update the routing bundle:

1. Edit `config/opencode-agent-routing.json` with the new model IDs, prompts, permissions, routing rules, or optional temperature overrides.
2. Update the tables in this document so the documented heads, subagents, and routing match the JSON fragment.
3. Update the `Last updated` date near the top of this document.
4. Run `node scripts/install-opencode-routing.mjs --dry-run --skip-validate` to inspect the merged output without writing.
5. Run `node scripts/install-opencode-routing.mjs` to deploy to the current machine.
6. Validate representative agents with `opencode debug agent <agent-name>`, especially any renamed agents or agents with dotted names.
7. If the deployed config is wrong, restore the latest `~/.config/opencode/opencode.json.backup-YYYYMMDD-HHMMSS` backup.

When adding a new managed agent, pick an explicit name that includes the model identity when helpful, then add the matching `permission.task` allow-list entries for the heads that should be allowed to invoke it.
