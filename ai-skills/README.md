# AI Skills

Reusable agent skill documentation for AI coding environments.

## Skills

- `agy-usage-query`: Query Antigravity CLI usage quotas (Gemini Flash/Pro models) from the private Cloud Code Assist endpoint.
  - Intended for Antigravity CLI only.
- `codebase-docs`: Maintain codebase documentation in the `docs/` folder using surgical git-based updates.
  - Intended for OpenCode, Claude Code, Antigravity Windows App/IDE, and Antigravity CLI.
- `deep-research`: Deep research harness — clarify scope, confirm a research plan, fan out web searches, verify claims, and deliver a cited long-form report.
  - Intended for all AI coding agents.
- `deepseek-usage-query`: Query DeepSeek API balance and estimate token budget from current pricing.
  - Intended for OpenCode and Claude Code.
- `export-chat-codex`: Export a Codex conversation and its execution trace to a chronological Markdown transcript.
  - Intended for Codex only.
- `kimi-usage-query`: Check Kimi Code membership usage, quota limits, concurrency, and Extra Usage balance.
  - Intended for OpenCode and Claude Code.
- `minimax-usage-query`: Query MiniMax token usage, quota limits, and model-specific allowances.
  - Intended for OpenCode and Claude Code.
- `polish-document`: Refine rough, translated, or inconsistent documents into professional, presentation-ready deliverables.
  - Intended for OpenCode, Claude Code, Antigravity Windows App/IDE, Antigravity CLI, and Codex.
- `session-exporter`: Export the current session conversation history to Markdown.
  - Intended for Antigravity CLI only.
- `web-search-ddg`: Search current web information using DuckDuckGo with no API key.
  - Intended for OpenCode and Claude Code.
- `web-search-startpage`: Search current web information using Startpage with no API key.
  - Intended for OpenCode and Claude Code.
- `z-ai-usage-query`: Query Z.AI GLM Coding Plan usage, tool usage, and quota limits.
  - Intended for OpenCode and Claude Code.

## Install

From the PowerShell profile, run:

```powershell
Install-AiSkills
```

The installer fetches this `ai-skills` directory with a shallow sparse Git clone, overwrites the intended skill directories, and updates OpenCode skill permissions. Shared Antigravity skills are copied to both current global locations; CLI-only skills remain isolated to AGY CLI.

For manual installs, copy a skill directory into its intended tool's skill directory, preserving the `SKILL.md` filename:

- OpenCode: `%USERPROFILE%\.agents\skills\<skill-name>\SKILL.md`
- Claude Code: `%USERPROFILE%\.claude\skills\<skill-name>\SKILL.md`
- Antigravity Windows App/IDE: `%USERPROFILE%\.gemini\config\skills\<skill-name>\SKILL.md`
- Antigravity CLI: `%USERPROFILE%\.gemini\antigravity-cli\skills\<skill-name>\SKILL.md`
- Codex: `%CODEX_HOME%\skills\<skill-name>\SKILL.md` (defaults to `%USERPROFILE%\.codex\skills`)

The installer does not migrate or modify legacy Antigravity skill roots such as `%USERPROFILE%\.gemini\skills` or `%USERPROFILE%\.gemini\antigravity\skills`.

Some skills require credentials. Provide those through local environment variables or the PowerShell profile's `Set-AiApiKeysCS` / `Load-AiApiKeysFromCS` helpers; do not commit secrets to this repository.
