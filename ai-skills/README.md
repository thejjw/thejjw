# AI Skills

Reusable agent skill documentation for AI coding environments.

## Skills

- `agy-usage-query`: Query Antigravity CLI usage quotas (Gemini Flash/Pro models) from the private Cloud Code Assist endpoint.
  - Intended for Antigravity CLI only.
- `codebase-docs`: Maintain codebase documentation in the `docs/` folder using surgical git-based updates.
  - Intended for OpenCode, Claude Code, and Antigravity.
- `deep-research`: Deep research harness — clarify scope, confirm a research plan, fan out web searches, verify claims, and write a cited long-form report to a file.
  - Intended for all AI coding agents.
- `deepseek-usage-query`: Query DeepSeek API balance and estimate token budget from current pricing.
  - Intended for OpenCode and Claude Code.
- `export-chat-codex`: Export a Codex conversation and its execution trace to a chronological Markdown transcript.
  - Intended for Codex only.
- `kimi-usage-query`: Check Kimi Code membership usage, quota limits, concurrency, and Extra Usage balance.
  - Intended for OpenCode and Claude Code.
- `minimax-usage-query`: Query MiniMax token usage, quota limits, and model-specific allowances.
  - Intended for OpenCode and Claude Code.
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

The installer fetches this `ai-skills` directory with a shallow sparse Git clone, overwrites the intended skill directories, and updates OpenCode skill permissions.

For manual installs, copy a skill directory into its intended tool's skill directory, preserving the `SKILL.md` filename:

- OpenCode: `%USERPROFILE%\.agents\skills\<skill-name>\SKILL.md`
- Claude Code: `%USERPROFILE%\.claude\skills\<skill-name>\SKILL.md`
- Antigravity CLI: `%USERPROFILE%\.gemini\antigravity-cli\skills\<skill-name>\SKILL.md`
- Codex: `%CODEX_HOME%\skills\<skill-name>\SKILL.md` (defaults to `%USERPROFILE%\.codex\skills`)

Some skills require credentials. Provide those through local environment variables or the PowerShell profile's `Set-AiApiKeysCS` / `Load-AiApiKeysFromCS` helpers; do not commit secrets to this repository.
