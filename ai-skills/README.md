# AI Skills

Reusable agent skill documentation for AI coding environments.

## Skills

- `deepseek-usage-query`: Query DeepSeek API balance and estimate token budget from current pricing.
- `minimax-usage-query`: Query MiniMax token usage, quota limits, and model-specific allowances.
- `session-exporter`: Export the current session conversation history to Markdown.
- `web-search-ddg`: Search current web information using DuckDuckGo with no API key.
- `web-search-startpage`: Search current web information using Startpage with no API key.
- `z-ai-usage-query`: Query Z.AI GLM Coding Plan usage, tool usage, and quota limits.

## Install

Copy a skill directory into the target tool's skill directory, preserving the `SKILL.md` filename:

- OpenCode: `%USERPROFILE%\.agents\skills\<skill-name>\SKILL.md`
- Claude Code: `%USERPROFILE%\.claude\skills\<skill-name>\SKILL.md`
- Antigravity CLI: `%USERPROFILE%\.gemini\antigravity-cli\skills\<skill-name>\SKILL.md`

Some skills require credentials. Provide those through local environment variables or your own credential-store setup; do not commit secrets to this repository.
