# Usage queries

The profile ships a family of `Get-*Usage` functions that report the quota of
one AI provider each. `Get-AllAiUsage` discovers them and runs them in turn.

| Function | Provider | Source |
|---|---|---|
| `Get-AgyUsage` | Google Antigravity CLI | private `cloudcode-pa` endpoint |
| `Get-ClaudeUsage` | Anthropic Claude Code (Pro, Max) | private `/api/oauth/usage` endpoint |
| `Get-CodexUsage` | OpenAI Codex (ChatGPT plan) | private `/backend-api/wham/usage` endpoint |
| `Get-DeepseekUsage` | DeepSeek | balance endpoint |
| `Get-KimiUsage` | Kimi Code | membership quota endpoint |
| `Get-MinimaxUsage` | MiniMax | token-plan endpoint |
| `Get-OpencodeGoUsage` | OpenCode Go | documented usage endpoint |
| `Get-QwenUsage` | QwenCloud Token Plan | private console gateway |
| `Get-ZaiUsage` | Z.AI | model-usage endpoint |

## Claude Code and Codex

Neither vendor publishes an API for consumer plan quota. Anthropic documents
its Admin APIs as unavailable for individual accounts, and OpenAI has no
public HTTP endpoint for a personal Codex plan. Both CLIs therefore call a
private endpoint of their own, and both store an OAuth token on disk, so the
profile can borrow an existing login instead of asking for one:

- Claude Code keeps its token in `%USERPROFILE%\.claude\.credentials.json`
  (or `$CLAUDE_CONFIG_DIR\.credentials.json`).
- Codex keeps its token in `%USERPROFILE%\.codex\auth.json` (or
  `$CODEX_HOME\auth.json`).

Both endpoints are undocumented and change without notice, so the functions
are written to degrade rather than to fail hard:

- A window is named by its length, never by the slot it arrived in. A Team
  plan reports the weekly window in `primary_window` and leaves
  `secondary_window` null, and OpenAI has both added and removed the short
  window without notice.
- Claude returns two shapes at once (the flat `five_hour`/`seven_day`
  objects and a `limits` array). The richer array wins, so a window is never
  reported twice.
- An unrecognised payload names the fields it did find, so a shape change is
  diagnosable from the error message.
- A token that has expired is refreshed in memory. The rotated pair is written
  back to the CLI's own credential store, because both vendors rotate refresh
  tokens and the CLI holds the same one; the write is skipped when the store
  changed while the refresh was in flight.

`Get-AllAiUsage` picks both functions up automatically.

## Certificate handling

Corporate networks sometimes re-sign TLS traffic with an inspection proxy
whose certificate the local store does not trust. The usage queries accept
that certificate by default and therefore need `-Strict` to insist on the
default validation:

```powershell
Get-CodexUsage              # tolerates an inspection proxy
Get-CodexUsage -Strict      # rejects an untrusted certificate
```

The relaxation is implemented with a compiled callback rather than a
PowerShell scriptblock: the TLS handshake runs on a worker thread, and a
scriptblock delegate fails there with "There is no Runspace available to run
scripts in this thread".
