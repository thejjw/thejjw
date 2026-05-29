---
name: minimax-usage-query
description: Query MiniMax API token usage, quota limits, and model-specific allowances
metadata:
  audience: developers
  workflow: minimax-monitoring
---

## What I do

Query **token usage** and **remaining quota** from MiniMax platform. Returns JSON with usage/allowance for all models (MiniMax-M*, speech-hd, Hailuo video, music, image, coding-plan-vlm/search, etc.).

## Configuration

**API Key:** `$env:MINIMAX_API_KEY` (Windows) or `MINIMAX_API_KEY` (Linux/Mac).

## API Endpoint

**URL:** `https://www.minimax.io/v1/token_plan/remains`

**Method:** `GET`

**Headers:**
- `Content-Type: application/json`
- `Authorization: Bearer <your-api-key>`

## Calling the API

### Bash / Git Bash / WSL
```bash
curl -s 'https://www.minimax.io/v1/token_plan/remains' \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $MINIMAX_API_KEY"
```

### PowerShell
```powershell
$headers = @{
    'Content-Type' = 'application/json'
    'Authorization' = "Bearer $env:MINIMAX_API_KEY"
}
Invoke-RestMethod -Uri 'https://www.minimax.io/v1/token_plan/remains' -Headers $headers
```

> Note: On Windows, `$env:MINIMAX_API_KEY` may not expand inside `curl` arguments — use `$MINIMAX_API_KEY` with bash-style curl, or use `Invoke-RestMethod` for PowerShell.
> Note: pipe to `jq` if available for formatted output

## Response

JSON with `model_remains` array containing usage/allowance for each model over both current interval and weekly periods.