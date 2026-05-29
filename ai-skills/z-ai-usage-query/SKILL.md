---
name: z-ai-usage-query
description: Query Z.AI GLM Coding Plan usage including model usage, tool usage, and quota limits (portable version)
license: MIT
metadata:
  audience: developers
  workflow: z-ai-monitoring
---

## What I do

- Query **model usage** stats from the Z.AI Global platform (`api.z.ai`)
- Query **tool usage** stats from the Z.AI Global platform
- Query **quota limits** including Token usage (5-hour window) and MCP usage (1-month window)
- Authenticate using a token from the `Z_AI_AUTH_TOKEN` environment variable and output all data in JSON format
- Automatically compute a time window from yesterday at the current hour to today

## When to use me

Use this skill when you need to check your Z.AI GLM Coding Plan usage, monitor token consumption, review tool usage patterns, or inspect quota limits.

## Configuration

**Auth Token:**
- **Windows:** Read from the `$env:Z_AI_AUTH_TOKEN` environment variable.
- **Linux/Mac:** Read from the `Z_AI_AUTH_TOKEN` environment variable.

## Usage

### Windows

Use the **PowerShell** tool. Ensure `$env:Z_AI_AUTH_TOKEN` is set, then execute the query:

```powershell
$token = $env:Z_AI_AUTH_TOKEN
if (-not $token) { Write-Error "Auth token not available"; exit 1 }
$base = "https://api.z.ai"
$now = Get-Date
$start = Get-Date $now.AddDays(-1).Date.AddHours($now.Hour) -Format "yyyy-MM-dd HH:mm:ss"
$end = Get-Date $now.Date.AddHours($now.Hour).AddMinutes(59).AddSeconds(59) -Format "yyyy-MM-dd HH:mm:ss"
$q = "?startTime=$([uri]::EscapeDataString($start))&endTime=$([uri]::EscapeDataString($end))"
$headers = @{ Authorization = $token; Accept = "application/json" }

function Query-Endpoint($label, $path, [string]$pp) {
  Write-Host "$label data:"
  Write-Host ""
  try {
    $resp = Invoke-RestMethod -Uri "$base$path" -Headers $headers
    $data = if ($resp.data) { $resp.data } else { $resp }
    if ($pp -eq "quota" -and $data.limits) {
      $data.limits = @($data.limits | ForEach-Object {
        if ($_.type -eq "TOKENS_LIMIT") { $_.type = "Token usage(5 Hour)"; $_ }
        elseif ($_.type -eq "TIME_LIMIT") { $_.type = "MCP usage(1 Month)"; $_ }
        else { $_ }
      } | Select-Object type, percentage, @{N='currentUsage';E={$_.currentValue}}, @{N='totol';E={$_.usage}}, usageDetails)
      $data | ConvertTo-Json -Depth 5
    } else {
      $data | ConvertTo-Json -Depth 5
    }
  } catch {
    Write-Error "[$label] $($_.Exception.Message)"
  }
  Write-Host ""
}

Query-Endpoint "Model usage" "/api/monitor/usage/model-usage$q"
Query-Endpoint "Tool usage" "/api/monitor/usage/tool-usage$q"
Query-Endpoint "Quota limit" "/api/monitor/usage/quota/limit" -pp "quota"
```

### Linux / Mac

Requires `curl`. Exit with an error if not found.

Use the **Bash** tool:

```bash
command -v curl >/dev/null 2>&1 || { echo "Error: curl is required but not installed"; exit 1; }
token="${Z_AI_AUTH_TOKEN:?Error: Z_AI_AUTH_TOKEN environment variable is not set}"
base="https://api.z.ai"
now=$(date +%H)
start=$(date -d "yesterday ${now}:00:00" "+%Y-%m-%d %H:%M:%S" | sed 's/ /%20/g')
end=$(date -d "today ${now}:59:59" "+%Y-%m-%d %H:%M:%S" | sed 's/ /%20/g')
qs="startTime=${start}&endTime=${end}"

query() {
  echo "$1 data:"
  echo ""
  curl -sS -H "Authorization: $token" -H "Accept: application/json" "$base$2"
  echo ""
}

query "Model usage" "/api/monitor/usage/model-usage?$qs"
query "Tool usage" "/api/monitor/usage/tool-usage?$qs"
query "Quota limit" "/api/monitor/usage/quota/limit"
```

## Implementation Details

This skill queries the Z.AI Global platform with no Node.js dependency:

1. Uses the fixed Z.AI Global platform URL (`https://api.z.ai`).
2. Authenticates using the provided token.
3. Queries three endpoints: model usage, tool usage, and quota limits.
4. Outputs the data in structured JSON format.
5. **Windows:** uses PowerShell `Invoke-RestMethod`. **Linux/Mac:** uses `curl` only.
