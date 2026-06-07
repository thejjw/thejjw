<#
.SYNOPSIS
    Query Z.AI GLM Coding Plan usage (model, tool, quota) and emit raw data
    + insights + concerns.

.DESCRIPTION
    Standalone PowerShell script. Hits three Z.AI Global endpoints:
      - /api/monitor/usage/model-usage      (24h hourly buckets of model calls/tokens)
      - /api/monitor/usage/tool-usage       (24h hourly buckets of tool calls)
      - /api/monitor/usage/quota/limit      (current token + MCP quota usage)

    Prints, in order:
      1. The full raw JSON response from each endpoint.
      2. Summaries: totals, hourly averages, peak hour, and a per-tool table
         for the last 24h of tool activity.
      3. A "Concerns" block flagging any quota or spike conditions that
         trip the configurable thresholds.

    Time window: the script queries "yesterday at the current hour" through
    "the end of the current hour" by default, matching the upstream skill.

.PARAMETER Token
    Z.AI auth token. Defaults to $env:Z_AI_AUTH_TOKEN.

.PARAMETER McpWarnPercent
    MCP-usage percent (0-100) at or above which a CRITICAL flag is raised.
    Default: 80.

.PARAMETER TokenWarnPercent
    Token-usage percent (0-100) at or above which a CRITICAL flag is raised.
    Default: 80.

.PARAMETER SpikeRatio
    If any hourly bucket exceeds SpikeRatio * hourly_average, that bucket
    is flagged as a spike. Default: 3.0.

.PARAMETER All
    When set, inline-prints the full raw JSON for every endpoint. By
    default the raw JSON is suppressed and only stored in
    $Global:zaiLastQuery (a hashtable @{ Model; Tool; Quota } of the
    parsed PSObjects the API returned) so you can inspect them later.

.OUTPUTS
    None. The three parsed API responses are exposed via the session
    global $Global:zaiLastQuery.Model / .Tool / .Quota. Summaries and
    concerns are written to the host.

.EXAMPLE
    pwsh ./z-ai-usage-query.ps1

.EXAMPLE
    pwsh ./z-ai-usage-query.ps1 -All

.EXAMPLE
    pwsh ./z-ai-usage-query.ps1; $Global:zaiLastQuery.Quota.data.limits
#>

[CmdletBinding()]
param(
    [string]$Token = $env:Z_AI_AUTH_TOKEN,
    [int]$McpWarnPercent = 80,
    [int]$TokenWarnPercent = 80,
    [double]$SpikeRatio = 3.0,
    [switch]$All
)

# -- Helpers ----------------------------------------------------------------

# Render a TimeSpan as a compact human-readable string.
function Format-Duration([TimeSpan]$ts) {
    if ($ts.TotalDays -ge 1)  { return ('{0:N1} d ({1:N0} h)' -f $ts.TotalDays,  $ts.TotalHours) }
    if ($ts.TotalHours -ge 1) { return ('{0:N1} h ({1:N0} m)'  -f $ts.TotalHours, $ts.TotalMinutes) }
    return ('{0:N0} m ({1:N0} s)' -f $ts.TotalMinutes, $ts.TotalSeconds)
}

# Print a section banner.
function Write-Section([string]$title) {
    Write-Host ''
    Write-Host ('== {0} ==' -f $title) -ForegroundColor Cyan
}

# Compute the (avg, peak index, peak value) for an integer series aligned to
# $xTime. Returns an empty/zero result if the series is null or all zeros.
function Get-SeriesStats([object[]]$xTime, [object[]]$series) {
    if (-not $series -or $series.Count -eq 0) {
        return [pscustomobject]@{ Total = 0; Avg = 0; Peak = 0; PeakHour = $null }
    }
    $total = 0; $peak = 0; $peakIdx = -1
    for ($i = 0; $i -lt $series.Count; $i++) {
        $v = [int]$series[$i]
        $total += $v
        if ($v -gt $peak) { $peak = $v; $peakIdx = $i }
    }
    $avg = if ($series.Count -gt 0) { [double]$total / $series.Count } else { 0 }
    $peakHour = if ($peakIdx -ge 0 -and $xTime -and $peakIdx -lt $xTime.Count) { [string]$xTime[$peakIdx] } else { $null }
    return [pscustomobject]@{ Total = $total; Avg = $avg; Peak = $peak; PeakHour = $peakHour }
}

# Detect spikes: indexes where value > SpikeRatio * avg. Returns array of
# @{ Hour = ...; Value = ... } records (or empty array).
function Get-Spikes([object[]]$xTime, [object[]]$series, [double]$avg) {
    $out = @()
    if (-not $series -or $avg -le 0) { return $out }
    $threshold = $SpikeRatio * $avg
    for ($i = 0; $i -lt $series.Count; $i++) {
        $v = [int]$series[$i]
        if ($v -gt $threshold) {
            $hour = if ($xTime -and $i -lt $xTime.Count) { [string]$xTime[$i] } else { "idx $i" }
            $out += [pscustomobject]@{ Hour = $hour; Value = $v }
        }
    }
    return $out
}

# -- Auth check -------------------------------------------------------------

if (-not $Token) {
    Write-Error 'Z_AI_AUTH_TOKEN is not set (env var or -Token).'
    exit 1
}

# -- Time window (matches the upstream skill) -------------------------------

$base = 'https://api.z.ai'
$now  = Get-Date
$start = Get-Date $now.AddDays(-1).Date.AddHours($now.Hour) -Format 'yyyy-MM-dd HH:mm:ss'
$end   = Get-Date $now.Date.AddHours($now.Hour).AddMinutes(59).AddSeconds(59) -Format 'yyyy-MM-dd HH:mm:ss'
$q = "?startTime=$([uri]::EscapeDataString($start))&endTime=$([uri]::EscapeDataString($end))"
$headers = @{ Authorization = $Token; Accept = 'application/json' }

# -- API calls --------------------------------------------------------------

function Invoke-Zai {
    param([string]$Path)
    try {
        $r = Invoke-RestMethod -Uri ($base + $Path) -Headers $headers -Method GET
        return $r
    } catch {
        Write-Error "API call failed for $Path`: $($_.Exception.Message)"
        return $null
    }
}

# Returns the .data subtree if present, otherwise the response itself.
function Unwrap-Data([object]$resp) {
    if ($null -eq $resp) { return $null }
    if ($resp.PSObject.Properties['data'] -and $null -ne $resp.data) { return $resp.data }
    return $resp
}

$modelResp = Invoke-Zai "/api/monitor/usage/model-usage$q"
$toolResp  = Invoke-Zai "/api/monitor/usage/tool-usage$q"
$quotaResp = Invoke-Zai '/api/monitor/usage/quota/limit'

# Always stash the parsed responses so the user can poke at them later
# (e.g. $Global:zaiLastQuery.Quota.data.limits[0].currentValue).
$Global:zaiLastQuery = @{
    Model = $modelResp
    Tool  = $toolResp
    Quota = $quotaResp
}

# -- Section 1: raw responses ----------------------------------------------

Write-Section 'Raw API responses'

# Pipe to Out-Host so the JSON writes to the host alongside Write-Host
# calls instead of being captured by the script's output pipeline.
if ($All) {
    Write-Host '--- model-usage ---'
    if ($modelResp) { $modelResp | ConvertTo-Json -Depth 8 | Out-Host } else { Write-Host '(no response)' }

    Write-Host ''
    Write-Host '--- tool-usage ---'
    if ($toolResp) { $toolResp | ConvertTo-Json -Depth 8 | Out-Host } else { Write-Host '(no response)' }

    Write-Host ''
    Write-Host '--- quota/limit ---'
    if ($quotaResp) { $quotaResp | ConvertTo-Json -Depth 8 | Out-Host } else { Write-Host '(no response)' }
} else {
    Write-Host '  (suppressed; stored in $Global:zaiLastQuery as @{ Model; Tool; Quota }.' -ForegroundColor DarkGray
    Write-Host '   Use -All to display inline.)' -ForegroundColor DarkGray
}

# -- Section 2: model usage summary ----------------------------------------

Write-Section 'Model usage summary (last 24h)'
$modelData = Unwrap-Data $modelResp
if ($modelData) {
    $callStats = Get-SeriesStats $modelData.x_time $modelData.modelCallCount
    $tokStats  = Get-SeriesStats $modelData.x_time $modelData.tokensUsage
    [pscustomobject]@{
        Total_Calls = $callStats.Total
        Hourly_Avg  = ('{0:N2}' -f $callStats.Avg)
        Peak_Calls  = ('{0} at {1}' -f $callStats.Peak, $callStats.PeakHour)
        Total_Tokens = $tokStats.Total
        Hourly_Tok_Avg = ('{0:N0}' -f $tokStats.Avg)
        Peak_Tokens = ('{0} at {1}' -f $tokStats.Peak, $tokStats.PeakHour)
    } | Format-Table -AutoSize | Out-Host
} else {
    Write-Host '  (no data)' -ForegroundColor DarkGray
}

# -- Section 3: tool usage summary -----------------------------------------

Write-Section 'Tool usage summary (last 24h)'
$toolData = Unwrap-Data $toolResp
if ($toolData) {
    # Per-tool stats for the most common Z.AI buckets.
    $netStats = Get-SeriesStats $toolData.x_time $toolData.networkSearchCount
    $webStats = Get-SeriesStats $toolData.x_time $toolData.webReadMcpCount
    $zreStats = Get-SeriesStats $toolData.x_time $toolData.zreadMcpCount

    [pscustomobject]@{
        Tool           = 'network-search (search-prime)'
        Total          = $netStats.Total
        Hourly_Avg     = ('{0:N2}' -f $netStats.Avg)
        Peak           = ('{0} at {1}' -f $netStats.Peak, $netStats.PeakHour)
    },
    [pscustomobject]@{
        Tool           = 'web-reader'
        Total          = $webStats.Total
        Hourly_Avg     = ('{0:N2}' -f $webStats.Avg)
        Peak           = ('{0} at {1}' -f $webStats.Peak, $webStats.PeakHour)
    },
    [pscustomobject]@{
        Tool           = 'zread'
        Total          = $zreStats.Total
        Hourly_Avg     = ('{0:N2}' -f $zreStats.Avg)
        Peak           = ('{0} at {1}' -f $zreStats.Peak, $zreStats.PeakHour)
    } | Format-Table -AutoSize | Out-Host

    # Spike detection: only meaningful if the series has any non-zero values.
    $spikes = @()
    $spikes += Get-Spikes $toolData.x_time $toolData.networkSearchCount $netStats.Avg
    $spikes += Get-Spikes $toolData.x_time $toolData.webReadMcpCount   $webStats.Avg
    $spikes += Get-Spikes $toolData.x_time $toolData.zreadMcpCount     $zreStats.Avg
    if ($spikes.Count -gt 0) {
        Write-Host ''
        # -f is a binary string operator; parentheses ensure PowerShell does
        # not mis-parse it as a parameter to Write-Host.
        Write-Host ('  Spikes (> {0:N1}x hourly avg):' -f $SpikeRatio)
        # Spikes from multiple series don't carry their tool name; tag them
        # by mapping back via the original x_time alignment.
        # Keep it simple: just print hour + value.
        $spikes | ForEach-Object { Write-Host ('    {0}  ->  {1}' -f $_.Hour, $_.Value) }
    } else {
        Write-Host ''
        Write-Host ('  No hourly spikes above {0:N1}x average.' -f $SpikeRatio) -ForegroundColor DarkGray
    }
} else {
    Write-Host '  (no data)' -ForegroundColor DarkGray
}

# -- Section 4: quota -------------------------------------------------------

Write-Section 'Quota summary'
$quotaData = Unwrap-Data $quotaResp
if ($quotaData -and $quotaData.limits) {
    # The API may include a nextResetTime (epoch ms) on each limit. When
    # present we use that for an exact "time until reset"; otherwise we
    # fall back to a label derived from unit + number.
    # unit codes (observed): 3=hours, 5=months. number is the count.
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($lim in $quotaData.limits) {
        $type    = [string]$lim.type
        $pct     = if ($null -ne $lim.percentage) { [int]$lim.percentage } else { 0 }
        $cur     = $lim.currentValue
        $tot     = $lim.usage
        $used    = if ($null -eq $cur) { 'n/a' } else { [string]$cur }
        $limit   = if ($null -eq $tot) { 'n/a' } else { [string]$tot }

        $reset = 'n/a'
        if ($lim.PSObject.Properties['nextResetTime'] -and $null -ne $lim.nextResetTime) {
            $resetDt  = [DateTimeOffset]::FromUnixTimeMilliseconds([long]$lim.nextResetTime).LocalDateTime
            $delta    = $resetDt - (Get-Date)
            $reset    = ('{0} ({1} from now)' -f $resetDt.ToString('yyyy-MM-dd HH:mm'), (Format-Duration $delta))
        } elseif ($lim.PSObject.Properties['unit'] -and $lim.PSObject.Properties['number']) {
            $unitName = switch ([int]$lim.unit) {
                3 { 'h' }
                5 { 'mo' }
                default { "unit$($lim.unit)" }
            }
            $reset = ('{0} {1} (window)' -f $lim.number, $unitName)
        }

        $rows.Add([pscustomobject]@{
            Type      = $type
            Used      = $used
            Limit     = $limit
            Percent   = ('{0}%' -f $pct)
            Reset     = $reset
        })
    }
    $rows | Format-Table -AutoSize -Wrap | Out-Host
} else {
    Write-Host '  (no data)' -ForegroundColor DarkGray
}

# -- Section 5: concerns ---------------------------------------------------

Write-Section 'Concerns'
$concerns = New-Object System.Collections.Generic.List[string]

# Quota concerns.
if ($quotaData -and $quotaData.limits) {
    foreach ($lim in $quotaData.limits) {
        $pct  = if ($null -ne $lim.percentage) { [int]$lim.percentage } else { 0 }
        $type = [string]$lim.type
        if ($type -match 'TOKEN' -and $pct -ge $TokenWarnPercent) {
            $concerns.Add(('[HIGH] Token window: {0}% used (>= {1}%)' -f $pct, $TokenWarnPercent))
        }
        if (($type -match 'TIME_LIMIT' -or $type -match 'MCP') -and $pct -ge $McpWarnPercent) {
            $concerns.Add(('[HIGH] MCP/month window: {0}% used (>= {1}%)' -f $pct, $McpWarnPercent))
        }
    }
}

# Spike concerns.
if ($toolData) {
    foreach ($seriesName in @('networkSearchCount', 'webReadMcpCount', 'zreadMcpCount')) {
        $stats = Get-SeriesStats $toolData.x_time $toolData.$seriesName
        $spikes = Get-Spikes $toolData.x_time $toolData.$seriesName $stats.Avg
        if ($spikes.Count -gt 0) {
            $concerns.Add(('[SPIKE] {0}: {1} hour(s) above {2:N1}x hourly avg' -f $seriesName, $spikes.Count, $SpikeRatio))
        }
    }
}

if ($concerns.Count -eq 0) {
    Write-Host '  No concerns flagged.' -ForegroundColor Green
} else {
    foreach ($c in $concerns) { Write-Host ('  - ' + $c) -ForegroundColor Yellow }
}

Write-Host ''
