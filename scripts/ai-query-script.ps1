<#
.SYNOPSIS
    AI provider usage-query tools. Dot-source this file to load three
    functions into your session:

        Get-MinimaxUsage
        Get-ZaiUsage
        Get-DeepseekUsage

.DESCRIPTION
    Each function queries its provider's API, prints a summary plus
    threshold-driven concerns to the host, stashes the parsed response
    in $Global:<name>LastQuery for later inspection, and returns the
    parsed response object so it can be captured and inspected
    programmatically.

    The three functions and the parameters they accept mirror the
    standalone scripts that this file replaces:

      - Get-MinimaxUsage  : MiniMax token-plan endpoint
                            (-ApiKey, -LowPercent, -CriticalPercent,
                             -ResetWarnHours, -BurnWarnRatio, -All)

      - Get-ZaiUsage      : Z.AI model/tool/quota endpoints
                            (-Token, -McpWarnPercent, -TokenWarnPercent,
                             -SpikeRatio, -All)

      - Get-DeepseekUsage : DeepSeek balance endpoint
                            (-ApiKey, -LowBalanceUsd, -LowBalanceCny, -All)

    Dot-source once at the start of a session (or add to your PowerShell
    profile), then call the functions individually.

.EXAMPLE
    . '.\thejjw\scripts\ai-query-script.ps1'
    Get-MinimaxUsage
    Get-ZaiUsage
    Get-DeepseekUsage

.EXAMPLE
    . '.\thejjw\scripts\ai-query-script.ps1'
    $data = Get-DeepseekUsage
    $data.balance_infos | Where-Object { $_.currency -eq 'CNY' }

.EXAMPLE
    . '.\thejjw\scripts\ai-query-script.ps1'
    Get-ZaiUsage -McpWarnPercent 50 -All
#>

# -- Detect invocation mode ------------------------------------------------
# When dot-sourced, the script's functions are loaded into the caller's
# scope and persist. When run directly, the functions are scoped to this
# script and disappear when it exits, so we print a help message instead.
$script:IsDotSourced = $MyInvocation.InvocationName -eq '.'

# -- Shared helpers --------------------------------------------------------

# Render a TimeSpan as a compact human-readable string.
function Format-Duration {
    param([TimeSpan]$ts)
    if ($ts.TotalDays -ge 1)  { return ('{0:N1} d ({1:N0} h)' -f $ts.TotalDays,  $ts.TotalHours) }
    if ($ts.TotalHours -ge 1) { return ('{0:N1} h ({1:N0} m)'  -f $ts.TotalHours, $ts.TotalMinutes) }
    return ('{0:N0} m ({1:N0} s)' -f $ts.TotalMinutes, $ts.TotalSeconds)
}

# Print a section banner.
function Write-Section {
    param([string]$title)
    Write-Host ''
    Write-Host ('== {0} ==' -f $title) -ForegroundColor Cyan
}

# Convert epoch milliseconds to a local DateTime.
function From-EpochMs {
    param([long]$ms)
    return [DateTimeOffset]::FromUnixTimeMilliseconds($ms).LocalDateTime
}

# Format a token count as a compact human-readable string.
function Format-Tokens {
    param([double]$n)
    if ($n -le 0) { return '0' }
    if ($n -ge 1e9) { return ('{0:N2}B' -f ($n / 1e9)) }
    if ($n -ge 1e6) { return ('{0:N2}M' -f ($n / 1e6)) }
    if ($n -ge 1e3) { return ('{0:N2}K' -f ($n / 1e3)) }
    return ('{0:N0}' -f $n)
}

# Format a cost value as a compact decimal, stripping trailing zeros.
function Format-Price {
    param([double]$n)
    $s = ('{0:N6}' -f $n).TrimEnd('0')
    if ($s.EndsWith('.')) { $s = $s.Substring(0, $s.Length - 1) }
    return $s
}

# Compute total/avg/peak for a numeric series aligned to xTime.
function Get-SeriesStats {
    param([object[]]$xTime, [object[]]$series)
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

# Detect spikes: indexes where value > SpikeRatio * avg. Returns array
# of @{ Hour; Value } records (or empty array).
function Get-Spikes {
    param([object[]]$xTime, [object[]]$series, [double]$avg, [double]$SpikeRatio = 3.0)
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

# Z.AI's quota endpoint wraps payload under .data; pull that out.
function Unwrap-ZaiData {
    param([object]$resp)
    if ($null -eq $resp) { return $null }
    if ($resp.PSObject.Properties['data'] -and $null -ne $resp.data) { return $resp.data }
    return $resp
}

# -- Get-MinimaxUsage ------------------------------------------------------
# Queries MiniMax's token-plan endpoint for remaining quotas and burn rates
# over the current interval and the current week. Stashes the parsed
# response in $Global:minimaxLastQuery and returns it.

function Get-MinimaxUsage {
    [CmdletBinding()]
    param(
        [string]$ApiKey = $env:MINIMAX_API_KEY,
        [int]$LowPercent = 30,
        [int]$CriticalPercent = 10,
        [int]$ResetWarnHours = 1,
        [double]$BurnWarnRatio = 1.0,
        [switch]$All
    )

    if (-not $ApiKey) { Write-Error 'MINIMAX_API_KEY not set (env var or -ApiKey).'; return }

    $headers = @{
        'Content-Type'  = 'application/json'
        'Authorization' = "Bearer $ApiKey"
    }
    try {
        $resp = Invoke-RestMethod -Uri 'https://www.minimax.io/v1/token_plan/remains' -Headers $headers -Method GET
    } catch {
        Write-Error "API call failed: $($_.Exception.Message)"
        return
    }

    $Global:minimaxLastQuery = $resp

    Write-Section 'Raw API response (MiniMax)'
    if ($All) { $resp | ConvertTo-Json -Depth 8 | Out-Host }
    else      { Write-Host '  (suppressed; stored in $Global:minimaxLastQuery. Use -All to display inline.)' -ForegroundColor DarkGray }

    $now = Get-Date
    Write-Section 'Per-model insights (MiniMax)'
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($m in $resp.model_remains) {
        $intervalStart   = From-EpochMs ([long]$m.start_time)
        $intervalEnd     = From-EpochMs ([long]$m.end_time)
        $intervalTotal   = $intervalEnd - $intervalStart
        $intervalElapsed = $now - $intervalStart
        if ($intervalElapsed.TotalSeconds -lt 0) { $intervalElapsed = [TimeSpan]::Zero }
        if ($intervalElapsed -gt $intervalTotal)  { $intervalElapsed = $intervalTotal }

        $weeklyStart   = From-EpochMs ([long]$m.weekly_start_time)
        $weeklyEnd     = From-EpochMs ([long]$m.weekly_end_time)
        $weeklyTotal   = $weeklyEnd - $weeklyStart
        $weeklyElapsed = $now - $weeklyStart
        if ($weeklyElapsed.TotalSeconds -lt 0) { $weeklyElapsed = [TimeSpan]::Zero }
        if ($weeklyElapsed -gt $weeklyTotal)   { $weeklyElapsed = $weeklyTotal }

        $iRemain = [int]$m.current_interval_remaining_percent
        $wRemain = [int]$m.current_weekly_remaining_percent
        # remains_time / weekly_remains_time come back in ms, not s.
        $iReset  = [TimeSpan]::FromMilliseconds([double]$m.remains_time)
        $wReset  = [TimeSpan]::FromMilliseconds([double]$m.weekly_remains_time)

        $flags = New-Object System.Collections.Generic.List[string]
        $iRatio = $null
        if ($m.current_interval_total_count -gt 0 -and $intervalTotal.TotalSeconds -gt 0) {
            $fracElapsed = $intervalElapsed.TotalSeconds / $intervalTotal.TotalSeconds
            if ($fracElapsed -gt 0) {
                $fracUsed = [double]$m.current_interval_usage_count / [double]$m.current_interval_total_count
                $iRatio = $fracUsed / $fracElapsed
            }
        }
        $wRatio = $null
        if ($m.current_weekly_total_count -gt 0 -and $weeklyTotal.TotalSeconds -gt 0) {
            $fracElapsed = $weeklyElapsed.TotalSeconds / $weeklyTotal.TotalSeconds
            if ($fracElapsed -gt 0) {
                $fracUsed = [double]$m.current_weekly_usage_count / [double]$m.current_weekly_total_count
                $wRatio = $fracUsed / $fracElapsed
            }
        }
        if ($null -ne $iRatio -and $iRatio -gt $BurnWarnRatio) { $flags.Add('INTERVAL BURN > LINEAR') }
        if ($null -ne $wRatio -and $wRatio -gt $BurnWarnRatio) { $flags.Add('WEEKLY BURN > LINEAR') }

        if ($m.current_interval_total_count -gt 0) {
            $iUsedStr = '{0}/{1} (burn {2:N2}x)' -f $m.current_interval_usage_count, $m.current_interval_total_count, $iRatio
        } else {
            $iUsedStr = '-'
        }
        if ($m.current_weekly_total_count -gt 0) {
            $wUsedStr = '{0}/{1} (burn {2:N2}x)' -f $m.current_weekly_usage_count, $m.current_weekly_total_count, $wRatio
        } else {
            $wUsedStr = '-'
        }

        $rows.Add([pscustomobject]@{
            Model              = $m.model_name
            Interval_Remaining = ('{0}%' -f $iRemain)
            Interval_Reset     = (Format-Duration $iReset)
            Interval_Used      = $iUsedStr
            Weekly_Remaining   = ('{0}%' -f $wRemain)
            Weekly_Reset       = (Format-Duration $wReset)
            Weekly_Used        = $wUsedStr
            Alerts             = ($flags -join ', ')
        })
    }
    $rows | Format-Table -AutoSize -Wrap | Out-Host

    Write-Section 'Concerns (MiniMax)'
    $concerns = New-Object System.Collections.Generic.List[string]
    foreach ($m in $resp.model_remains) {
        $name    = [string]$m.model_name
        $iRemain = [int]$m.current_interval_remaining_percent
        $wRemain = [int]$m.current_weekly_remaining_percent
        $iReset  = [TimeSpan]::FromMilliseconds([double]$m.remains_time)
        if ($iRemain -le $CriticalPercent) {
            $concerns.Add(('[CRITICAL] {0}: only {1}% left in current interval' -f $name, $iRemain))
        } elseif ($iRemain -le $LowPercent) {
            $concerns.Add(('[LOW]      {0}: {1}% left in current interval' -f $name, $iRemain))
        }
        if ($wRemain -le $CriticalPercent) {
            $concerns.Add(('[CRITICAL] {0}: only {1}% left this week' -f $name, $wRemain))
        } elseif ($wRemain -le $LowPercent) {
            $concerns.Add(('[LOW]      {0}: {1}% left this week' -f $name, $wRemain))
        }
        if ($iReset.TotalSeconds -gt 0 -and $iReset.TotalHours -le $ResetWarnHours) {
            $concerns.Add(('[INFO]     {0}: interval resets in {1}' -f $name, (Format-Duration $iReset)))
        }
    }
    if ($concerns.Count -eq 0) {
        Write-Host '  No concerns flagged.' -ForegroundColor Green
    } else {
        foreach ($c in $concerns) { Write-Host ('  - ' + $c) -ForegroundColor Yellow }
    }

    return $resp
}

# -- Get-ZaiUsage ----------------------------------------------------------
# Hits Z.AI's three monitoring endpoints (model-usage, tool-usage,
# quota/limit) over the last 24h, prints summaries, flags spikes and
# threshold breaches. Stashes the three responses in
# $Global:zaiLastQuery as @{ Model; Tool; Quota } and returns the
# hashtable.

function Get-ZaiUsage {
    [CmdletBinding()]
    param(
        [string]$Token = $env:Z_AI_AUTH_TOKEN,
        [int]$McpWarnPercent = 80,
        [int]$TokenWarnPercent = 80,
        [double]$SpikeRatio = 3.0,
        [switch]$All
    )

    if (-not $Token) { Write-Error 'Z_AI_AUTH_TOKEN not set (env var or -Token).'; return }

    $base = 'https://api.z.ai'
    $now  = Get-Date
    # Time window matches the upstream skill: yesterday at the current
    # hour through end of the current hour.
    $start = Get-Date $now.AddDays(-1).Date.AddHours($now.Hour) -Format 'yyyy-MM-dd HH:mm:ss'
    $end   = Get-Date $now.Date.AddHours($now.Hour).AddMinutes(59).AddSeconds(59) -Format 'yyyy-MM-dd HH:mm:ss'
    $q = "?startTime=$([uri]::EscapeDataString($start))&endTime=$([uri]::EscapeDataString($end))"
    $headers = @{ Authorization = $Token; Accept = 'application/json' }

    function Invoke-Zai-Internal {
        param([string]$Path)
        try {
            return Invoke-RestMethod -Uri ($base + $Path) -Headers $headers -Method GET
        } catch {
            Write-Error "API call failed for $Path`: $($_.Exception.Message)"
            return $null
        }
    }

    $modelResp = Invoke-Zai-Internal "/api/monitor/usage/model-usage$q"
    $toolResp  = Invoke-Zai-Internal "/api/monitor/usage/tool-usage$q"
    $quotaResp = Invoke-Zai-Internal '/api/monitor/usage/quota/limit'

    $Global:zaiLastQuery = @{
        Model = $modelResp
        Tool  = $toolResp
        Quota = $quotaResp
    }

    Write-Section 'Raw API responses (Z.AI)'
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

    $modelData = Unwrap-ZaiData $modelResp
    $toolData  = Unwrap-ZaiData $toolResp
    $quotaData = Unwrap-ZaiData $quotaResp

    Write-Section 'Model usage summary (Z.AI, last 24h)'
    if ($modelData) {
        $callStats = Get-SeriesStats $modelData.x_time $modelData.modelCallCount
        $tokStats  = Get-SeriesStats $modelData.x_time $modelData.tokensUsage
        [pscustomobject]@{
            Total_Calls    = $callStats.Total
            Hourly_Avg     = ('{0:N2}' -f $callStats.Avg)
            Peak_Calls     = ('{0} at {1}' -f $callStats.Peak, $callStats.PeakHour)
            Total_Tokens   = $tokStats.Total
            Hourly_Tok_Avg = ('{0:N0}' -f $tokStats.Avg)
            Peak_Tokens    = ('{0} at {1}' -f $tokStats.Peak, $tokStats.PeakHour)
        } | Format-Table -AutoSize | Out-Host
    } else {
        Write-Host '  (no data)' -ForegroundColor DarkGray
    }

    Write-Section 'Tool usage summary (Z.AI, last 24h)'
    if ($toolData) {
        $netStats = Get-SeriesStats $toolData.x_time $toolData.networkSearchCount
        $webStats = Get-SeriesStats $toolData.x_time $toolData.webReadMcpCount
        $zreStats = Get-SeriesStats $toolData.x_time $toolData.zreadMcpCount
        [pscustomobject]@{
            Tool       = 'network-search (search-prime)'
            Total      = $netStats.Total
            Hourly_Avg = ('{0:N2}' -f $netStats.Avg)
            Peak       = ('{0} at {1}' -f $netStats.Peak, $netStats.PeakHour)
        },
        [pscustomobject]@{
            Tool       = 'web-reader'
            Total      = $webStats.Total
            Hourly_Avg = ('{0:N2}' -f $webStats.Avg)
            Peak       = ('{0} at {1}' -f $webStats.Peak, $webStats.PeakHour)
        },
        [pscustomobject]@{
            Tool       = 'zread'
            Total      = $zreStats.Total
            Hourly_Avg = ('{0:N2}' -f $zreStats.Avg)
            Peak       = ('{0} at {1}' -f $zreStats.Peak, $zreStats.PeakHour)
        } | Format-Table -AutoSize | Out-Host

        $spikes = @()
        $spikes += Get-Spikes $toolData.x_time $toolData.networkSearchCount $netStats.Avg $SpikeRatio
        $spikes += Get-Spikes $toolData.x_time $toolData.webReadMcpCount   $webStats.Avg $SpikeRatio
        $spikes += Get-Spikes $toolData.x_time $toolData.zreadMcpCount     $zreStats.Avg $SpikeRatio
        if ($spikes.Count -gt 0) {
            Write-Host ''
            Write-Host ('  Spikes (> {0:N1}x hourly avg):' -f $SpikeRatio)
            $spikes | ForEach-Object { Write-Host ('    {0}  ->  {1}' -f $_.Hour, $_.Value) }
        } else {
            Write-Host ''
            Write-Host ('  No hourly spikes above {0:N1}x average.' -f $SpikeRatio) -ForegroundColor DarkGray
        }
    } else {
        Write-Host '  (no data)' -ForegroundColor DarkGray
    }

    Write-Section 'Quota summary (Z.AI)'
    if ($quotaData -and $quotaData.limits) {
        # Use the API's nextResetTime when present, else fall back to a
        # label derived from the (unit, number) pair. unit codes
        # observed: 3=hours, 5=months.
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($lim in $quotaData.limits) {
            $type  = [string]$lim.type
            $pct   = if ($null -ne $lim.percentage) { [int]$lim.percentage } else { 0 }
            $cur   = $lim.currentValue
            $tot   = $lim.usage
            $used  = if ($null -eq $cur) { 'n/a' } else { [string]$cur }
            $limit = if ($null -eq $tot) { 'n/a' } else { [string]$tot }
            $reset = 'n/a'
            if ($lim.PSObject.Properties['nextResetTime'] -and $null -ne $lim.nextResetTime) {
                $resetDt = [DateTimeOffset]::FromUnixTimeMilliseconds([long]$lim.nextResetTime).LocalDateTime
                $delta   = $resetDt - (Get-Date)
                $reset   = ('{0} ({1} from now)' -f $resetDt.ToString('yyyy-MM-dd HH:mm'), (Format-Duration $delta))
            } elseif ($lim.PSObject.Properties['unit'] -and $lim.PSObject.Properties['number']) {
                $unitName = switch ([int]$lim.unit) {
                    3 { 'h' }
                    5 { 'mo' }
                    default { "unit$($lim.unit)" }
                }
                $reset = ('{0} {1} (window)' -f $lim.number, $unitName)
            }
            $rows.Add([pscustomobject]@{
                Type    = $type
                Used    = $used
                Limit   = $limit
                Percent = ('{0}%' -f $pct)
                Reset   = $reset
            })
        }
        $rows | Format-Table -AutoSize -Wrap | Out-Host
    } else {
        Write-Host '  (no data)' -ForegroundColor DarkGray
    }

    Write-Section 'Concerns (Z.AI)'
    $concerns = New-Object System.Collections.Generic.List[string]
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
    if ($toolData) {
        foreach ($seriesName in @('networkSearchCount', 'webReadMcpCount', 'zreadMcpCount')) {
            $stats = Get-SeriesStats $toolData.x_time $toolData.$seriesName
            $spikes = Get-Spikes $toolData.x_time $toolData.$seriesName $stats.Avg $SpikeRatio
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

    return $Global:zaiLastQuery
}

# -- Get-DeepseekUsage -----------------------------------------------------
# Queries DeepSeek's user-balance endpoint and estimates the token budget
# remaining under V4 Flash / V4 Pro pricing for each currency with a
# non-zero balance. Stashes the parsed response in
# $Global:deepseekLastQuery and returns it.

function Get-DeepseekUsage {
    [CmdletBinding()]
    param(
        [string]$ApiKey = $env:DEEPSEEK_API_KEY,
        [double]$LowBalanceUsd = 5.0,
        [double]$LowBalanceCny = 35.0,
        [switch]$All
    )

    # Pricing per 1M tokens (cache_hit, cache_miss, output) for V4 Flash/Pro.
    # Source: api-docs.deepseek.com/quick_start/pricing. Update these rows
    # if pricing changes upstream.
    $pricing = @(
        [pscustomobject]@{ Model = 'V4 Flash'; Scenario = 'Input  (cache hit)';  CostUsd = 0.0028;   CostCny = 0.02 }
        [pscustomobject]@{ Model = 'V4 Flash'; Scenario = 'Input  (cache miss)'; CostUsd = 0.14;     CostCny = 1.0 }
        [pscustomobject]@{ Model = 'V4 Flash'; Scenario = 'Output';              CostUsd = 0.28;     CostCny = 2.0 }
        [pscustomobject]@{ Model = 'V4 Pro';   Scenario = 'Input  (cache hit)';  CostUsd = 0.003625; CostCny = 0.025 }
        [pscustomobject]@{ Model = 'V4 Pro';   Scenario = 'Input  (cache miss)'; CostUsd = 0.435;    CostCny = 3.0 }
        [pscustomobject]@{ Model = 'V4 Pro';   Scenario = 'Output';              CostUsd = 0.87;     CostCny = 6.0 }
    )

    if (-not $ApiKey) { Write-Error 'DEEPSEEK_API_KEY not set (env var or -ApiKey).'; return }

    $headers = @{
        'Content-Type'  = 'application/json'
        'Authorization' = "Bearer $ApiKey"
    }
    try {
        $resp = Invoke-RestMethod -Uri 'https://api.deepseek.com/user/balance' -Headers $headers -Method GET
    } catch {
        Write-Error "API call failed: $($_.Exception.Message)"
        return
    }

    $Global:deepseekLastQuery = $resp

    Write-Section 'Raw API response (DeepSeek)'
    if ($All) { $resp | ConvertTo-Json -Depth 8 | Out-Host }
    else      { Write-Host '  (suppressed; stored in $Global:deepseekLastQuery. Use -All to display inline.)' -ForegroundColor DarkGray }

    $balances = @{}
    foreach ($b in $resp.balance_infos) {
        $balances[[string]$b.currency] = [double]$b.total_balance
    }

    Write-Section 'Balance summary (DeepSeek)'
    $balanceRows = foreach ($b in $resp.balance_infos) {
        [pscustomobject]@{
            Currency     = [string]$b.currency
            Total        = [double]$b.total_balance
            Granted      = [double]$b.granted_balance
            Topped_Up    = [double]$b.topped_up_balance
            Is_Available = [bool]$resp.is_available
        }
    }
    $balanceRows | Format-Table -AutoSize | Out-Host

    $hasAny = $false
    foreach ($cur in @('USD', 'CNY')) {
        if (-not $balances.ContainsKey($cur)) { continue }
        $bal = $balances[$cur]
        if ($bal -le 0) { continue }
        $hasAny = $true
        $rows = New-Object System.Collections.Generic.List[object]
        $costKey = 'Cost' + $cur
        foreach ($p in $pricing) {
            $cost   = [double]$p.$costKey
            $tokens = if ($cost -gt 0) { $bal / $cost * 1e6 } else { 0 }
            $rows.Add([pscustomobject]@{
                Model            = $p.Model
                Scenario         = $p.Scenario
                Cost_per_1M      = ('{0} {1}' -f $cur, (Format-Price $cost))
                Available_Tokens = (Format-Tokens $tokens)
            })
        }
        $title = if ($cur -eq 'USD') { 'Estimated USD token budget (DeepSeek)' } else { 'Estimated CNY token budget (DeepSeek)' }
        Write-Section $title
        $rows | Format-Table -AutoSize -Wrap | Out-Host
    }
    if (-not $hasAny) {
        Write-Section 'Estimated token budget (DeepSeek)'
        Write-Host '  (no USD or CNY balance > 0 reported)' -ForegroundColor DarkGray
    }
    Write-Host ('  Estimate formula: tokens = balance / cost_per_1M * 1,000,000.') -ForegroundColor DarkGray
    Write-Host ('  Actual spend depends on cache-hit ratio, prompt size, output length, and model mix.') -ForegroundColor DarkGray

    Write-Section 'Concerns (DeepSeek)'
    $concerns = New-Object System.Collections.Generic.List[string]
    if (-not [bool]$resp.is_available) {
        $concerns.Add('[CRITICAL] is_available=false: account cannot make API calls')
    }
    if ($balances.ContainsKey('USD') -and $balances['USD'] -le $LowBalanceUsd) {
        $concerns.Add(('[LOW] USD balance ${0:N2} at or below threshold ${1:N2}' -f $balances['USD'], $LowBalanceUsd))
    }
    if ($balances.ContainsKey('CNY') -and $balances['CNY'] -le $LowBalanceCny) {
        $concerns.Add(('[LOW] CNY balance {0:N2} at or below threshold {1:N2}' -f $balances['CNY'], $LowBalanceCny))
    }
    if ($balances.Count -gt 0) {
        $total = ($balances.Values | Measure-Object -Sum).Sum
        if ($total -le 0) {
            $concerns.Add('[CRITICAL] All reported balances are zero')
        }
    }
    if ($concerns.Count -eq 0) {
        Write-Host '  No concerns flagged.' -ForegroundColor Green
    } else {
        foreach ($c in $concerns) { Write-Host ('  - ' + $c) -ForegroundColor Yellow }
    }

    return $resp
}

# -- Direct-execution behavior ---------------------------------------------
# If the user runs this file directly (not dot-sourced), the three
# functions are scoped to this script and disappear when it exits, so
# calling them here would be useless. Print a help message instead and
# tell them how to load the functions for real.

if (-not $script:IsDotSourced) {
    Write-Host ''
    Write-Host 'ai-query-script.ps1' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  Dot-source this file to load three functions into your session:'
    Write-Host ''
    Write-Host ('      . ''{0}''' -f $PSCommandPath) -ForegroundColor White
    Write-Host ''
    Write-Host '  Then call them individually:'
    Write-Host ''
    Write-Host '      Get-MinimaxUsage        # MiniMax token plan'
    Write-Host '      Get-ZaiUsage            # Z.AI model/tool/quota (24h window)'
    Write-Host '      Get-DeepseekUsage       # DeepSeek balance + token budget'
    Write-Host ''
    Write-Host '  Each function returns the parsed API response, sets'
    Write-Host '  $Global:<name>LastQuery, and accepts -All to show raw JSON.'
    Write-Host ''
}
