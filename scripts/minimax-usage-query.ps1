<#
.SYNOPSIS
    Query MiniMax token plan usage and emit raw data + insights + concerns.

.DESCRIPTION
    Standalone PowerShell script. Calls
    https://www.minimax.io/v1/token_plan/remains and prints:
      1. The full raw JSON response from the API.
      2. A per-model table with: remaining %, time until reset, used/total
         (when the API populates counts), and a burn-rate projection.
      3. A "Concerns" block listing any models that trip the warning
         thresholds passed via -LowPercent, -CriticalPercent, etc.

    Thresholds (with defaults) are surfaced as parameters and chosen so the
    default run flags any quota below 30% remaining, anything below 10%, any
    interval reset under 1 hour away, and any burn ratio above 1.0x linear
    (i.e. projected to exhaust before the window ends).

.PARAMETER ApiKey
    MiniMax API key. Defaults to $env:MINIMAX_API_KEY.

.PARAMETER LowPercent
    Remaining-percent threshold below which a model is flagged as LOW.
    Default: 30.

.PARAMETER CriticalPercent
    Remaining-percent threshold below which a model is flagged as CRITICAL.
    Default: 10.

.PARAMETER ResetWarnHours
    Hours-below which an imminent interval reset is flagged.
    Default: 1.

.PARAMETER BurnWarnRatio
    Burn-ratio threshold (usage_rate / linear_rate) above which the burn
    is flagged as outpacing linear. Default: 1.0.

.PARAMETER All
    When set, inline-prints the full raw JSON response. By default the raw
    JSON is suppressed and only stored in $Global:minimaxLastQuery (the
    parsed PSObject the API returned) so you can inspect it later.

.OUTPUTS
    None. The parsed API response is exposed via the session global
    $Global:minimaxLastQuery. Per-model insights and concerns are written
    to the host.

.EXAMPLE
    pwsh ./minimax-usage-query.ps1

.EXAMPLE
    pwsh ./minimax-usage-query.ps1 -All

.EXAMPLE
    pwsh ./minimax-usage-query.ps1; $Global:minimaxLastQuery.model_remains
#>

[CmdletBinding()]
param(
    [string]$ApiKey = $env:MINIMAX_API_KEY,
    [int]$LowPercent = 30,
    [int]$CriticalPercent = 10,
    [int]$ResetWarnHours = 1,
    [double]$BurnWarnRatio = 1.0,
    [switch]$All
)

# -- Helpers ----------------------------------------------------------------

# Convert epoch milliseconds to a local DateTime.
function From-EpochMs([long]$ms) {
    return [DateTimeOffset]::FromUnixTimeMilliseconds($ms).LocalDateTime
}

# Render a TimeSpan as a compact human-readable string. We pick the
# largest unit that yields a value >= 1 so very short spans still read
# cleanly (e.g. "12 m (740 s)" rather than "0.0 h").
function Format-Duration([TimeSpan]$ts) {
    if ($ts.TotalDays -ge 1)  { return ('{0:N1} d ({1:N0} h)' -f $ts.TotalDays,  $ts.TotalHours) }
    if ($ts.TotalHours -ge 1) { return ('{0:N1} h ({1:N0} m)'  -f $ts.TotalHours, $ts.TotalMinutes) }
    return ('{0:N0} m ({1:N0} s)' -f $ts.TotalMinutes, $ts.TotalSeconds)
}

# Print a section banner. Cyan stands out from the data tables.
function Write-Section([string]$title) {
    Write-Host ''
    Write-Host ('== {0} ==' -f $title) -ForegroundColor Cyan
}

# -- Auth check -------------------------------------------------------------

if (-not $ApiKey) {
    Write-Error 'MINIMAX_API_KEY is not set (env var or -ApiKey).'
    exit 1
}

# -- API call ---------------------------------------------------------------

$headers = @{
    'Content-Type'  = 'application/json'
    'Authorization' = "Bearer $ApiKey"
}

try {
    $resp = Invoke-RestMethod -Uri 'https://www.minimax.io/v1/token_plan/remains' `
                              -Headers $headers -Method GET
} catch {
    Write-Error "API call failed: $($_.Exception.Message)"
    exit 1
}

# Always stash the parsed response so the user can poke at it later
# (e.g. $Global:minimaxLastQuery.model_remains[0].current_interval_remaining_percent).
$Global:minimaxLastQuery = $resp

# -- Section 1: raw response -----------------------------------------------

Write-Section 'Raw API response'
if ($All) {
    $resp | ConvertTo-Json -Depth 8 | Out-Host
} else {
    Write-Host '  (suppressed; stored in $Global:minimaxLastQuery. Use -All to display inline.)' -ForegroundColor DarkGray
}

# -- Section 2: per-model insights ----------------------------------------

$now = Get-Date

Write-Section 'Per-model insights'

# Build one row per model. We use a List to avoid the PowerShell "scalar
# vs array" trap when a future response contains a single model.
$rows = New-Object System.Collections.Generic.List[object]
foreach ($m in $resp.model_remains) {
    # Convert both interval and weekly timestamps to DateTime so we can
    # compute elapsed/total windows and project usage.
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
    # remains_time / weekly_remains_time come back in milliseconds (verified
    # against the interval start/end millisecond timestamps), so we build the
    # TimeSpan from ms rather than seconds.
    $iReset  = [TimeSpan]::FromMilliseconds([double]$m.remains_time)
    $wReset  = [TimeSpan]::FromMilliseconds([double]$m.weekly_remains_time)

    $flags = New-Object System.Collections.Generic.List[string]

    # Compute burn ratio: (used / total) / (elapsed / window).
    # 1.0 == on track to exactly hit the limit at window end. > 1.0 ==
    # projected to exhaust early. Only meaningful when total > 0.
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

    # Build the "used/total (burn Nx)" strings up front. PowerShell's parser
    # does not accept multi-line -f operators inside pscustomobject property
    # scriptblocks, so we pre-format and then assign.
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

# -- Section 3: concerns ---------------------------------------------------

Write-Section 'Concerns'
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

Write-Host ''
