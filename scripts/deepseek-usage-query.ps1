<#
.SYNOPSIS
    Query DeepSeek account balance and estimate remaining token budget
    under V4 Flash / V4 Pro pricing.

.DESCRIPTION
    Standalone PowerShell script. Calls https://api.deepseek.com/user/balance
    and prints:
      1. The full raw JSON response (suppressed by default; -All to display).
      2. A balance summary per currency (total, granted, topped-up).
      3. Estimated tokens available per (model, scenario, currency) using
         the embedded V4 Flash / V4 Pro pricing from the skill.
      4. A "Concerns" block flagging low balance (configurable thresholds).

    The DeepSeek balance endpoint does NOT return a periodic quota or reset
    timestamp, so this script focuses on available resources rather than
    reset timing. Tokens-available = balance / cost_per_1M * 1_000_000.

.PARAMETER ApiKey
    DeepSeek API key. Defaults to $env:DEEPSEEK_API_KEY.

.PARAMETER LowBalanceUsd
    USD balance at or below this triggers a LOW concern. Default: 5.

.PARAMETER LowBalanceCny
    CNY balance at or below this triggers a LOW concern. Default: 35.

.PARAMETER All
    When set, inline-prints the full raw JSON response. By default the
    raw JSON is suppressed and only stored in $Global:deepseekLastQuery
    (the parsed PSObject) so you can inspect it later.

.OUTPUTS
    None. The parsed API response is exposed via the session global
    $Global:deepseekLastQuery. Balance/budget tables and concerns are
    written to the host.

.EXAMPLE
    pwsh ./deepseek-usage-query.ps1

.EXAMPLE
    pwsh ./deepseek-usage-query.ps1 -All

.EXAMPLE
    pwsh ./deepseek-usage-query.ps1; $Global:deepseekLastQuery.balance_infos
#>

[CmdletBinding()]
param(
    [string]$ApiKey = $env:DEEPSEEK_API_KEY,
    [double]$LowBalanceUsd = 5.0,
    [double]$LowBalanceCny = 35.0,
    [switch]$All
)

# -- Pricing (cost per 1M tokens) ------------------------------------------
# Sourced from the deepseek-usage-query skill, which references
# https://api-docs.deepseek.com/quick_start/pricing. Update these rows
# if pricing changes upstream.
$pricing = @(
    [pscustomobject]@{ Model = 'V4 Flash'; Scenario = 'Input  (cache hit)';  CostUsd = 0.0028;   CostCny = 0.02 }
    [pscustomobject]@{ Model = 'V4 Flash'; Scenario = 'Input  (cache miss)'; CostUsd = 0.14;     CostCny = 1.0 }
    [pscustomobject]@{ Model = 'V4 Flash'; Scenario = 'Output';              CostUsd = 0.28;     CostCny = 2.0 }
    [pscustomobject]@{ Model = 'V4 Pro';   Scenario = 'Input  (cache hit)';  CostUsd = 0.003625; CostCny = 0.025 }
    [pscustomobject]@{ Model = 'V4 Pro';   Scenario = 'Input  (cache miss)'; CostUsd = 0.435;    CostCny = 3.0 }
    [pscustomobject]@{ Model = 'V4 Pro';   Scenario = 'Output';              CostUsd = 0.87;     CostCny = 6.0 }
)

# -- Helpers ----------------------------------------------------------------

# Print a section banner.
function Write-Section([string]$title) {
    Write-Host ''
    Write-Host ('== {0} ==' -f $title) -ForegroundColor Cyan
}

# Format a token count as a compact human-readable string. K=1e3, M=1e6,
# B=1e9. Anything below 1k is shown as a plain integer.
function Format-Tokens([double]$n) {
    if ($n -le 0) { return '0' }
    if ($n -ge 1e9) { return ('{0:N2}B' -f ($n / 1e9)) }
    if ($n -ge 1e6) { return ('{0:N2}M' -f ($n / 1e6)) }
    if ($n -ge 1e3) { return ('{0:N2}K' -f ($n / 1e3)) }
    return ('{0:N0}' -f $n)
}

# Format a cost value as a compact decimal. Strips trailing zeros so
# 0.002800 prints as "0.0028" but 2.000000 prints as "2".
function Format-Price([double]$n) {
    $s = ('{0:N6}' -f $n).TrimEnd('0')
    if ($s.EndsWith('.')) { $s = $s.Substring(0, $s.Length - 1) }
    return $s
}

# -- Auth check -------------------------------------------------------------

if (-not $ApiKey) {
    Write-Error 'DEEPSEEK_API_KEY is not set (env var or -ApiKey).'
    exit 1
}

# -- API call ---------------------------------------------------------------

$headers = @{
    'Content-Type'  = 'application/json'
    'Authorization' = "Bearer $ApiKey"
}

try {
    $resp = Invoke-RestMethod -Uri 'https://api.deepseek.com/user/balance' `
                              -Headers $headers -Method GET
} catch {
    Write-Error "API call failed: $($_.Exception.Message)"
    exit 1
}

# Always stash the parsed response for ad-hoc inspection.
$Global:deepseekLastQuery = $resp

# -- Section 1: raw response -----------------------------------------------

Write-Section 'Raw API response'
if ($All) {
    $resp | ConvertTo-Json -Depth 8 | Out-Host
} else {
    Write-Host '  (suppressed; stored in $Global:deepseekLastQuery. Use -All to display inline.)' -ForegroundColor DarkGray
}

# -- Section 2: balance summary --------------------------------------------

# The API returns total/granted/topped_up balances as strings, so we
# coerce to double once into a lookup keyed by currency.
$balances = @{}
foreach ($b in $resp.balance_infos) {
    $balances[[string]$b.currency] = [double]$b.total_balance
}

Write-Section 'Balance summary'
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

# -- Section 3: estimated token budget -------------------------------------

# For each currency the user actually has a non-zero balance in, build a
# table mapping each (model, scenario) to its cost and to the resulting
# token budget. A `-` in the cost column for a currency means we have
# pricing data for it; a `-` in the available-tokens column means the
# balance is zero for that currency.
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

    $title = if ($cur -eq 'USD') { 'Estimated USD token budget' } else { 'Estimated CNY token budget' }
    Write-Section $title
    $rows | Format-Table -AutoSize -Wrap | Out-Host
}
if (-not $hasAny) {
    Write-Section 'Estimated token budget'
    Write-Host '  (no USD or CNY balance > 0 reported)' -ForegroundColor DarkGray
}

# Footnote: explain the math so the user can sanity-check.
Write-Host ('  Estimate formula: tokens = balance / cost_per_1M * 1,000,000.') -ForegroundColor DarkGray
Write-Host ('  Actual spend depends on cache-hit ratio, prompt size, output length, and model mix.') -ForegroundColor DarkGray

# -- Section 4: concerns ---------------------------------------------------

Write-Section 'Concerns'
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

Write-Host ''
