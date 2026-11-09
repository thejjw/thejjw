#Requires -Version 5.1
<#
.SYNOPSIS
    Configures oh-my-pi (omp) to use LiquidAI LFM3-1.7B, served by AMD Lemonade, as its `judge`
    model: the classifier behind the `auto` thinking level.

.DESCRIPTION
    1. Verifies Lemonade Server and omp are available and that Lemonade's default llama.cpp backend
       runs (or after a Lemonade-managed install/update will run) a build that supports LFM3.
       Backend version pins are never changed; a too-old backend aborts before anything is modified.
    2. Looks for an LFM3-1.7B GGUF registered from Hugging Face. Registers and downloads one when
       none exists (registrations from other sources such as ModelScope are ignored), then sends a
       test prompt through Lemonade's OpenAI-compatible API.
    3. Adds a managed provider block to omp's models.yml and points modelRoles.judge at the model;
       the previous judge becomes the first entry of retry.fallbackChains.judge.

    Prints the state before and after the changes, then usage directions. Exits 1 on any failure.
    omp files are touched only after the Lemonade test prompt succeeds, and are backed up first.
    Re-running is safe: the managed models.yml block is replaced in place.

.PARAMETER Checkpoint
    Hugging Face checkpoint (repo:variant) registered when no LFM3 model exists yet. Any variant of
    the same repo that is already registered from Hugging Face is reused.

.PARAMETER ModelName
    Lemonade model name for a new registration.

.PARAMETER ProviderId
    omp provider id for the Lemonade endpoint (the selector becomes <ProviderId>/<model id>).

.PARAMETER ContextWindow
    Context size Lemonade loads the model with, and the window omp budgets for it.

.PARAMETER MinLlamaCppBuild
    Oldest llama.cpp build that supports LFM3 (b11960 per the LFM3-1.7B-GGUF model card).

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Set-OmpLemonadeJudge.ps1
#>
[CmdletBinding()]
param(
    [ValidatePattern('^[^/:\s]+/[^/:\s]+:[^/:\s]+$')]
    [string]$Checkpoint = 'LiquidAI/LFM3-1.7B-GGUF:Q4_K_M',
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$ModelName = 'user.LFM3-1.7B',
    [ValidatePattern('^[a-z0-9][a-z0-9._-]*$')]
    [string]$ProviderId = 'lemonade',
    [ValidateRange(2048, 262144)]
    [int]$ContextWindow = 32768,
    [int]$MinLlamaCppBuild = 11960
)

$ErrorActionPreference = 'Stop'

$MarkerStart = '# >>> omp-lemonade-judge'
$MarkerEnd = '# <<< omp-lemonade-judge'
$AbortToken = 'OMP_LEMONADE_SETUP_ABORTED'
$CheckpointRepo = $Checkpoint.Split(':')[0]
$TestSystemPrompt = 'Classify how much reasoning effort a coding-assistant request needs. Reply with exactly one word: low, medium, or high.'
$TestUserPrompt = 'Rename the local variable tmp to total in utils.py.'

# ---------------------------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------------------------

# Prints a section heading.
function Write-Section([string]$Title) {
    Write-Host ''
    Write-Host "== $Title ==" -ForegroundColor Cyan
}

# Prints one aligned report row; $Ok colors the value (green = good, yellow = needs attention).
function Write-Row([string]$Label, $Value, $Ok = $null) {
    $color = if ($null -eq $Ok) { 'Gray' } elseif ($Ok) { 'Green' } else { 'Yellow' }
    Write-Host ('  {0,-32}' -f $Label) -NoNewline
    Write-Host ([string]$Value) -ForegroundColor $color
}

# Prints a progress step.
function Write-Step([string]$Text) {
    Write-Host ''
    Write-Host "-> $Text" -ForegroundColor White
}

# Reports a fatal error with follow-up directions, then aborts the script with exit code 1.
function Stop-Setup([string]$Message, [string[]]$Directions = @()) {
    Write-Host ''
    Write-Host "FAILED: $Message" -ForegroundColor Red
    foreach ($line in $Directions) {
        if ($line) { Write-Host "  $line" -ForegroundColor Yellow }
    }
    throw $AbortToken
}

# ---------------------------------------------------------------------------------------------
# Process and API helpers
# ---------------------------------------------------------------------------------------------

# Runs a CLI command and returns its exit code with stdout and stderr text kept apart.
function Invoke-Cli([string]$Command, [string[]]$Arguments) {
    # Native stderr must not become a terminating error under ErrorActionPreference=Stop.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $records = & $Command @Arguments 2>&1
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    $stdout = @($records | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } | ForEach-Object { "$_" })
    $stderr = @($records | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | ForEach-Object { "$_" })
    [pscustomobject]@{ ExitCode = $code; StdOut = ($stdout -join "`n"); StdErr = ($stderr -join "`n") }
}

# Runs a lemonade CLI command with live console output (downloads show progress); aborts on failure.
function Invoke-LemonadeLive([string[]]$Arguments) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & lemonade @Arguments | Out-Host
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    if ($code -ne 0) { Stop-Setup "lemonade $($Arguments -join ' ') exited with code $code." }
}

# Quotes a JSON argument for native programs. Windows PowerShell (and pwsh before 7.3 or in Legacy
# mode) strips embedded double quotes from native arguments, so they must be backslash-escaped.
function ConvertTo-NativeArgument([string]$Value) {
    $modern = $PSVersionTable.PSVersion -ge [version]'7.3' -and "$PSNativeCommandArgumentPassing" -ne 'Legacy'
    if ($modern) { $Value } else { $Value.Replace('"', '\"') }
}

# Calls the Lemonade REST API and returns the parsed JSON response.
function Invoke-Lemonade([string]$Path, [string]$Method = 'GET', $Body = $null, [int]$TimeoutSec = 30) {
    $request = @{ Uri = "$script:LemonadeUrl$Path"; Method = $Method; TimeoutSec = $TimeoutSec; Headers = $script:LemonadeHeaders }
    if ($null -ne $Body) {
        $request.ContentType = 'application/json; charset=utf-8'
        $request.Body = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Body -Depth 10 -Compress))
    }
    try {
        Invoke-RestMethod @request
    } catch {
        $detail = if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        throw "Lemonade $Method $Path failed: $detail"
    }
}

# Runs omp and returns the result; aborts when omp exits non-zero unless -AllowFailure is given.
function Invoke-Omp([string[]]$Arguments, [switch]$AllowFailure) {
    $result = Invoke-Cli 'omp' $Arguments
    if ($result.ExitCode -ne 0 -and -not $AllowFailure) {
        Stop-Setup "omp $($Arguments -join ' ') exited with code $($result.ExitCode)." @($result.StdErr, $result.StdOut)
    }
    $result
}

# Returns the effective value of one omp setting ($null when unset).
function Get-OmpSetting([string]$Key) {
    ((Invoke-Omp @('config', 'get', $Key, '--json')).StdOut | ConvertFrom-Json).value
}

# Writes one record-typed omp setting to the global config.yml; warns when another layer overrides it.
function Set-OmpRecordSetting([string]$Key, $Value) {
    $json = ConvertTo-Json -InputObject $Value -Depth 10 -Compress
    $result = (Invoke-Omp @('config', 'set', $Key, (ConvertTo-NativeArgument $json), '--json')).StdOut | ConvertFrom-Json
    if ($result.overriddenBy) {
        Write-Warning "omp setting '$Key' was saved, but '$($result.overriddenBy)' still overrides it."
    }
}

# Copies a JSON object's properties into an ordered dictionary (empty when $Object is $null).
function ConvertTo-OrderedMap($Object) {
    $map = [ordered]@{}
    if ($null -ne $Object) {
        foreach ($property in $Object.PSObject.Properties) { $map[$property.Name] = $property.Value }
    }
    $map
}

# Formats a fallback chain value for the report.
function Format-Chain($Chains) {
    if ($null -eq $Chains -or -not $Chains.PSObject.Properties['judge']) { return '(unset: built-in chain)' }
    $entries = @($Chains.judge)
    if ($entries.Count -eq 0) { return '[] (no fallback)' }
    $entries -join ', '
}

# ---------------------------------------------------------------------------------------------
# Lemonade state
# ---------------------------------------------------------------------------------------------

# Returns the numeric llama.cpp build from a tag such as "b11960", or $null for other formats.
function Get-BuildNumber($Version) {
    if ([string]$Version -match '^b(\d+)$') { [int]$Matches[1] } else { $null }
}

# Returns a Lemonade model's main checkpoint ("owner/repo:variant").
function Get-MainCheckpoint($Model) {
    if ($Model.checkpoints -and $Model.checkpoints.main) { [string]$Model.checkpoints.main } else { [string]$Model.checkpoint }
}

# Returns the registry a Lemonade model downloads from (huggingface, modelscope, ...).
function Get-ModelSource($Model) {
    if ($Model.source) { [string]$Model.source } elseif ($Model.registry_source) { [string]$Model.registry_source } else { 'huggingface' }
}

# Collects Lemonade's default llama.cpp backend status and its LFM3 registrations.
function Get-LemonadeState {
    $llama = (Invoke-Lemonade '/v1/system-info').recipes.llamacpp
    if (-not $llama) { Stop-Setup 'Lemonade reports no llamacpp recipe on this system.' }
    $backendName = [string]$llama.default_backend
    $backend = if ($backendName) { $llama.backends.$backendName } else { $null }

    $models = @((Invoke-Lemonade '/v1/models?show_all=true').data)
    $repoPattern = '^' + [regex]::Escape($CheckpointRepo) + '(:|$)'
    $lfm = @($models | Where-Object { (Get-MainCheckpoint $_) -match $repoPattern })
    $huggingFace = @($lfm | Where-Object { (Get-ModelSource $_) -eq 'huggingface' })
    # Prefer a downloaded copy, then the exact requested variant.
    $pick = $huggingFace | Sort-Object -Property `
        @{ Expression = { [bool]$_.downloaded }; Descending = $true },
        @{ Expression = { (Get-MainCheckpoint $_) -eq $Checkpoint }; Descending = $true } |
        Select-Object -First 1

    [pscustomobject]@{
        BackendName    = $backendName
        BackendState   = if ($backend) { [string]$backend.state } else { 'unsupported' }
        BackendVersion = if ($backend) { [string]$backend.version } else { $null }
        BackendMessage = if ($backend) { [string]$backend.message } else { 'No llama.cpp backend can run on this system.' }
        Model          = $pick
        Ignored        = @($lfm | Where-Object { (Get-ModelSource $_) -ne 'huggingface' })
        ModelIds       = @($models | ForEach-Object { [string]$_.id })
    }
}

# Returns the llama.cpp version the default backend runs, or would run after Lemonade installs/updates it.
function Get-BackendTargetVersion($State) {
    if ($State.BackendState -in 'installed', 'update_available') { return $State.BackendVersion }
    try {
        $plan = Invoke-Lemonade '/v1/install/dry-run' -Method POST -Body @{ recipe = 'llamacpp'; backend = $State.BackendName } -TimeoutSec 60
        [string]$plan.version
    } catch {
        Write-Warning "Could not resolve the backend version Lemonade would install: $_"
        $State.BackendVersion
    }
}

# Sends one short classification prompt through Lemonade and returns the answer with timings.
function Invoke-TestPrompt([string]$ModelId) {
    $body = @{
        model           = $ModelId
        stream          = $false
        temperature     = 0.1
        max_tokens      = 16
        enable_thinking = $false
        ctx_size        = $ContextWindow
        messages        = @(
            @{ role = 'system'; content = $TestSystemPrompt },
            @{ role = 'user'; content = $TestUserPrompt }
        )
    }
    $timer = [Diagnostics.Stopwatch]::StartNew()
    # The first request also loads the model, so allow a generous timeout.
    $response = Invoke-Lemonade '/v1/chat/completions' -Method POST -Body $body -TimeoutSec 900
    $timer.Stop()
    [pscustomobject]@{
        Answer          = ([string]$response.choices[0].message.content).Trim()
        Seconds         = [math]::Round($timer.Elapsed.TotalSeconds, 2)
        Build           = [string]$response.system_fingerprint
        TokensPerSecond = if ($response.timings) { [math]::Round([double]$response.timings.predicted_per_second, 1) } else { $null }
    }
}

# ---------------------------------------------------------------------------------------------
# omp state and models.yml editing
# ---------------------------------------------------------------------------------------------

# Parses models.yml into lines and decides how the managed provider block fits in.
# Mode: replace (managed block exists), insert (append to the providers mapping), append
# (no providers key yet), conflict (an unmanaged provider uses ProviderId), or flow
# (providers is written in flow style and cannot be edited line-wise).
function Read-ModelsYaml([string]$Path) {
    $text = if (Test-Path -LiteralPath $Path) { [IO.File]::ReadAllText($Path) } else { '' }
    $newline = if ($text.Contains("`r`n")) { "`r`n" } else { "`n" }
    $lines = New-Object 'System.Collections.Generic.List[string]'
    if ($text.Length -gt 0) { $lines.AddRange([string[]]($text -split "`r?`n")) }
    if ($lines.Count -gt 0 -and $lines[$lines.Count - 1] -eq '') { $lines.RemoveAt($lines.Count - 1) }

    $plan = [pscustomobject]@{ Path = $Path; Lines = $lines; NewLine = $newline; Mode = 'append'; Start = -1; End = -1; Indent = '  ' }
    $startPattern = '^\s*' + [regex]::Escape($MarkerStart)
    $endPattern = '^\s*' + [regex]::Escape($MarkerEnd)
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($plan.Start -lt 0 -and $lines[$i] -match $startPattern) { $plan.Start = $i }
        elseif ($plan.Start -ge 0 -and $lines[$i] -match $endPattern) { $plan.End = $i; break }
    }
    if ($plan.Start -ge 0) {
        if ($plan.End -lt 0) { Stop-Setup "$Path has a '$MarkerStart' line without '$MarkerEnd'. Fix or remove that block, then re-run." }
        $plan.Mode = 'replace'
        $plan.Indent = ([regex]::Match($lines[$plan.Start], '^\s*')).Value
        return $plan
    }

    $providers = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^providers\s*:\s*(#.*)?$') { $providers = $i; break }
        if ($lines[$i] -match '^providers\s*:') { $plan.Mode = 'flow'; return $plan }
    }
    if ($providers -lt 0) { return $plan }

    # The providers mapping ends at the next top-level key (or end of file).
    $sectionEnd = $lines.Count
    for ($i = $providers + 1; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^[^\s#]') { $sectionEnd = $i; break }
    }
    for ($i = $providers + 1; $i -lt $sectionEnd; $i++) {
        if ($lines[$i] -match '^(\s+)[^\s#]') { $plan.Indent = $Matches[1]; break }
    }
    $keyPattern = '^' + [regex]::Escape($plan.Indent) + '["'']?' + [regex]::Escape($ProviderId) + '["'']?\s*:'
    for ($i = $providers + 1; $i -lt $sectionEnd; $i++) {
        if ($lines[$i] -match $keyPattern) { $plan.Mode = 'conflict'; return $plan }
    }
    # Insert after the last provider line, before trailing blanks and top-level comments.
    $insert = $sectionEnd
    while ($insert -gt $providers + 1 -and ($lines[$insert - 1].Trim() -eq '' -or $lines[$insert - 1] -match '^#')) { $insert-- }
    $plan.Mode = 'insert'
    $plan.Start = $insert
    $plan
}

# Builds the managed provider block for models.yml at the given indentation.
function Format-ProviderBlock([string]$Indent, [string]$ModelId) {
    $auth = if ($env:LEMONADE_API_KEY) { 'apiKey: LEMONADE_API_KEY # env var name; omp reads the key from it' } else { 'auth: none' }
    $block = @(
        "$MarkerStart (managed by Set-OmpLemonadeJudge.ps1; re-run to update, delete through the end marker to remove)",
        "${ProviderId}:",
        "  baseUrl: '$script:LemonadeUrl/v1'",
        '  api: openai-completions',
        "  $auth",
        '  models:',
        "    - id: '$ModelId'",
        "      name: 'LFM3 1.7B (Lemonade)'",
        '      kind: tiny # small-model kind: selectable for judge/tiny/memory, kept out of chat model cycling',
        '      reasoning: false',
        '      input: [text]',
        "      contextWindow: $ContextWindow",
        '      maxTokens: 2048',
        '      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }',
        '      compat:',
        '        extraBody:',
        '          enable_thinking: false # Lemonade extension',
        "          ctx_size: $ContextWindow # Lemonade extension: context size used when this request loads the model",
        $MarkerEnd
    )
    $block | ForEach-Object { "$Indent$_" }
}

# Applies the managed provider block according to the plan from Read-ModelsYaml and saves the file.
function Write-ModelsYaml($Plan, [string]$ModelId) {
    $lines = $Plan.Lines
    switch ($Plan.Mode) {
        'replace' {
            $lines.RemoveRange($Plan.Start, $Plan.End - $Plan.Start + 1)
            $lines.InsertRange($Plan.Start, [string[]](Format-ProviderBlock $Plan.Indent $ModelId))
        }
        'insert' {
            $lines.InsertRange($Plan.Start, [string[]](Format-ProviderBlock $Plan.Indent $ModelId))
        }
        'append' {
            if ($lines.Count -gt 0 -and $lines[$lines.Count - 1].Trim() -ne '') { $lines.Add('') }
            $lines.Add('providers:')
            $lines.AddRange([string[]](Format-ProviderBlock '  ' $ModelId))
        }
        default { throw "Unexpected models.yml mode '$($Plan.Mode)'." }
    }
    $text = ($lines -join $Plan.NewLine) + $Plan.NewLine
    [IO.File]::WriteAllText($Plan.Path, $text, (New-Object System.Text.UTF8Encoding $false))
}

# Describes the provider entry in models.yml for the report.
function Get-ProviderStatus([string]$Mode) {
    switch ($Mode) {
        'replace' { 'managed block present' }
        'conflict' { "'$ProviderId' exists (not managed by this script)" }
        'flow' { "providers uses flow style (cannot edit)" }
        default { 'absent' }
    }
}

# Collects the omp configuration this script reads or changes.
function Get-OmpState {
    $plan = Read-ModelsYaml $script:ModelsPath
    $listing = Invoke-Omp @('models', $ProviderId, '--kind', 'all', '--json') -AllowFailure
    $selectors = @()
    if ($listing.ExitCode -eq 0) {
        $selectors = @(($listing.StdOut | ConvertFrom-Json).models | ForEach-Object { "$($_.selector) (kind $($_.kind))" })
    }
    [pscustomobject]@{
        Provider  = Get-ProviderStatus $plan.Mode
        Plan      = $plan
        Listed    = $selectors
        ListError = if ($listing.ExitCode -ne 0) { $listing.StdErr } else { $null }
        Judge     = [string](Get-OmpSetting 'modelRoles').judge
        Chains    = Get-OmpSetting 'retry.fallbackChains'
        Thinking  = [string](Get-OmpSetting 'defaultThinkingLevel')
    }
}

# Points modelRoles.judge at $Selector and keeps the previous judge as the first fallback.
# Only the global config layer is read and written so project/env values are not copied into it.
function Set-OmpJudge([string]$Selector) {
    $global = (Invoke-Omp @('config', 'list', '--scope', 'global', '--json')).StdOut | ConvertFrom-Json
    $roles = ConvertTo-OrderedMap $(if ($global.modelRoles) { $global.modelRoles.value })
    $chains = ConvertTo-OrderedMap $(if ($global.'retry.fallbackChains') { $global.'retry.fallbackChains'.value })

    $previous = [string]$roles['judge']
    if ($previous -ne $Selector) {
        $roles['judge'] = $Selector
        Set-OmpRecordSetting 'modelRoles' $roles
    }

    $hadChain = $chains.Contains('judge')
    $oldChain = if ($hadChain) { @($chains['judge']) } else { @() }
    $newChain = @(@($previous) + $oldChain | Where-Object { $_ -and $_ -ne $Selector } | Select-Object -Unique)
    # Leave an unset chain alone when there is no previous judge to preserve.
    if (($previous -or $hadChain) -and (($newChain -join "`n") -ne ($oldChain -join "`n") -or -not $hadChain)) {
        $chains['judge'] = $newChain
        Set-OmpRecordSetting 'retry.fallbackChains' $chains
    }
}

# Copies a file next to itself with a timestamp suffix and returns the backup path ($null if absent).
function Backup-File([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $backup = '{0}.{1}.bak' -f $Path, (Get-Date -Format 'yyyyMMdd-HHmmss')
    Copy-Item -LiteralPath $Path -Destination $backup
    $backup
}

# ---------------------------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------------------------

# Prints the Lemonade and omp state (plus the test prompt result when available).
function Show-Report([string]$Title, $Lemonade, $Omp, $Test = $null) {
    Write-Section $Title
    $build = Get-BuildNumber $Lemonade.BackendVersion
    $backendOk = $Lemonade.BackendState -in 'installed', 'update_available'
    Write-Host '  Lemonade' -ForegroundColor DarkCyan
    Write-Row 'Server' "$script:LemonadeVersion at $script:LemonadeUrl" $true
    Write-Row 'llama.cpp backend' "$($Lemonade.BackendName): $($Lemonade.BackendState)" $backendOk
    $versionText = if ($Lemonade.BackendVersion) { $Lemonade.BackendVersion } else { '(none)' }
    $versionOk = if ($null -ne $build) { $backendOk -and $build -ge $MinLlamaCppBuild } else { $null }
    Write-Row 'llama.cpp version' "$versionText (LFM3 needs b$MinLlamaCppBuild+)" $versionOk
    if ($Lemonade.Model) {
        $state = if ($Lemonade.Model.downloaded) { 'downloaded' } else { 'registered, not downloaded' }
        Write-Row 'LFM3 model (Hugging Face)' "$($Lemonade.Model.id): $state [$(Get-MainCheckpoint $Lemonade.Model)]" ([bool]$Lemonade.Model.downloaded)
    } else {
        Write-Row 'LFM3 model (Hugging Face)' 'not registered' $false
    }
    foreach ($ignored in $Lemonade.Ignored) {
        Write-Row 'Ignored registration' "$($ignored.id) (source: $(Get-ModelSource $ignored))"
    }
    if ($Test) {
        $label = $Test.Answer.ToLowerInvariant().Trim('.', ' ')
        Write-Row 'Test prompt answer' "'$($Test.Answer)' (expected low)" ($label -eq 'low')
        Write-Row 'Test prompt time' "$($Test.Seconds) s total, $($Test.TokensPerSecond) tok/s, build $($Test.Build)"
    }

    Write-Host '  omp' -ForegroundColor DarkCyan
    Write-Row 'Version / agent dir' "$script:OmpVersion / $script:AgentDir"
    Write-Row "models.yml '$ProviderId' provider" $Omp.Provider ($Omp.Provider -eq 'managed block present')
    $listed = if ($Omp.Listed.Count) { $Omp.Listed -join ', ' } elseif ($Omp.ListError) { "error: $($Omp.ListError)" } else { '(none)' }
    Write-Row "omp models '$ProviderId'" $listed ([bool]$Omp.Listed.Count)
    $judgeOk = $Omp.Judge -like "$ProviderId/*"
    Write-Row 'modelRoles.judge' $(if ($Omp.Judge) { $Omp.Judge } else { '(unset: built-in chain)' }) $judgeOk
    Write-Row 'retry.fallbackChains.judge' (Format-Chain $Omp.Chains)
    Write-Row 'defaultThinkingLevel' $Omp.Thinking ($Omp.Thinking -eq 'auto')
}

# ---------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------

# Runs the setup: preflight, initial report, Lemonade backend/model, omp configuration, final report.
function Invoke-Setup {
    Write-Section 'Preflight'
    foreach ($tool in 'lemonade', 'omp') {
        if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
            Stop-Setup "'$tool' is not on PATH." @(
                'Install AMD Lemonade Server (https://lemonade-server.ai) and oh-my-pi (omp), open a new terminal, and re-run.')
        }
    }
    $status = Invoke-Cli 'lemonade' @('status', '--json')
    if ($status.ExitCode -ne 0) {
        Stop-Setup 'Lemonade Server is not reachable.' @(
            'Start Lemonade Server (Start menu: Lemonade Server, or LemonadeServer.exe), then re-run.', $status.StdErr, $status.StdOut)
    }
    $server = $status.StdOut | ConvertFrom-Json
    # LEMONADE_HOST may hold the server's bind address; a wildcard bind is reached via loopback.
    $lemonadeHost = if ($env:LEMONADE_HOST -and $env:LEMONADE_HOST -notin '0.0.0.0', '::', '[::]', '*') { $env:LEMONADE_HOST } else { '127.0.0.1' }
    $script:LemonadeUrl = "http://${lemonadeHost}:$($server.port)"
    $script:LemonadeVersion = [string]$server.version
    $script:LemonadeHeaders = @{}
    if ($env:LEMONADE_API_KEY) { $script:LemonadeHeaders.Authorization = "Bearer $env:LEMONADE_API_KEY" }

    $script:OmpVersion = (Invoke-Omp @('--version')).StdOut.Trim()
    $script:AgentDir = (Invoke-Omp @('config', 'path')).StdOut.Trim()
    if (-not (Test-Path -LiteralPath $script:AgentDir)) { Stop-Setup "omp agent directory '$script:AgentDir' does not exist. Run omp once to initialize it." }
    $yamlFile = Join-Path $script:AgentDir 'models.yaml'
    $script:ModelsPath = if ((Test-Path -LiteralPath $yamlFile) -and -not (Test-Path -LiteralPath (Join-Path $script:AgentDir 'models.yml'))) { $yamlFile } else { Join-Path $script:AgentDir 'models.yml' }
    $configYaml = Join-Path $script:AgentDir 'config.yaml'
    $script:ConfigPath = if ((Test-Path -LiteralPath $configYaml) -and -not (Test-Path -LiteralPath (Join-Path $script:AgentDir 'config.yml'))) { $configYaml } else { Join-Path $script:AgentDir 'config.yml' }
    Write-Host '  lemonade and omp found; Lemonade Server is running.' -ForegroundColor Green

    $lemonade = Get-LemonadeState
    $omp = Get-OmpState
    Show-Report 'Initial state' $lemonade $omp

    # Checks that would block step 3 run first, so a doomed run downloads nothing.
    if ($omp.Plan.Mode -eq 'conflict') {
        Stop-Setup "$script:ModelsPath already defines a '$ProviderId' provider that this script does not manage. Nothing was changed." @(
            "Remove that provider, or re-run with -ProviderId <other-id>.")
    }
    if ($omp.Plan.Mode -eq 'flow') {
        Stop-Setup "$script:ModelsPath writes 'providers:' in flow style ({...}). Nothing was changed." @(
            'Rewrite it as an indented (block-style) mapping, then re-run.')
    }
    if ($lemonade.BackendState -notin 'installed', 'update_available', 'update_required', 'installable') {
        Stop-Setup "Lemonade's llama.cpp backend '$($lemonade.BackendName)' is '$($lemonade.BackendState)': $($lemonade.BackendMessage)" @(
            'Run "lemonade backends" to see which llama.cpp backends this system supports.')
    }
    $targetVersion = Get-BackendTargetVersion $lemonade
    $targetBuild = Get-BuildNumber $targetVersion
    if ($null -eq $targetBuild) {
        Write-Warning "Cannot read a build number from llama.cpp version '$targetVersion'; the test prompt will show whether LFM3 loads."
    } elseif ($targetBuild -lt $MinLlamaCppBuild) {
        $binKey = "llamacpp.$($lemonade.BackendName)_bin"
        Stop-Setup "Lemonade's llama.cpp '$($lemonade.BackendName)' backend resolves to $targetVersion; LFM3 needs b$MinLlamaCppBuild or newer. Nothing was changed." @(
            'Options:',
            "  - Update Lemonade Server to a release that bundles llama.cpp b$MinLlamaCppBuild+ (check with: lemonade backends), then re-run.",
            "  - Or pin the backend yourself; this affects every model on '$($lemonade.BackendName)' (undo with =builtin):",
            "      lemonade config set $binKey=b$MinLlamaCppBuild",
            '    then re-run this script.')
    }

    # Step 1: llama.cpp backend.
    if ($lemonade.BackendState -in 'update_required', 'installable') {
        Write-Step "Installing Lemonade llama.cpp backend '$($lemonade.BackendName)' ($targetVersion)"
        Invoke-LemonadeLive @('backends', 'install', "llamacpp:$($lemonade.BackendName)")
        $lemonade = Get-LemonadeState
        if ($lemonade.BackendState -notin 'installed', 'update_available') {
            Stop-Setup "Backend '$($lemonade.BackendName)' is still '$($lemonade.BackendState)' after installing: $($lemonade.BackendMessage)"
        }
    }

    # Step 2: LFM3 model from Hugging Face, then a test prompt.
    if (-not $lemonade.Model) {
        $bare = $ModelName -replace '^user\.', ''
        if ($lemonade.ModelIds -contains $ModelName -or $lemonade.ModelIds -contains $bare) {
            Stop-Setup "Lemonade already has a model named '$ModelName' that is not an LFM3 Hugging Face registration." @(
                'Re-run with -ModelName user.<another-name>.')
        }
        Write-Step "Registering $ModelName from Hugging Face ($Checkpoint) and downloading it"
        Invoke-LemonadeLive @('pull', $ModelName, '--checkpoint', 'main', $Checkpoint, '--recipe', 'llamacpp', '--source', 'huggingface')
        $lemonade = Get-LemonadeState
    } elseif (-not $lemonade.Model.downloaded) {
        Write-Step "Downloading $($lemonade.Model.id) from Hugging Face"
        Invoke-LemonadeLive @('pull', [string]$lemonade.Model.id)
        $lemonade = Get-LemonadeState
    } else {
        Write-Step "Using downloaded model $($lemonade.Model.id)"
    }
    if (-not $lemonade.Model -or -not $lemonade.Model.downloaded) {
        Stop-Setup 'The LFM3 model is still not downloaded after pulling it.' @('Check "lemonade list" and the Lemonade Server log.')
    }
    $modelId = [string]$lemonade.Model.id

    Write-Step "Test prompt via Lemonade ($modelId; the first request loads the model)"
    try {
        $test = Invoke-TestPrompt $modelId
    } catch {
        Stop-Setup "Test prompt failed: $_. omp was not changed." @(
            'Check the Lemonade Server log (lemonade logs). An unknown-architecture error means the llama.cpp backend is too old for LFM3.')
    }
    if (-not $test.Answer) { Stop-Setup 'Test prompt returned an empty answer. omp was not changed.' }
    Write-Host "  answer: '$($test.Answer)' in $($test.Seconds) s" -ForegroundColor Green

    # Step 3: omp provider and judge role (backups first; models.yml is restored if omp rejects it).
    $selector = "$ProviderId/$modelId"
    Write-Step "Configuring omp: provider '$ProviderId' in models.yml, modelRoles.judge = $selector"
    $script:Backups = @(@(Backup-File $script:ModelsPath; Backup-File $script:ConfigPath) | Where-Object { $_ })
    $modelsBackup = $script:Backups | Where-Object { $_ -like "$script:ModelsPath.*" } | Select-Object -First 1
    Write-ModelsYaml (Read-ModelsYaml $script:ModelsPath) $modelId
    $check = Invoke-Omp @('models', $ProviderId, '--kind', 'all', '--json') -AllowFailure
    $listed = $check.ExitCode -eq 0 -and @(($check.StdOut | ConvertFrom-Json).models | Where-Object { $_.selector -eq $selector }).Count -gt 0
    if (-not $listed) {
        if ($modelsBackup) { Copy-Item -LiteralPath $modelsBackup -Destination $script:ModelsPath -Force } else { Remove-Item -LiteralPath $script:ModelsPath }
        Stop-Setup "omp does not list $selector after editing models.yml; the file was restored." @($check.StdErr)
    }
    if ($check.StdErr) { Write-Warning "omp reported while loading models.yml: $($check.StdErr)" }
    Set-OmpJudge $selector

    $finalLemonade = Get-LemonadeState
    $finalOmp = Get-OmpState
    Show-Report 'Final state' $finalLemonade $finalOmp $test
    if ($finalOmp.Judge -ne $selector) {
        Stop-Setup "modelRoles.judge resolves to '$($finalOmp.Judge)', not $selector." @(
            'A project .omp/config.yml or another settings layer overrides it; run "omp config get modelRoles" in that directory.')
    }

    Write-Section 'How to use it'
    Write-Host "  - omp now sends judge-role requests to ${selector}: the 'auto' thinking-level classifier,"
    Write-Host '    Smart unexpected-stop detection, AI staging in "omp git", and judge() in eval.'
    if ($finalOmp.Thinking -eq 'auto') {
        Write-Host "  - defaultThinkingLevel is already 'auto', so every new omp session uses the classifier."
    } else {
        Write-Host "  - defaultThinkingLevel is '$($finalOmp.Thinking)'. Turn the classifier on with:"
        Write-Host '      omp config set defaultThinkingLevel auto      (or per run: omp --thinking auto)'
    }
    Write-Host '  - Per prompt: "ultrathink" raises effort to the maximum, "chillax" lowers it, overriding the classifier.'
    Write-Host '  - The classifier stops at xhigh by default; allow max with: omp config set providers.autoThinkingMaxEffort max'
    Write-Host "  - Check it: in omp open /model -> Roles (judge = $selector), or run: omp models $ProviderId --kind all"
    Write-Host "  - Keep Lemonade Server running. While it is down omp uses: $(Format-Chain $finalOmp.Chains)"
    Write-Host '  - Undo: restore the backups below, or delete the block between the omp-lemonade-judge markers'
    Write-Host '    in models.yml and set modelRoles.judge back.'
    foreach ($backup in $script:Backups) { Write-Host "      backup: $backup" }
}

$previousEncoding = $null
try {
    # Decode omp/lemonade output as UTF-8 regardless of the console code page.
    try { $previousEncoding = [Console]::OutputEncoding; [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { $previousEncoding = $null }
    Invoke-Setup
    Write-Host ''
    Write-Host 'Done.' -ForegroundColor Green
    $exitCode = 0
} catch {
    if ("$_" -ne $AbortToken) {
        Write-Host ''
        Write-Host "FAILED: unexpected error: $_" -ForegroundColor Red
        Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    }
    $exitCode = 1
} finally {
    if ($previousEncoding) { try { [Console]::OutputEncoding = $previousEncoding } catch { } }
}
exit $exitCode
