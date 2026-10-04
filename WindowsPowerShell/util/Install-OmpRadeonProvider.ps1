<#
.SYNOPSIS
    Registers the AMD Radeon Cloud Token Factory as an omp model provider.
.DESCRIPTION
    Prompts for a Radeon Cloud API key (rc-...), verifies it against the live endpoint with
    a short chat completion, and merges an 'amd-radeon' provider block into the active omp
    model configuration (models.yml / models.yaml inside the omp agent directory).

    Nothing is written until the key passes both probes: GET /models (fast, rejects a bad key
    with 401) and a one-word chat completion on the quickest selected model (proves the model
    route works, not just the credential). A failure prints a diagnostic naming the likely
    cause -- wrong or rotated key, account still under review, or a model that is missing from
    the roster -- and writes nothing.

    The provider reuses omp's built-in 'openai-completions' transport, so no omp code change is
    involved. The merge is idempotent: the range replaced is this provider's block plus the
    contiguous comment header directly above it, so re-running never stacks a second header.
    Every other provider in the file is preserved byte-for-byte, and an append lands inside the
    'providers:' section rather than at end of file. When the file already carries an
    'amd-radeon' block it is copied to a timestamped .bak first, and any pre-existing backups
    are reported so they can be pruned.

    The API key is written to Windows Credential Manager (DPAPI-encrypted at rest), never into
    models.yml and never into a User-scope environment variable. It is injected into the current
    process environment so an omp session started from this shell can use it.

.PARAMETER ApiKey
    Radeon Cloud API key. When omitted the script prompts with hidden input and retries a failed
    probe up to three times. A key passed with -ApiKey is probed once and never retried. Required
    on a non-interactive host, where no prompt can be answered.

.PARAMETER AgentDir
    omp agent directory. Defaults to $env:PI_CODING_AGENT_DIR, then $HOME\.omp\agent. Must be a
    native Windows path: omp silently ignores POSIX-style paths such as /c/Users/me/.omp/agent
    and falls back to the default agent directory.

.PARAMETER ModelId
    Model ids to register. Defaults to every model in the built-in catalog.

.PARAMETER Force
    Replace an API key already present in Credential Manager instead of keeping it.

.EXAMPLE
    .\Install-OmpRadeonProvider.ps1

.EXAMPLE
    .\Install-OmpRadeonProvider.ps1 -ModelId Qwen3.8-Flash-Next -WhatIf

.NOTES
    Copyright (c) 2026 @thejjw. All rights reserved.
    Last Updated: October 4, 2026
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ApiKey,
    [string]$AgentDir,
    [string[]]$ModelId,
    [switch]$Force
)

# Force TLS 1.2 for web queries (Windows PowerShell 5.1 still defaults to SSL3/TLS1.0).
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

$ErrorActionPreference = "Stop"

# Configuration
$ProviderId = 'amd-radeon'
$BaseUrl = 'https://developer.amd.com.cn/radeon/api/v1'
$VaultResource = 'AMDRC_API_KEY'
$VaultUserName = 'api-key'
$DevDate = "October 4, 2026"

# Verified against the live endpoint: every id below completed a real omp bash tool loop.
# Vision/Tokenizer come from /radeon/api/v1/models metadata.
$ModelCatalog = @(
    [ordered]@{ Id = 'Qwen3.8-Flash-Next'; Name = 'Qwen3.8 Flash Next (AMD)'; Context = 262144; Tokenizer = 'qwen3'; Vision = $true },
    [ordered]@{ Id = 'MiMo-V2.6-Flash'; Name = 'MiMo V2.6 Flash (AMD)'; Context = 1048576; Tokenizer = ''; Vision = $true },
    [ordered]@{ Id = 'DeepSeek-V4.1-Flash'; Name = 'DeepSeek V4.1 Flash (AMD)'; Context = 1048576; Tokenizer = 'deepseek-v3'; Vision = $true },
    [ordered]@{ Id = 'GLM-5.3-Flash'; Name = 'GLM 5.3 Flash (AMD)'; Context = 262144; Tokenizer = 'glm5'; Vision = $false }
)

# Ordered probe preference: the shared free endpoints answered 12-13s for the first two ids and
# 470-514s for the last two, so probe with the quickest selected model.
$ProbePreference = @('Qwen3.8-Flash-Next', 'MiMo-V2.6-Flash', 'DeepSeek-V4.1-Flash', 'GLM-5.3-Flash')

# Resolve the omp agent directory for the running environment.
function Get-OmpAgentDir {
    param([string]$Override)

    if ($Override) { return $Override }
    if ($env:PI_CODING_AGENT_DIR) { return $env:PI_CODING_AGENT_DIR }
    return (Join-Path $HOME '.omp\agent')
}

# Locate the model configuration file, preferring models.yml. omp reads models.yml first, then
# models.yaml, so an existing .yaml stays authoritative and must be updated in place.
function Get-OmpModelConfigPath {
    param([string]$Dir)

    $yml = Join-Path $Dir 'models.yml'
    $yaml = Join-Path $Dir 'models.yaml'
    if (Test-Path -LiteralPath $yml) { return $yml }
    if (Test-Path -LiteralPath $yaml) { return $yaml }
    return $yml
}

# True when a prompt could actually be answered. Read-Host on a redirected stdin blocks forever.
function Test-InteractiveHost {
    try { return ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected) } catch { return $false }
}

# Read a hidden secret as plaintext, zeroing the unmanaged BSTR copy afterwards.
function Read-SecretPlain {
    param([string]$Prompt)

    $secure = Read-Host -AsSecureString -Prompt $Prompt
    if ($null -eq $secure -or -not ($secure -is [System.Security.SecureString]) -or $secure.Length -eq 0) {
        return $null
    }

    $ptr = [IntPtr]::Zero
    try {
        $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        return [Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr)
    }
    finally {
        if ($ptr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
    }
}

# Retrieve a stored credential's plaintext value, or $null when it is absent.
function Get-StoredKey {
    param($Vault, [string]$Resource)

    try {
        $cred = $Vault.Retrieve($Resource, $VaultUserName)
        $cred.RetrievePassword()
        return $cred.Password
    }
    catch {
        return $null
    }
}

# Persist a credential, replacing any previous value for the same resource.
function Set-StoredKey {
    param($Vault, [string]$Resource, [string]$Value)

    try { $Vault.Remove($Vault.Retrieve($Resource, $VaultUserName)) } catch { }
    $Vault.Add((New-Object Windows.Security.Credentials.PasswordCredential($Resource, $VaultUserName, $Value)))
}

# True when a profile that runs on shell startup already references the key variable.
function Test-ProfileLoadsKey {
    param([string]$Name)

    foreach ($p in @($PROFILE.CurrentUserCurrentHost, $PROFILE.CurrentUserAllHosts)) {
        if ($p -and (Test-Path -LiteralPath $p)) {
            if ((Get-Content -LiteralPath $p -Raw) -match [regex]::Escape($Name)) { return $true }
        }
    }
    return $false
}

# Regex matching this script's own provider key at any indent.
function Get-ProviderKeyPattern {
    return ('^(\s+){0}\s*:\s*$' -f [regex]::Escape($ProviderId))
}

# Mask a key for display; the full value is never printed or thrown.
function Format-MaskedKey {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return '<empty>' }
    if ($Value.Length -le 8) { return '***' }
    return ('{0}...{1}' -f $Value.Substring(0, 4), $Value.Substring($Value.Length - 4))
}

# POST/GET JSON returning @{ Status; Body }. Never throws; a transport failure is Status 0.
function Invoke-JsonProbe {
    param([string]$Url, [string]$Method, [hashtable]$Headers, $Payload, [int]$TimeoutSec)

    $params = @{
        Uri             = $Url
        Method          = $Method
        Headers         = $Headers
        TimeoutSec      = $TimeoutSec
        UseBasicParsing = $true
        ErrorAction     = 'Stop'
    }
    if ($null -ne $Payload) {
        $params.Body = ($Payload | ConvertTo-Json -Depth 10 -Compress)
        $params.ContentType = 'application/json'
    }

    try {
        $r = Invoke-WebRequest @params
        return @{ Status = [int]$r.StatusCode; Body = [string]$r.Content }
    }
    catch {
        $status = 0
        $body = ''
        $resp = $_.Exception.Response
        if ($null -ne $resp) {
            try { $status = [int]$resp.StatusCode } catch { $status = 0 }
            try {
                $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
                $body = $reader.ReadToEnd()
                $reader.Close()
            }
            catch { $body = '' }
        }
        else {
            $body = $_.Exception.Message
        }
        return @{ Status = $status; Body = $body }
    }
}

# Render the 'amd-radeon' provider block (2-space indent under 'providers:').
# The effort ladder is pinned to low|medium|high because the shared router 400s on
# reasoning_effort 'max'; the watchdog floor covers its 70-100s idle latency. The YAML anchors
# are emitted on the first model actually rendered, so any -ModelId subset stays valid YAML.
function Get-ProviderBlock {
    param([object[]]$Models)

    $lines = @(
        '  # AMD Radeon Cloud Token Factory - free shared endpoints (daily spend cap).',
        '  # OpenAI-compatible chat completions at /radeon/api/v1. The Anthropic wire',
        '  # (/v1/messages) authenticates but drops tool results, so openai-completions only.',
        '  # The shared router accepts reasoning_effort only as low|medium|high and rejects',
        '  # max, so every model effort ladder is capped there. Shared free endpoints also',
        '  # idle 70-100s per request, so the stream watchdog floor is raised.',
        "  ${ProviderId}:",
        "    baseUrl: $BaseUrl",
        '    api: openai-completions',
        "    apiKey: $VaultResource # env-var name; falls back to this literal string if unset",
        '    authHeader: true',
        '    models:'
    )

    for ($i = 0; $i -lt $Models.Count; $i++) {
        $m = $Models[$i]
        $lines += "      - id: $($m.Id)"
        $lines += "        name: $($m.Name)"
        $lines += "        contextWindow: $($m.Context)"
        $lines += '        maxTokens: 32768 # endpoint advertises no output cap; local budget only'
        if ($m.Tokenizer) { $lines += "        tokenizer: $($m.Tokenizer)" }
        $lines += '        reasoning: true'
        $lines += "        input: $(if ($m.Vision) { '[text, image]' } else { '[text]' })"
        if ($i -eq 0) {
            $lines += '        thinking: &efforts { mode: effort, efforts: [low, medium, high], defaultLevel: low }'
            $lines += '        compat: &slow { streamIdleTimeoutMs: 300000 }'
        }
        else {
            $lines += '        thinking: *efforts'
            $lines += '        compat: *slow'
        }
    }
    return $lines
}

# Index of the first line that belongs to the 'providers:' mapping, i.e. the insertion point for
# a new provider. Returns -1 when the document has no 'providers:' root at all. End of file is
# only correct when 'providers:' is the last root key, which is why this scans instead.
function Get-ProviderInsertIndex {
    param([string[]]$Lines)

    $root = -1
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match '^providers\s*:\s*$') { $root = $i; break }
    }
    if ($root -lt 0) { return -1 }

    $end = $Lines.Count
    for ($i = $root + 1; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i].Trim() -eq '') { continue }
        if (([regex]::Match($Lines[$i], '^\s*')).Value.Length -eq 0) { $end = $i; break }
    }
    # Do not strand the block behind blank lines that belong to the next root key.
    while ($end -gt ($root + 1) -and $Lines[$end - 1].Trim() -eq '') { $end-- }
    return $end
}

# Replace this provider's block in place, or insert it at the end of the 'providers:' section.
# The replaced range reaches upward over the block's own contiguous comment header, which is what
# makes a second run a no-op instead of stacking another six comment lines above the key.
function Merge-ProviderBlock {
    param([string[]]$Lines, [string[]]$Block)

    $pattern = Get-ProviderKeyPattern
    $updated = [System.Collections.Generic.List[string]]::new()
    $start = -1
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match $pattern) { $start = $i; break }
    }

    if ($start -lt 0) {
        $at = Get-ProviderInsertIndex $Lines
        if ($at -lt 0) {
            foreach ($line in $Lines) { $updated.Add($line) }
            if ($updated.Count -gt 0 -and $updated[$updated.Count - 1].Trim() -ne '') { $updated.Add('') }
            $updated.Add('providers:')
            $at = $updated.Count
        }
        for ($i = 0; $i -lt $at; $i++) { $updated.Add($Lines[$i]) }
        foreach ($line in $Block) { $updated.Add($line) }
        $updated.Add('')
        for ($i = $at; $i -lt $Lines.Count; $i++) { $updated.Add($Lines[$i]) }
        return $updated.ToArray()
    }

    $indent = ([regex]::Match($Lines[$start], '^\s+')).Value.Length

    # The block runs until the next line indented no deeper than the provider key. This is
    # scanned from the key itself, before the header comments are absorbed above: those same
    # comment lines would otherwise satisfy the "<= indent" test and cut the block off after
    # the first comment, which duplicates the block on every run.
    $end = $Lines.Count
    for ($i = $start + 1; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i].Trim() -eq '') { continue }
        if (([regex]::Match($Lines[$i], '^\s*')).Value.Length -le $indent) { $end = $i; break }
    }

    # Walk upward over comment lines at the provider's own indent; those are this block's header
    # and must be replaced along with it, or a re-run stacks another header above the key.
    while ($start -gt 0) {
        $prev = $Lines[$start - 1]
        if ($prev.Trim() -eq '') { break }
        if (([regex]::Match($prev, '^\s*')).Value.Length -ne $indent) { break }
        if (-not $prev.TrimStart().StartsWith('#')) { break }
        $start--
    }

    for ($i = 0; $i -lt $start; $i++) { $updated.Add($Lines[$i]) }
    foreach ($line in $Block) { $updated.Add($line) }
    for ($i = $end; $i -lt $Lines.Count; $i++) { $updated.Add($Lines[$i]) }
    return $updated.ToArray()
}

# True when the file already carries this script's provider block.
function Test-HasProviderBlock {
    param([string[]]$Lines)

    return @($Lines | Where-Object { $_ -match (Get-ProviderKeyPattern) }).Count -gt 0
}

# Print the reason a probe failed and what the operator should do about it.
function Write-ProbeDiagnostic {
    param([int]$Status, [string]$Body, [string]$Stage, [string]$Model)

    Write-Host ''
    Write-Host "Endpoint check failed at the $Stage probe (HTTP $Status)." -ForegroundColor Red
    if ($Body) { Write-Host "  response: $Body" -ForegroundColor DarkGray }

    switch ($Status) {
        0 {
            Write-Host '  The request never completed: DNS, TLS, or a blocked outbound connection.' -ForegroundColor Yellow
            Write-Host '  Check network/proxy access to developer.amd.com.cn and retry.' -ForegroundColor Yellow
        }
        401 {
            Write-Host '  The key was rejected. Copy it again from the Token Factory page.' -ForegroundColor Yellow
            Write-Host '  Note: rotating the key in the AMD console invalidates the previous one immediately.' -ForegroundColor Yellow
        }
        403 {
            Write-Host '  The account is authenticated but not cleared for use (review pending).' -ForegroundColor Yellow
            Write-Host '  Finish AMD account verification, then retry.' -ForegroundColor Yellow
        }
        404 {
            Write-Host "  '$BaseUrl' did not resolve the expected route." -ForegroundColor Yellow
            Write-Host '  The base URL changed upstream; re-check the Token Factory docs.' -ForegroundColor Yellow
        }
        default {
            Write-Host '  The service rejected or failed the request. It is a shared free tier, so' -ForegroundColor Yellow
            Write-Host '  5xx and timeouts are usually transient -- retry in a minute.' -ForegroundColor Yellow
        }
    }

    if ($Stage -eq 'chat' -and $Model) {
        Write-Host "  The credential passed, so re-check the '$Model' model entry rather than the key." -ForegroundColor Yellow
    }
}

# Main body. Kept in a function so a test can dot-source the helpers without firing the live
# probe, the Credential Manager write, or the models.yml rewrite.
function Invoke-InstallOmpRadeonProvider {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    Write-Host ("[{0}] omp-amd-radeon" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')) -ForegroundColor DarkGray

    # --- model selection -----------------------------------------------------
    $agentDir = Get-OmpAgentDir $AgentDir
    $known = @($ModelCatalog | ForEach-Object { $_.Id })
    if ($ModelId) {
        $unknown = @($ModelId | Where-Object { $known -notcontains $_ })
        if ($unknown) { throw ("Unknown model id(s): {0}. Known: {1}" -f ($unknown -join ', '), ($known -join ', ')) }
        $models = @($ModelCatalog | Where-Object { $ModelId -contains $_.Id })
    }
    else {
        $models = @($ModelCatalog)
    }
    $probeModel = @($ProbePreference | Where-Object { $models.Id -contains $_ })[0]
    if (-not $probeModel) { $probeModel = $models[0].Id }

    # --- API key: acquire, validate, then persist ----------------------------
    [void][Windows.Security.Credentials.PasswordVault, Windows.Security.Credentials, ContentType=WindowsRuntime]
    $vault = New-Object Windows.Security.Credentials.PasswordVault
    $stored = Get-StoredKey $vault $VaultResource

    if (-not $ApiKey -and -not $stored -and -not (Test-InteractiveHost)) {
        throw "No API key available and this host cannot prompt. Pass -ApiKey, or run interactively."
    }

    $candidate = $null
    $newlyEntered = $false
    if ($stored -and -not $Force -and -not $ApiKey) {
        Write-Host "Reusing the API key already in Credential Manager. Use -Force to replace it." -ForegroundColor DarkGray
        $candidate = $stored
    }
    else {
        if (-not $ApiKey) {
            Write-Host 'Paste the Radeon Cloud API key from https://developer.amd.com.cn/radeon/tokenfactory' -ForegroundColor Cyan
        }
        $candidate = if ($ApiKey) { $ApiKey } else { Read-SecretPlain "AMD Radeon Cloud API key (input hidden, blank to cancel)" }
        if (-not $candidate) { throw 'No API key supplied.' }
        $newlyEntered = $true
    }

    $maxAttempts = if ($ApiKey) { 1 } else { 3 }
    $attempt = 0
    $verified = $false
    while ($attempt -lt $maxAttempts) {
        $attempt++
        if ($candidate -notmatch '^rc-[0-9a-fA-F]{48}$') {
            Write-Host ''
            # Masked: the rejected value is still a secret.
            Write-Host ("  {0} is not a Radeon Cloud key: expected 'rc-' plus 48 hex characters." -f (Format-MaskedKey $candidate)) -ForegroundColor Red
        }
        else {
            Write-Host ("[{0}/{1}] Checking {2} against {3} ..." -f $attempt, $maxAttempts, (Format-MaskedKey $candidate), $BaseUrl) -ForegroundColor DarkGray

            $modelsProbe = Invoke-JsonProbe -Url "$BaseUrl/models" -Method 'GET' -Headers @{ Authorization = "Bearer $candidate" } -TimeoutSec 30
            if ($modelsProbe.Status -ne 200) {
                Write-ProbeDiagnostic -Status $modelsProbe.Status -Body $modelsProbe.Body -Stage 'models'
            }
            else {
                $available = @()
                try { $available = @((ConvertFrom-Json $modelsProbe.Body).data.id) } catch { }
                if ($available.Count -gt 0 -and $available -notcontains $probeModel) {
                    Write-Host ''
                    Write-Host "The key is valid, but '$probeModel' is not in the served roster." -ForegroundColor Red
                    Write-Host ("  served: {0}" -f ($available -join ', ')) -ForegroundColor DarkGray
                }
                else {
                    Write-Host ("  credential accepted; probing chat on {0} ..." -f $probeModel) -ForegroundColor DarkGray
                    $payload = @{
                        model      = $probeModel
                        max_tokens = 16
                        messages   = @(@{ role = 'user'; content = 'Reply with the single word: ok' })
                    }
                    $chatProbe = Invoke-JsonProbe -Url "$BaseUrl/chat/completions" -Method 'POST' -Headers @{ Authorization = "Bearer $candidate" } -Payload $payload -TimeoutSec 180
                    if ($chatProbe.Status -eq 200) {
                        $verified = $true
                        break
                    }
                    Write-ProbeDiagnostic -Status $chatProbe.Status -Body $chatProbe.Body -Stage 'chat' -Model $probeModel
                }
            }
        }

        if ($attempt -lt $maxAttempts) {
            Write-Host '  Enter a different key, or press Ctrl+C to stop.' -ForegroundColor Yellow
            $candidate = Read-SecretPlain "AMD Radeon Cloud API key (input hidden)"
            if (-not $candidate) { throw 'No API key supplied.' }
            $newlyEntered = $true
        }
    }

    if (-not $verified) { throw 'The Radeon Cloud endpoint check did not pass; nothing was written.' }

    Write-Host 'Endpoint check passed.' -ForegroundColor Green

    if ($newlyEntered -or $Force) {
        if ($PSCmdlet.ShouldProcess("Windows Credential Manager entry '$VaultResource'", 'Save Radeon Cloud API key')) {
            Set-StoredKey $vault $VaultResource $candidate
            Write-Host "Saved $VaultResource to Windows Credential Manager." -ForegroundColor Green
        }
    }
    $stored = $candidate

    # Inject into this process so an omp session started from this shell resolves it.
    [Environment]::SetEnvironmentVariable($VaultResource, $stored, 'Process')
    Write-Host "Injected $VaultResource into the current process environment." -ForegroundColor Green

    # --- models.yml ----------------------------------------------------------
    if (-not (Test-Path -LiteralPath $agentDir)) {
        if (-not $PSCmdlet.ShouldProcess($agentDir, 'Create omp agent directory')) { return }
        New-Item -ItemType Directory -Path $agentDir -Force | Out-Null
    }

    $configPath = Get-OmpModelConfigPath $agentDir
    $content = if (Test-Path -LiteralPath $configPath) { Get-Content -LiteralPath $configPath -Raw } else { '' }
    $newline = if ($content -match "`r`n") { "`r`n" } else { "`n" }
    $lines = if ([string]::IsNullOrEmpty($content)) { [string[]]@() } else { [string[]]($content -split "`r?`n") }

    if (Test-HasProviderBlock $lines) {
        # Bump the existing file out of the way so a bad rewrite stays recoverable.
        $stale = @(Get-ChildItem -LiteralPath $agentDir -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like 'models.yml.*.bak' -or $_.Name -like 'models.yaml.*.bak' })
        if ($stale.Count -gt 0) {
            $bytes = ($stale | Measure-Object -Property Length -Sum).Sum
            Write-Host ("{0} backup file(s) already present ({1:N0} bytes total)." -f $stale.Count, $bytes) -ForegroundColor Yellow
            Write-Host 'Delete the stale ones you no longer need before they pile up.' -ForegroundColor Yellow
            foreach ($f in ($stale | Sort-Object Name | Select-Object -Last 3)) {
                Write-Host ("  {0}  ({1})" -f $f.Name, $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm')) -ForegroundColor DarkGray
            }
        }
        if (-not $PSCmdlet.ShouldProcess($configPath, 'Back up and rewrite the amd-radeon provider block')) { return }
        $backupPath = '{0}.{1}.bak' -f $configPath, (Get-Date -Format 'yyyyMMddHHmmss')
        Copy-Item -LiteralPath $configPath -Destination $backupPath -Force
        Write-Host "Backed up existing config to $backupPath" -ForegroundColor DarkGray
    }
    elseif (-not $PSCmdlet.ShouldProcess($configPath, 'Add the amd-radeon provider block')) {
        return
    }

    $merged = Merge-ProviderBlock $lines (Get-ProviderBlock $models)
    $body = (($merged -join $newline).TrimEnd() + $newline)
    if (-not $PSCmdlet.ShouldProcess($configPath, 'Write omp model configuration')) { return }

    # No-BOM UTF-8 so the YAML parser sees a clean document start.
    [IO.File]::WriteAllText($configPath, $body, [Text.UTF8Encoding]::new($false))
    Write-Host "Wrote $($models.Count) model(s) to $configPath" -ForegroundColor Green

    Write-Host ''
    Write-Host 'Verify with: omp models amd-radeon' -ForegroundColor Cyan
    if (-not (Test-ProfileLoadsKey $VaultResource)) {
        Write-Host ''
        Write-Host "Note: no startup profile exports $VaultResource yet, so new shells lose the key." -ForegroundColor Yellow
        Write-Host "Add '$VaultResource' to the `$Names list in `$_AiKeysInternal" -ForegroundColor Yellow
        Write-Host 'in Microsoft.PowerShell_profile.ps1 to have it re-injected on every shell start.' -ForegroundColor Yellow
    }
}

# Dot-sourcing (what a Pester BeforeAll does) must define the helpers without running the
# installer: no live probe, no Credential Manager write, no models.yml rewrite.
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-InstallOmpRadeonProvider
}