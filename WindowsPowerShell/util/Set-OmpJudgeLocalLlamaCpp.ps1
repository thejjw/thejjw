#Requires -Version 5.1
<#
.SYNOPSIS
    Configures oh-my-pi (omp) to use a small local GGUF model (default LiquidAI LFM3-1.7B), served by
    a self-managed llama.cpp `llama-server`, as its `judge` model: the classifier behind the `auto`
    thinking level. Works on any Windows GPU vendor (Vulkan) or CPU only; no Lemonade/Ollama/Python.

.DESCRIPTION
    Setup (default):
    1. Checks omp and curl.exe, reports the current state, and collects the machine's resources.
    2. Resolves the llama.cpp build of the latest stable release (or -Build nightly / b####) with its
       Windows asset and SHA-256 digest, the GGUF file and its SHA-256 on Hugging Face, any verified local copy of it,
       and a free loopback port (9941, else the next free one).
    3. Prints the environment and every planned change, then asks for confirmation (default yes
       without warnings, no with warnings). Nothing is downloaded or written before that.
    4. Downloads and verifies llama.cpp and the model under ~\llama-cpp-tiny, starts llama-server,
       and sends a test prompt. A new build that fails is rolled back to the previous build.
    5. Only after the test passes: adds a managed provider block to omp's models.yml and points
       modelRoles.judge at it; the previous judge becomes the first judge fallback.

    -Start / -Stop / -Status manage the server later (the optional logon task runs -Start).
    -Start never checks for updates; re-run setup to update llama.cpp.

    Note: the omp helpers (models.yml editing, judge role) are copied from
    Set-OmpJudgeLocalLemonade.ps1 because the profile wrapper downloads this script as one file.

.PARAMETER Checkpoint
    Hugging Face checkpoint (owner/repo:variant); the variant selects the single *-<variant>.gguf file.

.PARAMETER ModelId
    Model id served by llama-server (--alias) and used in omp (selector <ProviderId>/<ModelId>).

.PARAMETER ProviderId
    omp provider id for the llama-server endpoint (default llama-cpp-tiny, distinct from omp's
    built-in auto-discovered 'llama.cpp' provider). Changing it replaces the managed block and drops
    the old id from the judge fallback chain.

.PARAMETER Backend
    auto (Vulkan build; GPU when a real Vulkan device exists, else CPU), vulkan (require a GPU) or
    cpu (smaller CPU-only build).

.PARAMETER ContextWindow
    'auto' (by total RAM: 4096 below 12 GB, 8192 below 24 GB, else 32768) or a number 2048-262144.

.PARAMETER Port
    Preferred loopback port. When not given explicitly and busy, the next free port is used.

.PARAMETER Build
    'latest' (the build behind the latest stable release, e.g. v0.9.0 -> b12110), 'nightly' (newest
    b#### build with the Windows asset) or a specific b#### tag (b11960 or newer).

.PARAMETER IdleSleepSeconds
    Unload the model after this many idle seconds (reloaded on the next request); -1 disables.

.PARAMETER AutoStart
    Also register the per-user logon task 'llama-cpp-tiny' that runs this script with -Start.

.PARAMETER Yes
    Skip the confirmation prompt (the environment and plan are still printed).

.PARAMETER Start
    Start the configured server (no-op when already running).

.PARAMETER Stop
    Stop the configured server.

.PARAMETER Status
    Show the server, port, model and logon task status.

.PARAMETER RemoveAutoStart
    Remove the logon task.

.PARAMETER InstallService
    (Elevated) Run llama-server as the Windows service 'llama-cpp-tiny' through shawl, as the virtual
    account NT SERVICE\llama-cpp-tiny, starting at boot (delayed). Grants that account Modify on
    ~\llama-cpp-tiny and the installing user start/stop rights on the service, so setup, -Start
    and -Stop keep working unelevated. Replaces the logon task. Run setup first.
    Prerequisite: shawl (winget install --id mtkennerly.shawl --exact --scope machine).

.PARAMETER ShawlPath
    Path to shawl.exe for -InstallService (default: shawl.exe on PATH, e.g. from
    winget install --id mtkennerly.shawl --scope machine).

.PARAMETER RemoveService
    (Elevated) Stop and delete the service and remove its folder permission.

.PARAMETER Run
    Internal: run llama-server in the foreground from server.json (the service command).

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Set-OmpJudgeLocalLlamaCpp.ps1
.EXAMPLE
    .\Set-OmpJudgeLocalLlamaCpp.ps1 -Backend cpu -ContextWindow 8192 -AutoStart
.EXAMPLE
    .\Set-OmpJudgeLocalLlamaCpp.ps1 -Status
#>
[CmdletBinding(DefaultParameterSetName = 'Setup')]
param(
    [Parameter(ParameterSetName = 'Setup')]
    [ValidatePattern('^[^/:\s]+/[^/:\s]+:[^/:\s]+$')]
    [string]$Checkpoint = 'LiquidAI/LFM3-1.7B-GGUF:Q4_K_M',
    [Parameter(ParameterSetName = 'Setup')]
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$ModelId = 'LFM3-1.7B',
    [Parameter(ParameterSetName = 'Setup')]
    [ValidatePattern('^[a-z0-9][a-z0-9._-]*$')]
    [string]$ProviderId = 'llama-cpp-tiny',
    [Parameter(ParameterSetName = 'Setup')]
    [ValidateSet('auto', 'vulkan', 'cpu')]
    [string]$Backend = 'auto',
    [Parameter(ParameterSetName = 'Setup')]
    [ValidatePattern('^(auto|\d+)$')]
    [string]$ContextWindow = 'auto',
    [Parameter(ParameterSetName = 'Setup')]
    [ValidateRange(1024, 65535)]
    [int]$Port = 9941,
    [Parameter(ParameterSetName = 'Setup')]
    [ValidatePattern('^(latest|nightly|b\d+)$')]
    [string]$Build = 'latest',
    [Parameter(ParameterSetName = 'Setup')]
    [ValidateRange(-1, 604800)]
    [int]$IdleSleepSeconds = 900,
    [Parameter(ParameterSetName = 'Setup')]
    [switch]$AutoStart,
    [Parameter(ParameterSetName = 'Setup')]
    [switch]$Yes,
    [Parameter(ParameterSetName = 'Start', Mandatory = $true)]
    [switch]$Start,
    [Parameter(ParameterSetName = 'Stop', Mandatory = $true)]
    [switch]$Stop,
    [Parameter(ParameterSetName = 'Status', Mandatory = $true)]
    [switch]$Status,
    [Parameter(ParameterSetName = 'RemoveAutoStart', Mandatory = $true)]
    [switch]$RemoveAutoStart,
    [Parameter(ParameterSetName = 'InstallService', Mandatory = $true)]
    [switch]$InstallService,
    [Parameter(ParameterSetName = 'InstallService')]
    [string]$ShawlPath,
    [Parameter(ParameterSetName = 'RemoveService', Mandatory = $true)]
    [switch]$RemoveService,
    [Parameter(ParameterSetName = 'Run', Mandatory = $true)]
    [switch]$Run
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# Captured here: inside functions $PSBoundParameters refers to the function's own parameters.
$ExplicitPort = $PSBoundParameters.ContainsKey('Port')

$MarkerStart = '# >>> omp-llamacpp-judge'
$MarkerEnd = '# <<< omp-llamacpp-judge'
$AbortToken = 'OMP_LLAMACPP_SETUP_ABORTED'
$MinLlamaCppBuild = 11960
$TaskName = 'llama-cpp-tiny'
$ServiceName = 'llama-cpp-tiny'
$ServiceAccount = "NT SERVICE\$ServiceName"
# The service runs under another account, so it passes the root explicitly.
$Root = if ($env:LLAMA_CPP_TINY_HOME) { $env:LLAMA_CPP_TINY_HOME } else { Join-Path $HOME 'llama-cpp-tiny' }
$ServiceScriptPath = Join-Path $Root 'service\Set-OmpJudgeLocalLlamaCpp.ps1'
$BinRoot = Join-Path $Root 'bin'
$ModelsDir = Join-Path $Root 'models'
$ServerConfigPath = Join-Path $Root 'server.json'
$CurlExe = Join-Path $env:SystemRoot 'System32\curl.exe'
$GitHubRepo = 'ggml-org/llama.cpp'
$PortRangeSize = 49
$KvBytesPerToken = 30KB
$DiskMarginBytes = 512MB
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
    Write-Host ('  {0,-38}' -f $Label) -NoNewline
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

# Formats a byte count as MB below 1 GB, else GB.
function Format-Bytes([double]$Bytes) {
    if ($Bytes -lt 1GB) { '{0:N1} MB' -f ($Bytes / 1MB) } else { '{0:N2} GB' -f ($Bytes / 1GB) }
}

# Shortens a path under the user's home to ~\...
function Format-HomePath([string]$Path) {
    if ($Path -and $Path.StartsWith($HOME, [StringComparison]::OrdinalIgnoreCase)) { '~' + $Path.Substring($HOME.Length) } else { $Path }
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

# Quotes a JSON argument for native programs. Windows PowerShell (and pwsh before 7.3 or in Legacy
# mode) strips embedded double quotes from native arguments, so they must be backslash-escaped.
function ConvertTo-NativeArgument([string]$Value) {
    $modern = $PSVersionTable.PSVersion -ge [version]'7.3' -and "$PSNativeCommandArgumentPassing" -ne 'Legacy'
    if ($modern) { $Value } else { $Value.Replace('"', '\"') }
}

# Quotes one argument for a Windows command line (CommandLineToArgvW rules), for Start-Process.
function ConvertTo-CommandLineArgument([string]$Value) {
    if ($Value -ne '' -and $Value -notmatch '[\s"]') { return $Value }
    # Backslashes are literal unless they precede a quote (or the closing quote): double those.
    $escaped = [regex]::Replace($Value, '(\\*)"', [Text.RegularExpressions.MatchEvaluator] { param($m) ($m.Groups[1].Value * 2) + '\"' })
    $escaped = [regex]::Replace($escaped, '(\\+)$', [Text.RegularExpressions.MatchEvaluator] { param($m) $m.Groups[1].Value * 2 })
    '"' + $escaped + '"'
}

# Calls a JSON REST endpoint and returns the parsed response.
function Invoke-Json([string]$Uri, [string]$Method = 'GET', $Body = $null, [int]$TimeoutSec = 30, [hashtable]$Headers = @{}) {
    $request = @{ Uri = $Uri; Method = $Method; TimeoutSec = $TimeoutSec; Headers = $Headers; UseBasicParsing = $true }
    if ($null -ne $Body) {
        $request.ContentType = 'application/json; charset=utf-8'
        $request.Body = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Body -Depth 10 -Compress))
    }
    try {
        Invoke-RestMethod @request
    } catch {
        $detail = if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        throw "$Method $Uri failed: $detail"
    }
}

# Calls the GitHub REST API for the llama.cpp repository (uses GH_TOKEN/GITHUB_TOKEN when set).
function Invoke-GitHubApi([string]$Path) {
    $headers = @{ Accept = 'application/vnd.github+json'; 'X-GitHub-Api-Version' = '2022-11-28' }
    $token = if ($env:GH_TOKEN) { $env:GH_TOKEN } else { $env:GITHUB_TOKEN }
    if ($token) { $headers.Authorization = "Bearer $token" }
    Invoke-Json "https://api.github.com/repos/$GitHubRepo$Path" -Headers $headers
}

# Downloads a URL to $OutFile with curl.exe (resumable via a .partial file); aborts on failure.
function Invoke-Download([string]$Url, [string]$OutFile) {
    $partial = "$OutFile.partial"
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $CurlExe -L --fail --retry 3 --retry-all-errors --progress-bar -C - -o $partial $Url
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    if ($code -ne 0) { Stop-Setup "Download failed (curl exit code $code): $Url" @('Re-run to resume the download.') }
    Move-Item -LiteralPath $partial -Destination $OutFile -Force
}

# ---------------------------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------------------------

# Returns 'arm64' or 'x64' for the llama.cpp asset name.
function Get-HostArch {
    $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    if ($arch -eq 'ARM64') { 'arm64' } else { 'x64' }
}

# Collects OS, CPU, RAM, GPU and disk information with read-only CIM/.NET queries.
function Get-EnvironmentResources {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $cpus = @(Get-CimInstance Win32_Processor)
    $gpus = @(Get-CimInstance Win32_VideoController | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; Driver = [string]$_.DriverVersion } })
    $drive = New-Object IO.DriveInfo ([IO.Path]::GetPathRoot($Root))
    $rootSize = 0
    if (Test-Path -LiteralPath $Root) {
        $rootSize = [double](Get-ChildItem -LiteralPath $Root -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
    }
    [pscustomobject]@{
        Os           = "$($os.Caption) $($os.BuildNumber)".Trim()
        Arch         = Get-HostArch
        Cpu          = if ($cpus) { ([string]$cpus[0].Name).Trim() } else { 'unknown' }
        Cores        = [int](($cpus | Measure-Object -Property NumberOfCores -Sum).Sum)
        Threads      = [int](($cpus | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum)
        RamTotal     = [double]$cs.TotalPhysicalMemory
        RamAvailable = [double]$os.FreePhysicalMemory * 1KB
        Gpus         = $gpus
        DriveRoot    = $drive.Name
        DiskFree     = [double]$drive.AvailableFreeSpace
        DiskTotal    = [double]$drive.TotalSize
        RootSize     = $rootSize
    }
}

# Returns the context size for ContextWindow 'auto' from total RAM (32768 is all the judge needs).
function Get-ContextTier([double]$RamTotal) {
    if ($RamTotal -lt 12GB) { 4096 } elseif ($RamTotal -lt 24GB) { 8192 } else { 32768 }
}

# Returns disk and RAM needs. Sizes of things already present are passed as 0.
function Get-InstallRequirement([double]$ZipSize, [double]$ModelDownloadSize, [double]$ModelSize, [int]$Context) {
    $extracted = $ZipSize * 3  # observed: 37.9 MB Vulkan zip -> ~106 MB extracted
    $download = $ZipSize + $extracted + $ModelDownloadSize
    [pscustomobject]@{
        ExtractedSize = $extracted
        DiskNeeded    = if ($download -gt 0) { $download + $DiskMarginBytes } else { 0 }
        RamEstimate   = $ModelSize + $Context * $KvBytesPerToken  # KV cache: ~30 KB/token estimate
    }
}

# Returns the warnings that switch the confirmation default to "no".
function Get-InstallWarnings($Resources, $Requirement) {
    $warnings = @()
    if ($Resources.RamTotal -lt 8GB) {
        $warnings += "Total RAM is $(Format-Bytes $Resources.RamTotal), below 8 GB; consider omp's built-in ONNX tiny-model path instead."
    }
    if ($Resources.RamAvailable -lt $Requirement.RamEstimate) {
        $warnings += "Available RAM ($(Format-Bytes $Resources.RamAvailable)) is below the estimated server need ($(Format-Bytes $Requirement.RamEstimate))."
    }
    if ($Requirement.DiskNeeded -gt 0 -and ($Resources.DiskFree - $Requirement.DiskNeeded) -lt 5GB) {
        $warnings += "Less than 5 GB would remain free on $($Resources.DriveRoot) after installing."
    }
    $warnings
}

# Returns $true when this session can ask a question (console input, interactive host).
function Test-CanPrompt {
    if (-not [Environment]::UserInteractive) { return $false }
    if ([Console]::IsInputRedirected) { return $false }
    -not ([Environment]::GetCommandLineArgs() | Where-Object { $_ -match '^-noni' })
}

# Applies the disk hard stop, shows warnings, then asks for confirmation. The default is yes
# without warnings and no with warnings; unrecognized answers ask again. Returns $true to proceed.
function Confirm-Install([string[]]$Warnings, [bool]$NothingToInstall, [bool]$AssumeYes, [bool]$CanPrompt, [double]$DiskNeeded, [double]$DiskFree, [string]$DriveRoot) {
    $Warnings = @($Warnings | Where-Object { $_ })
    if ($DiskNeeded -gt $DiskFree) {
        Stop-Setup "Not enough free disk on ${DriveRoot}: need $(Format-Bytes $DiskNeeded), have $(Format-Bytes $DiskFree) (short by $(Format-Bytes ($DiskNeeded - $DiskFree))). Nothing was changed."
    }
    foreach ($warning in $Warnings) { Write-Host "  WARNING: $warning" -ForegroundColor Yellow }
    if ($NothingToInstall) {
        Write-Host '  Nothing to download or install; continuing without a prompt.' -ForegroundColor Green
        return $true
    }
    if ($AssumeYes) {
        Write-Host '  -Yes given; continuing without a prompt.' -ForegroundColor Green
        return $true
    }
    if (-not $CanPrompt) {
        Stop-Setup 'This session cannot ask for confirmation. Nothing was changed.' @('Review the plan above and re-run with -Yes to proceed.')
    }
    $defaultYes = $Warnings.Count -eq 0
    $choices = if ($defaultYes) { '[Y/n]' } else { '[y/N]' }
    $note = if ($defaultYes) { 'no warnings, Enter = yes' } else { "$($Warnings.Count) warning(s), Enter = no" }
    while ($true) {
        $answer = ([string](Read-Host "Proceed? $choices ($note)")).Trim().ToLowerInvariant()
        if ($answer -eq '') { return $defaultYes }
        if ($answer -in 'y', 'yes') { return $true }
        if ($answer -in 'n', 'no') { return $false }
        Write-Host '  Please answer y or n.' -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------------------------
# llama.cpp releases and builds
# ---------------------------------------------------------------------------------------------

# Returns the Windows release asset name for a build tag, flavor (vulkan|cpu) and arch (x64|arm64).
function Get-AssetName([string]$Tag, [string]$Flavor, [string]$Arch) {
    "llama-$Tag-bin-win-$Flavor-$Arch.zip"
}

# Returns the release's matching asset with its SHA-256 digest, or $null when missing or unverifiable.
function Get-ReleaseAsset($Release, [string]$Flavor, [string]$Arch) {
    $tag = [string]$Release.tag_name
    if ($tag -notmatch '^b(\d+)$') { return $null }
    $buildNumber = [int]$Matches[1]
    $name = Get-AssetName $tag $Flavor $Arch
    $asset = @($Release.assets) | Where-Object { $_.name -eq $name } | Select-Object -First 1
    if (-not $asset -or [string]$asset.digest -notmatch '^sha256:([0-9a-fA-F]{64})$') { return $null }
    [pscustomobject]@{
        Tag    = $tag
        Build  = $buildNumber
        Name   = $name
        Url    = [string]$asset.browser_download_url
        Size   = [double]$asset.size
        Sha256 = $Matches[1].ToLowerInvariant()
    }
}

# Picks the newest non-draft b#### release (>= $MinBuild) that has the asset with a digest. All b####
# builds are published as prereleases, so prereleases are allowed; the newest one may still be
# uploading its Windows assets and is then skipped.
function Select-LlamaRelease($Releases, [string]$Flavor, [string]$Arch, [int]$MinBuild) {
    $candidates = foreach ($release in $Releases) {
        if ($release.draft) { continue }
        if ([string]$release.tag_name -notmatch '^b(\d+)$' -or [int]$Matches[1] -lt $MinBuild) { continue }
        $release
    }
    foreach ($release in @($candidates | Sort-Object { [int]([string]$_.tag_name).Substring(1) } -Descending)) {
        $asset = Get-ReleaseAsset $release $Flavor $Arch
        if ($asset) { return $asset }
    }
    $null
}

# Downloads a small text file and returns its trimmed content.
function Get-WebText([string]$Url) {
    $content = (Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 30).Content
    if ($content -is [byte[]]) { $content = [Text.Encoding]::UTF8.GetString($content) }
    ([string]$content).Trim()
}

# Returns the b#### build behind the latest stable (semver) release: its nightly-tag.txt asset
# names the build whose binaries it corresponds to (v0.9.0 -> b12110).
function Get-StableBuildTag {
    $release = Invoke-GitHubApi '/releases/latest'
    $marker = @($release.assets) | Where-Object { $_.name -eq 'nightly-tag.txt' } | Select-Object -First 1
    if (-not $marker) { throw "the latest stable release $($release.tag_name) has no nightly-tag.txt" }
    $tag = Get-WebText ([string]$marker.browser_download_url)
    if ($tag -notmatch '^b\d+$') { throw "nightly-tag.txt of $($release.tag_name) holds '$tag', not a b#### tag" }
    Write-Host "  Latest stable llama.cpp release: $($release.tag_name) -> $tag"
    $tag
}

# Resolves -Build to a verified asset: latest (stable release's build), nightly (newest b#### with
# the asset) or b####. When GitHub is unreachable, falls back to the installed build recorded in
# server.json (returned with Offline = $true).
function Resolve-LlamaRelease([string]$BuildSpec, [string]$Flavor, [string]$Arch, $Saved) {
    try {
        if ($BuildSpec -eq 'nightly') {
            $releases = Invoke-GitHubApi '/releases?per_page=30'
            $asset = Select-LlamaRelease $releases $Flavor $Arch $MinLlamaCppBuild
            if (-not $asset) {
                Stop-Setup "None of the latest 30 llama.cpp releases has $(Get-AssetName 'b<N>' $Flavor $Arch) with a SHA-256 digest." @('Re-run later, or pass -Build latest or b<N>.')
            }
            return $asset
        }
        $tag = if ($BuildSpec -eq 'latest') { Get-StableBuildTag } else { $BuildSpec }        if ([int]$tag.Substring(1) -lt $MinLlamaCppBuild) {
            Stop-Setup "llama.cpp $tag is older than b$MinLlamaCppBuild, the first build that supports LFM3."
        }
        $asset = Get-ReleaseAsset (Invoke-GitHubApi "/releases/tags/$tag") $Flavor $Arch
        if (-not $asset) { Stop-Setup "llama.cpp release $tag has no $(Get-AssetName $tag $Flavor $Arch) with a SHA-256 digest." @('Pass -Build nightly or another -Build b<N>.') }
        $asset
    } catch {
        if ("$_" -eq $AbortToken) { throw }
        $dir = if ($Saved) { [string]$Saved.current } else { '' }
        $installed = $dir -match '^(b(\d+))-(\w+)-(\w+)$' -and $Matches[3] -eq $Flavor -and $Matches[4] -eq $Arch -and
            ($BuildSpec -in 'latest', 'nightly' -or $BuildSpec -eq $Matches[1]) -and (Test-Path -LiteralPath (Join-Path $BinRoot "$dir\llama-server.exe"))
        if (-not $installed) {
            Stop-Setup "Cannot resolve llama.cpp release '$BuildSpec': $_" @('Check the network (api.github.com), then re-run, or pass -Build b<N> once GitHub is reachable.')
        }
        Write-Warning "Cannot reach GitHub ($_); keeping the installed build $($Matches[1])."
        [pscustomobject]@{ Tag = $Matches[1]; Build = [int]$Matches[2]; Name = $null; Url = $null; Size = 0; Sha256 = $null; Offline = $true }
    }
}

# Returns "b<N> (<version>)" reported by a llama.cpp executable, or $null when it does not run.
function Get-LlamaVersion([string]$Exe) {
    if (-not (Test-Path -LiteralPath $Exe)) { return $null }
    $result = Invoke-Cli $Exe @('--version')
    $text = "$($result.StdOut)`n$($result.StdErr)"
    if ($text -match 'version:\s*(\S+)\s*\(build (\d+)') { "b$($Matches[2]) ($($Matches[1]))" } else { $null }
}

# Returns $true when $Dir holds a llama-server that reports build $BuildNumber.
function Test-BuildInstalled([string]$Dir, [int]$BuildNumber) {
    $version = Get-LlamaVersion (Join-Path $Dir 'llama-server.exe')
    [bool]($version -and $version -match "^b$BuildNumber ")
}

# Downloads, verifies (SHA-256 digest) and extracts a release asset into $TargetDir.
function Install-LlamaRelease($Asset, [string]$TargetDir) {
    New-Item -ItemType Directory -Path $BinRoot -Force | Out-Null
    $zip = Join-Path $BinRoot $Asset.Name
    Write-Step "Downloading $($Asset.Name) ($(Format-Bytes $Asset.Size))"
    Invoke-Download $Asset.Url $zip
    $hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -ne $Asset.Sha256) {
        Remove-Item -LiteralPath $zip -Force
        Stop-Setup "SHA-256 mismatch for $($Asset.Name) (expected $($Asset.Sha256), got $hash); the file was deleted." @('Re-run to download it again.')
    }
    Write-Host '  SHA-256 verified.' -ForegroundColor Green
    $staging = "$TargetDir.tmp"
    if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
    Expand-Archive -LiteralPath $zip -DestinationPath $staging -Force
    if (-not (Test-Path -LiteralPath (Join-Path $staging 'llama-server.exe'))) {
        Stop-Setup "$($Asset.Name) does not contain llama-server.exe at its root; the archive layout may have changed."
    }
    if (Test-Path -LiteralPath $TargetDir) { Remove-Item -LiteralPath $TargetDir -Recurse -Force }
    Rename-Item -LiteralPath $staging -NewName (Split-Path -Leaf $TargetDir)
    Remove-Item -LiteralPath $zip -Force
    Write-Host "  Installed to $(Format-HomePath $TargetDir)" -ForegroundColor Green
}

# Lists build dirs under bin\ that are not kept and not in use by a running process.
function Get-PrunableBuilds([string[]]$Keep) {
    if (-not (Test-Path -LiteralPath $BinRoot)) { return @() }
    $running = @(Get-Process -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Path } catch { $null } } | Where-Object { $_ })
    $prunable = foreach ($dir in Get-ChildItem -LiteralPath $BinRoot -Directory) {
        if ($dir.Name -notmatch '^b\d+-\w+-\w+(\.tmp)?$' -or $dir.Name -in $Keep) { continue }
        $prefix = $dir.FullName + '\'
        if ($running | Where-Object { $_.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) }) { continue }
        $dir.FullName
    }
    @($prunable)
}

# Parses `llama-server --list-devices` output into real and software (llvmpipe etc.) Vulkan devices.
# Parsed = $false when the "Available devices:" header is missing (unknown format).
function Get-VulkanDevices([string[]]$Lines) {
    $text = @($Lines) -join "`n"
    $devices = @([regex]::Matches($text, '(?m)^\s*(Vulkan\d+):\s*(.+?)\s*$') | ForEach-Object { "$($_.Groups[1].Value): $($_.Groups[2].Value)" })
    $software = @($devices | Where-Object { $_ -match 'llvmpipe|SwiftShader|Microsoft Basic Render' })
    [pscustomobject]@{
        Parsed   = $text -match '(?m)^\s*Available devices:'
        Real     = @($devices | Where-Object { $_ -notin $software })
        Software = $software
    }
}

# Chooses -ngl: all (real GPU), 0 (CPU), or auto when a Vulkan build's output cannot be parsed.
function Select-GpuLayers([string]$Backend, $Probe) {
    if ($Backend -eq 'cpu') { return '0' }
    if (-not $Probe.Parsed) {
        Write-Warning 'Could not parse llama-server --list-devices output; letting llama.cpp choose GPU offload (-ngl auto).'
        return 'auto'
    }
    if ($Probe.Real.Count -gt 0) { return 'all' }
    if ($Backend -eq 'vulkan') {
        Stop-Setup 'No hardware Vulkan device found (-Backend vulkan).' @('Update the GPU driver, or re-run with -Backend auto or cpu.')
    }
    '0'
}

# ---------------------------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------------------------

# Picks the single *-<variant>.gguf file from a Hugging Face tree listing (path, size, sha256).
function Get-HfModelFile($Items, [string]$Variant) {
    $pattern = '(?i)^[^/]*[-_.]' + [regex]::Escape($Variant) + '\.gguf$'
    $files = @($Items | Where-Object { $_.type -eq 'file' -and [string]$_.path -match $pattern })
    if ($files.Count -eq 0) { Stop-Setup "The Hugging Face repo has no *-$Variant.gguf file." }
    if ($files.Count -gt 1) { Stop-Setup "Several files match *-$Variant.gguf: $(($files | ForEach-Object { $_.path }) -join ', ')." }
    $file = $files[0]
    if (-not $file.lfs -or [string]$file.lfs.oid -notmatch '^[0-9a-fA-F]{64}$') {
        Stop-Setup "Hugging Face reports no SHA-256 for $($file.path); it cannot be verified."
    }
    [pscustomobject]@{ Path = [string]$file.path; Size = [double]$file.lfs.size; Sha256 = ([string]$file.lfs.oid).ToLowerInvariant() }
}

# Returns the .sha256 sidecar line for a file: "<sha256> <length> <last-write UTC ticks>".
function Get-SidecarLine([string]$Path, [string]$Sha256) {
    $item = Get-Item -LiteralPath $Path
    "$Sha256 $($item.Length) $($item.LastWriteTimeUtc.Ticks)"
}

# Returns $true when $Path has the expected SHA-256. A matching sidecar avoids re-hashing.
function Test-FileSha256([string]$Path, [string]$Sha256, [double]$Size) {
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    if ($Size -gt 0 -and (Get-Item -LiteralPath $Path).Length -ne $Size) { return $false }
    $sidecar = "$Path.sha256"
    if ((Test-Path -LiteralPath $sidecar) -and ([IO.File]::ReadAllText($sidecar).Trim() -eq (Get-SidecarLine $Path $Sha256))) { return $true }
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -eq $Sha256
}

# Returns the Hugging Face / ModelScope cache roots that exist (HF_HUB_CACHE, HF_HOME\hub, ~\.cache\huggingface\hub).
function Get-HfCacheRoots {
    $roots = @($env:HF_HUB_CACHE)
    if ($env:HF_HOME) { $roots += Join-Path $env:HF_HOME 'hub' }
    $roots += Join-Path $HOME '.cache\huggingface\hub'
    @($roots | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique)
}

# Finds a verified copy of the model: ~\llama-cpp-tiny\models first, then Lemonade's HF/ModelScope
# cache (used in place). Only reads files. Returns @{ Path; Source } or $null.
function Find-ModelCopy([string]$Repo, [string]$FileName, [string]$Sha256, [double]$Size) {
    $own = Join-Path $ModelsDir $FileName
    if (Test-FileSha256 $own $Sha256 $Size) { return [pscustomobject]@{ Path = $own; Source = 'own' } }
    $cacheName = 'models--' + $Repo.Replace('/', '--')
    foreach ($cacheRoot in Get-HfCacheRoots) {
        $dirs = @(Get-ChildItem -LiteralPath $cacheRoot -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $cacheName -or $_.Name -like "*--$cacheName" })
        foreach ($dir in $dirs) {
            $snapshots = @(Get-ChildItem -LiteralPath (Join-Path $dir.FullName 'snapshots') -Directory -ErrorAction SilentlyContinue)
            foreach ($snapshot in $snapshots) {
                $copy = Join-Path $snapshot.FullName $FileName
                if (Test-FileSha256 $copy $Sha256 $Size) { return [pscustomobject]@{ Path = $copy; Source = 'cache' } }
            }
        }
    }
    $null
}

# Resolves the model file and any verified local copy. When Hugging Face is unreachable, reuses the
# model recorded in server.json if it still verifies against its sidecar.
function Resolve-Model([string]$Checkpoint, $Saved) {
    $repo, $variant = $Checkpoint.Split(':')
    try {
        $items = Invoke-Json "https://huggingface.co/api/models/$repo/tree/main"
    } catch {
        if ($Saved -and $Saved.model -and $Saved.modelSha256 -and (Test-FileSha256 $Saved.model $Saved.modelSha256 0)) {
            Write-Warning "Cannot reach Hugging Face ($_); keeping $($Saved.model)."
            $item = Get-Item -LiteralPath $Saved.model
            return [pscustomobject]@{ FileName = $item.Name; Size = [double]$item.Length; Sha256 = $Saved.modelSha256; Url = $null; Copy = [pscustomobject]@{ Path = $Saved.model; Source = 'saved' } }
        }
        Stop-Setup "Cannot read the Hugging Face file list for ${repo}: $_" @('Check the network (huggingface.co), then re-run.')
    }
    $file = Get-HfModelFile $items $variant
    Write-Host "  Checking for an existing copy of $($file.Path) (hashing may take a few seconds)..."
    [pscustomobject]@{
        FileName = $file.Path
        Size     = $file.Size
        Sha256   = $file.Sha256
        Url      = "https://huggingface.co/$repo/resolve/main/$($file.Path)"
        Copy     = Find-ModelCopy $repo $file.Path $file.Sha256 $file.Size
    }
}

# Downloads the model into models\, verifies it and writes the sidecar; returns the path.
function Install-Model($Model) {
    New-Item -ItemType Directory -Path $ModelsDir -Force | Out-Null
    $target = Join-Path $ModelsDir $Model.FileName
    Write-Step "Downloading $($Model.FileName) ($(Format-Bytes $Model.Size))"
    Invoke-Download $Model.Url $target
    $hash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -ne $Model.Sha256) {
        Remove-Item -LiteralPath $target -Force
        Stop-Setup "SHA-256 mismatch for $($Model.FileName) (expected $($Model.Sha256), got $hash); the file was deleted." @('Re-run to download it again.')
    }
    [IO.File]::WriteAllText("$target.sha256", (Get-SidecarLine $target $Model.Sha256))
    Write-Host '  SHA-256 verified.' -ForegroundColor Green
    $target
}

# ---------------------------------------------------------------------------------------------
# Ports and server process
# ---------------------------------------------------------------------------------------------

# Returns $true when a loopback listener can bind $Port and nothing listens on it (any address).
# The bind test also catches Hyper-V/WinNAT excluded port ranges.
function Test-PortFree([int]$Port) {
    if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) { return $false }
    $listener = New-Object Net.Sockets.TcpListener ([Net.IPAddress]::Loopback, $Port)
    try { $listener.Start(); $true } catch { $false } finally { $listener.Stop() }
}

# Returns the process listening on $Port as @{ Id; Name; Path }, or $null.
function Get-PortOwner([int]$Port) {
    $connection = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $connection) { return $null }
    $process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
    $path = if ($process) { try { $process.Path } catch { $null } } else { $null }
    [pscustomobject]@{ Id = [int]$connection.OwningProcess; Name = if ($process) { $process.ProcessName } else { '?' }; Path = $path }
}

# Describes the owner of a port for messages ("name pid N").
function Format-PortOwner($Owner) {
    if ($Owner) { "$($Owner.Name) pid $($Owner.Id)" } else { 'an unknown process (or a reserved port range)' }
}

# Returns $true when $Process runs an executable under ~\llama-cpp-tiny\bin (any build).
function Test-OurProcess($Process) {
    $path = if ($Process) { [string]$Process.Path } else { '' }
    [bool]($path -and $path.StartsWith($BinRoot + '\', [StringComparison]::OrdinalIgnoreCase))
}

# Returns $true when the listener on $Port is our llama-server (an executable under bin\, any
# build or alias; such a server is restarted rather than avoided).
function Test-OurServer([int]$Port) {
    $owner = Get-PortOwner $Port
    (Test-OurProcess $owner) -or ($owner -and (Test-ServiceChild $owner.Id))
}

# Returns the llama-cpp-tiny service (Win32_Service: State, ProcessId, StartName), or $null.
function Get-JudgeService {
    Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
}

# Returns $true when $ProcessId runs under the running service (shawl -> powershell -> llama-server).
function Test-ServiceChild([int]$ProcessId) {
    $service = Get-JudgeService
    if (-not $service -or -not $service.ProcessId) { return $false }
    $current = $ProcessId
    for ($depth = 0; $depth -lt 4 -and $current; $depth++) {
        $process = Get-CimInstance Win32_Process -Filter "ProcessId=$current" -ErrorAction SilentlyContinue
        if (-not $process) { return $false }
        if ([int]$process.ParentProcessId -eq [int]$service.ProcessId) { return $true }
        $current = [int]$process.ParentProcessId
    }
    $false
}

# Waits until the service reaches $Status (Running/Stopped); returns $true on success.
function Wait-ServiceStatus([string]$Status, [int]$TimeoutSec = 30) {
    try {
        (Get-Service -Name $ServiceName).WaitForStatus($Status, [TimeSpan]::FromSeconds($TimeoutSec))
        $true
    } catch { $false }
}

# Picks the port: saved, then preferred, then preferred+1..+49; the first that is ours or free wins.
# An explicit port is the only candidate. Returns @{ Port; Ours; Skipped (port/owner list) }.
function Resolve-ServerPort([int]$SavedPort, [int]$PreferredPort, [bool]$Explicit) {
    $last = [Math]::Min(65535, $PreferredPort + $PortRangeSize)
    $candidates = if ($Explicit) { @($PreferredPort) } else { @(@($SavedPort, $PreferredPort) + ($PreferredPort + 1)..$last | Where-Object { $_ -gt 0 } | Select-Object -Unique) }
    $skipped = @()
    foreach ($candidate in $candidates) {
        if (Test-OurServer $candidate) { return [pscustomobject]@{ Port = $candidate; Ours = $true; Skipped = $skipped } }
        if (Test-PortFree $candidate) { return [pscustomobject]@{ Port = $candidate; Ours = $false; Skipped = $skipped } }
        $owner = Get-PortOwner $candidate
        if ($Explicit) { Stop-Setup "Port $candidate is held by $(Format-PortOwner $owner)." @('Free it, or pass another -Port (or omit -Port to pick a free one).') }
        $skipped += [pscustomobject]@{ Port = $candidate; Owner = $owner }
    }
    Stop-Setup "No free port in $PreferredPort-$last." @('Pass -Port <free port>.')
}

# Formats the chosen port for reports, e.g. "9943 (9941 held by foo pid 12)".
function Format-PortChoice($Choice) {
    $notes = @($Choice.Skipped | ForEach-Object { "$($_.Port) held by $(Format-PortOwner $_.Owner)" })
    if ($notes.Count) { "$($Choice.Port) ($($notes -join '; '))" } else { [string]$Choice.Port }
}

# Returns the HTTP status of GET /health on $Port (200 ready, 503 loading), or 0 when unreachable.
function Get-HealthStatus([int]$Port) {
    try {
        (Invoke-WebRequest -Uri "http://127.0.0.1:$Port/health" -UseBasicParsing -TimeoutSec 2).StatusCode
    } catch {
        if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
    }
}

# Returns the llama-server argument list for a server config.
function Get-ServerArguments($Config) {
    $arguments = @(
        '--host', '127.0.0.1', '--port', [string]$Config.port,
        '-m', [string]$Config.model,
        '-c', [string]$Config.ctx,
        '-ngl', [string]$Config.ngl,
        '--alias', [string]$Config.alias,
        '--parallel', '1',  # one slot gets the whole context
        '--no-webui',
        '--chat-template-kwargs', '{"enable_thinking":false}',
        '--log-file', [string]$Config.log
    )
    if ([int]$Config.idleSleepSeconds -gt 0) { $arguments += '--sleep-idle-seconds', [string]$Config.idleSleepSeconds }
    $arguments
}

# Returns the llama-server.exe path of a build dir name.
function Get-ServerExe([string]$BuildDir) {
    Join-Path $BinRoot "$BuildDir\llama-server.exe"
}

# Reads server.json ($null when absent).
function Read-ServerConfig {
    if (-not (Test-Path -LiteralPath $ServerConfigPath)) { return $null }
    [IO.File]::ReadAllText($ServerConfigPath) | ConvertFrom-Json
}

# Writes server.json.
function Write-ServerConfig($Config) {
    New-Item -ItemType Directory -Path $Root -Force | Out-Null
    [IO.File]::WriteAllText($ServerConfigPath, (ConvertTo-Json -InputObject $Config -Depth 5), (New-Object Text.UTF8Encoding $false))
}

# Rewrites baseUrl inside the managed models.yml block (backup first). Returns $false when the
# block is absent (the file is then left alone).
function Update-ManagedBaseUrl([string]$Path, [string]$BaseUrl, [switch]$NoBackup) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $false }
    $text = [IO.File]::ReadAllText($Path)
    $newline = if ($text.Contains("`r`n")) { "`r`n" } else { "`n" }
    $lines = [string[]]($text -split "`r?`n")
    $start = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($start -lt 0 -and $lines[$i] -match ('^\s*' + [regex]::Escape($MarkerStart))) { $start = $i; continue }
        if ($start -ge 0 -and $lines[$i] -match ('^\s*' + [regex]::Escape($MarkerEnd))) {
            for ($j = $start + 1; $j -lt $i; $j++) {
                if ($lines[$j] -match '^(\s*baseUrl:\s*).*$') {
                    if (-not $NoBackup) { Backup-File $Path | Out-Null }
                    $lines[$j] = "$($Matches[1])'$BaseUrl'"
                    [IO.File]::WriteAllText($Path, ($lines -join $newline), (New-Object Text.UTF8Encoding $false))
                    return $true
                }
            }
            return $false
        }
    }
    $false
}

# Moves the server to $NewPort: updates server.json and, unless -SkipOmp, the models.yml baseUrl.
function Move-ServerPort($Config, [int]$NewPort, [string]$Reason, [switch]$SkipOmp) {
    Write-Warning "Moving llama-server from port $($Config.port) to $NewPort ($Reason)."
    $Config.port = $NewPort
    Write-ServerConfig $Config
    if ($SkipOmp) { return }
    if (Update-ManagedBaseUrl $Config.modelsPath "http://127.0.0.1:$NewPort/v1") {
        Write-Host "  Updated baseUrl in $($Config.modelsPath)." -ForegroundColor Green
    } else {
        Write-Warning "No managed omp-llamacpp-judge block in '$($Config.modelsPath)'; omp was not updated. Re-run setup to repair it."
    }
}

# Returns the last $Count lines of the server logs.
function Get-LogTail($Config, [int]$Count = 30) {
    $lines = @()
    foreach ($log in @($Config.log)) {
        if ($log -and (Test-Path -LiteralPath $log)) { $lines += @(Get-Content -LiteralPath $log -Tail $Count) }
    }
    $lines | Select-Object -Last $Count
}

# Starts llama-server for $Config unless it already runs. Moves to a free port when the port is taken
# (not for explicit ports), retrying after bind races. Throws on failure. -InSetup skips models.yml
# edits (setup writes the block itself after the test).
function Start-JudgeServer($Config, [switch]$InSetup) {
    $exe = Get-ServerExe $Config.current
    if (-not (Test-Path -LiteralPath $exe)) { throw "llama-server not found at $exe. Re-run setup." }
    if (-not (Test-Path -LiteralPath $Config.model)) { throw "Model file not found at $($Config.model). Re-run setup." }
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $port = [int]$Config.port
        if (Test-OurServer $port) {
            Write-Host "  llama-server is already running on port $port." -ForegroundColor Green
            return
        }
        if (-not (Test-PortFree $port)) {
            $owner = Get-PortOwner $port
            if ($Config.portExplicit) { throw "Port $port is held by $(Format-PortOwner $owner). Free it or re-run setup with another -Port." }
            $choice = Resolve-ServerPort 0 ([int]$Config.preferredPort) $false
            Move-ServerPort $Config $choice.Port "port $port held by $(Format-PortOwner $owner)" -SkipOmp:$InSetup
            if ($choice.Ours) { return }
            $port = [int]$Config.port
        }

        if (Get-JudgeService) {
            # Service mode: the service command (-Run) reads server.json, so just (re)start it.
            try { Start-Service -Name $ServiceName } catch { throw "Cannot start service '$ServiceName': $($_.Exception.Message) Re-run -InstallService elevated to grant start/stop rights." }
            $deadline = (Get-Date).AddSeconds(120)
            while ((Get-Date) -lt $deadline) {
                if ((Get-HealthStatus $port) -eq 200) {
                    Write-Host "  llama-server ready on 127.0.0.1:$port (service '$ServiceName')." -ForegroundColor Green
                    return
                }
                if ((Get-Service -Name $ServiceName).Status -eq 'Stopped') { break }
                Start-Sleep -Milliseconds 500
            }
            throw "Service '$ServiceName' did not serve /health on port $port within 120 s. Log tail:`n$((Get-LogTail $Config) -join "`n")"
        }

        $commandLine = (Get-ServerArguments $Config | ForEach-Object { ConvertTo-CommandLineArgument $_ }) -join ' '
        # No stream redirection: that would make the server inherit the caller's stdout/stderr handles
        # and keep a capturing caller waiting until the server exits. Logs go to --log-file instead.
        $process = Start-Process -FilePath $exe -ArgumentList $commandLine -WorkingDirectory (Split-Path $exe) -WindowStyle Hidden -PassThru
        [IO.File]::WriteAllText($Config.pidFile, [string]$process.Id)

        $deadline = (Get-Date).AddSeconds(120)
        while ((Get-Date) -lt $deadline) {
            if ($process.HasExited) { break }
            if ((Get-HealthStatus $port) -eq 200) {
                Write-Host "  llama-server ready on 127.0.0.1:$port (pid $($process.Id))." -ForegroundColor Green
                return
            }
            Start-Sleep -Milliseconds 500
        }
        $tail = (Get-LogTail $Config) -join "`n"
        if (-not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            throw "llama-server did not become healthy within 120 s. Log tail:`n$tail"
        }
        Remove-Item -LiteralPath $Config.pidFile -Force -ErrorAction SilentlyContinue
        # Another process may have taken the port between the probe and the bind: try the next one.
        if ($tail -match 'bind' -and -not $Config.portExplicit -and $attempt -lt 3) {
            $choice = Resolve-ServerPort 0 ([int]$Config.preferredPort) $false
            Move-ServerPort $Config $choice.Port "bind on port $port failed" -SkipOmp:$InSetup
            continue
        }
        throw "llama-server exited with code $($process.ExitCode). Log tail:`n$tail"
    }
}

# Stops our llama-server (pid file, else the listener on the configured port). Returns $true if one stopped.
function Stop-JudgeServer($Config) {
    $service = Get-JudgeService
    if ($service) {
        if ($service.State -eq 'Stopped') { return $false }
        try { Stop-Service -Name $ServiceName -Force } catch { throw "Cannot stop service '$ServiceName': $($_.Exception.Message) Re-run -InstallService elevated to grant start/stop rights." }
        Wait-ServiceStatus 'Stopped' | Out-Null
        return $true
    }
    $process = $null
    if ($Config.pidFile -and (Test-Path -LiteralPath $Config.pidFile)) {
        $process = Get-Process -Id ([int][IO.File]::ReadAllText($Config.pidFile).Trim()) -ErrorAction SilentlyContinue
        if ($process -and -not (Test-OurProcess $process)) { $process = $null }  # pid reused by another program
    }
    if (-not $process) {
        $owner = Get-PortOwner ([int]$Config.port)
        if (Test-OurProcess $owner) { $process = Get-Process -Id $owner.Id -ErrorAction SilentlyContinue }
    }
    if ($Config.pidFile) { Remove-Item -LiteralPath $Config.pidFile -Force -ErrorAction SilentlyContinue }
    if (-not $process) { return $false }
    Stop-Process -Id $process.Id -Force
    $process.WaitForExit(10000) | Out-Null
    $true
}

# Returns the earliest whole-word label in $Text (longer label wins a tie), mirroring omp's
# parseChoiceReply; $null when no label appears.
function Get-FirstLabel([string]$Text, [string[]]$Labels) {
    $best = $null
    $bestAt = [int]::MaxValue
    foreach ($label in $Labels) {
        $match = [regex]::Match($Text, '(?i)(?<![\p{L}\p{N}_])' + [regex]::Escape($label) + '(?![\p{L}\p{N}_])')
        if (-not $match.Success) { continue }
        if ($match.Index -lt $bestAt -or ($match.Index -eq $bestAt -and $label.Length -gt $best.Length)) { $best = $label; $bestAt = $match.Index }
    }
    $best
}

# Sends the judge test prompt and returns the answer with timings; throws on HTTP errors.
function Invoke-TestPrompt([int]$Port, [string]$Model) {
    $body = @{
        model                = $Model
        stream               = $false
        temperature          = 0.1
        max_tokens           = 16
        chat_template_kwargs = @{ enable_thinking = $false }
        messages             = @(
            @{ role = 'system'; content = $TestSystemPrompt },
            @{ role = 'user'; content = $TestUserPrompt }
        )
    }
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $response = Invoke-Json "http://127.0.0.1:$Port/v1/chat/completions" -Method POST -Body $body -TimeoutSec 300
    $timer.Stop()
    [pscustomobject]@{
        Answer          = ([string]$response.choices[0].message.content).Trim()
        Seconds         = [math]::Round($timer.Elapsed.TotalSeconds, 2)
        Build           = [string]$response.system_fingerprint
        TokensPerSecond = if ($response.timings) { [math]::Round([double]$response.timings.predicted_per_second, 1) } else { $null }
    }
}

# ---------------------------------------------------------------------------------------------
# Logon task
# ---------------------------------------------------------------------------------------------

# Returns the logon task, or $null.
function Get-AutoStartTask {
    Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
}

# Registers (or replaces) the per-user logon task that runs this script with -Start.
function Register-AutoStartTask([string]$ScriptPath) {
    $user = "$env:USERDOMAIN\$env:USERNAME"
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File $(ConvertTo-CommandLineArgument $ScriptPath) -Start"
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
    # No 72 h execution limit; keep running on battery.
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
        -Description 'Starts the local llama.cpp server (~\llama-cpp-tiny) used as the omp judge model.' -Force | Out-Null
}

# ---------------------------------------------------------------------------------------------
# omp state and models.yml editing (from Set-OmpJudgeLocalLemonade.ps1)
# ---------------------------------------------------------------------------------------------

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

    $plan = [pscustomobject]@{ Path = $Path; Lines = $lines; NewLine = $newline; Mode = 'append'; Start = -1; End = -1; Indent = '  '; OldProviderId = $null }
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
        # The first mapping key inside the block is the provider id it declares.
        for ($i = $plan.Start + 1; $i -lt $plan.End; $i++) {
            if ($lines[$i] -match '^\s*["'']?([^"''\s:#]+)["'']?\s*:') { $plan.OldProviderId = $Matches[1]; break }
        }
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
function Format-ProviderBlock([string]$Indent, [string]$BaseUrl, [string]$Model, [int]$Context) {
    $block = @(
        "$MarkerStart (managed by Set-OmpJudgeLocalLlamaCpp.ps1; re-run to update, delete through the end marker to remove)",
        "${ProviderId}:",
        "  baseUrl: '$BaseUrl'",
        '  api: openai-completions',
        '  auth: none',
        '  models:',
        "    - id: '$Model'",
        "      name: '$Model (llama.cpp)'",
        '      kind: tiny # small-model kind: selectable for judge/tiny/memory, kept out of chat model cycling',
        '      reasoning: false',
        '      input: [text]',
        "      contextWindow: $Context",
        '      maxTokens: 2048',
        '      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }',
        '      compat:',
        '        extraBody:',
        '          chat_template_kwargs: { enable_thinking: false } # also forced server-side',
        $MarkerEnd
    )
    $block | ForEach-Object { "$Indent$_" }
}

# Applies the managed provider block according to the plan from Read-ModelsYaml and saves the file.
function Write-ModelsYaml($Plan, [string]$BaseUrl, [string]$Model, [int]$Context) {
    $lines = $Plan.Lines
    switch ($Plan.Mode) {
        'replace' {
            $lines.RemoveRange($Plan.Start, $Plan.End - $Plan.Start + 1)
            $lines.InsertRange($Plan.Start, [string[]](Format-ProviderBlock $Plan.Indent $BaseUrl $Model $Context))
        }
        'insert' {
            $lines.InsertRange($Plan.Start, [string[]](Format-ProviderBlock $Plan.Indent $BaseUrl $Model $Context))
        }
        'append' {
            if ($lines.Count -gt 0 -and $lines[$lines.Count - 1].Trim() -ne '') { $lines.Add('') }
            $lines.Add('providers:')
            $lines.AddRange([string[]](Format-ProviderBlock '  ' $BaseUrl $Model $Context))
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
# Selectors of $DropProvider (a provider id this run renamed away) are removed, not kept as
# fallbacks, because that provider no longer exists.
# Only the global config layer is read and written so project/env values are not copied into it.
function Set-OmpJudge([string]$Selector, [string]$DropProvider) {
    $global = (Invoke-Omp @('config', 'list', '--scope', 'global', '--json')).StdOut | ConvertFrom-Json
    $roles = ConvertTo-OrderedMap $(if ($global.modelRoles) { $global.modelRoles.value })
    $chains = ConvertTo-OrderedMap $(if ($global.'retry.fallbackChains') { $global.'retry.fallbackChains'.value })

    $previous = [string]$roles['judge']
    $dropped = if ($DropProvider) { "$DropProvider/*" } else { $null }
    if ($dropped -and $previous -like $dropped) { $previous = '' }
    if ([string]$roles['judge'] -ne $Selector) {
        $roles['judge'] = $Selector
        Set-OmpRecordSetting 'modelRoles' $roles
    }

    $hadChain = $chains.Contains('judge')
    $oldChain = if ($hadChain) { @($chains['judge']) } else { @() }
    $newChain = @(@($previous) + $oldChain | Where-Object { $_ -and $_ -ne $Selector -and -not ($dropped -and $_ -like $dropped) } | Select-Object -Unique)
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

# Resolves omp's agent dir and the models.yml/config.yml paths (preferring existing .yaml files).
function Initialize-OmpPaths {
    $script:OmpVersion = (Invoke-Omp @('--version')).StdOut.Trim()
    $script:AgentDir = (Invoke-Omp @('config', 'path')).StdOut.Trim()
    if (-not (Test-Path -LiteralPath $script:AgentDir)) { Stop-Setup "omp agent directory '$script:AgentDir' does not exist. Run omp once to initialize it." }
    $yamlFile = Join-Path $script:AgentDir 'models.yaml'
    $script:ModelsPath = if ((Test-Path -LiteralPath $yamlFile) -and -not (Test-Path -LiteralPath (Join-Path $script:AgentDir 'models.yml'))) { $yamlFile } else { Join-Path $script:AgentDir 'models.yml' }
    $configYaml = Join-Path $script:AgentDir 'config.yaml'
    $script:ConfigPath = if ((Test-Path -LiteralPath $configYaml) -and -not (Test-Path -LiteralPath (Join-Path $script:AgentDir 'config.yml'))) { $configYaml } else { Join-Path $script:AgentDir 'config.yml' }
}

# ---------------------------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------------------------

# Collects the llama.cpp side of the report from server.json and the live system.
function Get-LlamaState($Config) {
    $exe = if ($Config -and $Config.current) { Get-ServerExe $Config.current } else { $null }
    $port = if ($Config) { [int]$Config.port } else { 0 }
    [pscustomobject]@{
        Root    = $Root
        Build   = if ($exe) { Get-LlamaVersion $exe } else { $null }
        Dir     = if ($Config) { [string]$Config.current } else { $null }
        Model   = if ($Config) { [string]$Config.model } else { $null }
        Port    = $port
        Health  = if ($port) { Get-HealthStatus $port } else { 0 }
        Task    = [bool](Get-AutoStartTask)
    }
}

# Prints the llama.cpp and omp state (plus the test prompt result when available).
function Show-Report([string]$Title, $Llama, $Omp, $Test = $null) {
    Write-Section $Title
    Write-Host '  llama.cpp' -ForegroundColor DarkCyan
    Write-Row 'Root' (Format-HomePath $Llama.Root) (Test-Path -LiteralPath $Llama.Root)
    Write-Row 'Installed build' $(if ($Llama.Build) { "$($Llama.Build) [$($Llama.Dir)]" } else { '(none)' }) ([bool]$Llama.Build)
    $modelOk = $Llama.Model -and (Test-Path -LiteralPath $Llama.Model)
    Write-Row 'Model' $(if ($Llama.Model) { Format-HomePath $Llama.Model } else { '(none)' }) ([bool]$modelOk)
    $health = switch ($Llama.Health) { 200 { 'running' } 503 { 'loading' } default { 'not running' } }
    Write-Row 'Server' $(if ($Llama.Port) { "127.0.0.1:$($Llama.Port) $health" } else { '(not configured)' }) ($Llama.Health -eq 200)
    Write-Row "Logon task '$TaskName'" $(if ($Llama.Task) { 'registered' } else { 'not registered' })
    if ($Test) {
        # omp's TextJudge takes the earliest label in the reply, so a stray tail does not matter.
        $label = Get-FirstLabel $Test.Answer @('low', 'medium', 'high')
        Write-Row 'Test prompt answer' "'$($Test.Answer)' -> omp reads: $(if ($label) { $label } else { '(no label)' })" ([bool]$label)
        Write-Row 'Test prompt time' "$($Test.Seconds) s total, $($Test.TokensPerSecond) tok/s, build $($Test.Build)"
    }

    Write-Host '  omp' -ForegroundColor DarkCyan
    Write-Row 'Version / agent dir' "$script:OmpVersion / $script:AgentDir"
    Write-Row "models.yml '$ProviderId' provider" $Omp.Provider ($Omp.Provider -eq 'managed block present')
    $listed = if ($Omp.Listed.Count) { $Omp.Listed -join ', ' } elseif ($Omp.ListError) { "error: $($Omp.ListError)" } else { '(none)' }
    Write-Row "omp models '$ProviderId'" $listed ([bool]$Omp.Listed.Count)
    Write-Row 'modelRoles.judge' $(if ($Omp.Judge) { $Omp.Judge } else { '(unset: built-in chain)' }) ($Omp.Judge -like "$ProviderId/*")
    Write-Row 'retry.fallbackChains.judge' (Format-Chain $Omp.Chains)
    Write-Row 'defaultThinkingLevel' $Omp.Thinking ($Omp.Thinking -eq 'auto')
}

# Prints the environment and planned-changes sections shown before the confirmation prompt.
function Show-Plan($Resources, $Plan) {
    Write-Section 'Environment'
    Write-Row 'OS / arch' "$($Resources.Os) / $($Resources.Arch)"
    Write-Row 'CPU' "$($Resources.Cpu) ($($Resources.Cores) cores, $($Resources.Threads) threads)"
    Write-Row 'RAM' "$(Format-Bytes $Resources.RamTotal) total, $(Format-Bytes $Resources.RamAvailable) available"
    if ($Resources.Gpus.Count -eq 0) { Write-Row 'GPU (driver)' '(none reported)' }
    foreach ($gpu in $Resources.Gpus) { Write-Row 'GPU (driver)' "$($gpu.Name) ($($gpu.Driver))" }
    Write-Row "Disk $($Resources.DriveRoot) (holds ~\llama-cpp-tiny)" "$(Format-Bytes $Resources.DiskFree) free of $(Format-Bytes $Resources.DiskTotal)"
    if ($Resources.RootSize -gt 0) { Write-Row '~\llama-cpp-tiny uses' (Format-Bytes $Resources.RootSize) }

    Write-Section 'Planned changes'
    $asset = $Plan.Asset
    if ($Plan.BuildPresent) {
        Write-Row 'llama.cpp' "$($asset.Tag) $($Plan.Flavor)-$($Plan.Arch) already installed"
    } else {
        Write-Row 'Download llama.cpp' "$($asset.Tag) $($Plan.Flavor)-$($Plan.Arch) zip, $(Format-Bytes $asset.Size) (sha256 verified)"
        Write-Row 'Install to' "$(Format-HomePath (Join-Path $BinRoot $Plan.BuildDir)) (~$(Format-Bytes $Plan.Requirement.ExtractedSize))"
    }
    $model = $Plan.Model
    if ($model.Copy) {
        Write-Row 'Model' "$($model.FileName), reuse $(Format-HomePath $model.Copy.Path) (no download)"
    } else {
        Write-Row 'Model' "$($model.FileName), download $(Format-Bytes $model.Size) to $(Format-HomePath $ModelsDir)"
    }
    if ($Plan.Requirement.DiskNeeded -gt 0) {
        Write-Row 'Disk needed / free after' "$(Format-Bytes $Plan.Requirement.DiskNeeded) / $(Format-Bytes ($Resources.DiskFree - $Plan.Requirement.DiskNeeded))"
    }
    Write-Row 'Server RAM (estimate)' "~$(Format-Bytes $Plan.Requirement.RamEstimate) at ctx $($Plan.Context)"
    $idle = if ($IdleSleepSeconds -gt 0) { "idle-unload after $IdleSleepSeconds s" } else { 'no idle unload' }
    Write-Row 'Server' "127.0.0.1:$(Format-PortChoice $Plan.PortChoice), started now, $idle"
    Write-Row 'omp' "models.yml block '$ProviderId', judge -> $ProviderId/$ModelId"
    if (Get-JudgeService) {
        Write-Row 'Service' "'$ServiceName' restarted with these settings"
    } else {
        $task = if ($AutoStart) { "register '$TaskName'" } elseif (Get-AutoStartTask) { "'$TaskName' already registered (kept)" } else { 'not registered (use -AutoStart)' }
        Write-Row 'Logon task' $task
    }
    foreach ($dir in $Plan.Prune) { Write-Row 'Remove after success' "$(Format-HomePath $dir) (old build)" }
}

# ---------------------------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------------------------

# Starts the server, then sends the test prompt; returns the test result or throws.
function Invoke-StartAndTest($Config) {
    Start-JudgeServer $Config -InSetup
    Write-Step "Test prompt ($($Config.alias) on port $($Config.port))"
    $test = Invoke-TestPrompt ([int]$Config.port) $Config.alias
    if (-not $test.Answer) { throw 'The test prompt returned an empty answer.' }
    Write-Host "  answer: '$($test.Answer)' in $($test.Seconds) s" -ForegroundColor Green
    $test
}

# Runs the setup: read-only resolution, confirmation, install, test, omp configuration, report.
function Invoke-Setup {
    Write-Section 'Preflight'
    if (-not (Get-Command 'omp' -ErrorAction SilentlyContinue)) {
        Stop-Setup "'omp' is not on PATH." @('Install oh-my-pi (omp), open a new terminal, and re-run.')
    }
    if (-not (Test-Path -LiteralPath $CurlExe)) { Stop-Setup "$CurlExe not found (it ships with Windows 10 1803+)." }
    Initialize-OmpPaths
    Write-Host '  omp and curl.exe found.' -ForegroundColor Green

    $saved = Read-ServerConfig
    $omp = Get-OmpState
    Show-Report 'Initial state' (Get-LlamaState $saved) $omp
    if ($omp.Plan.Mode -eq 'conflict') {
        Stop-Setup "$script:ModelsPath already defines a '$ProviderId' provider that this script does not manage. Nothing was changed." @(
            'Remove that provider, or re-run with -ProviderId <other-id>.')
    }
    if ($omp.Plan.Mode -eq 'flow') {
        Stop-Setup "$script:ModelsPath writes 'providers:' in flow style ({...}). Nothing was changed." @(
            'Rewrite it as an indented (block-style) mapping, then re-run.')
    }

    # Steps 3-5: read-only resolution.
    Write-Step 'Resolving llama.cpp release, model and port (read-only)'
    $resources = Get-EnvironmentResources
    $context = if ($ContextWindow -eq 'auto') { Get-ContextTier $resources.RamTotal } else { [int]$ContextWindow }
    if ($context -lt 2048 -or $context -gt 262144) { Stop-Setup "-ContextWindow must be 'auto' or 2048-262144 (got $ContextWindow)." }
    $flavor = if ($Backend -eq 'cpu') { 'cpu' } else { 'vulkan' }
    $arch = $resources.Arch
    $asset = Resolve-LlamaRelease $Build $flavor $arch $saved
    $buildDir = "$($asset.Tag)-$flavor-$arch"
    $buildPresent = Test-BuildInstalled (Join-Path $BinRoot $buildDir) $asset.Build
    if (-not $buildPresent -and $asset.Offline) { Stop-Setup "Build $buildDir is not installed and GitHub is unreachable." }
    $model = Resolve-Model $Checkpoint $saved
    $savedPort = if ($saved) { [int]$saved.port } else { 0 }
    $explicitPort = $ExplicitPort
    $portChoice = Resolve-ServerPort $(if ($explicitPort) { 0 } else { $savedPort }) $Port $explicitPort

    $previousDir = if ($saved -and $saved.current -and $saved.current -ne $buildDir) { [string]$saved.current } elseif ($saved) { [string]$saved.previous } else { '' }
    $previousExe = if ($previousDir) { Get-ServerExe $previousDir } else { $null }
    if (-not $previousExe -or -not (Test-Path -LiteralPath $previousExe)) { $previousDir = '' }
    $prune = Get-PrunableBuilds @($buildDir, $previousDir)
    $zipSize = if ($buildPresent) { 0 } else { $asset.Size }
    $modelDownload = if ($model.Copy) { 0 } else { $model.Size }
    $requirement = Get-InstallRequirement $zipSize $modelDownload $model.Size $context
    $plan = [pscustomobject]@{
        Asset = $asset; Flavor = $flavor; Arch = $arch; BuildDir = $buildDir; BuildPresent = $buildPresent
        Model = $model; Context = $context; PortChoice = $portChoice; Requirement = $requirement; Prune = $prune
    }
    Show-Plan $resources $plan

    # Step 6: confirmation gate.
    $warnings = @(Get-InstallWarnings $resources $requirement)
    $proceed = Confirm-Install $warnings ($buildPresent -and [bool]$model.Copy) $Yes.IsPresent (Test-CanPrompt) `
        $requirement.DiskNeeded $resources.DiskFree $resources.DriveRoot
    if (-not $proceed) {
        Write-Host ''
        Write-Host 'Cancelled. Nothing was changed.' -ForegroundColor Yellow
        return
    }

    # Steps 7-9: install llama.cpp, probe devices, install the model.
    $buildPath = Join-Path $BinRoot $buildDir
    $installedNew = -not $buildPresent
    if ($installedNew) { Install-LlamaRelease $asset $buildPath }
    $exe = Get-ServerExe $buildDir
    $listing = Invoke-Cli $exe @('--list-devices')
    $probe = Get-VulkanDevices "$($listing.StdOut)`n$($listing.StdErr)".Split("`n")
    $ngl = Select-GpuLayers $Backend $probe
    $device = if ($ngl -eq 'all') { $probe.Real -join ', ' } elseif ($ngl -eq '0') { 'CPU' } else { 'auto' }
    Write-Host "  Device: $device (-ngl $ngl)" -ForegroundColor Green
    if ($probe.Software.Count) { Write-Host "  Ignored software devices: $($probe.Software -join ', ')" -ForegroundColor DarkGray }
    $modelPath = if ($model.Copy) {
        if ($model.Copy.Source -eq 'own' -and -not (Test-Path -LiteralPath "$($model.Copy.Path).sha256")) {
            [IO.File]::WriteAllText("$($model.Copy.Path).sha256", (Get-SidecarLine $model.Copy.Path $model.Sha256))
        }
        $model.Copy.Path
    } else { Install-Model $model }

    # Step 10: server.json.
    # Settings may change, so restart: stop the saved server and any of ours on the chosen port.
    if ($saved) { Stop-JudgeServer $saved | Out-Null }
    if ($portChoice.Ours) { Stop-JudgeServer ([pscustomobject]@{ pidFile = $null; port = $portChoice.Port }) | Out-Null }
    $config = [pscustomobject][ordered]@{
        schema           = 1
        current          = $buildDir
        previous         = $previousDir
        model            = $modelPath
        modelSha256      = $model.Sha256
        alias            = $ModelId
        ctx              = $context
        ngl              = $ngl
        port             = $portChoice.Port
        preferredPort    = $Port
        portExplicit     = $explicitPort
        idleSleepSeconds = $IdleSleepSeconds
        providerId       = $ProviderId
        modelsPath       = $script:ModelsPath
        log              = Join-Path $Root 'server.log'
        pidFile          = Join-Path $Root 'server.pid'
    }
    Write-ServerConfig $config

    # Step 11: start and test, rolling back to the previous build when a new build fails.
    Write-Step "Starting llama-server ($buildDir)"
    $badBuild = $null
    try {
        $test = Invoke-StartAndTest $config
    } catch {
        if ("$_" -eq $AbortToken) { throw }
        $failure = "$_"
        Stop-JudgeServer $config | Out-Null
        if (-not ($installedNew -and $previousDir)) {
            Stop-Setup "llama-server failed: $failure. omp was not changed." @("Logs: $($config.log)")
        }
        Write-Warning "Build $buildDir failed ($failure); rolling back to $previousDir."
        $badBuild = $buildDir
        $config.current = $previousDir
        $config.previous = ''
        Write-ServerConfig $config
        try {
            $test = Invoke-StartAndTest $config
        } catch {
            if ("$_" -eq $AbortToken) { throw }
            Stop-JudgeServer $config | Out-Null
            Stop-Setup "The previous build $previousDir failed too: $_. omp was not changed." @("Logs: $($config.log)")
        }
    }
    foreach ($dir in Get-PrunableBuilds @($config.current, $config.previous, $badBuild)) {
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  Removed old build $(Format-HomePath $dir)" -ForegroundColor DarkGray
    }

    # Step 12: omp provider and judge role (backups first; models.yml is restored if omp rejects it).
    $selector = "$ProviderId/$ModelId"
    $baseUrl = "http://127.0.0.1:$($config.port)/v1"
    Write-Step "Configuring omp: provider '$ProviderId' in models.yml ($baseUrl), modelRoles.judge = $selector"
    $script:Backups = @(@(Backup-File $script:ModelsPath; Backup-File $script:ConfigPath) | Where-Object { $_ })
    $modelsBackup = $script:Backups | Where-Object { $_ -like "$script:ModelsPath.*" } | Select-Object -First 1
    $modelsPlan = Read-ModelsYaml $script:ModelsPath
    $renamedFrom = if ($modelsPlan.OldProviderId -and $modelsPlan.OldProviderId -ne $ProviderId) { $modelsPlan.OldProviderId } else { $null }
    if ($renamedFrom) { Write-Host "  Renaming provider '$renamedFrom' to '$ProviderId'; '$renamedFrom/*' is dropped from the judge fallback chain." }
    Write-ModelsYaml $modelsPlan $baseUrl $ModelId $context
    $check = Invoke-Omp @('models', $ProviderId, '--kind', 'all', '--json') -AllowFailure
    $listed = $check.ExitCode -eq 0 -and @(($check.StdOut | ConvertFrom-Json).models | Where-Object { $_.selector -eq $selector }).Count -gt 0
    if (-not $listed) {
        if ($modelsBackup) { Copy-Item -LiteralPath $modelsBackup -Destination $script:ModelsPath -Force } else { Remove-Item -LiteralPath $script:ModelsPath }
        Stop-Setup "omp does not list $selector after editing models.yml; the file was restored." @($check.StdErr)
    }
    if ($check.StdErr) { Write-Warning "omp reported while loading models.yml: $($check.StdErr)" }
    Set-OmpJudge $selector $renamedFrom

    # The service runs a copy of this script inside the root (readable by the service account).
    if ((Get-JudgeService) -and $PSCommandPath -and $PSCommandPath -ne $ServiceScriptPath) {
        Copy-Item -LiteralPath $PSCommandPath -Destination $ServiceScriptPath -Force
    }

    # Step 13: optional logon task (not needed when the service is installed).
    if ($AutoStart -and (Get-JudgeService)) {
        Write-Warning "Service '$ServiceName' is installed and starts at boot; the logon task was not registered."
    } elseif ($AutoStart) {
        Write-Step "Registering logon task '$TaskName'"
        Register-AutoStartTask $PSCommandPath
        Write-Host '  Registered.' -ForegroundColor Green
    }

    # Step 14: final report.
    $finalOmp = Get-OmpState
    Show-Report 'Final state' (Get-LlamaState $config) $finalOmp $test
    if ($badBuild) { Write-Warning "Build $badBuild failed the test and was kept aside; running $($config.current). Re-run later to retry it." }
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
    $portNote = if ($config.port -ne $Port) { " (moved from ${Port}: $(Format-PortChoice $portChoice))" } else { '' }
    Write-Host "  - llama-server listens on 127.0.0.1:$($config.port)$portNote and is running now."
    if (Get-JudgeService) {
        Write-Host "  - The Windows service '$ServiceName' runs it from boot; -Start and -Stop control the service."
    } elseif ($AutoStart) {
        Write-Host "  - The logon task '$TaskName' starts it at each sign-in."
    } else {
        Write-Host '  - It is not started at sign-in. Start it when needed (or re-run setup with -AutoStart):'
    }
    Write-Host '      Set-OmpJudgeLocalLlamaCpp -Start | -Stop | -Status'
    Write-Host "  - While it is down omp uses: $(Format-Chain $finalOmp.Chains)"
    Write-Host '  - Update llama.cpp or the model: re-run Set-OmpJudgeLocalLlamaCpp (-Start never updates).'
    Write-Host "  - Logs: $(Format-HomePath $config.log)"
    Write-Host '  - Undo: restore the backups below (or delete the omp-llamacpp-judge block in models.yml and'
    Write-Host '    set modelRoles.judge back), run -RemoveAutoStart, then delete ~\llama-cpp-tiny.'
    foreach ($backup in $script:Backups) { Write-Host "      backup: $backup" }
}

# -Start: starts the configured server (used by the logon task); logs to start.log.
function Invoke-StartMode {
    $config = Read-ServerConfig
    if (-not $config) { Stop-Setup "No $ServerConfigPath. Run Set-OmpJudgeLocalLlamaCpp (setup) first." }
    try {
        Start-JudgeServer $config
    } catch {
        if ("$_" -eq $AbortToken) { throw }
        Stop-Setup "$_" @("Logs: $($config.log)")
    }
}

# -Stop: stops the configured server.
function Invoke-StopMode {
    $config = Read-ServerConfig
    if (-not $config) { Stop-Setup "No $ServerConfigPath; nothing to stop." }
    if (Stop-JudgeServer $config) { Write-Host 'llama-server stopped.' -ForegroundColor Green } else { Write-Host 'llama-server was not running.' }
}

# -Status: shows server, port, model, idle state and logon task.
function Invoke-StatusMode {
    $config = Read-ServerConfig
    Write-Section 'llama-cpp-tiny status'
    if (-not $config) { Write-Row 'server.json' 'absent (run setup first)' $false; return }
    $llama = Get-LlamaState $config
    Write-Row 'Build' $(if ($llama.Build) { "$($llama.Build) [$($config.current)]" } else { "missing [$($config.current)]" }) ([bool]$llama.Build)
    Write-Row 'Model' (Format-HomePath $config.model) (Test-Path -LiteralPath $config.model)
    Write-Row 'Settings' "alias $($config.alias), ctx $($config.ctx), -ngl $($config.ngl), idle-unload $($config.idleSleepSeconds) s"
    $health = switch ($llama.Health) { 200 { 'running' } 503 { 'loading' } default { 'not running' } }
    Write-Row 'Server' "127.0.0.1:$($config.port) $health" ($llama.Health -eq 200)
    $owner = Get-PortOwner ([int]$config.port)
    if ($owner) { Write-Row 'Listener' "$($owner.Name) pid $($owner.Id)" (Test-OurServer ([int]$config.port)) }
    $service = Get-JudgeService
    if ($service) {
        Write-Row "Service '$ServiceName'" "$($service.State), start $($service.StartMode), as $($service.StartName)" ($service.State -eq 'Running')
        Write-Row 'Service logs' (Format-HomePath (Join-Path $Root 'service-logs'))
    }
    if ($llama.Health -eq 200) {
        try {
            $props = Invoke-Json "http://127.0.0.1:$($config.port)/props" -TimeoutSec 5
            if ($null -ne $props.is_sleeping) { Write-Row 'Model loaded' $(if ($props.is_sleeping) { 'no (idle, unloaded)' } else { 'yes' }) }
        } catch { }
    }
    Write-Row "Logon task '$TaskName'" $(if ($llama.Task) { 'registered' } else { 'not registered' })
    Write-Row 'Logs' (Format-HomePath $config.log)
}

# -Run (service command): runs llama-server in the foreground from server.json; returns its exit code.
# Output goes to shawl's log; a non-zero exit makes shawl restart it after a delay.
function Invoke-RunMode {
    $config = Read-ServerConfig
    if (-not $config) { Write-Host "No $ServerConfigPath; run setup first."; return 1 }
    $exe = Get-ServerExe $config.current
    if (-not (Test-Path -LiteralPath $exe)) { Write-Host "llama-server not found at $exe; re-run setup."; return 1 }
    $commandLine = (Get-ServerArguments $config | ForEach-Object { ConvertTo-CommandLineArgument $_ }) -join ' '
    Write-Host "$(Get-Date -Format s) starting $exe $commandLine"
    $info = New-Object Diagnostics.ProcessStartInfo $exe, $commandLine
    $info.UseShellExecute = $false
    $info.WorkingDirectory = Split-Path $exe
    $process = [Diagnostics.Process]::Start($info)
    $process.WaitForExit()
    Write-Host "$(Get-Date -Format s) llama-server exited with code $($process.ExitCode)"
    $process.ExitCode
}

# Returns $true when this session runs elevated (Administrators token).
function Test-Elevated {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Adds an allow ACE for $Sid (start, stop, query status/config, interrogate, user control, read) to a
# service security descriptor's DACL, before the SACL when there is one. Idempotent.
function Add-ServiceAce([string]$Sddl, [string]$Sid) {
    $ace = "(A;;RPWPLCLOCRRC;;;$Sid)"
    if ($Sddl.Contains($ace)) { return $Sddl }
    $sacl = $Sddl.IndexOf('S:')
    if ($sacl -ge 0) { $Sddl.Insert($sacl, $ace) } else { $Sddl + $ace }
}

# Runs sc.exe and aborts on failure.
function Invoke-Sc([string[]]$Arguments) {
    $result = Invoke-Cli "$env:SystemRoot\System32\sc.exe" $Arguments
    if ($result.ExitCode -ne 0) { Stop-Setup "sc.exe $($Arguments[0]) $ServiceName failed (exit $($result.ExitCode))." @($result.StdOut, $result.StdErr) }
    $result.StdOut
}

# Runs icacls.exe and aborts on failure.
function Invoke-Icacls([string[]]$Arguments) {
    $result = Invoke-Cli "$env:SystemRoot\System32\icacls.exe" $Arguments
    if ($result.ExitCode -ne 0) { Stop-Setup "icacls $($Arguments -join ' ') failed (exit $($result.ExitCode))." @($result.StdOut, $result.StdErr) }
}

# Returns the files outside the root that the service account must read (a model in an HF cache).
function Get-ExternalServiceFiles($Config) {
    @(@($Config.model) | Where-Object { $_ -and -not ([string]$_).StartsWith($Root + '\', [StringComparison]::OrdinalIgnoreCase) })
}

# -InstallService (elevated): creates the shawl-wrapped service and its permissions, then starts it.
function Invoke-InstallServiceMode {
    # Prerequisites first (none of these checks needs elevation), so one run reports them all.
    $config = Read-ServerConfig
    if (-not $config) { Stop-Setup "No $ServerConfigPath. Run Set-OmpJudgeLocalLlamaCpp (setup, unelevated) first." }
    $shawl = if ($ShawlPath) { $ShawlPath } else { (Get-Command 'shawl.exe' -ErrorAction SilentlyContinue | Select-Object -First 1).Source }
    $elevated = Test-Elevated
    if (-not $shawl -or -not (Test-Path -LiteralPath $shawl)) {
        $directions = @('Prerequisite: shawl. Install it machine-wide from an elevated PowerShell:',
            '  winget install --id mtkennerly.shawl --exact --scope machine',
            'then re-run -InstallService elevated (new window, or pass -ShawlPath <path to shawl.exe>).')
        Stop-Setup 'shawl.exe not found.' $directions
    }
    if (-not $elevated) { Stop-Setup '-InstallService needs an elevated PowerShell (Run as administrator).' }
    $item = Get-Item -LiteralPath $shawl
    if ($item.LinkType -and $item.Target) { $shawl = [string](@($item.Target)[0]) }  # winget Links are symlinks
    if (-not $shawl.StartsWith($env:ProgramFiles + '\', [StringComparison]::OrdinalIgnoreCase)) {
        Write-Warning "shawl.exe is outside Program Files ($shawl); anything running as you could replace the service binary."
    }
    Write-Host "  shawl: $shawl ($((Invoke-Cli $shawl @('--version')).StdOut.Trim()))"

    Write-Step 'Stopping the current server'
    Stop-JudgeServer $config | Out-Null
    if (Get-AutoStartTask) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "  Removed logon task '$TaskName' (the service replaces it)."
    }
    if (Get-JudgeService) {
        Write-Host "  Replacing the existing service '$ServiceName'."
        Invoke-Sc @('delete', $ServiceName) | Out-Null
        Start-Sleep -Seconds 2
    }

    Write-Step "Creating service '$ServiceName' (account $ServiceAccount)"
    New-Item -ItemType Directory -Path (Split-Path $ServiceScriptPath) -Force | Out-Null
    Copy-Item -LiteralPath $PSCommandPath -Destination $ServiceScriptPath -Force
    $add = @(
        'add', '--name', $ServiceName, '--cwd', $Root, '--log-dir', (Join-Path $Root 'service-logs'),
        '--restart-delay', '10000', '--stop-timeout', '10000', '--kill-process-tree',
        '--env', "LLAMA_CPP_TINY_HOME=$Root",
        '--', 'powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $ServiceScriptPath, '-Run'
    )
    $result = Invoke-Cli $shawl $add
    if ($result.ExitCode -ne 0) { Stop-Setup "shawl add failed (exit $($result.ExitCode))." @($result.StdOut, $result.StdErr) }
    Invoke-Sc @('config', $ServiceName, 'start=', 'delayed-auto', 'obj=', $ServiceAccount) | Out-Null
    Invoke-Sc @('description', $ServiceName, 'llama.cpp server (~\llama-cpp-tiny) serving the omp judge model on loopback.') | Out-Null
    # If shawl itself dies, let the service manager restart it.
    Invoke-Sc @('failure', $ServiceName, 'reset=', '86400', 'actions=', 'restart/10000/restart/10000/restart/60000') | Out-Null

    # The virtual account exists once the service does: grant it the root, and any external model file.
    Invoke-Icacls @($Root, '/grant', "${ServiceAccount}:(OI)(CI)M", '/Q')
    foreach ($file in Get-ExternalServiceFiles $config) { Invoke-Icacls @($file, '/grant', "${ServiceAccount}:R", '/Q') }
    # Let the installing user start and stop the service without elevation.
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $sddl = ((Invoke-Sc @('sdshow', $ServiceName)) -split "`n" | Where-Object { $_.Trim() }) -join ''
    Invoke-Sc @('sdset', $ServiceName, (Add-ServiceAce $sddl.Trim() $sid)) | Out-Null
    Write-Host "  Created; start type delayed-auto; $ServiceAccount has Modify on $Root; $env:USERNAME may start/stop it." -ForegroundColor Green

    Write-Step "Starting service '$ServiceName'"
    try { Start-JudgeServer $config } catch { if ("$_" -eq $AbortToken) { throw }; Stop-Setup "$_" @("Service logs: $(Join-Path $Root 'service-logs')") }
    $log = (Get-LogTail $config 400) -join "`n"
    $devices = @([regex]::Matches($log, '(?m)(using device|Vulkan\d+ \(|ggml_vulkan: \d+ =)[^\r\n]*') | ForEach-Object { $_.Value } | Select-Object -Unique -First 3)
    if ($devices) { $devices | ForEach-Object { Write-Host "  log: $_" -ForegroundColor DarkGray } }
    Write-Host ''
    Write-Host "Service '$ServiceName' is running. Manage it unelevated with Set-OmpJudgeLocalLlamaCpp -Start | -Stop | -Status;" -ForegroundColor Green
    Write-Host 'remove it (elevated) with -RemoveService.' -ForegroundColor Green
}

# -RemoveService (elevated): stops and deletes the service and removes its permissions.
function Invoke-RemoveServiceMode {
    if (-not (Test-Elevated)) { Stop-Setup '-RemoveService needs an elevated PowerShell (Run as administrator).' }
    if (-not (Get-JudgeService)) { Write-Host "Service '$ServiceName' is not installed."; return }
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Wait-ServiceStatus 'Stopped' | Out-Null
    # Remove the ACEs while the virtual account name still resolves.
    if (Test-Path -LiteralPath $Root) { Invoke-Icacls @($Root, '/remove:g', $ServiceAccount, '/T', '/Q') }
    $config = Read-ServerConfig
    if ($config) { foreach ($file in Get-ExternalServiceFiles $config) { Invoke-Icacls @($file, '/remove:g', $ServiceAccount, '/Q') } }
    Invoke-Sc @('delete', $ServiceName) | Out-Null
    Remove-Item -LiteralPath (Split-Path $ServiceScriptPath) -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Removed service '$ServiceName'. Start the server on demand with -Start, or re-run setup with -AutoStart." -ForegroundColor Green
}

# -RemoveAutoStart: removes the logon task.
function Invoke-RemoveAutoStartMode {
    if (Get-AutoStartTask) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Removed logon task '$TaskName'." -ForegroundColor Green
    } else {
        Write-Host "Logon task '$TaskName' is not registered."
    }
}

$previousEncoding = $null
$transcript = $false
$runExitCode = $null
try {
    # Decode omp/llama.cpp output as UTF-8 regardless of the console code page.
    try { $previousEncoding = [Console]::OutputEncoding; [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { $previousEncoding = $null }
    # Windows PowerShell 5.1 defaults to older TLS versions on some systems.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    switch ($PSCmdlet.ParameterSetName) {
        'Start' {
            # The logon task has no console: keep a record of the last start.
            if (Test-Path -LiteralPath $Root) {
                try { Start-Transcript -Path (Join-Path $Root 'start.log') -Force | Out-Null; $transcript = $true } catch { }
            }
            Invoke-StartMode
        }
        'Stop' { Invoke-StopMode }
        'Status' { Invoke-StatusMode }
        'RemoveAutoStart' { Invoke-RemoveAutoStartMode }
        'InstallService' { Invoke-InstallServiceMode }
        'RemoveService' { Invoke-RemoveServiceMode }
        'Run' { $runExitCode = Invoke-RunMode }
        default { Invoke-Setup; Write-Host ''; Write-Host 'Done.' -ForegroundColor Green }
    }
    # -Run passes llama-server's exit code through so shawl can restart it on failure.
    $exitCode = if ($null -ne $runExitCode) { [int]$runExitCode } else { 0 }
} catch {
    if ("$_" -ne $AbortToken) {
        Write-Host ''
        Write-Host "FAILED: unexpected error: $_" -ForegroundColor Red
        Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    }
    $exitCode = 1
} finally {
    if ($transcript) { try { Stop-Transcript | Out-Null } catch { } }
    if ($previousEncoding) { try { [Console]::OutputEncoding = $previousEncoding } catch { } }
}
exit $exitCode
