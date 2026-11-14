#Requires -Version 5.1
<#
.SYNOPSIS
    Downloads and verifies the PC recovery USB file set.
.DESCRIPTION
    Builds the download tree for a Ventoy-based recovery USB under a single
    root folder. Ventoy itself goes to ventoy\, Rufus portable plus the Fido
    download script go to tools\, and the ISO catalog (netboot.xyz, rescue
    images, installer images) goes to isos\. An official Windows 11 ISO is
    resolved through Fido and downloaded like any other entry, and a Tiny11
    build can run on top of it when elevation is available.

    Every step is independent: a failed download or build records a failure
    with manual retry directions and the run continues with the next entry.
    The run ends with a summary table plus a consolidated manual-retry block.
    The exit code is 1 when any failure was recorded, else 0. Re-running is
    safe: files that already match their expected hash are skipped.

    Nothing is written under -WhatIf; the planned table is printed instead.
    Without -Elevate the run never elevates: privileged steps record
    skip-failures instead of prompting. -Elevate enables nothing itself;
    inline sudo must already be enabled before the run.
.PARAMETER Root
    Download root. Defaults to Tools\pc-recovery under the user profile.
    -Destination is an alias for the same folder, handy for dev/test runs.
.PARAMETER NetbootArch
    Which netboot.xyz image to fetch: x64, or multi for the combined
    x86_64 + ARM64 image.
.PARAMETER MintHwe
    Extra Linux Mint HWE image to fetch: None, 6.17, or 7.0. The regular
    Mint image is always fetched.
.PARAMETER CleanDownloads
    Delete tool ZIPs after extraction instead of keeping them for offline
    reuse.
.PARAMETER SkipTiny11
    Skip the Tiny11 build even when an official ISO and elevation are ready.
.PARAMETER Elevate
    Allow privileged steps through sudo.exe inline mode. Without it the run
    never elevates. Already-elevated shells do not call sudo.exe.
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Prepare-PcRecovery.ps1
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Prepare-PcRecovery.ps1 -Destination D:\pc-recovery-test -Elevate -WhatIf
.NOTES
    Per-entry maintenance lives in the catalog rows (Get-RecoveryCatalog):
    each row carries About (one-line project blurb), Released (publisher
    date), SizeNote, the pinned Hash, and Check (one-line re-verify
    instruction). After any upstream release, update the Pinned URL plus
    hash together; Rolling rows resolve live every run and need no edits;
    Manual rows are handled by dedicated functions, never by raw URLs.
    Release dates come from upstream checksum-file Last-Modified headers,
    SourceForge file dates, or the project download page -- never guess.
    HWE Mint rows share the kernel.org tree; both HWE ISOs ship from the
    same host as regular Mint, so one AlternateUrl pattern covers all three.
    Microsoft's Sentinel service rate-limits Fido's download-links endpoint
    per IP: a rejected run ("Sentinel marked this request as rejected") is
    transient -- the script retries 3x with pauses, but a persistent block
    means placing the ISO by hand (Win11_*.iso or en-us_windows_11_*.iso).
    The Tiny11 step needs the 95 MB WinUI zip only for hash context; the
    scripted build uses the 28 KB tiny11maker.ps1 plus 140 KB oscdimg.exe
    and 2 KB autounattend.xml, all staged beside the maker and deleted by
    it on completion (so re-staged every run). The elevated child must use
    'Continue' (the maker relies on non-terminating errors), a shadowed
    Read-Host for its two prompts, and pre-unloaded HKLM\z* hives.
    Download rule: keep the .partial on transport failures (curl 18/28/33/
    52/55/56), delete only on server rejection (22/36), so -C - resumes.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Alias('Destination')]
    [string]$Root = (Join-Path $env:USERPROFILE 'Tools\pc-recovery'),
    [ValidateSet('x64', 'multi')]
    [string]$NetbootArch = 'x64',
    [ValidateSet('None', '6.17', '7.0')]
    [string]$MintHwe = 'None',
    [switch]$CleanDownloads,
    [switch]$SkipTiny11,
    [switch]$Elevate
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

$script:CurlExe = Join-Path $env:SystemRoot 'System32\curl.exe'
$script:FidoUrl = 'https://raw.githubusercontent.com/pbatard/Fido/master/Fido.ps1'
$script:Tiny11MakerUrl = 'https://raw.githubusercontent.com/ntdevlabs/tiny11builder/winui-preview/tiny11maker.ps1'
$script:Tiny11AnswerUrl = 'https://raw.githubusercontent.com/ntdevlabs/tiny11builder/winui-preview/autounattend.xml'
$script:OscdimgUrl = 'https://msdl.microsoft.com/download/symbols/oscdimg.exe/3D44737265000/oscdimg.exe'
$script:Failures = @()
$script:Results = @()
$script:UseSudo = $false

# -----------------------------------------------------------------------------
# Maintained text blocks. These two readmes are written into the download tree
# (root README.txt, isos\README.txt) on every run; edit the text inside these
# two functions, not in the tree, so a re-run never loses the update.
# Functions are the loadable unit (tests dot-source functions only), so the
# text lives here instead of in top-level assignments. Keep ASCII, no BOM.
# -----------------------------------------------------------------------------

# What the destination root is and how to use it.
function Get-RootReadmeText {
    param([string]$WrittenUtc)
    @"
PC RECOVERY USB - download tree
================================
This file was written $WrittenUtc.
Built by util/Prepare-PcRecovery.ps1. Re-running the script is safe: files
that already match their expected hash are skipped, interrupted downloads
resume from their .partial file.

STRUCTURE
  ventoy\            Ventoy media tool (Ventoy2Disk.exe lives here).
                     Run Ventoy2Disk.exe, pick the USB stick, Install, then
                     copy the ISO files below onto the USB drive.
  tools\             Rufus portable, Fido.ps1, and tiny11builder\.
  isos\01-Network\   netboot.xyz network-boot image (needs internet to use).
  isos\02-Rescue\    Hiren's BootCD PE, SystemRescue, Clonezilla.
  isos\03-Installers\ Ubuntu Server, Rocky, Debian netinst, Mint, antiX,
                     Fedora, the Windows 11 ISO (Fido's Win11_*.iso name or
                     the official en-us_windows_11_*.iso name), tiny11\.
  isos\04-etc\       Spare room for drivers, notes, one-off utilities.
  isos\README.txt    Per-folder contents, sizes, and re-verify notes.

WINDOWS 11 ISO
  Resolved in English (en-US) through Fido headless. Microsoft links expire,
  so it is kept without hash verification. If Fido is blocked, download from
  https://www.microsoft.com/en-US/software-download/Windows11 by hand and
  place the file (Win11_*.iso or en-us_windows_11_*.iso) into
  isos\03-Installers\.

TINY11 BUILD
  Produces isos\03-Installers\tiny11\tiny11.iso from the official ISO.
  Needs -Elevate (inline sudo pre-enabled) or an elevated shell.
  See tools\tiny11builder\ for the builder files used.
"@
}

# Per-folder contents of isos\. {0} is replaced with one block per ISO:
# project blurb, release, size, the SHA-256 known at write time, and how
# to re-verify. Hashes recorded here are a cheap local integrity check:
# compare with Get-FileHash before trusting a file, and re-check against
# the upstream source (the Re-verify line) when freshness matters.
function Get-IsosReadmeTemplate {
    param([string]$WrittenUtc)
    @"
RECOVERY ISO SET
================
Grouped for a Ventoy USB: copy these files onto the Ventoy drive and boot.
This file was written $WrittenUtc.
Each entry below names the file, what it is, and the SHA-256 recorded when
this file was written. To verify a file cheaply, hash it locally:

  powershell -NoProfile -Command "Get-FileHash <file> -Algorithm SHA256"

and compare with the SHA-256 below. To confirm it is still current,
follow the Re-verify note for that entry.

{0}

FOLDERS
  01-Network\    Small network-boot images and bootloaders.
  02-Rescue\     Offline-capable rescue and imaging environments.
  03-Installers\ Installer ISOs, including Windows 11 and tiny11\.
  04-etc\        Misc files that do not fit the other categories.

NOTES
  - Ventoy itself is a tool, not an ISO: see ..\ventoy\Ventoy2Disk.exe.
  - Windows and Tiny11 ISOs usually need Secure Boot off (or Ventoy's key
    enrolled); test before relying on them.
  - netboot.xyz needs a working network connection to be useful.
"@
}

# -----------------------------------------------------------------------------
# Messaging helpers. All routine output goes through these two cmdlets only.
# -----------------------------------------------------------------------------

# Prints a section heading.
function Write-Section([string]$Title) {
    Write-Host ''
    Write-Host "== $Title ==" -ForegroundColor Cyan
}

# Prints a progress step.
function Write-Step([string]$Text) {
    Write-Host ''
    Write-Host "-> $Text" -ForegroundColor White
}

# Prints a success line.
function Write-Ok([string]$Text) {
    Write-Host "  ok: $Text" -ForegroundColor Green
}

# Prints a low-key detail line.
function Write-Detail([string]$Text) {
    Write-Host "  $Text" -ForegroundColor DarkGray
}

# Records a failure with manual retry directions and prints it immediately.
# Never throws: every product flow funnels here and the run continues.
function Write-Failure([string]$Name, [string]$Detail, [string[]]$Manual = @()) {
    $script:Failures += [pscustomobject]@{ Name = $Name; Detail = $Detail; Manual = ($Manual -join "`n") }
    $script:Results += [pscustomobject]@{ Name = $Name; Status = 'Failed'; Detail = $Detail }
    Write-Host ''
    Write-Host "FAILED: $Name" -ForegroundColor Red
    if ($Detail) { Write-Host "  $Detail" -ForegroundColor DarkGray }
    foreach ($line in $Manual) {
        if ($line) { Write-Host "  $line" -ForegroundColor Yellow }
    }
}

# Runs one product step; an unexpected throw becomes a recorded failure so
# later steps still run. Expected download failures are recorded by the
# download engine itself and return normally through here.
function Invoke-SafeStep([string]$Name, [scriptblock]$Body, [string[]]$Manual = @()) {
    try {
        &$Body
    } catch {
        $detail = if ($_.Exception) { $_.Exception.Message } else { "$_" }
        Write-Failure -Name $Name -Detail $detail -Manual $Manual
    }
}

# Creates a directory when missing. Gated so -WhatIf writes nothing.
function Ensure-Directory {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) { return }
    if ($PSCmdlet.ShouldProcess($Path, 'Create directory')) {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
    }
}

# -----------------------------------------------------------------------------
# Elevation helpers. Copied from the profile in behavior (scriptblock branch
# only); this script never enables sudo itself, it only consumes inline mode.
# -----------------------------------------------------------------------------

# Returns true when the current session already runs elevated.
function Test-IsAdministrator {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Runs one PowerShell script block elevated through sudo.exe inline mode.
# Requires Windows 11 build 26100+ with sudo.exe present and Enabled -eq 3.
function Invoke-Elevated {
    [CmdletBinding()]
    param(
        [switch]$NoProfile,

        [Parameter(Mandatory = $true, Position = 0, ValueFromRemainingArguments = $true)]
        [object[]]$Command
    )

    $sudoPath = Join-Path $env:SystemRoot 'System32\sudo.exe'
    $windowsVersion = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
    $build = 0
    if ($windowsVersion -and -not [int]::TryParse([string]$windowsVersion.CurrentBuildNumber, [ref]$build)) {
        $build = 0
    }

    if ($build -lt 26100 -or -not (Test-Path -LiteralPath $sudoPath -PathType Leaf)) {
        Write-Error 'Invoke-Elevated requires Windows 11 version 24H2 (build 26100) or later.'
        return
    }

    $sudoConfig = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo' -ErrorAction SilentlyContinue
    if (-not $sudoConfig -or $sudoConfig.Enabled -ne 3) {
        Write-Error 'Windows Sudo is not enabled in inline mode. Run Enable-WindowsSudo first.'
        return
    }

    if ($Command.Count -eq 1 -and $Command[0] -is [scriptblock]) {
        $powerShellPath = (Get-Process -Id $PID -ErrorAction Stop).MainModule.FileName
        $location = $ExecutionContext.SessionState.Path.CurrentLocation.Path.Replace("'", "''")
        $scriptText = $Command[0].ToString()
        $wrappedCommand = @"
`$ProgressPreference = 'SilentlyContinue'
Set-Location -LiteralPath '$location'
`$global:LASTEXITCODE = `$null
& {
$scriptText
}
`$commandSucceeded = `$?
`$nativeExitCode = `$global:LASTEXITCODE
if (`$null -ne `$nativeExitCode) { exit `$nativeExitCode }
if (-not `$commandSucceeded) { exit 1 }
"@
        $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($wrappedCommand))
        $powerShellArguments = @('-NoLogo', '-OutputFormat', 'Text')
        if ($NoProfile) { $powerShellArguments += '-NoProfile' }
        $powerShellArguments += @('-EncodedCommand', $encodedCommand)

        & $sudoPath $powerShellPath @powerShellArguments
        return
    }

    Write-Error 'The command must be a single PowerShell script block.'
}

# Sets $script:UseSudo from the -Elevate intent. Records exactly one failure
# when elevation was requested but inline sudo is unavailable, then leaves
# the rest of the run unelevated. Never elevates and never enables sudo.
function Initialize-ElevationState([switch]$Elevate) {
    $script:UseSudo = $false
    if (-not $Elevate) { return }
    if (Test-IsAdministrator) {
        Write-Warning 'Already running elevated; sudo.exe will not be used.'
        return
    }
    $config = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo' -ErrorAction SilentlyContinue
    if ($config -and $config.Enabled -eq 3) {
        $script:UseSudo = $true
        return
    }
    Write-Failure -Name 'Inline sudo unavailable' -Detail 'Sudo Enabled is not 3.' -Manual @(
        'Run Enable-WindowsSudo in an elevated shell, then re-run with -Elevate.',
        'Or re-run without -Elevate; privileged steps record skip-failures and the rest continues.'
    )
}

# -----------------------------------------------------------------------------
# Download engine. Network access goes through Invoke-Cli (native curl) and
# the two thin REST wrappers so tests can stub the network edge.
# -----------------------------------------------------------------------------

# Runs a CLI command and returns its exit code with stdout/stderr kept apart.
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

# Fetches a GitHub REST endpoint and returns the parsed response.
function Invoke-GitHubApiJson([string]$Uri) {
    Invoke-RestMethod -Uri $Uri -Headers @{ 'User-Agent' = 'pc-recovery' } -UseBasicParsing
}

# Fetches a small text file (checksum lists) fresh on every call. GitHub
# serves release assets as application/octet-stream, for which 5.1 returns
# .Content as a byte array; decode those as UTF-8 instead of stringifying.
function Invoke-WebText([string]$Uri) {
    $content = (Invoke-WebRequest -Uri $Uri -Headers @{ 'User-Agent' = 'pc-recovery' } -UseBasicParsing).Content
    if ($content -is [byte[]]) { return [Text.Encoding]::UTF8.GetString($content) }
    return [string]$content
}

# Resolves the newest release asset of a GitHub repo. Logs the resolved tag
# plus the published hash; records one failure and returns $null when the
# release, asset, or hash reference cannot be resolved.
function Get-GitHubLatestAsset([string]$Repo, [string]$AssetPattern, [string]$HashAssetName = '', [string]$HashSuffix = '') {
    try {
        $release = Invoke-GitHubApiJson -Uri "https://api.github.com/repos/$Repo/releases/latest"
    } catch {
        $detail = if ($_.Exception) { $_.Exception.Message } else { "$_" }
        Write-Failure -Name "$Repo release lookup" -Detail $detail -Manual @(
            'GitHub API may be rate-limited (403 without a token); re-run later.',
            "Or download the asset by hand from https://github.com/$Repo/releases/latest."
        )
        return $null
    }
    $asset = @($release.assets | Where-Object { $_.name -match $AssetPattern } | Where-Object { $_.name -notmatch 'arm64|x86' }) | Select-Object -First 1
    if (-not $asset) {
        Write-Failure -Name "$Repo asset lookup" -Detail "No asset matches $AssetPattern in $($release.tag_name)." -Manual @(
            "Open https://github.com/$Repo/releases/latest and download the Windows asset by hand."
        )
        return $null
    }
    $hashUrl = ''
    if ($HashAssetName) {
        $hashAsset = @($release.assets | Where-Object { $_.name -eq $HashAssetName }) | Select-Object -First 1
        if ($hashAsset) { $hashUrl = $hashAsset.browser_download_url }
    } elseif ($HashSuffix) {
        $hashAsset = @($release.assets | Where-Object { $_.name -eq ($asset.name + $HashSuffix) }) | Select-Object -First 1
        if ($hashAsset) { $hashUrl = $hashAsset.browser_download_url }
    }
    Write-Detail "Resolved $Repo $($release.tag_name): $($asset.name)"
    [pscustomobject]@{ Tag = $release.tag_name; Name = $asset.name; ZipUrl = $asset.browser_download_url; HashUrl = $hashUrl }
}

# Finds the SHA-256 for one file inside a checksum-list text (handles both
# "hash  file" and "hash *file" styles). Returns $null when absent.
function Find-HashInChecksumText([string]$Text, [string]$FileName) {
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^\s*([0-9a-fA-F]{64})\s+[\* ]?(.+?)\s*$') {
            $listed = $Matches[2]
            if ($listed -eq $FileName -or $listed.EndsWith('/' + $FileName)) {
                return $Matches[1].ToLowerInvariant()
            }
        }
    }
    return $null
}

# Resolves a rolling checksum: downloads the checksum file fresh and extracts
# the hash for the target file. Records a failure and returns '' on miss.
function Get-RollingExpectedHash([string]$Name, [string]$ChecksumUrl, [string]$FileName, [string[]]$Manual) {
    try {
        $text = Invoke-WebText -Uri $ChecksumUrl
    } catch {
        $detail = if ($_.Exception) { $_.Exception.Message } else { "$_" }
        Write-Failure -Name $Name -Detail "Checksum list download failed: $detail" -Manual $Manual
        return ''
    }
    $hash = Find-HashInChecksumText -Text "$text" -FileName $FileName
    if (-not $hash) {
        Write-Failure -Name $Name -Detail "No checksum entry for $FileName." -Manual $Manual
        return ''
    }
    Write-Detail "Rolling hash for ${FileName}: $hash"
    return $hash
}

# Downloads one URL to $OutFile with curl.exe (resumable via .partial, then
# atomic move). Timeouts keep a stalled socket from hanging the run forever.
# Keeps the .partial on every transport failure so the next run resumes with
# -C -; deletes it only when the server rejects the request (22 HTTP error,
# 36 resume not supported). Returns $true on success, $false on failure.
function Invoke-FileDownload {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Url, [string]$OutFile)
    $partial = "$OutFile.partial"
    # Stalled-socket guard: bail after 30 s connect or 60 s under 1 KB/s, then
    # let curl retry within this attempt; ResumeFailed keeps the partial too.
    $result = Invoke-Cli -Command $script:CurlExe -Arguments @('-L', '--fail', '--retry', '3', '--retry-all-errors', '--retry-delay', '5', '--connect-timeout', '30', '--speed-limit', '1024', '--speed-time', '60', '--progress-bar', '-C', '-', '-o', $partial, $Url)
    if ($result.ExitCode -ne 0) {
        $code = "$($result.ExitCode)"
        if ($code -in @('22', '36')) {
            Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue
        } else {
            Write-Detail "Transfer failed (curl exit $code); keeping $partial for resume."
        }
        return $false
    }
    if (-not (Test-Path -LiteralPath $partial)) { return $false }
    if ($PSCmdlet.ShouldProcess($OutFile, 'Move downloaded file into place')) {
        Move-Item -LiteralPath $partial -Destination $OutFile -Force
    }
    return $true
}

# Compares a local file against an expected SHA-256 (case-insensitive).
function Test-LocalFileHash([string]$Path, [string]$ExpectedHash) {
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    return ($actual -eq $ExpectedHash.ToLowerInvariant())
}

# Downloads $Url to $OutFile and verifies its SHA-256. Skips files that
# already verify. On hash mismatch the file is deleted, the download is
# retried once, and a failure is recorded only if it still mismatches.
# Returns $true on download-or-skip, $false on recorded failure. Never throws.
function Save-VerifiedFile {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Url, [string]$OutFile, [string]$ExpectedHash = '', [string]$AlternateUrl = '', [string]$Name = '')
    $label = if ($Name) { $Name } else { $OutFile }
    if (-not $PSCmdlet.ShouldProcess($OutFile, "Download $Url")) { return $true }
    if (Test-Path -LiteralPath $OutFile) {
        if ($ExpectedHash) {
            if (Test-LocalFileHash -Path $OutFile -ExpectedHash $ExpectedHash) {
                Write-Ok "Skipped (verified): $label"
                $script:Results += [pscustomobject]@{ Name = $label; Status = 'Skipped'; Detail = 'hash matches' }
                return $true
            }
            Write-Detail "Stale file fails verification, re-downloading: $label"
            Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
        } else {
            Write-Warning "Already present without a published hash, kept as-is: $label"
            $script:Results += [pscustomobject]@{ Name = $label; Status = 'Skipped'; Detail = 'present, no hash to check' }
            return $true
        }
    }
    $candidates = @($Url)
    if ($AlternateUrl) { $candidates += $AlternateUrl }
    $downloaded = $false
    for ($n = 0; $n -lt $candidates.Count; $n++) {
        if ($n -gt 0) {
            # A stale .partial belongs to the previous host; resuming from its
            # byte offset would corrupt the alternate's bytes. Start that one clean.
            Write-Detail "Primary failed; retrying from alternate mirror: $label"
            Remove-Item -LiteralPath "$OutFile.partial" -Force -ErrorAction SilentlyContinue
        }
        if (Invoke-FileDownload -Url $candidates[$n] -OutFile $OutFile) { $downloaded = $true; break }
    }
    if (-not $downloaded) {
        Write-Failure -Name $label -Detail "Download failed: $Url" -Manual @(
            "Download $Url by hand into $OutFile.",
            'Re-run the script; verified files are skipped.'
        )
        return $false
    }
    if ($ExpectedHash -and -not (Test-LocalFileHash -Path $OutFile -ExpectedHash $ExpectedHash)) {
        Write-Detail "Hash mismatch, retrying once: $label"
        Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
        if ((Invoke-FileDownload -Url $Url -OutFile $OutFile) -and (Test-LocalFileHash -Path $OutFile -ExpectedHash $ExpectedHash)) {
            Write-Ok "Downloaded (verified on retry): $label"
            $script:Results += [pscustomobject]@{ Name = $label; Status = 'Downloaded'; Detail = 'verified on retry' }
            return $true
        }
        Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
        Write-Failure -Name $label -Detail "Hash mismatch after retry: $Url" -Manual @(
            "Download $Url by hand into $OutFile and compare its SHA-256 with $ExpectedHash.",
            'A SourceForge interstitial page instead of bytes is the usual cause; retry later.'
        )
        return $false
    }
    Write-Ok "Downloaded: $label"
    $script:Results += [pscustomobject]@{ Name = $label; Status = 'Downloaded'; Detail = 'verified' }
    return $true
}

# -----------------------------------------------------------------------------
# ISO catalog. HashKind is Pinned (hash below), Rolling (checksum file fetched
# live every run), or Manual (resolved by a dedicated function, never a URL).
# MintHwe marks HWE rows fetched only when -MintHwe names them; NetbootVariant
# marks the x64/multi rows of which only the selected one is fetched.
# -----------------------------------------------------------------------------

function Get-RecoveryCatalog {
    @(
        [pscustomobject]@{ Name = 'netboot.xyz'; Category = '01-Network'; FileName = 'netboot.xyz.iso'; Url = 'https://boot.netboot.xyz/ipxe/netboot.xyz.iso'; AlternateUrl = ''; Hash = ''; HashKind = 'Rolling'; ChecksumUrl = 'https://boot.netboot.xyz/ipxe/netboot.xyz-sha256-checksums.txt'; NetbootVariant = 'x64'; MintHwe = ''; About = 'Network-boot menu that loads installer and utility images over the internet (needs a working network connection).'; Released = 'Rolling release, re-resolved every run (checksum file dated 2026-11-13).'; SizeNote = 'About 3 MB.'; Check = 'Re-download netboot.xyz-sha256-checksums.txt and match the ISO filename.' },
        [pscustomobject]@{ Name = 'netboot.xyz multi-arch'; Category = '01-Network'; FileName = 'netboot.xyz-multiarch.iso'; Url = 'https://boot.netboot.xyz/ipxe/netboot.xyz-multiarch.iso'; AlternateUrl = ''; Hash = ''; HashKind = 'Rolling'; ChecksumUrl = 'https://boot.netboot.xyz/ipxe/netboot.xyz-sha256-checksums.txt'; NetbootVariant = 'multi'; MintHwe = ''; About = 'netboot.xyz combined image for x86_64 and ARM64 machines.'; Released = 'Rolling release, re-resolved every run (checksum file dated 2026-11-13).'; SizeNote = 'Combined x86_64 + ARM64 network-boot ISO.'; Check = 'Re-download netboot.xyz-sha256-checksums.txt and match the ISO filename.' },
        [pscustomobject]@{ Name = "Hiren's BootCD PE x64"; Category = '02-Rescue'; FileName = 'HBCD_PE_x64.iso'; Url = 'https://www.hirensbootcd.org/files/HBCD_PE_x64.iso'; AlternateUrl = ''; Hash = '8c4c670c9c84d6c4b5a9c32e0aa5a55d8c23de851d259207d54679ea774c2498'; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Windows PE rescue environment with disk, partition, recovery, and antivirus tools (BootCD PE x64 v1.0.8).'; Released = 'BootCD PE x64 v1.0.8, March 2024 (download page and changelog); the URL itself carries no version, so the hash is pinned to that build.'; SizeNote = 'About 3.06 GB.'; Check = 'Unversioned URL; re-pin hash only after official announcement.' },
        [pscustomobject]@{ Name = 'SystemRescue'; Category = '02-Rescue'; FileName = 'systemrescue-13.03-amd64.iso'; Url = 'https://sourceforge.net/projects/systemrescuecd/files/sysresccd-x86/13.03/systemrescue-13.03-amd64.iso/download'; AlternateUrl = ''; Hash = 'b71b98ba6b92145524cb1a72206b9888a59861ad6fb05d127faf618ca0136891'; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Arch-based Linux rescue toolkit (disk tools, filesystem repair, network utilities).'; Released = 'Version 13.03, November 2026 (SourceForge release date 2026-11-07).'; SizeNote = 'About 1.4 GB.'; Check = 'SourceForge Files page for sysresccd-x86 13.03 plus its .sha256 sidecar.' },
        [pscustomobject]@{ Name = 'Clonezilla'; Category = '02-Rescue'; FileName = 'clonezilla-live-3.3.3-37-amd64.iso'; Url = 'https://sourceforge.net/projects/clonezilla/files/clonezilla_live_stable/3.3.3-37/clonezilla-live-3.3.3-37-amd64.iso/download'; AlternateUrl = ''; Hash = '3079458d926a37d3533e5d5caeb61b6e49c2dc69e2c97e0332ef37986bb3414f'; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Disk imaging and cloning (device-to-device and device-to-image). UEFI and Secure Boot capable amd64 build.'; Released = 'Version 3.3.3-37, September 2026 (SourceForge file date; pin rests on the draft: the folder publishes no sidecar).'; SizeNote = 'About 505 MB.'; Check = 'SourceForge Files page for clonezilla_live_stable 3.3.3-37 (pin rests on the draft: the folder publishes no sidecar).' },
        [pscustomobject]@{ Name = 'Ubuntu Server'; Category = '03-Installers'; FileName = 'ubuntu-26.04.1-live-server-amd64.iso'; Url = 'https://releases.ubuntu.com/26.04/ubuntu-26.04.1-live-server-amd64.iso'; AlternateUrl = ''; Hash = 'cc8a95cde20f6ced61a322420de00f10cc3c90ced545daa46cb9c1a117f1d927'; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Ubuntu Server installer (minimal CLI base; add ubuntu-desktop afterwards for a desktop).'; Released = 'Version 26.04.1, August 2026 (SHA256SUMS dated 2026-08-27).'; SizeNote = 'About 2.7 GB.'; Check = 'releases.ubuntu.com SHA256SUMS for 26.04.1.' },
        [pscustomobject]@{ Name = 'Rocky Linux minimal'; Category = '03-Installers'; FileName = 'Rocky-10.2-x86_64-minimal.iso'; Url = 'https://download.rockylinux.org/pub/rocky/10/isos/x86_64/Rocky-10.2-x86_64-minimal.iso'; AlternateUrl = 'https://download.rockylinux.org/pub/rocky/10/isos/x86_64/Rocky-10-latest-x86_64-minimal.iso'; Hash = 'aac6ac3ce781b91a91ce78463405f66c611a5dca4b3840c79e5e01d97302f6c8'; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Minimal offline installer for a small RHEL-compatible server/CLI base (RHEL 10 generation, supported to roughly May 2035).'; Released = 'Version 10.2, May 2026 (ISO 2026-05-27, CHECKSUM signed 2026-05-29, 2072444928 bytes).'; SizeNote = 'About 2.1 GB.'; Check = 'Rocky-10.2-x86_64-minimal.iso CHECKSUM entry in the same directory.' },
        [pscustomobject]@{ Name = 'Debian netinst'; Category = '03-Installers'; FileName = 'debian-13.7.0-amd64-netinst.iso'; Url = 'https://cdimage.debian.org/debian-cd/13.7.0/amd64/iso-cd/debian-13.7.0-amd64-netinst.iso'; AlternateUrl = 'https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-13.7.0-amd64-netinst.iso'; Hash = 'a7ef94ac2fb9a7fec454552abd629b7cc9d5155c886165a45649f5ce6167e355'; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Small Debian network installer (Debian 13 includes non-free firmware for Wi-Fi/BT/GPU).'; Released = 'Version 13.7.0, September 2026 (SHA256SUMS dated 2026-09-12).'; SizeNote = 'About 400 MB.'; Check = 'Debian cdimage SHA256SUMS for 13.7.0 (upstream-verified 2026-11-14); versioned path first, /current/ fallback.' },
        [pscustomobject]@{ Name = 'Linux Mint Xfce'; Category = '03-Installers'; FileName = 'linuxmint-22.3-xfce-64bit.iso'; Url = 'https://mirrors.kernel.org/linuxmint/stable/22.3/linuxmint-22.3-xfce-64bit.iso'; AlternateUrl = 'https://mirror.math.princeton.edu/pub/linuxmint/stable/22.3/linuxmint-22.3-xfce-64bit.iso'; Hash = '45a835b5dddaf40e84d776549e0b19b3fbd49673b6cc6434ebddbfcd217df776'; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Live/installer ISO with the Xfce desktop (based on Ubuntu 24.04 LTS, kernel 6.14).'; Released = 'Version 22.3, January 2026 (sha256sum.txt dated 2026-01-11).'; SizeNote = 'About 3.0 GB.'; Check = 'mirrors.kernel.org/linuxmint stable/22.3 sha256sum.txt (Princeton mirror is a byte-identical fallback).' },
        [pscustomobject]@{ Name = 'Linux Mint Xfce HWE 6.17'; Category = '03-Installers'; FileName = 'linuxmint-22.3-xfce-64bit-hwe-6.17.iso'; Url = 'https://mirrors.kernel.org/linuxmint/hwe/linuxmint-22.3-xfce-64bit-hwe-6.17.iso'; AlternateUrl = 'https://mirror.math.princeton.edu/pub/linuxmint/hwe/linuxmint-22.3-xfce-64bit-hwe-6.17.iso'; Hash = '8c8eb200642bca2f34b7f22e812e4ac3d97483b06b188355cdff8ff98f03f550'; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = '6.17'; About = 'Mint Xfce with the newer HWE 6.17 kernel for hardware the regular ISO does not support.'; Released = 'Version 22.3 with HWE kernel 6.17 (hwe sha256sum.txt dated 2026-08-08).'; SizeNote = 'Fetch only with -MintHwe 6.17 (HWE kernel 6.17 for newer hardware).'; Check = 'mirrors.kernel.org/linuxmint hwe/sha256sum.txt (Princeton mirror is a byte-identical fallback).' },
        [pscustomobject]@{ Name = 'Linux Mint Xfce HWE 7.0'; Category = '03-Installers'; FileName = 'linuxmint-22.3-xfce-64bit-hwe-7.0.iso'; Url = 'https://mirrors.kernel.org/linuxmint/hwe/linuxmint-22.3-xfce-64bit-hwe-7.0.iso'; AlternateUrl = 'https://mirror.math.princeton.edu/pub/linuxmint/hwe/linuxmint-22.3-xfce-64bit-hwe-7.0.iso'; Hash = '17475774172776978f24677a847a62d7595c5bee34cb1f96ee3d26eedeca33c8'; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = '7.0'; About = 'Mint Xfce with the newer HWE 7.0 kernel for hardware the regular ISO does not support.'; Released = 'Version 22.3 with HWE kernel 7.0 (hwe sha256sum.txt dated 2026-08-08).'; SizeNote = 'Fetch only with -MintHwe 7.0 (HWE kernel 7.0 for newer hardware).'; Check = 'mirrors.kernel.org/linuxmint hwe/sha256sum.txt (Princeton mirror is a byte-identical fallback).' },
        [pscustomobject]@{ Name = 'antiX full'; Category = '03-Installers'; FileName = 'antiX-26.1_x64-full.iso'; Url = 'https://sourceforge.net/projects/antix-linux/files/Final/antiX-26.1/antiX-26.1_x64-full.iso/download'; AlternateUrl = ''; Hash = '293381af0b7c48399abe015da8f67d41fd34372b73c4aafcf53747fbaed22371'; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Debian 13-based, systemd-free live/installer with a desktop; suits modern and older PCs alike.'; Released = 'Version 26.1, September 2026 (SourceForge files dated 2026-09-28).'; SizeNote = 'About 2.5 GB.'; Check = 'SourceForge Final/antiX-26.1 file list plus the .sha256 sidecar.' },
        [pscustomobject]@{ Name = 'Fedora Workstation Live'; Category = '03-Installers'; FileName = 'Fedora-Workstation-Live-45-1.4.x86_64.iso'; Url = 'https://download.fedoraproject.org/pub/fedora/linux/releases/45/Workstation/x86_64/iso/Fedora-Workstation-Live-45-1.4.x86_64.iso'; AlternateUrl = ''; Hash = '68338c6bfe4f0d64151f2e47efe9f44a8855ad05b460e56b844fb3fa2c9a3beb'; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Live desktop installer with GNOME.'; Released = 'Version 45-1.4, October 2026.'; SizeNote = 'About 2.72 GB.'; Check = 'Fedora-Workstation-45-1.4-x86_64-CHECKSUM in the same directory.' }
    )
}

# Verified hashes recorded during this run, keyed by full path. Pinned rows
# are verified by the download engine; Rolling rows resolve live. The readme
# reuses these instead of re-hashing gigabytes on every run.
$script:VerifiedHashes = @{}

# Builds one readme block for a catalog row. Uses the hash verified during
# this run when available; otherwise falls back to the catalog hash for
# Pinned rows. Never throws.
function Format-IsoReadmeEntry($Row, [string]$Root) {
    $lines = @()
    $lines += "== $($Row.Name) ($($Row.Category)\$($Row.FileName)) =="
    $lines += $Row.About
    $lines += "Release: $($Row.Released)  Size: $($Row.SizeNote)"
    $path = Join-Path (Join-Path (Join-Path $Root 'isos') $Row.Category) $Row.FileName
    if ($script:VerifiedHashes.ContainsKey($path)) {
        $lines += "SHA-256 (verified this run): $($script:VerifiedHashes[$path])"
    } elseif ($Row.Hash) {
        $lines += "SHA-256 (catalog, $($Row.HashKind)): $($Row.Hash.ToLowerInvariant())"
    }
    if (Test-Path -LiteralPath $path) {
        $lines += "Bytes on disk: $((Get-Item -LiteralPath $path).Length)"
    } else {
        $lines += 'Not present in this tree (download did not complete or was not selected).'
    }
    $lines += "Re-verify: $($Row.Check)"
    return ($lines -join "`r`n")
}
# Returns the SHA-256 plus size of a large non-catalog file, reusing a
# small sidecar (tools\filefacts.json) when size and timestamp are unchanged
# so re-runs cost seconds instead of re-hashing gigabytes. Never throws.
function Get-ManualIsoFact([string]$Path, [string]$Root) {
    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) { return $null }
    $factsPath = Join-Path (Join-Path $Root 'tools') 'filefacts.json'
    $facts = @{}
    if (Test-Path -LiteralPath $factsPath) {
        try {
            $raw = [IO.File]::ReadAllText($factsPath, [Text.Encoding]::UTF8)
            foreach ($entry in ((ConvertFrom-Json -InputObject $raw).PSObject.Properties)) {
                $facts[$entry.Name] = $entry.Value
            }
        } catch { $facts = @{} }
    }
    $known = $facts[$Path]
    if ($known -and $known.Bytes -eq $item.Length -and $known.LastWriteUtc -eq $item.LastWriteTimeUtc.Ticks) {
        return [pscustomobject]@{ Hash = [string]$known.Hash; Bytes = [long]$known.Bytes }
    }
    try {
        $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    } catch {
        return $null
    }
    $facts[$Path] = [pscustomobject]@{ Hash = $hash; Bytes = $item.Length; LastWriteUtc = $item.LastWriteTimeUtc.Ticks }
    try {
        $dir = Split-Path -Parent $factsPath
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        [IO.File]::WriteAllText($factsPath, (ConvertTo-Json -InputObject $facts -Depth 4), [Text.UTF8Encoding]::new($false))
    } catch { }
    return [pscustomobject]@{ Hash = $hash; Bytes = $item.Length }
}

# Builds one readme block for a hand-placed or locally built ISO: records the
# actual file hash (via the sidecar cache) so the reader gets a cheap
# integrity check even though no catalog hash exists. Never throws.
function Format-ManualIsoReadmeEntry([string]$Title, [string]$Path, [string]$Folder, [string]$Note, [string]$Root) {
    $lines = @()
    $leaf = Split-Path -Leaf $Path
    $lines += "== $Title ($Folder\$leaf) =="
    $lines += $Note
    $fact = Get-ManualIsoFact -Path $Path -Root $Root
    if ($fact) {
        $lines += "SHA-256 (on disk at write time): $($fact.Hash)"
        $lines += "Bytes on disk: $($fact.Bytes)"
    } else {
        $lines += 'On-disk hash unavailable; file may have moved since the write.'
    }
    return ($lines -join "`r`n")
}

# Downloads one catalog row into its category folder. Selects Rolling hashes
# live; Pinned rows verify against the catalog hash. Never throws.
function Save-CatalogRow {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param($Row, [string]$Root)
    $dir = Join-Path (Join-Path $Root 'isos') $Row.Category
    Ensure-Directory -Path $dir
    $outFile = Join-Path $dir $Row.FileName
    $expected = $Row.Hash
    if ($Row.HashKind -eq 'Rolling') {
        $expected = Get-RollingExpectedHash -Name $Row.Name -ChecksumUrl $Row.ChecksumUrl -FileName $Row.FileName -Manual @($Row.Check)
        if (-not $expected) { return $false }
    }
    $ok = (Save-VerifiedFile -Url $Row.Url -OutFile $outFile -ExpectedHash $expected -AlternateUrl $Row.AlternateUrl -Name $Row.Name)
    # Record the hash this file verified against so the readme reuses it
    # instead of re-hashing gigabytes. Skipped-verified files carry the
    # same expected hash, so presence implies a match.
    if ($ok -and $expected -and (Test-Path -LiteralPath $outFile)) {
        $script:VerifiedHashes[$outFile] = $expected.ToLowerInvariant()
    }
    return $ok
}

# Downloads every selected catalog row, netboot first so network rescue is
# usable even when a later multi-GB file fails. Never throws.
function Save-CatalogIsos {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Root, [string]$NetbootArch = 'x64', [string]$MintHwe = 'None')
    $order = @{ '01-Network' = 0; '02-Rescue' = 1; '03-Installers' = 2 }
    $rows = Get-RecoveryCatalog | Where-Object {
        (($_.NetbootVariant -eq '') -or ($_.NetbootVariant -eq $NetbootArch)) -and
        (($_.MintHwe -eq '') -or ($_.MintHwe -eq $MintHwe))
    } | Sort-Object { $order[$_.Category] }, Name
    foreach ($row in $rows) {
        $entry = $row
        Invoke-SafeStep -Name $entry.Name -Manual @($entry.Check) -Body {
            Save-CatalogRow -Row $entry -Root $Root | Out-Null
        }
    }
}

# -----------------------------------------------------------------------------
# Tool flows: Ventoy, Rufus portable + Fido.
# -----------------------------------------------------------------------------

# Downloads the latest Ventoy Windows zip (verified against sha256.txt) and
# extracts it into ventoy\. Keeps the zip unless -CleanDownloads. Never throws.
function Install-Ventoy {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Root, [switch]$CleanDownloads)
    $ventoyDir = Join-Path $Root 'ventoy'
    Ensure-Directory -Path $ventoyDir
    $release = Get-GitHubLatestAsset -Repo 'ventoy/Ventoy' -AssetPattern '^ventoy-.*-windows\.zip$' -HashAssetName 'sha256.txt'
    if (-not $release) { return $false }
    if (-not $release.HashUrl) {
        Write-Failure -Name 'Ventoy' -Detail 'Release has no sha256.txt asset.' -Manual @(
            'Download the Windows zip by hand from https://github.com/ventoy/Ventoy/releases/latest,',
            "verify it against sha256.txt, and extract it into $ventoyDir."
        )
        return $false
    }
    try {
        $hashText = Invoke-WebText -Uri $release.HashUrl
    } catch {
        $detail = if ($_.Exception) { $_.Exception.Message } else { "$_" }
        Write-Failure -Name 'Ventoy' -Detail "sha256.txt download failed: $detail" -Manual @(
            'Download the Windows zip by hand from https://github.com/ventoy/Ventoy/releases/latest,',
            "verify it against sha256.txt, and extract it into $ventoyDir."
        )
        return $false
    }
    $expected = Find-HashInChecksumText -Text "$hashText" -FileName $release.Name
    if (-not $expected) {
        Write-Failure -Name 'Ventoy' -Detail "No checksum entry for $($release.Name)." -Manual @(
            'Download the Windows zip by hand from https://github.com/ventoy/Ventoy/releases/latest,',
            "verify it against sha256.txt, and extract it into $ventoyDir."
        )
        return $false
    }
    Write-Detail "Ventoy hash for $($release.Name): $expected"
    $exe = Join-Path $ventoyDir 'Ventoy2Disk.exe'
    if ((Test-Path -LiteralPath $exe) -and (Test-Path -LiteralPath (Join-Path $ventoyDir $release.Name)) -and (Test-LocalFileHash -Path (Join-Path $ventoyDir $release.Name) -ExpectedHash $expected)) {
        Write-Ok 'Skipped (present): Ventoy2Disk.exe'
        $script:Results += [pscustomobject]@{ Name = 'Ventoy'; Status = 'Skipped'; Detail = 'present, zip hash matches' }
        return $true
    }
    $zipPath = Join-Path $ventoyDir $release.Name
    if (-not (Save-VerifiedFile -Url $release.ZipUrl -OutFile $zipPath -ExpectedHash $expected -Name 'Ventoy')) { return $false }
    if ($PSCmdlet.ShouldProcess($ventoyDir, "Extract $($release.Name)")) {
        # The zip ships one top-level wrapper folder holding Ventoy2Disk.exe.
        # Expand into a temp dir, move the wrapper's children up, drop empties.
        # Directory moves merge when the target exists (Move-Item refuses).
        $stageDir = Join-Path $ventoyDir '_stage'
        Remove-Item -LiteralPath $stageDir -Recurse -Force -ErrorAction SilentlyContinue
        Expand-Archive -LiteralPath $zipPath -DestinationPath $stageDir -Force
        try {
            $wrapper = @(Get-ChildItem -LiteralPath $stageDir -Directory) | Select-Object -First 1
            $inner = if ($wrapper -and (Test-Path -LiteralPath (Join-Path $wrapper.FullName 'Ventoy2Disk.exe'))) { $wrapper.FullName } else { $stageDir }
            Get-ChildItem -LiteralPath $inner -Force | ForEach-Object {
                $target = Join-Path $ventoyDir $_.Name
                if (($_.PSIsContainer) -and (Test-Path -LiteralPath $target)) {
                    @(Get-ChildItem -LiteralPath $_.FullName -Recurse -Force) | ForEach-Object {
                        $suffix = $_.FullName.Substring($inner.Length).TrimStart('\', '/')
                        $dest = Join-Path $ventoyDir $suffix
                        if ($_.PSIsContainer) {
                            if (-not (Test-Path -LiteralPath $dest)) { New-Item -ItemType Directory -Path $dest -Force | Out-Null }
                        } else {
                            Move-Item -LiteralPath $_.FullName -Destination $dest -Force
                        }
                    }
                    Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
                } else {
                    Move-Item -LiteralPath $_.FullName -Destination $target -Force
                }
            }
        } finally {
            Remove-Item -LiteralPath $stageDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    if (-not $WhatIfPreference) {
        $exe = Join-Path $ventoyDir 'Ventoy2Disk.exe'
        if (-not (Test-Path -LiteralPath $exe)) {
            Write-Failure -Name 'Ventoy' -Detail 'Ventoy2Disk.exe missing after extraction.' -Manual @(
                "Extract $zipPath into $ventoyDir by hand."
            )
            return $false
        }
        if ($CleanDownloads -and $PSCmdlet.ShouldProcess($zipPath, 'Remove Ventoy zip')) {
            Remove-Item -LiteralPath $zipPath -Force
        }
    }
    return $true
}

# Downloads the latest Rufus portable exe (no published hash; only a failed
# download records a failure) plus Fido.ps1 into tools\. Never throws.
function Save-RufusTools {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Root)
    $toolsDir = Join-Path $Root 'tools'
    Ensure-Directory -Path $toolsDir
    $ok = $true
    $release = Get-GitHubLatestAsset -Repo 'pbatard/rufus' -AssetPattern '^rufus-.*p\.exe$'
    if (-not $release) {
        $ok = $false
    } else {
        Write-Warning 'Rufus publishes no hash; the exe is kept as downloaded.'
        if (-not (Save-VerifiedFile -Url $release.ZipUrl -OutFile (Join-Path $toolsDir $release.Name) -Name 'Rufus portable')) { $ok = $false }
    }
    $fidoPath = Join-Path $toolsDir 'Fido.ps1'
    if (Test-Path -LiteralPath $fidoPath) {
        Write-Ok 'Skipped (present): Fido.ps1'
        $script:Results += [pscustomobject]@{ Name = 'Fido.ps1'; Status = 'Skipped'; Detail = 'present, no hash to check' }
    } else {
        if ($PSCmdlet.ShouldProcess($fidoPath, "Download $($script:FidoUrl)")) {
            if (Invoke-FileDownload -Url $script:FidoUrl -OutFile $fidoPath) {
                Write-Ok 'Downloaded: Fido.ps1'
                $script:Results += [pscustomobject]@{ Name = 'Fido.ps1'; Status = 'Downloaded'; Detail = 'unverified upstream script' }
            } else {
                Write-Failure -Name 'Fido.ps1' -Detail "Download failed: $($script:FidoUrl)" -Manual @(
                    "Save $($script:FidoUrl) into $fidoPath by hand."
                )
                $ok = $false
            }
        }
    }
    return $ok
}

# Finds official Windows ISOs in the installers folder, newest first.
# Matches Fido-style names (Win11_*.iso) and official Microsoft names
# (en-us_windows_11_*.iso). Never matches the tiny11\ build output.
function Find-WindowsIso([string]$InstallersDir) {
    @(Get-ChildItem -LiteralPath $InstallersDir -Filter '*.iso' -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(Win11|Win10|en-us_windows_1[01])' } | Sort-Object LastWriteTime -Descending)
}

# Resolves an official Windows 11 ISO URL through Fido headless and downloads
# it into isos\03-Installers\. Microsoft links expire, so no hash is pinned:
# only a failed step records a failure. Never throws.
function Get-WindowsIsoViaFido {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Root)
    $installersDir = Join-Path (Join-Path $Root 'isos') '03-Installers'
    Ensure-Directory -Path $installersDir
    $existing = Find-WindowsIso -InstallersDir $installersDir
    if ($existing.Count -gt 0) {
        Write-Ok "Skipped (present): $($existing[0].Name)"
        $script:Results += [pscustomobject]@{ Name = 'Windows 11 ISO'; Status = 'Skipped'; Detail = $existing[0].Name }
        return $true
    }
    $fidoPath = Join-Path (Join-Path $Root 'tools') 'Fido.ps1'
    if (-not (Test-Path -LiteralPath $fidoPath)) {
        Write-Failure -Name 'Windows 11 ISO' -Detail 'Fido.ps1 is missing; cannot resolve the Microsoft URL.' -Manual @(
            'Open https://www.microsoft.com/en-US/software-download/Windows11 and download the ISO by hand,',
            "then place the Windows ISO (Win11_*.iso or en-us_windows_11_*.iso) into $installersDir."
        )
        return $false
    }
    if (-not $PSCmdlet.ShouldProcess($installersDir, 'Resolve Windows 11 URL via Fido and download')) { return $true }
    $powerShellPath = (Get-Process -Id $PID -ErrorAction Stop).MainModule.FileName
    # Fido reports errors via Write-Host (child stdout), not stderr; keep the
    # tail for the failure detail. Retry a few times with a pause: Microsoft's
    # Sentinel rate-limits the download-links endpoint transiently.
    $url = ''
    $lastOutput = ''
    $attempts = 3
    for ($n = 1; $n -le $attempts; $n++) {
        $result = Invoke-Cli -Command $powerShellPath -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $fidoPath, '-Win', 'Windows 11', '-Rel', 'Latest', '-Lang', 'English', '-Arch', 'x64', '-GetUrl')
        $url = @($result.StdOut -split "`r?`n" | Where-Object { $_ -match '^https?://' } | ForEach-Object { $_.Trim() }) | Select-Object -Last 1
        if ($result.ExitCode -eq 0 -and $url) { break }
        $lastOutput = (($result.StdOut + "`n" + $result.StdErr).Trim() | Select-Object -Last 1)
        if ($lastOutput.Length -gt 300) { $lastOutput = '...' + $lastOutput.Substring($lastOutput.Length - 300) }
        if ($n -lt $attempts) { Start-Sleep -Seconds 10 }
        $url = ''
    }
    if (-not $url) {
        $detail = if ($lastOutput) { "Fido printed no URL. Last output: $lastOutput" } else { 'Fido printed no URL.' }
        Write-Failure -Name 'Windows 11 ISO' -Detail "Fido resolution failed: $detail" -Manual @(
            'Open https://www.microsoft.com/en-US/software-download/Windows11 and download the ISO by hand,',
            "then place the Windows ISO (Win11_*.iso or en-us_windows_11_*.iso) into $installersDir."
        )
        return $false
    }
    $leaf = ($url.Split('?')[0].Split('/') | Where-Object { $_ } | Select-Object -Last 1)
    if (-not $leaf -or $leaf -notmatch '\.iso$') { $leaf = 'Win11.iso' }
    if ($leaf -notmatch '^Win') { $leaf = 'Win11_' + $leaf }
    Write-Warning 'Microsoft links expire, so the Windows ISO is kept without hash verification.'
    return (Save-VerifiedFile -Url $url -OutFile (Join-Path $installersDir $leaf) -Name 'Windows 11 ISO')
}

# Downloads the tiny11builder release zip (verified) plus the legacy
# tiny11maker.ps1 build script, then runs the privileged build: mount the
# official ISO, run the maker, move tiny11.iso into isos\03-Installers\tiny11.
# Without -Elevate (or without inline sudo) records a skip-failure instead of
# prompting. Never throws.
function Invoke-Tiny11Build {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Root, [switch]$Elevate, [switch]$CleanDownloads)
    $builderDir = Join-Path (Join-Path $Root 'tools') 'tiny11builder'
    Ensure-Directory -Path $builderDir
    $release = Get-GitHubLatestAsset -Repo 'ntdevlabs/tiny11builder' -AssetPattern '^Tiny11Builder-.*-win-x64\.zip$' -HashSuffix '.sha256'
    if (-not $release) { return $false }
    if (-not $release.HashUrl) {
        Write-Failure -Name 'Tiny11 builder' -Detail 'Release has no published .sha256 sidecar.' -Manual @(
            'Download the builder by hand from https://github.com/ntdevlabs/tiny11builder/releases/latest,',
            'mount the official Windows ISO, and run tiny11maker.ps1 -ISO <letter> -SCRATCH <letter> as admin.'
        )
        return $false
    }
    try {
        $hashText = Invoke-WebText -Uri $release.HashUrl
    } catch {
        $detail = if ($_.Exception) { $_.Exception.Message } else { "$_" }
        Write-Failure -Name 'Tiny11 builder' -Detail "Hash download failed: $detail" -Manual @(
            'Download the builder by hand from https://github.com/ntdevlabs/tiny11builder/releases/latest,',
            'mount the official Windows ISO, and run tiny11maker.ps1 -ISO <letter> -SCRATCH <letter> as admin.'
        )
        return $false
    }
    $expected = Find-HashInChecksumText -Text "$hashText" -FileName $release.Name
    if (-not $expected) {
        Write-Failure -Name 'Tiny11 builder' -Detail "No checksum entry for $($release.Name)." -Manual @(
            'Download the builder by hand from https://github.com/ntdevlabs/tiny11builder/releases/latest,',
            'mount the official Windows ISO, and run tiny11maker.ps1 -ISO <letter> -SCRATCH <letter> as admin.'
        )
        return $false
    }
    $zipPath = Join-Path $builderDir $release.Name
    if (-not (Save-VerifiedFile -Url $release.ZipUrl -OutFile $zipPath -ExpectedHash $expected -Name 'Tiny11 builder')) { return $false }
    if ($PSCmdlet.ShouldProcess($builderDir, "Extract $($release.Name)")) {
        Expand-Archive -LiteralPath $zipPath -DestinationPath $builderDir -Force
    }
    if ($CleanDownloads -and -not $WhatIfPreference -and $PSCmdlet.ShouldProcess($zipPath, 'Remove Tiny11 zip')) {
        Remove-Item -LiteralPath $zipPath -Force
    }
    # The release zip ships the WinUI app; the scripted build uses the legacy
    # maker script from the same repo branch (no published hash for it).
    $makerPath = Join-Path $builderDir 'tiny11maker.ps1'
    if (-not (Test-Path -LiteralPath $makerPath)) {
        if (-not $PSCmdlet.ShouldProcess($makerPath, "Download $($script:Tiny11MakerUrl)")) { return $true }
        Write-Warning 'tiny11maker.ps1 has no published hash; review it before the elevated build runs.'
        if (-not (Invoke-FileDownload -Url $script:Tiny11MakerUrl -OutFile $makerPath)) {
            Write-Failure -Name 'Tiny11 builder' -Detail "tiny11maker.ps1 download failed." -Manual @(
                "Save $($script:Tiny11MakerUrl) into $makerPath by hand,",
                'mount the official Windows ISO, and run tiny11maker.ps1 -ISO <letter> -SCRATCH <letter> as admin.'
            )
            return $false
        }
    }
    $installersDir = Join-Path (Join-Path $Root 'isos') '03-Installers'
    $tiny11Dir = Join-Path $installersDir 'tiny11'
    Ensure-Directory -Path $tiny11Dir
    $finalIso = Join-Path $tiny11Dir 'tiny11.iso'
    if (Test-Path -LiteralPath $finalIso) {
        Write-Ok 'Skipped (present): tiny11.iso'
        $script:Results += [pscustomobject]@{ Name = 'Tiny11 ISO'; Status = 'Skipped'; Detail = 'present' }
        return $true
    }
    $official = Find-WindowsIso -InstallersDir $installersDir
    if ($official.Count -eq 0) {
        Write-Failure -Name 'Tiny11 ISO' -Detail 'No official Windows ISO to build from.' -Manual @(
            'Place the official Windows ISO (Win11_*.iso or en-us_windows_11_*.iso) into 03-Installers first (Fido step above), then re-run.'
        )
        return $false
    }
    if (-not ($Elevate -and $script:UseSudo)) {
        Write-Failure -Name 'Tiny11 ISO' -Detail 'Privileged build skipped: no elevation.' -Manual @(
            'Re-run with -Elevate after enabling inline sudo,',
            "or mount $($official[0].Name) and run tiny11maker.ps1 -ISO <letter> -SCRATCH <letter> from an elevated shell,"
        )
        return $false
    }
    if (-not $PSCmdlet.ShouldProcess($finalIso, 'Mount official ISO and run tiny11maker.ps1 elevated')) { return $true }
    # Pre-stage autounattend.xml next to the maker: the script fetches it from a
    # deleted 'main' branch (404) when absent, and deletes it when it finishes.
    $answerPath = Join-Path $builderDir 'autounattend.xml'
    if (-not (Test-Path -LiteralPath $answerPath)) {
        if (-not (Invoke-FileDownload -Url $script:Tiny11AnswerUrl -OutFile $answerPath)) {
            Write-Failure -Name 'Tiny11 ISO' -Detail 'autounattend.xml download failed.' -Manual @(
                "Save $($script:Tiny11AnswerUrl) into $answerPath by hand, then re-run."
            )
            return $false
        }
    }
    # Pre-stage oscdimg.exe the same way: the maker downloads it with
    # Invoke-WebRequest (no timeout) when neither the ADK nor the local copy
    # exists, which can stall the elevated child forever. The maker deletes
    # it when it finishes, so re-stage it on every run.
    $oscdimgPath = Join-Path $builderDir 'oscdimg.exe'
    $adkOscdimg = 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\x64\Oscdimg\oscdimg.exe'
    if (-not (Test-Path -LiteralPath $adkOscdimg) -and -not (Test-Path -LiteralPath $oscdimgPath)) {
        if (-not (Invoke-FileDownload -Url $script:OscdimgUrl -OutFile $oscdimgPath)) {
            Write-Failure -Name 'Tiny11 ISO' -Detail 'oscdimg.exe download failed.' -Manual @(
                "Save $($script:OscdimgUrl) into $oscdimgPath by hand, then re-run."
            )
            return $false
        }
    }
    $scratchLetter = ([IO.Path]::GetPathRoot($Root)).Substring(0, 1).ToUpperInvariant()
    $escapedIso = ($official[0].FullName).Replace("'", "''")
    $escapedMaker = ($makerPath).Replace("'", "''")
    $escapedFinal = ($finalIso).Replace("'", "''")
    # The child must NOT use 'Stop': the maker depends on non-terminating errors
    # (absent install.esd, already-removed packages, reg edits). 'Continue' keeps
    # the builder's own error tolerance; the try/catch here still reports failure.
    # Read-Host is shadowed so the two interactive prompts cannot hang or loop:
    # the image-index prompt gets the computed Pro index, everything else gets ''.
    # Unloads the five maker hives first so a re-run never edits a stale mount.
$buildText = @"
`$ErrorActionPreference = 'Continue'
foreach (`$hive in @('zCOMPONENTS','zDEFAULT','zNTUSER','zSOFTWARE','zSYSTEM')) {
    & reg unload "HKLM\`$hive" 2>`$null
}
function global:Read-Host([string]`$Prompt) {
    if (`$Prompt -match 'image index') {
        `$media = `$isoLetter + ':\sources\install.wim'
        if (-not (Test-Path -LiteralPath `$media)) { `$media = `$isoLetter + ':\sources\install.esd' }
        `$images = @(Get-WindowsImage -ImagePath `$media -ErrorAction SilentlyContinue)
        `$pick = @(`$images | Where-Object { `$_.ImageName -match 'Pro' }) | Select-Object -First 1
        if (-not `$pick) { `$pick = `$images | Select-Object -First 1 }
        if (`$pick) { return "`$(`$pick.ImageIndex)" }
    }
    return ''
}
`$isoImage = Mount-DiskImage -ImagePath '$escapedIso' -PassThru
`$isoLetter = (`$isoImage | Get-Volume).DriveLetter
try {
    & '$escapedMaker' -ISO `$isoLetter -SCRATCH $scratchLetter
} finally {
    Remove-Item 'function:Read-Host' -ErrorAction SilentlyContinue
    Dismount-DiskImage -ImagePath '$escapedIso' -ErrorAction SilentlyContinue
}
Move-Item -LiteralPath (Join-Path (Split-Path -LiteralPath '$escapedMaker') 'tiny11.iso') -Destination '$escapedFinal' -Force
"@
    try {
        Invoke-Elevated ([scriptblock]::Create($buildText))
    } catch {
        $detail = if ($_.Exception) { $_.Exception.Message } else { "$_" }
        Write-Failure -Name 'Tiny11 ISO' -Detail "Elevated build failed: $detail" -Manual @(
            "Mount $($official[0].Name) and run tiny11maker.ps1 -ISO <letter> -SCRATCH <letter> from an elevated shell,"
        )
        return $false
    }
    if (-not (Test-Path -LiteralPath $finalIso)) {
        Write-Failure -Name 'Tiny11 ISO' -Detail 'Build finished without producing tiny11.iso.' -Manual @(
            "Mount $($official[0].Name) and run tiny11maker.ps1 -ISO <letter> -SCRATCH <letter> from an elevated shell,"
        )
        return $false
    }
    Write-Ok 'Built: tiny11.iso'
    $script:Results += [pscustomobject]@{ Name = 'Tiny11 ISO'; Status = 'Downloaded'; Detail = 'built from official ISO' }
    return $true
}

# -----------------------------------------------------------------------------
# Orchestration.
# -----------------------------------------------------------------------------

# Prints the planned file set without touching the network or disk.
function Write-PlanTable {
    param([string]$NetbootArch = 'x64', [string]$MintHwe = 'None')
    Write-Section 'Planned recovery file set (WhatIf: nothing downloaded)'
    Write-Detail 'Tools: latest Ventoy Windows zip, latest Rufus portable, Fido.ps1, tiny11builder x64 zip + tiny11maker.ps1'
    Write-Detail 'Windows 11 ISO resolved live through Fido; Tiny11 built from it with -Elevate.'
    $rows = Get-RecoveryCatalog | Where-Object {
        (($_.NetbootVariant -eq '') -or ($_.NetbootVariant -eq $NetbootArch)) -and
        (($_.MintHwe -eq '') -or ($_.MintHwe -eq $MintHwe))
    }
    foreach ($row in $rows) {
        Write-Host ("  {0,-28} {1,-42} {2}" -f $row.Category, $row.FileName, $row.SizeNote)
    }
}
# Writes a maintained text block to the tree (BOMless UTF-8, CRLF endings).
# Runs under ShouldProcess so -WhatIf writes nothing. Never throws.
function Write-ReadmeFile {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Path, [string]$Text)
    if (-not $PSCmdlet.ShouldProcess($Path, 'Write readme')) { return }
    try {
        [IO.File]::WriteAllText($Path, ($Text -replace "`r`n", "`n").Replace("`n", "`r`n"), [Text.UTF8Encoding]::new($false))
    } catch {
        $detail = if ($_.Exception) { $_.Exception.Message } else { "$_" }
        Write-Failure -Name (Split-Path -Leaf $Path) -Detail "Readme write failed: $detail" -Manual @(
            "Create $Path by hand; the tree works without it."
        )
    }
}

# Prints the summary table plus the consolidated manual-retry block. Returns
# 1 when any failure was recorded, else 0.
function Write-Summary {
    Write-Section 'Summary'
    $downloaded = @($script:Results | Where-Object { $_.Status -eq 'Downloaded' }).Count
    $skipped = @($script:Results | Where-Object { $_.Status -eq 'Skipped' }).Count
    $failed = @($script:Results | Where-Object { $_.Status -eq 'Failed' }).Count
    Write-Host ("  Downloaded: {0}   Skipped (verified): {1}   Failed: {2}" -f $downloaded, $skipped, $failed)
    foreach ($entry in ($script:Results | Where-Object { $_.Status -eq 'Failed' })) {
        Write-Host "  FAILED: $($entry.Name) -- $($entry.Detail)" -ForegroundColor Red
    }
    if ($script:Failures.Count -eq 0) {
        Write-Ok 'All entries ready.'
        return 0
    }
    Write-Host ''
    Write-Host 'Manual retry for the failed entries:' -ForegroundColor Yellow
    foreach ($failure in $script:Failures) {
        Write-Host "  * $($failure.Name)" -ForegroundColor Yellow
        foreach ($line in ($failure.Manual -split "`n")) {
            if ($line) { Write-Host "    $line" -ForegroundColor Yellow }
        }
    }
    return 1
}

# Main flow: folders, Ventoy, Rufus/Fido, catalog ISOs, Windows ISO, Tiny11.
# Returns the process exit code (0 clean, 1 with failures). Never throws out.
function Invoke-PreparePcRecovery {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$Root = (Join-Path $env:USERPROFILE 'Tools\pc-recovery'),
        [string]$NetbootArch = 'x64',
        [string]$MintHwe = 'None',
        [switch]$CleanDownloads,
        [switch]$SkipTiny11,
        [switch]$Elevate
    )
    $savedEncoding = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = [Text.Encoding]::UTF8
        if (-not $PSCmdlet.ShouldProcess($Root, 'Download and verify the recovery USB file set')) {
            Write-PlanTable -NetbootArch $NetbootArch -MintHwe $MintHwe
            return 0
        }
        Write-Section "Preparing recovery files in $Root"
        $script:VerifiedHashes = @{}
        Initialize-ElevationState -Elevate:$Elevate
        Ensure-Directory -Path $Root
        Ensure-Directory -Path (Join-Path $Root 'tools')
        Ensure-Directory -Path (Join-Path $Root 'ventoy')
        Ensure-Directory -Path (Join-Path (Join-Path $Root 'isos') '01-Network')
        Ensure-Directory -Path (Join-Path (Join-Path $Root 'isos') '02-Rescue')
        Ensure-Directory -Path (Join-Path (Join-Path $Root 'isos') '03-Installers')
        Ensure-Directory -Path (Join-Path (Join-Path $Root 'isos') '04-etc')
        Write-ReadmeFile -Path (Join-Path $Root 'README.txt') -Text (Get-RootReadmeText -WrittenUtc ((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm') + ' UTC'))
        Write-Step 'Ventoy media tool'
        Invoke-SafeStep -Name 'Ventoy' -Manual @('See the failure message above for the manual Ventoy steps.') -Body {
            Install-Ventoy -Root $Root -CleanDownloads:$CleanDownloads | Out-Null
        }
        Write-Step 'Rufus portable + Fido'
        Invoke-SafeStep -Name 'Rufus + Fido' -Manual @('Download portable Rufus from https://rufus.ie/ into tools\ by hand.') -Body {
            Save-RufusTools -Root $Root | Out-Null
        }
        Write-Step 'Catalog ISOs (netboot first)'
        Save-CatalogIsos -Root $Root -NetbootArch $NetbootArch -MintHwe $MintHwe
        Write-Step 'Windows 11 ISO via Fido'
        Invoke-SafeStep -Name 'Windows 11 ISO' -Manual @('Open https://www.microsoft.com/en-US/software-download/Windows11 and place the Windows ISO (Win11_*.iso or en-us_windows_11_*.iso) into isos\03-Installers\.') -Body {
            Get-WindowsIsoViaFido -Root $Root | Out-Null
        }
        if (-not $SkipTiny11) {
            Write-Step 'Tiny11 build'
            Invoke-SafeStep -Name 'Tiny11 ISO' -Manual @('Mount the official ISO and run tiny11maker.ps1 -ISO <letter> -SCRATCH <letter> from an elevated shell.') -Body {
                Invoke-Tiny11Build -Root $Root -Elevate:$Elevate -CleanDownloads:$CleanDownloads | Out-Null
            }
        } else {
            Write-Detail 'Tiny11 build skipped by -SkipTiny11.'
        }
        # Refresh the isos readme: one block per selected catalog row (with
        # the on-disk hash when present), then the two non-catalog entries
        # (official Windows ISO, Tiny11 output) hashed the same way, so the
        # file is a self-contained verification sheet for the real tree.
        $isoBlocks = Get-RecoveryCatalog | Where-Object {
            (($_.NetbootVariant -eq '') -or ($_.NetbootVariant -eq $NetbootArch)) -and
            (($_.MintHwe -eq '') -or ($_.MintHwe -eq $MintHwe))
        } | ForEach-Object { Format-IsoReadmeEntry -Row $_ -Root $Root }
        $installersDir = Join-Path (Join-Path $Root 'isos') '03-Installers'
        $winIso = Find-WindowsIso -InstallersDir $installersDir | Select-Object -First 1
        if ($winIso) {
            $isoBlocks += (Format-ManualIsoReadmeEntry -Title 'Official Windows 11 ISO' -Path $winIso.FullName -Folder '03-Installers' -Note 'Kept as downloaded; Microsoft links expire, so no hash is pinned in the catalog.' -Root $Root)
        } else {
            $isoBlocks += '== Official Windows 11 ISO (not present) ==' + "`r`n" + 'Resolve via Fido or place Win11_*.iso / en-us_windows_11_*.iso by hand.'
        }
        $tinyIso = Join-Path (Join-Path $installersDir 'tiny11') 'tiny11.iso'
        if (Test-Path -LiteralPath $tinyIso) {
            $tinyNote = 'Built by tiny11builder (legacy tiny11maker.ps1 script) from the official ISO above. Removes bundled apps (Clipchamp, News, Weather, Xbox, Teams, Copilot hooks), Edge/WebView2 binaries, OneDrive setup, and sponsored tasks; keeps Windows Update, Defender, WinRE, the Store, and shared runtimes. Practical limits: some removals need a reinstall of that app from the Store or Winget (Edge: reinstall from microsoft.com if a web-dependent installer needs it); hardware-check bypasses are baked in, so in-place upgrades on unsupported PCs stay possible but are untested; no product key is injected -- activate with your own license. Full parity IS recoverable through Windows Update afterwards for anything still serviced, but removed provisioned apps do not come back on their own -- reinstall them explicitly. Always test-boot the ISO (VM or spare stick) before relying on it.'
            $isoBlocks += (Format-ManualIsoReadmeEntry -Title 'Tiny11 ISO (built locally)' -Path $tinyIso -Folder '03-Installers\tiny11' -Note $tinyNote -Root $Root)
        } else {
            $isoBlocks += '== Tiny11 ISO (not present) ==' + "`r`n" + 'Build with -Elevate once the official ISO is present.'
        }
        Write-ReadmeFile -Path (Join-Path (Join-Path $Root 'isos') 'README.txt') -Text ((Get-IsosReadmeTemplate -WrittenUtc ((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm') + ' UTC')) -f ($isoBlocks -join "`r`n`r`n"))
        return (Write-Summary)
    } finally {
        [Console]::OutputEncoding = $savedEncoding
    }
}

$script:Catalog = Get-RecoveryCatalog

if ($MyInvocation.InvocationName -ne '.') {
    exit (Invoke-PreparePcRecovery -Root $Root -NetbootArch $NetbootArch -MintHwe $MintHwe -CleanDownloads:$CleanDownloads -SkipTiny11:$SkipTiny11 -Elevate:$Elevate)
}
