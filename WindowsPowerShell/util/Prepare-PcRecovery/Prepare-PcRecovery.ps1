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
    build can run on top of it when elevation is available. Firefox ESR
    (en-US, x64) is resolved live for Tiny11/Windows 11 where Edge is removed;
    a pinned release is the fallback when the live lookup fails.

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
    Mint image (without HWE version) is fetched by default.
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
    Copyright (c) 2026 @thejjw. All rights reserved.
    Last Updated: November 16, 2026

    Catalog: per-ISO About / Released / SizeNote / Hash / Check rows in
    Get-RecoveryCatalog. Re-pin Pinned rows only (Hash + Released +
    SizeNote together); Rolling rows resolve live, Manual rows are
    handled by dedicated functions. Dates come from checksum headers,
    SourceForge file dates, or the project page -- never guess.
    HWE Mint rows share the kernel.org tree; one AlternateUrl pattern
    covers all three (kernel.org stalls large ISOs: Princeton fallback).
    Sentinel may refuse Fido per IP: "Sentinel marked this request as
    rejected" is transient (retried 3x), then place the ISO by hand.
    Elevation: sudo.exe inline mode raises a UAC consent dialog and waits;
    unattended -Elevate runs need elevate-without-prompting
    (ConsentPromptBehaviorAdmin 0) or they hang there with no output.
    Partials: keep on transport failure (curl 18/28/33/52/55/56), delete
    only on server reject (22/36), so -C - resumes.
    Tiny11: scripted build is maker (28 KB) + oscdimg (140 KB) + answer
    file (2 KB), staged per run; the 95 MB WinUI zip is hash context
    only and never runs. Child uses 'Continue', shadowed Read-Host,
    unloaded HKLM\z* hives.
    Python rows: pinned to python.org 3.15.2 (Oct 2026). 3.16+ stop shipping
    the traditional Windows installer (PEP 773 / Python install manager), so
    drop the installer row then; the embeddable zip stays. Re-pin Hash +
    Released + SizeNote together.
    Go/Node rows: pinned Go 1.27.4 and Node.js LTS 26.13.1, Windows ZIP plus
    Linux tar.gz. Node's tar.gz avoids an xz extractor; re-pin version and
    hashes together.
    VNC rows: TigerVNC viewer + Linux X11 server; UltraVNC Windows server/
    viewer. The generic TigerVNC tarball has no w0vncserver; Wayland uses
    distro packages or built-in sharing.
    Maintenance: pinned rows are snapshots. Follow the re-pin checklist in
    the Get-RecoveryCatalog header and the Check text on each row.
    Firefox ESR: resolves FIREFOX_ESR live from product-details.mozilla.org
    and verifies the release SHA256SUMS (publisher checksum). The pinned
    153.7.0esr release is the fallback ONLY when the metadata or checksum
    lookup fails; refresh that pin when ESR 153 leaves support. The EXE is
    about 86 MB; old installers stay in isos\04-etc\firefox\ and are deleted
    by hand after a newer one verifies.
    Suite: Invoke-Pester .\tests\Prepare-PcRecovery.Tests.ps1 (offline).
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
# Shared names: one edit point when Microsoft renames files or the tree layout
# changes. Folder names are bare (no slashes); file names are exact leaves.
$script:DirTools = 'tools'
$script:DirVentoy = 'ventoy'
$script:DirIsos = 'isos'
$script:DirInstallers = '03-Installers'
$script:DirTiny11 = 'tiny11'
$script:DirBuilder = 'tiny11builder'
$script:DirCopyparty = 'copyparty'
$script:DirPython = 'python'
$script:DirSevenZip = '7zip'
$script:DirPutty = 'putty'
$script:DirWinScp = 'winscp'
$script:DirCyberduck = 'cyberduck'
$script:DirTabby = 'tabby'
$script:PyVersion = '3.15.2'
$script:PyUrlBase = 'https://www.python.org/ftp/python/' + $script:PyVersion + '/'
$script:FilePythonInstaller = 'python-' + $script:PyVersion + '-amd64.exe'
$script:FilePythonEmbed = 'python-' + $script:PyVersion + '-embed-amd64.zip'
$script:SevenZipVersion = '26.06'
$script:SevenZipUrlBase = 'https://github.com/ip7z/7zip/releases/download/' + $script:SevenZipVersion + '/'
$script:FileSevenZipInstaller = '7z' + $script:SevenZipVersion.Replace('.', '') + '-x64.exe'
$script:FileSevenZipExtra = '7z' + $script:SevenZipVersion.Replace('.', '') + '-extra.7z'
$script:FileSevenZipBootstrap = '7zr-' + $script:SevenZipVersion.Replace('.', '') + '.exe'
$script:PuttyVersion = '0.85'
$script:PuttyUrlBase = 'https://the.earth.li/~sgtatham/putty/' + $script:PuttyVersion + '/w64/'
$script:FilePuttyZip = 'putty-' + $script:PuttyVersion + '.zip'
$script:FilePuttySums = 'putty-' + $script:PuttyVersion + '-sha256sums.txt'
$script:WinScpVersion = '6.7.1'
$script:WinScpUrlBase = 'https://sourceforge.net/projects/winscp/files/WinSCP/' + $script:WinScpVersion + '/'
$script:FileWinScpPortable = 'WinSCP-' + $script:WinScpVersion + '-Portable.zip'
$script:CyberduckVersion = '9.6.0.46406'
$script:CyberduckUrlBase = 'https://update.cyberduck.io/windows/'
$script:CyberduckGitHubUrlBase = 'https://github.com/iterate-ch/cyberduck/releases/download/release-9-6-0/'
$script:FileCyberduckInstaller = 'Cyberduck-Installer-' + $script:CyberduckVersion + '.exe'
$script:FileCyberduckDuck = 'duck_' + $script:CyberduckVersion + '_amd64.deb'
$script:FileCyberduckDuckRpm = 'duck-' + $script:CyberduckVersion + '-1.x86_64.rpm'
$script:CyberduckDownloadPage = 'https://cyberduck.io/download/'
$script:TabbyVersion = '1.0.238'
$script:TabbyUrlBase = 'https://github.com/Eugeny/tabby/releases/download/v' + $script:TabbyVersion + '/'
$script:FileTabbyZip = 'tabby-' + $script:TabbyVersion + '-portable-x64.zip'
$script:FileTabbyDeb = 'tabby-' + $script:TabbyVersion + '-linux-x64.deb'
$script:FileTabbyRpm = 'tabby-' + $script:TabbyVersion + '-linux-x64.rpm'
# Go and Node.js LTS: portable x64 toolchains for Windows and Linux. Linux
# artifacts are .tar.gz (Node also publishes .tar.xz) so extraction needs only
# tar/gzip, not xz. Re-pin version and both hashes together.
$script:DirGolang = 'golang'
$script:GoVersion = '1.27.4'
$script:GoReleased = '2026-11-10'
$script:GoUrlBase = 'https://go.dev/dl/'
$script:FileGoWindows = 'go' + $script:GoVersion + '.windows-amd64.zip'
$script:FileGoLinux = 'go' + $script:GoVersion + '.linux-amd64.tar.gz'
$script:GoWindowsSha256 = '178ab98950ac69ab25069307dc6ade79f3816e414cce95b4da166a115cde1e7e'
$script:GoLinuxSha256 = '7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840'
$script:DirNodeJs = 'nodejs'
$script:NodeVersion = '26.13.1'
$script:NodeLtsName = 'Lithium'
$script:NodeReleased = '2026-11-10'
$script:NodeUrlBase = 'https://nodejs.org/dist/v' + $script:NodeVersion + '/'
$script:FileNodeWindows = 'node-v' + $script:NodeVersion + '-win-x64.zip'
$script:FileNodeLinux = 'node-v' + $script:NodeVersion + '-linux-x64.tar.gz'
$script:FileNodeSums = 'SHASUMS256-node-v' + $script:NodeVersion + '.txt'
$script:NodeSumsUrl = $script:NodeUrlBase + 'SHASUMS256.txt'
$script:NodeWindowsSha256 = 'e2edda75bfb089654705cf65a13b58933bfd5f57148e8ebda916f58a2474f1f7'
$script:NodeLinuxSha256 = '518674de2b621728a5e4486f5fb3b7d2900bb3cc4aa97969edaa463db99f9778'
# VNC: TigerVNC viewer on both platforms plus the Linux X11 server; UltraVNC
# supplies the Windows server/viewer. The generic TigerVNC archive has no
# w0vncserver, so Wayland stays with distro packages or built-in sharing.
$script:DirTigerVnc = 'tigervnc'
$script:TigerVncVersion = '1.16.2'
$script:TigerVncReleased = '2026-03-26'
$script:TigerVncUrlBase = 'https://sourceforge.net/projects/tigervnc/files/stable/' + $script:TigerVncVersion + '/'
$script:FileTigerVncWindows = 'vncviewer64-' + $script:TigerVncVersion + '.exe'
$script:FileTigerVncLinux = 'tigervnc-' + $script:TigerVncVersion + '.x86_64.tar.gz'
$script:TigerVncViewerSha256 = '58396d99556026da6b906c9ed51ad6cb5c840cc3fb65e53653c52ca5a80bfad9'
$script:TigerVncLinuxSha256 = '5b70c84baefc09a030cfc78315c34ccb55b2a0dde4092b7da67a1962c5f0dea6'
$script:DirUltraVnc = 'ultravnc'
$script:UltraVncVersion = '1.8.3.2'
$script:UltraVncReleased = '2026-11-08'
$script:UltraVncUrlBase = 'https://uvnc.eu/download/1800/'
$script:FileUltraVncZip = 'UltraVNC_' + $script:UltraVncVersion.Replace('.', '') + '.zip'
$script:FileUltraVncInstaller = 'UltraVNC_' + $script:UltraVncVersion.Replace('.', '') + '_x64_Setup.exe'
$script:UltraVncZipSha256 = '8984e920169238de2a878ca3af71b7b8ac4feb3bbe295916dcd3ff1219456aad'
$script:UltraVncInstallerSha256 = 'ae1bb545c59e082620997d98589e3aef871e71494cb100144c95608c8323b4f7'
# CJK display font: one Regular OTF for Linux and Windows; the KR variant is
# the user-selected face. Pinned to a commit because upstream has no checksum.
$script:DirFonts = 'fonts'
$script:FileFont = 'NotoSansMonoCJKkr-Regular.otf'
$script:FileFontLicense = 'OFL.txt'
$script:FontCommit = '165c01b46ea533872e002e0785ff17e44f6d97d8'
$script:FontVersion = '2.004'
$script:FontReleased = '2021-04-30'
$script:FontSha256 = 'd5afed9988a28ae96afb0f4791754d3c9f4f08d08477eb1a7d6e2d905679a472'
$script:FontLicenseSha256 = '6a73f9541c2de74158c0e7cf6b0a58ef774f5a780bf191f2d7ec9cc53efe2bf2'
$script:FontRawUrl = 'https://raw.githubusercontent.com/notofonts/noto-cjk/' + $script:FontCommit + '/Sans/Mono/' + $script:FileFont
$script:FontLicenseUrl = 'https://raw.githubusercontent.com/notofonts/noto-cjk/' + $script:FontCommit + '/LICENSE'
$script:FontSourceUrl = 'https://github.com/notofonts/noto-cjk/blob/' + $script:FontCommit + '/Sans/Mono/' + $script:FileFont
# ImgBurn: the official host is the only first-party source; its installer
# carries OpenCandy, so it is extracted with 7-Zip and never executed or
# shipped. Hashes are pinned locally; the installer also matches the
# CRC32/MD5/SHA-1 published on imgburn.com.
$script:ImgBurnVersion = '2.5.8.0'
$script:ImgBurnReleased = '2013-06-16'
$script:ImgBurnUrl = 'https://download.imgburn.com/SetupImgBurn_' + $script:ImgBurnVersion + '.exe'
$script:FileImgBurnInstaller = 'SetupImgBurn_' + $script:ImgBurnVersion + '.exe'
$script:ImgBurnInstallerSha256 = '49aa06eaffe431f05687109fee25f66781abbe1108f3f8ca78c79bdec8753420'
$script:DirImgBurn = 'imgburn'
$script:FileImgBurnExe = 'ImgBurn.exe'
$script:FileImgBurnLauncher = 'ImgBurn Portable.cmd'
$script:FileImgBurnIni = 'ImgBurn.ini'
$script:ImgBurnPayload = [ordered]@{
    'ImgBurn.exe' = '02c74678128a9dfef58eab5abe269382c6b4862440c26c22cde7b83868f478f1'
    'ImgBurnPreview.exe' = '363f61889adaf3ee4bb95bda5f6d7cb1d7c906b61c310c8e98ad02717c5203f9'
    'ReadMe.txt' = '8b9d97c137459a495936af47f5140fe75f795728a30e9ec3d8ac9c1cb2e5c65f'
    'Sounds\Error.wav' = 'acad74b9bb57809e1b35bc06f357941986ebdc547ba33fc618f07e6e7bdc49bd'
    'Sounds\Success.wav' = '8dae19fc9c722a7fb169f37b5881e74551a8d3b8b43ec6f52b6d5d46e885ed6c'
}
# Firefox ESR: the version moves every few weeks. The flow resolves
# FIREFOX_ESR live and verifies the release SHA256SUMS; this pinned release is
# only the fallback when the metadata or checksum lookup fails.
$script:DirFirefox = 'firefox'
$script:FirefoxVersionsUrl = 'https://product-details.mozilla.org/1.0/firefox_versions.json'
$script:FirefoxReleasesUrl = 'https://ftp.mozilla.org/pub/firefox/releases/'
$script:FirefoxFallbackVersion = '153.7.0esr'
$script:FirefoxFallbackSha256 = '3d6fabd249aa1338c0667991fb73891fce941d7dc35ba278da24074874c67508'
$script:FirefoxFallbackReleased = '2026-11-10'
$script:FirefoxJsonUrl = 'https://product-details.mozilla.org/1.0/firefox.json'
$script:FileVentoyExe = 'Ventoy2Disk.exe'
$script:FileFido = 'Fido.ps1'
$script:FileRufusPatternNote = 'rufus-.*p\.exe'
$script:FileTiny11Iso = 'tiny11.iso'
$script:FileMaker = 'tiny11maker.ps1'
$script:FileAnswer = 'autounattend.xml'
$script:FileOscdimg = 'oscdimg.exe'
$script:FileFacts = 'filefacts.json'
$script:FileReadme = 'README.txt'
$script:FileCopypartySfx = 'copyparty-sfx.py'
$script:FileCopypartyExe = 'copyparty.exe'
$script:FileCopypartyTag = '.release'
# User-facing pointers: the official download page, the third-party fallback,
# and the accepted Windows ISO naming, shared by readmes and failure text.
$script:MsDownloadPage = 'https://www.microsoft.com/en-US/software-download/Windows11'
$script:ThirdPartyTip = 'TIP: visit https://massgrave.dev/ for third party downloads'
$script:WinIsoNaming = 'Win11_*.iso or en-us_windows_11_*.iso'
$script:RufusUrl = 'https://rufus.ie/'
$script:RufusReleasesHint = 'Download portable Rufus from https://rufus.ie/ into tools\ by hand.'
$script:VentoyReleasesUrl = 'https://github.com/ventoy/Ventoy/releases/latest'
$script:Tiny11BuilderReleasesUrl = 'https://github.com/ntdevlabs/tiny11builder/releases/latest'
$script:CopypartyApiUrl = 'https://api.github.com/repos/9001/copyparty/releases/latest'
$script:CopypartyReleasesUrl = 'https://github.com/9001/copyparty/releases/latest'
$script:CopypartyTagUrlBase = 'https://github.com/9001/copyparty/releases/tag/'
# Manual-retry text for the Tiny11 build. MakerHintManual takes the official
# ISO file name (or a placeholder) through -f.
$script:MakerHintAdmin = 'Run Enable-WindowsSudo in an elevated shell, then re-run with -Elevate; or mount the official ISO, save ' + $script:Tiny11AnswerUrl + ' as autounattend.xml next to tiny11maker.ps1, run it with -ISO <letter> -SCRATCH <letter> from an elevated shell, then move tiny11.iso into isos\03-Installers\tiny11\.'
$script:MakerHintSudo = 'Re-run with -Elevate from a normal shell after running Enable-WindowsSudo in an elevated one.'
$script:MakerHintManual = 'Save ' + $script:Tiny11MakerUrl + ' as tools\tiny11builder\tiny11maker.ps1 (skip if already there), mount {0}, save ' + $script:Tiny11AnswerUrl + ' as autounattend.xml next to it, run it with -ISO <letter> -SCRATCH <letter> from an elevated shell, then move tiny11.iso into isos\03-Installers\tiny11\.'
$script:Failures = @()
$script:Results = @()
$script:UseSudo = $false
$script:FirefoxRelease = $null
$script:FirefoxResolved = $null

# -----------------------------------------------------------------------------
# Maintained text blocks. These readmes are written into the download tree
# (root README.txt, isos\README.txt, isos\04-etc\<topic>\README.txt) on every
# run; edit the text inside these functions, not in the tree, so a re-run never
# loses the update. Functions are the loadable unit (tests dot-source functions
# only), so the text lives here instead of in top-level assignments. Keep ASCII,
# no BOM.
# -----------------------------------------------------------------------------


# Returns the current UTC time as the shared readme stamp.
function Get-UtcStamp {
    return [DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) + ' UTC'
}

# Builds the fixed metadata header used by the 04-etc topic sheets.
function Get-ReadmeHeader {
    param(
        [string]$RunStartedUtc,
        [string]$WrittenUtc,
        [string]$Package,
        [string]$Version,
        [string]$Released,
        [string]$Source,
        [string]$Trust,
        [string]$Note = ''
    )
    if (-not $RunStartedUtc -or -not $WrittenUtc) { throw 'Readme header requires RunStartedUtc and WrittenUtc.' }
    if (-not $Package -or -not $Version -or -not $Released -or -not $Source -or -not $Trust) {
        throw 'Readme header requires Package, Version, Released, Source, and Trust.'
    }
    $lines = @(
        "Run started: $RunStartedUtc",
        "Written:     $WrittenUtc",
        "Package:     $Package",
        "Version:     $Version",
        "Released:    $Released",
        "Source:      $Source",
        "Trust:       $Trust",
        'Hashes:      ..\..\README.txt (when the run completes)'
    )
    if ($Note) { $lines += "Note:        $Note" }
    $lines += ''
    $lines += 'Re-runs replace this file.'
    return ($lines -join "`r`n")
}

# Reads the short release date from the first catalog row in a category.
function Find-CatalogReleasedDate([string]$Category) {
    $row = Get-RecoveryCatalog | Where-Object { $_.Category -eq $Category } | Select-Object -First 1
    if (-not $row -or -not $row.Released) { return '' }
    if ($row.Released -match '(?i)Version\s+[^,]+,\s*([A-Za-z]+ \d{4})') { return $Matches[1] }
    return ''
}

# Returns the metadata for a pinned 04-etc topic.
function Get-TopicReadmeMeta([string]$Topic) {
    switch ($Topic) {
        'python' {
            $released = Find-CatalogReleasedDate '04-etc\python'
            if (-not $released) { $released = 'see catalog' }
            [pscustomobject]@{ Package = 'Python for Windows'; Version = $script:PyVersion; Released = $released; Source = $script:PyUrlBase; Trust = 'pinned SHA-256 (prep script); see INTEGRITY'; Note = '' }
        }
        '7zip' {
            $released = Find-CatalogReleasedDate '04-etc\7zip'
            if (-not $released) { $released = 'see catalog' }
            [pscustomobject]@{ Package = '7-Zip for Windows'; Version = $script:SevenZipVersion; Released = $released; Source = ('https://github.com/ip7z/7zip/releases/tag/' + $script:SevenZipVersion); Trust = 'GitHub asset SHA-256; see INTEGRITY'; Note = '' }
        }
        'putty' {
            $released = Find-CatalogReleasedDate '04-etc\putty'
            if (-not $released) { $released = 'see catalog' }
            [pscustomobject]@{ Package = 'PuTTY for Windows'; Version = $script:PuttyVersion; Released = $released; Source = $script:PuttyUrlBase; Trust = 'official sha256sums; see INTEGRITY'; Note = '' }
        }
        'winscp' {
            $released = Find-CatalogReleasedDate '04-etc\winscp'
            if (-not $released) { $released = 'see catalog' }
            [pscustomobject]@{ Package = 'WinSCP'; Version = $script:WinScpVersion; Released = $released; Source = $script:WinScpUrlBase; Trust = 'release ReadMe SHA-256; see INTEGRITY'; Note = '' }
        }
        'cyberduck' {
            $released = Find-CatalogReleasedDate '04-etc\cyberduck'
            if (-not $released) { $released = 'see catalog' }
            [pscustomobject]@{ Package = 'Cyberduck and duck'; Version = $script:CyberduckVersion; Released = $released; Source = $script:CyberduckDownloadPage; Trust = 'cyberduck.io pin + GitHub asset digests; see INTEGRITY'; Note = '' }
        }
        'tabby' {
            $released = Find-CatalogReleasedDate '04-etc\tabby'
            if (-not $released) { $released = 'see catalog' }
            [pscustomobject]@{ Package = 'Tabby'; Version = $script:TabbyVersion; Released = $released; Source = ('https://github.com/Eugeny/tabby/releases/tag/v' + $script:TabbyVersion); Trust = 'GitHub asset SHA-256; see INTEGRITY'; Note = '' }
        }
        'golang' {
            [pscustomobject]@{ Package = 'Go'; Version = $script:GoVersion; Released = $script:GoReleased; Source = $script:GoUrlBase; Trust = 'pinned SHA-256 from go.dev/dl; see INTEGRITY'; Note = '' }
        }
        'nodejs' {
            [pscustomobject]@{ Package = 'Node.js LTS'; Version = ($script:NodeVersion + ' (' + $script:NodeLtsName + ')'); Released = $script:NodeReleased; Source = $script:NodeUrlBase; Trust = 'pinned SHA-256 from SHASUMS256.txt; see INTEGRITY'; Note = '' }
        }
        'tigervnc' {
            [pscustomobject]@{ Package = 'TigerVNC'; Version = $script:TigerVncVersion; Released = $script:TigerVncReleased; Source = ('https://github.com/TigerVNC/tigervnc/releases/tag/v' + $script:TigerVncVersion); Trust = 'EXE Authenticode + pinned SHA-256; tarball first-download pin (no publisher checksum); see INTEGRITY'; Note = 'Windows viewer and Linux X11 viewer/server; no Windows server.' }
        }
        'ultravnc' {
            [pscustomobject]@{ Package = 'UltraVNC'; Version = $script:UltraVncVersion; Released = $script:UltraVncReleased; Source = 'https://uvnc.com/downloads/ultravnc/175-ultravnc-1-8-3-2.html'; Trust = 'official SHA-256 + Authenticode; see INTEGRITY'; Note = 'Windows server/viewer; use UltraVNC viewer for DSM, MS Logon, Repeater, or SC.' }
        }
        'fonts' {
            [pscustomobject]@{ Package = 'Noto Sans Mono CJK KR'; Version = $script:FontVersion; Released = $script:FontReleased; Source = $script:FontSourceUrl; Trust = ('pinned SHA-256 at noto-cjk commit ' + $script:FontCommit.Substring(0, 7) + ' (no upstream checksum); see INTEGRITY'); Note = '' }
        }
        'imgburn' {
            [pscustomobject]@{ Package = 'ImgBurn'; Version = $script:ImgBurnVersion; Released = $script:ImgBurnReleased; Source = $script:ImgBurnUrl; Trust = 'payload SHA-256 pin; see INTEGRITY'; Note = '' }
        }
        default { throw "Unknown readme topic: $Topic" }
    }
}

# Parses a GitHub published_at value into yyyy-MM-dd, accepting string or datetime.
function Format-ReleaseDate($Value) {
    if ($null -eq $Value -or "$Value" -eq '') { return '' }
    if ($Value -is [datetime]) {
        return $Value.ToUniversalTime().ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    }
    $parsed = [datetime]::MinValue
    $styles = [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        return $parsed.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    }
    return [string]$Value
}

# Builds copyparty metadata from the verified rows, not the lookup tag.
function Get-CopypartyReadmeMeta {
    $rows = @($script:CopypartyRows)
    $tag = ''
    $published = ''
    if ($rows.Count -gt 0) {
        $tag = [string]$rows[0].Tag
        $published = Format-ReleaseDate $rows[0].PublishedAt
    }
    if (-not $tag) {
        return [pscustomobject]@{
            Package = 'copyparty'
            Version = 'not verified this run'
            Released = 'unknown (not verified this run)'
            Source = $script:CopypartyReleasesUrl
            Trust = 'GitHub asset digest; see INTEGRITY'
            Note = 'No copyparty files verified this run; re-run online. Files from earlier runs may remain in this folder.'
        }
    }
    $missing = @()
    foreach ($name in @($script:FileCopypartySfx, $script:FileCopypartyExe)) {
        $verified = @($rows | Where-Object { $_.FileName -eq $name })
        if ($verified.Count -eq 0) { $missing += $name }
    }
    $note = ''
    if ($missing.Count -gt 0) { $note = 'not verified this run: ' + ($missing -join ', ') }
    if (-not $published) { $published = 'see GitHub release' }
    return [pscustomobject]@{
        Package = 'copyparty'
        Version = $tag
        Released = $published
        Source = $script:CopypartyTagUrlBase + $tag
        Trust = 'GitHub asset digest; see INTEGRITY'
        Note = $note
    }
}

# Builds Firefox metadata for staged, resolved-but-not-staged, or unresolved.
function Get-FirefoxReadmeMeta {
    $staged = $script:FirefoxRelease
    $resolved = $script:FirefoxResolved
    if ($staged) {
        $version = $staged.Version
        $released = $staged.Released
        $source = $staged.Url
        $note = ''
        if ($staged.Source -eq 'fallback') { $note = 'pinned fallback; live lookup failed' }
    } elseif ($resolved) {
        $version = $resolved.Version
        $released = $resolved.Released
        $source = $resolved.Url
        $note = 'resolved but not staged this run; re-run online to download it. Installers from earlier runs may remain in this folder; see ..\..\README.txt.'
        if ($resolved.Source -eq 'fallback') { $note = 'pinned fallback; live lookup failed; ' + $note }
    } else {
        $version = 'unresolved this run'
        $released = 'unknown (not resolved this run)'
        $source = $script:FirefoxReleasesUrl
        $note = 'no Firefox ESR version resolved this run; re-run online. Installers from earlier runs may remain in this folder; see ..\..\README.txt.'
    }
    if (-not $released) { $released = 'see Mozilla release notes' }
    return [pscustomobject]@{
        Package = 'Firefox ESR'
        Version = $version
        Released = $released
        Source = $source
        Trust = 'Mozilla SHA256SUMS; see INTEGRITY'
        Note = $note
    }
}

# Prepends the standard header to a topic template.
function Add-TopicReadmeHeader([string]$Text, $Meta, [string]$RunStartedUtc, [string]$WrittenUtc) {
    $header = Get-ReadmeHeader -RunStartedUtc $RunStartedUtc -WrittenUtc $WrittenUtc -Package $Meta.Package -Version $Meta.Version -Released $Meta.Released -Source $Meta.Source -Trust $Meta.Trust -Note $Meta.Note
    return $Text.Replace('{HEADER}', $header)
}

# What the destination root is and how to use it.

function Get-RootReadmeText {
    param([string]$WrittenUtc, [string]$RunStartedUtc = '')
    @"
PC RECOVERY USB - download tree
================================
Run started: $RunStartedUtc
This file was written $WrittenUtc.
Built by util/Prepare-PcRecovery/Prepare-PcRecovery.ps1. Re-running the script is safe: files
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
  isos\04-etc\       Post-boot utilities by topic: copyparty\ (portable file
                     server), imgburn\ (portable optical media burner and
                     imager), firefox\ (offline ESR browser for Tiny11),
                     fonts\ (one CJK display font for Linux/Windows),
                     cyberduck\ (cloud/SFTP GUI and duck CLI),
                     python\ (Windows x64), golang\ (Go), nodejs\
                     (Node.js LTS), tigervnc\ (VNC), ultravnc\ (VNC),
                     7zip\ (extractor), putty\, tabby\,
                     winscp\ (terminals and transfer clients).
  isos\README.txt    Per-folder contents, sizes, and re-verify notes.

WINDOWS 11 ISO
  Resolved in English (en-US) through Fido headless. Microsoft links expire,
  so it is kept without hash verification. If Fido is blocked, download from
  https://www.microsoft.com/en-US/software-download/Windows11 by hand and
  place the file (Win11_*.iso or en-us_windows_11_*.iso) into
  isos\03-Installers\.
  TIP: visit https://massgrave.dev/ for third party download

TINY11 BUILD
  Produces isos\03-Installers\tiny11\tiny11.iso from the official ISO.
  (iso filename is always tiny11.iso. the base image comes from Windows iso in ..\)
  Needs -Elevate (inline sudo pre-enabled) or an elevated shell.
  See tools\tiny11builder\ for the builder files used.

IMGBURN (OPTICAL MEDIA)
  isos\04-etc\imgburn\bin\ImgBurn.exe burns ISO images to CD/DVD/BD and
  creates images from discs. Start it through "ImgBurn Portable.cmd": that
  keeps settings in bin\ImgBurn.ini and writes nothing to the PC. The vendor
  installer is not shipped; its OpenCandy offer never runs.

FIREFOX ESR (OFFLINE)
  isos\04-etc\firefox\Firefox Setup <version>.exe is the en-US x64 ESR
  installer. Tiny11 removes Edge and WebView2; Firefox ESR supplies the
  browser (but not WebView2). The script resolves the current ESR live and
  verifies Mozilla's SHA256SUMS; a pinned ESR release is the fallback when
  that metadata or checksum lookup fails. Re-run online for a newer ESR.

PROGRAMMING ENVIRONMENTS
  isos\04-etc\golang\ and nodejs\ carry portable x64 Go and Node.js LTS
  toolchains for Windows and Linux. Extract the archive and add its bin
  folder to PATH; each README has the exact commands.

REMOTE DESKTOP (VNC)
  isos\04-etc\tigervnc\ has the cross-platform viewer and Linux X11 server.
  isos\04-etc\ultravnc\ has the Windows server and viewer, portable ZIP plus
  x64 installer. Use the UltraVNC viewer for UltraVNC/DSM/Repeater; use
  TigerVNC viewer for Linux/TLS. VNC is unencrypted unless TLS, DSM, or a
  tunnel is used. Prefer built-in RDP (mstsc) when the target edition supports it.
"@
}

# Per-folder contents of isos\. {0} is replaced with one block per ISO:
# project blurb, release, size, the SHA-256 known at write time, and how
# to re-verify. Hashes recorded here are a cheap local integrity check:
# compare with Get-FileHash before trusting a file, and re-check against
# the upstream source (the Re-verify line) when freshness matters.
function Get-IsosReadmeTemplate {
    param([string]$WrittenUtc, [string]$RunStartedUtc = '')
    @"
RECOVERY ISO SET
================
Run started: $RunStartedUtc
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
  04-etc\        Post-boot utilities by topic: copyparty\, cyberduck\,
                 firefox\, fonts\, golang\, imgburn\, nodejs\, python\,
                 tigervnc\, ultravnc\, 7zip\, putty\, tabby\, winscp\.

NOTES
  - Ventoy itself is a tool, not an ISO: see ..\ventoy\Ventoy2Disk.exe.
  - Windows and Tiny11 ISOs usually need Secure Boot off (or Ventoy's key
    enrolled); test before relying on them.
  - netboot.xyz needs a working network connection to be useful.
"@
}

# Usage sheet for isos\04-etc\copyparty\. Commands show the safe form: account,
# explicit bind address, read-only source, separate writable folder, and the
# index moved off read-only media.
function Get-CopypartyReadmeText {
    param([string]$RunStartedUtc, [string]$WrittenUtc)
    $text = @'
COPYPARTY - portable file server
================================
{HEADER}

FILES
  copyparty-sfx.py  Linux / macOS. Needs Python 2 or 3 (live images usually
                    have python3).
  copyparty.exe     Windows 8+ x64. Unsigned; Windows 8 also needs the Visual
                    C++ 2015 redistributable, Windows 10/11 do not.
  .release          Tag of the last release lookup; used to discard stale
                    .partial files when the release changes.

SAFE START (replace the address, paths, and password)
  Linux/macOS (sh/bash):
    python3 copyparty-sfx.py -p 3923 -i 192.168.1.10 -a admin:change-me \
      -v /mnt/data:data:r,admin -v /mnt/incoming:incoming:w,admin --hist /tmp/copyparty
  Windows (cmd.exe):
    copyparty.exe -p 3923 -i 192.168.1.10 -a admin:change-me ^
      -v C:\data:data:r,admin -v C:\incoming:incoming:w,admin --hist "%TEMP%\copyparty"
  Windows (PowerShell):
    .\copyparty.exe -p 3923 -i 192.168.1.10 -a admin:change-me `
      -v 'C:\data:data:r,admin' -v 'C:\incoming:incoming:w,admin' --hist "$env:TEMP\copyparty"

  Then browse to http://192.168.1.10:3923/data/ or /incoming/ and log in.

  Windows without Python: extract PYEMBED from ..\python\ into a writable
  folder such as $env:TEMP\pyembed, then run from this folder with the same
  safe arguments as above, only the interpreter differs:
    & "$env:TEMP\pyembed\python.exe" .\copyparty-sfx.py -p 3923 -i 192.168.1.10 `
      -a admin:change-me -v 'C:\data:data:r,admin' `
      -v 'C:\incoming:incoming:w,admin' --hist "$env:TEMP\copyparty"
  That runtime is a PSF-signed binary, unlike this unsigned copyparty.exe, so
  SmartScreen may treat it better. The embeddable build has no pip, venv, or
  tkinter.

INTEGRITY
  SHA-256 comes from the GitHub release asset digest; the isos README records
  the verified hash. Check a file with:
    Get-FileHash .\copyparty.exe -Algorithm SHA256
    Get-FileHash .\copyparty-sfx.py -Algorithm SHA256
  and compare with ..\..\README.txt or the GitHub release digest.

WARNING
  Starting it with no arguments shares the current folder read/write with
  everyone on every interface, port 3923. Always pass -a, -v, and -i.
  copyparty.exe has no code signature; expect SmartScreen and Windows
  Firewall prompts. Windows PE (Hiren's BootCD PE) is not supported.

NOTES
  - Volume syntax is -v SRC:DST:PERMS; each folder needs a distinct DST.
    r=read, w=write, m=move, d=delete; add a user to restrict, e.g. r,admin.
  - .hist holds the index and thumbnails; --hist keeps it off the USB.
  - Keep the USB mount read-only in -v unless you intend to write to it.
'@
    return Add-TopicReadmeHeader -Text $text.Replace('PYEMBED', $script:FilePythonEmbed) -Meta (Get-CopypartyReadmeMeta) -RunStartedUtc $RunStartedUtc -WrittenUtc $WrittenUtc
}

# Offline Python sheet for isos\04-etc\python\. Filenames come from the shared
# constants so a version bump is one edit point; the commands are the safe
# per-user form (no Store alias, no file associations, no shortcuts).
function Get-PythonReadmeText {
    param([string]$RunStartedUtc, [string]$WrittenUtc)
    $text = @'
PYTHON FOR WINDOWS (offline)
============================
{HEADER}

FILES
  PYINST          Full installer for Windows 10/11 x64.
  PYEMBED         Extract-and-run runtime, no installation.
  Linux live images normally ship python3; nothing here is needed there.

INSTALL (per-user, no admin; explicit target keeps the path predictable)
  cmd.exe:
    start "" /wait PYINST /quiet /log "%TEMP%\py-install.log" ^
      InstallAllUsers=0 TargetDir="%LOCALAPPDATA%\Programs\Python\Python315" ^
      Include_launcher=0 PrependPath=0 Include_test=0 AssociateFiles=0 Shortcuts=0
    echo %ERRORLEVEL%
  PowerShell:
    $installArgs = "/quiet /log `"$env:TEMP\py-install.log`" InstallAllUsers=0 " +
      "TargetDir=`"$env:LOCALAPPDATA\Programs\Python\Python315`" " +
      "Include_launcher=0 PrependPath=0 Include_test=0 AssociateFiles=0 Shortcuts=0"
    (Start-Process -Wait -PassThru -FilePath .\PYINST -ArgumentList $installArgs).ExitCode
  Run the result as %LOCALAPPDATA%\Programs\Python\Python315\python.exe, or add
  that folder to PATH yourself. With PrependPath=0 and Include_launcher=0, a
  bare "python" still opens the Microsoft Store alias.
  All-users install: from an elevated shell, InstallAllUsers=1 and a TargetDir
  under Program Files. Uninstall the same scope with PYINST /quiet /uninstall.

EMBEDDABLE (no installer)
  The zip cannot run in place. Extract PYEMBED into a writable folder (for
  example %TEMP%\pyembed, or a folder on the stick), then from that folder run:
    .\python.exe C:\path\to\yourscript.py
  PowerShell does not look in the current folder for python.exe, and a bare
  "python" still opens the Store alias. The build includes sqlite3 and ssl but
  no pip, venv, or tkinter. Its ._pth file keeps the script's own folder off
  sys.path, so use the full installer for anything that imports modules stored
  beside it. It does run copyparty-sfx.py from ..\copyparty\, which is a
  PSF-signed-binary alternative to the unsigned copyparty.exe.

INTEGRITY
  The prep script pins SHA-256 for both files. python.org publishes SPDX
  sidecars (PYINST.spdx.json and PYEMBED.spdx.json); their CPython package
  entry carries the same hash. The independent check is Authenticode:
  Get-AuthenticodeSignature on the installer, and on python.exe inside the zip,
  should report Valid with the Python Software Foundation as signer. Sigstore
  bundles are published next to each artifact. After a version bump, old
  python-* files stay in the folder; delete the previous pair.

NOTES
  - x64 builds run on Windows 11 ARM through emulation; 32-bit Windows is out
    of scope. Python 3.15 supports Windows 10 and newer; use 3.12 for 8.1.
  - WinPE is not supported (untested).
'@
    return Add-TopicReadmeHeader -Text $text.Replace('PYINST', $script:FilePythonInstaller).Replace('PYEMBED', $script:FilePythonEmbed).Replace('PYVER', $script:PyVersion) -Meta (Get-TopicReadmeMeta -Topic 'python') -RunStartedUtc $RunStartedUtc -WrittenUtc $WrittenUtc
}

# Offline 7-Zip sheet for isos\04-etc\7zip\. Filenames come from the shared
# constants so a version bump is one edit point; the install form needs admin,
# so the portable 7za path is documented next to it.
function Get-SevenZipReadmeText {
    param([string]$RunStartedUtc, [string]$WrittenUtc)
    $text = @'
7-ZIP FOR WINDOWS (offline)
===========================
{HEADER}

FILES
  7ZINST    x64 installer, about 1.6 MB. Installs and elevates itself.
  7ZEXTRA   portable extras archive, about 1.7 MB; contains 7za.exe.
  7ZR       bootstrap extractor, about 600 KB; reads .7z only.

INSTALL (needs admin; /S does not suppress UAC)
  cmd.exe:
    start "" /wait 7ZINST /S
    echo %ERRORLEVEL%
  PowerShell:
    (Start-Process -Wait -PassThru .\7ZINST '/S').ExitCode
  Default target is C:\Program Files\7-Zip. From a normal shell the installer
  raises a UAC prompt, and a standard user needs admin credentials. To change
  the target, append /D=<dir> as the last parameter (see the 7-Zip FAQ).
  Uninstall from an elevated shell:
    cmd.exe:    "%ProgramFiles%\7-Zip\Uninstall.exe" /S
    PowerShell: & "$env:ProgramFiles\7-Zip\Uninstall.exe" /S

PORTABLE (no admin; no install)
  cmd.exe:
    7ZR x 7ZEXTRA "-o%TEMP%\7za"
    "%TEMP%\7za\7za.exe" x archive.zip
  PowerShell:
    .\7ZR x .\7ZEXTRA "-o$env:TEMP\7za"
    & "$env:TEMP\7za\7za.exe" x archive.zip
  7za handles 7z, xz, bzip2, gzip, tar, and zip; no RAR, no ISO, and no
  Explorer context menu.

INTEGRITY
  SHA-256 is pinned in the prep script from the GitHub release digest. For the
  installer, that digest also equals the winget 7zip.7zip InstallerSha256 and
  the bytes served by 7-zip.org. The installer and the portables are unsigned:
  Authenticode reports NotSigned, which is expected; the hash is the check.
  7ZEXTRA and 7ZR are GitHub-only. Verify by hand with Get-FileHash.

NOTES
  - Check 7-zip.org for a newer build before installing on a networked PC; the
    hash is pinned to 7ZVER. Re-pinning leaves old 7z* files behind, so delete
    the previous set.
  - x64 runs on Windows 11 ARM through emulation, but the Explorer context menu
    may not appear in ARM64 Explorer.
  - License: LGPL-2.1-or-later with the unRAR restriction, plus BSD 3-clause
    parts. The installer carries the license text.
  - winget alternative (needs App Installer and network):
    winget install --id 7zip.7zip -e --accept-package-agreements --accept-source-agreements
'@
    return Add-TopicReadmeHeader -Text $text.Replace('7ZINST', $script:FileSevenZipInstaller).Replace('7ZEXTRA', $script:FileSevenZipExtra).Replace('7ZR', $script:FileSevenZipBootstrap).Replace('7ZVER', $script:SevenZipVersion) -Meta (Get-TopicReadmeMeta -Topic '7zip') -RunStartedUtc $RunStartedUtc -WrittenUtc $WrittenUtc
}

# Offline PuTTY sheet for isos\04-etc\putty\. One portable zip keeps the tools
# together with no install, PATH, or Start-menu changes; PuTTY still writes its
# own HKCU settings and seed file, and -cleanup removes them.
function Get-PuttyReadmeText {
    param([string]$RunStartedUtc, [string]$WrittenUtc)
    $text = @'
PUTTY FOR WINDOWS (offline)
===========================
{HEADER}

FILES
  PUTTYZIP   portable bundle, about 3.9 MB; all tools, no installer.
  PUTTYSUMS  official checksums; GPG-signed upstream.

USE (no install, no admin)
  Extract beside this file:
    PowerShell:  Expand-Archive .\PUTTYZIP -DestinationPath .\bin
    Explorer:    right-click PUTTYZIP, choose Extract All, target .\bin
  Then run:
    .\bin\PUTTY.EXE
    .\bin\PLINK.EXE -V
  No install, PATH, or Start-menu changes. PuTTY still writes host keys and
  saved sessions to HKCU\Software\SimonTatham\PuTTY and a seed file to
  %LOCALAPPDATA%\PUTTY.RND by default. If PuTTY was never installed or used on
  this machine, run this before deleting bin:
    .\bin\PUTTY.EXE -cleanup
  It removes ALL of the current user's PuTTY settings, including saved
  sessions and known host keys from any installed copy (after a confirmation
  prompt). Skip it if PuTTY was already in use here.

TOOLS
  PUTTY.EXE    SSH, telnet, and serial GUI client (saved sessions).
  PLINK.EXE    Scripted SSH, suitable for batch files.
  PSCP.EXE     SCP file copy; PSFTP.EXE is the SFTP counterpart.
  PUTTYGEN.EXE Key generation; PAGEANT.EXE holds keys for the session.
  PUTTY.CHM    Built-in help.

INTEGRITY
  SHA-256 is pinned from the official sha256sums. Check by hand with
    Get-FileHash .\PUTTYZIP -Algorithm SHA256
  and compare with the w64/putty.zip line in PUTTYSUMS (the file is stored as
  PUTTYZIP, so the saved name will not match the line). The executables are
  Authenticode-valid with Simon Tatham as signer. The sums file's GPG signature
  and the release key are not staged; fetch both from the release page online
  if you need that check. On the first connection, compare the host-key
  fingerprint through a second channel.

NOTES
  - Telnet is plaintext; prefer SSH when the peer supports it.
  - Serial mode needs the COM port number (Device Manager, or the adapter's
    documentation); 115200 8N1 is a common default.
  - x64 runs on Windows 11 ARM through emulation; WinPE is untested.
  - MIT licensed. After a version bump the old putty-* zip stays in place;
    delete the previous one.
  - For GUI transfers and synchronize, see the WinSCP sheet in ..\winscp\;
    PuTTY stays the terminal, serial, and key tool.

'@
    return Add-TopicReadmeHeader -Text $text.Replace('PUTTYSUMS', $script:FilePuttySums).Replace('PUTTYZIP', $script:FilePuttyZip) -Meta (Get-TopicReadmeMeta -Topic 'putty') -RunStartedUtc $RunStartedUtc -WrittenUtc $WrittenUtc
}

# Offline WinSCP sheet for isos\04-etc\winscp\. Portable GUI plus scripting for
# SFTP/SCP/FTP/FTPS/WebDAV/S3; no install, and the INI keeps settings on the
# stick instead of the host registry.
function Get-WinScpReadmeText {
    param([string]$RunStartedUtc, [string]$WrittenUtc)
    $text = @'
WINSCP FOR WINDOWS (offline)
============================
{HEADER}

FILES
  WINSZIP   portable package, about 8.4 MB; extracts to about 20 MB.

USE (no install, no admin)
  Extract beside this file:
    PowerShell:  Expand-Archive .\WINSZIP -DestinationPath .\bin
    Explorer:    right-click WINSZIP, choose Extract All, target .\bin
  Write the portable settings before the first run (edit the INI only while
  WinSCP is closed):
    $ini = @(
      '[Configuration\Interface]'
      'RandomSeedFile=%WINSCP_PATH%\winscp.rnd'
      'DDTemporaryDirectory=%WINSCP_PATH%\temp\'
    )
    Set-Content .\bin\WinSCP.ini $ini
  Then start the GUI or the scriptable console:
    .\bin\WinSCP.exe
    .\bin\WinSCP.com /ini=nul /log=%TEMP%\winscp.log /script=job.txt
  WinSCP uses /ini=, /log=, and /script= with an equals sign. With /ini=nul
  there is no host-key cache, so an open command needs
  -hostkey="ssh-ed25519 255 <fingerprint>" in the script.

PROTOCOLS
  SFTP, SCP, FTP, FTPS, WebDAV, and S3; synchronize, resumable transfer queue,
  remote file editing, and drag-and-drop.

PUTTY INTEGRATION
  Import existing PuTTY sessions with Tools > Import Sites. For "Open in PuTTY",
  set Preferences > Integration > Applications > PuTTY/Terminal Client Path to
  %WINSCP_PATH%\..\..\putty\bin\PUTTY.EXE.
  PuTTY remains the terminal/serial/key tool; WinSCP is the file manager.

STORAGE AND CLEANUP
  The INI written in USE keeps the seed and temp files under bin, so the setup
  stays on the stick. Without those settings WinSCP writes winscp.rnd to
  %USERPROFILE% and temporary files to %TEMP%. Relative paths resolve against
  the startup folder, while %WINSCP_PATH% always means the folder holding
  WinSCP.exe.
  If bin is read-only, WinSCP falls back to the registry; create the INI on a
  writable copy instead. Saved sessions, including passwords if you save them,
  live in .\bin\WinSCP.ini on the stick: do not save passwords on shared media,
  and delete bin before handing the stick over. WinSCP.com runs with
  /ini=nul ignore those settings, and /log=%TEMP%\winscp.log writes a session
  log (host names, user names, remote paths) to the host: delete it after
  scripted runs. On the host, Tools > Clean Up
  on the Login dialog removes selected data (INI, registry configuration,
  sites, caches, seed file, temp folders); if WinSCP was already installed on
  this PC, untick the registry entries.

INTEGRITY
  SHA-256 is pinned from the official WinSCP-WINSVER-ReadMe.txt. The zip itself
  is unsigned; WinSCP.exe and WinSCP.com inside are Authenticode-valid with
  Martin Prikryl as signer. Check by hand with
    Get-FileHash .\WINSZIP -Algorithm SHA256
  and compare with the release ReadMe at winscp.net.

NOTES
  - GPLv3. The x86 portable build runs on x64 and on Windows 11 ARM through
    emulation; WinPE is untested.
  - Check winscp.net for a newer build; after a version bump the old WinSCP-*
    zip stays in place, so delete the previous one.

'@
    return Add-TopicReadmeHeader -Text $text.Replace('WINSZIP', $script:FileWinScpPortable).Replace('WINSVER', $script:WinScpVersion) -Meta (Get-TopicReadmeMeta -Topic 'winscp') -RunStartedUtc $RunStartedUtc -WrittenUtc $WrittenUtc
}

# Offline Cyberduck sheet for isos\04-etc\cyberduck\. Windows needs an installer
# (no portable build); macOS builds and the Windows/macOS duck CLI exist
# upstream but are not stored here; the Linux x86_64 deb/rpm packages are.
function Get-CyberduckReadmeText {
    param([string]$RunStartedUtc, [string]$WrittenUtc)
    $text = @'
CYBERDUCK AND DUCK (offline)
============================
{HEADER}

FILES
  CYBERINSTALLER   Windows x64 GUI installer, about 88 MB.
  CYBERDEB         Linux x86_64 Debian/Ubuntu package, about 106 MB.
  CYBERRPM         Linux x86_64 Fedora/Rocky package, about 108 MB.

INSTALL
  Double-click CYBERINSTALLER and follow the wizard. For an unattended
  install, run:
    .\CYBERINSTALLER /s
  Windows 10 64-bit or later. Uninstall from Settings > Apps.
  Cyberduck publishes no portable Windows build: this is an installer, not an
  extract-and-run tool. A macOS build and the Windows/macOS duck CLI are on
  the download page; Linux uses the packages below.

LINUX CLI
  Both packages bundle their own Java runtime and need only glibc. Install on
  Debian or Ubuntu:
    sudo apt install ./CYBERDEB
    duck --version
  Install on Fedora or Rocky (repos off so it works offline):
    sudo dnf install --disablerepo='*' ./CYBERRPM
    duck --version
  If dnf is unavailable or fails, use rpm directly:
    sudo rpm -ivh ./CYBERRPM
    duck --version
  To run the deb without installing on any x86_64 Linux (binutils provides
  ar; tar needs zstd only when the member is data.tar.zst):
    d=$(mktemp -d "$HOME/duck.XXXXXX"); cd "$d"
    ar x /path/to/CYBERDEB
    tar -xf data.tar.*
    ./opt/duck/bin/duck --version
  The launcher finds its libraries relative to bin/duck, so the extracted
  opt/duck tree is relocatable. These packages are x86_64 only; arm64 builds
  are on the GitHub release page.

PROTOCOLS
  SFTP, FTP/FTPS, WebDAV, S3, Azure Blob, Backblaze B2, Google Drive, Dropbox,
  OneDrive, SharePoint, and OpenStack Swift; bookmarks, synchronize, and a
  transfer queue.

COMPARED WITH WINSCP
  WinSCP in ..\winscp\ is portable and Windows-only, with WinSCP.com scripting.
  Cyberduck's GUI needs an install but adds cloud backends and runs on macOS;
  the bundled duck CLI covers Linux. Use WinSCP for a no-install Windows
  transfer; use Cyberduck when you need the cloud services.

INTEGRITY
  The Windows installer's SHA-256 is pinned from the official cyberduck.io
  download page and matches the GitHub release asset digest; the installer is
  Authenticode-valid with iterate GmbH as signer. Check it with
    Get-FileHash .\CYBERINSTALLER -Algorithm SHA256
    Get-AuthenticodeSignature .\CYBERINSTALLER
  and compare with CYBERPAGE.
  The two duck packages are pinned from the GitHub release asset digests,
  which are also recorded in isos\README.txt. Check them on Linux with
    sha256sum CYBERDEB CYBERRPM

NOTES
  - GPLv3. The app shows a donation prompt; a contributor key or a store
    purchase disables it.
  - The Microsoft Store build is not an offline file; this installer is.
  - After a version bump the old Cyberduck-* installer and duck_*.deb or
    duck-*.rpm stay in place; delete the previous ones.

'@
    return Add-TopicReadmeHeader -Text $text.Replace('CYBERINSTALLER', $script:FileCyberduckInstaller).Replace('CYBERDEB', $script:FileCyberduckDuck).Replace('CYBERRPM', $script:FileCyberduckDuckRpm).Replace('CYBERPAGE', $script:CyberduckDownloadPage) -Meta (Get-TopicReadmeMeta -Topic 'cyberduck') -RunStartedUtc $RunStartedUtc -WrittenUtc $WrittenUtc
}

# Offline Tabby sheet for isos\04-etc\tabby\. Windows portable zip plus Linux
# deb/rpm; the Linux tarball and AppImage are deliberately not stored.
function Get-TabbyReadmeText {
    param([string]$RunStartedUtc, [string]$WrittenUtc)
    $text = @'
TABBY TERMINAL (offline)
========================
{HEADER}

FILES
  TABBYZIP   Windows x64 portable zip, about 177 MB; extracts to about 481 MB.
  TABBYDEB   Debian/Ubuntu x64 package, about 124 MB.
  TABBYRPM   Fedora/RHEL/Rocky x64 package, about 108 MB.

WINDOWS PORTABLE
  Extract into .\bin:
    PowerShell:  Expand-Archive .\TABBYZIP -DestinationPath .\bin
    Explorer:    right-click TABBYZIP, choose Extract All, target .\bin
  Create the portable data folder before the first run:
    New-Item .\bin\data -ItemType Directory
  Then start:
    .\bin\Tabby.exe
  Without data, Tabby writes configuration under %APPDATA%. With it,
  configuration and host lists stay on the stick. Remembered passwords go to
  Windows Credential Manager unless Tabby's encrypted vault is enabled: do
  not save passwords on shared media, and delete data before handing the
  stick over. The setup .exe is not stored here; this zip is the portable
  build.

LINUX
  Debian/Ubuntu:
    sudo apt install ./TABBYDEB
    tabby --no-sandbox
  Fedora/Rocky (repos off so a local install works offline):
    sudo dnf install --disablerepo='*' ./TABBYRPM
    tabby --no-sandbox
  If dnf is unavailable and gnome-keyring is already installed:
    sudo rpm -ivh ./TABBYRPM
  With no offline gnome-keyring, rpm -ivh --nodeps installs anyway, but
  Tabby's encrypted secret storage may not work. Do not treat rpm as a
  generic rescue for missing dependencies.
  The deb writes /usr/bin/tabby as a wrapper that adds --no-sandbox; the RPM
  links /usr/bin/tabby straight to /opt/Tabby/tabby, so pass --no-sandbox
  yourself on a live root session. The desktop entry already uses the flag.
  Runtime needs GTK3, NSS/NSPR, GBM, ALSA, ATK, CUPS, D-Bus, and xkbcommon.
  On Debian/Ubuntu the declared dependencies omit libgbm1 and the ALSA
  library; when Tabby reports a missing library, install:
    sudo apt install libgbm1 libasound2t64 libgtk-3-0t64
  (Debian 12 / Ubuntu 22.04 and older use libasound2 and libgtk-3-0.)
  Fedora/Rocky equivalents are mesa-libgbm, alsa-lib, and gtk3.
  A minimal live system may install the package but still need these from
  the distro media before Tabby starts.

SCOPE
  SSH, telnet, serial, and local shells, with split panes and saved sessions.
  SSH tabs include an interactive SFTP panel. Zmodem works in SSH, telnet,
  and serial tabs when the remote side has lrzsz (sz/rz). Not a replacement
  for scripted transfer (PuTTY's pscp/psftp, WinSCP.com) or for puttygen and
  Pageant; see ..\putty\ and ..\winscp\.

INTEGRITY
  SHA-256 values come from the GitHub release asset digests and are also
  recorded in isos\README.txt. Check on Windows:
    Get-FileHash .\TABBYZIP -Algorithm SHA256
    Get-AuthenticodeSignature .\bin\Tabby.exe
  and on Linux:
    sha256sum TABBYDEB TABBYRPM
  The zip itself is unsigned; Tabby.exe inside is Authenticode-valid with
  Eugen Pankov Softwareentwicklung as signer. The Linux packages are
  unsigned.

NOTES
  - MIT licensed. Electron app: needs a desktop session, not WinPE or a
    text-only console.
  - The Linux .tar.gz and AppImage builds are not stored here; the deb and
    rpm cover the intended package managers.
  - After a version bump the old tabby-* files stay in place; delete the
    previous ones.

'@
    return Add-TopicReadmeHeader -Text $text.Replace('TABBYZIP', $script:FileTabbyZip).Replace('TABBYDEB', $script:FileTabbyDeb).Replace('TABBYRPM', $script:FileTabbyRpm) -Meta (Get-TopicReadmeMeta -Topic 'tabby') -RunStartedUtc $RunStartedUtc -WrittenUtc $WrittenUtc
}

# Offline Go sheet for isos\04-etc\golang\. Windows and Linux x64 archives;
# extraction is user-local and the offline toolchain switches are explicit.
function Get-GoReadmeText {
    param([string]$RunStartedUtc, [string]$WrittenUtc)
    $text = @'
GO FOR WINDOWS AND LINUX (offline)
==================================
{HEADER}

FILES
  GOZIP   Windows 10/11 x64 portable toolchain, about 75 MB.
  GOTAR   Linux x64 portable toolchain, about 67 MB.

WINDOWS (no admin)
  Extract into a writable folder, for example C:\Tools (create it first):
    tar -xf .\GOZIP -C C:\Tools
  That creates C:\Tools\go. Add C:\Tools\go\bin to PATH (user), or call
  C:\Tools\go\bin\go.exe directly. Then:
    go version
  Expand-Archive .\GOZIP -DestinationPath C:\Tools is a fallback, but it is
  much slower for the many files in the toolchain. 7za.exe from ..\7zip\ can
  also extract the zip. Remove an old go\ folder before extracting a new
  version; extracting over an existing toolchain can leave a broken mix.

LINUX (no admin for a user-local tree)
    mkdir -p ~/.local
    tar -xzf ./GOTAR -C ~/.local
  That creates ~/.local/go. Add ~/.local/go/bin to PATH, then:
    export PATH="$HOME/.local/go/bin:$PATH"
    go version
  For a system-wide tree, run as root:
    sudo tar -xzf ./GOTAR -C /usr/local
  and add /usr/local/go/bin to PATH.

OFFLINE USE
  The toolchain and standard library build without a network. Modules need
  a proxy or a populated module cache; for vendored source use:
    GOTOOLCHAIN=local GOPROXY=off go build -mod=vendor
  GOTOOLCHAIN=local stops Go from trying to download a newer toolchain named
  by a go.mod; GOPROXY=off makes a missing module fail instead of hanging.

INTEGRITY
  Go publishes SHA-256 for every file at https://go.dev/dl/.
  Windows:
    Get-FileHash .\GOZIP -Algorithm SHA256
  Linux:
    sha256sum ./GOTAR
  Pinned values:
    GOZIP  GOWINHASH
    GOTAR  GOLINHASH
  The archives include LICENSE (BSD-3-Clause).

NOTES
  - x64 only. Windows 11 ARM runs the x64 toolchain through emulation.
  - A live Linux session keeps the extracted tree in RAM; Go needs a few
    hundred MB.
  - After a version bump, old go* archives stay in this folder; delete the
    previous pair by hand.
'@
    return Add-TopicReadmeHeader -Text $text.Replace('GOZIP', $script:FileGoWindows).Replace('GOTAR', $script:FileGoLinux).Replace('GOWINHASH', $script:GoWindowsSha256).Replace('GOLINHASH', $script:GoLinuxSha256) -Meta (Get-TopicReadmeMeta -Topic 'golang') -RunStartedUtc $RunStartedUtc -WrittenUtc $WrittenUtc
}

# Offline Node.js LTS sheet for isos\04-etc\nodejs\. Windows and Linux x64
# archives; the Linux archive is tar.gz so no xz decompressor is needed.
function Get-NodeReadmeText {
    param([string]$RunStartedUtc, [string]$WrittenUtc)
    $text = @'
NODE.JS LTS FOR WINDOWS AND LINUX (offline)
===========================================
{HEADER}

FILES
  NODEZIP   Windows 10/11 x64 runtime with npm, about 39 MB.
  NODETAR   Linux x64 runtime with npm, about 60 MB.
  NODESUMS  Publisher SHASUMS256.txt for the Linux and Windows files.

The Linux file is .tar.gz on purpose: extraction needs only tar and gzip,
with no separate decompressor.

WINDOWS (no admin)
  Extract into a writable folder, for example C:\Tools (create it first):
    tar -xf .\NODEZIP -C C:\Tools
  That creates C:\Tools\node-vNODEVER-win-x64. Add that folder to PATH, then:
    node --version
    npm --version
  Expand-Archive .\NODEZIP -DestinationPath C:\Tools is a fallback, but it
  is slower for npm's many files. Remove an old node-* folder before
  extracting a new version.

LINUX (no admin for a user-local tree)
  Extract to a writable Linux filesystem, not onto the USB stick:
    mkdir -p ~/.local
    tar -xzf ./NODETAR -C ~/.local
  The archive contains symlinks (bin/npm, bin/npx); extracting onto exFAT or
  FAT can fail or break them. Add the resulting
  ~/.local/node-vNODEVER-linux-x64/bin folder to PATH, then:
    export PATH="$HOME/.local/node-vNODEVER-linux-x64/bin:$PATH"
    node --version
    npm --version
  For a system-wide tree, use /usr/local as root and add its bin folder.
  The official build needs glibc 2.28 or newer; it does not run on musl or
  Alpine.

OFFLINE USE
  The runtime works without a network. npm install still needs a registry
  unless the package cache is already populated:
    npm install --offline
  or carry npm pack tarballs and install from those files.

INTEGRITY
  Node publishes SHASUMS256.txt at https://nodejs.org/dist/vNODEVER/.
  The publisher file is stored here as NODESUMS.
  Windows:
    Get-FileHash .\NODEZIP -Algorithm SHA256
  Linux:
    grep 'NODETAR' NODESUMS
    sha256sum ./NODETAR
  Pinned values:
    NODEZIP  NODEWINHASH
    NODETAR  NODELINHASH
  The archives include LICENSE (MIT); npm is included.

NOTES
  - x64 only. Windows 11 ARM runs the x64 runtime through emulation.
  - Node.js LTS NODELTS. A live Linux session keeps the extracted tree in
    RAM; Node is modest but not zero.
  - After a version bump, old node-* archives stay in this folder; delete the
    previous set by hand.
'@
    return Add-TopicReadmeHeader -Text $text.Replace('NODEZIP', $script:FileNodeWindows).Replace('NODETAR', $script:FileNodeLinux).Replace('NODESUMS', $script:FileNodeSums).Replace('NODEVER', $script:NodeVersion).Replace('NODELTS', $script:NodeLtsName).Replace('NODEWINHASH', $script:NodeWindowsSha256).Replace('NODELINHASH', $script:NodeLinuxSha256) -Meta (Get-TopicReadmeMeta -Topic 'nodejs') -RunStartedUtc $RunStartedUtc -WrittenUtc $WrittenUtc
}

# Offline TigerVNC sheet for isos\04-etc\tigervnc\. Windows viewer plus the
# generic Linux X11 viewer/server archive; the tarball has no w0vncserver.
function Get-TigerVncReadmeText {
    param([string]$RunStartedUtc, [string]$WrittenUtc)
    $text = @'
TIGERVNC VIEWER AND LINUX SERVER (offline)
==========================================
{HEADER}

FILES
  TVWIN   Windows x64 standalone viewer, no installer.
  TVTAR   Linux x86_64 generic archive: viewer and X11 servers.

WINDOWS VIEWER (no install)
  Run .\TVWIN, enter the host and display (host:1) or host::5901.
  The viewer supports TLS/VeNCrypt when the server offers it. For general
  VNC and TigerVNC Linux servers, this is the preferred client.
  It may write per-user connection settings; it does not install a service.

LINUX (extract on a Linux filesystem, not the exFAT USB stick)
    mkdir -p ~/.local/tigervnc
    tar -xzf ./TVTAR -C ~/.local/tigervnc
    export TVROOT="$HOME/.local/tigervnc/tigervnc-TVVER.x86_64"
    export PATH="$TVROOT/usr/bin:$PATH"
  Check dependencies before relying on it:
    ldd "$TVROOT/usr/bin/x0vncserver" | grep 'not found'
  If libraries are missing, use the distribution's tigervnc package instead.

SHARE THE EXISTING X11 DESKTOP (recommended for rescue images)
  The generic tarball has x0vncserver but no w0vncserver. This works only on
  X11, not Wayland.
    rm -f /tmp/vnc.pass
    (umask 077; "$TVROOT/usr/bin/vncpasswd" /tmp/vnc.pass)
    "$TVROOT/usr/bin/x0vncserver" -display :0 -rfbauth /tmp/vnc.pass -localhost yes
  On the helper, in a second terminal, open a tunnel. The target must be
  running sshd; most live images do not start it by default.
    ssh -N -L 5900:localhost:5900 user@host
  Then connect from the helper with its own viewer:
    Windows: .\TVWIN localhost::5900
    Linux:   vncviewer localhost::5900
  On Linux, use vncviewer from the tarball or the distribution package.

DIRECT VIRTUAL X SESSION (X11 only)
  Using /tmp/vnc.pass from above, start Xvnc and a desktop on display :1:
    "$TVROOT/usr/bin/Xvnc" :1 -geometry 1920x1080 -depth 24 \
      -rfbauth /tmp/vnc.pass -localhost yes &
    DISPLAY=:1 startxfce4 &
  Tunnel 5901 and connect to localhost:1 or localhost::5901.
  Do not rely on the relocated usr/libexec/vncserver or usr/sbin/vncsession
  from an extracted tree: they expect /usr/bin/Xvnc, /etc/tigervnc, and PAM
  paths. Use the distribution package when you need its service wrapper.

SECURITY
  The default VNC password is weak and VNC Authentication truncates it to
  eight characters. x0vncserver on localhost plus an SSH tunnel is the safe
  recovery default.
  Direct TLS:
    -SecurityTypes TLSVnc with -rfbauth encrypts the session, but TLSVnc is
    anonymous TLS and does not prove the server identity.
    -SecurityTypes X509Vnc with -rfbauth uses a certificate for identity;
    also pass -X509Cert <cert> and -X509Key <key>, and make the viewer trust
    that certificate.
  Avoid X509Plain as a default: Plain authentication depends on the
  tigervnc PAM service, which may be absent on live images.

WAYLAND
  The generic tarball does not include w0vncserver. Mint Xfce, antiX, and
  SystemRescue use X11 and work with x0vncserver. Fedora GNOME is Wayland;
  use GNOME Remote Desktop (RDP) there, not this archive.

ULTRAVNC WINDOWS SERVERS
  TigerVNC viewer can use UltraVNC's classic VNC password. For UltraVNC
  MS Logon, DSM encryption, Repeater, or SC, use the UltraVNC viewer.

INTEGRITY
  Windows:
    Get-FileHash .\TVWIN -Algorithm SHA256
    Get-AuthenticodeSignature .\TVWIN
  Linux:
    sha256sum ./TVTAR
  Pinned values:
    TVWIN  TVWINHASH
    TVTAR  TVLINHASH
  The EXE is Authenticode-valid, signer "Open Source Developer, Brian Hinz".
  The Linux tarball has no publisher checksum; this is a first-download pin.
  TigerVNC is GPL-2.0; source: https://github.com/TigerVNC/tigervnc

NOTES
  - x64 only. Windows 11 ARM runs the x64 viewer through emulation.
  - No Windows server is included; use UltraVNC for that.
  - After a version bump, old vncviewer64-* and tigervnc-* files stay here;
    delete the previous set.
'@
    return Add-TopicReadmeHeader -Text $text.Replace('TVWINHASH', $script:TigerVncViewerSha256).Replace('TVLINHASH', $script:TigerVncLinuxSha256).Replace('TVWIN', $script:FileTigerVncWindows).Replace('TVTAR', $script:FileTigerVncLinux).Replace('TVVER', $script:TigerVncVersion) -Meta (Get-TopicReadmeMeta -Topic 'tigervnc') -RunStartedUtc $RunStartedUtc -WrittenUtc $WrittenUtc
}

# Offline UltraVNC sheet for isos\04-etc\ultravnc\. Windows server and viewer;
# the ZIP is the portable/WinPE path, the x64 installer the service path.
function Get-UltraVncReadmeText {
    param([string]$RunStartedUtc, [string]$WrittenUtc)
    $text = @'
ULTRAVNC SERVER AND VIEWER FOR WINDOWS (offline)
================================================
{HEADER}

FILES
  UVZIP   Portable ZIP, x86 and x64 server/viewer, SecureVNC DSM plugin.
  UVINST  x64 installer for service-mode use.

PORTABLE (no install; use a local writable folder)
  Extract UVZIP to C:\Tools\UltraVNC, not directly on the USB stick.
    x64\vncviewer.exe   viewer
    x64\winvnc.exe      server
    x64\SecureVNCPlugin64.dsm
  Run the server elevated; otherwise UAC prompts can be black and
  Ctrl-Alt-Del may not reach the target. Set a password before the first
  connection; with no password the server refuses connections.
  Keep configuration and logs on the local disk, not on shared media.
  If you must run from the stick, delete the generated ultravnc.ini and logs
  before handing it over.
  Firewall rule (admin; replace the helper address):
    netsh advfirewall firewall add rule name="UltraVNC 5900" dir=in action=allow protocol=TCP localport=5900 remoteip=<helper-ip>
    netsh advfirewall firewall delete rule name="UltraVNC 5900"

WINPE
  Use the ZIP in portable mode; the server can run headless without Explorer.
  Base WinPE has no Expand-Archive. Extract on a working PC, or use 7za:
  7zr only opens .7z, so unpack the 7-Zip extra package first; then use
  "7za.exe x UVZIP -oC:\Tools\UltraVNC".
  In WinPE:
    wpeutil InitializeNetwork
    wpeutil DisableFirewall
  Test network drivers and the exact PE build before relying on it. HBCD PE
  is the WinPE in this kit.

INSTALLER / SERVICE MODE (normal Windows)
  Run UVINST, install Server and Viewer. Use service mode when you need the
  logon screen or unattended access. Open TCP 5900 to the helper only.
  Do not run the installed server and the portable server at the same time.

AUTHENTICATION AND ENCRYPTION
  - 1.8.3.2 retired MS-Logon II. Use the classic VNC password or the
    remaining MS Logon. Classic VNC passwords are cut to eight characters
    and are weak.
  - TigerVNC viewer can connect with the classic VNC password. For UltraVNC
    MS Logon, DSM encryption, Repeater, or SC, use UltraVNC viewer.
  - SecureVNC DSM: enable the plugin on both server and viewer. Non-DSM
    viewers, including TigerVNC, cannot connect to a DSM-only server.
  - Otherwise use an SSH/VPN tunnel. Windows has no sshd by default, and
    WinPE never does. With PuTTY:
      plink -R 5900:localhost:5900 user@linuxhost
    then on the Linux host:
      vncviewer localhost::5900
    A tunnel arrives from 127.0.0.1. If the server refuses it, enable
    "Allow Loopback Connections" in the server settings (portable or service
    mode), or set AllowLoopback=1 in the applicable ultravnc.ini, then
    restart the server.
    Optional reverse connect, where the target initiates:
      winvnc -connect helper.example:5500
      vncviewer -listen
    Reverse connect is unencrypted unless DSM or a tunnel is used, and TCP
    5500 must be reachable on the helper. Verify the exact syntax on the
    build you deploy.
  - Do not install the UVncVirtualDisplay driver unless a headless display is
    required.

INTEGRITY
  Get-FileHash .\UVZIP -Algorithm SHA256
  Get-FileHash .\UVINST -Algorithm SHA256
  Get-AuthenticodeSignature .\UVINST
  Pinned values:
    UVZIP   UVZIPHASH
    UVINST  UVINSTHASH
  The official UltraVNC 1.8.3.2 page publishes both SHA-256 values. Its
  displayed size fields are stale; the hashes match the served bytes.
  The installer and the x64 viewer/server binaries are Authenticode-valid,
  signer "Open Source Developer Rudi De Vos". UltraVNC is GPL-3.0;
  source: https://github.com/ultravnc/UltraVNC

NOTES
  - Windows-only. The ZIP includes x86 and x64; use x64 on current Windows.
  - After a version bump, old UltraVNC_* files stay here; delete the previous set.
  - Prefer built-in RDP (mstsc) when the target edition supports it.
'@
    return Add-TopicReadmeHeader -Text $text.Replace('UVZIPHASH', $script:UltraVncZipSha256).Replace('UVINSTHASH', $script:UltraVncInstallerSha256).Replace('UVZIP', $script:FileUltraVncZip).Replace('UVINST', $script:FileUltraVncInstaller) -Meta (Get-TopicReadmeMeta -Topic 'ultravnc') -RunStartedUtc $RunStartedUtc -WrittenUtc $WrittenUtc
}

# CJK display font sheet for isos\04-etc\fonts\. One Regular OTF plus its
# OFL license; install steps stay general and display-only.
function Get-FontsReadmeText {
    param([string]$RunStartedUtc, [string]$WrittenUtc)
    $text = @'
CJK DISPLAY FONT
================
{HEADER}

FILES
  FONTFILE  Noto Sans Mono CJK KR Regular, version 2.004; one
                       Regular weight, monospaced, about 15.6 MB.
  FONTLICENSE        Upstream SIL OFL 1.1 license, byte-for-byte.

INSTALL - LINUX (no admin)
  mkdir -p ~/.local/share/fonts
  cp FONTFILE ~/.local/share/fonts/
  fc-cache -fv
  fc-list :lang=ko | grep -i "Noto Sans Mono CJK"
  fc-match "Noto Sans Mono CJK KR"
  Select "Noto Sans Mono CJK KR" in the terminal or editor and restart the app.
  System-wide: copy to /usr/local/share/fonts/ and run fc-cache -fv.
  A live session loses the install at reboot. Many desktop ISOs already ship
  Noto CJK; check fc-list first. If the Ventoy partition is busy, copy the
  file with copyparty or from a second stick.

INSTALL - WINDOWS (usually not needed)
  Full Windows already has CJK fonts (Malgun Gothic, Yu Gothic, Microsoft
  YaHei, JhengHei). Install this only if text shows boxes.
  Right-click the OTF > Install for all users (needs admin; may be under
  Show more options), or Settings > Personalization > Fonts.
  A command-line copy to %WINDIR%\Fonts does not register the font.
  Select "Noto Sans Mono CJK KR" explicitly in Windows Terminal: Settings >
  profile > Appearance > Font face. Classic conhost does not offer this
  CFF-based OTF. An added font is not used by automatic fallback.
  Optional fallback list: Cascadia Mono, Noto Sans Mono CJK KR.
  In WinPE, use the Install button if offered; otherwise prefer SSH or Linux.

USE
  Display only; no IME. Linux fontconfig usually falls back to the family;
  Windows requires selecting it. A bare Linux text console needs a GUI
  terminal or fbterm/kmscon; SSH from Tabby/PuTTY is simpler and renders CJK
  with the client font. Keep a UTF-8 locale.

INTEGRITY
  SHA-256:
    sha256sum FONTFILE
    Get-FileHash .\FONTFILE -Algorithm SHA256
  Pinned value: FONTHASH
  Source commit: FONTCOMMIT
  FONTLICENSE is the upstream LICENSE renamed byte-for-byte; the font is
  unmodified, so the Reserved Font Name "Source" does not apply. If an editor
  rewrites FONTLICENSE line endings, the next run re-downloads it.

LICENSE
  SIL Open Font License 1.1; see FONTLICENSE.
'@
    $body = $text.Replace('FONTFILE', $script:FileFont).Replace('FONTLICENSE', $script:FileFontLicense).Replace('FONTHASH', $script:FontSha256).Replace('FONTCOMMIT', $script:FontCommit)
    return Add-TopicReadmeHeader -Text $body -Meta (Get-TopicReadmeMeta -Topic 'fonts') -RunStartedUtc $RunStartedUtc -WrittenUtc $WrittenUtc
}

# Portable ImgBurn sheet for isos\04-etc\imgburn\. Placeholders keep the
# version, payload file names, and hash in one edit point.
function Get-ImgBurnReadmeText {
    param([string]$RunStartedUtc, [string]$WrittenUtc)
    $text = @'
IMGBURN (PORTABLE)
==================
{HEADER}

FILES
  bin/{IBEXE}             Portable disc burner/imager, version {IBVER}.
  bin/ImgBurnPreview.exe  Image preview helper used by Write mode.
  bin/ReadMe.txt          Official vendor readme (command-line switches).
  bin/{IBINI}             Settings; created on first close, stays on the stick.
  {IBLAUNCH}              Launcher; use it for portable mode.

START (no install, no registry writes)
  Double-click {IBLAUNCH}, or run:
    bin/{IBEXE} /PORTABLE /SETTINGS "bin/{IBINI}"
  /PORTABLE stops the file-association, autoplay, and shell-extension writes;
  /SETTINGS keeps settings in bin/{IBINI} instead of the registry. Starting
  bin/{IBEXE} directly still loads bin/{IBINI}, but may also write registry
  entries, so prefer the launcher.

BURN AN ISO TO CD/DVD/BD
  1. Start through the launcher, choose Write image file to disc.
  2. Source: browse for the .iso. Destination: the optical drive.
  3. Pick a safe Write Speed (4x-8x on old media), enable Verify, click Write.
  Without ImgBurn, Windows 11 can burn a plain ISO through the signed
  C:\Windows\System32\isoburn.exe (right-click the ISO > Burn disc image).

IMAGE A DISC OR BUILD ONE
  Read mode copies a CD/DVD/BD to an image file (ISO/MDS/CUE) for archiving.
  Build mode writes a folder tree or files to an ISO, including bootable
  discs. Verify mode re-reads a burned disc against its image.

SETTINGS AND CLEANUP
  bin/{IBINI} holds settings, recent paths, and window state; delete it to
  reset. It travels with the stick: do not leave private paths or credentials
  on shared media. ImgBurn writes logs to the folder chosen under
  Tools > Settings > General (by default the current user's Documents).
  No install or uninstall is needed: delete this folder to remove it.

INTEGRITY
  The files were extracted from the official {IBINST} installer and
  verified against these SHA-256 values:
    {IBEXE}: {IBHASH}
  The installer's SHA-256 is pinned in the prep script; it also matches the
  CRC32/MD5/SHA-1 published on imgburn.com. The extracted binaries are
  unsigned (Authenticode NotSigned), so the hash is the check. The installer
  itself is not shipped: its OpenCandy offer never runs.

NOTES
  - 2013 freeware, 32-bit x86, asInvoker (the app does not request admin).
  - Smart App Control or an AV policy may block unsigned binaries; allow the
    file, or use the signed isoburn.exe for a simple ISO burn.
  - Windows-only; WinPE is untested. x86 runs on x64 and on Windows 11 ARM
    through emulation.
'@
    return Add-TopicReadmeHeader -Text $text.Replace('{IBVER}', $script:ImgBurnVersion).Replace('{IBEXE}', $script:FileImgBurnExe).Replace('{IBINST}', $script:FileImgBurnInstaller).Replace('{IBLAUNCH}', $script:FileImgBurnLauncher).Replace('{IBINI}', $script:FileImgBurnIni).Replace('{IBHASH}', $script:ImgBurnPayload[$script:FileImgBurnExe]) -Meta (Get-TopicReadmeMeta -Topic 'imgburn') -RunStartedUtc $RunStartedUtc -WrittenUtc $WrittenUtc
}

# Offline Firefox ESR sheet for isos\04-etc\firefox\. The live flow resolves
# the version; FBVER is only the fallback pinned in the script.
function Get-FirefoxReadmeText {
    param([string]$RunStartedUtc, [string]$WrittenUtc)
    $text = @'
FIREFOX ESR (OFFLINE)
=====================
{HEADER}

FILES
  Firefox Setup <version>.exe  en-US x64 ESR installer, about 86 MB. The
                               exact resolved version and hash are recorded
                               in ..\..\README.txt.

INSTALL (machine-wide; needs an elevated shell)
  GUI: double-click the installer.
  cmd.exe:
    start "" /wait "Firefox Setup <version>.exe" /S
    start "" /wait "Firefox Setup <version>.exe" /S /MaintenanceService=false ^
      /DesktopShortcut=false /TaskbarShortcut=false /StartMenuShortcut=false
  PowerShell:
    Start-Process -Wait -FilePath ".\Firefox Setup <version>.exe" -ArgumentList '/S'
    Start-Process -Wait -FilePath ".\Firefox Setup <version>.exe" `
      -ArgumentList '/S','/MaintenanceService=false','/DesktopShortcut=false',`
      '/TaskbarShortcut=false','/StartMenuShortcut=false'
  All installer options imply silent mode; /S and -ms are equivalent.
  To inspect the payload without installing:
    cmd.exe: "Firefox Setup <version>.exe" /ExtractDir=<directory>
  (/ExtractDir must be the only option.)

UNINSTALL
  Settings > Apps > Mozilla Firefox, or from an elevated shell:
    cmd.exe:
      "%ProgramFiles%\Mozilla Firefox\uninstall\helper.exe" -ms
    PowerShell:
      & "$env:ProgramFiles\Mozilla Firefox\uninstall\helper.exe" -ms
  A per-user install uses the same helper under its install path.

PROFILE AND PRIVACY
  Profiles live in %APPDATA%\Mozilla\Firefox\Profiles. They hold history,
  bookmarks, saved passwords, and cookies; do not copy them to shared media,
  and delete the profile before handing the stick or PC to someone else.

VERSIONS AND UPDATES
  The prep script resolves FIREFOX_ESR from product-details.mozilla.org on
  every run and verifies the release SHA256SUMS. If that lookup or its
  checksum entry fails, it falls back to the pinned FBVER release and warns.
  Old installers stay in this folder; delete the previous one after a newer
  one verifies. An offline PC does not update Firefox by itself: re-run the
  prep script and carry the newer installer.

INTEGRITY
  SHA-256 comes from the release SHA256SUMS published by Mozilla. The
  installer should be Authenticode-valid with Mozilla Corporation as signer;
  verify it with:
    Get-AuthenticodeSignature '.\Firefox Setup <version>.exe'
  The isos README records the exact version, hash, and whether it was
  resolved live or from the pinned fallback.

NOTES
  - Tiny11 removes Edge and WebView2. Firefox ESR supplies the browser; it
    does not restore WebView2 for apps that embed it.
  - en-US, x64. ARM64 Windows runs this under emulation; language packs are
    not included.
  - Windows-only; WinPE is not supported. Firefox needs a full user session.
  - The MSI package exists upstream but is not stored here; this folder keeps
    the EXE full installer for a simple double-click or /S deployment.
'@
    return Add-TopicReadmeHeader -Text $text.Replace('FBVER', $script:FirefoxFallbackVersion) -Meta (Get-FirefoxReadmeMeta) -RunStartedUtc $RunStartedUtc -WrittenUtc $WrittenUtc
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
function Initialize-Directory {
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
    param([string]$Url, [string]$OutFile, [string]$ExpectedHash = '', [string]$AlternateUrl = '', [string]$Name = '', [string[]]$Manual = @())
    $label = if ($Name) { $Name } else { $OutFile }
    $downloadManual = @(
        "Download $Url by hand into $OutFile.",
        'Re-run the script; verified files are skipped.'
    )
    $mismatchManual = @(
        "Download $Url by hand into $OutFile and compare its SHA-256 with $ExpectedHash.",
        'A SourceForge interstitial page instead of bytes is the usual cause; retry later.'
    )
    if ($Manual.Count -gt 0) {
        $downloadManual = $Manual
        $mismatchManual = $Manual
    }
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
        Write-Failure -Name $label -Detail "Download failed: $Url" -Manual $downloadManual
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
        Write-Failure -Name $label -Detail "Hash mismatch after retry: $Url" -Manual $mismatchManual
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
#
# MAINTENANCE - re-pin checklist (last full audit 2026-11-16):
#   1. Open the upstream release/checksum page named in the row's Check text.
#   2. Update FileName, Url, AlternateUrl, Hash, Released, SizeNote, About,
#      Check, and any SidecarUrl/SidecarName together. Also update every
#      shared $script: version/hash/URL-base constant the row uses, plus
#      Get-TopicReadmeMeta, readme examples, and tests that repeat the
#      version. Search for dotted, dashed, and dotless forms (9.6.0,
#      release-9-6-0, 1832, 7z2606) and for the old hash; tests may
#      hard-code all of them.
#   3. Run Invoke-Pester .\tests\Prepare-PcRecovery.Tests.ps1.
#   4. Run -WhatIf, then one real run. A second run must be all verified skips.
# Audit 2026-11-16: all Pinned rows matched upstream. Clonezilla stable was
# 3.3.3-37; 3.3.4-28 was testing at audit time, so re-check before pinning.
# SourceForge sidecars use the /download URL and are best effort. A sidecar
# that no longer contains the pinned hash is removed and reported so the row
# gets re-pinned; a moving sidecar URL (Clonezilla stable/data, Mint
# hwe/sha256sum.txt) is re-downloaded and warned on each selected run until
# re-pinned.
#
# For ISO rows, SidecarUrl/SidecarName name the publisher checksum file staged
# beside the artifact. Leave them empty only when upstream publishes none; say
# so in Check. Prefer a versioned SidecarName when the URL is a moving pointer;
# shared sidecars that list multiple artifacts are acceptable. Tool rows
# (04-etc) may omit a sidecar even when upstream publishes one; their pinned
# hash and Check text are authoritative.
# -----------------------------------------------------------------------------

function Get-RecoveryCatalog {
    @(
        [pscustomobject]@{ Name = 'netboot.xyz'; Category = '01-Network'; FileName = 'netboot.xyz.iso'; Url = 'https://boot.netboot.xyz/ipxe/netboot.xyz.iso'; AlternateUrl = ''; Hash = ''; HashKind = 'Rolling'; ChecksumUrl = 'https://boot.netboot.xyz/ipxe/netboot.xyz-sha256-checksums.txt'; NetbootVariant = 'x64'; SidecarUrl = 'https://boot.netboot.xyz/ipxe/netboot.xyz-sha256-checksums.txt'; SidecarName = 'netboot.xyz-sha256-checksums.txt'; MintHwe = ''; About = 'Network-boot menu that loads installer and utility images over the internet (needs a working network connection).'; Released = 'Rolling release, re-resolved every run (checksum file dated 2026-11-13).'; SizeNote = 'About 3 MB.'; Check = 'Re-download netboot.xyz-sha256-checksums.txt and match the ISO filename.' },
        [pscustomobject]@{ Name = 'netboot.xyz multi-arch'; Category = '01-Network'; FileName = 'netboot.xyz-multiarch.iso'; Url = 'https://boot.netboot.xyz/ipxe/netboot.xyz-multiarch.iso'; AlternateUrl = ''; Hash = ''; HashKind = 'Rolling'; ChecksumUrl = 'https://boot.netboot.xyz/ipxe/netboot.xyz-sha256-checksums.txt'; NetbootVariant = 'multi'; SidecarUrl = 'https://boot.netboot.xyz/ipxe/netboot.xyz-sha256-checksums.txt'; SidecarName = 'netboot.xyz-sha256-checksums.txt'; MintHwe = ''; About = 'netboot.xyz combined image for x86_64 and ARM64 machines.'; Released = 'Rolling release, re-resolved every run (checksum file dated 2026-11-13).'; SizeNote = 'Combined x86_64 + ARM64 network-boot ISO.'; Check = 'Re-download netboot.xyz-sha256-checksums.txt and match the ISO filename.' },
        [pscustomobject]@{ Name = "Hiren's BootCD PE x64"; Category = '02-Rescue'; FileName = 'HBCD_PE_x64.iso'; Url = 'https://www.hirensbootcd.org/files/HBCD_PE_x64.iso'; AlternateUrl = ''; Hash = '8c4c670c9c84d6c4b5a9c32e0aa5a55d8c23de851d259207d54679ea774c2498'; HashKind = 'Pinned'; ChecksumUrl = ''; SidecarUrl = ''; SidecarName = ''; NetbootVariant = ''; MintHwe = ''; About = 'Windows PE rescue environment with disk, partition, recovery, and antivirus tools (BootCD PE x64 v1.0.8).'; Released = 'BootCD PE x64 v1.0.8, March 2024 (download page and changelog); the URL itself carries no version, so the hash is pinned to that build.'; SizeNote = 'About 3.06 GB.'; Check = 'Unversioned URL; the official download page publishes the SHA-256, and there is no upstream checksum file. Re-pin only after an official announcement.' },
        [pscustomobject]@{ Name = 'SystemRescue'; Category = '02-Rescue'; FileName = 'systemrescue-13.03-amd64.iso'; Url = 'https://sourceforge.net/projects/systemrescuecd/files/sysresccd-x86/13.03/systemrescue-13.03-amd64.iso/download'; AlternateUrl = ''; Hash = 'b71b98ba6b92145524cb1a72206b9888a59861ad6fb05d127faf618ca0136891'; SidecarUrl = 'https://sourceforge.net/projects/systemrescuecd/files/sysresccd-x86/13.03/systemrescue-13.03-amd64.iso.sha256/download'; SidecarName = 'systemrescue-13.03-amd64.iso.sha256'; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Arch-based Linux rescue toolkit (disk tools, filesystem repair, network utilities).'; Released = 'Version 13.03, November 2026 (SourceForge release date 2026-11-07).'; SizeNote = 'About 1.4 GB.'; Check = 'SourceForge Files page for sysresccd-x86 13.03 plus its .sha256 sidecar.' },
        [pscustomobject]@{ Name = 'Clonezilla'; Category = '02-Rescue'; FileName = 'clonezilla-live-3.3.3-37-amd64.iso'; Url = 'https://sourceforge.net/projects/clonezilla/files/clonezilla_live_stable/3.3.3-37/clonezilla-live-3.3.3-37-amd64.iso/download'; AlternateUrl = ''; Hash = '3079458d926a37d3533e5d5caeb61b6e49c2dc69e2c97e0332ef37986bb3414f'; HashKind = 'Pinned'; ChecksumUrl = ''; SidecarUrl = 'https://clonezilla.org/downloads/stable/data/CHECKSUMS.TXT'; SidecarName = 'CHECKSUMS-clonezilla-3.3.3-37.txt'; NetbootVariant = ''; MintHwe = ''; About = 'Disk imaging and cloning (device-to-device and device-to-image). UEFI and Secure Boot capable amd64 build.'; Released = 'Version 3.3.3-37, September 2026 (SourceForge file date; official stable CHECKSUMS.TXT).'; SizeNote = 'About 505 MB.'; Check = 'clonezilla.org stable CHECKSUMS.TXT (SHA-256 section) lists the pinned hash; the stable URL moves with the next stable release, so re-pin the row and sidecar name together.' },
        [pscustomobject]@{ Name = 'Ubuntu Server'; Category = '03-Installers'; FileName = 'ubuntu-26.04.1-live-server-amd64.iso'; Url = 'https://releases.ubuntu.com/26.04/ubuntu-26.04.1-live-server-amd64.iso'; AlternateUrl = ''; Hash = 'cc8a95cde20f6ced61a322420de00f10cc3c90ced545daa46cb9c1a117f1d927'; SidecarUrl = 'https://releases.ubuntu.com/26.04/SHA256SUMS'; SidecarName = 'SHA256SUMS-ubuntu-26.04'; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Ubuntu Server installer (minimal CLI base; add ubuntu-desktop afterwards for a desktop).'; Released = 'Version 26.04.1, August 2026 (SHA256SUMS dated 2026-08-27).'; SizeNote = 'About 2.7 GB.'; Check = 'releases.ubuntu.com SHA256SUMS for 26.04.1.' },
        [pscustomobject]@{ Name = 'Rocky Linux minimal'; Category = '03-Installers'; FileName = 'Rocky-10.2-x86_64-minimal.iso'; Url = 'https://download.rockylinux.org/pub/rocky/10/isos/x86_64/Rocky-10.2-x86_64-minimal.iso'; AlternateUrl = 'https://download.rockylinux.org/pub/rocky/10/isos/x86_64/Rocky-10-latest-x86_64-minimal.iso'; Hash = 'aac6ac3ce781b91a91ce78463405f66c611a5dca4b3840c79e5e01d97302f6c8'; SidecarUrl = 'https://download.rockylinux.org/pub/rocky/10/isos/x86_64/CHECKSUM'; SidecarName = 'CHECKSUM-rocky-10'; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Minimal offline installer for a small RHEL-compatible server/CLI base (RHEL 10 generation, supported to roughly May 2035).'; Released = 'Version 10.2, May 2026 (ISO 2026-05-27, CHECKSUM signed 2026-05-29, 2072444928 bytes).'; SizeNote = 'About 2.1 GB.'; Check = 'Rocky-10.2-x86_64-minimal.iso CHECKSUM entry in the same directory.' },
        [pscustomobject]@{ Name = 'Debian netinst'; Category = '03-Installers'; FileName = 'debian-13.7.0-amd64-netinst.iso'; Url = 'https://cdimage.debian.org/debian-cd/13.7.0/amd64/iso-cd/debian-13.7.0-amd64-netinst.iso'; AlternateUrl = 'https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-13.7.0-amd64-netinst.iso'; Hash = 'a7ef94ac2fb9a7fec454552abd629b7cc9d5155c886165a45649f5ce6167e355'; SidecarUrl = 'https://cdimage.debian.org/debian-cd/13.7.0/amd64/iso-cd/SHA256SUMS'; SidecarName = 'SHA256SUMS-debian-13.7.0'; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Small Debian network installer (Debian 13 includes non-free firmware for Wi-Fi/BT/GPU).'; Released = 'Version 13.7.0, September 2026 (SHA256SUMS dated 2026-09-12).'; SizeNote = 'About 400 MB.'; Check = 'Debian cdimage SHA256SUMS for 13.7.0 (upstream-verified 2026-11-14); versioned path first, /current/ fallback.' },
        [pscustomobject]@{ Name = 'Linux Mint Xfce'; Category = '03-Installers'; FileName = 'linuxmint-22.3-xfce-64bit.iso'; Url = 'https://mirrors.kernel.org/linuxmint/stable/22.3/linuxmint-22.3-xfce-64bit.iso'; AlternateUrl = 'https://mirror.math.princeton.edu/pub/linuxmint/stable/22.3/linuxmint-22.3-xfce-64bit.iso'; Hash = '45a835b5dddaf40e84d776549e0b19b3fbd49673b6cc6434ebddbfcd217df776'; SidecarUrl = 'https://mirrors.kernel.org/linuxmint/stable/22.3/sha256sum.txt'; SidecarName = 'sha256sum-mint-22.3.txt'; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Live/installer ISO with the Xfce desktop (based on Ubuntu 24.04 LTS, kernel 6.14).'; Released = 'Version 22.3, January 2026 (sha256sum.txt dated 2026-01-11).'; SizeNote = 'About 3.0 GB.'; Check = 'mirrors.kernel.org/linuxmint stable/22.3 sha256sum.txt (Princeton mirror is a byte-identical fallback).' },
        [pscustomobject]@{ Name = 'Linux Mint Xfce HWE 6.17'; Category = '03-Installers'; FileName = 'linuxmint-22.3-xfce-64bit-hwe-6.17.iso'; Url = 'https://mirrors.kernel.org/linuxmint/hwe/linuxmint-22.3-xfce-64bit-hwe-6.17.iso'; AlternateUrl = 'https://mirror.math.princeton.edu/pub/linuxmint/hwe/linuxmint-22.3-xfce-64bit-hwe-6.17.iso'; Hash = '8c8eb200642bca2f34b7f22e812e4ac3d97483b06b188355cdff8ff98f03f550'; SidecarUrl = 'https://mirrors.kernel.org/linuxmint/hwe/sha256sum.txt'; SidecarName = 'sha256sum-mint-hwe.txt'; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = '6.17'; About = 'Mint Xfce with the newer HWE 6.17 kernel for hardware the regular ISO does not support.'; Released = 'Version 22.3 with HWE kernel 6.17 (hwe sha256sum.txt dated 2026-08-08).'; SizeNote = 'Fetch only with -MintHwe 6.17 (HWE kernel 6.17 for newer hardware).'; Check = 'mirrors.kernel.org/linuxmint hwe/sha256sum.txt (Princeton mirror is a byte-identical fallback).' },
        [pscustomobject]@{ Name = 'Linux Mint Xfce HWE 7.0'; Category = '03-Installers'; FileName = 'linuxmint-22.3-xfce-64bit-hwe-7.0.iso'; Url = 'https://mirrors.kernel.org/linuxmint/hwe/linuxmint-22.3-xfce-64bit-hwe-7.0.iso'; AlternateUrl = 'https://mirror.math.princeton.edu/pub/linuxmint/hwe/linuxmint-22.3-xfce-64bit-hwe-7.0.iso'; Hash = '17475774172776978f24677a847a62d7595c5bee34cb1f96ee3d26eedeca33c8'; SidecarUrl = 'https://mirrors.kernel.org/linuxmint/hwe/sha256sum.txt'; SidecarName = 'sha256sum-mint-hwe.txt'; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = '7.0'; About = 'Mint Xfce with the newer HWE 7.0 kernel for hardware the regular ISO does not support.'; Released = 'Version 22.3 with HWE kernel 7.0 (hwe sha256sum.txt dated 2026-08-08).'; SizeNote = 'Fetch only with -MintHwe 7.0 (HWE kernel 7.0 for newer hardware).'; Check = 'mirrors.kernel.org/linuxmint hwe/sha256sum.txt (Princeton mirror is a byte-identical fallback).' },
        [pscustomobject]@{ Name = 'antiX full'; Category = '03-Installers'; FileName = 'antiX-26.1_x64-full.iso'; Url = 'https://sourceforge.net/projects/antix-linux/files/Final/antiX-26.1/antiX-26.1_x64-full.iso/download'; AlternateUrl = ''; Hash = '293381af0b7c48399abe015da8f67d41fd34372b73c4aafcf53747fbaed22371'; SidecarUrl = 'https://sourceforge.net/projects/antix-linux/files/Final/antiX-26.1/antiX-26.1_x64-full.iso.sha256/download'; SidecarName = 'antiX-26.1_x64-full.iso.sha256'; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Debian 13-based, systemd-free live/installer with a desktop; suits modern and older PCs alike.'; Released = 'Version 26.1, September 2026 (SourceForge files dated 2026-09-28).'; SizeNote = 'About 2.5 GB.'; Check = 'SourceForge Final/antiX-26.1 file list plus the .sha256 sidecar.' },
        [pscustomobject]@{ Name = 'Fedora Workstation Live'; Category = '03-Installers'; FileName = 'Fedora-Workstation-Live-45-1.4.x86_64.iso'; Url = 'https://download.fedoraproject.org/pub/fedora/linux/releases/45/Workstation/x86_64/iso/Fedora-Workstation-Live-45-1.4.x86_64.iso'; AlternateUrl = ''; Hash = '68338c6bfe4f0d64151f2e47efe9f44a8855ad05b460e56b844fb3fa2c9a3beb'; SidecarUrl = 'https://download.fedoraproject.org/pub/fedora/linux/releases/45/Workstation/x86_64/iso/Fedora-Workstation-45-1.4-x86_64-CHECKSUM'; SidecarName = 'Fedora-Workstation-45-1.4-x86_64-CHECKSUM'; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Live desktop installer with GNOME.'; Released = 'Version 45-1.4, October 2026.'; SizeNote = 'About 2.72 GB.'; Check = 'Fedora-Workstation-45-1.4-x86_64-CHECKSUM in the same directory.' },
        [pscustomobject]@{ Name = 'Python 3.15 Windows installer'; Category = '04-etc\python'; FileName = $script:FilePythonInstaller; Url = ($script:PyUrlBase + $script:FilePythonInstaller); AlternateUrl = ''; Hash = '06e225a228191b0f4d1dcf6905fbb21bf9f6970d13a2ec63137ab9bee76f15aa'; SidecarUrl = ''; SidecarName = ''; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Full offline CPython for Windows 10/11 x64: pip, venv, tkinter, and a normal per-user or all-users install.'; Released = 'Version 3.15.2, October 2026 (last line to ship the traditional Windows installer; 3.16+ use the Python install manager).'; SizeNote = 'About 36 MB.'; Check = 'python.org SPDX sidecar (CPython package SHA-256) matches the pinned hash; Authenticode signer is the Python Software Foundation. Download ' + $script:PyUrlBase + $script:FilePythonInstaller + ' into isos\04-etc\python\ by hand; the next run verifies it against the pinned hash and skips it.' },
        [pscustomobject]@{ Name = 'Python 3.15 Windows embeddable'; Category = '04-etc\python'; FileName = $script:FilePythonEmbed; Url = ($script:PyUrlBase + $script:FilePythonEmbed); AlternateUrl = ''; Hash = 'd012f3aa29cf07436dae8aea1fec0fd195c2612a0b059b1f915ae0afb9ad1f62'; SidecarUrl = ''; SidecarName = ''; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Extract-and-run CPython for Windows 10/11 x64: sqlite3 and ssl, no pip/venv/tkinter; runs copyparty-sfx.py without installation.'; Released = 'Version 3.15.2, October 2026.'; SizeNote = 'About 13 MB.'; Check = 'python.org SPDX sidecar (CPython package SHA-256) matches the pinned hash; python.exe inside the zip is signed by the Python Software Foundation. Download ' + $script:PyUrlBase + $script:FilePythonEmbed + ' into isos\04-etc\python\ by hand; the next run verifies it against the pinned hash and skips it.' },
        [pscustomobject]@{ Name = 'Go 1.27.4 Windows x64'; Category = '04-etc\golang'; FileName = $script:FileGoWindows; Url = ($script:GoUrlBase + $script:FileGoWindows); AlternateUrl = ''; Hash = $script:GoWindowsSha256; SidecarUrl = ''; SidecarName = ''; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Portable Go toolchain for Windows 10/11 x64; unzip and add go\bin to PATH, no installer or admin.'; Released = ('Version ' + $script:GoVersion + ', ' + $script:GoReleased + ' (go.dev/dl; 79,077,744 bytes).'); SizeNote = 'About 75 MB.'; Check = ('go.dev/dl SHA-256 for ' + $script:GoVersion + ' matches the pinned hash. Download ' + $script:GoUrlBase + $script:FileGoWindows + ' into isos\04-etc\golang\ by hand; the next run verifies it and skips.') }
        [pscustomobject]@{ Name = 'Go 1.27.4 Linux x64'; Category = '04-etc\golang'; FileName = $script:FileGoLinux; Url = ($script:GoUrlBase + $script:FileGoLinux); AlternateUrl = ''; Hash = $script:GoLinuxSha256; SidecarUrl = ''; SidecarName = ''; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Portable Go toolchain for Linux x64; extract with tar/gzip, no package manager or admin for a user-local tree.'; Released = ('Version ' + $script:GoVersion + ', ' + $script:GoReleased + ' (go.dev/dl; 70,680,823 bytes).'); SizeNote = 'About 67 MB.'; Check = ('go.dev/dl SHA-256 for ' + $script:GoVersion + ' matches the pinned hash. Download ' + $script:GoUrlBase + $script:FileGoLinux + ' into isos\04-etc\golang\ by hand; the next run verifies it and skips.') }
        [pscustomobject]@{ Name = 'Node.js LTS 26.13.1 Windows x64'; Category = '04-etc\nodejs'; FileName = $script:FileNodeWindows; Url = ($script:NodeUrlBase + $script:FileNodeWindows); AlternateUrl = ''; Hash = $script:NodeWindowsSha256; SidecarUrl = $script:NodeSumsUrl; SidecarName = $script:FileNodeSums; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Portable Node.js LTS runtime with npm for Windows 10/11 x64; unzip and add the extracted folder to PATH, no installer or admin.'; Released = ('Version ' + $script:NodeVersion + ' (' + $script:NodeLtsName + '), ' + $script:NodeReleased + ' (nodejs.org; 41,166,246 bytes).'); SizeNote = 'About 39 MB.'; Check = ('nodejs.org SHASUMS256.txt matches the pinned hash; the sidecar is kept as ' + $script:FileNodeSums + '. Download ' + $script:NodeUrlBase + $script:FileNodeWindows + ' into isos\04-etc\nodejs\ by hand; the next run verifies it and skips.') }
        [pscustomobject]@{ Name = 'Node.js LTS 26.13.1 Linux x64'; Category = '04-etc\nodejs'; FileName = $script:FileNodeLinux; Url = ($script:NodeUrlBase + $script:FileNodeLinux); AlternateUrl = ''; Hash = $script:NodeLinuxSha256; SidecarUrl = $script:NodeSumsUrl; SidecarName = $script:FileNodeSums; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Portable Node.js LTS runtime with npm for Linux x64; tar.gz avoids an xz extractor, and the official build needs glibc 2.28 or newer.'; Released = ('Version ' + $script:NodeVersion + ' (' + $script:NodeLtsName + '), ' + $script:NodeReleased + ' (nodejs.org; 62,904,977 bytes).'); SizeNote = 'About 60 MB.'; Check = ('nodejs.org SHASUMS256.txt matches the pinned hash; the sidecar is kept as ' + $script:FileNodeSums + '. Download ' + $script:NodeUrlBase + $script:FileNodeLinux + ' into isos\04-etc\nodejs\ by hand; the next run verifies it and skips.') }
        [pscustomobject]@{ Name = '7-Zip 26.06 Windows installer'; Category = '04-etc\7zip'; FileName = $script:FileSevenZipInstaller; Url = ($script:SevenZipUrlBase + $script:FileSevenZipInstaller); AlternateUrl = ('https://www.7-zip.org/a/' + $script:FileSevenZipInstaller); Hash = '9b697f65ecc2d9b0152f5ee96d72dde522a7827690349d9307935dacf40f42ec'; SidecarUrl = ''; SidecarName = ''; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'x64 Windows installer for the 7z/zip/iso extractor; installs to Program Files and elevates itself.'; Released = 'Version 26.06, November 2026 (1,659,704 bytes; unsigned, NotSigned is expected).'; SizeNote = 'About 1.6 MB.'; Check = 'GitHub asset digest (ip7z/7zip 26.06) equals the winget 7zip.7zip InstallerSha256 and the 7-zip.org copy; unsigned, so NotSigned is expected. Download ' + $script:SevenZipUrlBase + $script:FileSevenZipInstaller + ' into isos\04-etc\7zip\ by hand; the next run verifies it against the pinned hash and skips it.' },
        [pscustomobject]@{ Name = '7-Zip 26.06 portable extras'; Category = '04-etc\7zip'; FileName = $script:FileSevenZipExtra; Url = ($script:SevenZipUrlBase + $script:FileSevenZipExtra); AlternateUrl = ''; Hash = '396c180f12d2247c24b0b1fcd482c6fc2a2700f61211ffede1061dd971f5e104'; SidecarUrl = ''; SidecarName = ''; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = ('Portable archive with a standalone 7za.exe (zip/gz/tar/xz/bz2) that needs no admin install; unpack with ' + $script:FileSevenZipBootstrap + '.'); Released = 'Version 26.06, November 2026 (1,758,340 bytes; unsigned, NotSigned is expected).'; SizeNote = 'About 1.7 MB.'; Check = 'GitHub asset digest (ip7z/7zip 26.06); unsigned, so NotSigned is expected; GitHub-only (7-zip.org has no copy). Download ' + $script:SevenZipUrlBase + $script:FileSevenZipExtra + ' into isos\04-etc\7zip\ by hand; the next run verifies it against the pinned hash and skips it.' },
        [pscustomobject]@{ Name = '7-Zip 26.06 bootstrap extractor'; Category = '04-etc\7zip'; FileName = $script:FileSevenZipBootstrap; Url = ($script:SevenZipUrlBase + '7zr.exe'); AlternateUrl = ''; Hash = 'e80db2dad715a6c5adabe292d31ed54e11f4e9b99ca349827b50573b175891bc'; SidecarUrl = ''; SidecarName = ''; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = '7zr.exe: .7z-only extractor used to unpack the extra package without installing 7-Zip.'; Released = 'Version 26.06, November 2026 (600,064 bytes; unsigned, NotSigned is expected).'; SizeNote = 'About 600 KB.'; Check = 'GitHub asset digest (ip7z/7zip 26.06); unsigned, so NotSigned is expected; GitHub-only (the 7-zip.org 7zr.exe is a different build). Download ' + $script:SevenZipUrlBase + '7zr.exe' + ' into isos\04-etc\7zip\ by hand and save it as ' + $script:FileSevenZipBootstrap + '; the next run verifies it against the pinned hash and skips it.' },
        [pscustomobject]@{ Name = 'PuTTY 0.85 portable bundle'; Category = '04-etc\putty'; FileName = $script:FilePuttyZip; Url = ($script:PuttyUrlBase + 'putty.zip'); AlternateUrl = ''; Hash = 'e0b36e5381ecc78dd06a291bab25fb9d95bc991d0d864cf2741a5bde82816668'; SidecarUrl = ('https://the.earth.li/~sgtatham/putty/' + $script:PuttyVersion + '/sha256sums'); SidecarName = $script:FilePuttySums; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Portable SSH/telnet/serial bundle: putty, plink, pscp, psftp, puttygen, pageant.'; Released = 'Version 0.85, August 2026 (4,096,601 bytes; binaries signed by Simon Tatham).'; SizeNote = 'About 3.9 MB.'; Check = 'Official sha256sums (GPG-signed) matches; binaries Authenticode-valid, signer Simon Tatham. Download ' + $script:PuttyUrlBase + 'putty.zip' + ' into isos\04-etc\putty\ by hand and save it as ' + $script:FilePuttyZip + '; the next run verifies it against the pinned hash and skips it.' },
        [pscustomobject]@{ Name = 'WinSCP 6.7.1 portable'; Category = '04-etc\winscp'; FileName = $script:FileWinScpPortable; Url = ($script:WinScpUrlBase + $script:FileWinScpPortable + '/download'); AlternateUrl = ''; Hash = 'e6d2f8e1249e41f3bf8638319bb9bd15a541a64720df0805cb0bebdedb5eda83'; SidecarUrl = ''; SidecarName = ''; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'GUI SFTP/SCP/FTP/FTPS/WebDAV/S3 client with synchronize, a resumable transfer queue, remote editing, and WinSCP.com scripting.'; Released = 'Version 6.7.1, November 2026 (8,833,106 bytes; WinSCP.exe and WinSCP.com signed by Martin Prikryl).'; SizeNote = 'About 8.4 MB (extracts to about 20 MB).'; Check = 'SHA-256 matches WinSCP-6.7.1-ReadMe.txt (winscp.net); the zip is unsigned, and the executables inside are Authenticode-valid with Martin Prikryl as signer. Download ' + $script:WinScpUrlBase + $script:FileWinScpPortable + '/download' + ' into isos\04-etc\winscp\ by hand; the next run verifies it against the pinned hash and skips it.' },
        [pscustomobject]@{ Name = 'Cyberduck 9.6.0 Windows installer'; Category = '04-etc\cyberduck'; FileName = $script:FileCyberduckInstaller; Url = ($script:CyberduckUrlBase + $script:FileCyberduckInstaller); AlternateUrl = ($script:CyberduckGitHubUrlBase + $script:FileCyberduckInstaller); Hash = '9a66f8fb400feaa5f7f390f9e4100e873f6be06cbf7c61f1651fca8b1f31c930'; SidecarUrl = ''; SidecarName = ''; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'GUI browser for SFTP, FTP/FTPS, WebDAV, S3, Azure, Backblaze B2, Google Drive, Dropbox, OneDrive, and SharePoint; Windows installer, no portable build.'; Released = 'Version 9.6.0 (build 46406), November 2026 (92,009,848 bytes; Authenticode-valid, signed by iterate GmbH).'; SizeNote = 'About 88 MB.'; Check = 'SHA-256 matches the official cyberduck.io download page and the GitHub asset digest; the installer is Authenticode-valid with iterate GmbH as signer. Download ' + $script:CyberduckUrlBase + $script:FileCyberduckInstaller + ' into isos\04-etc\cyberduck\ by hand; the next run verifies it against the pinned hash and skips it.' }
        [pscustomobject]@{ Name = 'Cyberduck CLI (duck) 9.6.0 Linux x64'; Category = '04-etc\cyberduck'; FileName = $script:FileCyberduckDuck; Url = ($script:CyberduckGitHubUrlBase + $script:FileCyberduckDuck); AlternateUrl = ''; Hash = 'b76f3fefdd0756b08e7e3015f46273a73f5cf78bc9f0d83c7d0d6e7e90ea6ca6'; SidecarUrl = ''; SidecarName = ''; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'duck command-line client for the same protocols; Debian/Ubuntu amd64 package that bundles its own Java runtime and declares no dependencies. Extracts and runs without installation.'; Released = 'Version 9.6.0 (build 46406), November 2026 (110,921,096 bytes; installs to about 226 MB).'; SizeNote = 'About 106 MB.'; Check = 'SHA-256 matches the GitHub release asset digest. Download ' + $script:CyberduckGitHubUrlBase + $script:FileCyberduckDuck + ' into isos\04-etc\cyberduck\ by hand; the next run verifies it against the pinned hash and skips it.' }
        [pscustomobject]@{ Name = 'Cyberduck CLI (duck) 9.6.0 Linux x64 RPM'; Category = '04-etc\cyberduck'; FileName = $script:FileCyberduckDuckRpm; Url = ($script:CyberduckGitHubUrlBase + $script:FileCyberduckDuckRpm); AlternateUrl = ''; Hash = '7731551675755846ec1a502ca2a2cf2a697e30026afe80c29f43ec9e8e090c6d'; SidecarUrl = ''; SidecarName = ''; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'duck command-line client for Fedora/RHEL/Rocky; x86_64 RPM that bundles its own Java runtime and requires only glibc.'; Released = 'Version 9.6.0 (build 46406), November 2026 (113,352,754 bytes; installs to about 230 MB).'; SizeNote = 'About 108 MB.'; Check = 'SHA-256 matches the GitHub release asset digest. Download ' + $script:CyberduckGitHubUrlBase + $script:FileCyberduckDuckRpm + ' into isos\04-etc\cyberduck\ by hand; the next run verifies it against the pinned hash and skips it.' }
        [pscustomobject]@{ Name = 'Tabby 1.0.238 Windows portable'; Category = '04-etc\tabby'; FileName = $script:FileTabbyZip; Url = ($script:TabbyUrlBase + $script:FileTabbyZip); AlternateUrl = ''; Hash = '56de045fbb5a74d586903367d3f7227276d538281b0068d8132de3318cdd5019'; SidecarUrl = ''; SidecarName = ''; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Electron terminal with built-in SSH, telnet, serial, and local shells, an SSH SFTP panel, and Zmodem transfers; portable-mode zip that keeps configuration and host lists in a data folder beside Tabby.exe.'; Released = 'Version 1.0.238, October 2026 (185,884,613 bytes; Tabby.exe signed by Eugen Pankov Softwareentwicklung).'; SizeNote = 'About 177 MB (extracts to about 481 MB).'; Check = 'SHA-256 matches the GitHub release asset digest; the zip is unsigned, and Tabby.exe inside is Authenticode-valid with Eugen Pankov Softwareentwicklung as signer. Download ' + $script:TabbyUrlBase + $script:FileTabbyZip + ' into isos\04-etc\tabby\ by hand; the next run verifies it against the pinned hash and skips it.' }
        [pscustomobject]@{ Name = 'Tabby 1.0.238 Linux x64 deb'; Category = '04-etc\tabby'; FileName = $script:FileTabbyDeb; Url = ($script:TabbyUrlBase + $script:FileTabbyDeb); AlternateUrl = ''; Hash = '5ea2b9aa84f2b5cdcb98cb7e94bd3d92de48c96254a98b52bf2d1f30a52d1d1c'; SidecarUrl = ''; SidecarName = ''; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Debian/Ubuntu x64 package for the same terminal; installs /opt/Tabby and a /usr/bin/tabby wrapper that adds --no-sandbox.'; Released = 'Version 1.0.238, October 2026 (130,349,456 bytes; unsigned; needs gnome-keyring and GUI libraries).'; SizeNote = 'About 124 MB (installs to about 431 MB).'; Check = 'SHA-256 matches the GitHub release asset digest; the package is unsigned. Download ' + $script:TabbyUrlBase + $script:FileTabbyDeb + ' into isos\04-etc\tabby\ by hand; the next run verifies it against the pinned hash and skips it.' }
        [pscustomobject]@{ Name = 'Tabby 1.0.238 Linux x64 rpm'; Category = '04-etc\tabby'; FileName = $script:FileTabbyRpm; Url = ($script:TabbyUrlBase + $script:FileTabbyRpm); AlternateUrl = ''; Hash = 'd5027a5f905edf40aaf1fd42ef5015abfaffbd96f5825b3622ef352dfc3136b3'; SidecarUrl = ''; SidecarName = ''; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Fedora/RHEL/Rocky x64 package for the same terminal; requires gnome-keyring and links /usr/bin/tabby to /opt/Tabby/tabby.'; Released = 'Version 1.0.238, October 2026 (113,337,069 bytes; unsigned; requires gnome-keyring).'; SizeNote = 'About 108 MB (installs to about 431 MB).'; Check = 'SHA-256 matches the GitHub release asset digest; the package is unsigned. Download ' + $script:TabbyUrlBase + $script:FileTabbyRpm + ' into isos\04-etc\tabby\ by hand; the next run verifies it against the pinned hash and skips it.' }
        [pscustomobject]@{ Name = 'TigerVNC 1.16.2 Windows viewer'; Category = '04-etc\tigervnc'; FileName = $script:FileTigerVncWindows; Url = ($script:TigerVncUrlBase + $script:FileTigerVncWindows + '/download'); AlternateUrl = ''; Hash = $script:TigerVncViewerSha256; SidecarUrl = ''; SidecarName = ''; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Standalone TigerVNC viewer for Windows x64; no installer or service, and TLS/VeNCrypt support when the server offers it.'; Released = ('Version ' + $script:TigerVncVersion + ', ' + $script:TigerVncReleased + ' (TigerVNC release page; 24,072,224 bytes; Authenticode-valid, signer Brian Hinz).'); SizeNote = 'About 23 MB.'; Check = ('SourceForge HTTPS plus the pinned SHA-256; Authenticode signer is Brian Hinz. Download ' + $script:TigerVncUrlBase + $script:FileTigerVncWindows + '/download into isos\04-etc\tigervnc\ by hand; the next run verifies it and skips.') }
        [pscustomobject]@{ Name = 'TigerVNC 1.16.2 Linux x64'; Category = '04-etc\tigervnc'; FileName = $script:FileTigerVncLinux; Url = ($script:TigerVncUrlBase + $script:FileTigerVncLinux + '/download'); AlternateUrl = ''; Hash = $script:TigerVncLinuxSha256; SidecarUrl = ''; SidecarName = ''; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Generic Linux x86_64 TigerVNC archive: vncviewer, Xvnc, x0vncserver, vncpasswd, and the X11 server pieces; no w0vncserver.'; Released = ('Version ' + $script:TigerVncVersion + ', ' + $script:TigerVncReleased + ' (TigerVNC release page; 15,042,988 bytes; no publisher checksum).'); SizeNote = 'About 14 MB.'; Check = ('SourceForge HTTPS; TigerVNC publishes no checksum for this generic archive, so the first-download SHA-256 is pinned. Download ' + $script:TigerVncUrlBase + $script:FileTigerVncLinux + '/download into isos\04-etc\tigervnc\ by hand; the next run verifies it and skips.') }
        [pscustomobject]@{ Name = 'UltraVNC 1.8.3.2 Windows portable'; Category = '04-etc\ultravnc'; FileName = $script:FileUltraVncZip; Url = ($script:UltraVncUrlBase + $script:FileUltraVncZip); AlternateUrl = ''; Hash = $script:UltraVncZipSha256; SidecarUrl = ''; SidecarName = ''; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Portable x86/x64 UltraVNC ZIP with server, viewer, SecureVNC DSM plugin, and virtual display driver; the WinPE-friendly path.'; Released = ('Version ' + $script:UltraVncVersion + ', ' + $script:UltraVncReleased + ' (release announcement; 17,283,281 bytes; page size field is stale; hash matches).'); SizeNote = 'About 16 MB.'; Check = ('Official UltraVNC 1.8.3.2 SHA-256 matches the served bytes; the page size field is stale. Authenticode signer is Rudi De Vos. Download ' + $script:UltraVncUrlBase + $script:FileUltraVncZip + ' into isos\04-etc\ultravnc\ by hand; the next run verifies it and skips.') }
        [pscustomobject]@{ Name = 'UltraVNC 1.8.3.2 Windows x64 installer'; Category = '04-etc\ultravnc'; FileName = $script:FileUltraVncInstaller; Url = ($script:UltraVncUrlBase + $script:FileUltraVncInstaller); AlternateUrl = ''; Hash = $script:UltraVncInstallerSha256; SidecarUrl = ''; SidecarName = ''; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'x64 UltraVNC installer for normal Windows service mode, logon-screen access, and unattended support; includes server and viewer.'; Released = ('Version ' + $script:UltraVncVersion + ', ' + $script:UltraVncReleased + ' (release announcement; 6,256,464 bytes; page size field is stale; hash matches).'); SizeNote = 'About 6 MB.'; Check = ('Official UltraVNC 1.8.3.2 SHA-256 matches the served bytes; the page size field is stale. Authenticode signer is Rudi De Vos. Download ' + $script:UltraVncUrlBase + $script:FileUltraVncInstaller + ' into isos\04-etc\ultravnc\ by hand; the next run verifies it and skips.') }
        [pscustomobject]@{ Name = 'Noto Sans Mono CJK KR'; Category = '04-etc\fonts'; FileName = $script:FileFont; Url = $script:FontRawUrl; AlternateUrl = ''; Hash = $script:FontSha256; SidecarUrl = ''; SidecarName = ''; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'Single Regular-weight OFL font for CJK display on Linux and Windows; covers Han, Kana, Hangul, and Bopomofo with KR-default glyph forms.'; Released = ('Version ' + $script:FontVersion + ', April 2021 (file date ' + $script:FontReleased + ' at commit ' + $script:FontCommit.Substring(0, 7) + '; 16,389,532 bytes).'); SizeNote = 'About 15.6 MB.'; Check = ('Download ' + $script:FontRawUrl + ' into isos\04-etc\fonts\ by hand (commit-pinned source; no upstream checksum); the next run verifies SHA-256 and skips it.') }
        [pscustomobject]@{ Name = 'Noto CJK OFL license'; Category = '04-etc\fonts'; FileName = $script:FileFontLicense; Url = $script:FontLicenseUrl; AlternateUrl = ''; Hash = $script:FontLicenseSha256; SidecarUrl = ''; SidecarName = ''; HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'OFL 1.1 text for the bundled Noto CJK font; upstream LICENSE renamed byte-for-byte.'; Released = ('OFL 1.1, file date ' + $script:FontReleased + ' at commit ' + $script:FontCommit.Substring(0, 7) + '.'); SizeNote = 'About 4 KB.'; Check = ('Download ' + $script:FontLicenseUrl + ' into isos\04-etc\fonts\ by hand and save it as OFL.txt; the next run verifies it against the pinned hash and skips it.') }
    )
}

# Verified hashes recorded during this run, keyed by full path. Pinned rows
# are verified by the download engine; Rolling rows resolve live. The readme
# reuses these instead of re-hashing gigabytes on every run.
$script:VerifiedHashes = @{}
# Sidecars fetched this run, keyed by ISO path. Listed in the readme so the
# reader knows the publisher's own checksum file sits next to the ISO.
$script:Sidecars = @{}

# Builds one readme block for a catalog row. Uses the hash verified during
# this run when available; otherwise falls back to the catalog hash for
# Pinned rows. Never throws.
function Format-IsoReadmeEntry($Row, [string]$Root) {
    $lines = @()
    $lines += "== $($Row.Name) ($($Row.Category)\$($Row.FileName)) =="
    $lines += $Row.About
    $lines += "Release: $($Row.Released)  Size: $($Row.SizeNote)"
    $path = Join-Path (Join-Path (Join-Path $Root $script:DirIsos) $Row.Category) $Row.FileName
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
    if ($script:Sidecars.ContainsKey($path)) {
        $lines += "Checksum file (shipped alongside): $($script:Sidecars[$path])"
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
    $factsPath = Join-Path (Join-Path $Root $script:DirTools) $script:FileFacts
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

# Returns true when a publisher checksum sidecar contains the expected hash.
# The check is format-agnostic: GNU, BSD, Fedora/Rocky, and PuTTY sidecars all
# carry the SHA-256 as text. Missing or unreadable files return false.
function Test-SidecarListsHash([string]$Path, [string]$Hash) {
    if (-not $Hash) { return $false }
    try { $text = [IO.File]::ReadAllText($Path) } catch { return $false }
    return ($text.IndexOf($Hash, [StringComparison]::OrdinalIgnoreCase) -ge 0)
}

# Returns true when a sidecar download is an HTML/XML page instead of a
# checksum file (SourceForge interstitials, captive portals, bot checks).
# Any file whose first non-blank character is "<" is treated as markup.
# Never throws.
function Test-SidecarLooksLikeHtml([string]$Path) {
    try { $text = [IO.File]::ReadAllText($Path).TrimStart() } catch { return $false }
    return ($text.Length -gt 0 -and $text[0] -eq '<')
}

# Downloads one catalog row into its category folder. Selects Rolling hashes
# live; Pinned rows verify against the catalog hash. Never throws.
function Save-CatalogRow {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param($Row, [string]$Root)
    $dir = Join-Path (Join-Path $Root $script:DirIsos) $Row.Category
    Initialize-Directory -Path $dir
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
    # Fetch the publisher's checksum sidecar next to the ISO when the row
    # names one (a few KB against gigabytes). Best effort: a missing sidecar
    # never fails the row, it just is not listed in the readme.
    if ($ok -and $Row.SidecarUrl -and $Row.SidecarName) {
        $sidecarPath = Join-Path $dir $Row.SidecarName
        if ((Test-Path -LiteralPath $sidecarPath) -and $expected -and
            -not (Test-SidecarListsHash -Path $sidecarPath -Hash $expected)) {
            Write-Detail "Stale sidecar, re-downloading: $($Row.SidecarName)"
            Remove-Item -LiteralPath $sidecarPath -Force -ErrorAction SilentlyContinue
        }
        if (-not (Test-Path -LiteralPath $sidecarPath)) {
            if (-not (Invoke-FileDownload -Url $Row.SidecarUrl -OutFile $sidecarPath)) {
                Write-Detail "Sidecar unavailable, skipping: $($Row.SidecarName)"
            }
        }
        if (Test-Path -LiteralPath $sidecarPath) {
            if ($expected -and -not (Test-SidecarListsHash -Path $sidecarPath -Hash $expected)) {
                $isHtml = Test-SidecarLooksLikeHtml -Path $sidecarPath
                Remove-Item -LiteralPath $sidecarPath -Force -ErrorAction SilentlyContinue
                if ($isHtml) {
                    Write-Warning "Sidecar $($Row.SidecarName) is an HTML page, not a checksum file; retry later."
                } elseif ($Row.HashKind -eq 'Pinned') {
                    Write-Warning "Sidecar $($Row.SidecarName) does not list the pinned SHA-256; upstream moved past this pin. Re-pin $($Row.Name)."
                } else {
                    Write-Warning "Sidecar $($Row.SidecarName) does not list the resolved checksum; re-run later."
                }
            } else {
                $script:Sidecars[$outFile] = $Row.SidecarName
            }
        }
    }
    return $ok
}

# Downloads every selected catalog row, netboot first so network rescue is
# usable even when a later multi-GB file fails. Never throws.
function Save-CatalogIsos {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Root, [string]$NetbootArch = 'x64', [string]$MintHwe = 'None')
    $order = @{ '01-Network' = 0; '02-Rescue' = 1; '03-Installers' = 2; '04-etc' = 3 }
    $rows = Get-RecoveryCatalog | Where-Object {
        (($_.NetbootVariant -eq '') -or ($_.NetbootVariant -eq $NetbootArch)) -and
        (($_.MintHwe -eq '') -or ($_.MintHwe -eq $MintHwe))
    } | Sort-Object { $order[($_.Category -split '\\')[0]] }, Name
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
    $ventoyDir = Join-Path $Root $script:DirVentoy
    Initialize-Directory -Path $ventoyDir
    $ventoyManual = @(
        'Download the Windows zip by hand from ' + $script:VentoyReleasesUrl + ',',
        "verify it against sha256.txt, and extract it into $ventoyDir."
    )
    $release = Get-GitHubLatestAsset -Repo 'ventoy/Ventoy' -AssetPattern '^ventoy-.*-windows\.zip$' -HashAssetName 'sha256.txt'
    if (-not $release) { return $false }
    if (-not $release.HashUrl) {
        Write-Failure -Name 'Ventoy' -Detail 'Release has no sha256.txt asset.' -Manual $ventoyManual
        return $false
    }
    try {
        $hashText = Invoke-WebText -Uri $release.HashUrl
    } catch {
        $detail = if ($_.Exception) { $_.Exception.Message } else { "$_" }
        Write-Failure -Name 'Ventoy' -Detail "sha256.txt download failed: $detail" -Manual $ventoyManual
        return $false
    }
    $expected = Find-HashInChecksumText -Text "$hashText" -FileName $release.Name
    if (-not $expected) {
        Write-Failure -Name 'Ventoy' -Detail "No checksum entry for $($release.Name)." -Manual $ventoyManual
        return $false
    }
    Write-Detail "Ventoy hash for $($release.Name): $expected"
    $exe = Join-Path $ventoyDir $script:FileVentoyExe
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
            $inner = if ($wrapper -and (Test-Path -LiteralPath (Join-Path $wrapper.FullName $script:FileVentoyExe))) { $wrapper.FullName } else { $stageDir }
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
        $exe = Join-Path $ventoyDir $script:FileVentoyExe
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
    Initialize-Directory -Path $toolsDir
    $ok = $true
    $release = Get-GitHubLatestAsset -Repo 'pbatard/rufus' -AssetPattern '^rufus-.*p\.exe$'
    if (-not $release) {
        $ok = $false
    } else {
        Write-Warning 'Rufus publishes no hash; the exe is kept as downloaded.'
        if (-not (Save-VerifiedFile -Url $release.ZipUrl -OutFile (Join-Path $toolsDir $release.Name) -Name 'Rufus portable')) { $ok = $false }
    }
    $fidoPath = Join-Path $toolsDir $script:FileFido
    if (Test-Path -LiteralPath $fidoPath) {
        Write-Ok 'Skipped (present): Fido.ps1'
        $script:Results += [pscustomobject]@{ Name = $script:FileFido; Status = 'Skipped'; Detail = 'present, no hash to check' }
    } else {
        if ($PSCmdlet.ShouldProcess($fidoPath, "Download $($script:FidoUrl)")) {
            if (Invoke-FileDownload -Url $script:FidoUrl -OutFile $fidoPath) {
                Write-Ok 'Downloaded: Fido.ps1'
                $script:Results += [pscustomobject]@{ Name = $script:FileFido; Status = 'Downloaded'; Detail = 'unverified upstream script' }
            } else {
                Write-Failure -Name $script:FileFido -Detail "Download failed: $($script:FidoUrl)" -Manual @(
                    "Save $($script:FidoUrl) into $fidoPath by hand."
                )
                $ok = $false
            }
        }
    }
    return $ok
}

# Restores a copyparty build moved aside by an interrupted or failed update.
# Returns $true when the move happened; names the .prev path on failure.
function Restore-PreviousCopyparty([string]$PrevFile, [string]$Target) {
    try {
        Move-Item -LiteralPath $PrevFile -Destination $Target -Force -ErrorAction Stop
        return $true
    } catch {
        Write-Detail "Could not restore $(Split-Path -Leaf $Target); the previous build is at $PrevFile."
        return $false
    }
}

# Downloads the copyparty sfx and Windows exe from ONE GitHub release into
# isos\04-etc\copyparty, verified against GitHub's per-asset sha256 digest.
# Records the resolved rows for the isos readme. Never throws.
function Save-CopypartyTools {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Root)
    $script:CopypartyRows = @()
    $dir = Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirCopyparty
    Initialize-Directory -Path $dir
    # An interrupted update can leave only <name>.prev. Put it back before the
    # release lookup so a failing API never leaves no runnable file.
    if ($PSCmdlet.ShouldProcess($dir, 'Restore an interrupted update')) {
        foreach ($orphanName in @($script:FileCopypartySfx, $script:FileCopypartyExe)) {
            $orphanTarget = Join-Path $dir $orphanName
            $orphanPrev = "$orphanTarget.prev"
            if ((Test-Path -LiteralPath $orphanPrev) -and -not (Test-Path -LiteralPath $orphanTarget)) {
                Restore-PreviousCopyparty -PrevFile $orphanPrev -Target $orphanTarget | Out-Null
            }
        }
    }
    $manual = @(
        "Open $($script:CopypartyReleasesUrl) and download $($script:FileCopypartySfx) and $($script:FileCopypartyExe) into $dir."
    )
    try {
        $release = Invoke-GitHubApiJson -Uri $script:CopypartyApiUrl
    } catch {
        $detail = if ($_.Exception) { $_.Exception.Message } else { "$_" }
        $lookupManual = @('GitHub API may be rate-limited (403 without a token); re-run later.') + $manual
        Write-Failure -Name 'copyparty release lookup' -Detail $detail -Manual $lookupManual
        return $false
    }
    $tag = [string]$release.tag_name
    $publishedAt = Format-ReleaseDate $release.published_at
    if (-not $tag) {
        Write-Failure -Name 'copyparty release lookup' -Detail 'Release has no tag name.' -Manual $manual
        return $false
    }
    # A .partial from another release cannot be resumed against this one.
    # Clear it when the tag changes and remember the tag for the next run.
    if ($PSCmdlet.ShouldProcess($dir, "Record release $tag")) {
        $markerPath = Join-Path $dir $script:FileCopypartyTag
        try {
            $oldTag = ''
            if (Test-Path -LiteralPath $markerPath) {
                $oldTag = ([IO.File]::ReadAllText($markerPath)).Trim()
            }
            if ($oldTag -ne $tag) {
                Get-ChildItem -LiteralPath $dir -Filter '*.partial' -File -ErrorAction SilentlyContinue | ForEach-Object {
                    Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
                }
            }
            [IO.File]::WriteAllText($markerPath, $tag, [Text.UTF8Encoding]::new($false))
        } catch {
            $detail = if ($_.Exception) { $_.Exception.Message } else { "$_" }
            Write-Failure -Name 'copyparty release marker' -Detail "Could not record ${tag}: $detail" -Manual @(
                "Check write access to $dir, then re-run."
            )
        }
    }
    $ok = $true
    foreach ($name in @($script:FileCopypartySfx, $script:FileCopypartyExe)) {
        $asset = @($release.assets | Where-Object { $_.name -eq $name }) | Select-Object -First 1
        if (-not $asset) {
            Write-Failure -Name $name -Detail "No $name asset in ${tag}." -Manual $manual
            $ok = $false
            continue
        }
        if ("$($asset.digest)" -notmatch '^sha256:([0-9a-fA-F]{64})$') {
            Write-Failure -Name $name -Detail "No usable sha256 digest on the $tag asset." -Manual @(
                "Download $($asset.browser_download_url) by hand into $dir."
            )
            $ok = $false
            continue
        }
        $hash = $Matches[1].ToLowerInvariant()
        $outFile = Join-Path $dir $name
        $exists = Test-Path -LiteralPath $outFile
        $isStale = $false
        if ($exists) {
            try {
                $isStale = -not (Test-LocalFileHash -Path $outFile -ExpectedHash $hash)
            } catch {
                $detail = if ($_.Exception) { $_.Exception.Message } else { "$_" }
                Write-Failure -Name $name -Detail "Could not hash the existing ${name}: $detail" -Manual @(
                    "Close anything using $outFile, then re-run."
                )
                $ok = $false
                continue
            }
        }
        # Save-VerifiedFile deletes a stale versionless file before downloading.
        # Keep it as .prev so a failed update cannot destroy the only working
        # copy, and restore it when the download fails.
        $prevFile = "$outFile.prev"
        $backedUp = $false
        if ($PSCmdlet.ShouldProcess($outFile, 'Back up the existing file')) {
            if ($exists -and $isStale) {
                try {
                    Move-Item -LiteralPath $outFile -Destination $prevFile -Force -ErrorAction Stop
                    $backedUp = $true
                } catch {
                    Write-Failure -Name $name -Detail "Could not move the old $name aside." -Manual @(
                        "Close anything using $outFile, then re-run."
                    )
                    $ok = $false
                    continue
                }
            } elseif (Test-Path -LiteralPath $prevFile) {
                if (Test-Path -LiteralPath $outFile) {
                    Remove-Item -LiteralPath $prevFile -Force -ErrorAction SilentlyContinue
                } else {
                    $backedUp = $true
                }
            }
        } elseif ($exists -and $isStale) {
            # A declined backup must not let Save-VerifiedFile delete the only
            # working copy before the download starts.
            Write-Detail "Kept the existing $name; backup declined, so the update is skipped."
            $ok = $false
            continue
        }
        $saved = $false
        $resultsBefore = $script:Results.Count
        try {
            $saved = Save-VerifiedFile -Url $asset.browser_download_url -OutFile $outFile -ExpectedHash $hash -Name $name
        } catch {
            $detail = if ($_.Exception) { $_.Exception.Message } else { "$_" }
            Write-Failure -Name $name -Detail "Download failed: $detail" -Manual @(
                "Download $($asset.browser_download_url) by hand into $dir."
            )
            if ($backedUp) {
                Restore-PreviousCopyparty -PrevFile $prevFile -Target $outFile | Out-Null
            }
            $ok = $false
            continue
        }
        if (-not $saved) {
            if ($backedUp) {
                if (Restore-PreviousCopyparty -PrevFile $prevFile -Target $outFile) {
                    Write-Detail "Download failed; restored the previous $name."
                }
            }
            $ok = $false
            continue
        }
        # A confirmed No can make Save-VerifiedFile return true without a file;
        # document only bytes that are on disk and match the digest.
        $verified = $false
        try {
            $verified = (Test-Path -LiteralPath $outFile) -and (Test-LocalFileHash -Path $outFile -ExpectedHash $hash)
        } catch {
            $verified = $false
        }
        if (-not $verified) {
            if ($backedUp) {
                if (Restore-PreviousCopyparty -PrevFile $prevFile -Target $outFile) {
                    Write-Detail "Downloaded file failed verification; restored the previous $name."
                }
            }
            if ($script:Results.Count -gt $resultsBefore) {
                Write-Failure -Name $name -Detail 'File failed verification after download.' -Manual @(
                    "Download $($asset.browser_download_url) by hand into $dir."
                )
            } else {
                Write-Detail "No verified file was produced for $name."
            }
            $ok = $false
            continue
        }
        if ($backedUp) { Remove-Item -LiteralPath $prevFile -Force -ErrorAction SilentlyContinue }
        # The row drives the isos readme, so it must describe only a file that
        # verified this run; a restored old build gets the fallback entry.
        if (-not $WhatIfPreference) {
            $script:VerifiedHashes[$outFile] = $hash
            $title = if ($name -eq $script:FileCopypartySfx) { 'copyparty sfx (Linux/macOS)' } else { 'copyparty exe (Windows)' }
            $about = if ($name -eq $script:FileCopypartySfx) { 'Portable file server for Linux/macOS live sessions; runs with python3.' } else { 'Portable file server for Windows 8+ x64; no Python needed.' }
            $sizeMb = [math]::Round($asset.size / 1MB, 1).ToString([Globalization.CultureInfo]::InvariantCulture)
            $script:CopypartyRows += [pscustomobject]@{
                Name = $title
                Category = (Join-Path '04-etc' $script:DirCopyparty)
                FileName = $name
                Url = $asset.browser_download_url
                Hash = $hash
                HashKind = 'GitHub digest'
                Released = "$tag (GitHub asset digest, sha256)"
                Tag = $tag
                PublishedAt = $publishedAt
                SizeNote = "About $sizeMb MB."
                About = $about
                Check = "GitHub API releases/tags/$tag digest field, or the release page."
            }
        }
    }
    return $ok
}

# Returns true when every allowlisted payload file exists under bin\ and
# matches its pinned SHA-256. Never throws.
function Test-ImgBurnPayload([string]$BinDir, [System.Collections.IDictionary]$Payload) {
    foreach ($name in $Payload.Keys) {
        $path = Join-Path $BinDir $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $false }
        try {
            if (-not (Test-LocalFileHash -Path $path -ExpectedHash ([string]$Payload[$name]))) { return $false }
        } catch {
            return $false
        }
    }
    return $true
}

# Locates a 7z.exe that can unpack the ImgBurn NSIS installer: first the
# private copy bootstrapped from the pinned 7-Zip installer under
# tools\imgburn\7z, then a host installation. Returns '' when none is usable.
function Find-SevenZipExe {
    [CmdletBinding()]
    param([string]$Root)
    $bootstrapDir = Join-Path (Join-Path (Join-Path $Root $script:DirTools) 'imgburn') '7z'
    $bootExe = Join-Path $bootstrapDir '7z.exe'
    if (Test-Path -LiteralPath $bootExe -PathType Leaf) { return $bootExe }
    $zipDir = Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirSevenZip
    $zipr = Join-Path $zipDir $script:FileSevenZipBootstrap
    $zipInstaller = Join-Path $zipDir $script:FileSevenZipInstaller
    if ((Test-Path -LiteralPath $zipr -PathType Leaf) -and (Test-Path -LiteralPath $zipInstaller -PathType Leaf)) {
        Initialize-Directory -Path $bootstrapDir
        $result = Invoke-Cli -Command $zipr -Arguments @('x', $zipInstaller, '7z.exe', '7z.dll', "-o$bootstrapDir", '-y')
        if ($result.ExitCode -eq 0 -and (Test-Path -LiteralPath $bootExe -PathType Leaf)) { return $bootExe }
        Write-Detail "7-Zip bootstrap failed (7zr exit $($result.ExitCode)); trying a host 7z.exe."
    }
    $hostCommand = Get-Command 7z.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($hostCommand) { return $hostCommand.Source }
    $candidates = @()
    if ($env:ProgramFiles) { $candidates += (Join-Path $env:ProgramFiles '7-Zip\7z.exe') }
    if (${env:ProgramFiles(x86)}) { $candidates += (Join-Path ${env:ProgramFiles(x86)} '7-Zip\7z.exe') }
    if ($env:LOCALAPPDATA) { $candidates += (Join-Path $env:LOCALAPPDATA 'Programs\7-Zip\7z.exe') }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    return ''
}

# Unpacks an NSIS installer with the supplied 7z.exe. Exit 1 ("warning") is a
# failure here; the caller verifies every extracted hash before moving files.
function Expand-NsisPayload([string]$SevenZip, [string]$Installer, [string]$Destination) {
    try {
        $result = Invoke-Cli -Command $SevenZip -Arguments @('x', $Installer, "-o$Destination", '-y', '-bso0', '-bsp0')
    } catch {
        Write-Detail "7-Zip could not start: $($_.Exception.Message)"
        return $false
    }
    if ($result.ExitCode -ne 0) {
        Write-Detail "7-Zip extraction failed (exit $($result.ExitCode)): $($result.StdErr)"
        return $false
    }
    return $true
}

# Writes the portable launcher and seeds the settings file beside ImgBurn.exe.
# Never overwrites an existing ImgBurn.ini (user settings live there).
# Returns true on success and records a failure itself on write errors.
function Write-ImgBurnPortableFiles([string]$TopicDir, [string]$BinDir) {
    $launcherPath = Join-Path $TopicDir $script:FileImgBurnLauncher
    $iniPath = Join-Path $BinDir $script:FileImgBurnIni
    $launcher = '@echo off' + "`r`n" + 'start "" /d "%~dp0bin" "%~dp0bin\ImgBurn.exe" /PORTABLE /SETTINGS "%~dp0bin\ImgBurn.ini"' + "`r`n"
    try {
        [IO.File]::WriteAllText($launcherPath, $launcher, [Text.UTF8Encoding]::new($false))
        if (-not (Test-Path -LiteralPath $iniPath)) {
            [IO.File]::WriteAllText($iniPath, '', [Text.UTF8Encoding]::new($false))
        }
        return $true
    } catch {
        $detail = if ($_.Exception) { $_.Exception.Message } else { "$_" }
        Write-Failure -Name 'ImgBurn' -Detail "Could not write the portable launcher or settings file: $detail" -Manual @(
            "Create $launcherPath by hand; it must start bin\ImgBurn.exe with /PORTABLE /SETTINGS bin\ImgBurn.ini.",
            "Create an empty $iniPath only when it does not exist."
        )
        return $false
    }
}

# Installs the portable ImgBurn payload into isos\04-etc\imgburn\bin by
# extracting the official installer with 7-Zip. The installer is never
# executed, so its OpenCandy offer never runs, and it is deleted after a
# verified extraction. Never throws.
function Install-ImgBurnPortable {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$Root,
        [System.Collections.IDictionary]$Payload = $script:ImgBurnPayload,
        [string]$InstallerHash = $script:ImgBurnInstallerSha256
    )
    $topicDir = Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirImgBurn
    $binDir = Join-Path $topicDir 'bin'
    $hostDir = Join-Path (Join-Path $Root $script:DirTools) 'imgburn'
    $stageDir = Join-Path $hostDir '_stage'
    if (-not $PSCmdlet.ShouldProcess($binDir, "Install ImgBurn $($script:ImgBurnVersion) portable")) { return $true }
    Initialize-Directory -Path $binDir
    # An interrupted run leaves NSIS scaffolding on the prep host. It must
    # never reach the stick, and a skip run still cleans it.
    Remove-Item -LiteralPath $stageDir -Recurse -Force -ErrorAction SilentlyContinue
    $manual = @(
        ("Place these files under {0}: {1}." -f $binDir, (@($Payload.Keys) -join ', ')),
        'The next run verifies their SHA-256 values and skips the download.'
    )
    if (Test-ImgBurnPayload -BinDir $binDir -Payload $Payload) {
        if (-not (Write-ImgBurnPortableFiles -TopicDir $topicDir -BinDir $binDir)) { return $false }
        Write-Ok "Skipped (verified): ImgBurn $($script:ImgBurnVersion)"
        $script:Results += [pscustomobject]@{ Name = 'ImgBurn'; Status = 'Skipped'; Detail = 'payload hashes match' }
        foreach ($name in $Payload.Keys) {
            $script:VerifiedHashes[(Join-Path $binDir $name)] = ([string]$Payload[$name]).ToLowerInvariant()
        }
        return $true
    }
    Initialize-Directory -Path $hostDir
    $installerPath = Join-Path $hostDir $script:FileImgBurnInstaller
    try {
        if (-not (Save-VerifiedFile -Url $script:ImgBurnUrl -OutFile $installerPath -ExpectedHash $InstallerHash -Name "ImgBurn $($script:ImgBurnVersion) installer")) { return $false }
    } catch {
        $detail = if ($_.Exception) { $_.Exception.Message } else { "$_" }
        Write-Failure -Name 'ImgBurn' -Detail "Installer verification failed: $detail" -Manual $manual
        return $false
    }
    $sevenZip = Find-SevenZipExe -Root $Root
    if (-not $sevenZip) {
        Write-Failure -Name 'ImgBurn' -Detail 'No 7-Zip extractor was available (bootstrap and host lookup failed).' -Manual (@(
            'Re-run after the 7-Zip files exist under isos\04-etc\7zip\, or install 7-Zip on this PC.'
        ) + $manual)
        return $false
    }
    Initialize-Directory -Path $stageDir
    if (-not (Expand-NsisPayload -SevenZip $sevenZip -Installer $installerPath -Destination $stageDir)) {
        Write-Failure -Name 'ImgBurn' -Detail 'The installer payload could not be extracted.' -Manual $manual
        return $false
    }
    $found = @(Get-ChildItem -LiteralPath $stageDir -Recurse -File -Filter $script:FileImgBurnExe -ErrorAction SilentlyContinue) | Select-Object -First 1
    if (-not $found) {
        Write-Failure -Name 'ImgBurn' -Detail "No $($script:FileImgBurnExe) in the extracted payload." -Manual $manual
        return $false
    }
    $payloadRoot = Split-Path -Parent $found.FullName
    $staged = @{}
    foreach ($name in $Payload.Keys) {
        $source = Join-Path $payloadRoot $name
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            Write-Failure -Name 'ImgBurn' -Detail "Extracted payload is missing $name." -Manual $manual
            return $false
        }
        try {
            if (-not (Test-LocalFileHash -Path $source -ExpectedHash ([string]$Payload[$name]))) {
                Write-Failure -Name 'ImgBurn' -Detail "Extracted $name does not match its pinned hash." -Manual $manual
                return $false
            }
        } catch {
            $detail = if ($_.Exception) { $_.Exception.Message } else { "$_" }
            Write-Failure -Name 'ImgBurn' -Detail "Could not hash extracted ${name}: $detail" -Manual $manual
            return $false
        }
        $staged[$name] = $source
    }
    try {
        foreach ($name in $Payload.Keys) {
            $target = Join-Path $binDir $name
            $parent = Split-Path -Parent $target
            if ($parent) { Initialize-Directory -Path $parent }
            Move-Item -LiteralPath $staged[$name] -Destination $target -Force
            if (-not (Test-LocalFileHash -Path $target -ExpectedHash ([string]$Payload[$name]))) {
                throw "verification failed after moving $name"
            }
        }
    } catch {
        $detail = if ($_.Exception) { $_.Exception.Message } else { "$_" }
        Write-Failure -Name 'ImgBurn' -Detail "Could not install the payload: $detail" -Manual $manual
        return $false
    }
    Remove-Item -LiteralPath $stageDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $installerPath -Force -ErrorAction SilentlyContinue
    if (-not (Write-ImgBurnPortableFiles -TopicDir $topicDir -BinDir $binDir)) { return $false }
    foreach ($name in $Payload.Keys) {
        $script:VerifiedHashes[(Join-Path $binDir $name)] = ([string]$Payload[$name]).ToLowerInvariant()
    }
    Write-Ok "Installed: ImgBurn $($script:ImgBurnVersion) portable"
    $script:Results += [pscustomobject]@{ Name = 'ImgBurn'; Status = 'Downloaded'; Detail = 'verified payload' }
    return $true
}

# Builds the pinned fallback release object. The SHA-256 is the one Mozilla
# published for that release; it is used only when the live lookup fails.
function New-FirefoxFallbackRelease {
    $version = $script:FirefoxFallbackVersion
    $fileName = 'Firefox Setup ' + $version + '.exe'
    [pscustomobject]@{
        Version = $version
        FileName = $fileName
        Url = $script:FirefoxReleasesUrl + $version + '/win64/en-US/' + [uri]::EscapeDataString($fileName)
        ChecksumUrl = $script:FirefoxReleasesUrl + $version + '/SHA256SUMS'
        ChecksumPath = 'win64/en-US/' + $fileName
        Source = 'fallback'
        FallbackHash = $script:FirefoxFallbackSha256
        Released = $script:FirefoxFallbackReleased
    }
}

# Looks up the exact per-release date for an ESR version. Returns '' when the
# release catalog is unavailable or has no entry.
function Get-FirefoxReleaseDate([string]$Version) {
    try {
        $data = Invoke-RestMethod -Uri $script:FirefoxJsonUrl -Headers @{ 'User-Agent' = 'pc-recovery' } -UseBasicParsing
        $entry = $data.releases.('firefox-' + $Version)
        if ($entry -and $entry.date) { return [string]$entry.date }
    } catch {
        Write-Detail "Firefox release date lookup failed: $($_.Exception.Message)"
    }
    return ''
}

# Resolves the current Firefox ESR win64/en-US installer from Mozilla's
# product metadata. Returns the pinned fallback when the lookup or its
# validation fails. Never throws.
function Get-FirefoxEsrRelease {
    try {
        $meta = Invoke-RestMethod -Uri $script:FirefoxVersionsUrl -Headers @{ 'User-Agent' = 'pc-recovery' } -UseBasicParsing
    } catch {
        Write-Detail "Firefox ESR metadata lookup failed: $($_.Exception.Message)"
        return (New-FirefoxFallbackRelease)
    }
    $version = [string]$meta.FIREFOX_ESR
    if ($version -notmatch '^\d+\.\d+(\.\d+)?esr$') {
        Write-Detail "Firefox ESR metadata returned no usable FIREFOX_ESR ('$version')."
        return (New-FirefoxFallbackRelease)
    }
    $fileName = 'Firefox Setup ' + $version + '.exe'
    [pscustomobject]@{
        Version = $version
        FileName = $fileName
        Url = $script:FirefoxReleasesUrl + $version + '/win64/en-US/' + [uri]::EscapeDataString($fileName)
        ChecksumUrl = $script:FirefoxReleasesUrl + $version + '/SHA256SUMS'
        ChecksumPath = 'win64/en-US/' + $fileName
        Source = 'live'
        FallbackHash = ''
        Released = (Get-FirefoxReleaseDate -Version $version)
    }
}

# Returns the SHA-256 for one installer from the release SHA256SUMS, or ''.
# Does not record a failure: the caller falls back to the pinned release.
function Get-FirefoxEsrHash([string]$ChecksumUrl, [string]$ChecksumPath) {
    try {
        $text = Invoke-WebText -Uri $ChecksumUrl
    } catch {
        Write-Detail "Firefox SHA256SUMS download failed: $($_.Exception.Message)"
        return ''
    }
    $hash = Find-HashInChecksumText -Text "$text" -FileName $ChecksumPath
    if (-not $hash) { Write-Detail "No SHA256SUMS entry for $ChecksumPath." }
    return $hash
}

# Resolves and stages the current Firefox ESR installer. Live metadata and its
# SHA256SUMS are authoritative; when either lookup fails, the pinned fallback
# is used with a warning. Never throws.
function Save-FirefoxEsr {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Root)
    $dir = Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirFirefox
    if (-not $PSCmdlet.ShouldProcess($dir, 'Resolve and download Firefox ESR')) { return $true }
    Initialize-Directory -Path $dir
    $release = Get-FirefoxEsrRelease
    $hash = ''
    if ($release.Source -eq 'live') {
        $hash = Get-FirefoxEsrHash -ChecksumUrl $release.ChecksumUrl -ChecksumPath $release.ChecksumPath
    }
    if (-not $hash) {
        $release = New-FirefoxFallbackRelease
        $hash = $release.FallbackHash
        Write-Warning "Firefox ESR live lookup failed; using the pinned $($release.Version) fallback. Re-run online for the current ESR."
    }
    $script:FirefoxResolved = $release
    $outFile = Join-Path $dir $release.FileName
    $label = 'Firefox ESR ' + $release.Version
    if ($release.Source -eq 'fallback') { $label += ' (pinned fallback)' }
    $manual = @(
        ("Download {0} by hand into {1}." -f $release.Url, $outFile),
        ("SHA-256 must be {0}. A later run that resolves this same version verifies it and skips the download; a different resolved version downloads its own installer and lists this file as unverified." -f $hash)
    )
    if ($release.Source -eq 'fallback') {
        $manual += 'The live ESR lookup failed; this is the pinned fallback release.'
    }
    try {
        if (-not (Save-VerifiedFile -Url $release.Url -OutFile $outFile -ExpectedHash $hash -Name $label -Manual $manual)) { return $false }
    } catch {
        $detail = if ($_.Exception) { $_.Exception.Message } else { "$_" }
        Write-Failure -Name 'Firefox ESR' -Detail "Download failed: $detail" -Manual $manual
        return $false
    }
    if (-not (Test-Path -LiteralPath $outFile -PathType Leaf)) {
        Write-Failure -Name 'Firefox ESR' -Detail 'Download reported success but no file exists.' -Manual $manual
        return $false
    }
    $script:VerifiedHashes[$outFile] = $hash.ToLowerInvariant()
    $script:FirefoxRelease = [pscustomobject]@{
        Version = $release.Version
        FileName = $release.FileName
        Url = $release.Url
        Hash = $hash.ToLowerInvariant()
        Source = $release.Source
        OutFile = $outFile
        Released = $release.Released
    }
    Write-Detail "Firefox ESR $($release.Version) staged ($($release.Source))."
    return $true
}

# Builds the isos readme block for Firefox ESR. A release verified this run is
# documented as verified; an installer left by an earlier run is listed with
# its on-disk hash and an explicit "not verified this run" label; an empty
# folder says so. Never claims a stale file is current.
function Get-FirefoxIsosBlock([string]$Root) {
    $dir = Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirFirefox
    if ($script:FirefoxRelease -and $script:VerifiedHashes.ContainsKey($script:FirefoxRelease.OutFile)) {
        if ($script:FirefoxRelease.Source -eq 'fallback') {
            $source = 'pinned fallback; live lookup failed'
            $hashKind = 'pinned fallback'
        } else {
            $source = 'resolved live'
            $hashKind = 'Mozilla SHA256SUMS'
        }
        $row = [pscustomobject]@{
            Name = 'Firefox ESR'
            Category = (Join-Path '04-etc' $script:DirFirefox)
            FileName = $script:FirefoxRelease.FileName
            Url = $script:FirefoxRelease.Url
            Hash = $script:FirefoxRelease.Hash
            HashKind = $hashKind
            Released = ('Version ' + $script:FirefoxRelease.Version + ', ' + $source + '.')
            SizeNote = 'About 86 MB.'
            About = 'Offline Firefox ESR browser for Windows 11/Tiny11 where Edge is removed.'
            Check = 'Mozilla release SHA256SUMS; verify Authenticode with Get-AuthenticodeSignature.'
        }
        $block = Format-IsoReadmeEntry -Row $row -Root $Root
        $others = @(Get-ChildItem -LiteralPath $dir -Filter 'Firefox Setup *.exe' -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne $script:FirefoxRelease.FileName } | Sort-Object LastWriteTime -Descending)
        foreach ($file in $others) {
            $block += "`r`n`r`n" + (Format-ManualIsoReadmeEntry -Title 'Firefox ESR (other installer, not verified this run)' -Path $file.FullName -Folder (Join-Path '04-etc' $script:DirFirefox) -Note 'Installer left in this folder by another run; not verified against Mozilla SHA256SUMS this run.' -Root $Root)
        }
        return $block
    }
    $existing = @(Get-ChildItem -LiteralPath $dir -Filter 'Firefox Setup *.exe' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    if ($existing.Count -gt 0) {
        $blocks = @()
        foreach ($file in $existing) {
            $blocks += (Format-ManualIsoReadmeEntry -Title 'Firefox ESR (present, not verified this run)' -Path $file.FullName -Folder (Join-Path '04-etc' $script:DirFirefox) -Note 'Present on disk but not verified against Mozilla SHA256SUMS this run; re-run online to resolve and verify.' -Root $Root)
        }
        return ($blocks -join "`r`n`r`n")
    }
    return ('== Firefox ESR (not present) ==' + "`r`n" + 'Run the prep script with network access; the current ESR is resolved live and falls back to the pinned release.')
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
    $installersDir = Join-Path (Join-Path $Root $script:DirIsos) '03-Installers'
    Initialize-Directory -Path $installersDir
    $existing = Find-WindowsIso -InstallersDir $installersDir
    if ($existing.Count -gt 0) {
        Write-Ok "Skipped (present): $($existing[0].Name)"
        $script:Results += [pscustomobject]@{ Name = 'Windows 11 ISO'; Status = 'Skipped'; Detail = $existing[0].Name }
        return $true
    }
    $fidoPath = Join-Path (Join-Path $Root $script:DirTools) $script:FileFido
    if (-not (Test-Path -LiteralPath $fidoPath)) {
        Write-Failure -Name 'Windows 11 ISO' -Detail 'Fido.ps1 is missing; cannot resolve the Microsoft URL.' -Manual @(
            'Open ' + $script:MsDownloadPage + ' and download the ISO by hand,',
            "then place the Windows ISO (" + $script:WinIsoNaming + ") into $installersDir.",
            $script:ThirdPartyTip
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
            'Open ' + $script:MsDownloadPage + ' and download the ISO by hand,',
            "then place the Windows ISO (" + $script:WinIsoNaming + ") into $installersDir.",
            $script:ThirdPartyTip
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
# Retry hints: MakerHintAdmin (maker download, normal shell), MakerHintSudo
# (no elevation, normal shell), MakerHintManual (full manual build steps, also
# the Invoke-SafeStep fallback; ISO name via -f). Never throws.
function Invoke-Tiny11Build {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Root, [switch]$Elevate, [switch]$CleanDownloads)
    $builderDir = Join-Path (Join-Path $Root $script:DirTools) $script:DirBuilder
    Initialize-Directory -Path $builderDir
    $release = Get-GitHubLatestAsset -Repo 'ntdevlabs/tiny11builder' -AssetPattern '^Tiny11Builder-.*-win-x64\.zip$' -HashSuffix '.sha256'
    if (-not $release) { return $false }
    $builderManual = @(
        'Download the builder by hand from ' + $script:Tiny11BuilderReleasesUrl + ', run its app from an elevated shell, and save the resulting ISO as isos\03-Installers\tiny11\tiny11.iso.'
    )
    if (-not $release.HashUrl) {
        Write-Failure -Name 'Tiny11 builder' -Detail 'Release has no published .sha256 sidecar.' -Manual $builderManual
        return $false
    }
    try {
        $hashText = Invoke-WebText -Uri $release.HashUrl
    } catch {
        $detail = if ($_.Exception) { $_.Exception.Message } else { "$_" }
        Write-Failure -Name 'Tiny11 builder' -Detail "Hash download failed: $detail" -Manual $builderManual
        return $false
    }
    $expected = Find-HashInChecksumText -Text "$hashText" -FileName $release.Name
    if (-not $expected) {
        Write-Failure -Name 'Tiny11 builder' -Detail "No checksum entry for $($release.Name)." -Manual $builderManual
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
    $makerPath = Join-Path $builderDir $script:FileMaker
    if (-not (Test-Path -LiteralPath $makerPath)) {
        if (-not $PSCmdlet.ShouldProcess($makerPath, "Download $($script:Tiny11MakerUrl)")) { return $true }
        Write-Warning 'tiny11maker.ps1 has no published hash; review it before the elevated build runs.'
        if (-not (Invoke-FileDownload -Url $script:Tiny11MakerUrl -OutFile $makerPath)) {
            $makerManual = if ($Elevate -and $script:UseSudo) {
                @(
                    "Save $($script:Tiny11MakerUrl) into $makerPath by hand.",
                    'Then re-run with -Elevate.'
                )
            } elseif (Test-IsAdministrator) {
                @(
                    'This shell is already elevated; run the manual steps below.',
                    ($script:MakerHintManual -f 'the official ISO')
                )
            } else {
                @(
                    "Save $($script:Tiny11MakerUrl) into $makerPath by hand.",
                    $script:MakerHintAdmin
                )
            }
            Write-Failure -Name 'Tiny11 builder' -Detail "tiny11maker.ps1 download failed." -Manual $makerManual
            return $false
        }
    }
    $installersDir = Join-Path (Join-Path $Root $script:DirIsos) $script:DirInstallers
    $tiny11Dir = Join-Path $installersDir $script:DirTiny11
    Initialize-Directory -Path $tiny11Dir
    $finalIso = Join-Path $tiny11Dir $script:FileTiny11Iso
    if (Test-Path -LiteralPath $finalIso) {
        Write-Ok 'Skipped (present): tiny11.iso'
        $script:Results += [pscustomobject]@{ Name = 'Tiny11 ISO'; Status = 'Skipped'; Detail = 'present' }
        return $true
    }
    $official = Find-WindowsIso -InstallersDir $installersDir
    if ($official.Count -eq 0) {
        Write-Failure -Name 'Tiny11 ISO' -Detail 'No official Windows ISO to build from.' -Manual @(
            'Place the official Windows ISO (' + $script:WinIsoNaming + ') into 03-Installers first (Fido step above), then re-run.'
        )
        return $false
    }
    if (-not ($Elevate -and $script:UseSudo)) {
        $skipDetail = 'Privileged build skipped: no elevation.'
        $skipManual = @($script:MakerHintSudo, ($script:MakerHintManual -f $official[0].Name))
        if (Test-IsAdministrator) {
            $skipDetail = 'Scripted build skipped: sudo is not used from an elevated shell.'
            $skipManual = @(
                'This shell is already elevated; run the manual steps below.',
                ($script:MakerHintManual -f $official[0].Name)
            )
        }
        Write-Failure -Name 'Tiny11 ISO' -Detail $skipDetail -Manual $skipManual
        return $false
    }
    if (-not $PSCmdlet.ShouldProcess($finalIso, 'Mount official ISO and run tiny11maker.ps1 elevated')) { return $true }
    # Pre-stage autounattend.xml next to the maker: the script fetches it from a
    # deleted 'main' branch (404) when absent, and deletes it when it finishes.
    $answerPath = Join-Path $builderDir $script:FileAnswer
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
    $oscdimgPath = Join-Path $builderDir $script:FileOscdimg
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
            ($script:MakerHintManual -f $official[0].Name)
        )
        return $false
    }
    if (-not (Test-Path -LiteralPath $finalIso)) {
        Write-Failure -Name 'Tiny11 ISO' -Detail 'Build finished without producing tiny11.iso.' -Manual @(
            ($script:MakerHintManual -f $official[0].Name)
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
    Write-Detail 'copyparty: latest GitHub release, sfx.py + exe under isos\04-etc\copyparty\.'
    Write-Detail 'ImgBurn: official 2.5.8.0 installer, extracted into isos\04-etc\imgburn\bin\.'
    Write-Detail 'Go 1.27.4 and Node.js LTS 26.13.1: Windows ZIP plus Linux tar.gz under 04-etc.'
    Write-Detail 'TigerVNC viewer/Linux server and UltraVNC Windows server/viewer under 04-etc.'
    Write-Detail "Firefox ESR: latest en-US win64 resolved live; pinned $($script:FirefoxFallbackVersion) fallback if metadata/checksum lookup fails."
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
        $runStartedUtc = Get-UtcStamp
        $writtenUtc = Get-UtcStamp
        $script:VerifiedHashes = @{}
        $script:Sidecars = @{}
        $script:CopypartyRows = @()
        $script:FirefoxRelease = $null
        $script:FirefoxResolved = $null
        Initialize-ElevationState -Elevate:$Elevate
        Initialize-Directory -Path $Root
        Initialize-Directory -Path (Join-Path $Root $script:DirTools)
        Initialize-Directory -Path (Join-Path $Root $script:DirVentoy)
        Initialize-Directory -Path (Join-Path (Join-Path $Root $script:DirIsos) '01-Network')
        Initialize-Directory -Path (Join-Path (Join-Path $Root $script:DirIsos) '02-Rescue')
        Initialize-Directory -Path (Join-Path (Join-Path $Root $script:DirIsos) '03-Installers')
        Initialize-Directory -Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc')
        Initialize-Directory -Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirCopyparty)
        Initialize-Directory -Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirPython)
        Initialize-Directory -Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirSevenZip)
        Initialize-Directory -Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirPutty)
        Initialize-Directory -Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirWinScp)
        Initialize-Directory -Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirCyberduck)
        Initialize-Directory -Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirTabby)
        Initialize-Directory -Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirGolang)
        Initialize-Directory -Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirNodeJs)
        Initialize-Directory -Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirTigerVnc)
        Initialize-Directory -Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirUltraVnc)
        Initialize-Directory -Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirImgBurn)
        Initialize-Directory -Path (Join-Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirImgBurn) 'bin')
        Initialize-Directory -Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirFirefox)
        Initialize-Directory -Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirFonts)
        Write-ReadmeFile -Path (Join-Path $Root $script:FileReadme) -Text (Get-RootReadmeText -WrittenUtc $writtenUtc -RunStartedUtc $runStartedUtc)
        Write-ReadmeFile -Path (Join-Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirPython) $script:FileReadme) -Text (Get-PythonReadmeText -RunStartedUtc $runStartedUtc -WrittenUtc $writtenUtc)
        Write-ReadmeFile -Path (Join-Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirSevenZip) $script:FileReadme) -Text (Get-SevenZipReadmeText -RunStartedUtc $runStartedUtc -WrittenUtc $writtenUtc)
        Write-ReadmeFile -Path (Join-Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirPutty) $script:FileReadme) -Text (Get-PuttyReadmeText -RunStartedUtc $runStartedUtc -WrittenUtc $writtenUtc)
        Write-ReadmeFile -Path (Join-Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirWinScp) $script:FileReadme) -Text (Get-WinScpReadmeText -RunStartedUtc $runStartedUtc -WrittenUtc $writtenUtc)
        Write-ReadmeFile -Path (Join-Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirCyberduck) $script:FileReadme) -Text (Get-CyberduckReadmeText -RunStartedUtc $runStartedUtc -WrittenUtc $writtenUtc)
        Write-ReadmeFile -Path (Join-Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirTabby) $script:FileReadme) -Text (Get-TabbyReadmeText -RunStartedUtc $runStartedUtc -WrittenUtc $writtenUtc)
        Write-ReadmeFile -Path (Join-Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirGolang) $script:FileReadme) -Text (Get-GoReadmeText -RunStartedUtc $runStartedUtc -WrittenUtc $writtenUtc)
        Write-ReadmeFile -Path (Join-Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirNodeJs) $script:FileReadme) -Text (Get-NodeReadmeText -RunStartedUtc $runStartedUtc -WrittenUtc $writtenUtc)
        Write-ReadmeFile -Path (Join-Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirTigerVnc) $script:FileReadme) -Text (Get-TigerVncReadmeText -RunStartedUtc $runStartedUtc -WrittenUtc $writtenUtc)
        Write-ReadmeFile -Path (Join-Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirUltraVnc) $script:FileReadme) -Text (Get-UltraVncReadmeText -RunStartedUtc $runStartedUtc -WrittenUtc $writtenUtc)
        Write-ReadmeFile -Path (Join-Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirImgBurn) $script:FileReadme) -Text (Get-ImgBurnReadmeText -RunStartedUtc $runStartedUtc -WrittenUtc $writtenUtc)
        Write-ReadmeFile -Path (Join-Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirFonts) $script:FileReadme) -Text (Get-FontsReadmeText -RunStartedUtc $runStartedUtc -WrittenUtc $writtenUtc)
        # Provisional sheets so live topics still have documentation if the
        # run is interrupted before their downloads. Never replace a sheet from
        # an earlier run; the post-step writes refresh them on success.
        $cpReadmePath = Join-Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirCopyparty) $script:FileReadme
        $ffReadmePath = Join-Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirFirefox) $script:FileReadme
        if (-not (Test-Path -LiteralPath $cpReadmePath)) {
            Write-ReadmeFile -Path $cpReadmePath -Text (Get-CopypartyReadmeText -RunStartedUtc $runStartedUtc -WrittenUtc $writtenUtc)
        }
        if (-not (Test-Path -LiteralPath $ffReadmePath)) {
            Write-ReadmeFile -Path $ffReadmePath -Text (Get-FirefoxReadmeText -RunStartedUtc $runStartedUtc -WrittenUtc $writtenUtc)
        }
        Write-Step 'Ventoy media tool'
        Invoke-SafeStep -Name 'Ventoy' -Manual @('See the failure message above for the manual Ventoy steps.') -Body {
            Install-Ventoy -Root $Root -CleanDownloads:$CleanDownloads | Out-Null
        }
        Write-Step 'Rufus portable + Fido'
        Invoke-SafeStep -Name 'Rufus + Fido' -Manual @($script:RufusReleasesHint) -Body {
            Save-RufusTools -Root $Root | Out-Null
        }
        Write-Step 'copyparty tools (04-etc)'
        Invoke-SafeStep -Name 'copyparty' -Manual @("Open $($script:CopypartyReleasesUrl) and place $($script:FileCopypartySfx) and $($script:FileCopypartyExe) into isos\04-etc\copyparty\.") -Body {
            Save-CopypartyTools -Root $Root | Out-Null
        }
        Write-ReadmeFile -Path (Join-Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirCopyparty) $script:FileReadme) -Text (Get-CopypartyReadmeText -RunStartedUtc $runStartedUtc -WrittenUtc (Get-UtcStamp))
        Write-Step 'Catalog ISOs (netboot first)'
        Save-CatalogIsos -Root $Root -NetbootArch $NetbootArch -MintHwe $MintHwe
        Write-Step 'ImgBurn portable (04-etc)'
        Invoke-SafeStep -Name 'ImgBurn' -Manual @('Place the ImgBurn payload files in isos\04-etc\imgburn\bin\ by hand; the next run verifies them.') -Body {
            Install-ImgBurnPortable -Root $Root | Out-Null
        }
        Write-Step 'Firefox ESR (04-etc)'
        $firefoxFallback = New-FirefoxFallbackRelease
        $firefoxHint = 'Download the Firefox ESR en-US win64 installer from ' + $script:FirefoxReleasesUrl + '<version>/win64/en-US/ into isos\04-etc\firefox\ and compare it with that release SHA256SUMS. Pinned fallback: ' + $firefoxFallback.Url + ' (SHA-256 ' + $script:FirefoxFallbackSha256 + ').'
        Invoke-SafeStep -Name 'Firefox ESR' -Manual @($firefoxHint) -Body {
            Save-FirefoxEsr -Root $Root | Out-Null
        }
        Write-ReadmeFile -Path (Join-Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirFirefox) $script:FileReadme) -Text (Get-FirefoxReadmeText -RunStartedUtc $runStartedUtc -WrittenUtc (Get-UtcStamp))
        Write-Step 'Windows 11 ISO via Fido'
        Invoke-SafeStep -Name 'Windows 11 ISO' -Manual @('Open ' + $script:MsDownloadPage + ' and place the Windows ISO (' + $script:WinIsoNaming + ') into isos\03-Installers\.') -Body {
            Get-WindowsIsoViaFido -Root $Root | Out-Null
        }
        if (-not $SkipTiny11) {
            Write-Step 'Tiny11 build'
            Invoke-SafeStep -Name 'Tiny11 ISO' -Manual @(($script:MakerHintManual -f 'the official ISO')) -Body {
                Invoke-Tiny11Build -Root $Root -Elevate:$Elevate -CleanDownloads:$CleanDownloads | Out-Null
            }
        } else {
            Write-Detail 'Tiny11 build skipped by -SkipTiny11.'
        }
        # Refresh the isos readme: one block per selected catalog row (with
        # the on-disk hash when present), then the non-catalog entries
        # (copyparty, ImgBurn, Firefox ESR, Windows ISO, Tiny11) hashed the
        # same way, so the file is a self-contained verification sheet for the
        # real tree.
        $isoBlocks = Get-RecoveryCatalog | Where-Object {
            (($_.NetbootVariant -eq '') -or ($_.NetbootVariant -eq $NetbootArch)) -and
            (($_.MintHwe -eq '') -or ($_.MintHwe -eq $MintHwe))
        } | ForEach-Object { Format-IsoReadmeEntry -Row $_ -Root $Root }
        $copypartyDir = Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirCopyparty
        foreach ($cpName in @($script:FileCopypartySfx, $script:FileCopypartyExe)) {
            $cpRow = @($script:CopypartyRows | Where-Object { $_.FileName -eq $cpName }) | Select-Object -First 1
            $cpPath = Join-Path $copypartyDir $cpName
            if ($cpRow) {
                $isoBlocks += (Format-IsoReadmeEntry -Row $cpRow -Root $Root)
            } elseif (Test-Path -LiteralPath $cpPath) {
                $isoBlocks += (Format-ManualIsoReadmeEntry -Title "copyparty ($cpName, not verified this run)" -Path $cpPath -Folder (Join-Path '04-etc' $script:DirCopyparty) -Note 'Not verified against a GitHub asset digest this run; on-disk hash only.' -Root $Root)
            }
        }
        $imgBurnBin = Join-Path (Join-Path (Join-Path (Join-Path $Root $script:DirIsos) '04-etc') $script:DirImgBurn) 'bin'
        $imgBurnExe = Join-Path $imgBurnBin $script:FileImgBurnExe
        if ($script:VerifiedHashes.ContainsKey($imgBurnExe)) {
            $imgBurnRow = [pscustomobject]@{
                Name = 'ImgBurn portable'
                Category = (Join-Path '04-etc' (Join-Path $script:DirImgBurn 'bin'))
                FileName = $script:FileImgBurnExe
                Url = $script:ImgBurnUrl
                Hash = [string]$script:ImgBurnPayload[$script:FileImgBurnExe]
                HashKind = 'Pinned'
                Released = ('Version ' + $script:ImgBurnVersion + ', ' + $script:ImgBurnReleased + '.')
                SizeNote = 'About 2.6 MB.'
                About = 'Portable optical media burner and imager: ISO to CD/DVD/BD, disc to image, verify.'
                Check = 'Official imgburn.com download plus the pinned payload hash.'
            }
            $isoBlocks += (Format-IsoReadmeEntry -Row $imgBurnRow -Root $Root)
        } else {
            $isoBlocks += '== ImgBurn portable (not present) ==' + "`r`n" + 'Run the prep script again; the payload is extracted from the official installer.'
        }
        $isoBlocks += (Get-FirefoxIsosBlock -Root $Root)
        $installersDir = Join-Path (Join-Path $Root $script:DirIsos) '03-Installers'
        $winIso = Find-WindowsIso -InstallersDir $installersDir | Select-Object -First 1
        if ($winIso) {
            $isoBlocks += (Format-ManualIsoReadmeEntry -Title 'Official Windows 11 ISO' -Path $winIso.FullName -Folder '03-Installers' -Note 'Kept as downloaded; Microsoft links expire, so no hash is pinned in the catalog.' -Root $Root)
        } else {
            $isoBlocks += '== Official Windows 11 ISO (not present) ==' + "`r`n" + 'Resolve via Fido or place Win11_*.iso / en-us_windows_11_*.iso by hand.'
        }
        $tinyIso = Join-Path (Join-Path $installersDir 'tiny11') $script:FileTiny11Iso
        if (Test-Path -LiteralPath $tinyIso) {
            $tinyNote = 'Built by tiny11builder (legacy tiny11maker.ps1 script) from the official ISO above. Removes bundled apps (Clipchamp, News, Weather, Xbox, Teams, Copilot hooks), Edge/WebView2 binaries, OneDrive setup, and sponsored tasks; keeps Windows Update, Defender, WinRE, the Store, and shared runtimes. Practical limits: some removals need a reinstall of that app from the Store or Winget (Edge: reinstall from microsoft.com if a web-dependent installer needs it); hardware-check bypasses are baked in, so in-place upgrades on unsupported PCs stay possible but are untested; no product key is injected -- activate with your own license. Full parity IS recoverable through Windows Update afterwards for anything still serviced, but removed provisioned apps do not come back on their own -- reinstall them explicitly. Always test-boot the ISO (VM or spare stick) before relying on it.'
            $isoBlocks += (Format-ManualIsoReadmeEntry -Title 'Tiny11 ISO (built locally)' -Path $tinyIso -Folder '03-Installers\tiny11' -Note $tinyNote -Root $Root)
        } else {
            $isoBlocks += '== Tiny11 ISO (not present) ==' + "`r`n" + 'Build with -Elevate once the official ISO is present.'
        }
        $isosWrittenUtc = Get-UtcStamp
        Write-ReadmeFile -Path (Join-Path (Join-Path $Root $script:DirIsos) $script:FileReadme) -Text ((Get-IsosReadmeTemplate -WrittenUtc $isosWrittenUtc -RunStartedUtc $runStartedUtc) -f ($isoBlocks -join "`r`n`r`n"))
        return (Write-Summary)
    } finally {
        [Console]::OutputEncoding = $savedEncoding
    }
}

$script:Catalog = Get-RecoveryCatalog

if ($MyInvocation.InvocationName -ne '.') {
    exit (Invoke-PreparePcRecovery -Root $Root -NetbootArch $NetbootArch -MintHwe $MintHwe -CleanDownloads:$CleanDownloads -SkipTiny11:$SkipTiny11 -Elevate:$Elevate)
}
