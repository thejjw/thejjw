# OSC 9;9 hyperlink lets Windows Terminal / VS Code detect and click the working directory
function prompt {
    <#
.SYNOPSIS
    Renders the interactive PowerShell prompt.
.DESCRIPTION
    Overrides PowerShell's built-in prompt function to return the standard
    "PS <location>" prompt prefixed with an OSC 9;9 working-directory escape
    sequence for terminals that support clickable or detectable paths.
.OUTPUTS
    System.String. The prompt text returned to the PowerShell host.
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-07
#>
    $loc = $executionContext.SessionState.Path.CurrentLocation
    $out = "PS $loc$('>' * ($nestedPromptLevel + 1)) "
    "$([char]27)]9;9;`"$loc`"$([char]27)\" + $out
}

# Raw content URL used by Update-Profile to self-update; keep in sync with repo path
$_ProfileUpdateUrl = "https://raw.githubusercontent.com/thejjw/thejjw/refs/heads/main/WindowsPowerShell/Microsoft.PowerShell_profile.ps1"

# Pinned nvm release used by ephemeral remote Claude launchers.
$_NvmVersion = "v0.40.7"

# Official uv installer used by ephemeral remote Claude launchers.
$_UvInstallUrl = "https://astral.sh/uv/install.sh"

# Generic browser-like User-Agent for outbound HTTP (used by the Save-* chunked downloader).
# Kept here so it can be updated in one place; bump the Chrome major version periodically to
# stay current (latest stable: https://chromereleases.googleblog.com/).
$_DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"

# --- $_ProfileHelpers: shared helper object for the whole profile ----------
# General-purpose helpers exposed as methods on $_ProfileHelpers (e.g.
# $_ProfileHelpers.WriteSection('x')). Home for ANY cross-cutting helper.

$_ProfileHelpers = New-Module -AsCustomObject -ScriptBlock {
    # Resolves Windows Update COM API result codes to human-readable labels.
    function ResolveWUResultCode {
        param([int]$Code)
        switch ($Code) {
            0 { 'NotStarted (0)' }
            1 { 'InProgress (1)' }
            2 { 'Succeeded (2)' }
            3 { 'SucceededWithErrors (3)' }
            4 { 'Failed (4)' }
            5 { 'Aborted (5)' }
            default { "Unknown ($Code)" }
        }
    }

    # Resolves Windows Update HResult codes to human-readable error descriptions.
    function ResolveWUHResult {
        param([int]$H)
        $hex = '0x{0:X8}' -f $H
        $known = @{
            '0x00000000' = 'Success'
            '0x80240022' = 'WU_E_ALL_UPDATES_FAILED - every update in the batch failed'
            '0x80240044' = 'WU_E_NO_USERTOKEN - not elevated'
            '0x80070005' = 'E_ACCESSDENIED - needs elevation'
            '0x8024402C' = 'WU_E_PT_WINHTTP_NAME_NOT_RESOLVED - proxy/DNS'
            '0x80240438' = 'Blocked by policy (WSUS/Intune managed)'
            '0x8024001E' = 'WU_E_SERVICE_STOP - wuauserv stopping'
            '0x80072EE2' = 'Timeout reaching server'
        }
        if ($known.ContainsKey($hex)) { "$hex - $($known[$hex])" } else { $hex }
    }

    # Render a TimeSpan as a compact human-readable string.
    function FormatDuration {
        param([TimeSpan]$Value)
        if ($Value.TotalDays -ge 1)  { return ('{0:N1} d ({1:N0} h)' -f $Value.TotalDays,  $Value.TotalHours) }
        if ($Value.TotalHours -ge 1) { return ('{0:N1} h ({1:N0} m)'  -f $Value.TotalHours, $Value.TotalMinutes) }
        return ('{0:N0} m ({1:N0} s)' -f $Value.TotalMinutes, $Value.TotalSeconds)
    }

    # Print a section banner.
    function WriteSection {
        param([string]$Title)
        Write-Host ''
        Write-Host ('== {0} ==' -f $Title) -ForegroundColor Cyan
    }

    # Print the local start time for a usage-query command.
    function WriteUsageTimestamp {
        param([string]$CommandName)
        Write-Host ('[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'), $CommandName) -ForegroundColor DarkGray
    }

    # Convert epoch milliseconds to a local DateTime.
    function FromEpochMs {
        param([long]$Value)
        return [DateTimeOffset]::FromUnixTimeMilliseconds($Value).LocalDateTime
    }

    # Format a token count as a compact human-readable string.
    function FormatTokens {
        param([double]$Value)
        if ($Value -le 0) { return '0' }
        if ($Value -ge 1e9) { return ('{0:N2}B' -f ($Value / 1e9)) }
        if ($Value -ge 1e6) { return ('{0:N2}M' -f ($Value / 1e6)) }
        if ($Value -ge 1e3) { return ('{0:N2}K' -f ($Value / 1e3)) }
        return ('{0:N0}' -f $Value)
    }

    # Format a cost value as a compact decimal, stripping trailing zeros.
    function FormatPrice {
        param([double]$Value)
        $s = ('{0:N6}' -f $Value).TrimEnd('0')
        if ($s.EndsWith('.')) { $s = $s.Substring(0, $s.Length - 1) }
        return $s
    }

    # Compute total/avg/peak for a numeric series aligned to xTime.
    function GetSeriesStats {
        param([object[]]$XTime, [object[]]$Series)
        if (-not $Series -or $Series.Count -eq 0) {
            return [pscustomobject]@{ Total = 0; Avg = 0; Peak = 0; PeakHour = $null }
        }
        $total = 0; $peak = 0; $peakIdx = -1
        for ($i = 0; $i -lt $Series.Count; $i++) {
            $v = [int]$Series[$i]
            $total += $v
            if ($v -gt $peak) { $peak = $v; $peakIdx = $i }
        }
        $avg = if ($Series.Count -gt 0) { [double]$total / $Series.Count } else { 0 }
        $peakHour = if ($peakIdx -ge 0 -and $XTime -and $peakIdx -lt $XTime.Count) { [string]$XTime[$peakIdx] } else { $null }
        return [pscustomobject]@{ Total = $total; Avg = $avg; Peak = $peak; PeakHour = $peakHour }
    }

    # Detect spikes: indexes where value > SpikeRatio * avg.
    function GetSpikes {
        param([object[]]$XTime, [object[]]$Series, [double]$Avg, [double]$SpikeRatio = 3.0)
        $out = @()
        if (-not $Series -or $Avg -le 0) { return $out }
        $threshold = $SpikeRatio * $Avg
        for ($i = 0; $i -lt $Series.Count; $i++) {
            $v = [int]$Series[$i]
            if ($v -gt $threshold) {
                $hour = if ($XTime -and $i -lt $XTime.Count) { [string]$XTime[$i] } else { "idx $i" }
                $out += [pscustomobject]@{ Hour = $hour; Value = $v }
            }
        }
        return $out
    }

    # Z.AI's quota endpoint wraps payload under .data; pull that out.
    function UnwrapZaiData {
        param([object]$Response)
        if ($null -eq $Response) { return $null }
        if ($Response.PSObject.Properties['data'] -and $null -ne $Response.data) { return $Response.data }
        return $Response
    }

    # Big-endian readers for OpenType tables (all multi-byte fields are BE).
    function _U16 { param([byte[]]$d, [int]$o) return ([int]$d[$o] -shl 8) -bor $d[$o + 1] }
    function _U32 {
        param([byte[]]$d, [int]$o)
        return ([long]([uint32]$d[$o] -shl 24) -bor ([uint32]$d[$o + 1] -shl 16) -bor ([uint32]$d[$o + 2] -shl 8) -bor $d[$o + 3])
    }

    # Read typographic family/subfamily from a font byte[]. Handles single fonts
    # and .ttc/.otc collections (reports the first face). Returns $null on failure.
    function _ReadFontNames {
        param([byte[]]$b)
        if ($b.Length -lt 16) { return $null }
        $base = 0
        # A collection begins with the 'ttcf' tag; jump to the first face's dir.
        if ([System.Text.Encoding]::ASCII.GetString($b, 0, 4) -eq 'ttcf') { $base = [int](_U32 $b 12) }
        if (($base + 12) -gt $b.Length) { return $null }
        $num = _U16 $b ($base + 4)
        $nameOff = -1
        for ($i = 0; $i -lt $num; $i++) {
            $o = $base + 12 + $i * 16
            if (($o + 12) -gt $b.Length) { break }
            if ([System.Text.Encoding]::ASCII.GetString($b, $o, 4) -eq 'name') { $nameOff = [int](_U32 $b ($o + 8)); break }
        }
        if ($nameOff -lt 0 -or ($nameOff + 6) -gt $b.Length) { return $null }
        $count = _U16 $b ($nameOff + 2)
        $strOff = $nameOff + (_U16 $b ($nameOff + 4))
        $vals = @{}       # nameID -> value
        $score = @{}      # nameID -> priority of the value currently kept
        for ($i = 0; $i -lt $count; $i++) {
            $r = $nameOff + 6 + $i * 12
            if (($r + 12) -gt $b.Length) { break }
            $plat = _U16 $b $r; $lang = _U16 $b ($r + 4); $nameID = _U16 $b ($r + 6); $len = _U16 $b ($r + 8); $off = _U16 $b ($r + 10)
            if ($nameID -notin 1, 2, 16, 17) { continue }
            $s = $strOff + $off
            if (($s + $len) -gt $b.Length) { continue }
            if ($plat -eq 3 -or $plat -eq 0) { $v = [System.Text.Encoding]::BigEndianUnicode.GetString($b, $s, $len) }
            elseif ($plat -eq 1) { $v = [System.Text.Encoding]::ASCII.GetString($b, $s, $len) }
            else { continue }
            # Prefer Windows English (plat 3 / lang 0x0409), then any Windows
            # record, then Unicode, then Mac -- so a multilingual font shows its
            # English family name rather than whichever localized record is last.
            $pri = if ($plat -eq 3 -and $lang -eq 0x0409) { 4 } elseif ($plat -eq 3) { 3 } elseif ($plat -eq 0) { 2 } else { 1 }
            if (-not $vals.ContainsKey($nameID) -or $pri -gt $score[$nameID]) { $vals[$nameID] = $v; $score[$nameID] = $pri }
        }
        $fam = if ($vals.ContainsKey(16)) { $vals[16] } elseif ($vals.ContainsKey(1)) { $vals[1] } else { '(no family)' }
        $sub = if ($vals.ContainsKey(17)) { $vals[17] } elseif ($vals.ContainsKey(2)) { $vals[2] } else { '' }
        return [pscustomobject]@{ Family = $fam; Sub = $sub }
    }

    # Inspect a font archive (zip) for Install-Fonts catalog authoring. Prints
    # every entry with its size and, for font files (.ttf/.otf/.ttc/.otc), the
    # registered family/subfamily read from the OpenType 'name' table.
    function ShowFontArchive {
        param($Path, $Include, $NoNames)

        if ([string]::IsNullOrWhiteSpace($Path)) { Write-Error 'ShowFontArchive: -Path is required.'; return }
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

        $temp = $null
        if ($Path -match '^https?://') {
            $temp = Join-Path ([System.IO.Path]::GetTempPath()) ('fontarch_' + [System.Guid]::NewGuid().ToString('N') + '.zip')
            Write-Host ("Downloading {0}" -f $Path) -ForegroundColor DarkGray
            $swf = Get-Command Save-WebFile -ErrorAction SilentlyContinue
            try {
                if ($swf) {
                    & $swf -Uri $Path -OutFile $temp -Force -Quiet -ErrorAction Stop | Out-Null
                } else {
                    $pp = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'
                    try { Invoke-WebRequest -Uri $Path -OutFile $temp -UseBasicParsing } finally { $ProgressPreference = $pp }
                }
            } catch { Write-Error ("Download failed: {0}" -f $_.Exception.Message); return }
            $zipPath = $temp
        } else {
            $zipPath = [System.IO.Path]::GetFullPath($Path)
            if (-not (Test-Path -LiteralPath $zipPath)) { Write-Error "Archive not found: $zipPath"; return }
        }

        $fontExt = '.ttf', '.otf', '.ttc', '.otc'
        $leaf = ($Path -split '[\\/]')[-1]
        try {
            $archLen = (Get-Item -LiteralPath $zipPath).Length
            $zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
            try {
                $entries = @($zip.Entries | Where-Object { $_.Name })
                Write-Host ''
                Write-Host ("== {0}" -f $leaf) -ForegroundColor Cyan
                Write-Host ("   archive: {0:N0} bytes, {1} file entr{2}" -f $archLen, $entries.Count, $(if ($entries.Count -eq 1) { 'y' } else { 'ies' })) -ForegroundColor DarkGray

                $tally = @{}
                foreach ($e in $entries) { $x = [System.IO.Path]::GetExtension($e.Name).ToLowerInvariant(); if (-not $x) { $x = '(none)' }; $tally[$x] = 1 + ($tally[$x]) }
                Write-Host ("   formats: {0}" -f (($tally.GetEnumerator() | Sort-Object Name | ForEach-Object { '{0}={1}' -f $_.Name, $_.Value }) -join '  ')) -ForegroundColor DarkGray

                $shown = $entries
                if ($Include) {
                    $shown = @($entries | Where-Object { $_.FullName -match $Include })
                    Write-Host ("   Include '{0}' -> {1} of {2} entries match" -f $Include, $shown.Count, $entries.Count) -ForegroundColor Yellow
                }

                Write-Host ''
                foreach ($e in ($shown | Sort-Object FullName)) {
                    $isFont = ([System.IO.Path]::GetExtension($e.Name).ToLowerInvariant() -in $fontExt)
                    $nameInfo = ''
                    if ($isFont -and -not $NoNames) {
                        try {
                            $ms = New-Object System.IO.MemoryStream
                            $s = $e.Open(); $s.CopyTo($ms); $s.Close()
                            $n = _ReadFontNames $ms.ToArray()
                            $ms.Dispose()
                            if ($n) { $nameInfo = ('  family="{0}"{1}' -f $n.Family, $(if ($n.Sub) { ' sub="' + $n.Sub + '"' } else { '' })) }
                            else { $nameInfo = '  (name read failed)' }
                        } catch { $nameInfo = '  (name read failed)' }
                    }
                    Write-Host ("  {0,10:N0}  {1}{2}" -f $e.Length, $e.FullName, $nameInfo)
                }
                Write-Host ''
            } finally { $zip.Dispose() }
        } finally {
            if ($temp -and (Test-Path -LiteralPath $temp)) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
        }
    }

    # Extracts selected files from a 7z archive with Windows' inbox tar.exe.
    # Throws a terminating error when the environment or archive is unsupported.
    function Expand7ZipArchive {
        param(
            [Parameter(Mandatory = $true)][string]$Path,
            [Parameter(Mandatory = $true)][string]$DestinationPath,
            [string]$Include
        )

        $archive = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($archive.PSIsContainer) { throw "7z archive path must be a file: $Path" }

        $tar = Get-Command tar.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $tar) {
            throw '7z extraction is unavailable: Windows tar.exe was not found. Install a current Windows archive-tools component and try again.'
        }

        $listing = @(& $tar.Source -tf $archive.FullName 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw ('Could not list 7z archive: {0}' -f (($listing | ForEach-Object { [string]$_ }) -join ' '))
        }

        $entries = @($listing | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
        foreach ($entry in $entries) {
            $normalized = $entry.Replace('\', '/')
            if ($normalized -match '^(?:/|[A-Za-z]:)' -or $normalized -match '(^|/)\.\.(/|$)') {
                throw "Refusing unsafe 7z archive entry: $entry"
            }
        }

        $selected = @($entries | Where-Object {
            -not $_.EndsWith('/') -and ([string]::IsNullOrWhiteSpace($Include) -or $_ -match $Include)
        })
        if ($selected.Count -eq 0) { throw "No 7z archive entries matched Include '$Include'." }

        $destination = [System.IO.Path]::GetFullPath($DestinationPath)
        $destinationPrefix = $destination.TrimEnd('\') + '\'
        [System.IO.Directory]::CreateDirectory($destination) | Out-Null
        $extractOutput = @(& $tar.Source -xf $archive.FullName -C $destination -- @selected 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw ('Could not extract 7z archive: {0}' -f (($extractOutput | ForEach-Object { [string]$_ }) -join ' '))
        }

        $result = @()
        foreach ($entry in $selected) {
            $relative = $entry.Replace('/', '\')
            $extractedPath = [System.IO.Path]::GetFullPath((Join-Path $destination $relative))
            if (-not $extractedPath.StartsWith($destinationPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Refusing extracted path outside destination: $entry"
            }
            $item = Get-Item -LiteralPath $extractedPath -Force -ErrorAction Stop
            if ($item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                throw "Refusing non-file 7z archive entry: $entry"
            }
            $result += $item.FullName
        }
        return $result
    }

    # Removes a temporary SSH identity directory created by NewTemporarySshIdentity.
    function RemoveTemporarySshIdentity {
        param([Parameter(Mandatory = $true)]$Identity)

        $directory = [string]$Identity.Directory
        if ([string]::IsNullOrWhiteSpace($directory) -or -not (Test-Path -LiteralPath $directory)) { return }

        $resolved = Get-Item -LiteralPath $directory -Force -ErrorAction Stop
        $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\')
        if ($resolved.Parent.FullName.TrimEnd('\') -ne $tempRoot -or $resolved.Name -notlike 'claude-ssh-*') {
            throw "Refusing to remove unexpected SSH identity directory: $directory"
        }
        Remove-Item -LiteralPath $resolved.FullName -Recurse -Force -ErrorAction Stop
    }

    # Creates a temporary SSH identity protected for the current user.
    function NewTemporarySshIdentity {
        param([Parameter(Mandatory = $true)][string]$KeyFile)

        $source = Get-Item -LiteralPath (Resolve-Path -LiteralPath $KeyFile -ErrorAction Stop).Path -Force
        if ($source.PSIsContainer) { throw "SSH key path must be a file: $KeyFile" }

        $tempDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ('claude-ssh-' + [guid]::NewGuid().ToString('N'))
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $sid = $identity.User
        [System.IO.Directory]::CreateDirectory($tempDirectory) | Out-Null

        try {
            # Secure the empty directory before any private-key material is written.
            $directorySecurity = New-Object System.Security.AccessControl.DirectorySecurity
            $directorySecurity.SetOwner($sid)
            $directorySecurity.SetAccessRuleProtection($true, $false)
            $directoryRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $sid,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $directorySecurity.AddAccessRule($directoryRule)
            [System.IO.Directory]::SetAccessControl($tempDirectory, $directorySecurity)

            $target = Join-Path $tempDirectory 'identity'
            $header = Get-Content -LiteralPath $source.FullName -TotalCount 1 -ErrorAction Stop
            $format = if ($header -match '^PuTTY-User-Key-File-[23]:') { 'PPK' } else { 'OpenSSH' }
            Copy-Item -LiteralPath $source.FullName -Destination $target -Force -ErrorAction Stop

            $fileSecurity = New-Object System.Security.AccessControl.FileSecurity
            $fileSecurity.SetOwner($sid)
            $fileSecurity.SetAccessRuleProtection($true, $false)
            $fileRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $sid,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $fileSecurity.AddAccessRule($fileRule)
            [System.IO.File]::SetAccessControl($target, $fileSecurity)

            $acl = Get-Acl -LiteralPath $target
            $ownerAccount = New-Object System.Security.Principal.NTAccount -ArgumentList $acl.Owner
            $ownerSid = $ownerAccount.Translate(
                [System.Security.Principal.SecurityIdentifier]
            )
            $unexpectedAllow = @($acl.Access | Where-Object {
                $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
                $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -ne $sid
            })
            if (-not $acl.AreAccessRulesProtected -or $ownerSid -ne $sid -or $unexpectedAllow.Count -gt 0) {
                throw 'Failed to restrict the temporary SSH key to the current user.'
            }

            [pscustomobject]@{ Path = $target; Directory = $tempDirectory; Format = $format }
        } catch {
            RemoveTemporarySshIdentity ([pscustomobject]@{ Directory = $tempDirectory })
            throw
        }
    }

    $profileHelperFunctions = @(
        'ResolveWUResultCode',
        'ResolveWUHResult',
        'FormatDuration',
        'WriteSection',
        'WriteUsageTimestamp',
        'FromEpochMs',
        'FormatTokens',
        'FormatPrice',
        'GetSeriesStats',
        'GetSpikes',
        'UnwrapZaiData',
        'ShowFontArchive',
        'Expand7ZipArchive',
        'NewTemporarySshIdentity',
        'RemoveTemporarySshIdentity'
    )
    Export-ModuleMember -Function $profileHelperFunctions
}

function Invoke-WebRequest2 {
    <#
.SYNOPSIS
    Invokes a web request with response compression enabled by default.
.DESCRIPTION
    Wraps Invoke-WebRequest and adds an Accept-Encoding header that prefers gzip
    over deflate unless the caller already supplied Accept-Encoding.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [uri] $Uri,

        [Microsoft.PowerShell.Commands.WebRequestMethod] $Method,

        [System.Collections.IDictionary] $Headers,

        [object] $Body,

        [string] $ContentType,

        [string] $InFile,

        [string] $OutFile,

        [int] $TimeoutSec,

        [string] $UserAgent,

        [switch] $UseBasicParsing,

        [switch] $PassThru
    )

    $requestHeaders = @{}
    if ($Headers) {
        foreach ($key in $Headers.Keys) {
            $requestHeaders[$key] = $Headers[$key]
        }
    }

    if (-not ($requestHeaders.Keys | Where-Object { $_ -ieq 'Accept-Encoding' })) {
        $requestHeaders['Accept-Encoding'] = 'gzip, deflate;q=0.5'
    }

    $invokeParams = @{ Uri = $Uri; Headers = $requestHeaders }
    foreach ($key in @('Method', 'Body', 'ContentType', 'InFile', 'OutFile', 'TimeoutSec', 'UserAgent', 'UseBasicParsing', 'PassThru')) {
        if ($PSBoundParameters.ContainsKey($key)) {
            $invokeParams[$key] = $PSBoundParameters[$key]
        }
    }

    Invoke-WebRequest @invokeParams
}

# Internal configuration group for New-RandomDir to keep global namespace clean
$_NrdInternal = @{
    Colors         = @(
        'amber', 'aqua', 'azure', 'beige', 'black', 'blue', 'bronze', 'brown', 'coral',
        'crimson', 'cyan', 'denim', 'ebony', 'emerald', 'fuchsia', 'gold', 'golden',
        'gray', 'green', 'indigo', 'ivory', 'jade', 'lavender', 'lemon', 'lilac',
        'lime', 'magenta', 'mahogany', 'marigold', 'maroon', 'mint', 'mocha', 'navy',
        'ochre', 'olive', 'onyx', 'orange', 'orchid', 'peach', 'pearl', 'periwinkle',
        'pine', 'pink', 'plum', 'purple', 'red', 'rose', 'ruby', 'rust', 'saffron',
        'sage', 'salmon', 'sapphire', 'scarlet', 'sepia', 'silver', 'slate', 'tan',
        'tangerine', 'taupe', 'teal', 'topaz', 'turquoise', 'umber', 'vermilion',
        'violet', 'walnut', 'white', 'wine', 'yellow'
    )
    Adjectives     = @(
        'ancient', 'bold', 'brisk', 'calm', 'clear', 'cool', 'curious', 'deep', 'eager', 'fast',
        'gentle', 'grand', 'hidden', 'icy', 'jolly', 'kind', 'lively', 'lucky', 'misty', 'modern',
        'mossy', 'nimble', 'odd', 'quiet', 'rapid', 'shiny', 'silent', 'small', 'solar', 'steady',
        'stormy', 'swift', 'tiny', 'urban', 'warm', 'wild', 'wise', 'young'
    )
    Nouns          = @(
        'brook', 'cabin', 'cloud', 'comet', 'delta', 'dream', 'falcon', 'field', 'fire', 'forest',
        'garden', 'glade', 'harbor', 'hill', 'lab', 'lake', 'leaf', 'meadow', 'moon', 'mountain',
        'otter', 'owl', 'path', 'peak', 'pine', 'planet', 'pond', 'rabbit', 'river', 'shadow',
        'sky', 'star', 'stone', 'sun', 'thicket', 'trail', 'tree', 'valley', 'wave', 'wind',
        'wolf', 'wood', 'workshop'
    )

    # PowerShell heredoc requires two `` to escape a single literal backtick in the content; this is used for file paths and command examples in the agent guidance
    AgentsMarkdown = @"
# AGENTS.md

## Grounding

* Always utilize web search to ground your answers, ensuring all technical advice and references are accurate and up-to-date.

## Environment

* Platform: Windows 11, shell: Windows PowerShell (powershell.exe).
* Use PowerShell commands and syntax -- not Unix/bash equivalents.
  * ``Get-ChildItem`` not ``ls -la``, ``Remove-Item`` not ``rm -rf``, ``Get-Content`` not ``cat``.
  * Redirect to ``$null`` not ``/dev/null``.
  * Use semicolons or separate statements -- not ``&&`` to chain commands.
  * Paths use backslashes (``src\lib\utils.ps1``); avoid forward slashes.
* When useful and already available, use fast CLI tools such as ``rg``, ``fd``, ``fzf``, or comparable installed tools; otherwise use PowerShell-native commands.
* If invoking ``git``, ``npm``, ``dotnet``, or other cross-platform CLIs, those are fine as-is.

## Code Style

* Prefer concise, minimal implementations -- avoid boilerplate and unnecessary abstraction.
* Comment every public function/method and any non-obvious logic inline.
* Prefer ASCII in source code. Use non-ASCII characters only when required for user-facing text, test fixtures, protocol/data literals, or existing project conventions.

## Git Discipline

* If the requested work is inside a cloned Git repository nested under this directory, treat that nested repository as the project root. Verify with ``git rev-parse --show-toplevel``, then stage and commit only within that repository; do not stage or commit in any containing parent repository unless explicitly directed.
* Always commit after each logical change with a descriptive commit message; never bundle unrelated changes.
* Do not stage or commit AI-agent instruction/context Markdown files unless explicitly directed. This includes ``AGENTS.md``, ``CLAUDE.md``, ``QWEN.md``, and similar local ``.md`` files used to guide agents.
* This restriction does not apply to normal project documentation such as ``README.md``, ``CHANGELOG.md``, API docs, design docs, or user-facing Markdown files when those files are part of the requested change.
* Use Conventional Commits: ``feat:``, ``fix:``, ``refactor:``, ``docs:``, ``chore:``, ``test:``, etc.
* Write short, imperative descriptions (e.g. ``feat: add input validation``, ``fix: off-by-one in retry loop``).
* Never append Co-Authored-By trailers to commit messages.

## Dependencies

* Pick the latest version the package manager resolves against existing project constraints, including lockfiles and manifest ranges.
* Before finalizing a dependency add/update, check the registry (npm, NuGet, PyPI, GitHub, ...) for explicit deprecation signals, such as ``deprecated``, yanked releases, or archived repositories, on the chosen package and version. If any are found, prefer a non-deprecated alternative when practical; otherwise warn inline with the package name, signal source, and suggested alternative if the registry provides one, then proceed.

## Subagents

* Default to delegating context-heavy work to subagents so the main session
  accumulates conclusions, not raw process. Strong candidates: codebase
  exploration/research, reading or summarizing many files, and independent
  sub-tasks that can run in parallel. The subagent absorbs the noisy tool
  calls and returns only a summary.
* Do not wrap trivial or single tool calls in a subagent. A one-file read or a
  quick ``rg``/``fd`` search is cheaper run directly than paying the spawn and
  round-trip overhead.
* Keep tightly-coupled work in the main context. Do not delegate edits that
  depend on each other's output, and never have two subagents edit the same
  file -- they share the working directory and will clobber each other.
* Subagents start with a fresh context and the task prompt is the only input
  channel. Pass every needed file path, error message, and decision explicitly;
  they cannot see the main conversation.
* Give each subagent explicit success criteria and a structured return format
  so it reports cleanly instead of exploring open-endedly.
* Where it cuts cost without hurting quality, route exploration/search
  subagents to a smaller/faster model and reserve the main session for
  synthesis and architectural judgment.
"@
}

# Internal configuration for Install-GlobalClaudeMd and related Claude Code setup functions
# DeepSeek Web Search behavior: https://api-docs.deepseek.com/quick_start/agent_integrations/claude_code
$_ClaudeInternal = @{
    GlobalClaudeMd = @"
## MCP Tool Preferences

**When using Z.ai models (glm-*):**
Use Z.ai MCP servers for:
- Web searches
- Web content
- Image analysis
- Text extraction

**When using MiniMax models (MiniMax-*):**
Note: MiniMax-M3 natively supports multimodal input (images and video) in addition to MCP.
Use MiniMax MCP server for:
- Web searches (``web_search``)
- Image understanding (``understand_image``)

**When using DeepSeek models (deepseek-*):**
Use Claude Code's built-in Web Search tool for web searches; DeepSeek supports it natively through its API. Web Search incurs additional model token costs because DeepSeek makes extra LLM API requests to summarize retrieved content.
Use MiniMax MCP and Z.ai MCP servers, if available, for image analysis because DeepSeek models are text-only. Fall back to other available means if those MCP tools are unavailable or underperforming.

**When using genuine Anthropic account (Claude Code with native models):**
Use built-in web fetch and web search tools directly -- they will yield the best results.

If an MCP tool is unavailable or underperforming, inform the user and suggest alternatives.
"@
}

# Internal configuration for Install-AiTools and Invoke-AiUpgrade
$_AiToolsInternal = @{
    PowerShellModules      = @(
        @{
            Name               = 'Pester'
            MinimumVersion     = '6.0'
            Repository         = 'PSGallery'
            Scope              = 'CurrentUser'
            Force              = $true
            SkipPublisherCheck = $true
        }
    )
    WingetPackages         = @(
        'Microsoft.Coreutils',
        'Microsoft.VCRedist.2015+.x64',
        'Microsoft.VCRedist.2015+.x86',
        'Microsoft.IntelligentTerminal',
        'TwibrightLabs.Links',
        'OpenJS.NodeJS.LTS',
        'GnuPG.Gpg4win',
        'Oven-sh.Bun',
        '7zip.7zip',
        'FiloSottile.age',
        'GitHub.cli',
        'Notepad++.Notepad++',
        'Lapce.Lapce',
        'Microsoft.Edit',
        'Python.PythonInstallManager',
        'cURL.cURL',
        'aria2.aria2',
        'jqlang.jq',
        'BurntSushi.ripgrep.MSVC',
        'junegunn.fzf',
        'sharkdp.fd',
        'JFLarvoire.Ag',
        'chmln.sd',
        'dandavison.delta',
        'sharkdp.bat',
        'eza-community.eza',
        'dalance.procs',
        'MrKaran.Doggo',
        'ducaale.xh',
        'medialab.xan',
        'oschwartz10612.Poppler',
        'uutils.diffutils',
        'EliFulkerson.tcping',
        'FujiApple.Trippy',
        'natesales.q',
        'tstack.lnav',
        'Microsoft.Pave',
        'Microsoft.err',
        'wagoodman.dive',
        'astral-sh.uv',
        'pnpm.pnpm',
        'SQLite.SQLite',
        'koalaman.shellcheck',
        'Microsoft.VisualStudioCode',
        'VSCodium.VSCodium',
        'marlocarlo.psmux',
        'marlocarlo.pstop',
        'marlocarlo.psnet'
    )
    MoreAiWingetPackages   = @(
        'SST.OpenCodeDesktop',
        'Google.Antigravity',
        'Google.AntigravityIDE',
        'ZhipuAI.ZCode',
        'MiniMax.MiniMaxCode',
        'Anysphere.Cursor'
    )
    ExtendedWingetPackages = @(
        'Insecure.Nmap',
        'Buct0r.fullfetch',
        'HTTPie.HTTPie',
        'Orange-OpenSource.Hurl',
        'Gyan.FFmpeg',
        'ImageMagick.ImageMagick',
        'Inkscape.Inkscape',
        'Google.Libwebp',
        'libjxl.libjxl',
        'JohnMacFarlane.Pandoc',
        'tesseract-ocr.tesseract',
        'AquaSecurity.Trivy',
        'Cisco.ClamAV',
        'astral-sh.ruff',
        'Microsoft.Sqlcmd',
        'HeidiSQL.HeidiSQL',
        'TheDocumentFoundation.LibreOffice',
        'OlegShparber.Zeal',
        'Mozilla.SeaMonkey',
        'Microsoft.Sysinternals.Suite'
    )
    DbWingetPackages       = @(
        'Oracle.MySQLShell',
        'Oracle.SQLcl',
        'PostgreSQL.psqlODBC',
        'PostgreSQL.pgAdmin'
    )
    SdkWingetPackages      = @(
        'Microsoft.OpenJDK.25',
        'Rustlang.Rustup',
        'GoLang.Go',
        'StrawberryPerl.StrawberryPerl'
    )
    DockerWingetPackage    = 'Docker.DockerDesktop'
    PodmanWingetPackage    = 'RedHat.Podman'
    GitWingetPackage       = 'Git.Git'
    Urls                   = @{
        AgyCli        = 'https://antigravity.google/cli/install.ps1'
        ClaudeCli     = 'https://claude.ai/install.ps1'
        CodexCli      = 'https://chatgpt.com/codex/install.ps1'
        GrokCli       = 'https://x.ai/cli/install.ps1'
        CursorCli     = 'https://cursor.com/install?win32=true'
        CcStatusline  = 'https://raw.githubusercontent.com/thejjw/thejjw/main/bin/cc_statusline.sh'
        AgyStatusline = 'https://raw.githubusercontent.com/thejjw/thejjw/main/WindowsPowerShell/util/agy_statusline.ps1'
    }
    NpmPackages            = @(
        '@earendil-works/pi-coding-agent',
        '@oh-my-pi/pi-coding-agent',
        '@musistudio/claude-code-router',
        'oh-my-free-models',
        '@firecrawl/anydoc',
        'typescript',
        'eslint',
        'prettier',
        'terser'
    )

    # commented out entries:
    # '@mimo-ai/cli',
    MoreAiNpmPackages      = @(
        '@qwen-code/qwen-code',
        '@moonshot-ai/kimi-code',
        '@deepseek-ai/dsh',
        'gloomberb'
    )
    # Keep this registry synchronized with AI CLIs managed by Install-AiTools
    # that ship a native self-update command. Probe defaults to Cmd; set it when
    # a CLI's updater probe differs from the command. npm-installed packages are
    # not listed here -- aiu updates them straight from NpmPackages and
    # MoreAiNpmPackages above.
    UpgradeCommands        = @(
        @{ Label = 'agy';      Cmd = 'agy';      Args = @('update') },
        @{ Label = 'claude';   Cmd = 'claude';   Args = @('update') },
        @{ Label = 'codex';    Cmd = 'codex';    Args = @('update') },
        @{ Label = 'opencode'; Cmd = 'opencode'; Args = @('upgrade') },
        @{ Label = 'grok';     Cmd = 'grok';     Args = @('update') },
        @{ Label = 'cursor';   Cmd = 'agent';    Probe = 'cursor-agent'; Args = @('update') }
    )
}

# Internal configuration for Install-Fonts.
#
# Each pack is pinned to a specific upstream release. When bumping a version,
# update Url, Bytes, and (if the archive layout changed) Include/Probe together.
#
# Fields:
#   Name     Human-readable pack name; also the token matched by -Name filtering.
#   Url      Direct download URL (GitHub release asset or CDN). Warned on failure.
#   Bytes    Download size measured at authoring time; used for the pre-run size
#            report so the user sees the transfer cost before anything downloads.
#   Fonts    Approx. count of font files this pack installs after Include filtering
#            (from archive inspection); used only for the pre-run summary total.
#   Kind     'Zip' = archive to open with .NET; '7z' = archive to extract with
#            Windows' inbox tar.exe; 'File' = the URL is itself a single font.
#   Include  Regex (case-insensitive) matched against each archive entry's relative
#            path. Only matching entries are extracted+installed. Chosen per pack
#            to install ONE clean set and skip redundant format folders plus
#            __MACOSX/AppleDouble junk. When a pack ships multiple formats the
#            preference is variable -> OTF -> static, EXCEPT where a font's
#            variable build renames its family (e.g. "Pretendard Variable" instead
#            of "Pretendard", verified by reading the name table); those fall back
#            to a static set so a plain family name keeps resolving.
#            Ignored for Kind='File'.
#   Probe    A representative installed font filename. If it already exists in the
#            target Fonts folder, the whole pack is skipped (no download) unless
#            -Force is passed. This is the cheap pre-download idempotency check.
#   Extended $true packs are skipped unless -Extended is passed. This keeps the
#            especially large Source Han CJK downloads explicitly opt-in.
#   Note     Optional freeform note shown in -ListOnly output.
$_FontInstallInternal = @{
    # Per-user (no admin) install target and its font-registration registry key.
    UserFontsDir = (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Fonts')
    UserRegPath  = 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Fonts'
    # All-users (-AllUsers, requires admin) install target and its registry key.
    MachineFontsDir = (Join-Path $env:WINDIR 'Fonts')
    MachineRegPath  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts'

    Packs = @(
        [pscustomobject]@{ Name = 'GoormSansCode';       Url = 'https://statics.goorm.io/fonts/GoormSansCode/v1.0.1/goorm-sans-code-1.0.1.zip'; Bytes = 4528715;   Fonts = 1;  Kind = 'Zip';  Include = '(?i)^goorm sans code 2/Public/[^/]+\.ttf$'; Probe = 'goorm_Sans_Code_400.ttf';                 Extended = $false; Note = 'Coding sans (single weight).' }
        [pscustomobject]@{ Name = 'Jetendard';           Url = 'https://github.com/kuskhan/jetendard/releases/download/v0.1.0/Jetendard-TTF.zip'; Bytes = 37427141; Fonts = 16; Kind = 'Zip';  Include = '(?i)^ttf/[^/]+\.ttf$';                     Probe = 'Jetendard-Regular.ttf';                  Extended = $false; Note = 'Static TTF weights.' }
        [pscustomobject]@{ Name = 'YeomilMono';          Url = 'https://github.com/taevel02/yeomil-mono/releases/download/v1.1.1/YeomilMono-TTF.zip'; Bytes = 3055540; Fonts = 3; Kind = 'Zip';  Include = '(?i)^[^/]+\.ttf$';                         Probe = 'YeomilMono-Regular.ttf';                 Extended = $false; Note = 'Monospace, 3 weights.' }
        [pscustomobject]@{ Name = 'Pretendard';          Url = 'https://github.com/orioncactus/pretendard/releases/download/v1.3.9/Pretendard-1.3.9.zip'; Bytes = 47304526; Fonts = 9; Kind = 'Zip'; Include = '(?i)^public/static/alternative/[^/]+\.ttf$'; Probe = 'Pretendard-Regular.ttf';        Extended = $false; Note = 'Static TTF: its variable build registers as family "Pretendard Variable", so static is used for a clean "Pretendard" family.' }
        [pscustomobject]@{ Name = 'WantedSans';          Url = 'https://github.com/wanteddev/wanted-sans/releases/download/v1.0.3/WantedSans-1.0.3.zip'; Bytes = 21656532; Fonts = 7; Kind = 'Zip'; Include = '(?i)^ttf/[^/]+\.ttf$';                     Probe = 'WantedSans-Regular.ttf';                 Extended = $false; Note = 'Static TTF: variable build registers as "Wanted Sans Variable"; static keeps a clean "Wanted Sans" family.' }
        [pscustomobject]@{ Name = 'Galmuri';             Url = 'https://github.com/quiple/galmuri/releases/download/v2.40.3/Galmuri-v2.40.3.zip'; Bytes = 19936233; Fonts = 20; Kind = 'Zip'; Include = '(?i)^[^/]+\.(ttf|ttc)$';                   Probe = 'Galmuri11.ttf';                          Extended = $false; Note = 'Pixel font family; all root-level ttf/ttc.' }
        [pscustomobject]@{ Name = 'OpenDyslexic';        Url = 'https://github.com/antijingoist/opendyslexic/releases/download/v0.91.12/opendyslexic-0.910.12-rc2-2019.10.17.zip'; Bytes = 3627458; Fonts = 4; Kind = 'Zip'; Include = '(?i)^[^/]+\.otf$';               Probe = 'OpenDyslexic-Regular.otf';               Extended = $false; Note = 'OTF; skips eot/woff web formats.' }
        [pscustomobject]@{ Name = 'FiraCode';            Url = 'https://github.com/tonsky/FiraCode/releases/download/6.2/Fira_Code_v6.2.zip'; Bytes = 2462987; Fonts = 6; Kind = 'Zip'; Include = '(?i)^ttf/[^/]+\.ttf$';                          Probe = 'FiraCode-Regular.ttf';                   Extended = $false; Note = 'Static TTF: the VF defaults to Light weight and legacy apps see "Fira Code Light"; static defaults to Regular with a clean "Fira Code" family.' }
        [pscustomobject]@{ Name = 'SarasaGothicK';       Url = 'https://github.com/be5invis/Sarasa-Gothic/releases/download/v1.0.40/SarasaGothicK-TTF-1.0.40.7z'; Bytes = 63464316; Fonts = 10; Kind = '7z'; Include = '(?i)^SarasaGothicK-[^/]+\.ttf$'; Probe = 'SarasaGothicK-Regular.ttf'; Extended = $false; Note = 'Korean Sarasa Gothic, 5 hinted weights with italics. Requires Windows tar.exe.' }
        [pscustomobject]@{ Name = 'SarasaMonoK';         Url = 'https://github.com/be5invis/Sarasa-Gothic/releases/download/v1.0.40/SarasaMonoK-TTF-1.0.40.7z'; Bytes = 66316218; Fonts = 10; Kind = '7z'; Include = '(?i)^SarasaMonoK-[^/]+\.ttf$'; Probe = 'SarasaMonoK-Regular.ttf'; Extended = $false; Note = 'Korean monospaced Sarasa, 5 hinted weights with italics. Requires Windows tar.exe.' }
        [pscustomobject]@{ Name = 'SourceHanSans';       Url = 'https://github.com/adobe-fonts/source-han-sans/releases/download/2.005R/02_SourceHanSans-VF.zip'; Bytes = 888816761; Fonts = 1; Kind = 'Zip'; Include = '(?i)^Variable/OTC/SourceHanSans-VF\.ttf\.ttc$'; Probe = 'SourceHanSans-VF.ttf.ttc';       Extended = $true;  Note = 'LARGE ~848 MB. Installs only the pan-CJK OTC variable collection.' }
        [pscustomobject]@{ Name = 'SourceHanSerif';      Url = 'https://github.com/adobe-fonts/source-han-serif/releases/download/2.003R/02_SourceHanSerif-VF.zip'; Bytes = 750817685; Fonts = 1; Kind = 'Zip'; Include = '(?i)^Variable/OTC/SourceHanSerif-VF\.ttf\.ttc$'; Probe = 'SourceHanSerif-VF.ttf.ttc';   Extended = $true;  Note = 'LARGE ~716 MB. Installs only the pan-CJK OTC variable collection.' }
        [pscustomobject]@{ Name = 'SourceHanMono';       Url = 'https://github.com/adobe-fonts/source-han-mono/releases/download/1.002/SourceHanMono.ttc'; Bytes = 122117628; Fonts = 1; Kind = 'File'; Include = $null;                              Probe = 'SourceHanMono.ttc';                      Extended = $true;  Note = 'LARGE ~116 MB. Direct .ttc download (no archive).' }
        [pscustomobject]@{ Name = 'JetBrainsMono';       Url = 'https://github.com/JetBrains/JetBrainsMono/releases/download/v2.304/JetBrainsMono-2.304.zip'; Bytes = 5622857; Fonts = 2; Kind = 'Zip'; Include = '(?i)^fonts/variable/[^/]+\.ttf$';         Probe = 'JetBrainsMono[wght].ttf';                Extended = $false; Note = 'Variable TTF (upright + italic); registers cleanly as "JetBrains Mono", so variable is kept over the static ttf/ set.' }
        [pscustomobject]@{ Name = 'IBMPlexMono';         Url = 'https://github.com/IBM/plex/releases/download/%40ibm%2Fplex-mono%402.5.0/ibm-plex-mono.zip'; Bytes = 6940652; Fonts = 16; Kind = 'Zip'; Include = '(?i)^ibm-plex-mono/fonts/complete/otf/[^/]+\.otf$'; Probe = 'IBMPlexMono-Regular.otf';        Extended = $false; Note = 'OTF, all 16 weights incl. italics; skips ttf/woff/woff2.' }
        [pscustomobject]@{ Name = 'IBMPlexSansKR';       Url = 'https://github.com/IBM/plex/releases/download/%40ibm%2Fplex-sans-kr%401.1.0/ibm-plex-sans-kr.zip'; Bytes = 73268731; Fonts = 8; Kind = 'Zip'; Include = '(?i)^ibm-plex-sans-kr/fonts/complete/otf/[^/]+\.otf$'; Probe = 'IBMPlexSansKR-Regular.otf';    Extended = $false; Note = 'LARGE ~73 MB (full zip also bundles ttf/woff/woff2); installs OTF, all 8 Korean weights.' }
        [pscustomobject]@{ Name = 'MonaSans';            Url = 'https://github.com/github/mona-sans/releases/download/v2.0.27/mona-sans-variable-v2.0.27.zip'; Bytes = 2674251; Fonts = 11; Kind = 'Zip'; Include = '(?i)^fonts/variable/[^/]+\.ttf$';          Probe = 'MonaSansVF[opsz,wght].ttf';              Extended = $false; Note = 'Variable-only distribution (multiple width/optical axes).' }
        [pscustomobject]@{ Name = 'SUIT';                Url = 'https://github.com/sun-typeface/SUIT/releases/download/v2.0.5/SUIT-Variable-ttf.zip'; Bytes = 812043; Fonts = 1; Kind = 'Zip'; Include = '(?i)^[^/]+\.ttf$';                            Probe = 'SUIT-Variable.ttf';                      Extended = $false; Note = 'Single variable TTF.' }
        [pscustomobject]@{ Name = 'MonoplexKR';          Url = 'https://github.com/y-kim/monoplex/releases/download/v0.0.2/MonoplexKR-v0.0.2.zip'; Bytes = 74226250; Fonts = 64; Kind = 'Zip'; Include = '(?i)^[^/]+/[^/]+\.ttf$';                      Probe = 'MonoplexKR-Regular.ttf';                 Extended = $false; Note = 'LARGE ~74 MB. Four families (base/Nerd/Wide/WideNerd), 16 weights each.' }
        [pscustomobject]@{ Name = 'MinSans';             Url = 'https://github.com/poposnail61/min-sans/releases/download/v1.4.2/fonts.zip'; Bytes = 31533194; Fonts = 10; Kind = 'Zip'; Include = '(?i)^fonts/static/[^/]+\.otf$';              Probe = 'MinSans-Regular.otf';                    Extended = $false; Note = 'Static OTF: variable build registers as "Min Sans VF"; static keeps a clean "Min Sans" family. Skips __MACOSX.' }
        [pscustomobject]@{ Name = 'Dalmoori';            Url = 'https://github.com/RanolP/dalmoori-font/releases/download/v0.200/dalmoori-font.zip'; Bytes = 775035; Fonts = 1; Kind = 'Zip'; Include = '(?i)^[^/]+\.ttf$';                            Probe = 'dalmoori.ttf';                           Extended = $false; Note = 'Single pixel TTF.' }
        [pscustomobject]@{ Name = 'NanumGothicCoding';   Url = 'https://github.com/naver/nanumfont/releases/download/VER2.5/NanumGothicCoding-2.5.zip'; Bytes = 1707449; Fonts = 2; Kind = 'Zip'; Include = '(?i)^[^/]+\.ttf$';                       Probe = 'NanumGothicCoding.ttf';                  Extended = $false; Note = 'Regular + Bold; skips __MACOSX.' }
        [pscustomobject]@{ Name = 'NanumGothic';         Url = 'https://hangeul.naver.com/hangeul_static/webfont/zips/nanum-gothic.zip'; Bytes = 12905726; Fonts = 4; Kind = 'Zip'; Include = '(?i)^[^/]+\.ttf$';                Probe = 'NanumGothic.ttf';                        Extended = $false; Note = 'TTF, 4 weights (Light/Regular/Bold/ExtraBold). TTF is used because the bundled OTF renames the family to "NanumGothicOTF".' }
        [pscustomobject]@{ Name = 'NanumMyeongjo';       Url = 'https://hangeul.naver.com/hangeul_static/webfont/zips/nanum-myeongjo.zip'; Bytes = 7353677; Fonts = 3; Kind = 'Zip'; Include = '(?i)^[^/]+\.ttf$';               Probe = 'NanumMyeongjo.ttf';                      Extended = $false; Note = 'TTF, 3 weights (Regular/Bold/ExtraBold). TTF keeps a clean "NanumMyeongjo" family (OTF is "NanumMyeongjoOTF").' }
        [pscustomobject]@{ Name = 'NanumBarunGothic';    Url = 'https://hangeul.naver.com/hangeul_static/webfont/zips/nanum-barun-gothic.zip'; Bytes = 15416063; Fonts = 4; Kind = 'Zip'; Include = '(?i)^[^/]+\.ttf$';         Probe = 'NanumBarunGothic.ttf';                   Extended = $false; Note = 'TTF, 4 weights (UltraLight/Light/Regular/Bold). TTF keeps a clean "NanumBarunGothic" family (OTF is "NanumBarunGothicOTF").' }
        [pscustomobject]@{ Name = 'NanumSquare';         Url = 'https://hangeul.naver.com/hangeul_static/webfont/zips/nanum-square.zip'; Bytes = 4203717; Fonts = 8; Kind = 'Zip'; Include = '(?i)^[^/]+\.ttf$';                 Probe = 'NanumSquareR.ttf';                       Extended = $false; Note = 'TTF, 8 files: "NanumSquare" + "NanumSquare_ac" (alphabet-matched) sub-families, 4 weights each. TTF keeps clean names (OTF appends "OTF").' }
        [pscustomobject]@{ Name = 'NanumSquareNeo';      Url = 'https://hangeul.naver.com/hangeul_static/webfont/zips/nanum-square-neo.zip'; Bytes = 9765932; Fonts = 5; Kind = 'Zip'; Include = '(?i)^nanum-square-neo/TTF/[^/]+\.ttf$'; Probe = 'NanumSquareNeo-bRg.ttf';            Extended = $false; Note = 'Static TTF, 5 weights (Light..Heavy). Static TTF is used because both the variable ("NanumSquare Neo variable") and OTF ("NanumSquare Neo OTF") rename the family; static keeps a clean "NanumSquare Neo".' }
        [pscustomobject]@{ Name = 'NanumSquareRound';    Url = 'https://hangeul.naver.com/hangeul_static/webfont/zips/nanum-square-round.zip'; Bytes = 2535434; Fonts = 4; Kind = 'Zip'; Include = '(?i)^[^/]+\.ttf$';          Probe = 'NanumSquareRoundR.ttf';                  Extended = $false; Note = 'TTF, 4 weights (Light/Regular/Bold/ExtraBold). TTF keeps a clean "NanumSquareRound" family (OTF appends "OTF").' }
        [pscustomobject]@{ Name = 'NanumHuman';          Url = 'https://hangeul.naver.com/hangeul_static/webfont/zips/NanumHuman.zip'; Bytes = 6190692; Fonts = 6; Kind = 'Zip'; Include = '(?i)^NanumHuman/[^/]+\.ttf$';           Probe = 'NanumHumanRegular.ttf';                  Extended = $false; Note = 'TTF, 6 weights (ExtraLight..Heavy); skips __MACOSX/woff. Both formats are suffixed upstream, so this registers as "NanumHuman TTF".' }
        [pscustomobject]@{ Name = 'D2Coding';            Url = 'https://github.com/naver/d2codingfont/releases/download/VER1.3.2/D2Coding-Ver1.3.2-20180524.zip'; Bytes = 21256997; Fonts = 1; Kind = 'Zip'; Include = '(?i)^D2CodingAll/[^/]+\.ttc$';           Probe = 'D2Coding-Ver1.3.2-20180524-all.ttc';     Extended = $false; Note = 'Installs the D2CodingAll .ttc (regular+bold+ligature in one collection).' }
        [pscustomobject]@{ Name = 'KoPubWorld';          Url = 'https://www.kopus.org/wp-content/uploads/2026/04/KOPUBWORLD_OTF_FONTS2026.zip'; Bytes = 20297063; Fonts = 6; Kind = 'Zip'; Include = '(?i)^[^/]+\.otf$';        Probe = 'KoPubWorld Batang_Pro Light.otf';        Extended = $false; Note = 'OTF-only (2026 release). KoPubWorld Batang (serif) + Dotum (sans), 3 weights each (Light/Medium/Bold).' }
        [pscustomobject]@{ Name = 'KoPub';               Url = 'https://www.kopus.org/wp-content/uploads/2022/04/KOPUB2.0_OTF_FONTS.zip'; Bytes = 12640328; Fonts = 6; Kind = 'Zip'; Include = '(?i)^[^/]+\.otf$';             Probe = 'KoPub Batang_Pro Light.otf';             Extended = $false; Note = 'OTF-only (classic KoPub 2.0). KoPub Batang (serif) + Dotum (sans), 3 weights each (Light/Medium/Bold).' }
    )
}

# Internal configuration for Install-AiSkills
$_AiSkillsInternal = @{
    RepoUrl               = 'https://github.com/thejjw/thejjw.git'
    Branch                = 'main'
    SparsePath            = 'ai-skills'
    OpenCodeClaudeSkills  = @('codebase-docs', 'web-search-ddg', 'web-search-startpage', 'z-ai-usage-query', 'minimax-usage-query', 'deepseek-usage-query', 'kimi-usage-query', 'deep-research', 'polish-document')
    AntigravitySharedSkills  = @('codebase-docs', 'deep-research', 'polish-document')
    AntigravityCliOnlySkills = @('session-exporter', 'agy-usage-query')
    CodexSkills           = @('export-chat-codex', 'polish-document')
    OpenCodeSkillsPath    = '.agents\skills'
    ClaudeSkillsPath      = '.claude\skills'
    AntigravityAppSkillsPath = '.gemini\config\skills'
    AntigravityCliSkillsPath = '.gemini\antigravity-cli\skills'
    CodexSkillsPath       = 'skills'
    OpenCodeConfigPath    = '.config\opencode\opencode.json'

    # External skill sources installed into EVERY tool's skill directory in
    # addition to the internal lists above. Each source is shallow-cloned to its
    # tip commit at install time; a clone failure warns and skips that source
    # (internal thejjw skills still install). Fields:
    #   Name       Unique label; also its subdirectory under the temp clone root.
    #   RepoUrl    Git remote to clone.
    #   Branch     Branch or tag (--branch accepts both; pin a tag to freeze).
    #   SparsePath Optional repo-relative directory containing the skills. When
    #              set, the clone is blobless+sparse and fetches only that path;
    #              omit when the repo root IS the skill tree.
    #   Skills     Skill directory names to install from the source root. The
    #              same skill name in two sources overwrites on later install,
    #              so keep the lists disjoint.
    ExternalSources       = @(
        @{
            Name       = 'go-skills'
            RepoUrl    = 'https://github.com/spf13/go-skills.git'
            Branch     = 'main'
            Skills     = @('go', 'cobra-viper', 'go-spec-reviewer', 'go-release', 'wails', 'fileflow-pathologize')
        },
        @{
            Name       = 'apollo-skills'
            RepoUrl    = 'https://github.com/apollographql/skills.git'
            Branch     = 'main'
            SparsePath = 'skills'
            Skills     = @('rust-best-practices')
        },
        @{
            Name       = 'taste-skill'
            RepoUrl    = 'https://github.com/Leonxlnx/taste-skill.git'
            Branch     = 'main'
            SparsePath = 'skills'
            Skills     = @('taste-skill')
        }
    )
}

# Internal configuration for Install-ClaudeCCRSetup (Claude Code Router).
# Underscore prefix hides it from Get-Variable default scope per PowerShell convention.
# Endpoint URLs, model lists, and router role mappings are the only literals that need to
# change when retuning the cccr profile.
$_CcrInternal = @{
    Host      = '127.0.0.1'
    Port      = 3456
    Log       = $true
    Timeout   = 3000000
    Threshold = 60000
    Router = @{
        default    = 'zai,glm-5.3[1m]'             # Sonnet (daily work)
        background = 'zai,glm-4.7'                 # Haiku (background subagents)
        think      = 'zai,glm-5.3[1m]'             # Opus (Plan Mode / reasoning)
        webSearch  = 'gemini,gemini-2.5-flash'     # Google search grounding via Gemini Flash
    }
    Providers = @{
        zai = @{
            base        = 'https://api.z.ai/api/anthropic/v1/messages'
            key         = '$ZAI_API_KEY'
            models      = @('glm-4.7', 'glm-5.3[1m]', 'glm-4.6v')
            transformer = 'Anthropic'
        }
        minimax = @{
            base        = 'https://api.minimax.io/anthropic/v1/messages'
            key         = '$MINIMAX_API_KEY'
            models      = @('MiniMax-M3[1m]')
            transformer = 'Anthropic'
        }
        deepseek = @{
            base        = 'https://api.deepseek.com/anthropic/v1/messages'
            key         = '$DEEPSEEK_API_KEY'
            models      = @('deepseek-v4-flash[1m]', 'deepseek-v4-pro[1m]')
            transformer = 'Anthropic'
        }
        gemini = @{
            # Gemini's native API. The CCR gemini transformer appends '{model}:generateContent'
            # to the base URL, so the trailing slash is required.
            #
            # Reference:
            #   https://ai.google.dev/gemini-api/docs              -- API docs
            #   https://ai.google.dev/gemini-api/docs/pricing     -- per-model pricing
            #   https://ai.google.dev/gemini-api/docs/rate-limits -- per-tier rate limits
            #   https://aistudio.google.com/rate-limit            -- AI Studio tier limits dashboard
            base        = 'https://generativelanguage.googleapis.com/v1beta/models/'
            key         = '$GEMINI_API_KEY'
            models      = @('gemini-2.5-flash', 'gemini-2.5-flash-lite', 'gemini-3.5-flash', 'gemini-3.1-flash-lite', 'gemini-3.1-pro-preview', 'gemini-3-flash-preview', 'gemini-2.5-pro')
            transformer = 'gemini'
        }
    }
}

function New-RandomPassword {
    <#
.SYNOPSIS
    Generates a random password using System.Web.Security.Membership.
.DESCRIPTION
    Wraps the built-in [System.Web.Security.Membership]::GeneratePassword() method
    to generate cryptographically strong random passwords with customizable length
    and special character requirements. Uses RNGCryptoServiceProvider for high entropy.
.PARAMETER Length
    The total number of characters in the generated password (default: 16).
.PARAMETER MinimumSpecialCharacters
    The minimum number of special characters to include in the password (default: 3).
.EXAMPLE
    PS C:\> New-RandomPassword
    Generates a 16-character password with at least 3 special characters.
.EXAMPLE
    PS C:\> New-RandomPassword -Length 20 -MinimumSpecialCharacters 5
    Generates a 20-character password with at least 5 special characters.
.OUTPUTS
    System.String. A randomly generated password.
.LINK
    https://learn.microsoft.com/en-us/dotnet/api/system.web.security.membership.generatepassword
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-04

    Requires Windows PowerShell or PowerShell with .NET Framework installed.
    Characters include: uppercase, lowercase, digits, and special characters (!@#$%^&*()_-+=[{]};:<>|./?).
#>
    param(
        [int]$Length = 16,
        [int]$MinimumSpecialCharacters = 3
    )

    # System.Web is only available on .NET Framework (WinPS); pwsh on non-Windows lacks it
    try {
        Add-Type -AssemblyName System.Web -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to load System.Web assembly. Ensure .NET Framework is installed." -ErrorAction Stop
        return
    }

    try {
        $password = [System.Web.Security.Membership]::GeneratePassword($Length, $MinimumSpecialCharacters)
        return $password
    }
    catch {
        Write-Error "Failed to generate password: $_" -ErrorAction Stop
    }
}

function Clear-WorkingSet {
    <#
.SYNOPSIS
    function that executes EmptyWorkingSet() Win32 API call  (port from c# program)
.DESCRIPTION
    function that executes EmptyWorkingSet() Win32 API call  (port from c# program)
.EXAMPLE
    PS C:\> Clear-WorkingSet chrome firefox
    Calls EmptyWorkingSet() for process 'chrome' and 'firefox'
.INPUTS
    Array of process name string, or * for all processes
.OUTPUTS
    result string that tells how many processes it has executed EmptyWorkingSet() API call for
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2021-05

    result is dependent on process host permission (i.e. admin powershell will have more power than user powershell)
    In case of error running its host script, try: 
    Set-ExecutionPolicy Bypass -Scope Process -Force; . .\Clear-WorkingSetFunc.ps1
#>
    param (
        # list of TargetProcess
        [Parameter(Mandatory = $true)]
        [string[]]
        $TargetProcesses
    )

    # Compile C# shim once into the session via Add-Type so repeated calls avoid recompilation
    if ($null -eq $Global:hasEWSType) {
        $code = @"
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ewsConsole
{
    public class Program
    {
        [DllImport("psapi")]
        public static extern bool EmptyWorkingSet(long hProcess);

        public static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: ewsConsole processname. Press Enter to exit.");
                Console.ReadLine();
            }
            else if (args.Length == 1 && args[0] == "*")
            {
                Process[] plist = Process.GetProcesses();
                try
                {
                    List<int> pid = new List<int>();
                    foreach (Process p in plist)
                    {
                        try
                        {
                            EmptyWorkingSet(p.Handle.ToInt64());
                            pid.Add(p.Id);
                        }
                        catch
                        {
                            continue;
                        }
                    }
                    Console.WriteLine("Processed EmptyWorkingSet() for all running processes(n={0}/{1})", pid.Count, plist.Length);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
            }
            else
            {
                foreach (string s in args)
                {
                    String title = s;
                    Process[] plist = Process.GetProcessesByName(title);
                    try
                    {
                        List<int> pid = new List<int>();
                        foreach (Process p in plist)
                        {
                            EmptyWorkingSet(p.Handle.ToInt64());
                            pid.Add(p.Id);
                        }
                        if(pid.Count == 0) Console.WriteLine("Processed EmptyWorkingSet() for 0 processes of {0} (check process name again?)", title);
                        else Console.WriteLine("Processed EmptyWorkingSet() for {0} processes of {1}", pid.Count, title);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                    }
                }
            }

        }
    }
}
"@;
        Add-Type -TypeDefinition $code;
        $Global:hasEWSType = $true;
    }

    # Invoke the compiled C# entry point; it writes results directly to stdout
    [ewsConsole.Program]::Main($TargetProcesses);
}

function Get-ISOWeek {
    <#
.SYNOPSIS
    Returns the ISO 8601 week number for a date.
.DESCRIPTION
    Calculates the ISO week number using Monday as the first day of the week
    and the first four-day week as week 1. Defaults to the current date.
.PARAMETER Date
    The date whose ISO week number should be returned.
.EXAMPLE
    PS C:\> Get-ISOWeek

    Returns the ISO week number for the current date.
.EXAMPLE
    PS C:\> Get-ISOWeek '2026-08-10'
    33
.OUTPUTS
    System.Int32. A week number from 1 through 53.
#>
    param(
        [datetime]$Date = (Get-Date)
    )

    $calendar = [System.Globalization.CultureInfo]::InvariantCulture.Calendar
    $dayOfWeek = $calendar.GetDayOfWeek($Date)

    # Shift early weekdays into Thursday so year-boundary dates use the ISO week-year.
    if ($dayOfWeek -ge [DayOfWeek]::Monday -and $dayOfWeek -le [DayOfWeek]::Wednesday) {
        $Date = $Date.AddDays(3)
    }

    return $calendar.GetWeekOfYear(
        $Date,
        [System.Globalization.CalendarWeekRule]::FirstFourDayWeek,
        [DayOfWeek]::Monday
    )
}

function Get-AAA {
    <#
.SYNOPSIS
    function that outputs string of adjective-adjective-animal format
.DESCRIPTION
    function that outputs string of adjective-adjective-animal format.
    Depends on availability of https://raw.githubusercontent.com resources.
    Tested under Windows Powershell
    Caution: NOT FOR PRODUCTION USE.
    In case of error running its host script, try: 
    Set-ExecutionPolicy Bypass -Scope Process -Force; . .\Get-AAAFunc.ps1
.EXAMPLE
    PS C:\> Get-AAA
    snoopy-spiffy-squeaker
.EXAMPLE
    PS C:\> Get-AAA 2
    or
    PS C:\> Get-AAA -Repeat 2
    powderblue-flat-alpinegoat
    academic-relieved-rainbowtrout
.INPUTS
    -Repeat <number> dictates how many AAA format Get-AAA will output (default 1)
.OUTPUTS
    string of adjective-adjective-animal format
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2021-07

    Tip: you can add the function declaration to $PROFILE then call it on future shell sessions with ease
    (note that script execution policy should allow local script execution at least, i.e. RemoteSigned)
#>
    param (
        $Repeat = 1
    )

    # Fetch word lists once per session; subsequent calls reuse the cached $Global:getAAA
    try {
        if ($null -eq $Global:getAAA) {
            $Global:getAAA = @{
                ganm = (Invoke-WebRequest2 https://raw.githubusercontent.com/thejjw/thejjw/main/animals -UseBasicParsing -ErrorAction Stop | Select-Object -ExpandProperty Content).Trim() -split "`n"
                gadj = (Invoke-WebRequest2 https://raw.githubusercontent.com/thejjw/thejjw/main/adjectives -UseBasicParsing -ErrorAction Stop | Select-Object -ExpandProperty Content).Trim() -split "`n"
            }
        }
    } catch {
        Write-Error "Failed to retrieve words for Get-AAA: $_"
        return
    }
    
    # HashSet guarantees two distinct adjectives per iteration without a retry loop
    $result = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $Repeat; $i++) {
        $adjs = New-Object System.Collections.Generic.HashSet[string]
        while ($adjs.Count -ne 2) {
            $adjs.Add($Global:getAAA.gadj.Get((Get-Random) % $Global:getAAA.gadj.Count)) | Out-Null
        }
        
        $adjsarr = [System.Collections.Generic.List[string]]::new()
        foreach ($adj in $adjs) {
            $adjsarr.Add(([string]$adj).Trim())
        }
        $adjsarr.Add($Global:getAAA.ganm.Get((Get-Random) % $Global:getAAA.ganm.Count))
        $result.Add(($adjsarr -join "-"))
    }
    return $result.ToArray()
}

function Get-MyIP {
    <#
.SYNOPSIS
    Uses Google DNS to return external IP
.EXAMPLE
    PS C:\> Get-MyIP
    100.100.100.100
    Returns external IP observed from Google nameserver(ns1.google.com)
.INPUTS
    none
.OUTPUTS
    Output (if any)
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-07

    Tested with Windows Powershell. Should work with pwsh.
#>
    # Google's TXT record for this hostname reflects the querier's public IP
    return (Resolve-DnsName -Name o-o.myaddr.l.google.com -Server ns1.google.com -Type TXT | Select-Object -ExpandProperty Strings);
}

function Test-InternetSpeed {
    <#
.SYNOPSIS
    Tests internet download and upload throughput against Cloudflare.
.DESCRIPTION
    Performs one streaming download and one in-memory upload against Cloudflare's
    speed test endpoints. Displays progress and returns a structured result with
    decimal megabits-per-second measurements and per-direction failure details.
.PARAMETER DownloadUrl
    URL used for the download test. The default requests a 50 MB payload.
.PARAMETER UploadUrl
    URL used for the upload test.
.PARAMETER UploadSizeMB
    Size of the generated upload payload in megabytes. The default is 25 MB.
.PARAMETER Force
    Bypasses the data-usage confirmation prompt. Intended for automation and
    non-interactive sessions.
.EXAMPLE
    PS C:\> Test-InternetSpeed
    Shows the estimated 75 MB payload usage, then prompts before testing.
.EXAMPLE
    PS C:\> Test-InternetSpeed -DownloadUrl 'https://speed.cloudflare.com/__down?bytes=1000000' -UploadSizeMB 1 -Force
    Runs a low-bandwidth smoke test with 1 MB download and upload payloads.
.OUTPUTS
    PSCustomObject containing success state, speed, byte count, duration, and
    error details for each direction.
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-07

    Compatible with Windows PowerShell 5.1 and PowerShell.
    Reference: https://github.com/cloudflare/speedtest
#>
    [CmdletBinding()]
    param(
        [uri] $DownloadUrl = 'https://speed.cloudflare.com/__down?bytes=50000000',
        [uri] $UploadUrl = 'https://speed.cloudflare.com/__up',
        [ValidateRange(1, 1024)]
        [int] $UploadSizeMB = 25,
        [switch] $Force
    )

    $uploadBytesCount = [long]$UploadSizeMB * 1000000
    [long]$downloadBytesEstimate = 0
    $downloadSizeKnown = (
        $DownloadUrl.Query -match '(?:^\?|&)bytes=(\d+)(?:&|$)' -and
        [long]::TryParse($Matches[1], [ref]$downloadBytesEstimate)
    )

    if ($downloadSizeKnown) {
        $totalMegabytes = ($downloadBytesEstimate + $uploadBytesCount) / 1000000
        $dataUsageMessage = (
            'This test will transfer approximately {0:N2} MB of payload data ' +
            '({1:N2} MB download + {2:N2} MB upload). Protocol overhead may ' +
            'increase actual network usage slightly.'
        ) -f $totalMegabytes, ($downloadBytesEstimate / 1000000), ($uploadBytesCount / 1000000)
    } else {
        $dataUsageMessage = (
            'This test will upload {0:N2} MB of payload data. The download size ' +
            'cannot be determined from the supplied URL, and protocol overhead ' +
            'may increase actual network usage slightly.'
        ) -f ($uploadBytesCount / 1000000)
    }

    if (-not $Force -and -not $PSCmdlet.ShouldContinue(
        "$dataUsageMessage`nProceed with the internet speed test?",
        'Confirm internet speed test'
    )) {
        Write-Host 'Internet speed test cancelled. No test data was transferred.' -ForegroundColor Yellow
        return
    }

    Add-Type -AssemblyName System.Net.Http

    $downloadSucceeded = $false
    $downloadMbps = $null
    $downloadBytes = $null
    $downloadSeconds = $null
    $downloadError = $null
    $uploadSucceeded = $false
    $uploadMbps = $null
    $uploadBytes = $null
    $uploadSeconds = $null
    $uploadError = $null

    $httpClient = [System.Net.Http.HttpClient]::new()
    $stopwatch = [System.Diagnostics.Stopwatch]::new()

    try {
        Write-Host '1. Testing Download Speed...' -ForegroundColor Cyan

        $response = $null
        $stream = $null
        try {
            $stopwatch.Restart()
            $response = $httpClient.GetAsync(
                $DownloadUrl,
                [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead
            ).GetAwaiter().GetResult()
            $response.EnsureSuccessStatusCode() | Out-Null
            $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()

            $buffer = [byte[]]::new(8192)
            $totalBytesDownloaded = 0L
            while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $totalBytesDownloaded += $bytesRead
            }
            $stopwatch.Stop()

            $downloadSeconds = $stopwatch.Elapsed.TotalSeconds
            $downloadBytes = $totalBytesDownloaded
            if ($downloadSeconds -gt 0) {
                $downloadMbps = ($downloadBytes * 8) / (1000000 * $downloadSeconds)
            }
            $downloadSucceeded = $true

            Write-Host ('Downloaded : {0:N2} MB in {1:N2}s' -f ($downloadBytes / 1000000), $downloadSeconds)
            Write-Host ('Download   : {0:N2} Mbps' -f $downloadMbps) -ForegroundColor Green
        } catch {
            $stopwatch.Stop()
            $downloadError = $_.Exception.Message
            Write-Error -Message "Download test failed: $downloadError" -ErrorAction Continue
        } finally {
            if ($null -ne $stream) {
                $stream.Dispose()
            }
            if ($null -ne $response) {
                $response.Dispose()
            }
        }

        Write-Host "`n2. Testing Upload Speed..." -ForegroundColor Cyan

        $response = $null
        $content = $null
        try {
            # Generate the requested random payload in memory immediately before upload.
            $payloadBytes = [byte[]]::new([int]$uploadBytesCount)
            [System.Random]::new().NextBytes($payloadBytes)
            $content = [System.Net.Http.ByteArrayContent]::new($payloadBytes)

            $stopwatch.Restart()
            $response = $httpClient.PostAsync($UploadUrl, $content).GetAwaiter().GetResult()
            $response.EnsureSuccessStatusCode() | Out-Null
            $stopwatch.Stop()

            $uploadSeconds = $stopwatch.Elapsed.TotalSeconds
            $uploadBytes = $uploadBytesCount
            if ($uploadSeconds -gt 0) {
                $uploadMbps = ($uploadBytes * 8) / (1000000 * $uploadSeconds)
            }
            $uploadSucceeded = $true

            Write-Host ('Uploaded   : {0:N2} MB in {1:N2}s' -f ($uploadBytes / 1000000), $uploadSeconds)
            Write-Host ('Upload     : {0:N2} Mbps' -f $uploadMbps) -ForegroundColor Green
        } catch {
            $stopwatch.Stop()
            $uploadError = $_.Exception.Message
            Write-Error -Message "Upload test failed: $uploadError" -ErrorAction Continue
        } finally {
            if ($null -ne $content) {
                $content.Dispose()
            }
            if ($null -ne $response) {
                $response.Dispose()
            }
        }
    } finally {
        $httpClient.Dispose()
    }

    Write-Host "`n===============================" -ForegroundColor Yellow
    if ($downloadSucceeded) {
        Write-Host ('FINAL DOWNLOAD : {0:N2} Mbps' -f $downloadMbps) -ForegroundColor Green
    } else {
        Write-Host 'FINAL DOWNLOAD : Failed' -ForegroundColor Red
    }
    if ($uploadSucceeded) {
        Write-Host ('FINAL UPLOAD   : {0:N2} Mbps' -f $uploadMbps) -ForegroundColor Green
    } else {
        Write-Host 'FINAL UPLOAD   : Failed' -ForegroundColor Red
    }
    Write-Host '===============================' -ForegroundColor Yellow

    return [pscustomobject]@{
        DownloadSucceeded = $downloadSucceeded
        DownloadMbps      = $downloadMbps
        DownloadBytes     = $downloadBytes
        DownloadSeconds   = $downloadSeconds
        DownloadError     = $downloadError
        UploadSucceeded   = $uploadSucceeded
        UploadMbps        = $uploadMbps
        UploadBytes       = $uploadBytes
        UploadSeconds     = $uploadSeconds
        UploadError       = $uploadError
    }
}

function Get-WhoisInfo {
    <#
.SYNOPSIS
    Returns WHOIS information for given domain or ip
.EXAMPLE
    PS C:\> Get-WhoisInfo 39.116.73.30
    query       : 39.116.73.30
    queryType   : IPv4
    countryCode : KR
    korean      : @{ISP=; user=}
    english     : @{ISP=; user=}
    
    More information can be accessed via properties like .korean.ISP .korean.user
.INPUTS
    Domain or ip address
.OUTPUTS
    WHOIS information queried from whois.kisa.or.kr
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2021-06

    Tested with Windows Powershell. Should work with pwsh.
#>
    param (
        # ip or domain to query for
        [Parameter(Mandatory = $true)]
        [string]
        $DomainOrIp,
        # key if not already set
        [Parameter(Mandatory = $false)]
        [string]
        $WhoisKisaApiKey = $Global:WhoisKisaApiKey
    )

    if ($null -eq $WhoisKisaApiKey) {
        Write-Host 'Whois API key from KISA (whois.kisa.or.kr) not set. Please configure either -WhoisKisaApiKey parameter or $Global:WhoisKisaApiKey. Exiting...';
        return;
    }
    $DomainOrIp = $DomainOrIp.Trim();
    Set-Variable -Name queryurl -Value "http://whois.kisa.or.kr/openapi/whois.jsp?query=$DomainOrIp&key=$WhoisKisaApiKey&answer=json" -Option Constant;
    return (Invoke-WebRequest2 -Uri $queryurl -UseBasicParsing | Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty whois);
}

function Get-NewPassword {
    <#
.SYNOPSIS
    Generates a random password with customizable options.
.DESCRIPTION
    Generates a password of specified length and character classes (upper, lower, digit, special).
    Ensures no more than a specified number of consecutive identical characters.
    Optionally enforces at least one character from each enabled class and uses Fisher-Yates shuffle.
.EXAMPLE
    PS C:\> Get-NewPassword -Length 20 -IncludeSpecial $true -MaxConsecutive 2
    Generates a 20-character password with special characters and at most 2 consecutive identical characters.
.EXAMPLE
    PS C:\> Get-NewPassword -Length 16 -MoreSecure
    Generates a 16-character password with all enabled classes present and Fisher-Yates shuffle.
.PARAMETER Length
    Length of the password to generate (default: 16).
.PARAMETER MaxConsecutive
    Maximum allowed consecutive identical characters (default: 2).
.PARAMETER IncludeUpper
    Include uppercase letters (default: $true).
.PARAMETER IncludeLower
    Include lowercase letters (default: $true).
.PARAMETER IncludeDigit
    Include digits (default: $true).
.PARAMETER IncludeSpecial
    Include special characters (default: $true).
.PARAMETER MoreSecure
    If set, ensures at least one character from each enabled class and uses Fisher-Yates shuffle.
.OUTPUTS
    System.String. The generated password.
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2025-06
    Pure PowerShell implementation, no external dependencies.
#>
    param(
        [int]$Length = 16,
        [int]$MaxConsecutive = 2,
        [bool]$IncludeUpper = $true,
        [bool]$IncludeLower = $true,
        [bool]$IncludeDigit = $true,
        [bool]$IncludeSpecial = $true,
        [switch]$MoreSecure
    )
    $upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $lower = "abcdefghijklmnopqrstuvwxyz"
    $digits = "0123456789"
    $special = "!@#$%^&*()-_=+[]{};:,.<>/?"

    $charPool = ""
    $required = @()
    if ($IncludeUpper) { $charPool += $upper; $required += $upper }
    if ($IncludeLower) { $charPool += $lower; $required += $lower }
    if ($IncludeDigit) { $charPool += $digits; $required += $digits }
    if ($IncludeSpecial) { $charPool += $special; $required += $special }

    if ($charPool.Length -eq 0) {
        throw "No character classes selected for password generation."
    }
    if ($MoreSecure -and ($required.Count -gt $Length)) {
        throw "Password length too short for all required classes."
    }

    # Inner functions capture $charPool and $MaxConsecutive from the outer scope
    function Get-RandomChar {
        param($set)
        if ($null -eq $set) { $set = $charPool }
        return $set[(Get-Random -Minimum 0 -Maximum $set.Length)]
    }

    function IsValidPassword($password) {
        $lastChar = ''
        $count = 1
        foreach ($char in $password.ToCharArray()) {
            if ($char -eq $lastChar) {
                $count++
                if ($count -gt $MaxConsecutive) {
                    return $false
                }
            }
            else {
                $count = 1
                $lastChar = $char
            }
        }
        return $true
    }

    # Generate-and-validate loop: build a candidate, reject if it violates MaxConsecutive.
    # Rejection rate is negligible for reasonable lengths and pool sizes.
    do {
        $passwordChars = @()
        if ($MoreSecure) {
            # Seed one character from each enabled class to guarantee coverage
            foreach ($class in $required) {
                $passwordChars += Get-RandomChar $class
            }
            for ($i = $passwordChars.Count; $i -lt $Length; $i++) {
                $passwordChars += Get-RandomChar $charPool
            }
            # Fisher-Yates shuffle
            for ($i = $passwordChars.Count - 1; $i -gt 0; $i--) {
                $j = Get-Random -Minimum 0 -Maximum ($i + 1)
                $tmp = $passwordChars[$i]
                $passwordChars[$i] = $passwordChars[$j]
                $passwordChars[$j] = $tmp
            }
        }
        else {
            $passwordChars = for ($i = 0; $i -lt $Length; $i++) {
                Get-RandomChar $charPool
            }
            # Sort-Object { Get-Random } is a quick-and-dirty shuffle (not perfectly
            # uniform like Fisher-Yates, but acceptable for the non-MoreSecure path)
            $passwordChars = $passwordChars | Sort-Object { Get-Random }
        }
        $password = -join $passwordChars
    } while (-not (IsValidPassword $password))

    return $password
}

function Get-NewPasswordNode {
    <#
.SYNOPSIS
    Generates random password using Node.js (Firefox logic)
.DESCRIPTION
    Utilizes node.js CLI to invoke password generator logic used by Firefox.
    Will NOT run without node.js runtime installed
.EXAMPLE
    PS C:\> Get-NewPasswordNode
    uafF7MdSYftgh4N
    Generates password of default length(15)
.EXAMPLE    
    PS C:\> Get-NewPasswordNode 8
    or
    PS C:\> Get-NewPasswordNode -Length 8
    3rBBHBcw
    Generates password of length 8
.INPUTS
    Length parameter to specify a length of the generated password (defaults to 15)
.OUTPUTS
    Password string of specified Length
.NOTES
    Firefox Password Generator logic is taken and modified from:
        https://github.com/mozilla/gecko-dev/blob/4ca7c3542cc16420efd6f7e7931241ab102484f6/toolkit/components/passwordmgr/PasswordGenerator.jsm
    upstream version is at:
        (as of 2025.6) https://github.com/mozilla/gecko-dev/blob/master/toolkit/components/passwordmgr/shared/PasswordGenerator.sys.mjs
        (previously) https://github.com/mozilla/gecko-dev/blob/master/toolkit/components/passwordmgr/PasswordGenerator.jsm
    nonexistent window.crypto workaround for node.js is borrowed from:
        https://gist.github.com/Chrischuck/aa6447c4f9b540113f85108e0681f773
    Author: jjw(@thejjw)
    Last Edit: 2021-07

    Tested with Windows Powershell. Should work with pwsh. Requires Node.js runtime installed (tested with 14.17).
#>
    param (
        $Length = 15
    )

    # Delegates to Node.js because the Firefox password generator uses Web Crypto APIs
    if (Get-Command node.exe -ErrorAction SilentlyContinue) {
        $code = @"
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

 "use strict";

/**
 * This file is a port of a subset of Chromium's implementation from
 * https://cs.chromium.org/chromium/src/components/password_manager/core/browser/generation/password_generator.cc?l=93&rcl=a896a3ac4ea731b5ab3d2ab5bd76a139885d5c4f
 * which is Copyright 2018 The Chromium Authors. All rights reserved.
 */
 
// === Patch for Node.js v19+ compatibility ===
// Use built-in Web Crypto if available; otherwise polyfill it.
const nodeCrypto = require("crypto");
if (typeof globalThis.crypto === "undefined") {
  // Older Node (pre-v19)
  globalThis.crypto = {
    getRandomValues: (buffer) => nodeCrypto.randomFillSync(buffer),
  };
} else if (!globalThis.crypto.getRandomValues) {
  // Some environments expose crypto without getRandomValues
  globalThis.crypto.getRandomValues = (buffer) => nodeCrypto.randomFillSync(buffer);
}

const EXPORTED_SYMBOLS = ["PasswordGenerator"];

const DEFAULT_PASSWORD_LENGTH = 15;
const MAX_UINT8 = Math.pow(2, 8) - 1;
const MAX_UINT32 = Math.pow(2, 32) - 1;

// Some characters are removed due to visual similarity:
const LOWER_CASE_ALPHA = "abcdefghijkmnpqrstuvwxyz"; // no 'l' or 'o'
const UPPER_CASE_ALPHA = "ABCDEFGHJKLMNPQRSTUVWXYZ"; // no 'I' or 'O'
const DIGITS = "23456789"; // no '1' or '0'
const SPECIAL_CHARACTERS = " -~!@#$%^&*_+=`|(){}[:;\"'<>,.?]";
const ALPHANUMERIC_CHARACTERS = LOWER_CASE_ALPHA + UPPER_CASE_ALPHA + DIGITS;
const ALL_CHARACTERS = ALPHANUMERIC_CHARACTERS + SPECIAL_CHARACTERS;

const REQUIRED_CHARACTER_CLASSES = [LOWER_CASE_ALPHA, UPPER_CASE_ALPHA, DIGITS];

// Consts for different password rules
const REQUIRED = "required";
const MAX_LENGTH = "maxlength";
const MIN_LENGTH = "minlength";
const MAX_CONSECUTIVE = "max-consecutive";
const UPPER = "upper";
const LOWER = "lower";
const DIGIT = "digit";
const SPECIAL = "special";

// Default password rules
const DEFAULT_RULES = new Map();
DEFAULT_RULES.set(MIN_LENGTH, REQUIRED_CHARACTER_CLASSES.length);
DEFAULT_RULES.set(MAX_LENGTH, MAX_UINT8);
DEFAULT_RULES.set(REQUIRED, [UPPER, LOWER, DIGIT]);

this.PasswordGenerator = {
    /**
     * @param {Object} options
     * @param {number} options.length - length of the generated password if there are no rules that override the length
     * @param {Map} options.rules - map of password rules
     * @returns {string} password that was generated
     * @throws Error if `length` is invalid
     * @copyright 2018 The Chromium Authors. All rights reserved.
     * @see https://cs.chromium.org/chromium/src/components/password_manager/core/browser/generation/password_generator.cc?l=93&rcl=a896a3ac4ea731b5ab3d2ab5bd76a139885d5c4f
     */
    generatePassword({
        length = DEFAULT_PASSWORD_LENGTH,
        rules = DEFAULT_RULES,
    }) {
        rules = new Map([...DEFAULT_RULES, ...rules]);
        if (rules.get(MIN_LENGTH) > length) {
            length = rules.get(MIN_LENGTH);
        }
        if (rules.get(MAX_LENGTH) < length) {
            length = rules.get(MAX_LENGTH);
        }

        let password = "";
        let requiredClasses = [];
        let allRequiredCharacters = "";

        // Generate one character of each required class and/or required character list from the rules
        this._addRequiredClassesAndCharacters(rules, requiredClasses);

        // Generate one of each required class
        for (const charClassString of requiredClasses) {
            password +=
                charClassString[this._randomUInt8Index(charClassString.length)];
            allRequiredCharacters += charClassString;
        }

        // Now fill the rest of the password with random characters.
        while (password.length < length) {
            password +=
                allRequiredCharacters[
                this._randomUInt8Index(allRequiredCharacters.length)
                ];
        }

        // So far the password contains the minimally required characters at the
        // the beginning. Therefore, we create a random permutation.
        password = this._shuffleString(password);

        // Make sure the password passes the "max-consecutive" rule, if the rule exists
        if (rules.has(MAX_CONSECUTIVE)) {
            // Ensures that a password isn't shuffled an infinite number of times.
            const DEFAULT_NUMBER_OF_SHUFFLES = 15;
            let shuffleCount = 0;
            let consecutiveFlag = this._checkConsecutiveCharacters(
                password,
                rules.get(MAX_CONSECUTIVE)
            );
            while (!consecutiveFlag) {
                password = this._shuffleString(password);
                consecutiveFlag = this._checkConsecutiveCharacters(
                    password,
                    rules.get(MAX_CONSECUTIVE)
                );
                ++shuffleCount;
                if (shuffleCount === DEFAULT_NUMBER_OF_SHUFFLES) {
                    consecutiveFlag = true;
                }
            }
        }

        return password;
    },

    /**
     * Adds special characters and/or other required characters to the requiredCharacters array.
     * @param {Map} rules
     * @param {string[]} requiredClasses
     */
    _addRequiredClassesAndCharacters(rules, requiredClasses) {
        for (const charClass of rules.get(REQUIRED)) {
            if (charClass === UPPER) {
                requiredClasses.push(UPPER_CASE_ALPHA);
            } else if (charClass === LOWER) {
                requiredClasses.push(LOWER_CASE_ALPHA);
            } else if (charClass === DIGIT) {
                requiredClasses.push(DIGITS);
            } else if (charClass === SPECIAL) {
                requiredClasses.push(SPECIAL_CHARACTERS);
            } else {
                requiredClasses.push(charClass);
            }
        }
    },

    /**
     * @param range to generate the number in
     * @returns a random number in range [0, range).
     * @copyright 2018 The Chromium Authors. All rights reserved.
     * @see https://cs.chromium.org/chromium/src/base/rand_util.cc?l=58&rcl=648a59893e4ed5303b5c381b03ce0c75e4165617
     */
    _randomUInt8Index(range) {
        if (range > MAX_UINT8) {
            throw new Error("range cannot fit into uint8");
        }
        // We must discard random results above this number, as they would
        // make the random generator non-uniform (consider e.g. if
        // MAX_UINT64 was 7 and |range| was 5, then a result of 1 would be twice
        // as likely as a result of 3 or 4).
        // See https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle#Modulo_bias
        const MAX_ACCEPTABLE_VALUE = Math.floor(MAX_UINT8 / range) * range - 1;

        const randomValueArr = new Uint8Array(1);
        do {
            crypto.getRandomValues(randomValueArr);
        } while (randomValueArr[0] > MAX_ACCEPTABLE_VALUE);
        return randomValueArr[0] % range;
    },

    /**
     * Shuffle the order of characters in a string.
     * @param {string} str to shuffle
     * @returns {string} shuffled string
     */
    _shuffleString(str) {
        let arr = Array.from(str);
        // Generate all the random numbers that will be needed.
        const randomValues = new Uint32Array(arr.length - 1);
        crypto.getRandomValues(randomValues);

        // Fisher-Yates Shuffle
        // https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle
        for (let i = arr.length - 1; i > 0; i--) {
            const j = Math.floor((randomValues[i - 1] / MAX_UINT32) * (i + 1));
            [arr[i], arr[j]] = [arr[j], arr[i]];
        }
        return arr.join("");
    },

    /**
     * Determine the number of consecutive characters in a string.
     * This is primarily used to validate the "max-consecutive" rule
     * of a generated password.
     * @param {string} generatedPassword
     * @param {number} value the number of consecutive characters allowed
     * @return {boolean} true if the generatePassword has less than the value argument number of characters, false otherwise
     */
    _checkConsecutiveCharacters(generatedPassword, value) {
        let max = 0;
        for (let start = 0, end = 1; end < generatedPassword.length;) {
            if (generatedPassword[end] === generatedPassword[start]) {
                if (max < end - start + 1) {
                    max = end - start + 1;
                    if (max > value) {
                        return false;
                    }
                }
                end++;
            } else {
                start = end++;
            }
        }
        return true;
    },
    _getUpperCaseCharacters() {
        return UPPER_CASE_ALPHA;
    },
    _getLowerCaseCharacters() {
        return LOWER_CASE_ALPHA;
    },
    _getDigits() {
        return DIGITS;
    },
    _getSpecialCharacters() {
        return SPECIAL_CHARACTERS;
    },
};
console.log(PasswordGenerator.generatePassword({
    length: $length,
    rules: DEFAULT_RULES
}));
"@;
        $code | node.exe;
    }
    else {
        Write-Output "No Node.js runtime found. Please install one and try running the command again
 (ex: winget install OpenJS.NodeJSLTS)(visit http://nodejs.org/ for more information)";
    }
}

function Save-Download {
    <#
    .SYNOPSIS
        Given a the result of WebResponseObject, will download the file to disk without having to specify a name.
    .DESCRIPTION
        Given a the result of WebResponseObject, will download the file to disk without having to specify a name.
        original reference https://hodgkins.io/download-file-with-powershell-without-renaming
    .PARAMETER WebResponse
        A WebResponseObject from running Invoke-WebRequest2 on a file to download
    .EXAMPLE
        # Download Microsoft Edge
        $download = Invoke-WebRequest2 -Uri "https://go.microsoft.com/fwlink/?linkid=2109047&Channel=Stable&language=en&consent=1"
        $download | Save-Download 
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline)]
        [Microsoft.PowerShell.Commands.WebResponseObject]
        $WebResponse,

        [Parameter(Mandatory = $false)]
        [string]
        $Directory = "."
    )

    $errorMessage = "Cannot determine filename for download."

    if (!($WebResponse.Headers.ContainsKey("Content-Disposition"))) {
        Write-Error $errorMessage -ErrorAction Stop
    }

    # Parse Content-Disposition with the framework class rather than regex to handle
    # quoted filenames, charset parameters, and RFC 6266 edge cases correctly
    $content = [System.Net.Mime.ContentDisposition]::new($WebResponse.Headers["Content-Disposition"])
    
    $fileName = $content.FileName

    if (!$fileName) {
        Write-Error $errorMessage -ErrorAction Stop
    }

    if (!(Test-Path -Path $Directory)) {
        New-Item -Path $Directory -ItemType Directory
    }
    
    $fullPath = Join-Path -Path $Directory -ChildPath $fileName

    Write-Verbose "Downloading to $fullPath"

    # Write via FileStream instead of Set-Content/Out-File because the response
    # body is a raw byte array; converting to string would corrupt binary downloads
    $file = [System.IO.FileStream]::new($fullPath, [System.IO.FileMode]::Create)
    try {
        $file.Write($WebResponse.Content, 0, $WebResponse.RawContentLength)
    } finally {
        $file.Close()
    }
}

function Send-SshKey {
    <#
.SYNOPSIS
    Sends public SSH key to remote Linux server (ssh-copy-id equivalent for Windows PowerShell)
.DESCRIPTION
    Sends user's SSH public key to a specified remote server's ~/.ssh/authorized_keys over SSH.
    Requires OpenSSH client tools (`ssh`, `ssh-keygen`) available in the system PATH.

.PARAMETER User
    The username to authenticate with on the remote server.

.PARAMETER Hostname
    The remote server (IP address or hostname).

.PARAMETER Port
    The SSH port number. Default is 22.

.EXAMPLE
    PS C:\> Send-SshKey -User root -Hostname 192.168.1.100
    Uploads the current user's public key to root@192.168.1.100 on port 22.

.EXAMPLE
    PS C:\> Send-SshKey -User user -Hostname example.com -Port 2222
    Uploads the public key to user@example.com using SSH over port 2222.

.INPUTS
    String parameters -User, -Hostname, and optionally -Port

.OUTPUTS
    None. Writes operation status to console.

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2025-06-17

    To make this function persist, add it to your $PROFILE:
        notepad $PROFILE
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$User,

        [Parameter(Mandatory = $true)]
        [string]$Hostname,

        [int]$Port = 22
    )
    # Prefer common public key filenames. This avoids false negatives when
    # ssh-keygen creates id_ed25519.pub (the modern default) instead of id_rsa.pub.
    $sshDir = Join-Path $env:USERPROFILE '.ssh'
    if (-not (Test-Path $sshDir)) { New-Item -ItemType Directory -Path $sshDir | Out-Null }

    $candidates = @('id_ed25519.pub', 'id_rsa.pub', 'id_ecdsa.pub', 'id_dsa.pub')
    $pubkeyPath = $null
    foreach ($name in $candidates) {
        $p = Join-Path $sshDir $name
        if (Test-Path $p) { $pubkeyPath = $p; break }
    }

    if (-not $pubkeyPath) {
        Write-Host "SSH public key not found. Generating ed25519 key now..." -ForegroundColor Yellow
        # Generate an ed25519 key non-interactively with empty passphrase so the function
        # can be used in scripts. Some shells / platforms may drop an empty "" argument
        # which causes ssh-keygen to see -N with no value. Build an explicit argument
        # array and invoke the program so the empty passphrase is passed reliably.
        $privateKey = Join-Path $sshDir 'id_ed25519'
        $pubkeyPath = "${privateKey}.pub"

        # Prefer explicit path to ssh-keygen if available (compatible with Windows PowerShell v5.1)
        $cmd = Get-Command ssh-keygen -ErrorAction SilentlyContinue
        if ($cmd -ne $null) { $sshCmd = $cmd.Source } else { $sshCmd = 'ssh-keygen' }

        $sshArgs = @('-t', 'ed25519', '-f', $privateKey, '-N', '')

        # Diagnostic output to help debug argument passing and environment
        Write-Verbose "PowerShell version: $($PSVersionTable.PSVersion)"
        Write-Verbose "Resolved sshCmd: $sshCmd"
        Write-Verbose "Resolved privateKey: $privateKey"
        Write-Verbose "sshArgs count: $($sshArgs.Count)"
        for ($i = 0; $i -lt $sshArgs.Count; $i++) {
            $arg = $sshArgs[$i]
            if ($null -eq $arg) { $len = '<null>' } else { $len = $arg.ToString().Length }
            Write-Verbose "  [$i] -> '$arg' (length=$len)"
        }
        Write-Verbose "Joined args (for logging only): $([string]::Join(' ', $sshArgs))"

        try {
            if ($sshArgs -contains '') {
                # Some Windows native binaries (including OpenSSH's ssh-keygen) can drop
                # an empty argument when invoked via PowerShell argument arrays. To ensure
                # the empty quoted string for -N is preserved, build a single quoted
                # command line and run it through cmd.exe /c which preserves "" as an
                # explicit empty-argument token.
                $cmdLine = '"' + $sshCmd + '" -t ed25519 -f "' + $privateKey + '" -N ""'
                Write-Verbose "Invoking via cmd.exe /c: $cmdLine"
                $output = & cmd.exe /c $cmdLine 2>&1
                $exit = $LASTEXITCODE
                Write-Verbose "ssh-keygen (via cmd) exit code: $exit"
                if ($output) { Write-Verbose "ssh-keygen output (via cmd):`n$([string]::Join("`n", $output))" }
                if ($exit -ne 0) {
                    Write-Warning "ssh-keygen failed (exit=$exit). See verbose output above for args and output."
                }
            }
            else {
                Write-Verbose "Invoking: $sshCmd with arg array (see above)"
                $output = & $sshCmd @sshArgs 2>&1
                $exit = $LASTEXITCODE
                Write-Verbose "ssh-keygen exit code: $exit"
                if ($output) { Write-Verbose "ssh-keygen output:`n$([string]::Join("`n", $output))" }
                if ($exit -ne 0) {
                    Write-Warning "ssh-keygen failed (exit=$exit). See verbose output above for args and output."
                }
            }
        }
        catch {
            Write-Warning "Exception while running ssh-keygen: $_"
        }
    }

    if (Test-Path $pubkeyPath) {
        Write-Host "Sending public key $pubkeyPath to ${User}@${Hostname}:${Port} ..." -ForegroundColor Cyan
        # Ensure remote .ssh exists and append the public key; set umask to keep permissions strict.
        Get-Content -Raw $pubkeyPath | ssh "$User@$Hostname" -p $Port 'mkdir -p ~/.ssh; umask 077; cat >> ~/.ssh/authorized_keys'
        Write-Host " Public key installed on $Hostname" -ForegroundColor Green
    }
    else {
        Write-Warning " Could not locate or generate SSH public key. Searched: $($candidates -join ', ')"
    }
}

function Add-WingetPackagePaths {
    <#
.SYNOPSIS
    Adds directories containing executables from winget package installs to the user PATH.

.DESCRIPTION
    Scans subdirectories in %LOCALAPPDATA%\Microsoft\WinGet\Packages that contain .exe files,
    and appends them to the user's PATH environment variable if they are not already present.

.EXAMPLE
    PS C:\> Add-WingetPackagePaths
     Added the following paths to your user PATH:
      C:\Users\User\AppData\Local\Microsoft\WinGet\Packages\ExampleTool\bin
     Updated user PATH:
      C:\Tools\Bin
      C:\Users\User\AppData\Local\Microsoft\WinGet\Packages\ExampleTool\bin
    Adds new executable directories and shows final PATH.

.INPUTS
    None

.OUTPUTS
    Writes status messages to the host; modifies the user PATH environment variable.

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2025-06

    Compatible with Windows PowerShell.
    See Remove-WingetPackagePaths
#>
    $wingetPath = "$env:LOCALAPPDATA\Microsoft\WinGet\Packages"

    if (!(Test-Path $wingetPath)) {
        Write-Host "Winget package directory not found at $wingetPath"
        return
    }

    # Scan all subdirectories containing .exe files; winget does not use a
    # standard bin/ layout so we must discover executable dirs heuristically.
    $binPaths = Get-ChildItem -Path $wingetPath -Directory -Recurse |
    Where-Object { (Get-ChildItem -Path $_.FullName -Filter *.exe -File -ErrorAction SilentlyContinue).Count -gt 0 } |
    Select-Object -ExpandProperty FullName

    $added = @()
    foreach ($path in @($binPaths | Sort-Object -Unique)) {
        $userPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
        $present = @($userPath -split ';' | Where-Object { $_.TrimEnd('\') -ieq $path.TrimEnd('\') }).Count -gt 0
        $pathReady = Add-UserPathEntry -Path $path
        if (-not $present -and $pathReady) {
            $added += $path
        }
    }

    if ($added.Count -eq 0) {
        Write-Host "No new paths were added. All executable directories are already in PATH."
    }
    else {
        Write-Host " Added the following paths to your user PATH:"
        $added | ForEach-Object { Write-Host "  - $_" }
    }

    Write-Host "`n Updated user PATH:"
    [Environment]::GetEnvironmentVariable('PATH', 'User').Split(';') | ForEach-Object { Write-Host "  $_" }
}

function Remove-WingetPackagePaths {
    <#
.SYNOPSIS
    Removes all user PATH entries under the winget package directory.

.DESCRIPTION
    Scans the current user PATH for any entries that start with
    $env:LOCALAPPDATA\Microsoft\WinGet\Packages and removes them.

.EXAMPLE
    PS C:\> Remove-WingetPackagePaths
    [OK] Removed the following winget directories from your user PATH:
      - C:\Users\User\AppData\Local\Microsoft\WinGet\Packages\SomeTool\bin

.INPUTS
    None

.OUTPUTS
    Writes status messages to the host; modifies the user PATH environment variable.

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2025-06

    Compatible with Windows PowerShell.
    See Add-WingetPackagePaths
#>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()

    $wingetRoot = [IO.Path]::Combine($env:LOCALAPPDATA, "Microsoft\WinGet\Packages")
    $normalizedRoot = $wingetRoot.TrimEnd('\')
    $isWingetPackagePath = {
        param([string]$Candidate)
        $normalizedCandidate = $Candidate.TrimEnd('\')
        return $normalizedCandidate -ieq $normalizedRoot -or
            $normalizedCandidate.StartsWith($normalizedRoot + '\', [StringComparison]::OrdinalIgnoreCase)
    }

    try {
        $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
        if (-not $key) { throw 'Could not open HKCU\Environment for writing.' }
        try {
            $currentPath = [string]$key.GetValue('PATH', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $currentPathArr = @($currentPath -split ';' | Where-Object { $_ })
            $removed = @($currentPathArr | Where-Object { & $isWingetPackagePath $_ })
            if ($removed.Count -eq 0) {
                Write-Host 'No Winget package paths found in the user PATH.'
                return
            }

            if (-not $PSCmdlet.ShouldProcess("$($removed.Count) Winget package PATH entries", 'Remove from the user PATH')) {
                return
            }

            $filtered = @($currentPathArr | Where-Object { -not (& $isWingetPackagePath $_) })
            $key.SetValue('PATH', ($filtered -join ';'), [Microsoft.Win32.RegistryValueKind]::ExpandString)
        }
        finally {
            $key.Dispose()
        }

        $processPathArr = @($env:PATH -split ';' | Where-Object { $_ })
        $env:PATH = @($processPathArr | Where-Object { -not (& $isWingetPackagePath $_) }) -join ';'

        Write-Host '[OK] Removed the following Winget directories from the user PATH:'
        $removed | ForEach-Object { Write-Host "  - $_" }
    }
    catch {
        Write-Warning "Could not remove Winget package paths. $($_.Exception.Message)"
    }
}

function New-RandomMacAddress {
    <#
.SYNOPSIS
    Generates a random MAC address, with optional locally administered format.

.DESCRIPTION
    Creates a MAC address for virtual machines, containers, or testing scenarios.
    By default, the MAC address is locally administered (bit 1 of first octet set) and unicast (bit 0 cleared).
    Use the -FullyRandom switch to generate a completely random MAC that may not conform to local/unicast standards.

.PARAMETER FullyRandom
    If specified, generates a fully random MAC address without enforcing local or unicast bits.

.EXAMPLE
    PS C:\> New-RandomMacAddress
    06:3c:74:1a:cc:2e

.EXAMPLE
    PS C:\> New-RandomMacAddress -FullyRandom
    9f:83:ad:75:b2:01

.INPUTS
    None

.OUTPUTS
    System.String. Returns a MAC address as a string (e.g. '02:ab:cd:ef:12:34').

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2025-06

    Compatible with Windows PowerShell and PowerShell Core.
#>
    [CmdletBinding()]
    param (
        [switch]$FullyRandom
    )

    if ($FullyRandom) {
        # All octets are fully random
        $octets = @(for ($i = 0; $i -lt 6; $i++) { (Get-Random -Minimum 0 -Maximum 256).ToString("x2") })
    }
    else {
        # First octet: locally administered (bit 1 set), unicast (bit 0 cleared)
        # Per IEEE 802, bit 0 = multicast, bit 1 = locally administered.
        # Setting bit 1 and clearing bit 0 produces addresses safe for VMs
        # and containers that won't collide with OUI-assigned hardware MACs.
        $first = ((Get-Random -Minimum 0 -Maximum 256) -bor 0x02) -band 0xFE
        $octets = @($first.ToString("x2"))
        for ($i = 1; $i -lt 6; $i++) {
            $octets += (Get-Random -Minimum 0 -Maximum 256).ToString("x2")
        }
    }

    return ($octets -join ":")
}

function Get-MacAdapters {
    <#
.SYNOPSIS
    Lists all network adapters and their MAC addresses.

.DESCRIPTION
    Queries all network adapters and displays their name, description, MAC address, and status.
    Useful for identifying the correct adapter to modify.

.EXAMPLE
    PS C:\> Get-MacAdapters

.OUTPUTS
    Table of adapter details.

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2025-06
#>
    Get-NetAdapter | Format-Table Name, InterfaceDescription, MacAddress, Status
}

function Set-RandomMacAddress {
    <#
.SYNOPSIS
    Sets a network adapter's MAC address to a random value.

.DESCRIPTION
    Generates a random MAC address and applies it to the specified adapter.
    By default, the MAC is locally administered and unicast.
    Use the -FullyRandom switch to generate a completely random MAC address.

.PARAMETER AdapterName
    The name of the network adapter to modify. Use Get-MacAdapters to list available adapters.

.PARAMETER FullyRandom
    If specified, generates a fully random MAC address
    (may not be locally administered or unicast).

.EXAMPLE
    PS C:\> Set-RandomMacAddress -AdapterName "Wi-Fi"
    Sets "Wi-Fi" adapter to a locally administered, unicast random MAC.

.EXAMPLE
    PS C:\> Set-RandomMacAddress -AdapterName "Ethernet" -FullyRandom
    Sets "Ethernet" adapter to a fully random MAC.

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2025-06
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$AdapterName,
        [switch]$FullyRandom
    )

    # Generate MAC address
    if ($FullyRandom) {
        $octets = @(for ($i = 0; $i -lt 6; $i++) { (Get-Random -Minimum 0 -Maximum 256).ToString("x2") })
    }
    else {
        $first = ((Get-Random -Minimum 0 -Maximum 256) -bor 0x02) -band 0xFE
        $octets = @($first.ToString("x2"))
        for ($i = 1; $i -lt 6; $i++) {
            $octets += (Get-Random -Minimum 0 -Maximum 256).ToString("x2")
        }
    }
    # Set-NetAdapter expects a bare hex string (no colons), unlike the
    # colon-separated format New-RandomMacAddress returns for display.
    $newMac = $octets -join ""
    Write-Host "Attempting to set MAC address for adapter '$AdapterName' to $newMac..."

    try {
        Set-NetAdapter -Name $AdapterName -MacAddress $newMac -Confirm:$false
        Write-Host " Successfully changed MAC address."
        Write-Host "Restarting adapter '$AdapterName'..."
        Restart-NetAdapter -Name $AdapterName -Confirm:$false
        Write-Host "Adapter restarted."
        Get-NetAdapter -Name $AdapterName | Select-Object Name, MacAddress
    }
    catch {
        Write-Error "Failed to set MAC address: $_"
        Write-Error "Ensure you are running PowerShell as Administrator and the adapter name is correct."
    }
}

function Reset-MacAddress {
    <#
.SYNOPSIS
    Resets a network adapter's MAC address to its default (hardware) value.

.DESCRIPTION
    Clears the custom MAC address and restores the adapter's original hardware MAC.

.PARAMETER AdapterName
    The name of the network adapter to modify.

.EXAMPLE
    PS C:\> Reset-MacAddress -AdapterName "Wi-Fi"

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2025-06
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$AdapterName
    )

    Write-Host "Resetting MAC address for adapter '$AdapterName' to its default..."
    try {
        Set-NetAdapter -Name $AdapterName -MacAddress $null -Confirm:$false
        Restart-NetAdapter -Name $AdapterName -Confirm:$false
        Write-Host " MAC address reset to default."
        Get-NetAdapter -Name $AdapterName | Select-Object Name, MacAddress
    }
    catch {
        Write-Error "Failed to reset MAC address: $_"
        Write-Error "Ensure you are running PowerShell as Administrator and the adapter name is correct."
    }
}

function Convert-JpgToJxl {
    <#
.SYNOPSIS
    Converts all jpg images in a directory (recursively) to .jxl using ImageMagick, in parallel. DELETES ORIGINALS ON SUCCESS.
.DESCRIPTION
    Finds all .jpg and .jpeg files recursively from a target directory (default: current), starts a background job for each conversion,
    and deletes the original file only on successful conversion. Reports progress and elapsed time.
    Uses Windows PowerShell Start-Job for parallelism (suitable for PowerShell 5.1+).
.PARAMETER Path
    The directory to search for .jpg/.jpeg images. Default is current directory.
.PARAMETER ThrottleLimit
    Maximum number of parallel jobs allowed. Default is 4.
.EXAMPLE
    PS C:\> Convert-JpgToJxl
.EXAMPLE
    PS C:\> Convert-JpgToJxl -Path "D:\Photos" -ThrottleLimit 8
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2025-06
    - Compatible with Windows PowerShell and PowerShell Core.
    - Requires ImageMagick (magick.exe) in PATH.
    - Deletes .jpg/.jpeg only on successful conversion.
#>
    [CmdletBinding()]
    param(
        [string]$Path = ".",
        [int]$ThrottleLimit = 4
    )

    # Collect both extensions explicitly; WinPS 5.1's -Filter does not
    # accept comma-separated values or -Include reliably with -Recurse.
    $images = @(Get-ChildItem -Path $Path -Filter *.jpg -Recurse -File) + @(Get-ChildItem -Path $Path -Filter *.jpeg -Recurse -File)
    $total = $images.Count
    if ($total -eq 0) {
        Write-Host "No .jpg or .jpeg files found in $Path"
        return
    }
    $startTime = Get-Date
    $jobs = @()
    $i = 0

    foreach ($image in $images) {
        # Throttle by polling running-job count; WinPS 5.1 lacks the
        # -ThrottleLimit parameter available in pwsh's Start-Job.
        while (@(Get-Job -State "Running").Count -ge $ThrottleLimit) {
            Start-Sleep -Milliseconds 200
        }
        $jobs += Start-Job -ArgumentList $image.FullName -ScriptBlock {
            param($imgPath)
            $jxlPath = $imgPath -replace '\.(jpg|jpeg)$', '.jxl'
            try {
                & magick.exe $imgPath $jxlPath
                if (Test-Path $jxlPath) {
                    Remove-Item $imgPath -Verbose
                    [PSCustomObject]@{Status = "Success"; Path = $imgPath }
                }
                else {
                    [PSCustomObject]@{Status = "Fail"; Path = $imgPath }
                }
            }
            catch {
                [PSCustomObject]@{Status = "Error"; Path = $imgPath; Message = $_ }
            }
        }
    }

    # Drain jobs as they complete rather than Wait-Job on the full array,
    # so progress updates stream in real time instead of appearing all at once.
    $completed = 0
    while ($jobs.Count -gt 0) {
        $finishedJobs = Wait-Job -Job $jobs -Any
        $results = Receive-Job -Job $finishedJobs -AutoRemoveJob
        $jobs = @($jobs | Where-Object { $finishedJobs.Id -notcontains $_.Id })
        foreach ($result in $results) {
            $completed++
            $pct = [math]::Round($completed * 100 / $total, 2)
            $elapsed = (Get-Date) - $startTime
            if ($result.Status -eq "Success") {
                Write-Host ("[{0}] Converted [{1}] ({2}/{3}, {4}%) ({5} sec elapsed)" -f (Get-Date), $result.Path, $completed, $total, $pct, [math]::Round($elapsed.TotalSeconds, 2))
            }
            elseif ($result.Status -eq "Fail") {
                Write-Warning "Conversion failed for $($result.Path)"
            }
            elseif ($result.Status -eq "Error") {
                Write-Warning "Error converting $($result.Path): $($result.Message)"
            }
        }
        Start-Sleep -Milliseconds 200
    }

    $endTime = Get-Date
    $elapsedTime = $endTime - $startTime
    Write-Host "The script took $($elapsedTime.TotalSeconds) seconds to convert $total images."
}

# Sequential variant kept for systems where background jobs are unavailable
# or undesirable (e.g., constrained runspaces, CI pipelines, single-core VMs).
function Convert-JpgToJxl-Sequential {
    <#
.SYNOPSIS
    Converts all jpg images in a directory (recursively) to .jxl using ImageMagick. DELETES ORIGINALS ON SUCCESS.
.DESCRIPTION
    Finds all .jpg and .jpeg files recursively from a target directory (default: current), converts each to .jxl using magick.exe,
    and deletes the original file only on successful conversion.
    Reports progress and elapsed time. Designed for Windows PowerShell compatibility (v5.1+).
.PARAMETER Path
    The directory to search for .jpg/.jpeg images. Default is current directory.
.EXAMPLE
    PS C:\> Convert-JpgToJxl-Sequential
.EXAMPLE
    PS C:\> Convert-JpgToJxl-Sequential -Path "D:\Photos"
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2025-06
    - Compatible with Windows PowerShell and PowerShell Core.
    - Requires ImageMagick (magick.exe) in PATH.
    - Deletes .jpg/.jpeg only on successful conversion.
#>
    [CmdletBinding()]
    param(
        [string]$Path = "."
    )
    $images = @(Get-ChildItem -Path $Path -Filter *.jpg -Recurse -File) + @(Get-ChildItem -Path $Path -Filter *.jpeg -Recurse -File)
    $total = $images.Count
    if ($total -eq 0) {
        Write-Host "No .jpg or .jpeg files found in $Path"
        return
    }
    $startTime = Get-Date
    $i = 0
    foreach ($image in $images) {
        $jxlPath = $image.FullName -replace '\.(jpg|jpeg)$', '.jxl'
        try {
            & magick.exe $image.FullName $jxlPath
            if (Test-Path $jxlPath) {
                Remove-Item $image.FullName -Verbose
            }
            else {
                Write-Warning "Conversion failed for $($image.FullName)"
            }
        }
        catch {
            Write-Warning "Error converting $($image.FullName): $_"
        }
        $i++
        $pct = [math]::Round($i * 100 / $total, 2)
        $elapsed = (Get-Date) - $startTime
        Write-Host ("[{0}] Converted {1} of {2} images ({3}%) ({4} sec elapsed)" -f (Get-Date), $i, $total, $pct, [math]::Round($elapsed.TotalSeconds, 2))
    }
    $endTime = Get-Date
    $elapsedTime = $endTime - $startTime
    Write-Host "The script took $($elapsedTime.TotalSeconds) seconds to convert $total images."
}

# Reverse conversion utility -- kept separate from the jpg-to-jxl functions
# because the output extension logic and error semantics differ enough that
# merging them would add branching complexity for little benefit.
function Convert-JxlToJpg {
    <#
.SYNOPSIS
    Converts all .jxl images in a directory (recursively) to .jpg using ImageMagick. DELETES ORIGINALS ON SUCCESS.
.DESCRIPTION
    Finds all .jxl files recursively from a target directory (default: current), converts each to .jpg using magick.exe,
    and deletes the original .jxl only on successful conversion. Reports progress and elapsed time.
    Designed for Windows PowerShell compatibility (v5.1+).
.PARAMETER Path
    The directory to search for .jxl images. Default is current directory.
.EXAMPLE
    PS C:\> Convert-JxlToJpg
.EXAMPLE
    PS C:\> Convert-JxlToJpg -Path "D:\Photos"
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2025-06
    - Compatible with Windows PowerShell and PowerShell Core.
    - Requires ImageMagick (magick.exe) in PATH.
    - Deletes .jxl only on successful conversion.
#>
    [CmdletBinding()]
    param(
        [string]$Path = "."
    )
    $images = Get-ChildItem -Path $Path -Filter *.jxl -Recurse -File
    $total = $images.Count
    if ($total -eq 0) {
        Write-Host "No .jxl files found in $Path"
        return
    }
    $startTime = Get-Date
    $i = 0
    foreach ($image in $images) {
        $jpgPath = $image.FullName -replace '\.jxl$', '.jpg'
        try {
            & magick.exe $image.FullName $jpgPath
            if (Test-Path $jpgPath) {
                Remove-Item $image.FullName -Verbose
            }
            else {
                Write-Warning "Conversion failed for $($image.FullName)"
            }
        }
        catch {
            Write-Warning "Error converting $($image.FullName): $_"
        }
        $i++
        $pct = [math]::Round($i * 100 / $total, 2)
        $elapsed = (Get-Date) - $startTime
        Write-Host ("[{0}] Converted {1} of {2} images ({3}%) ({4} sec elapsed)" -f (Get-Date), $i, $total, $pct, [math]::Round($elapsed.TotalSeconds, 2))
    }
    $endTime = Get-Date
    $elapsedTime = $endTime - $startTime
    Write-Host "The script took $($elapsedTime.TotalSeconds) seconds to convert $total images."
}

function Get-IpInfo {
    <#
.SYNOPSIS
    Prints the command to query ipregistry.co for a given IP address using curl-like User-Agent.
.DESCRIPTION
    Outputs the exact Invoke-RestMethod command for the user to copy and run manually.
.EXAMPLE
    PS C:\> Get-IpInfo 1.1.1.1
    Prints the command to query ipregistry.co for 1.1.1.1
.INPUTS
    IP address as string.
.OUTPUTS
    String: PowerShell command to run manually.
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2025-06
#>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Ip
    )
    $cmd = "Invoke-RestMethod -Uri 'https://api.ipregistry.co/${Ip}?key=tryout' -Headers @{ 'User-Agent' = 'curl/7.68.0' }"
    Write-Host "Run this command manually in your shell:" -ForegroundColor Yellow
    Write-Host $cmd -ForegroundColor Cyan
}

function Test-IsAdministrator {
    <#
.SYNOPSIS
Tests if the current PowerShell session is running with administrator privileges.

.DESCRIPTION
Returns $true if running as administrator, $false otherwise.

.EXAMPLE
if (Test-IsAdministrator) { Write-Host "Running as admin" }

.NOTES
Author: jjw(@thejjw)
Last Edit: Aug 2025
#>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-DeviceIdentity {
    <#
.SYNOPSIS
Retrieves per-Windows-install identifiers: the Microsoft GDID and the crypto MachineGuid.

.DESCRIPTION
Reads two identifiers that persist across OS updates but change on a clean Windows
reinstall, so they identify an installation rather than the hardware:

- GDID: derived from the per-user Microsoft identity LID at
  HKCU\SOFTWARE\Microsoft\IdentityCRL\ExtendedProperties. The LID is a 64-bit hex
  value; the GDID is 'g:' + its decimal form (the format seen in Microsoft's device
  graph / court filings). Absent when no Microsoft Account has provisioned the profile.
- MachineGuid: the documented, always-present installation GUID at
  HKLM\SOFTWARE\Microsoft\Cryptography. Used as the fallback when GDID is absent.

Both registry values are readable with normal user rights; no elevation is required.

.PARAMETER AsString
Returns a single string (the GDID if present, otherwise the MachineGuid) instead of an
object. Convenient when you just want one stable ID for the current install.

.EXAMPLE
Get-DeviceIdentity
# Returns an object with Gdid, LidHex, MachineGuid, and Primary.

.EXAMPLE
Get-DeviceIdentity -AsString
# g:6755494590140176   (falls back to the MachineGuid if no GDID exists)

.OUTPUTS
PSCustomObject (default) or String (with -AsString).

.NOTES
Author: jjw(@thejjw)
Last Edit: Jul 2026
#>
    [CmdletBinding()]
    [OutputType([PSCustomObject], [string])]
    param(
        [switch] $AsString
    )

    # GDID: read the per-user LID (hex) and convert to the 'g:<decimal>' form.
    # Missing key/value or an unparseable LID all collapse to $null (GDID simply absent).
    $gdid = $null
    $lidHex = $null
    try {
        $lid = (Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\IdentityCRL\ExtendedProperties' -ErrorAction Stop).LID
        if (-not [string]::IsNullOrWhiteSpace($lid)) {
            $lidHex = $lid
            $gdid = 'g:' + [System.Convert]::ToUInt64($lid, 16)
        }
    } catch {
        Write-Verbose "GDID unavailable: $($_.Exception.Message)"
    }

    # MachineGuid: documented installation GUID, present on every Windows install.
    $machineGuid = $null
    try {
        $machineGuid = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -ErrorAction Stop).MachineGuid
    } catch {
        Write-Verbose "MachineGuid unavailable: $($_.Exception.Message)"
    }

    # Primary = GDID when present, else fall back to MachineGuid.
    $primary = if ($gdid) { $gdid } else { $machineGuid }

    if ($AsString) {
        return $primary
    }

    return [PSCustomObject]@{
        Gdid        = $gdid
        LidHex      = $lidHex
        MachineGuid = $machineGuid
        Primary     = $primary
    }
}

function New-SafeFileNameFromCertificateName {
    <#
.SYNOPSIS
Creates a filesystem-safe filename from a certificate subject or other string.

.DESCRIPTION
Removes or replaces characters that are invalid in filenames, extracts CN from subject strings,
and ensures the result is not empty.

.PARAMETER InputString
The string to convert to a safe filename.

.PARAMETER DefaultName
Default name to use if the input results in an empty string.

.EXAMPLE
New-SafeFileNameFromCertificateName -InputString "CN=*.example.com, O=Example Corp" -DefaultName "cert"
# Returns: example.com

.NOTES
Author: jjw(@thejjw)
Last Edit: Aug 2025
#>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string] $InputString,
        
        [string] $DefaultName = "cert"
    )
    
    # Extract CN if it's a certificate subject
    $cleaned = $InputString -replace 'CN=', '' -replace ',.*', ''
    
    # Replace invalid filesystem characters
    $safeName = ($cleaned -replace '[^\w\.-]+', '_').Trim('_')
    
    # Return default if empty
    if ([string]::IsNullOrWhiteSpace($safeName)) {
        return $DefaultName
    }
    
    return $safeName
}

function Get-CertutilPath {
    <#
.SYNOPSIS
Locates the certutil.exe executable on the system.

.DESCRIPTION
Searches common paths for certutil.exe and returns the full path if found.

.EXAMPLE
$certutilPath = Get-CertutilPath

.NOTES
Author: jjw(@thejjw)
Last Edit: Aug 2025
#>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    
    $commonPaths = @(
        "${env:SystemRoot}\System32\certutil.exe",
        "${env:SystemRoot}\SysWOW64\certutil.exe",
        "${env:windir}\Sysnative\certutil.exe"
    )
    
    foreach ($path in $commonPaths) {
        if (Test-Path $path) {
            return $path
        }
    }
    
    # Try to find it in PATH
    $pathResult = Get-Command certutil.exe -ErrorAction SilentlyContinue
    if ($pathResult) {
        return $pathResult.Source
    }
    
    throw "certutil.exe not found on this system"
}

function Install-ServerCertificateTrust {
    <#
.SYNOPSIS
Connects to an HTTPS server, retrieves its certificate chain, and installs selected certificates into Windows trust stores.

.DESCRIPTION
Useful for trusting dev servers, internal hosts, or self-signed certs so that browsers and clients stop complaining. 
By default, installs into CurrentUser; use -MachineStore for system-wide trust with elevation. 
You can choose to install Root, Intermediate, Leaf, or all certificates.

Supports two installation methods:
- X509Store: Direct .NET API installation (default)
- Certutil: Uses certutil.exe for installation

.PARAMETER Url
The full HTTPS URL of the server (e.g. https://localhost:8443).

.PARAMETER WhatToInstall
Selects certificate level: 'Root', 'Intermediate', 'Leaf', or 'All'.

.PARAMETER InstallMethod
Method to use for certificate installation: 'X509Store' (default) or 'Certutil'.

.PARAMETER MachineStore
If set, installs to LocalMachine stores (requires admin).

.PARAMETER SaveToFiles
If set, exports selected certificates to disk for inspection.

.PARAMETER OutDir
Folder where exported certificates go. Defaults to '.\certs'.

.PARAMETER SNIHost
Optional override for the hostname sent during TLS handshake.

.PARAMETER SkipCertValidation
Skip certificate validation during TLS connection (allows self-signed/invalid certs).

.PARAMETER WhatIfOnly
Fetch and export certificates, but skip installation steps.

.PARAMETER InstallEndEntity
Also installs the server certificate (end-entity) into the Personal (My) store. 
Only applies when using Certutil method.

.PARAMETER Force
Overwrites existing certificate files in OutDir if SaveToFiles is used.

.EXAMPLE
Install-ServerCertificateTrust -Url https://dev.local -WhatToInstall All -MachineStore

.EXAMPLE
Install-ServerCertificateTrust -Url https://api.example.com -InstallMethod Certutil -WhatIfOnly

.NOTES
Author: jjw(@thejjw)
Last Edit: Aug 2025
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Url,

        [ValidateSet('Root', 'Intermediate', 'Leaf', 'All')]
        [string] $WhatToInstall = 'Root',

        [ValidateSet('X509Store', 'Certutil')]
        [string] $InstallMethod = 'X509Store',

        [switch] $MachineStore,
        [switch] $SaveToFiles,
        [string] $OutDir = (Join-Path $PWD 'certs'),
        [string] $SNIHost,
        [switch] $SkipCertValidation,
        [switch] $WhatIfOnly,
        [switch] $InstallEndEntity,
        [switch] $Force
    )

    # --- Internal helper functions ---
    # HashSet-based dedup by thumbprint; SslStream can return duplicate
    # chain elements depending on the server's chain configuration.
    function Get-UniqueByThumbprint {
        param([System.Collections.IEnumerable] $Certificates)
        $certList = @($Certificates)
        $seen = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($cert in $certList) {
            if ($null -ne $cert -and $seen.Add($cert.Thumbprint)) { $cert }
        }
    }

    function Test-SelfSignedCertificate {
        param([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)
        return ($Certificate.Subject -eq $Certificate.Issuer)
    }

    function Get-CertificateType {
        param(
            [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
            [bool] $IsFirstInChain = $false,
            [bool] $IsLastInChain = $false
        )
        
        $isSelfSigned = Test-SelfSignedCertificate -Certificate $Certificate
        
        # Check basic constraints extension for CA status
        $isCA = $false
        foreach ($ext in $Certificate.Extensions) {
            if ($ext -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
                $isCA = $ext.CertificateAuthority
                break
            }
        }
        
        # Position-based classification takes precedence
        if ($IsFirstInChain -and -not $isSelfSigned) { return "Leaf" }
        elseif ($IsLastInChain -or $isSelfSigned) { return "Root" }
        elseif ($isCA) { return "Intermediate" }
        else { return "Leaf" }
    }

    # Maps a certificate to the correct Windows store name (Root/CA/My)
    # for X509Store-based installation. Falls through to 'My' (Personal) for
    # end-entity certs that lack BasicConstraints.
    function Get-CertificateStoreName {
        param([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)

        if (Test-SelfSignedCertificate -Certificate $Certificate) { return 'Root' }

        $bc = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' } | Select-Object -First 1
        if ($bc -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
            if ($bc.CertificateAuthority) { return 'CA' }
        }

        return 'My'
    }

    # Separate classification for certutil install planning -- uses
    # 'CA'/'EndEntity' labels instead of 'Intermediate'/'Leaf' to align
    # with certutil's own store naming (Root, CA, My).
    function Classify-Certificate {
        param([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)

        $isSelfSigned = Test-SelfSignedCertificate -Certificate $Certificate
        $isCA = $false
        
        foreach ($ext in $Certificate.Extensions) {
            if ($ext -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
                $isCA = $ext.CertificateAuthority
            }
        }

        if ($isCA -and $isSelfSigned) { return 'Root' }
        if ($isCA -and -not $isSelfSigned) { return 'CA' }
        return 'EndEntity'
    }

    function Save-CertificateAsFile {
        param(
            [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
            [string] $Directory,
            [switch] $Overwrite
        )
        
        # Improved CN extraction with better handling of escaped characters
        $subjectParts = $Certificate.Subject -split '(?<!\\),' | ForEach-Object { $_.Trim() }
        $cnPart = $subjectParts | Where-Object { $_ -like 'CN=*' } | Select-Object -First 1
        $cn = if ($cnPart) { $cnPart -replace '^CN=', '' -replace '\\(.)', '$1' } else { $null }
        
        if ([string]::IsNullOrWhiteSpace($cn)) { 
            $cn = $Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) 
        }
        if ([string]::IsNullOrWhiteSpace($cn)) { $cn = 'Unknown' }

        # Double-underscore separates human-readable name from thumbprint so
        # filenames stay unique across renewals without collisions.
        $safeName = New-SafeFileNameFromCertificateName -InputString $cn -DefaultName "cert"
        $thumb = $Certificate.Thumbprint -replace '\s', ''
        $fileBase = "{0}__{1}" -f $safeName, $thumb
        $path = Join-Path $Directory ($fileBase + '.cer')

        if ((-not $Overwrite) -and (Test-Path -LiteralPath $path)) {
            return $path
        }

        $bytes = $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
        [IO.File]::WriteAllBytes($path, $bytes)
        return $path
    }

    function Escape-CertutilArgument {
        param([string] $Argument)
        if ($Argument -match '\s') { return "`"$Argument`"" }
        return $Argument
    }

    # Launches certutil.exe via System.Diagnostics.Process instead of
    # direct invocation so we can capture stdout/stderr and check the exit
    # code -- certutil returns non-zero on failure but still writes to stderr
    # on partial success, so we need both streams.
    function Invoke-CertutilAddStore {
        param(
            [string] $StoreName,
            [string] $CertificatePath,
            [switch] $MachineStore
        )
        
        $certutil = Get-CertutilPath
        $args = @()
        if (-not $MachineStore) { $args += '-user' }
        $args += '-addstore'
        $args += $StoreName
        $args += $CertificatePath

        # Properly escape arguments that contain spaces
        $escapedArgs = $args | ForEach-Object { Escape-CertutilArgument $_ }
        $argumentString = $escapedArgs -join ' '

        Write-Verbose ("certutil {0}" -f $argumentString)
        
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $certutil
        $psi.Arguments = $argumentString
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $psi
        
        try {
            [void]$p.Start()
            $stdout = $p.StandardOutput.ReadToEnd()
            $stderr = $p.StandardError.ReadToEnd()
            $p.WaitForExit()

            if ($p.ExitCode -ne 0) {
                throw "certutil failed (exit $($p.ExitCode)) for $CertificatePath to $StoreName. Error: $stderr`nOutput: $stdout"
            }
            else {
                Write-Verbose $stdout.Trim()
            }
        }
        finally {
            if ($p) { $p.Dispose() }
        }
    }

    # --- Permission validation ---
    if ($MachineStore -and -not (Test-IsAdministrator)) {
        throw "Must run PowerShell as Administrator to use -MachineStore."
    }

    $storeLocation = if ($MachineStore) { 'LocalMachine' } else { 'CurrentUser' }

    # --- Parse URL ---
    if ($Url -notmatch '^\w+://') { $Url = "https://${Url}" }
    $uri = [Uri]$Url
    $targetHost = $uri.Host
    $targetPort = if ($uri.IsDefaultPort) { 443 } else { $uri.Port }
    if (-not $SNIHost) { $SNIHost = $targetHost }

    Write-Verbose "Connecting to ${targetHost}:${targetPort} with SNI '${SNIHost}'"

    # --- TLS connection and cert retrieval ---
    $tcp = $null; $ssl = $null; $leaf = $null
    try {
        Write-Verbose "Establishing TCP connection to ${targetHost}:${targetPort}..."
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $tcp.ReceiveTimeout = 10000
        $tcp.SendTimeout = 10000
        $tcp.Connect($targetHost, $targetPort)
        
        # Certificate validation callback configuration
        # GetNewClosure() captures $serverChainElements by reference so both
        # branches of the callback can populate it during the TLS handshake.
        # We always return $true to let the handshake complete even with
        # invalid certs -- the user explicitly opted in via -SkipCertValidation
        # or wants to inspect chain issues via -WhatIfOnly.
        $serverChainElements = [System.Collections.ArrayList]::new()
        $certCallback = if ($SkipCertValidation) {
            { param($s, $c, $chain, $errors)
                if ($chain) { foreach ($e in $chain.ChainElements) { [void]$serverChainElements.Add($e.Certificate) } }
                return $true 
            }.GetNewClosure()
        }
        else {
            { param($s, $c, $chain, $errors) 
                if ($chain) { foreach ($e in $chain.ChainElements) { [void]$serverChainElements.Add($e.Certificate) } }
                if ($errors -ne [System.Net.Security.SslPolicyErrors]::None) {
                    Write-Warning "TLS certificate validation errors: $errors"
                }
                return $true  # Still proceed but warn about issues
            }.GetNewClosure()
        }
        
        $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false, $certCallback)
        $ssl.AuthenticateAsClient($SNIHost)
        $leaf = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
        Write-Verbose "Successfully retrieved server certificate: $($leaf.Subject)"
    }
    catch {
        throw "Failed to retrieve certificate from ${targetHost}:${targetPort}. $_"
    }
    finally {
        if ($ssl) { $ssl.Dispose() }
        if ($tcp) { $tcp.Dispose() }
    }

    # --- Chain building ---
    # Prefer certs collected by the validation callback (they reflect what the
    # server actually sent). Fall back to X509Chain.Build() when the callback
    # didn't capture anything -- e.g. on older .NET Framework where the chain
    # parameter may be null in the callback.
    if ($serverChainElements.Count -gt 0) {
        $chainCertsRaw = $serverChainElements.ToArray()
    } else {
        $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
        $chain.ChainPolicy.RevocationMode = 'NoCheck'

        if ($InstallMethod -eq 'Certutil') {
            # More extensive verification flags for certutil method
            $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EndCertificateOnly
            $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(20)
            $chain.ChainPolicy.VerificationFlags = `
                [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreCertificateAuthorityRevocationUnknown `
                -bor [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreCtlSignerRevocationUnknown `
                -bor [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreEndRevocationUnknown `
                -bor [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreRootRevocationUnknown
        }
        else {
            $chain.ChainPolicy.VerificationFlags = 'AllowUnknownCertificateAuthority'
        }
        
        $buildResult = $chain.Build($leaf)
        if (-not $buildResult -and $InstallMethod -eq 'Certutil') {
            Write-Warning "Certificate chain building incomplete. Some intermediate certificates may be missing. Chain status: $($chain.ChainStatus | ForEach-Object { $_.Status })"
        }
        $chainCertsRaw = @($chain.ChainElements | ForEach-Object { $_.Certificate })
    }
    $elements = @(Get-UniqueByThumbprint -Certificates $chainCertsRaw)

    if (-not $elements -or $elements.Count -eq 0) {
        $elements = @($leaf)
        Write-Warning "Server did not provide a certificate chain. Using only leaf certificate."
    }

    # Chain is ordered leaf-first from the TLS handshake, so root is the
    # last element. Intermediates are everything between leaf and root.
    # --- Certificate selection helpers ---
    function Get-RootCert { param($e) if ($e.Count -gt 0) { $e[-1] } }
    function Get-Intermediates { param($e) if ($e.Count -gt 2) { $e[1..($e.Count - 2)] } else { @() } }

    # --- Select certificates to work with ---
    $toInstall = switch ($WhatToInstall) {
        'Root' { @(Get-RootCert $elements) | Where-Object { $_ } }
        'Intermediate' { @(Get-Intermediates $elements) | Where-Object { $_ } }
        'Leaf' { @($leaf) | Where-Object { $_ } }
        'All' { $elements | Where-Object { $_ } }
    }

    if (-not $toInstall -or $toInstall.Count -eq 0) {
        throw "No certificates selected for '${WhatToInstall}'."
    }

    # --- Optional export to files ---
    if ($SaveToFiles) {
        if (-not (Test-Path $OutDir)) { 
            $null = New-Item -ItemType Directory -Path $OutDir -Force
            Write-Verbose "Created output directory: ${OutDir}"
        }
        
        foreach ($cert in $toInstall) {
            if ($InstallMethod -eq 'Certutil') {
                # Certutil method uses Save-CertificateAsFile
                $path = Save-CertificateAsFile -Certificate $cert -Directory $OutDir -Overwrite:$Force
                Write-Verbose "Exported: ${path}"
            }
            else {
                # X509Store method uses simpler export
                $safeName = New-SafeFileNameFromCertificateName -InputString $cert.Subject
                $filePath = Join-Path $OutDir ("${safeName}-${cert.Thumbprint}.cer")
                [IO.File]::WriteAllBytes($filePath, $cert.Export('Cert'))
                Write-Verbose "Exported: ${filePath}"
            }
        }
        
        Write-Host "Exported $($toInstall.Count) certificate(s) to: ${OutDir}"
    }

    # --- Installation planning (for Certutil method) ---
    if ($InstallMethod -eq 'Certutil') {
        $plan = @()
        foreach ($cert in $toInstall) {
            $type = Classify-Certificate -Certificate $cert
            $path = if ($SaveToFiles) {
                # Already saved, just get the path
                $safeName = New-SafeFileNameFromCertificateName -InputString $cert.Subject
                Join-Path $OutDir ("${safeName}-${cert.Thumbprint}.cer")
            }
            else {
                # Need to save to temp for certutil
                $tempDir = if (-not (Test-Path $OutDir)) {
                    $null = New-Item -ItemType Directory -Path $OutDir -Force
                    $OutDir
                }
                else { $OutDir }
                Save-CertificateAsFile -Certificate $cert -Directory $tempDir -Overwrite:$Force
            }

            $store = switch ($type) {
                'Root' { 'Root' }
                'CA' { 'CA' }
                'EndEntity' {
                    if ($InstallEndEntity) { 'My' } else { $null }
                }
                default { $null }
            }

            $plan += [pscustomobject]@{
                Subject     = $cert.Subject
                Thumbprint  = $cert.Thumbprint -replace '\s', ''
                Type        = $type
                Path        = $path
                Store       = $store
                Certificate = $cert
            }
        }

        # Display plan
        Write-Host "`nCertificate installation plan:"
        foreach ($item in $plan) {
            $storeLabel = if ($item.Store) { $item.Store } else { '(skip install)' }
            Write-Host (" - {0} [{1}] -> {2}" -f $item.Subject, $item.Type, $storeLabel)
        }

        if ($WhatIfOnly) {
            Write-Host "`nWhatIfOnly specified: no installation attempted."
            Write-Host "`n--- Certificate Chain Summary ---"
            Write-Host "Target server: ${targetHost}:${targetPort}"
            Write-Host "Leaf:   ${leaf.Subject} [${leaf.Thumbprint}]"
            Write-Host "Chain:"
            for ($i = 0; $i -lt $elements.Count; $i++) {
                $tag = if ($i -eq 0) { '[Leaf]' } elseif ($i -eq $elements.Count - 1) { '[Root]' } else { '[Interm]' }
                Write-Host ("  ${tag} ${elements[$i].Subject} [${elements[$i].Thumbprint}]")
            }
            return $plan
        }

        # Install using certutil
        foreach ($item in $plan | Where-Object { $_.Store }) {
            try {
                Invoke-CertutilAddStore -StoreName $item.Store -CertificatePath $item.Path -MachineStore:$MachineStore
                Write-Host ("Installed via certutil: {0} -> {1}" -f (Split-Path -Leaf $item.Path), $item.Store)
            }
            catch {
                Write-Warning "Failed to install $($item.Path) into store $($item.Store): $($_.Exception.Message)"
            }
        }
    }
    else {
        # Install using X509Store method
        if ($WhatIfOnly) {
            Write-Host "`nWhatIfOnly specified: no installation attempted (X509Store method)."
        }
        else {
            foreach ($cert in $toInstall) {
                if ($WhatToInstall -eq 'Leaf' -and -not (Test-SelfSignedCertificate -Certificate $cert)) {
                    Write-Warning "Skipping non-self-signed leaf certificate. Install its issuer instead."
                    continue
                }

                $storeName = Get-CertificateStoreName -Certificate $cert
                
                # Skip end-entity certs unless explicitly requested -- installing
                # a server cert into the Personal store is rarely needed for
                # trust and can cause confusion with SChannel cert selection.
                if ($storeName -eq 'My' -and -not $InstallEndEntity -and $WhatToInstall -ne 'Leaf') {
                    Write-Verbose "Skipping end-entity certificate (use -InstallEndEntity to include)"
                    continue
                }

                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, $storeLocation)
                $store.Open('ReadWrite')
                try {
                    $existing = $store.Certificates.Find('FindByThumbprint', $cert.Thumbprint, $false)
                    if ($existing.Count -eq 0) {
                        $store.Add($cert)
                        Write-Host ("Installed via X509Store: ${cert.Subject} => ${storeLocation}\${storeName}")
                    }
                    else {
                        Write-Host ("Already present: ${cert.Subject} in ${storeLocation}\${storeName}")
                    }
                }
                finally {
                    $store.Close()
                }
            }
        }
    }

    # --- Summary ---
    Write-Host "`n--- Certificate Chain Summary ---"
    Write-Host "Target server: ${targetHost}:${targetPort}"
    Write-Host "Leaf:   ${leaf.Subject} [${leaf.Thumbprint}]"
    Write-Host "Chain:"
    for ($i = 0; $i -lt $elements.Count; $i++) {
        $tag = if ($i -eq 0) { '[Leaf]' } elseif ($i -eq $elements.Count - 1) { '[Root]' } else { '[Intermediate]' }
        Write-Host ("  ${tag} ${elements[$i].Subject} [${elements[$i].Thumbprint}]")
    }
}

function Export-TlsCertificates {
    <#
.SYNOPSIS
Retrieves and exports TLS certificates from a remote server without installing them.

.DESCRIPTION
Connects to a remote server via TLS, retrieves the certificate chain, and exports
selected certificates to files in PEM and/or DER format. Does not modify the 
Windows certificate store. Useful for certificate analysis, backup, or 
importing into other systems.

.PARAMETER TargetHost
The hostname or IP address of the target server to retrieve certificates from.

.PARAMETER TargetPort
The TCP port to connect to. Defaults to 443 (HTTPS).

.PARAMETER SNIHost
The Server Name Indication (SNI) hostname to use during TLS handshake.
Defaults to the same value as TargetHost. Useful for servers hosting 
multiple certificates.

.PARAMETER WhatToExport
Specifies which certificates from the chain to export:
- 'Root': Only the root CA certificate
- 'Intermediate': Only intermediate CA certificates  
- 'Leaf': Only the server certificate
- 'All': All certificates in the chain (default)

.PARAMETER OutDir
Directory path where exported certificate files will be saved.
Defaults to ".\certificates". Directory will be created if it doesn't exist.

.PARAMETER Format
Certificate export format:
- 'PEM': Base64 encoded with BEGIN/END markers
- 'DER': Binary format
- 'Both': Export in both formats (default)

.PARAMETER NoExport
Switch to only display certificate information without exporting files.
Useful for certificate analysis and troubleshooting.

.OUTPUTS
PSCustomObject with properties:
- LeafCertificate: The server certificate
- CertificateChain: Array of all certificates in chain
- ExportedCertificates: Array of certificates that were exported
- OutputDirectory: Path where files were saved (null if -NoExport)

.EXAMPLE
Export-TlsCertificates -TargetHost "google.com"

Exports all certificates from google.com:443 in both PEM and DER formats
to the .\certificates directory.

.EXAMPLE
Export-TlsCertificates -TargetHost "github.com" -WhatToExport "Intermediate" -Format "PEM"

Exports only intermediate CA certificates from github.com in PEM format.

.EXAMPLE
Export-TlsCertificates -TargetHost "example.com" -NoExport

Retrieves and displays certificate information from example.com without
saving any files.

.EXAMPLE
Export-TlsCertificates -TargetHost "internal.company.com" -TargetPort 8443 -SNIHost "api.company.com"

Connects to internal.company.com:8443 using SNI hostname api.company.com
and exports all certificates.

.EXAMPLE
$result = Export-TlsCertificates -TargetHost "microsoft.com" -OutDir "C:\temp\certs"
$result.LeafCertificate.Subject

Exports certificates to custom directory and examines the leaf certificate.

.NOTES
Requires .NET Framework with System.Net.Security.SslStream support.
Certificate validation is bypassed during retrieval to allow analysis of
invalid or self-signed certificates.

Author: jjw(@thejjw)
Last Edit: Aug 2025

.LINK
https://docs.microsoft.com/en-us/dotnet/api/system.net.security.sslstream
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetHost,
        
        [Parameter(Mandatory = $false)]
        [int]$TargetPort = 443,
        
        [Parameter(Mandatory = $false)]
        [string]$SNIHost = $TargetHost,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Root', 'Intermediate', 'Leaf', 'All')]
        [string]$WhatToExport = 'All',
        
        [Parameter(Mandatory = $false)]
        [string]$OutDir = ".\certificates",
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('PEM', 'DER', 'Both')]
        [string]$Format = 'Both',
        
        [Parameter(Mandatory = $false)]
        [switch]$NoExport
    )
    
    # --- Internal helper functions ---
    function Get-UniqueByThumbprint {
        param([System.Collections.IEnumerable] $Certificates)
        $certList = @($Certificates)
        $seen = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($cert in $certList) {
            if ($null -ne $cert -and $seen.Add($cert.Thumbprint)) { $cert }
        }
    }

    function Test-SelfSignedCertificate {
        param([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)
        return ($Certificate.Subject -eq $Certificate.Issuer)
    }

    function Get-CertificateType {
        param(
            [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
            [bool] $IsFirstInChain = $false,
            [bool] $IsLastInChain = $false
        )
        
        $isSelfSigned = Test-SelfSignedCertificate -Certificate $Certificate
        
        # Check basic constraints extension for CA status
        $isCA = $false
        foreach ($ext in $Certificate.Extensions) {
            if ($ext -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
                $isCA = $ext.CertificateAuthority
                break
            }
        }
        
        # Position-based classification takes precedence
        if ($IsFirstInChain -and -not $isSelfSigned) { return "Leaf" }
        elseif ($IsLastInChain -or $isSelfSigned) { return "Root" }
        elseif ($isCA) { return "Intermediate" }
        else { return "Leaf" }
    }
    
    Write-Host "Connecting to ${TargetHost}:${TargetPort} (SNI: ${SNIHost})"
    Write-Verbose "Target server: ${TargetHost}:${TargetPort}"
    
    # --- TLS connection and cert retrieval ---
    $tcp = $null; $ssl = $null; $leaf = $null
    try {
        Write-Verbose "Establishing TCP connection to ${TargetHost}:${TargetPort}..."
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $tcp.Connect($TargetHost, $TargetPort)
        $serverChainElements = [System.Collections.ArrayList]::new()
        $ssl = [System.Net.Security.SslStream]::new(
            $tcp.GetStream(), $false,
            { param($sender, $cert, $chain, $errors) 
                if ($chain) { foreach ($e in $chain.ChainElements) { [void]$serverChainElements.Add($e.Certificate) } }
                return $true 
            }.GetNewClosure()
        )
        $ssl.AuthenticateAsClient($SNIHost)
        $leaf = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
        Write-Verbose "Successfully retrieved server certificate from ${TargetHost}:${TargetPort}"
    }
    catch {
        throw "Failed to retrieve certificate from ${TargetHost}:${TargetPort}. $_"
    }
    finally {
        if ($ssl) { $ssl.Dispose() }
        if ($tcp) { $tcp.Dispose() }
    }

    # --- Chain building ---
    if ($serverChainElements.Count -gt 0) {
        $chainCertsRaw = $serverChainElements.ToArray()
    } else {
        $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
        $chain.ChainPolicy.RevocationMode = 'NoCheck'
        $chain.ChainPolicy.VerificationFlags = 'AllowUnknownCertificateAuthority'
        $null = $chain.Build($leaf)
        $chainCertsRaw = @($chain.ChainElements | ForEach-Object { $_.Certificate })
    }
    $elements = @(Get-UniqueByThumbprint -Certificates $chainCertsRaw)

    if (-not $elements -or $elements.Count -eq 0) {
        $elements = @($leaf)
        Write-Warning "Server did not provide a certificate chain. Using only leaf certificate."
    }

    # --- Helper functions for certificate selection ---
    function Get-RootCert { param($e) if ($e.Count -gt 0) { $e[-1] } }
    function Get-Intermediates { param($e) if ($e.Count -gt 2) { $e[1..($e.Count - 2)] } else { @() } }

    # --- Certificate selection and filtering ---
    $toExport = switch ($WhatToExport) {
        'Root' { @(Get-RootCert $elements) | Where-Object { $_ } }
        'Intermediate' { @(Get-Intermediates $elements) | Where-Object { $_ } }
        'Leaf' { @($leaf) | Where-Object { $_ } }
        'All' { $elements | Where-Object { $_ } }
    }

    if (-not $toExport -or $toExport.Count -eq 0) {
        throw "No certificates were obtained from ${TargetHost}:${TargetPort} for export type '${WhatToExport}'."
    }

    # --- File export operations ---
    if (-not $NoExport) {
        if (-not (Test-Path $OutDir)) { 
            $null = New-Item -ItemType Directory -Path $OutDir -Force
            Write-Host "Created output directory: ${OutDir}"
        }
        
        foreach ($cert in $toExport) {
            # Safe filename generation
            $safeName = New-SafeFileNameFromCertificateName -InputString $cert.Subject
            $certType = Get-CertificateType -Certificate $cert `
                -IsFirstInChain ($cert -eq $elements[0]) `
                -IsLastInChain ($cert -eq $elements[-1])
            $thumbprint = $cert.Thumbprint.Substring(0, 8)  # First 8 chars of thumbprint
            $baseFileName = "${safeName}_${certType}_${thumbprint}"
            
            # Format-specific export
            if ($Format -eq 'DER' -or $Format -eq 'Both') {
                $derPath = Join-Path $OutDir "${baseFileName}.cer"
                [IO.File]::WriteAllBytes($derPath, $cert.Export('Cert'))
                Write-Host "Exported DER: ${derPath}"
            }
            
            if ($Format -eq 'PEM' -or $Format -eq 'Both') {
                $pemPath = Join-Path $OutDir "${baseFileName}.pem"
                # Explicit CRLF line endings match what most tools (OpenSSL, certutil)
                # expect on Windows; .NET's InsertLineBreaks produces LF-only.
                $pemContent = @(
                    "-----BEGIN CERTIFICATE-----"
                    [Convert]::ToBase64String($cert.Export('Cert'), 'InsertLineBreaks')
                    "-----END CERTIFICATE-----"
                ) -join "`r`n"
                [IO.File]::WriteAllText($pemPath, $pemContent)
                Write-Host "Exported PEM: ${pemPath}"
            }
        }
        
        Write-Host "`nExported $($toExport.Count) certificate(s) to: ${OutDir}"
    }

    # --- Certificate chain summary display ---
    Write-Host "`n--- Certificate Chain Summary ---"
    Write-Host "Target server: ${TargetHost}:${TargetPort}"
    Write-Host "Leaf Certificate:"
    Write-Host "  Subject: $($leaf.Subject)"
    Write-Host "  Issuer:  $($leaf.Issuer)"
    Write-Host "  Thumbprint: $($leaf.Thumbprint)"
    Write-Host "  Valid From: $($leaf.NotBefore)"
    Write-Host "  Valid To:   $($leaf.NotAfter)"
    
    Write-Host "`nComplete Chain:"
    for ($i = 0; $i -lt $elements.Count; $i++) {
        $cert = $elements[$i]
        $type = Get-CertificateType -Certificate $cert `
            -IsFirstInChain ($i -eq 0) `
            -IsLastInChain ($i -eq $elements.Count - 1)
        $tag = if ($i -eq 0) { '[Leaf]' } elseif ($i -eq $elements.Count - 1) { '[Root]' } else { '[Intermediate]' }
        Write-Host "  ${tag} [${type}] $($cert.Subject) [$($cert.Thumbprint)]"
    }
    
    # --- Return certificate objects for further processing ---
    return [PSCustomObject]@{
        LeafCertificate      = $leaf
        CertificateChain     = $elements
        ExportedCertificates = $toExport
        OutputDirectory      = if (-not $NoExport) { $OutDir } else { $null }
        TargetHost           = $TargetHost
        TargetPort           = $TargetPort
        SNIHost              = $SNIHost
    }
}

function Lock-File {
    <#
.SYNOPSIS
Completely locks down a file by removing all explicit and inherited access rules.

.DESCRIPTION
The Lock-File function disables inheritance on the specified file and removes
all access control entries (ACEs). This leaves the file with no access rules,
effectively preventing all users (including Administrators) from accessing it
until permissions are explicitly restored.

.PARAMETER Path
The full path to the file you want to lock down.

.EXAMPLE
Lock-File -Path "C:\Path\To\Secret.txt"

Locks down the file Secret.txt so that no one has access.

.NOTES
- You may need to run PowerShell as Administrator if the file is in a protected location.
- To restore access, you must take ownership and reapply permissions manually

Author: jjw(@thejjw)
Last Edit: Sept 2025
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        Write-Error "The file '$Path' does not exist."
        return
    }

    try {
        # Get current ACL
        $acl = Get-Acl $Path

        # Disable inheritance and remove inherited rules
        $acl.SetAccessRuleProtection($true, $false)

        # Remove any explicit rules that might remain
        $acl.Access | ForEach-Object {
            $acl.RemoveAccessRule($_) | Out-Null
        }

        # Apply the stripped ACL back to the file
        Set-Acl -Path $Path -AclObject $acl

        Write-Output "File '$Path' has been locked down. Current access rules:"

        $rules = (Get-Acl $Path).Access
        if ($rules.Count -eq 0) {
            Write-Output "  [Empty: no access rules](expected result)"
        }
        else {
            $rules
            Write-Error "some access rules are detected(unexpected result)"
        }
    }
    catch {
        Write-Error "Failed to lock down file '$Path'. Error: $_"
    }
}

function Convert-VideoWithTransposeIntelQuickSync {
    <#
.SYNOPSIS
Rotates a video 90 degrees using Intel Quick Sync hardware acceleration.

.DESCRIPTION
Transposes (rotates) video files 90 degrees clockwise or counter-clockwise using Intel Quick Sync
encoding. Outputs an HEVC-encoded MKV file with AAC audio. Hardware acceleration via Intel QSV
significantly speeds up transcoding compared to software processing.

.PARAMETER InputFile
The full path to the input video file to rotate.

.PARAMETER CounterClockwise
If specified, rotates the video 90 degrees counter-clockwise. By default, rotates clockwise.

.PARAMETER Quality
HEVC quality level (0-51). Lower values mean higher quality. Defaults to 15.

.EXAMPLE
Convert-VideoWithTransposeIntelQuickSync -InputFile "C:\Videos\input.mp4"

Rotates input.mp4 90 degrees clockwise and saves as input_v.mkv.

.EXAMPLE
Convert-VideoWithTransposeIntelQuickSync -InputFile "C:\Videos\video.mov" -CounterClockwise

Rotates video.mov 90 degrees counter-clockwise and saves as video_v.mkv.

.EXAMPLE
Convert-VideoWithTransposeIntelQuickSync -InputFile "C:\Videos\video.mp4" -Quality 20

Rotates video.mp4 with quality level 20 (lower quality, faster encoding).

.NOTES
Requires ffmpeg with Intel QSV support and compatible Intel GPU hardware.
Output file is appended with "_v.mkv" suffix and saved in the same directory as the input.

Quality Presets (HEVC 0-51 scale, lower = better quality):
- 0-10:   Very high quality (slow encoding, ~0.5x speed)
- 11-18:  High quality (medium speed, ~1-2x speed) - DEFAULT RANGE (15)
- 19-28:  Medium/Normal quality (good balance, ~3-5x speed)
- 29-38:  Lower quality (fast encoding, ~5-10x speed)
- 39-51:  Very low quality (very fast, ~10x+ speed)

Quality 8 for archival/high-quality use cases
Quality 20 for balanced quality/speed
Quality 32 for fast encoding with acceptable quality loss

Author: jjw(@thejjw)
Last Edit: Mar 2026
#>
    param (
        [Parameter(Mandatory = $true)]
        [string]$InputFile,
        [switch]$CounterClockwise,
        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 51)]
        [int]$Quality = 15,
        [switch]$Enhance
    )
    # Strip backtick escapes before [ and ] (PowerShell tab-completion artifact)
    $InputFile = $InputFile -replace '`(?=[\[\]])', ''
    $ResolvedInput = (Get-Item -LiteralPath $InputFile).FullName
    # Build output filename by appending "_v.mkv"
    $BaseName = [System.IO.Path]::GetFileNameWithoutExtension($ResolvedInput)
    $Directory = [System.IO.Path]::GetDirectoryName($ResolvedInput)
    if ([string]::IsNullOrEmpty($Directory)) {
        $Directory = "."
    }
    $OutputFile = Join-Path $Directory ($BaseName + "_v.mkv")
    # QSV vpp_qsv transpose operates in the GPU's video pipeline, avoiding CPU decode/encode
    if ($CounterClockwise) {
        $Mode = "vpp_qsv=transpose=cclock"
    }
    else {
        $Mode = "vpp_qsv=transpose=clock"
    }
    # Add detail enhancement if requested
    if ($Enhance) {
        $Mode = "${Mode}:detail=30"
    }
    # Pipe input through QSV hardware pipeline: decode -> transpose -> HEVC encode
    # -hwaccel qsv and -hwaccel_output_format qsv keep frames on the GPU throughout
    $ffmpegArgs = @(
        "-hwaccel", "qsv",
        "-hwaccel_output_format", "qsv",
        "-i", $ResolvedInput,
        "-vf", $Mode,
        "-c:v", "hevc_qsv",
        "-global_quality", $Quality,
        "-c:a", "aac",
        "-b:a", "192k",
        $OutputFile
    )
    Write-Host "Running ffmpeg on $ResolvedInput..."
    & ffmpeg @ffmpegArgs
}

function New-RandomDir {
    <#
.SYNOPSIS
Creates a new directory (random name by default) and changes into it.

.DESCRIPTION
New-RandomDir creates a directory inside the specified BasePath. If -Name is
not provided, a random human-readable name is generated. The command then
changes the current location to the newly created directory.

Optional switches allow initializing a git repository with a synthetic local
identity and creating basic agent documentation files (AGENTS.md, etc).

.PARAMETER BasePath
The parent directory where the new directory will be created.
Defaults to the current location.

.PARAMETER Name
Explicit name for the directory. If omitted, a random name is generated.

.PARAMETER Git
Initializes a git repository in the new directory and configures a local
identity using the format: username@hostname.local.

.PARAMETER Agents
Creates basic AGENTS.md, CLAUDE.md, and GEMINI.md template files in the
directory.
Requires -Git.

.PARAMETER Temp
Uses the user temp directory ($env:TEMP) as the base path instead of
the current location.

.PARAMETER MaxAttempts
Maximum number of attempts when generating a random directory name.

.EXAMPLE
nrd
Creates a randomly named directory in the current location and changes into it.

.EXAMPLE
nrd -Git
Creates a random directory, initializes git, and sets a synthetic local identity.

.EXAMPLE
nrd -Name scratch-api
Creates a directory with the specified name and changes into it.

.EXAMPLE
nrd -Temp -Git
Creates a random directory under $env:TEMP, initializes git.

.EXAMPLE
nrd -Git -Agents -Verbose
Creates a random directory, initializes git, creates agent templates,
and prints verbose output.

.NOTES
Alias: nrd
Author: jjw(@thejjw)
Last Edit: 2026-04

#>
    [CmdletBinding()]
    param(
        [string]$BasePath = (Get-Location).Path,
        [string]$Name,
        [switch]$Git,
        [switch]$Agents,
        [switch]$Temp,
        [int]$MaxAttempts = 50
    )

    if ($Agents -and -not $Git) {
        throw "-Agents requires -Git."
    }

    # Override base path to user temp directory when -Temp is specified
    if ($Temp) { $BasePath = $env:TEMP }

    # Retrieve randomized elements from global internal configuration
    $colors = $_NrdInternal.Colors
    $adjectives = $_NrdInternal.Adjectives
    $nouns = $_NrdInternal.Nouns

    if (-not (Test-Path -LiteralPath $BasePath)) {
        throw "Base path does not exist: $BasePath"
    }

    $BasePath = (Resolve-Path -LiteralPath $BasePath).Path
    Write-Verbose "Base path: $BasePath"

    if (-not $Name) {
        for ($i = 1; $i -le $MaxAttempts; $i++) {
            $Name = '{0}-{1}-{2}' -f
            $colors[(Get-Random -Minimum 0 -Maximum $colors.Count)],
            $adjectives[(Get-Random -Minimum 0 -Maximum $adjectives.Count)],
            $nouns[(Get-Random -Minimum 0 -Maximum $nouns.Count)]

            $candidate = Join-Path $BasePath $Name
            Write-Verbose "Attempt ${i}: $candidate"

            if (-not (Test-Path -LiteralPath $candidate)) { break }
            $Name = $null
        }

        if (-not $Name) {
            throw "Failed to generate a unique directory name after $MaxAttempts attempts."
        }
    }

    $Path = Join-Path $BasePath $Name

    if (Test-Path -LiteralPath $Path) {
        throw "Directory already exists: $Path"
    }
    Write-Verbose "Creating directory: $Path"
    $null = New-Item -ItemType Directory -Path $Path

    if ($Git) {
        $gitCmd = Get-Command git -ErrorAction SilentlyContinue
        if (-not $gitCmd) {
            Write-Warning "git not found on PATH. Skipping git setup."
        }
        else {
            $user = $env:USERNAME
            $hostName = $env:COMPUTERNAME
            $email = '{0}@{1}.local' -f $user.ToLower(), $hostName.ToLower()

            Write-Verbose "Initializing git repository"
            & git -C $Path init | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "git init failed for: $Path"
            }

            # Confirm the repository exists before writing repository-local config.
            & git -C $Path rev-parse --is-inside-work-tree *> $null
            if ($LASTEXITCODE -ne 0) {
                throw "git init did not create a repository at: $Path"
            }

            & git -C $Path config --local user.name $user
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to set local git user.name for: $Path"
            }

            & git -C $Path config --local user.email $email
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to set local git user.email for: $Path"
            }

            Write-Host ("Git identity: {0} <{1}>" -f $user, $email)
        }
    }

    if ($Agents) {
        Write-Verbose "Creating AGENTS.md (canonical) + CLAUDE.md/GEMINI.md (@import)"

        # Write canonical AGENTS.md using the template defined in global internal configuration
        $_NrdInternal.AgentsMarkdown | Set-Content -LiteralPath (Join-Path $Path 'AGENTS.md') -Encoding UTF8

        # CLAUDE.md imports AGENTS.md -- Claude Code reads CLAUDE.md, not AGENTS.md
        '@AGENTS.md' | Set-Content -LiteralPath (Join-Path $Path 'CLAUDE.local.md') -Encoding UTF8

        # QWEN.md imports AGENTS.md -- Qwen Code reads QWEN.md, not AGENTS.md
        '@./AGENTS.md' | Set-Content -LiteralPath (Join-Path $Path 'QWEN.md') -Encoding UTF8
    }
    Write-Verbose "Changing location to: $Path"
    Set-Location -LiteralPath $Path

    Get-Item -LiteralPath $Path
}

Set-Alias nrd New-RandomDir

function Invoke-LoginAudit {
    <#
.SYNOPSIS
  Audits Windows login activity for the last N hours and writes a Markdown report.

.DESCRIPTION
  Reads the Security event log for logon-related events, summarizes them, and
  produces a human-readable Markdown file you can skim yourself and raw event
  data for further analysis. Raw event data is saved alongside as CSV so
  you can drill into specific rows.

.EXAMPLE
    Invoke-LoginAudit
    Invoke-LoginAudit -Hours 168 -OutDir C:\audits

.PARAMETER Hours
  How many hours back to look. Default 48.

.PARAMETER OutDir
  Where to write the report and CSVs. Default: cwd

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-04

    Tip: you can add the function declaration to $PROFILE then call it on future shell sessions with ease
    (note that script execution policy should allow local script execution at least, i.e. RemoteSigned)
#>
    [CmdletBinding()]
    param(
        [int]$Hours = 48,
        [string]$OutDir = (Get-Location).Path
    )

    $ErrorActionPreference = 'Stop'

    # Fail fast if not elevated - Security event log read requires admin
    $currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Invoke-LoginAudit requires an elevated PowerShell session (reading the Security event log needs Administrator rights).'
    }

    if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

    $since = (Get-Date).AddHours(-$Hours)
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $reportMd = Join-Path $OutDir "login-audit-$stamp.md"
    $successCsv = Join-Path $OutDir "4624-success-$stamp.csv"
    $failCsv = Join-Path $OutDir "4625-failed-$stamp.csv"

    $logonTypeMap = @{
        2  = 'Interactive'
        3  = 'Network'
        4  = 'Batch'
        5  = 'Service'
        7  = 'Unlock'
        8  = 'NetworkCleartext'
        9  = 'NewCredentials'
        10 = 'RemoteInteractive(RDP)'
        11 = 'CachedInteractive'
    }

    # 4625 sub-status codes -> plain English (common ones)
    $subStatusMap = @{
        '0xC0000064' = 'User does not exist'
        '0xC000006A' = 'Bad password'
        '0xC000006D' = 'Bad username or password'
        '0xC000006F' = 'Outside allowed hours'
        '0xC0000070' = 'Workstation restriction'
        '0xC0000071' = 'Password expired'
        '0xC0000072' = 'Account disabled'
        '0xC0000193' = 'Account expired'
        '0xC0000224' = 'Password must change'
        '0xC0000234' = 'Account locked out'
        '0xC000015B' = 'Logon type not granted'
    }

    function Get-Events($id) {
        try {
            Get-WinEvent -FilterHashtable @{LogName = 'Security'; Id = $id; StartTime = $since } -ErrorAction Stop
        }
        catch [System.Exception] {
            if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') { @() } else { throw }
        }
    }

    function Md-Table($rows, $columns) {
        if (-not $rows) { return "_(none)_`n" }
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine('| ' + ($columns -join ' | ') + ' |')
        [void]$sb.AppendLine('|' + (($columns | ForEach-Object { '---' }) -join '|') + '|')
        foreach ($r in $rows) {
            $cells = $columns | ForEach-Object {
                $v = $r.$_
                if ($null -eq $v -or $v -eq '') { '-' } else { ($v -replace '\|', '\|') }
            }
            [void]$sb.AppendLine('| ' + ($cells -join ' | ') + ' |')
        }
        $sb.ToString()
    }

    Write-Host "Collecting events since $since ..." -ForegroundColor Cyan

    $raw4624 = Get-Events 4624
    $raw4625 = Get-Events 4625
    $raw4634 = Get-Events 4634
    $raw4647 = Get-Events 4647
    $raw4740 = try {
        Get-WinEvent -FilterHashtable @{LogName = 'Security'; Id = 4740; StartTime = (Get-Date).AddDays(-30) } -ErrorAction Stop
    }
    catch { @() }
    $raw4800 = Get-Events 4800
    $raw4801 = Get-Events 4801

    $ok = $raw4624 | ForEach-Object {
        $lt = [int]$_.Properties[8].Value
        [PSCustomObject]@{
            Time          = $_.TimeCreated
            User          = $_.Properties[5].Value
            Domain        = $_.Properties[6].Value
            LogonType     = $lt
            LogonTypeName = $logonTypeMap[$lt]
            Workstation   = $_.Properties[11].Value
            IP            = $_.Properties[18].Value
            LogonProcess  = $_.Properties[9].Value
            AuthPackage   = $_.Properties[10].Value
            ProcessName   = $_.Properties[17].Value
        }
    }

    $fail = $raw4625 | ForEach-Object {
        $lt = [int]$_.Properties[10].Value
        $sub = ('0x{0:X}' -f [int64]$_.Properties[9].Value)
        [PSCustomObject]@{
            Time          = $_.TimeCreated
            User          = $_.Properties[5].Value
            Domain        = $_.Properties[6].Value
            LogonType     = $lt
            LogonTypeName = $logonTypeMap[$lt]
            Status        = ('0x{0:X}' -f [int64]$_.Properties[7].Value)
            SubStatus     = $sub
            Reason        = $subStatusMap[$sub]
            Workstation   = $_.Properties[13].Value
            IP            = $_.Properties[19].Value
            ProcessName   = $_.Properties[18].Value
        }
    }

    if ($ok) { $ok   | Export-Csv -NoTypeInformation -Path $successCsv }
    if ($fail) { $fail | Export-Csv -NoTypeInformation -Path $failCsv }

    # Logon types that indicate a real person at a keyboard (interactive, unlock, RDP, cached)
    $humanTypes = 2, 7, 10, 11
    $human = $ok | Where-Object { $_.LogonType -in $humanTypes }
    # Network (type 3) logons from real user accounts are worth reviewing -- these represent
    # remote access to this machine via SMB, WinRM, etc.
    $netNonSys = $ok | Where-Object {
        $_.LogonType -eq 3 -and
        $_.User -notin 'SYSTEM', 'ANONYMOUS LOGON', 'LOCAL SERVICE', 'NETWORK SERVICE' -and
        $_.IP -and $_.IP -ne '-'
    }

    # Flag non-loopback IPs on interactive/unlock events - unusual for console sign-in
    $remoteHumanFlags = $human | Where-Object { $_.IP -and $_.IP -ne '-' -and $_.IP -ne '127.0.0.1' -and $_.IP -ne '::1' }

    # Flag human logons outside business hours -- often worth investigating for compromised accounts
    $offHours = $human | Where-Object { $_.Time.Hour -lt 6 -or $_.Time.Hour -ge 22 }

    $userBreakdown = $ok | Group-Object User, LogonTypeName |
    Sort-Object Count -Descending |
    ForEach-Object {
        [PSCustomObject]@{
            Count = $_.Count
            Group = $_.Name
        }
    }

    $computer = $env:COMPUTERNAME
    $now = Get-Date
    $windowEnd = $now.ToString('yyyy-MM-dd HH:mm:ss')
    $windowStart = $since.ToString('yyyy-MM-dd HH:mm:ss')

    $md = @()
    $md += "# Login Activity Report - $computer"
    $md += ""
    $md += "- **Window:** $windowStart -> $windowEnd  (last $Hours hours)"
    $md += "- **Generated:** $now"
    $md += "- **Generated by:** ``Invoke-LoginAudit``"
    $csvRefs = @()
    if (Test-Path $successCsv) { $csvRefs += "``$successCsv``" }
    if (Test-Path $failCsv) { $csvRefs += "``$failCsv``" }
    if ($csvRefs) { $md += "- **Raw CSVs:** " + ($csvRefs -join ', ') }
    $md += ""
    $md += "## Totals"
    $md += ""
    $md += "| Event | Count | Meaning |"
    $md += "|---|---:|---|"
    $md += "| 4624 Successful logon | $($ok.Count) | All successful session creations |"
    $md += "| 4625 Failed logon | $($fail.Count) | Bad passwords / rejected auth |"
    $md += "| 4634 Logoff | $(($raw4634 | Measure-Object).Count) | Session teardowns |"
    $md += "| 4647 User-initiated logoff | $(($raw4647 | Measure-Object).Count) | Explicit sign-outs |"
    $md += "| 4740 Lockouts (last 30d) | $(($raw4740 | Measure-Object).Count) | Account lockouts |"
    $md += "| 4800 Lock | $(($raw4800 | Measure-Object).Count) | Workstation locks |"
    $md += "| 4801 Unlock | $(($raw4801 | Measure-Object).Count) | Workstation unlocks |"
    $md += ""

    $md += "## Automatic flags"
    $md += ""
    $flags = @()
    if ($fail.Count -gt 0) { $flags += "- **$($fail.Count) failed logon attempts** - see the failures table below." }
    if ((($raw4740 | Measure-Object).Count) -gt 0) { $flags += "- **Account lockouts occurred** in the last 30 days." }
    if ($remoteHumanFlags) { $flags += "- **$($remoteHumanFlags.Count) human-type logons recorded a non-loopback source IP** - unusual for a console sign-in." }
    if ($offHours) { $flags += "- **$($offHours.Count) human-type logons outside 06:00-22:00** - double-check these are yours." }
    if ($netNonSys) { $flags += "- **$($netNonSys.Count) non-SYSTEM network logons** from remote hosts - confirm each source is expected." }
    if (-not $flags) { $flags += "_No automatic flags raised. Still eyeball the tables below._" }
    $md += $flags
    $md += ""

    $md += "## Breakdown by user + logon type (4624)"
    $md += ""
    $md += (Md-Table $userBreakdown @('Count', 'Group'))

    $md += "## Human-type logons (Interactive / Unlock / RDP / CachedInteractive)"
    $md += ""
    $md += "Logon types 2, 7, 10, 11. These are the events that represent a real person signing in."
    $md += ""
    $md += (Md-Table ($human | Sort-Object Time -Descending) @('Time', 'User', 'Domain', 'LogonTypeName', 'Workstation', 'IP'))

    $md += "## Network logons from non-SYSTEM accounts (type 3)"
    $md += ""
    $md += "Remote access to this machine (SMB shares, WinRM, etc.) that used a real user credential."
    $md += ""
    $md += (Md-Table ($netNonSys | Sort-Object Time -Descending) @('Time', 'User', 'Domain', 'IP', 'Workstation'))

    $md += "## Failed logons (4625)"
    $md += ""
    $md += (Md-Table ($fail | Sort-Object Time -Descending) @('Time', 'User', 'Domain', 'LogonTypeName', 'Reason', 'SubStatus', 'IP', 'Workstation'))

    $md += "## Account lockouts (4740, last 30 days)"
    $md += ""
    $lockoutRows = $raw4740 | ForEach-Object {
        [PSCustomObject]@{
            Time           = $_.TimeCreated
            LockedAccount  = $_.Properties[0].Value
            CallerComputer = $_.Properties[1].Value
        }
    }
    $md += (Md-Table $lockoutRows @('Time', 'LockedAccount', 'CallerComputer'))

    $md += "## Logon type reference"
    $md += ""
    $md += "| Type | Name | Meaning |"
    $md += "|---:|---|---|"
    $md += "| 2 | Interactive | Signed in at the console (keyboard) |"
    $md += "| 3 | Network | Accessed a share / WinRM / remote API |"
    $md += "| 4 | Batch | Scheduled task |"
    $md += "| 5 | Service | Service account starting |"
    $md += "| 7 | Unlock | Unlocked a locked session |"
    $md += "| 8 | NetworkCleartext | Network logon with cleartext creds (!) |"
    $md += "| 9 | NewCredentials | RunAs /netonly |"
    $md += "| 10 | RemoteInteractive | RDP |"
    $md += "| 11 | CachedInteractive | Cached domain creds (offline) |"
    $md += ""

    $md += "## What to do next"
    $md += ""
    $md += "1. Skim the **Human-type logons** table - do you recognize every row?"
    $md += "2. For any flagged non-loopback IP on an interactive/unlock event, check whether an RDP / remote-management tool was running at that time."
    $md += "3. For **Network logons**, confirm each source hostname/IP is a device you own."
    $md += "4. If something looks off, run again with a longer window: ``-Hours 168`` for a week."
    $md += "5. Paste this Markdown file back to other tools for further analysis - include the raw CSVs if you want row-level drilldown."
    $md += ""

    $md -join "`r`n" | Set-Content -Encoding UTF8 -Path $reportMd

    Write-Host ""
    Write-Host "Report written: $reportMd" -ForegroundColor Green
    if (Test-Path $successCsv) { Write-Host "Success CSV:    $successCsv" } else { Write-Host "Success CSV:    (not created - no 4624 events)" -ForegroundColor DarkGray }
    if (Test-Path $failCsv) { Write-Host "Failed CSV:     $failCsv" }    else { Write-Host "Failed CSV:     (not created - no 4625 events)" -ForegroundColor DarkGray }
    Write-Host ""
    Write-Host "Open the report:" -ForegroundColor Cyan
    Write-Host "  notepad `"$reportMd`""
}

function Invoke-RebootAudit {
    <#
.SYNOPSIS
  Audits recent Windows shutdown/reboot events and writes a Markdown diagnosis.

.DESCRIPTION
  Reads System event log reboot markers, planned-shutdown records, unexpected
  shutdown records, Kernel-Power bugcheck fields, and nearby update/service
  context. Produces a short Markdown report plus raw CSV data, with search
  hints for bugcheck codes and other evidence that is useful for follow-up
  diagnosis.

.EXAMPLE
    Invoke-RebootAudit
    Invoke-RebootAudit -Hours 336 -ContextMinutes 90 -OutDir C:\audits

.PARAMETER Hours
  How many hours back to look. Default 168.

.PARAMETER ContextMinutes
  How many minutes around the current boot time to use for the main diagnosis.
  Default 60.

.PARAMETER OutDir
  Where to write the report and CSV. Default: cwd

.PARAMETER IncludeReliability
  Also query Reliability Monitor WMI records for nearby Windows failures.

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-06

    References:
    - https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs
    - https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/event-id-41-restart
    - https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2
#>
    [CmdletBinding()]
    param(
        [int]$Hours = 168,
        [int]$ContextMinutes = 60,
        [string]$OutDir = (Get-Location).Path,
        [switch]$IncludeReliability
    )

    $ErrorActionPreference = 'Stop'

    if (-not (Test-Path -LiteralPath $OutDir)) {
        New-Item -ItemType Directory -Path $OutDir | Out-Null
    }

    $since = (Get-Date).AddHours(-$Hours)
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $reportMd = Join-Path $OutDir "reboot-audit-$stamp.md"
    $eventsCsv = Join-Path $OutDir "reboot-events-$stamp.csv"
    $reliabilityCsv = Join-Path $OutDir "reboot-reliability-$stamp.csv"

    $eventNames = @{
        12   = 'OS start'
        13   = 'OS shutdown'
        19   = 'Windows Update install'
        41   = 'Kernel-Power unexpected restart'
        1001 = 'Bugcheck / WER'
        1074 = 'Planned restart/shutdown'
        6005 = 'Event Log service started'
        6006 = 'Event Log service stopped'
        6008 = 'Previous shutdown unexpected'
        6009 = 'OS version at boot'
        7045 = 'Service installed'
    }

    $bugcheckNames = @{
        '0x1A'  = 'MEMORY_MANAGEMENT'
        '0x3B'  = 'SYSTEM_SERVICE_EXCEPTION'
        '0x50'  = 'PAGE_FAULT_IN_NONPAGED_AREA'
        '0x7A'  = 'KERNEL_DATA_INPAGE_ERROR'
        '0x7B'  = 'INACCESSIBLE_BOOT_DEVICE'
        '0x7E'  = 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED'
        '0x9C'  = 'MACHINE_CHECK_EXCEPTION'
        '0xA'   = 'IRQL_NOT_LESS_OR_EQUAL'
        '0xD1'  = 'DRIVER_IRQL_NOT_LESS_OR_EQUAL'
        '0xEF'  = 'CRITICAL_PROCESS_DIED'
        '0xF4'  = 'CRITICAL_OBJECT_TERMINATION'
        '0x101' = 'CLOCK_WATCHDOG_TIMEOUT'
        '0x116' = 'VIDEO_TDR_FAILURE'
        '0x124' = 'WHEA_UNCORRECTABLE_ERROR'
        '0x133' = 'DPC_WATCHDOG_VIOLATION'
        '0x139' = 'KERNEL_SECURITY_CHECK_FAILURE'
        '0x154' = 'UNEXPECTED_STORE_EXCEPTION'
        '0x1E'  = 'KMODE_EXCEPTION_NOT_HANDLED'
        '0x1F7' = 'KERNEL_MODE_HEAP_CORRUPTION'
    }

    function Get-RebootEvents {
        param([int[]]$Ids)
        try {
            Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = $Ids; StartTime = $since } -ErrorAction Stop
        }
        catch [System.Exception] {
            if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') { @() } else { throw }
        }
    }

    function Get-EventDataMap {
        param([System.Diagnostics.Eventing.Reader.EventRecord]$Event)
        $map = @{}
        try {
            [xml]$xml = $Event.ToXml()
            foreach ($data in $xml.Event.EventData.Data) {
                $name = [string]$data.Name
                if (-not $name) { continue }
                $map[$name] = [string]$data.'#text'
            }
        }
        catch {
            return @{}
        }
        return $map
    }

    function Convert-BugcheckCode {
        param([object]$Value)
        if ($null -eq $Value -or [string]$Value -eq '') { return $null }

        $text = [string]$Value
        try {
            if ($text.StartsWith('0x', [System.StringComparison]::OrdinalIgnoreCase)) {
                $decimal = [convert]::ToInt64($text.Substring(2), 16)
            }
            else {
                $decimal = [int64]$text
            }

            return [pscustomobject]@{
                Decimal = $decimal
                Hex     = ('0x{0:X}' -f $decimal)
                Name    = $bugcheckNames[('0x{0:X}' -f $decimal)]
            }
        }
        catch {
            return [pscustomobject]@{
                Decimal = $null
                Hex     = $text
                Name    = $null
            }
        }
    }

    function Get-WerDetails {
        param([System.Diagnostics.Eventing.Reader.EventRecord]$Event)

        $code = $null
        $dump = $null
        if ($Event.Message -match '(?i)bugcheck was:\s+(0x[0-9a-f]+)') { $code = $Matches[1].ToUpperInvariant() }
        if ($Event.Message -match '(?i)dump was saved in:\s+([^\r\n]+)') { $dump = $Matches[1].Trim() }

        return [pscustomobject]@{
            BugcheckCode = $code
            DumpPath     = $dump
        }
    }

    function Format-SearchHint {
        param([string]$Query)
        if (-not $Query) { return $null }
        return "Search: $Query"
    }

    function Format-MdTable {
        param(
            [object[]]$Rows,
            [string[]]$Columns
        )
        if (-not $Rows -or $Rows.Count -eq 0) { return "_(none)_`n" }

        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine('| ' + ($Columns -join ' | ') + ' |')
        [void]$sb.AppendLine('|' + (($Columns | ForEach-Object { '---' }) -join '|') + '|')
        foreach ($row in $Rows) {
            $cells = $Columns | ForEach-Object {
                $value = $row.$_
                if ($null -eq $value -or $value -eq '') { '-' } else { ([string]$value -replace '\|', '\|') }
            }
            [void]$sb.AppendLine('| ' + ($cells -join ' | ') + ' |')
        }
        return $sb.ToString()
    }

    Write-Host "Collecting reboot events since $since ..." -ForegroundColor Cyan

    $rawEvents = Get-RebootEvents -Ids ([int[]]$eventNames.Keys)
    $lastBootSource = 'Win32_OperatingSystem.LastBootUpTime'
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $lastBoot = $os.LastBootUpTime
    }
    catch {
        $lastBootSource = 'latest System boot marker event'
        $lastBootEvent = $rawEvents |
            Where-Object { $_.Id -in 12, 6005, 6009 } |
            Sort-Object TimeCreated -Descending |
            Select-Object -First 1
        if (-not $lastBootEvent) {
            throw "Could not determine last boot time from CIM or System boot marker events: $($_.Exception.Message)"
        }
        $lastBoot = $lastBootEvent.TimeCreated
    }
    $contextStart = $lastBoot.AddMinutes(-1 * $ContextMinutes)
    $contextEnd = $lastBoot.AddMinutes($ContextMinutes)
    $events = $rawEvents | Sort-Object TimeCreated | ForEach-Object {
        $data = Get-EventDataMap $_
        $bugcheck = $null
        $bugcheckName = $null
        $powerButton = $null
        $sleepInProgress = $null
        $dumpPath = $null
        $hint = $null

        if ($_.Id -eq 41 -and $data.ContainsKey('BugcheckCode')) {
            $bugcheck = Convert-BugcheckCode $data.BugcheckCode
            $bugcheckName = $bugcheck.Name
            $powerButton = $data.PowerButtonTimestamp
            $sleepInProgress = $data.SleepInProgress
            if ($bugcheck.Decimal -and $bugcheck.Decimal -ne 0) {
                $query = if ($bugcheck.Name) { "Windows bugcheck $($bugcheck.Hex) $($bugcheck.Name)" } else { "Windows bugcheck $($bugcheck.Hex)" }
                $hint = Format-SearchHint $query
            }
        }
        elseif ($_.Id -eq 1001) {
            $wer = Get-WerDetails $_
            if ($wer.BugcheckCode) {
                $bugcheck = Convert-BugcheckCode $wer.BugcheckCode
                $bugcheckName = $bugcheck.Name
                $query = if ($bugcheck.Name) { "Windows bugcheck $($bugcheck.Hex) $($bugcheck.Name)" } else { "Windows bugcheck $($bugcheck.Hex)" }
                $hint = Format-SearchHint $query
            }
            $dumpPath = $wer.DumpPath
        }
        elseif ($_.Id -eq 1074) {
            $hint = Format-SearchHint 'Windows Event ID 1074 shutdown reason code process user'
        }
        elseif ($_.Id -eq 6008) {
            $hint = Format-SearchHint 'Windows Event ID 6008 previous shutdown was unexpected'
        }

        [pscustomobject]@{
            Time            = $_.TimeCreated
            Id              = $_.Id
            Event           = $eventNames[$_.Id]
            Provider        = $_.ProviderName
            Level           = $_.LevelDisplayName
            BugcheckCode    = if ($bugcheck) { $bugcheck.Hex } else { $null }
            BugcheckName    = $bugcheckName
            PowerButtonTime = $powerButton
            SleepInProgress = $sleepInProgress
            DumpPath        = $dumpPath
            SearchHint      = $hint
            Message         = ($_.Message -replace '\s+', ' ').Trim()
        }
    }

    if ($events) {
        $events | Export-Csv -NoTypeInformation -Path $eventsCsv
    }

    $nearBoot = @($events | Where-Object { $_.Time -ge $contextStart -and $_.Time -le $contextEnd })
    $planned = @($nearBoot | Where-Object { $_.Id -eq 1074 } | Sort-Object Time -Descending)
    $unexpected = @($nearBoot | Where-Object { $_.Id -in 41, 6008 } | Sort-Object Time -Descending)
    $bugchecks = @($nearBoot | Where-Object { $_.BugcheckCode -and $_.BugcheckCode -ne '0x0' } | Sort-Object Time -Descending)
    $werBugchecks = @($nearBoot | Where-Object { $_.Id -eq 1001 -and $_.BugcheckCode } | Sort-Object Time -Descending)
    $updateContext = @($events | Where-Object { $_.Id -in 19, 7045 -and $_.Time -ge $lastBoot.AddHours(-6) -and $_.Time -le $lastBoot } | Sort-Object Time -Descending)
    $lastKernelPower = @($nearBoot | Where-Object { $_.Id -eq 41 } | Sort-Object Time -Descending | Select-Object -First 1)
    $lastUnexpected = @($nearBoot | Where-Object { $_.Id -eq 6008 } | Sort-Object Time -Descending | Select-Object -First 1)

    $likelyType = 'Inconclusive'
    $interpretation = 'No planned shutdown, unexpected shutdown, or bugcheck marker was found near the current boot window.'
    if ($bugchecks -or $werBugchecks) {
        $likelyType = 'Unexpected reboot with bugcheck / BSOD evidence'
        $firstBugcheck = @($bugchecks + $werBugchecks | Sort-Object Time -Descending | Select-Object -First 1)[0]
        $label = if ($firstBugcheck.BugcheckName) { "$($firstBugcheck.BugcheckCode) $($firstBugcheck.BugcheckName)" } else { $firstBugcheck.BugcheckCode }
        $interpretation = "Windows recorded a non-zero bugcheck code near boot: $label."
    }
    elseif ($unexpected) {
        $likelyType = 'Unexpected reboot without captured bugcheck'
        $kp = @($lastKernelPower)[0]
        if ($kp -and $kp.PowerButtonTime -and $kp.PowerButtonTime -ne '0' -and $kp.PowerButtonTime -ne '0x0') {
            $interpretation = 'Kernel-Power recorded a power-button timestamp, so a long power-button press is plausible.'
        }
        else {
            $interpretation = 'Windows did not record a clean shutdown or a non-zero bugcheck. Suspect power loss, hard hang, reset, firmware, thermal, storage, or PSU causes.'
        }
    }
    elseif ($planned) {
        $likelyType = 'Planned restart/shutdown'
        $interpretation = 'A USER32/Event ID 1074 planned shutdown or restart event was found near the current boot.'
    }

    $reliabilityRows = @()
    if ($IncludeReliability) {
        try {
            $reliabilityRows = @(Get-CimInstance -ClassName Win32_ReliabilityRecords -ErrorAction Stop |
                ForEach-Object {
                    $time = [System.Management.ManagementDateTimeConverter]::ToDateTime($_.TimeGenerated)
                    if ($time -lt $since) { return }
                    [pscustomobject]@{
                        Time    = $time
                        Source  = $_.SourceName
                        Product = $_.ProductName
                        EventId = $_.EventIdentifier
                        Message = ($_.Message -replace '\s+', ' ').Trim()
                    }
                } |
                Sort-Object Time -Descending)

            if ($reliabilityRows) {
                $reliabilityRows | Export-Csv -NoTypeInformation -Path $reliabilityCsv
            }
        }
        catch {
            $reliabilityRows = @([pscustomobject]@{
                    Time    = Get-Date
                    Source  = 'Invoke-RebootAudit'
                    Product = 'Reliability Monitor'
                    EventId = ''
                    Message = "Reliability records unavailable: $($_.Exception.Message)"
                })
        }
    }

    $computer = $env:COMPUTERNAME
    $now = Get-Date
    $windowStart = $since.ToString('yyyy-MM-dd HH:mm:ss')
    $windowEnd = $now.ToString('yyyy-MM-dd HH:mm:ss')

    $evidence = @()
    if ($planned) { $evidence += "- Planned shutdown/restart events near boot: $($planned.Count)" }
    if ($unexpected) { $evidence += "- Unexpected shutdown/restart events near boot: $($unexpected.Count)" }
    if ($bugchecks -or $werBugchecks) {
        foreach ($row in @($bugchecks + $werBugchecks | Sort-Object Time -Descending | Select-Object -First 3)) {
            $codeLabel = if ($row.BugcheckName) { "$($row.BugcheckCode) $($row.BugcheckName)" } else { $row.BugcheckCode }
            $evidence += "- Bugcheck evidence: $codeLabel at $($row.Time)"
        }
    }
    if ($lastKernelPower) {
        $kp = @($lastKernelPower)[0]
        $evidence += "- Kernel-Power 41: BugcheckCode=$($kp.BugcheckCode), PowerButtonTimestamp=$($kp.PowerButtonTime), SleepInProgress=$($kp.SleepInProgress)"
    }
    if ($lastUnexpected) { $evidence += "- EventLog 6008 reports the previous shutdown was unexpected." }
    if (-not $evidence) { $evidence += "_No direct evidence found in the current boot context window._" }

    $hints = @()
    foreach ($row in @($nearBoot | Where-Object SearchHint | Select-Object -ExpandProperty SearchHint -Unique)) {
        $hints += "- $row"
    }
    foreach ($row in @($bugchecks + $werBugchecks | Where-Object DumpPath | Select-Object -First 3)) {
        $hints += "- Dump file to inspect with WinDbg: ``$($row.DumpPath)``"
    }
    $hints += "- Reference: Microsoft Bug Check Code Reference - https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2"
    $hints += "- Reference: Kernel-Power Event ID 41 - https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/event-id-41-restart"

    $md = @()
    $md += "# Reboot Cause Report - $computer"
    $md += ""
    $md += "- **Window:** $windowStart -> $windowEnd  (last $Hours hours)"
    $md += "- **Generated:** $now"
    $md += "- **Generated by:** ``Invoke-RebootAudit``"
    $md += "- **Last boot:** $lastBoot  ($lastBootSource)"
    $md += "- **Diagnosis context:** $($contextStart.ToString('yyyy-MM-dd HH:mm:ss')) -> $($contextEnd.ToString('yyyy-MM-dd HH:mm:ss'))"
    if (Test-Path -LiteralPath $eventsCsv) { $md += "- **Raw event CSV:** ``$eventsCsv``" }
    if (Test-Path -LiteralPath $reliabilityCsv) { $md += "- **Reliability CSV:** ``$reliabilityCsv``" }
    $md += ""
    $md += "## Likely cause"
    $md += ""
    $md += "- **Type:** $likelyType"
    $md += "- **Interpretation:** $interpretation"
    $md += ""
    $md += "## Evidence"
    $md += ""
    $md += $evidence
    $md += ""
    $md += "## Search hints"
    $md += ""
    $md += ($hints | Select-Object -Unique)
    $md += ""
    $md += "## Events around current boot"
    $md += ""
    $md += (Format-MdTable ($nearBoot | Sort-Object Time -Descending | Select-Object Time, Id, Event, Provider, BugcheckCode, BugcheckName, PowerButtonTime, SearchHint) @('Time', 'Id', 'Event', 'Provider', 'BugcheckCode', 'BugcheckName', 'PowerButtonTime', 'SearchHint'))
    $md += "## Planned shutdown/restart records"
    $md += ""
    $md += (Format-MdTable ($planned | Select-Object Time, Id, Event, Provider, Message) @('Time', 'Id', 'Event', 'Provider', 'Message'))
    $md += "## Nearby update/service context"
    $md += ""
    $md += (Format-MdTable ($updateContext | Select-Object Time, Id, Event, Provider, Message) @('Time', 'Id', 'Event', 'Provider', 'Message'))
    if ($IncludeReliability) {
        $md += "## Reliability Monitor records"
        $md += ""
        $md += (Format-MdTable ($reliabilityRows | Select-Object -First 30) @('Time', 'Source', 'Product', 'EventId', 'Message'))
    }
    $md += "## What to do next"
    $md += ""
    $md += "1. If a bugcheck code is listed, search the exact code plus the bugcheck name and inspect the dump path with WinDbg."
    $md += "2. If Kernel-Power 41 has BugcheckCode 0 and PowerButtonTimestamp 0, prioritize power loss, hard hang, thermal, firmware, PSU, and storage checks."
    $md += "3. If Event ID 1074 is present, inspect the process/user in the planned shutdown table to see what initiated the restart."
    $md += "4. If update or service-install events appear shortly before the reboot, correlate those packages or drivers with the failure time."
    $md += "5. Run with ``-IncludeReliability`` for Reliability Monitor records, or extend the range with ``-Hours 336``."
    $md += ""

    $md -join "`r`n" | Set-Content -Encoding UTF8 -Path $reportMd

    Write-Host ""
    Write-Host "Likely type: $likelyType" -ForegroundColor Yellow
    Write-Host "Last boot:   $lastBoot"
    Write-Host "Report:      $reportMd" -ForegroundColor Green
    if (Test-Path -LiteralPath $eventsCsv) { Write-Host "Events CSV:  $eventsCsv" }
    if (Test-Path -LiteralPath $reliabilityCsv) { Write-Host "Reliability: $reliabilityCsv" }
    Write-Host ""
    Write-Host "Open the report:" -ForegroundColor Cyan
    Write-Host "  notepad `"$reportMd`""

    [pscustomobject]@{
        LastBoot       = $lastBoot
        LikelyType     = $likelyType
        Interpretation = $interpretation
        ReportPath     = $reportMd
        EventsCsv      = if (Test-Path -LiteralPath $eventsCsv) { $eventsCsv } else { $null }
    }
}

function Install-GlobalClaudeMd {
    <#
.SYNOPSIS
    Creates the global ~/.claude/CLAUDE.md with multi-model MCP tool preferences.

.DESCRIPTION
    Idempotent - skips creation if the file already exists.
    Shared by all Claude Code provider setup functions (claudez, claudemm, etc.).

.EXAMPLE
    Install-GlobalClaudeMd

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-05
#>
    [CmdletBinding()]
    param()

    $claudeDir = Join-Path $HOME '.claude'
    $globalMd = Join-Path $claudeDir 'CLAUDE.md'
    # Retrieve template from internal configuration
    $prefText = $_ClaudeInternal.GlobalClaudeMd

    if (-not (Test-Path -LiteralPath $claudeDir)) {
        $null = New-Item -ItemType Directory -Path $claudeDir -Force
    }

    if (Test-Path -LiteralPath $globalMd) {
        Write-Host "global CLAUDE.md: $globalMd already exists -- skipping"
        Write-Verbose 'global CLAUDE.md: edit it manually to include multi-model MCP preferences'
    }
    else {
        Set-Content -LiteralPath $globalMd -Value $prefText -Encoding UTF8
        Write-Host "global CLAUDE.md: created $globalMd" -ForegroundColor Green
    }
}

function Install-GlobalClaudeSettings {
    <#
.SYNOPSIS
    Ensures ~/.claude/settings.json has attribution disabled (no Co-Authored-By).

.DESCRIPTION
    One-shot: after successful update, drops a sentinel file (.claude/.no_attribution)
    so subsequent calls skip immediately. Uses native PowerShell JSON handling (no jq).
    Shared by all Claude Code provider setup functions (claudez, claudemm, etc.).

.EXAMPLE
    Install-GlobalClaudeSettings

.EXAMPLE
    Install-GlobalClaudeSettings -Force

.PARAMETER Force
    Bypass the sentinel check and reapply settings even if setup was previously completed.

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-06
#>
    [CmdletBinding()]
    param(
        [switch]$Force
    )

    $claudeDir = Join-Path $HOME '.claude'
    $claudeBinDir = Join-Path $claudeDir 'bin'
    $sentinel = Join-Path $claudeDir '.config_setup_done'

    if ((Test-Path -LiteralPath $sentinel) -and -not $Force) {
        Write-Host "claude: global config setup already done -- skipping"
        return
    }

    if (-not (Test-Path -LiteralPath $claudeBinDir)) {
        $null = New-Item -ItemType Directory -Path $claudeBinDir -Force
    }

    $targetStatusLine = Join-Path $claudeBinDir 'cc_statusline.sh'

    try {
        Invoke-RestMethod -Uri $_AiToolsInternal.Urls.CcStatusline -OutFile $targetStatusLine
    } catch {
        Write-Warning "claude: download failure caused setup to stop ($($_)). Please check internet availability and run the command again."
        return
    }

    $settingsJson = Join-Path $claudeDir 'settings.json'

    if (Test-Path -LiteralPath $settingsJson) {
        $settings = Get-Content -LiteralPath $settingsJson -Raw | ConvertFrom-Json
    }
    else {
        $settings = [pscustomobject]@{}
    }

    $settings | Add-Member -NotePropertyName 'attribution' -NotePropertyValue ([pscustomobject]@{ commit = ''; pr = ''; sessionUrl = $false }) -Force

    # Prefer PowerShell tool over Bash on Windows
    $settings | Add-Member -NotePropertyName 'env' -NotePropertyValue ([pscustomobject]@{ CLAUDE_CODE_USE_POWERSHELL_TOOL = '1' }) -Force

    if (Test-Path -LiteralPath $targetStatusLine) {
        # On Windows, .sh files are not directly executable; locate Git bash and
        # write a .cmd wrapper so Claude Code can invoke the script without PATH issues.
        $bashExe = $null
        foreach ($candidate in @('C:\Program Files\Git\bin\bash.exe', 'C:\Program Files\Git\usr\bin\bash.exe')) {
            if (Test-Path $candidate) { $bashExe = $candidate; break }
        }
        if (-not $bashExe) {
            $bashCmd = Get-Command bash.exe -ErrorAction SilentlyContinue
            if ($bashCmd) { $bashExe = $bashCmd.Source }
        }

        if ($bashExe) {
            $wrapperPath = Join-Path $claudeBinDir 'statusline.cmd'
            $wrapperContent = "@echo off`r`n`"$bashExe`" `"$targetStatusLine`"`r`n"
            [IO.File]::WriteAllText($wrapperPath, $wrapperContent, [Text.Encoding]::ASCII)
            $statusLineCommand = $wrapperPath -replace '\\', '/'
        } else {
            # No bash found; fall back to raw .sh (may not work on Windows)
            $statusLineCommand = $targetStatusLine -replace '\\', '/'
            Write-Warning "claude: bash.exe not found; statusline may not work. Install Git for Windows and re-run."
        }
        $settings | Add-Member -NotePropertyName 'statusLine' -NotePropertyValue ([pscustomobject]@{ type = 'command'; command = $statusLineCommand; refreshInterval = 2 }) -Force
    }

    [IO.File]::WriteAllText($settingsJson, ($settings | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
    $null = New-Item -ItemType File -Path $sentinel -Force
    Write-Host "claude: config setup complete" -ForegroundColor Green
}

function Install-AgySettings {
    <#
.SYNOPSIS
    Configures the Antigravity CLI status line and safe tool permissions.

.DESCRIPTION
    Ensures ~/.gemini/antigravity-cli/settings.json has the custom status line
    and managed read, web, and read-only Git permissions configured. Existing
    unrelated permission rules and settings are preserved.

.PARAMETER Force
    Bypass the sentinel check and reapply settings even if setup was previously completed.
#>
    [CmdletBinding()]
    param(
        [switch]$Force
    )

    $agyDir = Join-Path $HOME '.gemini\antigravity-cli'
    $agyBinDir = Join-Path $agyDir 'bin'
    $sentinel = Join-Path $agyDir '.config_setup_done'

    if ((Test-Path -LiteralPath $sentinel) -and -not $Force) {
        Write-Host "agy: config setup already done -- skipping"
        return
    }

    if (-not (Test-Path -LiteralPath $agyBinDir)) {
        $null = New-Item -ItemType Directory -Path $agyBinDir -Force
    }

    $targetStatusLine = Join-Path $agyBinDir 'agy_statusline.ps1'

    try {
        Invoke-RestMethod -Uri $_AiToolsInternal.Urls.AgyStatusline -OutFile $targetStatusLine
    } catch {
        if (-not (Test-Path -LiteralPath $targetStatusLine)) {
            Write-Warning "agy: download failure caused setup to stop ($($_)). Please check internet availability and run the command again."
            return
        }
        Write-Warning "agy: unable to update agy_statusline.ps1 script ($($_)), using existing file."
    }

    $settingsJson = Join-Path $agyDir 'settings.json'

    if (Test-Path -LiteralPath $settingsJson) {
        $settings = Get-Content -LiteralPath $settingsJson -Raw | ConvertFrom-Json
    }
    else {
        $settings = [pscustomobject]@{}
    }

    # Use the current Antigravity permission resource names. Migrate only the
    # legacy Git rules managed here, preserving every unrelated user rule.
    $managedPermissionAllow = @(
        'read_file(*)',
        'read_url(*)',
        'command(git status)',
        'command(git log)',
        'command(git diff)'
    )
    $permissionsProperty = $settings.PSObject.Properties['permissions']
    if ($permissionsProperty -and $settings.permissions -isnot [pscustomobject]) {
        Write-Warning 'agy: permissions must be a JSON object; settings were not changed.'
        return
    }
    if ($permissionsProperty) {
        $permissions = $settings.permissions
    }
    else {
        $permissions = [pscustomobject]@{
            allow = [object[]]@()
            ask   = [object[]]@()
            deny  = [object[]]@()
        }
        $settings | Add-Member -NotePropertyName 'permissions' -NotePropertyValue $permissions -Force
    }

    $mergedAllow = @()
    foreach ($rule in @($permissions.allow)) {
        $normalizedRule = switch -CaseSensitive ([string]$rule) {
            'command(git status*)' { 'command(git status)'; break }
            'command(git log*)' { 'command(git log)'; break }
            'command(git diff*)' { 'command(git diff)'; break }
            default { $rule }
        }
        if ($mergedAllow -cnotcontains $normalizedRule) {
            $mergedAllow += $normalizedRule
        }
    }
    foreach ($rule in $managedPermissionAllow) {
        if ($mergedAllow -cnotcontains $rule) {
            $mergedAllow += $rule
        }
    }
    $permissions | Add-Member -NotePropertyName 'allow' -NotePropertyValue ([object[]]@($mergedAllow)) -Force
    foreach ($permissionList in @('ask', 'deny')) {
        if (-not $permissions.PSObject.Properties[$permissionList]) {
            $permissions | Add-Member -NotePropertyName $permissionList -NotePropertyValue ([object[]]@())
        }
    }

    if (Test-Path -LiteralPath $targetStatusLine) {
        # Create a .cmd wrapper to bypass Go's space-tokenization/quoting bugs on Windows
        $cmdWrapperPath = Join-Path $agyBinDir 'agy_statusline.cmd'
        $cmdWrapperContent = "@echo off`r`npowershell -NoProfile -ExecutionPolicy Bypass -File `"%~dp0agy_statusline.ps1`"`r`n"
        [IO.File]::WriteAllText($cmdWrapperPath, $cmdWrapperContent, [Text.Encoding]::ASCII)

        $statusLineCommand = $cmdWrapperPath -replace '\\', '/'
        $settings | Add-Member -NotePropertyName 'statusLine' -NotePropertyValue ([pscustomobject]@{ type = 'command'; command = $statusLineCommand }) -Force
    }

    # Set-Content -Encoding UTF8 writes a BOM in WinPS 5.1; use WriteAllText
    # with an explicit no-BOM encoder so JSON parsers don't choke on it.
    [IO.File]::WriteAllText($settingsJson, ($settings | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
    $null = New-Item -ItemType File -Path $sentinel -Force
    Write-Host "agy: config setup complete" -ForegroundColor Green
}

function Install-CodexSettings {
    <#
.SYNOPSIS
    Ensures ~/.codex/config.toml has the custom status line array and no attribution.

.PARAMETER Force
    Bypass the sentinel check and reapply settings even if setup was previously completed.
#>
    [CmdletBinding()]
    param(
        [switch]$Force
    )

    $codexDir = Join-Path $HOME '.codex'
    $sentinel = Join-Path $codexDir '.config_setup_done'

    if (-not (Test-Path -LiteralPath $codexDir)) {
        $null = New-Item -ItemType Directory -Path $codexDir -Force
    }

    $sentinelExists = Test-Path -LiteralPath $sentinel
    if ($sentinelExists -and -not $Force) {
        Write-Host "codex: config setup already done -- skipping"
        return
    }

    $configToml = Join-Path $codexDir 'config.toml'
    if (-not (Test-Path -LiteralPath $configToml)) {
        New-Item -ItemType File -Path $configToml -Force | Out-Null
    }

    $content = Get-Content -LiteralPath $configToml -Raw
    $newline = if ($content -match "`r`n") { "`r`n" } else { "`n" }
    $lines = if ([string]::IsNullOrEmpty($content)) {
        [string[]]@()
    }
    else {
        [string[]]($content -split "`r?`n")
    }

    $statusLineBlock = [string[]]@(
        'status_line = ['
        '    "model-with-reasoning",'
        '    "git-branch",'
        '    "current-dir",'
        '    "context-used",'
        '    "total-output-tokens",'
        '    "five-hour-limit",'
        '    "weekly-limit",'
        '    "fast-mode"'
        ']'
    )

    $updated = [System.Collections.Generic.List[string]]::new()
    foreach ($line in $lines) {
        if ($line -notmatch '^\s*commit_attribution\s*=') {
            $updated.Add($line)
        }
    }

    while ($updated.Count -gt 0 -and [string]::IsNullOrWhiteSpace($updated[0])) {
        $updated.RemoveAt(0)
    }
    $updated.Insert(0, '')
    $updated.Insert(0, 'commit_attribution = ""')

    $tuiStart = -1
    for ($i = 0; $i -lt $updated.Count; $i++) {
        if ($updated[$i] -match '^\s*\[tui\]\s*(?:#.*)?$') {
            $tuiStart = $i
            break
        }
    }

    if ($tuiStart -lt 0) {
        while ($updated.Count -gt 0 -and [string]::IsNullOrWhiteSpace($updated[$updated.Count - 1])) {
            $updated.RemoveAt($updated.Count - 1)
        }
        if ($updated.Count -gt 0) {
            $updated.Add('')
        }
        $updated.Add('[tui]')
        foreach ($line in $statusLineBlock) {
            $updated.Add($line)
        }
    }
    else {
        $tuiEnd = $updated.Count
        for ($i = $tuiStart + 1; $i -lt $updated.Count; $i++) {
            if ($updated[$i] -match '^\s*\[') {
                $tuiEnd = $i
                break
            }
        }

        for ($i = $tuiStart + 1; $i -lt $tuiEnd; $i++) {
            if ($updated[$i] -match '^\s*status_line\s*=') {
                $arrayDepth = 0
                $removeEnd = $i
                do {
                    $arrayDepth += ([regex]::Matches($updated[$removeEnd], '\[')).Count
                    $arrayDepth -= ([regex]::Matches($updated[$removeEnd], '\]')).Count
                    $removeEnd++
                } while ($removeEnd -lt $tuiEnd -and $arrayDepth -gt 0)

                $updated.RemoveRange($i, $removeEnd - $i)
                $tuiEnd -= ($removeEnd - $i)
                break
            }
        }

        $updated.InsertRange($tuiStart + 1, $statusLineBlock)
    }

    [IO.File]::WriteAllText($configToml, (($updated -join $newline).TrimEnd() + $newline), [Text.UTF8Encoding]::new($false))
    if ($sentinelExists -and $Force) {
        Write-Host "codex: config setup sentinel exists -- reapplied due to -Force" -ForegroundColor Yellow
    }
    Write-Host "codex: statusline preset configured"

    $null = New-Item -ItemType File -Path $sentinel -Force
    Write-Host "codex: config setup complete" -ForegroundColor Green
}

function Install-KimiSettings {
    <#
.SYNOPSIS
    Configures user-level defaults for Kimi Code CLI.

.DESCRIPTION
    Disables anonymous telemetry persistently for the current user and immediately
    for the current PowerShell process.
#>
    [CmdletBinding()]
    param()

    [Environment]::SetEnvironmentVariable('KIMI_DISABLE_TELEMETRY', '1', 'User')
    $env:KIMI_DISABLE_TELEMETRY = '1'
    Write-Host "kimi: telemetry disabled for the current user" -ForegroundColor Green
}

function Install-QwenSettings {
    <#
.SYNOPSIS
    Configures user-level privacy defaults for Qwen Code.

.DESCRIPTION
    Creates or updates ~/.qwen/settings.json while preserving unrelated settings.
    Disables usage statistics, user feedback prompts, and telemetry. After a
    successful update, creates a sentinel so later calls skip configuration.

.PARAMETER Force
    Bypass the sentinel check and reapply the settings.

.NOTES
    Settings reference (review when updating these defaults):
    https://qwenlm.github.io/qwen-code-docs/en/users/configuration/settings/
#>
    [CmdletBinding()]
    param(
        [switch]$Force
    )

    $qwenDir = Join-Path $HOME '.qwen'
    $settingsJson = Join-Path $qwenDir 'settings.json'
    $sentinel = Join-Path $qwenDir '.config_setup_done'

    if ((Test-Path -LiteralPath $sentinel) -and -not $Force) {
        Write-Host "qwen: config setup already done -- skipping"
        return
    }

    if (-not (Test-Path -LiteralPath $qwenDir)) {
        $null = New-Item -ItemType Directory -Path $qwenDir -Force
    }

    if (Test-Path -LiteralPath $settingsJson) {
        try {
            $settings = Get-Content -LiteralPath $settingsJson -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            throw "qwen: unable to parse settings file '$settingsJson': $($_.Exception.Message)"
        }
    }
    else {
        $settings = [pscustomobject]@{}
    }

    if ($null -eq $settings -or $settings -isnot [pscustomobject]) {
        throw "qwen: settings file '$settingsJson' must contain a JSON object."
    }

    foreach ($sectionName in @('privacy', 'ui', 'telemetry')) {
        $section = $settings.PSObject.Properties[$sectionName]
        if ($null -eq $section -or $null -eq $section.Value -or $section.Value -isnot [pscustomobject]) {
            $settings | Add-Member -NotePropertyName $sectionName -NotePropertyValue ([pscustomobject]@{}) -Force
        }
    }

    $settings.privacy | Add-Member -NotePropertyName 'usageStatisticsEnabled' -NotePropertyValue $false -Force
    $settings.ui | Add-Member -NotePropertyName 'enableUserFeedback' -NotePropertyValue $false -Force
    $settings.telemetry | Add-Member -NotePropertyName 'enabled' -NotePropertyValue $false -Force

    [IO.File]::WriteAllText($settingsJson, ($settings | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
    $null = New-Item -ItemType File -Path $sentinel -Force
    Write-Host "qwen: privacy and telemetry settings configured" -ForegroundColor Green
}

function Install-GrokSettings {
    <#
.SYNOPSIS
    Configures Grok CLI settings, disabling telemetry, feedback, and trace uploads.

.PARAMETER Force
    Bypass the sentinel check and reapply settings even if setup was previously completed.
#>
    [CmdletBinding()]
    param(
        [switch]$Force
    )

    $grokDir = Join-Path $HOME '.grok'
    $sentinel = Join-Path $grokDir '.config_setup_done'

    if (-not (Test-Path -LiteralPath $grokDir)) {
        $null = New-Item -ItemType Directory -Path $grokDir -Force
    }

    $sentinelExists = Test-Path -LiteralPath $sentinel
    if ($sentinelExists -and -not $Force) {
        Write-Host "grok: config setup already done -- skipping"
        return
    }

    # Set user environment variables persistently
    $envVars = @{
        'GROK_TELEMETRY_ENABLED' = 'false'
        'GROK_FEEDBACK_ENABLED'  = 'false'
        'GROK_TRACE_UPLOAD'      = 'false'
    }

    foreach ($key in $envVars.Keys) {
        $val = $envVars[$key]
        [Environment]::SetEnvironmentVariable($key, $val, 'Process')
        [Environment]::SetEnvironmentVariable($key, $val, 'User')
        Write-Host "grok: env var $key set to $val" -ForegroundColor Gray
    }

    # Configure ~/.grok/config.toml
    $configToml = Join-Path $grokDir 'config.toml'
    if (-not (Test-Path -LiteralPath $configToml)) {
        New-Item -ItemType File -Path $configToml -Force | Out-Null
    }

    $content = Get-Content -LiteralPath $configToml -Raw
    $newline = if ($content -match "`r`n") { "`r`n" } else { "`n" }
    
    $lines = if ([string]::IsNullOrEmpty($content)) {
        [string[]]@()
    } else {
        [string[]]($content -split "`r?`n")
    }

    $updated = [System.Collections.Generic.List[string]]::new()
    $hasFeaturesSection = $false
    $hasTelemetrySection = $false

    $currentSection = ""
    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if ($trimmed -match '^\[\s*([a-zA-Z0-9_\.-]+)\s*\]$') {
            $currentSection = $Matches[1]
            $updated.Add($line)
            if ($currentSection -eq 'features') { $hasFeaturesSection = $true }
            if ($currentSection -eq 'telemetry') { $hasTelemetrySection = $true }
        }
        else {
            if ($currentSection -eq 'features' -and $trimmed -match '^(telemetry|feedback)\s*=') {
                continue
            }
            if ($currentSection -eq 'telemetry' -and $trimmed -match '^trace_upload\s*=') {
                continue
            }
            $updated.Add($line)
        }
    }

    if ($hasFeaturesSection) {
        $idx = -1
        for ($i = 0; $i -lt $updated.Count; $i++) {
            if ($updated[$i].Trim() -match '^\[\s*features\s*\]$') {
                $idx = $i
                break
            }
        }
        $updated.Insert($idx + 1, 'feedback = false')
        $updated.Insert($idx + 1, 'telemetry = false')
    } else {
        if ($updated.Count -gt 0 -and $updated[$updated.Count - 1].Trim() -ne "") {
            $updated.Add("")
        }
        $updated.Add("[features]")
        $updated.Add("telemetry = false")
        $updated.Add("feedback = false")
    }

    if ($hasTelemetrySection) {
        $idx = -1
        for ($i = 0; $i -lt $updated.Count; $i++) {
            if ($updated[$i].Trim() -match '^\[\s*telemetry\s*\]$') {
                $idx = $i
                break
            }
        }
        $updated.Insert($idx + 1, 'trace_upload = false')
    } else {
        if ($updated.Count -gt 0 -and $updated[$updated.Count - 1].Trim() -ne "") {
            $updated.Add("")
        }
        $updated.Add("[telemetry]")
        $updated.Add("trace_upload = false")
    }

    [IO.File]::WriteAllText($configToml, (($updated -join $newline).TrimEnd() + $newline), [Text.UTF8Encoding]::new($false))
    Write-Host "grok: configuration file ($configToml) updated" -ForegroundColor Green

    $null = New-Item -ItemType File -Path $sentinel -Force
    Write-Host "grok: config setup complete" -ForegroundColor Green
}

function Install-ClaudezSetup {
    <#
.SYNOPSIS
    Configures claudez MCP servers for Z.AI.

.DESCRIPTION
    Configures claude MCP servers for Z.AI.
    Uses a flag file under ~/.claude to skip duplicate MCP setup runs unless -Force is specified.

.PARAMETER Token
    Z.AI API token used for MCP server configuration.

.PARAMETER Force
    Re-runs MCP setup even if the setup flag already exists.

.EXAMPLE
    Install-ClaudezSetup -Token "<token>"

.EXAMPLE
    Install-ClaudezSetup -Token "<token>" -Force

.NOTES
    for delete/cleanup of existing MCP servers (if you want to start fresh):
    claude mcp list | ForEach-Object {
        $name = ($_ -split ':')[0].Trim()
        if ($name) { claude mcp remove $name }
    }

    Author: jjw(@thejjw)
    Last Edit: 2026-04
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Token,
        [switch]$Force
    )

    $claudeDir = Join-Path $HOME '.claude'
    $setupFlag = Join-Path $claudeDir '.claudez_setup_complete'

    $claudeCmd = Get-Command claude -ErrorAction SilentlyContinue
    if ($null -eq $claudeCmd) {
        Write-Host 'WARNING: claude CLI not found, skipping MCP server configuration' -ForegroundColor Yellow
        return $false
    }

    if ((Test-Path -LiteralPath $setupFlag) -and -not $Force) {
        Write-Host "claudez: MCP setup already completed (flag: $setupFlag) -- skipping"
        Write-Host 'claudez: use Install-ClaudezSetup -Force to reconfigure MCP servers' -ForegroundColor DarkGray
        return $true
    }

    Write-Host "claudez: configuring MCP servers..." -ForegroundColor Cyan

    # Check-before-add pattern: 'claude mcp list' is slow but idempotent; avoids duplicate entries
    # web-search-prime
    # https://docs.z.ai/devpack/mcp/search-mcp-server
    if (& claude mcp list | Select-String -Pattern 'web-search-prime' -Quiet) {
        Write-Host "claudez: web-search-prime already exists -- skipping" -ForegroundColor DarkGray
    }
    else {
        & claude mcp add -s user -t http web-search-prime https://api.z.ai/api/mcp/web_search_prime/mcp --header "Authorization: Bearer $Token" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "claudez: added web-search-prime" -ForegroundColor Green
        }
        else {
            Write-Warning "claudez: failed to add web-search-prime"
        }
    }

    # web-reader
    # https://docs.z.ai/devpack/mcp/reader-mcp-server
    if (& claude mcp list | Select-String -Pattern 'web-reader' -Quiet) {
        Write-Host "claudez: web-reader already exists -- skipping" -ForegroundColor DarkGray
    }
    else {
        & claude mcp add -s user -t http web-reader https://api.z.ai/api/mcp/web_reader/mcp --header "Authorization: Bearer $Token" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "claudez: added web-reader" -ForegroundColor Green
        }
        else {
            Write-Warning "claudez: failed to add web-reader"
        }
    }

    # zread
    # https://docs.z.ai/devpack/mcp/zread-mcp-server
    if (& claude mcp list | Select-String -Pattern 'zread' -Quiet) {
        Write-Host "claudez: zread already exists -- skipping" -ForegroundColor DarkGray
    }
    else {
        & claude mcp add -s user -t http zread https://api.z.ai/api/mcp/zread/mcp --header "Authorization: Bearer $Token" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "claudez: added zread" -ForegroundColor Green
        }
        else {
            Write-Warning "claudez: failed to add zread"
        }
    }

    # zai-mcp-server runs locally via npx (stdio transport), unlike the HTTP-based servers above
    # zai-mcp-server
    # https://docs.z.ai/devpack/mcp/vision-mcp-server
    if (& claude mcp list | Select-String -Pattern 'zai-mcp-server' -Quiet) {
        Write-Host "claudez: zai-mcp-server already exists -- skipping" -ForegroundColor DarkGray
    }
    else {
        & claude mcp add -s user zai-mcp-server --env Z_AI_API_KEY=$Token Z_AI_MODE=ZAI -- cmd /c npx -y "@z_ai/mcp-server" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "claudez: added zai-mcp-server" -ForegroundColor Green
        }
        else {
            Write-Warning "claudez: failed to add zai-mcp-server"
        }
    }

    # Write a sentinel flag with metadata so future runs can detect and skip re-setup
    $flagInfo = @(
        "configuredAt=$(Get-Date -Format o)",
        "user=$env:USERNAME",
        'mode=ZAI'
    ) -join "`r`n"
    Set-Content -LiteralPath $setupFlag -Value $flagInfo -Encoding UTF8
    Write-Host 'claudez: MCP setup complete' -ForegroundColor Green
    return $true
}

function Save-ProcessEnvVars {
    <#
.SYNOPSIS
    Snapshot process-scope environment variables so they can be restored later.

.DESCRIPTION
    Returns an ordered hashtable mapping each name to its current process-scope
    value (or $null when unset). Pass the result to Restore-ProcessEnvVars in a
    finally block to undo any temporary overrides cleanly.

.PARAMETER Names
    The environment variable names to capture.
#>
    param([Parameter(Mandatory)][string[]]$Names)

    $saved = [ordered]@{}
    foreach ($n in $Names) {
        $saved[$n] = [Environment]::GetEnvironmentVariable($n, 'Process')
    }
    return $saved
}

function Restore-ProcessEnvVars {
    <#
.SYNOPSIS
    Restore environment variables captured by Save-ProcessEnvVars.

.DESCRIPTION
    Re-applies each saved value, or removes the variable entirely when it was
    unset at snapshot time, leaving the process environment as it was found.

.PARAMETER Saved
    The hashtable produced by Save-ProcessEnvVars.
#>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Saved)

    foreach ($n in $Saved.Keys) {
        if ($null -eq $Saved[$n]) {
            Remove-Item "Env:\$n" -ErrorAction SilentlyContinue
        } else {
            [Environment]::SetEnvironmentVariable($n, $Saved[$n], 'Process')
        }
    }
}

# Briefly warn when Z.AI's UTC+8 peak window is active.
# Peak-hours and quota policy: https://docs.z.ai/devpack/overview
function Show-ZaiPeakWarning {
    param(
        [DateTime]$UtcNow = [DateTime]::UtcNow,
        [int]$DelaySeconds = 3
    )

    $UtcNow = $UtcNow.ToUniversalTime()
    if ($UtcNow.DayOfWeek -in [DayOfWeek]::Saturday, [DayOfWeek]::Sunday) {
        return
    }

    $peakStart = $UtcNow.Date.AddHours(6)
    $peakEnd = $UtcNow.Date.AddHours(10)
    if ($UtcNow -lt $peakStart -or $UtcNow -ge $peakEnd) {
        return
    }

    # Ceiling preserves a visible final minute until the peak window ends.
    $minutesLeft = [int][Math]::Ceiling(($peakEnd - $UtcNow).TotalMinutes)
    Write-Host ("Z.AI peak hours are active (14:00-18:00 UTC+8, Mon-Fri); ends in {0}h {1}m. Launching in 3 seconds..." -f [int][Math]::Floor($minutesLeft / 60), ($minutesLeft % 60)) -ForegroundColor Yellow
    Start-Sleep -Seconds $DelaySeconds
}

function claudez {
    <#
.SYNOPSIS
    Launches Claude Code through the Z.AI-backed profile helper.

.DESCRIPTION
    Reads the Z.AI API key from the ZAI_API_KEY environment variable
    (current session first, then User scope), runs one-time claudez setup,
    configures runtime environment, then invokes claude with the supplied arguments.
    If ZAI_API_KEY is not set, the function aborts and prints setup guidance.
    about supported models:
        "All plans support GLM-5.3, GLM-5-Turbo, and GLM-4.7." (https://docs.z.ai/devpack/overview)
        See https://docs.z.ai/devpack/latest-model for the current lineup.
    about 1M context:
        GLM-5.3 supports a 1M context window (request via the [1m] suffix on the model name, e.g. glm-5.3[1m]).
        Z.AI also requires CLAUDE_CODE_AUTO_COMPACT_WINDOW=1000000 to actually exercise the 1M window
        (this profile sets it for you). Other GLM models cap at 200K (GLM-5-Turbo, GLM-4.7) or 128K (GLM-4.5-Air).

.EXAMPLE
    claudez

.EXAMPLE
    claudez "Explain the current repository"

.EXAMPLE
    [Environment]::SetEnvironmentVariable('ZAI_API_KEY', '<your_token>', 'User')
    # Restart PowerShell, then run:
    claudez

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-08
#>
    # Read token using Get-AiApiKey helper (process first, then Credential Manager, then legacy User env)
    $token = Get-AiApiKey 'ZAI_API_KEY'

    if (-not $token) {
        Write-Host "ZAI_API_KEY is not set. Aborting." -ForegroundColor Red
        Write-Host ""
        Write-Host "Please set it securely using: Set-AiApiKeysCS" -ForegroundColor Yellow
        return
    }

    $originalEnvVars = Save-ProcessEnvVars @(
        'ANTHROPIC_BASE_URL', 'ANTHROPIC_AUTH_TOKEN', 'API_TIMEOUT_MS',
        'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC', 'CLAUDE_CODE_AUTO_COMPACT_WINDOW',
        'CLAUDE_CODE_USE_POWERSHELL_TOOL', 'ANTHROPIC_DEFAULT_HAIKU_MODEL',
        'ANTHROPIC_DEFAULT_SONNET_MODEL', 'ANTHROPIC_DEFAULT_OPUS_MODEL',
        'CLAUDE_CODE_SUBAGENT_MODEL', 'CLAUDE_CODE_EFFORT_LEVEL',
        'ENABLE_PROMPT_CACHING_1H'
    )

    $env:ANTHROPIC_BASE_URL = "https://api.z.ai/api/anthropic"
    $env:ANTHROPIC_AUTH_TOKEN = $token
    $env:API_TIMEOUT_MS = "3000000"
    $env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = "1"
    # Request 1-hour prompt-cache TTL (API-key backends default to 5m; opt in explicitly)
    $env:ENABLE_PROMPT_CACHING_1H = "1"
    # GLM-5.3 supports 1M context (suffix [1m] on the model name); see https://docs.z.ai/devpack/latest-model
    $env:CLAUDE_CODE_AUTO_COMPACT_WINDOW = "1000000"
    $env:CLAUDE_CODE_USE_POWERSHELL_TOOL = "1"

    # Map Anthropic model slots to Z.AI equivalents; remove once Claude Code auto-detects these
    $env:ANTHROPIC_DEFAULT_HAIKU_MODEL = "glm-4.7"
    $env:ANTHROPIC_DEFAULT_SONNET_MODEL = "glm-4.7"
    $env:ANTHROPIC_DEFAULT_OPUS_MODEL = "glm-5.3[1m]"

    $env:CLAUDE_CODE_SUBAGENT_MODEL = "glm-4.7"
    # "max is recommended for coding tasks." (2026-08-14, https://z.ai/blog/glm-5.3)
    $env:CLAUDE_CODE_EFFORT_LEVEL = "max"

    try {
        Install-GlobalClaudeMd
        Install-GlobalClaudeSettings
        [void](Install-ClaudezSetup -Token $token)

        Show-ZaiPeakWarning
        claude @args
    }
    finally {
        Restore-ProcessEnvVars $originalEnvVars
    }
}

function claudezm {
    <#
.SYNOPSIS
    Launches Claude Code with Z.AI settings and GLM model overrides. (Max plan compatibility mode)

.DESCRIPTION
    Performs the same setup as claudez, then temporarily sets the default Anthropic model variables
    to GLM-backed values before invoking claude.

.EXAMPLE
    claudezm

.EXAMPLE
    claudezm "Summarize the changed files"

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-08
#>
    # Read token using Get-AiApiKey helper (process first, then Credential Manager, then legacy User env)
    $token = Get-AiApiKey 'ZAI_API_KEY'

    if (-not $token) {
        Write-Host "ZAI_API_KEY is not set. Aborting." -ForegroundColor Red
        Write-Host ""
        Write-Host "Please set it securely using: Set-AiApiKeysCS" -ForegroundColor Yellow
        return
    }

    $originalEnvVars = Save-ProcessEnvVars @(
        'ANTHROPIC_BASE_URL', 'ANTHROPIC_AUTH_TOKEN', 'API_TIMEOUT_MS',
        'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC', 'CLAUDE_CODE_AUTO_COMPACT_WINDOW',
        'CLAUDE_CODE_USE_POWERSHELL_TOOL', 'ANTHROPIC_DEFAULT_HAIKU_MODEL',
        'ANTHROPIC_DEFAULT_SONNET_MODEL', 'ANTHROPIC_DEFAULT_OPUS_MODEL',
        'CLAUDE_CODE_SUBAGENT_MODEL', 'CLAUDE_CODE_EFFORT_LEVEL',
        'ENABLE_PROMPT_CACHING_1H'
    )

    $env:ANTHROPIC_BASE_URL = "https://api.z.ai/api/anthropic"
    $env:ANTHROPIC_AUTH_TOKEN = $token
    $env:API_TIMEOUT_MS = "3000000"
    $env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = "1"
    # Request 1-hour prompt-cache TTL (API-key backends default to 5m; opt in explicitly)
    $env:ENABLE_PROMPT_CACHING_1H = "1"
    # GLM-5.3 supports 1M context (suffix [1m] on the model name); see https://docs.z.ai/devpack/latest-model
    $env:CLAUDE_CODE_AUTO_COMPACT_WINDOW = "1000000"
    $env:CLAUDE_CODE_USE_POWERSHELL_TOOL = "1"

    # Max plan compatibility mode uses different default model routing.
    $env:ANTHROPIC_DEFAULT_HAIKU_MODEL = "glm-4.7"
    $env:ANTHROPIC_DEFAULT_SONNET_MODEL = "glm-5.3[1m]"
    $env:ANTHROPIC_DEFAULT_OPUS_MODEL = "glm-5.3[1m]"

    $env:CLAUDE_CODE_SUBAGENT_MODEL = "glm-5.3[1m]"
    # "max is recommended for coding tasks." (2026-08-14, https://z.ai/blog/glm-5.3)
    $env:CLAUDE_CODE_EFFORT_LEVEL = "max"

    try {
        Install-GlobalClaudeMd
        Install-GlobalClaudeSettings
        [void](Install-ClaudezSetup -Token $token)

        Show-ZaiPeakWarning
        claude @args
    }
    finally {
        Restore-ProcessEnvVars $originalEnvVars
    }
}

function claudezd {
    <#
.SYNOPSIS
    Launches claudez with permissions skipped.

.DESCRIPTION
    Forwards all arguments to claudez and appends --dangerously-skip-permissions.

.EXAMPLE
    claudezd

.EXAMPLE
    claudezd "Explain the current repository"

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-04
#>
    $claudeArgs = $args + '--dangerously-skip-permissions'
    claudez @claudeArgs
}

function claudezmd {
    <#
.SYNOPSIS
    Launches claudezm with permissions skipped.

.DESCRIPTION
    Forwards all arguments to claudezm and appends --dangerously-skip-permissions.

.EXAMPLE
    claudezmd

.EXAMPLE
    claudezmd "Summarize the changed files"

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-04
#>
    $claudeArgs = $args + '--dangerously-skip-permissions'
    claudezm @claudeArgs
}

# Briefly warn when DeepSeek's peak windows (01:00-04:00, 06:00-10:00 UTC / 09:00-12:00, 14:00-18:00 UTC+8) are active.
# Pricing & peak-hours policy: https://api-docs.deepseek.com/quick_start/pricing
function Show-DeepseekPeakWarning {
    param(
        [DateTime]$UtcNow = [DateTime]::UtcNow,
        [int]$DelaySeconds = 3
    )

    $UtcNow = $UtcNow.ToUniversalTime()

    $w1Start = $UtcNow.Date.AddHours(1)
    $w1End   = $UtcNow.Date.AddHours(4)
    $w2Start = $UtcNow.Date.AddHours(6)
    $w2End   = $UtcNow.Date.AddHours(10)

    $inWindow = $false
    $activeEnd = $null
    $windowLabel = ''

    if ($UtcNow -ge $w1Start -and $UtcNow -lt $w1End) {
        $inWindow = $true
        $activeEnd = $w1End
        $windowLabel = '01:00-04:00 UTC (09:00-12:00 UTC+8)'
    } elseif ($UtcNow -ge $w2Start -and $UtcNow -lt $w2End) {
        $inWindow = $true
        $activeEnd = $w2End
        $windowLabel = '06:00-10:00 UTC (14:00-18:00 UTC+8)'
    }

    if (-not $inWindow) {
        return
    }

    $minutesLeft = [int][Math]::Ceiling(($activeEnd - $UtcNow).TotalMinutes)
    Write-Host ("DeepSeek peak hours are active ({0}); 2x rates apply; ends in {1}h {2}m. Launching in {3} seconds..." -f $windowLabel, [int][Math]::Floor($minutesLeft / 60), ($minutesLeft % 60), $DelaySeconds) -ForegroundColor Yellow
    Start-Sleep -Seconds $DelaySeconds
}

function claudeds {
    <#
.SYNOPSIS
    Launches Claude Code through the DeepSeek endpoint.

.DESCRIPTION
    Reads the DeepSeek API key from the DEEPSEEK_API_KEY environment variable
    (current session first, then User scope), configures runtime environment,
    then invokes claude with the supplied arguments.
    If DEEPSEEK_API_KEY is not set, the function aborts and prints setup guidance.

.EXAMPLE
    claudeds

.EXAMPLE
    claudeds "Explain the current repository"

.EXAMPLE
    [Environment]::SetEnvironmentVariable('DEEPSEEK_API_KEY', '<your_key>', 'User')
    # Restart PowerShell, then run:
    claudeds

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-08
#>
    # Read key using Get-AiApiKey helper (process first, then Credential Manager, then legacy User env)
    $key = Get-AiApiKey 'DEEPSEEK_API_KEY'

    if (-not $key) {
        Write-Host "DEEPSEEK_API_KEY is not set. Aborting." -ForegroundColor Red
        Write-Host ""
        Write-Host "Please set it securely using: Set-AiApiKeysCS" -ForegroundColor Yellow
        return
    }

    $originalEnvVars = Save-ProcessEnvVars @(
        'ANTHROPIC_BASE_URL', 'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_MODEL',
        'ANTHROPIC_DEFAULT_HAIKU_MODEL', 'ANTHROPIC_DEFAULT_SONNET_MODEL',
        'ANTHROPIC_DEFAULT_OPUS_MODEL', 'CLAUDE_CODE_SUBAGENT_MODEL',
        'CLAUDE_CODE_EFFORT_LEVEL', 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC',
        'CLAUDE_CODE_USE_POWERSHELL_TOOL', 'ENABLE_PROMPT_CACHING_1H'
    )

    $env:ANTHROPIC_BASE_URL = "https://api.deepseek.com/anthropic"
    $env:ANTHROPIC_AUTH_TOKEN = $key
    # [1m] suffix requests 1M context window from DeepSeek's Anthropic-compatible endpoint
    $env:ANTHROPIC_MODEL = "deepseek-v4-pro[1m]"
    $env:ANTHROPIC_DEFAULT_HAIKU_MODEL = "deepseek-v4-flash"
    $env:ANTHROPIC_DEFAULT_SONNET_MODEL = "deepseek-v4-pro[1m]"
    $env:ANTHROPIC_DEFAULT_OPUS_MODEL = "deepseek-v4-pro[1m]"
    # Use flash for subagents -- they handle tool routing, not heavy reasoning
    $env:CLAUDE_CODE_SUBAGENT_MODEL = "deepseek-v4-flash"
    $env:CLAUDE_CODE_EFFORT_LEVEL = "max"
    $env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = "1"
    # Request 1-hour prompt-cache TTL (API-key backends default to 5m; opt in explicitly)
    $env:ENABLE_PROMPT_CACHING_1H = "1"
    $env:CLAUDE_CODE_USE_POWERSHELL_TOOL = "1"

    try {
        Show-DeepseekPeakWarning
        claude @args
    }
    finally {
        Restore-ProcessEnvVars $originalEnvVars
    }
}

function claudedsd {
    <#
.SYNOPSIS
    Launches claudeds with permissions skipped.

.DESCRIPTION
    Forwards all arguments to claudeds and appends --dangerously-skip-permissions.

.EXAMPLE
    claudedsd

.EXAMPLE
    claudedsd "Explain the current repository"

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-05
#>
    $claudeArgs = $args + '--dangerously-skip-permissions'
    claudeds @claudeArgs
}

function claudeds2 {
    <#
.SYNOPSIS
    Launches Claude Code through the cheaper DeepSeek endpoint profile.

.DESCRIPTION
    Reads the DeepSeek API key from the DEEPSEEK_API_KEY environment variable
    (current session first, then User scope), configures a cheaper routing profile
    where Sonnet uses the flash model and only Opus uses the pro model, then
    invokes claude with the supplied arguments.
    If DEEPSEEK_API_KEY is not set, the function aborts and prints setup guidance.

.EXAMPLE
    claudeds2

.EXAMPLE
    claudeds2 "Explain the current repository"

.EXAMPLE
    [Environment]::SetEnvironmentVariable('DEEPSEEK_API_KEY', '<your_key>', 'User')
    # Restart PowerShell, then run:
    claudeds2

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-05
#>
    # Read key using Get-AiApiKey helper (process first, then Credential Manager, then legacy User env)
    $key = Get-AiApiKey 'DEEPSEEK_API_KEY'

    if (-not $key) {
        Write-Host "DEEPSEEK_API_KEY is not set. Aborting." -ForegroundColor Red
        Write-Host ""
        Write-Host "Please set it securely using: Set-AiApiKeysCS" -ForegroundColor Yellow
        return
    }

    $originalEnvVars = Save-ProcessEnvVars @(
        'ANTHROPIC_BASE_URL', 'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_MODEL',
        'ANTHROPIC_DEFAULT_HAIKU_MODEL', 'ANTHROPIC_DEFAULT_SONNET_MODEL',
        'ANTHROPIC_DEFAULT_OPUS_MODEL', 'CLAUDE_CODE_SUBAGENT_MODEL',
        'CLAUDE_CODE_EFFORT_LEVEL', 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC',
        'CLAUDE_CODE_USE_POWERSHELL_TOOL', 'ENABLE_PROMPT_CACHING_1H'
    )

    $env:ANTHROPIC_BASE_URL = "https://api.deepseek.com/anthropic"
    $env:ANTHROPIC_AUTH_TOKEN = $key
    # Cheaper profile: Sonnet routes to flash (fast/cheap), only Opus uses pro (expensive/capable)
    $env:ANTHROPIC_MODEL = "deepseek-v4-flash[1m]"
    $env:ANTHROPIC_DEFAULT_HAIKU_MODEL = "deepseek-v4-flash"
    $env:ANTHROPIC_DEFAULT_SONNET_MODEL = "deepseek-v4-flash[1m]"
    $env:ANTHROPIC_DEFAULT_OPUS_MODEL = "deepseek-v4-pro[1m]"
    $env:CLAUDE_CODE_SUBAGENT_MODEL = "deepseek-v4-flash"
    $env:CLAUDE_CODE_EFFORT_LEVEL = "high"
    $env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = "1"
    # Request 1-hour prompt-cache TTL (API-key backends default to 5m; opt in explicitly)
    $env:ENABLE_PROMPT_CACHING_1H = "1"
    $env:CLAUDE_CODE_USE_POWERSHELL_TOOL = "1"

    try {
        Show-DeepseekPeakWarning
        claude @args
    }
    finally {
        Restore-ProcessEnvVars $originalEnvVars
    }
}

function claudeds2d {
    <#
.SYNOPSIS
    Launches claudeds2 with permissions skipped.

.DESCRIPTION
    Forwards all arguments to claudeds2 and appends --dangerously-skip-permissions.

.EXAMPLE
    claudeds2d

.EXAMPLE
    claudeds2d "Summarize the changed files"

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-05
#>
    $claudeArgs = $args + '--dangerously-skip-permissions'
    claudeds2 @claudeArgs
}


function Invoke-RemoteClaudeCodeBase {
    <#
.SYNOPSIS
Runs Claude Code on a remote SSH endpoint with temporary remote state.

.DESCRIPTION
Base64-encodes a bash launcher and delivers it via the SSH command argument,
keeping stdin free for the interactive Claude Code TUI. Sets the Anthropic
environment variables inline and starts claude on the remote host with a
temporary HOME, npm prefix, and workspace. When tmux with per-window
environment support is available, Claude runs in an isolated detachable tmux
server whose additional windows do not inherit Claude credentials. Otherwise,
the launcher uses the direct one-shot behavior.

.PARAMETER RemoteHost
SSH hostname, IP address, or legacy user@host target.

.PARAMETER RemoteUser
Optional SSH login name. Do not use this with a user@host RemoteHost value.

.PARAMETER ApiKey
Anthropic-compatible API key for the remote session.

.PARAMETER Port
SSH port to connect to. Defaults to 22.

.PARAMETER KeyFile
Path to an OpenSSH or PuTTY PPK private key. The key is copied to a restricted
temporary identity and used exclusively. PPK files use Plink; other keys use
OpenSSH.

.PARAMETER BaseUrl
Anthropic-compatible API base URL. Optional - omit for direct Anthropic API access.
Only needed when routing through a proxy or alternative endpoint.

.PARAMETER AnthropicModel
Optional primary model name (ANTHROPIC_MODEL).

.PARAMETER FableModel
Optional default Fable model name (ANTHROPIC_DEFAULT_FABLE_MODEL).

.PARAMETER HaikuModel
Default Haiku model name.

.PARAMETER SonnetModel
Default Sonnet model name.

.PARAMETER OpusModel
Default Opus model name.

.PARAMETER TimeoutMs
API timeout in milliseconds.

.PARAMETER Disable1M
Sets CLAUDE_CODE_DISABLE_1M_CONTEXT on the remote host.

.PARAMETER SubagentModel
Optional subagent model name (CLAUDE_CODE_SUBAGENT_MODEL). Default: empty.
Pass the same value the local claudez/claudezm profile uses so remote subagent
routing matches the local one.

.PARAMETER EffortLevel
Optional effort level (CLAUDE_CODE_EFFORT_LEVEL), e.g. "high" or "max".
Default: empty.

.PARAMETER AutoCompactWindow
Optional 1M-context auto-compact window (CLAUDE_CODE_AUTO_COMPACT_WINDOW).
Z.AI's glm-5.3[1m] requires "1000000" to actually exercise the 1M context window.
Default: empty.

.PARAMETER MaxContextTokens
Optional maximum context token count (CLAUDE_CODE_MAX_CONTEXT_TOKENS).

.EXAMPLE
Invoke-RemoteClaudeCodeBase remote-host -RemoteUser user -ApiKey $env:ANTHROPIC_API_KEY

.EXAMPLE
Invoke-RemoteClaudeCodeBase -RemoteHost user@remote-host -ApiKey $env:ZAI_API_KEY -BaseUrl "https://api.z.ai/api/anthropic"

.EXAMPLE
# Match local claudezm routing for Z.AI:
Invoke-RemoteClaudeCodeBase -RemoteHost user@remote-host -ApiKey $env:ZAI_API_KEY `
    -BaseUrl "https://api.z.ai/api/anthropic" `
    -HaikuModel "glm-4.7" -SonnetModel "glm-5.3[1m]" -OpusModel "glm-5.3[1m]" `
    -SubagentModel "glm-5.3[1m]" -EffortLevel "max" -AutoCompactWindow "1000000" `
    -Disable1M "0"

.NOTES
Author: jjw(@thejjw)
Last Edit: 2026-08
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$RemoteHost,

        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [int]$Port = 22,

        # Optional: SSH private key file for authentication.
        [string]$KeyFile,

        # Optional: only needed for proxy/alternative endpoints.
        # Leave empty to use the default Anthropic API (api.anthropic.com).
        [string]$BaseUrl = "",

        [string]$AnthropicModel = "",

        [string]$FableModel = "",

        [Parameter(Mandatory = $true)]
        [string]$HaikuModel,

        [Parameter(Mandatory = $true)]
        [string]$SonnetModel,

        [Parameter(Mandatory = $true)]
        [string]$OpusModel,

        [Parameter(Mandatory = $true)]
        [string]$TimeoutMs,

        [Parameter(Mandatory = $true)]
        [string]$Disable1M,

        # Optional: subagent model (CLAUDE_CODE_SUBAGENT_MODEL). Empty leaves it unset on the remote.
        [string]$SubagentModel = "",

        # Optional: effort level (CLAUDE_CODE_EFFORT_LEVEL). Empty leaves it unset.
        [string]$EffortLevel = "",

        # Optional: 1M-context auto-compact window (CLAUDE_CODE_AUTO_COMPACT_WINDOW).
        # Z.AI's glm-5.3[1m] requires "1000000" to actually exercise 1M context.
        [string]$AutoCompactWindow = "",

        [string]$MaxContextTokens = "",

        [string]$RemoteUser
    )

    # Bash single-quote escaping: end quote, insert a literal quote, reopen quote
    # (Bash has no backslash escape inside single quotes, so this is the only way)
    # Bash has no backslash escape inside single quotes; the only way to embed a
    # literal quote is to end the quote, add an escaped quote, and reopen: 'foo'\''bar'
    function Escape-BashSingleQuotedValue {
        param([string]$Value)
        if ($null -eq $Value) { return "''" }
        return "'" + ($Value -replace "'", "'`"'`"'") + "'"
    }

    if ([string]::IsNullOrWhiteSpace($RemoteHost)) {
        throw 'RemoteHost is required.'
    }

    if (-not [string]::IsNullOrWhiteSpace($RemoteUser) -and $RemoteHost.Contains('@')) {
        throw 'Specify the SSH login with either -RemoteUser or a user@host RemoteHost value, not both.'
    }

    if ([string]::IsNullOrWhiteSpace($ApiKey)) {
        throw 'ApiKey is required.'
    }

    $script = @'
unset HISTFILE
set +o history
CC_TMP="$(mktemp -d /tmp/cc-XXXXXX)"
trap 'echo "[cleanup] Wiping $CC_TMP ..."; rm -rf "$CC_TMP"' EXIT
CC_NPM="$CC_TMP/npm"; CC_BIN="$CC_TMP/bin"; CC_HOME="$CC_TMP/home"; CC_WORK="$CC_TMP/workspace"
CC_START_DIR="$PWD"; CC_REAL_HOME="$HOME"; CC_ORIGINAL_PATH="$PATH"
mkdir -p "$CC_NPM" "$CC_BIN" "$CC_HOME" "$CC_WORK"
# Use an installed English UTF-8 locale for the entire remote session.
CC_LOCALE="$(locale -a 2>/dev/null | awk 'tolower($0) ~ /^c\.utf-?8$/ { print; exit }')"
[ -n "$CC_LOCALE" ] || CC_LOCALE="$(locale -a 2>/dev/null | awk 'tolower($0) ~ /^en_us\.utf-?8$/ { print; exit }')"
CC_LOCALE="${CC_LOCALE:-C}"
export LANG="$CC_LOCALE" LC_ALL="$CC_LOCALE" LANGUAGE=en
export ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:?not set}"
# ANTHROPIC_BASE_URL is optional - only exported when the caller provided a value
[ -n "${ANTHROPIC_BASE_URL:-}" ] && export ANTHROPIC_BASE_URL="$ANTHROPIC_BASE_URL"
[ -n "${ANTHROPIC_MODEL:-}" ] && export ANTHROPIC_MODEL="$ANTHROPIC_MODEL"
[ -n "${ANTHROPIC_DEFAULT_FABLE_MODEL:-}" ] && export ANTHROPIC_DEFAULT_FABLE_MODEL="$ANTHROPIC_DEFAULT_FABLE_MODEL"
export ANTHROPIC_DEFAULT_HAIKU_MODEL="${ANTHROPIC_DEFAULT_HAIKU_MODEL:-}"
export ANTHROPIC_DEFAULT_SONNET_MODEL="${ANTHROPIC_DEFAULT_SONNET_MODEL:-}"
export ANTHROPIC_DEFAULT_OPUS_MODEL="${ANTHROPIC_DEFAULT_OPUS_MODEL:-}"
export CLAUDE_CODE_SUBAGENT_MODEL="${CLAUDE_CODE_SUBAGENT_MODEL:-}"
[ -n "${CLAUDE_CODE_EFFORT_LEVEL:-}" ] && export CLAUDE_CODE_EFFORT_LEVEL="$CLAUDE_CODE_EFFORT_LEVEL"
export CLAUDE_CODE_AUTO_COMPACT_WINDOW="${CLAUDE_CODE_AUTO_COMPACT_WINDOW:-}"
[ -n "${CLAUDE_CODE_MAX_CONTEXT_TOKENS:-}" ] && export CLAUDE_CODE_MAX_CONTEXT_TOKENS="$CLAUDE_CODE_MAX_CONTEXT_TOKENS"
export API_TIMEOUT_MS="${API_TIMEOUT_MS:-300000}"
export CLAUDE_CODE_DISABLE_1M_CONTEXT="${CLAUDE_CODE_DISABLE_1M_CONTEXT:-1}"
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
export ENABLE_PROMPT_CACHING_1H=1
export DISABLE_AUTOUPDATER=1
CC_TMUX="$(command -v tmux 2>/dev/null || true)"
if [ -n "$CC_TMUX" ]; then
    echo "[tmux] Found $CC_TMUX; using an isolated detachable session (detach: Ctrl-b d)."
else
    echo "[tmux] Not found; Claude will run directly in this SSH session."
fi
if ! command -v node &>/dev/null; then
    export NVM_DIR="$CC_TMP/nvm"; mkdir -p "$NVM_DIR"
    curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/__NVM_VERSION__/install.sh \
        | NVM_DIR="$NVM_DIR" PROFILE=/dev/null bash
    . "$NVM_DIR/nvm.sh" --no-use
    nvm install --lts --no-progress && nvm use --lts
fi
if ! command -v claude &>/dev/null; then
    npm install --global --prefix "$CC_NPM" --no-audit --no-fund @anthropic-ai/claude-code
    export PATH="$CC_NPM/bin:$PATH"
fi
CC_SYSTEM_UV="$(command -v uv 2>/dev/null || true)"
if curl -LsSf __UV_INSTALL_URL__ \
        | env UV_UNMANAGED_INSTALL="$CC_BIN" sh >/dev/null &&
    [ -x "$CC_BIN/uv" ] &&
    CC_UV_VERSION="$("$CC_BIN/uv" --version 2>/dev/null)"; then
    export PATH="$CC_BIN:$PATH"
    echo "[uv] Using ephemeral $CC_UV_VERSION at $CC_BIN/uv."
elif [ -n "$CC_SYSTEM_UV" ] &&
    CC_UV_VERSION="$("$CC_SYSTEM_UV" --version 2>/dev/null)"; then
    echo "[uv] Ephemeral install failed; using $CC_UV_VERSION at $CC_SYSTEM_UV."
else
    echo "[uv] WARNING: unavailable; Python bootstrap and uv package tools will not be available." >&2
fi
echo "[uv] Continuing in 3 seconds..."
sleep 3
CC_CLAUDE="$(command -v claude)"
CC_CLAUDE_PATH="$PATH"

# Run tmux itself without provider settings so new user-created windows are clean.
cc_tmux_clean() (
    unset ANTHROPIC_API_KEY ANTHROPIC_BASE_URL ANTHROPIC_MODEL
    unset ANTHROPIC_DEFAULT_FABLE_MODEL ANTHROPIC_DEFAULT_HAIKU_MODEL
    unset ANTHROPIC_DEFAULT_SONNET_MODEL ANTHROPIC_DEFAULT_OPUS_MODEL
    unset CLAUDE_CODE_SUBAGENT_MODEL CLAUDE_CODE_EFFORT_LEVEL
    unset CLAUDE_CODE_AUTO_COMPACT_WINDOW CLAUDE_CODE_MAX_CONTEXT_TOKENS
    unset API_TIMEOUT_MS CLAUDE_CODE_DISABLE_1M_CONTEXT
    unset CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC ENABLE_PROMPT_CACHING_1H
    unset DISABLE_AUTOUPDATER NVM_DIR
    HOME="$CC_REAL_HOME" PATH="$CC_ORIGINAL_PATH" \
        "$CC_TMUX" -L "$CC_TMUX_LABEL" "$@"
)

if [ -n "$CC_TMUX" ]; then
    CC_TMUX_LABEL="cc-$(date +%Y%m%d-%H%M%S)-$$-$RANDOM"
    if cc_tmux_clean new-session -d -s claude -n bootstrap -c "$CC_START_DIR" \
        'while :; do sleep 3600; done' &&
        cc_tmux_clean set-environment -t claude HISTFILE /dev/null; then
        CC_TMUX_ENV=(
            -e "HOME=$CC_HOME"
            -e "PATH=$PATH"
            -e "CC_TMP=$CC_TMP"
            -e "CC_HOME=$CC_HOME"
            -e "CC_WORK=$CC_WORK"
            -e "CC_CLAUDE=$CC_CLAUDE"
            -e "CC_CLAUDE_PATH=$CC_CLAUDE_PATH"
            -e "ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY"
            -e "ANTHROPIC_DEFAULT_HAIKU_MODEL=$ANTHROPIC_DEFAULT_HAIKU_MODEL"
            -e "ANTHROPIC_DEFAULT_SONNET_MODEL=$ANTHROPIC_DEFAULT_SONNET_MODEL"
            -e "ANTHROPIC_DEFAULT_OPUS_MODEL=$ANTHROPIC_DEFAULT_OPUS_MODEL"
            -e "CLAUDE_CODE_SUBAGENT_MODEL=$CLAUDE_CODE_SUBAGENT_MODEL"
            -e "CLAUDE_CODE_AUTO_COMPACT_WINDOW=$CLAUDE_CODE_AUTO_COMPACT_WINDOW"
            -e "API_TIMEOUT_MS=$API_TIMEOUT_MS"
            -e "CLAUDE_CODE_DISABLE_1M_CONTEXT=$CLAUDE_CODE_DISABLE_1M_CONTEXT"
            -e "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=$CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"
            -e "ENABLE_PROMPT_CACHING_1H=$ENABLE_PROMPT_CACHING_1H"
            -e "DISABLE_AUTOUPDATER=$DISABLE_AUTOUPDATER"
        )
        [ -n "${NVM_DIR:-}" ] && CC_TMUX_ENV+=(-e "NVM_DIR=$NVM_DIR")
        [ -n "${ANTHROPIC_BASE_URL:-}" ] && CC_TMUX_ENV+=(-e "ANTHROPIC_BASE_URL=$ANTHROPIC_BASE_URL")
        [ -n "${ANTHROPIC_MODEL:-}" ] && CC_TMUX_ENV+=(-e "ANTHROPIC_MODEL=$ANTHROPIC_MODEL")
        [ -n "${ANTHROPIC_DEFAULT_FABLE_MODEL:-}" ] && CC_TMUX_ENV+=(-e "ANTHROPIC_DEFAULT_FABLE_MODEL=$ANTHROPIC_DEFAULT_FABLE_MODEL")
        [ -n "${CLAUDE_CODE_EFFORT_LEVEL:-}" ] && CC_TMUX_ENV+=(-e "CLAUDE_CODE_EFFORT_LEVEL=$CLAUDE_CODE_EFFORT_LEVEL")
        [ -n "${CLAUDE_CODE_MAX_CONTEXT_TOKENS:-}" ] && CC_TMUX_ENV+=(-e "CLAUDE_CODE_MAX_CONTEXT_TOKENS=$CLAUDE_CODE_MAX_CONTEXT_TOKENS")

        CC_RUNNER="$CC_TMP/run-claude"
        cat > "$CC_RUNNER" <<'CC_RUNNER_EOF'
#!/usr/bin/env bash
unset HISTFILE
set +o history
cc_cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    echo "[cleanup] Wiping $CC_TMP ..."
    rm -rf -- "$CC_TMP"
    exit "$status"
}
trap cc_cleanup EXIT HUP INT TERM
cd "$CC_WORK"
export HOME="$CC_HOME" PATH="$CC_CLAUDE_PATH"
"$CC_CLAUDE" --dangerously-skip-permissions
CC_RUNNER_EOF
        chmod 600 "$CC_RUNNER"

        if cc_tmux_clean new-window -d -t claude: -n claude -c "$CC_WORK" \
            "${CC_TMUX_ENV[@]}" bash "$CC_RUNNER"; then
            # The Claude pane now owns cleanup and survives SSH client detachment.
            trap - EXIT
            cc_tmux_clean bind-key c new-window -c "$CC_START_DIR"
            cc_tmux_clean kill-window -t claude:bootstrap
            echo "[tmux] Reattach after logging in: tmux -L $CC_TMUX_LABEL attach -t claude"
            cc_tmux_clean attach-session -t claude
            exit $?
        fi
    fi
    cc_tmux_clean kill-server 2>/dev/null || true
    echo "[tmux] Isolated session setup failed; Claude will run directly in this SSH session." >&2
fi

cd "$CC_WORK"
HOME="$CC_HOME" claude --dangerously-skip-permissions
'@
    $script = $script.Replace('__NVM_VERSION__', $_NvmVersion)
    $script = $script.Replace('__UV_INSTALL_URL__', $_UvInstallUrl)

    # Base64-encode the script so it travels as an SSH command argument, not stdin.
    # Claude Code's interactive TUI needs stdin; piping via 'bash -s' would steal it.
    $encoded = [Convert]::ToBase64String(
        [System.Text.Encoding]::UTF8.GetBytes($script)
    )

    # Prepend environment variables as SSH command arguments.
    # BaseUrl is conditionally included to avoid sending an empty value that
    # would override the remote's default (Anthropic direct) endpoint.
    $envParts = [System.Collections.Generic.List[string]]@(
        "ANTHROPIC_API_KEY=$(Escape-BashSingleQuotedValue $ApiKey)"
        "ANTHROPIC_DEFAULT_HAIKU_MODEL=$(Escape-BashSingleQuotedValue $HaikuModel)"
        "ANTHROPIC_DEFAULT_SONNET_MODEL=$(Escape-BashSingleQuotedValue $SonnetModel)"
        "ANTHROPIC_DEFAULT_OPUS_MODEL=$(Escape-BashSingleQuotedValue $OpusModel)"
        "CLAUDE_CODE_SUBAGENT_MODEL=$(Escape-BashSingleQuotedValue $SubagentModel)"
        "CLAUDE_CODE_AUTO_COMPACT_WINDOW=$(Escape-BashSingleQuotedValue $AutoCompactWindow)"
        "API_TIMEOUT_MS=$(Escape-BashSingleQuotedValue $TimeoutMs)"
        "CLAUDE_CODE_DISABLE_1M_CONTEXT=$(Escape-BashSingleQuotedValue $Disable1M)"
    )
    if (-not [string]::IsNullOrWhiteSpace($BaseUrl)) {
        $envParts.Insert(1, "ANTHROPIC_BASE_URL=$(Escape-BashSingleQuotedValue $BaseUrl)")
    }
    if (-not [string]::IsNullOrWhiteSpace($AnthropicModel)) {
        $envParts.Add("ANTHROPIC_MODEL=$(Escape-BashSingleQuotedValue $AnthropicModel)")
    }
    if (-not [string]::IsNullOrWhiteSpace($FableModel)) {
        $envParts.Add("ANTHROPIC_DEFAULT_FABLE_MODEL=$(Escape-BashSingleQuotedValue $FableModel)")
    }
    if (-not [string]::IsNullOrWhiteSpace($EffortLevel)) {
        $envParts.Add("CLAUDE_CODE_EFFORT_LEVEL=$(Escape-BashSingleQuotedValue $EffortLevel)")
    }
    if (-not [string]::IsNullOrWhiteSpace($MaxContextTokens)) {
        $envParts.Add("CLAUDE_CODE_MAX_CONTEXT_TOKENS=$(Escape-BashSingleQuotedValue $MaxContextTokens)")
    }
    $envPrefix = $envParts -join ' '

    # -t: pseudo-TTY required for Claude Code's TUI rendering
    # StrictHostKeyChecking=accept-new: trusts first-seen host keys but
    #   still rejects changed keys (protects against MITM on reconnects)
    # Process substitution supplies the script as a file while preserving the SSH PTY on stdin.
    $temporaryIdentity = $null
    try {
        if (-not [string]::IsNullOrWhiteSpace($KeyFile)) {
            $temporaryIdentity = $_ProfileHelpers.NewTemporarySshIdentity($KeyFile)
        }
        $remoteCommand = "$envPrefix bash -c 'bash <(printf %s $encoded | base64 -d)'"
        if ($temporaryIdentity -and $temporaryIdentity.Format -eq 'PPK') {
            if (-not (Get-Command plink.exe -CommandType Application -ErrorAction SilentlyContinue)) {
                throw 'Plink is required to use a PPK key. Install PuTTY or pass an OpenSSH-format key.'
            }
            $clientArgs = @('-ssh', '-t', '-P', $Port, '-noagent')
            if (-not [string]::IsNullOrWhiteSpace($RemoteUser)) { $clientArgs += @('-l', $RemoteUser) }
            $clientArgs += @('-i', $temporaryIdentity.Path, $RemoteHost, $remoteCommand)
            plink.exe @clientArgs
        } else {
            $clientArgs = @('-tt', '-o', 'StrictHostKeyChecking=accept-new', '-p', $Port)
            if (-not [string]::IsNullOrWhiteSpace($RemoteUser)) { $clientArgs += @('-l', $RemoteUser) }
            if ($temporaryIdentity) {
                $clientArgs += @('-o', 'IdentitiesOnly=yes', '-i', $temporaryIdentity.Path)
            }
            $clientArgs += @($RemoteHost, $remoteCommand)
            ssh @clientArgs
        }
    } finally {
        if ($temporaryIdentity) {
            $_ProfileHelpers.RemoveTemporarySshIdentity($temporaryIdentity)
        }
    }
}

function Invoke-RemoteClaudeCodeZ {
    <#
.SYNOPSIS
Runs Claude Code on a remote SSH endpoint with temporary remote state.

.DESCRIPTION
Prompts for the API key from ZAI_API_KEY if it is not provided, then runs
the remote Claude launcher with the remote defaults defined inside
Invoke-RemoteClaudeCodeBase. The remote Claude invocation always uses
--dangerously-skip-permissions.

.PARAMETER RemoteHost
SSH hostname, IP address, or legacy user@host target.

.PARAMETER RemoteUser
Optional SSH login name. Do not use this with a user@host RemoteHost value.

.PARAMETER ApiKey
Anthropic-compatible API key for the remote session.
Optional - falls back to ZAI_API_KEY env var.

.PARAMETER Port
SSH port to connect to. Defaults to 22.

.EXAMPLE
Invoke-RemoteClaudeCodeZ remote-host -RemoteUser user

.EXAMPLE
Invoke-RemoteClaudeCodeZ -RemoteHost user@remote-host -ApiKey $env:ZAI_API_KEY

.NOTES
Author: jjw(@thejjw)
Last Edit: 2026-08
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$RemoteHost,

        [string]$ApiKey,

        [int]$Port = 22,

        # Optional: SSH private key file for authentication.
        [string]$KeyFile,

        [string]$RemoteUser
    )

    if ([string]::IsNullOrWhiteSpace($ApiKey)) {
        $ApiKey = Get-AiApiKey 'ZAI_API_KEY'
    }

    if (-not $ApiKey) {
        Write-Host "ZAI_API_KEY is not set. Aborting." -ForegroundColor Red
        Write-Host ""
        Write-Host "Please set it securely using: Set-AiApiKeysCS" -ForegroundColor Yellow
        return
    }

    # Keep the editable remote defaults here so they are easy to tweak later.
    # Matches the local claudezm profile: glm-5.3[1m] for Sonnet/Opus/Subagent,
    # effort=max, 1M context enabled via CLAUDE_CODE_AUTO_COMPACT_WINDOW=1000000.
    $BaseUrl = "https://api.z.ai/api/anthropic"
    $HaikuModel = "glm-4.7"
    $SonnetModel = "glm-5.3[1m]"
    $OpusModel = "glm-5.3[1m]"
    $SubagentModel = "glm-5.3[1m]"
    $EffortLevel = "max"
    $AutoCompactWindow = "1000000"
    $TimeoutMs = "3000000"
    $Disable1M = "0"

    $baseParams = @{
        RemoteHost        = $RemoteHost
        ApiKey            = $ApiKey
        Port              = $Port
        BaseUrl           = $BaseUrl
        HaikuModel        = $HaikuModel
        SonnetModel       = $SonnetModel
        OpusModel         = $OpusModel
        SubagentModel     = $SubagentModel
        EffortLevel       = $EffortLevel
        AutoCompactWindow = $AutoCompactWindow
        TimeoutMs         = $TimeoutMs
        Disable1M         = $Disable1M
    }
    if (-not [string]::IsNullOrWhiteSpace($KeyFile)) { $baseParams['KeyFile'] = $KeyFile }
    if (-not [string]::IsNullOrWhiteSpace($RemoteUser)) { $baseParams['RemoteUser'] = $RemoteUser }
    Invoke-RemoteClaudeCodeBase @baseParams
}

function Install-ClaudemmSetup {
    <#
.SYNOPSIS
    Configures MiniMax MCP server for Claude Code.

.DESCRIPTION
    Adds the minimax-coding-plan-mcp server via Claude CLI if not already present.
    Requires 'uv' (uvx) to be installed. Uses a flag file under ~/.claude to skip
    duplicate setup runs unless -Force is specified.

.PARAMETER Token
    MiniMax API key used for MCP server configuration.

.PARAMETER Force
    Re-runs MCP setup even if the setup flag already exists.

.EXAMPLE
    Install-ClaudemmSetup -Token "<api_key>"

.EXAMPLE
    Install-ClaudemmSetup -Token "<api_key>" -Force

.NOTES
    Requires 'uv' to be installed (uvx is used to run minimax-coding-plan-mcp).
    Install uv: winget install astral-sh.uv

    Author: jjw(@thejjw)
    Last Edit: 2026-05
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Token,
        [switch]$Force
    )

    $claudeDir = Join-Path $HOME '.claude'
    $setupFlag = Join-Path $claudeDir '.claudemm_setup_complete'

    if (-not (Test-Path -LiteralPath $claudeDir)) {
        $null = New-Item -ItemType Directory -Path $claudeDir -Force
    }

    $claudeCmd = Get-Command claude -ErrorAction SilentlyContinue
    if ($null -eq $claudeCmd) {
        Write-Host 'WARNING: claude CLI not found, skipping MCP server configuration' -ForegroundColor Yellow
        return $false
    }

    if ((Test-Path -LiteralPath $setupFlag) -and -not $Force) {
        Write-Host "claudemm: MCP setup already completed (flag: $setupFlag) -- skipping"
        Write-Host 'claudemm: use Install-ClaudemmSetup -Force to reconfigure' -ForegroundColor DarkGray
        return $true
    }

    # Check for uv (required by uvx for minimax-coding-plan-mcp)
    $uvCmd = Get-Command uv -ErrorAction SilentlyContinue
    if ($null -eq $uvCmd) {
        Write-Host "claudemm: WARNING: 'uv' not found -- skipping MiniMax MCP server" -ForegroundColor Yellow
        Write-Host "  Install uv:  winget install astral-sh.uv" -ForegroundColor Cyan
        return $false
    }

    Write-Host "claudemm: configuring MCP servers..." -ForegroundColor Cyan

    # MiniMax coding-plan-mcp
    if (& claude mcp list | Select-String -Pattern 'minimax' -Quiet) {
        Write-Host "claudemm: MiniMax MCP server already exists -- skipping" -ForegroundColor DarkGray
    }
    else {
        & claude mcp add -s user MiniMax --env MINIMAX_API_KEY="$Token" --env MINIMAX_API_HOST=https://api.minimax.io -- uvx --with "mcp<2.0.0" minimax-coding-plan-mcp -y 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "claudemm: added MiniMax MCP server" -ForegroundColor Green
        }
        else {
            Write-Warning "claudemm: failed to add MiniMax MCP server"
        }
    }

    $flagInfo = @(
        "configuredAt=$(Get-Date -Format o)",
        "user=$env:USERNAME",
        'mode=MiniMax'
    ) -join "`r`n"
    Set-Content -LiteralPath $setupFlag -Value $flagInfo -Encoding UTF8
    Write-Host 'claudemm: MCP setup complete' -ForegroundColor Green
    return $true
}

function claudemm {
    <#
.SYNOPSIS
    Launches Claude Code through the MiniMax endpoint.

.DESCRIPTION
    Reads the MiniMax API key from the MINIMAX_API_KEY environment variable
    (current session first, then User scope), runs one-time claudemm MCP setup,
    configures runtime environment, then invokes claude with the supplied arguments.
    If MINIMAX_API_KEY is not set, the function aborts and prints setup guidance.

.EXAMPLE
    claudemm

.EXAMPLE
    claudemm "Explain the current repository"

.EXAMPLE
    [Environment]::SetEnvironmentVariable('MINIMAX_API_KEY', '<your_key>', 'User')
    # Restart PowerShell, then run:
    claudemm

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-05
#>
    # Read key using Get-AiApiKey helper (process first, then Credential Manager, then legacy User env)
    $key = Get-AiApiKey 'MINIMAX_API_KEY'

    if (-not $key) {
        Write-Host "MINIMAX_API_KEY is not set. Aborting." -ForegroundColor Red
        Write-Host ""
        Write-Host "Please set it securely using: Set-AiApiKeysCS" -ForegroundColor Yellow
        return
    }

    $originalEnvVars = Save-ProcessEnvVars @(
        'ANTHROPIC_BASE_URL', 'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_MODEL',
        'ANTHROPIC_DEFAULT_HAIKU_MODEL', 'ANTHROPIC_DEFAULT_SONNET_MODEL',
        'ANTHROPIC_DEFAULT_OPUS_MODEL', 'API_TIMEOUT_MS',
        'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC', 'CLAUDE_CODE_USE_POWERSHELL_TOOL',
        'CLAUDE_CODE_SUBAGENT_MODEL', 'CLAUDE_CODE_EFFORT_LEVEL',
        'ENABLE_PROMPT_CACHING_1H'
    )

    $env:ANTHROPIC_BASE_URL = "https://api.minimax.io/anthropic"
    $env:ANTHROPIC_AUTH_TOKEN = $key
    # MiniMax offers a single model (M3[1m]), so all Anthropic model slots route to it
    $env:ANTHROPIC_MODEL = "MiniMax-M3[1m]"
    $env:ANTHROPIC_DEFAULT_HAIKU_MODEL = "MiniMax-M3[1m]"
    $env:ANTHROPIC_DEFAULT_SONNET_MODEL = "MiniMax-M3[1m]"
    $env:ANTHROPIC_DEFAULT_OPUS_MODEL = "MiniMax-M3[1m]"
    $env:API_TIMEOUT_MS = "3000000"
    $env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = "1"
    # Request 1-hour prompt-cache TTL (API-key backends default to 5m; opt in explicitly)
    $env:ENABLE_PROMPT_CACHING_1H = "1"
    $env:CLAUDE_CODE_USE_POWERSHELL_TOOL = "1"

    $env:CLAUDE_CODE_SUBAGENT_MODEL = "MiniMax-M3[1m]"
    $env:CLAUDE_CODE_EFFORT_LEVEL = "max"

    try {
        Install-GlobalClaudeMd
        Install-GlobalClaudeSettings
        [void](Install-ClaudemmSetup -Token $key)

        claude @args
    }
    finally {
        Restore-ProcessEnvVars $originalEnvVars
    }
}

function claudemmd {
    <#
.SYNOPSIS
    Launches claudemm with permissions skipped.

.DESCRIPTION
    Forwards all arguments to claudemm and appends --dangerously-skip-permissions.

.EXAMPLE
    claudemmd

.EXAMPLE
    claudemmd "Explain the current repository"

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-05
#>
    $claudeArgs = $args + '--dangerously-skip-permissions'
    claudemm @claudeArgs
}

function claudek {
    <#
.SYNOPSIS
    Launches Claude Code through the Kimi Code endpoint.

.DESCRIPTION
    Reads KIMI_CODE_PLAN_API_KEY from the current process, Windows Credential Manager, or
    legacy User environment, then temporarily configures Claude Code to use Kimi
    K3 with a 1M context window. Restores the previous environment after Claude exits.

.EXAMPLE
    claudek

.EXAMPLE
    claudek "Explain the current repository"

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-07
#>
    $key = Get-AiApiKey 'KIMI_CODE_PLAN_API_KEY'

    if (-not $key) {
        Write-Host "KIMI_CODE_PLAN_API_KEY is not set. Aborting." -ForegroundColor Red
        Write-Host ""
        Write-Host "Please set it securely using: Set-AiApiKeysCS" -ForegroundColor Yellow
        return
    }

    $originalEnvVars = Save-ProcessEnvVars @(
        'ANTHROPIC_BASE_URL', 'ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN',
        'ANTHROPIC_MODEL', 'ANTHROPIC_DEFAULT_FABLE_MODEL',
        'ANTHROPIC_DEFAULT_OPUS_MODEL', 'ANTHROPIC_DEFAULT_SONNET_MODEL',
        'ANTHROPIC_DEFAULT_HAIKU_MODEL', 'CLAUDE_CODE_SUBAGENT_MODEL',
        'CLAUDE_CODE_AUTO_COMPACT_WINDOW', 'CLAUDE_CODE_MAX_CONTEXT_TOKENS',
        'CLAUDE_CODE_USE_POWERSHELL_TOOL'
    )

    $env:ANTHROPIC_BASE_URL = 'https://api.kimi.com/coding/'
    $env:ANTHROPIC_API_KEY = $key
    Remove-Item Env:\ANTHROPIC_AUTH_TOKEN -ErrorAction SilentlyContinue

    # Kimi K3 uses one model for every Claude Code routing slot.
    $env:ANTHROPIC_MODEL = 'k3[1m]'
    $env:ANTHROPIC_DEFAULT_FABLE_MODEL = $env:ANTHROPIC_MODEL
    $env:ANTHROPIC_DEFAULT_OPUS_MODEL = $env:ANTHROPIC_MODEL
    $env:ANTHROPIC_DEFAULT_SONNET_MODEL = $env:ANTHROPIC_MODEL
    $env:ANTHROPIC_DEFAULT_HAIKU_MODEL = $env:ANTHROPIC_MODEL
    $env:CLAUDE_CODE_SUBAGENT_MODEL = $env:ANTHROPIC_MODEL

    $env:CLAUDE_CODE_AUTO_COMPACT_WINDOW = '1048576'
    $env:CLAUDE_CODE_MAX_CONTEXT_TOKENS = '1048576'
    $env:CLAUDE_CODE_USE_POWERSHELL_TOOL = '1'

    try {
        Install-GlobalClaudeMd
        Install-GlobalClaudeSettings
        claude @args
    }
    finally {
        Restore-ProcessEnvVars $originalEnvVars
    }
}

function claudekd {
    <#
.SYNOPSIS
    Launches claudek with permissions skipped.

.DESCRIPTION
    Forwards all arguments to claudek and appends --dangerously-skip-permissions.

.EXAMPLE
    claudekd

.EXAMPLE
    claudekd "Explain the current repository"

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-07
#>
    $claudeArgs = $args + '--dangerously-skip-permissions'
    claudek @claudeArgs
}

function Invoke-RemoteClaudeCodeK {
    <#
.SYNOPSIS
Runs Claude Code on a remote SSH endpoint through Kimi Code.

.DESCRIPTION
Reads KIMI_CODE_PLAN_API_KEY when ApiKey is omitted, then launches the shared temporary
remote Claude environment with the same K3 1M model routing as claudek.

.PARAMETER RemoteHost
SSH hostname, IP address, or legacy user@host target.

.PARAMETER ApiKey
Kimi Code API key. Defaults to KIMI_CODE_PLAN_API_KEY from the configured credential sources.

.PARAMETER Port
SSH port to connect to. Defaults to 22.

.PARAMETER KeyFile
Path to an OpenSSH or PuTTY PPK private key.

.PARAMETER RemoteUser
Optional SSH login name. Do not use this with a user@host RemoteHost value.

.EXAMPLE
Invoke-RemoteClaudeCodeK remote-host -RemoteUser user

.EXAMPLE
Invoke-RemoteClaudeCodeK user@remote-host -KeyFile C:\Keys\remote.ppk

.NOTES
Author: jjw(@thejjw)
Last Edit: 2026-07
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$RemoteHost,

        [string]$ApiKey,

        [int]$Port = 22,

        [string]$KeyFile,

        [string]$RemoteUser
    )

    if ([string]::IsNullOrWhiteSpace($ApiKey)) {
        $ApiKey = Get-AiApiKey 'KIMI_CODE_PLAN_API_KEY'
    }

    if (-not $ApiKey) {
        Write-Host "KIMI_CODE_PLAN_API_KEY is not set. Aborting." -ForegroundColor Red
        Write-Host ""
        Write-Host "Please set it securely using: Set-AiApiKeysCS" -ForegroundColor Yellow
        return
    }

    # Mirror claudek: route every Claude Code model slot through Kimi K3 1M.
    $model = 'k3[1m]'
    $baseParams = @{
        RemoteHost        = $RemoteHost
        ApiKey            = $ApiKey
        Port              = $Port
        BaseUrl           = 'https://api.kimi.com/coding/'
        AnthropicModel    = $model
        FableModel        = $model
        HaikuModel        = $model
        SonnetModel       = $model
        OpusModel         = $model
        SubagentModel     = $model
        AutoCompactWindow = '1048576'
        MaxContextTokens = '1048576'
        TimeoutMs        = '3000000'
        Disable1M        = '0'
    }
    if (-not [string]::IsNullOrWhiteSpace($KeyFile)) { $baseParams['KeyFile'] = $KeyFile }
    if (-not [string]::IsNullOrWhiteSpace($RemoteUser)) { $baseParams['RemoteUser'] = $RemoteUser }
    Invoke-RemoteClaudeCodeBase @baseParams
}

# Qwen Cloud Token Plan (Bailian Token Plan) endpoints for configuring other agents:
#   Anthropic base: https://token-plan.ap-southeast-1.maas.aliyuncs.com/apps/anthropic
#   Anthropic messages: https://token-plan.ap-southeast-1.maas.aliyuncs.com/apps/anthropic/v1/messages
#   OpenAI-compatible base: https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1
# Current promotions and supported models:
#   https://docs.qwencloud.com/token-plan/personal/token-plan-personal-overview
# References:
#   https://www.alibabacloud.com/help/en/model-studio/claude-code
#   https://docs.qwencloud.com/developer-guides/clients-and-developer-tools/claude-code
function Show-QwenPeakWarning {
    <#
.SYNOPSIS
    Warns when the Qwen Cloud Token Plan night discount is inactive.

.DESCRIPTION
    During the current 08:00-22:00 UTC+8 daytime window, reports the time until
    the qwen3.8-max night discount begins and briefly delays launch. Model calls
    during the night window receive 50% off Credits consumption for a limited time.

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-07
#>
    param(
        [DateTime]$UtcNow = [DateTime]::UtcNow,
        [int]$DelaySeconds = 3
    )

    # The UTC+8 daytime window maps directly to 00:00-14:00 UTC.
    $discountStart = $UtcNow.Date.AddHours(14)
    if ($UtcNow -ge $discountStart) {
        return
    }

    # Ceiling preserves a visible final minute until the night window begins.
    $minutesLeft = [int][Math]::Ceiling(($discountStart - $UtcNow).TotalMinutes)
    Write-Host ("Qwen3.8-max limited-time night discount is inactive (22:00-08:00 UTC+8; 50% off Credits consumption); starts in {0}h {1}m. Launching in 3 seconds..." -f [int][Math]::Floor($minutesLeft / 60), ($minutesLeft % 60)) -ForegroundColor Yellow
    Start-Sleep -Seconds $DelaySeconds
}

function claudeq {
    <#
.SYNOPSIS
    Launches Claude Code through the Qwen Cloud Token Plan endpoint.

.DESCRIPTION
    Reads QWEN_TOKEN_PLAN_API_KEY from the current process, Windows Credential
    Manager, or legacy User environment, then temporarily configures Claude Code
    to use the Qwen 3.7 model profile. Restores the previous environment after
    Claude exits.

.EXAMPLE
    claudeq

.EXAMPLE
    claudeq "Explain the current repository"

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-08
#>
    $key = Get-AiApiKey 'QWEN_TOKEN_PLAN_API_KEY'

    if (-not $key) {
        Write-Host "QWEN_TOKEN_PLAN_API_KEY is not set. Aborting." -ForegroundColor Red
        Write-Host ""
        Write-Host "Please set it securely using: Set-AiApiKeysCS" -ForegroundColor Yellow
        return
    }

    $originalEnvVars = Save-ProcessEnvVars @(
        'ANTHROPIC_BASE_URL', 'ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN',
        'ANTHROPIC_MODEL', 'ANTHROPIC_DEFAULT_FABLE_MODEL', 'ANTHROPIC_DEFAULT_HAIKU_MODEL',
        'ANTHROPIC_DEFAULT_SONNET_MODEL', 'ANTHROPIC_DEFAULT_OPUS_MODEL',
        'CLAUDE_CODE_SUBAGENT_MODEL', 'CLAUDE_CODE_EFFORT_LEVEL',
        'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC',
        'CLAUDE_CODE_MAX_CONTEXT_TOKENS', 'CLAUDE_CODE_USE_POWERSHELL_TOOL'
    )

    $env:ANTHROPIC_BASE_URL = 'https://token-plan.ap-southeast-1.maas.aliyuncs.com/apps/anthropic'
    $env:ANTHROPIC_AUTH_TOKEN = $key
    Remove-Item Env:\ANTHROPIC_API_KEY -ErrorAction SilentlyContinue

    $env:ANTHROPIC_MODEL = 'qwen3.7-max'
    $env:ANTHROPIC_DEFAULT_FABLE_MODEL = 'qwen3.8-max'
    $env:ANTHROPIC_DEFAULT_HAIKU_MODEL = 'qwen3.6-flash'
    $env:ANTHROPIC_DEFAULT_SONNET_MODEL = 'qwen3.7-plus'
    $env:ANTHROPIC_DEFAULT_OPUS_MODEL = 'qwen3.7-max'
    $env:CLAUDE_CODE_SUBAGENT_MODEL = 'qwen3.7-max'
    $env:CLAUDE_CODE_EFFORT_LEVEL = 'xhigh'
    $env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = '1'
    $env:CLAUDE_CODE_MAX_CONTEXT_TOKENS = '983616'
    $env:CLAUDE_CODE_USE_POWERSHELL_TOOL = '1'
    try {
        Install-GlobalClaudeMd
        Install-GlobalClaudeSettings
        Show-QwenPeakWarning
        claude @args
    }
    finally {
        Restore-ProcessEnvVars $originalEnvVars
    }
}

function claudeqd {
    <#
.SYNOPSIS
    Launches claudeq with permissions skipped.

.DESCRIPTION
    Forwards all arguments to claudeq and appends --dangerously-skip-permissions.

.EXAMPLE
    claudeqd

.EXAMPLE
    claudeqd "Explain the current repository"

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-07
#>
    $claudeArgs = $args + '--dangerously-skip-permissions'
    claudeq @claudeArgs
}

function claudeq2 {
    <#
.SYNOPSIS
    Launches Claude Code through the Qwen Cloud Token Plan Qwen 3.8 Max profile.

.DESCRIPTION
    Reads QWEN_TOKEN_PLAN_API_KEY from the current process, Windows Credential
    Manager, or legacy User environment, then temporarily configures Claude Code
    to use Qwen 3.8 Max with Qwen 3.7 and 3.6 fallback routing. Restores
    the previous environment after Claude exits.

.EXAMPLE
    claudeq2

.EXAMPLE
    claudeq2 "Explain the current repository"

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-08
#>
    $key = Get-AiApiKey 'QWEN_TOKEN_PLAN_API_KEY'

    if (-not $key) {
        Write-Host "QWEN_TOKEN_PLAN_API_KEY is not set. Aborting." -ForegroundColor Red
        Write-Host ""
        Write-Host "Please set it securely using: Set-AiApiKeysCS" -ForegroundColor Yellow
        return
    }

    $originalEnvVars = Save-ProcessEnvVars @(
        'ANTHROPIC_BASE_URL', 'ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN',
        'ANTHROPIC_MODEL', 'ANTHROPIC_DEFAULT_FABLE_MODEL', 'ANTHROPIC_DEFAULT_HAIKU_MODEL',
        'ANTHROPIC_DEFAULT_SONNET_MODEL', 'ANTHROPIC_DEFAULT_OPUS_MODEL',
        'CLAUDE_CODE_SUBAGENT_MODEL', 'CLAUDE_CODE_EFFORT_LEVEL',
        'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC',
        'CLAUDE_CODE_MAX_CONTEXT_TOKENS', 'CLAUDE_CODE_USE_POWERSHELL_TOOL'
    )

    $env:ANTHROPIC_BASE_URL = 'https://token-plan.ap-southeast-1.maas.aliyuncs.com/apps/anthropic'
    $env:ANTHROPIC_AUTH_TOKEN = $key
    Remove-Item Env:\ANTHROPIC_API_KEY -ErrorAction SilentlyContinue

    $env:ANTHROPIC_MODEL = 'qwen3.8-max'
    $env:ANTHROPIC_DEFAULT_FABLE_MODEL = 'qwen3.8-max'
    $env:ANTHROPIC_DEFAULT_HAIKU_MODEL = 'qwen3.6-flash'
    $env:ANTHROPIC_DEFAULT_SONNET_MODEL = 'qwen3.8-max'
    $env:ANTHROPIC_DEFAULT_OPUS_MODEL = 'qwen3.8-max'
    $env:CLAUDE_CODE_SUBAGENT_MODEL = 'qwen3.7-max'
    $env:CLAUDE_CODE_EFFORT_LEVEL = 'xhigh'
    $env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = '1'
    $env:CLAUDE_CODE_MAX_CONTEXT_TOKENS = '983616'
    $env:CLAUDE_CODE_USE_POWERSHELL_TOOL = '1'
    try {
        Install-GlobalClaudeMd
        Install-GlobalClaudeSettings
        Show-QwenPeakWarning
        claude @args
    }
    finally {
        Restore-ProcessEnvVars $originalEnvVars
    }
}

function claudeq2d {
    <#
.SYNOPSIS
    Launches claudeq2 with permissions skipped.

.DESCRIPTION
    Forwards all arguments to claudeq2 and appends --dangerously-skip-permissions.

.EXAMPLE
    claudeq2d

.EXAMPLE
    claudeq2d "Explain the current repository"

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-07
#>
    $claudeArgs = $args + '--dangerously-skip-permissions'
    claudeq2 @claudeArgs
}

function Install-ClaudeCCRSetup {
    <#
.SYNOPSIS
    Configures Claude Code Router for the local multi-provider Claude Code profile.

.DESCRIPTION
    Creates ~/.claude-code-router/config.json (or rewrites it with -Force) wiring Z.AI, MiniMax,
    DeepSeek, and Gemini as providers, and routing default/background/think/longContext/image
    roles to the user's preferred GLM model tiers. webSearch routes to Gemini Flash for Google
    search grounding. API keys are stored as $ENV references in the config; the launcher
    exposes the resolved values from the Credential Manager just-in-time.

    This setup also runs the shared Claude Code global setup and the existing Z.AI/MiniMax MCP
    setup helpers so cccr can use the same MCP servers as claudez and claudemm.

.PARAMETER ZaiToken
    Z.AI token. Defaults to Get-AiApiKey 'ZAI_API_KEY'.

.PARAMETER MiniMaxKey
    MiniMax API key. Defaults to Get-AiApiKey 'MINIMAX_API_KEY'. Optional; if missing, MiniMax
    is omitted from Providers and the longContext route falls back to DeepSeek.

.PARAMETER DeepSeekKey
    DeepSeek API key. Defaults to Get-AiApiKey 'DEEPSEEK_API_KEY'. Optional; required only if
    longContext would otherwise have no fallback provider.

.PARAMETER GeminiKey
    Google Gemini API key. Defaults to Get-AiApiKey 'GEMINI_API_KEY'. Optional; if missing, the
    Gemini provider is omitted (and the webSearch router role becomes a no-op).

.PARAMETER Force
    Rewrites config.json and re-runs nested setup helpers even when sentinel files exist.

.EXAMPLE
    Install-ClaudeCCRSetup

.EXAMPLE
    Install-ClaudeCCRSetup -Force

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-08
#>
    [CmdletBinding()]
    param(
        [string]$ZaiToken,
        [string]$MiniMaxKey,
        [string]$DeepSeekKey,
        [string]$GeminiKey,
        [switch]$Force
    )

    if ([string]::IsNullOrWhiteSpace($ZaiToken))    { $ZaiToken    = Get-AiApiKey 'ZAI_API_KEY' }
    if ([string]::IsNullOrWhiteSpace($MiniMaxKey))  { $MiniMaxKey  = Get-AiApiKey 'MINIMAX_API_KEY' }
    if ([string]::IsNullOrWhiteSpace($DeepSeekKey)) { $DeepSeekKey = Get-AiApiKey 'DEEPSEEK_API_KEY' }
    if ([string]::IsNullOrWhiteSpace($GeminiKey))   { $GeminiKey   = Get-AiApiKey 'GEMINI_API_KEY' }

    if (-not $GeminiKey) {
        Write-Host "cccr: GEMINI_API_KEY not set -- Gemini provider and webSearch route skipped" -ForegroundColor Yellow
    }

    if (-not $ZaiToken) {
        Write-Host "ZAI_API_KEY is not set. Aborting CCR setup." -ForegroundColor Red
        Write-Host ""
        Write-Host "Please set it securely using: Set-AiApiKeysCS" -ForegroundColor Yellow
        return $false
    }

    $ccrDir     = Join-Path $HOME '.claude-code-router'
    $configJson = Join-Path $ccrDir 'config.json'
    $setupFlag  = Join-Path $ccrDir '.cccr_setup_complete'

    if (-not (Test-Path -LiteralPath $ccrDir)) {
        $null = New-Item -ItemType Directory -Path $ccrDir -Force
    }

    # Run shared Claude Code global setup + the existing provider MCP setup helpers so cccr
    # has the same ~/.claude/CLAUDE.md, settings.json, and MCP servers as claudez/claudemm.
    Install-GlobalClaudeMd
    Install-GlobalClaudeSettings
    [void](Install-ClaudezSetup -Token $ZaiToken -Force:$Force)

    if ($MiniMaxKey) {
        [void](Install-ClaudemmSetup -Token $MiniMaxKey -Force:$Force)
    }
    else {
        Write-Host "cccr: MINIMAX_API_KEY not set -- MiniMax MCP setup skipped" -ForegroundColor Yellow
    }

    # Skip config rewrite when both the sentinel and config.json exist and -Force was not passed.
    $alreadyConfigured = (Test-Path -LiteralPath $setupFlag) -and (Test-Path -LiteralPath $configJson) -and -not $Force
    if ($alreadyConfigured) {
        Write-Host "cccr: CCR config setup already done -- skipping"
        return $true
    }

    # Pick the long-context provider. MiniMax is preferred (1M context); otherwise DeepSeek.
    # The model slot is derived from the provider's first model in $_CcrInternal so editing the model
    # list above is enough -- no second place to update.
    $longContextRoute = $null
    if ($MiniMaxKey) {
        $longContextRoute = '{0},{1}' -f 'minimax', $_CcrInternal.Providers.minimax.models[0]
    }
    elseif ($DeepSeekKey) {
        $proModel = $_CcrInternal.Providers.deepseek.models | Where-Object { $_ -like '*pro*' } | Select-Object -First 1
        if (-not $proModel) { $proModel = $_CcrInternal.Providers.deepseek.models[0] }
        $longContextRoute = '{0},{1}' -f 'deepseek', $proModel
    }
    else {
        Write-Host "cccr: no MiniMax or DeepSeek key -- longContext will fall through to default" -ForegroundColor Yellow
    }

    # Always (re)write the config when sentinel is missing or -Force was passed, OR when the
    # user has never had a config.json. If a stale config.json exists without a sentinel we
    # still rewrite it so the env-var interpolation stays in sync with current credentials.
    $shouldWriteConfig = $Force -or -not (Test-Path -LiteralPath $setupFlag)
    if ((Test-Path -LiteralPath $configJson) -and -not $shouldWriteConfig) {
        Write-Host "cccr: existing config.json found -- leaving it unchanged" -ForegroundColor Yellow
        Write-Host "cccr: use Install-ClaudeCCRSetup -Force to rewrite it" -ForegroundColor DarkGray
    }

    if ($shouldWriteConfig) {
        if (Test-Path -LiteralPath $configJson) {
            # Bump existing config out of the way so a broken rewrite is recoverable.
            $backupPath = "$configJson.$(Get-Date -Format 'yyyyMMddHHmmss').bak"
            Copy-Item -LiteralPath $configJson -Destination $backupPath -Force
            Write-Host "cccr: backed up existing config to $backupPath" -ForegroundColor DarkGray
        }

        $router = [ordered]@{
            default              = $_CcrInternal.Router.default
            background           = $_CcrInternal.Router.background
            think                = $_CcrInternal.Router.think
            longContextThreshold = $_CcrInternal.Threshold
        }
        if ($longContextRoute)  { $router['longContext'] = $longContextRoute }
        if ($MiniMaxKey)        { $router['image']       = '{0},{1}' -f 'minimax', $_CcrInternal.Providers.minimax.models[0] }
        if ($GeminiKey)         { $router['webSearch']   = $_CcrInternal.Router.webSearch }

        # Provider order in the generated config. Each entry is included only when the matching
        # API key is available; zai is always present since the launcher requires it.
        $providers = foreach ($pName in @('zai', 'minimax', 'deepseek', 'gemini')) {
            $hasKey = switch ($pName) {
                'zai'     { $true }
                'minimax' { [bool]$MiniMaxKey }
                'deepseek'{ [bool]$DeepSeekKey }
                'gemini'  { [bool]$GeminiKey }
            }
            if (-not $hasKey) { continue }
            $p = $_CcrInternal.Providers[$pName]
            [ordered]@{
                name         = $pName
                # Anthropic transformer passes through, so use the FULL endpoint URL (incl.
                # /v1/messages). The base URL used by claudez intentionally omits the suffix
                # because Claude Code's Anthropic client appends it for you.
                api_base_url = $p.base
                api_key      = $p.key
                models       = $p.models
                transformer  = [ordered]@{ use = @($p.transformer) }
            }
        }

        $config = [ordered]@{
            PORT           = $_CcrInternal.Port
            HOST           = $_CcrInternal.Host
            LOG            = $_CcrInternal.Log
            API_TIMEOUT_MS = $_CcrInternal.Timeout
            Providers      = $providers
            Router         = $router
        }

        # No-BOM UTF-8 so the file is valid JSON and CCR's JSON5 reader stays happy.
        $json = $config | ConvertTo-Json -Depth 20
        [IO.File]::WriteAllText($configJson, $json, [Text.UTF8Encoding]::new($false))
        Write-Host "cccr: wrote CCR config to $configJson" -ForegroundColor Green
    }

    $flagInfo = @(
        "configuredAt=$(Get-Date -Format o)"
        "user=$env:USERNAME"
        "configJson=$configJson"
        'mode=CCR'
        "default=$($_CcrInternal.Router.default)"
        "background=$($_CcrInternal.Router.background)"
        "think=$($_CcrInternal.Router.think)"
        "webSearch=$(if ($GeminiKey) { $_CcrInternal.Router.webSearch } else { '<unset>' })"
        "longContext=$(if ($longContextRoute) { $longContextRoute } else { '<unset>' })"
    ) -join "`r`n"
    Set-Content -LiteralPath $setupFlag -Value $flagInfo -Encoding UTF8
    Write-Host 'cccr: CCR setup complete' -ForegroundColor Green
    return $true
}

function cccr {
    <#
.SYNOPSIS
    Launches Claude Code through Claude Code Router (CCR).

.DESCRIPTION
    Ensures the local CCR config/MCP setup exists, exposes provider API keys to the current
    process so CCR's $VAR interpolation resolves them, starts/restarts the local CCR service,
    points Claude Code at http://127.0.0.1:3456, then invokes claude with the supplied arguments.

    Pass -Force or --force-ccr-setup to rewrite the CCR config and re-run nested setup helpers.

.EXAMPLE
    cccr

.EXAMPLE
    cccr "Explain the current repository"

.EXAMPLE
    cccr -Force

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-08
#>
    # Strip the CCR-only force flag from the forwarded claude args so /model etc. still work.
    $forceSetup   = $false
    $claudeArgArr = @()
    foreach ($arg in $args) {
        if ($arg -in @('-Force', '--force-ccr-setup')) { $forceSetup = $true }
        else                                           { $claudeArgArr += $arg }
    }

    $zaiToken    = Get-AiApiKey 'ZAI_API_KEY'
    if (-not $zaiToken) {
        Write-Host "ZAI_API_KEY is not set. Aborting." -ForegroundColor Red
        Write-Host ""
        Write-Host "Please set it securely using: Set-AiApiKeysCS" -ForegroundColor Yellow
        return
    }
    $miniMaxKey  = Get-AiApiKey 'MINIMAX_API_KEY'
    $deepSeekKey = Get-AiApiKey 'DEEPSEEK_API_KEY'
    $geminiKey   = Get-AiApiKey 'GEMINI_API_KEY'

    # Snapshot every env var we may transiently mutate so the caller's session is untouched
    # once claude exits (or this function returns early).
    $originalEnvVars = Save-ProcessEnvVars @(
        'ZAI_API_KEY', 'MINIMAX_API_KEY', 'DEEPSEEK_API_KEY', 'GEMINI_API_KEY',
        'ANTHROPIC_BASE_URL', 'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_API_KEY',
        'ANTHROPIC_MODEL', 'ANTHROPIC_DEFAULT_HAIKU_MODEL', 'ANTHROPIC_DEFAULT_SONNET_MODEL',
        'ANTHROPIC_DEFAULT_OPUS_MODEL', 'API_TIMEOUT_MS', 'NO_PROXY',
        'DISABLE_TELEMETRY', 'DISABLE_COST_WARNINGS',
        'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC', 'CLAUDE_CODE_DISABLE_1M_CONTEXT',
        'CLAUDE_CODE_USE_POWERSHELL_TOOL',
        'CLAUDE_CODE_SUBAGENT_MODEL', 'CLAUDE_CODE_EFFORT_LEVEL',
        'ENABLE_PROMPT_CACHING_1H'
    )

    try {
        # CCR reads provider api_key values from the env at startup. The keys normally live in
        # the Windows Credential Manager; surface them as process env so $ZAI_API_KEY, etc.
        # resolve inside config.json. They are torn down in the finally block.
        $env:ZAI_API_KEY = $zaiToken
        if ($miniMaxKey)  { $env:MINIMAX_API_KEY  = $miniMaxKey }
        if ($deepSeekKey) { $env:DEEPSEEK_API_KEY = $deepSeekKey }
        if ($geminiKey)   { $env:GEMINI_API_KEY   = $geminiKey }

        if (-not (Install-ClaudeCCRSetup -ZaiToken $zaiToken -MiniMaxKey $miniMaxKey -DeepSeekKey $deepSeekKey -GeminiKey $geminiKey -Force:$forceSetup)) {
            return
        }

        if (-not (Get-Command ccr -ErrorAction SilentlyContinue)) {
            Write-Host 'ccr CLI not found.' -ForegroundColor Red
            Write-Host 'Install via: npm install -g @musistudio/claude-code-router' -ForegroundColor Yellow
            return
        }
        if (-not (Get-Command claude -ErrorAction SilentlyContinue)) {
            Write-Host 'claude CLI not found.' -ForegroundColor Red
            Write-Host 'Install via: irm https://claude.ai/install.ps1 | iex' -ForegroundColor Yellow
            return
        }

        # `ccr restart` is the documented way to apply config changes; fall back to `ccr start`
        # for the first launch (when no process exists yet) since some CCR builds reject restart
        # in that case.
        $restartOutput = & ccr restart 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host 'cccr: ccr restart did not complete cleanly; trying ccr start...' -ForegroundColor Yellow
            $startOutput = & ccr start 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Host 'cccr: failed to start Claude Code Router.' -ForegroundColor Red
                if ($restartOutput) { $restartOutput | ForEach-Object { Write-Host $_ } }
                if ($startOutput)   { $startOutput   | ForEach-Object { Write-Host $_ } }
                return
            }
        }

        # Point Claude Code at the local CCR proxy. ANTHROPIC_AUTH_TOKEN is a placeholder --
        # CCR forwards the real provider key, so the value here is never validated. Clearing
        # ANTHROPIC_API_KEY prevents a User-scope Anthropic key from taking precedence.
        $env:ANTHROPIC_BASE_URL    = 'http://127.0.0.1:3456'
        $env:ANTHROPIC_AUTH_TOKEN  = 'ccr-local-router'
        $env:ANTHROPIC_API_KEY     = ''
        $env:API_TIMEOUT_MS        = '3000000'
        $env:DISABLE_TELEMETRY     = '1'
        $env:DISABLE_COST_WARNINGS = '1'
        $env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = '1'
        # Request 1-hour prompt-cache TTL (API-key backends default to 5m; opt in explicitly)
        $env:ENABLE_PROMPT_CACHING_1H = '1'
        # Allow 1M context only when MiniMax is in the longContext route.
        $env:CLAUDE_CODE_DISABLE_1M_CONTEXT = if ($miniMaxKey) { '0' } else { '1' }
        $env:CLAUDE_CODE_USE_POWERSHELL_TOOL = '1'

        # Route the local CCR endpoint around any system HTTP proxy to avoid CONNECT failures.
        $noProxyItems = @()
        if ($env:NO_PROXY) { $noProxyItems += $env:NO_PROXY -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } }
        foreach ($hostName in @('127.0.0.1', 'localhost')) {
            if ($noProxyItems -notcontains $hostName) { $noProxyItems += $hostName }
        }
        $env:NO_PROXY = $noProxyItems -join ','

        claude @claudeArgArr
    }
    finally {
        Restore-ProcessEnvVars $originalEnvVars
    }
}

function cccrd {
    <#
.SYNOPSIS
    Launches cccr with permissions skipped.

.DESCRIPTION
    Forwards all arguments to cccr and appends --dangerously-skip-permissions.

.EXAMPLE
    cccrd

.EXAMPLE
    cccrd "Explain the current repository"

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-06
#>
    $claudeArgs = $args + '--dangerously-skip-permissions'
    cccr @claudeArgs
}

function Invoke-RemoteClaudeCodeMM {
    <#
.SYNOPSIS
Runs Claude Code on a remote SSH endpoint via MiniMax with temporary remote state.

.DESCRIPTION
Reads the API key from MINIMAX_API_KEY if not provided, then runs the remote
Claude launcher with MiniMax endpoint defaults. The remote invocation always
uses --dangerously-skip-permissions.

.PARAMETER RemoteHost
SSH hostname, IP address, or legacy user@host target.

.PARAMETER RemoteUser
Optional SSH login name. Do not use this with a user@host RemoteHost value.

.PARAMETER ApiKey
MiniMax API key for the remote session.
Optional -- falls back to MINIMAX_API_KEY env var.

.PARAMETER Port
SSH port to connect to. Defaults to 22.

.PARAMETER KeyFile
Path to an OpenSSH or PuTTY PPK private key.

.EXAMPLE
Invoke-RemoteClaudeCodeMM remote-host -RemoteUser user

.EXAMPLE
Invoke-RemoteClaudeCodeMM -RemoteHost user@remote-host -ApiKey $env:MINIMAX_API_KEY

.NOTES
Author: jjw(@thejjw)
Last Edit: 2026-05
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$RemoteHost,

        [string]$ApiKey,

        [int]$Port = 22,

        # Optional: SSH private key file for authentication.
        [string]$KeyFile,

        [string]$RemoteUser
    )

    if ([string]::IsNullOrWhiteSpace($ApiKey)) {
        $ApiKey = Get-AiApiKey 'MINIMAX_API_KEY'
    }

    if (-not $ApiKey) {
        Write-Host "MINIMAX_API_KEY is not set. Aborting." -ForegroundColor Red
        Write-Host ""
        Write-Host "Please set it securely using: Set-AiApiKeysCS" -ForegroundColor Yellow
        return
    }

    # All three model tiers map to the same MiniMax model; Claude Code selects
    # the tier internally and MiniMax routes accordingly.
    $BaseUrl = "https://api.minimax.io/anthropic"
    $HaikuModel = "MiniMax-M3[1m]"
    $SonnetModel = "MiniMax-M3[1m]"
    $OpusModel = "MiniMax-M3[1m]"
    # 50-minute timeout -- MiniMax inference can be slow for complex agentic loops.
    $TimeoutMs = "3000000"
    $Disable1M = "0"

    # Build the splat hashtable and optionally attach KeyFile so a single
    # Invoke-RemoteClaudeCodeBase call covers both key-file and API-key modes.
    $baseParams = @{
        RemoteHost  = $RemoteHost
        ApiKey      = $ApiKey
        Port        = $Port
        BaseUrl     = $BaseUrl
        HaikuModel  = $HaikuModel
        SonnetModel = $SonnetModel
        OpusModel   = $OpusModel
        TimeoutMs   = $TimeoutMs
        Disable1M   = $Disable1M
    }
    if (-not [string]::IsNullOrWhiteSpace($KeyFile)) { $baseParams['KeyFile'] = $KeyFile }
    if (-not [string]::IsNullOrWhiteSpace($RemoteUser)) { $baseParams['RemoteUser'] = $RemoteUser }
    Invoke-RemoteClaudeCodeBase @baseParams
}

function Get-ScriptFunction {
    <#
.SYNOPSIS
    Lists top-level functions defined by a PowerShell script.
.DESCRIPTION
    Parses the script with the PowerShell AST and returns function/filter names
    declared in the script's root script block as a numbered table, with a
    single total count line and a short Get-Help synopsis when that function is
    already loaded in the current session. The script is not executed, so dynamic
    definitions made through aliases, variables, Invoke-Expression, or imported
    files are not reported.
.PARAMETER Path
    One or more PowerShell script paths to inspect.
.PARAMETER DescriptionLength
    Maximum number of characters to show from each Get-Help synopsis.
.PARAMETER NameOnly
    Returns only function names without Get-Help descriptions.
.EXAMPLE
    PS C:\> Get-ScriptFunction $PROFILE
    Lists functions callable after the current profile is loaded as a table.
.EXAMPLE
    PS C:\> Get-ScriptFunction $PROFILE -NameOnly
    Lists only the function names.
.OUTPUTS
    System.Management.Automation.PSCustomObject. Function rows with number,
    name, and help synopsis text. System.String when -NameOnly is used.
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-07
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('FullName')]
        [string[]]$Path,

        [ValidateRange(0, 500)]
        [int]$DescriptionLength = 80,

        [switch]$NameOnly
    )

    process {
        foreach ($inputPath in $Path) {
            $resolvedPath = (Resolve-Path -LiteralPath $inputPath -ErrorAction Stop).ProviderPath
            $tokens = $null
            $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($resolvedPath, [ref]$tokens, [ref]$errors)

            if ($errors) {
                $message = ($errors | ForEach-Object {
                    '{0}:{1}: {2}' -f $_.Extent.StartLineNumber, $_.Extent.StartColumnNumber, $_.Message
                }) -join [Environment]::NewLine
                Write-Error "Failed to parse '$resolvedPath': $message"
                continue
            }

            $functionNames = @($ast.FindAll({
                param($node)

                if ($node -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) {
                    return $false
                }

                # Nested functions belong to another ScriptBlockAst, so exclude them.
                $parent = $node.Parent
                while ($parent -and ($parent -isnot [System.Management.Automation.Language.ScriptBlockAst])) {
                    $parent = $parent.Parent
                }

                return [object]::ReferenceEquals($parent, $ast)
            }, $true) |
                ForEach-Object {
                    ([string]$_.Name) -replace '^(global|local|private|script):', ''
                } |
                Sort-Object -Unique)

            if ($NameOnly) {
                $functionNames
                continue
            }

            $functionCount = $functionNames.Count
            if ($functionCount -eq 0) { continue }
            $functionIndex = 0
            Write-Host ('Total functions: {0}' -f $functionCount) -ForegroundColor DarkGray

            foreach ($functionName in $functionNames) {
                $functionIndex++
                $description = ''
                if (Get-Command -Name $functionName -CommandType Function -ErrorAction SilentlyContinue) {
                    $help = Get-Help -Name $functionName -ErrorAction SilentlyContinue
                    if ($help) {
                        $synopsis = ([string]$help.Synopsis -replace '\s+', ' ').Trim()
                        $syntaxPattern = '^{0}(\s|\[|$)' -f [regex]::Escape($functionName)
                        if ($synopsis -and ($synopsis -notmatch $syntaxPattern)) {
                            $description = $synopsis
                        }
                    }
                }

                if ($DescriptionLength -gt 0 -and $description.Length -gt $DescriptionLength) {
                    $clipLength = [Math]::Max(0, $DescriptionLength - 3)
                    $description = $description.Substring(0, $clipLength) + '...'
                }

                [pscustomobject]@{
                    No          = $functionIndex
                    Name        = $functionName
                    Description = $description
                }
            }
        }
    }
}

function Update-Profile {
    <#
.SYNOPSIS
    Updates the current PowerShell profile ($PROFILE) from the remote repository.
.DESCRIPTION
    Downloads the latest version of the PowerShell profile from the GitHub repository
    and overwrites the local $PROFILE file.
.EXAMPLE
    Update-Profile
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-05
#>
    [CmdletBinding()]
    param()

    # Validate that $_ProfileUpdateUrl is set
    if (-not $_ProfileUpdateUrl) {
        Write-Error "Profile update URL is not defined (`$_ProfileUpdateUrl)."
        return
    }

    # Fetch just enough commit metadata to show which version we are updating from.
    # --filter=blob:none avoids downloading file content, saving bandwidth.
    if ((Get-Command git -ErrorAction SilentlyContinue) -and
        ($_ProfileUpdateUrl -match 'raw\.githubusercontent\.com/([^/]+/[^/]+)/refs/heads/[^/]+/(.+)')) {
        $tmpDir = $null
        try {
            $repoUrl  = "https://github.com/$($Matches[1]).git"
            $filePath = $Matches[2]
            $tmpDir   = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
            git clone --filter=blob:none --no-checkout --quiet $repoUrl $tmpDir
            $commitInfo = git -C $tmpDir log -1 --format="Remote commit at %cs, [%h]  %s" -- $filePath
            if ($commitInfo) {
                Write-Host $commitInfo -ForegroundColor DarkGray
            }
        } catch {
        } finally {
            if ($tmpDir -and (Test-Path $tmpDir)) {
                Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
            }
        }
    }

    Write-Host "Updating profile from $_ProfileUpdateUrl..." -ForegroundColor Cyan
    $tempFile = $null
    try {
        # Download to a temp file first; only overwrite $PROFILE on success to avoid corruption
        $tempFile = [System.IO.Path]::GetTempFileName()
        $downloadResponse = Invoke-WebRequest2 -Uri $_ProfileUpdateUrl -OutFile $tempFile -UseBasicParsing -PassThru
        $contentEncoding = $downloadResponse.Headers['Content-Encoding']
        if (-not $contentEncoding) { $contentEncoding = 'identity' }
        $wireBytes = $downloadResponse.Headers['Content-Length']
        $decodedBytes = (Get-Item -LiteralPath $tempFile).Length
        if ($wireBytes) {
            Write-Host ("Downloaded {0} bytes over the wire using {1} ({2} bytes after decoding)." -f $wireBytes, $contentEncoding, $decodedBytes) -ForegroundColor DarkGray
        } else {
            Write-Host ("Downloaded profile using {0} ({1} bytes after decoding)." -f $contentEncoding, $decodedBytes) -ForegroundColor DarkGray
        }
        # .NET Copy with overwrite is more reliable than Move-Item -Force in PS 5.1,
        # which can throw IndexOutOfRangeException when replacing a larger file
        # (and hides the real error inside a broken Out-LineOutput formatter).
        [System.IO.File]::Copy($tempFile, $PROFILE, $true)
        Write-Host "Profile updated successfully! Restart your shell or run '. `$PROFILE' to apply changes." -ForegroundColor Green
    }
    catch {
        $msg = if ($_.Exception -and $_.Exception.Message) { $_.Exception.Message } else { "$_" }
        Write-Error "Failed to update profile: $msg"
    }
    finally {
        if ($tempFile -and (Test-Path $tempFile)) {
            Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
        }
    }
}

Set-Alias -Name updp -Value Update-Profile

function Install-AiSkills {
    <#
.SYNOPSIS
    Installs public AI skills from the thejjw repository.
.DESCRIPTION
    Uses a shallow, blobless, sparse Git clone to fetch only the ai-skills
    directory from the thejjw repository, then overwrites the configured skill
    directories for OpenCode, Claude Code, Antigravity App/IDE, Antigravity CLI,
    and Codex. External
    skill sources configured in $_AiSkillsInternal.ExternalSources are
    shallow-cloned to their tip commit and installed into every tool's skill
    directory. Existing named skill directories are replaced so repeat manual
    runs refresh changed files and remove stale files. An unavailable external
    source warns and is skipped without blocking the internal skills.
.PARAMETER RepoUrl
    Git repository URL that contains the ai-skills directory.
.PARAMETER Branch
    Branch to clone from the repository.
.PARAMETER KeepTemp
    Preserves the temporary sparse clone for debugging.
.EXAMPLE
    Install-AiSkills
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-08
#>
    [CmdletBinding()]
    param(
        [string]$RepoUrl = $_AiSkillsInternal.RepoUrl,
        [string]$Branch = $_AiSkillsInternal.Branch,
        [switch]$KeepTemp
    )

    $tmpDir = $null

    $openCodeClaudeSkills = $_AiSkillsInternal.OpenCodeClaudeSkills
    $antigravitySharedSkills = $_AiSkillsInternal.AntigravitySharedSkills
    $antigravityCliSkills = @($antigravitySharedSkills + $_AiSkillsInternal.AntigravityCliOnlySkills | Select-Object -Unique)
    $codexSkills = $_AiSkillsInternal.CodexSkills

    $openCodeSkillsDir = Join-Path $env:USERPROFILE $_AiSkillsInternal.OpenCodeSkillsPath
    $claudeSkillsDir = Join-Path $env:USERPROFILE $_AiSkillsInternal.ClaudeSkillsPath
    $antigravityTargets = @(
        @{
            ToolName        = 'Antigravity Windows App and IDE'
            DestinationRoot = Join-Path $env:USERPROFILE $_AiSkillsInternal.AntigravityAppSkillsPath
            Skills          = $antigravitySharedSkills
        },
        @{
            ToolName        = 'Antigravity CLI'
            DestinationRoot = Join-Path $env:USERPROFILE $_AiSkillsInternal.AntigravityCliSkillsPath
            Skills          = $antigravityCliSkills
        }
    )
    $codexHome = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $env:USERPROFILE '.codex' }
    $codexSkillsDir = Join-Path $codexHome $_AiSkillsInternal.CodexSkillsPath
    $openCodeConfigFile = Join-Path $env:USERPROFILE $_AiSkillsInternal.OpenCodeConfigPath
    $openCodeConfigDir = Split-Path -Parent $openCodeConfigFile

    function Test-ChildPath {
        param(
            [Parameter(Mandatory = $true)]
            [string]$ParentPath,
            [Parameter(Mandatory = $true)]
            [string]$ChildPath
        )

        $parentFull = [System.IO.Path]::GetFullPath($ParentPath).TrimEnd('\')
        $childFull = [System.IO.Path]::GetFullPath($ChildPath).TrimEnd('\')
        return $childFull.StartsWith("$parentFull\", [System.StringComparison]::OrdinalIgnoreCase)
    }

    function Copy-SkillDirectory {
        param(
            [Parameter(Mandatory = $true)]
            [string]$SkillName,
            [Parameter(Mandatory = $true)]
            [string]$SourceRoot,
            [Parameter(Mandatory = $true)]
            [string]$DestinationRoot,
            [Parameter(Mandatory = $true)]
            [string]$ToolName
        )

        $src = Join-Path $SourceRoot $SkillName
        $dst = Join-Path $DestinationRoot $SkillName

        if (-not (Test-Path -LiteralPath $src -PathType Container)) {
            throw "Missing skill source: $src"
        }
        if (-not (Test-Path -LiteralPath (Join-Path $src 'SKILL.md') -PathType Leaf)) {
            throw "Missing SKILL.md for skill '$SkillName': $src"
        }
        if (-not (Test-ChildPath -ParentPath $DestinationRoot -ChildPath $dst)) {
            throw "Refusing to remove destination outside expected skill root: $dst"
        }

        Write-Host "[info] Installing skill '$SkillName' to $ToolName"
        if (-not (Test-Path -LiteralPath $DestinationRoot)) {
            Write-Verbose "Creating skill root: $DestinationRoot"
            $null = New-Item -ItemType Directory -Path $DestinationRoot -Force -ErrorAction Stop
        }

        # Use recoverable sibling directories so an interrupted or failed swap
        # can restore the previous complete installation.
        $staging = "$dst.tmp-install"
        $backup = "$dst.backup-install"

        try {
            if (Test-Path -LiteralPath $backup) {
                if (Test-Path -LiteralPath $dst) {
                    Write-Verbose "Removing stale backup directory: $backup"
                    Remove-Item -LiteralPath $backup -Recurse -Force -ErrorAction Stop
                }
                else {
                    Write-Verbose "Restoring interrupted skill installation from: $backup"
                    Rename-Item -LiteralPath $backup -NewName $SkillName -ErrorAction Stop
                }
            }
            if (Test-Path -LiteralPath $staging) {
                Write-Verbose "Removing stale staging directory: $staging"
                Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction Stop
            }

            Write-Verbose "Staging '$src\*' in '$staging'"
            $null = New-Item -ItemType Directory -Path $staging -Force -ErrorAction Stop
            Copy-Item -Path (Join-Path $src '*') -Destination $staging -Recurse -Force -ErrorAction Stop
            if (-not (Test-Path -LiteralPath (Join-Path $staging 'SKILL.md') -PathType Leaf)) {
                throw "Copy verification failed for skill '$SkillName': $staging"
            }

            if (Test-Path -LiteralPath $dst) {
                Write-Verbose "Backing up existing skill directory: $dst"
                Rename-Item -LiteralPath $dst -NewName (Split-Path -Leaf $backup) -ErrorAction Stop
            }
            Write-Verbose "Moving staged skill into place: $dst"
            Rename-Item -LiteralPath $staging -NewName $SkillName -ErrorAction Stop
            if (Test-Path -LiteralPath $backup) {
                Write-Verbose "Removing replaced skill backup: $backup"
                Remove-Item -LiteralPath $backup -Recurse -Force -ErrorAction Stop
            }
        }
        catch {
            $installError = $_
            if (Test-Path -LiteralPath $backup) {
                try {
                    if (Test-Path -LiteralPath $dst) {
                        Remove-Item -LiteralPath $dst -Recurse -Force -ErrorAction Stop
                    }
                    Rename-Item -LiteralPath $backup -NewName $SkillName -ErrorAction Stop
                    Write-Warning "Restored previous skill installation after failure: $dst"
                }
                catch {
                    Write-Warning "Could not restore previous skill installation; backup remains at: $backup"
                }
            }

            # Best-effort staging cleanup must not mask the original failure.
            if (Test-Path -LiteralPath $staging) {
                Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
                if (Test-Path -LiteralPath $staging) {
                    Write-Warning "Staging directory still exists after cleanup: $staging"
                }
            }
            throw $installError
        }
    }

    function Set-OpenCodeSkillPermissions {
        param(
            [Parameter(Mandatory = $true)]
            [string[]]$SkillNames
        )

        if (-not (Test-Path -LiteralPath $openCodeConfigDir)) {
            Write-Verbose "Creating OpenCode config directory: $openCodeConfigDir"
            $null = New-Item -ItemType Directory -Path $openCodeConfigDir -Force
        }

        if (-not (Test-Path -LiteralPath $openCodeConfigFile)) {
            Write-Verbose "Creating OpenCode config file: $openCodeConfigFile"
            [IO.File]::WriteAllText($openCodeConfigFile, '{}', [Text.UTF8Encoding]::new($false))
        }

        Write-Verbose "Reading OpenCode config: $openCodeConfigFile"
        try {
            $config = Get-Content -LiteralPath $openCodeConfigFile -Raw | ConvertFrom-Json
        }
        catch {
            throw "OpenCode config is not valid JSON: $openCodeConfigFile"
        }

        if (-not $config) {
            $config = [pscustomobject]@{}
        }

        # OpenCode permits scalar forms such as "permission": "allow" and
        # "permission": { "skill": "ask" }. Normalize to the granular object
        # form, preserving any scalar as the wildcard default.
        $permissionProp = $config.PSObject.Properties['permission']
        if (-not $permissionProp -or $null -eq $permissionProp.Value) {
            Write-Verbose "Adding OpenCode permission object"
            $config | Add-Member -NotePropertyName 'permission' -NotePropertyValue ([pscustomobject]@{}) -Force
        }
        elseif ($permissionProp.Value -is [string]) {
            if ($permissionProp.Value -eq 'allow') {
                Write-Verbose "OpenCode permission is already 'allow'; skill permissions not needed."
                return
            }
            Write-Verbose "Converting scalar OpenCode permission '$($permissionProp.Value)' to object form"
            $config.permission = [pscustomobject]@{ '*' = $permissionProp.Value }
        }
        elseif ($permissionProp.Value -isnot [pscustomobject]) {
            throw "OpenCode config 'permission' has unexpected type: $($permissionProp.Value.GetType().Name)"
        }

        $skillProp = $config.permission.PSObject.Properties['skill']
        if (-not $skillProp -or $null -eq $skillProp.Value) {
            Write-Verbose "Adding OpenCode permission.skill object"
            $config.permission | Add-Member -NotePropertyName 'skill' -NotePropertyValue ([pscustomobject]@{}) -Force
        }
        elseif ($skillProp.Value -is [string]) {
            if ($skillProp.Value -eq 'allow') {
                Write-Verbose "OpenCode skill permission is already 'allow'; nothing to change."
                return
            }
            Write-Verbose "Converting scalar OpenCode skill permission '$($skillProp.Value)' to object form"
            $config.permission.skill = [pscustomobject]@{ '*' = $skillProp.Value }
        }
        elseif ($skillProp.Value -isnot [pscustomobject]) {
            throw "OpenCode config 'permission.skill' has unexpected type: $($skillProp.Value.GetType().Name)"
        }

        foreach ($skill in $SkillNames) {
            Write-Verbose "Allowing OpenCode skill permission: $skill"
            $config.permission.skill | Add-Member -NotePropertyName $skill -NotePropertyValue 'allow' -Force
            # 'taste-skill' uses 'design-taste-frontend' as its canonical skill/install name in OpenCode.
            # Explicitly allow 'design-taste-frontend' so permissions apply under both identifiers.
            if ($skill -eq 'taste-skill') {
                $config.permission.skill | Add-Member -NotePropertyName 'design-taste-frontend' -NotePropertyValue 'allow' -Force
            }
        }

        Write-Verbose "Writing updated OpenCode config: $openCodeConfigFile"
        [IO.File]::WriteAllText($openCodeConfigFile, ($config | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
        Write-Host "[info] Updated OpenCode skill permissions."
    }

    # Clones one external skill source down to its tip commit and returns the
    # directory that contains its skill directories. Throws on any git or layout
    # failure; the caller decides whether to warn and skip.
    function Get-ExternalSkillSource {
        param(
            [Parameter(Mandatory = $true)]$Source,
            [Parameter(Mandatory = $true)]
            [string]$CloneRoot
        )

        $name = [string]$Source.Name
        $cloneDir = Join-Path $CloneRoot $name
        if (Test-Path -LiteralPath $cloneDir) {
            throw "Duplicate external skill source name: $name"
        }

        # Tip commit only: shallow, single branch, no tag objects.
        $cloneArgs = @('clone', '--depth', '1', '--single-branch', '--no-tags', '--branch', [string]$Source.Branch, [string]$Source.RepoUrl, $cloneDir)
        $sparsePath = [string]$Source.SparsePath
        if ($sparsePath) {
            # Large monorepo sources: blobless sparse clone fetching only SparsePath.
            $cloneArgs += @('--filter=blob:none', '--sparse')
        }

        Write-Verbose "Cloning external skill source '$name' ($($Source.Branch)) from $($Source.RepoUrl)"
        & git @cloneArgs
        if ($LASTEXITCODE -ne 0) {
            throw "git clone failed with exit code $LASTEXITCODE"
        }

        if ($sparsePath) {
            Write-Verbose "Sparse-checking out '$sparsePath' for external skill source '$name'"
            & git -C $cloneDir sparse-checkout set $sparsePath
            if ($LASTEXITCODE -ne 0) {
                throw "git sparse-checkout failed with exit code $LASTEXITCODE"
            }
            $skillRoot = Join-Path $cloneDir $sparsePath
        }
        else {
            $skillRoot = $cloneDir
        }

        if (-not (Test-Path -LiteralPath $skillRoot -PathType Container)) {
            throw "Clone did not produce expected skill directory: $skillRoot"
        }
        return $skillRoot
    }

    # Installs every fetched external skill source into one tool's skill root.
    # Individual skill failures (upstream rename/removal, disk error) warn and
    # skip that skill only. Returns the skill names actually installed.
    function Install-ExternalSkillSources {
        param(
            # Not mandatory: an empty array is a valid input when every
            # external source failed to clone, and Mandatory parameters
            # reject empty arrays outright.
            [object[]]$Installs,
            [Parameter(Mandatory = $true)]
            [string]$DestinationRoot,
            [Parameter(Mandatory = $true)]
            [string]$ToolName
        )

        $installed = @()
        foreach ($install in $Installs) {
            foreach ($skill in $install.Skills) {
                try {
                    Copy-SkillDirectory -SkillName $skill -SourceRoot $install.SourceDir -DestinationRoot $DestinationRoot -ToolName $ToolName
                    $installed += $skill
                }
                catch {
                    Write-Warning "Skipping external skill '$skill' from source '$($install.Name)' for ${ToolName}: $_"
                }
            }
        }
        return $installed
    }

    try {
        if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
            throw 'git is required but was not found in PATH.'
        }

        $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
        $null = New-Item -ItemType Directory -Path $tmpDir -Force -ErrorAction Stop
        Write-Verbose "Temporary clone root: $tmpDir"

        $internalCloneDir = Join-Path $tmpDir 'thejjw'
        Write-Verbose "Cloning only branch '$Branch' from $RepoUrl"
        & git clone --depth 1 --single-branch --no-tags --branch $Branch --filter=blob:none --sparse $RepoUrl $internalCloneDir
        if ($LASTEXITCODE -ne 0) {
            throw "git clone failed with exit code $LASTEXITCODE"
        }

        Write-Verbose "Sparse-checking out $($_AiSkillsInternal.SparsePath)"
        & git -C $internalCloneDir sparse-checkout set $_AiSkillsInternal.SparsePath
        if ($LASTEXITCODE -ne 0) {
            throw "git sparse-checkout failed with exit code $LASTEXITCODE"
        }

        $skillsSourceDir = Join-Path $internalCloneDir $_AiSkillsInternal.SparsePath
        if (-not (Test-Path -LiteralPath $skillsSourceDir -PathType Container)) {
            throw "Sparse checkout did not produce expected directory: $skillsSourceDir"
        }
        Write-Verbose "Skill source directory: $skillsSourceDir"

        # External sources: fetch each one's tip commit only. An unavailable
        # source warns and is skipped; it must not block the internal skills.
        $externalInstalls = @()
        foreach ($source in $_AiSkillsInternal.ExternalSources) {
            try {
                $sourceDir = Get-ExternalSkillSource -Source $source -CloneRoot $tmpDir
                $externalInstalls += @{
                    Name      = [string]$source.Name
                    SourceDir = $sourceDir
                    Skills    = @($source.Skills)
                }
            }
            catch {
                Write-Warning "External skill source '$($source.Name)' unavailable: $_; skipping."
            }
        }

        foreach ($skill in $openCodeClaudeSkills) {
            Copy-SkillDirectory -SkillName $skill -SourceRoot $skillsSourceDir -DestinationRoot $openCodeSkillsDir -ToolName 'OpenCode'
        }
        $installedExternalOpenCode = @(Install-ExternalSkillSources -Installs $externalInstalls -DestinationRoot $openCodeSkillsDir -ToolName 'OpenCode')

        # Configure OpenCode as soon as its own installation is complete so a
        # failure in another tool cannot leave installed skills inaccessible.
        Set-OpenCodeSkillPermissions -SkillNames ($openCodeClaudeSkills + $installedExternalOpenCode)

        foreach ($skill in $openCodeClaudeSkills) {
            Copy-SkillDirectory -SkillName $skill -SourceRoot $skillsSourceDir -DestinationRoot $claudeSkillsDir -ToolName 'Claude Code'
        }
        $null = Install-ExternalSkillSources -Installs $externalInstalls -DestinationRoot $claudeSkillsDir -ToolName 'Claude Code'

        foreach ($target in $antigravityTargets) {
            foreach ($skill in $target.Skills) {
                Copy-SkillDirectory -SkillName $skill -SourceRoot $skillsSourceDir -DestinationRoot $target.DestinationRoot -ToolName $target.ToolName
            }
            $null = Install-ExternalSkillSources -Installs $externalInstalls -DestinationRoot $target.DestinationRoot -ToolName $target.ToolName
        }

        foreach ($skill in $codexSkills) {
            Copy-SkillDirectory -SkillName $skill -SourceRoot $skillsSourceDir -DestinationRoot $codexSkillsDir -ToolName 'Codex'
        }
        $null = Install-ExternalSkillSources -Installs $externalInstalls -DestinationRoot $codexSkillsDir -ToolName 'Codex'

        Write-Host ""
        Write-Host "[done] Installed AI skills:" -ForegroundColor Green
        Write-Host "  OpenCode and Claude Code: $($openCodeClaudeSkills -join ', ')"
        Write-Host "  Antigravity Windows App and IDE: $($antigravitySharedSkills -join ', ')"
        Write-Host "  Antigravity CLI: $($antigravityCliSkills -join ', ')"
        Write-Host "  Codex: $($codexSkills -join ', ')"
        foreach ($install in $externalInstalls) {
            Write-Host "  All tools [$($install.Name)]: $($install.Skills -join ', ')"
        }
    }
    catch {
        Write-Host "[error] Install-AiSkills failed: $_" -ForegroundColor Red
        throw
    }
    finally {
        if ($tmpDir -and (Test-Path -LiteralPath $tmpDir)) {
            if ($KeepTemp) {
                Write-Verbose "Keeping temporary clone for debugging: $tmpDir"
            }
            else {
                Write-Verbose "Removing temporary clone: $tmpDir"
                # Best-effort cleanup; must not mask an in-flight failure.
                Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
                if (Test-Path -LiteralPath $tmpDir) {
                    Write-Warning "Temporary clone still exists after cleanup: $tmpDir"
                }
                else {
                    Write-Verbose "Temporary clone removed successfully."
                }
            }
        }
    }
}

function Add-UserPathEntry {
    <#
.SYNOPSIS
    Adds a directory to the current user's PATH when it is not already present.
.DESCRIPTION
    Preserves the registry value as ExpandString and also updates the current
    PowerShell process so newly available commands can be used immediately.
.PARAMETER Path
    Directory to add to the user PATH.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $normalizedPath = $Path.TrimEnd('\')
    try {
        $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
        if (-not $key) { throw 'Could not open HKCU\Environment for writing.' }
        try {
            $userPath = [string]$key.GetValue('PATH', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $entries = @($userPath -split ';' | Where-Object { $_ })
            $persisted = @($entries | Where-Object { $_.TrimEnd('\') -ieq $normalizedPath }).Count -gt 0
            if (-not $persisted) {
                $key.SetValue('PATH', (($entries + $Path) -join ';'), [Microsoft.Win32.RegistryValueKind]::ExpandString)
                Write-Host "Added $Path to the user PATH." -ForegroundColor Green
            }
        }
        finally {
            $key.Dispose()
        }

        $available = @($env:PATH -split ';' | Where-Object { $_.TrimEnd('\') -ieq $normalizedPath }).Count -gt 0
        if (-not $available) {
            $env:PATH = $env:PATH.TrimEnd(';') + ';' + $Path
        }
        return $true
    }
    catch {
        Write-Warning "Could not add $Path to the user PATH. $($_.Exception.Message)"
        return $false
    }
}

function Get-GlobalNpmInventory {
    <#
.SYNOPSIS
    Returns healthy top-level globally installed npm packages.
.DESCRIPTION
    Reads npm's global package inventory as JSON and preserves healthy entries
    even when npm reports an unrelated invalid or missing package.
#>
    [CmdletBinding()]
    param()

    $json = @(& npm ls -g --depth=0 --json 2>$null)
    $exitCode = $LASTEXITCODE
    try {
        $data = ($json -join [Environment]::NewLine) | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not parse the global npm inventory. $($_.Exception.Message)"
        return [pscustomobject]@{ Available = $false; Packages = @{} }
    }

    $packages = @{}
    if ($data.dependencies) {
        foreach ($property in $data.dependencies.PSObject.Properties) {
            $package = $property.Value
            $missing = $package.PSObject.Properties['missing'] -and $package.missing
            $invalid = $package.PSObject.Properties['invalid'] -and $package.invalid
            if ($package.version -and -not $missing -and -not $invalid) {
                $packages[$property.Name] = [string]$package.version
            }
        }
    }
    if ($exitCode -ne 0) {
        Write-Warning "npm global inventory returned exit code $exitCode; healthy entries will still be used."
    }
    return [pscustomobject]@{ Available = $true; Packages = $packages }
}

function Install-AiTools {
    <#
.SYNOPSIS
    Installs common developer tools, PowerShell modules, and CLIs.

.DESCRIPTION
    Checks for configured PowerShell modules and installs them for the current user
    before processing a curated list of Windows packages via `winget`. Also ensures
    `git` is present, installs global `npm` packages, and bootstraps AI CLIs using
    their supported installers.

    On first run this helper will ask once whether to proceed automatically with
    installations; if you decline, it will list missing items for manual review and exit.

.PARAMETER Auto
    When supplied, skip the initial confirmation and proceed automatically.

.PARAMETER Update
    When supplied, upgrade any already-installed winget packages to their latest versions.

.PARAMETER ExtendedSetup
    When supplied, also installs the extended (non-minimal) package set: heavier tools such as
    FFmpeg, ImageMagick, security scanners, database CLIs, and similar large-scope packages.

.PARAMETER Sdk
    When supplied, also installs language SDK runtimes.

.PARAMETER Dotnet
    When supplied, installs the .NET SDK via the official dotnet-install.ps1 script from dot.net.
    Runs in a separate PowerShell process to avoid the script's exit call ending the current session.

.PARAMETER Docker
    When supplied, installs Docker Desktop via winget.

.PARAMETER Podman
    When supplied, installs Podman via winget. Cannot be used together with -Docker.

.PARAMETER Database
    When supplied, installs database client tools.

.PARAMETER MoreAi
    When supplied, also installs extra AI developer tools (SST.OpenCodeDesktop, Google.Antigravity,
    Google.AntigravityIDE, ZhipuAI.ZCode, MiniMax.MiniMaxCode, Anysphere.Cursor) via winget, extra global npm packages
    (@qwen-code/qwen-code, @mimo-ai/cli), and the Kimi Code, Grok, and Cursor CLIs if not present.

.PARAMETER All
    When supplied, enables all optional package groups: extended tools, SDK runtimes, .NET SDK,
    Docker Desktop, database clients, and extra AI developer tools. Equivalent to -ExtendedSetup -Sdk -Docker -Database -MoreAi.
    Since Docker and Podman are alternatives, -All selects Docker; use -Podman explicitly if preferred.

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-07
#>
    [CmdletBinding()]
    param(
        [switch]$Auto,
        [switch]$Update,
        [switch]$ExtendedSetup,
        [switch]$Sdk,
        [switch]$Dotnet,
        [switch]$Docker,
        [switch]$Podman,
        [switch]$Database,
        [switch]$MoreAi,
        [switch]$All
    )

    # Maintenance: CLIs with a native self-updater need a matching entry in
    # $_AiToolsInternal.UpgradeCommands. npm packages in NpmPackages /
    # MoreAiNpmPackages are picked up by aiu automatically -- no registry edit.

    if ($Docker -and $Podman) {
        throw "Cannot specify both -Docker and -Podman switches simultaneously."
    }

    # -All expands into every optional group; Docker is chosen over Podman since they are alternatives.
    # If -Podman was explicitly passed alongside -All, honour Podman instead of Docker.
    if ($All) {
        $ExtendedSetup = $true
        $Sdk = $true
        if (-not $Podman) { $Docker = $true }
        $Database = $true
        $MoreAi = $true
    }

    $powerShellModules = @($_AiToolsInternal.PowerShellModules)
    $wingetPackages = $_AiToolsInternal.WingetPackages
    if ($ExtendedSetup) {
        $wingetPackages += $_AiToolsInternal.ExtendedWingetPackages
    }
    # -Sdk implicitly enables -Dotnet because .NET is part of the SDK runtime stack.
    if ($Sdk) {
        $wingetPackages += $_AiToolsInternal.SdkWingetPackages
        $Dotnet = $true
    }
    if ($Docker) {
        $wingetPackages += $_AiToolsInternal.DockerWingetPackage
    }
    if ($Podman) {
        $wingetPackages += $_AiToolsInternal.PodmanWingetPackage
    }
    if ($Database) {
        $wingetPackages += $_AiToolsInternal.DbWingetPackages
    }
    # Add extra AI tools if MoreAi is requested
    if ($MoreAi) {
        $wingetPackages += $_AiToolsInternal.MoreAiWingetPackages
    }

    $npmPackages = $_AiToolsInternal.NpmPackages
    # Add extra global npm packages if MoreAi is requested
    if ($MoreAi) {
        $npmPackages += $_AiToolsInternal.MoreAiNpmPackages
    }

    $setupLabels = @('standard')
    if ($ExtendedSetup) { $setupLabels += 'extended' }
    if ($Sdk) { $setupLabels += 'sdk' }
    if ($Dotnet) { $setupLabels += 'dotnet' }
    if ($Docker) { $setupLabels += 'docker' }
    if ($Podman) { $setupLabels += 'podman' }
    if ($Database) { $setupLabels += 'db' }
    if ($MoreAi) { $setupLabels += 'moreai' }
    if ($All) { $setupLabels = @('all') }
    $setupLabel = $setupLabels -join ', '
    Write-Host "The setup will check/install the following items ($setupLabel):" -ForegroundColor Cyan
    Write-Host "PowerShell modules (total: $($powerShellModules.Count)):" -ForegroundColor Cyan
    $moduleIdx = 0
    foreach ($module in $powerShellModules) {
        $moduleIdx++
        Write-Host " - [$moduleIdx/$($powerShellModules.Count)] $($module.Name) >= $($module.MinimumVersion) ($($module.Scope))"
    }

    Write-Host "Winget packages (total: $($wingetPackages.Count)):" -ForegroundColor Cyan
    $wingetIdx = 0
    foreach ($p in $wingetPackages) {
        $wingetIdx++
        Write-Host " - [$wingetIdx/$($wingetPackages.Count)] $p"
    }

    Write-Host "NPM global packages (installed via npm -g) (total: $($npmPackages.Count)):" -ForegroundColor Cyan
    $npmIdx = 0
    foreach ($np in $npmPackages) {
        $npmIdx++
        Write-Host " - [$npmIdx/$($npmPackages.Count)] $np"
    }

    Write-Host "Command-line tools to verify/install:" -ForegroundColor Cyan
    Write-Host " - git (installed via winget if missing)"
    if ($Dotnet) { Write-Host " - .NET SDK (via dotnet-install.ps1)" }

    Write-Host "CLIs to verify:" -ForegroundColor Cyan
    Write-Host " - agy (Antigravity CLI)"
    Write-Host " - claude (Claude CLI)"
    Write-Host " - codex (Codex CLI)"
    Write-Host " - opencode (opencode CLI)"
    if ($MoreAi) {
        Write-Host " - kimi (Kimi Code CLI)"
        Write-Host " - grok (Grok CLI)"
        Write-Host " - cursor (Cursor CLI / agent)"
    }
    if (-not $Auto) {
        $choice = Read-Host -Prompt "Proceed with automatic installation of missing items? This will install PowerShell modules and run winget/npm/installers. Continue? (Y/n)"
        if ($choice -in @('n', 'N')) {
            Write-Host "Aborting automatic installs. Run Install-AiTools -Auto when ready to continue." -ForegroundColor Yellow
            return
        }
    }

    # Install configured modules before Winget so PowerShell-only setup remains
    # useful on machines where App Installer is absent or unavailable.
    if ($powerShellModules.Count -gt 0) {
        Write-Host 'Checking PowerShell modules...' -ForegroundColor Cyan
        # PowerShellGet 1.0.0.1 requires NuGet provider 2.8.5.201 or newer to
        # access NuGet-backed repositories such as PSGallery. This is a shared
        # package-management prerequisite, not a requirement of Pester itself.
        $minimumNuGetVersion = [version]'2.8.5.201'
        $moduleInstallIdx = 0

        foreach ($module in $powerShellModules) {
            $moduleInstallIdx++
            $minimumVersion = [version]$module.MinimumVersion
            $installedModule = Get-Module -ListAvailable -Name $module.Name |
                Where-Object { $_.Version -ge $minimumVersion } |
                Sort-Object Version -Descending |
                Select-Object -First 1

            if ($installedModule -and -not $Update) {
                Write-Host "[$moduleInstallIdx/$($powerShellModules.Count)] installed: $($module.Name) $($installedModule.Version)" -ForegroundColor Green
                continue
            }

            $action = if ($installedModule) { 'Updating' } else { 'Installing' }
            Write-Host "[$moduleInstallIdx/$($powerShellModules.Count)] $action $($module.Name) >= $minimumVersion..." -ForegroundColor Cyan

            try {
                if (-not (Get-Command Install-Module -ErrorAction SilentlyContinue)) {
                    throw 'Install-Module is unavailable. Install PowerShellGet and retry.'
                }

                # Older Windows PowerShell defaults may not negotiate the TLS
                # version required by PowerShell Gallery.
                [Net.ServicePointManager]::SecurityProtocol =
                    [Net.ServicePointManager]::SecurityProtocol -bor
                    [Net.SecurityProtocolType]::Tls12

                $nuGetProvider = Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue |
                    Where-Object { $_.Version -ge $minimumNuGetVersion } |
                    Sort-Object Version -Descending |
                    Select-Object -First 1
                if (-not $nuGetProvider) {
                    Write-Host "Bootstrapping NuGet provider >= $minimumNuGetVersion..." -ForegroundColor Yellow
                    Install-PackageProvider -Name NuGet -MinimumVersion $minimumNuGetVersion `
                        -Scope CurrentUser -Force -Confirm:$false -ErrorAction Stop | Out-Null
                }

                $installParameters = @{
                    Name           = $module.Name
                    MinimumVersion = $module.MinimumVersion
                    Repository     = $module.Repository
                    Scope          = $module.Scope
                    Confirm        = $false
                    ErrorAction    = 'Stop'
                }
                if ($module.Force) { $installParameters.Force = $true }
                if ($module.SkipPublisherCheck) { $installParameters.SkipPublisherCheck = $true }
                Install-Module @installParameters

                $installedModule = Get-Module -ListAvailable -Name $module.Name |
                    Where-Object { $_.Version -ge $minimumVersion } |
                    Sort-Object Version -Descending |
                    Select-Object -First 1
                if (-not $installedModule) {
                    throw "$($module.Name) >= $minimumVersion was not discoverable after installation."
                }

                Write-Host "Installed $($module.Name) $($installedModule.Version)." -ForegroundColor Green
            }
            catch {
                Write-Warning "PowerShell module setup failed for $($module.Name): $($_.Exception.Message)"
            }
        }
    }

    # App Installer exposes winget through the per-user WindowsApps aliases.
    $windowsAppsDir = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps'
    $null = Add-UserPathEntry -Path $windowsAppsDir

    # Ensure winget exists
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host "winget not found. Please install 'App Installer' (winget) from Microsoft Store and retry." -ForegroundColor Red
        return
    }

    # Winget installs shim executables into this Links directory, but some
    # system images don't include it in the default User PATH.  Ensure it's
    # present so `winget list` results translate to discoverable commands.
    $wingetLinksDir = Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Links"
    $null = Add-UserPathEntry -Path $wingetLinksDir

    $wingetListOutput = @()
    try {
        $wingetListOutput = & winget list 2>$null
    }
    catch {
        Write-Host "Failed to query winget package inventory: $_" -ForegroundColor Red
        return
    }

    # winget list output is unstructured text; we match the package id then
    # verify the "Source" column contains "winget" to avoid false positives from
    # similarly-named packages in other sources (e.g. MSStore).
    function Test-WingetInstalledPackage {
        param(
            [string[]]$Rows,
            [string]$PackageId
        )

        $escapedId = [regex]::Escape($PackageId)
        foreach ($row in $Rows) {
            if ($row -notmatch $escapedId) {
                continue
            }

            if ($row -match "\bwinget\b") {
                return $true
            }
        }

        return $false
    }

    $missing = @()
    $installed = @()
    $totalWinget = $wingetPackages.Count
    $wingetCheckIdx = 0
    # Enumerate and check install status of each winget package, printing progress
    foreach ($pkg in $wingetPackages) {
        $wingetCheckIdx++
        $isInstalled = Test-WingetInstalledPackage -Rows $wingetListOutput -PackageId $pkg
        if ($isInstalled) {
            Write-Host "[$wingetCheckIdx/$totalWinget] installed:   $pkg" -ForegroundColor Green
            $installed += $pkg
        }
        else {
            Write-Host "[$wingetCheckIdx/$totalWinget] not installed: $pkg" -ForegroundColor Yellow
            $missing += $pkg
        }
    }

    if ($missing.Count -gt 0) {
        Write-Host "Missing winget packages:" -ForegroundColor Yellow
        foreach ($m in $missing) { Write-Host " - $m" }

        Write-Host "Installing missing packages via winget..." -ForegroundColor Cyan
        $totalMissing = $missing.Count
        $wingetInstallIdx = 0
        # Install each missing winget package, printing progress
        foreach ($m in $missing) {
            $wingetInstallIdx++
            Write-Host "[$wingetInstallIdx/$totalMissing] Installing $m..." -ForegroundColor Cyan
            try {
                # Start-Process is used instead of direct invocation so winget can
                # prompt for UAC elevation without deadlocking the parent console.
                Start-Process -FilePath 'winget' -ArgumentList "install -s winget -e --id $m" -NoNewWindow -Wait
            }
            catch { Write-Host "Failed to start winget for $($m): $_" -ForegroundColor Red }
        }

        $wingetListOutput = & winget list 2>$null
        $stillMissing = $missing | Where-Object { -not (Test-WingetInstalledPackage -Rows $wingetListOutput -PackageId $_) }
        if ($stillMissing) {
            Write-Host "The following packages failed to install:" -ForegroundColor Red
            foreach ($m in $stillMissing) { Write-Host " - $m" -ForegroundColor Red }
        }
        else {
            Write-Host "All packages installed successfully." -ForegroundColor Green
        }
    }
    else {
        Write-Host "All winget packages already present." -ForegroundColor Green
    }

    if ($Update -and $installed.Count -gt 0) {
        Write-Host "Upgrading existing winget packages..." -ForegroundColor Cyan
        $totalInstalled = $installed.Count
        $wingetUpgradeIdx = 0
        # Upgrade each installed winget package, printing progress
        foreach ($pkg in $installed) {
            $wingetUpgradeIdx++
            Write-Host "[$wingetUpgradeIdx/$totalInstalled] Upgrading $pkg..." -ForegroundColor Cyan
            try {
                Start-Process -FilePath 'winget' -ArgumentList "upgrade -s winget -e --id $pkg" -NoNewWindow -Wait
            }
            catch { Write-Host "Failed to start winget upgrade for $($pkg): $_" -ForegroundColor Red }
        }
    }

    # Ensure git is present; if not, offer interactive installer
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Host "git not found. Launching interactive winget installer for Git..." -ForegroundColor Yellow
        Start-Process -FilePath 'winget' -ArgumentList "install -s winget -e --id $($_AiToolsInternal.GitWingetPackage) -i" -NoNewWindow -Wait
    }

    # Install .NET SDK via official install script (https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-install-script)
    if ($Dotnet) {
        Write-Host "Installing .NET SDK via dotnet-install.ps1..." -ForegroundColor Cyan
        # dotnet-install.ps1 calls exit internally, so it must run in a child process.
        # Forcing TLS 1.2 ensures the download succeeds on older Windows 10 builds.
        & powershell -NoProfile -ExecutionPolicy Unrestricted -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; &([scriptblock]::Create((Invoke-WebRequest -UseBasicParsing 'https://dot.net/v1/dotnet-install.ps1')))"
        Write-Host ".NET SDK install script completed." -ForegroundColor Green
    }

    # Keep npm defaults grouped here so additional setup can be added later.
    function Set-NpmConfiguration {
        & npm config set fund false
    }

    # Install global npm packages if npm available
    if (Get-Command npm -ErrorAction SilentlyContinue) {
        $npmPrefix = [string](@(& npm prefix -g 2>$null) | Select-Object -Last 1)
        if ($npmPrefix) {
            $null = Add-UserPathEntry -Path $npmPrefix.Trim()
        }

        Set-NpmConfiguration
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "npm funding configuration failed with exit code $LASTEXITCODE; continuing."
        }

        $inventory = Get-GlobalNpmInventory
        $totalNpm = $npmPackages.Count
        $npmCheckIdx = 0
        $missingNpmPackages = @()
        foreach ($np in $npmPackages) {
            $npmCheckIdx++
            if ($inventory.Available -and $inventory.Packages.ContainsKey($np)) {
                Write-Host "[$npmCheckIdx/$totalNpm] installed:   $np $($inventory.Packages[$np])" -ForegroundColor Green
            }
            else {
                Write-Host "[$npmCheckIdx/$totalNpm] not installed: $np" -ForegroundColor Yellow
                $missingNpmPackages += $np
            }
        }

        if ($missingNpmPackages.Count -eq 0) {
            Write-Host "All selected global npm packages are already installed." -ForegroundColor Green
        }
        else {
            $npmArgs = @('install', '-g') + $missingNpmPackages
            Write-Host "Installing missing npm packages: $($missingNpmPackages -join ', ')" -ForegroundColor Cyan
            & npm @npmArgs
            $npmInstallExitCode = $LASTEXITCODE
            if ($npmInstallExitCode -ne 0) {
                Write-Warning "npm install failed with exit code $npmInstallExitCode for: $($missingNpmPackages -join ', ')"
            }

            $refreshedInventory = Get-GlobalNpmInventory
            if ($refreshedInventory.Available) {
                $stillMissing = @($missingNpmPackages | Where-Object { -not $refreshedInventory.Packages.ContainsKey($_) })
                if ($stillMissing.Count -gt 0) {
                    Write-Warning "The following global npm packages remain missing or invalid: $($stillMissing -join ', ')"
                }
                elseif ($npmInstallExitCode -eq 0) {
                    Write-Host "All missing global npm packages installed successfully." -ForegroundColor Green
                }
            }
        }
    }
    else {
        Write-Host "npm not found - aborting Install-AiTools. Please inspect your Node/npm installation and re-run." -ForegroundColor Red
        return
    }

    Write-Host "CLIs to verify:" -ForegroundColor Cyan
    Write-Host " - agy (Antigravity CLI)"
    Write-Host " - claude (Claude CLI)"
    Write-Host " - codex (Codex CLI)"
    Write-Host " - opencode (opencode CLI)"
    if ($MoreAi) {
        Write-Host " - kimi (Kimi Code CLI)"
        Write-Host " - grok (Grok CLI)"
        Write-Host " - cursor (Cursor CLI / agent)"
    }
    # Install Antigravity and Claude CLIs using their recommended installers
    Write-Host "Verifying CLIs and Configuring AI tool settings..." -ForegroundColor Cyan

    if (-not (Get-Command agy -ErrorAction SilentlyContinue)) {
        Write-Host "agy CLI not found; installing via $($_AiToolsInternal.Urls.AgyCli)..." -ForegroundColor Yellow
        try { & powershell -NoProfile -Command "iex (irm '$($_AiToolsInternal.Urls.AgyCli)')" } catch { Write-Host "Failed to install agy: $_" -ForegroundColor Red }
    } else {
        # If agy is present, ensure it's configured with the default settings
        Install-AgySettings
    }

    if (-not (Get-Command claude -ErrorAction SilentlyContinue)) {
        Write-Host "claude CLI not found; installing via $($_AiToolsInternal.Urls.ClaudeCli)..." -ForegroundColor Yellow
        try { & powershell -NoProfile -Command "iex (irm '$($_AiToolsInternal.Urls.ClaudeCli)')" } catch { Write-Host "Failed to install claude: $_" -ForegroundColor Red }
        # The claude installer places the binary in ~/.local/bin; ensure it's on the user PATH.
        $claudeBin = Join-Path $env:USERPROFILE '.local\bin'
        $null = Add-UserPathEntry -Path $claudeBin
    } else {
        # If claude is present, ensure it's configured with the default settings
        Install-GlobalClaudeSettings
    }

    if (-not (Get-Command codex -ErrorAction SilentlyContinue)) {
        Write-Host "codex CLI not found; installing via $($_AiToolsInternal.Urls.CodexCli)..." -ForegroundColor Yellow
        try { & powershell -NoProfile -ExecutionPolicy ByPass -Command "irm '$($_AiToolsInternal.Urls.CodexCli)' | iex" } catch { Write-Host "Failed to install codex: $_" -ForegroundColor Red }
    } else {
        # If codex is present, ensure it's configured with the default settings
        Install-CodexSettings
    }

    # Install opencode via npm (not winget) so the package is managed by npm
    # and the native `opencode upgrade` command works as upstream intended.
    if (-not (Get-Command opencode -ErrorAction SilentlyContinue)) {
        Write-Host "opencode CLI not found; installing via 'npm install -g opencode-ai'..." -ForegroundColor Yellow
        & npm install -g opencode-ai
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Failed to install opencode-ai with npm exit code $LASTEXITCODE."
        }
    }

    # Configure Qwen Code and Kimi Code if MoreAi is requested. Their npm packages
    # are managed through MoreAiNpmPackages with the other optional AI tools.
    if ($MoreAi) {
        Install-QwenSettings
        Install-KimiSettings
    }

    # Verify and install Grok CLI if MoreAi is requested. Probe on the grok binary
    # (installed as grok.exe under ~/.grok/bin); the upstream installer adds that
    # directory to the user PATH itself, so no manual PATH handling is needed here.
    if ($MoreAi) {
        if (-not (Get-Command grok -ErrorAction SilentlyContinue)) {
            Write-Host "grok CLI not found; installing via $($_AiToolsInternal.Urls.GrokCli)..." -ForegroundColor Yellow
            try {
                & powershell -NoProfile -ExecutionPolicy ByPass -Command "iex (irm '$($_AiToolsInternal.Urls.GrokCli)')"
                Install-GrokSettings
            } catch {
                Write-Host "Failed to install grok: $_" -ForegroundColor Red
            }
        } else {
            # If grok is present, ensure it's configured with the default settings
            Install-GrokSettings
        }
    }

    # Verify and install Cursor CLI (agent) if MoreAi is requested.
    # The upstream installer places binaries in %LOCALAPPDATA%\cursor-agent.
    if ($MoreAi) {
        if (-not (Get-Command cursor-agent -ErrorAction SilentlyContinue) -and -not (Get-Command agent -ErrorAction SilentlyContinue)) {
            Write-Host "Cursor CLI (agent) not found; installing via $($_AiToolsInternal.Urls.CursorCli)..." -ForegroundColor Yellow
            try {
                & powershell -NoProfile -ExecutionPolicy ByPass -Command "iex (irm '$($_AiToolsInternal.Urls.CursorCli)')"
                $cursorAgentDir = Join-Path $env:LOCALAPPDATA 'cursor-agent'
                $null = Add-UserPathEntry -Path $cursorAgentDir
            } catch {
                Write-Host "Failed to install Cursor CLI: $_" -ForegroundColor Red
            }
        }
    }

    # Create a docker.bat shim so tools that hardcode `docker` commands
    # (compose files, scripts) transparently route through podman.
    if ($Podman) {
        Write-Host "Configuring Podman aliases..." -ForegroundColor Cyan
        $wingetLinksDir = Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Links"
        if (-not (Test-Path -LiteralPath $wingetLinksDir)) {
            $null = New-Item -ItemType Directory -Path $wingetLinksDir -Force -Verbose
        }
        $dockerBat = Join-Path $wingetLinksDir "docker.bat"
        "@echo off`r`npodman %*" | Out-File -FilePath $dockerBat -Encoding ascii
        Write-Host "Created docker alias (docker.bat) for podman in Winget Links directory." -ForegroundColor Green
    }

    Write-Host "Install-AiTools finished. You may need to restart PowerShell to pick up new PATH or env changes." -ForegroundColor Green
}

function Get-AiApiKey {
    <#
    .SYNOPSIS
        Retrieves an API key, prioritizing current process environment, then Windows Credential Manager,
        and finally legacy User environment variables.

    .NOTES
        Author: jjw(@thejjw)
        Last Edit: 2026-05
#>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    # 1. Process environment (allows temporary session overrides)
    $v = [Environment]::GetEnvironmentVariable($Name, 'Process')
    if ($v) { return $v }

    # 2. Windows Credential Manager (DPAPI-backed, survives reboots, no plaintext in registry)
    [void][Windows.Security.Credentials.PasswordVault, Windows.Security.Credentials, ContentType=WindowsRuntime]
    $vault = New-Object Windows.Security.Credentials.PasswordVault
    try {
        $cred = $vault.Retrieve($Name, 'api-key')
        $cred.RetrievePassword()
        return $cred.Password
    }
    catch {
        # 3. Fallback: legacy plaintext env vars for keys stored before Credential Manager migration
        return [Environment]::GetEnvironmentVariable($Name, 'User')
    }
}

function Set-AiApiKeysCS {
    <#
    .SYNOPSIS
        Interactive helper to view and set Claude-related API keys in Windows Credential Manager.

    .DESCRIPTION
        Checks for existing values of AI API keys in the Windows Credential Manager (PasswordVault).
        Presents a summary and prompts the user to enter missing keys (or optionally overwrite existing ones).
        Values are securely saved using Windows Credential Manager (DPAPI-encrypted), keeping plaintext
        credentials out of your registry. Saving QWEN_TOKEN_PLAN_API_KEY also saves the same value as
        BAILIAN_TOKEN_PLAN_API_KEY without an additional prompt.

    .PARAMETER Force
        When supplied, prompt to overwrite existing keys instead of skipping them.

    .NOTES
        Author: jjw(@thejjw)
        Last Edit: 2026-08
    #>
    [CmdletBinding()]
    param(
        [switch]$Force
    )

    # WinRT PasswordVault is per-user and DPAPI-encrypted at rest -- no plaintext
    # credentials in the registry. The explicit type load is required for both
    # Windows PowerShell 5.1 and PowerShell 7+ on Windows.
    [void][Windows.Security.Credentials.PasswordVault, Windows.Security.Credentials, ContentType=WindowsRuntime]
    $vault = New-Object Windows.Security.Credentials.PasswordVault
    $names = @('DEEPSEEK_API_KEY', 'ZAI_API_KEY', 'MINIMAX_API_KEY', 'KIMI_CODE_PLAN_API_KEY', 'QWEN_TOKEN_PLAN_API_KEY', 'GEMINI_API_KEY', 'NVIDIA_API_KEY', 'OPENROUTER_API_KEY')
    # All keys share a single resource userName so they form a logical group in
    # Credential Manager and can be enumerated/cleared together.
    $userName = 'api-key'

    # Retrieve a stored key's plaintext value from vault
    function Get-StoredKey($n) {
        try {
            $cred = $vault.Retrieve($n, $userName)
            $cred.RetrievePassword()
            return $cred.Password
        }
        catch {
            return $null
        }
    }

    # Format the masked key display status
    function MaskValue($v) {
        if (-not $v) { return '<missing>' }
        return "<secured in Credential Manager, length=$($v.Length)>"
    }

    Write-Host "Checking existing keys in Windows Credential Manager:" -ForegroundColor Cyan
    $found = @{}
    foreach ($n in $names) {
        $v = Get-StoredKey $n
        $found[$n] = $v
        Write-Host " - $($n) : $(MaskValue $v)"
    }

    Write-Host ""
    Write-Host "You can press Enter to skip setting a key. To keep an existing value, leave it blank when prompted." -ForegroundColor Yellow

    foreach ($n in $names) {
        $current = $found[$n]
        if ($current -and -not $Force) {
            Write-Host "Skipping $n (already set in vault). Use -Force to overwrite." -ForegroundColor DarkGray
            continue
        }

        if ($current -and $Force) {
            $resp = Read-Host -Prompt "$n already set in vault. Overwrite? (y/N)"
            if ($resp -notin @('y', 'Y')) { Write-Host "Keeping existing $n." -ForegroundColor DarkGray; continue }
        }

        # Read hidden input as SecureString. Skip if empty.
        $secure = Read-Host -AsSecureString -Prompt "Enter value for $n (input hidden, blank to skip)"
        if ($null -eq $secure -or -not ($secure -is [System.Security.SecureString]) -or $secure.Length -eq 0) {
            Write-Host "Skipped $n." -ForegroundColor DarkGray
            continue
        }

        $ptr = [IntPtr]::Zero
        try {
            $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
            $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr)

            # Store inside the vault
            $newCred = New-Object Windows.Security.Credentials.PasswordCredential($n, $userName, $plain)
            $vault.Add($newCred)
            Write-Host "Successfully saved $n to Windows Credential Manager." -ForegroundColor Green

            if ($n -eq 'QWEN_TOKEN_PLAN_API_KEY') {
                try {
                    $bailianName = 'BAILIAN_TOKEN_PLAN_API_KEY'
                    $bailianCred = New-Object Windows.Security.Credentials.PasswordCredential($bailianName, $userName, $plain)
                    $vault.Add($bailianCred)
                    Write-Host "Duplicated $n to $bailianName in Windows Credential Manager." -ForegroundColor Cyan
                }
                catch {
                    Write-Host "Failed to duplicate $n to BAILIAN_TOKEN_PLAN_API_KEY: $_" -ForegroundColor Red
                }
            }
        }
        catch {
            Write-Host "Failed to save secure input for $($n): $_" -ForegroundColor Red
            continue
        }
        finally {
            if ($ptr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
        }
    }

    Write-Host ""
    Write-Host "Done! Run 'Load-AiApiKeysFromCS' to load these into your current terminal process." -ForegroundColor Cyan
}

function Load-AiApiKeysFromCS {
    <#
    .SYNOPSIS
        Loads secure API keys from Windows Credential Manager into the current process environment.

    .DESCRIPTION
        Retrieves saved credentials from the Windows PasswordVault and registers them as
        session-level (Process) environment variables. This makes them immediately available
        to all CLI tools, scripts, and processes run from this PowerShell terminal (e.g. claude, python, etc.),
        without saving them as plaintext in registry variables.

    .PARAMETER Quiet
        When supplied, skips detailed output and only prints a short status message.

    .NOTES
        Author: jjw(@thejjw)
        Last Edit: 2026-08
    #>
    [CmdletBinding()]
    param(
        [switch]$Quiet
    )
    [void][Windows.Security.Credentials.PasswordVault, Windows.Security.Credentials, ContentType=WindowsRuntime]
    $vault = New-Object Windows.Security.Credentials.PasswordVault
    $names = @('DEEPSEEK_API_KEY', 'ZAI_API_KEY', 'MINIMAX_API_KEY', 'KIMI_CODE_PLAN_API_KEY', 'QWEN_TOKEN_PLAN_API_KEY', 'BAILIAN_TOKEN_PLAN_API_KEY', 'GEMINI_API_KEY', 'NVIDIA_API_KEY', 'OPENROUTER_API_KEY')
    $userName = 'api-key'

    $loadedCount = 0
    foreach ($n in $names) {
        try {
            $cred = $vault.Retrieve($n, $userName)
            $cred.RetrievePassword()
            $envKey = $cred.Password
            if ($envKey) {
                [Environment]::SetEnvironmentVariable($n, $envKey, 'Process')
                $loadedCount++
            }
        }
        catch {
            # Silent skip if credential is not in vault
        }
    }
    if ($loadedCount -gt 0) {
        if ($Quiet) {
            Write-Host "Credential storage load completed." -ForegroundColor Green
        } else {
            Write-Host "Loaded $loadedCount API key(s) from Windows Credential Manager into session environment." -ForegroundColor Green
        }
    } else {
        Write-Host "No saved API keys found in Windows Credential Manager." -ForegroundColor DarkGray
    }
}

function Remove-AiApiKeysFromCS {
    <#
    .SYNOPSIS
        Removes the profile's API keys from Windows Credential Manager and the current process.

    .DESCRIPTION
        Removes every credential grouped under the api-key username in Windows PasswordVault.
        Also clears the corresponding current-process environment variable for each grouped
        credential resource. User- and Machine-scope variables are not changed.

    .EXAMPLE
        Remove-AiApiKeysFromCS -WhatIf

    .EXAMPLE
        Remove-AiApiKeysFromCS -Confirm:$false

    .EXAMPLE
        Remove-AiApiKeysFromCS -Verbose

    .NOTES
        Author: jjw(@thejjw)
        Last Edit: 2026-08
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()

    $target = "Windows Credential Manager entries grouped as 'api-key' and matching process variables"
    if (-not $PSCmdlet.ShouldProcess($target, 'Remove AI API keys')) {
        return
    }

    [void][Windows.Security.Credentials.PasswordVault, Windows.Security.Credentials, ContentType=WindowsRuntime]
    $vault = New-Object Windows.Security.Credentials.PasswordVault
    try {
        # RetrieveAll returns a stable snapshot, so removing entries while iterating is safe.
        $credentials = @($vault.RetrieveAll() | Where-Object { $_.UserName -eq 'api-key' })
    }
    catch {
        Write-Error "Failed to enumerate Windows Credential Manager: $_"
        return
    }

    $names = @($credentials.Resource | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)

    $removedCount = 0
    $failureCount = 0
    foreach ($credential in $credentials) {
        try {
            $vault.Remove($credential)
            $removedCount++
            Write-Verbose "Scrubbed credential: $($credential.Resource)"
        }
        catch {
            $failureCount++
            Write-Error "Failed to remove credential '$($credential.Resource)': $_" -ErrorAction Continue
        }
    }

    $clearedCount = 0
    foreach ($name in $names) {
        try {
            if ($null -ne [Environment]::GetEnvironmentVariable($name, 'Process')) {
                [Environment]::SetEnvironmentVariable($name, $null, 'Process')
                $clearedCount++
            }
        }
        catch {
            $failureCount++
            Write-Error "Failed to clear process variable '$name': $_" -ErrorAction Continue
        }
    }

    $message = "Scrubbed $removedCount credential(s) from the api-key group and cleared $clearedCount process variable(s)."
    Write-Host $message -ForegroundColor Green
    if ($failureCount -gt 0) {
        Write-Warning "$failureCount operation(s) failed."
    }
}

# https://code.claude.com/docs/en/model-config#special-model-behavior
# default model setting
# The behavior of default depends on your account type:
# Max, Team Premium, Enterprise pay-as-you-go, and Anthropic API: defaults to Opus 4.8
# Pro, Team Standard, and Enterprise subscription seats: defaults to Sonnet 4.6
# opusplan model setting
# The opusplan model alias provides an automated hybrid approach:
# In plan mode - Uses opus for complex reasoning and architecture decisions
# In execution mode - Automatically switches to sonnet for code generation and implementation
# This gives you the best of both worlds: Opus’s superior reasoning for planning, and Sonnet’s efficiency for execution.
# The plan-mode Opus phase uses the same context window as the opus model setting. 
# On subscription tiers where Opus is automatically upgraded to 1M context, opusplan receives the upgrade in plan mode as well. 
# To force 1M context for both phases when you are not on an auto-upgrade tier, set the model to opusplan[1m].
# For a hybrid approach where Claude decides mid-task when to consult a second model rather than switching at the plan boundary, see the advisor tool.
# https://code.claude.com/docs/en/advisor
# The advisor tool lets Claude consult a second, typically stronger model at key moments during a task, such as before committing to an approach, when stuck on a recurring error, 
# or before declaring a task complete. The advisor receives the full conversation, including every tool call and result, and returns guidance that Claude applies before continuing.
# Pairing	When to use
# Sonnet main + Opus advisor	Sonnet handles routine work and escalates planning, ambiguous failures, and completion checks to Opus
# Sonnet main + Fable advisor	Fable 5 guidance at decision points without running Fable 5 throughout. Requires v2.1.170 or later and Fable 5 access
# Haiku main + Opus advisor	Lowest-cost main model with strong planning. Expect higher cost than Haiku alone but lower than switching the main model to Sonnet or Opus
# Opus main + Opus advisor	A second Opus reviews the first. Useful for high-stakes tasks where an independent check matters more than cost
# Fable main + Fable advisor	Highest-capability pairing when Fable 5 is available (v2.1.170+). Fable is a higher tier than Opus and Sonnet, so it is the only accepted advisor for a Fable main model
# Sonnet main + Sonnet advisor	A lower-cost second opinion for catching routine oversights
# Claude decides when to call the advisor. It tends to consult before committing to an approach, when an error keeps recurring, and before declaring a task done, but the timing is model-driven rather than rule-based.
# Claude calls the advisor at decision points rather than on every turn, so pairing a faster main model with a stronger advisor typically costs less than running the stronger model throughout. Advisor usage counts toward the session totals shown by /usage.

function ccd {
    <#
.SYNOPSIS
Shorthand for running claude with the --dangerously-skip-permissions flag.

.DESCRIPTION
Equivalent of the bash alias: alias ccd='claude --dangerously-skip-permissions'
Checks whether the claude CLI is installed before invoking it.

.EXAMPLE
ccd

Runs Claude Code with permissions skipped.

.EXAMPLE
ccd --model claude-opus

Runs Claude Code with a specific model and permissions skipped.

.NOTES
Author: jjw(@thejjw)
Last Edit: 2026-05
#>
    if (-not (Get-Command claude -ErrorAction SilentlyContinue)) {
        Write-Host 'claude CLI not found.' -ForegroundColor Red
        Write-Host 'Install via: irm https://claude.ai/install.ps1 | iex' -ForegroundColor Yellow
        Write-Host 'Or visit:    https://claude.com/product/claude-code' -ForegroundColor Yellow
        return
    }
    claude --dangerously-skip-permissions @args
}

function agyd {
    <#
.SYNOPSIS
    Launches agy with permissions skipped.

.DESCRIPTION
    Forwards all arguments to agy and appends --dangerously-skip-permissions.
    Checks whether the agy CLI is installed before invoking it.

.EXAMPLE
    agyd

.EXAMPLE
    agyd "Summarize the changed files"

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-05
#>
    if (-not (Get-Command agy -ErrorAction SilentlyContinue)) {
        Write-Host 'agy CLI not found.' -ForegroundColor Red
        Write-Host 'Install via: irm https://antigravity.google/cli/install.ps1 | iex' -ForegroundColor Yellow
        Write-Host 'Or visit:    https://antigravity.google' -ForegroundColor Yellow
        return
    }
    agy --dangerously-skip-permissions @args
}

function Test-AnthropicApi {
    <#
.SYNOPSIS
    Tests connectivity to an Anthropic-compatible API endpoint.

.DESCRIPTION
    Sends a minimal chat-completion request to the specified Anthropic Messages API
    endpoint and reports whether the API key, URL, and model combination is working.
    Useful for verifying credentials and endpoint reachability before integrating
    with tools or scripts.

.PARAMETER ApiKey
    The API key used for authentication (sent as x-api-key header).

.PARAMETER ApiUrl
    The base URL of the Anthropic-compatible API (e.g. "https://api.anthropic.com"
    or "https://api.z.ai/api/anthropic").

.PARAMETER Model
    The model identifier to use for the test request (e.g. "claude-sonnet-4-20250514").

.EXAMPLE
    Test-AnthropicApi -ApiKey $env:ANTHROPIC_API_KEY -ApiUrl "https://api.anthropic.com" -Model "claude-sonnet-4-20250514"

.EXAMPLE
    Test-AnthropicApi $env:SOME_AUTH_TOKEN "https://api.z.ai/api/anthropic" "glm-5.1"

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-05
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$ApiKey,

        [Parameter(Mandatory, Position = 1)]
        [string]$ApiUrl,

        [Parameter(Mandatory, Position = 2)]
        [string]$Model
    )

    Write-Host "Testing API connectivity..."
    Write-Host "URL: $ApiUrl"
    Write-Host "Model: $Model"
    Write-Host ("-" * 40)

    $headers = @{
        "x-api-key"         = $ApiKey
        "Content-Type"      = "application/json"
        "anthropic-version" = "2023-06-01"
    }

    $body = @{
        model      = $Model
        max_tokens = 100
        messages   = @(
            @{
                role    = "user"
                content = "Say 'API is working'"
            }
        )
    } | ConvertTo-Json -Depth 10

    try {
        $response = Invoke-WebRequest2 -Uri "$ApiUrl/v1/messages" `
            -Method POST `
            -Headers $headers `
            -Body $body `
            -TimeoutSec 30 `
            -UseBasicParsing

        Write-Host "Status Code: $($response.StatusCode)"

        if ($response.StatusCode -eq 200) {
            $data = $response.Content | ConvertFrom-Json
            Write-Host "[OK] API is responding!"
            if ($data.content -and $data.content.Count -gt 0) {
                Write-Host "Response: $($data.content[0].text)"
            }
        }
    }
    catch {
        Write-Host "[ERROR] $($_.Exception.Message)"
        if ($_.Exception.Response) {
            $errorBody = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorBody)
            $errorText = $reader.ReadToEnd()
            Write-Host $errorText
        }
    }
}

function Test-OpenAiApi {
    <#
.SYNOPSIS
    Tests connectivity to an OpenAI-compatible API endpoint.

.DESCRIPTION
    Sends a minimal chat-completion request to the specified OpenAI Chat Completions
    API endpoint and reports whether the API key, URL, and model combination is working.
    Useful for verifying credentials and endpoint reachability before integrating
    with tools or scripts.

.PARAMETER ApiKey
    The API key used for authentication (sent as Bearer token in Authorization header).

.PARAMETER ApiUrl
    The base URL of the OpenAI-compatible API (e.g. "https://api.openai.com/v1"
    or "https://api.deepseek.com/v1").

.PARAMETER Model
    The model identifier to use for the test request (e.g. "gpt-4o", "deepseek-chat").

.EXAMPLE
    Test-OpenAiApi -ApiKey $env:OPENAI_API_KEY -ApiUrl "https://api.openai.com/v1" -Model "gpt-4o"

.EXAMPLE
    Test-OpenAiApi $env:DEEPSEEK_API_KEY "https://api.deepseek.com/v1" "deepseek-chat"

.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-05
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$ApiKey,

        [Parameter(Mandatory, Position = 1)]
        [string]$ApiUrl,

        [Parameter(Mandatory, Position = 2)]
        [string]$Model
    )

    Write-Host "Testing API connectivity..."
    Write-Host "URL: $ApiUrl"
    Write-Host "Model: $Model"
    Write-Host ("-" * 40)

    $headers = @{
        "Authorization" = "Bearer $ApiKey"
        "Content-Type"  = "application/json"
    }

    $body = @{
        model      = $Model
        max_tokens = 100
        messages   = @(
            @{
                role    = "user"
                content = "Say 'API is working'"
            }
        )
    } | ConvertTo-Json -Depth 10

    try {
        $response = Invoke-WebRequest2 -Uri "$ApiUrl/chat/completions" `
            -Method POST `
            -Headers $headers `
            -Body $body `
            -TimeoutSec 30 `
            -UseBasicParsing

        Write-Host "Status Code: $($response.StatusCode)"

        if ($response.StatusCode -eq 200) {
            $data = $response.Content | ConvertFrom-Json
            Write-Host "[OK] API is responding!"
            if ($data.choices -and $data.choices.Count -gt 0) {
                Write-Host "Response: $($data.choices[0].message.content)"
            }
        }
    }
    catch {
        Write-Host "[ERROR] $($_.Exception.Message)"
        if ($_.Exception.Response) {
            $errorBody = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorBody)
            $errorText = $reader.ReadToEnd()
            Write-Host $errorText
        }
    }
}

function Invoke-AiUpgrade {
    <#
.SYNOPSIS
    Updates all AI CLI tools in one shot.
.DESCRIPTION
    Runs the native update/upgrade command for each available CLI registered in
    $_AiToolsInternal.UpgradeCommands (agy, Claude, Codex, OpenCode, Grok, and Cursor),
    then checks and updates every npm-installed managed package -- from
    $_AiToolsInternal.NpmPackages and MoreAiNpmPackages -- through one global
    npm command. Winget packages are upgraded only when -Winget is supplied.
    Use the alias 'aiu' for convenience.
.PARAMETER Winget
    Upgrade the reported managed Winget packages. Without this switch, Winget
    updates are listed only because they may be large or require elevation.
.EXAMPLE
    Invoke-AiUpgrade
.EXAMPLE
    aiu -winget
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-08
#>
    [CmdletBinding()]
    param(
        [switch]$Winget
    )

    foreach ($tool in $_AiToolsInternal.UpgradeCommands) {
        $probe = if ($tool.Probe) { $tool.Probe } else { $tool.Cmd }
        if (-not (Get-Command $probe -ErrorAction SilentlyContinue)) {
            continue
        }
        if ($probe -ne $tool.Cmd -and -not (Get-Command $tool.Cmd -ErrorAction SilentlyContinue)) {
            continue
        }
        Write-Host ">>> $($tool.Label): $($tool.Cmd) $($tool.Args -join ' ')" -ForegroundColor Cyan
        & $tool.Cmd @($tool.Args)
    }

    # Winget stage: discover updates once, restrict the results to every package
    # Install-AiTools may manage, and require an explicit switch before installing.
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host '>>> winget: skipped (winget is not available).' -ForegroundColor Yellow
    }
    else {
        $managedWinget = @(
            @($_AiToolsInternal.WingetPackages) +
            @($_AiToolsInternal.ExtendedWingetPackages) +
            @($_AiToolsInternal.SdkWingetPackages) +
            @($_AiToolsInternal.DbWingetPackages) +
            @($_AiToolsInternal.MoreAiWingetPackages) +
            @(
                $_AiToolsInternal.DockerWingetPackage,
                $_AiToolsInternal.PodmanWingetPackage,
                $_AiToolsInternal.GitWingetPackage
            ) | Where-Object { $_ } | Sort-Object -Unique
        )

        Write-Host ">>> winget: checking $($managedWinget.Count) managed package(s) for updates..." -ForegroundColor Cyan
        $wingetOutput = @(& winget list --upgrade-available --source winget --disable-interactivity 2>$null)
        $wingetExitCode = $LASTEXITCODE
        if ($wingetExitCode -ne 0) {
            Write-Warning "Could not query managed Winget updates (exit code $wingetExitCode)."
        }
        else {
            $wingetUpdates = @()
            foreach ($packageId in $managedWinget) {
                $escapedId = [regex]::Escape($packageId)
                # A source-restricted query may omit the Source column; older
                # Winget versions can still include it in redirected output.
                $pattern = "(?i)(?:^|\s)$escapedId\s+(?<Current>\S+)\s+(?<Available>\S+)(?:\s+winget)?\s*$"
                $matchingRow = $wingetOutput | Where-Object { $_ -match $pattern } | Select-Object -First 1
                if ($matchingRow -and $matchingRow -match $pattern) {
                    $wingetUpdates += [pscustomobject]@{
                        Id        = $packageId
                        Current   = $Matches.Current
                        Available = $Matches.Available
                    }
                }
            }

            if ($wingetUpdates.Count -eq 0) {
                Write-Host '>>> winget: all managed packages are already up to date.' -ForegroundColor Green
            }
            else {
                Write-Host ">>> winget: $($wingetUpdates.Count) managed update(s) available:" -ForegroundColor Cyan
                $nameWidth = ($wingetUpdates.Id | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
                foreach ($update in $wingetUpdates) {
                    Write-Host ("      {0}  {1} -> {2}" -f $update.Id.PadRight($nameWidth), $update.Current, $update.Available) -ForegroundColor Cyan
                }

                if (-not $Winget) {
                    Write-Host ">>> winget: report only; run 'aiu -Winget' to install these updates." -ForegroundColor Yellow
                }
                else {
                    $wingetFailures = @()
                    $wingetUpgradeIndex = 0
                    foreach ($update in $wingetUpdates) {
                        $wingetUpgradeIndex++
                        $wingetArgs = @('upgrade', '--source', 'winget', '--exact', '--id', $update.Id)
                        Write-Host (">>> winget: [{0}/{1}] upgrading {2}  {3} -> {4}" -f $wingetUpgradeIndex, $wingetUpdates.Count, $update.Id, $update.Current, $update.Available) -ForegroundColor Cyan
                        try {
                            # A child process lets installers display UI and request UAC elevation.
                            $process = Start-Process -FilePath 'winget' -ArgumentList $wingetArgs -NoNewWindow -Wait -PassThru
                            if ($process.ExitCode -ne 0) {
                                $wingetFailures += "$($update.Id) (exit code $($process.ExitCode))"
                            }
                        }
                        catch {
                            $wingetFailures += "$($update.Id) ($($_.Exception.Message))"
                        }
                    }
                    if ($wingetFailures.Count -eq 0) {
                        Write-Host 'Winget-managed packages updated successfully.' -ForegroundColor Green
                    }
                    else {
                        Write-Warning "Winget update failed for: $($wingetFailures -join ', ')"
                    }
                }
            }
        }
    }

    # npm stage: update all npm-installed managed packages in one command.
    # Candidates come from the Install-AiTools npm lists (single source of
    # truth). opencode-ai is deliberately excluded: the native
    # 'opencode upgrade' command above owns its updates.
    if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
        Write-Host '>>> npm: skipped (npm is not available).' -ForegroundColor Yellow
        return
    }

    $inventory = Get-GlobalNpmInventory
    if (-not $inventory.Available) {
        Write-Host '>>> npm: skipped (global package inventory is unavailable).' -ForegroundColor Yellow
        return
    }

    $managedNpm = @(@($_AiToolsInternal.NpmPackages) + @($_AiToolsInternal.MoreAiNpmPackages) | Sort-Object -Unique)
    $npmPackages = @($managedNpm | Where-Object { $inventory.Packages.ContainsKey($_) })
    if ($npmPackages.Count -eq 0) {
        Write-Host '>>> npm: no managed npm packages are installed.' -ForegroundColor DarkGray
        return
    }

    # Phase 1: show the checked set (managed packages that are actually
    # installed) with installed versions, plus managed packages skipped
    # because they are not installed.
    $candidateList = ($npmPackages | ForEach-Object { "$_ ($($inventory.Packages[$_]))" }) -join ', '
    Write-Host ">>> npm: checking $($npmPackages.Count) managed package(s): $candidateList" -ForegroundColor Cyan
    $skippedNpm = @($managedNpm | Where-Object { -not $inventory.Packages.ContainsKey($_) })
    if ($skippedNpm.Count -gt 0) {
        Write-Host ">>> npm: not installed, skipped: $($skippedNpm -join ', ')" -ForegroundColor DarkGray
    }

    # npm outdated exits 1 when updates exist; that is not an error, so
    # its exit code is deliberately ignored here.
    $outdatedJson = @(& npm outdated -g --json @npmPackages 2>$null)
    $outdatedText = ($outdatedJson -join [Environment]::NewLine).Trim()
    $outdatedData = $null
    if ($outdatedText) {
        try {
            $outdatedData = $outdatedText | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            Write-Warning "Could not determine which managed npm packages are outdated; updating all installed candidates. $($_.Exception.Message)"
        }
    }
    # Empty stdout means nothing is outdated. Non-empty stdout that
    # failed to parse falls back to updating every candidate.
    $outdatedPackages = @()
    if ($outdatedData) {
        $outdatedPackages = @($npmPackages | Where-Object { $_ -in @($outdatedData.PSObject.Properties.Name) })
    }
    elseif ($outdatedText) {
        $outdatedPackages = $npmPackages
    }

    if ($outdatedPackages.Count -eq 0) {
        Write-Host '>>> npm: all managed npm packages are already up to date.' -ForegroundColor Green
        return
    }

    # Phase 2: show current -> latest per package before touching
    # anything. For -g, wanted == latest in practice; fall back to
    # wanted (then the inventory version) when a field is absent.
    Write-Host ">>> npm: $($outdatedPackages.Count) update(s) available:" -ForegroundColor Cyan
    $nameWidth = ($outdatedPackages | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
    foreach ($name in $outdatedPackages) {
        $info = if ($outdatedData) { $outdatedData.$name } else { $null }
        $latest = if ($info -and $info.latest) { $info.latest } elseif ($info -and $info.wanted) { $info.wanted } else { '?' }
        $current = if ($info -and $info.current) { $info.current } else { $inventory.Packages[$name] }
        Write-Host ("      {0}  {1} -> {2}" -f $name.PadRight($nameWidth), $current, $latest) -ForegroundColor Cyan
    }

    $npmArgs = @('up', '-g') + $outdatedPackages
    Write-Host ">>> npm: npm $($npmArgs -join ' ')" -ForegroundColor Cyan
    & npm @npmArgs
    if ($LASTEXITCODE -eq 0) {
        Write-Host 'npm-managed packages updated successfully.' -ForegroundColor Green
    }
    else {
        Write-Warning "npm update failed with exit code $LASTEXITCODE for: $($outdatedPackages -join ', ')"
    }
}
Set-Alias -Name aiu -Value Invoke-AiUpgrade

# === AI provider usage-query functions ===
# Provides provider-specific Get-*Usage functions and Get-AllAiUsage to discover
# and run the currently loaded usage functions. Call the provider functions after
# the vault credentials load further down (Load-AiApiKeysFromCS) so
# $env:MINIMAX_API_KEY, $env:ZAI_API_KEY, $env:DEEPSEEK_API_KEY, and
# $env:KIMI_CODE_PLAN_API_KEY are populated.


# --- Get-MinimaxUsage ------------------------------------------------------
# Queries MiniMax's token-plan endpoint for remaining quotas and burn rates
# over the current interval and the current week. Stashes the parsed
# response in $Global:minimaxLastQuery and returns it.

function Get-MinimaxUsage {
<#
.SYNOPSIS
    Queries MiniMax's token-plan endpoint and reports per-model remaining quotas and burn rate.
.DESCRIPTION
    Calls https://www.minimax.io/v1/token_plan/remains with the API key in
    $env:MINIMAX_API_KEY, computes time-until-reset and burn rate
    (used / elapsed) for both the current interval and the current week per
    model, and flags concerns when remaining percent drops below threshold
    or burn outpaces linear consumption. Stores the parsed response in
    $Global:minimaxLastQuery and returns it.
.PARAMETER ApiKey
    MiniMax API key. Defaults to $env:MINIMAX_API_KEY.
.PARAMETER LowPercent
    Remaining-percent threshold below which a model is reported as LOW.
.PARAMETER CriticalPercent
    Remaining-percent threshold below which a model is reported as CRITICAL.
.PARAMETER ResetWarnHours
    Flag an interval that resets within this many hours.
.PARAMETER BurnWarnRatio
    Flag a model whose burn rate exceeds this multiple of linear consumption.
.PARAMETER All
    When supplied, prints the raw API response inline. Otherwise the raw
    response stays in $Global:minimaxLastQuery.
.EXAMPLE
    Get-MinimaxUsage
.EXAMPLE
    $r = Get-MinimaxUsage
    $r.model_remains | Where-Object { $_.current_interval_remaining_percent -lt 10 }
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-06
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

    $_ProfileHelpers.WriteUsageTimestamp($MyInvocation.MyCommand.Name)

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

    $_ProfileHelpers.WriteSection('Raw API response (MiniMax)')
    if ($All) { $resp | ConvertTo-Json -Depth 8 | Out-Host }
    else      { Write-Host '  (suppressed; stored in $Global:minimaxLastQuery. Use -All to display inline.)' -ForegroundColor DarkGray }

    $now = Get-Date
    $_ProfileHelpers.WriteSection('Per-model insights (MiniMax)')
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($m in $resp.model_remains) {
        $intervalStart   = $_ProfileHelpers.FromEpochMs([long]$m.start_time)
        $intervalEnd     = $_ProfileHelpers.FromEpochMs([long]$m.end_time)
        $intervalTotal   = $intervalEnd - $intervalStart
        $intervalElapsed = $now - $intervalStart
        if ($intervalElapsed.TotalSeconds -lt 0) { $intervalElapsed = [TimeSpan]::Zero }
        if ($intervalElapsed -gt $intervalTotal)  { $intervalElapsed = $intervalTotal }

        $weeklyStart   = $_ProfileHelpers.FromEpochMs([long]$m.weekly_start_time)
        $weeklyEnd     = $_ProfileHelpers.FromEpochMs([long]$m.weekly_end_time)
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
            Interval_Reset     = ($_ProfileHelpers.FormatDuration($iReset))
            Interval_Used      = $iUsedStr
            Weekly_Remaining   = ('{0}%' -f $wRemain)
            Weekly_Reset       = ($_ProfileHelpers.FormatDuration($wReset))
            Weekly_Used        = $wUsedStr
            Alerts             = ($flags -join ', ')
        })
    }
    $rows | Format-Table -AutoSize -Wrap | Out-Host

    $_ProfileHelpers.WriteSection('Concerns (MiniMax)')
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
            $concerns.Add(('[INFO]     {0}: interval resets in {1}' -f $name, ($_ProfileHelpers.FormatDuration($iReset))))
        }
    }
    if ($concerns.Count -eq 0) {
        Write-Host '  No concerns flagged.' -ForegroundColor Green
    } else {
        foreach ($c in $concerns) { Write-Host ('  - ' + $c) -ForegroundColor Yellow }
    }

    return $resp
}

# --- Get-ZaiUsage ----------------------------------------------------------
# Hits Z.AI's three monitoring endpoints (model-usage, tool-usage,
# quota/limit) over the last 24h, prints summaries, flags spikes and
# threshold breaches. Stashes the three responses in
# $Global:zaiLastQuery as @{ Model; Tool; Quota } and returns the
# hashtable.

function Get-ZaiUsage {
<#
.SYNOPSIS
    Queries Z.AI's model-usage, tool-usage, and quota-limit endpoints over
    the trailing 24 hours.
.DESCRIPTION
    Calls api.z.ai with the bearer token in $env:ZAI_API_KEY over a
    yesterday-at-current-hour to end-of-current-hour window. Prints model
    and tool usage totals, hourly averages, peak hours, hourly spikes
    (configurable multiplier), and quota usage with reset times. Stores
    the three responses in $Global:zaiLastQuery as @{ Model; Tool; Quota }
    and returns the same.
.PARAMETER Token
    Z.AI auth token. Defaults to $env:ZAI_API_KEY.
.PARAMETER McpWarnPercent
    Quota-percent threshold for the MCP/month window.
.PARAMETER TokenWarnPercent
    Quota-percent threshold for the 5-hour token window.
.PARAMETER SpikeRatio
    Multiplier used to flag hourly tool-usage spikes.
.PARAMETER All
    When supplied, prints the raw API responses inline. Otherwise the
    raw responses stay in $Global:zaiLastQuery.
.EXAMPLE
    Get-ZaiUsage
.EXAMPLE
    Get-ZaiUsage -McpWarnPercent 50 -All
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-08
#>
    [CmdletBinding()]
    param(
        [string]$Token = $env:ZAI_API_KEY,
        [int]$McpWarnPercent = 80,
        [int]$TokenWarnPercent = 80,
        [double]$SpikeRatio = 3.0,
        [switch]$All
    )

    $_ProfileHelpers.WriteUsageTimestamp($MyInvocation.MyCommand.Name)

    if (-not $Token) { Write-Error 'ZAI_API_KEY not set (env var or -Token).'; return }

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

    $_ProfileHelpers.WriteSection('Raw API responses (Z.AI)')
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

    $modelData = $_ProfileHelpers.UnwrapZaiData($modelResp)
    $toolData  = $_ProfileHelpers.UnwrapZaiData($toolResp)
    $quotaData = $_ProfileHelpers.UnwrapZaiData($quotaResp)

    $_ProfileHelpers.WriteSection('Model usage summary (Z.AI, last 24h)')
    if ($modelData) {
        $callStats = $_ProfileHelpers.GetSeriesStats($modelData.x_time, $modelData.modelCallCount)
        $tokStats  = $_ProfileHelpers.GetSeriesStats($modelData.x_time, $modelData.tokensUsage)
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

    $_ProfileHelpers.WriteSection('Tool usage summary (Z.AI, last 24h)')
    if ($toolData) {
        $netStats = $_ProfileHelpers.GetSeriesStats($toolData.x_time, $toolData.networkSearchCount)
        $webStats = $_ProfileHelpers.GetSeriesStats($toolData.x_time, $toolData.webReadMcpCount)
        $zreStats = $_ProfileHelpers.GetSeriesStats($toolData.x_time, $toolData.zreadMcpCount)
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
        $spikes += $_ProfileHelpers.GetSpikes($toolData.x_time, $toolData.networkSearchCount, $netStats.Avg, $SpikeRatio)
        $spikes += $_ProfileHelpers.GetSpikes($toolData.x_time, $toolData.webReadMcpCount, $webStats.Avg, $SpikeRatio)
        $spikes += $_ProfileHelpers.GetSpikes($toolData.x_time, $toolData.zreadMcpCount, $zreStats.Avg, $SpikeRatio)
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

    $_ProfileHelpers.WriteSection('Quota summary (Z.AI)')
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
                $reset   = ('{0} ({1} from now)' -f $resetDt.ToString('yyyy-MM-dd HH:mm'), ($_ProfileHelpers.FormatDuration($delta)))
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

    $_ProfileHelpers.WriteSection('Concerns (Z.AI)')
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
            $stats = $_ProfileHelpers.GetSeriesStats($toolData.x_time, $toolData.$seriesName)
            $spikes = $_ProfileHelpers.GetSpikes($toolData.x_time, $toolData.$seriesName, $stats.Avg, $SpikeRatio)
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

# --- Get-DeepseekUsage -----------------------------------------------------
# Queries DeepSeek's user-balance endpoint and estimates the token budget
# remaining under V4 Flash / V4 Pro pricing for each currency with a
# non-zero balance. Stashes the parsed response in
# $Global:deepseekLastQuery and returns it.

function Get-DeepseekUsage {
<#
.SYNOPSIS
    Queries DeepSeek's user-balance endpoint and estimates remaining token
    budget under V4 Flash / V4 Pro pricing.
.DESCRIPTION
    Calls https://api.deepseek.com/user/balance with the API key in
    $env:DEEPSEEK_API_KEY, prints the per-currency balances, and for each
    currency with a non-zero balance projects the token count available
    under every (model, scenario) pricing row in the embedded $pricing
    table. Flags concerns when the account is unavailable or balances
    are at or below threshold. Stores the parsed response in
    $Global:deepseekLastQuery and returns it.
.PARAMETER ApiKey
    DeepSeek API key. Defaults to $env:DEEPSEEK_API_KEY.
.PARAMETER LowBalanceUsd
    USD-balance threshold below which a LOW concern is raised.
.PARAMETER LowBalanceCny
    CNY-balance threshold below which a LOW concern is raised.
.PARAMETER All
    When supplied, prints the raw API response inline. Otherwise the raw
    response stays in $Global:deepseekLastQuery.
.EXAMPLE
    Get-DeepseekUsage
.EXAMPLE
    $d = Get-DeepseekUsage
    $d.balance_infos | Where-Object { $_.currency -eq 'CNY' }
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-06
#>
    [CmdletBinding()]
    param(
        [string]$ApiKey = $env:DEEPSEEK_API_KEY,
        [double]$LowBalanceUsd = 5.0,
        [double]$LowBalanceCny = 35.0,
        [switch]$All
    )

    $_ProfileHelpers.WriteUsageTimestamp($MyInvocation.MyCommand.Name)

    # Pricing per 1M tokens (cache_hit, cache_miss, output) for V4 Flash/Pro.
    # Source: api-docs.deepseek.com/quick_start/pricing (effective Aug 17, 2026 00:00 UTC+8 / Aug 16, 2026 16:00 UTC).
    $pricing = @(
        [pscustomobject]@{ Model = 'V4 Flash'; Tier = 'Off-Peak'; Scenario = 'Input  (cache hit)';  CostUsd = 0.007; CostCny = 0.05 }
        [pscustomobject]@{ Model = 'V4 Flash'; Tier = 'Off-Peak'; Scenario = 'Input  (cache miss)'; CostUsd = 0.22;  CostCny = 1.50 }
        [pscustomobject]@{ Model = 'V4 Flash'; Tier = 'Off-Peak'; Scenario = 'Output';              CostUsd = 0.66;  CostCny = 4.50 }
        [pscustomobject]@{ Model = 'V4 Flash'; Tier = 'Peak';     Scenario = 'Input  (cache hit)';  CostUsd = 0.014; CostCny = 0.10 }
        [pscustomobject]@{ Model = 'V4 Flash'; Tier = 'Peak';     Scenario = 'Input  (cache miss)'; CostUsd = 0.44;  CostCny = 3.00 }
        [pscustomobject]@{ Model = 'V4 Flash'; Tier = 'Peak';     Scenario = 'Output';              CostUsd = 1.32;  CostCny = 9.00 }
        [pscustomobject]@{ Model = 'V4 Pro';   Tier = 'Off-Peak'; Scenario = 'Input  (cache hit)';  CostUsd = 0.022; CostCny = 0.15 }
        [pscustomobject]@{ Model = 'V4 Pro';   Tier = 'Off-Peak'; Scenario = 'Input  (cache miss)'; CostUsd = 0.66;  CostCny = 4.50 }
        [pscustomobject]@{ Model = 'V4 Pro';   Tier = 'Off-Peak'; Scenario = 'Output';              CostUsd = 1.98;  CostCny = 13.50 }
        [pscustomobject]@{ Model = 'V4 Pro';   Tier = 'Peak';     Scenario = 'Input  (cache hit)';  CostUsd = 0.044; CostCny = 0.30 }
        [pscustomobject]@{ Model = 'V4 Pro';   Tier = 'Peak';     Scenario = 'Input  (cache miss)'; CostUsd = 1.32;  CostCny = 9.00 }
        [pscustomobject]@{ Model = 'V4 Pro';   Tier = 'Peak';     Scenario = 'Output';              CostUsd = 3.96;  CostCny = 27.00 }
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

    $_ProfileHelpers.WriteSection('Raw API response (DeepSeek)')
    if ($All) { $resp | ConvertTo-Json -Depth 8 | Out-Host }
    else      { Write-Host '  (suppressed; stored in $Global:deepseekLastQuery. Use -All to display inline.)' -ForegroundColor DarkGray }

    $balances = @{}
    foreach ($b in $resp.balance_infos) {
        $balances[[string]$b.currency] = [double]$b.total_balance
    }

    $_ProfileHelpers.WriteSection('Balance summary (DeepSeek)')
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
                Tier             = $p.Tier
                Scenario         = $p.Scenario
                Cost_per_1M      = ('{0} {1}' -f $cur, ($_ProfileHelpers.FormatPrice($cost)))
                Available_Tokens = ($_ProfileHelpers.FormatTokens($tokens))
            })
        }
        $title = if ($cur -eq 'USD') { 'Estimated USD token budget (DeepSeek)' } else { 'Estimated CNY token budget (DeepSeek)' }
        $_ProfileHelpers.WriteSection($title)
        $rows | Format-Table -AutoSize -Wrap | Out-Host
    }
    if (-not $hasAny) {
        $_ProfileHelpers.WriteSection('Estimated token budget (DeepSeek)')
        Write-Host '  (no USD or CNY balance > 0 reported)' -ForegroundColor DarkGray
    }
    Write-Host ('  Estimate formula: tokens = balance / cost_per_1M * 1,000,000.') -ForegroundColor DarkGray
    Write-Host ('  Actual spend depends on cache-hit ratio, prompt size, output length, and model mix.') -ForegroundColor DarkGray

    $_ProfileHelpers.WriteSection('Concerns (DeepSeek)')
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

# --- Get-KimiUsage ---------------------------------------------------------
# Queries Kimi Code's private membership-usage endpoint. The schema is
# observed rather than a documented public contract, so all fields are handled
# defensively. Stashes the parsed response in $Global:kimiLastQuery and returns it.

function Get-KimiUsage {
<#
.SYNOPSIS
    Queries Kimi Code membership quota, rolling limits, and Extra Usage status.
.DESCRIPTION
    Calls the private https://api.kimi.com/coding/v1/usages endpoint with the
    Kimi Code API key in $env:KIMI_CODE_PLAN_API_KEY. Reports membership details, weekly
    quota, rolling rate windows, local reset times, concurrent-session limit,
    aggregate quota, and optional Extra Usage wallet fields. Stores the parsed
    response in $Global:kimiLastQuery and returns it.
.PARAMETER ApiKey
    Kimi Code API key. Defaults to $env:KIMI_CODE_PLAN_API_KEY.
.PARAMETER BaseUrl
    Kimi Code OpenAI-compatible base URL. Defaults to KIMI_CODE_BASE_URL, then
    https://api.kimi.com/coding/v1. The function appends /usages.
.PARAMETER TimeoutSec
    HTTP request timeout in seconds. Defaults to the upstream client's 8 seconds.
.PARAMETER LowPercent
    Remaining-percent threshold at or below which a quota is reported as LOW.
.PARAMETER CriticalPercent
    Remaining-percent threshold at or below which a quota is reported as CRITICAL.
.PARAMETER ResetWarnHours
    Report an informational concern when a quota resets within this many hours.
.PARAMETER All
    When supplied, prints the raw API response inline. Otherwise the raw
    response stays in $Global:kimiLastQuery.
.EXAMPLE
    Get-KimiUsage
.EXAMPLE
    Get-KimiUsage -LowPercent 25 -CriticalPercent 10 -All
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-07
#>
    [CmdletBinding()]
    param(
        [string]$ApiKey = $env:KIMI_CODE_PLAN_API_KEY,
        [string]$BaseUrl = $env:KIMI_CODE_BASE_URL,
        [ValidateRange(1, 300)]
        [int]$TimeoutSec = 8,
        [ValidateRange(0, 100)]
        [int]$LowPercent = 30,
        [ValidateRange(0, 100)]
        [int]$CriticalPercent = 10,
        [ValidateRange(0, 8760)]
        [int]$ResetWarnHours = 1,
        [switch]$All
    )

    $_ProfileHelpers.WriteUsageTimestamp($MyInvocation.MyCommand.Name)

    if ([string]::IsNullOrWhiteSpace($ApiKey)) {
        Write-Error 'KIMI_CODE_PLAN_API_KEY not set (env var or -ApiKey).'
        return
    }
    if ($CriticalPercent -gt $LowPercent) {
        Write-Error 'CriticalPercent must be less than or equal to LowPercent.'
        return
    }

    $headers = @{
        Accept        = 'application/json'
        Authorization = "Bearer $ApiKey"
    }
    if ([string]::IsNullOrWhiteSpace($BaseUrl)) { $BaseUrl = 'https://api.kimi.com/coding/v1' }
    $usageUrl = $BaseUrl.TrimEnd('/') + '/usages'
    try {
        $resp = Invoke-RestMethod -Uri $usageUrl -Headers $headers -Method GET -TimeoutSec $TimeoutSec -ErrorAction Stop
    } catch {
        Write-Error "Kimi API call failed: $($_.Exception.Message)"
        Write-Host "  Fallback: run '/usage' in Kimi Code CLI or check the Kimi Code Console." -ForegroundColor DarkGray
        return
    }

    $Global:kimiLastQuery = $resp

    $_ProfileHelpers.WriteSection('Raw API response (Kimi Code)')
    if ($All) { $resp | ConvertTo-Json -Depth 8 | Out-Host }
    else      { Write-Host '  (suppressed; stored in $Global:kimiLastQuery. Use -All to display inline.)' -ForegroundColor DarkGray }

    $_ProfileHelpers.WriteSection('Membership summary (Kimi Code)')
    [pscustomobject]@{
        Membership       = if ($resp.user -and $resp.user.membership) { $resp.user.membership.level } else { 'n/a' }
        Subscription     = if ($resp.PSObject.Properties['subType']) { $resp.subType } else { 'n/a' }
        Authentication   = if ($resp.authentication) { $resp.authentication.method } else { 'n/a' }
        Parallel_Limit   = if ($resp.parallel) { $resp.parallel.limit } else { 'n/a' }
    } | Format-Table -AutoSize | Out-Host

    # Normalize weekly and rolling quota objects before formatting them together.
    $quotaItems = New-Object System.Collections.Generic.List[object]
    if ($resp.usage) {
        $weeklyLabel = if ($resp.usage.name) { $resp.usage.name } elseif ($resp.usage.title) { $resp.usage.title } else { 'Weekly limit' }
        $quotaItems.Add([pscustomobject]@{ Label = $weeklyLabel; Detail = $resp.usage })
    }
    $limitIndex = 0
    foreach ($limitItem in @($resp.limits)) {
        if (-not $limitItem) { continue }
        $limitIndex++
        $detail = if ($limitItem.detail) { $limitItem.detail } else { $limitItem }
        $duration = if ($limitItem.window -and $null -ne $limitItem.window.duration) {
            $limitItem.window.duration
        } elseif ($null -ne $limitItem.duration) {
            $limitItem.duration
        } else {
            $detail.duration
        }
        $unit = if ($limitItem.window -and $limitItem.window.timeUnit) {
            [string]$limitItem.window.timeUnit
        } elseif ($limitItem.timeUnit) {
            [string]$limitItem.timeUnit
        } else {
            [string]$detail.timeUnit
        }
        $unitLabel = switch ($unit) {
            'TIME_UNIT_MINUTE' { 'min' }
            'TIME_UNIT_HOUR'   { 'h' }
            'TIME_UNIT_DAY'    { 'd' }
            default            { if ($unit) { $unit } else { 'window' } }
        }
        $label = if ($limitItem.name) {
            [string]$limitItem.name
        } elseif ($limitItem.title) {
            [string]$limitItem.title
        } elseif ($limitItem.scope) {
            [string]$limitItem.scope
        } elseif ($detail.name) {
            [string]$detail.name
        } elseif ($detail.title) {
            [string]$detail.title
        } elseif ($detail.scope) {
            [string]$detail.scope
        } elseif ($null -ne $duration) {
            if ($unit -like '*MINUTE*' -and [double]$duration -ge 60 -and ([double]$duration % 60) -eq 0) {
                '{0:N0}h limit' -f ([double]$duration / 60)
            } else {
                "$duration$unitLabel limit"
            }
        } else {
            "Limit #$limitIndex"
        }
        $quotaItems.Add([pscustomobject]@{ Label = $label; Detail = $detail })
    }

    $_ProfileHelpers.WriteSection('Quota summary (Kimi Code)')
    $rows = New-Object System.Collections.Generic.List[object]
    $concerns = New-Object System.Collections.Generic.List[string]
    foreach ($item in $quotaItems) {
        $detail = $item.Detail
        $limit = if ($detail -and $null -ne $detail.limit) { [double]$detail.limit } else { $null }
        $used = if ($detail -and $null -ne $detail.used) { [double]$detail.used } else { $null }
        $remaining = if ($detail -and $null -ne $detail.remaining) { [double]$detail.remaining } else { $null }
        if ($null -eq $used -and $null -ne $limit -and $null -ne $remaining) { $used = $limit - $remaining }
        if ($null -eq $remaining -and $null -ne $limit -and $null -ne $used) { $remaining = $limit - $used }
        $remainingPercent = if ($null -ne $limit -and $limit -gt 0 -and $null -ne $remaining) { 100 * $remaining / $limit } else { $null }

        $resetText = 'n/a'
        $resetDelta = $null
        $resetValue = $null
        foreach ($resetKey in @('reset_at', 'resetAt', 'reset_time', 'resetTime')) {
            if ($detail -and $detail.PSObject.Properties[$resetKey] -and $detail.$resetKey) {
                $resetValue = [string]$detail.$resetKey
                break
            }
        }
        if ($resetValue) {
            $resetDto = [DateTimeOffset]::MinValue
            if ([DateTimeOffset]::TryParse($resetValue, [ref]$resetDto)) {
                $resetLocal = $resetDto.ToLocalTime().LocalDateTime
                $resetDelta = $resetLocal - (Get-Date)
                if ($resetDelta.TotalSeconds -gt 0) {
                    $resetText = '{0} ({1} from now)' -f $resetLocal.ToString('yyyy-MM-dd HH:mm'), ($_ProfileHelpers.FormatDuration($resetDelta))
                } else {
                    $resetText = '{0} (reset due)' -f $resetLocal.ToString('yyyy-MM-dd HH:mm')
                }
            }
        } else {
            foreach ($relativeKey in @('reset_in', 'resetIn', 'ttl', 'window')) {
                if ($detail -and $detail.PSObject.Properties[$relativeKey] -and $null -ne $detail.$relativeKey) {
                    $relativeSeconds = 0L
                    if ([long]::TryParse([string]$detail.$relativeKey, [ref]$relativeSeconds) -and $relativeSeconds -gt 0) {
                        $resetDelta = [TimeSpan]::FromSeconds($relativeSeconds)
                        $resetText = 'in {0}' -f ($_ProfileHelpers.FormatDuration($resetDelta))
                        break
                    }
                }
            }
        }

        $rows.Add([pscustomobject]@{
            Window            = $item.Label
            Used              = if ($null -ne $used) { $used } else { 'n/a' }
            Limit             = if ($null -ne $limit) { $limit } else { 'n/a' }
            Remaining         = if ($null -ne $remaining) { $remaining } else { 'n/a' }
            Remaining_Percent = if ($null -ne $remainingPercent) { '{0:N1}%' -f $remainingPercent } else { 'n/a' }
            Reset             = $resetText
        })

        if ($null -ne $remainingPercent) {
            if ($remainingPercent -le $CriticalPercent) {
                $concerns.Add(('[CRITICAL] {0}: only {1:N1}% remaining' -f $item.Label, $remainingPercent))
            } elseif ($remainingPercent -le $LowPercent) {
                $concerns.Add(('[LOW]      {0}: {1:N1}% remaining' -f $item.Label, $remainingPercent))
            }
        }
        if ($null -ne $resetDelta -and $resetDelta.TotalSeconds -gt 0 -and $resetDelta.TotalHours -le $ResetWarnHours) {
            $concerns.Add(('[INFO]     {0}: resets in {1}' -f $item.Label, ($_ProfileHelpers.FormatDuration($resetDelta))))
        }
    }
    if ($rows.Count -gt 0) { $rows | Format-Table -AutoSize -Wrap | Out-Host }
    else { Write-Host '  (no weekly or rolling quota data returned)' -ForegroundColor DarkGray }

    if ($resp.totalQuota) {
        $_ProfileHelpers.WriteSection('Aggregate quota (Kimi Code)')
        [pscustomobject]@{
            Limit     = if ($null -ne $resp.totalQuota.limit) { $resp.totalQuota.limit } else { 'n/a' }
            Remaining = if ($null -ne $resp.totalQuota.remaining) { $resp.totalQuota.remaining } else { 'n/a' }
        } | Format-Table -AutoSize | Out-Host
    }

    $_ProfileHelpers.WriteSection('Extra Usage (Kimi Code)')
    $wallet = $resp.boosterWallet
    if ($wallet -and $wallet.balance -and $wallet.balance.type -eq 'BOOSTER' -and [double]$wallet.balance.amount -gt 0) {
        # Upstream stores balance amounts as fixed-point cents (1,000,000 units per cent).
        $totalCentsRaw = [double]$wallet.balance.amount / 1000000
        $leftCentsRaw = if ($null -ne $wallet.balance.amountLeft) { [double]$wallet.balance.amountLeft / 1000000 } else { 0 }
        $totalCents = if ($totalCentsRaw -gt 0 -and $totalCentsRaw -lt 1) { 1 } else { [Math]::Round($totalCentsRaw) }
        $leftCents = if ($leftCentsRaw -gt 0 -and $leftCentsRaw -lt 1) { 1 } else { [Math]::Round($leftCentsRaw) }
        $monthlyLimitCents = if ($wallet.monthlyChargeLimit -and $null -ne $wallet.monthlyChargeLimit.priceInCents) { [double]$wallet.monthlyChargeLimit.priceInCents } else { 0 }
        $monthlyUsedCents = if ($wallet.monthlyUsed -and $null -ne $wallet.monthlyUsed.priceInCents) { [double]$wallet.monthlyUsed.priceInCents } else { 0 }
        $currency = if ($wallet.monthlyChargeLimit -and $wallet.monthlyChargeLimit.currency) {
            [string]$wallet.monthlyChargeLimit.currency
        } elseif ($wallet.monthlyUsed -and $wallet.monthlyUsed.currency) {
            [string]$wallet.monthlyUsed.currency
        } else {
            'USD'
        }
        [pscustomobject]@{
            Currency              = $currency
            Balance               = '{0:N2}' -f ($leftCents / 100)
            Total                 = '{0:N2}' -f ($totalCents / 100)
            Monthly_Limit_Enabled = [bool]$wallet.monthlyChargeLimitEnabled
            Monthly_Limit         = if ($monthlyLimitCents -gt 0) { '{0:N2}' -f ($monthlyLimitCents / 100) } else { 'unlimited' }
            Monthly_Used          = '{0:N2}' -f ($monthlyUsedCents / 100)
        } | Format-Table -AutoSize | Out-Host
    } else {
        Write-Host '  No Extra Usage wallet reported.' -ForegroundColor DarkGray
    }

    $_ProfileHelpers.WriteSection('Concerns (Kimi Code)')
    if (-not $resp.usage) {
        $concerns.Add('[WARN] No weekly quota data returned')
    }
    if ($concerns.Count -eq 0) {
        Write-Host '  No concerns flagged.' -ForegroundColor Green
    } else {
        foreach ($concern in $concerns) { Write-Host ('  - ' + $concern) -ForegroundColor Yellow }
    }

    return $resp
}

# --- Get-QwenUsage ---------------------------------------------------------
# Queries QwenCloud Token Plan's private console quota endpoint. The browser
# session cookie is stored separately in Windows Credential Manager and is
# never copied into an environment variable or returned with query results.

function Get-QwenUsage {
<#
.SYNOPSIS
    Queries QwenCloud Token Plan five-hour and seven-day Credit usage.
.DESCRIPTION
    Retrieves a QwenCloud console Cookie header from Windows Credential Manager,
    obtains a temporary console security token, and calls the Token Plan Personal
    quota endpoint. On first use, displays browser DevTools capture instructions
    and prompts for the Cookie using hidden input. A newly entered Cookie is saved
    only after a successful quota query.
.PARAMETER Setup
    Forces the Cookie capture and validation flow, replacing the stored value only
    when the new Cookie successfully queries quota.
.PARAMETER TimeoutSec
    HTTP timeout for each QwenCloud request.
.PARAMETER LowPercent
    Remaining-percent threshold at or below which a quota is reported as LOW.
.PARAMETER CriticalPercent
    Remaining-percent threshold at or below which a quota is reported as CRITICAL.
.PARAMETER ResetWarnHours
    Reports an informational concern when a quota resets within this many hours.
.PARAMETER All
    Prints the raw quota response. Otherwise it remains in $Global:qwenLastQuery.
.EXAMPLE
    Get-QwenUsage
.EXAMPLE
    Get-QwenUsage -Setup
.EXAMPLE
    Get-QwenUsage -LowPercent 25 -CriticalPercent 10 -All
.NOTES
    The Cookie is sensitive and session-lived. If QwenCloud rejects a stored
    session, rerun Get-QwenUsage -Setup to capture and validate a replacement.
#>
    [CmdletBinding()]
    param(
        [switch]$Setup,
        [ValidateRange(1, 300)]
        [int]$TimeoutSec = 15,
        [ValidateRange(0, 100)]
        [int]$LowPercent = 30,
        [ValidateRange(0, 100)]
        [int]$CriticalPercent = 10,
        [ValidateRange(0, 8760)]
        [int]$ResetWarnHours = 1,
        [switch]$All,
        [Parameter(DontShow = $true)]
        [scriptblock]$QueryInvoker
    )

    $_ProfileHelpers.WriteUsageTimestamp($MyInvocation.MyCommand.Name)

    $credentialResource = 'QWEN_TOKEN_PLAN_COOKIE'
    $credentialUserName = 'qwencloud-cookie'
    $consoleOrigin = 'https://home.qwencloud.com'
    $dashboardUrl = "$consoleOrigin/billing/subscription/token-plan-individual"
    $userInfoUrl = "$consoleOrigin/tool/user/info.json"
    $gatewayAction = 'IntlBroadScopeAspnGateway'
    $usageApi = 'zeldaHttp.apikeyMgr./tokenplan/personal/api/v2/usage'
    $usageUrl = "https://cs-data.qwencloud.com/data/api.json?product=sfm_bailian&action=$gatewayAction&api=$([Uri]::EscapeDataString($usageApi))"
    $browserUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36'

    # Read the Cookie directly from the per-user Credential Locker. It is
    # deliberately not routed through Get-AiApiKey or an environment variable.
    function Get-StoredCookie {
        [void][Windows.Security.Credentials.PasswordVault, Windows.Security.Credentials, ContentType=WindowsRuntime]
        $vault = New-Object Windows.Security.Credentials.PasswordVault
        try {
            $credential = $vault.Retrieve($credentialResource, $credentialUserName)
            $credential.RetrievePassword()
            return $credential.Password
        } catch {
            return $null
        }
    }

    # Persist an already validated Cookie in the same Credential Locker used by
    # the profile's API keys, but under a distinct resource and user name.
    function Save-StoredCookie([string]$Cookie) {
        [void][Windows.Security.Credentials.PasswordVault, Windows.Security.Credentials, ContentType=WindowsRuntime]
        $vault = New-Object Windows.Security.Credentials.PasswordVault
        $credential = New-Object Windows.Security.Credentials.PasswordCredential(
            $credentialResource,
            $credentialUserName,
            $Cookie
        )
        $vault.Add($credential)
    }

    # Prompt without echoing the Cookie, then normalize and reject malformed or
    # multiline input before it can reach an HTTP header.
    function Read-NewCookie {
        Write-Host ''
        Write-Host 'QwenCloud Token Plan Cookie setup' -ForegroundColor Cyan
        Write-Host "  1. Sign in and open: $dashboardUrl"
        Write-Host '  2. Open browser DevTools > Network and reload the page.'
        Write-Host '  3. Filter for api.json, then inspect the api query parameter.'
        Write-Host "  4. Select exactly: $usageApi" -ForegroundColor Yellow
        Write-Host '     Do not select: zeldaEasy.bailian-telemetry.platform-model.getModelMonitorDataWithOss' -ForegroundColor DarkGray
        Write-Host '  5. Copy the complete Request Headers > Cookie value.'
        Write-Host ''

        $secure = Read-Host -AsSecureString -Prompt 'Paste the complete Cookie header (input hidden; blank to cancel)'
        if ($null -eq $secure -or $secure.Length -eq 0) { return $null }

        $pointer = [IntPtr]::Zero
        try {
            $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
            $cookie = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
        } finally {
            if ($pointer -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
            }
        }

        $cookie = ($cookie.Trim() -replace '^Cookie:\s*', '').Trim()
        if (-not $cookie) { return $null }
        if ($cookie -match '[\r\n]') {
            throw 'The Cookie must be a single-line request-header value.'
        }
        $validPairs = @(
            $cookie.Split(';') |
                Where-Object { $_ -match '^\s*[^=;]+\s*=\s*.+$' }
        )
        if ($validPairs.Count -eq 0) {
            throw 'The Cookie does not contain a complete name=value pair.'
        }
        return $cookie
    }

    # Execute both private console requests and return only the raw quota payload
    # plus normalized limits. Cookie and secToken never leave this helper.
    function Invoke-QwenCloudUsageQuery([string]$Cookie) {
        function Get-JsonProperty([object]$InputObject, [string]$Name) {
            if ($null -eq $InputObject) { return $null }
            $property = $InputObject.PSObject.Properties[$Name]
            if ($null -eq $property) { return $null }
            return $property.Value
        }

        function Send-JsonRequest(
            [System.Net.Http.HttpClient]$Client,
            [System.Net.Http.HttpRequestMessage]$Request,
            [string]$Stage
        ) {
            $response = $null
            try {
                $response = $Client.SendAsync($Request).GetAwaiter().GetResult()
                $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                $status = [int]$response.StatusCode
                if ($status -in @(301, 302, 303, 307, 308, 401, 403)) {
                    throw "[QwenAuth] $Stage rejected the console session (HTTP $status)."
                }
                if (-not $response.IsSuccessStatusCode) {
                    throw "[QwenTransient] $Stage failed with HTTP $status $($response.ReasonPhrase)."
                }
                try {
                    return $body | ConvertFrom-Json
                } catch {
                    throw "[QwenResponse] $Stage returned invalid JSON."
                }
            } finally {
                if ($null -ne $response) { $response.Dispose() }
                $Request.Dispose()
            }
        }

        function ConvertTo-UsedPercent([object]$Value) {
            if ($null -eq $Value) { return $null }
            $parsed = 0.0
            if (-not [double]::TryParse(
                [string]$Value,
                [Globalization.NumberStyles]::Float,
                [Globalization.CultureInfo]::InvariantCulture,
                [ref]$parsed
            ) -or $parsed -lt 0) {
                return $null
            }
            $percent = if ($parsed -le 1) { $parsed * 100 } else { $parsed }
            return [Math]::Min(100, $percent)
        }

        function ConvertTo-ResetTime([object]$Value) {
            if ($null -eq $Value) { return $null }
            $parsed = 0.0
            if (-not [double]::TryParse(
                [string]$Value,
                [Globalization.NumberStyles]::Float,
                [Globalization.CultureInfo]::InvariantCulture,
                [ref]$parsed
            ) -or $parsed -le 0) {
                return $null
            }
            $milliseconds = if ($parsed -lt 1000000000000) { $parsed * 1000 } else { $parsed }
            try {
                return [DateTimeOffset]::FromUnixTimeMilliseconds([long]$milliseconds)
            } catch {
                return $null
            }
        }

        function Get-CookieValue([string]$Name) {
            foreach ($segment in $Cookie.Split(';')) {
                $separator = $segment.IndexOf('=')
                if ($separator -lt 0 -or $segment.Substring(0, $separator).Trim() -cne $Name) { continue }
                $value = $segment.Substring($separator + 1).Trim()
                if ($value) { return $value }
            }
            return $null
        }

        Add-Type -AssemblyName System.Net.Http
        $handler = New-Object System.Net.Http.HttpClientHandler
        $handler.AllowAutoRedirect = $false
        # Automatic cookie management replaces a manually supplied Cookie header
        # with the handler's empty CookieContainer, producing ConsoleNeedLogin.
        $handler.UseCookies = $false
        $client = New-Object System.Net.Http.HttpClient($handler)
        $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)

        try {
            $userRequest = New-Object System.Net.Http.HttpRequestMessage(
                [System.Net.Http.HttpMethod]::Get,
                $userInfoUrl
            )
            [void]$userRequest.Headers.TryAddWithoutValidation('Accept', 'application/json, text/plain, */*')
            [void]$userRequest.Headers.TryAddWithoutValidation('Cookie', $Cookie)
            [void]$userRequest.Headers.TryAddWithoutValidation('Referer', "$consoleOrigin/")
            [void]$userRequest.Headers.TryAddWithoutValidation('User-Agent', $browserUserAgent)
            $userPayload = Send-JsonRequest $client $userRequest 'QwenCloud session lookup'
            $userData = Get-JsonProperty $userPayload 'data'
            $secToken = Get-JsonProperty $userData 'secToken'
            $errorCode = [string](Get-JsonProperty $userPayload 'code')
            if ($errorCode -eq 'ConsoleNeedLogin' -or $secToken -isnot [string] -or -not $secToken) {
                throw '[QwenAuth] QwenCloud requires a fresh console login.'
            }

            $cornerstoneParam = [ordered]@{
                domain      = 'home.qwencloud.com'
                consoleSite = 'QWENCLOUD'
                console     = 'ONE_CONSOLE'
                xsp_lang    = 'en-US'
                protocol    = 'V2'
                productCode = 'p_efm'
            }
            $requestParams = [ordered]@{
                Api  = $usageApi
                Data = @{ cornerstoneParam = $cornerstoneParam }
                V    = '1.0'
            } | ConvertTo-Json -Depth 6 -Compress
            $form = New-Object 'System.Collections.Generic.Dictionary[string,string]'
            $form.Add('product', 'sfm_bailian')
            $form.Add('action', $gatewayAction)
            $form.Add('region', 'ap-southeast-1')
            $form.Add('sec_token', $secToken)
            $form.Add('params', $requestParams)

            $usageRequest = New-Object System.Net.Http.HttpRequestMessage(
                [System.Net.Http.HttpMethod]::Post,
                $usageUrl
            )
            $usageRequest.Content = New-Object System.Net.Http.FormUrlEncodedContent($form)
            [void]$usageRequest.Headers.TryAddWithoutValidation('Accept', 'application/json, text/plain, */*')
            [void]$usageRequest.Headers.TryAddWithoutValidation('Cookie', $Cookie)
            [void]$usageRequest.Headers.TryAddWithoutValidation('Origin', $consoleOrigin)
            [void]$usageRequest.Headers.TryAddWithoutValidation('Referer', $dashboardUrl)
            [void]$usageRequest.Headers.TryAddWithoutValidation('User-Agent', $browserUserAgent)
            [void]$usageRequest.Headers.TryAddWithoutValidation('X-Requested-With', 'XMLHttpRequest')
            $csrf = Get-CookieValue 'login_aliyunid_csrf'
            if (-not $csrf) { $csrf = Get-CookieValue 'csrf' }
            if ($csrf) {
                [void]$usageRequest.Headers.TryAddWithoutValidation('x-xsrf-token', $csrf)
                [void]$usageRequest.Headers.TryAddWithoutValidation('x-csrf-token', $csrf)
            }

            $payload = Send-JsonRequest $client $usageRequest 'QwenCloud usage lookup'
            $successResponse = Get-JsonProperty $payload 'successResponse'
            $responseData = Get-JsonProperty $payload 'data'
            if ($successResponse -eq $false -or $null -eq $responseData) {
                $failureShape = $payload | ConvertTo-Json -Depth 6 -Compress
                if ($failureShape -match '(?i)ConsoleNeedLogin|NeedLogin|not.?logged.?in|login.{0,24}expired|unauthorized|forbidden') {
                    throw '[QwenAuth] QwenCloud requires a fresh console login.'
                }
                throw '[QwenResponse] QwenCloud usage lookup returned an unsuccessful response.'
            }

            $stringData = Get-JsonProperty $responseData 'Data'
            if ($stringData -is [string]) {
                try { $responseData = $stringData | ConvertFrom-Json } catch {}
            }
            $dataV2 = Get-JsonProperty $responseData 'DataV2'
            $dataV2Data = Get-JsonProperty $dataV2 'data'
            if ($null -ne $dataV2Data) { $responseData = $dataV2Data }
            $nestedData = Get-JsonProperty $responseData 'data'
            if ($null -ne $nestedData) { $responseData = $nestedData }

            $limits = New-Object System.Collections.Generic.List[object]
            $fiveHourUsed = ConvertTo-UsedPercent (Get-JsonProperty $responseData 'per5HourPercentage')
            $sevenDayUsed = ConvertTo-UsedPercent (Get-JsonProperty $responseData 'per1WeekPercentage')
            if ($null -ne $fiveHourUsed) {
                $limits.Add([pscustomobject]@{
                    Window      = '5 Hour Credits'
                    UsedPercent = $fiveHourUsed
                    ResetAt     = ConvertTo-ResetTime (Get-JsonProperty $responseData 'per5HourResetTime')
                })
            }
            if ($null -ne $sevenDayUsed) {
                $limits.Add([pscustomobject]@{
                    Window      = '7 Day Credits'
                    UsedPercent = $sevenDayUsed
                    ResetAt     = ConvertTo-ResetTime (Get-JsonProperty $responseData 'per1WeekResetTime')
                })
            }
            if ($limits.Count -eq 0) {
                throw '[QwenResponse] QwenCloud returned no recognized quota fields.'
            }

            return [pscustomobject]@{
                Raw    = $payload
                Limits = [object[]]$limits
            }
        } catch [System.Threading.Tasks.TaskCanceledException] {
            throw '[QwenTransient] QwenCloud usage query timed out.'
        } catch [System.Net.Http.HttpRequestException] {
            throw "[QwenTransient] QwenCloud usage query failed: $($_.Exception.Message)"
        } finally {
            $client.Dispose()
            $handler.Dispose()
            $secToken = $null
        }
    }

    if ($CriticalPercent -gt $LowPercent) {
        Write-Error 'CriticalPercent must be less than or equal to LowPercent.'
        return
    }

    $newCookie = $false
    $cookie = if ($Setup) { $null } else { Get-StoredCookie }
    if (-not $cookie) {
        if (-not $Setup) {
            Write-Host 'No stored QwenCloud Cookie was found; starting setup.' -ForegroundColor Yellow
        }
        try {
            $cookie = Read-NewCookie
        } catch {
            Write-Error $_.Exception.Message
            return
        }
        if (-not $cookie) {
            Write-Host 'QwenCloud Cookie setup cancelled; no credential was changed.' -ForegroundColor Yellow
            return
        }
        $newCookie = $true
    }

    try {
        $query = if ($QueryInvoker) {
            & $QueryInvoker $cookie
        } else {
            Invoke-QwenCloudUsageQuery $cookie
        }
    } catch {
        $message = $_.Exception.Message
        if ($message.StartsWith('[QwenAuth]', [StringComparison]::Ordinal)) {
            $prefix = if ($newCookie) { 'The entered QwenCloud Cookie was rejected and was not saved.' } else { 'The stored QwenCloud Cookie is invalid or expired.' }
            Write-Error "$prefix Run: Get-QwenUsage -Setup"
        } elseif ($message.StartsWith('[QwenTransient]', [StringComparison]::Ordinal)) {
            Write-Error "$($message.Substring('[QwenTransient]'.Length).Trim()) The stored Cookie was retained."
        } else {
            Write-Error $message
        }
        $cookie = $null
        return
    }

    if ($newCookie) {
        try {
            Save-StoredCookie $cookie
            Write-Host 'Validated and saved the QwenCloud Cookie in Windows Credential Manager.' -ForegroundColor Green
        } catch {
            Write-Error "Quota query succeeded, but the Cookie could not be saved: $($_.Exception.Message)"
            $cookie = $null
            return
        }
    }
    $cookie = $null

    $Global:qwenLastQuery = $query.Raw
    $_ProfileHelpers.WriteSection('Raw API response (QwenCloud Token Plan)')
    if ($All) { $query.Raw | ConvertTo-Json -Depth 10 | Out-Host }
    else      { Write-Host '  (suppressed; stored in $Global:qwenLastQuery. Use -All to display inline.)' -ForegroundColor DarkGray }

    $_ProfileHelpers.WriteSection('Quota summary (QwenCloud Token Plan)')
    $rows = New-Object System.Collections.Generic.List[object]
    $concerns = New-Object System.Collections.Generic.List[string]
    $now = [DateTimeOffset]::Now
    foreach ($limit in @($query.Limits)) {
        $usedPercent = [Math]::Max(0, [Math]::Min(100, [double]$limit.UsedPercent))
        $remainingPercent = 100 - $usedPercent
        $status = if ($usedPercent -ge 100) {
            'EXHAUSTED'
        } elseif ($remainingPercent -le $CriticalPercent) {
            'CRITICAL'
        } elseif ($remainingPercent -le $LowPercent) {
            'LOW'
        } else {
            'OK'
        }

        $resetText = 'n/a'
        if ($limit.ResetAt -is [DateTimeOffset]) {
            $resetLocal = $limit.ResetAt.ToLocalTime()
            $delta = $resetLocal - $now
            if ($delta.TotalSeconds -gt 0) {
                $resetText = '{0} ({1} from now)' -f $resetLocal.ToString('yyyy-MM-dd HH:mm'), ($_ProfileHelpers.FormatDuration($delta))
                if ($delta.TotalHours -le $ResetWarnHours) {
                    $concerns.Add(('[INFO] {0}: resets in {1}' -f $limit.Window, ($_ProfileHelpers.FormatDuration($delta))))
                }
            } else {
                $resetText = '{0} (reset due)' -f $resetLocal.ToString('yyyy-MM-dd HH:mm')
            }
        }

        $rows.Add([pscustomobject]@{
            Window    = $limit.Window
            Used      = '{0:N1}%' -f $usedPercent
            Remaining = '{0:N1}%' -f $remainingPercent
            Status    = $status
            Reset     = $resetText
        })
        if ($status -ne 'OK') {
            $concerns.Add(('[{0}] {1}: {2:N1}% remaining' -f $status, $limit.Window, $remainingPercent))
        }
    }
    $rows | Format-Table -AutoSize -Wrap | Out-Host

    $_ProfileHelpers.WriteSection('Concerns (QwenCloud Token Plan)')
    if ($concerns.Count -eq 0) {
        Write-Host '  No concerns flagged.' -ForegroundColor Green
    } else {
        foreach ($concern in $concerns) { Write-Host ('  - ' + $concern) -ForegroundColor Yellow }
    }

    return $query.Raw
}

# --- Get-AgyUsage ----------------------------------------------------------
# Queries Antigravity's private cloudcode-pa retrieveUserQuotaSummary API endpoint.
# Extracts generic credentials from Windows Credential Manager under 'gemini:antigravity'.
# Stashes the parsed response in $Global:agyLastQuery and returns it.

function Get-AgyUsage {
<#
.SYNOPSIS
    Queries Google Antigravity CLI model quotas and remaining requests.
.DESCRIPTION
    Retrieves the active Google OAuth token for "gemini:antigravity" from the Windows
    Credential Manager using Win32 CredRead, reads the active project from the Antigravity cache,
    and calls the private cloudcode-pa retrieveUserQuotaSummary API endpoint. Reports remaining fraction,
    limit status, and reset times for each Gemini model.
.PARAMETER Project
    Google Cloud Project ID. Defaults to the value cached in ~/.gemini/antigravity-cli/cache/default_project_id.txt.
.PARAMETER TimeoutSec
    HTTP request timeout in seconds. Defaults to 8.
.PARAMETER All
    When supplied, prints the raw API response inline. Otherwise, the raw response is stored in $Global:agyLastQuery.
.EXAMPLE
    Get-AgyUsage
.EXAMPLE
    Get-AgyUsage -All
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-07
#>
    [CmdletBinding()]
    param(
        [string]$Project,
        [ValidateRange(1, 300)]
        [int]$TimeoutSec = 8,
        [ValidateRange(0, 100)]
        [int]$LowPercent = 30,
        [ValidateRange(0, 100)]
        [int]$CriticalPercent = 10,
        [ValidateRange(0, 8760)]
        [int]$ResetWarnHours = 1,
        [switch]$All
    )

    $_ProfileHelpers.WriteUsageTimestamp($MyInvocation.MyCommand.Name)

    if ($CriticalPercent -gt $LowPercent) {
        Write-Error 'CriticalPercent must be less than or equal to LowPercent.'
        return
    }

    # 1. Define C# type for CredRead if not already loaded in the session
    if (-not ([System.Management.Automation.PSTypeName]'AgyCredentialHelper').Type) {
        $code = @"
        using System;
        using System.Runtime.InteropServices;
        using System.Text;

        public class AgyCredentialHelper {
            [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern bool CredRead(string target, uint type, int reserved, out IntPtr credentialPtr);
            
            [DllImport("advapi32.dll", EntryPoint = "CredFree", SetLastError = true)]
            public static extern void CredFree(IntPtr credentialPtr);
            
            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct CREDENTIAL {
                public uint Flags;
                public uint Type;
                public string TargetName;
                public string Comment;
                public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
                public uint CredentialBlobSize;
                public IntPtr CredentialBlob;
                public uint Persist;
                public uint AttributeCount;
                public IntPtr Attributes;
                public string TargetAlias;
                public string UserName;
            }
            
            public static string GetSecret(string target) {
                IntPtr credPtr;
                if (CredRead(target, 1, 0, out credPtr)) {
                    try {
                        CREDENTIAL cred = (CREDENTIAL)Marshal.PtrToStructure(credPtr, typeof(CREDENTIAL));
                        if (cred.CredentialBlobSize > 0) {
                            byte[] blob = new byte[cred.CredentialBlobSize];
                            Marshal.Copy(cred.CredentialBlob, blob, 0, (int)cred.CredentialBlobSize);
                            return Encoding.UTF8.GetString(blob);
                        }
                    } finally {
                        CredFree(credPtr);
                    }
                }
                return null;
            }
        }
"@
        Add-Type -TypeDefinition $code -ErrorAction SilentlyContinue
    }

    # 2. Extract token from the Windows Credential Manager keyring
    $secretRaw = [AgyCredentialHelper]::GetSecret("gemini:antigravity")
    if (-not $secretRaw) {
        Write-Error "Failed to retrieve Antigravity credentials from Windows Credential Manager."
        Write-Host "Ensure that agy is logged in and active." -ForegroundColor Yellow
        return
    }

    $secretJson = $null
    try {
        $secretJson = ConvertFrom-Json $secretRaw
    } catch {
        Write-Error "Failed to parse keyring secret JSON."
        return
    }

    $accessToken = $secretJson.token.access_token
    if (-not $accessToken) {
        Write-Error "No access_token found in Antigravity credentials."
        return
    }

    # 3. Resolve Project ID
    if ([string]::IsNullOrWhiteSpace($Project)) {
        $projectFile = "$env:USERPROFILE\.gemini\antigravity-cli\cache\default_project_id.txt"
        if (Test-Path $projectFile) {
            $Project = (Get-Content $projectFile).Trim()
        } else {
            $Project = "default-cli-project"
        }
    }

    # 4. Invoke Quota Summary endpoints with fallback
    $headers = @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type"  = "application/json"
        "User-Agent"    = "vscode/1.X.X (Antigravity/4.3.0)"
    }
    $body = @{ "project" = $Project } | ConvertTo-Json

    $endpoints = @(
        "https://daily-cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary",
        "https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary"
    )

    $resp = $null
    $success = $false
    foreach ($url in $endpoints) {
        try {
            $resp = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body -TimeoutSec $TimeoutSec -ErrorAction Stop
            $success = $true
            break
        } catch {
            # Fallback to the next endpoint
        }
    }

    if (-not $success) {
        Write-Error "Antigravity retrieveUserQuotaSummary API call failed on all endpoints."
        return
    }

    $Global:agyLastQuery = $resp

    $_ProfileHelpers.WriteSection('Raw API response (Antigravity)')
    if ($All) { 
        $resp | ConvertTo-Json -Depth 8 | Out-Host 
    } else { 
        Write-Host '  (suppressed; stored in $Global:agyLastQuery. Use -All to display inline.)' -ForegroundColor DarkGray 
    }

    $_ProfileHelpers.WriteSection('Antigravity Grouped Quota Status')

    $concerns = New-Object System.Collections.Generic.List[string]

    foreach ($group in $resp.groups) {
        $groupDesc = if ($group.description) { " ($($group.description))" } else { "" }
        Write-Host "  * Group: $($group.displayName)$groupDesc" -ForegroundColor Cyan
        
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($bucket in $group.buckets) {
            $percentVal = [double]($bucket.remainingFraction * 100)
            
            $statusText = 'Quota available'
            if ($percentVal -lt 100.0) {
                if ($bucket.resetTime) {
                    $resetDto = [DateTimeOffset]::MinValue
                    if ([DateTimeOffset]::TryParse($bucket.resetTime, [ref]$resetDto)) {
                        $resetLocal = $resetDto.ToLocalTime().LocalDateTime
                        $resetDelta = $resetLocal - (Get-Date)
                        if ($resetDelta.TotalSeconds -gt 0) {
                            $h = [math]::Floor($resetDelta.TotalHours)
                            $m = $resetDelta.Minutes
                            $statusText = 'Refreshes in {0}h {1}m' -f $h, $m
                        } else {
                            $statusText = 'Reset due'
                        }
                    }
                }
            }

            $resetLocalStr = 'n/a'
            if ($bucket.resetTime) {
                $resetDto = [DateTimeOffset]::MinValue
                if ([DateTimeOffset]::TryParse($bucket.resetTime, [ref]$resetDto)) {
                    $resetLocalStr = $resetDto.ToLocalTime().LocalDateTime.ToString('yyyy-MM-dd HH:mm')
                }
            }

            $rows.Add([pscustomobject]@{
                Window      = $bucket.window
                Limit_Name  = $bucket.displayName
                Remaining   = '{0:N2}%' -f $percentVal
                Status      = $statusText
                Reset_Local = $resetLocalStr
            })

            # Check concerns thresholds
            if ($percentVal -le $CriticalPercent) {
                $concerns.Add(("[CRITICAL] {0} ({1}): only {2:N2}% remaining" -f $group.displayName, $bucket.displayName, $percentVal))
            } elseif ($percentVal -le $LowPercent) {
                $concerns.Add(("[LOW]      {0} ({1}): {2:N2}% remaining" -f $group.displayName, $bucket.displayName, $percentVal))
            }

            # Check reset time proximity warnings
            if ($bucket.resetTime) {
                $resetDto = [DateTimeOffset]::MinValue
                if ([DateTimeOffset]::TryParse($bucket.resetTime, [ref]$resetDto)) {
                    $resetLocal = $resetDto.ToLocalTime().LocalDateTime
                    $resetDelta = $resetLocal - (Get-Date)
                    if ($resetDelta.TotalSeconds -gt 0 -and $resetDelta.TotalHours -le $ResetWarnHours) {
                        $concerns.Add(("[INFO]     {0} ({1}): resets in {2}" -f $group.displayName, $bucket.displayName, ($_ProfileHelpers.FormatDuration($resetDelta))))
                    }
                }
            }
        }
        $rows | Format-Table -AutoSize | Out-Host
    }

    $_ProfileHelpers.WriteSection('Concerns (Antigravity)')
    if ($concerns.Count -eq 0) {
        Write-Host '  No concerns flagged.' -ForegroundColor Green
    } else {
        foreach ($concern in $concerns) {
            if ($concern -like '*CRITICAL*') {
                Write-Host ('  - ' + $concern) -ForegroundColor Red
            } elseif ($concern -like '*LOW*') {
                Write-Host ('  - ' + $concern) -ForegroundColor Yellow
            } else {
                Write-Host ('  - ' + $concern) -ForegroundColor Gray
            }
        }
    }

    return $resp
}

# --- Get-AllAiUsage --------------------------------------------------------
# Discovers currently loaded Get-*Usage functions, confirms the complete list,
# and invokes each accepted function sequentially.

function Get-AllAiUsage {
<#
.SYNOPSIS
    Discovers and sequentially runs all currently loaded Get-*Usage functions.
.DESCRIPTION
    Finds imported functions whose names match Get-*Usage, excludes this
    aggregate function, and displays the sorted execution list. Prompts once
    before running anything; pressing Enter accepts the default Yes response.
    Each discovered FunctionInfo is invoked directly so the reviewed command
    cannot change through later name resolution. A terminating failure in one
    function is reported without preventing the remaining functions from running.
.EXAMPLE
    Get-AllAiUsage
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-08
#>
    [CmdletBinding()]
    param()

    $_ProfileHelpers.WriteUsageTimestamp($MyInvocation.MyCommand.Name)

    $selfName = $MyInvocation.MyCommand.Name
    $usageFunctions = @(
        Get-Command -Name 'Get-*Usage' -CommandType Function -ListImported -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ine $selfName } |
            Sort-Object Name
    )

    if ($usageFunctions.Count -eq 0) {
        Write-Host 'No other Get-*Usage functions are currently loaded.' -ForegroundColor Yellow
        return
    }

    Write-Host ("Discovered {0} Get-*Usage function(s):" -f $usageFunctions.Count) -ForegroundColor Cyan
    for ($index = 0; $index -lt $usageFunctions.Count; $index++) {
        $usageFunction = $usageFunctions[$index]
        $origin = if ($usageFunction.ModuleName) { " ($($usageFunction.ModuleName))" } else { '' }
        Write-Host ('  {0}. {1}{2}' -f ($index + 1), $usageFunction.Name, $origin)
    }

    while ($true) {
        $choice = (Read-Host -Prompt ("Run these {0} usage function(s) sequentially? (Y/n)" -f $usageFunctions.Count)).Trim()
        if (-not $choice -or $choice -match '^(y|yes)$') { break }
        if ($choice -match '^(n|no)$') {
            Write-Host 'AI usage queries cancelled.' -ForegroundColor Yellow
            return
        }
        Write-Warning 'Enter Y or N, or press Enter to accept the default (Y).'
    }

    for ($index = 0; $index -lt $usageFunctions.Count; $index++) {
        $usageFunction = $usageFunctions[$index]
        Write-Host ("`n>>> [{0}/{1}] {2}" -f ($index + 1), $usageFunctions.Count, $usageFunction.Name) -ForegroundColor Cyan
        try {
            & $usageFunction
        } catch {
            Write-Warning ("{0} failed: {1}" -f $usageFunction.Name, $_.Exception.Message)
        }
    }
}

function Save-WebFile {
    <#
.SYNOPSIS
    Downloads a URL to a file using concurrent HTTP range requests (aria2-style).
.DESCRIPTION
    Wraps an embedded C# program (compiled once per session via Add-Type, the same
    pattern as Clear-WorkingSet) that splits a download into N contiguous byte
    ranges and fetches them over parallel connections, writing each range to its
    offset in a pre-allocated file. On a link where a single connection is
    throttled server-side (e.g. GitHub's release CDN caps one connection to
    ~30 MB/s), this is several times faster than a plain Invoke-WebRequest.

    Range support is detected with a one-byte probe: a 206 response carrying a
    Content-Range total means chunking is possible. Otherwise -- unsupported
    ranges, unknown size, a file below -ChunkThresholdMB, or any hard error --
    it transparently falls back to a single streaming download, so it is never
    slower-by-design than Invoke-WebRequest, only sometimes faster.

    Files smaller than -ChunkThresholdMB are single-streamed on purpose: they
    usually complete within the CDN's initial burst allowance where one
    connection is already full speed, so chunking would only add overhead.
.PARAMETER Uri
    The URL to download. Redirects are followed; the resolved URL is reused for
    every chunk.
.PARAMETER OutFile
    Destination path. If omitted, the (URL-decoded) file name from the URL is used
    in the current directory.
.PARAMETER Chunks
    Number of parallel connections when chunking (default 8, range 1-32). 8
    captures nearly all the available speedup on GitHub's CDN; more barely helps.
.PARAMETER MinChunkMB
    Minimum size per chunk (default 2). Caps the effective chunk count on smaller
    files so each connection still transfers a worthwhile amount.
.PARAMETER ChunkThresholdMB
    Only files at or above this size are chunked (default 16); smaller ones are
    single-streamed.
.PARAMETER TimeoutSec
    Per-connection read/write timeout in seconds (default 600).
.PARAMETER Force
    Overwrite an existing destination file.
.PARAMETER Quiet
    Suppress the live progress line and the completion summary.
.EXAMPLE
    Save-WebFile 'https://example.com/big.zip'
    # Chunked download to .\big.zip with a live progress line.
.EXAMPLE
    Save-WebFile -Uri $url -OutFile C:\tmp\a.zip -Chunks 16 -Force
.OUTPUTS
    System.IO.FileInfo for the downloaded file, or nothing on failure (a
    terminating error is written).
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-07

    Correctness note: chunked output is byte-identical to a single download
    (verified by SHA-256). Requires HttpWebRequest (Windows PowerShell / .NET).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $Uri,
        [Parameter(Position = 1)]
        [string] $OutFile,
        [ValidateRange(1, 32)]
        [int]    $Chunks = 8,
        [double] $MinChunkMB = 2,
        [double] $ChunkThresholdMB = 16,
        [int]    $TimeoutSec = 600,
        [switch] $Force,
        [switch] $Quiet
    )

    # Compile the embedded chunked-download program once into the session; repeat
    # calls reuse the loaded type. Guarded by a global flag like Clear-WorkingSet.
    if ($null -eq $Global:hasChunkDownloaderType) {
        $code = @"
using System;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace ChunkDownload
{
    public class DownloadResult
    {
        public bool Success;
        public long Bytes;
        public long ExpectedBytes;
        public long ElapsedMs;
        public int Chunks;
        public bool FellBack;
        public string Error;
        public string FinalUrl;
    }

    public class Downloader
    {
        static long _written;

        static Downloader()
        {
            try { ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | (SecurityProtocolType)12288; }
            catch { ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12; }
            ServicePointManager.DefaultConnectionLimit = 256;
            ServicePointManager.Expect100Continue = false;
        }

        static HttpWebRequest MakeReq(string url, int timeoutMs)
        {
            HttpWebRequest r = (HttpWebRequest)WebRequest.Create(url);
            r.Method = "GET";
            r.AllowAutoRedirect = true;
            r.UserAgent = "$_DefaultUserAgent";
            r.Timeout = 60000;
            r.ReadWriteTimeout = timeoutMs;
            r.KeepAlive = true;
            r.Proxy = WebRequest.DefaultWebProxy;
            return r;
        }

        // Returns total size if the server supports ranges (206 + Content-Range), else -1. Sets finalUrl.
        static long Probe(string url, int timeoutMs, out string finalUrl)
        {
            finalUrl = url;
            HttpWebRequest r = MakeReq(url, timeoutMs);
            r.AddRange(0, 0);
            using (HttpWebResponse resp = (HttpWebResponse)r.GetResponse())
            {
                finalUrl = resp.ResponseUri.ToString();
                if (resp.StatusCode == HttpStatusCode.PartialContent)
                {
                    string cr = resp.Headers["Content-Range"];
                    if (!string.IsNullOrEmpty(cr))
                    {
                        int slash = cr.LastIndexOf('/');
                        if (slash >= 0)
                        {
                            long t;
                            if (long.TryParse(cr.Substring(slash + 1).Trim(), out t) && t > 0) return t;
                        }
                    }
                }
                return -1;
            }
        }

        static void ProgressLoop(long total, ManualResetEvent done)
        {
            DateTime start = DateTime.UtcNow;
            bool more = true;
            while (more)
            {
                more = !done.WaitOne(400);
                long w = Interlocked.Read(ref _written);
                double secs = (DateTime.UtcNow - start).TotalSeconds;
                double mbps = secs > 0 ? (w / 1048576.0) / secs : 0;
                double pct = total > 0 ? (w * 100.0 / total) : 0;
                Console.Write(string.Format("\r      {0,5:0.0}%  {1,7:0.0} / {2,7:0.0} MB  {3,6:0.0} MB/s   ",
                    pct, w / 1048576.0, total / 1048576.0, mbps));
            }
            Console.Write("\n");
        }

        static void DownloadChunk(string url, string origUrl, string path, long start, long end, int timeoutMs, int maxRetries)
        {
            int attempt = 0;
            string useUrl = url;
            while (true)
            {
                attempt++;
                try
                {
                    HttpWebRequest r = MakeReq(useUrl, timeoutMs);
                    r.AddRange(start, end);
                    using (HttpWebResponse resp = (HttpWebResponse)r.GetResponse())
                    using (Stream rs = resp.GetResponseStream())
                    using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite))
                    {
                        // Guard against a server that ignores Range: writing a full
                        // 200 body at this offset would silently corrupt the file.
                        if (resp.StatusCode != HttpStatusCode.PartialContent)
                            throw new IOException("Expected 206 for range request, got " + (int)resp.StatusCode);
                        fs.Seek(start, SeekOrigin.Begin);
                        byte[] buf = new byte[81920];
                        int n;
                        long got = 0;
                        while ((n = rs.Read(buf, 0, buf.Length)) > 0)
                        {
                            fs.Write(buf, 0, n);
                            Interlocked.Add(ref _written, n);
                            got += n;
                        }
                        // A dropped connection can surface as a clean end-of-stream
                        // instead of an exception; the pre-allocated file would keep
                        // zeros for the missing tail and pass the final size check.
                        // Make it loud so the retry loop fetches the range again.
                        long want = end - start + 1;
                        if (got != want)
                            throw new IOException(string.Format("Short read: got {0} of {1} bytes for range {2}-{3}", got, want, start, end));
                    }
                    return;
                }
                catch (WebException we)
                {
                    // A 403 usually means a time-limited signed CDN URL expired; re-resolve from the original.
                    HttpWebResponse er = we.Response as HttpWebResponse;
                    if (er != null && (int)er.StatusCode == 403 && useUrl != origUrl) useUrl = origUrl;
                    if (attempt > maxRetries) throw;
                    Thread.Sleep(500 * attempt);
                }
                catch
                {
                    if (attempt > maxRetries) throw;
                    Thread.Sleep(500 * attempt);
                }
            }
        }

        static void SingleStream(string url, string path, int timeoutMs)
        {
            HttpWebRequest r = MakeReq(url, timeoutMs);
            using (HttpWebResponse resp = (HttpWebResponse)r.GetResponse())
            using (Stream rs = resp.GetResponseStream())
            using (FileStream fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                byte[] buf = new byte[81920];
                int n;
                while ((n = rs.Read(buf, 0, buf.Length)) > 0)
                {
                    fs.Write(buf, 0, n);
                    Interlocked.Add(ref _written, n);
                }
            }
        }

        public static DownloadResult Download(string url, string path, int chunks, long minChunkBytes, long chunkThresholdBytes, int timeoutSec, bool quiet)
        {
            DownloadResult res = new DownloadResult();
            res.ExpectedBytes = -1;
            Interlocked.Exchange(ref _written, 0);
            DateTime t0 = DateTime.UtcNow;
            int timeoutMs = timeoutSec * 1000;

            string finalUrl = url;
            long total = -1;
            try { total = Probe(url, timeoutMs, out finalUrl); }
            catch { total = -1; finalUrl = url; }
            res.FinalUrl = finalUrl;

            if (chunks < 1) chunks = 1;
            int useChunks = chunks;
            bool chunked = total > 0 && total >= chunkThresholdBytes;
            if (chunked)
            {
                res.ExpectedBytes = total;
                long maxByMin = total / Math.Max(minChunkBytes, 1L);
                if (maxByMin < 1) maxByMin = 1;
                if (useChunks > maxByMin) useChunks = (int)maxByMin;
                if (useChunks < 1) useChunks = 1;
                if (useChunks == 1) chunked = false;
            }

            ManualResetEvent done = new ManualResetEvent(false);
            Thread progThread = null;

            try
            {
                if (!chunked)
                {
                    res.FellBack = true;
                    res.Chunks = 1;
                    if (!quiet && total > 0) { progThread = new Thread(delegate() { ProgressLoop(total, done); }); progThread.Start(); }
                    SingleStream(total > 0 ? finalUrl : url, path, timeoutMs);
                }
                else
                {
                    res.Chunks = useChunks;
                    using (FileStream fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.ReadWrite)) { fs.SetLength(total); }
                    if (!quiet) { progThread = new Thread(delegate() { ProgressLoop(total, done); }); progThread.Start(); }
                    long chunkSize = (total + useChunks - 1) / useChunks;
                    List<Task> tasks = new List<Task>();
                    for (int i = 0; i < useChunks; i++)
                    {
                        long s = (long)i * chunkSize;
                        long e = Math.Min(s + chunkSize - 1, total - 1);
                        if (s > e) break;
                        long cs = s, ce = e;
                        tasks.Add(Task.Factory.StartNew(delegate() { DownloadChunk(finalUrl, url, path, cs, ce, timeoutMs, 3); }, TaskCreationOptions.LongRunning));
                    }
                    Task.WaitAll(tasks.ToArray());
                }
                done.Set();
                if (progThread != null) progThread.Join();

                FileInfo fi = new FileInfo(path);
                res.Bytes = fi.Length;
                if (total > 0 && fi.Length != total) { res.Success = false; res.Error = string.Format("size mismatch: got {0}, expected {1}", fi.Length, total); }
                else { res.Success = true; }
            }
            catch (Exception ex)
            {
                done.Set();
                if (progThread != null) { try { progThread.Join(); } catch { } }
                res.Success = false;
                res.Error = Flatten(ex);
            }
            res.ElapsedMs = (long)(DateTime.UtcNow - t0).TotalMilliseconds;
            return res;
        }

        static string Flatten(Exception e)
        {
            AggregateException ae = e as AggregateException;
            if (ae != null)
            {
                StringBuilder sb = new StringBuilder();
                foreach (Exception inner in ae.Flatten().InnerExceptions) sb.Append(inner.Message + "; ");
                return sb.ToString();
            }
            return e.Message;
        }
    }
}
"@
        Add-Type -TypeDefinition $code
        $Global:hasChunkDownloaderType = $true
    }

    # Derive the output path from the URL when not supplied (URL-decoded leaf name).
    if (-not $OutFile) {
        $leaf = [System.IO.Path]::GetFileName(([Uri]$Uri).AbsolutePath)
        if ([string]::IsNullOrEmpty($leaf)) { $leaf = 'download.bin' }
        $OutFile = Join-Path (Get-Location).Path ([Uri]::UnescapeDataString($leaf))
    }
    $OutFile = [System.IO.Path]::GetFullPath($OutFile)
    $dir = Split-Path -Parent $OutFile
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if ((Test-Path -LiteralPath $OutFile) -and -not $Force) {
        Write-Error "File already exists: $OutFile (use -Force to overwrite)."
        return
    }

    $res = [ChunkDownload.Downloader]::Download(
        $Uri, $OutFile, $Chunks, [long]($MinChunkMB * 1MB), [long]($ChunkThresholdMB * 1MB), $TimeoutSec, [bool]$Quiet)

    if (-not $res.Success) {
        if (Test-Path -LiteralPath $OutFile) { Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue }
        Write-Error ("Download failed for {0}: {1}" -f $Uri, $res.Error)
        return
    }

    if (-not $Quiet) {
        $mb = $res.Bytes / 1MB
        $sec = $res.ElapsedMs / 1000.0
        $rate = if ($sec -gt 0) { $mb / $sec } else { 0 }
        $mode = if ($res.FellBack) { 'single-stream' } else { ('{0} chunks' -f $res.Chunks) }
        Write-Host ("      {0:N1} MB in {1:N1}s ({2:N1} MB/s, {3})" -f $mb, $sec, $rate, $mode) -ForegroundColor DarkGray
    }

    return (Get-Item -LiteralPath $OutFile)
}

function Install-Fonts {
    <#
.SYNOPSIS
    Downloads and installs a curated catalog of fonts into Windows.
.DESCRIPTION
    Iterates the pinned font catalog in $_FontInstallInternal.Packs. For each
    enabled pack it processes one item fully before moving on -- download ->
    selective extract -> install -> delete temporary files -- so peak disk usage
    stays close to a single archive rather than the whole catalog.

    Installs per-user by default (%LOCALAPPDATA%\Microsoft\Windows\Fonts plus the
    HKCU Fonts registry key), which needs no administrator rights. Pass -AllUsers
    to install machine-wide (C:\Windows\Fonts + HKLM), which requires an elevated
    session.

    Idempotency is filename-based and works at two levels: a cheap pre-download
    probe skips a whole pack when its representative font is already present, and
    each individual font already in the target folder is skipped at install time.
    Pass -Force to re-download and overwrite regardless.

    ZIP extraction uses .NET's System.IO.Compression. Compact 7z packs use the
    libarchive-based tar.exe included with current Windows; 7-Zip is not required.

    Failed downloads are warned (with the URL) and collected into a summary at the
    end so a broken/moved release can be spotted and its Url updated.
.PARAMETER Name
    One or more pack names (see the Name column of -ListOnly) to limit the run to.
    Matching is case-insensitive and substring-based. Omit to process all packs.
.PARAMETER Force
    Reinstall even when the font already appears installed (re-downloads and
    overwrites both the file and its registry entry).
.PARAMETER AllUsers
    Install machine-wide instead of per-user. Requires an elevated (admin) shell.
.PARAMETER Extended
    Also process the extended (opt-in) packs marked Extended=$true in the catalog,
    including the large Adobe Source Han families.
.PARAMETER ListOnly
    Print the catalog (names, sizes, extended state, notes) and the estimated
    download total, then exit without downloading or installing anything.
.PARAMETER Retries
    How many extra times to re-download and re-extract a pack after a transient
    failure (default 2, so up to 3 attempts total). Only transient errors are
    retried -- corrupt-archive/truncated-zip signatures and common network hiccups
    (e.g. the intermittent "A local file header is corrupt" seen on large chunked
    GitHub downloads). Genuine failures (bad URL, 404) are reported immediately
    without wasting retries. Set 0 to disable retrying.
.EXAMPLE
    Install-Fonts -ListOnly
    # Review the catalog and total download size before committing to a run.
.EXAMPLE
    Install-Fonts
    # Install every standard pack per-user (skips the extended Source Han giants).
.EXAMPLE
    Install-Fonts -Name Pretendard,FiraCode,D2Coding
    # Install just the named packs.
.EXAMPLE
    Install-Fonts -Extended -Name SourceHanMono
    # Opt into one of the large extended CJK packs.
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-07

    Adding a new pack? Inspect the archive first with the helper:
        $_ProfileHelpers.ShowFontArchive('<zip-url-or-path>')
        $_ProfileHelpers.ShowFontArchive($url, '<candidate-Include-regex>')
    It lists every entry with its size, reads each font's registered family
    name (to pick TTF vs OTF vs variable -- some builds rename the family with
    an "OTF"/"variable" suffix), and, given an Include regex, previews exactly
    which entries would be extracted -- i.e. the Include, Probe, Bytes and Fonts
    values a new Packs entry needs.
#>
    [CmdletBinding()]
    param(
        [string[]] $Name,
        [switch]   $Force,
        [switch]   $AllUsers,
        [switch]   $Extended,
        [switch]   $ListOnly,
        [ValidateRange(0, 10)]
        [int]      $Retries = 2
    )

    $cfg = $_FontInstallInternal

    # Windows PowerShell 5.1 does not load the ZipFile assembly by default
    # (PowerShell 7+ does); load it so selective extraction works on both.
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

    # Resolve install target (per-user vs machine-wide) up front.
    if ($AllUsers) {
        if (-not (Test-IsAdministrator)) {
            Write-Host "Install-Fonts -AllUsers requires an elevated (Administrator) session." -ForegroundColor Red
            return
        }
        $fontsDir = $cfg.MachineFontsDir
        $regPath  = $cfg.MachineRegPath
        $machine  = $true
    } else {
        $fontsDir = $cfg.UserFontsDir
        $regPath  = $cfg.UserRegPath
        $machine  = $false
    }

    # Select packs: standard packs unless -Extended, then optional -Name filter.
    $packs = $cfg.Packs | Where-Object { -not $_.Extended -or $Extended }
    if ($Name) {
        $packs = $packs | Where-Object {
            $p = $_
            $Name | Where-Object { $p.Name -like "*$_*" }
        }
    }
    $packs = @($packs)

    # Human-readable byte formatter for the size report.
    $fmtSize = {
        param([long]$b)
        if ($b -ge 1GB) { return ('{0:N2} GB' -f ($b / 1GB)) }
        if ($b -ge 1MB) { return ('{0:N1} MB' -f ($b / 1MB)) }
        if ($b -ge 1KB) { return ('{0:N0} KB' -f ($b / 1KB)) }
        return ('{0} B' -f $b)
    }

    if ($packs.Count -eq 0) {
        Write-Host "No matching font packs to install." -ForegroundColor Yellow
        return
    }

    # Pre-run summary: number of packs, per-pack size, and estimated totals.
    $totalBytes = ($packs | Measure-Object -Property Bytes -Sum).Sum
    $totalFonts = ($packs | Measure-Object -Property Fonts -Sum).Sum
    Write-Host ''
    Write-Host ("== Install-Fonts: {0} pack(s), ~{1} font file(s), ~{2} to download ==" -f `
        $packs.Count, $totalFonts, (& $fmtSize $totalBytes)) -ForegroundColor Cyan
    Write-Host ("   Target: {0} ({1})" -f $fontsDir, ($(if ($machine) { 'all users' } else { 'current user' }))) -ForegroundColor DarkGray
    $i = 0
    foreach ($p in $packs) {
        $i++
        $tag = if ($p.Extended) { ' [extended]' } elseif ($p.Bytes -ge 50MB) { ' [LARGE]' } else { '' }
        Write-Host ("   {0,2}. {1,-20} {2,10}  ~{3} fonts{4}" -f $i, $p.Name, (& $fmtSize $p.Bytes), $p.Fonts, $tag)
        if ($ListOnly -and $p.Note) { Write-Host ("       {0}" -f $p.Note) -ForegroundColor DarkGray }
    }

    if ($ListOnly) { return }

    # Fail before confirmation or downloading when a selected 7z pack cannot be
    # handled by Windows' inbox libarchive-based tar.exe.
    if (($packs | Where-Object Kind -eq '7z') -and
        -not (Get-Command tar.exe -CommandType Application -ErrorAction SilentlyContinue)) {
        Write-Error 'Selected font packs require 7z extraction, but Windows tar.exe is unavailable.'
        return
    }

    # Short confirmation before doing any network/disk work (Enter defaults to Yes).
    $choice = Read-Host -Prompt ("Proceed with downloading and installing {0} font pack(s)? (Y/n)" -f $packs.Count)
    if ($choice -in @('n', 'N')) {
        Write-Host "Aborting. Nothing was downloaded or installed." -ForegroundColor Yellow
        return
    }

    # Ensure the target folder and registry key exist before installing.
    if (-not (Test-Path -LiteralPath $fontsDir)) {
        New-Item -ItemType Directory -Path $fontsDir -Force | Out-Null
    }
    if (-not (Test-Path -LiteralPath $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    # P/Invoke for live font registration + notifying running apps of the change.
    if (-not ('FontInstaller.NativeMethods' -as [type])) {
        Add-Type -Namespace FontInstaller -Name NativeMethods -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("gdi32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
public static extern int AddFontResource(string lpFilename);

[System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Auto)]
public static extern System.IntPtr SendMessageTimeout(System.IntPtr hWnd, uint Msg, System.IntPtr wParam, System.IntPtr lParam, uint fuFlags, uint uTimeout, out System.IntPtr lpdwResult);
'@
    }

    # Copy a single font file to the target folder and register it. Returns
    # 'installed' or 'skipped' (already present and -Force not set).
    $installOne = {
        param([string]$SrcPath)
        $leaf = Split-Path -Path $SrcPath -Leaf
        $dest = Join-Path $fontsDir $leaf
        if ((Test-Path -LiteralPath $dest) -and -not $Force) { return 'skipped' }
        Copy-Item -LiteralPath $SrcPath -Destination $dest -Force
        $ext    = [System.IO.Path]::GetExtension($leaf).ToLowerInvariant()
        $suffix = if ($ext -eq '.otf') { '(OpenType)' } else { '(TrueType)' }
        # Registry value NAME must be unique per file; the font's own name table
        # supplies the family shown in apps, so a filename-based label is safe.
        $valueName = ('{0} {1}' -f [System.IO.Path]::GetFileNameWithoutExtension($leaf), $suffix)
        # Machine scope stores the bare filename (relative to Windows\Fonts);
        # per-user scope requires the full path.
        $regData = if ($machine) { $leaf } else { $dest }
        New-ItemProperty -Path $regPath -Name $valueName -Value $regData -PropertyType String -Force | Out-Null
        [void][FontInstaller.NativeMethods]::AddFontResource($dest)
        return 'installed'
    }

    # Classify a download/extract error as transient (worth re-downloading) vs
    # permanent (bad URL, 404 -- reported immediately, no retry). The dominant
    # transient case is a chunked download that lands a byte-corrupt archive, which
    # surfaces only at extract time as ".ExtractToFile ... A local file header is
    # corrupt" or a truncated central directory; for 7z via tar.exe the same zeroed
    # region surfaces as "Unexpected Property ID" (its header parser reading zero
    # bytes); network stalls are covered too.
    $isTransientError = {
        param([string]$Message)
        if ([string]::IsNullOrEmpty($Message)) { return $false }
        return ($Message -match '(?i)(local file header is corrupt|central directory|end of (the )?stream|unexpected end( of archive)?|damaged 7-zip archive|unexpected property id|exit delayed from previous errors|data error|corrupt|crc|block length|compressed data|number of entries|timed out|timeout|connection|transport|prematurely|reset by|unable to read data|actively refused)')
    }

    # Temp working directory (single archive at a time; cleaned per pack).
    $work = Join-Path ([System.IO.Path]::GetTempPath()) ('fonts_' + [System.Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work -Force | Out-Null

    $totalInstalled = 0
    $totalSkipped   = 0
    $failed         = @()

    try {
        $i = 0
        foreach ($p in $packs) {
            $i++
            Write-Host ''
            Write-Host ("[{0}/{1}] {2} ({3})" -f $i, $packs.Count, $p.Name, (& $fmtSize $p.Bytes)) -ForegroundColor White

            # Cheap pre-download skip: representative font already installed?
            $probePath = Join-Path $fontsDir $p.Probe
            if ((Test-Path -LiteralPath $probePath) -and -not $Force) {
                Write-Host ("      already installed ({0}); skipping download." -f $p.Probe) -ForegroundColor DarkGray
                continue
            }

            $dl = Join-Path $work ([System.IO.Path]::GetFileName(([Uri]$p.Url).AbsolutePath))
            Write-Host ("      source: {0}" -f $p.Url) -ForegroundColor DarkGray

            # Download AND extract are retried as one unit: the intermittent
            # "local file header is corrupt" is a byte-corrupt chunked download that
            # only shows up at extract time, so re-extracting the same file cannot
            # help -- only a fresh download can. Each attempt starts its counters
            # from zero and, on the winning attempt, already-installed fonts from a
            # partial earlier attempt are simply skipped (idempotent by filename).
            $maxAttempts   = 1 + $Retries
            $packInstalled = 0
            $packSkipped   = 0
            $packOk        = $false
            $lastError     = $null
            for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
                if ($attempt -gt 1) {
                    Write-Host ("      retry {0}/{1} (transient error: {2})" -f `
                        ($attempt - 1), ($maxAttempts - 1), $lastError) -ForegroundColor Yellow
                    Start-Sleep -Seconds ([math]::Min(10, 2 * ($attempt - 1)))
                }
                $packInstalled = 0
                $packSkipped   = 0
                try {
                    Write-Host "      downloading..." -ForegroundColor DarkGray
                    # Chunked concurrent download; several times faster than a single
                    # connection on GitHub's throttled CDN for the larger packs, with
                    # a transparent single-stream fallback. -ErrorAction Stop routes
                    # any failure into the catch below.
                    Save-WebFile -Uri $p.Url -OutFile $dl -Force -TimeoutSec 1800 -ErrorAction Stop | Out-Null

                    if ($p.Kind -eq 'File') {
                        # URL is itself a font file: install it directly.
                        $r = & $installOne $dl
                        if ($r -eq 'installed') { $packInstalled++ } else { $packSkipped++ }
                    } elseif ($p.Kind -eq '7z') {
                        # Keep 7z handling behind the shared helper; it validates
                        # archive paths and returns only the selected extracted files.
                        $extractDir = Join-Path $work ('extract_' + [System.Guid]::NewGuid().ToString('N'))
                        try {
                            $fontPaths = @($_ProfileHelpers.Expand7ZipArchive($dl, $extractDir, $p.Include))
                            foreach ($fontPath in $fontPaths) {
                                $r = & $installOne $fontPath
                                if ($r -eq 'installed') { $packInstalled++ } else { $packSkipped++ }
                            }
                        } finally {
                            if (Test-Path -LiteralPath $extractDir) {
                                Remove-Item -LiteralPath $extractDir -Recurse -Force -ErrorAction SilentlyContinue
                            }
                        }
                    } elseif ($p.Kind -eq 'Zip') {
                        # Open the archive and extract ONLY the entries we want, one
                        # at a time, so we never expand the full archive to disk.
                        $zip = [System.IO.Compression.ZipFile]::OpenRead($dl)
                        try {
                            foreach ($entry in $zip.Entries) {
                                if ([string]::IsNullOrEmpty($entry.Name)) { continue }   # directory
                                $rel = $entry.FullName
                                # Guard against macOS archive cruft regardless of Include.
                                if ($rel -like '*__MACOSX*' -or $entry.Name -like '._*') { continue }
                                if ($rel -notmatch $p.Include) { continue }
                                $tmp = Join-Path $work $entry.Name
                                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $tmp, $true)
                                $r = & $installOne $tmp
                                if ($r -eq 'installed') { $packInstalled++ } else { $packSkipped++ }
                                Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
                            }
                        } finally {
                            $zip.Dispose()
                        }
                    } else {
                        throw "Unsupported font pack kind '$($p.Kind)' for '$($p.Name)'."
                    }
                    $packOk = $true
                    break
                } catch {
                    $lastError = $_.Exception.Message
                    $canRetry  = ($attempt -lt $maxAttempts) -and (& $isTransientError $lastError)
                    if ($canRetry) {
                        Write-Warning ("Attempt {0}/{1} FAILED for '{2}': {3}" -f $attempt, $maxAttempts, $p.Name, $lastError)
                    } else {
                        $suffix = if ($attempt -gt 1) { (" after {0} attempts" -f $attempt) } else { '' }
                        Write-Warning ("Install FAILED for '{0}'{1}: {2}" -f $p.Name, $suffix, $lastError)
                        Write-Warning ("  URL: {0}  -- verify/update this Url in `$_FontInstallInternal.Packs" -f $p.Url)
                        $failed += $p
                        break
                    }
                } finally {
                    # Always drop the (possibly corrupt) archive so a retry re-downloads.
                    if (Test-Path -LiteralPath $dl) { Remove-Item -LiteralPath $dl -Force -ErrorAction SilentlyContinue }
                }
            }

            if ($packOk) {
                $totalInstalled += $packInstalled
                $totalSkipped   += $packSkipped
                Write-Host ("      installed {0}, skipped {1} (running total installed: {2})" -f `
                    $packInstalled, $packSkipped, $totalInstalled) -ForegroundColor Green
            }
        }
    } finally {
        if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
    }

    # Notify running applications that the font set changed (WM_FONTCHANGE to
    # HWND_BROADCAST) so new fonts appear without a sign-out.
    if ($totalInstalled -gt 0) {
        $result = [System.IntPtr]::Zero
        [void][FontInstaller.NativeMethods]::SendMessageTimeout(
            [System.IntPtr]0xffff, 0x001D, [System.IntPtr]::Zero, [System.IntPtr]::Zero, 2, 1000, [ref]$result)
    }

    Write-Host ''
    Write-Host ("== Done: {0} installed, {1} skipped, {2} download failure(s). ==" -f `
        $totalInstalled, $totalSkipped, $failed.Count) -ForegroundColor Cyan
    if ($failed.Count -gt 0) {
        Write-Host "   Failed packs (check/update their Url):" -ForegroundColor Yellow
        foreach ($f in $failed) { Write-Host ("     - {0}: {1}" -f $f.Name, $f.Url) -ForegroundColor Yellow }
    }
}

function Enable-WindowsSudo {
    <#
.SYNOPSIS
    Enables the inbox Windows Sudo command in inline mode.
.DESCRIPTION
    Requires Windows 11 version 24H2 (build 26100) or later. Requests elevation
    once and configures sudo.exe to run elevated commands in the current console.
.EXAMPLE
    PS C:\> Enable-WindowsSudo
.OUTPUTS
    System.Boolean. True when inline Windows Sudo is enabled; otherwise false.
.NOTES
    Inline mode lets unelevated processes share console input with the elevated
    process. Enable it only on a trusted interactive workstation.
#>
    [CmdletBinding()]
    param()

    $sudoPath = Join-Path $env:SystemRoot 'System32\sudo.exe'
    $windowsVersion = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
    $build = 0
    if ($windowsVersion -and -not [int]::TryParse([string]$windowsVersion.CurrentBuildNumber, [ref]$build)) {
        $build = 0
    }

    if ($build -lt 26100 -or -not (Test-Path -LiteralPath $sudoPath -PathType Leaf)) {
        Write-Error 'Windows Sudo requires Windows 11 version 24H2 (build 26100) or later.'
        return $false
    }

    $sudoConfigPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo'
    $sudoConfig = Get-ItemProperty -LiteralPath $sudoConfigPath -ErrorAction SilentlyContinue
    if ($sudoConfig -and $sudoConfig.Enabled -eq 3) {
        Write-Host 'Windows Sudo is already enabled in inline mode.' -ForegroundColor Green
        return $true
    }

    try {
        $process = Start-Process -FilePath $sudoPath -ArgumentList @('config', '--enable', 'normal') `
            -Verb RunAs -Wait -PassThru -ErrorAction Stop
    } catch {
        Write-Error "Windows Sudo setup was cancelled or failed: $($_.Exception.Message)"
        return $false
    }

    $sudoConfig = Get-ItemProperty -LiteralPath $sudoConfigPath -ErrorAction SilentlyContinue
    if ($process.ExitCode -ne 0 -or -not $sudoConfig -or $sudoConfig.Enabled -ne 3) {
        Write-Error "Windows Sudo did not enable inline mode (exit code $($process.ExitCode))."
        return $false
    }

    Write-Host 'Windows Sudo is enabled in inline mode.' -ForegroundColor Green
    return $true
}

function Invoke-Elevated {
    <#
.SYNOPSIS
    Runs a native command or PowerShell script block with administrator rights.
.DESCRIPTION
    Uses the inbox Windows Sudo command and the normal UAC consent flow. Native
    executables receive arguments directly. PowerShell cmdlets, functions,
    pipelines, and expressions must be supplied as one script block.
.PARAMETER NoProfile
    Prevents the elevated PowerShell child from loading PowerShell profiles.
.PARAMETER Command
    A native executable plus arguments, or one PowerShell script block.
.EXAMPLE
    PS C:\> Invoke-Elevated winget upgrade --all
.EXAMPLE
    PS C:\> Invoke-Elevated { Get-Service -Name wuauserv | Restart-Service }
.EXAMPLE
    PS C:\> Invoke-Elevated -NoProfile { whoami /groups }
.NOTES
    A script block runs in a new process and does not inherit live variables or
    objects from the calling session.
#>
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

    if ($Command[0] -isnot [string]) {
        Write-Error 'The command must be a native executable name or a single PowerShell script block.'
        return
    }

    $nativeCommand = Get-Command -Name ([string]$Command[0]) -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $nativeCommand) {
        Write-Error "'$($Command[0])' is not a native executable. Wrap PowerShell commands in braces: Invoke-Elevated { <command> }."
        return
    }

    $nativeArguments = if ($Command.Count -gt 1) { $Command[1..($Command.Count - 1)] } else { @() }
    & $sudoPath $nativeCommand.Source @nativeArguments
}

function Invoke-WindowsUpdateScan {
    <#
.SYNOPSIS
    Scans for pending Windows Updates without making any system changes.
.DESCRIPTION
    Queries the Microsoft.Update.Session COM API for applicable updates and prints
    a summary table (KB, SizeMB, Severity, Reboot requirement, Title).
    Can be run in non-elevated user sessions.
.EXAMPLE
    PS C:\> Invoke-WindowsUpdateScan
.OUTPUTS
    Microsoft.Update.SearchResult or $null
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-07
#>
    [CmdletBinding()]
    param()

    try {
        $session  = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $searcher.ServerSelection = 2
    } catch {
        Write-Host "Failed to create Microsoft.Update.Session COM object: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }

    Write-Host "Scanning for Windows Updates..." -ForegroundColor Cyan
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $result = $searcher.Search("IsInstalled=0 AND IsHidden=0")
    } catch {
        Write-Host "Scan threw: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ($_ProfileHelpers.ResolveWUHResult($_.Exception.HResult)) -ForegroundColor Red
        return $null
    }
    $sw.Stop()

    $color = switch ($result.ResultCode) { 2 {'Green'} 3 {'Yellow'} default {'Red'} }
    Write-Host ("Scan finished in {0:N1}s - {1}" -f `
        $sw.Elapsed.TotalSeconds, ($_ProfileHelpers.ResolveWUResultCode($result.ResultCode))) -ForegroundColor $color

    foreach ($w in $result.Warnings) {
        Write-Host ("  WARN {0} {1}" -f ($_ProfileHelpers.ResolveWUHResult($w.HResult)), $w.Message) -ForegroundColor Yellow
    }

    if ($result.ResultCode -notin 2,3) { Write-Host "Result not trustworthy." -ForegroundColor Red; return $result }

    if ($result.Updates.Count -eq 0) {
        if ($result.ResultCode -eq 3) {
            Write-Host "No updates returned, but scan reported errors - inconclusive." -ForegroundColor Yellow
        } else {
            Write-Host "No applicable updates available - system is up to date." -ForegroundColor Green
        }
        if ((New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired) {
            Write-Host "Note: reboot pending - more updates may appear after restart." -ForegroundColor Yellow
        }
        return $result
    }

    Write-Host "$($result.Updates.Count) update(s) available:" -ForegroundColor Yellow
    $result.Updates | ForEach-Object {
        [pscustomobject]@{
            KB        = ($_.KBArticleIDs -join ',')
            SizeMB    = [math]::Round($_.MaxDownloadSize / 1MB, 1)
            Severity  = $_.MsrcSeverity
            Reboot    = $_.InstallationBehavior.RebootBehavior -ne 0
            Dl        = $_.IsDownloaded
            Title     = if ($_.Title.Length -gt 60) { $_.Title.Substring(0,57) + '...' } else { $_.Title }
        }
    } | Format-Table -AutoSize | Out-Host

    return $result
}

function Invoke-WindowsUpdate {
    <#
.SYNOPSIS
    Downloads and installs pending Windows Updates. Requires Administrator rights.
.DESCRIPTION
    Scans, downloads, and installs pending updates using the Windows Update Agent API.
    Fails immediately if running in an un-elevated PowerShell session.
.PARAMETER ScanOnly
    Delegates to Invoke-WindowsUpdateScan without attempting download or installation.
.EXAMPLE
    PS C:\> Invoke-WindowsUpdate
.EXAMPLE
    PS C:\> Invoke-WindowsUpdate -ScanOnly
.NOTES
    Author: jjw(@thejjw)
    Last Edit: 2026-07
#>
    [CmdletBinding()]
    param(
        [switch]$ScanOnly
    )

    if ($ScanOnly) {
        Invoke-WindowsUpdateScan
        return
    }

    $isAdmin = ([Security.Principal.WindowsPrincipal]`
                [Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Host "Error: Administrator rights are required to download and install Windows Updates." -ForegroundColor Red
        Write-Host "Please re-run PowerShell as Administrator (e.g. right-click -> 'Run as Administrator' or 'sudo powershell')." -ForegroundColor Yellow
        return
    }

    $scanResult = Invoke-WindowsUpdateScan
    if ($null -eq $scanResult -or $scanResult.Updates.Count -eq 0) {
        return
    }

    try {
        $session = New-Object -ComObject Microsoft.Update.Session
    } catch {
        Write-Host "Failed to create Microsoft.Update.Session COM object: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # --- Download ---
    $coll = New-Object -ComObject Microsoft.Update.UpdateColl
    foreach ($u in $scanResult.Updates) {
        if ($u.InstallationBehavior.CanRequestUserInput) {
            Write-Host "Skipping (needs user input): $($u.Title)" -ForegroundColor Yellow
            continue
        }
        if (-not $u.EulaAccepted) { $u.AcceptEula() }
        $null = $coll.Add($u)
    }
    if ($coll.Count -eq 0) { Write-Host "Nothing eligible to install." -ForegroundColor Yellow; return }

    Write-Host "Downloading $($coll.Count) update(s)..." -ForegroundColor Cyan
    $dl = $session.CreateUpdateDownloader()
    $dl.Updates = $coll
    try { $dlResult = $dl.Download() }
    catch {
        Write-Host "Download threw: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ($_ProfileHelpers.ResolveWUHResult($_.Exception.HResult)) -ForegroundColor Red
        return
    }
    Write-Host ("Download: {0}" -f ($_ProfileHelpers.ResolveWUResultCode($dlResult.ResultCode)))

    for ($i = 0; $i -lt $coll.Count; $i++) {
        $ur = $dlResult.GetUpdateResult($i)
        if ($ur.ResultCode -ne 2) {
            Write-Host ("  FAILED {0}`n         {1}" -f `
                $coll.Item($i).Title, ($_ProfileHelpers.ResolveWUHResult($ur.HResult))) -ForegroundColor Red
        }
    }

    # --- Install (only what actually downloaded) ---
    $ready = New-Object -ComObject Microsoft.Update.UpdateColl
    foreach ($u in $coll) { if ($u.IsDownloaded) { $null = $ready.Add($u) } }

    if ($ready.Count -eq 0) {
        Write-Host "No updates downloaded successfully - nothing to install." -ForegroundColor Red
        return
    }

    Write-Host "Installing $($ready.Count) update(s)..." -ForegroundColor Cyan
    $inst = $session.CreateUpdateInstaller()
    $inst.Updates = $ready
    try { $r = $inst.Install() }
    catch {
        Write-Host "Install threw: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ($_ProfileHelpers.ResolveWUHResult($_.Exception.HResult)) -ForegroundColor Red
        return
    }

    Write-Host ("Install: {0}  RebootRequired={1}" -f `
        ($_ProfileHelpers.ResolveWUResultCode($r.ResultCode)), $r.RebootRequired)

    $(for ($i = 0; $i -lt $ready.Count; $i++) {
        $ur = $r.GetUpdateResult($i)
        [pscustomobject]@{
            Result  = $_ProfileHelpers.ResolveWUResultCode($ur.ResultCode)
            HResult = '0x{0:X8}' -f $ur.HResult
            Title   = $ready.Item($i).Title
        }
    }) | Format-Table -AutoSize -Wrap | Out-Host
}

# Auto-load vault credentials at profile load time so every session starts with
# keys available. Uses -Quiet to avoid printing key counts in transient shells.
Load-AiApiKeysFromCS -Quiet

