Describe 'Prepare-PcRecovery.ps1' {
    BeforeAll {
        # Load only the function definitions from the util script (no execution, no side effects).
        $scriptPath = Join-Path $PSScriptRoot '..\util\Prepare-PcRecovery.ps1'
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
        if ($errors) { throw "Script contains parse errors: $($errors -join '; ')" }
        $functions = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)
        foreach ($function in $functions) { . ([scriptblock]::Create($function.Extent.Text)) }

        # Script-level state the helpers read; every path points into TestDrive.
        # Evaluate the script's own shared-name constant assignments (not stubs):
        # a mangled constant (e.g. self-assignment to $null) surfaces here.
        $constAssignments = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -match '^\$script:(Dir|File|MsDownload|ThirdParty|WinIso|MakerHint|Tiny11BuilderReleasesUrl|VentoyReleasesUrl|Tiny11AnswerUrl|Tiny11MakerUrl|OscdimgUrl|Copyparty)' }, $true)
        if (-not $constAssignments) { throw 'No shared-name constants found in script.' }
        foreach ($assignment in $constAssignments) { . ([scriptblock]::Create($assignment.Extent.Text)) }
        $script:CurlExe = Join-Path $TestDrive 'curl.exe'
        $script:FidoUrl = 'https://example.invalid/Fido.ps1'
        $script:Tiny11MakerUrl = 'https://example.invalid/tiny11maker.ps1'
        $script:Tiny11AnswerUrl = 'https://example.invalid/autounattend.xml'
        $script:OscdimgUrl = 'https://example.invalid/oscdimg.exe'
        $script:MsDownloadPage = 'https://example.invalid/windows11'
        $script:ThirdPartyTip = 'TIP: example'
        $script:WinIsoNaming = 'Win11_*.iso'
        $script:VerifiedHashes = @{}
        # Lists only the catalog rows selected for the given switches (no downloads).
        function Select-CatalogFiles([string]$NetbootArch, [string]$MintHwe) {
            @(Get-RecoveryCatalog | Where-Object {
                (($_.NetbootVariant -eq '') -or ($_.NetbootVariant -eq $NetbootArch)) -and
                (($_.MintHwe -eq '') -or ($_.MintHwe -eq $MintHwe))
            } | Select-Object -ExpandProperty FileName)
        }

        # Resets recorded failures/results between tests.
        function Reset-State { $script:Failures = @(); $script:Results = @(); $script:UseSudo = $false; $script:VerifiedHashes = @{}; $script:Sidecars = @{}; $script:CopypartyRows = @() }
    }

    Context 'shared constants' {
        It 'defines every shared name with a real value (no self-assignment)' {
            $expected = @{
                DirTools = 'tools'; DirVentoy = 'ventoy'; DirIsos = 'isos'
                DirInstallers = '03-Installers'; DirTiny11 = 'tiny11'; DirBuilder = 'tiny11builder'; DirCopyparty = 'copyparty'
                FileVentoyExe = 'Ventoy2Disk.exe'; FileFido = 'Fido.ps1'; FileTiny11Iso = 'tiny11.iso'
                FileMaker = 'tiny11maker.ps1'; FileAnswer = 'autounattend.xml'; FileOscdimg = 'oscdimg.exe'
                FileFacts = 'filefacts.json'; FileReadme = 'README.txt'
                FileCopypartySfx = 'copyparty-sfx.py'; FileCopypartyExe = 'copyparty.exe'; FileCopypartyTag = '.release'
            }
            foreach ($name in $expected.Keys) {
                $actual = (Get-Variable -Name $name -Scope Script -ValueOnly -ErrorAction Stop)
                $actual | Should -Be $expected[$name]
            }
            $script:MsDownloadPage | Should -Match '^https://'
            $script:CopypartyApiUrl | Should -Match '^https://api\.github\.com/'
            $script:CopypartyReleasesUrl | Should -Match '^https://github\.com/'
            $script:ThirdPartyTip | Should -Not -BeNullOrEmpty
            $script:WinIsoNaming | Should -Match 'Win11_'
            $script:MakerHintAdmin | Should -Match 'Enable-WindowsSudo'
            $script:MakerHintSudo | Should -Match 'Enable-WindowsSudo'
            ($script:MakerHintManual -f 'X.iso') | Should -Match 'Mount X\.iso'
            $script:MakerHintManual | Should -Match 'winui-preview/autounattend\.xml'
            $script:MakerHintManual | Should -Match 'winui-preview/tiny11maker\.ps1'
            $script:MakerHintManual | Should -Match '03-Installers\\tiny11'
        }
    }

    Context 'catalog integrity' {
        It 'pins a 64-hex hash for every Pinned row' {
            $rows = Get-RecoveryCatalog | Where-Object { $_.HashKind -eq 'Pinned' }
            $rows.Count | Should -BeGreaterThan 5
            foreach ($row in $rows) {
                $row.Hash | Should -Match '^[0-9a-f]{64}$'
                $row.Url | Should -Match '^https://'
            }
        }

        It 'uses only Rolling or Manual for unpinned rows' {
            foreach ($row in (Get-RecoveryCatalog | Where-Object { $_.HashKind -ne 'Pinned' })) {
                $row.HashKind | Should -BeIn @('Rolling', 'Manual')
                $row.Check | Should -Not -BeNullOrEmpty
            }
        }

        It 'maps categories to folder names' {
            $names = Get-RecoveryCatalog | Select-Object -ExpandProperty Category -Unique
            $names | Should -Contain '01-Network'
            $names | Should -Contain '02-Rescue'
            $names | Should -Contain '03-Installers'
            foreach ($name in $names) { $name | Should -Match '^\d\d-[A-Za-z]+$' }
        }

        It 'selects the requested netboot variant and Mint HWE rows only' {
            $x64 = Select-CatalogFiles 'x64' 'None'
            $x64 | Should -Contain 'netboot.xyz.iso'
            $x64 | Should -Not -Contain 'netboot.xyz-multiarch.iso'
            $x64 | Should -Not -Contain 'linuxmint-22.3-xfce-64bit-hwe-6.17.iso'
            $multi = Select-CatalogFiles 'multi' '6.17'
            $multi | Should -Contain 'netboot.xyz-multiarch.iso'
            $multi | Should -Contain 'linuxmint-22.3-xfce-64bit-hwe-6.17.iso'
            $multi | Should -Not -Contain 'netboot.xyz.iso'
        }
    }

    Context 'download engine' {
        It 'keeps a file whose hash matches' {
            Reset-State
            $path = Join-Path $TestDrive 'match.iso'
            Set-Content -LiteralPath $path -Value 'bytes' -NoNewline
            $sha = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
            Mock Invoke-FileDownload { throw 'should not download' }
            Save-VerifiedFile -Url 'https://example.invalid/m.iso' -OutFile $path -ExpectedHash $sha -Name 'T-match' | Should -BeTrue
            $script:Failures | Should -HaveCount 0
        }

        It 'deletes a mismatch, records one failure, and returns false' {
            Reset-State
            $path = Join-Path $TestDrive 'bad.iso'
            Set-Content -LiteralPath $path -Value 'bytes' -NoNewline
            Mock Invoke-FileDownload { Set-Content -LiteralPath $OutFile -Value 'still-bad' -NoNewline; return $true }
            Save-VerifiedFile -Url 'https://example.invalid/b.iso' -OutFile $path -ExpectedHash ('00' * 32) -Name 'T-bad' | Should -BeFalse
            Test-Path -LiteralPath $path | Should -BeFalse
            $script:Failures | Should -HaveCount 1
            $script:Failures[0].Manual | Should -Not -BeNullOrEmpty
        }

        It 'skips an existing valid file without downloading' {
            Reset-State
            $path = Join-Path $TestDrive 'skip.iso'
            Set-Content -LiteralPath $path -Value 'bytes' -NoNewline
            $sha = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
            Mock Invoke-FileDownload { throw 'should not download' }
            Save-VerifiedFile -Url 'https://example.invalid/s.iso' -OutFile $path -ExpectedHash $sha -Name 'T-skip' | Should -BeTrue
            ($script:Results | Where-Object { $_.Status -eq 'Skipped' }) | Should -HaveCount 1
        }

        It 'performs zero writes under -WhatIf' {
            Reset-State
            $target = Join-Path (Join-Path $TestDrive 'whatif') 'w.iso'
            $params = @{ Url = 'https://example.invalid/w.iso'; OutFile = $target; ExpectedHash = ('ab' * 32); Name = 'T-whatif'; WhatIf = $true }
            Save-VerifiedFile @params | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $TestDrive 'whatif') | Should -BeFalse
        }

        It 'lets later steps run after a failing step' {
            Reset-State
            $log = New-Object System.Collections.Generic.List[string]
            function Invoke-FailingStub { $log.Add('fail'); Write-Failure -Name 'step-one' -Detail 'boom' -Manual @('fix one') }
            Invoke-SafeStep -Name 'step-one' -Manual @('fix one') -Body { Invoke-FailingStub }
            Invoke-SafeStep -Name 'step-two' -Manual @('fix two') -Body { $log.Add('ran') }
            $log | Should -Be @('fail', 'ran')
            $script:Failures | Should -HaveCount 1
        }

        It 'keeps the .partial on a stalled transfer for resume' {
            Reset-State
            $path = Join-Path $TestDrive 'stall.iso'
            $partial = "$path.partial"
            Set-Content -LiteralPath $partial -Value 'half-bytes' -NoNewline
            Mock Invoke-Cli { [pscustomobject]@{ ExitCode = 56; StdOut = ''; StdErr = 'reset' } }
            Invoke-FileDownload -Url 'https://example.invalid/st.iso' -OutFile $path | Should -BeFalse
            Test-Path -LiteralPath $partial | Should -BeTrue
        }

        It 'keeps the .partial on a dropped connection too' {
            Reset-State
            $path = Join-Path $TestDrive 'drop.iso'
            $partial = "$path.partial"
            Set-Content -LiteralPath $partial -Value 'half-bytes' -NoNewline
            Mock Invoke-Cli { [pscustomobject]@{ ExitCode = 52; StdOut = ''; StdErr = 'empty reply' } }
            Invoke-FileDownload -Url 'https://example.invalid/d.iso' -OutFile $path | Should -BeFalse
            Test-Path -LiteralPath $partial | Should -BeTrue
        }

        It 'deletes the .partial when the server rejects the request' {
            Reset-State
            $path = Join-Path $TestDrive 'gone.iso'
            $partial = "$path.partial"
            Set-Content -LiteralPath $partial -Value 'junk' -NoNewline
            Mock Invoke-Cli { [pscustomobject]@{ ExitCode = 22; StdOut = ''; StdErr = 'HTTP 404' } }
            Invoke-FileDownload -Url 'https://example.invalid/404.iso' -OutFile $path | Should -BeFalse
            Test-Path -LiteralPath $partial | Should -BeFalse
        }

        It 'starts the alternate URL from a clean .partial' {
            Reset-State
            $path = Join-Path $TestDrive 'alt.iso'
            $partial = "$path.partial"
            Set-Content -LiteralPath $partial -Value 'primary-host-bytes' -NoNewline
            $script:calls = 0
            Mock Invoke-FileDownload {
                $script:calls++
                if ($script:calls -eq 1) { return $false }
                if (Test-Path -LiteralPath "$OutFile.partial") { throw 'MUTATION: stale partial leaked into alternate' }
                Set-Content -LiteralPath $OutFile -Value 'ok' -NoNewline
                return $true
            }
            Save-VerifiedFile -Url 'https://example.invalid/primary.iso' -AlternateUrl 'https://example.invalid/alt.iso' -OutFile $path -Name 'T-alt' | Should -BeTrue
            $script:calls | Should -Be 2
        }
    }

    Context 'checksum text decoding' {
        It 'decodes a byte-array response instead of stringifying it' {
            Reset-State
            $line = 'ab' * 32 + '  vz.zip'
            Mock Invoke-WebRequest { [pscustomobject]@{ Content = [Text.Encoding]::UTF8.GetBytes($line) } }
            $text = Invoke-WebText -Uri 'https://example.invalid/sha.txt'
            $text | Should -Be $line
            Find-HashInChecksumText -Text $text -FileName 'vz.zip' | Should -Be ('ab' * 32)
        }

        It 'passes a string response through unchanged' {
            Reset-State
            $line = 'cd' * 32 + '  vz.zip'
            Mock Invoke-WebRequest { [pscustomobject]@{ Content = $line } }
            Invoke-WebText -Uri 'https://example.invalid/sha.txt' | Should -Be $line
        }
    }
    Context 'ventoy layout' {
        It 'finds Ventoy2Disk.exe after flattening the wrapper folder' {
            Reset-State
            $ventoyDir = Join-Path $TestDrive 'ventoy'
            New-Item -ItemType Directory -Path $ventoyDir -Force | Out-Null
            $stageDir = Join-Path $ventoyDir '_stage'
            $wrapper = Join-Path $stageDir 'ventoy-1.1.18'
            New-Item -ItemType Directory -Path $wrapper -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $wrapper 'Ventoy2Disk.exe') -Value 'exe' -NoNewline
            $found = @(Get-ChildItem -LiteralPath $stageDir -Directory) | Select-Object -First 1
            $inner = if ($found -and (Test-Path -LiteralPath (Join-Path $found.FullName 'Ventoy2Disk.exe'))) { $found.FullName } else { $stageDir }
            Get-ChildItem -LiteralPath $inner -Force | ForEach-Object {
                Move-Item -LiteralPath $_.FullName -Destination (Join-Path $ventoyDir $_.Name) -Force
            }
            Remove-Item -LiteralPath $stageDir -Recurse -Force -ErrorAction SilentlyContinue
            Test-Path -LiteralPath (Join-Path $ventoyDir 'Ventoy2Disk.exe') | Should -BeTrue
            Test-Path -LiteralPath $stageDir | Should -BeFalse
        }
    }

    Context 'ventoy install' {
        It 'still downloads the zip on a clean tree' {
            Reset-State
            $root = Join-Path $TestDrive 'vroot'
            Mock Get-GitHubLatestAsset { [pscustomobject]@{ Tag = 'v1.1.18'; Name = 'vz.zip'; ZipUrl = 'https://example.invalid/vz.zip'; HashUrl = 'https://example.invalid/sha.txt' } }
            Mock Invoke-WebText { 'ab' * 32 + '  vz.zip' }
            $script:sawUrl = ''
            Mock Save-VerifiedFile { $script:sawUrl = $Url; Set-Content -LiteralPath $OutFile -Value 'z' -NoNewline; return $true }
            Mock Expand-Archive { New-Item -ItemType Directory -Path (Join-Path $DestinationPath 'w') -Force | Out-Null; Set-Content -LiteralPath (Join-Path (Join-Path $DestinationPath 'w') 'Ventoy2Disk.exe') -Value 'e' -NoNewline }
            Install-Ventoy -Root $root | Should -BeTrue
            $script:sawUrl | Should -Be 'https://example.invalid/vz.zip'
        }

        It 'skips extraction when the exe and verified zip are present' {
            Reset-State
            $root = Join-Path $TestDrive 'vfull'
            $ventoyDir = Join-Path $root 'ventoy'
            New-Item -ItemType Directory -Path $ventoyDir -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $ventoyDir 'Ventoy2Disk.exe') -Value 'e' -NoNewline
            $zip = Join-Path $ventoyDir 'vz.zip'
            Set-Content -LiteralPath $zip -Value 'z' -NoNewline
            $sha = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
            Mock Get-GitHubLatestAsset { [pscustomobject]@{ Tag = 'v1.1.18'; Name = 'vz.zip'; ZipUrl = 'https://example.invalid/vz.zip'; HashUrl = 'https://example.invalid/sha.txt' } }
            Mock Invoke-WebText { "$sha  vz.zip" }
            Mock Expand-Archive { throw 'MUTATION: should not extract' }
            Install-Ventoy -Root $root | Should -BeTrue
            ($script:Results | Where-Object { $_.Status -eq 'Skipped' }) | Should -HaveCount 1
        }
    }

    Context 'copyparty tools' {
        It 'downloads both assets from the resolved tag with their GitHub digests' {
            Reset-State
            $root = Join-Path $TestDrive 'cpok'
            Mock Invoke-GitHubApiJson { [pscustomobject]@{ tag_name = 'v1.20.26'; assets = @(
                [pscustomobject]@{ name = 'copyparty-sfx.py'; size = 1206486; digest = 'sha256:' + ('a' * 64); browser_download_url = 'https://github.com/9001/copyparty/releases/download/v1.20.26/copyparty-sfx.py' }
                [pscustomobject]@{ name = 'copyparty.exe'; size = 13207240; digest = 'sha256:' + ('b' * 64); browser_download_url = 'https://github.com/9001/copyparty/releases/download/v1.20.26/copyparty.exe' }
            ) } }
            $script:sawDownloads = @()
            Mock Save-VerifiedFile { $script:sawDownloads += [pscustomobject]@{ Url = $Url; OutFile = $OutFile; Hash = $ExpectedHash }; Set-Content -LiteralPath $OutFile -Value 'x' -NoNewline; return $true }
            Save-CopypartyTools -Root $root | Should -BeTrue
            $script:sawDownloads.Count | Should -Be 2
            $script:sawDownloads[0].Url | Should -Match '/download/v1\.20\.26/copyparty-sfx\.py$'
            $script:sawDownloads[0].Hash | Should -Be ('a' * 64)
            $script:sawDownloads[0].OutFile | Should -Match 'isos\\04-etc\\copyparty\\copyparty-sfx\.py$'
            $script:sawDownloads[1].OutFile | Should -Match 'isos\\04-etc\\copyparty\\copyparty\.exe$'
            $script:CopypartyRows.Count | Should -Be 2
            $block = Format-IsoReadmeEntry -Row ($script:CopypartyRows | Where-Object { $_.FileName -eq 'copyparty.exe' }) -Root $root
            $block | Should -Match 'v1\.20\.26'
            $block | Should -Match ('b' * 64)
        }

        It 'records one failure per asset when a digest is unusable' {
            Reset-State
            $root = Join-Path $TestDrive 'cpnodigest'
            Mock Invoke-GitHubApiJson { [pscustomobject]@{ tag_name = 'v1.20.26'; assets = @(
                [pscustomobject]@{ name = 'copyparty-sfx.py'; size = 1; digest = 'sha512:abc'; browser_download_url = 'https://example.invalid/sfx' }
                [pscustomobject]@{ name = 'copyparty.exe'; size = 2; digest = 'sha256:' + ('c' * 64); browser_download_url = 'https://example.invalid/exe' }
            ) } }
            $script:calls = 0
            Mock Save-VerifiedFile { $script:calls++; Set-Content -LiteralPath $OutFile -Value 'x' -NoNewline; return $true }
            Save-CopypartyTools -Root $root | Should -BeFalse
            $script:calls | Should -Be 1
            $script:Failures | Should -HaveCount 1
            $script:Failures[0].Name | Should -Be 'copyparty-sfx.py'
        }

        It 'does not double-record a failed download' {
            Reset-State
            $root = Join-Path $TestDrive 'cpfail'
            Mock Invoke-GitHubApiJson { [pscustomobject]@{ tag_name = 'v1.20.26'; assets = @(
                [pscustomobject]@{ name = 'copyparty-sfx.py'; size = 1; digest = 'sha256:' + ('a' * 64); browser_download_url = 'https://example.invalid/sfx' }
                [pscustomobject]@{ name = 'copyparty.exe'; size = 2; digest = 'sha256:' + ('b' * 64); browser_download_url = 'https://example.invalid/exe' }
            ) } }
            Mock Invoke-Cli { [pscustomobject]@{ ExitCode = 22; StdOut = ''; StdErr = 'HTTP 404' } }
            Save-CopypartyTools -Root $root | Should -BeFalse
            $script:Failures | Should -HaveCount 2
        }

        It 'records one failure when the release lookup fails' {
            Reset-State
            $root = Join-Path $TestDrive 'cpapi'
            Mock Invoke-GitHubApiJson { throw 'rate limited' }
            Save-CopypartyTools -Root $root | Should -BeFalse
            $script:Failures | Should -HaveCount 1
            $script:CopypartyRows.Count | Should -Be 0
        }

        It 'clears stale partials when the release tag changes' {
            Reset-State
            $root = Join-Path $TestDrive 'cppart'
            $dir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'copyparty'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $dir '.release') -Value 'v1.20.25' -NoNewline
            $partial = Join-Path $dir 'copyparty.exe.partial'
            Set-Content -LiteralPath $partial -Value 'old' -NoNewline
            Mock Invoke-GitHubApiJson { [pscustomobject]@{ tag_name = 'v1.20.26'; assets = @(
                [pscustomobject]@{ name = 'copyparty-sfx.py'; size = 1; digest = 'sha256:' + ('a' * 64); browser_download_url = 'https://example.invalid/sfx' }
                [pscustomobject]@{ name = 'copyparty.exe'; size = 2; digest = 'sha256:' + ('b' * 64); browser_download_url = 'https://example.invalid/exe' }
            ) } }
            Mock Save-VerifiedFile { return $true }
            Save-CopypartyTools -Root $root | Should -BeTrue
            Test-Path -LiteralPath $partial | Should -BeFalse
            ([IO.File]::ReadAllText((Join-Path $dir '.release'))).Trim() | Should -Be 'v1.20.26'
        }
        It 'keeps the partial when the release tag is unchanged' {
            Reset-State
            $root = Join-Path $TestDrive 'cpsame'
            $dir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'copyparty'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $dir '.release') -Value 'v1.20.26' -NoNewline
            $partial = Join-Path $dir 'copyparty.exe.partial'
            Set-Content -LiteralPath $partial -Value 'old' -NoNewline
            Mock Invoke-GitHubApiJson { [pscustomobject]@{ tag_name = 'v1.20.26'; assets = @(
                [pscustomobject]@{ name = 'copyparty-sfx.py'; size = 1; digest = 'sha256:' + ('a' * 64); browser_download_url = 'https://example.invalid/sfx' }
                [pscustomobject]@{ name = 'copyparty.exe'; size = 2; digest = 'sha256:' + ('b' * 64); browser_download_url = 'https://example.invalid/exe' }
            ) } }
            Mock Save-VerifiedFile { return $true }
            Save-CopypartyTools -Root $root | Should -BeTrue
            Test-Path -LiteralPath $partial | Should -BeTrue
        }
        It 'restores the previous file when an update download fails' {
            Reset-State
            $root = Join-Path $TestDrive 'cpupdate'
            $dir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'copyparty'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $exe = Join-Path $dir 'copyparty.exe'
            Set-Content -LiteralPath $exe -Value 'old-build' -NoNewline
            Mock Invoke-GitHubApiJson { [pscustomobject]@{ tag_name = 'v1.20.26'; assets = @(
                [pscustomobject]@{ name = 'copyparty-sfx.py'; size = 1; digest = 'sha256:' + ('a' * 64); browser_download_url = 'https://example.invalid/sfx' }
                [pscustomobject]@{ name = 'copyparty.exe'; size = 2; digest = 'sha256:' + ('b' * 64); browser_download_url = 'https://example.invalid/exe' }
            ) } }
            Mock Invoke-Cli { [pscustomobject]@{ ExitCode = 22; StdOut = ''; StdErr = 'HTTP 404' } }
            Save-CopypartyTools -Root $root | Should -BeFalse
            (Get-Content -LiteralPath $exe -Raw).Trim() | Should -Be 'old-build'
            Test-Path -LiteralPath "$exe.prev" | Should -BeFalse
        }

        It 'records a failure when an asset is missing from the release' {
            Reset-State
            $root = Join-Path $TestDrive 'cpnoasset'
            Mock Invoke-GitHubApiJson { [pscustomobject]@{ tag_name = 'v1.20.26'; assets = @(
                [pscustomobject]@{ name = 'copyparty.exe'; size = 2; digest = 'sha256:' + ('b' * 64); browser_download_url = 'https://example.invalid/exe' }
            ) } }
            $script:calls = 0
            Mock Save-VerifiedFile { $script:calls++; Set-Content -LiteralPath $OutFile -Value 'x' -NoNewline; return $true }
            Save-CopypartyTools -Root $root | Should -BeFalse
            $script:calls | Should -Be 1
            $script:Failures | Should -HaveCount 1
            $script:Failures[0].Name | Should -Be 'copyparty-sfx.py'
        }
    }

    Context 'elevation' {
        It 'never invokes sudo.exe without -Elevate' {
            Reset-State
            Mock Test-IsAdministrator { return $true }
            Mock Invoke-Elevated { throw 'MUTATION: sudo invoked' }
            Initialize-ElevationState
            $script:UseSudo | Should -BeFalse
        }

        It 'records exactly one failure when sudo is unavailable and continues' {
            Reset-State
            Mock Test-IsAdministrator { return $false }
            Mock Get-ItemProperty { $null }
            Mock Invoke-Elevated { throw 'MUTATION: sudo invoked' }
            Initialize-ElevationState -Elevate
            $script:UseSudo | Should -BeFalse
            $script:Failures | Should -HaveCount 1
        }

        It 'does not call sudo.exe when already elevated' {
            Reset-State
            Mock Test-IsAdministrator { return $true }
            Mock Invoke-Elevated { throw 'MUTATION: sudo invoked' }
            Initialize-ElevationState -Elevate
            $script:UseSudo | Should -BeFalse
            $script:Failures | Should -HaveCount 0
        }

        It 'records a skip-failure for the Tiny11 build without elevation' {
            Reset-State
            $root = Join-Path $TestDrive 'noelev'
            $installers = Join-Path (Join-Path $root 'isos') '03-Installers'
            New-Item -ItemType Directory -Path $installers -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $installers 'Win11.iso') -Value 'x' -NoNewline
            Mock Get-GitHubLatestAsset { [pscustomobject]@{ Tag = 'v9'; Name = 'b.zip'; ZipUrl = 'https://example.invalid/b.zip'; HashUrl = 'https://example.invalid/b.zip.sha256' } }
            Mock Invoke-WebText { 'ab' * 32 + '  b.zip' }
            Mock Save-VerifiedFile { return $true }
            Mock Expand-Archive { }
            Mock Invoke-FileDownload { Set-Content -LiteralPath $OutFile -Value 'm' -NoNewline; return $true }
            Mock Test-IsAdministrator { $false }
            Invoke-Tiny11Build -Root $root | Should -BeFalse
            $script:Failures.Name | Should -Contain 'Tiny11 ISO'
            $script:Failures[-1].Manual | Should -Match 'tiny11maker'
            $script:Failures[-1].Manual | Should -Match 'Enable-WindowsSudo'
        }
    }

    Context 'manual-entry failures' {
        It 'routes a missing Fido.ps1 to Write-Failure instead of throwing' {
            Reset-State
            $root = Join-Path $TestDrive 'nofido'
            { Get-WindowsIsoViaFido -Root $root } | Should -Not -Throw
            $script:Failures | Should -HaveCount 1
            $script:Failures[0].Manual | Should -Match 'example\.invalid/windows11'
        }

        It 'routes a failed Fido run to Write-Failure instead of throwing' {
            Reset-State
            $root = Join-Path $TestDrive 'badfido'
            $tools = Join-Path $root 'tools'
            New-Item -ItemType Directory -Path $tools -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $tools 'Fido.ps1') -Value 'x' -NoNewline
            Mock Invoke-Cli { $script:fidoArgs = $Arguments; [pscustomobject]@{ ExitCode = 1; StdOut = ''; StdErr = 'blocked' } }
            Mock Start-Sleep { }
            { Get-WindowsIsoViaFido -Root $root } | Should -Not -Throw
            $script:Failures | Should -HaveCount 1
            ($script:fidoArgs -join ' ') | Should -Match "-Lang English"
        }

        It 'routes a failed Rufus download to Write-Failure instead of throwing' {
            Reset-State
            $root = Join-Path $TestDrive 'norufus'
            # One call only: a second call would record a second (Fido) failure.
            $toolsDir = Join-Path $root 'tools'
            New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $toolsDir 'Fido.ps1') -Value 'x' -NoNewline
            Mock Get-GitHubLatestAsset { [pscustomobject]@{ Tag = 'v4.15'; Name = 'rufus-4.15p.exe'; ZipUrl = 'https://example.invalid/rufus.exe'; HashUrl = '' } }
            Mock Invoke-Cli { [pscustomobject]@{ ExitCode = 22; StdOut = ''; StdErr = 'HTTP 404' } }
            Save-RufusTools -Root $root | Should -BeFalse
            $script:Failures.Name | Should -Contain 'Rufus portable'
        }
        It 'leaves the persistent User PATH unchanged' {
            $before = [Environment]::GetEnvironmentVariable('Path', 'User')
            Reset-State
            $root = Join-Path $TestDrive 'pathrun'
            $ventoyDir = Join-Path $root 'ventoy'
            Mock Get-GitHubLatestAsset { [pscustomobject]@{ Tag = 'v9'; Name = 'b.zip'; ZipUrl = 'https://example.invalid/b.zip'; HashUrl = 'https://example.invalid/b.zip.sha256' } }
            Mock Invoke-WebText { 'ab' * 32 + '  b.zip' }
            Mock Save-VerifiedFile { return $true }
            Mock Expand-Archive { Set-Content -LiteralPath (Join-Path $ventoyDir 'Ventoy2Disk.exe') -Value 'e' -NoNewline }
            { Install-Ventoy -Root $root } | Should -Not -Throw
            [Environment]::GetEnvironmentVariable('Path', 'User') | Should -Be $before
        }

        It 'writes the root and isos readmes from the top-of-script blocks' {
            Reset-State
            $root = Join-Path $TestDrive 'readme'
            $hbcdDir = Join-Path (Join-Path $root 'isos') '02-Rescue'
            New-Item -ItemType Directory -Path $hbcdDir -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $hbcdDir 'HBCD_PE_x64.iso') -Value 'bytes' -NoNewline
            Mock Invoke-WebText { 'ab' * 32 + '  b.zip' }
            Mock Install-Ventoy { return $true }
            Mock Save-RufusTools { return $true }
            Mock Save-CopypartyTools {
                $cpDir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'copyparty'
                New-Item -ItemType Directory -Path $cpDir -Force | Out-Null
                $cpFile = Join-Path $cpDir 'copyparty.exe'
                Set-Content -LiteralPath $cpFile -Value 'x' -NoNewline
                Set-Content -LiteralPath (Join-Path $cpDir 'copyparty-sfx.py') -Value 'y' -NoNewline
                $script:CopypartyRows = @([pscustomobject]@{
                    Name = 'copyparty exe (Windows)'
                    Category = '04-etc\copyparty'
                    FileName = 'copyparty.exe'
                    Url = 'https://example.invalid/copyparty.exe'
                    Hash = ('ab' * 32)
                    HashKind = 'GitHub digest'
                    Released = 'v1.20.26 (GitHub asset digest, sha256)'
                    SizeNote = 'About 13 MB.'
                    About = 'Portable file server for Windows.'
                    Check = 'GitHub API digest.'
                })
                return $true
            }
            Mock Save-CatalogIsos { $script:VerifiedHashes[(Join-Path (Join-Path (Join-Path $root 'isos') '02-Rescue') 'HBCD_PE_x64.iso')] = ('ab' * 32) }
            Mock Get-WindowsIsoViaFido { return $true }
            Mock Invoke-Tiny11Build { return $true }
            Invoke-PreparePcRecovery -Root $root | Out-Null
            $rootText = [IO.File]::ReadAllText((Join-Path $root 'README.txt'))
            $rootText | Should -Match 'tiny11builder'
            $rootText | Should -Match 'en-US'
            $rootText | Should -Match 'copyparty'
            $topicDir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'copyparty'
            $topicText = [IO.File]::ReadAllText((Join-Path $topicDir 'README.txt'))
            $topicText | Should -Match 'copyparty-sfx\.py'
            $topicText | Should -Match 'no arguments'
            $topicText | Should -Match '\-v SRC:DST:PERMS'
            $isosText = [IO.File]::ReadAllText((Join-Path (Join-Path $root 'isos') 'README.txt'))
            $isosText | Should -Match 'HBCD_PE_x64.iso'
            $isosText | Should -Match 'Windows PE rescue environment'
            $isosText | Should -Match 'Unversioned URL'
            $isosText | Should -Match 'SHA-256 \(verified this run\)'
            $isosText | Should -Match 'Official Windows 11 ISO \(not present\)'
            $isosText | Should -Match 'Tiny11 ISO \(not present\)'
            $isosText | Should -Match '04-etc\\copyparty\\copyparty\.exe'
            $isosText | Should -Match 'v1\.20\.26'
            $isosText | Should -Match 'copyparty \(copyparty-sfx\.py, not verified this run\)'
            $isosText | Should -Match 'SHA-256 \(on disk at write time\)'
        }

        It 'fetches the checksum sidecar next to the ISO and lists it' {
            Reset-State
            $root = Join-Path $TestDrive 'sidecar'
            $dir = Join-Path (Join-Path $root 'isos') '03-Installers'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $row = [pscustomobject]@{ Name = 'T-row'; Category = '03-Installers'; FileName = 'T.iso'; Url = 'https://example.invalid/T.iso'; AlternateUrl = ''; Hash = ('ab' * 32); HashKind = 'Pinned'; ChecksumUrl = ''; NetbootVariant = ''; MintHwe = ''; About = 'T'; Released = 'T'; SizeNote = 'T'; Check = 'T'; SidecarUrl = 'https://example.invalid/T.sha256'; SidecarName = 'T.iso.sha256' }
            Mock Save-VerifiedFile { Set-Content -LiteralPath $OutFile -Value 'bytes' -NoNewline; return $true }
            Mock Invoke-FileDownload { Set-Content -LiteralPath $OutFile -Value 'hashline' -NoNewline; return $true }
            Save-CatalogRow -Row $row -Root $root | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $dir 'T.iso.sha256') | Should -BeTrue
            $block = Format-IsoReadmeEntry -Row $row -Root $root
            $block | Should -Match 'Checksum file \(shipped alongside\): T\.iso\.sha256'
        }

        It 'formats a readme block with the on-disk hash when present' {
            Reset-State
            $root = Join-Path $TestDrive 'fmt'
            $dir = Join-Path (Join-Path $root 'isos') '02-Rescue'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $file = Join-Path $dir 'HBCD_PE_x64.iso'
            Set-Content -LiteralPath $file -Value 'bytes' -NoNewline
            $sha = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
            $row = Get-RecoveryCatalog | Where-Object { $_.FileName -eq 'HBCD_PE_x64.iso' } | Select-Object -First 1
            $script:VerifiedHashes[$file] = $sha
            $block = Format-IsoReadmeEntry -Row $row -Root $root
            $block | Should -Match 'Windows PE rescue environment'
            $block | Should -Match $sha
            $block | Should -Match 'Bytes on disk: 5'
        }

        It 'hashes a hand-placed ISO with no catalog hash' {
            Reset-State
            $file = Join-Path $TestDrive 'manual.iso'
            Set-Content -LiteralPath $file -Value 'manual-bytes' -NoNewline
            $sha = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
            $block = Format-ManualIsoReadmeEntry -Title 'Official Windows 11 ISO' -Path $file -Folder '03-Installers' -Note 'Kept as downloaded.' -Root $TestDrive
            $block | Should -Match $sha
            $block | Should -Match 'Bytes on disk'
        }

        It 'keeps the Tiny11 builder under tools' {
            Reset-State
            $root = Join-Path $TestDrive 'tpath'
            Mock Get-GitHubLatestAsset { [pscustomobject]@{ Tag = 'v9'; Name = 'b.zip'; ZipUrl = 'https://example.invalid/b.zip'; HashUrl = 'https://example.invalid/b.zip.sha256' } }
            Mock Invoke-WebText { 'ab' * 32 + '  b.zip' }
            Mock Save-VerifiedFile { Set-Content -LiteralPath $OutFile -Value 'z' -NoNewline; return $true }
            Mock Expand-Archive { }
            Mock Invoke-FileDownload { Set-Content -LiteralPath $OutFile -Value 'm' -NoNewline; return $true }
            New-Item -ItemType Directory -Path (Join-Path (Join-Path $root 'isos') '03-Installers') -Force | Out-Null
            { Invoke-Tiny11Build -Root $root } | Should -Not -Throw
            Test-Path -LiteralPath (Join-Path (Join-Path $root 'tools') 'tiny11builder') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $root 'tiny11builder') | Should -BeFalse
        }

        It 'keeps manual build steps when the builder hash sidecar is missing' {
            Reset-State
            $root = Join-Path $TestDrive 'nohash'
            Mock Get-GitHubLatestAsset { [pscustomobject]@{ Tag = 'v9'; Name = 'b.zip'; ZipUrl = 'https://example.invalid/b.zip'; HashUrl = '' } }
            Invoke-Tiny11Build -Root $root | Should -BeFalse
            $script:Failures.Name | Should -Contain 'Tiny11 builder'
            $script:Failures[-1].Manual | Should -Match 'releases/latest'
            $script:Failures[-1].Manual | Should -Match 'elevated shell'
            $script:Failures[-1].Manual | Should -Match '03-Installers\\tiny11'
        }

        It 'keeps the admin hint when the maker download fails' {
            Reset-State
            $root = Join-Path $TestDrive 'nomaker'
            Mock Get-GitHubLatestAsset { [pscustomobject]@{ Tag = 'v9'; Name = 'b.zip'; ZipUrl = 'https://example.invalid/b.zip'; HashUrl = 'https://example.invalid/b.zip.sha256' } }
            Mock Invoke-WebText { 'ab' * 32 + '  b.zip' }
            Mock Save-VerifiedFile { return $true }
            Mock Expand-Archive { }
            Mock Invoke-FileDownload { return $false }
            Mock Test-IsAdministrator { $false }
            Invoke-Tiny11Build -Root $root | Should -BeFalse
            $script:Failures.Name | Should -Contain 'Tiny11 builder'
            $script:Failures[-1].Manual | Should -Match 'Enable-WindowsSudo'
        }

        It 'skips the sudo advice when the shell is already elevated' {
            Reset-State
            $root = Join-Path $TestDrive 'adminnoelev'
            $installers = Join-Path (Join-Path $root 'isos') '03-Installers'
            New-Item -ItemType Directory -Path $installers -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $installers 'Win11.iso') -Value 'x' -NoNewline
            Mock Test-IsAdministrator { $true }
            Mock Get-GitHubLatestAsset { [pscustomobject]@{ Tag = 'v9'; Name = 'b.zip'; ZipUrl = 'https://example.invalid/b.zip'; HashUrl = 'https://example.invalid/b.zip.sha256' } }
            Mock Invoke-WebText { 'ab' * 32 + '  b.zip' }
            Mock Save-VerifiedFile { return $true }
            Mock Expand-Archive { }
            Mock Invoke-FileDownload { Set-Content -LiteralPath $OutFile -Value 'm' -NoNewline; return $true }
            Invoke-Tiny11Build -Root $root -Elevate | Should -BeFalse
            $script:Failures[-1].Manual | Should -Match 'tiny11maker'
            $script:Failures[-1].Manual | Should -Not -Match 'Enable-WindowsSudo'
        }

        It 'drops the admin hint when the maker download fails in an elevated shell' {
            Reset-State
            $root = Join-Path $TestDrive 'nomakeradmin'
            Mock Test-IsAdministrator { $true }
            Mock Get-GitHubLatestAsset { [pscustomobject]@{ Tag = 'v9'; Name = 'b.zip'; ZipUrl = 'https://example.invalid/b.zip'; HashUrl = 'https://example.invalid/b.zip.sha256' } }
            Mock Invoke-WebText { 'ab' * 32 + '  b.zip' }
            Mock Save-VerifiedFile { return $true }
            Mock Expand-Archive { }
            Mock Invoke-FileDownload { return $false }
            Invoke-Tiny11Build -Root $root -Elevate | Should -BeFalse
            $script:Failures.Name | Should -Contain 'Tiny11 builder'
            $script:Failures[-1].Manual | Should -Match 'already elevated'
            $script:Failures[-1].Manual | Should -Not -Match 're-run'
            $script:Failures[-1].Manual | Should -Not -Match 'Enable-WindowsSudo'
        }

        It 'drops the admin hint when the maker download fails under sudo' {
            Reset-State
            $root = Join-Path $TestDrive 'nomakersudo'
            Mock Get-GitHubLatestAsset { [pscustomobject]@{ Tag = 'v9'; Name = 'b.zip'; ZipUrl = 'https://example.invalid/b.zip'; HashUrl = 'https://example.invalid/b.zip.sha256' } }
            Mock Invoke-WebText { 'ab' * 32 + '  b.zip' }
            Mock Save-VerifiedFile { return $true }
            Mock Expand-Archive { }
            Mock Invoke-FileDownload { return $false }
            $script:UseSudo = $true
            Invoke-Tiny11Build -Root $root -Elevate | Should -BeFalse
            $script:Failures[-1].Manual | Should -Match 'Then re-run with -Elevate'
            $script:Failures[-1].Manual | Should -Not -Match 'Enable-WindowsSudo'
        }

        It 'drops the sudo advice when the elevated build fails' {
            Reset-State
            $root = Join-Path $TestDrive 'builtfail'
            $installers = Join-Path (Join-Path $root 'isos') '03-Installers'
            New-Item -ItemType Directory -Path $installers -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $installers 'Win11.iso') -Value 'x' -NoNewline
            Mock Get-GitHubLatestAsset { [pscustomobject]@{ Tag = 'v9'; Name = 'b.zip'; ZipUrl = 'https://example.invalid/b.zip'; HashUrl = 'https://example.invalid/b.zip.sha256' } }
            Mock Invoke-WebText { 'ab' * 32 + '  b.zip' }
            Mock Save-VerifiedFile { return $true }
            Mock Expand-Archive { }
            Mock Invoke-FileDownload { Set-Content -LiteralPath $OutFile -Value 'm' -NoNewline; return $true }
            Mock Invoke-Elevated { }
            $script:UseSudo = $true
            Invoke-Tiny11Build -Root $root -Elevate | Should -BeFalse
            $script:Failures[-1].Manual | Should -Match 'tiny11maker'
            $script:Failures[-1].Manual | Should -Not -Match 'Enable-WindowsSudo'
        }

        It 'routes a missing official ISO to a Tiny11 skip-failure' {
            Reset-State
            $root = Join-Path $TestDrive 'notiny'
            New-Item -ItemType Directory -Path (Join-Path (Join-Path $root 'isos') '03-Installers') -Force | Out-Null
            Mock Get-GitHubLatestAsset { [pscustomobject]@{ Tag = 'v9'; Name = 'b.zip'; ZipUrl = 'https://example.invalid/b.zip'; HashUrl = 'https://example.invalid/b.zip.sha256' } }
            Mock Invoke-WebText { 'ab' * 32 + '  b.zip' }
            Mock Save-VerifiedFile { return $true }
            Mock Expand-Archive { }
            Mock Invoke-FileDownload { Set-Content -LiteralPath $OutFile -Value 'm' -NoNewline; return $true }
            { Invoke-Tiny11Build -Root $root -Elevate } | Should -Not -Throw
            $script:Failures.Name | Should -Contain 'Tiny11 ISO'
            $script:Failures[-1].Manual | Should -Not -BeNullOrEmpty
            $script:UseSudo | Should -BeFalse
        }
    }
}

