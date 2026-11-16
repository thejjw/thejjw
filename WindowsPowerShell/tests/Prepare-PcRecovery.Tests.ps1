Describe 'Prepare-PcRecovery.ps1' {
    BeforeAll {
        # Load only the function definitions from the util script (no execution, no side effects).
        $scriptPath = Join-Path $PSScriptRoot '..\util\Prepare-PcRecovery\Prepare-PcRecovery.ps1'
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
        if ($errors) { throw "Script contains parse errors: $($errors -join '; ')" }
        $functions = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)
        foreach ($function in $functions) { . ([scriptblock]::Create($function.Extent.Text)) }

        # Script-level state the helpers read; every path points into TestDrive.
        # Evaluate the script's own shared-name constant assignments (not stubs):
        # a mangled constant (e.g. self-assignment to $null) surfaces here.
        $constAssignments = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -match '^\$script:(Dir|File|MsDownload|ThirdParty|WinIso|MakerHint|Tiny11BuilderReleasesUrl|VentoyReleasesUrl|Tiny11AnswerUrl|Tiny11MakerUrl|OscdimgUrl|Copyparty|Py|SevenZip|Putty|WinScp|Cyberduck|Tabby|ImgBurn|Firefox)' }, $false)
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
        function Reset-State { $script:Failures = @(); $script:Results = @(); $script:UseSudo = $false; $script:VerifiedHashes = @{}; $script:Sidecars = @{}; $script:CopypartyRows = @(); $script:FirefoxRelease = $null; $script:FirefoxResolved = $null }
    }

    Context 'shared constants' {
        It 'defines every shared name with a real value (no self-assignment)' {
            $expected = @{
                DirTools = 'tools'; DirVentoy = 'ventoy'; DirIsos = 'isos'
                DirInstallers = '03-Installers'; DirTiny11 = 'tiny11'; DirBuilder = 'tiny11builder'; DirCopyparty = 'copyparty'; DirPython = 'python'
                FileVentoyExe = 'Ventoy2Disk.exe'; FileFido = 'Fido.ps1'; FileTiny11Iso = 'tiny11.iso'
                FileMaker = 'tiny11maker.ps1'; FileAnswer = 'autounattend.xml'; FileOscdimg = 'oscdimg.exe'
                FileFacts = 'filefacts.json'; FileReadme = 'README.txt'
                FileCopypartySfx = 'copyparty-sfx.py'; FileCopypartyExe = 'copyparty.exe'; FileCopypartyTag = '.release'
                PyVersion = '3.15.2'; FilePythonInstaller = 'python-3.15.2-amd64.exe'; FilePythonEmbed = 'python-3.15.2-embed-amd64.zip'
                DirSevenZip = '7zip'; SevenZipVersion = '26.06'; FileSevenZipInstaller = '7z2606-x64.exe'; FileSevenZipExtra = '7z2606-extra.7z'; FileSevenZipBootstrap = '7zr-2606.exe'
                DirPutty = 'putty'; PuttyVersion = '0.85'; FilePuttyZip = 'putty-0.85.zip'; FilePuttySums = 'putty-0.85-sha256sums.txt'
                DirWinScp = 'winscp'; WinScpVersion = '6.7.1'; FileWinScpPortable = 'WinSCP-6.7.1-Portable.zip'
                DirCyberduck = 'cyberduck'; CyberduckVersion = '9.6.0.46406'; FileCyberduckInstaller = 'Cyberduck-Installer-9.6.0.46406.exe'; FileCyberduckDuck = 'duck_9.6.0.46406_amd64.deb'; FileCyberduckDuckRpm = 'duck-9.6.0.46406-1.x86_64.rpm'
                DirTabby = 'tabby'; TabbyVersion = '1.0.238'; FileTabbyZip = 'tabby-1.0.238-portable-x64.zip'; FileTabbyDeb = 'tabby-1.0.238-linux-x64.deb'; FileTabbyRpm = 'tabby-1.0.238-linux-x64.rpm'
                DirImgBurn = 'imgburn'; ImgBurnVersion = '2.5.8.0'; FileImgBurnInstaller = 'SetupImgBurn_2.5.8.0.exe'; FileImgBurnExe = 'ImgBurn.exe'; FileImgBurnLauncher = 'ImgBurn Portable.cmd'; FileImgBurnIni = 'ImgBurn.ini'
                DirFirefox = 'firefox'; FirefoxFallbackVersion = '153.7.0esr'; FirefoxFallbackReleased = '2026-11-10'; ImgBurnReleased = '2013-06-16'
            }
            foreach ($name in $expected.Keys) {
                $actual = (Get-Variable -Name $name -Scope Script -ValueOnly -ErrorAction Stop)
                $actual | Should -Be $expected[$name]
            }
            $script:MsDownloadPage | Should -Match '^https://'
            $script:CopypartyApiUrl | Should -Match '^https://api\.github\.com/'
            $script:CopypartyReleasesUrl | Should -Match '^https://github\.com/'
            $script:CopypartyTagUrlBase | Should -Be 'https://github.com/9001/copyparty/releases/tag/'
            $script:CyberduckDownloadPage | Should -Match '^https://cyberduck\.io/'
            $script:FirefoxVersionsUrl | Should -Be 'https://product-details.mozilla.org/1.0/firefox_versions.json'
            $script:FirefoxReleasesUrl | Should -Be 'https://ftp.mozilla.org/pub/firefox/releases/'
            $script:FirefoxFallbackSha256 | Should -Match '^[0-9a-f]{64}$'
            $script:FirefoxJsonUrl | Should -Be 'https://product-details.mozilla.org/1.0/firefox.json'
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
            $names | Should -Contain '04-etc\python'
            $names | Should -Contain '04-etc\cyberduck'
            $names | Should -Contain '04-etc\tabby'
            foreach ($name in $names) { $name | Should -Match '^\d\d-[A-Za-z]+(\\[a-z0-9-]+)?$' }
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
            $sample = Join-Path $TestDrive 'cp-sample.bin'
            Set-Content -LiteralPath $sample -Value 'x' -NoNewline
            $sha = (Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash.ToLowerInvariant()
            Mock Invoke-GitHubApiJson { [pscustomobject]@{ tag_name = 'v1.20.26'; assets = @(
                [pscustomobject]@{ name = 'copyparty-sfx.py'; size = 1206486; digest = "sha256:$sha"; browser_download_url = 'https://github.com/9001/copyparty/releases/download/v1.20.26/copyparty-sfx.py' }
                [pscustomobject]@{ name = 'copyparty.exe'; size = 13207240; digest = "sha256:$sha"; browser_download_url = 'https://github.com/9001/copyparty/releases/download/v1.20.26/copyparty.exe' }
            ) } }
            $script:sawDownloads = @()
            Mock Save-VerifiedFile { $script:sawDownloads += [pscustomobject]@{ Url = $Url; OutFile = $OutFile; Hash = $ExpectedHash }; Set-Content -LiteralPath $OutFile -Value 'x' -NoNewline; return $true }
            Save-CopypartyTools -Root $root | Should -BeTrue
            $script:sawDownloads.Count | Should -Be 2
            $script:sawDownloads[0].Url | Should -Match '/download/v1\.20\.26/copyparty-sfx\.py$'
            $script:sawDownloads[0].Hash | Should -Be $sha
            $script:sawDownloads[0].OutFile | Should -Match 'isos\\04-etc\\copyparty\\copyparty-sfx\.py$'
            $script:sawDownloads[1].OutFile | Should -Match 'isos\\04-etc\\copyparty\\copyparty\.exe$'
            $script:CopypartyRows.Count | Should -Be 2
            $block = Format-IsoReadmeEntry -Row ($script:CopypartyRows | Where-Object { $_.FileName -eq 'copyparty.exe' }) -Root $root
            $block | Should -Match 'v1\.20\.26'
            $block | Should -Match $sha
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
            $sample = Join-Path $TestDrive 'cppart-sample.bin'
            Set-Content -LiteralPath $sample -Value 'x' -NoNewline
            $sha = (Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash.ToLowerInvariant()
            Mock Invoke-GitHubApiJson { [pscustomobject]@{ tag_name = 'v1.20.26'; assets = @(
                [pscustomobject]@{ name = 'copyparty-sfx.py'; size = 1; digest = "sha256:$sha"; browser_download_url = 'https://example.invalid/sfx' }
                [pscustomobject]@{ name = 'copyparty.exe'; size = 2; digest = "sha256:$sha"; browser_download_url = 'https://example.invalid/exe' }
            ) } }
            Mock Save-VerifiedFile { Set-Content -LiteralPath $OutFile -Value 'x' -NoNewline; return $true }
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
            $sample = Join-Path $TestDrive 'cpsame-sample.bin'
            Set-Content -LiteralPath $sample -Value 'x' -NoNewline
            $sha = (Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash.ToLowerInvariant()
            Mock Invoke-GitHubApiJson { [pscustomobject]@{ tag_name = 'v1.20.26'; assets = @(
                [pscustomobject]@{ name = 'copyparty-sfx.py'; size = 1; digest = "sha256:$sha"; browser_download_url = 'https://example.invalid/sfx' }
                [pscustomobject]@{ name = 'copyparty.exe'; size = 2; digest = "sha256:$sha"; browser_download_url = 'https://example.invalid/exe' }
            ) } }
            Mock Save-VerifiedFile { Set-Content -LiteralPath $OutFile -Value 'x' -NoNewline; return $true }
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
            @($script:CopypartyRows | Where-Object { $_.FileName -eq 'copyparty.exe' }).Count | Should -Be 0
        }

        It 'restores a leftover .prev when its target is missing' {
            Reset-State
            $root = Join-Path $TestDrive 'cpprevonly'
            $dir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'copyparty'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $exe = Join-Path $dir 'copyparty.exe'
            Set-Content -LiteralPath "$exe.prev" -Value 'old-build' -NoNewline
            Mock Invoke-GitHubApiJson { [pscustomobject]@{ tag_name = 'v1.20.26'; assets = @(
                [pscustomobject]@{ name = 'copyparty-sfx.py'; size = 1; digest = 'sha256:' + ('a' * 64); browser_download_url = 'https://example.invalid/sfx' }
                [pscustomobject]@{ name = 'copyparty.exe'; size = 2; digest = 'sha256:' + ('b' * 64); browser_download_url = 'https://example.invalid/exe' }
            ) } }
            Mock Invoke-Cli { [pscustomobject]@{ ExitCode = 22; StdOut = ''; StdErr = 'HTTP 404' } }
            Save-CopypartyTools -Root $root | Should -BeFalse
            (Get-Content -LiteralPath $exe -Raw).Trim() | Should -Be 'old-build'
            Test-Path -LiteralPath "$exe.prev" | Should -BeFalse
            @($script:CopypartyRows | Where-Object { $_.FileName -eq 'copyparty.exe' }).Count | Should -Be 0
        }

        It 'drops a stale .prev once the target verifies' {
            Reset-State
            $root = Join-Path $TestDrive 'cpprevstale'
            $dir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'copyparty'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $exe = Join-Path $dir 'copyparty.exe'
            Set-Content -LiteralPath $exe -Value 'current-build' -NoNewline
            Set-Content -LiteralPath "$exe.prev" -Value 'older-build' -NoNewline
            $sha = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
            Mock Invoke-GitHubApiJson { [pscustomobject]@{ tag_name = 'v1.20.26'; assets = @(
                [pscustomobject]@{ name = 'copyparty-sfx.py'; size = 1; digest = 'sha256:' + ('a' * 64); browser_download_url = 'https://example.invalid/sfx' }
                [pscustomobject]@{ name = 'copyparty.exe'; size = 2; digest = "sha256:$sha"; browser_download_url = 'https://example.invalid/exe' }
            ) } }
            Mock Save-VerifiedFile {
                if (Test-Path -LiteralPath $OutFile) { return (Test-LocalFileHash -Path $OutFile -ExpectedHash $ExpectedHash) }
                return $false
            }
            Save-CopypartyTools -Root $root | Should -BeFalse
            Test-Path -LiteralPath "$exe.prev" | Should -BeFalse
            @($script:CopypartyRows | Where-Object { $_.FileName -eq 'copyparty.exe' }).Count | Should -Be 1
        }

        It 'leaves the old build untouched when it cannot be moved aside' {
            Reset-State
            $root = Join-Path $TestDrive 'cpmovefail'
            $dir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'copyparty'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $exe = Join-Path $dir 'copyparty.exe'
            Set-Content -LiteralPath $exe -Value 'old-build' -NoNewline
            Mock Invoke-GitHubApiJson { [pscustomobject]@{ tag_name = 'v1.20.26'; assets = @(
                [pscustomobject]@{ name = 'copyparty-sfx.py'; size = 1; digest = 'sha256:' + ('a' * 64); browser_download_url = 'https://example.invalid/sfx' }
                [pscustomobject]@{ name = 'copyparty.exe'; size = 2; digest = 'sha256:' + ('b' * 64); browser_download_url = 'https://example.invalid/exe' }
            ) } }
            Mock Move-Item { throw 'locked' } -ParameterFilter { $Destination -like '*.prev' }
            $script:svCalls = @()
            Mock Save-VerifiedFile { $script:svCalls += $Name; Set-Content -LiteralPath $OutFile -Value 'x' -NoNewline; return $true }
            Save-CopypartyTools -Root $root | Should -BeFalse
            (Get-Content -LiteralPath $exe -Raw).Trim() | Should -Be 'old-build'
            $script:svCalls | Should -Not -Contain 'copyparty.exe'
            $script:Failures.Name | Should -Contain 'copyparty.exe'
            @($script:CopypartyRows | Where-Object { $_.FileName -eq 'copyparty.exe' }).Count | Should -Be 0
        }

        It 'keeps .prev when the restore move fails' {
            Reset-State
            $root = Join-Path $TestDrive 'cprestorefail'
            $dir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'copyparty'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $exe = Join-Path $dir 'copyparty.exe'
            Set-Content -LiteralPath $exe -Value 'old-build' -NoNewline
            Mock Invoke-GitHubApiJson { [pscustomobject]@{ tag_name = 'v1.20.26'; assets = @(
                [pscustomobject]@{ name = 'copyparty-sfx.py'; size = 1; digest = 'sha256:' + ('a' * 64); browser_download_url = 'https://example.invalid/sfx' }
                [pscustomobject]@{ name = 'copyparty.exe'; size = 2; digest = 'sha256:' + ('b' * 64); browser_download_url = 'https://example.invalid/exe' }
            ) } }
            Mock Invoke-Cli { [pscustomobject]@{ ExitCode = 22; StdOut = ''; StdErr = 'HTTP 404' } }
            Mock Restore-PreviousCopyparty { return $false }
            Save-CopypartyTools -Root $root | Should -BeFalse
            Test-Path -LiteralPath $exe | Should -BeFalse
            (Get-Content -LiteralPath "$exe.prev" -Raw).Trim() | Should -Be 'old-build'
            @($script:CopypartyRows | Where-Object { $_.FileName -eq 'copyparty.exe' }).Count | Should -Be 0
        }

        It 'restores an orphaned .prev before the release lookup' {
            Reset-State
            $root = Join-Path $TestDrive 'cporphan'
            $dir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'copyparty'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $exe = Join-Path $dir 'copyparty.exe'
            Set-Content -LiteralPath "$exe.prev" -Value 'old-build' -NoNewline
            Mock Invoke-GitHubApiJson { throw 'rate limited' }
            Save-CopypartyTools -Root $root | Should -BeFalse
            (Get-Content -LiteralPath $exe -Raw).Trim() | Should -Be 'old-build'
            Test-Path -LiteralPath "$exe.prev" | Should -BeFalse
            $script:Failures | Should -HaveCount 1
        }

        It 'reports a restore it cannot perform' {
            Reset-State
            $missing = Join-Path $TestDrive 'missing.exe.prev'
            $target = Join-Path $TestDrive 'missing.exe'
            Restore-PreviousCopyparty -PrevFile $missing -Target $target | Should -BeFalse
            Test-Path -LiteralPath $target | Should -BeFalse
        }

        It 'restores the previous build when the download throws' {
            Reset-State
            $root = Join-Path $TestDrive 'cpthrow'
            $dir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'copyparty'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $exe = Join-Path $dir 'copyparty.exe'
            Set-Content -LiteralPath $exe -Value 'old-build' -NoNewline
            Mock Invoke-GitHubApiJson { [pscustomobject]@{ tag_name = 'v1.20.26'; assets = @(
                [pscustomobject]@{ name = 'copyparty-sfx.py'; size = 1; digest = 'sha256:' + ('a' * 64); browser_download_url = 'https://example.invalid/sfx' }
                [pscustomobject]@{ name = 'copyparty.exe'; size = 2; digest = 'sha256:' + ('b' * 64); browser_download_url = 'https://example.invalid/exe' }
            ) } }
            Mock Save-VerifiedFile { throw 'locked by scanner' }
            Save-CopypartyTools -Root $root | Should -BeFalse
            (Get-Content -LiteralPath $exe -Raw).Trim() | Should -Be 'old-build'
            Test-Path -LiteralPath "$exe.prev" | Should -BeFalse
            $script:Failures.Name | Should -Contain 'copyparty.exe'
        }

        It 'does not document a file that did not verify' {
            Reset-State
            $root = Join-Path $TestDrive 'cpunverified'
            $dir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'copyparty'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $exe = Join-Path $dir 'copyparty.exe'
            Set-Content -LiteralPath $exe -Value 'old-build' -NoNewline
            Mock Invoke-GitHubApiJson { [pscustomobject]@{ tag_name = 'v1.20.26'; assets = @(
                [pscustomobject]@{ name = 'copyparty-sfx.py'; size = 1; digest = 'sha256:' + ('a' * 64); browser_download_url = 'https://example.invalid/sfx' }
                [pscustomobject]@{ name = 'copyparty.exe'; size = 2; digest = 'sha256:' + ('b' * 64); browser_download_url = 'https://example.invalid/exe' }
            ) } }
            Mock Save-VerifiedFile { return $true }
            Save-CopypartyTools -Root $root | Should -BeFalse
            (Get-Content -LiteralPath $exe -Raw).Trim() | Should -Be 'old-build'
            Test-Path -LiteralPath "$exe.prev" | Should -BeFalse
            @($script:CopypartyRows | Where-Object { $_.FileName -eq 'copyparty.exe' }).Count | Should -Be 0
            $script:Failures | Should -HaveCount 0
        }

        It 'skips the update when the backup is declined' {
            Reset-State
            $root = Join-Path $TestDrive 'cpnobackup'
            $dir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'copyparty'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $exe = Join-Path $dir 'copyparty.exe'
            Set-Content -LiteralPath $exe -Value 'old-build' -NoNewline
            Mock Invoke-GitHubApiJson { [pscustomobject]@{ tag_name = 'v1.20.26'; assets = @(
                [pscustomobject]@{ name = 'copyparty-sfx.py'; size = 1; digest = 'sha256:' + ('a' * 64); browser_download_url = 'https://example.invalid/sfx' }
                [pscustomobject]@{ name = 'copyparty.exe'; size = 2; digest = 'sha256:' + ('b' * 64); browser_download_url = 'https://example.invalid/exe' }
            ) } }
            $script:svNames = @()
            Mock Save-VerifiedFile { $script:svNames += $Name; return $true }
            Save-CopypartyTools -Root $root -WhatIf | Should -BeFalse
            $script:svNames | Should -Not -Contain 'copyparty.exe'
            (Get-Content -LiteralPath $exe -Raw).Trim() | Should -Be 'old-build'
        }

        It 'continues with the other asset when the existing file cannot be hashed' {
            Reset-State
            $root = Join-Path $TestDrive 'cphashfail'
            $dir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'copyparty'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $exe = Join-Path $dir 'copyparty.exe'
            Set-Content -LiteralPath $exe -Value 'old-build' -NoNewline
            $sample = Join-Path $TestDrive 'cphashfail-sample.bin'
            Set-Content -LiteralPath $sample -Value 'x' -NoNewline
            $sha = (Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash.ToLowerInvariant()
            Mock Invoke-GitHubApiJson { [pscustomobject]@{ tag_name = 'v1.20.26'; assets = @(
                [pscustomobject]@{ name = 'copyparty-sfx.py'; size = 1; digest = "sha256:$sha"; browser_download_url = 'https://example.invalid/sfx' }
                [pscustomobject]@{ name = 'copyparty.exe'; size = 2; digest = "sha256:$sha"; browser_download_url = 'https://example.invalid/exe' }
            ) } }
            Mock Test-LocalFileHash { return ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -eq $ExpectedHash.ToLowerInvariant()) }
            Mock Test-LocalFileHash { throw 'locked' } -ParameterFilter { $Path -like '*copyparty.exe' }
            Mock Save-VerifiedFile { Set-Content -LiteralPath $OutFile -Value 'x' -NoNewline; return $true }
            Save-CopypartyTools -Root $root | Should -BeFalse
            $script:Failures.Name | Should -Contain 'copyparty.exe'
            @($script:CopypartyRows | Where-Object { $_.FileName -eq 'copyparty-sfx.py' }).Count | Should -Be 1
            (Get-Content -LiteralPath $exe -Raw).Trim() | Should -Be 'old-build'
        }

        It 'replaces a stale build and clears its .prev' {
            Reset-State
            $root = Join-Path $TestDrive 'cpupdateok'
            $dir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'copyparty'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $exe = Join-Path $dir 'copyparty.exe'
            Set-Content -LiteralPath $exe -Value 'old-build' -NoNewline
            $sample = Join-Path $TestDrive 'cpupdateok-sample.bin'
            Set-Content -LiteralPath $sample -Value 'x' -NoNewline
            $sha = (Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash.ToLowerInvariant()
            Mock Invoke-GitHubApiJson { [pscustomobject]@{ tag_name = 'v1.20.26'; assets = @(
                [pscustomobject]@{ name = 'copyparty-sfx.py'; size = 1; digest = "sha256:$sha"; browser_download_url = 'https://example.invalid/sfx' }
                [pscustomobject]@{ name = 'copyparty.exe'; size = 2; digest = "sha256:$sha"; browser_download_url = 'https://example.invalid/exe' }
            ) } }
            Mock Save-VerifiedFile {
                if (Test-Path -LiteralPath $OutFile) { throw "expected backup before $OutFile" }
                Set-Content -LiteralPath $OutFile -Value 'x' -NoNewline
                return $true
            }
            Save-CopypartyTools -Root $root | Should -BeTrue
            (Get-Content -LiteralPath $exe -Raw).Trim() | Should -Be 'x'
            Test-Path -LiteralPath "$exe.prev" | Should -BeFalse
            @($script:CopypartyRows | Where-Object { $_.FileName -eq 'copyparty.exe' }).Count | Should -Be 1
            $script:VerifiedHashes[$exe] | Should -Be $sha
        }

        It 'records a failure when a downloaded file fails verification' {
            Reset-State
            $root = Join-Path $TestDrive 'cpverifyfail'
            $dir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'copyparty'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $sample = Join-Path $TestDrive 'cpverifyfail-sample.bin'
            Set-Content -LiteralPath $sample -Value 'x' -NoNewline
            $sha = (Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash.ToLowerInvariant()
            Mock Invoke-GitHubApiJson { [pscustomobject]@{ tag_name = 'v1.20.26'; assets = @(
                [pscustomobject]@{ name = 'copyparty-sfx.py'; size = 1; digest = "sha256:$sha"; browser_download_url = 'https://example.invalid/sfx' }
                [pscustomobject]@{ name = 'copyparty.exe'; size = 2; digest = "sha256:$sha"; browser_download_url = 'https://example.invalid/exe' }
            ) } }
            Mock Test-LocalFileHash { return ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -eq $ExpectedHash.ToLowerInvariant()) }
            Mock Test-LocalFileHash { throw 'locked' } -ParameterFilter { $Path -like '*copyparty.exe' }
            Mock Save-VerifiedFile {
                Set-Content -LiteralPath $OutFile -Value 'x' -NoNewline
                $script:Results += [pscustomobject]@{ Name = $Name; Status = 'Downloaded'; Detail = 'mock' }
                return $true
            }
            Save-CopypartyTools -Root $root | Should -BeFalse
            $script:Failures | Should -HaveCount 1
            $script:Failures[0].Name | Should -Be 'copyparty.exe'
        }

        It 'records one failure when the release marker cannot be written' {
            Reset-State
            $root = Join-Path $TestDrive 'cpmarker'
            $dir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'copyparty'
            New-Item -ItemType Directory -Path (Join-Path $dir '.release') -Force | Out-Null
            $sample = Join-Path $TestDrive 'cpmarker-sample.bin'
            Set-Content -LiteralPath $sample -Value 'x' -NoNewline
            $sha = (Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash.ToLowerInvariant()
            Mock Invoke-GitHubApiJson { [pscustomobject]@{ tag_name = 'v1.20.26'; assets = @(
                [pscustomobject]@{ name = 'copyparty-sfx.py'; size = 1; digest = "sha256:$sha"; browser_download_url = 'https://example.invalid/sfx' }
                [pscustomobject]@{ name = 'copyparty.exe'; size = 2; digest = "sha256:$sha"; browser_download_url = 'https://example.invalid/exe' }
            ) } }
            Mock Save-VerifiedFile { Set-Content -LiteralPath $OutFile -Value 'x' -NoNewline; return $true }
            Save-CopypartyTools -Root $root | Should -BeTrue
            $script:Failures | Should -HaveCount 1
            $script:Failures[0].Name | Should -Be 'copyparty release marker'
            $script:CopypartyRows.Count | Should -Be 2
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

    Context 'python tools' {
        It 'pins both Python artifacts under 04-etc\python' {
            $rows = @(Get-RecoveryCatalog | Where-Object { $_.Category -eq '04-etc\python' })
            $rows.Count | Should -Be 2
            foreach ($row in $rows) {
                $row.HashKind | Should -Be 'Pinned'
                $row.Hash | Should -Match '^[0-9a-f]{64}$'
                $row.Url | Should -Match '^https://www\.python\.org/ftp/python/3\.15\.2/'
                $row.FileName | Should -Match '^python-3\.15\.2-(amd64\.exe|embed-amd64\.zip)$'
                $row.SidecarName | Should -BeNullOrEmpty
            }
            $rows.FileName | Should -Contain $script:FilePythonInstaller
            $rows.FileName | Should -Contain $script:FilePythonEmbed
        }

        It 'builds the topic readme from the catalog file names' {
            $text = Get-PythonReadmeText -RunStartedUtc '2026-11-16 00:00 UTC' -WrittenUtc '2026-11-16 00:00 UTC'
            foreach ($row in (Get-RecoveryCatalog | Where-Object { $_.Category -eq '04-etc\python' })) {
                $text.Contains($row.FileName) | Should -BeTrue
            }
            $text | Should -Match 'start "" /wait'
            $text | Should -Match 'Get-AuthenticodeSignature'
            $text | Should -Match 'no pip, venv, or tkinter'
            $text | Should -Match 'Windows 10/11 x64'
            $text | Should -Match 'WinPE is not supported'
            $text.Contains('TargetDir=`"$env:LOCALAPPDATA') | Should -BeTrue
            $text.Contains('/log `"$env:TEMP') | Should -BeTrue
            $text.Contains('.\python.exe') | Should -BeTrue
            $text | Should -Match 'cannot run in place'
        }

        It 'downloads netboot first and the 04-etc topics last' {
            Reset-State
            $script:order = @()
            Mock Save-CatalogRow { $script:order += $Row.FileName }
            Save-CatalogIsos -Root (Join-Path $TestDrive 'pyorder') -NetbootArch 'x64' -MintHwe 'None'
            $script:order[0] | Should -Be 'netboot.xyz.iso'
            $script:order[-1] | Should -Be $script:FileWinScpPortable
            $fedora = [array]::IndexOf($script:order, 'Fedora-Workstation-Live-45-1.4.x86_64.iso')
            $pythonEmbed = [array]::IndexOf($script:order, $script:FilePythonEmbed)
            $pythonInstaller = [array]::IndexOf($script:order, $script:FilePythonInstaller)
            $winScp = [array]::IndexOf($script:order, $script:FileWinScpPortable)
            $sevenZip = [array]::IndexOf($script:order, $script:FileSevenZipInstaller)
            $putty = [array]::IndexOf($script:order, $script:FilePuttyZip)
            $cyberduck = [array]::IndexOf($script:order, $script:FileCyberduckInstaller)
            $duck = [array]::IndexOf($script:order, $script:FileCyberduckDuck)
            $duckRpm = [array]::IndexOf($script:order, $script:FileCyberduckDuckRpm)
            $tabbyDeb = [array]::IndexOf($script:order, $script:FileTabbyDeb)
            $tabbyRpm = [array]::IndexOf($script:order, $script:FileTabbyRpm)
            $tabbyZip = [array]::IndexOf($script:order, $script:FileTabbyZip)
            $sevenZip | Should -BeGreaterThan $fedora
            $sevenZip | Should -BeLessThan $pythonEmbed
            $putty | Should -BeGreaterThan $fedora
            $putty | Should -BeLessThan $pythonEmbed
            $cyberduck | Should -BeGreaterThan $fedora
            $cyberduck | Should -BeLessThan $pythonEmbed
            $duck | Should -BeGreaterThan $cyberduck
            $duck | Should -BeLessThan $pythonEmbed
            $duckRpm | Should -BeGreaterThan $duck
            $duckRpm | Should -BeLessThan $pythonEmbed
            $pythonEmbed | Should -BeGreaterThan $fedora
            $pythonInstaller | Should -BeGreaterThan $pythonEmbed
            $tabbyDeb | Should -BeGreaterThan $pythonInstaller
            $tabbyRpm | Should -BeGreaterThan $tabbyDeb
            $tabbyZip | Should -BeGreaterThan $tabbyRpm
            $tabbyZip | Should -BeLessThan $winScp
            $winScp | Should -BeGreaterThan $pythonInstaller
        }
    }

    Context '7zip tools' {
        It 'pins the installer and both portable artifacts' {
            $rows = @(Get-RecoveryCatalog | Where-Object { $_.Category -eq '04-etc\7zip' })
            $rows.Count | Should -Be 3
            foreach ($row in $rows) {
                $row.HashKind | Should -Be 'Pinned'
                $row.Hash | Should -Match '^[0-9a-f]{64}$'
                $row.Url | Should -Match '^https://github\.com/ip7z/7zip/releases/download/26\.06/'
                $row.SidecarName | Should -BeNullOrEmpty
            }
            $rows.FileName | Should -Contain $script:FileSevenZipInstaller
            $rows.FileName | Should -Contain $script:FileSevenZipExtra
            $rows.FileName | Should -Contain $script:FileSevenZipBootstrap
            $installer = @($rows | Where-Object { $_.FileName -eq $script:FileSevenZipInstaller })
            $installer[0].AlternateUrl | Should -Be ('https://www.7-zip.org/a/' + $script:FileSevenZipInstaller)
            $bootstrap = @($rows | Where-Object { $_.FileName -eq $script:FileSevenZipBootstrap })
            $bootstrap[0].Url.Split('/')[-1] | Should -Be '7zr.exe'
            $bootstrap[0].FileName | Should -Match '^7zr-2606\.exe$'
            $bootstrap[0].Check.Contains($script:FileSevenZipBootstrap) | Should -BeTrue
            @($rows | Where-Object { $_.FileName -ne $script:FileSevenZipInstaller } | Where-Object { $_.AlternateUrl }) | Should -HaveCount 0
        }

        It 'builds the topic readme from the catalog file names' {
            $text = Get-SevenZipReadmeText -RunStartedUtc '2026-11-16 00:00 UTC' -WrittenUtc '2026-11-16 00:00 UTC'
            foreach ($row in (Get-RecoveryCatalog | Where-Object { $_.Category -eq '04-etc\7zip' })) {
                $text.Contains($row.FileName) | Should -BeTrue
            }
            $text | Should -Match 'start "" /wait'
            $text | Should -Match 'NotSigned, which is expected'
            $text | Should -Match '7zr'
            $text | Should -Match 'no RAR, no ISO'
            $text.Contains('"-o$env:TEMP\7za"') | Should -BeTrue
            $text.Contains('"-o%TEMP%\7za"') | Should -BeTrue
            $text.Contains('$env:ProgramFiles\7-Zip\Uninstall.exe') | Should -BeTrue
            $text | Should -Match 'LGPL-2\.1-or-later'
            $text | Should -Match 'winget install --id 7zip\.7zip'
        }
    }

    Context 'putty tools' {
        It 'pins the portable bundle and its official checksum file' {
            $row = @(Get-RecoveryCatalog | Where-Object { $_.Category -eq '04-etc\putty' })
            $row.Count | Should -Be 1
            $row[0].HashKind | Should -Be 'Pinned'
            $row[0].Hash | Should -Match '^[0-9a-f]{64}$'
            $row[0].Url | Should -Match '^https://the\.earth\.li/~sgtatham/putty/0\.85/w64/putty\.zip$'
            $row[0].FileName | Should -Be 'putty-0.85.zip'
            $row[0].SidecarUrl | Should -Match '/0\.85/sha256sums$'
            $row[0].SidecarName | Should -Be $script:FilePuttySums
        }

        It 'builds the topic readme from the catalog file names' {
            $text = Get-PuttyReadmeText -RunStartedUtc '2026-11-16 00:00 UTC' -WrittenUtc '2026-11-16 00:00 UTC'
            $text.Contains($script:FilePuttyZip) | Should -BeTrue
            $text.Contains($script:FilePuttySums) | Should -BeTrue
            $text | Should -Match 'Expand-Archive'
            $text | Should -Match 'PUTTY\.EXE'
            $text | Should -Match 'PLINK\.EXE'
            $text | Should -Match 'Authenticode-valid'
            $text | Should -Match 'No install, PATH, or Start-menu changes'
            $text | Should -Match 'MIT licensed'
            $text | Should -Match '-cleanup'
            $text | Should -Match 'Get-FileHash'
            $text | Should -Match 'w64/putty\.zip'
            $text | Should -Match '%LOCALAPPDATA%\\PUTTY\.RND'
            $text | Should -Match 'Skip it if PuTTY was already in use'
            $text | Should -Match 'not staged'
        }
    }

    Context 'winscp tools' {
        It 'pins the SourceForge portable package' {
            $row = @(Get-RecoveryCatalog | Where-Object { $_.Category -eq '04-etc\winscp' })
            $row.Count | Should -Be 1
            $row[0].HashKind | Should -Be 'Pinned'
            $row[0].Hash | Should -Match '^[0-9a-f]{64}$'
            $row[0].Url | Should -Be ('https://sourceforge.net/projects/winscp/files/WinSCP/6.7.1/WinSCP-6.7.1-Portable.zip/download')
            $row[0].FileName | Should -Be 'WinSCP-6.7.1-Portable.zip'
            $row[0].SidecarName | Should -BeNullOrEmpty
        }

        It 'builds the topic readme with the portable and scripting steps' {
            $text = Get-WinScpReadmeText -RunStartedUtc '2026-11-16 00:00 UTC' -WrittenUtc '2026-11-16 00:00 UTC'
            $text.Contains($script:FileWinScpPortable) | Should -BeTrue
            $text | Should -Match 'Expand-Archive'
            $text | Should -Match 'Set-Content \.\\bin\\WinSCP\.ini'
            $text | Should -Match '/script=job\.txt'
            $text | Should -Match '/ini=nul'
            $text | Should -Match '\[Configuration\\Interface\]'
            $text | Should -Match 'RandomSeedFile=%WINSCP_PATH%\\winscp\.rnd'
            $text | Should -Match 'DDTemporaryDirectory=%WINSCP_PATH%\\temp\\'
            $text | Should -Match '%TEMP%\\winscp\.log'
            $text | Should -Match 'delete it after'
            $text | Should -Match 'Tools > Clean Up'
            $text | Should -Match 'Tools > Import Sites'
            $text | Should -Match 'Integration > Applications > PuTTY/Terminal Client Path'
            $text | Should -Match '%WINSCP_PATH%\\\.\.\\\.\.\\putty\\bin\\PUTTY\.EXE'
            $text | Should -Match 'GPLv3'
        }

        It 'writes the portable settings before the first launch' {
            $text = Get-WinScpReadmeText -RunStartedUtc '2026-11-16 00:00 UTC' -WrittenUtc '2026-11-16 00:00 UTC'
            $settings = $text.IndexOf('RandomSeedFile=%WINSCP_PATH%')
            $launch = $text.IndexOf('.\bin\WinSCP.exe')
            $settings | Should -BeGreaterThan -1
            $launch | Should -BeGreaterThan -1
            $settings | Should -BeLessThan $launch
        }
    }

    Context 'cyberduck tools' {
        It 'pins the Windows installer and both Linux CLI packages' {
            $rows = @(Get-RecoveryCatalog | Where-Object { $_.Category -eq '04-etc\cyberduck' })
            $rows.Count | Should -Be 3
            $win = @($rows | Where-Object { $_.FileName -eq $script:FileCyberduckInstaller })[0]
            $deb = @($rows | Where-Object { $_.FileName -eq $script:FileCyberduckDuck })[0]
            $rpm = @($rows | Where-Object { $_.FileName -eq $script:FileCyberduckDuckRpm })[0]
            $win.HashKind | Should -Be 'Pinned'
            $win.Hash | Should -Be '9a66f8fb400feaa5f7f390f9e4100e873f6be06cbf7c61f1651fca8b1f31c930'
            $win.Url | Should -Be ('https://update.cyberduck.io/windows/' + $script:FileCyberduckInstaller)
            $win.AlternateUrl | Should -Match 'github\.com/iterate-ch/cyberduck/releases/download/release-9-6-0/'
            $win.Released | Should -Match 'iterate GmbH'
            $deb.HashKind | Should -Be 'Pinned'
            $deb.Hash | Should -Be 'b76f3fefdd0756b08e7e3015f46273a73f5cf78bc9f0d83c7d0d6e7e90ea6ca6'
            $deb.Url | Should -Be ('https://github.com/iterate-ch/cyberduck/releases/download/release-9-6-0/' + $script:FileCyberduckDuck)
            $rpm.HashKind | Should -Be 'Pinned'
            $rpm.Hash | Should -Be '7731551675755846ec1a502ca2a2cf2a697e30026afe80c29f43ec9e8e090c6d'
            $rpm.Url | Should -Be ('https://github.com/iterate-ch/cyberduck/releases/download/release-9-6-0/' + $script:FileCyberduckDuckRpm)
            $rpm.Url | Should -Not -Be $deb.Url
        }

        It 'builds the topic readme with the install and integrity steps' {
            $text = Get-CyberduckReadmeText -RunStartedUtc '2026-11-16 00:00 UTC' -WrittenUtc '2026-11-16 00:00 UTC'
            $text.Contains($script:FileCyberduckInstaller) | Should -BeTrue
            $text | Should -Match '\.exe /s'
            $text | Should -Match 'Get-FileHash'
            $text | Should -Match 'Get-AuthenticodeSignature'
            $text | Should -Match 'iterate GmbH'
            $text | Should -Match 'no portable Windows build'
            $text.Contains($script:FileCyberduckDuck) | Should -BeTrue
            $text.Contains($script:FileCyberduckDuckRpm) | Should -BeTrue
            $text | Should -Match 'LINUX CLI'
            $text | Should -Match 'apt install'
            $text | Should -Match "dnf install --disablerepo='\*'"
            $text | Should -Match 'If dnf is unavailable or fails'
            $text | Should -Match 'rpm -ivh'
            $text | Should -Match 'mktemp -d "\$HOME/duck\.XXXXXX"'
            $text | Should -Match 'data\.tar\.\*'
            $text | Should -Match 'sha256sum'
            $text | Should -Match 'opt/duck/bin/duck'
            $text | Should -Match 'own Java runtime'
            $text | Should -Not -Match 'CYBER(INSTALLER|DEB|RPM|PAGE)'
            $text.Contains($script:CyberduckDownloadPage) | Should -BeTrue
            $text | Should -Not -Match 'runs on macOS and Linux'
            $text | Should -Match 'GPLv3'
        }
    }

    Context 'tabby tools' {
        It 'pins the portable zip and both Linux packages' {
            $rows = @(Get-RecoveryCatalog | Where-Object { $_.Category -eq '04-etc\tabby' })
            $rows.Count | Should -Be 3
            $zip = @($rows | Where-Object { $_.FileName -eq $script:FileTabbyZip })[0]
            $deb = @($rows | Where-Object { $_.FileName -eq $script:FileTabbyDeb })[0]
            $rpm = @($rows | Where-Object { $_.FileName -eq $script:FileTabbyRpm })[0]
            $zip.HashKind | Should -Be 'Pinned'
            $zip.Hash | Should -Be '56de045fbb5a74d586903367d3f7227276d538281b0068d8132de3318cdd5019'
            $zip.Url | Should -Be ('https://github.com/Eugeny/tabby/releases/download/v1.0.238/' + $script:FileTabbyZip)
            $zip.Released | Should -Match 'Eugen Pankov Softwareentwicklung'
            $deb.HashKind | Should -Be 'Pinned'
            $deb.Hash | Should -Be '5ea2b9aa84f2b5cdcb98cb7e94bd3d92de48c96254a98b52bf2d1f30a52d1d1c'
            $deb.Url | Should -Be ('https://github.com/Eugeny/tabby/releases/download/v1.0.238/' + $script:FileTabbyDeb)
            $rpm.HashKind | Should -Be 'Pinned'
            $rpm.Hash | Should -Be 'd5027a5f905edf40aaf1fd42ef5015abfaffbd96f5825b3622ef352dfc3136b3'
            $rpm.Url | Should -Be ('https://github.com/Eugeny/tabby/releases/download/v1.0.238/' + $script:FileTabbyRpm)
            foreach ($row in $rows) { $row.Check | Should -Match 'GitHub release asset digest' }
        }

        It 'builds the topic readme with portable and Linux steps' {
            $text = Get-TabbyReadmeText -RunStartedUtc '2026-11-16 00:00 UTC' -WrittenUtc '2026-11-16 00:00 UTC'
            $text.Contains($script:FileTabbyZip) | Should -BeTrue
            $text.Contains($script:FileTabbyDeb) | Should -BeTrue
            $text.Contains($script:FileTabbyRpm) | Should -BeTrue
            $text | Should -Match 'Expand-Archive'
            $text.Contains('New-Item .\bin\data -ItemType Directory') | Should -BeTrue
            $text | Should -Match 'Windows Credential Manager'
            $text | Should -Match 'delete data before handing'
            $text.Contains('sudo apt install ./' + $script:FileTabbyDeb) | Should -BeTrue
            $text.Contains('sudo dnf install --disablerepo=''*'' ./' + $script:FileTabbyRpm) | Should -BeTrue
            $text.Contains('sudo rpm -ivh ./' + $script:FileTabbyRpm) | Should -BeTrue
            $text | Should -Match '--no-sandbox'
            $text | Should -Match 'SFTP panel'
            $text | Should -Match 'Zmodem works in SSH, telnet,\s+and serial tabs'
            $text | Should -Match 'scripted\s+transfer \(PuTTY''s pscp/psftp, WinSCP\.com\)'
            $text | Should -Match 'puttygen and\s+Pageant'
            $text | Should -Not -Match 'for file transfer and keys'
            $text | Should -Match 'libgbm1'
            $text | Should -Match 'libasound2t64'
            $text | Should -Match 'libgtk-3-0t64'
            $text | Should -Match 'Debian 12 / Ubuntu 22\.04 and older use libasound2 and libgtk-3-0\.'
            $text | Should -Match 'mesa-libgbm'
            $text | Should -Match 'sha256sum'
            $text | Should -Match 'Get-AuthenticodeSignature'
            $text | Should -Match 'Eugen Pankov Softwareentwicklung'
            $text | Should -Match 'Linux packages are\s+unsigned'
            $text | Should -Match 'setup \.exe is not stored'
            $text | Should -MatchExactly '\bMIT licensed\b'
            $text | Should -Match 'tar\.gz and AppImage builds are not stored'
            $text | Should -Not -Match 'TABBY(ZIP|DEB|RPM)'
        }

        It 'creates the portable data folder before the first launch' {
            $text = Get-TabbyReadmeText -RunStartedUtc '2026-11-16 00:00 UTC' -WrittenUtc '2026-11-16 00:00 UTC'
            $data = $text.IndexOf('New-Item .\bin\data -ItemType Directory')
            $launch = $text.IndexOf('.\bin\Tabby.exe')
            $data | Should -BeGreaterThan -1
            $launch | Should -BeGreaterThan -1
            $data | Should -BeLessThan $launch
        }
    }

    Context 'imgburn portable' {
        BeforeAll {
            # Builds a payload fixture whose real hashes stand in for the vendor
            # files, so the flow runs without the 2.6 MB download.
            function New-ImgBurnFixture([string]$BinDir) {
                $payload = [ordered]@{}
                foreach ($name in @('ImgBurn.exe', 'ImgBurnPreview.exe', 'ReadMe.txt', 'Sounds\Error.wav', 'Sounds\Success.wav')) {
                    $path = Join-Path $BinDir $name
                    $parent = Split-Path -Parent $path
                    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
                    Set-Content -LiteralPath $path -Value $name -NoNewline
                    $payload[$name] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
                }
                return $payload
            }

            # Returns the ImgBurn bin folder under a test root.
            function Get-ImgBurnBin([string]$Root) {
                return (Join-Path (Join-Path (Join-Path (Join-Path $Root 'isos') '04-etc') $script:DirImgBurn) 'bin')
            }
        }

        It 'pins the installer and all five payload files' {
            $script:ImgBurnInstallerSha256 | Should -Match '^[0-9a-f]{64}$'
            $script:ImgBurnPayload.Count | Should -Be 5
            foreach ($hash in $script:ImgBurnPayload.Values) { $hash | Should -Match '^[0-9a-f]{64}$' }
            $script:ImgBurnUrl | Should -Be ('https://download.imgburn.com/' + $script:FileImgBurnInstaller)
        }

        It 'skips when every payload hash matches' {
            Reset-State
            $root = Join-Path $TestDrive 'ib-skip'
            $bin = Get-ImgBurnBin $root
            New-Item -ItemType Directory -Path $bin -Force | Out-Null
            $payload = New-ImgBurnFixture $bin
            Mock Invoke-FileDownload { throw 'MUTATION: download attempted' }
            Mock Save-VerifiedFile { throw 'MUTATION: download attempted' }
            Mock Find-SevenZipExe { throw 'MUTATION: extractor lookup attempted' }
            Install-ImgBurnPortable -Root $root -Payload $payload | Should -BeTrue
            $script:Results[-1].Status | Should -Be 'Skipped'
            $script:VerifiedHashes[(Join-Path $bin 'ImgBurn.exe')] | Should -Be $payload['ImgBurn.exe']
            Test-Path -LiteralPath (Join-Path $root 'isos\04-etc\imgburn\ImgBurn Portable.cmd') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $bin 'ImgBurn.ini') | Should -BeTrue
        }

        It 'keeps an existing settings file byte-for-byte' {
            Reset-State
            $root = Join-Path $TestDrive 'ib-ini'
            $bin = Get-ImgBurnBin $root
            New-Item -ItemType Directory -Path $bin -Force | Out-Null
            $payload = New-ImgBurnFixture $bin
            $ini = Join-Path $bin 'ImgBurn.ini'
            Set-Content -LiteralPath $ini -Value 'keep-me' -NoNewline
            Install-ImgBurnPortable -Root $root -Payload $payload | Should -BeTrue
            [IO.File]::ReadAllText($ini) | Should -Be 'keep-me'
        }

        It 'removes an orphaned stage on a skip run' {
            Reset-State
            $root = Join-Path $TestDrive 'ib-orphan'
            $bin = Get-ImgBurnBin $root
            New-Item -ItemType Directory -Path $bin -Force | Out-Null
            $payload = New-ImgBurnFixture $bin
            $stage = Join-Path $root 'tools\imgburn\_stage'
            New-Item -ItemType Directory -Path $stage -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $stage 'leftover.dll') -Value 'x' -NoNewline
            Install-ImgBurnPortable -Root $root -Payload $payload | Should -BeTrue
            Test-Path -LiteralPath $stage | Should -BeFalse
        }

        It 'extracts, verifies, and moves only the allowlisted payload' {
            Reset-State
            $root = Join-Path $TestDrive 'ib-install'
            $bin = Get-ImgBurnBin $root
            $fixture = Join-Path $TestDrive 'ib-payload'
            New-Item -ItemType Directory -Path $fixture -Force | Out-Null
            $payload = New-ImgBurnFixture $fixture
            Set-Content -LiteralPath (Join-Path $fixture 'uninstall.exe') -Value 'no' -NoNewline
            New-Item -ItemType Directory -Path (Join-Path $fixture '$PLUGINSDIR') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $fixture '$PLUGINSDIR\tool.dll') -Value 'no' -NoNewline
            Mock Save-VerifiedFile { Set-Content -LiteralPath $OutFile -Value 'installer' -NoNewline; return $true }
            Mock Find-SevenZipExe { 'C:\fake\7z.exe' }
            Mock Expand-NsisPayload { Copy-Item -LiteralPath $fixture -Destination $Destination -Recurse -Force; return $true }
            Install-ImgBurnPortable -Root $root -Payload $payload | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $bin 'ImgBurn.exe') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $bin 'Sounds\Success.wav') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $bin 'uninstall.exe') | Should -BeFalse
            Test-Path -LiteralPath (Join-Path $bin '$PLUGINSDIR') | Should -BeFalse
            Test-Path -LiteralPath (Join-Path $root 'tools\imgburn\SetupImgBurn_2.5.8.0.exe') | Should -BeFalse
            $launcher = Join-Path $root 'isos\04-etc\imgburn\ImgBurn Portable.cmd'
            Test-Path -LiteralPath $launcher | Should -BeTrue
            $launcherText = [IO.File]::ReadAllText($launcher)
            $launcherText | Should -Match '/PORTABLE /SETTINGS'
            $launcherText | Should -Match '%~dp0bin\\ImgBurn\.exe'
            Test-Path -LiteralPath (Join-Path $bin 'ImgBurn.ini') | Should -BeTrue
            $script:Results[-1].Status | Should -Be 'Downloaded'
        }

        It 'replaces a stale payload only after the new files verify' {
            Reset-State
            $root = Join-Path $TestDrive 'ib-stale'
            $bin = Get-ImgBurnBin $root
            New-Item -ItemType Directory -Path $bin -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $bin 'ImgBurn.exe') -Value 'stale' -NoNewline
            $fixture = Join-Path $TestDrive 'ib-stale-payload'
            New-Item -ItemType Directory -Path $fixture -Force | Out-Null
            $payload = New-ImgBurnFixture $fixture
            Mock Save-VerifiedFile { Set-Content -LiteralPath $OutFile -Value 'installer' -NoNewline; return $true }
            Mock Find-SevenZipExe { 'C:\fake\7z.exe' }
            Mock Expand-NsisPayload { Copy-Item -LiteralPath $fixture -Destination $Destination -Recurse -Force; return $true }
            Install-ImgBurnPortable -Root $root -Payload $payload | Should -BeTrue
            (Get-FileHash -LiteralPath (Join-Path $bin 'ImgBurn.exe') -Algorithm SHA256).Hash.ToLowerInvariant() | Should -Be $payload['ImgBurn.exe']
        }

        It 'records one failure and keeps the installer when no extractor exists' {
            Reset-State
            $root = Join-Path $TestDrive 'ib-no7z'
            Mock Save-VerifiedFile { Set-Content -LiteralPath $OutFile -Value 'installer' -NoNewline; return $true }
            Mock Find-SevenZipExe { '' }
            Mock Expand-NsisPayload { throw 'MUTATION: extraction attempted' }
            Install-ImgBurnPortable -Root $root | Should -BeFalse
            $script:Failures | Should -HaveCount 1
            $script:Failures[0].Manual | Should -Match '7-Zip'
            Test-Path -LiteralPath (Join-Path $root 'tools\imgburn\SetupImgBurn_2.5.8.0.exe') | Should -BeTrue
        }

        It 'records a failure when extraction fails' {
            Reset-State
            $root = Join-Path $TestDrive 'ib-badextract'
            Mock Save-VerifiedFile { Set-Content -LiteralPath $OutFile -Value 'installer' -NoNewline; return $true }
            Mock Find-SevenZipExe { 'C:\fake\7z.exe' }
            Mock Expand-NsisPayload { return $false }
            Install-ImgBurnPortable -Root $root | Should -BeFalse
            $script:Failures | Should -HaveCount 1
        }

        It 'rejects a payload file whose hash differs from the pin' {
            Reset-State
            $root = Join-Path $TestDrive 'ib-badhash'
            $fixture = Join-Path $TestDrive 'ib-badhash-payload'
            New-Item -ItemType Directory -Path $fixture -Force | Out-Null
            $payload = New-ImgBurnFixture $fixture
            Set-Content -LiteralPath (Join-Path $fixture 'ReadMe.txt') -Value 'tampered' -NoNewline
            Mock Save-VerifiedFile { Set-Content -LiteralPath $OutFile -Value 'installer' -NoNewline; return $true }
            Mock Find-SevenZipExe { 'C:\fake\7z.exe' }
            Mock Expand-NsisPayload { Copy-Item -LiteralPath $fixture -Destination $Destination -Recurse -Force; return $true }
            Install-ImgBurnPortable -Root $root -Payload $payload | Should -BeFalse
            Test-Path -LiteralPath (Join-Path (Get-ImgBurnBin $root) 'ImgBurn.exe') | Should -BeFalse
        }

        It 'writes nothing and records nothing under -WhatIf' {
            Reset-State
            $root = Join-Path $TestDrive 'ib-whatif'
            Mock Save-VerifiedFile { throw 'MUTATION: download attempted' }
            Mock Find-SevenZipExe { throw 'MUTATION: extractor lookup attempted' }
            Mock Expand-NsisPayload { throw 'MUTATION: extraction attempted' }
            Install-ImgBurnPortable -Root $root -WhatIf | Should -BeTrue
            Test-Path -LiteralPath $root | Should -BeFalse
            $script:Results.Count | Should -Be 0
            $script:Failures.Count | Should -Be 0
        }

        It 'bootstraps 7z.exe from the pinned 7-Zip files' {
            $root = Join-Path $TestDrive 'ib-bootstrap'
            $zipDir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') $script:DirSevenZip
            New-Item -ItemType Directory -Path $zipDir -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $zipDir $script:FileSevenZipBootstrap) -Value 'zr' -NoNewline
            Set-Content -LiteralPath (Join-Path $zipDir $script:FileSevenZipInstaller) -Value 'zi' -NoNewline
            $bootstrap = Join-Path (Join-Path (Join-Path $root 'tools') 'imgburn') '7z'
            Mock Invoke-Cli {
                New-Item -ItemType Directory -Path $bootstrap -Force | Out-Null
                Set-Content -LiteralPath (Join-Path $bootstrap '7z.exe') -Value '7z' -NoNewline
                Set-Content -LiteralPath (Join-Path $bootstrap '7z.dll') -Value 'dll' -NoNewline
                [pscustomobject]@{ ExitCode = 0; StdOut = ''; StdErr = '' }
            }
            Find-SevenZipExe -Root $root | Should -Be (Join-Path $bootstrap '7z.exe')
        }

        It 'falls back to a host 7z.exe when the pinned files are absent' {
            $root = Join-Path $TestDrive 'ib-host7z'
            Mock Get-Command { [pscustomobject]@{ Source = 'C:\host\7z.exe' } } -ParameterFilter { $Name -eq '7z.exe' }
            Find-SevenZipExe -Root $root | Should -Be 'C:\host\7z.exe'
        }

        It 'treats a non-zero 7z exit as an extraction failure' {
            Mock Invoke-Cli { [pscustomobject]@{ ExitCode = 1; StdOut = ''; StdErr = 'warning' } }
            Expand-NsisPayload -SevenZip '7z.exe' -Installer 'setup.exe' -Destination $TestDrive | Should -BeFalse
        }

        It 'documents the portable launcher, switches, and trust boundary' {
            $text = Get-ImgBurnReadmeText -RunStartedUtc '2026-11-16 00:00 UTC' -WrittenUtc '2026-11-16 00:00 UTC'
            $text.Contains($script:FileImgBurnLauncher) | Should -BeTrue
            $text.Contains($script:FileImgBurnExe) | Should -BeTrue
            $text.Contains($script:FileImgBurnIni) | Should -BeTrue
            $text.Contains($script:ImgBurnPayload[$script:FileImgBurnExe]) | Should -BeTrue
            $text | Should -Match '/PORTABLE /SETTINGS'
            $text | Should -Match 'OpenCandy'
            $text | Should -Match 'isoburn\.exe'
            $text | Should -Match 'NotSigned'
            $text | Should -Not -Match '\{IB'
        }
    }

    Context 'firefox esr' {
        It 'pins a valid fallback and Mozilla endpoints' {
            $script:FirefoxFallbackVersion | Should -Match '^\d+\.\d+(\.\d+)?esr$'
            $script:FirefoxFallbackSha256 | Should -Match '^[0-9a-f]{64}$'
            $script:FirefoxVersionsUrl | Should -Be 'https://product-details.mozilla.org/1.0/firefox_versions.json'
            $script:FirefoxReleasesUrl | Should -Be 'https://ftp.mozilla.org/pub/firefox/releases/'
        }

        It 'resolves FIREFOX_ESR live and builds the win64 en-US URL' {
            Mock Invoke-RestMethod { [pscustomobject]@{ FIREFOX_ESR = '153.8.0esr' } }
            $release = Get-FirefoxEsrRelease
            $release.Source | Should -Be 'live'
            $release.Version | Should -Be '153.8.0esr'
            $release.FileName | Should -Be 'Firefox Setup 153.8.0esr.exe'
            $release.Url | Should -Be 'https://ftp.mozilla.org/pub/firefox/releases/153.8.0esr/win64/en-US/Firefox%20Setup%20153.8.0esr.exe'
            $release.ChecksumUrl | Should -Be 'https://ftp.mozilla.org/pub/firefox/releases/153.8.0esr/SHA256SUMS'
            $release.ChecksumPath | Should -Be 'win64/en-US/Firefox Setup 153.8.0esr.exe'
        }

        It 'falls back to the pinned release when metadata fails' {
            Mock Invoke-RestMethod { throw 'offline' }
            $release = Get-FirefoxEsrRelease
            $release.Source | Should -Be 'fallback'
            $release.Version | Should -Be $script:FirefoxFallbackVersion
            $release.FallbackHash | Should -Be $script:FirefoxFallbackSha256
            $release.Url | Should -Match '153\.7\.0esr/win64/en-US/Firefox%20Setup%20153\.7\.0esr\.exe$'
            $release.ChecksumPath | Should -Be 'win64/en-US/Firefox Setup 153.7.0esr.exe'
        }

        It 'accepts a two-component FIREFOX_ESR version' {
            Mock Invoke-RestMethod { [pscustomobject]@{ FIREFOX_ESR = '165.0esr' } }
            $release = Get-FirefoxEsrRelease
            $release.Source | Should -Be 'live'
            $release.FileName | Should -Be 'Firefox Setup 165.0esr.exe'
            $release.Url | Should -Be 'https://ftp.mozilla.org/pub/firefox/releases/165.0esr/win64/en-US/Firefox%20Setup%20165.0esr.exe'
        }

        It 'falls back when FIREFOX_ESR is malformed' {
            Mock Invoke-RestMethod { [pscustomobject]@{ FIREFOX_ESR = '153.8' } }
            (Get-FirefoxEsrRelease).Source | Should -Be 'fallback'
        }

        It 'falls back when FIREFOX_ESR is missing' {
            Mock Invoke-RestMethod { [pscustomobject]@{} }
            (Get-FirefoxEsrRelease).Source | Should -Be 'fallback'
        }

        It 'extracts the live installer hash from SHA256SUMS' {
            $script:liveHash = 'ab' * 32
            Mock Invoke-WebText { "$script:liveHash  win64/en-US/Firefox Setup 153.8.0esr.exe" }
            Get-FirefoxEsrHash -ChecksumUrl 'https://example.invalid/SHA256SUMS' -ChecksumPath 'win64/en-US/Firefox Setup 153.8.0esr.exe' | Should -Be $script:liveHash
        }

        It 'downloads the live ESR and records the verified release' {
            Reset-State
            $root = Join-Path $TestDrive 'firefox-live'
            $script:liveHash = 'cd' * 32
            Mock Invoke-RestMethod { [pscustomobject]@{ FIREFOX_ESR = '153.8.0esr' } }
            Mock Invoke-WebText { "$script:liveHash  win64/en-US/Firefox Setup 153.8.0esr.exe" }
            (Get-FirefoxEsrHash -ChecksumUrl 'https://example.invalid/SHA256SUMS' -ChecksumPath 'win64/en-US/Firefox Setup 153.8.0esr.exe') | Should -Be $script:liveHash
            Mock Save-VerifiedFile { Set-Content -LiteralPath $OutFile -Value 'firefox' -NoNewline; return $true }
            Save-FirefoxEsr -Root $root | Should -BeTrue
            Should -Invoke -CommandName Save-VerifiedFile -Times 1 -Exactly -ParameterFilter {
                $ExpectedHash -eq $script:liveHash -and $Url -like '*153.8.0esr/win64/en-US/*'
            }
            $script:FirefoxRelease.Version | Should -Be '153.8.0esr'
            $script:FirefoxRelease.Source | Should -Be 'live'
            $script:FirefoxRelease.Hash | Should -Be $script:liveHash
            Test-Path -LiteralPath $script:FirefoxRelease.OutFile | Should -BeTrue
            $script:VerifiedHashes[$script:FirefoxRelease.OutFile] | Should -Be $script:liveHash
            $script:Failures.Count | Should -Be 0
        }

        It 'uses the pinned fallback when the checksum entry is missing' {
            Reset-State
            $root = Join-Path $TestDrive 'firefox-nosum'
            Mock Invoke-RestMethod { [pscustomobject]@{ FIREFOX_ESR = '153.8.0esr' } }
            Mock Invoke-WebText { 'deadbeef  win64/en-US/other.exe' }
            Mock Save-VerifiedFile { Set-Content -LiteralPath $OutFile -Value 'firefox' -NoNewline; return $true }
            Save-FirefoxEsr -Root $root | Should -BeTrue
            Should -Invoke -CommandName Save-VerifiedFile -Times 1 -Exactly -ParameterFilter {
                $ExpectedHash -eq $script:FirefoxFallbackSha256 -and $Url -like '*153.7.0esr/win64/en-US/*'
            }
            $script:FirefoxRelease.Source | Should -Be 'fallback'
            $script:FirefoxRelease.Version | Should -Be $script:FirefoxFallbackVersion
            $script:FirefoxRelease.Hash | Should -Be $script:FirefoxFallbackSha256
            $script:Failures.Count | Should -Be 0
        }

        It 'uses the pinned fallback when metadata is unavailable' {
            Reset-State
            $root = Join-Path $TestDrive 'firefox-meta'
            Mock Invoke-RestMethod { throw 'offline' }
            Mock Save-VerifiedFile { Set-Content -LiteralPath $OutFile -Value 'firefox' -NoNewline; return $true }
            Save-FirefoxEsr -Root $root | Should -BeTrue
            Should -Invoke -CommandName Save-VerifiedFile -Times 1 -Exactly -ParameterFilter {
                $ExpectedHash -eq $script:FirefoxFallbackSha256 -and $Url -like '*153.7.0esr/win64/en-US/*'
            }
            $script:FirefoxRelease.Source | Should -Be 'fallback'
            $script:FirefoxRelease.Hash | Should -Be $script:FirefoxFallbackSha256
            $script:Failures.Count | Should -Be 0
        }

        It 'falls back when the checksum list cannot be downloaded' {
            Reset-State
            $root = Join-Path $TestDrive 'firefox-nosums'
            Mock Invoke-RestMethod { [pscustomobject]@{ FIREFOX_ESR = '153.8.0esr' } }
            Mock Invoke-WebText { throw 'offline' }
            Mock Save-VerifiedFile { Set-Content -LiteralPath $OutFile -Value 'firefox' -NoNewline; return $true }
            Save-FirefoxEsr -Root $root | Should -BeTrue
            Should -Invoke -CommandName Save-VerifiedFile -Times 1 -Exactly -ParameterFilter {
                $ExpectedHash -eq $script:FirefoxFallbackSha256 -and $Url -like '*153.7.0esr/win64/en-US/*'
            }
            $script:FirefoxRelease.Source | Should -Be 'fallback'
            $script:Failures.Count | Should -Be 0
        }

        It 'leaves the release state empty when the download is not produced' {
            Reset-State
            $root = Join-Path $TestDrive 'firefox-nodownload'
            Mock Invoke-RestMethod { [pscustomobject]@{ FIREFOX_ESR = '153.8.0esr' } }
            Mock Invoke-WebText { ('ab' * 32) + '  win64/en-US/Firefox Setup 153.8.0esr.exe' }
            Mock Save-VerifiedFile { return $false }
            Save-FirefoxEsr -Root $root | Should -BeFalse
            $script:FirefoxRelease | Should -BeNullOrEmpty
            $script:VerifiedHashes.Count | Should -Be 0
            (Get-FirefoxIsosBlock -Root $root) | Should -Match 'not present'
        }

        It 'uses the exact retry text when the download engine fails' {
            Reset-State
            $root = Join-Path $TestDrive 'firefox-downloadfail'
            Mock Invoke-RestMethod { throw 'offline' }
            Mock Invoke-FileDownload { return $false }
            Save-FirefoxEsr -Root $root | Should -BeFalse
            $script:Failures | Should -HaveCount 1
            $ff = New-FirefoxFallbackRelease
            $ffOut = Join-Path (Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'firefox') $ff.FileName
            $script:Failures[0].Manual | Should -Match ([regex]::Escape($script:FirefoxFallbackSha256))
            $script:Failures[0].Manual | Should -Match ([regex]::Escape($ff.Url))
            $script:Failures[0].Manual | Should -Match ([regex]::Escape($ffOut))
            $script:Failures[0].Manual | Should -Match 'same version'
            $script:Failures[0].Manual | Should -Match 'pinned fallback'
            $script:Failures[0].Manual | Should -Not -Match 'SourceForge'
            $script:FirefoxResolved.Version | Should -Be $script:FirefoxFallbackVersion
            $script:FirefoxResolved.Source | Should -Be 'fallback'
            $script:FirefoxRelease | Should -BeNullOrEmpty
            (Get-FirefoxReadmeText -RunStartedUtc '2026-11-16 00:00 UTC' -WrittenUtc '2026-11-16 00:00 UTC') | Should -Match 'resolved but not staged'
        }

        It 'uses the exact retry text when the hash still mismatches' {
            Reset-State
            $root = Join-Path $TestDrive 'firefox-mismatch'
            Mock Invoke-RestMethod { throw 'offline' }
            Mock Invoke-FileDownload { Set-Content -LiteralPath $OutFile -Value 'not-firefox' -NoNewline; return $true }
            Save-FirefoxEsr -Root $root | Should -BeFalse
            $ff = New-FirefoxFallbackRelease
            $ffOut = Join-Path (Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'firefox') $ff.FileName
            Test-Path -LiteralPath $ffOut | Should -BeFalse
            $script:Failures | Should -HaveCount 1
            $script:Failures[0].Detail | Should -Match 'Hash mismatch after retry'
            $script:Failures[0].Manual | Should -Match ([regex]::Escape($script:FirefoxFallbackSha256))
            $script:Failures[0].Manual | Should -Match ([regex]::Escape($ff.Url))
            $script:Failures[0].Manual | Should -Not -Match 'SourceForge'
            $script:FirefoxRelease | Should -BeNullOrEmpty
            $script:FirefoxResolved.Version | Should -Be $script:FirefoxFallbackVersion
            $script:FirefoxResolved.Source | Should -Be 'fallback'
            (Get-FirefoxReadmeText -RunStartedUtc '2026-11-16 00:00 UTC' -WrittenUtc '2026-11-16 00:00 UTC') | Should -Match 'resolved but not staged'
        }

        It 'names the exact fallback file and hash when the download throws' {
            Reset-State
            $root = Join-Path $TestDrive 'firefox-throw'
            Mock Invoke-RestMethod { throw 'offline' }
            Mock Save-VerifiedFile { throw 'locked by scanner' }
            Save-FirefoxEsr -Root $root | Should -BeFalse
            $script:Failures | Should -HaveCount 1
            $script:Failures[0].Name | Should -Be 'Firefox ESR'
            $script:Failures[0].Manual | Should -Match ([regex]::Escape($script:FirefoxFallbackVersion))
            $script:Failures[0].Manual | Should -Match ([regex]::Escape($script:FirefoxFallbackSha256))
        }

        It 'does not treat a silent download success as a file' {
            Reset-State
            $root = Join-Path $TestDrive 'firefox-nofile'
            Mock Invoke-RestMethod { [pscustomobject]@{ FIREFOX_ESR = '153.8.0esr' } }
            Mock Invoke-WebText { ('ab' * 32) + '  win64/en-US/Firefox Setup 153.8.0esr.exe' }
            Mock Save-VerifiedFile { return $true }
            Save-FirefoxEsr -Root $root | Should -BeFalse
            $script:Failures.Name | Should -Contain 'Firefox ESR'
        }

        It 'writes nothing and does not resolve under -WhatIf' {
            Reset-State
            $root = Join-Path $TestDrive 'firefox-whatif'
            Mock Invoke-RestMethod { throw 'MUTATION: metadata lookup' }
            Mock Save-VerifiedFile { throw 'MUTATION: download' }
            Save-FirefoxEsr -Root $root -WhatIf | Should -BeTrue
            Test-Path -LiteralPath $root | Should -BeFalse
            $script:Results.Count | Should -Be 0
            $script:Failures.Count | Should -Be 0
        }

        It 'documents install, uninstall, fallback, and integrity' {
            $text = Get-FirefoxReadmeText -RunStartedUtc '2026-11-16 00:00 UTC' -WrittenUtc '2026-11-16 00:00 UTC'
            $text | Should -Match '/S'
            $text | Should -Match 'MaintenanceService=false'
            $text | Should -Match 'StartMenuShortcut=false'
            $text | Should -Match 'cmd\.exe:'
            $text | Should -Match 'PowerShell:'
            $text | Should -Match 'start "" /wait'
            $text | Should -Match 'Start-Process -Wait'
            $text | Should -Match '\$env:ProgramFiles'
            $text | Should -Match 'Get-AuthenticodeSignature'
            $text | Should -Match 'helper\.exe" -ms'
            $text | Should -Match 'SHA256SUMS'
            $text | Should -Match 'Mozilla Corporation'
            $text | Should -Match 'Tiny11 removes Edge and WebView2'
            $text.Contains($script:FirefoxFallbackVersion) | Should -BeTrue
            $text | Should -Not -Match 'FBVER'
        }

        It 'prints the configured fallback version in the plan table' {
            $script:planLines = @()
            Mock Write-Host { $script:planLines += [string]$Object }
            Write-PlanTable
            ($script:planLines -join "`n") | Should -Match ([regex]::Escape($script:FirefoxFallbackVersion))
        }

        It 'labels a live verified release as resolved live' {
            Reset-State
            $root = Join-Path $TestDrive 'ff-block-live'
            $dir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'firefox'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $file = Join-Path $dir 'Firefox Setup 153.8.0esr.exe'
            Set-Content -LiteralPath $file -Value 'firefox' -NoNewline
            $hash = 'ab' * 32
            $script:FirefoxRelease = [pscustomobject]@{
                Version = '153.8.0esr'
                FileName = 'Firefox Setup 153.8.0esr.exe'
                Url = 'https://example.invalid/firefox.exe'
                Hash = $hash
                Source = 'live'
                OutFile = $file
            }
            $script:VerifiedHashes[$file] = $hash
            $block = Get-FirefoxIsosBlock -Root $root
            $block | Should -Match 'resolved live'
            $block | Should -Not -Match 'pinned fallback'
            $block | Should -Match 'SHA-256 \(verified this run\)'
        }

        It 'lists a leftover installer next to the verified one' {
            Reset-State
            $root = Join-Path $TestDrive 'ff-block-leftover'
            $dir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'firefox'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $verifiedFile = Join-Path $dir 'Firefox Setup 153.7.0esr.exe'
            Set-Content -LiteralPath $verifiedFile -Value 'verified' -NoNewline
            Set-Content -LiteralPath (Join-Path $dir 'Firefox Setup 153.8.0esr.exe') -Value 'leftover' -NoNewline
            $hash = 'ef' * 32
            $script:FirefoxRelease = [pscustomobject]@{
                Version = '153.7.0esr'
                FileName = 'Firefox Setup 153.7.0esr.exe'
                Url = 'https://example.invalid/firefox.exe'
                Hash = $hash
                Source = 'live'
                OutFile = $verifiedFile
            }
            $script:VerifiedHashes[$verifiedFile] = $hash
            $block = Get-FirefoxIsosBlock -Root $root
            $block | Should -Match 'Firefox Setup 153\.7\.0esr\.exe'
            $block | Should -Match 'Firefox Setup 153\.8\.0esr\.exe'
            $block | Should -Match 'other installer, not verified this run'
            $block | Should -Match 'SHA-256 \(verified this run\)'
        }

        It 'labels a fallback release as pinned fallback' {
            Reset-State
            $root = Join-Path $TestDrive 'ff-block-fallback'
            $dir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'firefox'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $file = Join-Path $dir 'Firefox Setup 153.7.0esr.exe'
            Set-Content -LiteralPath $file -Value 'firefox' -NoNewline
            $hash = 'cd' * 32
            $script:FirefoxRelease = [pscustomobject]@{
                Version = '153.7.0esr'
                FileName = 'Firefox Setup 153.7.0esr.exe'
                Url = 'https://example.invalid/firefox.exe'
                Hash = $hash
                Source = 'fallback'
                OutFile = $file
            }
            $script:VerifiedHashes[$file] = $hash
            $block = Get-FirefoxIsosBlock -Root $root
            $block | Should -Match 'pinned fallback; live lookup failed'
            $block | Should -Not -Match 'resolved live'
        }

        It 'does not list the verified file as an other installer under a relative root' {
            Reset-State
            Push-Location $TestDrive
            try {
                $root = 'ff-rel'
                $dir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'firefox'
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
                $verified = Join-Path $dir 'Firefox Setup 153.7.0esr.exe'
                Set-Content -LiteralPath $verified -Value 'verified' -NoNewline
                $hash = 'ef' * 32
                $script:FirefoxRelease = [pscustomobject]@{
                    Version = '153.7.0esr'
                    FileName = 'Firefox Setup 153.7.0esr.exe'
                    Url = 'https://example.invalid/firefox.exe'
                    Hash = $hash
                    Source = 'live'
                    OutFile = $verified
                }
                $script:VerifiedHashes[$verified] = $hash
                $block = Get-FirefoxIsosBlock -Root $root
                ([regex]::Matches($block, [regex]::Escape('Firefox Setup 153.7.0esr.exe'))).Count | Should -Be 1
                $block | Should -Not -Match 'other installer'
            } finally {
                Pop-Location
            }
        }

        It 'lists an unverified installer instead of saying not present' {
            Reset-State
            $root = Join-Path $TestDrive 'ff-block-unverified'
            $dir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'firefox'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $dir 'Firefox Setup 153.8.0esr.exe') -Value 'firefox' -NoNewline
            $block = Get-FirefoxIsosBlock -Root $root
            $block | Should -Match 'present, not verified this run'
            $block | Should -Match 'Bytes on disk'
            $block | Should -Not -Match '\(not present\)'
        }

        It 'says not present when the folder has no installer' {
            Reset-State
            $root = Join-Path $TestDrive 'ff-block-empty'
            New-Item -ItemType Directory -Path (Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'firefox') -Force | Out-Null
            (Get-FirefoxIsosBlock -Root $root) | Should -Match 'Firefox ESR \(not present\)'
        }
    }

    Context 'readme metadata' {
        It 'builds the fixed header in a stable order' {
            $h = Get-ReadmeHeader -RunStartedUtc '2026-11-16 00:00 UTC' -WrittenUtc '2026-11-16 00:01 UTC' -Package 'X' -Version '1.2' -Released 'October 2026' -Source 'https://example.invalid' -Trust 'hash'
            $h | Should -Match '^Run started: 2026-11-16 00:00 UTC'
            $h | Should -Match 'Written:     2026-11-16 00:01 UTC'
            $h | Should -Match 'Package:     X'
            $h | Should -Match 'Version:     1.2'
            $h | Should -Match 'Released:    October 2026'
            $h | Should -Match 'Source:      https://example.invalid'
            $h | Should -Match 'Trust:       hash'
            $h.Contains('Hashes:      ..\..\README.txt') | Should -BeTrue
            $h | Should -Match 'Re-runs replace this file\.'
        }

        It 'rejects an empty timestamp' {
            { Get-ReadmeHeader -RunStartedUtc '' -WrittenUtc 'x' -Package 'P' -Version '1' -Released 'd' -Source 's' -Trust 't' } | Should -Throw
        }

        It 'resolves pinned metadata for every 04-etc topic' {
            foreach ($topic in @('python', '7zip', 'putty', 'winscp', 'cyberduck', 'tabby', 'imgburn')) {
                $m = Get-TopicReadmeMeta -Topic $topic
                $m.Package | Should -Not -BeNullOrEmpty
                $m.Version | Should -Not -BeNullOrEmpty
                $m.Released | Should -Not -BeNullOrEmpty
                $m.Source | Should -Not -BeNullOrEmpty
                $m.Trust | Should -Not -BeNullOrEmpty
                $m.Released | Should -Not -Be 'see catalog'
                $m.Released | Should -Match '^[A-Za-z]+ \d{4}$|^\d{4}-\d{2}-\d{2}$'
            }
            { Get-TopicReadmeMeta -Topic 'nope' } | Should -Throw
        }

        It 'derives pinned release dates from the catalog' {
            (Get-TopicReadmeMeta -Topic 'python').Released | Should -Be 'October 2026'
            (Get-TopicReadmeMeta -Topic '7zip').Released | Should -Be 'November 2026'
            (Get-TopicReadmeMeta -Topic 'imgburn').Released | Should -Be '2013-06-16'
        }

        It 'parses published_at as string or datetime' {
            Format-ReleaseDate '2026-10-01T12:34:56Z' | Should -Be '2026-10-01'
            $utc = [datetime]::SpecifyKind([datetime]'2026-10-02T00:00:00', [DateTimeKind]::Utc)
            Format-ReleaseDate $utc | Should -Be '2026-10-02'
            Format-ReleaseDate '' | Should -Be ''
        }

        It 'builds copyparty metadata from verified rows' {
            Reset-State
            $script:CopypartyRows = @(
                [pscustomobject]@{ FileName = $script:FileCopypartySfx; Tag = 'v1.20.26'; PublishedAt = '2026-10-01' },
                [pscustomobject]@{ FileName = $script:FileCopypartyExe; Tag = 'v1.20.26'; PublishedAt = '2026-10-01' }
            )
            $m = Get-CopypartyReadmeMeta
            $m.Version | Should -Be 'v1.20.26'
            $m.Released | Should -Be '2026-10-01'
            $m.Source | Should -Be ($script:CopypartyTagUrlBase + 'v1.20.26')
            $m.Note | Should -Be ''
        }

        It 'marks a partial copyparty set' {
            Reset-State
            $script:CopypartyRows = @([pscustomobject]@{ FileName = $script:FileCopypartyExe; Tag = 'v1.20.26'; PublishedAt = '2026-10-01' })
            $m = Get-CopypartyReadmeMeta
            $m.Version | Should -Be 'v1.20.26'
            $m.Note | Should -Match ([regex]::Escape($script:FileCopypartySfx))
        }

        It 'marks an unresolved copyparty set' {
            Reset-State
            $m = Get-CopypartyReadmeMeta
            $m.Version | Should -Be 'not verified this run'
            $m.Released | Should -Be 'unknown (not verified this run)'
            $m.Note | Should -Match 'No copyparty files verified'
        }

        It 'labels staged, resolved, and unresolved Firefox states' {
            Reset-State
            $script:FirefoxRelease = [pscustomobject]@{ Version = '153.8.0esr'; Released = '2026-11-10'; Url = 'https://example.invalid/x'; Source = 'live' }
            $m = Get-FirefoxReadmeMeta
            $m.Version | Should -Be '153.8.0esr'
            $m.Released | Should -Be '2026-11-10'
            $m.Note | Should -Be ''
            $script:FirefoxRelease = $null
            $script:FirefoxResolved = [pscustomobject]@{ Version = '153.8.0esr'; Released = '2026-11-10'; Url = 'https://example.invalid/x'; Source = 'live' }
            $m = Get-FirefoxReadmeMeta
            $m.Version | Should -Be '153.8.0esr'
            $m.Note | Should -Match 'not staged'
            $m.Note | Should -Match 're-run online'
            $script:FirefoxResolved = $null
            $m = Get-FirefoxReadmeMeta
            $m.Version | Should -Be 'unresolved this run'
            $m.Released | Should -Be 'unknown (not resolved this run)'
            $m.Note | Should -Match 're-run online'
        }

        It 'uses the per-release Firefox date and tolerates its lookup failure' {
            Mock Invoke-RestMethod -ParameterFilter { $Uri -eq $script:FirefoxVersionsUrl } { [pscustomobject]@{ FIREFOX_ESR = '153.8.0esr' } }
            Mock Invoke-RestMethod -ParameterFilter { $Uri -eq $script:FirefoxJsonUrl } { [pscustomobject]@{ releases = [pscustomobject]@{ 'firefox-153.8.0esr' = [pscustomobject]@{ date = '2026-11-10' } } } }
            $release = Get-FirefoxEsrRelease
            $release.Source | Should -Be 'live'
            $release.Released | Should -Be '2026-11-10'
            Mock Invoke-RestMethod -ParameterFilter { $Uri -eq $script:FirefoxJsonUrl } { throw 'offline' }
            $release = Get-FirefoxEsrRelease
            $release.Source | Should -Be 'live'
            $release.Released | Should -Be ''
        }

        It 'formats stamps invariantly under a non-invariant culture' {
            $old = [Threading.Thread]::CurrentThread.CurrentCulture
            try {
                [Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::GetCultureInfo('th-TH')
                (Get-UtcStamp) | Should -Match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC$'
                (Get-UtcStamp).Substring(0, 4) | Should -Be ([DateTime]::UtcNow.ToString('yyyy', [Globalization.CultureInfo]::InvariantCulture))
            } finally {
                [Threading.Thread]::CurrentThread.CurrentCulture = $old
            }
        }

        It 'adds a header to every topic sheet' {
            Reset-State
            $stamp = '2026-11-16 00:00 UTC'
            $script:CopypartyRows = @([pscustomobject]@{ FileName = $script:FileCopypartySfx; Tag = 'v1.20.26'; PublishedAt = '2026-10-01' })
            $script:FirefoxRelease = [pscustomobject]@{ Version = '153.8.0esr'; Released = '2026-11-10'; Url = 'https://example.invalid/x'; Source = 'live' }
            $texts = @(
                (Get-CopypartyReadmeText -RunStartedUtc $stamp -WrittenUtc $stamp),
                (Get-PythonReadmeText -RunStartedUtc $stamp -WrittenUtc $stamp),
                (Get-SevenZipReadmeText -RunStartedUtc $stamp -WrittenUtc $stamp),
                (Get-PuttyReadmeText -RunStartedUtc $stamp -WrittenUtc $stamp),
                (Get-WinScpReadmeText -RunStartedUtc $stamp -WrittenUtc $stamp),
                (Get-CyberduckReadmeText -RunStartedUtc $stamp -WrittenUtc $stamp),
                (Get-TabbyReadmeText -RunStartedUtc $stamp -WrittenUtc $stamp),
                (Get-ImgBurnReadmeText -RunStartedUtc $stamp -WrittenUtc $stamp),
                (Get-FirefoxReadmeText -RunStartedUtc $stamp -WrittenUtc $stamp)
            )
            foreach ($t in $texts) {
                $t | Should -Match 'Run started:'
                $t | Should -Match 'Written:'
                $t | Should -Match 'Package:'
                $t | Should -Match 'Version:'
                $t | Should -Match 'Released:'
                $t | Should -Match 'Source:'
                $t | Should -Match 'Trust:'
                $t | Should -Match 'Hashes:'
                $t | Should -Not -Match '\{HEADER\}'
                if ($t -match 'see INTEGRITY') { $t | Should -Match '(?m)^INTEGRITY\r?$' }
            }
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
                    Tag = 'v1.20.26'
                    PublishedAt = '2026-10-01'
                    SizeNote = 'About 13 MB.'
                    About = 'Portable file server for Windows.'
                    Check = 'GitHub API digest.'
                })
                return $true
            }
            Mock Save-CatalogIsos { $script:VerifiedHashes[(Join-Path (Join-Path (Join-Path $root 'isos') '02-Rescue') 'HBCD_PE_x64.iso')] = ('ab' * 32) }
            Mock Install-ImgBurnPortable {
                $ibDir = Join-Path (Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'imgburn') 'bin'
                New-Item -ItemType Directory -Path $ibDir -Force | Out-Null
                $ibFile = Join-Path $ibDir $script:FileImgBurnExe
                Set-Content -LiteralPath $ibFile -Value 'imgburn' -NoNewline
                $script:VerifiedHashes[$ibFile] = $script:ImgBurnPayload[$script:FileImgBurnExe]
                return $true
            }
            Mock Save-FirefoxEsr {
                $ffDir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'firefox'
                New-Item -ItemType Directory -Path $ffDir -Force | Out-Null
                $ffName = 'Firefox Setup ' + $script:FirefoxFallbackVersion + '.exe'
                $ffFile = Join-Path $ffDir $ffName
                Set-Content -LiteralPath $ffFile -Value 'firefox' -NoNewline
                $ffHash = 'ef' * 32
                $script:VerifiedHashes[$ffFile] = $ffHash
                $script:FirefoxRelease = [pscustomobject]@{
                    Version = $script:FirefoxFallbackVersion
                    FileName = $ffName
                    Url = 'https://example.invalid/firefox.exe'
                    Hash = $ffHash
                    Source = 'fallback'
                    OutFile = $ffFile
                    Released = '2026-11-10'
                }
                $script:FirefoxResolved = $script:FirefoxRelease
                return $true
            }
            Mock Get-WindowsIsoViaFido { return $true }
            Mock Invoke-Tiny11Build { return $true }
            Invoke-PreparePcRecovery -Root $root | Should -Be 0
            $script:Failures.Count | Should -Be 0
            $rootText = [IO.File]::ReadAllText((Join-Path $root 'README.txt'))
            $rootText | Should -Match 'tiny11builder'
            $rootText | Should -Match 'en-US'
            $rootText | Should -Match 'copyparty'
            $rootText | Should -Match 'imgburn'
            $rootText | Should -Match 'firefox'
            $imgburnDir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'imgburn'
            $imgburnText = [IO.File]::ReadAllText((Join-Path $imgburnDir 'README.txt'))
            $imgburnText | Should -Match '/PORTABLE /SETTINGS'
            $imgburnText.Contains($script:ImgBurnPayload[$script:FileImgBurnExe]) | Should -BeTrue
            $imgburnText | Should -Match 'OpenCandy'
            $firefoxDir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'firefox'
            $firefoxText = [IO.File]::ReadAllText((Join-Path $firefoxDir 'README.txt'))
            $firefoxText | Should -Match '/S'
            $firefoxText | Should -Match 'SHA256SUMS'
            $firefoxText.Contains($script:FirefoxFallbackVersion) | Should -BeTrue
            $rootText | Should -Match 'python\\'
            $topicDir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'copyparty'
            $topicText = [IO.File]::ReadAllText((Join-Path $topicDir 'README.txt'))
            $topicText | Should -Match 'copyparty-sfx\.py'
            $topicText | Should -Match 'no arguments'
            $topicText | Should -Match '\-v SRC:DST:PERMS'
            $topicText.Contains("-v 'C:\data:data:r,admin'") | Should -BeTrue
            $topicText.Contains('.\copyparty.exe -p 3923') | Should -BeTrue
            $topicText.Contains('--hist "%TEMP%\copyparty"') | Should -BeTrue
            $topicText.Contains($script:FilePythonEmbed) | Should -BeTrue
            $topicText.Contains('$env:TEMP\pyembed\python.exe') | Should -BeTrue
            $topicText.Contains('-i 192.168.1.10') | Should -BeTrue
            $topicText.Contains('--hist "$env:TEMP\copyparty"') | Should -BeTrue
            $pythonDir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'python'
            $pythonText = [IO.File]::ReadAllText((Join-Path $pythonDir 'README.txt'))
            $pythonText.Contains($script:FilePythonInstaller) | Should -BeTrue
            $pythonText.Contains($script:FilePythonEmbed) | Should -BeTrue
            $pythonText | Should -Match 'start "" /wait'
            $rootText | Should -Match '7zip'
            $rootText | Should -Match 'putty'
            $sevenDir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') '7zip'
            $sevenText = [IO.File]::ReadAllText((Join-Path $sevenDir 'README.txt'))
            $sevenText.Contains($script:FileSevenZipInstaller) | Should -BeTrue
            $sevenText.Contains($script:FileSevenZipExtra) | Should -BeTrue
            $sevenText.Contains($script:FileSevenZipBootstrap) | Should -BeTrue
            $sevenText | Should -Match '/S'
            $puttyDir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'putty'
            $puttyText = [IO.File]::ReadAllText((Join-Path $puttyDir 'README.txt'))
            $puttyText.Contains($script:FilePuttyZip) | Should -BeTrue
            $puttyText.Contains($script:FilePuttySums) | Should -BeTrue
            $puttyText | Should -Match 'Expand-Archive'
            $rootText | Should -Match 'winscp'
            $rootText | Should -Match 'cyberduck'
            $rootText | Should -Match 'tabby'
            $tabbyDir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'tabby'
            $tabbyText = [IO.File]::ReadAllText((Join-Path $tabbyDir 'README.txt'))
            $tabbyText.Contains($script:FileTabbyZip) | Should -BeTrue
            $tabbyText.Contains($script:FileTabbyDeb) | Should -BeTrue
            $tabbyText.Contains($script:FileTabbyRpm) | Should -BeTrue
            $tabbyText | Should -Match 'New-Item \.\\bin\\data -ItemType Directory'
            $tabbyText | Should -Match '--no-sandbox'
            $cyberduckDir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'cyberduck'
            $cyberduckText = [IO.File]::ReadAllText((Join-Path $cyberduckDir 'README.txt'))
            $cyberduckText.Contains($script:FileCyberduckInstaller) | Should -BeTrue
            $cyberduckText | Should -Match 'no portable Windows build'
            $cyberduckText | Should -Match 'Get-AuthenticodeSignature'
            $winScpDir = Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'winscp'
            $winScpText = [IO.File]::ReadAllText((Join-Path $winScpDir 'README.txt'))
            $winScpText.Contains($script:FileWinScpPortable) | Should -BeTrue
            $winScpText | Should -Match '/script=job\.txt'
            $winScpText | Should -Match 'Tools > Clean Up'
            $isosText = [IO.File]::ReadAllText((Join-Path (Join-Path $root 'isos') 'README.txt'))
            $isosText | Should -Match 'HBCD_PE_x64.iso'
            $isosText | Should -Match 'Windows PE rescue environment'
            $isosText | Should -Match 'Unversioned URL'
            $isosText | Should -Match 'SHA-256 \(verified this run\)'
            $isosText | Should -Match 'Official Windows 11 ISO \(not present\)'
            $isosText | Should -Match 'Tiny11 ISO \(not present\)'
            $isosText | Should -Match '04-etc\\copyparty\\copyparty\.exe'
            $isosText | Should -Match '04-etc\\imgburn\\bin\\ImgBurn\.exe'
            $isosText | Should -Match '04-etc\\firefox\\Firefox Setup 153\.7\.0esr\.exe'
            $isosText | Should -Match 'pinned fallback; live lookup failed'
            $isosText | Should -Match '04-etc\\python\\python-3\.15\.2-amd64\.exe'
            $isosText | Should -Match '04-etc\\python\\python-3\.15\.2-embed-amd64\.zip'
            $isosText | Should -Match '04-etc\\7zip\\7z2606-x64\.exe'
            $isosText | Should -Match '04-etc\\7zip\\7z2606-extra\.7z'
            $isosText | Should -Match '04-etc\\7zip\\7zr-2606\.exe'
            $isosText | Should -Match '04-etc\\putty\\putty-0\.85\.zip'
            $isosText | Should -Match '04-etc\\winscp\\WinSCP-6\.7\.1-Portable\.zip'
            $isosText | Should -Match '04-etc\\cyberduck\\Cyberduck-Installer-9\.6\.0\.46406\.exe'
            $isosText | Should -Match '04-etc\\cyberduck\\duck_9\.6\.0\.46406_amd64\.deb'
            $isosText | Should -Match '04-etc\\cyberduck\\duck-9\.6\.0\.46406-1\.x86_64\.rpm'
            $isosText | Should -Match '04-etc\\tabby\\tabby-1\.0\.238-portable-x64\.zip'
            $isosText | Should -Match '04-etc\\tabby\\tabby-1\.0\.238-linux-x64\.deb'
            $isosText | Should -Match '04-etc\\tabby\\tabby-1\.0\.238-linux-x64\.rpm'
            $isosText | Should -Match 'v1\.20\.26'
            $isosText | Should -Match 'copyparty \(copyparty-sfx\.py, not verified this run\)'
            $isosText | Should -Match 'SHA-256 \(on disk at write time\)'
            $rootRun = [regex]::Match($rootText, 'Run started: (.+)').Groups[1].Value
            $isosRun = [regex]::Match($isosText, 'Run started: (.+)').Groups[1].Value
            $rootRun | Should -Not -BeNullOrEmpty
            $isosRun | Should -Be $rootRun
            $baseReadmes = @(
                (Join-Path $root 'README.txt'),
                (Join-Path (Join-Path $root 'isos') 'README.txt')
            )
            $topicReadmes = @(Get-ChildItem -LiteralPath (Join-Path (Join-Path $root 'isos') '04-etc') -Directory | ForEach-Object { Join-Path $_.FullName 'README.txt' })
            foreach ($path in @($baseReadmes + $topicReadmes)) {
                $text = [IO.File]::ReadAllText($path)
                $text | Should -Match 'Run started:'
                $text | Should -Not -Match '\{HEADER\}'
                $bytes = [IO.File]::ReadAllBytes($path)
                ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) | Should -BeFalse
                (@($bytes | Where-Object { $_ -gt 127 }).Count) | Should -Be 0
            }
            foreach ($path in $topicReadmes) {
                $text = [IO.File]::ReadAllText($path)
                $text | Should -Match 'Package:'
                $text | Should -Match 'Version:'
                $text | Should -Match 'Released:'
                $text | Should -Match 'Source:'
                $text | Should -Match 'Trust:'
                $text | Should -Match 'Hashes:'
            }
            $cpText = [IO.File]::ReadAllText((Join-Path (Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'copyparty') 'README.txt'))
            $cpText | Should -Match 'Version:\s+v1\.20\.26'
            $cpText | Should -Match 'Released:\s+2026-10-01'
            $cpText | Should -Match ('Note:\s+not verified this run: ' + [regex]::Escape($script:FileCopypartySfx))
            $ffText = [IO.File]::ReadAllText((Join-Path (Join-Path (Join-Path (Join-Path $root 'isos') '04-etc') 'firefox') 'README.txt'))
            $ffText | Should -Match ('Version:\s+' + [regex]::Escape($script:FirefoxFallbackVersion))
            $ffText | Should -Match 'Note:\s+pinned fallback; live lookup failed'
            $ffText | Should -Not -Match 'unresolved this run'
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

