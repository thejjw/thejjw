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
        $script:CurlExe = Join-Path $TestDrive 'curl.exe'
        $script:FidoUrl = 'https://example.invalid/Fido.ps1'
        $script:Tiny11MakerUrl = 'https://example.invalid/tiny11maker.ps1'
        $script:Tiny11AnswerUrl = 'https://example.invalid/autounattend.xml'
        $script:Failures = @()
        $script:Results = @()
        $script:UseSudo = $false
        # Lists only the catalog rows selected for the given switches (no downloads).
        function Select-CatalogFiles([string]$NetbootArch, [string]$MintHwe) {
            @(Get-RecoveryCatalog | Where-Object {
                (($_.NetbootVariant -eq '') -or ($_.NetbootVariant -eq $NetbootArch)) -and
                (($_.MintHwe -eq '') -or ($_.MintHwe -eq $MintHwe))
            } | Select-Object -ExpandProperty FileName)
        }

        # Resets recorded failures/results between tests.
        function Reset-State { $script:Failures = @(); $script:Results = @(); $script:UseSudo = $false }
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
            Invoke-Tiny11Build -Root $root | Should -BeFalse
            $script:Failures.Name | Should -Contain 'Tiny11 ISO'
        }
    }

    Context 'manual-entry failures' {
        It 'routes a missing Fido.ps1 to Write-Failure instead of throwing' {
            Reset-State
            $root = Join-Path $TestDrive 'nofido'
            { Get-WindowsIsoViaFido -Root $root } | Should -Not -Throw
            $script:Failures | Should -HaveCount 1
            $script:Failures[0].Manual | Should -Match 'microsoft.com'
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
            Mock Get-GitHubLatestAsset { [pscustomobject]@{ Tag = 'v9'; Name = 'b.zip'; ZipUrl = 'https://example.invalid/b.zip'; HashUrl = 'https://example.invalid/b.zip.sha256' } }
            Mock Invoke-WebText { 'ab' * 32 + '  b.zip' }
            Mock Install-Ventoy { return $true }
            Mock Save-RufusTools { return $true }
            Mock Save-CatalogIsos { }
            Mock Get-WindowsIsoViaFido { return $true }
            Mock Invoke-Tiny11Build { return $true }
            Invoke-PreparePcRecovery -Root $root | Out-Null
            $rootText = [IO.File]::ReadAllText((Join-Path $root 'README.txt'))
            $rootText | Should -Match 'tiny11builder'
            $rootText | Should -Match 'en-US'
            $isosText = [IO.File]::ReadAllText((Join-Path (Join-Path $root 'isos') 'README.txt'))
            $isosText | Should -Match 'HBCD_PE_x64.iso'
            $isosText | Should -Match 'Unversioned URL'
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
            $script:UseSudo | Should -BeFalse
        }
    }
}

