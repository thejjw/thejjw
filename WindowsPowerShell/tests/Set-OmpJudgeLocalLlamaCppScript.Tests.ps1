Describe 'Set-OmpJudgeLocalLlamaCpp.ps1 helpers' {
    BeforeAll {
        # Load only the function definitions from the util script (no execution, no exit).
        $scriptPath = Join-Path $PSScriptRoot '..\util\Set-OmpJudgeLocalLlamaCpp.ps1'
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
        if ($errors) { throw "Script contains parse errors: $($errors -join '; ')" }
        $functions = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)
        foreach ($function in $functions) { . ([scriptblock]::Create($function.Extent.Text)) }

        # Script-level constants the helpers read; all paths point into TestDrive.
        $AbortToken = 'OMP_LLAMACPP_SETUP_ABORTED'
        $MarkerStart = '# >>> omp-llamacpp-judge'
        $MarkerEnd = '# <<< omp-llamacpp-judge'
        $MinLlamaCppBuild = 11960
        $PortRangeSize = 49
        $KvBytesPerToken = 30KB
        $DiskMarginBytes = 512MB
        $ProviderId = 'llamacpp'
        $Root = Join-Path $TestDrive 'llama-cpp-tiny'
        $BinRoot = Join-Path $Root 'bin'
        $ModelsDir = Join-Path $Root 'models'

        # Builds a fake GitHub release object.
        function New-Release([string]$Tag, [string[]]$Assets, [switch]$NoDigest, [switch]$Draft, [switch]$Prerelease) {
            [pscustomobject]@{
                tag_name   = $Tag
                draft      = [bool]$Draft
                prerelease = [bool]$Prerelease
                assets     = @($Assets | ForEach-Object {
                        [pscustomobject]@{
                            name                 = $_
                            size                 = 37891857
                            browser_download_url = "https://example.invalid/$_"
                            digest               = if ($NoDigest) { $null } else { 'sha256:' + ('ab' * 32) }
                        }
                    })
            }
        }

        # Builds a resources object for the warning/requirement tests.
        function New-Resources([double]$RamTotal = 64GB, [double]$RamAvailable = 32GB, [double]$DiskFree = 200GB) {
            [pscustomobject]@{ RamTotal = $RamTotal; RamAvailable = $RamAvailable; DiskFree = $DiskFree; DriveRoot = 'C:\' }
        }
    }

    Context 'context tier' {
        It 'maps total RAM to <Expected>' -ForEach @(
            @{ Ram = 6GB; Expected = 4096 }
            @{ Ram = 8GB; Expected = 4096 }
            @{ Ram = 16GB; Expected = 8192 }
            @{ Ram = 32GB; Expected = 32768 }
            @{ Ram = 128GB; Expected = 32768 }
        ) {
            Get-ContextTier $Ram | Should -Be $Expected
        }
    }

    Context 'device probe' {
        It 'finds a real Vulkan device' {
            $probe = Get-VulkanDevices @('Available devices:', '  Vulkan0: AMD Radeon(TM) 8060S Graphics (104978 MiB, 99729 MiB free)')
            $probe.Parsed | Should -BeTrue
            $probe.Real | Should -HaveCount 1
            Select-GpuLayers 'auto' $probe | Should -Be 'all'
        }

        It 'ignores llvmpipe and falls back to CPU' {
            $probe = Get-VulkanDevices @('Available devices:', '  Vulkan0: llvmpipe (LLVM 17.0.6, 256 bits) (16384 MiB, 16384 MiB free)')
            $probe.Real | Should -HaveCount 0
            $probe.Software | Should -HaveCount 1
            Select-GpuLayers 'auto' $probe | Should -Be '0'
        }

        It 'uses CPU when only the header is printed' {
            $probe = Get-VulkanDevices @('Available devices:')
            Select-GpuLayers 'auto' $probe | Should -Be '0'
        }

        It 'fails for -Backend vulkan without a real device' {
            $probe = Get-VulkanDevices @('Available devices:')
            { Select-GpuLayers 'vulkan' $probe } | Should -Throw $AbortToken
        }

        It 'lets llama.cpp choose when the output cannot be parsed' {
            $probe = Get-VulkanDevices @('')
            $probe.Parsed | Should -BeFalse
            Select-GpuLayers 'auto' $probe 3>$null | Should -Be 'auto'
        }

        It 'always uses CPU for -Backend cpu' {
            Select-GpuLayers 'cpu' (Get-VulkanDevices @('Available devices:', '  Vulkan0: Real GPU')) | Should -Be '0'
        }
    }

    Context 'release selection' {
        It 'builds asset names for each backend and architecture' {
            Get-AssetName 'b12242' 'vulkan' 'x64' | Should -Be 'llama-b12242-bin-win-vulkan-x64.zip'
            Get-AssetName 'b12242' 'cpu' 'arm64' | Should -Be 'llama-b12242-bin-win-cpu-arm64.zip'
        }

        It 'picks the newest b#### build (prereleases allowed) and skips semver and draft entries' {
            $releases = @(
                (New-Release 'v0.9.0' @('nightly-tag.txt'))
                (New-Release 'b12244' @('llama-b12244-bin-win-vulkan-x64.zip') -Draft)
                (New-Release 'b12241' @('llama-b12241-bin-win-vulkan-x64.zip') -Prerelease)
                (New-Release 'b12242' @('llama-b12242-bin-win-vulkan-x64.zip') -Prerelease)
            )
            $asset = Select-LlamaRelease $releases 'vulkan' 'x64' 11960
            $asset.Tag | Should -Be 'b12242'
            $asset.Build | Should -Be 12242
            $asset.Sha256 | Should -Be ('ab' * 32)
        }

        It 'resolves latest through the stable release nightly-tag.txt' {
            Mock Invoke-GitHubApi {
                if ($Path -eq '/releases/latest') { New-Release 'v0.9.0' @('nightly-tag.txt') }
                elseif ($Path -eq '/releases/tags/b12110') { New-Release 'b12110' @('llama-b12110-bin-win-vulkan-x64.zip') -Prerelease }
                else { throw "unexpected $Path" }
            }
            Mock Get-WebText { 'b12110' }
            $asset = Resolve-LlamaRelease 'latest' 'vulkan' 'x64' $null 6>$null
            $asset.Tag | Should -Be 'b12110'
            $asset.Name | Should -Be 'llama-b12110-bin-win-vulkan-x64.zip'
        }

        It 'resolves nightly to the newest b#### build' {
            Mock Invoke-GitHubApi { @((New-Release 'b12242' @('llama-b12242-bin-win-cpu-x64.zip') -Prerelease)) }
            (Resolve-LlamaRelease 'nightly' 'cpu' 'x64' $null).Tag | Should -Be 'b12242'
        }

        It 'treats a malformed nightly-tag.txt as unresolvable' {
            Mock Invoke-GitHubApi { New-Release 'v0.9.0' @('nightly-tag.txt') }
            Mock Get-WebText { '<html>' }
            { Resolve-LlamaRelease 'latest' 'vulkan' 'x64' $null 6>$null } | Should -Throw $AbortToken
        }

        It 'skips the newest release while it lacks the asset or its digest' {
            $releases = @(
                (New-Release 'b12244' @('llama-b12244-bin-win-cpu-x64.zip'))
                (New-Release 'b12243' @('llama-b12243-bin-win-vulkan-x64.zip') -NoDigest)
                (New-Release 'b12242' @('llama-b12242-bin-win-vulkan-x64.zip'))
            )
            (Select-LlamaRelease $releases 'vulkan' 'x64' 11960).Tag | Should -Be 'b12242'
        }

        It 'enforces the minimum build' {
            $releases = @((New-Release 'b11000' @('llama-b11000-bin-win-vulkan-x64.zip')))
            Select-LlamaRelease $releases 'vulkan' 'x64' 11960 | Should -BeNullOrEmpty
        }

        It 'fails for an explicit tag without a digest' {
            Mock Invoke-GitHubApi { New-Release 'b12242' @('llama-b12242-bin-win-vulkan-x64.zip') -NoDigest }
            { Resolve-LlamaRelease 'b12242' 'vulkan' 'x64' $null } | Should -Throw $AbortToken
        }

        It 'rejects an explicit tag below the minimum build' {
            Mock Invoke-GitHubApi { throw 'should not be called' }
            { Resolve-LlamaRelease 'b11000' 'vulkan' 'x64' $null } | Should -Throw $AbortToken
        }

        It 'keeps the installed build when GitHub is unreachable' {
            $dir = Join-Path $BinRoot 'b12100-vulkan-x64'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $dir 'llama-server.exe') -Value ''
            Mock Invoke-GitHubApi { throw 'offline' }
            $asset = Resolve-LlamaRelease 'latest' 'vulkan' 'x64' ([pscustomobject]@{ current = 'b12100-vulkan-x64' }) 3>$null
            $asset.Tag | Should -Be 'b12100'
            $asset.Offline | Should -BeTrue
        }

        It 'fails offline without an installed build' {
            Mock Invoke-GitHubApi { throw 'offline' }
            { Resolve-LlamaRelease 'latest' 'vulkan' 'x64' $null } | Should -Throw $AbortToken
        }
    }

    Context 'Hugging Face file selection' {
        It 'returns the variant file with its size and sha256' {
            $items = @(
                [pscustomobject]@{ type = 'file'; path = 'README.md'; size = 10 }
                [pscustomobject]@{ type = 'file'; path = 'LFM3-1.7B-Q4_K_M.gguf'; size = 134; lfs = [pscustomobject]@{ oid = ('3793e1e6' * 8).ToUpper(); size = 1099627808 } }
                [pscustomobject]@{ type = 'file'; path = 'LFM3-1.7B-Q8_0.gguf'; size = 134; lfs = [pscustomobject]@{ oid = ('cd' * 32); size = 1 } }
            )
            $file = Get-HfModelFile $items 'Q4_K_M'
            $file.Path | Should -Be 'LFM3-1.7B-Q4_K_M.gguf'
            $file.Size | Should -Be 1099627808
            $file.Sha256 | Should -Be ('3793e1e6' * 8)
        }

        It 'fails when no file matches' {
            { Get-HfModelFile @([pscustomobject]@{ type = 'file'; path = 'x-Q8_0.gguf' }) 'Q4_K_M' } | Should -Throw $AbortToken
        }

        It 'fails when the file has no LFS sha256' {
            { Get-HfModelFile @([pscustomobject]@{ type = 'file'; path = 'x-Q4_K_M.gguf'; size = 5 }) 'Q4_K_M' } | Should -Throw $AbortToken
        }
    }

    Context 'model copies' {
        It 'trusts a matching sidecar without re-hashing' {
            $path = Join-Path $TestDrive 'sidecar.gguf'
            Set-Content -LiteralPath $path -Value 'model' -NoNewline
            [IO.File]::WriteAllText("$path.sha256", (Get-SidecarLine $path ('00' * 32)))
            Mock Get-FileHash { throw 'should not hash' }
            Test-FileSha256 $path ('00' * 32) 5 | Should -BeTrue
        }

        It 'hashes when there is no sidecar and rejects a size mismatch' {
            $path = Join-Path $TestDrive 'plain.gguf'
            Set-Content -LiteralPath $path -Value 'model' -NoNewline
            $sha = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            Test-FileSha256 $path $sha 5 | Should -BeTrue
            Test-FileSha256 $path $sha 6 | Should -BeFalse
        }

        It 'finds a verified copy in an HF or ModelScope cache' {
            $cache = Join-Path $TestDrive 'hub'
            $snapshot = Join-Path $cache 'modelscope--models--LiquidAI--LFM3-1.7B-GGUF\snapshots\abc'
            New-Item -ItemType Directory -Path $snapshot -Force | Out-Null
            $file = Join-Path $snapshot 'LFM3-1.7B-Q4_K_M.gguf'
            Set-Content -LiteralPath $file -Value 'weights' -NoNewline
            $sha = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
            Mock Get-HfCacheRoots { $cache }
            $copy = Find-ModelCopy 'LiquidAI/LFM3-1.7B-GGUF' 'LFM3-1.7B-Q4_K_M.gguf' $sha 7
            $copy.Path | Should -Be $file
            $copy.Source | Should -Be 'cache'
            Find-ModelCopy 'LiquidAI/LFM3-1.7B-GGUF' 'LFM3-1.7B-Q4_K_M.gguf' ('11' * 32) 7 | Should -BeNullOrEmpty
        }
    }

    Context 'port selection' {
        BeforeEach {
            $script:busy = @()
            $script:ours = @()
            Mock Test-PortFree { $Port -notin $script:busy -and $Port -notin $script:ours }
            Mock Test-OurServer { $Port -in $script:ours }
            Mock Get-PortOwner { [pscustomobject]@{ Id = 42; Name = 'other'; Path = 'C:\other.exe' } }
        }

        It 'keeps the saved port' {
            $choice = Resolve-ServerPort 9945 9941 $false
            $choice.Port | Should -Be 9945
            $choice.Skipped | Should -HaveCount 0
        }

        It 'moves to 9942 when 9941 is busy' {
            $script:busy = @(9941)
            $choice = Resolve-ServerPort 0 9941 $false
            $choice.Port | Should -Be 9942
            Format-PortChoice $choice | Should -Be '9942 (9941 held by other pid 42)'
        }

        It 'fails for a busy explicit port' {
            $script:busy = @(9941)
            { Resolve-ServerPort 0 9941 $true } | Should -Throw $AbortToken
        }

        It 'reuses a port held by our own server' {
            $script:ours = @(9941)
            $choice = Resolve-ServerPort 0 9941 $false
            $choice.Port | Should -Be 9941
            $choice.Ours | Should -BeTrue
        }

        It 'fails when the whole range is busy' {
            $script:busy = 9941..9990
            { Resolve-ServerPort 0 9941 $false } | Should -Throw $AbortToken
        }

        It 'treats only executables under bin\ as ours' {
            Test-OurProcess ([pscustomobject]@{ Path = (Join-Path $BinRoot 'b1-vulkan-x64\llama-server.exe') }) | Should -BeTrue
            Test-OurProcess ([pscustomobject]@{ Path = 'C:\tools\llama-server.exe' }) | Should -BeFalse
            Test-OurProcess $null | Should -BeFalse
        }
    }

    Context 'models.yml editing' {
        It 'formats the provider block' {
            $block = Format-ProviderBlock '  ' 'http://127.0.0.1:9941/v1' 'LFM3-1.7B' 32768
            $block[0] | Should -Match '^  # >>> omp-llamacpp-judge'
            $block | Should -Contain '  llamacpp:'
            $block | Should -Contain "    baseUrl: 'http://127.0.0.1:9941/v1'"
            $block | Should -Contain '        contextWindow: 32768'
            $block[-1] | Should -Be '  # <<< omp-llamacpp-judge'
        }

        It 'appends a providers mapping to an empty file and replaces it in place on re-run' {
            $path = Join-Path $TestDrive 'models-append.yml'
            Write-ModelsYaml (Read-ModelsYaml $path) 'http://127.0.0.1:9941/v1' 'LFM3-1.7B' 8192
            $plan = Read-ModelsYaml $path
            $plan.Mode | Should -Be 'replace'
            Write-ModelsYaml $plan 'http://127.0.0.1:9942/v1' 'LFM3-1.7B' 8192
            $text = [IO.File]::ReadAllText($path)
            ([regex]::Matches($text, 'omp-llamacpp-judge \(managed')).Count | Should -Be 1
            $text | Should -Match '9942'
        }

        It 'rewrites baseUrl inside the managed block only' {
            $path = Join-Path $TestDrive 'models-move.yml'
            $lines = @('providers:', '  other:', "    baseUrl: 'http://127.0.0.1:1/v1'") + (Format-ProviderBlock '  ' 'http://127.0.0.1:9941/v1' 'LFM3-1.7B' 8192)
            [IO.File]::WriteAllText($path, ($lines -join "`n") + "`n")
            Update-ManagedBaseUrl $path 'http://127.0.0.1:9943/v1' -NoBackup | Should -BeTrue
            $text = [IO.File]::ReadAllText($path)
            $text | Should -Match "baseUrl: 'http://127.0.0.1:1/v1'"
            $text | Should -Match "baseUrl: 'http://127.0.0.1:9943/v1'"
            $text | Should -Not -Match '9941'
        }

        It 'leaves a file without the managed block alone' {
            $path = Join-Path $TestDrive 'models-none.yml'
            [IO.File]::WriteAllText($path, "providers:`n  other:`n    baseUrl: 'x'`n")
            Update-ManagedBaseUrl $path 'http://127.0.0.1:9943/v1' -NoBackup | Should -BeFalse
            [IO.File]::ReadAllText($path) | Should -Be "providers:`n  other:`n    baseUrl: 'x'`n"
        }
    }

    Context 'requirements and warnings' {
        It 'counts zip, extracted size, model and margin' {
            $req = Get-InstallRequirement 100MB 1GB 1GB 32768
            $req.ExtractedSize | Should -Be 300MB
            $req.DiskNeeded | Should -Be (100MB + 300MB + 1GB + 512MB)
            $req.RamEstimate | Should -Be (1GB + 32768 * 30KB)
        }

        It 'needs no disk when nothing is downloaded' {
            (Get-InstallRequirement 0 0 1GB 4096).DiskNeeded | Should -Be 0
        }

        It 'estimates RAM for ctx <Ctx>' -ForEach @(
            @{ Ctx = 4096 }, @{ Ctx = 8192 }, @{ Ctx = 32768 }
        ) {
            (Get-InstallRequirement 0 0 1GB $Ctx).RamEstimate | Should -Be (1GB + $Ctx * 30KB)
        }

        It 'warns about low RAM, low available RAM and low remaining disk' {
            $req = Get-InstallRequirement 100MB 1GB 1GB 4096
            $warnings = @(Get-InstallWarnings (New-Resources -RamTotal 6GB -RamAvailable 512MB -DiskFree 6GB) $req)
            $warnings | Should -HaveCount 3
            ($warnings -join ' ') | Should -Match 'below 8 GB'
            ($warnings -join ' ') | Should -Match 'Available RAM'
            ($warnings -join ' ') | Should -Match 'Less than 5 GB'
        }

        It 'has no warnings on a roomy machine' {
            @(Get-InstallWarnings (New-Resources) (Get-InstallRequirement 100MB 1GB 1GB 32768)) | Should -HaveCount 0
        }
    }

    Context 'confirmation gate' {
        BeforeAll {
            # Calls Confirm-Install with defaults that can be overridden per test.
            function Invoke-Gate([string[]]$Warnings = @(), [bool]$Nothing = $false, [bool]$AssumeYes = $false, [bool]$CanPrompt = $true, [double]$Need = 1GB, [double]$Free = 100GB) {
                Confirm-Install $Warnings $Nothing $AssumeYes $CanPrompt $Need $Free 'C:\' 6>$null
            }
        }

        BeforeEach {
            $script:answers = New-Object System.Collections.Queue
            $script:prompts = New-Object System.Collections.Generic.List[string]
            Mock Read-Host { $script:prompts.Add($Prompt); $script:answers.Dequeue() }
            Mock Install-LlamaRelease { }
        }

        It 'defaults to yes without warnings' {
            $script:answers.Enqueue('')
            Invoke-Gate | Should -BeTrue
            $script:prompts[0] | Should -Match '\[Y/n\]'
        }

        It 'returns false for <Answer> without warnings' -ForEach @(@{ Answer = 'n' }, @{ Answer = 'NO ' }) {
            $script:answers.Enqueue($Answer)
            Invoke-Gate | Should -BeFalse
            Should -Invoke Install-LlamaRelease -Times 0
        }

        It 'defaults to no with a warning' {
            $script:answers.Enqueue('')
            Invoke-Gate -Warnings @('low RAM') | Should -BeFalse
            $script:prompts[0] | Should -Match '\[y/N\]'
            $script:prompts[0] | Should -Match '1 warning'
        }

        It 'accepts <Answer> with a warning' -ForEach @(@{ Answer = 'y' }, @{ Answer = 'Yes' }) {
            $script:answers.Enqueue($Answer)
            Invoke-Gate -Warnings @('low RAM') | Should -BeTrue
        }

        It 'asks again after invalid input' {
            $script:answers.Enqueue('maybe')
            $script:answers.Enqueue('y')
            Invoke-Gate -Warnings @('low RAM') | Should -BeTrue
            Should -Invoke Read-Host -Times 2 -Exactly
        }

        It 'skips the prompt with -Yes' {
            Invoke-Gate -AssumeYes $true -Warnings @('low RAM') | Should -BeTrue
            Should -Invoke Read-Host -Times 0
        }

        It 'aborts when it cannot prompt and -Yes is absent' {
            { Invoke-Gate -CanPrompt $false } | Should -Throw $AbortToken
            Should -Invoke Read-Host -Times 0
        }

        It 'aborts before the prompt when disk is insufficient' {
            { Invoke-Gate -Need 10GB -Free 1GB -AssumeYes $true } | Should -Throw $AbortToken
            Should -Invoke Read-Host -Times 0
        }

        It 'does not prompt when nothing is downloaded or installed' {
            Invoke-Gate -Nothing $true | Should -BeTrue
            Should -Invoke Read-Host -Times 0
        }
    }

    Context 'answer parsing' {
        It 'reads the earliest label like omp does: <Text> -> <Expected>' -ForEach @(
            @{ Text = 'low'; Expected = 'low' }
            @{ Text = 'medium</think>low'; Expected = 'medium' }
            @{ Text = 'Effort: HIGH.'; Expected = 'high' }
            @{ Text = 'lowered'; Expected = $null }
            @{ Text = ''; Expected = $null }
        ) {
            Get-FirstLabel $Text @('low', 'medium', 'high') | Should -Be $Expected
        }

        It 'prefers the longer label at the same position' {
            Get-FirstLabel 'xhigh' @('high', 'xhigh') | Should -Be 'xhigh'
        }
    }

    Context 'service helpers' {
        BeforeAll { $ServiceName = 'llama-cpp-tiny' }

        It 'adds the start/stop ACE before the SACL, once' {
            $sddl = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWLOCRRC;;;IU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)'
            $result = Add-ServiceAce $sddl 'S-1-5-21-1-2-3-1001'
            $result | Should -Be 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWLOCRRC;;;IU)(A;;RPWPLCLOCRRC;;;S-1-5-21-1-2-3-1001)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)'
            Add-ServiceAce $result 'S-1-5-21-1-2-3-1001' | Should -Be $result
        }

        It 'appends the ACE when there is no SACL' {
            Add-ServiceAce 'D:(A;;LC;;;IU)' 'S-1-5-21-9' | Should -Be 'D:(A;;LC;;;IU)(A;;RPWPLCLOCRRC;;;S-1-5-21-9)'
        }

        It 'lists only model files outside the root' {
            Get-ExternalServiceFiles ([pscustomobject]@{ model = (Join-Path $Root 'models\m.gguf') }) | Should -BeNullOrEmpty
            Get-ExternalServiceFiles ([pscustomobject]@{ model = 'C:\cache\m.gguf' }) | Should -Be 'C:\cache\m.gguf'
        }

        It 'recognizes a listener under the running service process tree' {
            Mock Get-JudgeService { [pscustomobject]@{ ProcessId = 100; State = 'Running' } }
            Mock Get-CimInstance {
                $id = [int]($Filter -replace '\D', '')
                switch ($id) { 300 { [pscustomobject]@{ ParentProcessId = 200 } } 200 { [pscustomobject]@{ ParentProcessId = 100 } } 400 { [pscustomobject]@{ ParentProcessId = 1 } } default { $null } }
            } -ParameterFilter { $ClassName -eq 'Win32_Process' }
            Test-ServiceChild 300 | Should -BeTrue
            Test-ServiceChild 400 | Should -BeFalse
        }

        It 'is false without a service' {
            Mock Get-JudgeService { $null }
            Test-ServiceChild 300 | Should -BeFalse
        }
    }
    Context 'server command line' {
        It 'builds the llama-server arguments' {
            $config = [pscustomobject]@{ port = 9941; model = 'C:\Users\A B\m.gguf'; ctx = 8192; ngl = 'all'; alias = 'LFM3-1.7B'; idleSleepSeconds = 900; log = 'C:\r\server.log' }
            $arguments = Get-ServerArguments $config
            ($arguments -join ' ') | Should -Be '--host 127.0.0.1 --port 9941 -m C:\Users\A B\m.gguf -c 8192 -ngl all --alias LFM3-1.7B --parallel 1 --no-webui --chat-template-kwargs {"enable_thinking":false} --log-file C:\r\server.log --sleep-idle-seconds 900'
        }

        It 'omits idle sleep when disabled' {
            $config = [pscustomobject]@{ port = 1; model = 'm'; ctx = 4096; ngl = '0'; alias = 'a'; idleSleepSeconds = -1 }
            Get-ServerArguments $config | Should -Not -Contain '--sleep-idle-seconds'
        }

        It 'quotes arguments for the Windows command line' {
            ConvertTo-CommandLineArgument 'plain' | Should -Be 'plain'
            ConvertTo-CommandLineArgument 'C:\Users\A B\m.gguf' | Should -Be '"C:\Users\A B\m.gguf"'
            ConvertTo-CommandLineArgument '{"enable_thinking":false}' | Should -Be '"{\"enable_thinking\":false}"'
            ConvertTo-CommandLineArgument 'C:\dir with space\' | Should -Be '"C:\dir with space\\"'
            ConvertTo-CommandLineArgument '' | Should -Be '""'
        }
    }
}
