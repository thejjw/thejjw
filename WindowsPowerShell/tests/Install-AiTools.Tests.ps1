BeforeAll {
    $script:userPathBeforeInstallAiToolsTests = [Environment]::GetEnvironmentVariable('PATH', 'User')
}

AfterAll {
    [Environment]::GetEnvironmentVariable('PATH', 'User') | Should -BeExactly $script:userPathBeforeInstallAiToolsTests
}

Describe 'Install-AiTools PowerShell modules' {
    BeforeAll {
        $profilePath = Join-Path $PSScriptRoot '..\Microsoft.PowerShell_profile.ps1'
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $profilePath,
            [ref]$tokens,
            [ref]$errors
        )
        if ($errors) { throw "Profile contains parse errors: $($errors -join '; ')" }

        $configAst = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left.Extent.Text -eq '$_AiToolsInternal'
        }, $true)
        $installerAst = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'Install-AiTools'
        }, $true)
        if (-not $configAst -or -not $installerAst) {
            throw 'Could not load Install-AiTools and its configuration from the profile.'
        }

        $script:installerAst = $installerAst
        . ([scriptblock]::Create($configAst.Extent.Text))
        . ([scriptblock]::Create($installerAst.Extent.Text))
        function Add-UserPathEntry { param([string]$Path) }
        $script:configuredModules = @($_AiToolsInternal.PowerShellModules)
        $script:configuredWingetPackages = @($_AiToolsInternal.WingetPackages)
        $script:originalAiToolsConfig = $_AiToolsInternal
    }

    BeforeEach {
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
            WingetPackages         = @()
            ExtendedWingetPackages = @()
            SdkWingetPackages      = @()
            DbWingetPackages       = @()
            MoreAiWingetPackages   = @()
            DockerWingetPackage    = 'Docker.DockerDesktop'
            PodmanWingetPackage    = 'RedHat.Podman'
            GitWingetPackage       = 'Git.Git'
            NpmPackages            = @()
            MoreAiNpmPackages      = @()
        }
        $script:moduleInstalled = $false
        $script:events = @()

        Mock Write-Host {}
        Mock Write-Warning {}
        Mock Get-Command {
            if ($Name -eq 'Install-Module') {
                return [pscustomobject]@{ Name = 'Install-Module' }
            }
            if ($Name -eq 'winget') {
                $script:events += 'winget'
            }
            return $null
        }
        Mock Get-Module {
            if ($script:moduleInstalled) {
                return [pscustomobject]@{ Name = 'Pester'; Version = [version]'6.0.1' }
            }
            return $null
        }
        Mock Get-PackageProvider {
            return [pscustomobject]@{ Name = 'NuGet'; Version = [version]'2.8.5.208' }
        }
        Mock Install-PackageProvider {}
        Mock Install-Module {
            $script:events += 'module'
            $script:moduleInstalled = $true
        }
    }

    AfterAll {
        $_AiToolsInternal = $script:originalAiToolsConfig
    }

    It 'configures current stable Pester for the current user' {
        $pester = $script:configuredModules | Where-Object Name -eq 'Pester'

        $pester.MinimumVersion | Should -Be '6.0'
        $pester.Repository | Should -Be 'PSGallery'
        $pester.Scope | Should -Be 'CurrentUser'
        $pester.Force | Should -BeTrue
        $pester.SkipPublisherCheck | Should -BeTrue
    }

    It 'includes Bun in the standard Winget packages' {
        $script:configuredWingetPackages | Should -Contain 'Oven-sh.Bun'
    }

    It 'does not write the user PATH directly' {
        $script:installerAst.Extent.Text | Should -Not -Match "SetValue\('PATH'"
        $script:installerAst.Extent.Text | Should -Not -Match "SetEnvironmentVariable\('PATH'"
    }

    It 'configures npm funding notices before global package installs' {
        $npmConfigurationAst = $script:installerAst.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'Set-NpmConfiguration'
        }, $true)
        $configurationCalls = @($script:installerAst.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -eq 'Set-NpmConfiguration'
        }, $true))
        $npmInstallCalls = @($script:installerAst.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -eq 'npm' -and
                $node.Extent.Text -match '\binstall\b'
        }, $true))

        $npmConfigurationAst | Should -Not -BeNullOrEmpty
        $npmConfigurationAst.Extent.Text | Should -Match '& npm config set fund false'
        $configurationCalls.Count | Should -Be 1
        $npmInstallCalls.Count | Should -BeGreaterThan 0
        $configurationCalls[0].Extent.StartOffset | Should -BeLessThan $npmInstallCalls[0].Extent.StartOffset
    }

    It 'installs a missing module before checking Winget' {
        Install-AiTools -Auto

        ($script:events -join ',') | Should -Be 'module,winget'
        Should -Invoke Install-Module -Times 1 -Exactly -ParameterFilter {
            $Name -eq 'Pester' -and
            $MinimumVersion -eq '6.0' -and
            $Repository -eq 'PSGallery' -and
            $Scope -eq 'CurrentUser' -and
            $Force -and
            $SkipPublisherCheck -and
            $Confirm -eq $false
        }
    }

    It 'skips a module that already meets the minimum version' {
        $script:moduleInstalled = $true

        Install-AiTools -Auto

        Should -Invoke Install-Module -Times 0 -Exactly
    }

    It 'refreshes an installed module during an update run' {
        $script:moduleInstalled = $true

        Install-AiTools -Auto -Update

        Should -Invoke Install-Module -Times 1 -Exactly
    }

    It 'bootstraps NuGet when a suitable provider is unavailable' {
        Mock Get-PackageProvider { return $null }

        Install-AiTools -Auto

        Should -Invoke Install-PackageProvider -Times 1 -Exactly -ParameterFilter {
            $Name -eq 'NuGet' -and
            $MinimumVersion -eq [version]'2.8.5.201' -and
            $Scope -eq 'CurrentUser' -and
            $Force -and
            $Confirm -eq $false
        }
    }

    It 'warns and continues to Winget when module installation fails' {
        Mock Install-Module { throw 'gallery unavailable' }

        Install-AiTools -Auto

        Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter {
            $Message -like '*Pester*gallery unavailable*'
        }
        $script:events | Should -Contain 'winget'
    }
}

Describe 'Install-AiTools npm packages' {
    BeforeAll {
        $profilePath = Join-Path $PSScriptRoot '..\Microsoft.PowerShell_profile.ps1'
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $profilePath,
            [ref]$tokens,
            [ref]$errors
        )
        if ($errors) { throw "Profile contains parse errors: $($errors -join '; ')" }

        $configAst = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left.Extent.Text -eq '$_AiToolsInternal'
        }, $true)
        $installerAst = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'Install-AiTools'
        }, $true)
        $inventoryAst = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'Get-GlobalNpmInventory'
        }, $true)
        if (-not $inventoryAst) { throw 'Could not load Get-GlobalNpmInventory from the profile.' }
        . ([scriptblock]::Create($inventoryAst.Extent.Text))
        . ([scriptblock]::Create($configAst.Extent.Text))
        . ([scriptblock]::Create($installerAst.Extent.Text))
        $script:originalAiToolsConfigForNpm = $_AiToolsInternal

        function New-NpmInventoryJson {
            param([string[]]$Names)
            $dependencies = [ordered]@{}
            foreach ($name in $Names) {
                $dependencies[$name] = [ordered]@{ version = '1.0.0' }
            }
            return ([ordered]@{ dependencies = $dependencies } | ConvertTo-Json -Compress -Depth 4)
        }

        # These settings helpers are outside the isolated function AST used by
        # the tests; no-op definitions let the installer reach its normal end.
        function Install-QwenSettings {}
        function Install-KimiSettings {}
        function Install-GrokSettings {}
        function Add-UserPathEntry { param([string]$Path) }
        function winget {
            param([Parameter(ValueFromRemainingArguments = $true)][object[]]$ArgumentList)
        }
        function npm {
            param([Parameter(ValueFromRemainingArguments = $true)][object[]]$ArgumentList)
        }
    }

    BeforeEach {
        $_AiToolsInternal = @{
            PowerShellModules      = @()
            WingetPackages         = @()
            ExtendedWingetPackages = @()
            SdkWingetPackages      = @()
            DbWingetPackages       = @()
            MoreAiWingetPackages   = @()
            DockerWingetPackage    = 'Docker.DockerDesktop'
            PodmanWingetPackage    = 'RedHat.Podman'
            GitWingetPackage       = 'Git.Git'
            NpmPackages            = @($script:originalAiToolsConfigForNpm.NpmPackages)
            MoreAiNpmPackages      = @($script:originalAiToolsConfigForNpm.MoreAiNpmPackages)
            Urls                   = @{}
        }
        $script:npmCalls = @()
        $script:inventoryResponses = New-Object System.Collections.Queue

        Mock Write-Host {}
        Mock Write-Warning {}
        Mock Add-UserPathEntry { return $true }
        Mock Get-Command {
            if ($Name -in @('winget', 'git', 'npm', 'opencode')) {
                return [pscustomobject]@{ Name = $Name }
            }
            return $null
        }
        Mock Get-ItemPropertyValue { return (Join-Path $env:USERPROFILE '.local\bin') }
        Mock winget { return @() }
        Mock powershell {}
        Mock Install-QwenSettings {}
        Mock Install-KimiSettings {}
        Mock Install-GrokSettings {}
        Mock npm {
            param($ArgumentList)
            $callArgs = @($ArgumentList)
            $script:npmCalls += [pscustomobject]@{ Args = $callArgs }
            if ($callArgs[0] -eq 'ls') {
                $response = $script:inventoryResponses.Dequeue()
                $global:LASTEXITCODE = $response.ExitCode
                return $response.Json
            }
            if ($callArgs[0] -eq 'prefix') {
                $global:LASTEXITCODE = 0
                return 'C:\npm-global'
            }
            $global:LASTEXITCODE = 0
        }
    }

    AfterAll {
        $_AiToolsInternal = $script:originalAiToolsConfigForNpm
    }

    It 'skips healthy packages even during an update run' {
        $script:inventoryResponses.Enqueue([pscustomobject]@{
            ExitCode = 0
            Json = New-NpmInventoryJson $_AiToolsInternal.NpmPackages
        })

        Install-AiTools -Auto -Update

        @($script:npmCalls | Where-Object { $_.Args[0] -eq 'install' }).Count | Should -Be 0
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter {
            $Object -eq 'All selected global npm packages are already installed.'
        }
    }

    It 'repairs command shim paths before using winget and npm' {
        $script:inventoryResponses.Enqueue([pscustomobject]@{
            ExitCode = 0
            Json = New-NpmInventoryJson $_AiToolsInternal.NpmPackages
        })

        Install-AiTools -Auto

        Should -Invoke Add-UserPathEntry -Times 1 -Exactly -ParameterFilter {
            $Path -eq (Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps')
        }
        Should -Invoke Add-UserPathEntry -Times 1 -Exactly -ParameterFilter {
            $Path -eq 'C:\npm-global'
        }
    }

    It 'installs all missing standard packages in one call' {
        $script:inventoryResponses.Enqueue([pscustomobject]@{ ExitCode = 0; Json = New-NpmInventoryJson @() })
        $script:inventoryResponses.Enqueue([pscustomobject]@{ ExitCode = 0; Json = New-NpmInventoryJson $_AiToolsInternal.NpmPackages })

        Install-AiTools -Auto

        $installCalls = @($script:npmCalls | Where-Object { $_.Args[0] -eq 'install' })
        $installCalls.Count | Should -Be 1
        $installCalls[0].Args | Should -Be (@('install', '-g') + $_AiToolsInternal.NpmPackages)
    }

    It 'adds MoreAi packages to the same consolidated call' {
        $allPackages = @($_AiToolsInternal.NpmPackages) + @($_AiToolsInternal.MoreAiNpmPackages)
        $script:inventoryResponses.Enqueue([pscustomobject]@{ ExitCode = 0; Json = New-NpmInventoryJson @() })
        $script:inventoryResponses.Enqueue([pscustomobject]@{ ExitCode = 0; Json = New-NpmInventoryJson $allPackages })

        Install-AiTools -Auto -MoreAi

        $installCalls = @($script:npmCalls | Where-Object { $_.Args[0] -eq 'install' })
        $installCalls.Count | Should -Be 1
        $installCalls[0].Args | Should -Be (@('install', '-g') + $allPackages)
    }

    It 'falls back to installing every candidate when inventory JSON is unusable' {
        $script:inventoryResponses.Enqueue([pscustomobject]@{ ExitCode = 1; Json = 'not-json' })
        $script:inventoryResponses.Enqueue([pscustomobject]@{ ExitCode = 0; Json = New-NpmInventoryJson $_AiToolsInternal.NpmPackages })

        Install-AiTools -Auto

        @($script:npmCalls | Where-Object { $_.Args[0] -eq 'install' }).Count | Should -Be 1
        Should -Invoke Write-Warning -ParameterFilter { $Message -like '*Could not parse the global npm inventory*' }
    }

    It 'uses healthy entries from a nonzero inventory result' {
        $installedPackage = $_AiToolsInternal.NpmPackages[0]
        $remainingPackages = @($_AiToolsInternal.NpmPackages | Where-Object { $_ -ne $installedPackage })
        $script:inventoryResponses.Enqueue([pscustomobject]@{
            ExitCode = 1
            Json = New-NpmInventoryJson @($installedPackage)
        })
        $script:inventoryResponses.Enqueue([pscustomobject]@{
            ExitCode = 0
            Json = New-NpmInventoryJson $_AiToolsInternal.NpmPackages
        })

        Install-AiTools -Auto

        $installCall = @($script:npmCalls | Where-Object { $_.Args[0] -eq 'install' })[0]
        $installCall.Args | Should -Be (@('install', '-g') + $remainingPackages)
        Should -Invoke Write-Warning -ParameterFilter { $Message -like 'npm global inventory returned exit code 1*' }
    }

    It 'warns on a failed consolidated install and reports packages still missing' {
        $script:inventoryResponses.Enqueue([pscustomobject]@{ ExitCode = 0; Json = New-NpmInventoryJson @() })
        $script:inventoryResponses.Enqueue([pscustomobject]@{ ExitCode = 0; Json = New-NpmInventoryJson @() })
        Mock npm {
            param($ArgumentList)
            $callArgs = @($ArgumentList)
            $script:npmCalls += [pscustomobject]@{ Args = $callArgs }
            if ($callArgs[0] -eq 'ls') {
                $response = $script:inventoryResponses.Dequeue()
                $global:LASTEXITCODE = $response.ExitCode
                return $response.Json
            }
            $global:LASTEXITCODE = if ($callArgs[0] -eq 'install') { 9 } else { 0 }
        }

        Install-AiTools -Auto

        Should -Invoke Write-Warning -ParameterFilter { $Message -like 'npm install failed with exit code 9*' }
        Should -Invoke Write-Warning -ParameterFilter { $Message -like '*remain missing or invalid*' }
    }

    It 'warns but continues when npm funding configuration fails' {
        $script:inventoryResponses.Enqueue([pscustomobject]@{
            ExitCode = 0
            Json = New-NpmInventoryJson $_AiToolsInternal.NpmPackages
        })
        Mock npm {
            param($ArgumentList)
            $callArgs = @($ArgumentList)
            $script:npmCalls += [pscustomobject]@{ Args = $callArgs }
            if ($callArgs[0] -eq 'config') {
                $global:LASTEXITCODE = 7
                return
            }
            if ($callArgs[0] -eq 'ls') {
                $response = $script:inventoryResponses.Dequeue()
                $global:LASTEXITCODE = $response.ExitCode
                return $response.Json
            }
            $global:LASTEXITCODE = 0
        }

        Install-AiTools -Auto

        Should -Invoke Write-Warning -ParameterFilter { $Message -like 'npm funding configuration failed with exit code 7*' }
        Should -Invoke Write-Host -ParameterFilter { $Object -eq 'Install-AiTools finished. You may need to restart PowerShell to pick up new PATH or env changes.' }
    }

    It 'checks the native exit code for the separate OpenCode bootstrap' {
        $script:inventoryResponses.Enqueue([pscustomobject]@{
            ExitCode = 0
            Json = New-NpmInventoryJson $_AiToolsInternal.NpmPackages
        })
        Mock Get-Command {
            if ($Name -in @('winget', 'git', 'npm')) {
                return [pscustomobject]@{ Name = $Name }
            }
            return $null
        }
        Mock npm {
            param($ArgumentList)
            $callArgs = @($ArgumentList)
            $script:npmCalls += [pscustomobject]@{ Args = $callArgs }
            if ($callArgs[0] -eq 'ls') {
                $response = $script:inventoryResponses.Dequeue()
                $global:LASTEXITCODE = $response.ExitCode
                return $response.Json
            }
            $global:LASTEXITCODE = if ($callArgs -contains 'opencode-ai') { 8 } else { 0 }
        }

        Install-AiTools -Auto

        Should -Invoke Write-Warning -ParameterFilter { $Message -eq 'Failed to install opencode-ai with npm exit code 8.' }
    }
}
