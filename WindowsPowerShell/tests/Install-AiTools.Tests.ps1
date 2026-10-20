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
        $wingetPkgAst = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'Invoke-WingetPackage'
        }, $true)
        if (-not $wingetPkgAst) { throw 'Could not load Invoke-WingetPackage from the profile.' }
        . ([scriptblock]::Create($wingetPkgAst.Extent.Text))
        . ([scriptblock]::Create($configAst.Extent.Text))
        . ([scriptblock]::Create($installerAst.Extent.Text))
        function Add-UserPathEntry { param([string]$Path) }
        function Test-IsAdministrator { return $false }
        $script:configuredModules = @($_AiToolsInternal.PowerShellModules)
        $script:configuredWingetPackages = @($_AiToolsInternal.WingetPackages)
        $script:configuredMoreAiWingetPackages = @($_AiToolsInternal.MoreAiWingetPackages)
        $script:configuredUrls = $_AiToolsInternal.Urls
        $script:configuredUpgradeCommands = @($_AiToolsInternal.UpgradeCommands)
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

    It 'includes age in the standard Winget packages' {
        $script:configuredWingetPackages | Should -Contain 'FiloSottile.age'
    }

    It 'includes Gpg4win in the standard Winget packages' {
        $script:configuredWingetPackages | Should -Contain 'GnuPG.Gpg4win'
    }

    It 'includes Anysphere.Cursor in the MoreAi Winget packages' {
        $script:configuredMoreAiWingetPackages | Should -Contain 'Anysphere.Cursor'
    }

    It 'configures the official win32 install script URL for Cursor CLI' {
        $script:configuredUrls.CursorCli | Should -Be 'https://cursor.com/install?win32=true'
    }

    It 'configures an upgrade command for Cursor CLI' {
        $cursorUpgrade = $script:configuredUpgradeCommands | Where-Object Label -eq 'cursor'
        $cursorUpgrade | Should -Not -BeNullOrEmpty
        $cursorUpgrade.Cmd | Should -Be 'agent'
        $cursorUpgrade.Probe | Should -Be 'cursor-agent'
        $cursorUpgrade.Args | Should -Be @('update')
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
        $wingetPkgAst = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'Invoke-WingetPackage'
        }, $true)
        if (-not $wingetPkgAst) { throw 'Could not load Invoke-WingetPackage from the profile.' }
        . ([scriptblock]::Create($inventoryAst.Extent.Text))
        . ([scriptblock]::Create($wingetPkgAst.Extent.Text))
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
        function Test-IsAdministrator { return $false }
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
        Mock winget { $global:LASTEXITCODE = 0; return @() }
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

    It 'queries Winget inventory without interactive prompts before and after installation' {
        $_AiToolsInternal.WingetPackages = @('Example.Inventory')
        Mock Start-Process {}
        $script:wingetCalls = @()
        Mock winget {
            param($ArgumentList)
            $script:wingetCalls += [pscustomobject]@{ Args = @($ArgumentList) }
            $global:LASTEXITCODE = 0
            if ($script:wingetCalls.Count -gt 1) { return 'Example Example.Inventory 1.0' }
            return @()
        }
        $script:inventoryResponses.Enqueue([pscustomobject]@{
            ExitCode = 0
            Json = New-NpmInventoryJson $_AiToolsInternal.NpmPackages
        })

        Install-AiTools -Auto

        $script:wingetCalls.Count | Should -Be 2
        foreach ($call in $script:wingetCalls) {
            $call.Args | Should -Be @('list', '--source', 'winget', '--accept-source-agreements', '--disable-interactivity')
        }
        Should -Invoke Start-Process -Times 1 -Exactly
    }

    It 'stops before installers when the initial Winget inventory fails' {
        $_AiToolsInternal.WingetPackages = @('Example.Inventory')
        Mock Start-Process {}
        Mock winget { $global:LASTEXITCODE = 9; return 'source unavailable' }

        Install-AiTools -Auto

        Should -Invoke winget -Times 1 -Exactly
        Should -Invoke Start-Process -Times 0 -Exactly
        $script:npmCalls.Count | Should -Be 0
        Should -Invoke Write-Host -ParameterFilter { $Object -like '*inventory*9*' }
    }

    It 'stops after a failed Winget recheck instead of reporting successful installation' {
        $_AiToolsInternal.WingetPackages = @('Example.Inventory')
        Mock Start-Process {}
        $script:wingetQueryCount = 0
        Mock winget {
            $script:wingetQueryCount++
            $global:LASTEXITCODE = if ($script:wingetQueryCount -eq 1) { 0 } else { 9 }
            return @()
        }

        Install-AiTools -Auto

        Should -Invoke winget -Times 2 -Exactly
        Should -Invoke Start-Process -Times 1 -Exactly
        $script:npmCalls.Count | Should -Be 0
        Should -Invoke Write-Host -Times 0 -Exactly -ParameterFilter { $Object -eq 'All packages installed successfully.' }
        Should -Invoke Write-Host -ParameterFilter { $Object -like '*inventory*9*' }
    }

    It 'skips healthy packages that are already installed' {
        $script:inventoryResponses.Enqueue([pscustomobject]@{
            ExitCode = 0
            Json = New-NpmInventoryJson $_AiToolsInternal.NpmPackages
        })

        Install-AiTools -Auto

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
            $global:LASTEXITCODE = if ($callArgs -contains '@opencode/cli') { 8 } else { 0 }
        }

        Install-AiTools -Auto

        Should -Invoke Write-Warning -ParameterFilter { $Message -eq 'Failed to install @opencode/cli with npm exit code 8.' }
    }

    It 'removes interactively entered package ids from the pending lists' {
        $removedPackage = $_AiToolsInternal.NpmPackages[0]
        $remainingPackages = @($_AiToolsInternal.NpmPackages | Where-Object { $_ -ne $removedPackage })
        $script:pruneResponses = [System.Collections.Queue]::new()
        $script:pruneResponses.Enqueue($removedPackage)
        $script:pruneResponses.Enqueue('')
        Mock Read-Host { return $script:pruneResponses.Dequeue() }
        $script:inventoryResponses.Enqueue([pscustomobject]@{ ExitCode = 0; Json = New-NpmInventoryJson @() })
        $script:inventoryResponses.Enqueue([pscustomobject]@{ ExitCode = 0; Json = New-NpmInventoryJson $remainingPackages })

        Install-AiTools -Auto -Customize

        $installCall = @($script:npmCalls | Where-Object { $_.Args[0] -eq 'install' })[0]
        $installCall.Args | Should -Be (@('install', '-g') + $remainingPackages)
        Should -Invoke Read-Host -Times 2 -Exactly
    }

    It 'keeps every package when entered ids match nothing' {
        $script:pruneResponses = [System.Collections.Queue]::new()
        $script:pruneResponses.Enqueue('does.not.exist')
        $script:pruneResponses.Enqueue('')
        Mock Read-Host { return $script:pruneResponses.Dequeue() }
        $script:inventoryResponses.Enqueue([pscustomobject]@{ ExitCode = 0; Json = New-NpmInventoryJson @() })
        $script:inventoryResponses.Enqueue([pscustomobject]@{ ExitCode = 0; Json = New-NpmInventoryJson $_AiToolsInternal.NpmPackages })

        Install-AiTools -Auto -Customize

        $installCall = @($script:npmCalls | Where-Object { $_.Args[0] -eq 'install' })[0]
        $installCall.Args | Should -Be (@('install', '-g') + $_AiToolsInternal.NpmPackages)
        Should -Invoke Write-Host -ParameterFilter {
            $Object -eq "Package id 'does.not.exist' was not found in any install list."
        }
    }

    It 'removes interactively entered winget ids from the pending installs' {
        $_AiToolsInternal.WingetPackages = @('Example.One', 'Example.Two')
        Mock Start-Process {}
        $script:pruneResponses = [System.Collections.Queue]::new()
        $script:pruneResponses.Enqueue('Example.One')
        $script:pruneResponses.Enqueue('')
        Mock Read-Host { return $script:pruneResponses.Dequeue() }
        $script:inventoryResponses.Enqueue([pscustomobject]@{ ExitCode = 0; Json = New-NpmInventoryJson @() })
        $script:inventoryResponses.Enqueue([pscustomobject]@{ ExitCode = 0; Json = New-NpmInventoryJson $_AiToolsInternal.NpmPackages })

        Install-AiTools -Auto -Customize

        Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter { $ArgumentList -like '*Example.Two*' }
        Should -Invoke Start-Process -Times 0 -Exactly -ParameterFilter { $ArgumentList -like '*Example.One*' }
    }

    It 'rejects -UserScope when session is elevated' {
        Mock Test-IsAdministrator { return $true }
        { Install-AiTools -UserScope -Auto } | Should -Throw '*Cannot use -UserScope in an elevated PowerShell session*'
    }

    It 'installs winget packages with user scope when -UserScope is supplied' {
        $_AiToolsInternal.WingetPackages = @('Example.UserScope')
        Mock Start-Process {}
        $script:inventoryResponses.Enqueue([pscustomobject]@{ ExitCode = 0; Json = New-NpmInventoryJson @() })
        $script:inventoryResponses.Enqueue([pscustomobject]@{ ExitCode = 0; Json = New-NpmInventoryJson $_AiToolsInternal.NpmPackages })

        Install-AiTools -Auto -UserScope

        Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter {
            $ArgumentList -contains '--scope' -and
            $ArgumentList -contains 'user' -and
            $ArgumentList -contains '--silent' -and
            $ArgumentList -contains 'Example.UserScope'
        }
    }

    It 'launches interactive installer for missing Git in default scope' {
        $_AiToolsInternal.WingetPackages = @()
        Mock Get-Command {
            if ($Name -in @('winget', 'npm', 'opencode')) { return [pscustomobject]@{ Name = $Name } }
            return $null
        }
        Mock Start-Process {}
        $script:inventoryResponses.Enqueue([pscustomobject]@{ ExitCode = 0; Json = New-NpmInventoryJson @() })
        $script:inventoryResponses.Enqueue([pscustomobject]@{ ExitCode = 0; Json = New-NpmInventoryJson $_AiToolsInternal.NpmPackages })

        Install-AiTools -Auto

        Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter {
            ($ArgumentList -join ' ') -eq 'install --source winget --exact --id Git.Git -i'
        }
    }

    It 'installs missing Git silently with user scope when -UserScope is supplied' {
        $_AiToolsInternal.WingetPackages = @()
        Mock Get-Command {
            if ($Name -in @('winget', 'npm', 'opencode')) { return [pscustomobject]@{ Name = $Name } }
            return $null
        }
        Mock Start-Process {}
        $script:inventoryResponses.Enqueue([pscustomobject]@{ ExitCode = 0; Json = New-NpmInventoryJson @() })
        $script:inventoryResponses.Enqueue([pscustomobject]@{ ExitCode = 0; Json = New-NpmInventoryJson $_AiToolsInternal.NpmPackages })

        Install-AiTools -Auto -UserScope

        Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter {
            ($ArgumentList -join ' ') -eq 'install --source winget --exact --id Git.Git --scope user --silent --disable-interactivity --accept-package-agreements --accept-source-agreements'
        }
    }

    It 'passes --no-upgrade when installing missing Winget packages' {
        $_AiToolsInternal.WingetPackages = @('Example.Package')
        Mock Start-Process { return [pscustomobject]@{ ExitCode = 0 } }
        $script:inventoryResponses.Enqueue([pscustomobject]@{ ExitCode = 0; Json = New-NpmInventoryJson @() })
        $script:inventoryResponses.Enqueue([pscustomobject]@{ ExitCode = 0; Json = New-NpmInventoryJson $_AiToolsInternal.NpmPackages })

        Install-AiTools -Auto

        Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter {
            $ArgumentList -contains '--no-upgrade' -and
            $ArgumentList -contains 'Example.Package'
        }
    }

    It 'treats benign Winget exit codes for already-installed packages as successful' {
        $_AiToolsInternal.WingetPackages = @('Example.AlreadyInstalled')
        Mock Start-Process { return [pscustomobject]@{ ExitCode = -1978335135 } }
        $script:inventoryResponses.Enqueue([pscustomobject]@{ ExitCode = 0; Json = New-NpmInventoryJson @() })
        $script:inventoryResponses.Enqueue([pscustomobject]@{ ExitCode = 0; Json = New-NpmInventoryJson $_AiToolsInternal.NpmPackages })

        Install-AiTools -Auto

        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter {
            $Object -eq 'Example.AlreadyInstalled is already installed.'
        }
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter {
            $Object -eq 'All packages installed successfully.'
        }
    }
}

Describe 'Install-AiTools REA toolchain' {
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
        if (-not $configAst) { throw 'Could not load $_AiToolsInternal from the profile.' }

        function Get-ProfileFunctionText {
            param([string]$Name)
            $found = $ast.Find({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -eq $Name
            }, $true)
            if (-not $found) { throw "Could not load $Name from the profile." }
            return $found.Extent.Text
        }

        . ([scriptblock]::Create((Get-ProfileFunctionText 'Get-JdkInstallation')))
        . ([scriptblock]::Create((Get-ProfileFunctionText 'Install-ReaToolchain')))
        . ([scriptblock]::Create((Get-ProfileFunctionText 'Set-UserEnvironmentValue')))
        . ([scriptblock]::Create($configAst.Extent.Text))

        $script:originalReaConfig = $_AiToolsInternal
        $script:reaEnvNames = @('GHIDRA_INSTALL_DIR', 'JAVA_HOME', 'REA_ANALYSIS_PROVIDER')
        $script:reaEnvBackup = @{}
        foreach ($name in $script:reaEnvNames) {
            $script:reaEnvBackup[$name] = @{
                User    = [Environment]::GetEnvironmentVariable($name, 'User')
                Process = [Environment]::GetEnvironmentVariable($name, 'Process')
            }
        }
        $script:reaPathBackup = $env:PATH

        # Stubs for the commands the stage shells out to. The stubs record their
        # arguments so the tests can assert on them.
        function Save-WebFile {
            [CmdletBinding()]
            param($Uri, $OutFile, [switch]$Force, [switch]$Quiet)
        }
        function Invoke-WingetPackage {
            [CmdletBinding()]
            param($Action, $PackageId, [switch]$UserScope, [switch]$Interactive, [switch]$NoUpgrade)
        }
        function npm {
            [CmdletBinding()]
            param([Parameter(ValueFromRemainingArguments = $true)][object[]]$ArgumentList)
            $script:reaNpmCalls += , @($ArgumentList)
            # A completed global install makes the CLI resolvable.
            $script:reaPresent = $true
            $global:LASTEXITCODE = 0
        }
        function rea {
            [CmdletBinding()]
            param([Parameter(ValueFromRemainingArguments = $true)][object[]]$ArgumentList)
            $script:reaCalls += , @($ArgumentList)
            '{"healthy":true}'
        }
        function node {
            [CmdletBinding()]
            param([Parameter(ValueFromRemainingArguments = $true)][object[]]$ArgumentList)
            'v24.11.0'
        }
    }

    AfterAll {
        foreach ($name in $script:reaEnvNames) {
            $backup = $script:reaEnvBackup[$name]
            if ([Environment]::GetEnvironmentVariable($name, 'User') -ne $backup.User) {
                [Environment]::SetEnvironmentVariable($name, $backup.User, 'User')
            }
            if ([Environment]::GetEnvironmentVariable($name, 'Process') -ne $backup.Process) {
                [Environment]::SetEnvironmentVariable($name, $backup.Process, 'Process')
            }
        }
        $env:PATH = $script:reaPathBackup
        $_AiToolsInternal = $script:originalReaConfig
    }

    BeforeEach {
        # A disposable workspace holds both the extracted Ghidra tree and the
        # archive fixture the mocked downloader copies into place.
        $script:reaWorkspace = Join-Path ([System.IO.Path]::GetTempPath()) ('rea-stage-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:reaWorkspace -Force | Out-Null

        $fixtureRoot = Join-Path $script:reaWorkspace 'fixture'
        $fixtureGhidra = Join-Path $fixtureRoot 'ghidra_9.9.9_PUBLIC'
        New-Item -ItemType Directory -Path $fixtureGhidra -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $fixtureGhidra 'ghidraRun.bat') -Value '@echo off'
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $script:reaZip = Join-Path $script:reaWorkspace 'ghidra_9.9.9_PUBLIC_20260101.zip'
        [System.IO.Compression.ZipFile]::CreateFromDirectory($fixtureRoot, $script:reaZip)
        $script:reaZipSha = (Get-FileHash -LiteralPath $script:reaZip -Algorithm SHA256).Hash.ToLowerInvariant()
        $script:reaZipSize = (Get-Item -LiteralPath $script:reaZip).Length

        # Copy the configuration so the shared profile config is never mutated.
        $config = @{}
        foreach ($key in $script:originalReaConfig.Keys) { $config[$key] = $script:originalReaConfig[$key] }
        $ghidra = @{}
        foreach ($key in $script:originalReaConfig.Ghidra.Keys) { $ghidra[$key] = $script:originalReaConfig.Ghidra[$key] }
        $ghidra['Root'] = $script:reaWorkspace
        $config['Ghidra'] = $ghidra
        $_AiToolsInternal = $config

        foreach ($name in $script:reaEnvNames) {
            [Environment]::SetEnvironmentVariable($name, $null, 'Process')
        }

        $script:reaNpmCalls = @()
        $script:reaCalls = @()
        $script:reaEnvWrites = @()
        $script:reaPresent = $false

        Mock Write-Host {}
        Mock Write-Warning {}
        # The real setter writes to the user registry, which is slow and mutates
        # the machine; the scope semantics are covered by their own test.
        Mock Set-UserEnvironmentValue {
            $script:reaEnvWrites += [pscustomobject]@{ Name = $Name; Value = $Value }
        }
        Mock Get-JdkInstallation {
            return [pscustomobject]@{ Home = 'C:\Program Files\Microsoft\jdk-25.0.0.1-hotspot'; Major = 25 }
        }
        Mock Invoke-RestMethod {
            return [pscustomobject]@{
                tag_name = 'Ghidra_9.9.9_build'
                body     = 'SHA-256: `' + $script:reaZipSha + '`'
                assets   = @([pscustomobject]@{
                        name                 = 'ghidra_9.9.9_PUBLIC_20260101.zip'
                        size                 = $script:reaZipSize
                        browser_download_url = 'https://example.invalid/ghidra_9.9.9_PUBLIC_20260101.zip'
                    })
            }
        }
        Mock Save-WebFile { Copy-Item -LiteralPath $script:reaZip -Destination $OutFile -Force }
        Mock Invoke-WingetPackage { return 0 }
        Mock Get-Command {
            if ($Name -eq 'rea' -and $script:reaPresent) {
                return [pscustomobject]@{ Name = 'rea'; Source = 'C:\npm\rea.cmd' }
            }
            if ($Name -eq 'node') { return [pscustomobject]@{ Name = 'node'; Source = 'C:\node\node.exe' } }
            return $null
        }
    }

    AfterEach {
        if (Test-Path -LiteralPath $script:reaWorkspace) {
            Remove-Item -LiteralPath $script:reaWorkspace -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'extracts the resolved Ghidra release and points REA at it' {
        Install-ReaToolchain

        $target = Join-Path $script:reaWorkspace 'ghidra_9.9.9_PUBLIC'
        Test-Path -LiteralPath (Join-Path $target 'ghidraRun.bat') | Should -BeTrue

        $writes = @{}
        foreach ($write in $script:reaEnvWrites) { $writes[$write.Name] = $write.Value }
        $writes['GHIDRA_INSTALL_DIR'] | Should -Be $target
        $writes['REA_ANALYSIS_PROVIDER'] | Should -Be 'ghidra'
        $writes['JAVA_HOME'] | Should -Be 'C:\Program Files\Microsoft\jdk-25.0.0.1-hotspot'
    }

    It 'installs the REA CLI globally and never wires an agent' {
        Install-ReaToolchain

        $script:reaNpmCalls | Should -HaveCount 1
        ($script:reaNpmCalls[0] -join ' ') | Should -Be 'install --global rea-agents'

        $reaCommand = ($script:reaCalls | ForEach-Object { $_ -join ' ' }) -join '; '
        $reaCommand | Should -Match 'doctor'
        $reaCommand | Should -Not -Match 'setup'
    }

    It 'skips the npm install when the REA CLI is already present' {
        $script:reaPresent = $true

        Install-ReaToolchain

        $script:reaNpmCalls | Should -HaveCount 0
    }

    It 'installs the machine-scoped JDK when no supported one is present' {
        Mock Get-JdkInstallation { return $null }

        Install-ReaToolchain

        Should -Invoke Invoke-WingetPackage -Times 1 -Exactly -ParameterFilter {
            $PackageId -eq 'Microsoft.OpenJDK.25' -and -not $UserScope
        }
    }

    It 'rejects an archive whose digest does not match the release' {
        Mock Invoke-RestMethod {
            return [pscustomobject]@{
                tag_name = 'Ghidra_9.9.9_build'
                body     = 'SHA-256: `0000000000000000000000000000000000000000000000000000000000000000`'
                assets   = @([pscustomobject]@{
                        name                 = 'ghidra_9.9.9_PUBLIC_20260101.zip'
                        size                 = $script:reaZipSize
                        browser_download_url = 'https://example.invalid/ghidra_9.9.9_PUBLIC_20260101.zip'
                    })
            }
        }

        Install-ReaToolchain

        Should -Invoke Write-Warning -ParameterFilter { $Message -like '*SHA-256 mismatch*' }
        Test-Path -LiteralPath (Join-Path $script:reaWorkspace 'ghidra_9.9.9_PUBLIC') | Should -BeFalse
        @($script:reaEnvWrites | Where-Object { $_.Name -eq 'GHIDRA_INSTALL_DIR' }) | Should -HaveCount 0
    }

    It 'keeps an existing analysis provider instead of overwriting it' {
        $env:REA_ANALYSIS_PROVIDER = 'hopper'

        Install-ReaToolchain

        @($script:reaEnvWrites | Where-Object { $_.Name -eq 'REA_ANALYSIS_PROVIDER' }) | Should -HaveCount 0
    }

    It 'prints a usage guide that leaves agent registration to the user' {
        Install-ReaToolchain

        Should -Invoke Write-Host -ParameterFilter { $Object -like '*ghidraRun.bat*' }
        Should -Invoke Write-Host -ParameterFilter { $Object -like '*rea doctor*' }
        Should -Invoke Write-Host -ParameterFilter { $Object -like '*rea setup*' }
    }
}

Describe 'Install-AiTools -REA switch' {
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
        if (-not $installerAst) { throw 'Could not load Install-AiTools from the profile.' }
        . ([scriptblock]::Create($inventoryAst.Extent.Text))
        . ([scriptblock]::Create($configAst.Extent.Text))
        . ([scriptblock]::Create($installerAst.Extent.Text))
        $script:originalSwitchConfig = $_AiToolsInternal

        # Settings helpers and the REA stage live outside the isolated function AST.
        function Install-QwenSettings {}
        function Install-KimiSettings {}
        function Install-GrokSettings {}
        function Install-ReaToolchain {}
        function Add-UserPathEntry { param([string]$Path) }
        function Test-IsAdministrator { return $false }
        function winget {
            param([Parameter(ValueFromRemainingArguments = $true)][object[]]$ArgumentList)
        }
        function npm {
            param([Parameter(ValueFromRemainingArguments = $true)][object[]]$ArgumentList)
        }
    }

    AfterAll {
        $_AiToolsInternal = $script:originalSwitchConfig
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
            NpmPackages            = @()
            MoreAiNpmPackages      = @()
            Urls                   = @{}
            ReaNpmPackage          = 'rea-agents'
            ReaWingetPackage       = 'Microsoft.OpenJDK.25'
            Ghidra                 = @{ Version = '12.1.4'; Root = 'C:\Tools'; Bytes = 1 }
        }

        Mock Write-Host {}
        Mock Write-Warning {}
        Mock Get-Command {
            if ($Name -in @('winget', 'npm', 'opencode')) { return [pscustomobject]@{ Name = $Name } }
            return $null
        }
        Mock winget { $global:LASTEXITCODE = 0; return @() }
        Mock npm { $global:LASTEXITCODE = 0 }
        Mock powershell {}
        Mock Start-Process {}
        Mock Install-ReaToolchain {}
    }

    It 'runs the REA stage when -REA is supplied' {
        Install-AiTools -Auto -REA

        Should -Invoke Install-ReaToolchain -Times 1 -Exactly
    }

    It 'skips the REA stage by default' {
        Install-AiTools -Auto

        Should -Invoke Install-ReaToolchain -Times 0 -Exactly
    }

    It 'runs the REA stage through -All' {
        Install-AiTools -Auto -All

        Should -Invoke Install-ReaToolchain -Times 1 -Exactly
    }
}

Describe 'Set-UserEnvironmentValue' {
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

        $setterAst = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'Set-UserEnvironmentValue'
        }, $true)
        if (-not $setterAst) { throw 'Could not load Set-UserEnvironmentValue from the profile.' }
        . ([scriptblock]::Create($setterAst.Extent.Text))

        $script:envTestName = 'OMP_PROFILE_ENV_TEST'
    }

    AfterAll {
        [Environment]::SetEnvironmentVariable($script:envTestName, $null, 'User')
        [Environment]::SetEnvironmentVariable($script:envTestName, $null, 'Process')
    }

    It 'writes the value to the user scope and to the current process' {
        Set-UserEnvironmentValue -Name $script:envTestName -Value 'probe'

        [Environment]::GetEnvironmentVariable($script:envTestName, 'User') | Should -Be 'probe'
        [Environment]::GetEnvironmentVariable($script:envTestName, 'Process') | Should -Be 'probe'
    }
}
