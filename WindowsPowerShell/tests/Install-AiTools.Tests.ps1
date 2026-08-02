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
        $script:configuredModules = @($_AiToolsInternal.PowerShellModules)
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
