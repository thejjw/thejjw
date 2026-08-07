Describe 'Invoke-AiUpgrade managed packages' {
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

        foreach ($functionName in @('Get-GlobalNpmInventory', 'Invoke-AiUpgrade')) {
            $functionAst = $ast.Find({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -eq $functionName
            }, $true)
            if (-not $functionAst) { throw "Could not load $functionName from the profile." }
            . ([scriptblock]::Create($functionAst.Extent.Text))
        }

        function npm {
            param([Parameter(ValueFromRemainingArguments = $true)][object[]]$ArgumentList)
        }
        function winget {
            param([Parameter(ValueFromRemainingArguments = $true)][object[]]$ArgumentList)
        }
    }

    BeforeEach {
        $_AiToolsInternal = @{
            UpgradeCommands        = @()
            WingetPackages         = @('ZhipuAI.ZCode')
            ExtendedWingetPackages = @('Microsoft.VCRedist.2015+.x64')
            SdkWingetPackages      = @()
            DbWingetPackages       = @()
            MoreAiWingetPackages   = @('MiniMax.MiniMaxCode')
            DockerWingetPackage    = 'Docker.DockerDesktop'
            PodmanWingetPackage    = 'RedHat.Podman'
            GitWingetPackage       = 'Git.Git'
            NpmPackages            = @('@earendil-works/pi-coding-agent')
            MoreAiNpmPackages      = @('@qwen-code/qwen-code', '@mimo-ai/cli', '@moonshot-ai/kimi-code')
        }
        $script:npmCalls = @()
        $script:wingetCalls = @()
        $script:wingetOutput = @('No installed package found matching input criteria.')
        $script:wingetExitCode = 0
        $script:startProcessCalls = @()
        $script:upgradeExitCodes = @{}
        $script:inventoryJson = '{"dependencies":{}}'
        $script:outdatedJson = '{}'
        $script:updateExitCode = 0

        Mock Write-Host {}
        Mock Write-Warning {}
        Mock Get-Command {
            if ($Name -in @('npm', 'winget')) { return [pscustomobject]@{ Name = $Name } }
            return $null
        }
        Mock winget {
            param($ArgumentList)
            $script:wingetCalls += [pscustomobject]@{ Args = @($ArgumentList) }
            $global:LASTEXITCODE = $script:wingetExitCode
            return $script:wingetOutput
        }
        Mock Start-Process {
            $script:startProcessCalls += [pscustomobject]@{
                FilePath     = $PesterBoundParameters.FilePath
                ArgumentList = @($PesterBoundParameters.ArgumentList)
            }
            $packageId = @($PesterBoundParameters.ArgumentList)[-1]
            $exitCode = if ($script:upgradeExitCodes.ContainsKey($packageId)) {
                $script:upgradeExitCodes[$packageId]
            }
            else {
                0
            }
            return [pscustomobject]@{ ExitCode = $exitCode }
        }
        Mock npm {
            param($ArgumentList)
            $callArgs = @($ArgumentList)
            $script:npmCalls += [pscustomobject]@{ Args = $callArgs }
            if ($callArgs[0] -eq 'ls') {
                $global:LASTEXITCODE = 0
                return $script:inventoryJson
            }
            if ($callArgs[0] -eq 'outdated') {
                $global:LASTEXITCODE = if ($script:outdatedJson -eq '{}') { 0 } else { 1 }
                return $script:outdatedJson
            }
            $global:LASTEXITCODE = $script:updateExitCode
        }
    }

    It 'reports when no managed npm AI tools are installed' {
        Invoke-AiUpgrade

        @($script:npmCalls | Where-Object { $_.Args[0] -in @('outdated', 'up') }).Count | Should -Be 0
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter {
            $Object -eq '>>> npm: no managed npm packages are installed.'
        }
    }

    It 'discovers installed tools from npm inventory without command probes' {
        $script:inventoryJson = '{"dependencies":{"@qwen-code/qwen-code":{"version":"1.0.0"},"@mimo-ai/cli":{"version":"1.0.0"}}}'

        Invoke-AiUpgrade

        $outdatedCall = @($script:npmCalls | Where-Object { $_.Args[0] -eq 'outdated' })[0]
        $outdatedCall.Args | Should -Be @('outdated', '-g', '--json', '@mimo-ai/cli', '@qwen-code/qwen-code')
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter {
            $Object -eq '>>> npm: all managed npm packages are already up to date.'
        }
    }

    It 'updates only installed packages reported as outdated' {
        $script:inventoryJson = '{"dependencies":{"@qwen-code/qwen-code":{"version":"1.0.0"},"@mimo-ai/cli":{"version":"1.0.0"}}}'
        $script:outdatedJson = '{"@mimo-ai/cli":{"current":"1.0.0","wanted":"2.0.0","latest":"2.0.0"}}'

        Invoke-AiUpgrade

        $updateCall = @($script:npmCalls | Where-Object { $_.Args[0] -eq 'up' })[0]
        $updateCall.Args | Should -Be @('up', '-g', '@mimo-ai/cli')
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter {
            $Object -eq 'npm-managed packages updated successfully.'
        }
    }

    It 'prints a skip message when npm is unavailable' {
        Mock Get-Command { return $null }

        Invoke-AiUpgrade

        $script:npmCalls.Count | Should -Be 0
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter {
            $Object -eq '>>> npm: skipped (npm is not available).'
        }
    }

    It 'skips safely when the npm inventory cannot be parsed' {
        $script:inventoryJson = 'not-json'

        Invoke-AiUpgrade

        @($script:npmCalls | Where-Object { $_.Args[0] -eq 'up' }).Count | Should -Be 0
        Should -Invoke Write-Warning -ParameterFilter { $Message -like 'Could not parse the global npm inventory*' }
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter {
            $Object -eq '>>> npm: skipped (global package inventory is unavailable).'
        }
    }

    It 'warns when an npm update fails' {
        $script:inventoryJson = '{"dependencies":{"@qwen-code/qwen-code":{"version":"1.0.0"}}}'
        $script:outdatedJson = '{"@qwen-code/qwen-code":{"current":"1.0.0","wanted":"2.0.0","latest":"2.0.0"}}'
        $script:updateExitCode = 9

        Invoke-AiUpgrade

        Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter {
            $Message -eq 'npm update failed with exit code 9 for: @qwen-code/qwen-code'
        }
    }

    It 'reports managed Winget updates without installing them by default' {
        $script:wingetOutput = @(
            'Name                  Id                    Version Available',
            '-------------------------------------------------------------',
            'ZCode                 ZhipuAI.ZCode          1.0.0   2.0.0',
            'Unrelated application Vendor.Unrelated      3.0.0   4.0.0'
        )

        Invoke-AiUpgrade

        ($script:wingetCalls[0].Args -join ' ') | Should -Be 'list --upgrade-available --source winget --disable-interactivity'
        $script:startProcessCalls.Count | Should -Be 0
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter {
            $Object -eq ">>> winget: report only; run 'aiu -Winget' to install these updates."
        }
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter {
            $Object -eq '      ZhipuAI.ZCode  1.0.0 -> 2.0.0'
        }
    }

    It 'accepts lowercase -winget and upgrades only reported managed packages' {
        $script:wingetOutput = @(
            'Name         Id                    Version Available Source',
            '-----------------------------------------------------------',
            'ZCode        ZhipuAI.ZCode          1.0.0   2.0.0     winget',
            'MiniMax Code MiniMax.MiniMaxCode    1.1.0   1.2.0     winget',
            'Other        Vendor.Unrelated       3.0.0   4.0.0     winget'
        )

        Invoke-AiUpgrade -winget

        $script:startProcessCalls.Count | Should -Be 2
        ($script:startProcessCalls[0].ArgumentList -join ' ') | Should -Be 'upgrade --source winget --exact --id MiniMax.MiniMaxCode'
        ($script:startProcessCalls[1].ArgumentList -join ' ') | Should -Be 'upgrade --source winget --exact --id ZhipuAI.ZCode'
    }

    It 'matches regex punctuation in an exact managed Winget package ID' {
        $script:wingetOutput = @(
            'Name                  Id                               Version Available Source',
            '----------------------------------------------------------------------------',
            'Visual C++ Runtime    Microsoft.VCRedist.2015+.x64     14.1    14.2      winget'
        )

        Invoke-AiUpgrade -Winget

        $script:startProcessCalls.Count | Should -Be 1
        ($script:startProcessCalls[0].ArgumentList -join ' ') | Should -Be 'upgrade --source winget --exact --id Microsoft.VCRedist.2015+.x64'
    }

    It 'warns on a Winget query failure and continues to npm' {
        $script:wingetExitCode = 7

        Invoke-AiUpgrade -winget

        $script:startProcessCalls.Count | Should -Be 0
        Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter {
            $Message -eq 'Could not query managed Winget updates (exit code 7).'
        }
        @($script:npmCalls | Where-Object { $_.Args[0] -eq 'ls' }).Count | Should -Be 1
    }

    It 'continues after a managed Winget package upgrade fails' {
        $script:wingetOutput = @(
            'Name         Id                    Version Available Source',
            '-----------------------------------------------------------',
            'ZCode        ZhipuAI.ZCode          1.0.0   2.0.0     winget',
            'MiniMax Code MiniMax.MiniMaxCode    1.1.0   1.2.0     winget'
        )
        $script:upgradeExitCodes['MiniMax.MiniMaxCode'] = 9

        Invoke-AiUpgrade -Winget

        $script:startProcessCalls.Count | Should -Be 2
        Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter {
            $Message -eq 'Winget update failed for: MiniMax.MiniMaxCode (exit code 9)'
        }
        @($script:npmCalls | Where-Object { $_.Args[0] -eq 'ls' }).Count | Should -Be 1
    }
}
