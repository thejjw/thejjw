Describe 'Invoke-AiUpgrade npm packages' {
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
    }

    BeforeEach {
        $_AiToolsInternal = @{
            UpgradeCommands = @(
                @{ Label = 'agy'; Cmd = 'agy'; Args = @('update') },
                @{ Label = 'qwen'; Probe = 'qwen'; Cmd = 'npm'; NpmPackage = '@qwen-code/qwen-code' },
                @{ Label = 'mimo'; Probe = 'mimo'; Cmd = 'npm'; NpmPackage = '@mimo-ai/cli' },
                @{ Label = 'kimi'; Probe = 'kimi'; Cmd = 'npm'; NpmPackage = '@moonshot-ai/kimi-code' }
            )
        }
        $script:npmCalls = @()
        $script:inventoryJson = '{"dependencies":{}}'
        $script:outdatedJson = '{}'
        $script:updateExitCode = 0

        Mock Write-Host {}
        Mock Write-Warning {}
        Mock Get-Command {
            if ($Name -eq 'npm') { return [pscustomobject]@{ Name = 'npm' } }
            return $null
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
            $Object -eq '>>> npm: no managed npm AI tools are installed.'
        }
    }

    It 'discovers installed tools from npm inventory without command probes' {
        $script:inventoryJson = '{"dependencies":{"@qwen-code/qwen-code":{"version":"1.0.0"},"@mimo-ai/cli":{"version":"1.0.0"}}}'

        Invoke-AiUpgrade

        $outdatedCall = @($script:npmCalls | Where-Object { $_.Args[0] -eq 'outdated' })[0]
        $outdatedCall.Args | Should -Be @('outdated', '-g', '--json', '@qwen-code/qwen-code', '@mimo-ai/cli')
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter {
            $Object -eq '>>> npm: all managed npm AI tools are already up to date.'
        }
    }

    It 'updates only installed packages reported as outdated' {
        $script:inventoryJson = '{"dependencies":{"@qwen-code/qwen-code":{"version":"1.0.0"},"@mimo-ai/cli":{"version":"1.0.0"}}}'
        $script:outdatedJson = '{"@mimo-ai/cli":{"current":"1.0.0","wanted":"2.0.0","latest":"2.0.0"}}'

        Invoke-AiUpgrade

        $updateCall = @($script:npmCalls | Where-Object { $_.Args[0] -eq 'up' })[0]
        $updateCall.Args | Should -Be @('up', '-g', '@mimo-ai/cli')
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter {
            $Object -eq 'npm-managed AI tools updated successfully.'
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
}
