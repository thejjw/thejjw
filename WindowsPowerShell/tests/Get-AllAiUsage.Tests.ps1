Describe 'Get-AllAiUsage discovery and execution' {
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

        $functionAst = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'Get-AllAiUsage'
        }, $true)
        if (-not $functionAst) { throw 'Could not load Get-AllAiUsage from the profile.' }
        . ([scriptblock]::Create($functionAst.Extent.Text))

        function Get-AlphaUsage {
            $script:invocations.Add('Alpha')
            'alpha-result'
        }

        function Get-BrokenUsage {
            $script:invocations.Add('Broken')
            throw 'provider unavailable'
        }

        function Get-ZuluUsage {
            $script:invocations.Add('Zulu')
            'zulu-result'
        }

        $script:alphaCommand = Microsoft.PowerShell.Core\Get-Command Get-AlphaUsage -CommandType Function
        $script:brokenCommand = Microsoft.PowerShell.Core\Get-Command Get-BrokenUsage -CommandType Function
        $script:zuluCommand = Microsoft.PowerShell.Core\Get-Command Get-ZuluUsage -CommandType Function
        $script:allCommand = Microsoft.PowerShell.Core\Get-Command Get-AllAiUsage -CommandType Function

        $Global:_ProfileHelpers = [pscustomobject]@{}
        $Global:_ProfileHelpers | Add-Member -MemberType ScriptMethod -Name WriteUsageTimestamp -Value {
            param($CommandName)
        }
    }

    AfterAll {
        Remove-Variable -Name _ProfileHelpers -Scope Global -ErrorAction SilentlyContinue
    }

    BeforeEach {
        $script:invocations = [System.Collections.Generic.List[string]]::new()
        $script:candidates = @($script:zuluCommand, $script:allCommand, $script:alphaCommand)

        Mock Get-Command { $script:candidates }
        Mock Read-Host { 'n' }
        Mock Write-Host {}
        Mock Write-Warning {}
    }

    It 'discovers imported functions and excludes itself from the displayed list' {
        Get-AllAiUsage

        Should -Invoke Get-Command -Times 1 -Exactly -ParameterFilter {
            $Name -eq 'Get-*Usage' -and
                $CommandType -eq 'Function' -and
                $ListImported -and
                $ErrorAction -eq 'SilentlyContinue'
        }
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter {
            $Object -eq '  1. Get-AlphaUsage'
        }
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter {
            $Object -eq '  2. Get-ZuluUsage'
        }
        Should -Invoke Write-Host -Times 0 -Exactly -ParameterFilter {
            $Object -like '*. Get-AllAiUsage*'
        }
    }

    It 'uses an empty response as Yes and runs functions in displayed order' {
        Mock Read-Host { '' }

        $result = @(Get-AllAiUsage)

        $script:invocations | Should -Be @('Alpha', 'Zulu')
        $result | Should -Be @('alpha-result', 'zulu-result')
    }

    It 'cancels without invoking any discovered function' {
        Mock Read-Host { 'No' }

        Get-AllAiUsage

        $script:invocations.Count | Should -Be 0
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter {
            $Object -eq 'AI usage queries cancelled.'
        }
    }

    It 'reprompts after invalid input' {
        $script:responses = [System.Collections.Generic.Queue[string]]::new()
        $script:responses.Enqueue('maybe')
        $script:responses.Enqueue('yes')
        Mock Read-Host { $script:responses.Dequeue() }

        Get-AllAiUsage

        Should -Invoke Read-Host -Times 2 -Exactly
        Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter {
            $Message -eq 'Enter Y or N, or press Enter to accept the default (Y).'
        }
        $script:invocations | Should -Be @('Alpha', 'Zulu')
    }

    It 'returns without prompting when no matching functions are loaded' {
        $script:candidates = @($script:allCommand)

        Get-AllAiUsage

        Should -Invoke Read-Host -Times 0 -Exactly
        $script:invocations.Count | Should -Be 0
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter {
            $Object -eq 'No other Get-*Usage functions are currently loaded.'
        }
    }

    It 'warns on a terminating failure and continues with later functions' {
        $script:candidates = @($script:zuluCommand, $script:brokenCommand)
        Mock Read-Host { 'y' }

        $result = @(Get-AllAiUsage)

        $script:invocations | Should -Be @('Broken', 'Zulu')
        $result | Should -Be @('zulu-result')
        Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter {
            $Message -eq 'Get-BrokenUsage failed: provider unavailable'
        }
    }
}
