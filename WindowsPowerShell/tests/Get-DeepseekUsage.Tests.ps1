Describe 'Get-DeepseekUsage' {
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
                $node.Name -eq 'Get-DeepseekUsage'
        }, $true)
        if (-not $functionAst) { throw 'Could not load Get-DeepseekUsage from the profile.' }

        . ([scriptblock]::Create($functionAst.Extent.Text))

        # The profile helper module is loaded whole, so the function under test
        # finds every helper it calls. The members that write to the host are
        # then replaced with stubs, because a module's own Write-Host cannot be
        # intercepted from the test scope.
        $helperAssignment = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left.Extent.Text -eq '$_ProfileHelpers'
        }, $true)
        if (-not $helperAssignment) { throw 'Could not load the profile helper module.' }
        . ([scriptblock]::Create($helperAssignment.Extent.Text))
        $_ProfileHelpers | Add-Member -MemberType ScriptMethod -Name WriteUsageTimestamp -Force -Value { param($CommandName) }
        $_ProfileHelpers | Add-Member -MemberType ScriptMethod -Name WriteSection -Force -Value {
            param($Title)
            [void]$script:sections.Add($Title)
        }
        $_ProfileHelpers | Add-Member -MemberType ScriptMethod -Name FormatTokens -Force -Value {
            param([double]$Value)
            if ($Value -le 0) { return '0' }
            if ($Value -ge 1e9) { return ('{0:N2}B' -f ($Value / 1e9)) }
            if ($Value -ge 1e6) { return ('{0:N2}M' -f ($Value / 1e6)) }
            if ($Value -ge 1e3) { return ('{0:N2}K' -f ($Value / 1e3)) }
            return ('{0:N0}' -f $Value)
        }
        $_ProfileHelpers | Add-Member -MemberType ScriptMethod -Name FormatPrice -Force -Value {
            param([double]$Value)
            $s = ('{0:N6}' -f $Value).TrimEnd('0')
            if ($s.EndsWith('.')) { $s = $s.Substring(0, $s.Length - 1) }
            return $s
        }
    }

    AfterAll {
        Remove-Variable -Name _ProfileHelpers -Scope Global -ErrorAction SilentlyContinue
        Remove-Variable -Name deepseekLastQuery -Scope Global -ErrorAction SilentlyContinue
    }

    BeforeEach {
        $script:sections = [System.Collections.Generic.List[string]]::new()
        $script:hostMessages = [System.Collections.Generic.List[string]]::new()
        $script:outHostObjects = [System.Collections.Generic.List[object]]::new()

        Remove-Variable -Name deepseekLastQuery -Scope Global -ErrorAction SilentlyContinue

        Mock Write-Host { [void]$script:hostMessages.Add([string]$Object) }
        Mock Out-Host {
            if ($Input) {
                foreach ($item in $Input) { [void]$script:outHostObjects.Add($item) }
            }
        }
    }

    It 'fails when DEEPSEEK_API_KEY is not provided' {
        Mock Write-Error {}
        Get-DeepseekUsage -ApiKey $null

        Should -Invoke Write-Error -Times 1 -Exactly -ParameterFilter {
            $Message -match 'DEEPSEEK_API_KEY not set'
        }
    }

    It 'queries balance endpoint and computes token and tool request budgets' {
        $mockResp = [pscustomobject]@{
            is_available  = $true
            balance_infos = @(
                [pscustomobject]@{
                    currency           = 'USD'
                    total_balance      = '7.50'
                    granted_balance    = '0.00'
                    topped_up_balance  = '7.50'
                }
            )
        }

        Mock Invoke-RestMethod { $mockResp }

        $res = Get-DeepseekUsage -ApiKey 'test-key'

        $res.is_available | Should -Be $true
        $Global:deepseekLastQuery.is_available | Should -Be $true

        # Verify sections include both token and tool request budgets
        $script:sections | Should -Contain 'Raw API response (DeepSeek)'
        $script:sections | Should -Contain 'Balance summary (DeepSeek)'
        $script:sections | Should -Contain 'Estimated USD token budget (DeepSeek)'
        $script:sections | Should -Contain 'Estimated USD tool request budget (DeepSeek)'
        $script:sections | Should -Contain 'Concerns (DeepSeek)'

        # Verify footnote messages
        $script:hostMessages | Should -Contain '  Estimate formula: tokens = balance / cost_per_1M * 1,000,000; requests = balance / cost_per_1K * 1,000.'
        $script:hostMessages | Should -Contain '  Actual spend depends on cache-hit ratio, prompt size, output length, tool requests, and model mix.'
        $script:hostMessages | Should -Contain '  No concerns flagged.'
    }

    It 'flags low balance concern when USD balance is below threshold' {
        $mockResp = [pscustomobject]@{
            is_available  = $true
            balance_infos = @(
                [pscustomobject]@{
                    currency           = 'USD'
                    total_balance      = '2.50'
                    granted_balance    = '0.00'
                    topped_up_balance  = '2.50'
                }
            )
        }

        Mock Invoke-RestMethod { $mockResp }

        Get-DeepseekUsage -ApiKey 'test-key' -LowBalanceUsd 5.0

        $script:hostMessages | Should -Contain '  - [LOW] USD balance $2.50 at or below threshold $5.00'
    }
}
