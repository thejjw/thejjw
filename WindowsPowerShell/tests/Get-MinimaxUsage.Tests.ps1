Describe 'Get-MinimaxUsage' {
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
                $node.Name -eq 'Get-MinimaxUsage'
        }, $true)
        if (-not $functionAst) { throw 'Could not load Get-MinimaxUsage from the profile.' }

        . ([scriptblock]::Create($functionAst.Extent.Text))

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
        $_ProfileHelpers | Add-Member -MemberType ScriptMethod -Name FormatDuration -Force -Value {
            param($Delta)
            return ('{0:dd}d{0:hh}h' -f $Delta)
        }

        # Same payload the Linux implementation tests against.
        $fixtures = Join-Path $PSScriptRoot '..\..\hermes\aiusage\tests\fixtures'
        $script:minimaxJson = Get-Content (Join-Path $fixtures 'minimax_token_plan.json') -Raw
    }

    AfterAll {
        Remove-Variable -Name _ProfileHelpers -Scope Global -ErrorAction SilentlyContinue
        Remove-Variable -Name minimaxLastQuery -Scope Global -ErrorAction SilentlyContinue
    }

    BeforeEach {
        $script:sections = [System.Collections.Generic.List[string]]::new()
        $script:hostMessages = [System.Collections.Generic.List[string]]::new()
        $script:outHostObjects = [System.Collections.Generic.List[object]]::new()

        Remove-Variable -Name minimaxLastQuery -Scope Global -ErrorAction SilentlyContinue

        Mock Write-Host { [void]$script:hostMessages.Add([string]$Object) }
        # Format-Table would emit formatting records; pass the row objects
        # through so assertions can read their properties.
        Mock Format-Table { $_ }
        Mock Out-Host { [void]$script:outHostObjects.Add($InputObject) }
    }

    It 'queries the token plan endpoint with auth header and 20s timeout' {
        Mock Invoke-RestMethod { $script:minimaxJson | ConvertFrom-Json }

        Get-MinimaxUsage -ApiKey 'test-key'

        Should -Invoke Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
            $Uri -eq 'https://www.minimax.io/v1/token_plan/remains' -and
            $Headers['Authorization'] -eq 'Bearer test-key' -and
            $TimeoutSec -eq 20
        }
    }

    It 'writes explicit no-countable-quota cells instead of blank burn math' {
        Mock Invoke-RestMethod { $script:minimaxJson | ConvertFrom-Json }

        Get-MinimaxUsage -ApiKey 'test-key'

        $rows = @($script:outHostObjects | Where-Object { $_.PSObject.Properties['Model'] })
        $rows.Count | Should -Be 2
        $general = $rows | Where-Object { $_.Model -eq 'general' }
        $general.Interval_Used | Should -Be 'no countable quota (total=0)'
        $general.Weekly_Used | Should -Be 'no countable quota (total=0)'
        $general.Alerts | Should -Not -Match 'BURN'
        # The video row carries countable totals and gets real burn cells.
        $video = $rows | Where-Object { $_.Model -eq 'video' }
        $video.Interval_Used | Should -Not -Match 'no countable quota'
    }
}
