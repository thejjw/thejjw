Describe 'Get-KimiUsage' {
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
                $node.Name -eq 'Get-KimiUsage'
        }, $true)
        if (-not $functionAst) { throw 'Could not load Get-KimiUsage from the profile.' }

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
        $script:kimiJson = Get-Content (Join-Path $fixtures 'kimi_usages.json') -Raw
    }

    AfterAll {
        Remove-Variable -Name _ProfileHelpers -Scope Global -ErrorAction SilentlyContinue
        Remove-Variable -Name kimiLastQuery -Scope Global -ErrorAction SilentlyContinue
    }

    BeforeEach {
        $script:sections = [System.Collections.Generic.List[string]]::new()
        $script:hostMessages = [System.Collections.Generic.List[string]]::new()
        $script:outHostObjects = [System.Collections.Generic.List[object]]::new()

        Remove-Variable -Name kimiLastQuery -Scope Global -ErrorAction SilentlyContinue

        Mock Write-Host { [void]$script:hostMessages.Add([string]$Object) }
        # Format-Table would emit formatting records; pass the row objects
        # through so assertions can read their properties.
        Mock Format-Table { $_ }
        Mock Out-Host { [void]$script:outHostObjects.Add($InputObject) }
    }

    It 'prefers the precomputed usages block and labels 5h/Weekly' {
        # The fixture's resets are frozen timestamps; pin the clock so the
        # 'from now' rendering never ages out.
        Mock Get-Date { [datetime]'2026-11-12T00:00:00' }
        Mock Invoke-RestMethod { $script:kimiJson | ConvertFrom-Json }

        Get-KimiUsage -ApiKey 'test-key'

        $rows = @($script:outHostObjects | Where-Object { $_.PSObject.Properties['Window'] })
        $rows.Count | Should -Be 2
        $rows[0].Window | Should -Be '5h'
        $rows[0].Used | Should -Be '0.00% used'
        $rows[0].Remaining_Percent | Should -Be '100.0%'
        $rows[1].Window | Should -Be 'Weekly'
        # used_ratio 0.0006 -> 99.94% remaining, invariant decimal point.
        $rows[1].Remaining_Percent | Should -Be '99.9%'
        $rows[0].Reset | Should -Match '\d{4}-\d{2}-\d{2} \d{2}:\d{2}'
        $rows[1].Reset | Should -Match 'from now'
    }

    It 'falls back to usage + limits when usages is absent' {
        $resp = $script:kimiJson | ConvertFrom-Json
        $resp.PSObject.Properties.Remove('usages')
        Mock Invoke-RestMethod { $resp }

        Get-KimiUsage -ApiKey 'test-key'

        $rows = @($script:outHostObjects | Where-Object { $_.PSObject.Properties['Window'] })
        $rows.Count | Should -Be 2
        $rows[0].Window | Should -Be 'Weekly limit'
        # 300 MINUTE renders as hours, not "300 min".
        $rows[1].Window | Should -Match '5h limit'
        $rows[1].Remaining_Percent | Should -Be '100.0%'
    }

    It 'normalizes string, epoch-seconds and epoch-milliseconds resets to the same instant' {
        $fromIso   = $_ProfileHelpers.ConvertToResetTime('2026-11-11T12:32:09Z')
        $fromSecs  = $_ProfileHelpers.ConvertToResetTime(1794400329)
        $fromMilli = $_ProfileHelpers.ConvertToResetTime(1794400329000)

        $fromIso.DateTime | Should -Be $fromMilli.DateTime
        $fromSecs.DateTime | Should -Be $fromMilli.DateTime
        $fromMilli | Should -BeOfType [DateTimeOffset]
    }
}
