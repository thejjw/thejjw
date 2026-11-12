Describe 'Get-ZaiUsage' {
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
                $node.Name -eq 'Get-ZaiUsage'
        }, $true)
        if (-not $functionAst) { throw 'Could not load Get-ZaiUsage from the profile.' }

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

        # Same payload the Linux implementation tests against.
        $fixtures = Join-Path $PSScriptRoot '..\..\hermes\aiusage\tests\fixtures'
        $script:quotaJson = Get-Content (Join-Path $fixtures 'zai_quota-limit.json') -Raw
        # Same fixture with one tool counter made non-zero.
        $script:quotaJsonWithDetails = $script:quotaJson -replace
            '\{"modelCode":"search-prime","usage":0\}',
            '{"modelCode":"search-prime","usage":5}'
    }

    AfterAll {
        Remove-Variable -Name _ProfileHelpers -Scope Global -ErrorAction SilentlyContinue
        Remove-Variable -Name zaiLastQuery -Scope Global -ErrorAction SilentlyContinue
    }

    BeforeEach {
        $script:sections = [System.Collections.Generic.List[string]]::new()
        $script:hostMessages = [System.Collections.Generic.List[string]]::new()
        $script:outHostObjects = [System.Collections.Generic.List[object]]::new()

        Remove-Variable -Name zaiLastQuery -Scope Global -ErrorAction SilentlyContinue

        Mock Write-Host { [void]$script:hostMessages.Add([string]$Object) }
        # Format-Table would emit formatting records; pass the row objects
        # through so assertions can read their properties.
        Mock Format-Table { $_ }
        Mock Out-Host { [void]$script:outHostObjects.Add($InputObject) }
    }

    It 'surfaces success:false with code 1001 instead of rendering zero usage' {
        Mock Invoke-RestMethod {
            [pscustomobject]@{ code = 1001; msg = 'invalid api key'; success = $false }
        }
        Mock Write-Error { [void]$script:hostMessages.Add('ERR: ' + $Message) }

        Get-ZaiUsage -Token 'invalid'

        Should -Invoke Write-Error -Times 1 -Exactly -ParameterFilter {
            $Message -match 'code 1001'
        }
        $script:outHostObjects | Should -BeNullOrEmpty
        $script:hostMessages | Should -Not -Contain 'ERR: API call failed'
    }

    It 'renders quota rows with reset time and explicit reset-not-reported' {
        Mock Invoke-RestMethod {
            if ($Uri -match 'quota/limit') { return ($script:quotaJson | ConvertFrom-Json) }
            return $null
        }

        Get-ZaiUsage -Token 'test-key'

        $rows = @($script:outHostObjects | Where-Object { $_.PSObject.Properties['Type'] })
        $rows.Count | Should -Be 2
        $rows[0].Type | Should -Be 'TIME_LIMIT'
        $rows[0].Reset | Should -Match '\d{4}-\d{2}-\d{2} \d{2}:\d{2}'
        # TOKENS_LIMIT carries no nextResetTime: say so instead of "(window)".
        $rows[1].Type | Should -Be 'TOKENS_LIMIT'
        $rows[1].Reset | Should -Be 'reset not reported (5h rolling)'
    }

    It 'emits per-tool lines for non-zero usageDetails' {
        Mock Invoke-RestMethod {
            if ($Uri -match 'quota/limit') { return ($script:quotaJsonWithDetails | ConvertFrom-Json) }
            return $null
        }

        Get-ZaiUsage -Token 'test-key'

        $script:hostMessages | Should -Contain '    [1mo] search-prime: 5'
    }
}
