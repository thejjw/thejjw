Describe 'Get-ClaudeUsage' {
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

        foreach ($name in @('Get-ClaudeUsage')) {
            $functionAst = $ast.Find({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -eq $name
            }, $true)
            if (-not $functionAst) { throw "Could not load $name from the profile." }
            . ([scriptblock]::Create($functionAst.Extent.Text))
        }

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

        $_ProfileHelpers | Add-Member -MemberType ScriptMethod -Name WriteUsageTimestamp -Value { param($CommandName) } -Force
        $_ProfileHelpers | Add-Member -MemberType ScriptMethod -Name WriteSection -Value { param($Title) } -Force

        $script:fixture = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures\claude-oauth-usage-flat.json') -Raw | ConvertFrom-Json
    }

    AfterAll {
        Remove-Variable -Name claudeLastQuery -Scope Global -ErrorAction SilentlyContinue
    }

    BeforeEach {
        $script:originalConfigDir = $env:CLAUDE_CONFIG_DIR
        $script:originalToken = $env:CLAUDE_CODE_OAUTH_TOKEN
        $env:CLAUDE_CODE_OAUTH_TOKEN = $null
        $script:queriedToken = $null
        $script:hostMessages = [System.Collections.Generic.List[string]]::new()
        $script:claudeDir = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $script:claudeDir -Force
        $env:CLAUDE_CONFIG_DIR = $script:claudeDir
        Mock Write-Host { [void]$script:hostMessages.Add([string]$Object) }
        Mock Out-Host {}
        $Error.Clear()
    }

    AfterEach {
        $env:CLAUDE_CONFIG_DIR = $script:originalConfigDir
        $env:CLAUDE_CODE_OAUTH_TOKEN = $script:originalToken
    }

    It 'reads the access token from the Claude credential store' {
        Set-Content -LiteralPath (Join-Path $script:claudeDir '.credentials.json') -Encoding UTF8 -Value (@{
            claudeAiOauth = @{
                accessToken = 'stored-claude-token'
                refreshToken = 'stored-claude-refresh'
                expiresAt = 1790000000000
                scopes = @('user:profile', 'user:inference')
                subscriptionType = 'max'
                rateLimitTier = 'default_claude_max_20x'
            }
        } | ConvertTo-Json -Depth 5)
        $query = {
            param($token)
            $script:queriedToken = $token
            return $script:fixture
        }

        Get-ClaudeUsage -QueryInvoker $query

        $script:queriedToken | Should -Be 'stored-claude-token'
        $Global:claudeLastQuery.five_hour.utilization | Should -Be 33
    }

    It 'reports a missing credential with actionable guidance' {
        Get-ClaudeUsage -ErrorAction SilentlyContinue

        $Error[0].Exception.Message | Should -BeLike '*No Claude access token found*claude login*'
    }

    It 'refuses thresholds that put the critical level below the low level' {
        Get-ClaudeUsage -LowPercent 90 -CriticalPercent 50 -ErrorAction SilentlyContinue

        $Error[0].Exception.Message | Should -BeLike '*CriticalPercent must be greater than or equal to LowPercent*'
    }
}
