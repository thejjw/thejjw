Describe 'Get-CodexUsage' {
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

        foreach ($name in @('Get-CodexUsage')) {
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

        $script:fixture = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures\codex-wham-usage.json') -Raw | ConvertFrom-Json
    }

    AfterAll {
        Remove-Variable -Name codexLastQuery -Scope Global -ErrorAction SilentlyContinue
    }

    BeforeEach {
        $script:originalCodexHome = $env:CODEX_HOME
        $script:originalAccessToken = $env:CODEX_ACCESS_TOKEN
        $env:CODEX_ACCESS_TOKEN = $null
        $script:queriedToken = $null
        $script:hostMessages = [System.Collections.Generic.List[string]]::new()
        $script:codexHome = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $script:codexHome -Force
        $env:CODEX_HOME = $script:codexHome
        Mock Write-Host { [void]$script:hostMessages.Add([string]$Object) }
        Mock Out-Host {}
        $Error.Clear()
    }

    AfterEach {
        $env:CODEX_HOME = $script:originalCodexHome
        $env:CODEX_ACCESS_TOKEN = $script:originalAccessToken
    }

    It 'reads the access token from the Codex auth store' {
        Set-Content -LiteralPath (Join-Path $script:codexHome 'auth.json') -Encoding UTF8 -Value (@{
            auth_mode = 'chatgpt'
            tokens = @{
                access_token = 'stored-access-token'
                refresh_token = 'stored-refresh-token'
                account_id = 'stored-account-id'
            }
        } | ConvertTo-Json -Depth 5)
        $query = {
            param($token)
            $script:queriedToken = $token
            return $script:fixture
        }

        Get-CodexUsage -QueryInvoker $query

        $script:queriedToken | Should -Be 'stored-access-token'
        $Global:codexLastQuery.plan_type | Should -Be 'pro'
    }

    It 'takes the account id from the id token claim when the store omits it' {
        $claims = @{ 'https://api.openai.com/auth' = @{ chatgpt_account_id = 'claim-account-id' } }
        $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($claims | ConvertTo-Json -Compress -Depth 5)))
        $payload = $payload.TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $idToken = "header.$payload.signature"
        Set-Content -LiteralPath (Join-Path $script:codexHome 'auth.json') -Encoding UTF8 -Value (@{
            tokens = @{ access_token = 'stored-access-token'; id_token = $idToken }
        } | ConvertTo-Json -Depth 5)
        $script:queriedAccountId = $null
        $query = {
            param($token, $accountId)
            $script:queriedToken = $token
            $script:queriedAccountId = $accountId
            return $script:fixture
        }

        Get-CodexUsage -QueryInvoker $query

        $script:queriedToken | Should -Be 'stored-access-token'
        $script:queriedAccountId | Should -Be 'claim-account-id'
    }

    It 'reports a missing credential with actionable guidance' {
        Get-CodexUsage -ErrorAction SilentlyContinue

        $Error[0].Exception.Message | Should -BeLike '*No Codex access token found*codex login*'
    }

    It 'refuses thresholds that put the critical level below the low level' {
        Get-CodexUsage -LowPercent 90 -CriticalPercent 50 -ErrorAction SilentlyContinue

        $Error[0].Exception.Message | Should -BeLike '*CriticalPercent must be greater than or equal to LowPercent*'
    }
}
