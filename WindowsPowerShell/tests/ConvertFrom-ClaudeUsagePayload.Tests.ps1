Describe 'ConvertFrom-ClaudeUsagePayload' {
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

        foreach ($name in @('Get-AiUsageJsonProperty', 'ConvertFrom-ClaudeUsagePayload')) {
            $functionAst = $ast.Find({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -eq $name
            }, $true)
            if (-not $functionAst) { throw "Could not load $name from the profile." }
            . ([scriptblock]::Create($functionAst.Extent.Text))
        }

        $script:flatPath = Join-Path $PSScriptRoot 'fixtures\claude-oauth-usage-flat.json'
        $script:limitsPath = Join-Path $PSScriptRoot 'fixtures\claude-oauth-usage-limits.json'
    }

    It 'maps the flat window shape' {
        $payload = Get-Content -LiteralPath $script:flatPath -Raw | ConvertFrom-Json

        $result = ConvertFrom-ClaudeUsagePayload -Payload $payload

        $result.Windows.Count | Should -Be 3
        $result.Windows[0].Window | Should -Be '5 Hour Credits'
        $result.Windows[0].UsedPercent | Should -Be 33
        $result.Windows[1].Window | Should -Be '7 Day Credits'
        $result.Windows[1].UsedPercent | Should -Be 13
        $result.Windows[2].Window | Should -Be '7 Day Credits (Sonnet)'
        $result.Windows[2].UsedPercent | Should -Be 1
    }

    It 'skips a window the console reports as null' {
        # The console reports the legacy per-model weekly buckets as null.
        $payload = Get-Content -LiteralPath $script:flatPath -Raw | ConvertFrom-Json

        $result = ConvertFrom-ClaudeUsagePayload -Payload $payload

        @($result.Windows | Where-Object { $_.Window -like '*Opus*' }).Count | Should -Be 0
    }

    It 'maps the limits array shape' {
        $payload = Get-Content -LiteralPath $script:limitsPath -Raw | ConvertFrom-Json

        $result = ConvertFrom-ClaudeUsagePayload -Payload $payload

        $result.Windows.Count | Should -Be 3
        $result.Windows[0].Window | Should -Be '5 Hour Credits'
        $result.Windows[0].UsedPercent | Should -Be 35.5
        $result.Windows[1].Window | Should -Be '7 Day Credits'
        $result.Windows[1].UsedPercent | Should -Be 12.25
        $result.Windows[2].Window | Should -Be '7 Day Credits (Fable)'
        $result.Windows[2].UsedPercent | Should -Be 4.5
        $result.ExtraPercent | Should -Be 17.5
    }

    It 'reports a window once when the payload carries both shapes' {
        # The console returns the flat five_hour and seven_day objects next to
        # the limits array, and they describe the same windows.
        $payload = Get-Content -LiteralPath $script:limitsPath -Raw | ConvertFrom-Json

        $result = ConvertFrom-ClaudeUsagePayload -Payload $payload

        $result.Windows.Count | Should -Be 3
        @($result.Windows | Where-Object { $_.Window -eq '5 Hour Credits' }).Count | Should -Be 1
        @($result.Windows | Where-Object { $_.Window -eq '7 Day Credits' }).Count | Should -Be 1
    }

    It 'keeps the reset deadline that the limits array reports' {
        # The flat five_hour object carries a null reset while the limits
        # array entry carries the real one.
        $payload = Get-Content -LiteralPath $script:limitsPath -Raw | ConvertFrom-Json

        $result = ConvertFrom-ClaudeUsagePayload -Payload $payload

        $result.Windows[0].ResetAt | Should -BeOfType [DateTimeOffset]
        $result.Windows[0].ResetAt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss') | Should -Be '2026-09-11T03:38:39'
    }

    It 'ignores extra usage on a plan that has not enabled it' {
        $payload = [pscustomobject]@{
            extra_usage = [pscustomobject]@{
                is_enabled = $false
                monthly_limit = 100
                used_credits = 0.0
                utilization = 0.0
                currency = 'USD'
            }
        }

        $result = ConvertFrom-ClaudeUsagePayload -Payload $payload

        $result.ExtraPercent | Should -BeNullOrEmpty
    }

    It 'parses the reset deadline as a local time' {
        $payload = Get-Content -LiteralPath $script:limitsPath -Raw | ConvertFrom-Json

        $result = ConvertFrom-ClaudeUsagePayload -Payload $payload

        $result.Windows[0].ResetAt | Should -BeOfType [DateTimeOffset]
        $result.Windows[0].ResetAt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss') | Should -Be '2026-09-11T03:38:39'
    }

    It 'keeps a fractional percentage instead of truncating it' {
        $payload = Get-Content -LiteralPath $script:limitsPath -Raw | ConvertFrom-Json

        $result = ConvertFrom-ClaudeUsagePayload -Payload $payload

        $result.Windows[0].UsedPercent | Should -Be 35.5
    }

    It 'reports no windows when the payload carries none' {
        $result = ConvertFrom-ClaudeUsagePayload -Payload ([pscustomobject]@{ extra_usage = [pscustomobject]@{ is_enabled = $false } })

        $result.Windows.Count | Should -Be 0
    }
}
