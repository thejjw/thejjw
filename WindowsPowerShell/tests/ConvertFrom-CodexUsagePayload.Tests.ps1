Describe 'ConvertFrom-CodexUsagePayload' {
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

        foreach ($name in @('Get-AiUsageJsonProperty', 'Get-AiUsageWindowLabel', 'ConvertFrom-CodexUsagePayload')) {
            $functionAst = $ast.Find({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -eq $name
            }, $true)
            if (-not $functionAst) { throw "Could not load $name from the profile." }
            . ([scriptblock]::Create($functionAst.Extent.Text))
        }

        $script:fixturePath = Join-Path $PSScriptRoot 'fixtures\codex-wham-usage.json'
    }

    It 'maps the windows the ChatGPT backend reports' {
        $payload = Get-Content -LiteralPath $script:fixturePath -Raw | ConvertFrom-Json

        $result = ConvertFrom-CodexUsagePayload -Payload $payload

        $result.Plan | Should -Be 'pro'
        $result.Windows.Count | Should -Be 3
        # 3600 seconds is one hour; the label follows the window length, not
        # the position of the slot in the response.
        $result.Windows[0].Window | Should -Be '1 Hour Credits'
        $result.Windows[0].UsedPercent | Should -Be 42
        $result.Windows[0].ResetAt | Should -Be ([DateTimeOffset]::FromUnixTimeSeconds(1735689720))
        $result.Windows[1].Window | Should -Be '1 Day Credits'
        $result.Windows[1].UsedPercent | Should -Be 5
        # The additional metered bucket is reported after the plan windows.
        $result.Windows[2].Window | Should -Be '30 Minute Credits (codex_other)'
        $result.Windows[2].UsedPercent | Should -Be 88
    }

    It 'reads the workspace spend limit' {
        $payload = Get-Content -LiteralPath $script:fixturePath -Raw | ConvertFrom-Json

        $result = ConvertFrom-CodexUsagePayload -Payload $payload

        $result.SpendLimit | Should -Not -BeNullOrEmpty
        $result.SpendLimit.UsedPercent | Should -Be 32
        $result.SpendLimit.RemainingPercent | Should -Be 68
        $result.SpendLimit.Limit | Should -Be '25000'
        $result.SpendLimit.ResetAt | Should -Be ([DateTimeOffset]::FromUnixTimeSeconds(1735693200))
    }

    It 'labels a weekly window by its length when the plan reports only that one' {
        # A Team plan reports the weekly window in primary_window and leaves
        # secondary_window null, so the label must not follow the slot.
        $payload = [pscustomobject]@{
            plan_type = 'team'
            rate_limit = [pscustomobject]@{
                allowed = $true
                limit_reached = $false
                primary_window = [pscustomobject]@{
                    used_percent = 55
                    limit_window_seconds = 604800
                    reset_after_seconds = 3600
                    reset_at = 1735689720
                }
                secondary_window = $null
            }
        }

        $result = ConvertFrom-CodexUsagePayload -Payload $payload

        $result.Windows.Count | Should -Be 1
        $result.Windows[0].Window | Should -Be '7 Day Credits'
        $result.Windows[0].UsedPercent | Should -Be 55
    }

    It 'clamps a used percent above one hundred' {
        $payload = [pscustomobject]@{
            rate_limit = [pscustomobject]@{
                primary_window = [pscustomobject]@{
                    used_percent = 140
                    limit_window_seconds = 18000
                    reset_at = 1735689720
                }
            }
        }

        $result = ConvertFrom-CodexUsagePayload -Payload $payload

        $result.Windows[0].UsedPercent | Should -Be 100
    }

    It 'reports no windows when the payload carries none' {
        $payload = [pscustomobject]@{ plan_type = 'free'; rate_limit = [pscustomobject]@{} }

        $result = ConvertFrom-CodexUsagePayload -Payload $payload

        $result.Windows.Count | Should -Be 0
    }
}
