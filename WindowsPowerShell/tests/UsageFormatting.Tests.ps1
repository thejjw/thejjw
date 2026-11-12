Describe 'Usage numeric formatting across cultures' {
    BeforeAll {
        $profilePath = Join-Path $PSScriptRoot '..\Microsoft.PowerShell_profile.ps1'
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($profilePath, [ref]$tokens, [ref]$errors)
        if ($errors) { throw "Profile contains parse errors: $($errors -join '; ')" }
        $helperAssignment = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left.Extent.Text -eq '$_ProfileHelpers'
        }, $true)
        if (-not $helperAssignment) { throw 'Could not load the profile helper module.' }
        . ([scriptblock]::Create($helperAssignment.Extent.Text))
        foreach ($name in @('Get-MinimaxUsage', 'Get-ZaiUsage', 'Get-DeepseekUsage', 'Get-KimiUsage')) {
            $functionAst = $ast.Find({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
            }, $true)
            if (-not $functionAst) { throw "Could not load $name from the profile." }
            . ([scriptblock]::Create($functionAst.Extent.Text))
        }
        $_ProfileHelpers | Add-Member -MemberType ScriptMethod -Name WriteUsageTimestamp -Force -Value { param($CommandName) }
        $_ProfileHelpers | Add-Member -MemberType ScriptMethod -Name WriteSection -Force -Value { param($Title) }
        $fixtures = Join-Path $PSScriptRoot '..\..\hermes\aiusage\tests\fixtures'
        $script:usageFixtureJson = @{}
        foreach ($name in @('minimax_token_plan', 'zai_model-usage', 'zai_tool-usage', 'zai_quota-limit', 'deepseek_balance', 'kimi_usages')) {
            $script:usageFixtureJson[$name] = Get-Content -LiteralPath (Join-Path $fixtures ($name + '.json')) -Raw
        }
        # Keep culture changes local even if an assertion or a mocked request fails.
        function Invoke-UsageCulture {
            param([string]$Culture, [scriptblock]$Body)
            $previousCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
            try {
                [System.Threading.Thread]::CurrentThread.CurrentCulture = [cultureinfo]::GetCultureInfo($Culture)
                & $Body
            } finally {
                [System.Threading.Thread]::CurrentThread.CurrentCulture = $previousCulture
            }
        }
    }

    BeforeEach {
        $script:hostMessages = [System.Collections.Generic.List[string]]::new()
        $script:usageRows = [System.Collections.Generic.List[object]]::new()
        $script:usageNow = [datetime]'2026-11-12T00:00:00'
        Mock Write-Host { [void]$script:hostMessages.Add([string]$Object) }
        Mock Format-Table { $_ }
        Mock Out-Host { [void]$script:usageRows.Add($InputObject) }
        Mock Get-Date { $script:usageNow }
    }

    AfterAll {
        foreach ($name in @('_ProfileHelpers', 'minimaxLastQuery', 'zaiLastQuery', 'deepseekLastQuery', 'kimiLastQuery')) {
            Remove-Variable -Name $name -Scope Global -ErrorAction SilentlyContinue
        }
    }

    It 'keeps real numeric helpers invariant under <Culture>' -TestCases @(@{ Culture = 'en-US' }, @{ Culture = 'de-DE' }, @{ Culture = 'ko-KR' }) {
        param($Culture)
        Invoke-UsageCulture $Culture {
            $_ProfileHelpers.FormatInvariant(1234.5, 'N2') | Should -BeExactly '1,234.50'
            $_ProfileHelpers.FormatInvariant(1234.5, 'G') | Should -BeExactly '1234.5'
            $_ProfileHelpers.FormatTokens(1250) | Should -BeExactly '1.25K'
            $_ProfileHelpers.FormatPrice(1) | Should -BeExactly '1'
            $_ProfileHelpers.FormatPrice(0) | Should -BeExactly '0'
            $_ProfileHelpers.FormatPrice(1.25) | Should -BeExactly '1.25'
        }
    }

    It 'keeps MiniMax burn ratios invariant under <Culture>' -TestCases @(@{ Culture = 'en-US' }, @{ Culture = 'de-DE' }, @{ Culture = 'ko-KR' }) {
        param($Culture)
        Invoke-UsageCulture $Culture {
            $script:providerResponse = $script:usageFixtureJson['minimax_token_plan'] | ConvertFrom-Json
            $video = $script:providerResponse.model_remains[1]
            $video.start_time = ([DateTimeOffset]$script:usageNow.AddHours(-1)).ToUnixTimeMilliseconds()
            $video.end_time = ([DateTimeOffset]$script:usageNow.AddHours(1)).ToUnixTimeMilliseconds()
            $video.weekly_start_time = ([DateTimeOffset]$script:usageNow.AddDays(-1)).ToUnixTimeMilliseconds()
            $video.weekly_end_time = ([DateTimeOffset]$script:usageNow.AddDays(1)).ToUnixTimeMilliseconds()
            $video.current_interval_usage_count = 3
            $video.current_interval_total_count = 4
            $video.current_weekly_usage_count = 7
            $video.current_weekly_total_count = 10
            Mock Invoke-RestMethod { $script:providerResponse }
            $null = Get-MinimaxUsage -ApiKey 'offline-test-key'
            $row = $script:usageRows | Where-Object { $_.Model -eq 'video' }
            $row.Interval_Used | Should -BeExactly '3/4 (burn 1.50x)'
            $row.Weekly_Used | Should -BeExactly '7/10 (burn 1.40x)'
            $row.Alerts | Should -BeExactly 'INTERVAL BURN > LINEAR, WEEKLY BURN > LINEAR'
        }
    }

    It 'keeps Zai averages, counts and spike warnings invariant under <Culture>' -TestCases @(@{ Culture = 'en-US' }, @{ Culture = 'de-DE' }, @{ Culture = 'ko-KR' }) {
        param($Culture)
        Invoke-UsageCulture $Culture {
            $script:zaiModel = $script:usageFixtureJson['zai_model-usage'] | ConvertFrom-Json
            $script:zaiTool = $script:usageFixtureJson['zai_tool-usage'] | ConvertFrom-Json
            $script:zaiQuota = $script:usageFixtureJson['zai_quota-limit'] | ConvertFrom-Json
            $script:zaiTool.data.networkSearchCount[0] = 10
            $script:zaiTool.data.networkSearchCount[1] = 2
            $script:zaiQuota.data.limits[0].currentValue = 12.5
            $script:zaiQuota.data.limits[0].usage = 4000.25
            $script:zaiQuota.data.limits[0].usageDetails[0].usage = 5.25
            Mock Invoke-RestMethod {
                if ($Uri -match '/model-usage') { return $script:zaiModel }
                if ($Uri -match '/tool-usage') { return $script:zaiTool }
                return $script:zaiQuota
            }
            $null = Get-ZaiUsage -Token 'offline-test-key' -SpikeRatio 1.5
            $model = $script:usageRows | Where-Object { $_.PSObject.Properties['Total_Calls'] }
            $model.Hourly_Avg | Should -BeExactly '1.73'
            $model.Total_Tokens | Should -BeExactly '5786304'
            $model.Hourly_Tok_Avg | Should -BeExactly '175,343'
            $model.Peak_Tokens | Should -BeExactly '3961692 at 2026-11-11 15:00'
            $tool = $script:usageRows | Where-Object { $_.Tool -eq 'network-search (search-prime)' }
            $tool.Hourly_Avg | Should -BeExactly '0.36'
            $quota = $script:usageRows | Where-Object { $_.Type -eq 'TIME_LIMIT' }
            $quota.Used | Should -BeExactly '12.5'
            $quota.Limit | Should -BeExactly '4000.25'
            $script:hostMessages | Should -Contain '  Spikes (> 1.5x hourly avg):'
            $script:hostMessages | Should -Contain '  - [SPIKE] networkSearchCount: 2 hour(s) above 1.5x hourly avg'
            $script:hostMessages | Should -Contain '    [1mo] search-prime: 5.25'
        }
    }

    It 'keeps DeepSeek balances, budgets and warnings invariant under <Culture>' -TestCases @(@{ Culture = 'en-US' }, @{ Culture = 'de-DE' }, @{ Culture = 'ko-KR' }) {
        param($Culture)
        Invoke-UsageCulture $Culture {
            $script:providerResponse = $script:usageFixtureJson['deepseek_balance'] | ConvertFrom-Json
            $usd = $script:providerResponse.balance_infos | Where-Object { $_.currency -eq 'USD' }
            $usd.total_balance = '2.50'; $usd.granted_balance = '0.25'; $usd.topped_up_balance = '2.25'
            $cny = $script:providerResponse.balance_infos | Where-Object { $_.currency -eq 'CNY' }
            $cny.total_balance = '35.25'; $cny.granted_balance = '0.50'; $cny.topped_up_balance = '34.75'
            Mock Invoke-RestMethod { $script:providerResponse }
            $response = Get-DeepseekUsage -ApiKey 'offline-test-key' -LowBalanceUsd 5.25 -LowBalanceCny 40.25
            ($response.balance_infos | Where-Object { $_.currency -eq 'USD' }).total_balance | Should -BeExactly '2.50'
            $balance = $script:usageRows | Where-Object { $_.Currency -eq 'USD' }
            $balance.Total | Should -BeOfType [string]
            $balance.Total | Should -BeExactly '2.5'
            $balance.Granted | Should -BeExactly '0.25'
            $balance.Topped_Up | Should -BeExactly '2.25'
            $token = $script:usageRows | Where-Object { $_.Cost_per_1M -eq 'USD 0.003' }
            $token.Available_Tokens | Should -BeExactly '833.33M'
            $script:usageRows.Cost_per_1M | Should -Contain 'USD 1.2'
            $script:usageRows.Cost_per_1M | Should -Contain 'CNY 1'
            $requests = $script:usageRows | Where-Object { $_.Cost -eq 'USD 0.75' }
            $requests.Count | Should -Be 2
            $requests[0].Available_Requests | Should -BeExactly '3,333'
            $requests = $script:usageRows | Where-Object { $_.Cost -eq 'CNY 5' }
            $requests[0].Available_Requests | Should -BeExactly '7,050'
            $script:hostMessages | Should -Contain '  - [LOW] USD balance $2.50 at or below threshold $5.25'
            $script:hostMessages | Should -Contain '  - [LOW] CNY balance 35.25 at or below threshold 40.25'
        }
    }

    It 'keeps Kimi usages percentages and warnings invariant under <Culture>' -TestCases @(@{ Culture = 'en-US' }, @{ Culture = 'de-DE' }, @{ Culture = 'ko-KR' }) {
        param($Culture)
        Invoke-UsageCulture $Culture {
            $script:providerResponse = $script:usageFixtureJson['kimi_usages'] | ConvertFrom-Json
            $script:providerResponse.usages.limit_5h.used_ratio = 0.875
            $script:providerResponse.usages.limit_7d.used_ratio = 0.975
            Mock Invoke-RestMethod { $script:providerResponse }
            $null = Get-KimiUsage -ApiKey 'offline-test-key'
            $rows = @($script:usageRows | Where-Object { $_.PSObject.Properties['Window'] })
            $rows[0].Used | Should -BeExactly '87.50% used'
            $rows[0].Remaining_Percent | Should -BeExactly '12.5%'
            $rows[1].Used | Should -BeExactly '97.50% used'
            $rows[1].Remaining_Percent | Should -BeExactly '2.5%'
            $script:hostMessages | Should -Contain '  - [LOW]      5h: 12.5% remaining'
            $script:hostMessages | Should -Contain '  - [CRITICAL] Weekly: only 2.5% remaining'
        }
    }

    It 'keeps Kimi legacy counts and booster wallet invariant under <Culture>' -TestCases @(@{ Culture = 'en-US' }, @{ Culture = 'de-DE' }, @{ Culture = 'ko-KR' }) {
        param($Culture)
        Invoke-UsageCulture $Culture {
            $script:providerResponse = $script:usageFixtureJson['kimi_usages'] | ConvertFrom-Json
            $script:providerResponse.PSObject.Properties.Remove('usages')
            $script:providerResponse.usage.limit = '100.5'
            $script:providerResponse.usage.remaining = '12.5'
            $script:providerResponse | Add-Member -NotePropertyName totalQuota -NotePropertyValue ([pscustomobject]@{ limit = 1000.5; remaining = 125.25 })
            $script:providerResponse | Add-Member -NotePropertyName parallel -NotePropertyValue ([pscustomobject]@{ limit = 2.5 })
            $script:providerResponse | Add-Member -NotePropertyName boosterWallet -NotePropertyValue ([pscustomobject]@{
                balance = [pscustomobject]@{ type = 'BOOSTER'; amount = 250000000; amountLeft = 125000000 }
                monthlyChargeLimitEnabled = $true
                monthlyChargeLimit = [pscustomobject]@{ priceInCents = 123456; currency = 'USD' }
                monthlyUsed = [pscustomobject]@{ priceInCents = 125 }
            })
            Mock Invoke-RestMethod { $script:providerResponse }
            $null = Get-KimiUsage -ApiKey 'offline-test-key'
            $weekly = $script:usageRows | Where-Object { $_.Window -eq 'Weekly limit' }
            $weekly.Used | Should -BeOfType [string]
            $weekly.Used | Should -BeExactly '88'
            $weekly.Limit | Should -BeExactly '100.5'
            $weekly.Remaining | Should -BeExactly '12.5'
            $weekly.Remaining_Percent | Should -BeExactly '12.4%'
            $script:usageRows.Window | Should -Contain '5h limit'
            $script:usageRows.Parallel_Limit | Should -Contain '2.5'
            $aggregate = $script:usageRows | Where-Object { $_.Limit -eq '1000.5' }
            $aggregate.Remaining | Should -BeExactly '125.25'
            $wallet = $script:usageRows | Where-Object { $_.Currency -eq 'USD' }
            $wallet.Balance | Should -BeExactly '1.25'
            $wallet.Total | Should -BeExactly '2.50'
            $wallet.Monthly_Limit | Should -BeExactly '1,234.56'
            $wallet.Monthly_Used | Should -BeExactly '1.25'
            $script:hostMessages | Should -Contain '  - [LOW]      Weekly limit: 12.4% remaining'
        }
    }
}


