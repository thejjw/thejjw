Describe 'DeepSeek Claude Code profiles' {
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

        $script:profileText = Get-Content -LiteralPath $profilePath -Raw
        $script:functionTexts = @{}
        foreach ($functionName in @('Show-DeepseekPeakWarning', 'claudeds', 'claudeds2', 'claudedsd', 'claudeds2d')) {
            $functionAst = $ast.Find({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -eq $functionName
            }, $true)
            if (-not $functionAst) { throw "Could not find $functionName in the profile." }

            $script:functionTexts[$functionName] = $functionAst.Extent.Text
        }

        . ([scriptblock]::Create($script:functionTexts['Show-DeepseekPeakWarning']))
    }

    BeforeEach {
        Mock Write-Host {}
        Mock Start-Sleep {}
    }

    It 'uses deepseek-flash and proper models in DeepSeek profiles' {
        $script:functionTexts['claudeds'] | Should -Match 'ANTHROPIC_MODEL = "deepseek-v4-pro\[1m\]"'
        $script:functionTexts['claudeds'] | Should -Match 'ANTHROPIC_DEFAULT_HAIKU_MODEL = "deepseek-flash"'
        $script:functionTexts['claudeds'] | Should -Match 'ANTHROPIC_DEFAULT_SONNET_MODEL = "deepseek-v4-pro\[1m\]"'
        $script:functionTexts['claudeds'] | Should -Match 'ANTHROPIC_DEFAULT_OPUS_MODEL = "deepseek-v4-pro\[1m\]"'
        $script:functionTexts['claudeds'] | Should -Match 'CLAUDE_CODE_SUBAGENT_MODEL = "deepseek-flash"'
        $script:functionTexts['claudeds'] | Should -Match 'CLAUDE_CODE_EFFORT_LEVEL = "max"'
        $script:functionTexts['claudeds'] | Should -Match 'CLAUDE_CODE_AUTO_COMPACT_WINDOW = "786432"'

        $script:functionTexts['claudeds2'] | Should -Match 'ANTHROPIC_MODEL = "deepseek-flash\[1m\]"'
        $script:functionTexts['claudeds2'] | Should -Match 'ANTHROPIC_DEFAULT_HAIKU_MODEL = "deepseek-flash"'
        $script:functionTexts['claudeds2'] | Should -Match 'ANTHROPIC_DEFAULT_SONNET_MODEL = "deepseek-flash\[1m\]"'
        $script:functionTexts['claudeds2'] | Should -Match 'ANTHROPIC_DEFAULT_OPUS_MODEL = "deepseek-v4-pro\[1m\]"'
        $script:functionTexts['claudeds2'] | Should -Match 'CLAUDE_CODE_SUBAGENT_MODEL = "deepseek-flash"'
        $script:functionTexts['claudeds2'] | Should -Match 'CLAUDE_CODE_EFFORT_LEVEL = "high"'
        $script:functionTexts['claudeds2'] | Should -Match 'CLAUDE_CODE_AUTO_COMPACT_WINDOW = "786432"'
    }

    It 'configures deepseek-flash in CCR provider models' {
        $script:profileText | Should -Match "'deepseek-flash\[1m\]'"
    }

    It 'passes --dangerously-skip-permissions in claudedsd and claudeds2d' {
        $script:functionTexts['claudedsd'] | Should -Match '--dangerously-skip-permissions'
        $script:functionTexts['claudeds2d'] | Should -Match '--dangerously-skip-permissions'
    }

    It 'warns and delays during peak windows on weekdays' -ForEach @(
        @{ UtcNow = [DateTime]::SpecifyKind([datetime]'2026-08-24T02:00:00', [System.DateTimeKind]::Utc) }
        @{ UtcNow = [DateTime]::SpecifyKind([datetime]'2026-08-24T08:00:00', [System.DateTimeKind]::Utc) }
    ) {
        Show-DeepseekPeakWarning -UtcNow $UtcNow -DelaySeconds 3

        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter {
            $Object -match 'DeepSeek peak hours are active' -and
                $Object -match '2x rates apply'
        }
        Should -Invoke Start-Sleep -Times 1 -Exactly -ParameterFilter { $Seconds -eq 3 }
    }

    It 'stays silent outside peak windows and on weekends' -ForEach @(
        @{ UtcNow = [DateTime]::SpecifyKind([datetime]'2026-08-24T00:30:00', [System.DateTimeKind]::Utc) }
        @{ UtcNow = [DateTime]::SpecifyKind([datetime]'2026-08-24T04:30:00', [System.DateTimeKind]::Utc) }
        @{ UtcNow = [DateTime]::SpecifyKind([datetime]'2026-08-24T10:30:00', [System.DateTimeKind]::Utc) }
        @{ UtcNow = [DateTime]::SpecifyKind([datetime]'2026-08-24T23:00:00', [System.DateTimeKind]::Utc) }
        @{ UtcNow = [DateTime]::SpecifyKind([datetime]'2026-08-22T02:00:00', [System.DateTimeKind]::Utc) }
    ) {
        Show-DeepseekPeakWarning -UtcNow $UtcNow -DelaySeconds 3

        Should -Invoke Write-Host -Times 0 -Exactly
        Should -Invoke Start-Sleep -Times 0 -Exactly
    }
}
