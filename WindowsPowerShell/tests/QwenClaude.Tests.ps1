Describe 'Qwen Claude Code profiles' {
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
        foreach ($functionName in @('Show-QwenPeakWarning', 'claudeq', 'claudeq2')) {
            $functionAst = $ast.Find({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -eq $functionName
            }, $true)
            if (-not $functionAst) { throw "Could not find $functionName in the profile." }

            $script:functionTexts[$functionName] = $functionAst.Extent.Text
        }

        . ([scriptblock]::Create($script:functionTexts['Show-QwenPeakWarning']))
    }

    BeforeEach {
        Mock Write-Host {}
        Mock Start-Sleep {}
    }

    It 'uses the production Qwen 3.8 Max model throughout the Qwen profiles' {
        $script:profileText | Should -Not -Match 'qwen3\.8-max-preview'
        $script:functionTexts['claudeq'] | Should -Match "ANTHROPIC_DEFAULT_FABLE_MODEL = 'qwen3\.8-max'"
        $script:functionTexts['claudeq2'] | Should -Match "ANTHROPIC_MODEL = 'qwen3\.8-max'"
        $script:functionTexts['claudeq2'] | Should -Match "ANTHROPIC_DEFAULT_FABLE_MODEL = 'qwen3\.8-max'"
        $script:functionTexts['claudeq2'] | Should -Match "ANTHROPIC_DEFAULT_SONNET_MODEL = 'qwen3\.8-max'"
        $script:functionTexts['claudeq2'] | Should -Match "ANTHROPIC_DEFAULT_OPUS_MODEL = 'qwen3\.8-max'"
        $script:functionTexts['claudeq2'] | Should -Match "CLAUDE_CODE_SUBAGENT_MODEL = 'qwen3\.7-max'"
    }

    It 'warns and delays before the night discount window' {
        Show-QwenPeakWarning -UtcNow ([datetime]'2026-08-03T13:00:00') -DelaySeconds 3

        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter {
            $Object -match 'Qwen3\.8-max' -and
                $Object -match '50% off Credits consumption' -and
                $Object -match 'starts in 1h 0m'
        }
        Should -Invoke Start-Sleep -Times 1 -Exactly -ParameterFilter { $Seconds -eq 3 }
    }

    It 'stays silent during the night discount window' -ForEach @(
        @{ UtcNow = [datetime]'2026-08-03T14:00:00' }
        @{ UtcNow = [datetime]'2026-08-03T23:59:00' }
    ) {
        Show-QwenPeakWarning -UtcNow $UtcNow -DelaySeconds 3

        Should -Invoke Write-Host -Times 0 -Exactly
        Should -Invoke Start-Sleep -Times 0 -Exactly
    }
}
