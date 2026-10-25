Describe 'MiniMax Claude Code profile' {
    BeforeAll {
        $profilePath = Join-Path $PSScriptRoot '..\Microsoft.PowerShell_profile.ps1'
        $tokens = $null
        $errors = $null
        $script:profileAst = [System.Management.Automation.Language.Parser]::ParseFile(
            $profilePath,
            [ref]$tokens,
            [ref]$errors
        )
        if ($errors) { throw "Profile contains parse errors: $($errors -join '; ')" }

        # Returns the source text of a profile function so it can be loaded in isolation.
        function Get-ProfileFunctionText {
            param([string]$Name)
            $functionAst = $script:profileAst.Find({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -eq $Name
            }, $true)
            if (-not $functionAst) { throw "Could not find $Name in the profile." }
            return $functionAst.Extent.Text
        }

        . ([scriptblock]::Create((Get-ProfileFunctionText 'claudemm')))
        . ([scriptblock]::Create((Get-ProfileFunctionText 'claudemmd')))
        . ([scriptblock]::Create((Get-ProfileFunctionText 'Invoke-RemoteClaudeCodeBase')))
        . ([scriptblock]::Create((Get-ProfileFunctionText 'Invoke-RemoteClaudeCodeMM')))

        # Profile-scope pins the remote launcher reads at call time.
        $script:_NvmVersion = 'v0.40.8'
        $script:_UvInstallUrl = 'https://astral.sh/uv/install.sh'

        # The profile helper module is loaded whole, so the functions under
        # test find every helper they call.
        $helperAssignment = $script:profileAst.Find({
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left.Extent.Text -eq '$_ProfileHelpers'
        }, $true)
        if (-not $helperAssignment) { throw 'Could not load the profile helper module.' }
        . ([scriptblock]::Create($helperAssignment.Extent.Text))

        # The launcher resolves the key through the vault helper; the profile's
        # shared setup steps must not touch the real machine.
        $_ProfileHelpers | Add-Member -MemberType ScriptMethod -Name GetAiApiKey -Force -Value {
            param([string]$Name)
            return 'test-key'
        }
        function Install-GlobalClaudeMd {}
        function Install-ClaudeGlobalSettings {}
        function Install-ClaudemmSetup { param([string]$Token, [switch]$Force) return $true }

        # Captures the environment the launcher hands to Claude Code.
        function claude {
            $script:capturedEnv = @{
                ANTHROPIC_BASE_URL             = $env:ANTHROPIC_BASE_URL
                ANTHROPIC_MODEL                = $env:ANTHROPIC_MODEL
                ANTHROPIC_DEFAULT_HAIKU_MODEL  = $env:ANTHROPIC_DEFAULT_HAIKU_MODEL
                ANTHROPIC_DEFAULT_SONNET_MODEL = $env:ANTHROPIC_DEFAULT_SONNET_MODEL
                ANTHROPIC_DEFAULT_OPUS_MODEL   = $env:ANTHROPIC_DEFAULT_OPUS_MODEL
                CLAUDE_CODE_SUBAGENT_MODEL     = $env:CLAUDE_CODE_SUBAGENT_MODEL
                CLAUDE_CODE_AUTO_COMPACT_WINDOW = $env:CLAUDE_CODE_AUTO_COMPACT_WINDOW
            }
            $script:capturedArgs = @($args)
        }

        # The remote launcher shells out to ssh; capture the composed command instead.
        function ssh { $script:sshCommandLine = $args[-1] }
    }

    BeforeEach {
        $script:capturedEnv = $null
        $script:capturedArgs = $null
        $script:sshCommandLine = $null
        $script:windowBefore = $env:CLAUDE_CODE_AUTO_COMPACT_WINDOW
    }

    It 'routes every Claude Code model slot to MiniMax-M3.1-Flash' {
        claudemm 'hello'

        $script:capturedEnv.ANTHROPIC_BASE_URL | Should -Be 'https://api.minimax.io/anthropic'
        $script:capturedEnv.ANTHROPIC_MODEL | Should -Be 'MiniMax-M3.1-Flash[1m]'
        $script:capturedEnv.ANTHROPIC_DEFAULT_HAIKU_MODEL | Should -Be 'MiniMax-M3.1-Flash[1m]'
        $script:capturedEnv.ANTHROPIC_DEFAULT_SONNET_MODEL | Should -Be 'MiniMax-M3.1-Flash[1m]'
        $script:capturedEnv.ANTHROPIC_DEFAULT_OPUS_MODEL | Should -Be 'MiniMax-M3.1-Flash[1m]'
        $script:capturedEnv.CLAUDE_CODE_SUBAGENT_MODEL | Should -Be 'MiniMax-M3.1-Flash[1m]'
    }

    It 'compacts MiniMax sessions at 512K' {
        claudemm 'hello'

        $script:capturedEnv.CLAUDE_CODE_AUTO_COMPACT_WINDOW | Should -Be '524288'
    }

    It 'restores the compaction window after the session ends' {
        claudemm 'hello'

        $env:CLAUDE_CODE_AUTO_COMPACT_WINDOW | Should -Be $script:windowBefore
    }

    It 'passes --dangerously-skip-permissions in claudemmd' {
        claudemmd 'hello'

        $script:capturedArgs | Should -Contain 'hello'
        $script:capturedArgs | Should -Contain '--dangerously-skip-permissions'
    }

    It 'launches the remote MiniMax profile with the same model and window' {
        Invoke-RemoteClaudeCodeMM -RemoteHost '10.0.0.1' -ApiKey 'test-key'

        $script:sshCommandLine | Should -Match "ANTHROPIC_BASE_URL='https://api\.minimax\.io/anthropic'"
        $script:sshCommandLine | Should -Match "ANTHROPIC_DEFAULT_HAIKU_MODEL='MiniMax-M3\.1-Flash\[1m\]'"
        $script:sshCommandLine | Should -Match "ANTHROPIC_DEFAULT_SONNET_MODEL='MiniMax-M3\.1-Flash\[1m\]'"
        $script:sshCommandLine | Should -Match "ANTHROPIC_DEFAULT_OPUS_MODEL='MiniMax-M3\.1-Flash\[1m\]'"
        $script:sshCommandLine | Should -Match "CLAUDE_CODE_AUTO_COMPACT_WINDOW='524288'"
    }

    It 'offers the bare MiniMax-M3.1-Flash id to the Claude Code Router' {
        $assignment = $script:profileAst.Find({
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
                $node.Left.VariablePath.UserPath -eq '_CcrInternal'
        }, $true)
        if (-not $assignment) { throw 'Could not find $_CcrInternal in the profile.' }

        $ccr = & ([scriptblock]::Create($assignment.Right.Extent.Text))
        $ccr.Providers.minimax.models | Should -Be @('MiniMax-M3.1-Flash')
    }
}
