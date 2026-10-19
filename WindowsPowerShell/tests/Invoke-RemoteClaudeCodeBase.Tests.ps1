Describe 'Invoke-RemoteClaudeCodeBase remote environment composition' {
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
                $node.Name -eq 'Invoke-RemoteClaudeCodeBase'
        }, $true)
        if (-not $functionAst) { throw 'Could not find Invoke-RemoteClaudeCodeBase in the profile.' }

        # Profile-scope pins the launcher reads at call time, plus the helper object.
        # NewTemporarySshIdentity is only touched when -KeyFile is supplied.
        $script:_NvmVersion = 'v0.40.8'
        $script:_UvInstallUrl = 'https://astral.sh/uv/install.sh'
        $script:_ProfileHelpers = [pscustomobject]@{}

        . ([scriptblock]::Create($functionAst.Extent.Text))

        # Invoke the launcher with the mandatory provider arguments and return the
        # SSH command line it composed. Extra entries override the defaults.
        function Invoke-Launcher {
            param([hashtable]$Extra)
            $script:sshCommandLine = $null
            $arguments = @{
                RemoteHost  = '10.0.0.1'
                ApiKey      = 'test-key'
                Port        = 10051
                HaikuModel  = 'h'
                SonnetModel = 's'
                OpusModel   = 'o'
                TimeoutMs   = '300000'
                Disable1M   = '0'
            }
            foreach ($key in $Extra.Keys) { $arguments[$key] = $Extra[$key] }
            Invoke-RemoteClaudeCodeBase @arguments
            return $script:sshCommandLine
        }

        # Decode the base64 launcher payload embedded in the SSH command line.
        function Get-LauncherPayload {
            param([string]$CommandLine)
            $match = [regex]::Match($CommandLine, 'printf %s ([A-Za-z0-9+/=]+) \| base64 -d')
            if (-not $match.Success) { throw "No base64 payload in: $CommandLine" }
            return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($match.Groups[1].Value))
        }
    }

    BeforeEach {
        # The launcher shells out to ssh; capture the composed remote command instead.
        function ssh { $script:sshCommandLine = $args[-1] }
    }

    It 'marks a root RemoteUser as running inside a deliberate sandbox' {
        $commandLine = Invoke-Launcher @{ RemoteUser = 'root' }
        $commandLine | Should -Match "IS_SANDBOX='1'"
    }

    It 'leaves a non-root RemoteUser without the marker' {
        $commandLine = Invoke-Launcher @{ RemoteUser = 'deploy' }
        $commandLine | Should -Not -Match 'IS_SANDBOX'
    }

    It 'marks the legacy root@host RemoteHost form' {
        $commandLine = Invoke-Launcher @{ RemoteHost = 'root@10.0.0.1' }
        $commandLine | Should -Match "IS_SANDBOX='1'"
    }

    It 'leaves a bare RemoteHost without the marker' {
        $commandLine = Invoke-Launcher @{}
        $commandLine | Should -Not -Match 'IS_SANDBOX'
    }

    It 'passes the marker to the tmux Claude window but not the tmux server' {
        $payload = Get-LauncherPayload (Invoke-Launcher @{ RemoteUser = 'root' })
        $payload.Contains('CC_TMUX_ENV+=(-e "IS_SANDBOX=$IS_SANDBOX")') | Should -BeTrue
        $payload.Contains('unset DISABLE_AUTOUPDATER NVM_DIR IS_SANDBOX') | Should -BeTrue
    }

    It 'allows the Claude Code postinstall through the npm allowlist probe' {
        $payload = Get-LauncherPayload (Invoke-Launcher @{ RemoteUser = 'deploy' })
        $payload.Contains("CC_CC_PKG='@anthropic-ai/claude-code'") | Should -BeTrue
        $payload.Contains('CC_CC_NPM_OPTS=(--allow-scripts="$CC_CC_PKG")') | Should -BeTrue
        $payload.Contains("grep -q '^allow-scripts'") | Should -BeTrue
        $payload.Contains('"${CC_CC_NPM_OPTS[@]}" "$CC_CC_PKG"') | Should -BeTrue
    }

    It 'still launches claude with the bypass flag on both the tmux and direct paths' {
        $payload = Get-LauncherPayload (Invoke-Launcher @{ RemoteUser = 'root' })
        $payload | Should -Match '"\$CC_CLAUDE" --dangerously-skip-permissions'
        $payload | Should -Match 'HOME="\$CC_HOME" claude --dangerously-skip-permissions'
    }
}
