Describe 'AGENTS.md oc-advisor template sync' {
    BeforeAll {
        # The ## oc-advisor section is shared verbatim across three files:
        # the workspace-root AGENTS.md, the canonical template in the
        # PowerShell profile, and the nrd copy in bin/install_j.sh.
        # All three are read as plain text; no profile code is executed.
        $rootAgents = Join-Path $PSScriptRoot '..\..\..\AGENTS.md'
        $profilePath = Join-Path $PSScriptRoot '..\Microsoft.PowerShell_profile.ps1'
        $installShPath = Join-Path $PSScriptRoot '..\..\bin\install_j.sh'

        function Get-OcAdvisorSection([string]$Path) {
            if (-not (Test-Path -LiteralPath $Path)) { return $null }
            # ReadAllLines normalizes CRLF/LF so line endings never diverge.
            $lines = [System.IO.File]::ReadAllLines($Path)
            $start = -1
            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -eq '## oc-advisor') { $start = $i; break }
            }
            if ($start -lt 0) { return $null }
            # Section ends at the next markdown header, the PowerShell
            # here-string closer, the shell heredoc closer, or EOF.
            $end = $lines.Count
            for ($i = $start + 1; $i -lt $lines.Count; $i++) {
                $line = $lines[$i]
                if ($line -match '^## ' -or $line -eq "'@" -or $line -eq 'AGENT_EOF') { $end = $i; break }
            }
            return (($lines[$start..($end - 1)] -join "`n").Trim())
        }
    }

    It 'has an oc-advisor section in all three files' {
        Get-OcAdvisorSection $rootAgents | Should -Not -BeNullOrEmpty
        Get-OcAdvisorSection $profilePath | Should -Not -BeNullOrEmpty
        Get-OcAdvisorSection $installShPath | Should -Not -BeNullOrEmpty
    }

    It 'keeps the profile template identical to the workspace AGENTS.md' {
        $expected = Get-OcAdvisorSection $rootAgents
        $actual = Get-OcAdvisorSection $profilePath
        $actual | Should -Be $expected
    }

    It 'keeps the install_j.sh copy identical to the workspace AGENTS.md' {
        $expected = Get-OcAdvisorSection $rootAgents
        $actual = Get-OcAdvisorSection $installShPath
        $actual | Should -Be $expected
    }

    It 'guards the section for harnesses without the tool' {
        foreach ($file in @($rootAgents, $profilePath, $installShPath)) {
            Get-OcAdvisorSection $file | Should -Match 'Otherwise ignore it'
        }
    }
}
