Describe 'Windows Sudo profile helpers' {
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

        foreach ($functionName in @('Enable-WindowsSudo', 'Invoke-Elevated')) {
            $functionAst = $ast.Find({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -eq $functionName
            }, $true)
            if (-not $functionAst) { throw "Could not load $functionName from the profile." }
            . ([scriptblock]::Create($functionAst.Extent.Text))
        }
    }

    It 'defines both public functions' {
        (Get-Command Enable-WindowsSudo -CommandType Function) | Should -Not -BeNullOrEmpty
        (Get-Command Invoke-Elevated -CommandType Function) | Should -Not -BeNullOrEmpty
    }

    It 'forces encoded PowerShell output to remain readable text' {
        (Get-Content -LiteralPath $profilePath -Raw) | Should -Match "'-OutputFormat', 'Text'"
    }

    It 'rejects a non-native direct command with script-block guidance' {
        Mock Get-ItemProperty {
            if ($LiteralPath -like '*CurrentVersion\Sudo') { return [pscustomobject]@{ Enabled = 3 } }
            return [pscustomobject]@{ CurrentBuildNumber = '26100' }
        }
        Mock Test-Path { return $true }
        Mock Get-Command { return $null } -ParameterFilter { $Name -eq 'Get-Service' }

        $message = $null
        Invoke-Elevated Get-Service -ErrorVariable message -ErrorAction SilentlyContinue

        ($message -join ' ') | Should -Match 'Wrap PowerShell commands in braces'
    }

    It 'rejects unsupported Windows builds' {
        Mock Get-ItemProperty { return [pscustomobject]@{ CurrentBuildNumber = '22000' } }
        Mock Test-Path { return $true }

        $message = $null
        Invoke-Elevated whoami -ErrorVariable message -ErrorAction SilentlyContinue

        ($message -join ' ') | Should -Match 'build 26100'
    }

    It 'reports an already enabled inline configuration' {
        Mock Get-ItemProperty {
            if ($LiteralPath -like '*CurrentVersion\Sudo') { return [pscustomobject]@{ Enabled = 3 } }
            return [pscustomobject]@{ CurrentBuildNumber = '26100' }
        }
        Mock Test-Path { return $true }
        Mock Start-Process { throw 'Start-Process should not be called' }

        Enable-WindowsSudo | Should -BeTrue
        Should -Invoke -CommandName Start-Process -Times 0 -Exactly
    }
}
