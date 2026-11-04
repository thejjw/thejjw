Describe 'Enable-LongPathSupport' {
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
                $node.Name -eq 'Enable-LongPathSupport'
        }, $true)
        if (-not $functionAst) { throw 'Could not load Enable-LongPathSupport from the profile.' }
        . ([scriptblock]::Create($functionAst.Extent.Text))
        function Test-IsAdministrator { return $false }
    }

    BeforeEach {
        # Registry value as seen by Get-ItemProperty; writers flip it to 1.
        $script:longPathValue = 0
        Mock Write-Host {}
        Mock Write-Warning {}
        Mock Get-ItemProperty { [pscustomobject]@{ LongPathsEnabled = $script:longPathValue } }
        Mock Test-IsAdministrator { $false }
        Mock New-ItemProperty { $script:longPathValue = 1 }
        Mock Start-Process {
            $script:longPathValue = 1
            [pscustomobject]@{ ExitCode = 0 }
        }
    }

    It 'returns true without writing when already enabled' {
        $script:longPathValue = 1

        Enable-LongPathSupport | Should -BeTrue
        Should -Invoke Start-Process -Times 0 -Exactly
        Should -Invoke New-ItemProperty -Times 0 -Exactly
    }

    It 'elevates reg.exe through UAC in a visible window when not elevated' {
        Enable-LongPathSupport | Should -BeTrue
        Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter {
            $FilePath -like '*\System32\reg.exe' -and
                $Verb -eq 'RunAs' -and
                -not $PSBoundParameters.ContainsKey('WindowStyle') -and
                ($ArgumentList -join ' ') -eq 'add HKLM\SYSTEM\CurrentControlSet\Control\FileSystem /v LongPathsEnabled /t REG_DWORD /d 1 /f'
        }
        Should -Invoke New-ItemProperty -Times 0 -Exactly
    }

    It 'returns false when the UAC prompt is cancelled' {
        Mock Start-Process { throw 'The operation was canceled by the user.' }

        Enable-LongPathSupport | Should -BeFalse
        Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter { $Message -like '*cancelled or failed*' }
    }

    It 'returns false when the value is still not set after reg.exe' {
        Mock Start-Process { [pscustomobject]@{ ExitCode = 1 } }

        Enable-LongPathSupport | Should -BeFalse
        Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter { $Message -like '*exit code 1*' }
    }

    It 'writes the value directly when already elevated' {
        Mock Test-IsAdministrator { $true }

        Enable-LongPathSupport | Should -BeTrue
        Should -Invoke New-ItemProperty -Times 1 -Exactly
        Should -Invoke Start-Process -Times 0 -Exactly
    }

    It 'only reports with -NoElevate' {
        Enable-LongPathSupport -NoElevate | Should -BeFalse
        Should -Invoke Start-Process -Times 0 -Exactly
        Should -Invoke New-ItemProperty -Times 0 -Exactly
    }
}
