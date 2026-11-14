Describe 'Invoke-SystemUpdate' {
    BeforeAll {
        $profilePath = Join-Path $PSScriptRoot '..\Microsoft.PowerShell_profile.ps1'
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($profilePath, [ref]$tokens, [ref]$errors)
        if ($errors) { throw "Profile parse errors: $errors" }
        foreach ($name in @('Invoke-SystemUpdate', 'Test-IsAdministrator', 'Enable-WindowsSudo', 'Invoke-Elevated', 'Invoke-WindowsUpdate', 'Invoke-WindowsUpdateScan', 'Format-SystemUpdateElapsed')) {
            $definition = $ast.Find({ param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
            }, $true)
            if (-not $definition) { throw "Missing function: $name" }
            . ([scriptblock]::Create($definition.Extent.Text))
        }
    }

    BeforeEach {
        $script:events = [Collections.Generic.List[string]]::new()
        $script:exitCode = 0
        $script:enabled = 3
        $script:compatDuringUpgrade = $null
        $script:arguments = @()
        $script:savedCompat = $env:__COMPAT_LAYER
        $script:savedExitCode = $global:LASTEXITCODE
        Mock Test-IsAdministrator { $false }
        Mock Get-ItemProperty {
            if ($LiteralPath -like '*CurrentVersion\Sudo') { return [pscustomobject]@{ Enabled = $script:enabled } }
            return [pscustomobject]@{ CurrentBuildNumber = '26100' }
        }
        Mock Test-Path { $true }
        Mock Get-Command { [pscustomobject]@{ Name = $Name } }
        Mock Get-Command { [pscustomobject]@{ Source = 'mock-winget.exe' } } -ParameterFilter { $Name -eq 'winget' }
        Mock Read-Host { throw 'Unexpected interactive prompt' }
        Mock Enable-WindowsSudo { throw 'Unexpected sudo setup' }
        Mock Invoke-Elevated {
            $script:events.Add('elevation')
            & $Command[0]
        }
        Mock Start-Process {
            $script:events.Add('winget')
            $script:arguments = $ArgumentList
            $script:compatDuringUpgrade = $env:__COMPAT_LAYER
            [pscustomobject]@{ ExitCode = $script:exitCode }
        }
        Mock Invoke-WindowsUpdateScan { $script:events.Add('scan') }
        Mock Invoke-WindowsUpdate { $script:events.Add('install') }
        Mock Write-Host {}
        Mock Write-Warning {}
    }

    AfterEach {
        if ($null -eq $script:savedCompat) { Remove-Item Env:\__COMPAT_LAYER -ErrorAction SilentlyContinue }
        else { $env:__COMPAT_LAYER = $script:savedCompat }
        $global:LASTEXITCODE = $script:savedExitCode
    }

    It 'elevates once before both stages and uses unattended WinGet flags' {
        Invoke-SystemUpdate
        ($script:events -join ',') | Should -Be 'elevation,winget,scan'
        Should -Invoke Invoke-Elevated -Times 1 -Exactly
        foreach ($flag in @('upgrade', '--all', '--silent', '--disable-interactivity', '--accept-package-agreements', '--accept-source-agreements', '--authentication-mode', 'silent')) {
            $script:arguments | Should -Contain $flag
        }
        $script:arguments | Should -Not -Contain '--scope'
        Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter { $Wait -and $PassThru -and $NoNewWindow }
        Should -Invoke Read-Host -Times 0 -Exactly
    }

    It 'installs Windows Updates in the same early elevated worker without a separate scan' {
        Invoke-SystemUpdate -InstallWindowsUpdates
        ($script:events -join ',') | Should -Be 'elevation,winget,install'
        Should -Invoke Invoke-Elevated -Times 1 -Exactly
        Should -Invoke Invoke-WindowsUpdateScan -Times 0 -Exactly
    }

    It 'runs directly when already elevated' {
        Mock Test-IsAdministrator { $true }
        Invoke-SystemUpdate -InstallWindowsUpdates
        ($script:events -join ',') | Should -Be 'winget,install'
        Should -Invoke Invoke-Elevated -Times 0 -Exactly
        Should -Invoke Get-ItemProperty -Times 0 -Exactly
    }

    It 'isolates user-scope upgrades and restores an existing compatibility layer' {
        $env:__COMPAT_LAYER = 'existing-value'
        Invoke-SystemUpdate -UserScope
        ($script:events -join ',') | Should -Be 'winget,scan'
        $script:arguments | Should -Contain '--scope'
        $script:arguments | Should -Contain 'user'
        $script:compatDuringUpgrade | Should -Be 'RunAsInvoker'
        $env:__COMPAT_LAYER | Should -Be 'existing-value'
        Should -Invoke Invoke-Elevated -Times 0 -Exactly
        Should -Invoke Get-ItemProperty -Times 0 -Exactly
    }

    It 'restores an absent compatibility layer after an installer exception and continues' {
        Remove-Item Env:\__COMPAT_LAYER -ErrorAction SilentlyContinue
        Mock Start-Process { throw 'simulated launch failure' }
        Invoke-SystemUpdate -UserScope
        $env:__COMPAT_LAYER | Should -BeNullOrEmpty
        Should -Invoke Invoke-WindowsUpdateScan -Times 1 -Exactly
        Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter { $Message -like '*simulated launch failure*' }
    }

    It 'rejects incompatible switches before starting or reporting timing' {
        { Invoke-SystemUpdate -UserScope -InstallWindowsUpdates } | Should -Throw '*Cannot combine*'
        Should -Invoke Start-Process -Times 0 -Exactly
        Should -Invoke Write-Host -Times 0 -Exactly
    }

    It 'rejects user scope from an elevated session' {
        Mock Test-IsAdministrator { $true }
        { Invoke-SystemUpdate -UserScope } | Should -Throw '*elevated PowerShell*'
        Should -Invoke Start-Process -Times 0 -Exactly
    }

    It 'enables sudo with consent and immediately starts the worker' {
        $script:enabled = 0
        Mock Read-Host { $script:events.Add('consent'); 'yes' }
        Mock Enable-WindowsSudo { $script:events.Add('setup'); $script:enabled = 3; $true }
        Invoke-SystemUpdate
        ($script:events -join ',') | Should -Be 'consent,setup,elevation,winget,scan'
    }

    It 'stops on declined sudo setup and reports stopped timing' {
        $script:enabled = 0
        Mock Read-Host { '' }
        Invoke-SystemUpdate
        Should -Invoke Enable-WindowsSudo -Times 0 -Exactly
        Should -Invoke Invoke-Elevated -Times 0 -Exactly
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { $Object -like 'Invoke-SystemUpdate stopped early at *; wall time *' }
    }

    It 'stops if sudo setup reports failure' {
        $script:enabled = 0
        Mock Read-Host { 'y' }
        Mock Enable-WindowsSudo { $false }
        { Invoke-SystemUpdate } | Should -Throw '*setup did not complete*'
        Should -Invoke Invoke-Elevated -Times 0 -Exactly
    }

    It 'verifies sudo configuration even when setup reports success' {
        $script:enabled = 0
        Mock Read-Host { 'y' }
        Mock Enable-WindowsSudo { $true }
        { Invoke-SystemUpdate } | Should -Throw '*setup did not complete*'
        Should -Invoke Invoke-Elevated -Times 0 -Exactly
    }

    It 'stops when setup UAC is cancelled' {
        $script:enabled = 0
        Mock Read-Host { 'y' }
        Mock Enable-WindowsSudo { throw 'UAC cancelled' }
        { Invoke-SystemUpdate } | Should -Throw '*UAC cancelled*'
        Should -Invoke Start-Process -Times 0 -Exactly
    }

    It 'stops on unsupported Windows without asking for setup consent' {
        Mock Test-Path { $false }
        { Invoke-SystemUpdate } | Should -Throw '*24H2*'
        Should -Invoke Read-Host -Times 0 -Exactly
        Should -Invoke Start-Process -Times 0 -Exactly
    }

    It 'reports an elevated worker failure as stopped early' {
        Mock Invoke-Elevated { $global:LASTEXITCODE = 1 }
        { Invoke-SystemUpdate } | Should -Throw '*worker exited with code 1*'
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { $Object -like 'Invoke-SystemUpdate stopped early at *' }
    }

    It 'continues after WinGet failures' {
        $script:exitCode = -1978335188
        Invoke-SystemUpdate
        ($script:events -join ',') | Should -Be 'elevation,winget,scan'
        Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter { $Message -like '*exit code -1978335188*' }
    }

    It 'treats no applicable upgrade as a normal completion' {
        $script:exitCode = -1978335189
        Invoke-SystemUpdate
        Should -Invoke Write-Warning -Times 0 -Exactly
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { $Object -like 'Invoke-SystemUpdate completed at *; wall time *' }
    }

    It 'scans when WinGet is missing' {
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'winget' }
        Invoke-SystemUpdate
        Should -Invoke Start-Process -Times 0 -Exactly
        Should -Invoke Invoke-WindowsUpdateScan -Times 1 -Exactly
    }

    It 'validates Windows Update availability before upgrading packages' {
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'Invoke-WindowsUpdateScan' }
        { Invoke-SystemUpdate -UserScope } | Should -Throw '*Missing Invoke-WindowsUpdateScan*'
        Should -Invoke Start-Process -Times 0 -Exactly
    }

    It 'prints timestamps and cumulative elapsed time for both stages' {
        Invoke-SystemUpdate -UserScope
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { $Object -match '^\[\d{4}-\d{2}-\d{2} .* \| \+\d{2}:\d{2}:\d{2}\] WinGet upgrades$' }
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { $Object -match '^\[.* \| \+\d{2}:\d{2}:\d{2}\] Windows Update scan$' }
    }

    It 'formats elapsed hours beyond 24 without wrapping' {
        Format-SystemUpdateElapsed ([timespan]::FromSeconds(90061)) | Should -Be '25:01:01'
    }

    It 'registers isu as the function alias' {
        $aliasStatement = $ast.Find({ param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and
            $node.Extent.Text -eq 'Set-Alias -Name isu -Value Invoke-SystemUpdate'
        }, $true)
        $aliasStatement | Should -Not -BeNullOrEmpty
    }
}
