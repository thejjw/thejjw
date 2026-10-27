Describe 'AppLocker live enforcement safety' {
    BeforeAll {
        $profilePath = Join-Path $PSScriptRoot '..\Microsoft.PowerShell_profile.ps1'
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($profilePath, [ref]$tokens, [ref]$errors)
        if ($errors) { throw "Profile contains parse errors: $($errors -join '; ')" }
        # Extract definitions only: profile initialization must never run in tests.
        foreach ($name in @('Test-AppLockerLiveEnforcement', 'Repair-AppLockerEnforcement', 'Stop-AppLockerProcesses')) {
            $definition = $ast.Find({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
            }, $true)
            if (-not $definition) { throw "Missing function: $name" }
            . ([scriptblock]::Create($definition.Extent.Text))
        }

        # Return an event-shaped object without reading or writing the machine log.
        function New-TestBlockEvent {
            param([string]$Path, [string]$Sid)
            $escapedPath = [System.Security.SecurityElement]::Escape($Path)
            $event = [pscustomobject]@{
                Id = 8004
                TimeCreated = Get-Date
                Xml = "<Event><EventData><Data Name='FilePath'>$escapedPath</Data><Data Name='TargetUser'>$Sid</Data></EventData></Event>"
            }
            $event | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $this.Xml }
            return $event
        }
    }

    BeforeEach {
        Mock Copy-Item {}
        Mock Remove-Item {}
        Mock Start-Process {}
        Mock Get-WinEvent { @() }
        Mock Restart-Service {}
        Mock Start-Sleep {}
        Mock gpupdate.exe {}
        Mock Stop-Process {}
        Mock Get-Process { @() }
        Mock Write-Warning {}
    }

    Context 'Live probes' {
        It 'reports a successful launch as not enforced and removes its probe' {
            $result = Test-AppLockerLiveEnforcement -FileName 'probe.exe' -Directory $TestDrive -Confirm:$false
            $result.Enforced | Should -BeFalse
            Should -Invoke Copy-Item -Times 1 -Exactly -ParameterFilter { -not $Force -and $ErrorAction -eq 'Stop' }
            Should -Invoke Start-Process -Times 1 -Exactly
            Should -Invoke Remove-Item -Times 1 -Exactly -ParameterFilter { $LiteralPath -eq (Join-Path $TestDrive 'probe.exe') }
        }

        It 'does not classify an unrelated launch failure as an AppLocker block' {
            Mock Start-Process { throw 'Access is denied by an unrelated component' }
            $result = Test-AppLockerLiveEnforcement -FileName 'probe.exe' -Directory $TestDrive -Confirm:$false
            $result.Enforced | Should -BeNullOrEmpty
            Should -Invoke Get-WinEvent -Times 1
            Should -Invoke Remove-Item -Times 1 -Exactly
        }

        It 'requires a matching executable path in the block event' {
            Mock Start-Process { throw 'Access denied' }
            Mock Get-WinEvent {
                New-TestBlockEvent -Path (Join-Path $TestDrive 'other.exe') -Sid ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
            }
            (Test-AppLockerLiveEnforcement -FileName 'probe.exe' -Directory $TestDrive -Confirm:$false).Enforced | Should -BeNullOrEmpty
        }

        It 'requires the current user in the block event' {
            Mock Start-Process { throw 'Access denied' }
            Mock Get-WinEvent { New-TestBlockEvent -Path (Join-Path $TestDrive 'probe.exe') -Sid 'S-1-5-18' }
            (Test-AppLockerLiveEnforcement -FileName 'probe.exe' -Directory $TestDrive -Confirm:$false).Enforced | Should -BeNullOrEmpty
        }

        It 'verifies a launch failure backed by a matching current-user block event' {
            Mock Start-Process { throw 'Access denied' }
            Mock Get-WinEvent {
                New-TestBlockEvent -Path (Join-Path $TestDrive 'probe.exe') -Sid ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
            }
            (Test-AppLockerLiveEnforcement -FileName 'probe.exe' -Directory $TestDrive -Confirm:$false).Enforced | Should -BeTrue
            Should -Invoke Get-WinEvent -Times 1 -Exactly -ParameterFilter { $FilterHashtable.Id -eq 8004 -and $null -ne $FilterHashtable.StartTime }
        }

        It 'returns unverified when block events cannot be read' {
            Mock Start-Process { throw 'Access denied' }
            Mock Get-WinEvent { throw 'Event log unavailable' }
            (Test-AppLockerLiveEnforcement -FileName 'probe.exe' -Directory $TestDrive -Confirm:$false).Enforced | Should -BeNullOrEmpty
            Should -Invoke Remove-Item -Times 1 -Exactly
        }

        It 'does not fall back to TEMP for an invalid explicit directory' {
            (Test-AppLockerLiveEnforcement -FileName 'probe.exe' -Directory (Join-Path $TestDrive 'missing') -Confirm:$false).Enforced | Should -BeNullOrEmpty
            Should -Invoke Copy-Item -Times 0 -Exactly
            Should -Invoke Start-Process -Times 0 -Exactly
            Should -Invoke Remove-Item -Times 0 -Exactly
        }

        It 'skips an existing target without overwriting or deleting it' {
            $path = Join-Path $TestDrive 'existing.exe'
            Set-Content -LiteralPath $path -Value 'sentinel'
            (Test-AppLockerLiveEnforcement -FileName 'existing.exe' -Directory $TestDrive -Confirm:$false).Enforced | Should -BeNullOrEmpty
            Get-Content -LiteralPath $path | Should -Be 'sentinel'
            Should -Invoke Copy-Item -Times 0 -Exactly
            Should -Invoke Start-Process -Times 0 -Exactly
            Should -Invoke Remove-Item -Times 0 -Exactly
        }

        It 'does not launch or delete a destination after a failed copy' {
            Mock Copy-Item { throw 'Copy failed' }
            (Test-AppLockerLiveEnforcement -FileName 'probe.exe' -Directory $TestDrive -Confirm:$false).Enforced | Should -BeNullOrEmpty
            Should -Invoke Start-Process -Times 0 -Exactly
            Should -Invoke Remove-Item -Times 0 -Exactly
        }

        It 'performs no probe operations under WhatIf' {
            (Test-AppLockerLiveEnforcement -FileName 'probe.exe' -Directory $TestDrive -WhatIf).Enforced | Should -BeNullOrEmpty
            Should -Invoke Copy-Item -Times 0 -Exactly
            Should -Invoke Start-Process -Times 0 -Exactly
            Should -Invoke Remove-Item -Times 0 -Exactly
            Should -Invoke Get-WinEvent -Times 0 -Exactly
        }
    }

    Context 'Single target recovery safety' {
        BeforeEach {
            Mock Test-AppLockerLiveEnforcement { [pscustomobject]@{ Enforced = $false; Detail = 'launched' } }
        }
        It 'skips probes and recovery for AuditOnly' {
            $result = Repair-AppLockerEnforcement -FileName 'one.exe' -EnforcementMode AuditOnly -Confirm:$false
            $result.NeedsReboot | Should -BeFalse
            Should -Invoke Test-AppLockerLiveEnforcement -Times 0 -Exactly
            Should -Invoke gpupdate.exe -Times 0 -Exactly
            Should -Invoke Restart-Service -Times 0 -Exactly
        }
        It 'skips all operations under WhatIf' {
            $null = Repair-AppLockerEnforcement -FileName 'one.exe' -WhatIf
            Should -Invoke Test-AppLockerLiveEnforcement -Times 0 -Exactly
            Should -Invoke gpupdate.exe -Times 0 -Exactly
            Should -Invoke Restart-Service -Times 0 -Exactly
            Should -Invoke Start-Sleep -Times 0 -Exactly
        }
        It 'does not claim a reboot is required after failed recovery' {
            Mock Restart-Service { throw 'Access denied' }
            $result = Repair-AppLockerEnforcement -FileName 'one.exe' -Confirm:$false
            $result.Enforcement | Should -Be 'NotEnforced'
            $result.NeedsReboot | Should -BeFalse
            Should -Invoke gpupdate.exe -Times 1 -Exactly
            Should -Invoke Restart-Service -Times 1 -Exactly
        }
    }
}

