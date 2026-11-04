Describe 'AppLocker service-only setup' {
    BeforeAll {
        # A function stub keeps Pester from resolving native sc.exe aliases.
        function sc.exe { throw 'Unmocked service command' }
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '..\Microsoft.PowerShell_profile.ps1'), [ref]$tokens, [ref]$errors)
        if ($errors) { throw ($errors -join '; ') }
        # Load definitions only; never run profile initialization or real service changes.
        foreach ($name in @('Add-AppLockerBlock', 'Enable-AppLockerServiceStartup', 'Write-AppLockerServiceStatus', 'Write-AppLockerEnforcementStatus', 'Test-IsAdministrator', 'Read-AppLockerPolicy', 'Repair-AppLockerEnforcement')) {
            $definition = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
            . ([scriptblock]::Create($definition.Extent.Text))
        }
    }
    BeforeEach {
        $script:serviceState = [pscustomobject]@{ Status = 'Stopped'; StartType = 'Manual' }
        Mock Test-IsAdministrator { $true }
        Mock Get-Service { $script:serviceState }
        Mock sc.exe { $global:LASTEXITCODE = 0; $script:serviceState.StartType = 'Automatic' }
        Mock Start-Service { $script:serviceState.Status = 'Running' }
        Mock Write-Host {}
        Mock Import-Module {}
        Mock Read-AppLockerPolicy { throw 'Policy must not be read' }
        Mock Set-AppLockerPolicy { throw 'Policy must not be changed' }
        Mock gpupdate.exe { throw 'Group Policy must not be refreshed' }
        Mock Repair-AppLockerEnforcement { throw 'Service-only setup must not launch probes' }
    }

    It 'configures and starts the service without requiring Name or touching policy' {
        $result = Add-AppLockerBlock -PersistServiceStartup -Confirm:$false
        $result.Action | Should -Be 'ServiceConfigured'
        $result.Status | Should -Be 'Running'
        $result.StartType | Should -Be 'Automatic'
        $result.Enforcement | Should -Be 'Unverified'
        Should -Invoke sc.exe -Times 1 -Exactly
        Should -Invoke Start-Service -Times 1 -Exactly
        Should -Invoke Import-Module -Times 0 -Exactly
        Should -Invoke Read-AppLockerPolicy -Times 0 -Exactly
        Should -Invoke Set-AppLockerPolicy -Times 0 -Exactly
        Should -Invoke gpupdate.exe -Times 0 -Exactly
        Should -Invoke Repair-AppLockerEnforcement -Times 0 -Exactly
    }
    It 'enables a Disabled service when persistence is explicitly requested' {
        $script:serviceState.StartType = 'Disabled'
        (Add-AppLockerBlock -PersistServiceStartup -Confirm:$false).Status | Should -Be 'Running'
    }
    It 'does no work when already Automatic and Running' {
        $script:serviceState = [pscustomobject]@{ Status = 'Running'; StartType = 'Automatic' }
        (Add-AppLockerBlock -PersistServiceStartup -Confirm:$false).Status | Should -Be 'Running'
        Should -Invoke sc.exe -Times 0 -Exactly
        Should -Invoke Start-Service -Times 0 -Exactly
    }
    It 'does not mutate the service under WhatIf' {
        @(Add-AppLockerBlock -PersistServiceStartup -WhatIf).Count | Should -Be 0
        Should -Invoke sc.exe -Times 0 -Exactly
        Should -Invoke Start-Service -Times 0 -Exactly
    }
    It 'requires elevation' {
        Mock Test-IsAdministrator { $false }
        { Add-AppLockerBlock -PersistServiceStartup -Confirm:$false } | Should -Throw '*elevated*'
        Should -Invoke sc.exe -Times 0 -Exactly
        Should -Invoke Start-Service -Times 0 -Exactly
    }
    It 'reports a failed native command without starting the service' {
        Mock sc.exe { $global:LASTEXITCODE = 5; 'Access denied' }
        { Add-AppLockerBlock -PersistServiceStartup -Confirm:$false } | Should -Throw '*exit 5*Access denied*'
        Should -Invoke Start-Service -Times 0 -Exactly
    }
    It 'checks startup configuration rather than trusting exit success' {
        Mock sc.exe { $global:LASTEXITCODE = 0 }
        { Add-AppLockerBlock -PersistServiceStartup -Confirm:$false } | Should -Throw '*did not become Automatic*'
    }
    It 'reports service start failure' {
        Mock Start-Service { throw 'Start denied' }
        { Add-AppLockerBlock -PersistServiceStartup -Confirm:$false } | Should -Throw '*Start denied*'
    }
    It 'checks Running status after starting' {
        Mock Start-Service {}
        { Add-AppLockerBlock -PersistServiceStartup -Confirm:$false } | Should -Throw '*did not reach*'
    }
    It 'reports a missing or inaccessible service' {
        Mock Get-Service { throw 'Service unavailable' }
        { Add-AppLockerBlock -PersistServiceStartup -Confirm:$false } | Should -Throw '*Service unavailable*'
    }
    It 'requires a name when the switch is absent or false' {
        { Add-AppLockerBlock } | Should -Throw '*Specify -Name*'
        { Add-AppLockerBlock -PersistServiceStartup:$false } | Should -Throw '*Specify -Name*'
    }
    It 'rejects rule options without a name' {
        { Add-AppLockerBlock -PersistServiceStartup -Mode Hash } | Should -Throw '*Mode requires -Name*'
        Should -Invoke sc.exe -Times 0 -Exactly
    }
}
