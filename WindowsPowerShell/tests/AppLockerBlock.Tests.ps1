Describe 'AppLocker block helpers' {
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

        # Load only the definitions these tests need; the full profile is not
        # dot-sourced so its side effects (credential loading) do not run.
        $helpersAst = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left.Extent.Text -eq '$_ProfileHelpers'
        }, $true)
        if (-not $helpersAst) { throw 'Could not load profile helpers from the profile.' }
        . ([scriptblock]::Create($helpersAst.Extent.Text))

        $internalAst = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left.Extent.Text -eq '$_AppLockerInternal'
        }, $true)
        if (-not $internalAst) { throw 'Could not load AppLocker internal configuration.' }
        . ([scriptblock]::Create($internalAst.Extent.Text))

        foreach ($functionName in @(
                'Read-AppLockerPolicy',
                'Get-AppLockerRuleIdList',
                'Add-AppLockerBlock',
                'Remove-AppLockerBlock',
                'Test-IsAdministrator'
            )) {
            $functionAst = $ast.Find({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -eq $functionName
            }, $true)
            if (-not $functionAst) { throw "Could not load $functionName from the profile." }
            . ([scriptblock]::Create($functionAst.Extent.Text))
        }

        function New-TestPolicy {
            param(
                [string]$Type = 'Exe',
                [string]$EnforcementMode = 'Enabled',
                [string[]]$RuleXml = @()
            )

            $rules = ($RuleXml -join "`n")
            return [xml]@"
<AppLockerPolicy Version="1">
  <RuleCollection Type="$Type" EnforcementMode="$EnforcementMode">
$rules
  </RuleCollection>
</AppLockerPolicy>
"@
        }
    }

    Describe 'Add-AppLockerBlock -List' {
        BeforeAll {
            Mock Test-IsAdministrator { return $true }
            Mock Import-Module {}
            Mock Get-AppLockerPolicy {
                return [xml]@'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="11111111-1111-1111-1111-111111111111" Name="Block example.exe" Description="Created by Add-AppLockerBlock" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions><FilePathCondition Path="*\example.exe" /></Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
'@
            }
            Mock Write-Host {}
        }

        It 'reports the filename blocks that exist' {
            $report = @(Add-AppLockerBlock -List)

            $report.Count | Should -Be 1
            $report[0].FileName | Should -Be 'example.exe'
            $report[0].Path | Should -Be '*\example.exe'
            $report[0].Action | Should -Be 'Deny'
        }

        It 'marks rules created by this profile as managed' {
            $report = @(Add-AppLockerBlock -List)

            $report[0].Managed | Should -BeTrue
            $report[0].Scope | Should -Be 'Local'
        }

        It 'lists without elevation because it only reads the policy' {
            Mock Test-IsAdministrator { return $false }

            $report = @(Add-AppLockerBlock -List)

            $report.Count | Should -Be 1
        }

        It 'lists an empty policy without failing' {
            # A machine without a local policy has no EXE rule collection, so
            # there are no local rule ids to compare against.
            Mock Get-AppLockerPolicy { return [xml]'<AppLockerPolicy Version="1" />' }

            $report = @(Add-AppLockerBlock -List)

            $report.Count | Should -Be 0
        }
    }

    Describe 'Add-AppLockerBlock rule building' {
        BeforeAll {
            Mock Test-IsAdministrator { return $true }
            Mock Import-Module {}
            Mock Write-Host {}
            Mock Write-Warning {}
            Mock Get-AppLockerPolicy { return [xml]'<AppLockerPolicy Version="1" />' }
            Mock Set-AppLockerPolicy {}
            Mock Get-Service {
                return [pscustomobject]@{ Name = 'AppIDSvc'; Status = 'Running'; StartType = 'Manual' }
            }
            Mock Start-Service {}
            Mock Set-Service {}
            Mock gpupdate.exe {}

            # Captures the policy file the helper writes, so the resulting
            # document can be inspected.
            $script:applied = @{}
            Mock Set-AppLockerPolicy { $script:applied.Xml = Get-Content -LiteralPath $XmlPolicy -Raw }
        }

        It 'refuses to run without elevation' {
            Mock Test-IsAdministrator { return $false }

            { Add-AppLockerBlock -Name example.exe } | Should -Throw '*elevated*'
        }

        It 'rejects a name that contains a directory' {
            { Add-AppLockerBlock -Name 'C:\Tools\example.exe' } | Should -Throw '*without a directory*'
        }

        It 'rejects a name that contains a wildcard' {
            { Add-AppLockerBlock -Name 'exam*.exe' } | Should -Throw '*wildcard*'
        }

        It 'adds a deny rule and an allow-all baseline to an empty policy' {
            $result = Add-AppLockerBlock -Name 'example.exe' -NoGroupPolicyRefresh -Confirm:$false

            $result.Action | Should -Be 'Blocked'
            $result.BlockedFiles | Should -Be 'example.exe'
            $result.BlockedPaths | Should -Be '*\example.exe'

            Should -Invoke -CommandName Set-AppLockerPolicy -Times 1 -Exactly
        }

        It 'does not add a second deny rule for an already blocked name' {
            Mock Get-AppLockerPolicy {
                return [xml]@'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="11111111-1111-1111-1111-111111111111" Name="Block example.exe" Description="Created by Add-AppLockerBlock" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions><FilePathCondition Path="*\example.exe" /></Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
'@
            }

            $result = Add-AppLockerBlock -Name 'example.exe' -NoGroupPolicyRefresh -Confirm:$false

            $result.Action | Should -Be 'AlreadyBlocked'
            $result.BlockedFiles | Should -Be 'example.exe'
            Should -Invoke -CommandName Set-AppLockerPolicy -Times 0 -Exactly
        }

        It 'writes a backup of the previous policy' {
            $backupRoot = Join-Path $TestDrive 'backups'
            $result = Add-AppLockerBlock -Name 'example.exe' -NoGroupPolicyRefresh -Confirm:$false -BackupDirectory $backupRoot

            $result.BackupPath | Should -Not -BeNullOrEmpty
            Test-Path -LiteralPath $result.BackupPath | Should -BeTrue
        }

        It 'scopes the rule to a directory when -Path is given' {
            $result = Add-AppLockerBlock -Name 'app.exe' -Path 'C:\Tools' -NoGroupPolicyRefresh -Confirm:$false

            $result.BlockedPaths | Should -Be 'C:\Tools\app.exe'
        }

        It 'applies the policy as a valid AppLocker document' {
            Add-AppLockerBlock -Name 'example.exe' -NoGroupPolicyRefresh -Confirm:$false | Out-Null

            $script:applied.Xml | Should -Not -BeNullOrEmpty
            $written = [xml]$script:applied.Xml
            $collection = $written.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq 'Exe' }
            $collection | Should -Not -BeNullOrEmpty
            $collection.EnforcementMode | Should -Be 'Enabled'

            $deny = @($collection.FilePathRule | Where-Object { $_.Action -eq 'Deny' })
            $deny.Count | Should -Be 1
            $deny[0].Conditions.FilePathCondition.Path | Should -Be '*\example.exe'
        }

        It 'adds a packaged-app rule so packaged apps stay runnable' {
            Add-AppLockerBlock -Name 'example.exe' -NoGroupPolicyRefresh -Confirm:$false | Out-Null

            $written = [xml]$script:applied.Xml
            $appx = $written.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq 'Appx' }
            $appx | Should -Not -BeNullOrEmpty
            @($appx.FilePublisherRule).Count | Should -Be 1
        }
    }

    Describe 'Remove-AppLockerBlock' {
        BeforeAll {
            Mock Test-IsAdministrator { return $true }
            Mock Import-Module {}
            Mock Write-Host {}
            Mock Write-Warning {}
            Mock Set-AppLockerPolicy {}
            Mock Get-Service {
                return [pscustomobject]@{ Name = 'AppIDSvc'; Status = 'Running'; StartType = 'Manual' }
            }
            Mock Start-Service {}
            Mock Set-Service {}
            Mock gpupdate.exe {}

            # Captures the policy file the helper writes, so the resulting
            # document can be inspected.
            $script:applied = @{}
            Mock Set-AppLockerPolicy { $script:applied.Xml = Get-Content -LiteralPath $XmlPolicy -Raw }
        }

        It 'removes the matching deny rule' {
            Mock Get-AppLockerPolicy {
                return [xml]@'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="11111111-1111-1111-1111-111111111111" Name="Block example.exe" Description="Created by Add-AppLockerBlock" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions><FilePathCondition Path="*\example.exe" /></Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
'@
            }

            $result = Remove-AppLockerBlock -Name 'example.exe' -NoGroupPolicyRefresh -Confirm:$false

            $result.Action | Should -Be 'Removed'
            $result.Removed | Should -Be '*\example.exe'
            Should -Invoke -CommandName Set-AppLockerPolicy -Times 1 -Exactly
        }

        It 'removes a rule matched by its rule id' {
            Mock Get-AppLockerPolicy {
                return [xml]@'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="11111111-1111-1111-1111-111111111111" Name="Block example.exe" Description="Created by Add-AppLockerBlock" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions><FilePathCondition Path="*\example.exe" /></Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
'@
            }

            $result = Remove-AppLockerBlock -Name '11111111-1111-1111-1111-111111111111' -NoGroupPolicyRefresh -Confirm:$false

            $result.Action | Should -Be 'Removed'
        }

        It 'keeps a rule that this profile did not create' {
            Mock Get-AppLockerPolicy {
                return [xml]@'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="22222222-2222-2222-2222-222222222222" Name="hand written" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions><FilePathCondition Path="*\other.exe" /></Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
'@
            }

            $result = Remove-AppLockerBlock -Name 'other.exe' -NoGroupPolicyRefresh -Confirm:$false

            $result.Action | Should -Be 'NotFound'
            $result.Kept.Count | Should -Be 1
            Should -Invoke -CommandName Set-AppLockerPolicy -Times 0 -Exactly
        }

        It 'removes a hand-written rule when -Force is given' {
            Mock Get-AppLockerPolicy {
                return [xml]@'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="22222222-2222-2222-2222-222222222222" Name="hand written" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions><FilePathCondition Path="*\other.exe" /></Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
'@
            }

            $result = Remove-AppLockerBlock -Name 'other.exe' -Force -NoGroupPolicyRefresh -Confirm:$false

            $result.Action | Should -Be 'Removed'
            Should -Invoke -CommandName Set-AppLockerPolicy -Times 1 -Exactly
        }

        It 'removes the allow-all baseline once no deny rule is left' {
            Mock Get-AppLockerPolicy {
                return [xml]@'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="33333333-3333-3333-3333-333333333333" Name="Allow all executables" Description="Created by Add-AppLockerBlock" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="11111111-1111-1111-1111-111111111111" Name="Block example.exe" Description="Created by Add-AppLockerBlock" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions><FilePathCondition Path="*\example.exe" /></Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
'@
            }

            Remove-AppLockerBlock -Name 'example.exe' -NoGroupPolicyRefresh -Confirm:$false | Out-Null

            $written = [xml]$script:applied.Xml
            $written.AppLockerPolicy.RuleCollection | Should -BeNullOrEmpty
        }
    }

    Describe 'Revert path' {
        BeforeAll {
            Mock Test-IsAdministrator { return $true }
            Mock Import-Module {}
            Mock Write-Host {}
            Mock Write-Warning {}
            Mock Set-AppLockerPolicy {}
            Mock Get-Service {
                return [pscustomobject]@{ Name = 'AppIDSvc'; Status = 'Running'; StartType = 'Manual' }
            }
            Mock Start-Service {}
            Mock Set-Service {}
            Mock gpupdate.exe {}
        }

        It 'removes the block through the revert path' {
            Mock Get-AppLockerPolicy {
                return [xml]@'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="11111111-1111-1111-1111-111111111111" Name="Block example.exe" Description="Created by Add-AppLockerBlock" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions><FilePathCondition Path="*\example.exe" /></Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
'@
            }

            Add-AppLockerBlock -Revert -Name 'example.exe' -NoGroupPolicyRefresh -Confirm:$false | Out-Null

            Should -Invoke -CommandName Set-AppLockerPolicy -Times 1 -Exactly
        }
    }
}
