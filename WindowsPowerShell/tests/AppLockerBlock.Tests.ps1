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
                'Repair-AppLockerEnforcement',
                'Write-AppLockerEnforcementStatus',
                'Stop-AppLockerProcesses',
                'Read-AppLockerPolicy',
                'Resolve-AppLockerTargetFile',
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

        Mock Repair-AppLockerEnforcement { [pscustomobject]@{ Enforcement = 'Unverified'; Recovery = @(); NeedsReboot = $false } }
        Mock Write-AppLockerEnforcementStatus {}

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

        It 'shows a rule that was just added even when the effective policy is still empty' {
            # The effective policy is a snapshot that only catches up with the
            # local policy after a Group Policy refresh, so it can still be
            # empty right after a rule was written.
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
            } -ParameterFilter { -not $Effective }
            Mock Get-AppLockerPolicy { return [xml]'<AppLockerPolicy Version="1" />' } -ParameterFilter { $Effective }

            $report = @(Add-AppLockerBlock -List)

            $report.Count | Should -Be 1
            $report[0].FileName | Should -Be 'example.exe'
            $report[0].Scope | Should -Be 'Local'
        }

        It 'drops a rule that was removed even when the effective policy still holds it' {
            # The same stale snapshot keeps a rule that was removed from the
            # local policy; it must not come back as a Group Policy rule.
            Mock Get-AppLockerPolicy { return [xml]'<AppLockerPolicy Version="1" />' } -ParameterFilter { -not $Effective }
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
            } -ParameterFilter { $Effective }

            $report = @(Add-AppLockerBlock -List)

            $report.Count | Should -Be 0
        }

        It 'shows a rule that a Group Policy contributes' {
            # A rule the local policy does not have and that this profile did
            # not create comes from a Group Policy.
            Mock Get-AppLockerPolicy { return [xml]'<AppLockerPolicy Version="1" />' } -ParameterFilter { -not $Effective }
            Mock Get-AppLockerPolicy {
                return [xml]@'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="22222222-2222-2222-2222-222222222222" Name="Block other.exe" Description="Set by the domain" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions><FilePathCondition Path="*\other.exe" /></Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
'@
            } -ParameterFilter { $Effective }

            $report = @(Add-AppLockerBlock -List)

            $report.Count | Should -Be 1
            $report[0].FileName | Should -Be 'other.exe'
            $report[0].Scope | Should -Be 'GroupPolicy'
            $report[0].Managed | Should -BeFalse
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

        It 'returns an unverified result when live verification is disabled' {
            $result = Add-AppLockerBlock -Name 'example.exe' -NoLiveVerify -NoGroupPolicyRefresh -Confirm:$false -BackupDirectory $TestDrive

            $result.Enforcement | Should -Be 'Unverified'
            Should -Invoke Repair-AppLockerEnforcement -Times 0 -Exactly
        }

        It 'passes audit mode to recovery without changing the requested policy mode' {
            $result = Add-AppLockerBlock -Name 'example.exe' -Enforcement AuditOnly -NoGroupPolicyRefresh -Confirm:$false -BackupDirectory $TestDrive

            $result.Enforcement | Should -Be 'Unverified'
            Should -Invoke Repair-AppLockerEnforcement -Times 1 -Exactly -ParameterFilter { $EnforcementMode -eq 'AuditOnly' }
            ([xml]$script:applied.Xml).AppLockerPolicy.RuleCollection[0].EnforcementMode | Should -Be 'AuditOnly'
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

        It 'verifies and stops both new and already blocked targets in one batch' {
            Mock Get-AppLockerPolicy {
                New-TestPolicy -RuleXml @('<FilePathRule Id="11111111-1111-1111-1111-111111111111" Name="Block example.exe" Description="Created by Add-AppLockerBlock" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="*\example.exe" /></Conditions></FilePathRule>')
            }
            Mock Stop-AppLockerProcesses { 101; 202 }
            Mock Repair-AppLockerEnforcement {
                [pscustomobject]@{ Enforcement = 'Unverified'; Recovery = @(); NeedsReboot = $false; Probes = @(
                    [pscustomobject]@{ FileName = 'example.exe'; Enforced = $true }
                    [pscustomobject]@{ FileName = 'other.exe'; Enforced = $null }
                ) }
            }
            $result = Add-AppLockerBlock -Name 'example.exe','other.exe' -StopRunning -NoGroupPolicyRefresh -Confirm:$false -BackupDirectory $TestDrive

            $result.AlreadyBlocked | Should -Be 'example.exe'
            $result.ProbeResults.Count | Should -Be 2
            $result.StoppedPids | Should -Be @(101, 202)
            Should -Invoke Repair-AppLockerEnforcement -Times 1 -Exactly -ParameterFilter { $FileName.Count -eq 2 -and $FileName -contains 'example.exe' -and $FileName -contains 'other.exe' }
            Should -Invoke Stop-AppLockerProcesses -Times 1 -Exactly -ParameterFilter { $FileName.Count -eq 2 -and $FileName -contains 'example.exe' -and $FileName -contains 'other.exe' }
        }

        It 'passes every already blocked target to verification and process stopping' {
            Mock Get-AppLockerPolicy {
                New-TestPolicy -RuleXml @(
                    '<FilePathRule Id="11111111-1111-1111-1111-111111111111" Name="Block example.exe" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="*\example.exe" /></Conditions></FilePathRule>'
                    '<FilePathRule Id="22222222-2222-2222-2222-222222222222" Name="Block other.exe" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="*\other.exe" /></Conditions></FilePathRule>'
                )
            }
            Mock Stop-AppLockerProcesses { 101; 202 }
            $result = Add-AppLockerBlock -Name 'example.exe','other.exe' -StopRunning -NoGroupPolicyRefresh -Confirm:$false -BackupDirectory $TestDrive

            $result.Action | Should -Be 'AlreadyBlocked'
            Should -Invoke Set-AppLockerPolicy -Times 0 -Exactly
            Should -Invoke Repair-AppLockerEnforcement -Times 1 -Exactly -ParameterFilter { $FileName.Count -eq 2 }
            Should -Invoke Stop-AppLockerProcesses -Times 1 -Exactly -ParameterFilter { $FileName.Count -eq 2 }
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

    Describe 'Rule modes' {
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
            Mock Test-AppLockerPolicy { return [pscustomobject]@{ PolicyDecision = 'Denied' } }

            # Captures the policy document the helper writes.
            $script:applied = @{}
            Mock Set-AppLockerPolicy { $script:applied.Xml = Get-Content -LiteralPath $XmlPolicy -Raw }

            # A stand-in for Get-AppLockerFileInformation on a signed binary.
            $script:fakeFileInfo = [pscustomobject]@{
                Path      = 'C:\Program Files\Vendor\data\example.exe'
                Hash      = 'SHA256 0x76DA8D68E5D73BE3006C26D76D8BD635EED1EA8FD52D83BF12806B01429C9608'
                Publisher = [pscustomobject]@{
                    PublisherName    = 'O=VENDOR INTERNATIONAL INC., S=SEOUL, C=KR'
                    ProductName      = ''
                    BinaryName       = ''
                    HasProductName   = $false
                    HasBinaryName    = $false
                }
            }
            Mock Get-AppLockerFileInformation { return $script:fakeFileInfo }
            Mock Resolve-AppLockerTargetFile { return 'C:\Program Files\Vendor\data\example.exe' }
        }

        It 'writes a path rule by default' {
            Add-AppLockerBlock -Name 'example.exe' -NoGroupPolicyRefresh -Confirm:$false | Out-Null

            $written = [xml]$script:applied.Xml
            $collection = $written.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq 'Exe' }
            $deny = @($collection.FilePathRule | Where-Object { $_.Action -eq 'Deny' })
            $deny.Count | Should -Be 1
            $deny[0].Conditions.FilePathCondition.Path | Should -Be '*\example.exe'
        }

        It 'writes a hash rule in hash mode' {
            Add-AppLockerBlock -Name 'example.exe' -Mode Hash -FilePath 'C:\Program Files\Vendor\data\example.exe' -NoGroupPolicyRefresh -Confirm:$false | Out-Null

            $written = [xml]$script:applied.Xml
            $collection = $written.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq 'Exe' }
            $deny = @($collection.FileHashRule)
            $deny.Count | Should -Be 1
            # The Data attribute holds only the hex value; the algorithm belongs
            # in the Type attribute, and the full "<algo> 0x<hex>" string is
            # rejected by AppLocker.
            $deny[0].Conditions.FileHashCondition.FileHash.Data | Should -Be '0x76DA8D68E5D73BE3006C26D76D8BD635EED1EA8FD52D83BF12806B01429C9608'
            $deny[0].Conditions.FileHashCondition.FileHash.Type | Should -Be 'SHA256'
        }

        It 'normalizes a hash to the value AppLocker expects' {
            $normalized = $_ProfileHelpers.ConvertToAppLockerHashValue('SHA256 0xABCDEF')

            $normalized | Should -Be '0xABCDEF'
        }

        It 'writes a publisher rule in publisher mode' {
            Add-AppLockerBlock -Name 'example.exe' -Mode Publisher -FilePath 'C:\Program Files\Vendor\data\example.exe' -NoGroupPolicyRefresh -Confirm:$false -Force | Out-Null

            $written = [xml]$script:applied.Xml
            $collection = $written.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq 'Exe' }
            $deny = @($collection.FilePublisherRule)
            $deny.Count | Should -Be 1
            $condition = $deny[0].Conditions.FilePublisherCondition
            $condition.PublisherName | Should -Be 'O=VENDOR INTERNATIONAL INC., S=SEOUL, C=KR'
            # No product or binary name means the rule covers the whole publisher.
            $condition.BinaryName | Should -Be '*'
        }

        It 'records the mode in the rule description' {
            Add-AppLockerBlock -Name 'example.exe' -Mode Hash -FilePath 'C:\Program Files\Vendor\data\example.exe' -NoGroupPolicyRefresh -Confirm:$false | Out-Null

            $written = [xml]$script:applied.Xml
            $collection = $written.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq 'Exe' }
            $deny = @($collection.FileHashRule)[0]
            $deny.Description | Should -Be 'Created by Add-AppLockerBlock (mode=hash)'
        }

        It 'refuses to combine -Path and -FilePath' {
            { Add-AppLockerBlock -Name 'example.exe' -Path 'C:\Tools' -FilePath 'C:\Tools\example.exe' -Confirm:$false } |
                Should -Throw '*cannot be combined*'
        }

        It 'fails when the file cannot be resolved to one file' {
            Mock Resolve-AppLockerTargetFile { return $null }

            { Add-AppLockerBlock -Name 'example.exe' -Mode Hash -Confirm:$false } |
                Should -Throw '*exactly one file*'
        }

        It 'reports the collateral of a publisher rule and refuses without -Force' {
            # The collateral scan finds one more executable that the probe
            # policy also denies.
            Mock Get-ChildItem {
                return @(
                    [pscustomobject]@{ FullName = 'C:\Program Files\Vendor\data\example.exe'; PSIsContainer = $false }
                )
            }
            Mock Test-AppLockerPolicy {
                return [pscustomobject]@{
                    FilePath        = 'C:\Program Files\Vendor\data\other.exe'
                    PolicyDecision  = 'Denied'
                }
            }

            { Add-AppLockerBlock -Name 'example.exe' -Mode Publisher -FilePath 'C:\Program Files\Vendor\data\example.exe' -Confirm:$false } |
                Should -Throw '*-Force*'
        }

        It 'adds the publisher rule with -Force despite the collateral' {
            Mock Get-ChildItem {
                return @(
                    [pscustomobject]@{ FullName = 'C:\Program Files\Vendor\data\example.exe'; PSIsContainer = $false }
                )
            }
            Mock Test-AppLockerPolicy {
                return [pscustomobject]@{
                    FilePath        = 'C:\Program Files\Vendor\data\other.exe'
                    PolicyDecision  = 'Denied'
                }
            }

            Add-AppLockerBlock -Name 'example.exe' -Mode Publisher -FilePath 'C:\Program Files\Vendor\data\example.exe' -NoGroupPolicyRefresh -Confirm:$false -Force | Out-Null

            $written = [xml]$script:applied.Xml
            $collection = $written.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq 'Exe' }
            @($collection.FilePublisherRule).Count | Should -Be 1
        }
    }

    Describe 'Resolve-AppLockerTargetFile' {
        BeforeAll {
            $profilePath = Join-Path $PSScriptRoot '..\Microsoft.PowerShell_profile.ps1'
            $tokens = $null
            $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile(
                $profilePath, [ref]$tokens, [ref]$errors)
            $functionAst = $ast.Find({
                    param($node)
                    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                        $node.Name -eq 'Resolve-AppLockerTargetFile'
                }, $true)
            if (-not $functionAst) { throw 'Could not load Resolve-AppLockerTargetFile from the profile.' }
            . ([scriptblock]::Create($functionAst.Extent.Text))
        }

        It 'resolves an explicit file path' {
            $probe = Join-Path $TestDrive 'example.exe'
            Set-Content -LiteralPath $probe -Value 'not a real binary' -Encoding ASCII

            $resolved = Resolve-AppLockerTargetFile -FileName 'example.exe' -FilePath $probe

            $resolved | Should -Not -BeNullOrEmpty
            (Split-Path -Leaf $resolved) | Should -Be 'example.exe'
        }

        It 'returns nothing for a file path that does not exist' {
            Resolve-AppLockerTargetFile -FileName 'example.exe' -FilePath (Join-Path $TestDrive 'missing.exe') |
                Should -BeNullOrEmpty
        }
    }



    Describe 'Update-Profile cache busting' {
        BeforeAll {
            $profilePath = Join-Path $PSScriptRoot '..\Microsoft.PowerShell_profile.ps1'
            $tokens = $null
            $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile(
                $profilePath, [ref]$tokens, [ref]$errors)
            $functionAst = $ast.Find({
                    param($node)
                    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                        $node.Name -eq 'Update-Profile'
                }, $true)
            if (-not $functionAst) { throw 'Could not load Update-Profile from the profile.' }
        }

        It 'adds a cache-busting query string to the download URL' {
            # The raw content endpoint caches for several minutes, so a profile
            # pushed moments ago could be served stale.
            $text = $functionAst.Extent.Text
            $text | Should -Match 'cacheBuster'
            $text | Should -Match ([regex]::Escape('$_ProfileUpdateUrl + $cacheBuster'))
        }
    }

    Describe 'Listing and reverting rule modes' {
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
            $script:applied = @{}
            Mock Set-AppLockerPolicy { $script:applied.Xml = Get-Content -LiteralPath $XmlPolicy -Raw }
        }

        It 'does not print the table and the objects at the same time' {
            Mock Get-AppLockerPolicy { return [xml]'<AppLockerPolicy Version="1" />' }

            $output = @(Add-AppLockerBlock -List)

            # Only the objects come back; the summary lines go to the host.
            $output.Count | Should -Be 0
        }

        It 'prints the blocks as a table with -Format' {
            $policyXml = '<AppLockerPolicy Version="1" />'
            Mock Get-AppLockerPolicy { return [xml]$policyXml }

            $output = @(Add-AppLockerBlock -List -Format)

            # -Format prints the table and returns nothing.
            $output.Count | Should -Be 0
        }

        It 'reports the mode of each block' {
            Mock Get-AppLockerPolicy {
                return [xml]@'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="11111111-1111-1111-1111-111111111111" Name="Block example.exe" Description="Created by Add-AppLockerBlock (mode=path)" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions><FilePathCondition Path="*\example.exe" /></Conditions>
    </FilePathRule>
    <FileHashRule Id="22222222-2222-2222-2222-222222222222" Name="Block other.exe" Description="Created by Add-AppLockerBlock (mode=hash)" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions><FileHashCondition><FileHash Type="SHA256" Data="SHA256 0xABC" SourceFileName="other.exe" SourceFileLength="0" /></FileHashCondition></Conditions>
    </FileHashRule>
  </RuleCollection>
</AppLockerPolicy>
'@
            }

            $report = @(Add-AppLockerBlock -List)

            $report.Count | Should -Be 2
            ($report | Where-Object { $_.FileName -eq 'example.exe' }).Mode | Should -Be 'Path'
            ($report | Where-Object { $_.FileName -eq 'other.exe' }).Mode | Should -Be 'Hash'
        }


        It 'removes a hash rule by its file name' {
            Mock Get-AppLockerPolicy {
                return [xml]@'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FileHashRule Id="22222222-2222-2222-2222-222222222222" Name="Block other.exe" Description="Created by Add-AppLockerBlock (mode=hash)" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions><FileHashCondition><FileHash Type="SHA256" Data="SHA256 0xABC" SourceFileName="other.exe" SourceFileLength="0" /></FileHashCondition></Conditions>
    </FileHashRule>
  </RuleCollection>
</AppLockerPolicy>
'@
            }

            $result = Remove-AppLockerBlock -Name 'other.exe' -NoGroupPolicyRefresh -Confirm:$false

            $result.Action | Should -Be 'Removed'
            $result.RemovedDetails | Should -Be 'Hash: other.exe'
        }

        It 'removes a rule by its rule id' {
            Mock Get-AppLockerPolicy {
                return [xml]@'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="11111111-1111-1111-1111-111111111111" Name="Block example.exe" Description="Created by Add-AppLockerBlock (mode=path)" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions><FilePathCondition Path="*\example.exe" /></Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
'@
            }

            $result = Remove-AppLockerBlock -Name '11111111-1111-1111-1111-111111111111' -NoGroupPolicyRefresh -Confirm:$false

            $result.Action | Should -Be 'Removed'
        }

        It 'keeps the allow-all baseline while another deny rule remains' {
            Mock Get-AppLockerPolicy {
                return [xml]@'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="11111111-1111-1111-1111-111111111111" Name="Allow all executables" Description="Created by Add-AppLockerBlock" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="22222222-2222-2222-2222-222222222222" Name="Block example.exe" Description="Created by Add-AppLockerBlock (mode=path)" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions><FilePathCondition Path="*\example.exe" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="33333333-3333-3333-3333-333333333333" Name="Block other.exe" Description="Created by Add-AppLockerBlock (mode=path)" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions><FilePathCondition Path="*\other.exe" /></Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
'@
            }

            Remove-AppLockerBlock -Name 'example.exe' -NoGroupPolicyRefresh -Confirm:$false | Out-Null

            $written = [xml]$script:applied.Xml
            $collection = $written.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq 'Exe' }
            # The baseline stays because a deny rule is still present.
            @($collection.FilePathRule | Where-Object { $_.Action -eq 'Allow' }).Count | Should -Be 1
            @($collection.FilePathRule | Where-Object { $_.Action -eq 'Deny' }).Count | Should -Be 1
        }
    }
}
