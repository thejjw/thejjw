Describe 'AI API key credential helpers' {
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

        $script:functionAsts = @{}
        foreach ($functionName in @('Set-AiApiKeysCS', 'Load-AiApiKeysFromCS', 'Remove-AiApiKeysFromCS')) {
            $functionAst = $ast.Find({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -eq $functionName
            }, $true)
            if (-not $functionAst) { throw "Could not find $functionName in the profile." }

            $script:functionAsts[$functionName] = $functionAst
        }

        $deprecatedFunction = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'Set-AiApiKeys'
        }, $true)
        $script:deprecatedFunctionExists = $null -ne $deprecatedFunction

        foreach ($functionName in $script:functionAsts.Keys) {
            . ([scriptblock]::Create($script:functionAsts[$functionName].Extent.Text))
        }
    }

    BeforeEach {
        $script:savedCredentials = [System.Collections.Generic.List[object]]::new()
        $script:existingCredentials = @{}
        $script:failBailianSave = $false
        $script:failRemoveResource = $null
        $script:failRetrieveAll = $false
        $script:hostMessages = [System.Collections.Generic.List[string]]::new()
        $script:removedCredentials = [System.Collections.Generic.List[object]]::new()
        $script:vaultCredentials = [System.Collections.Generic.List[object]]::new()
        $script:vault = [pscustomobject]@{
            All      = $script:vaultCredentials
            Existing = $script:existingCredentials
            Removed  = $script:removedCredentials
            Saved    = $script:savedCredentials
        }
        $script:vault | Add-Member -MemberType ScriptMethod -Name Retrieve -Value {
            param($resource, $userName)
            if (-not $this.Existing.ContainsKey($resource)) { throw "Missing credential: $resource" }

            $credential = [pscustomobject]@{ Password = $this.Existing[$resource] }
            $credential | Add-Member -MemberType ScriptMethod -Name RetrievePassword -Value {}
            return $credential
        }
        $script:vault | Add-Member -MemberType ScriptMethod -Name Add -Value {
            param($credential)
            if ($script:failBailianSave -and $credential.Resource -eq 'BAILIAN_TOKEN_PLAN_API_KEY') {
                throw 'Simulated Bailian save failure.'
            }

            [void]$this.Saved.Add($credential)
        }
        $script:vault | Add-Member -MemberType ScriptMethod -Name RetrieveAll -Value {
            if ($script:failRetrieveAll) { throw 'Simulated vault enumeration failure.' }
            return @($this.All)
        }
        $script:vault | Add-Member -MemberType ScriptMethod -Name Remove -Value {
            param($credential)
            if ($credential.Resource -eq $script:failRemoveResource) {
                throw "Simulated removal failure: $($credential.Resource)"
            }
            [void]$this.Removed.Add($credential)
        }

        $script:processNames = @('KIMI_CODE_PLAN_API_KEY', 'TEST_GROUPED_API_KEY', 'TEST_OTHER_API_KEY')
        $script:originalProcessValues = @{}
        foreach ($name in $script:processNames) {
            $script:originalProcessValues[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
        }

        Mock New-Object {
            if ($TypeName -eq 'Windows.Security.Credentials.PasswordVault') {
                return $script:vault
            }
            if ($TypeName -eq 'Windows.Security.Credentials.PasswordCredential') {
                return [pscustomobject]@{
                    Resource = [string]$ArgumentList[0]
                    UserName = [string]$ArgumentList[1]
                    Password = [string]$ArgumentList[2]
                }
            }

            throw "Unexpected New-Object type: $TypeName"
        }
        Mock Read-Host {
            if ($AsSecureString -and $Prompt -like 'Enter value for QWEN_TOKEN_PLAN_API_KEY*') {
                return ConvertTo-SecureString 'test-qwen-token' -AsPlainText -Force
            }
            if ($AsSecureString) { return [System.Security.SecureString]::new() }
            return 'n'
        }
        Mock Write-Host { [void]$script:hostMessages.Add([string]$Object) }
    }

    AfterEach {
        foreach ($name in $script:processNames) {
            [Environment]::SetEnvironmentVariable($name, $script:originalProcessValues[$name], 'Process')
        }
    }

    It 'removes the deprecated Set-AiApiKeys command' {
        $script:deprecatedFunctionExists | Should -BeFalse
    }

    It 'stores one Qwen input under both credential names without a Bailian prompt' {
        Set-AiApiKeysCS

        $script:savedCredentials.Count | Should -Be 2
        $script:savedCredentials[0].Resource | Should -Be 'QWEN_TOKEN_PLAN_API_KEY'
        $script:savedCredentials[1].Resource | Should -Be 'BAILIAN_TOKEN_PLAN_API_KEY'
        $script:savedCredentials[1].Password | Should -Be $script:savedCredentials[0].Password
        Should -Invoke Read-Host -Times 0 -Exactly -ParameterFilter {
            $Prompt -like '*BAILIAN_TOKEN_PLAN_API_KEY*'
        }
        $script:hostMessages | Should -Contain (
            'Duplicated QWEN_TOKEN_PLAN_API_KEY to BAILIAN_TOKEN_PLAN_API_KEY in Windows Credential Manager.'
        )
    }

    It 'does not backfill Bailian when an existing Qwen credential is skipped' {
        $script:existingCredentials['QWEN_TOKEN_PLAN_API_KEY'] = 'existing-qwen-token'

        Set-AiApiKeysCS

        $script:savedCredentials.Count | Should -Be 0
    }

    It 'does not duplicate Qwen when its input is blank' {
        Mock Read-Host {
            if ($AsSecureString) { return [System.Security.SecureString]::new() }
            return 'n'
        }

        Set-AiApiKeysCS

        $script:savedCredentials.Count | Should -Be 0
    }

    It 'does not duplicate Qwen when a forced overwrite is declined' {
        $script:existingCredentials['QWEN_TOKEN_PLAN_API_KEY'] = 'existing-qwen-token'

        Set-AiApiKeysCS -Force

        $script:savedCredentials.Count | Should -Be 0
    }

    It 'retains the Qwen save and reports a Bailian-specific alias failure' {
        $script:failBailianSave = $true

        Set-AiApiKeysCS

        $script:savedCredentials.Count | Should -Be 1
        $script:savedCredentials[0].Resource | Should -Be 'QWEN_TOKEN_PLAN_API_KEY'
        $script:hostMessages.Where({ $_ -like 'Failed to duplicate QWEN_TOKEN_PLAN_API_KEY to BAILIAN_TOKEN_PLAN_API_KEY:*' }).Count |
            Should -Be 1
    }

    It 'loads the Bailian alias without adding it to the setter prompt list' {
        $setterText = $script:functionAsts['Set-AiApiKeysCS'].Extent.Text
        $loaderText = $script:functionAsts['Load-AiApiKeysFromCS'].Extent.Text

        $setterNames = [regex]::Match($setterText, '\$names\s*=\s*@\(([^\r\n]+)\)').Groups[1].Value
        $loaderNames = [regex]::Match($loaderText, '\$names\s*=\s*@\(([^\r\n]+)\)').Groups[1].Value
        $setterNames | Should -Not -Match 'BAILIAN_TOKEN_PLAN_API_KEY'
        $loaderNames | Should -Match 'BAILIAN_TOKEN_PLAN_API_KEY'
    }

    It 'uses the dedicated Kimi Code plan credential name' {
        $setterText = $script:functionAsts['Set-AiApiKeysCS'].Extent.Text
        $loaderText = $script:functionAsts['Load-AiApiKeysFromCS'].Extent.Text
        $deprecatedKimiName = 'KIMI_' + 'API_KEY'

        $setterText | Should -Match 'KIMI_CODE_PLAN_API_KEY'
        $loaderText | Should -Match 'KIMI_CODE_PLAN_API_KEY'
        $setterText | Should -Not -Match ([regex]::Escape($deprecatedKimiName))
        $loaderText | Should -Not -Match ([regex]::Escape($deprecatedKimiName))
    }

    It 'removes only grouped credentials and clears their process variables' {
        $grouped = [pscustomobject]@{ Resource = 'TEST_GROUPED_API_KEY'; UserName = 'api-key' }
        $unrelated = [pscustomobject]@{ Resource = 'TEST_OTHER_API_KEY'; UserName = 'other-group' }
        [void]$script:vaultCredentials.Add($grouped)
        [void]$script:vaultCredentials.Add($unrelated)
        [Environment]::SetEnvironmentVariable('TEST_GROUPED_API_KEY', 'grouped-value', 'Process')
        [Environment]::SetEnvironmentVariable('TEST_OTHER_API_KEY', 'other-value', 'Process')

        Remove-AiApiKeysFromCS -Confirm:$false

        $script:removedCredentials.Count | Should -Be 1
        $script:removedCredentials[0] | Should -Be $grouped
        [Environment]::GetEnvironmentVariable('TEST_GROUPED_API_KEY', 'Process') | Should -BeNullOrEmpty
        [Environment]::GetEnvironmentVariable('TEST_OTHER_API_KEY', 'Process') | Should -Be 'other-value'
        $script:hostMessages | Should -Contain (
            'Scrubbed 1 credential(s) from the api-key group and cleared 1 process variable(s).'
        )
    }

    It 'does not mutate the vault or process environment with WhatIf' {
        $credential = [pscustomobject]@{ Resource = 'TEST_GROUPED_API_KEY'; UserName = 'api-key' }
        [void]$script:vaultCredentials.Add($credential)
        [Environment]::SetEnvironmentVariable('TEST_GROUPED_API_KEY', 'grouped-value', 'Process')

        Remove-AiApiKeysFromCS -WhatIf

        $script:removedCredentials.Count | Should -Be 0
        [Environment]::GetEnvironmentVariable('TEST_GROUPED_API_KEY', 'Process') | Should -Be 'grouped-value'
    }

    It 'does not clear an ungrouped process variable when the grouped vault is empty' {
        [Environment]::SetEnvironmentVariable('KIMI_CODE_PLAN_API_KEY', 'kimi-value', 'Process')

        Remove-AiApiKeysFromCS -Confirm:$false

        $script:removedCredentials.Count | Should -Be 0
        [Environment]::GetEnvironmentVariable('KIMI_CODE_PLAN_API_KEY', 'Process') | Should -Be 'kimi-value'
        $script:hostMessages | Should -Contain (
            'Scrubbed 0 credential(s) from the api-key group and cleared 0 process variable(s).'
        )
    }

    It 'lists each successfully scrubbed resource in verbose mode' {
        $first = [pscustomobject]@{ Resource = 'TEST_GROUPED_API_KEY'; UserName = 'api-key' }
        $second = [pscustomobject]@{ Resource = 'KIMI_CODE_PLAN_API_KEY'; UserName = 'api-key' }
        [void]$script:vaultCredentials.Add($first)
        [void]$script:vaultCredentials.Add($second)

        $verboseMessages = @(Remove-AiApiKeysFromCS -Confirm:$false -Verbose 4>&1)
        $renderedMessages = @($verboseMessages | ForEach-Object { $_.ToString() })

        $renderedMessages | Should -Contain 'Scrubbed credential: TEST_GROUPED_API_KEY'
        $renderedMessages | Should -Contain 'Scrubbed credential: KIMI_CODE_PLAN_API_KEY'
    }

    It 'derives cleanup names from the credential group instead of a managed-name list' {
        $removerText = $script:functionAsts['Remove-AiApiKeysFromCS'].Extent.Text

        $removerText | Should -Not -Match 'DEEPSEEK_API_KEY'
        $removerText | Should -Not -Match 'KIMI_CODE_PLAN_API_KEY'
    }

    It 'makes no changes when vault enumeration fails' {
        $script:failRetrieveAll = $true
        [Environment]::SetEnvironmentVariable('KIMI_CODE_PLAN_API_KEY', 'kimi-value', 'Process')

        Remove-AiApiKeysFromCS -Confirm:$false -ErrorAction SilentlyContinue

        $script:removedCredentials.Count | Should -Be 0
        [Environment]::GetEnvironmentVariable('KIMI_CODE_PLAN_API_KEY', 'Process') | Should -Be 'kimi-value'
    }

    It 'continues after an individual credential removal fails' {
        $failed = [pscustomobject]@{ Resource = 'TEST_GROUPED_API_KEY'; UserName = 'api-key' }
        $removed = [pscustomobject]@{ Resource = 'KIMI_CODE_PLAN_API_KEY'; UserName = 'api-key' }
        [void]$script:vaultCredentials.Add($failed)
        [void]$script:vaultCredentials.Add($removed)
        $script:failRemoveResource = 'TEST_GROUPED_API_KEY'
        [Environment]::SetEnvironmentVariable('TEST_GROUPED_API_KEY', 'failed-value', 'Process')
        [Environment]::SetEnvironmentVariable('KIMI_CODE_PLAN_API_KEY', 'removed-value', 'Process')

        Remove-AiApiKeysFromCS -Confirm:$false 2>$null

        $script:removedCredentials.Count | Should -Be 1
        $script:removedCredentials[0] | Should -Be $removed
        [Environment]::GetEnvironmentVariable('TEST_GROUPED_API_KEY', 'Process') | Should -BeNullOrEmpty
        [Environment]::GetEnvironmentVariable('KIMI_CODE_PLAN_API_KEY', 'Process') | Should -BeNullOrEmpty
    }
}
