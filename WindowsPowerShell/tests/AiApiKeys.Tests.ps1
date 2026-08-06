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
        foreach ($functionName in @('Set-AiApiKeysCS', 'Load-AiApiKeysFromCS')) {
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

        . ([scriptblock]::Create($script:functionAsts['Set-AiApiKeysCS'].Extent.Text))
    }

    BeforeEach {
        $script:savedCredentials = [System.Collections.Generic.List[object]]::new()
        $script:existingCredentials = @{}
        $script:failBailianSave = $false
        $script:hostMessages = [System.Collections.Generic.List[string]]::new()
        $script:vault = [pscustomobject]@{
            Saved   = $script:savedCredentials
            Existing = $script:existingCredentials
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
}
