Describe 'Get-QwenUsage' {
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
                $node.Name -eq 'Get-QwenUsage'
        }, $true)
        if (-not $functionAst) { throw 'Could not load Get-QwenUsage from the profile.' }

        $script:qwenFunctionText = $functionAst.Extent.Text
        . ([scriptblock]::Create($script:qwenFunctionText))

        $Global:_ProfileHelpers = [pscustomobject]@{}
        $Global:_ProfileHelpers | Add-Member -MemberType ScriptMethod -Name WriteSection -Value { param($Title) }
        $Global:_ProfileHelpers | Add-Member -MemberType ScriptMethod -Name FormatDuration -Value {
            param([TimeSpan]$Duration)
            return ('{0:N0}m' -f $Duration.TotalMinutes)
        }
    }

    AfterAll {
        Remove-Variable -Name _ProfileHelpers -Scope Global -ErrorAction SilentlyContinue
        Remove-Variable -Name qwenLastQuery -Scope Global -ErrorAction SilentlyContinue
    }

    BeforeEach {
        $script:storedCookie = $null
        $script:queriedCookie = $null
        $script:savedCredentials = [System.Collections.Generic.List[object]]::new()
        $script:hostMessages = [System.Collections.Generic.List[string]]::new()
        $script:vault = [pscustomobject]@{}
        $script:vault | Add-Member -MemberType ScriptMethod -Name Retrieve -Value {
            param($resource, $userName)
            if ($null -eq $script:storedCookie) { throw 'Credential not found.' }
            if ($resource -ne 'QWEN_TOKEN_PLAN_COOKIE' -or $userName -ne 'qwencloud-cookie') {
                throw 'Unexpected credential identity.'
            }

            $credential = [pscustomobject]@{ Password = $script:storedCookie }
            $credential | Add-Member -MemberType ScriptMethod -Name RetrievePassword -Value {}
            return $credential
        }
        $script:vault | Add-Member -MemberType ScriptMethod -Name Add -Value {
            param($credential)
            [void]$script:savedCredentials.Add($credential)
            $script:storedCookie = $credential.Password
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
            if ($TypeName -eq 'System.Collections.Generic.List[object]') {
                Write-Output -NoEnumerate ([System.Collections.Generic.List[object]]::new())
                return
            }
            if ($TypeName -eq 'System.Collections.Generic.List[string]') {
                Write-Output -NoEnumerate ([System.Collections.Generic.List[string]]::new())
                return
            }

            throw "Unexpected New-Object type: $TypeName"
        }
        Mock Read-Host { ConvertTo-SecureString 'fresh=console-cookie' -AsPlainText -Force }
        Mock Write-Host { [void]$script:hostMessages.Add([string]$Object) }
        Mock Out-Host {}
        $Error.Clear()
    }

    It 'uses a stored Cookie without prompting or writing credentials' {
        $script:storedCookie = 'stored=console-cookie'
        $query = {
            param($cookie)
            $script:queriedCookie = $cookie
            [pscustomobject]@{
                Raw = [pscustomobject]@{ requestId = 'stored-query' }
                Limits = @([pscustomobject]@{ Window = '5 Hour Credits'; UsedPercent = 25; ResetAt = $null })
            }
        }

        $result = Get-QwenUsage -QueryInvoker $query

        $script:queriedCookie | Should -Be 'stored=console-cookie'
        $result.requestId | Should -Be 'stored-query'
        $Global:qwenLastQuery.requestId | Should -Be 'stored-query'
        $script:savedCredentials.Count | Should -Be 0
        Should -Invoke Read-Host -Times 0 -Exactly
    }

    It 'guides first-run setup and saves only the validated Cookie' {
        $query = {
            param($cookie)
            $script:queriedCookie = $cookie
            [pscustomobject]@{
                Raw = [pscustomobject]@{ requestId = 'first-query' }
                Limits = @([pscustomobject]@{ Window = '7 Day Credits'; UsedPercent = 40; ResetAt = $null })
            }
        }

        Get-QwenUsage -QueryInvoker $query

        $script:queriedCookie | Should -Be 'fresh=console-cookie'
        $script:savedCredentials.Count | Should -Be 1
        $script:savedCredentials[0].Resource | Should -Be 'QWEN_TOKEN_PLAN_COOKIE'
        $script:savedCredentials[0].UserName | Should -Be 'qwencloud-cookie'
        $script:savedCredentials[0].Password | Should -Be 'fresh=console-cookie'
        $script:hostMessages | Should -Contain '  4. Select exactly: zeldaHttp.apikeyMgr./tokenplan/personal/api/v2/usage'
        $script:hostMessages | Should -Contain '     Do not select: zeldaEasy.bailian-telemetry.platform-model.getModelMonitorDataWithOss'
    }

    It 'forces replacement setup when Setup is specified' {
        $script:storedCookie = 'old=console-cookie'
        $query = {
            param($cookie)
            $script:queriedCookie = $cookie
            [pscustomobject]@{
                Raw = [pscustomobject]@{ requestId = 'replacement-query' }
                Limits = @([pscustomobject]@{ Window = '5 Hour Credits'; UsedPercent = 5; ResetAt = $null })
            }
        }

        Get-QwenUsage -Setup -QueryInvoker $query

        $script:queriedCookie | Should -Be 'fresh=console-cookie'
        $script:savedCredentials.Count | Should -Be 1
        $script:savedCredentials[0].Password | Should -Be 'fresh=console-cookie'
        Should -Invoke Read-Host -Times 1 -Exactly
    }

    It 'does not save a newly entered Cookie when validation rejects it' {
        $query = { throw '[QwenAuth] QwenCloud requires a fresh console login.' }

        Get-QwenUsage -QueryInvoker $query -ErrorAction SilentlyContinue

        $script:savedCredentials.Count | Should -Be 0
        $Error[0].Exception.Message | Should -BeLike '*entered QwenCloud Cookie was rejected and was not saved*Get-QwenUsage -Setup*'
    }

    It 'retains a stale stored Cookie and directs the user to Setup' {
        $script:storedCookie = 'expired=console-cookie'
        $query = { throw '[QwenAuth] QwenCloud requires a fresh console login.' }

        Get-QwenUsage -QueryInvoker $query -ErrorAction SilentlyContinue

        $script:savedCredentials.Count | Should -Be 0
        Should -Invoke Read-Host -Times 0 -Exactly
        $Error[0].Exception.Message | Should -BeLike '*stored QwenCloud Cookie is invalid or expired*Get-QwenUsage -Setup*'
    }

    It 'retains credentials when the query has a transient failure' {
        $script:storedCookie = 'stored=console-cookie'
        $query = { throw '[QwenTransient] QwenCloud usage query timed out.' }

        Get-QwenUsage -QueryInvoker $query -ErrorAction SilentlyContinue

        $script:savedCredentials.Count | Should -Be 0
        $Error[0].Exception.Message | Should -BeLike 'QwenCloud usage query timed out*stored Cookie was retained*'
    }

    It 'does not expose its implementation helpers after invocation' {
        $script:storedCookie = 'stored=console-cookie'
        $query = {
            [pscustomobject]@{
                Raw = [pscustomobject]@{ requestId = 'scope-query' }
                Limits = @([pscustomobject]@{ Window = '5 Hour Credits'; UsedPercent = 10; ResetAt = $null })
            }
        }

        Get-QwenUsage -QueryInvoker $query

        Get-Command Get-StoredCookie -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        Get-Command Save-StoredCookie -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        Get-Command Read-NewCookie -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        Get-Command Invoke-QwenCloudUsageQuery -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }
}
