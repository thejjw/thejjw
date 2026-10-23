Describe 'ConvertFromQwenCloudUsagePayload' {
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

        foreach ($name in @('GetAiUsageJsonProperty', 'ConvertFromQwenCloudUsagePayload')) {
            $functionAst = $ast.Find({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -eq $name
            }, $true)
            if (-not $functionAst) { throw "Could not load $name from the profile." }
            . ([scriptblock]::Create($functionAst.Extent.Text))
        }
    }

    It 'maps the five-hour and seven-day credit windows' {
        $payload = [pscustomobject]@{
            successResponse = $true
            data = [pscustomobject]@{
                DataV2 = [pscustomobject]@{
                    data = [pscustomobject]@{
                        data = [pscustomobject]@{
                            per5HourPercentage  = 0.25
                            per5HourResetTime   = 1800000000000
                            per1WeekPercentage  = 0.5
                            per1WeekResetTime   = 1800100000000
                        }
                    }
                }
            }
        }

        $result = ConvertFromQwenCloudUsagePayload -Payload $payload

        $result.Limits.Count | Should -Be 2
        $result.Limits[0].Window | Should -Be '5 Hour Credits'
        $result.Limits[0].UsedPercent | Should -Be 25
        $result.Limits[0].ResetAt | Should -Be ([DateTimeOffset]::FromUnixTimeMilliseconds(1800000000000))
        $result.Limits[1].Window | Should -Be '7 Day Credits'
        $result.Limits[1].UsedPercent | Should -Be 50
        $result.Limits[1].ResetAt | Should -Be ([DateTimeOffset]::FromUnixTimeMilliseconds(1800100000000))
    }

    It 'maps a monthly-only plan to the monthly credit window' {
        # A monthly plan reports only this bucket; the console never states the
        # span, so the window carries a reset deadline and no duration.
        $payload = [pscustomobject]@{
            successResponse = $true
            data = [pscustomobject]@{
                DataV2 = [pscustomobject]@{
                    data = [pscustomobject]@{
                        data = [pscustomobject]@{
                            per1MonthPercentage = 0.0104
                            per1MonthResetTime  = 1800200000000
                        }
                    }
                }
            }
        }

        $result = ConvertFromQwenCloudUsagePayload -Payload $payload

        $result.Limits.Count | Should -Be 1
        $result.Limits[0].Window | Should -Be 'Monthly Credits'
        $result.Limits[0].UsedPercent | Should -Be ([Math]::Round(1.04, 6))
        $result.Limits[0].ResetAt | Should -Be ([DateTimeOffset]::FromUnixTimeMilliseconds(1800200000000))
    }

    It 'reports the gateway error code when the quota request is rejected' {
        $payload = [pscustomobject]@{
            successResponse = $true
            data = [pscustomobject]@{
                success   = $false
                httpStatus = 200
                errorCode = 'BailianGateway.Workspace.NotAuthorised'
            }
        }

        { ConvertFromQwenCloudUsagePayload -Payload $payload } |
            Should -Throw '*was rejected (errorCode: BailianGateway.Workspace.NotAuthorised)*'
    }

    It 'names the available fields when no quota field is recognized' {
        $payload = [pscustomobject]@{
            successResponse = $true
            data = [pscustomobject]@{
                data = [pscustomobject]@{
                    someNewField = 1
                    anotherField = 2
                }
            }
        }

        { ConvertFromQwenCloudUsagePayload -Payload $payload } |
            Should -Throw '*no recognized quota fields (available fields: anotherField, someNewField)*'
    }

    It 'requires a fresh login when the console session expired' {
        $payload = [pscustomobject]@{
            code = 'ConsoleNeedLogin'
            message = 'You need to log in.'
            successResponse = $false
        }

        # Wildcards, not a literal match: Pester reads '[' as a character class.
        { ConvertFromQwenCloudUsagePayload -Payload $payload } |
            Should -Throw '*QwenAuth*requires a fresh console login*'
    }

    It 'keeps a fractional percentage instead of truncating it' {
        $payload = [pscustomobject]@{
            successResponse = $true
            data = [pscustomobject]@{
                data = [pscustomobject]@{
                    per5HourPercentage = 0.255
                }
            }
        }

        $result = ConvertFromQwenCloudUsagePayload -Payload $payload

        $result.Limits[0].UsedPercent | Should -Be 25.5
    }
}
