Describe 'Get-OpencodeGoUsage' {
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
                $node.Name -eq 'Get-OpencodeGoUsage'
        }, $true)
        if (-not $functionAst) { throw 'Could not load Get-OpencodeGoUsage from the profile.' }

        . ([scriptblock]::Create($functionAst.Extent.Text))

        $Global:_ProfileHelpers = [pscustomobject]@{}
        $Global:_ProfileHelpers | Add-Member -MemberType ScriptMethod -Name WriteUsageTimestamp -Value { param($CommandName) }
        $Global:_ProfileHelpers | Add-Member -MemberType ScriptMethod -Name WriteSection -Value { param($Title) }
        $Global:_ProfileHelpers | Add-Member -MemberType ScriptMethod -Name FormatDuration -Value {
            param([TimeSpan]$Duration)
            return ('{0:N0}m' -f $Duration.TotalMinutes)
        }
    }

    AfterAll {
        Remove-Variable -Name _ProfileHelpers -Scope Global -ErrorAction SilentlyContinue
        Remove-Variable -Name opencodeGoLastQuery -Scope Global -ErrorAction SilentlyContinue
    }

    BeforeEach {
        $script:queriedKey = $null
        $script:hostMessages = [System.Collections.Generic.List[string]]::new()
        $script:savedApiKey = $env:OPENCODE_GO_API_KEY
        $script:savedSharedKey = $env:OPENCODE_API_KEY
        $env:OPENCODE_GO_API_KEY = $null
        $env:OPENCODE_API_KEY = $null


        # A window that is comfortably healthy and far from reset, so concerns in
        # each test come only from the field the test is actually exercising.
        $script:farReset = [DateTimeOffset]::UtcNow.AddDays(30).ToString('o')

        # Start each test from a clean slate so a payload cached by an earlier test
        # cannot satisfy a later assertion about what was (not) stored.
        Remove-Variable -Name opencodeGoLastQuery -Scope Global -ErrorAction SilentlyContinue


        Mock Write-Host { [void]$script:hostMessages.Add([string]$Object) }
        Mock Out-Host {}
        Mock New-Object {
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
        $Error.Clear()
    }

    AfterEach {
        $env:OPENCODE_GO_API_KEY = $script:savedApiKey
        $env:OPENCODE_API_KEY = $script:savedSharedKey
    }

    It 'accepts the shared OPENCODE_API_KEY when no Go-specific key is set' {
        Mock Test-Path { $false }
        $env:OPENCODE_API_KEY = 'shared-key'
        $query = {
            param($key)
            $script:queriedKey = $key
            [pscustomobject]@{
                usage = [pscustomobject]@{
                    rolling = [pscustomobject]@{ status = 'ok'; percent = 1; resetsAt = $script:farReset }
                }
            }
        }

        Get-OpencodeGoUsage -QueryInvoker $query | Out-Null

        $script:queriedKey | Should -Be 'shared-key'
    }

    It 'reports all three windows and stashes the payload' {
        $query = {
            param($key)
            $script:queriedKey = $key
            [pscustomobject]@{
                usage = [pscustomobject]@{
                    rolling = [pscustomobject]@{ status = 'ok'; percent = 10; resetsAt = $script:farReset }
                    weekly  = [pscustomobject]@{ status = 'ok'; percent = 20; resetsAt = $script:farReset }
                    monthly = [pscustomobject]@{ status = 'ok'; percent = 30; resetsAt = $script:farReset }
                }
            }
        }

        $result = Get-OpencodeGoUsage -ApiKey 'test-key' -QueryInvoker $query

        $script:queriedKey | Should -Be 'test-key'
        $result.usage.monthly.percent | Should -Be 30
        $Global:opencodeGoLastQuery.usage.rolling.percent | Should -Be 10
        $script:hostMessages | Should -Contain '  (suppressed; stored in $Global:opencodeGoLastQuery. Use -All to display inline.)'
        $script:hostMessages | Should -Contain '  No concerns flagged.'
    }

    It 'shows the raw payload only when All is set' {
        $query = {
            param($key)
            [pscustomobject]@{
                usage = [pscustomobject]@{
                    rolling = [pscustomobject]@{ status = 'ok'; percent = 1; resetsAt = $script:farReset }
                }
            }
        }
        # Format-Table also writes through Out-Host, so match on the serialized
        # payload rather than counting total Out-Host calls.
        $isRawPayload = { [string]$InputObject -match '"usage"' }

        Get-OpencodeGoUsage -ApiKey 'test-key' -QueryInvoker $query | Out-Null
        Should -Invoke Out-Host -Times 0 -Exactly -ParameterFilter $isRawPayload

        Get-OpencodeGoUsage -ApiKey 'test-key' -All -QueryInvoker $query | Out-Null
        Should -Invoke Out-Host -Times 1 -Exactly -ParameterFilter $isRawPayload
    }


    It 'flags a rate-limited window as critical even when its percent is low' {
        $query = {
            param($key)
            [pscustomobject]@{
                usage = [pscustomobject]@{
                    rolling = [pscustomobject]@{ status = 'rate-limited'; percent = 5; resetsAt = $script:farReset }
                    weekly  = [pscustomobject]@{ status = 'ok'; percent = 20; resetsAt = $script:farReset }
                }
            }
        }

        Get-OpencodeGoUsage -ApiKey 'test-key' -QueryInvoker $query | Out-Null

        $script:hostMessages | Should -Contain '  - [CRITICAL] Rolling: upstream reports rate-limited'
    }

    It 'grades used percent against the warn thresholds' {
        $query = {
            param($key)
            [pscustomobject]@{
                usage = [pscustomobject]@{
                    rolling = [pscustomobject]@{ status = 'ok'; percent = 82; resetsAt = $script:farReset }
                    weekly  = [pscustomobject]@{ status = 'ok'; percent = 96; resetsAt = $script:farReset }
                    monthly = [pscustomobject]@{ status = 'ok'; percent = 80; resetsAt = $script:farReset }
                }
            }
        }

        Get-OpencodeGoUsage -ApiKey 'test-key' -QueryInvoker $query | Out-Null

        $script:hostMessages | Should -Contain '  - [LOW]      Rolling: 82.0% used (>= 80%)'
        $script:hostMessages | Should -Contain '  - [CRITICAL] Weekly: 96.0% used (>= 95%)'
        # 80 sits exactly on the low threshold and must still be reported.
        $script:hostMessages | Should -Contain '  - [LOW]      Monthly: 80.0% used (>= 80%)'
    }

    It 'rejects a critical threshold below the low threshold' {
        $query = { param($key) throw 'must not be called' }

        Get-OpencodeGoUsage -ApiKey 'test-key' -LowPercent 90 -CriticalPercent 10 -QueryInvoker $query -ErrorAction SilentlyContinue

        $script:queriedKey | Should -BeNullOrEmpty
        $Error[0].Exception.Message | Should -BeLike '*CriticalPercent must be greater than or equal to LowPercent*'
    }

    It 'parses a percent delivered as a string' {
        $query = {
            param($key)
            [pscustomobject]@{
                usage = [pscustomobject]@{
                    rolling = [pscustomobject]@{ status = 'ok'; percent = '77.5'; resetsAt = $script:farReset }
                }
            }
        }

        Get-OpencodeGoUsage -ApiKey 'test-key' -LowPercent 70 -QueryInvoker $query | Out-Null

        $script:hostMessages | Should -Contain '  - [LOW]      Rolling: 77.5% used (>= 70%)'
    }

    It 'reports a window that resets inside the warn horizon' {
        $soon = [DateTimeOffset]::UtcNow.AddMinutes(30).ToString('o')
        $query = {
            param($key)
            [pscustomobject]@{
                usage = [pscustomobject]@{
                    rolling = [pscustomobject]@{ status = 'ok'; percent = 10; resetsAt = $soon }
                }
            }
        }

        Get-OpencodeGoUsage -ApiKey 'test-key' -ResetWarnHours 1 -QueryInvoker $query | Out-Null

        $script:hostMessages | Should -Contain '  - [INFO]     Rolling: resets in 30m'
    }

    It 'surfaces the key guidance when no key can be resolved' {
        Mock Test-Path { $false }

        Get-OpencodeGoUsage -QueryInvoker { param($key) throw 'must not be called' } -ErrorAction SilentlyContinue

        $script:queriedKey | Should -BeNullOrEmpty
        $Error[0].Exception.Message | Should -BeLike '*No OpenCode Go API key found*opencode.ai/auth*'
    }

    It 'prefers the Go-specific session variable over every other source' {
        Mock Test-Path { $true }
        Mock Get-Content { '{"opencode-go":{"type":"api","key":"store-key"}}' }
        $env:OPENCODE_GO_API_KEY = 'go-env-key'
        $env:OPENCODE_API_KEY = 'shared-key'
        $query = {
            param($key)
            $script:queriedKey = $key
            [pscustomobject]@{
                usage = [pscustomobject]@{
                    rolling = [pscustomobject]@{ status = 'ok'; percent = 1; resetsAt = $script:farReset }
                }
            }
        }

        Get-OpencodeGoUsage -QueryInvoker $query | Out-Null

        $script:queriedKey | Should -Be 'go-env-key'
    }

    It 'prefers the shared session variable over the OpenCode auth store' {
        Mock Test-Path { $true }
        Mock Get-Content { '{"opencode-go":{"type":"api","key":"store-key"},"opencode":{"type":"api","key":"zen-key"}}' }
        $env:OPENCODE_API_KEY = 'shared-key'
        $query = {
            param($key)
            $script:queriedKey = $key
            [pscustomobject]@{
                usage = [pscustomobject]@{
                    rolling = [pscustomobject]@{ status = 'ok'; percent = 1; resetsAt = $script:farReset }
                }
            }
        }

        Get-OpencodeGoUsage -QueryInvoker $query | Out-Null

        # The documented order is Go-specific env, then the shared env, then the
        # store -- so an explicit session variable must beat a stored key.
        $script:queriedKey | Should -Be 'shared-key'
    }

    It 'falls back to the opencode-go entry in the auth store' {
        Mock Test-Path { $true }
        Mock Get-Content { '{"opencode-go":{"type":"api","key":"store-key"},"opencode":{"type":"api","key":"zen-key"}}' }
        $query = {
            param($key)
            $script:queriedKey = $key
            [pscustomobject]@{
                usage = [pscustomobject]@{
                    rolling = [pscustomobject]@{ status = 'ok'; percent = 1; resetsAt = $script:farReset }
                }
            }
        }

        Get-OpencodeGoUsage -QueryInvoker $query | Out-Null

        # The Zen entry shares the file but must never be mistaken for the Go key.
        $script:queriedKey | Should -Be 'store-key'
    }

    It 'ignores a non-api auth store entry' {
        Mock Test-Path { $true }
        Mock Get-Content { '{"opencode-go":{"type":"oauth","refresh":"r","access":"a","expires":1}}' }

        Get-OpencodeGoUsage -QueryInvoker { param($key) throw 'must not be called' } -ErrorAction SilentlyContinue

        $Error[0].Exception.Message | Should -BeLike '*No OpenCode Go API key found*'
    }

    It 'passes through the tagged auth, subscription, and transient failures' {
        Get-OpencodeGoUsage -ApiKey 'k' -QueryInvoker { param($key) throw '[GoAuth] OpenCode Go rejected the API key.' } -ErrorAction SilentlyContinue
        $Error[0].Exception.Message | Should -Be '[GoAuth] OpenCode Go rejected the API key.'
        Should -Invoke Out-Host -Times 0 -Exactly

        $Error.Clear()
        Get-OpencodeGoUsage -ApiKey 'k' -QueryInvoker { param($key) throw '[GoSubscription] An OpenCode Go subscription is required for this key.' } -ErrorAction SilentlyContinue
        $Error[0].Exception.Message | Should -Be '[GoSubscription] An OpenCode Go subscription is required for this key.'

        $Error.Clear()
        Get-OpencodeGoUsage -ApiKey 'k' -QueryInvoker { param($key) throw '[GoTransient] The OpenCode Go usage query timed out.' } -ErrorAction SilentlyContinue
        $Error[0].Exception.Message | Should -Be '[GoTransient] The OpenCode Go usage query timed out.'
    }

    It 'rejects an error envelope returned with HTTP 200' {
        $query = {
            param($key)
            [pscustomobject]@{ type = 'error'; error = [pscustomobject]@{ type = 'AuthError'; message = 'Unauthorized' } }
        }

        Get-OpencodeGoUsage -ApiKey 'k' -QueryInvoker $query -ErrorAction SilentlyContinue

        $Error[0].Exception.Message | Should -Be 'OpenCode Go returned no usage payload.'
        Get-Variable opencodeGoLastQuery -Scope Global -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }

    It 'does not expose its implementation helper after invocation' {
        $query = {
            param($key)
            [pscustomobject]@{
                usage = [pscustomobject]@{
                    rolling = [pscustomobject]@{ status = 'ok'; percent = 1; resetsAt = $script:farReset }
                }
            }
        }

        Get-OpencodeGoUsage -ApiKey 'test-key' -QueryInvoker $query | Out-Null

        Get-Command Invoke-OpencodeGoUsageQuery -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }
}
