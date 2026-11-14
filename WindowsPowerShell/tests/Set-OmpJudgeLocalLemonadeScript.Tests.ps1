Describe 'Set-OmpJudgeLocalLemonade.ps1 helpers' {
    BeforeAll {
        # Load only the function definitions from the util script (no execution, no exit).
        $scriptPath = Join-Path $PSScriptRoot '..\util\Set-OmpJudgeLocalLemonade.ps1'
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
        if ($errors) { throw "Script contains parse errors: $($errors -join '; ')" }
        $functions = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)
        foreach ($function in $functions) { . ([scriptblock]::Create($function.Extent.Text)) }

        # Script-level constants the helpers read.
        $AbortToken = 'OMP_LEMONADE_SETUP_ABORTED'
        $MarkerStart = '# >>> omp-lemonade-judge'
        $MarkerEnd = '# <<< omp-lemonade-judge'
        $ProviderId = 'lemonade'
        $MinLlamaCppBuild = 11960

        # Builds a models.yml from raw lines and returns the parsed plan.
        function New-Models([string[]]$Content) {
            $path = Join-Path $TestDrive ("models-{0}.yml" -f [Guid]::NewGuid().ToString('N'))
            [IO.File]::WriteAllText($path, ($Content -join "`n") + "`n")
            Read-ModelsYaml $path
        }
    }

    Context 'collision preflight' {
        It 'rejects a replacement onto an unmanaged sibling provider id' {
            $plan = New-Models @(
                'providers:'
                '  # >>> omp-lemonade-judge (managed by Set-OmpJudgeLocalLemonade.ps1; re-run to update, delete through the end marker to remove)'
                '  lemonade-old:'
                "    baseUrl: 'http://127.0.0.1:8000/v1'"
                '  # <<< omp-lemonade-judge'
                '  lemonade:'
                "    baseUrl: 'http://127.0.0.1:8000/v1'"
            )
            $plan.Mode | Should -Be 'conflict'
        }

        It 'rejects a collision hidden behind supported quoting' {
            $plan = New-Models @(
                'providers:'
                '  # >>> omp-lemonade-judge (managed by Set-OmpJudgeLocalLemonade.ps1; re-run to update, delete through the end marker to remove)'
                '  lemonade-old:'
                "    baseUrl: 'http://127.0.0.1:8000/v1'"
                '  # <<< omp-lemonade-judge'
                "  'lemonade':"
                "    baseUrl: 'http://127.0.0.1:8000/v1'"
            )
            $plan.Mode | Should -Be 'conflict'
        }

        It 'allows replacing when the managed block itself declares the requested id' {
            $plan = New-Models @(
                'providers:'
                '  # >>> omp-lemonade-judge (managed by Set-OmpJudgeLocalLemonade.ps1; re-run to update, delete through the end marker to remove)'
                '  lemonade:'
                "    baseUrl: 'http://127.0.0.1:8000/v1'"
                '  # <<< omp-lemonade-judge'
                '  other:'
                "    baseUrl: 'http://127.0.0.1:2/v1'"
            )
            $plan.Mode | Should -Be 'replace'
        }

        It 'does not treat nested model keys or comments as a provider collision' {
            $plan = New-Models @(
                'providers:'
                '  # >>> omp-lemonade-judge (managed by Set-OmpJudgeLocalLemonade.ps1; re-run to update, delete through the end marker to remove)'
                '  lemonade-old:'
                "    baseUrl: 'http://127.0.0.1:8000/v1'"
                '    models:'
                '      lemonade/LFM3-1.7B:'
                '        contextWindow: 32768'
                '  # <<< omp-lemonade-judge'
                '  # lemonade: mentioned in a comment'
                '  other:'
                "    baseUrl: 'http://127.0.0.1:2/v1'"
            )
            $plan.Mode | Should -Be 'replace'
        }

        It 'ignores matching ids under other top-level mappings when providers is absent' {
            $plan = New-Models @(
                'modelRoles:'
                '  judge: lemonade/LFM3-1.7B'
                '  # >>> omp-lemonade-judge (managed by Set-OmpJudgeLocalLemonade.ps1; re-run to update, delete through the end marker to remove)'
                '  lemonade-old:'
                "    baseUrl: 'http://127.0.0.1:8000/v1'"
                '  # <<< omp-lemonade-judge'
                '  lemonade:'
                "    baseUrl: 'http://127.0.0.1:8000/v1'"
            )
            $plan.Mode | Should -Be 'replace'
        }

        It 'rejects an unmanaged collision without a managed block (existing behavior)' {
            $plan = New-Models @(
                'providers:'
                '  other:'
                "    baseUrl: 'http://127.0.0.1:2/v1'"
                '  lemonade:'
                "    baseUrl: 'http://127.0.0.1:8000/v1'"
            )
            $plan.Mode | Should -Be 'conflict'
        }

        It 'still rejects a missing end marker and flow-style providers' {
            $missing = Join-Path $TestDrive 'models-missing-end.yml'
            [IO.File]::WriteAllText($missing, "providers:`n  # >>> omp-lemonade-judge (managed)`n  lemonade-old:`n")
            { Read-ModelsYaml $missing } | Should -Throw $AbortToken

            $flow = Join-Path $TestDrive 'models-flow.yml'
            [IO.File]::WriteAllText($flow, "providers: {other: {}}`n")
            (Read-ModelsYaml $flow).Mode | Should -Be 'flow'
        }
    }
    Context 'role assignment' {
        It 'inherits the previous tiny role for memory while LFM3 takes over both selectors' {
            $script:saved = @{}
            Mock Invoke-Omp {
                [pscustomobject]@{ ExitCode = 0; StdErr = ''; StdOut = (@{
                            modelRoles             = @{ value = @{ judge = 'local/lfm2-1.2b'; tiny = 'local/lfm2-1.2b' } }
                            'retry.fallbackChains' = @{ value = @{ judge = @('local/lfm2-1.2b') } }
                        } | ConvertTo-Json -Depth 5) }
            }
            Mock Set-OmpRecordSetting { $script:saved[$Key] = $Value }
            Set-OmpModelRoles 'lemonade/user.LFM3-1.7B'
            $script:saved['modelRoles']['judge'] | Should -Be 'lemonade/user.LFM3-1.7B'
            $script:saved['modelRoles']['tiny'] | Should -Be 'lemonade/user.LFM3-1.7B'
            $script:saved['modelRoles'].Contains('memory') | Should -BeFalse
            @($script:saved['retry.fallbackChains']['tiny']) | Should -Be @('local/lfm2-1.2b')
            @($script:saved['retry.fallbackChains']['memory']) | Should -Be @('local/lfm2-1.2b')
        }

        It 'writes explicit empty tiny and memory chains without a previous tiny role' {
            $script:saved = @{}
            Mock Invoke-Omp {
                [pscustomobject]@{ ExitCode = 0; StdErr = ''; StdOut = (@{ modelRoles = @{ value = @{ judge = 'local/lfm2-1.2b' } } } | ConvertTo-Json -Depth 5) }
            }
            Mock Set-OmpRecordSetting { $script:saved[$Key] = $Value }
            Set-OmpModelRoles 'lemonade/user.LFM3-1.7B'
            @($script:saved['retry.fallbackChains']['judge']) | Should -Be @('local/lfm2-1.2b')
            @($script:saved['retry.fallbackChains']['tiny']) | Should -Be @()
            @($script:saved['retry.fallbackChains']['memory']) | Should -Be @()
        }

        It 'leaves the target role configuration untouched without writing settings' {
            Mock Invoke-Omp {
                [pscustomobject]@{ ExitCode = 0; StdErr = ''; StdOut = (@{
                            modelRoles             = @{ value = @{ judge = 'lemonade/user.LFM3-1.7B'; tiny = 'lemonade/user.LFM3-1.7B' } }
                            'retry.fallbackChains' = @{ value = @{ judge = @('local/lfm2-1.2b'); tiny = @('local/lfm2-1.2b'); memory = @('local/lfm2-1.2b') } }
                        } | ConvertTo-Json -Depth 5) }
            }
            Mock Set-OmpRecordSetting { }
            Set-OmpModelRoles 'lemonade/user.LFM3-1.7B'
            Should -Invoke Set-OmpRecordSetting -Times 0
        }

        It 'preserves an explicit memory selection and its existing chain' {
            $script:saved = @{}
            Mock Invoke-Omp {
                [pscustomobject]@{ ExitCode = 0; StdErr = ''; StdOut = (@{
                            modelRoles             = @{ value = @{ tiny = 'local/lfm2-1.2b'; memory = 'other/memory' } }
                            'retry.fallbackChains' = @{ value = @{ memory = @('other/fallback') } }
                        } | ConvertTo-Json -Depth 5) }
            }
            Mock Set-OmpRecordSetting { $script:saved[$Key] = $Value }
            Set-OmpModelRoles 'lemonade/user.LFM3-1.7B'
            $script:saved['modelRoles']['memory'] | Should -Be 'other/memory'
            @($script:saved['retry.fallbackChains']['memory']) | Should -Be @('other/fallback')
        }
    }
    Context 'setup stops before mutations on a collision' {
        It 'reports conflict, runs no mutating helper, and leaves models.yml untouched' {
            $script:agentDir = Join-Path $TestDrive 'agent'
            New-Item -ItemType Directory -Path $script:agentDir -Force | Out-Null
            $modelsPath = Join-Path $script:agentDir 'models.yml'
            $lines = @(
                'providers:'
                '  # >>> omp-lemonade-judge (managed by Set-OmpJudgeLocalLemonade.ps1; re-run to update, delete through the end marker to remove)'
                '  lemonade-old:'
                "    baseUrl: 'http://127.0.0.1:8000/v1'"
                '  # <<< omp-lemonade-judge'
                '  lemonade:'
                "    baseUrl: 'http://127.0.0.1:8000/v1'"
                '    api: openai-completions'
            )
            [IO.File]::WriteAllText($modelsPath, ($lines -join "`n") + "`n")
            $before = [IO.File]::ReadAllBytes($modelsPath)

            # Read-only preflight stubs: both tools exist, Lemonade answers, omp answers.
            Mock Update-SetupPath { }
            Mock Initialize-Lemonade { [pscustomobject]@{ ExitCode = 0; StdErr = ''; StdOut = '{"port":8000,"version":"test"}' } }
            Mock Get-Command { [pscustomobject]@{ Source = 'tool' } } -ParameterFilter { $Name -eq 'omp' }
            Mock Invoke-Cli { [pscustomobject]@{ ExitCode = 0; StdErr = ''; StdOut = '{"port":8000,"version":"test"}' } } -ParameterFilter { $Command -eq 'lemonade' }
            Mock Invoke-Omp {
                if ($Arguments.Count -ge 2 -and $Arguments[0] -eq 'config' -and $Arguments[1] -eq 'path') {
                    [pscustomobject]@{ ExitCode = 0; StdErr = ''; StdOut = $script:agentDir }
                } else {
                    [pscustomobject]@{ ExitCode = 1; StdErr = ''; StdOut = '' }
                }
            }
            Mock Get-OmpSetting { $null }
            Mock Get-LemonadeState {
                [pscustomobject]@{
                    BackendName    = 'vulkan'
                    BackendState   = 'installed'
                    BackendVersion = 'b12345'
                    BackendMessage = ''
                    Model          = $null
                    Ignored        = @()
                    ModelIds       = @()
                }
            }
            # Every helper past the preflight must stay unused: zero calls is the assertion.
            Mock Get-BackendTargetVersion { throw 'MUTATION: backend resolution' }
            Mock Write-ModelsYaml { throw 'MUTATION: models.yml write' }
            Mock Set-OmpModelRoles { throw 'MUTATION: omp settings write' }
            Mock Backup-File { throw 'MUTATION: backup' }
            Mock Invoke-TestPrompt { throw 'MUTATION: test prompt' }

            { Invoke-Setup } | Should -Throw $AbortToken

            Should -Invoke Get-BackendTargetVersion -Times 0
            Should -Invoke Write-ModelsYaml -Times 0
            Should -Invoke Set-OmpModelRoles -Times 0
            Should -Invoke Backup-File -Times 0
            Should -Invoke Invoke-TestPrompt -Times 0
            [IO.File]::ReadAllBytes($modelsPath) | Should -Be $before
        }
    }
}
