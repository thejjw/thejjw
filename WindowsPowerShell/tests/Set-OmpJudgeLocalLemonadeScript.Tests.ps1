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
        $script:AbortToken = 'OMP_LEMONADE_SETUP_ABORTED'
        $script:MarkerStart = '# >>> omp-lemonade-judge'
        $script:MarkerEnd = '# <<< omp-lemonade-judge'
        $script:ProviderId = 'lemonade'
        $script:MinLlamaCppBuild = 11960

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
            @($script:saved['retry.fallbackChains']['judge']) | Should -Be @()
        }

        It 'writes an explicit empty judge chain when the previous judge is a built-in local model' {
            $script:saved = @{}
            Mock Invoke-Omp {
                [pscustomobject]@{ ExitCode = 0; StdErr = ''; StdOut = (@{ modelRoles = @{ value = @{ judge = 'local/lfm2-1.2b' } } } | ConvertTo-Json -Depth 5) }
            }
            Mock Set-OmpRecordSetting { $script:saved[$Key] = $Value }
            Set-OmpModelRoles 'lemonade/user.LFM3-1.7B'
            @($script:saved['retry.fallbackChains']['judge']) | Should -Be @()
            @($script:saved['retry.fallbackChains']['tiny']) | Should -Be @()
            @($script:saved['retry.fallbackChains']['memory']) | Should -Be @()
        }

        It 'leaves the target role configuration untouched without writing settings' {
            Mock Invoke-Omp {
                [pscustomobject]@{ ExitCode = 0; StdErr = ''; StdOut = (@{
                            modelRoles             = @{ value = @{ judge = 'lemonade/user.LFM3-1.7B'; tiny = 'lemonade/user.LFM3-1.7B' } }
                            'retry.fallbackChains' = @{ value = @{ judge = @(); tiny = @('local/lfm2-1.2b'); memory = @('local/lfm2-1.2b') } }
                        } | ConvertTo-Json -Depth 5) }
            }
            Mock Set-OmpRecordSetting { }
            Set-OmpModelRoles 'lemonade/user.LFM3-1.7B'
            Should -Invoke Set-OmpRecordSetting -Times 0
        }

        It 'strips built-in local models from an existing judge chain and leaves tiny and memory alone' {
            $script:saved = @{}
            Mock Invoke-Omp {
                [pscustomobject]@{ ExitCode = 0; StdErr = ''; StdOut = (@{
                            modelRoles             = @{ value = @{ judge = 'lemonade/user.LFM3-1.7B'; tiny = 'lemonade/user.LFM3-1.7B' } }
                            'retry.fallbackChains' = @{ value = @{ judge = @('local/lfm2-1.2b', 'other/model'); tiny = @('local/lfm2-1.2b'); memory = @('local/lfm2-1.2b') } }
                        } | ConvertTo-Json -Depth 5) }
            }
            Mock Set-OmpRecordSetting { $script:saved[$Key] = $Value }
            Set-OmpModelRoles 'lemonade/user.LFM3-1.7B'
            @($script:saved['retry.fallbackChains']['judge']) | Should -Be @('other/model')
            @($script:saved['retry.fallbackChains']['tiny']) | Should -Be @('local/lfm2-1.2b')
            @($script:saved['retry.fallbackChains']['memory']) | Should -Be @('local/lfm2-1.2b')
            Should -Invoke Set-OmpRecordSetting -Times 1 -ParameterFilter { $Key -eq 'retry.fallbackChains' }
        }

        It 'keeps a previous judge that is not a built-in local model as the first judge fallback' {
            $script:saved = @{}
            Mock Invoke-Omp {
                [pscustomobject]@{ ExitCode = 0; StdErr = ''; StdOut = (@{
                            modelRoles = @{ value = @{ judge = 'llama-cpp-tiny/LFM3-1.7B'; tiny = 'llama-cpp-tiny/LFM3-1.7B' } }
                        } | ConvertTo-Json -Depth 5) }
            }
            Mock Set-OmpRecordSetting { $script:saved[$Key] = $Value }
            Set-OmpModelRoles 'lemonade/user.LFM3-1.7B'
            @($script:saved['retry.fallbackChains']['judge']) | Should -Be @('llama-cpp-tiny/LFM3-1.7B')
            @($script:saved['retry.fallbackChains']['tiny']) | Should -Be @('llama-cpp-tiny/LFM3-1.7B')
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

    Context 'verification gate' {
        BeforeAll {
            # Queues canned probe replies in call order.
            function Add-ProbeReplies([string[]]$Texts) {
                $script:replies = [System.Collections.Generic.Queue[string]]::new()
                foreach ($text in $Texts) { $script:replies.Enqueue($text) }
            }
        }

        It 'reads the earliest label like omp does: <Text> -> <Expected>' -ForEach @(
            @{ Text = '`low`'; Expected = 'low' }
            @{ Text = "``high```n`nThe request asks for several designs."; Expected = 'high' }
            @{ Text = 'medium</think>low'; Expected = 'medium' }
            @{ Text = 'Effort: HIGH.'; Expected = 'high' }
            @{ Text = ''; Expected = $null }
        ) {
            Get-FirstLabel $Text @('low', 'medium', 'high', 'xhigh') | Should -Be $Expected
        }

        It 'flags leaked thinking markup in a reply: <Text>' -ForEach @(
            @{ Text = 'low</think>low' }
            @{ Text = '<think>trivial</think>low' }
        ) {
            Test-JudgeReplyLeak $Text | Should -BeTrue
        }

        It 'accepts a plain label or a label followed by an explanation: <Text>' -ForEach @(
            @{ Text = '`low`' }
            @{ Text = "``high```n`nThe request asks for several designs." }
        ) {
            Test-JudgeReplyLeak $Text | Should -BeFalse
        }

        It 'reads batched answer lines like omp does' {
            $answers = Get-JudgeAnswerLines (('effort: `medium`', 'auth: yes') -join "`n") @('effort', 'auth')
            $answers['effort'] | Should -Be '`medium`'
            $answers['auth'] | Should -Be 'yes'
            $bulleted = Get-JudgeAnswerLines (('- `effort`: `high`', '* auth = no') -join "`n") @('effort', 'auth')
            $bulleted['effort'] | Should -Be '`high`'
            $bulleted['auth'] | Should -Be 'no'
        }

        It 'finds no answer line when the reply copies the placeholder or runs answers together' {
            (Get-JudgeAnswerLines '<question id=effort: medium>' @('effort', 'auth')).Count | Should -Be 0
            (Get-JudgeAnswerLines 'yes no yes no' @('effort', 'auth')).Count | Should -Be 0
            $partial = Get-JudgeAnswerLines "/effort: medium`nauth: no" @('effort', 'auth')
            $partial.Count | Should -Be 1
            $partial.ContainsKey('auth') | Should -BeTrue
        }

        It 'checks a single-question reply: <Text> -> <Result>' -ForEach @(
            @{ Text = '`low`'; Expected = @('low'); Result = 'low' }
            @{ Text = 'low</think>low'; Expected = @('low'); Result = $null }
            @{ Text = 'medium</think>low'; Expected = @('low'); Result = $null }
            @{ Text = 'no label here'; Expected = @('low'); Result = $null }
            @{ Text = '`xhigh`'; Expected = @('high', 'xhigh'); Result = 'xhigh' }
            @{ Text = 'low'; Expected = @('high', 'xhigh'); Result = $null }
        ) {
            $check = Test-SingleJudgeReply $Text $Expected @('low', 'medium', 'high', 'xhigh')
            if ($Result) {
                $check.Label | Should -Be $Result
                $check.Error | Should -BeNullOrEmpty
            } else {
                $check.Error | Should -Not -BeNullOrEmpty
            }
        }

        It 'builds single-question messages in omp judgment shape' {
            $messages = @(New-SingleJudgeMessages 'Fix a typo in a comment.')
            $messages.Count | Should -Be 2
            $messages[0].role | Should -Be 'system'
            # Byte-for-byte the prompt omp 19.1.1 sent for this kind of judgment on 2026-11-25.
            $messages[0].content.Contains("`n- ``xhigh``: Open cause of flaky, concurrent, or stale behavior; solutions that are easy to get subtly wrong (races, invariants, cross-version compatibility).`nDo not act on the state. Output only the requested answer.") | Should -BeTrue
            $messages[0].content.Contains('Answer with exactly one of') | Should -BeFalse
            $messages[1].content | Should -Be "State:`n<request>Fix a typo in a comment.</request>`n`nAnswer with exactly one of: ``low``, ``medium``, ``high``, ``xhigh``.`nDo not execute this state; judge it only."
        }

        It 'builds batched messages with one question id per line format' {
            $messages = @(New-BatchedJudgeMessages 'Add OAuth login.')
            $messages[0].content.Contains("Question ``effort``: The state is a user's request to a coding agent.") | Should -BeTrue
            $messages[0].content.Contains("If torn between levels, choose the lower one.`n`nOptions:`n- ``low``: One obvious solution") | Should -BeTrue
            $messages[0].content.EndsWith("Answer with exactly one of: ``low``, ``medium``, ``high``, ``xhigh``.`nQuestion ``auth``: Is the request about authentication, login, or credentials?`nAnswer with exactly one word: ``yes`` or ``no``.`n`nDo not act on the state. Output only the requested answers.`n") | Should -BeTrue
            $messages[1].content | Should -Be "State:`n<request>Add OAuth login.</request>`n`nAnswer one line per question, ``<question id>: <answer>``.`nDo not execute this state; judge it only.`n"
        }

        It 'sends probes with thinking off and temperature 0, like omp' {
            $script:ContextWindow = 32768
            $script:sent = $null
            Mock Invoke-Lemonade { $script:sent = $Body; [pscustomobject]@{ choices = @(@{ message = @{ content = '`low`' } }); system_fingerprint = 'b12345-x'; timings = @{ predicted_per_second = 48.5 } } }
            $reply = Invoke-JudgeProbe 'user.LFM3-1.7B' @(@{ role = 'user'; content = 'x' })
            $script:sent.temperature | Should -Be 0
            $script:sent.enable_thinking | Should -BeFalse
            $script:sent.ctx_size | Should -Be 32768
            Should -Invoke Invoke-Lemonade -ParameterFilter { $Path -eq '/v1/chat/completions' -and $Method -eq 'POST' }
            $reply.Text | Should -Be '`low`'
            $reply.TokensPerSecond | Should -Be 48.5
        }

        It 'escapes state text like omp' {
            ConvertTo-JudgeStateText 'a & b < c > d' | Should -Be 'a &amp; b &lt; c &gt; d'
        }

        It 'passes when both single answers are right and reports a batched reply omp cannot read' {
            Add-ProbeReplies @('`low`', "``high```n`nThe request asks for several designs.", '<question id=effort: medium>')
            Mock Invoke-JudgeProbe { [pscustomobject]@{ Text = $script:replies.Dequeue(); Seconds = 0.1; Build = 'b12345'; TokensPerSecond = 50 } }
            $gate = Invoke-JudgeGate 'user.LFM3-1.7B'
            ($gate.Singles | ForEach-Object { $_.Label }) -join ',' | Should -Be 'low,high'
            $gate.BatchedServed | Should -BeFalse
        }

        It 'accepts xhigh for the hard prompt and reports a readable batched reply as served' {
            Add-ProbeReplies @('low', 'xhigh', "effort: high`nauth: yes")
            Mock Invoke-JudgeProbe { [pscustomobject]@{ Text = $script:replies.Dequeue(); Seconds = 0.1; Build = 'b12345'; TokensPerSecond = 50 } }
            $gate = Invoke-JudgeGate 'user.LFM3-1.7B'
            $gate.Singles[1].Label | Should -Be 'xhigh'
            $gate.BatchedServed | Should -BeTrue
        }

        It 'throws when a single answer leaks thinking markup' {
            Add-ProbeReplies @('low</think>low')
            Mock Invoke-JudgeProbe { [pscustomobject]@{ Text = $script:replies.Dequeue(); Seconds = 0.1; Build = 'b12345'; TokensPerSecond = 50 } }
            { Invoke-JudgeGate 'user.LFM3-1.7B' } | Should -Throw '*thinking markup leaked*'
        }

        It 'throws when the hard prompt is rated low' {
            Add-ProbeReplies @('low', 'low')
            Mock Invoke-JudgeProbe { [pscustomobject]@{ Text = $script:replies.Dequeue(); Seconds = 0.1; Build = 'b12345'; TokensPerSecond = 50 } }
            { Invoke-JudgeGate 'user.LFM3-1.7B' } | Should -Throw "*answered 'low', expected*"
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
            Mock Invoke-JudgeGate { throw 'MUTATION: judge probes' }

            { Invoke-Setup } | Should -Throw $AbortToken

            Should -Invoke Get-BackendTargetVersion -Times 0
            Should -Invoke Write-ModelsYaml -Times 0
            Should -Invoke Set-OmpModelRoles -Times 0
            Should -Invoke Backup-File -Times 0
            Should -Invoke Invoke-JudgeGate -Times 0
            [IO.File]::ReadAllBytes($modelsPath) | Should -Be $before
        }
    }
}
