Describe 'Install-AiSkills' {
    BeforeAll {
        # Load only the installer and its configuration; dot-sourcing the full
        # interactive profile would alter aliases, modules, and host settings.
        $runTokens = $null
        $runErrors = $null
        $runAst = [System.Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $PSScriptRoot '..\Microsoft.PowerShell_profile.ps1'),
            [ref]$runTokens,
            [ref]$runErrors
        )
        if ($runErrors) { throw "Profile contains parse errors: $($runErrors -join '; ')" }
        $runConfigAst = $runAst.Find({
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left.Extent.Text -eq '$_AiSkillsInternal'
        }, $true)
        $runInstallerAst = $runAst.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'Install-AiSkills'
        }, $true)
        if (-not $runConfigAst -or -not $runInstallerAst) {
            throw 'Could not load Install-AiSkills and its configuration from the profile.'
        }
        . ([scriptblock]::Create($runConfigAst.Extent.Text))
        . ([scriptblock]::Create($runInstallerAst.Extent.Text))
        $script:productionExternalSources = $_AiSkillsInternal.ExternalSources
        $_AiSkillsInternal.ExternalSources = @()
        $script:copyItemCommand = Get-Command Copy-Item -CommandType Cmdlet
        $script:renameItemCommand = Get-Command Rename-Item -CommandType Cmdlet
        $script:fixtureRepo = Join-Path $TestDrive 'fixture-repo'
        $fixtureSkills = Join-Path $script:fixtureRepo 'ai-skills'
        $null = New-Item -ItemType Directory -Path $fixtureSkills -Force

        $allSkills = @(
            $_AiSkillsInternal.OpenCodeClaudeSkills
            $_AiSkillsInternal.AntigravitySharedSkills
            $_AiSkillsInternal.AntigravityCliOnlySkills
            $_AiSkillsInternal.CodexSkills
        ) | Select-Object -Unique

        foreach ($skill in $allSkills) {
            $skillDir = Join-Path $fixtureSkills $skill
            $null = New-Item -ItemType Directory -Path $skillDir -Force
            Set-Content -LiteralPath (Join-Path $skillDir 'SKILL.md') -Value "# $skill" -Encoding UTF8
            Set-Content -LiteralPath (Join-Path $skillDir 'payload.txt') -Value "payload-$skill" -Encoding UTF8
        }

        $polishSkill = Join-Path $fixtureSkills 'polish-document'
        $polishReferences = Join-Path $polishSkill 'references'
        $polishScripts = Join-Path $polishSkill 'scripts'
        $polishAgents = Join-Path $polishSkill 'agents'
        $null = New-Item -ItemType Directory -Path $polishReferences, $polishScripts, $polishAgents -Force
        Set-Content -LiteralPath (Join-Path $polishReferences 'source-reconciliation.md') -Value 'nested-reference' -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $polishScripts 'find-related-files.ps1') -Value 'nested-script' -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $polishAgents 'openai.yaml') -Value 'nested-agent-metadata' -Encoding UTF8

        $externalSkill = Join-Path $script:fixtureRepo 'external-skills\external-test-skill'
        $null = New-Item -ItemType Directory -Path $externalSkill -Force
        Set-Content -LiteralPath (Join-Path $externalSkill 'SKILL.md') -Value '# external-test-skill' -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $externalSkill 'payload.txt') -Value 'external-payload' -Encoding UTF8

        & git -C $script:fixtureRepo init --initial-branch=main
        if ($LASTEXITCODE -ne 0) { throw 'Could not initialize the test Git repository.' }
        & git -C $script:fixtureRepo config user.email 'tests@example.invalid'
        & git -C $script:fixtureRepo config user.name 'Install-AiSkills Tests'
        # Ignore any machine-wide Git exclude rules when building the fixture.
        & git -C $script:fixtureRepo add --force ai-skills external-skills
        $commitOutput = & git -C $script:fixtureRepo -c commit.gpgsign=false commit -m 'test fixture' 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Could not commit the test Git fixture: $($commitOutput -join ' ')" }
    }

    BeforeEach {
        $_AiSkillsInternal.ExternalSources = @()
        $script:originalUserProfile = $env:USERPROFILE
        $script:originalCodexHome = $env:CODEX_HOME
        $env:USERPROFILE = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $env:CODEX_HOME = Join-Path $env:USERPROFILE '.codex'
        $null = New-Item -ItemType Directory -Path $env:USERPROFILE -Force
    }

    AfterEach {
        $env:USERPROFILE = $script:originalUserProfile
        $env:CODEX_HOME = $script:originalCodexHome
    }

    AfterAll {
        $_AiSkillsInternal.ExternalSources = $script:productionExternalSources
    }

    It 'installs and replaces complete skill directories without leftovers' {
        Install-AiSkills -RepoUrl $script:fixtureRepo -Branch main

        $skillPath = Join-Path $env:USERPROFILE '.agents\skills\deep-research'
        Test-Path -LiteralPath (Join-Path $skillPath 'SKILL.md') | Should -BeTrue
        Set-Content -LiteralPath (Join-Path $skillPath 'stale.txt') -Value 'stale'

        Install-AiSkills -RepoUrl $script:fixtureRepo -Branch main

        Test-Path -LiteralPath (Join-Path $skillPath 'stale.txt') | Should -BeFalse
        Test-Path -LiteralPath "$skillPath.tmp-install" | Should -BeFalse
        Test-Path -LiteralPath "$skillPath.backup-install" | Should -BeFalse
    }

    It 'installs the complete polish-document skill for Codex' {
        Install-AiSkills -RepoUrl $script:fixtureRepo -Branch main

        $skillPath = Join-Path $env:CODEX_HOME 'skills\polish-document'
        Test-Path -LiteralPath (Join-Path $skillPath 'SKILL.md') | Should -BeTrue
        Get-Content -LiteralPath (Join-Path $skillPath 'references\source-reconciliation.md') | Should -Be 'nested-reference'
        Get-Content -LiteralPath (Join-Path $skillPath 'scripts\find-related-files.ps1') | Should -Be 'nested-script'
        Get-Content -LiteralPath (Join-Path $skillPath 'agents\openai.yaml') | Should -Be 'nested-agent-metadata'
    }

    It 'routes shared and CLI-only skills to the current Antigravity roots' {
        $appRoot = Join-Path $env:USERPROFILE '.gemini\config\skills'
        $cliRoot = Join-Path $env:USERPROFILE '.gemini\antigravity-cli\skills'
        $null = New-Item -ItemType Directory -Path (Join-Path $appRoot 'unrelated-skill') -Force
        Set-Content -LiteralPath (Join-Path $appRoot 'unrelated-skill\keep.txt') -Value 'keep'

        Install-AiSkills -RepoUrl $script:fixtureRepo -Branch main

        foreach ($root in @($appRoot, $cliRoot)) {
            $skillPath = Join-Path $root 'polish-document'
            Test-Path -LiteralPath (Join-Path $skillPath 'SKILL.md') | Should -BeTrue
            Get-Content -LiteralPath (Join-Path $skillPath 'references\source-reconciliation.md') | Should -Be 'nested-reference'
            Get-Content -LiteralPath (Join-Path $skillPath 'scripts\find-related-files.ps1') | Should -Be 'nested-script'
            Get-Content -LiteralPath (Join-Path $skillPath 'agents\openai.yaml') | Should -Be 'nested-agent-metadata'
        }
        Test-Path -LiteralPath (Join-Path $appRoot 'agy-usage-query') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $appRoot 'session-exporter') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $cliRoot 'agy-usage-query\SKILL.md') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $cliRoot 'session-exporter\SKILL.md') | Should -BeTrue
        Get-Content -LiteralPath (Join-Path $appRoot 'unrelated-skill\keep.txt') | Should -Be 'keep'

        foreach ($root in @($appRoot, $cliRoot)) {
            Set-Content -LiteralPath (Join-Path $root 'polish-document\stale.txt') -Value 'stale'
        }
        Install-AiSkills -RepoUrl $script:fixtureRepo -Branch main
        foreach ($root in @($appRoot, $cliRoot)) {
            Test-Path -LiteralPath (Join-Path $root 'polish-document\stale.txt') | Should -BeFalse
        }
        Get-Content -LiteralPath (Join-Path $appRoot 'unrelated-skill\keep.txt') | Should -Be 'keep'
    }

    It 'installs external skills into both current Antigravity roots' {
        $_AiSkillsInternal.ExternalSources = @(
            @{
                Name       = 'fixture-external'
                RepoUrl    = $script:fixtureRepo
                Branch     = 'main'
                SparsePath = 'external-skills'
                Skills     = @('external-test-skill')
            }
        )

        Install-AiSkills -RepoUrl $script:fixtureRepo -Branch main

        foreach ($relativeRoot in @('.gemini\config\skills', '.gemini\antigravity-cli\skills')) {
            $payload = Join-Path $env:USERPROFILE "$relativeRoot\external-test-skill\payload.txt"
            Get-Content -LiteralPath $payload | Should -Be 'external-payload'
        }
    }

    It 'preserves the previous installation when staging copy fails' {
        $skillPath = Join-Path $env:USERPROFILE '.agents\skills\codebase-docs'
        $null = New-Item -ItemType Directory -Path $skillPath -Force
        Set-Content -LiteralPath (Join-Path $skillPath 'old.txt') -Value 'old'
        Mock Copy-Item { throw 'copy failed' }

        { Install-AiSkills -RepoUrl $script:fixtureRepo -Branch main } | Should -Throw '*copy failed*'

        Get-Content -LiteralPath (Join-Path $skillPath 'old.txt') | Should -Be 'old'
        Test-Path -LiteralPath "$skillPath.tmp-install" | Should -BeFalse
        Test-Path -LiteralPath "$skillPath.backup-install" | Should -BeFalse
    }

    It 'restores the previous installation when staged promotion fails' {
        $skillPath = Join-Path $env:USERPROFILE '.agents\skills\codebase-docs'
        $null = New-Item -ItemType Directory -Path $skillPath -Force
        Set-Content -LiteralPath (Join-Path $skillPath 'old.txt') -Value 'old'
        $script:renameCalls = 0
        Mock Rename-Item {
            param($LiteralPath, $NewName)
            $script:renameCalls++
            if ($script:renameCalls -eq 2) { throw 'promotion failed' }
            & $script:renameItemCommand -LiteralPath $LiteralPath -NewName $NewName -ErrorAction Stop
        }

        { Install-AiSkills -RepoUrl $script:fixtureRepo -Branch main } | Should -Throw '*promotion failed*'

        Get-Content -LiteralPath (Join-Path $skillPath 'old.txt') | Should -Be 'old'
        Test-Path -LiteralPath "$skillPath.tmp-install" | Should -BeFalse
        Test-Path -LiteralPath "$skillPath.backup-install" | Should -BeFalse
    }

    It 'restores the previous App and IDE installation when its copy fails' {
        $skillPath = Join-Path $env:USERPROFILE '.gemini\config\skills\codebase-docs'
        $null = New-Item -ItemType Directory -Path $skillPath -Force
        Set-Content -LiteralPath (Join-Path $skillPath 'old.txt') -Value 'old'
        Mock Copy-Item {
            param($Path, $Destination, $Recurse, $Force)
            if ($Destination -like '*\.gemini\config\skills\*') { throw 'App copy failed' }
            & $script:copyItemCommand -Path $Path -Destination $Destination -Recurse:$Recurse -Force:$Force -ErrorAction Stop
        }

        { Install-AiSkills -RepoUrl $script:fixtureRepo -Branch main } | Should -Throw '*App copy failed*'

        Get-Content -LiteralPath (Join-Path $skillPath 'old.txt') | Should -Be 'old'
        Test-Path -LiteralPath "$skillPath.tmp-install" | Should -BeFalse
        Test-Path -LiteralPath "$skillPath.backup-install" | Should -BeFalse
    }

    It 'configures OpenCode before a later Claude installation failure' {
        Mock Copy-Item {
            param($Path, $Destination, $Recurse, $Force)
            if ($Destination -like '*\.claude\*') { throw 'Claude copy failed' }
            & $script:copyItemCommand -Path $Path -Destination $Destination -Recurse:$Recurse -Force:$Force -ErrorAction Stop
        }

        { Install-AiSkills -RepoUrl $script:fixtureRepo -Branch main } | Should -Throw '*Claude copy failed*'

        $configPath = Join-Path $env:USERPROFILE '.config\opencode\opencode.json'
        $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
        foreach ($skill in $_AiSkillsInternal.OpenCodeClaudeSkills) {
            $config.permission.skill.$skill | Should -Be 'allow'
        }
    }

    It 'does not change OpenCode permissions when its installation fails' {
        $configPath = Join-Path $env:USERPROFILE '.config\opencode\opencode.json'
        $null = New-Item -ItemType Directory -Path (Split-Path -Parent $configPath) -Force
        $originalConfig = '{"permission":{"skill":{"*":"deny"}},"model":"test/model"}'
        [IO.File]::WriteAllText($configPath, $originalConfig, [Text.UTF8Encoding]::new($false))
        Mock Copy-Item { throw 'OpenCode copy failed' }

        { Install-AiSkills -RepoUrl $script:fixtureRepo -Branch main } | Should -Throw '*OpenCode copy failed*'

        Get-Content -LiteralPath $configPath -Raw | Should -BeExactly $originalConfig
    }

    It 'preserves a scalar permission as the wildcard default' {
        $configPath = Join-Path $env:USERPROFILE '.config\opencode\opencode.json'
        $null = New-Item -ItemType Directory -Path (Split-Path -Parent $configPath) -Force
        [IO.File]::WriteAllText($configPath, '{"permission":"ask","model":"test/model"}', [Text.UTF8Encoding]::new($false))

        Install-AiSkills -RepoUrl $script:fixtureRepo -Branch main

        $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
        $config.permission.'*' | Should -Be 'ask'
        $config.model | Should -Be 'test/model'
        $config.permission.skill.'deep-research' | Should -Be 'allow'
    }

    It 'preserves a scalar skill permission as the wildcard default' {
        $configPath = Join-Path $env:USERPROFILE '.config\opencode\opencode.json'
        $null = New-Item -ItemType Directory -Path (Split-Path -Parent $configPath) -Force
        [IO.File]::WriteAllText($configPath, '{"permission":{"skill":"deny"},"model":"test/model"}', [Text.UTF8Encoding]::new($false))

        Install-AiSkills -RepoUrl $script:fixtureRepo -Branch main

        $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
        $config.permission.skill.'*' | Should -Be 'deny'
        $config.model | Should -Be 'test/model'
        $config.permission.skill.'deep-research' | Should -Be 'allow'
    }
}
