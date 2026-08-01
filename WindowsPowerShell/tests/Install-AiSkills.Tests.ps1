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
        $script:copyItemCommand = Get-Command Copy-Item -CommandType Cmdlet
        $script:renameItemCommand = Get-Command Rename-Item -CommandType Cmdlet
        $script:fixtureRepo = Join-Path $TestDrive 'fixture-repo'
        $fixtureSkills = Join-Path $script:fixtureRepo 'ai-skills'
        $null = New-Item -ItemType Directory -Path $fixtureSkills -Force

        $allSkills = @(
            $_AiSkillsInternal.OpenCodeClaudeSkills
            $_AiSkillsInternal.AntigravitySkills
            $_AiSkillsInternal.CodexSkills
        ) | Select-Object -Unique

        foreach ($skill in $allSkills) {
            $skillDir = Join-Path $fixtureSkills $skill
            $null = New-Item -ItemType Directory -Path $skillDir -Force
            Set-Content -LiteralPath (Join-Path $skillDir 'SKILL.md') -Value "# $skill" -Encoding UTF8
            Set-Content -LiteralPath (Join-Path $skillDir 'payload.txt') -Value "payload-$skill" -Encoding UTF8
        }

        & git -C $script:fixtureRepo init --initial-branch=main
        if ($LASTEXITCODE -ne 0) { throw 'Could not initialize the test Git repository.' }
        & git -C $script:fixtureRepo config user.email 'tests@example.invalid'
        & git -C $script:fixtureRepo config user.name 'Install-AiSkills Tests'
        # Ignore any machine-wide Git exclude rules when building the fixture.
        & git -C $script:fixtureRepo add --force ai-skills
        $commitOutput = & git -C $script:fixtureRepo -c commit.gpgsign=false commit -m 'test fixture' 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Could not commit the test Git fixture: $($commitOutput -join ' ')" }
    }

    BeforeEach {
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
