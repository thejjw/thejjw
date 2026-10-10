Describe 'Install-OpenCodeSettings' {
    BeforeAll {
        # Load only the installer and the helpers it calls; dot-sourcing the full
        # interactive profile would alter aliases, modules, and host settings.
        $runTokens = $null
        $runErrors = $null
        $runAst = [System.Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $PSScriptRoot '..\Microsoft.PowerShell_profile.ps1'),
            [ref]$runTokens,
            [ref]$runErrors
        )
        if ($runErrors) { throw "Profile contains parse errors: $($runErrors -join '; ')" }

        function Get-ProfileAssignment {
            param([string]$Name)
            $runAst.Find({
                param($node)
                $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                    $node.Left.Extent.Text -eq $Name
            }, $true)
        }

        $runConfigAst = Get-ProfileAssignment '$_OpenCodeInternal'
        if (-not $runConfigAst) { throw 'Could not load $_OpenCodeInternal from the profile.' }
        . ([scriptblock]::Create($runConfigAst.Extent.Text))

        foreach ($helperName in @('Save-ProcessEnvVars', 'Restore-ProcessEnvVars', 'Install-OpenCodeSettings')) {
            $helperAst = $runAst.Find({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -eq $helperName
            }, $true)
            if (-not $helperAst) { throw "Could not load $helperName from the profile." }
            . ([scriptblock]::Create($helperAst.Extent.Text))
        }

        # The installer only needs the four files it validates plus enough extra
        # entries to prove a sparse checkout skips everything else. The real
        # plugin files are copied so the installer itself can run for real.
        $script:pluginFiles = @(
            'index.ts'
            'package.json'
            'src/advisor.ts'
            'scripts/install.mjs'
            'commands/advisor.md'
        )
        $script:repoPluginDir = Join-Path $PSScriptRoot '..\..\oc\plugins\oc-advisor'
        $script:fixtureRepo = Join-Path $TestDrive 'fixture-repo'
        $pluginRoot = Join-Path (Join-Path $script:fixtureRepo 'oc') 'plugins'
        $pluginRoot = Join-Path $pluginRoot 'oc-advisor'
        foreach ($relative in $script:pluginFiles) {
            $source = Join-Path $script:repoPluginDir ($relative -replace '/', '\')
            if (-not (Test-Path -LiteralPath $source)) {
                throw "Missing plugin file in the repository: $source"
            }
            $target = Join-Path $pluginRoot ($relative -replace '/', '\')
            $null = New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force
            Copy-Item -LiteralPath $source -Destination $target -Force
        }
        # Decoys: a root file and an unrelated directory that must not appear.
        Set-Content -LiteralPath (Join-Path $script:fixtureRepo 'README.md') -Value 'root readme' -Encoding UTF8
        $decoyDir = Join-Path (Join-Path $script:fixtureRepo 'bin') 'tools'
        $null = New-Item -ItemType Directory -Path $decoyDir -Force
        Set-Content -LiteralPath (Join-Path $decoyDir 'decoy.sh') -Value 'decoy' -Encoding UTF8
        $null = New-Item -ItemType Directory -Path (Join-Path $script:fixtureRepo 'ai-skills') -Force
        Set-Content -LiteralPath (Join-Path $script:fixtureRepo 'ai-skills\SKILL.md') -Value 'decoy skill' -Encoding UTF8

        & git -C $script:fixtureRepo init --initial-branch=main
        if ($LASTEXITCODE -ne 0) { throw 'Could not initialize the fixture Git repository.' }
        & git -C $script:fixtureRepo config user.email 'tests@example.invalid'
        & git -C $script:fixtureRepo config user.name 'Install-OpenCodeSettings Tests'
        # Keep the fixture byte-stable across checkout so the hash verdict is
        # deterministic whatever the machine's global autocrlf setting is.
        & git -C $script:fixtureRepo config core.autocrlf false
        & git -C $script:fixtureRepo add --force .
        $commitOutput = & git -C $script:fixtureRepo -c commit.gpgsign=false commit -m 'test fixture' 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Could not commit the test Git fixture: $($commitOutput -join ' ')" }

        $_OpenCodeInternal.RepoUrl = $script:fixtureRepo

        # The tests must not change the persistent User PATH.
        $script:persistentUserPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
    }

    AfterAll {
        [Environment]::GetEnvironmentVariable('PATH', 'User') | Should -Be $script:persistentUserPath
    }

    BeforeEach {
        $script:originalPath = $env:PATH
        $script:originalUserProfile = $env:USERPROFILE

        $script:sandboxHome = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $script:sandboxHome -Force
        $env:USERPROFILE = $script:sandboxHome

        $script:cloneDir = Join-Path $script:sandboxHome 'clone'
        $script:nodeArgsFile = Join-Path $script:sandboxHome 'node-args.txt'

        # Shadow node with a shim so the exact argument list and exit code are
        # observable without depending on a real Node installation.
        $script:fakeBin = Join-Path $script:sandboxHome 'fakebin'
        $null = New-Item -ItemType Directory -Path $script:fakeBin -Force
        $shim = @(
            '@echo off'
            'echo %*>>"%OC_TEST_NODE_ARGS%"'
            'if "%~1"=="--version" echo v20.11.0'
            'if "%OC_TEST_NODE_EXIT%"=="" exit /b 0'
            'exit /b %OC_TEST_NODE_EXIT%'
        ) -join "`r`n"
        [IO.File]::WriteAllText((Join-Path $script:fakeBin 'node.cmd'), $shim, [Text.Encoding]::ASCII)

        $env:OC_TEST_NODE_ARGS = $script:nodeArgsFile
        Remove-Item Env:\OC_TEST_NODE_EXIT -ErrorAction SilentlyContinue
        $env:PATH = "$script:fakeBin;$env:PATH"
    }

    AfterEach {
        $env:PATH = $script:originalPath
        $env:USERPROFILE = $script:originalUserProfile
        Remove-Item Env:\OC_TEST_NODE_ARGS -ErrorAction SilentlyContinue
        Remove-Item Env:\OC_TEST_NODE_EXIT -ErrorAction SilentlyContinue
    }

    It 'clones only the plugin, installs, verifies, and removes the clone' {
        # Pre-place a matching installed copy so the hash verdict is deterministic.
        $installedDir = Join-Path $script:sandboxHome ('.config\opencode\plugins\oc-advisor\src')
        $null = New-Item -ItemType Directory -Path $installedDir -Force
        Copy-Item -LiteralPath (Join-Path (Join-Path $script:fixtureRepo 'oc\plugins\oc-advisor\src') 'advisor.ts') -Destination $installedDir

        $output = @(Install-OpenCodeSettings -Ref main -CloneDir $script:cloneDir -SkipValidate 6>&1 | Out-String)

        $installedArgs = @(Get-Content -LiteralPath $script:nodeArgsFile)
        @($installedArgs | Where-Object { $_ -like '*install.mjs*' -and $_ -notlike '*--status*' }).Count | Should -Be 1
        @($installedArgs | Where-Object { $_ -like '*install.mjs*--status*' }).Count | Should -Be 1
        $output | Should -BeLike '*advisor.ts: MATCH*'
        Test-Path -LiteralPath $script:cloneDir | Should -BeFalse
    }

    It 'keeps the clone on request and checks out nothing outside the plugin path' {
        Install-OpenCodeSettings -Ref main -CloneDir $script:cloneDir -SkipValidate -KeepClone 6>&1 | Out-String

        Test-Path -LiteralPath $script:cloneDir | Should -BeTrue
        @(& git -C $script:cloneDir sparse-checkout list) | Should -Be @('oc/plugins/oc-advisor')
        # The index lists the whole tree; 'S' entries are skip-worktree (absent
        # from disk), so the materialized set must be exactly the plugin files.
        $materialized = @(
            & git -C $script:cloneDir ls-files -t |
                Where-Object { $_ -and $_ -notmatch '^S ' } |
                ForEach-Object { $_ -replace '^[A-Z]+\s+', '' }
        )
        @($materialized | Sort-Object) | Should -Be @($script:pluginFiles | ForEach-Object { "oc/plugins/oc-advisor/$_" } | Sort-Object)
        Test-Path -LiteralPath (Join-Path $script:cloneDir 'README.md') | Should -BeFalse
    }

    It 'passes --dry-run and writes nothing' {
        Install-OpenCodeSettings -Ref main -CloneDir $script:cloneDir -DryRun -SkipValidate 6>&1 | Out-String

        $installedArgs = @(Get-Content -LiteralPath $script:nodeArgsFile)
        @($installedArgs | Where-Object { $_ -like '*install.mjs*--dry-run*' }).Count | Should -Be 1
        @($installedArgs | Where-Object { $_ -like '*--status*' }).Count | Should -Be 0
        Test-Path -LiteralPath (Join-Path $script:sandboxHome '.config\opencode\plugins') | Should -BeFalse
        Test-Path -LiteralPath $script:cloneDir | Should -BeFalse
    }

    It 'passes --skip-validate when the opencode CLI is missing' {
        Mock Get-Command -ParameterFilter { $Name -eq 'opencode' } -MockWith { $null }

        Install-OpenCodeSettings -Ref main -CloneDir $script:cloneDir 6>&1 | Out-String

        $installedArgs = @(Get-Content -LiteralPath $script:nodeArgsFile)
        @($installedArgs | Where-Object { $_ -like '*install.mjs*--skip-validate*' }).Count | Should -Be 1
    }

    It 'removes the clone and reports the failure when the installer fails' {
        $env:OC_TEST_NODE_EXIT = '1'

        { Install-OpenCodeSettings -Ref main -CloneDir $script:cloneDir -SkipValidate 6>&1 | Out-String } |
            Should -Throw '*installer failed with exit code 1*'

        Test-Path -LiteralPath $script:cloneDir | Should -BeFalse
    }

    It 'replaces a previous clone instead of reusing it' {
        $null = New-Item -ItemType Directory -Path $script:cloneDir -Force
        Set-Content -LiteralPath (Join-Path $script:cloneDir 'stale.txt') -Value 'stale' -Encoding UTF8

        Install-OpenCodeSettings -Ref main -CloneDir $script:cloneDir -SkipValidate -KeepClone 6>&1 | Out-String

        Test-Path -LiteralPath (Join-Path $script:cloneDir 'stale.txt') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $script:cloneDir '.git') | Should -BeTrue
    }

    It 'installs with the real plugin installer when node is available' -Skip:(-not (Get-Command node -ErrorAction SilentlyContinue)) {
        # Use the real node from the machine, not the shim installed above.
        $env:PATH = $script:originalPath

        $output = @(Install-OpenCodeSettings -Ref main -CloneDir $script:cloneDir -SkipValidate 6>&1 | Out-String)

        $configRoot = Join-Path $script:sandboxHome '.config\opencode'
        Test-Path -LiteralPath (Join-Path $configRoot 'plugins\oc-advisor\src\advisor.ts') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $configRoot 'plugins\oc-advisor\index.ts') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $configRoot 'commands\advisor.md') | Should -BeTrue
        $output | Should -BeLike '*advisor.ts: MATCH*'
        Test-Path -LiteralPath $script:cloneDir | Should -BeFalse
    }
}
