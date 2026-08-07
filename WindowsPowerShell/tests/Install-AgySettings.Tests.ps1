Describe 'Install-AgySettings' {
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
                $node.Name -eq 'Install-AgySettings'
        }, $true)
        if (-not $functionAst) { throw 'Could not load Install-AgySettings from the profile.' }
        . ([scriptblock]::Create($functionAst.Extent.Text))
    }

    BeforeEach {
        $script:agyDir = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:settingsJson = Join-Path $script:agyDir 'settings.json'
        $script:sentinel = Join-Path $script:agyDir '.config_setup_done'
        $null = New-Item -ItemType Directory -Path $script:agyDir -Force
        $_AiToolsInternal = @{ Urls = @{ AgyStatusline = 'https://example.invalid/agy_statusline.ps1' } }

        Mock Join-Path {
            if ($Path -eq $HOME -and $ChildPath -eq '.gemini\antigravity-cli') {
                return $script:agyDir
            }
            return [IO.Path]::Combine($Path, $ChildPath)
        }
        Mock Invoke-RestMethod {
            [IO.File]::WriteAllText($OutFile, '# status line', [Text.Encoding]::ASCII)
        }
        Mock Write-Host {}
        Mock Write-Warning {}
    }

    It 'creates canonical permissions with empty ask and deny lists' {
        Install-AgySettings -Force

        $settings = Get-Content -LiteralPath $script:settingsJson -Raw | ConvertFrom-Json
        @($settings.permissions.allow) | Should -Be @(
            'read_file(*)',
            'read_url(*)',
            'command(git status)',
            'command(git log)',
            'command(git diff)'
        )
        @($settings.permissions.ask).Count | Should -Be 0
        @($settings.permissions.deny).Count | Should -Be 0
        $settings.statusLine.type | Should -Be 'command'

        $bytes = [IO.File]::ReadAllBytes($script:settingsJson)
        @($bytes | Select-Object -First 3) | Should -Not -Be @(0xEF, 0xBB, 0xBF)
    }

    It 'migrates managed legacy rules and preserves unrelated settings and permissions' {
        $existing = @{
            enableTelemetry = $false
            permissions     = @{
                preset = 'personal'
                allow = @(
                    'command(git status*)',
                    'command(git log*)',
                    'command(git diff*)',
                    'command(npm test)'
                )
                ask  = @('command(*)')
                deny = @('command(rm -rf)')
            }
        } | ConvertTo-Json -Depth 10
        [IO.File]::WriteAllText($script:settingsJson, $existing, [Text.UTF8Encoding]::new($false))

        Install-AgySettings -Force

        $settings = Get-Content -LiteralPath $script:settingsJson -Raw | ConvertFrom-Json
        $settings.enableTelemetry | Should -BeFalse
        $settings.permissions.preset | Should -Be 'personal'
        @($settings.permissions.allow) | Should -Contain 'command(npm test)'
        @($settings.permissions.allow) | Should -Contain 'read_file(*)'
        @($settings.permissions.allow) | Should -Contain 'read_url(*)'
        @($settings.permissions.allow) | Should -Contain 'command(git status)'
        @($settings.permissions.allow) | Should -Not -Contain 'command(git status*)'
        @($settings.permissions.ask) | Should -Be @('command(*)')
        @($settings.permissions.deny) | Should -Be @('command(rm -rf)')
    }

    It 'is idempotent when forced repeatedly' {
        Install-AgySettings -Force
        $first = Get-Content -LiteralPath $script:settingsJson -Raw

        Install-AgySettings -Force
        $second = Get-Content -LiteralPath $script:settingsJson -Raw

        $second | Should -BeExactly $first
        $settings = $second | ConvertFrom-Json
        @($settings.permissions.allow).Count | Should -Be 5
    }

    It 'leaves settings unchanged when the sentinel exists without Force' {
        [IO.File]::WriteAllText($script:settingsJson, '{"model":"keep-me"}', [Text.UTF8Encoding]::new($false))
        $null = New-Item -ItemType File -Path $script:sentinel -Force
        $before = Get-Content -LiteralPath $script:settingsJson -Raw

        Install-AgySettings

        (Get-Content -LiteralPath $script:settingsJson -Raw) | Should -BeExactly $before
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
    }

    It 'does not replace a malformed permissions value' {
        [IO.File]::WriteAllText($script:settingsJson, '{"permissions":"invalid"}', [Text.UTF8Encoding]::new($false))
        $before = Get-Content -LiteralPath $script:settingsJson -Raw

        Install-AgySettings -Force

        (Get-Content -LiteralPath $script:settingsJson -Raw) | Should -BeExactly $before
        Test-Path -LiteralPath $script:sentinel | Should -BeFalse
        Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter {
            $Message -eq 'agy: permissions must be a JSON object; settings were not changed.'
        }
    }
}
