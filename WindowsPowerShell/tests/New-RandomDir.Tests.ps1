Describe 'New-RandomDir' {
    BeforeAll {
        $profilePath = Join-Path $PSScriptRoot '..\Microsoft.PowerShell_profile.ps1'
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $profilePath, [ref]$tokens, [ref]$errors
        )
        if ($errors) { throw "Profile contains parse errors: $($errors -join '; ')" }
        $functionAst = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'New-RandomDir'
        }, $true)
        if (-not $functionAst) { throw 'Could not load New-RandomDir from the profile.' }
        . ([scriptblock]::Create($functionAst.Extent.Text))
        Set-Alias nrd New-RandomDir
        $_NrdInternal = @{
            Colors = @('lavender')
            Adjectives = @('small')
            Nouns = @('meadow')
            AgentsMarkdown = '# Test scaffold'
        }
    }

    BeforeEach {
        $originalLocation = Get-Location
    }

    AfterEach {
        Set-Location -LiteralPath $originalLocation.Path
    }

    It 'creates a randomly named directory and enters it' {
        $result = nrd -BasePath $TestDrive

        $result.Name | Should -Be 'lavender-small-meadow'
        $result.PSIsContainer | Should -BeTrue
        (Get-Location).Path | Should -Be $result.FullName
    }

    It 'preserves brackets in both the base path and directory name' {
        $base = New-Item -ItemType Directory -Path (Join-Path $TestDrive 'base[1]')
        $result = nrd -BasePath $base.FullName -Name 'child[2]'

        $result.FullName | Should -Be (Join-Path $base.FullName 'child[2]')
        (Get-Location).Path | Should -Be $result.FullName
    }

    It 'creates the directory before Git setup and writes the agent scaffold' {
        Mock git {
            if (-not (Test-Path -LiteralPath $args[1] -PathType Container)) {
                throw 'Git was invoked before the directory existed.'
            }
            $global:LASTEXITCODE = 0
        }

        $result = nrd -BasePath $TestDrive -Name scaffold -g -a

        (Get-Content -LiteralPath (Join-Path $result.FullName 'AGENTS.md') -Raw).Trim() |
            Should -Be '# Test scaffold'
        Should -Invoke git -Times 6 -Exactly
        (Get-Location).Path | Should -Be $result.FullName
    }

    It 'stops before Git, scaffold writes, and navigation when directory creation fails' {
        # A file cannot be the parent of a directory: exercise a real provider error.
        $baseFile = Join-Path $TestDrive 'parent-file'
        Set-Content -LiteralPath $baseFile -Value 'keep me'
        Mock git { throw 'Git must not run after a directory creation failure.' }

        { nrd -BasePath $baseFile -Name child -g -a } | Should -Throw

        Should -Invoke git -Times 0 -Exactly
        (Get-Location).Path | Should -Be $originalLocation.Path
        (Get-Content -LiteralPath $baseFile -Raw).Trim() | Should -Be 'keep me'
    }
}
