Describe 'Install-Fonts archive handling and catalog' {
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

        $helpersAst = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left.Extent.Text -eq '$_ProfileHelpers'
        }, $true)
        $configAst = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left.Extent.Text -eq '$_FontInstallInternal'
        }, $true)
        if (-not $helpersAst -or -not $configAst) {
            throw 'Could not load profile helpers and font configuration from the profile.'
        }

        . ([scriptblock]::Create($helpersAst.Extent.Text))
        . ([scriptblock]::Create($configAst.Extent.Text))
    }

    It 'extracts only matching files through the 7z helper' -Skip:(-not (Get-Command tar.exe -ErrorAction SilentlyContinue)) {
        $source = Join-Path $TestDrive 'source'
        $destination = Join-Path $TestDrive 'destination'
        $archive = Join-Path $TestDrive 'fixture.7z'
        New-Item -ItemType Directory -Path $source | Out-Null
        Set-Content -LiteralPath (Join-Path $source 'Match-Regular.ttf') -Value 'font'
        Set-Content -LiteralPath (Join-Path $source 'ignore.txt') -Value 'ignore'

        & tar.exe -caf $archive -C $source 'Match-Regular.ttf' 'ignore.txt'
        $LASTEXITCODE | Should -Be 0

        $result = @($_ProfileHelpers.Expand7ZipArchive(
            $archive,
            $destination,
            '(?i)^Match-[^/]+\.ttf$'
        ))

        $result.Count | Should -Be 1
        Split-Path -Path $result[0] -Leaf | Should -Be 'Match-Regular.ttf'
        Test-Path -LiteralPath (Join-Path $destination 'ignore.txt') | Should -BeFalse
    }

    It 'fails when no 7z entries match the requested filter' -Skip:(-not (Get-Command tar.exe -ErrorAction SilentlyContinue)) {
        $source = Join-Path $TestDrive 'empty-match-source'
        $archive = Join-Path $TestDrive 'empty-match.7z'
        New-Item -ItemType Directory -Path $source | Out-Null
        Set-Content -LiteralPath (Join-Path $source 'ignore.txt') -Value 'ignore'
        & tar.exe -caf $archive -C $source 'ignore.txt'
        $LASTEXITCODE | Should -Be 0

        {
            $_ProfileHelpers.Expand7ZipArchive($archive, (Join-Path $TestDrive 'empty-match-out'), '\.ttf$')
        } | Should -Throw '*No 7z archive entries matched*'
    }

    It 'returns an actionable error when tar.exe is unavailable' {
        $archive = Join-Path $TestDrive 'unsupported.7z'
        Set-Content -LiteralPath $archive -Value 'not used'
        $originalPath = $env:Path
        try {
            $env:Path = $TestDrive
            {
                $_ProfileHelpers.Expand7ZipArchive($archive, (Join-Path $TestDrive 'unsupported-out'), $null)
            } | Should -Throw '*Windows tar.exe was not found*'
        } finally {
            $env:Path = $originalPath
        }
    }

    It 'pins the two Korean Sarasa packs as standard 7z downloads' {
        $packs = @($_FontInstallInternal.Packs | Where-Object Name -like 'Sarasa*')

        $packs.Count | Should -Be 2
        $packs.Name | Should -Contain 'SarasaGothicK'
        $packs.Name | Should -Contain 'SarasaMonoK'
        $packs.Kind | Select-Object -Unique | Should -Be '7z'
        @($packs | Where-Object { $_.Extended }).Count | Should -Be 0
        ($packs | Measure-Object -Property Fonts -Sum).Sum | Should -Be 20

        $gothic = $packs | Where-Object Name -eq 'SarasaGothicK'
        $gothic.Bytes | Should -Be 63464316
        $gothic.Probe | Should -Be 'SarasaGothicK-Regular.ttf'
        $gothic.Url | Should -Be 'https://github.com/be5invis/Sarasa-Gothic/releases/download/v1.0.40/SarasaGothicK-TTF-1.0.40.7z'

        $mono = $packs | Where-Object Name -eq 'SarasaMonoK'
        $mono.Bytes | Should -Be 66316218
        $mono.Probe | Should -Be 'SarasaMonoK-Regular.ttf'
        $mono.Url | Should -Be 'https://github.com/be5invis/Sarasa-Gothic/releases/download/v1.0.40/SarasaMonoK-TTF-1.0.40.7z'
    }

    It 'matches ten expected styles per Sarasa family and rejects other variants' {
        $styles = @(
            'ExtraLight', 'ExtraLightItalic', 'Light', 'LightItalic', 'Regular',
            'Italic', 'SemiBold', 'SemiBoldItalic', 'Bold', 'BoldItalic'
        )

        foreach ($pack in @($_FontInstallInternal.Packs | Where-Object Name -like 'Sarasa*')) {
            @($styles | Where-Object { "$($pack.Name)-$_.ttf" -match $pack.Include }).Count | Should -Be 10
            "SarasaGothicJ-Regular.ttf" -match $pack.Include | Should -BeFalse
            "SarasaMonoSC-Regular.ttf" -match $pack.Include | Should -BeFalse
        }
    }
}
