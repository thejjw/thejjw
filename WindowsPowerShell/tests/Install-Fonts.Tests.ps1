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

    It 'pins the Monoplex CJK Nerd Font pack to the v1.1.0 Nerd Fonts 3.5.1 release' {
        $packs = @($_FontInstallInternal.Packs | Where-Object Name -like 'Monoplex*')

        # Exactly one Monoplex generation: v0.0.2 also shipped a Nerd family, so
        # leaving it pinned would install two competing sets of icon glyphs.
        $packs.Count | Should -Be 1
        $packs.Name | Should -Be 'MonoplexCJKNerd'
        $packs.Kind | Should -Be 'Zip'
        @($packs | Where-Object { $_.Extended }).Count | Should -Be 0
        $packs.Fonts | Should -Be 16
        $packs.Bytes | Should -Be 125695049
        $packs.Probe | Should -Be 'MonoplexCJKNerdFont-Regular.ttf'
        $packs.Url | Should -Be 'https://github.com/y-kim/monoplex/releases/download/monoplex-cjk-nerd-font-1.1.0/MonoplexCJKNerdFont_v1.1.0.zip'
    }

    It 'matches the sixteen Monoplex CJK Nerd styles and rejects non-TTF entries' {
        $pack = $_FontInstallInternal.Packs | Where-Object Name -eq 'MonoplexCJKNerd'
        # Real archive members. The Regular weight's italic is named
        # 'MonoplexCJKNerdFont-Italic.ttf' upstream, not '-RegularItalic.ttf',
        # so list the sixteen actual filenames rather than deriving them.
        $styles = @(
            'MonoplexCJKNerdFont/MonoplexCJKNerdFont-Thin.ttf'
            'MonoplexCJKNerdFont/MonoplexCJKNerdFont-ExtraLight.ttf'
            'MonoplexCJKNerdFont/MonoplexCJKNerdFont-Light.ttf'
            'MonoplexCJKNerdFont/MonoplexCJKNerdFont-Regular.ttf'
            'MonoplexCJKNerdFont/MonoplexCJKNerdFont-Text.ttf'
            'MonoplexCJKNerdFont/MonoplexCJKNerdFont-Medium.ttf'
            'MonoplexCJKNerdFont/MonoplexCJKNerdFont-SemiBold.ttf'
            'MonoplexCJKNerdFont/MonoplexCJKNerdFont-Bold.ttf'
            'MonoplexCJKNerdFont/MonoplexCJKNerdFont-ThinItalic.ttf'
            'MonoplexCJKNerdFont/MonoplexCJKNerdFont-ExtraLightItalic.ttf'
            'MonoplexCJKNerdFont/MonoplexCJKNerdFont-LightItalic.ttf'
            'MonoplexCJKNerdFont/MonoplexCJKNerdFont-Italic.ttf'
            'MonoplexCJKNerdFont/MonoplexCJKNerdFont-TextItalic.ttf'
            'MonoplexCJKNerdFont/MonoplexCJKNerdFont-MediumItalic.ttf'
            'MonoplexCJKNerdFont/MonoplexCJKNerdFont-SemiBoldItalic.ttf'
            'MonoplexCJKNerdFont/MonoplexCJKNerdFont-BoldItalic.ttf'
        )
        @($styles | Where-Object { $_ -match $pack.Include }).Count | Should -Be 16

        # The archive also ships a LICENSE.md next to the fonts; it must not install.
        'MonoplexCJKNerdFont/LICENSE.md' -match $pack.Include | Should -BeFalse
        # A sibling release's fonts live in their own directory and must be excluded.
        'MonoplexCJKNerdFontPropo/MonoplexCJKNerdFontPropo-Regular.ttf' -match $pack.Include | Should -BeFalse
    }

    It 'pins the Iosevka Fixed pack to the v34.9.0 default Sans release' {
        $packs = @($_FontInstallInternal.Packs | Where-Object Name -eq 'IosevkaFixed')

        # Exactly one Iosevka generation: the Fixed spacing variant only, so no
        # competing Default/Term/Slab/SS/Aile/Etoile entries.
        $packs.Count | Should -Be 1
        $packs.Kind | Should -Be 'Zip'
        @($packs | Where-Object { $_.Extended }).Count | Should -Be 0
        $packs.Fonts | Should -Be 4
        $packs.Bytes | Should -Be 148235929
        $packs.Probe | Should -Be 'IosevkaFixed-Regular.ttf'
        $packs.Url | Should -Be 'https://github.com/be5invis/Iosevka/releases/download/v34.9.0/PkgTTF-IosevkaFixed-34.9.0.zip'
    }

    It 'matches only the four Normal-width Iosevka Fixed styles' {
        $pack = $_FontInstallInternal.Packs | Where-Object Name -eq 'IosevkaFixed'
        # Real archive members at the zip root (verified against the v34.9.0
        # central directory: 54 root-level entries, no ttf/ prefix).
        $styles = @(
            'IosevkaFixed-Regular.ttf'
            'IosevkaFixed-Bold.ttf'
            'IosevkaFixed-Italic.ttf'
            'IosevkaFixed-BoldItalic.ttf'
        )
        @($styles | Where-Object { $_ -match $pack.Include }).Count | Should -Be 4
        $pack.Probe -match $pack.Include | Should -BeTrue

        # Normal width only: Extended companions must not install.
        'IosevkaFixed-Extended.ttf' -match $pack.Include | Should -BeFalse
        'IosevkaFixed-ExtendedBold.ttf' -match $pack.Include | Should -BeFalse
        # Italic slope only: Oblique variants must not install.
        'IosevkaFixed-Oblique.ttf' -match $pack.Include | Should -BeFalse
        'IosevkaFixed-BoldOblique.ttf' -match $pack.Include | Should -BeFalse
        # Other weights in the same asset must not install.
        'IosevkaFixed-Light.ttf' -match $pack.Include | Should -BeFalse
        'IosevkaFixed-MediumItalic.ttf' -match $pack.Include | Should -BeFalse
        # Sibling sub-packages live in their own assets and must be excluded.
        'IosevkaFixedSlab-Regular.ttf' -match $pack.Include | Should -BeFalse
        'IosevkaTerm-Regular.ttf' -match $pack.Include | Should -BeFalse
        'IosevkaFixedSS09-Regular.ttf' -match $pack.Include | Should -BeFalse
        'IosevkaAile-Regular.ttf' -match $pack.Include | Should -BeFalse
        'IosevkaEtoile-Regular.ttf' -match $pack.Include | Should -BeFalse
    }

    It 'selects only the four Iosevka Fixed fonts from a synthesized archive' {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $pack = $_FontInstallInternal.Packs | Where-Object Name -eq 'IosevkaFixed'
        $source = Join-Path $TestDrive 'iosevka-source'
        $archive = Join-Path $TestDrive 'iosevka-fixed.zip'
        New-Item -ItemType Directory -Path $source | Out-Null
        $members = @(
            'IosevkaFixed-Regular.ttf'
            'IosevkaFixed-Bold.ttf'
            'IosevkaFixed-Italic.ttf'
            'IosevkaFixed-BoldItalic.ttf'
            'IosevkaFixed-Extended.ttf'
            'IosevkaFixed-Oblique.ttf'
        )
        foreach ($member in $members) {
            Set-Content -LiteralPath (Join-Path $source $member) -Value 'stub'
        }
        Compress-Archive -Path (Join-Path $source '*') -DestinationPath $archive -Force

        $zip = [System.IO.Compression.ZipFile]::OpenRead($archive)
        try {
            $selected = @($zip.Entries | Where-Object {
                $_.Name -and $_.FullName -notlike '*__MACOSX*' -and $_.Name -notlike '._*' -and $_.FullName -match $pack.Include
            } | ForEach-Object { $_.FullName } | Sort-Object -Unique)
            $selected.Count | Should -Be 4
            $selected | Should -Contain 'IosevkaFixed-Regular.ttf'
            $selected | Should -Contain 'IosevkaFixed-Bold.ttf'
            $selected | Should -Contain 'IosevkaFixed-Italic.ttf'
            $selected | Should -Contain 'IosevkaFixed-BoldItalic.ttf'
        } finally {
            $zip.Dispose()
        }
    }
}
