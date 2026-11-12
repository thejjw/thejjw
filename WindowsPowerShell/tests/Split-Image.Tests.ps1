Describe 'Split-Image' {
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
                $node.Name -eq 'Split-Image'
        }, $true)
        if (-not $functionAst) { throw 'Could not load Split-Image from the profile.' }
        . ([scriptblock]::Create($functionAst.Extent.Text))
        Add-Type -AssemblyName System.Drawing

        # Distinct translucent pixels expose shifts, resampling, and alpha loss.
        $script:writeFixture = {
            param($Path, $Width = 5, $Height = 5)
            $bitmap = New-Object System.Drawing.Bitmap($Width, $Height)
            try {
                for ($y = 0; $y -lt $Height; $y++) {
                    for ($x = 0; $x -lt $Width; $x++) {
                        $bitmap.SetPixel($x, $y, [System.Drawing.Color]::FromArgb(
                            (32 + $x * 30 + $y * 4), (20 + $x * 30), (15 + $y * 40), (10 + $x + $y)
                        ))
                    }
                }
                $bitmap.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
            }
            finally { $bitmap.Dispose() }
        }
    }

    BeforeEach {
        $fixtureDirectory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $fixtureDirectory
        $sourcePath = Join-Path $fixtureDirectory 'sample [image] with spaces.png'
        & $script:writeFixture $sourcePath
    }

    It 'preserves every pixel for <Direction> on a <Width>x<Height> image' -TestCases @(
        @{ Direction = 'Horizontal'; Width = 4; Height = 6; Names = @('top', 'bottom'); Sizes = @(3, 3) }
        @{ Direction = 'Horizontal'; Width = 5; Height = 7; Names = @('top', 'bottom'); Sizes = @(3, 4) }
        @{ Direction = 'Vertical'; Width = 6; Height = 4; Names = @('left', 'right'); Sizes = @(3, 3) }
        @{ Direction = 'Vertical'; Width = 7; Height = 5; Names = @('left', 'right'); Sizes = @(3, 4) }
    ) {
        param($Direction, $Width, $Height, $Names, $Sizes)
        & $script:writeFixture $sourcePath $Width $Height
        $originalHash = (Get-FileHash -LiteralPath $sourcePath).Hash

        $result = @(Split-Image $sourcePath -Direction $Direction)

        $result.Count | Should -Be 2
        $source = [System.Drawing.Bitmap]::FromFile($sourcePath)
        try {
            for ($part = 0; $part -lt 2; $part++) {
                $result[$part] | Should -BeOfType [System.IO.FileInfo]
                $result[$part].FullName | Should -Be (Join-Path $fixtureDirectory "sample [image] with spaces-$($Names[$part]).png")
                $image = [System.Drawing.Bitmap]::FromFile($result[$part].FullName)
                try {
                    $image.RawFormat.Guid | Should -Be ([System.Drawing.Imaging.ImageFormat]::Png.Guid)
                    if ($Direction -eq 'Horizontal') {
                        $image.Width | Should -Be $Width
                        $image.Height | Should -Be $Sizes[$part]
                    }
                    else {
                        $image.Width | Should -Be $Sizes[$part]
                        $image.Height | Should -Be $Height
                    }
                    for ($y = 0; $y -lt $image.Height; $y++) {
                        for ($x = 0; $x -lt $image.Width; $x++) {
                            $sourceX = $x
                            $sourceY = $y
                            if ($part -eq 1) {
                                if ($Direction -eq 'Horizontal') { $sourceY += $Sizes[0] }
                                else { $sourceX += $Sizes[0] }
                            }
                            $image.GetPixel($x, $y).ToArgb() | Should -Be ($source.GetPixel($sourceX, $sourceY).ToArgb())
                        }
                    }
                }
                finally { $image.Dispose() }
            }
        }
        finally { $source.Dispose() }

        (Get-FileHash -LiteralPath $sourcePath).Hash | Should -Be $originalHash
        foreach ($path in @($sourcePath) + @($result.FullName)) {
            $stream = [System.IO.File]::Open($path, 'Open', 'ReadWrite', 'None')
            $stream.Dispose()
        }
    }

    It 'defaults to a horizontal split' {
        $result = @(Split-Image $sourcePath)
        $result.Count | Should -Be 2
        $result[0].Name | Should -Be 'sample [image] with spaces-top.png'
        $result[1].Name | Should -Be 'sample [image] with spaces-bottom.png'
    }

    It 'rejects a missing file, directory, and non-image file' {
        $textPath = Join-Path $fixtureDirectory 'text.png'
        Set-Content -LiteralPath $textPath -Value 'not an image'
        foreach ($path in @((Join-Path $fixtureDirectory 'missing.png'), $fixtureDirectory, $textPath)) {
            { Split-Image $path -ErrorAction Stop } | Should -Throw
        }
        @(Get-ChildItem -LiteralPath $fixtureDirectory -File).Count | Should -Be 2
        $stream = [System.IO.File]::Open($textPath, 'Open', 'ReadWrite', 'None')
        $stream.Dispose()
    }

    It 'rejects a one-pixel <Direction> axis without creating output' -TestCases @(
        @{ Direction = 'Horizontal'; Width = 5; Height = 1 }
        @{ Direction = 'Vertical'; Width = 1; Height = 5 }
    ) {
        param($Direction, $Width, $Height)
        & $script:writeFixture $sourcePath $Width $Height
        { Split-Image $sourcePath -Direction $Direction -ErrorAction Stop } | Should -Throw
        @(Get-ChildItem -LiteralPath $fixtureDirectory -File).Count | Should -Be 1
        $stream = [System.IO.File]::Open($sourcePath, 'Open', 'ReadWrite', 'None')
        $stream.Dispose()
    }

    It 'refuses an existing <Existing> output before creating either half' -TestCases @(
        @{ Direction = 'Horizontal'; Existing = 'top'; Other = 'bottom' }
        @{ Direction = 'Horizontal'; Existing = 'bottom'; Other = 'top' }
        @{ Direction = 'Vertical'; Existing = 'left'; Other = 'right' }
        @{ Direction = 'Vertical'; Existing = 'right'; Other = 'left' }
    ) {
        param($Direction, $Existing, $Other)
        $existingPath = Join-Path $fixtureDirectory "sample [image] with spaces-$Existing.png"
        $otherPath = Join-Path $fixtureDirectory "sample [image] with spaces-$Other.png"
        Set-Content -LiteralPath $existingPath -Value 'keep existing output'
        $originalHash = (Get-FileHash -LiteralPath $sourcePath).Hash
        $existingHash = (Get-FileHash -LiteralPath $existingPath).Hash

        { Split-Image $sourcePath -Direction $Direction -ErrorAction Stop } | Should -Throw

        Test-Path -LiteralPath $otherPath | Should -BeFalse
        (Get-FileHash -LiteralPath $existingPath).Hash | Should -Be $existingHash
        (Get-FileHash -LiteralPath $sourcePath).Hash | Should -Be $originalHash
    }

    It 'creates and returns no files with WhatIf for <Direction>' -TestCases @(
        @{ Direction = 'Horizontal' }
        @{ Direction = 'Vertical' }
    ) {
        param($Direction)
        $originalHash = (Get-FileHash -LiteralPath $sourcePath).Hash
        $result = @(Split-Image $sourcePath -Direction $Direction -WhatIf)
        $result.Count | Should -Be 0
        @(Get-ChildItem -LiteralPath $fixtureDirectory -File).Count | Should -Be 1
        (Get-FileHash -LiteralPath $sourcePath).Hash | Should -Be $originalHash
        $stream = [System.IO.File]::Open($sourcePath, 'Open', 'ReadWrite', 'None')
        $stream.Dispose()
    }
}
