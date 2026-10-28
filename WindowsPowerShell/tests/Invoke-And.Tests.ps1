Describe 'Invoke-And' {
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
                $node.Name -eq 'Invoke-And'
        }, $true)
        if (-not $functionAst) { throw 'Could not load Invoke-And from the profile.' }
        . ([scriptblock]::Create($functionAst.Extent.Text))
        Set-Alias -Name then -Value Invoke-And
    }

    It 'resolves the "then" alias' {
        (Get-Alias then).Definition | Should -Be 'Invoke-And'
    }

    It 'runs every block and emits 0 when all succeed' {
        $global:LASTEXITCODE = 42
        $result = @(then { 'a' } { 'b' } { cmd /c exit 0 } { 'd' })

        $result | Should -Be @('a', 'b', 'd', 0)
        $global:LASTEXITCODE | Should -Be 0
    }

    It 'short-circuits on a failing cmdlet and reports exit code 1' {
        $sentinel = 'unchanged'
        $threw = $false
        $last = $null
        try {
            $out = @(then { Write-Error 'boom' } { $sentinel = 'overwritten' })
            $last = $out[-1]
        } catch { $threw = $true }

        # Pester's ErrorActionPreference makes the error terminating (throwing),
        # a plain shell leaves it non-terminating (returning 1); the second
        # block must be skipped either way.
        ($threw -or ($last -eq 1)) | Should -BeTrue
        $sentinel | Should -Be 'unchanged'
        $global:LASTEXITCODE | Should -Be 1
    }

    It 'propagates a native executable failing exit code' {
        $sentinel = 'unchanged'
        $result = @(then { cmd /c exit 3 } { $sentinel = 'overwritten' })

        $result | Should -Be 3
        $sentinel | Should -Be 'unchanged'
        $global:LASTEXITCODE | Should -Be 3
    }

    It 'catches a cmdlet error written after a successful native exe in the same block' {
        $result = @(then { cmd /c exit 0; Write-Error 'boom' -ErrorAction Continue })

        $result | Should -Be 1
        $global:LASTEXITCODE | Should -Be 1
    }

    It 'propagates a terminating error and reports exit code 1' {
        $sentinel = 'unchanged'
        { then { throw 'boom' } { $sentinel = 'overwritten' } } | Should -Throw 'boom'

        $sentinel | Should -Be 'unchanged'
        $global:LASTEXITCODE | Should -Be 1
    }

    It 'rejects a call with no blocks' {
        { then } | Should -Throw
        { Invoke-And -Blocks @() } | Should -Throw
    }

    It 'fails the chain on a non-terminating cmdlet error in a fresh 5.1 shell' {
        # In the Pester scope the error may arrive as terminating; a child
        # shell with the default ErrorActionPreference exercises the path a
        # real interactive session takes.
        $profilePath = (Resolve-Path (Join-Path $PSScriptRoot '..\Microsoft.PowerShell_profile.ps1')).Path
        $driverPath = Join-Path $TestDrive 'invokeand-shell-driver.ps1'
        $source = @'
$profilePath = "[PROFILE]"
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($profilePath, [ref]$tokens, [ref]$errors)
if ($errors) { throw 'Profile contains parse errors.' }
$functionAst = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Invoke-And'
}, $true)
if (-not $functionAst) { throw 'Could not load Invoke-And from the profile.' }
. ([scriptblock]::Create($functionAst.Extent.Text))
Set-Alias then Invoke-And
$sentinel = 'unchanged'
$result = @(then { Write-Error 'boom' -ErrorAction Continue } { $sentinel = 'overwritten' })
Write-Output ('code=' + $result[-1])
Write-Output ('sentinel=' + $sentinel)
Write-Output ('lastexit=' + $global:LASTEXITCODE)
'@.Replace('[PROFILE]', $profilePath)
        Set-Content -LiteralPath $driverPath -Value $source

        $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $driverPath 2>$null

        $output | Should -Contain 'code=1'
        $output | Should -Contain 'sentinel=unchanged'
        $output | Should -Contain 'lastexit=1'
    }
}
