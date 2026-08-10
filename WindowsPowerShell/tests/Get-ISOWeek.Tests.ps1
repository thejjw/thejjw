Describe 'Get-ISOWeek' {
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
                $node.Name -eq 'Get-ISOWeek'
        }, $true)
        if (-not $functionAst) { throw 'Could not load Get-ISOWeek from the profile.' }
        . ([scriptblock]::Create($functionAst.Extent.Text))
    }

    It 'uses the current date when Date is omitted' {
        Mock Get-Date { [datetime]'2026-08-10' }

        Get-ISOWeek | Should -Be 33
        Should -Invoke Get-Date -Times 1 -Exactly
    }

    It 'returns the expected ISO week for <Date>' -TestCases @(
        @{ Date = '2005-01-01'; Week = 53 }
        @{ Date = '2019-12-30'; Week = 1 }
        @{ Date = '2020-12-31'; Week = 53 }
        @{ Date = '2021-01-01'; Week = 53 }
        @{ Date = '2021-01-04'; Week = 1 }
        @{ Date = '2026-08-10'; Week = 33 }
    ) {
        param($Date, $Week)

        Get-ISOWeek $Date | Should -Be $Week
    }

    It 'returns a single Int32 value' {
        $result = @(Get-ISOWeek '2026-08-10')

        $result.Count | Should -Be 1
        $result[0] | Should -BeOfType ([int])
    }
}
