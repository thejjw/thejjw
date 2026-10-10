Describe 'Get-JsoncText helper' {
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
        if (-not $helpersAst) { throw 'Could not load profile helpers from the profile.' }

        . ([scriptblock]::Create($helpersAst.Extent.Text))
    }

    It 'leaves plain JSON untouched' {
        $json = '{"a":1,"b":[1,2],"c":{"d":"e"}}'
        $result = $_ProfileHelpers.GetJsoncText($json)

        $result.Text | Should -BeExactly $json
        $result.CommentsRemoved | Should -BeFalse
        $result.TrailingCommasRemoved | Should -BeFalse
    }

    It 'strips line and block comments' {
        $jsonc = @'
{
  // line comment
  "a": 1, /* block
  comment */
  "b": 2
}
'@
        $result = $_ProfileHelpers.GetJsoncText($jsonc)

        $result.CommentsRemoved | Should -BeTrue
        $parsed = $result.Text | ConvertFrom-Json
        $parsed.a | Should -Be 1
        $parsed.b | Should -Be 2
    }

    It 'does not treat comment markers inside strings as comments' {
        $jsonc = '{"url":"http://example.com/a/*b*/c","note":"// not a comment","slash":"C:\\temp"}'
        $result = $_ProfileHelpers.GetJsoncText($jsonc)

        $result.CommentsRemoved | Should -BeFalse
        $parsed = $result.Text | ConvertFrom-Json
        $parsed.url | Should -Be 'http://example.com/a/*b*/c'
        $parsed.note | Should -Be '// not a comment'
        $parsed.slash | Should -Be 'C:\temp'
    }

    It 'respects escaped quotes when tracking strings' {
        $jsonc = '{"a":"say \"//hi\"","b":2}'
        $result = $_ProfileHelpers.GetJsoncText($jsonc)

        $result.CommentsRemoved | Should -BeFalse
        $parsed = $result.Text | ConvertFrom-Json
        $parsed.a | Should -Be 'say "//hi"'
        $parsed.b | Should -Be 2
    }

    It 'drops trailing commas in objects and arrays' {
        $jsonc = '{"a":[1,2,],"b":{"c":3,},}'
        $result = $_ProfileHelpers.GetJsoncText($jsonc)

        $result.TrailingCommasRemoved | Should -BeTrue
        $result.CommentsRemoved | Should -BeFalse
        $parsed = $result.Text | ConvertFrom-Json
        @($parsed.a).Count | Should -Be 2
        $parsed.b.c | Should -Be 3
    }

    It 'keeps a comma that separates real members' {
        $jsonc = '{"a":1,"b":2}'
        $result = $_ProfileHelpers.GetJsoncText($jsonc)

        $result.TrailingCommasRemoved | Should -BeFalse
        $result.Text | Should -BeExactly $jsonc
    }

    It 'handles comments and trailing commas together' {
        $jsonc = @'
{
  // comment before a trailing comma
  "a": [1, 2,],
  "b": "x", /* and here */
}
'@
        $result = $_ProfileHelpers.GetJsoncText($jsonc)

        $result.CommentsRemoved | Should -BeTrue
        $result.TrailingCommasRemoved | Should -BeTrue
        $parsed = $result.Text | ConvertFrom-Json
        @($parsed.a).Count | Should -Be 2
        $parsed.b | Should -Be 'x'
    }

    It 'returns empty input unchanged' {
        $result = $_ProfileHelpers.GetJsoncText('')

        $result.Text | Should -BeExactly ''
        $result.CommentsRemoved | Should -BeFalse
        $result.TrailingCommasRemoved | Should -BeFalse
    }
}
