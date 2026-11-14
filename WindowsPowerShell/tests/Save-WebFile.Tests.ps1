Describe 'Save-WebFile chunk resume and Install-Fonts classifier' {
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

        $saveAst = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'Save-WebFile'
        }, $true)
        if (-not $saveAst) { throw 'Could not load Save-WebFile from the profile.' }
        $script:saveText = $saveAst.Extent.Text

        $fontsAst = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'Install-Fonts'
        }, $true)
        if (-not $fontsAst) { throw 'Could not load Install-Fonts from the profile.' }

        $classifierAst = $fontsAst.Find({
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left.Extent.Text -eq '$isTransientError'
        }, $true)
        if (-not $classifierAst) { throw 'Could not load isTransientError from Install-Fonts.' }
        # Right extent includes the enclosing braces, which would make the
        # created block return the inner block instead of a bool; unwrap first.
        $raw = $classifierAst.Right.Extent.Text.Trim()
        $raw = $raw.Substring(1, $raw.Length - 2)
        $script:isTransientError = [scriptblock]::Create($raw)
    }

    It 'resumes truncated ranges instead of re-fetching from the start' {
        $script:saveText | Should -Match 'long pos = start'
        $script:saveText | Should -Match 'r\.AddRange\(pos, end\)'
        $script:saveText | Should -Match 'StartsWith\("bytes " \+ pos'
    }

    It 'rejects a 200 response that ignores the Range request' {
        $script:saveText | Should -Match 'Expected 206 for range request'
    }

    It 'retries a truncated tail chunk with a bounded resume budget' {
        $script:saveText | Should -Match 'DownloadChunk\(finalUrl, url, path, cs, ce, timeoutMs, 5\)'
    }

    It 'treats the transcript short-read failure as transient' {
        $msg = 'Short read: got 6608436 of 18529485 bytes for range 129706444-148235928'
        & $script:isTransientError $msg | Should -BeTrue
    }

    It 'treats range validation failures as transient' {
        (& $script:isTransientError "Range mismatch: Content-Range '' does not start at 0") | Should -BeTrue
        (& $script:isTransientError 'Expected 206 for range request, got 200') | Should -BeTrue
    }

    It 'does not treat HTTP 4xx statuses as transient' {
        (& $script:isTransientError 'The remote server returned an error: (404) Not Found.') | Should -BeFalse
        (& $script:isTransientError 'The remote server returned an error: (403) Forbidden.') | Should -BeFalse
    }
}
