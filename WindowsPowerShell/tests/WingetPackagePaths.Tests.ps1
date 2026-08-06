Describe 'Winget package PATH helpers' {
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

        $script:addPathsAst = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'Add-WingetPackagePaths'
        }, $true)
        $script:removePathsAst = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'Remove-WingetPackagePaths'
        }, $true)
    }

    It 'routes additions through the append-only helper' {
        $script:addPathsAst.Extent.Text | Should -Match 'Add-UserPathEntry -Path'
        $script:addPathsAst.Extent.Text | Should -Not -Match "SetValue\('PATH'"
    }

    It 'requires confirmation before removing persisted entries' {
        $script:removePathsAst.Extent.Text | Should -Match 'SupportsShouldProcess = \$true'
        $script:removePathsAst.Extent.Text | Should -Match '\$PSCmdlet\.ShouldProcess'
    }

    It 'preserves unexpanded registry values during removal' {
        $script:removePathsAst.Extent.Text | Should -Match 'DoNotExpandEnvironmentNames'
        $script:removePathsAst.Extent.Text | Should -Not -Match 'Get-ItemPropertyValue'
    }

    It 'uses a directory boundary instead of a loose prefix match' {
        $script:removePathsAst.Extent.Text | Should -Match 'StartsWith'
        $script:removePathsAst.Extent.Text | Should -Not -Match '-like "\$wingetRoot\*"'
    }
}
