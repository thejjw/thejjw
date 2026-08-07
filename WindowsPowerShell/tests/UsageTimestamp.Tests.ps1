Describe 'usage-query timestamps' {
    BeforeAll {
        $profilePath = Join-Path $PSScriptRoot '..\Microsoft.PowerShell_profile.ps1'
        $tokens = $null
        $errors = $null
        $script:profileAst = [System.Management.Automation.Language.Parser]::ParseFile(
            $profilePath,
            [ref]$tokens,
            [ref]$errors
        )
        if ($errors) { throw "Profile contains parse errors: $($errors -join '; ')" }

        $helperAst = $script:profileAst.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'WriteUsageTimestamp'
        }, $true)
        if (-not $helperAst) { throw 'Could not load WriteUsageTimestamp from the profile.' }
        . ([scriptblock]::Create($helperAst.Extent.Text))
    }

    It 'prints a labeled local timestamp without writing to the success stream' {
        Mock Get-Date { '2026-08-07 14:32:09 +09:00' }
        Mock Write-Host {}

        $result = @(WriteUsageTimestamp 'Get-KimiUsage')

        $result | Should -BeNullOrEmpty
        Should -Invoke Get-Date -Times 1 -Exactly -ParameterFilter {
            $Format -eq 'yyyy-MM-dd HH:mm:ss zzz'
        }
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter {
            $Object -eq '[2026-08-07 14:32:09 +09:00] Get-KimiUsage' -and
                $ForegroundColor -eq 'DarkGray'
        }
    }

    It 'exports the helper through the shared profile helper object' {
        $exportAssignment = $script:profileAst.Find({
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left.Extent.Text -eq '$profileHelperFunctions'
        }, $true)
        $exportedNames = @(
            $exportAssignment.Right.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.StringConstantExpressionAst]
            }, $true).Value
        )

        $exportedNames | Should -Contain 'WriteUsageTimestamp'
    }

    It 'is the first statement in every local Get-*Usage function' {
        $usageFunctions = @(
            $script:profileAst.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -like 'Get-*Usage'
            }, $true)
        )

        $usageFunctions.Count | Should -Be 7
        foreach ($functionAst in $usageFunctions) {
            $functionAst.Body.EndBlock.Statements[0].Extent.Text |
                Should -Be '$_ProfileHelpers.WriteUsageTimestamp($MyInvocation.MyCommand.Name)'
        }
    }
}
