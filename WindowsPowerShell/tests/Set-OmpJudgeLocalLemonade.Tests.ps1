Describe 'Set-OmpJudgeLocalLemonade' {
    BeforeAll {
        function Invoke-WebRequest2 {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true, Position = 0)][uri]$Uri,
                [string]$OutFile,
                [switch]$UseBasicParsing
            )
        }

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
                $node.Name -eq 'Set-OmpJudgeLocalLemonade'
        }, $true)
        if (-not $functionAst) { throw 'Could not load Set-OmpJudgeLocalLemonade from the profile.' }
        . ([scriptblock]::Create($functionAst.Extent.Text))
    }

    BeforeEach {
        $script:mockHome = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:mockProfileDir = Join-Path $script:mockHome 'Documents\WindowsPowerShell'
        $script:mockUtilDir = Join-Path $script:mockProfileDir 'util'
        $script:mockScriptPath = Join-Path $script:mockUtilDir 'Set-OmpJudgeLocalLemonade.ps1'

        $null = New-Item -ItemType Directory -Path $script:mockUtilDir -Force
        $script:dummyScriptContent = "param(`$Checkpoint, `$ModelName, `$ProviderId, [int]`$ContextWindow, [int]`$MinLlamaCppBuild)`n`"RAN: Checkpoint=`$Checkpoint ModelName=`$ModelName ProviderId=`$ProviderId ContextWindow=`$ContextWindow MinLlamaCppBuild=`$MinLlamaCppBuild`""
        [IO.File]::WriteAllText($script:mockScriptPath, $script:dummyScriptContent, [Text.Encoding]::UTF8)

        $PROFILE = [pscustomobject]@{
            CurrentUserCurrentHost = Join-Path $script:mockProfileDir 'Microsoft.PowerShell_profile.ps1'
        }

        $_AiToolsInternal = @{
            Urls = @{
                OmpJudgeLocalLemonade = 'https://example.invalid/util/Set-OmpJudgeLocalLemonade.ps1'
            }
        }
    }

    It 'executes the existing local script with forwarded parameters' {
        $out = Set-OmpJudgeLocalLemonade -Checkpoint 'LiquidAI/LFM3-1.7B-GGUF:Q4_K_M' -ContextWindow 32768
        $out | Should -Match 'RAN: Checkpoint=LiquidAI/LFM3-1.7B-GGUF:Q4_K_M.*ContextWindow=32768'
    }

    It 'downloads the script when missing' {
        Remove-Item -LiteralPath $script:mockScriptPath -Force

        Mock Invoke-WebRequest2 {
            [IO.File]::WriteAllText($OutFile, "param(`$Checkpoint)`n`"DOWNLOADED: Checkpoint=`$Checkpoint`"", [Text.Encoding]::UTF8)
        }

        $out = Set-OmpJudgeLocalLemonade -Checkpoint 'LiquidAI/LFM3-1.7B-GGUF:Q4_K_M'
        Test-Path -LiteralPath $script:mockScriptPath | Should -Be $true
        $out | Should -Match 'DOWNLOADED: Checkpoint=LiquidAI/LFM3-1.7B-GGUF:Q4_K_M'
    }

    It 'rejects invalid downloaded script syntax and does not overwrite local copy' {
        [IO.File]::WriteAllText($script:mockScriptPath, "param()`n`"ORIGINAL`"", [Text.Encoding]::UTF8)

        Mock Invoke-WebRequest2 {
            [IO.File]::WriteAllText($OutFile, "function (broken syntax", [Text.Encoding]::UTF8)
        }

        $out = Set-OmpJudgeLocalLemonade -UpdateScript
        (Get-Content -LiteralPath $script:mockScriptPath -Raw) | Should -Match 'ORIGINAL'
        $out | Should -Match 'ORIGINAL'
    }
}
