Describe 'Set-OmpJudgeLocalLlamaCpp' {
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
                $node.Name -eq 'Set-OmpJudgeLocalLlamaCpp'
        }, $true)
        if (-not $functionAst) { throw 'Could not load Set-OmpJudgeLocalLlamaCpp from the profile.' }
        . ([scriptblock]::Create($functionAst.Extent.Text))
    }

    BeforeEach {
        $script:mockHome = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:mockProfileDir = Join-Path $script:mockHome 'Documents\WindowsPowerShell'
        $script:mockUtilDir = Join-Path $script:mockProfileDir 'util'
        $script:mockScriptPath = Join-Path $script:mockUtilDir 'Set-OmpJudgeLocalLlamaCpp.ps1'

        $null = New-Item -ItemType Directory -Path $script:mockUtilDir -Force
        # Echoes every bound parameter so forwarding can be asserted.
        $script:dummyScriptContent = @'
param($Checkpoint, $ModelId, $ProviderId, $Backend, $ContextWindow, [int]$Port, $Build, [int]$IdleSleepSeconds,
    [switch]$AutoStart, [switch]$Yes, [switch]$Start, [switch]$Stop, [switch]$Status, [switch]$RemoveAutoStart,
    [switch]$InstallService, $ShawlPath, [switch]$RemoveService)
"RAN: " + (($PSBoundParameters.GetEnumerator() | Sort-Object Key | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' ')
'@
        [IO.File]::WriteAllText($script:mockScriptPath, $script:dummyScriptContent, [Text.Encoding]::UTF8)

        $PROFILE = [pscustomobject]@{
            CurrentUserCurrentHost = Join-Path $script:mockProfileDir 'Microsoft.PowerShell_profile.ps1'
        }

        $_AiToolsInternal = @{
            Urls = @{
                OmpJudgeLocalLlamaCpp = 'https://example.invalid/util/Set-OmpJudgeLocalLlamaCpp.ps1'
            }
        }
    }

    It 'executes the existing local script with forwarded values' {
        $out = Set-OmpJudgeLocalLlamaCpp -Checkpoint 'LiquidAI/LFM3-1.7B-GGUF:Q4_K_M' -Backend cpu -ContextWindow 8192 -Port 9950 -Build nightly -IdleSleepSeconds -1
        $out | Should -Match 'RAN: '
        $out | Should -Match 'Backend=cpu'
        $out | Should -Match 'Build=nightly'
        $out | Should -Match 'Checkpoint=LiquidAI/LFM3-1.7B-GGUF:Q4_K_M'
        $out | Should -Match 'ContextWindow=8192'
        $out | Should -Match 'IdleSleepSeconds=-1'
        $out | Should -Match 'Port=9950'
    }

    It 'forwards switches such as -Yes and -AutoStart, and omits unset ones' {
        $out = Set-OmpJudgeLocalLlamaCpp -Yes -AutoStart
        $out | Should -Match 'AutoStart=True'
        $out | Should -Match 'Yes=True'
        $out | Should -Not -Match 'Start=True Status'
        $out | Should -Not -Match 'Port='
    }

    It 'forwards the server management switches' {
        (Set-OmpJudgeLocalLlamaCpp -Status) | Should -Match 'RAN: Status=True$'
        (Set-OmpJudgeLocalLlamaCpp -Start) | Should -Match 'RAN: Start=True$'
        (Set-OmpJudgeLocalLlamaCpp -Stop) | Should -Match 'RAN: Stop=True$'
        (Set-OmpJudgeLocalLlamaCpp -RemoveAutoStart) | Should -Match 'RAN: RemoveAutoStart=True$'
        (Set-OmpJudgeLocalLlamaCpp -RemoveService) | Should -Match 'RAN: RemoveService=True$'
        (Set-OmpJudgeLocalLlamaCpp -InstallService -ShawlPath 'C:\Program Files\shawl\shawl.exe') | Should -Match 'RAN: InstallService=True ShawlPath=C:\\Program Files\\shawl\\shawl.exe$'
    }

    It 'downloads the script when missing' {
        Remove-Item -LiteralPath $script:mockScriptPath -Force

        Mock Invoke-WebRequest2 {
            [IO.File]::WriteAllText($OutFile, "param([switch]`$Status)`n`"DOWNLOADED: Status=`$Status`"", [Text.Encoding]::UTF8)
        }

        $out = Set-OmpJudgeLocalLlamaCpp -Status
        Test-Path -LiteralPath $script:mockScriptPath | Should -Be $true
        $out | Should -Match 'DOWNLOADED: Status=True'
    }

    It 'rejects invalid downloaded script syntax and does not overwrite local copy' {
        [IO.File]::WriteAllText($script:mockScriptPath, "param()`n`"ORIGINAL`"", [Text.Encoding]::UTF8)

        Mock Invoke-WebRequest2 {
            [IO.File]::WriteAllText($OutFile, "function (broken syntax", [Text.Encoding]::UTF8)
        }

        $out = Set-OmpJudgeLocalLlamaCpp -UpdateScript 2>$null 3>$null
        (Get-Content -LiteralPath $script:mockScriptPath -Raw) | Should -Match 'ORIGINAL'
        $out | Should -Match 'ORIGINAL'
    }
}
