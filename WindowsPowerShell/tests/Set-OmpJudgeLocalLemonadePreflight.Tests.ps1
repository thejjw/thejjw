Describe 'Lemonade prerequisite handling' {
    BeforeAll {
        $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '..\util\Set-OmpJudgeLocalLemonade.ps1'), [ref]$null, [ref]$null)
        foreach ($f in $ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)) { . ([scriptblock]::Create($f.Extent.Text)) }
        $AbortToken = 'OMP_LEMONADE_SETUP_ABORTED'
    }
    BeforeEach {
        $NonInteractive = $false
        Mock Write-Host { }
        Mock Update-SetupPath { }
        Mock Get-LemonadeInstallRoots { }
        Mock Start-Process { throw 'Unexpected process launch' }
        Mock Read-Host { throw 'Unexpected prompt' }
        Mock Get-Command { $null }
        Mock Get-LemonadeEligibility { [pscustomobject]@{ Eligible=$true; Reason='AMD GPU' } }
    }
    It 'stops before probing Lemonade when omp is missing' {
        Mock Initialize-Lemonade { throw 'Unexpected probe' }
        { Invoke-Setup } | Should -Throw $AbortToken
        Should -Invoke Initialize-Lemonade -Times 0
    }
    It 'stops before probing Lemonade when omp fails' {
        Mock Get-Command { [pscustomobject]@{Source='omp'} }
        Mock Invoke-Omp { throw 'broken omp' }
        Mock Initialize-Lemonade { throw 'Unexpected probe' }
        { Invoke-Setup } | Should -Throw '*broken omp*'
        Should -Invoke Initialize-Lemonade -Times 0
    }
    It 'uses a CLI on PATH' {
        Mock Get-Command { [pscustomobject]@{Source='C:\custom\lemonade.exe'} }
        Find-Lemonade | Should -Be 'C:\custom\lemonade.exe'
    }
    It 'resolves a custom registered installation' {
        $root = Join-Path $TestDrive 'custom'
        New-Item -ItemType Directory (Join-Path $root 'bin') | Out-Null
        New-Item -ItemType File (Join-Path $root 'bin\lemonade.exe') | Out-Null
        Mock Get-LemonadeInstallRoots { $root }
        Find-Lemonade | Should -Be (Join-Path $root 'bin\lemonade.exe')
    }
    It 'does not reinstall a damaged registered installation' {
        Mock Get-LemonadeInstallRoots { 'C:\missing-install' }
        Mock Test-Path { $false }
        { Find-Lemonade } | Should -Throw $AbortToken
    }
    It 'suppresses prompting in noninteractive mode' {
        $NonInteractive = $true
        Confirm-LemonadeInstall | Should -BeFalse
        Should -Invoke Read-Host -Times 0
    }
    It 'does not offer installation on ineligible hardware' {
        Mock Find-Lemonade { $null }
        Mock Get-LemonadeEligibility { [pscustomobject]@{Eligible=$false;Reason='No AMD GPU'} }
        Mock Confirm-LemonadeInstall { throw 'Unexpected prompt' }
        { Initialize-Lemonade } | Should -Throw $AbortToken
        Should -Invoke Confirm-LemonadeInstall -Times 0
    }
    It 'stops when winget is missing' {
        Mock Find-Lemonade { $null }
        Mock Confirm-LemonadeInstall { throw 'Unexpected prompt' }
        { Initialize-Lemonade } | Should -Throw $AbortToken
        Should -Invoke Confirm-LemonadeInstall -Times 0
    }
    It 'stops on refusal without starting an installer' {
        Mock Find-Lemonade { $null }
        Mock Get-Command { [pscustomobject]@{Source='installer-must-not-run.exe'} }
        Mock Confirm-LemonadeInstall { $false }
        { Initialize-Lemonade } | Should -Throw $AbortToken
        Should -Invoke Start-Process -Times 0
    }
    It 'continues with valid status from an existing installation' {
        Mock Find-Lemonade { 'C:\custom\lemonade.exe' }
        Mock Invoke-LemonadeStatus { [pscustomobject]@{ExitCode=0;StdOut='{"port":13305,"version":"test"}';StdErr=''} }
        (Initialize-Lemonade).ExitCode | Should -Be 0
        Should -Invoke Get-LemonadeEligibility -Times 0
    }
    It 'stops on unreachable existing server without launching it' {
        Mock Find-Lemonade { 'C:\custom\lemonade.exe' }
        Mock Invoke-LemonadeStatus { [pscustomobject]@{ExitCode=1;StdOut='';StdErr='offline'} }
        { Initialize-Lemonade } | Should -Throw $AbortToken
        Should -Invoke Start-Process -Times 0
    }
    It 'stops after installer failure' {
        Mock Find-Lemonade { $null }
        Mock Get-Command { [pscustomobject]@{Source='winget.exe'} }
        Mock Confirm-LemonadeInstall { $true }
        Mock Install-Lemonade { 3010 }
        { Initialize-Lemonade } | Should -Throw $AbortToken
        Should -Invoke Install-Lemonade -Times 1
    }
    It 'rediscovers and continues after installation' {
        $script:discoveryCount=0
        Mock Find-Lemonade { $script:discoveryCount++; if ($script:discoveryCount -gt 1) { 'C:\new\lemonade.exe' } }
        Mock Get-Command { [pscustomobject]@{Source='winget.exe'} }
        Mock Confirm-LemonadeInstall { $true }
        Mock Install-Lemonade { 0 }
        Mock Invoke-LemonadeStatus { [pscustomobject]@{ExitCode=0;StdOut='{"port":13305,"version":"test"}';StdErr=''} }
        (Initialize-Lemonade).ExitCode | Should -Be 0
        Should -Invoke Find-Lemonade -Times 2
        Should -Invoke Update-SetupPath -Times 1
    }
    It 'fails when successful install cannot be rediscovered' {
        Mock Find-Lemonade { $null }
        Mock Get-Command { [pscustomobject]@{Source='winget.exe'} }
        Mock Confirm-LemonadeInstall { $true }
        Mock Install-Lemonade { 0 }
        { Initialize-Lemonade } | Should -Throw $AbortToken
    }
    It 'classifies graphics health (<Name>)' -TestCases @(
        @{Name='AMD integrated';Vendor='PCI\VEN_1002';Code=0;Driver='1';Expected=$true}
        @{Name='AMD discrete';Vendor='PCI\VEN_1002&DEV_1234';Code=0;Driver='2';Expected=$true}
        @{Name='NVIDIA';Vendor='PCI\VEN_10DE';Code=0;Driver='1';Expected=$false}
        @{Name='disabled AMD';Vendor='PCI\VEN_1002';Code=22;Driver='1';Expected=$false}
        @{Name='NVIDIA Corporation';Vendor='';Manufacturer='NVIDIA Corporation';Code=0;Driver='1';Expected=$false}
        @{Name='Intel Corporation';Vendor='';Manufacturer='Intel Corporation';Code=0;Driver='1';Expected=$false}
        @{Name='Microsoft Corporation';Vendor='';Manufacturer='Microsoft Corporation';Code=0;Driver='1';Expected=$false}
        @{Name='AMD manufacturer';Vendor='';Manufacturer='Advanced Micro Devices, Inc.';Code=0;Driver='1';Expected=$true}
        @{Name='ATI manufacturer';Vendor='';Manufacturer='ATI Technologies Inc.';Code=0;Driver='1';Expected=$true}
        @{Name='AMD abbreviation';Vendor='';Manufacturer='AMD';Code=0;Driver='1';Expected=$true}
        @{Name='driver missing';Vendor='PCI\VEN_1002';Code=0;Driver='';Expected=$false}
    ) {
        param($Name,$Vendor,$Code,$Driver,$Expected,$Manufacturer)
        Mock Get-CimInstance {
            if ($ClassName -eq 'Win32_OperatingSystem') { [pscustomobject]@{BuildNumber=26100;ProductType=1;OSArchitecture='64-bit'} }
            else { [pscustomobject]@{Name=$Name;PNPDeviceID=$Vendor;AdapterCompatibility=$Manufacturer;ConfigManagerErrorCode=$Code;Status='OK';DriverVersion=$Driver} }
        }
        $oldArch=$env:PROCESSOR_ARCHITECTURE
        $oldWow=$env:PROCESSOR_ARCHITEW6432
        try {
            $env:PROCESSOR_ARCHITECTURE='AMD64'; $env:PROCESSOR_ARCHITEW6432=''
            $f=$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-LemonadeEligibility'},$false)[0]
            $result=& ([scriptblock]::Create($f.Body.Extent.Text.Trim('{}')))
            $result.Eligible | Should -Be $Expected
        } finally { $env:PROCESSOR_ARCHITECTURE=$oldArch; $env:PROCESSOR_ARCHITEW6432=$oldWow }
    }
    It 'stops initialization at the startup deadline and launches only once' {
        $script:discoveryCount=0
        Mock Find-Lemonade { $script:discoveryCount++; if ($script:discoveryCount -gt 1) { 'C:\new\lemonade.exe' } }
        Mock Get-Command { [pscustomobject]@{Source='winget.exe'} }
        Mock Confirm-LemonadeInstall { $true }
        Mock Install-Lemonade { 0 }
        Mock Invoke-LemonadeStatus { [pscustomobject]@{ExitCode=-1;StdOut='';StdErr='timed out'} }
        Mock Test-Path { $true }
        Mock Start-Process { }
        Mock Start-Sleep { }
        $clock=[Diagnostics.Stopwatch]::StartNew()
        { Initialize-Lemonade -StartupTimeoutSeconds 0.1 } | Should -Throw $AbortToken
        $clock.Elapsed.TotalSeconds | Should -BeLessThan 3
        Should -Invoke Start-Process -Times 1
        Should -Invoke Invoke-LemonadeStatus -ParameterFilter { $TimeoutMilliseconds -le 100 } -Times 1
    }
    It 'terminates a hung status executable within its timeout' {
        $exe=Join-Path $TestDrive 'hung-status.exe'
        $typeName='HungStatus'+[guid]::NewGuid().ToString('N')
        Add-Type -TypeDefinition "public class $typeName { public static void Main(string[] args) { System.Threading.Thread.Sleep(30000); } }" -OutputAssembly $exe -OutputType ConsoleApplication
        $clock=[Diagnostics.Stopwatch]::StartNew()
        $result=Invoke-LemonadeStatus $exe 300
        $result.ExitCode | Should -Be -1
        $result.StdErr | Should -Match 'timed out'
        $clock.Elapsed.TotalSeconds | Should -BeLessThan 5
    }
    It 'drains large stdout and stderr concurrently' {
        $exe=Join-Path $TestDrive 'noisy-status.exe'
        $typeName='NoisyStatus'+[guid]::NewGuid().ToString('N')
        Add-Type -TypeDefinition "public class $typeName { public static void Main(string[] args) { for (int i=0;i<20000;i++) { System.Console.Out.WriteLine(new string('o',100)); System.Console.Error.WriteLine(new string('e',100)); } } }" -OutputAssembly $exe -OutputType ConsoleApplication
        $result=Invoke-LemonadeStatus $exe 10000
        $result.ExitCode | Should -Be 0
        $result.StdOut.Length | Should -BeGreaterThan 2000000
        $result.StdErr.Length | Should -BeGreaterThan 2000000
    }
    It 'refreshes only process PATH and preserves persistent PATH' {
        $processBefore=$env:PATH
        $userBefore=[Environment]::GetEnvironmentVariable('PATH','User')
        try {
            # Invoke the real definition despite the per-test mock.
            $f=$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Update-SetupPath'},$false)[0]
            & ([scriptblock]::Create($f.Body.Extent.Text.Trim('{}')))
            [Environment]::GetEnvironmentVariable('PATH','User') | Should -Be $userBefore
        } finally { $env:PATH=$processBefore }
    }
}
