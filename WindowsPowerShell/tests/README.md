# PowerShell tests

The test suite targets the current stable Pester 6 release. Windows PowerShell
5.1 includes Microsoft-signed Pester 3.4.0; leave that system module in place
and install current Pester side by side for the active user:

```powershell
Install-Module -Name Pester -MinimumVersion 6.0 -Scope CurrentUser `
    -Force -SkipPublisherCheck
```

`-Force` permits the side-by-side installation and `-SkipPublisherCheck`
accepts the change from Microsoft's certificate on the inbox module to the
current community publisher. The unpinned command intentionally selects the
latest stable release instead of the maintenance-only Pester 5 line.

## Older PowerShellGet bootstrap

The inbox PowerShellGet 1.0.0.1 may fail before installation while attempting
to prompt for the NuGet provider. A headless session can report a
`ShouldContinue` null-reference error. Bootstrap NuGet explicitly, then repeat
the Pester installation:

```powershell
[Net.ServicePointManager]::SecurityProtocol =
    [Net.ServicePointManager]::SecurityProtocol -bor
    [Net.SecurityProtocolType]::Tls12

Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 `
    -Scope CurrentUser -Force -Confirm:$false

Install-Module -Name Pester -MinimumVersion 6.0 -Scope CurrentUser `
    -Force -SkipPublisherCheck
```

Administrator rights are not required for either current-user installation.
Start a new PowerShell session, verify that the newer module wins resolution,
and run the complete suite:

```powershell
Import-Module Pester -MinimumVersion 6.0 -Force
Get-Module Pester | Select-Object Name, Version, ModuleBase
Invoke-Pester -Path .\WindowsPowerShell\tests -Output Detailed
```

Pester 3.4.0 may still appear in `Get-Module -ListAvailable`; this is expected.
The imported module should be Pester 6 from the current user's module directory.
See Pester's official [installation and update guidance](https://pester.dev/docs/v5/introduction/installation)
for supported PowerShell versions and publisher-signing details.
