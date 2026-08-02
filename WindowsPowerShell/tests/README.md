# PowerShell tests

The test suite requires Pester 5 or later. Windows PowerShell includes an older
Microsoft-signed Pester release, so install the current version for the active
user with the publisher-change override:

```powershell
Install-Module -Name Pester -Scope CurrentUser -Force -SkipPublisherCheck
```

Administrator rights are not required. Start a new PowerShell session after
installation, then run:

```powershell
Invoke-Pester -Path .\WindowsPowerShell\tests
```
