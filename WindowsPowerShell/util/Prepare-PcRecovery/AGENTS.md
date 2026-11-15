# AGENTS.md - Prepare-PcRecovery

Scope: the recovery-USB prep script lives in this folder; its offline suite lives
at `WindowsPowerShell/tests/Prepare-PcRecovery.Tests.ps1`.

## Layout

- `Prepare-PcRecovery.ps1` - the whole tool: catalog, download engine, tool
  flows, readme generators, orchestration. Single file, dot-sourceable.
- `WindowsPowerShell/tests/Prepare-PcRecovery.Tests.ps1` - loads only functions
  and shared constants from the script with the PowerShell AST parser; no
  execution, no network, no writes outside `TestDrive`.
- Generated tree: `README.txt`, `isos\README.txt`,
  `isos\04-etc\<topic>\README.txt`. Edit the text generators in the script,
  never the generated tree.

## Environment

- Windows PowerShell 5.1 is the floor. Do not use `-AdditionalChildPath`,
  ternary, `??`, or other pwsh-only syntax. `-in`/`-notin` are fine (PowerShell
  3.0+).
- `$ErrorActionPreference = 'Stop'` applies: any real IO call can throw. A
  helper that claims "never throws" must wrap `Get-FileHash`, `Move-Item`,
  `[IO.File]`, and `Invoke-*` in `try`/`catch`.
- `Join-Path` takes two positional arguments in 5.1; nested path building needs
  one call per path segment.

## Contracts

- Every disk write runs under `ShouldProcess`; `-WhatIf` writes nothing and
  prints the plan table instead.
- Every failure goes through `Write-Failure` with actionable manual steps, and
  the run continues with the next entry. Exit code 1 when any failure exists.
- Success means observable state, not a return value: a file exists AND matches
  its expected SHA-256. Never document a file that was not verified this run.
- Never destroy the only working copy while updating. Versionless filenames
  need a backup (for example `.prev`), a rollback on failure, and orphan
  recovery at the start of the next run.
- Re-runs must be safe: matching hashes skip, stale files re-download, stale
  `.partial` files are discarded when the release tag changes.
- Trust labels must be exact. A GitHub release-asset `digest` is a GitHub digest,
  not a publisher-signed checksum.
- `isos\04-etc` is organized by topic folder (`copyparty\`, ...); root and isos
  readmes name the topic folder.
- Linux artifacts, in preference order: an official static binary when the
  project publishes one; otherwise both RPM (EL/Fedora) and DEB
  (Debian/Ubuntu) for the target architecture; otherwise whichever single
  package is published. Never substitute a distro repackage for an official
  release asset.
- Manual-retry text must be traceable: after the user follows it, the very next
  run must actually change the outcome.

## Verification

```powershell
cd WindowsPowerShell
Import-Module Pester -MinimumVersion 6.0 -Force
Invoke-Pester .\tests\Prepare-PcRecovery.Tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\util\Prepare-PcRecovery\Prepare-PcRecovery.ps1 -Root "$env:TEMP\pcr-whatif" -WhatIf
```

The suite needs Pester 6 (the inbox 3.4.0 cannot run `Should -Be`); see
`WindowsPowerShell/tests/README.md` for installation. Run the suite once after
the change; the `-WhatIf` smoke prints the plan table and must not touch the
network or disk.

## Recurring review patterns

These classes recurred across 11 opus review rounds. Check them before calling
a change done.

| Pattern | Failure shape | Guardrail |
|---|---|---|
| Dead-end retry advice | Instructions repeat a step the code will skip again (`-Elevate` in an already-elevated shell, re-run blocked by the same release check) | Trace the next-run path for every manual hint |
| Text/behavior drift | `.release` described as the source of files, rows documented before verification, comment naming the wrong path | Assert user-facing text against code order; re-read comments when ordering changes |
| Interruption windows | Backup moved but restore never reached; `.partial` resumed across releases; orphaned `.prev` | Enumerate state x operation: `{none, good, stale, .prev only, .partial}` x `{before lookup, after backup, during download, after verify}` |
| "Never throws" vs Stop | `Get-FileHash`/`Move-Item`/`[IO.File]` throw out of the helper and abort the batch | Wrap real IO; a throw fails one item, not the run |
| Data loss by ordering | Delete-before-download, declined backup then download, success assumed from a return value | Keep a restorable copy; verify on disk |
| Silent success | `ShouldProcess` returns true without writing; code treats that as downloaded | Success = file exists and hash matches |
| New branch, no test | Each fix adds a `catch`/`else`/`continue` that the next review finds untested | Regression test is part of the fix and fails when the branch is removed |
| Unfaithful test seams | Mocks write bytes that cannot match a fake digest, return true without a file, or a filtered Pester mock intercepts every call | Use real hashes of real content; mocks reproduce the callee contract |
| Trust-label inflation | GitHub asset digest presented as a publisher checksum | Name the trust boundary in the readme |
| PS 5.1 quirks | `Join-Path` arity, here-string backticks, `$Matches` reuse, `-WhatIf` vs `-Confirm` | Verify each quirk empirically once; keep it here |

## Polishing with claude -p (opus)

After a change is green locally, run the external review loop below. Run it from
the repo root and feed the cumulative local diff so the reviewer sees the whole
change, not one commit:

```powershell
$base = 'origin/main'   # or the commit before the change under review
$OutputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false
$diff = @(git diff "$base...HEAD")
if ($diff.Count -eq 0) { throw "No changes in $base...HEAD; set `$base" }
$prompt = @'
Review the local commits on stdin (PowerShell 5.1 util/Prepare-PcRecovery/Prepare-PcRecovery.ps1 + offline Pester suite). Review for actionable defects only: correctness bugs, regressions, broken tests, security or data-loss issues, misleading user-facing text, or missing coverage. Ignore style and anything pre-existing outside these commits. If nothing actionable remains, answer exactly 'NO ACTIONABLE FINDINGS'. Otherwise list findings with file:line, severity, and a concrete fix. Do not modify files.
'@
((@(git log --format='--- %h %s%n%b' "$base..HEAD") + $diff) -join "`r`n") |
    claude -p $prompt --model opus --tools Read Grep Glob --strict-mcp-config
```

- `$base` is `origin/main` or the commit before the change under review. The
  empty-diff guard prevents an unset base from producing a false clean review.
  The diff uses three dots (`base...HEAD`) so upstream commits that landed after
  the branch point do not appear as changes; the log keeps two dots because it
  should list only the commits under review.
- The UTF-8 line keeps non-ASCII diff text intact through the 5.1 pipe; the
  default `$OutputEncoding` is ASCII and would replace those characters.
- The reviewer gets only `Read`, `Grep`, and `Glob`, with all MCP servers
  disabled (`--strict-mcp-config`). That is an allowlist, so tools added to the
  CLI later stay unavailable without editing this file. If the installed CLI
  lacks `--tools`, fall back to a blocklist:
  `--disallowedTools Edit Write NotebookEdit Bash PowerShell EnterWorktree CronCreate RemoteTrigger --strict-mcp-config`,
  and re-check the list when new tools appear.
- Treat every claim as a hypothesis and reproduce it before editing: argv
  probes for language behavior, a Pester run, `git ls-files --eol`, the GitHub
  API for asset facts. Stale, duplicated, and wrong findings are normal; reject
  them with evidence and keep the code.
- Record each rejection and its evidence in the commit body (or the round
  summary), so the next round's `git log` shows why a claim was refused.
- Each accepted finding gets a regression test that fails when the branch is
  removed. Batch the fixes, run Pester once, then commit as one logical change.
- Loop shape: fix -> test -> commit -> re-review the cumulative diff. Keep the
  scope to the commits under review; do not re-litigate unrelated code.
- Termination rule: the polish loop ends in exactly one of two states.
  (a) No actionable claim remains: the round prints only
  `NO ACTIONABLE FINDINGS`. (b) Every remaining review claim has been
  rechecked and shown to be invalid, with the evidence recorded (argv probe,
  Pester run, file/tree check, upstream data). "Only low severity left" is not
  a stop condition while any claim is still valid, and a false claim is never
  a reason to weaken the code.
- Keep each round bounded: batch all accepted fixes, run Pester once, commit,
  then re-review. Each fix can add branches the next round will probe.

## Known false leads

- PowerShell 5.1 passes a comma-containing argument to a native program as one
  argument; `-v C:\data:data:r,admin` does not split (verified with an argv
  probe). Quoting it is still fine for clarity.
- copyparty ships no WinPE build in current releases; `copyparty-winpe64.exe`
  exists only for the deprecated v1.8.7 release.
