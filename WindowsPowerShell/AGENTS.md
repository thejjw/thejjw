# PowerShell encoding rules

Windows PowerShell 5.1 (`powershell.exe`) is the default host here, and its
cmdlet defaults differ from PowerShell 7 and .NET:

- `Get-Content` without `-Encoding` decodes BOMless files with the ANSI code
  page, not UTF-8.
- `Set-Content -Encoding UTF8` writes a UTF-8 BOM on 5.1.
- `Out-File` and `>` redirection write UTF-16LE.
- A BOMless `.ps1` containing non-ASCII is parsed as ANSI.

## Read

- Machine-readable data (JSON, TOML, YAML):
  `[IO.File]::ReadAllText($path)`, or
  `Get-Content -Raw -LiteralPath $path -Encoding UTF8`.
- Never use bare `Get-Content` for data files another program will parse.

## Write

- JSON, TOML, YAML, and other files read by strict parsers (serde, Go, jq):
  `[IO.File]::WriteAllText($path, $text, [Text.UTF8Encoding]::new($false))`.
- Do not use `Set-Content -Encoding UTF8` for those files; it emits a BOM and
  the parser rejects it.
- Avoid `Out-File` and `>` for data files.

## Source

- Keep `.ps1` source ASCII.
- When non-ASCII source is unavoidable, save it UTF-8 **with BOM**; 5.1 reads a
  BOMless file as ANSI.

## Verify

- No BOM (expected `7B` for JSON):
  `([IO.File]::ReadAllBytes($p)[0..2] | ForEach-Object { $_.ToString('X2') }) -join ' '`
- Non-ASCII round trip: write a known string, read it back, and compare with
  `-ceq` plus code points. Do not trust console output; it may render `?`.
- `ConvertTo-Json` on 5.1 escapes non-ASCII as `\uXXXX`; semantic round-trip
  is fine.
