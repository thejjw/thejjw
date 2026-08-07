<#
.SYNOPSIS
Finds conservative sibling-source candidates for a target document.

.DESCRIPTION
Ranks files in the target directory when their filename stem matches exactly or
matches after removal of a terminal locale token. Results are informational;
callers must inspect candidates before treating them as sources.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$TargetPath,

    [ValidateSet('Object', 'Json')]
    [string]$OutputFormat = 'Object'
)

$resolvedTarget = (Resolve-Path -LiteralPath $TargetPath -ErrorAction Stop).Path
$target = Get-Item -LiteralPath $resolvedTarget -ErrorAction Stop

if ($target.PSIsContainer) {
    throw "TargetPath must identify a file: $resolvedTarget"
}

$documentExtensions = @(
    '.html', '.htm', '.md', '.markdown', '.txt', '.docx', '.pdf', '.pptx',
    '.odt', '.rtf'
)

# Remove only a terminal locale marker so generic shared prefixes never match.
$localeSuffixPattern = '(?i)(?:[-_.](?:[a-z]{2,3})(?:[-_][a-z]{2})?)$'
$targetStem = [System.IO.Path]::GetFileNameWithoutExtension($target.Name)
$normalizedTargetStem = $targetStem -replace $localeSuffixPattern, ''

$results = Get-ChildItem -LiteralPath $target.DirectoryName -File |
    Where-Object {
        $_.FullName -ne $target.FullName -and
        $documentExtensions -contains $_.Extension.ToLowerInvariant()
    } |
    ForEach-Object {
        $candidateStem = [System.IO.Path]::GetFileNameWithoutExtension($_.Name)
        $normalizedCandidateStem = $candidateStem -replace $localeSuffixPattern, ''

        if ($candidateStem -ceq $targetStem) {
            [pscustomobject]@{
                Confidence = 100
                Relationship = 'exact-stem'
                Path = $_.FullName
                Reason = 'Same filename stem in another recognized document format.'
            }
        }
        elseif ($normalizedCandidateStem -ceq $normalizedTargetStem) {
            [pscustomobject]@{
                Confidence = 90
                Relationship = 'locale-neutral-stem'
                Path = $_.FullName
                Reason = 'Filename stems match after removing a terminal locale token.'
            }
        }
    } |
    Sort-Object -Property @{ Expression = 'Confidence'; Descending = $true }, Path

if ($OutputFormat -eq 'Json') {
    @($results) | ConvertTo-Json -Depth 3
}
else {
    $results
}
