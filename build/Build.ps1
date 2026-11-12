<#
.SYNOPSIS
    Builds the single-file Defender-Quarantine-Extractor.ps1 from the files in src\.

.DESCRIPTION
    The tool ships as one self-contained script so it can be pasted into PowerShell ISE. For maintenance it is kept as
    separate parts under src\ and stitched together here:

        Header.ps1    comment-based help and parameters
        assets\       emblem (embedded as base64)
        Report.html   HTML report template (embedded as a here-string)
        Engine.ps1    readers, parsers, archive writer
        Gui.ps1       WPF window
        Main.ps1      console mode and entry point

    The output is pure ASCII with CRLF line endings and no byte-order mark, so copy and paste cannot corrupt it.

.PARAMETER Check
    Builds in memory and fails if the committed Defender-Quarantine-Extractor.ps1 differs. Used by CI.
#>
[CmdletBinding()]
param([switch] $Check)

$ErrorActionPreference = 'Stop'
$Version = '1.0.0'
$RepoUrl = 'https://github.com/akhil-dara/Defender-Quarantine-Extractor'

$root = Split-Path -Parent $PSScriptRoot
$src = Join-Path $root 'src'
$target = Join-Path $root 'Defender-Quarantine-Extractor.ps1'
function Read-Part([string]$name) { [IO.File]::ReadAllText((Join-Path $src $name), [Text.Encoding]::UTF8).TrimEnd() }

$emblem = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $src 'assets\emblem-64.png')))
$report = (Read-Part 'Report.html').Replace('/*DQE_EMBLEM*/', $emblem)
if ($report -match "(?m)^'@") { throw "Report.html contains a line starting with '@, which would end the here-string early." }

$parts = @(
    (Read-Part 'Header.ps1')
    @"
# =====================================================================================================================
#  EMBEDDED ASSETS
# =====================================================================================================================
`$DqeEmblem = '$emblem'

`$DqeReportTemplate = @'
$report
'@
"@
    (Read-Part 'Engine.ps1')
    (Read-Part 'Gui.ps1')
    (Read-Part 'Main.ps1')
)
$text = ($parts -join "`r`n`r`n") + "`r`n"
$text = ($text -replace "`r?`n", "`r`n").Replace('__DQE_VERSION__', $Version).Replace('__DQE_REPO__', $RepoUrl)

$bytes = [Text.Encoding]::ASCII.GetBytes($text)
if ([Text.Encoding]::ASCII.GetString($bytes) -ne $text) {
    $bad = [regex]::Matches($text, '[^\x00-\x7F]') | Select-Object -First 5 | ForEach-Object { 'U+{0:X4}' -f [int][char]$_.Value }
    throw "Non-ASCII characters found: $($bad -join ', '). Keep sources ASCII so pasting into ISE cannot break."
}
$errors = $null
[void][Management.Automation.Language.Parser]::ParseInput($text, [ref]$null, [ref]$errors)
if ($errors) { $errors | Select-Object -First 10 | ForEach-Object { Write-Host "line $($_.Extent.StartLineNumber): $($_.Message)" -ForegroundColor Red }; throw 'The built script does not parse.' }

if ($Check) {
    $current = if (Test-Path $target) { [IO.File]::ReadAllBytes($target) } else { [byte[]]@() }
    if ([Convert]::ToBase64String($current) -ne [Convert]::ToBase64String($bytes)) { throw 'Defender-Quarantine-Extractor.ps1 is out of date. Run build\Build.ps1 and commit the result.' }
    Write-Host 'Defender-Quarantine-Extractor.ps1 is up to date.' -ForegroundColor Green
    return
}
[IO.File]::WriteAllBytes($target, $bytes)
Write-Host ('Built {0}  ({1:N0} lines, {2:N0} KB, version {3})' -f (Split-Path $target -Leaf), ($text -split "`n").Count, ($bytes.Length / 1KB), $Version) -ForegroundColor Green
