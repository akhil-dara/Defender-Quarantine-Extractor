<#
.SYNOPSIS
    Security tests: runs the tool against hostile, crafted evidence.

.DESCRIPTION
    Evidence comes from compromised hosts, so these tests assume every name, size and line in it is chosen by an
    attacker, and check that the tool's guarantees still hold:

      * nothing is written outside the chosen output folder, and archive entry names cannot climb out on extraction
      * evidence text cannot inject markup or script into the report, or formulas into the CSV exports
      * decompression bombs and lying size fields cannot exhaust memory (each case runs in its own process, and its
        peak working set is measured)
      * a crafted log cannot hang parsing
      * corrupted artifacts and archives never crash a run, and recovered content never reaches the disk unencrypted

    Called by Invoke-Tests.ps1; can also run on its own. Exit code is the number of failed checks.

.PARAMETER WorkDirectory
    Scratch folder for generated evidence and output. Deleted at the start.
#>
[CmdletBinding()]
param([string] $WorkDirectory, [int] $FuzzRounds = 25)

$ErrorActionPreference = 'Stop'
if (-not $WorkDirectory) { $WorkDirectory = Join-Path ([IO.Path]::GetTempPath()) 'dqe-tests\security' }
$work = [IO.Path]::GetFullPath($WorkDirectory)
$repo = Split-Path -Parent $PSScriptRoot
$tool = Join-Path $repo 'Defender-Quarantine-Extractor.ps1'
$script:Failed = 0; $script:Passed = 0
function Assert([bool]$cond, [string]$what) {
    if ($cond) { $script:Passed++; Write-Host "  ok    $what" -ForegroundColor DarkGreen }
    else { $script:Failed++; Write-Host "  FAIL  $what" -ForegroundColor Red }
}
function Section([string]$t) { Write-Host ''; Write-Host $t -ForegroundColor Cyan }

Section 'Hostile evidence'
if (Test-Path $work) { Remove-Item -LiteralPath $work -Recurse -Force }
$h = & (Join-Path $PSScriptRoot 'New-HostileEvidence.ps1') -OutputDirectory (Join-Path $work 'evidence') -FuzzRounds $FuzzRounds
$ev = $h.Root; $out = Join-Path $work 'output'
Assert (Test-Path (Join-Path $ev 'traversal.zip')) 'hostile evidence generated'

$fuzzRounds = $h.FuzzRounds
$env:DQE_IMPORT_ONLY = '1'
try { . $tool } finally { Remove-Item Env:\DQE_IMPORT_ONLY }
. $DqeEngine
$script:Quiet = $true
$latin1 = [Text.Encoding]::GetEncoding(28591)

function Invoke-Run([string[]]$paths, [string]$dest, [string]$raw = 'all', [string]$title = 'Security test') {
    $M = Dqe-Load $paths @()
    try {
        $sel = @($M.Rows | Where-Object { $_.Payload -eq 'File' -or $_.Payload -eq 'Registry hive' } | ForEach-Object { $_.Key })
        Dqe-Generate $M @{ Selected = $sel; OutDir = $dest; Password = 'infected'; Encryption = 'aes'; Raw = $raw; PerSample = $false; Verify = $true
            CaseId = 'SEC'; Analyst = 'tests'; Title = $title; Description = ''; Template = $DqeReportTemplate }
    } finally { Dqe-CloseSource $M.Src }
}
function Get-ArchiveNames([string]$zip) {
    $fs = [IO.File]::OpenRead($zip)
    try { @((Dqe-ZipOpenReader $fs 'output').Entries | ForEach-Object { $_.Name }) } finally { $fs.Dispose() }
}
function Get-ArchiveText([string]$zip, [string]$name) {
    $fs = [IO.File]::OpenRead($zip)
    try {
        $script:UserPasswords = @('infected'); $z = Dqe-ZipOpenReader $fs 'output'
        $e = $z.Entries | Where-Object { $_.Name -eq $name } | Select-Object -First 1
        if (-not $e) { return '' }
        [Text.Encoding]::UTF8.GetString((Dqe-ZipEntryBytes $z $e))
    } finally { $fs.Dispose() }
}
function Get-ReportOutsideData([string]$path) {
    # The report's masked data block is base64 and cannot carry markup; everything else is what the browser parses.
    $html = [IO.File]::ReadAllText($path)
    [regex]::Replace($html, '(?s)<script id="dqe-data" type="application/octet-stream">.*?</script>', '')
}

# ---------------------------------------------------------------- traversal
Section 'Path traversal'
$before = @(Get-ChildItem -LiteralPath $work -Recurse -File -Filter 'dqe-escape*' -ErrorAction SilentlyContinue).Count
$R = Invoke-Run @(Join-Path $ev 'traversal.zip') (Join-Path $out 'traversal')
$names = Get-ArchiveNames $R.Zip
Assert ($names.Count -gt 0) 'archive produced from evidence with hostile entry names'
Assert (@($names | Where-Object { $_ -match '(^|/)\.\.(/|$)' }).Count -eq 0) 'no archive entry name contains a ".." segment'
Assert (@($names | Where-Object { $_ -match '^[/\\]|:|\\' }).Count -eq 0) 'no archive entry name is absolute, has a drive letter or a backslash'
Assert (@($names | Where-Object { $_ -match '^raw/.*dqe-escape-[56]' }).Count -eq 2) 'hostile entries inside the Defender folder kept under raw/ with clean names'
$escaped = @(Get-ChildItem -LiteralPath (Split-Path $repo) -Recurse -File -Filter 'dqe-escape*' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notlike "$work*" })
Assert ($escaped.Count -eq 0) 'no file written outside the output folder'
Assert (@(Get-ChildItem -LiteralPath $work -Recurse -File -Filter 'dqe-escape*' -ErrorAction SilentlyContinue).Count -eq $before) 'no hostile file extracted to disk at all'

# ---------------------------------------------------------------- injection
Section 'Report and CSV injection'
$hostile = $h.HostileThreat
$R = Invoke-Run @((Join-Path $ev 'names\folder'), (Join-Path $ev 'names-in-warnings.zip')) (Join-Path $out 'names') 'core' $hostile
$page = Get-ReportOutsideData $R.Report
Assert ($R.Warnings -ge 1) 'warning quoting a hostile entry name was raised'
Assert (-not ($page -match '<script>window\.__dqePwned' -or $page -match '</script><script>window')) 'no evidence text closes or opens a script element in the report'
Assert (-not ($page -match '<img src=x')) 'no evidence-supplied tag in the report'
Assert ($page.Contains('&lt;img src=x') -and $page.Contains('<title>')) 'hostile report title is HTML-encoded'
$csv = Get-ArchiveText $R.Zip 'decoded/samples.csv'
Assert ($csv.Contains('"''=HYPERLINK')) 'formula-like threat name neutralised in samples.csv'
Assert (-not ($csv -match '(^|,)"=HYPERLINK')) 'no CSV cell starts with a formula'
$tl = Get-ArchiveText $R.Zip 'decoded/timeline.csv'
Assert (-not ($tl -match '(^|,)"[=+@-]')) 'no timeline CSV cell starts with a formula character'

# ---------------------------------------------------------------- bombs, each in its own process
Section 'Decompression bombs and lying sizes'
$child = Join-Path $work 'bomb-child.ps1'
@'
param([string]$ToolPath, [string]$BombPath, [string]$OutPath)
# Parameter names differ from the tool's own (Source, OutputDirectory): dot-sourcing the tool would reset them.
$ErrorActionPreference = 'Stop'
$env:DQE_IMPORT_ONLY = '1'; . $ToolPath; Remove-Item Env:\DQE_IMPORT_ONLY
. $DqeEngine; $script:Quiet = $true
$script:MaxItemBytes = 256MB; $script:MaxHeldBytes = 512MB
$status = 'ok'
try {
    $M = Dqe-Load @($BombPath) @()
    $sel = @($M.Rows | Where-Object { $_.Payload -eq 'File' -or $_.Payload -eq 'Registry hive' } | ForEach-Object { $_.Key })
    $R = Dqe-Generate $M @{ Selected = $sel; OutDir = $OutPath; Password = 'infected'; Encryption = 'aes'; Raw = 'core'; PerSample = $false; Verify = $true
        CaseId = 'BOMB'; Analyst = 't'; Title = 't'; Description = ''; Template = $DqeReportTemplate }
    Dqe-CloseSource $M.Src
    $status = "generated, $($R.Warnings) warning(s)"
} catch { $status = 'refused: ' + $_.Exception.Message }
[GC]::Collect()
'RESULT|' + $status
'PEAK|' + [Diagnostics.Process]::GetCurrentProcess().PeakWorkingSet64
'@ | Set-Content -LiteralPath $child -Encoding ASCII
# Expect: the run completes and reports the bad item as a warning, or (for a source that is itself a bomb) it is
# refused with a message naming the limit. Peak memory stays far below what the declared sizes would cost.
$cases = @(
    @{ File = 'ratio-log.zip'; Limit = 400MB; Expect = '^generated, [1-9]'; Note = '300 MB log bomb' }
    @{ File = 'understated.zip'; Limit = 400MB; Expect = '^generated'; Note = '300 MB stream declared as 1 MB' }
    @{ File = 'overstated.zip'; Limit = 400MB; Expect = '^generated, [1-9]'; Note = '4 KB entry declaring 900 MB' }
    @{ File = 'csize-past-end.zip'; Limit = 400MB; Expect = '^generated, [1-9]'; Note = 'compressed size past end of file' }
    @{ File = 'ratio-entry.zip'; Limit = 400MB; Expect = '^generated, [1-9]'; Note = '300 MB metadata bomb' }
    @{ File = 'nested-8.zip'; Limit = 600MB; Expect = '^generated, [1-9]'; Note = 'eight nested archives' }
    @{ File = 'bomb.zip.gz'; Limit = 700MB; Expect = '^refused: .*expands to more than'; Note = '1.2 GB gzip bomb' }
)
foreach ($c in $cases) {
    $o = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $child -ToolPath $tool -BombPath (Join-Path $ev "bombs\$($c.File)") -OutPath (Join-Path $out ("bomb-" + $c.File)) 2>&1 | Out-String
    $res = [regex]::Match($o, 'RESULT\|([^\r\n]*)').Groups[1].Value
    $peak = [int64]([regex]::Match($o, 'PEAK\|(\d+)').Groups[1].Value)
    Assert ($res -match $c.Expect -and $peak -gt 0 -and $peak -lt $c.Limit) ('{0}: {1}; peak memory {2:N0} MB' -f $c.Note, $res, ($peak / 1MB))
}

# ---------------------------------------------------------------- crafted log
Section 'Crafted log'
$sw = [Diagnostics.Stopwatch]::StartNew()
try { $R = Invoke-Run @(Join-Path $ev 'redos') (Join-Path $out 'redos') 'none'; $ok = $true } catch { $ok = $false }
Assert ($ok -and $sw.Elapsed.TotalSeconds -lt 60) ('log of 200,000 unterminated blocks parsed in {0:N1} s' -f $sw.Elapsed.TotalSeconds)

# ---------------------------------------------------------------- fuzzing
Section "Fuzzing ($fuzzRounds corrupted collections, $fuzzRounds corrupted archives)"
$crashes = 0; $slow = 0
for ($r = 1; $r -le $fuzzRounds; $r++) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try { [void](Invoke-Run @(Join-Path $ev ('fuzz\{0:D2}' -f $r)) (Join-Path $out ('fuzz-{0:D2}' -f $r)) 'core') }
    catch { $crashes++; Write-Host ("        round {0}: {1}" -f $r, $_.Exception.Message) -ForegroundColor DarkYellow }
    if ($sw.Elapsed.TotalSeconds -gt 60) { $slow++ }
}
Assert ($crashes -eq 0) "corrupted Defender artifacts never stop a run ($crashes of $fuzzRounds stopped)"
$unclean = 0
for ($r = 1; $r -le $fuzzRounds; $r++) {
    try { [void](Invoke-Run @(Join-Path $ev ('fuzz-zip\{0:D2}.zip' -f $r)) (Join-Path $out ('fuzzzip-{0:D2}' -f $r)) 'core') }
    catch { if (-not $_.Exception.Message -or $_.Exception -is [OutOfMemoryException] -or $_.Exception -is [StackOverflowException]) { $unclean++ } }
    if ($sw.Elapsed.TotalSeconds -gt 60) { $slow++ }
}
Assert ($unclean -eq 0) 'corrupted archives either load or fail with a clear message'
Assert ($slow -eq 0) 'no fuzz case took longer than 60 s'

# ---------------------------------------------------------------- the core promise, across every run above
Section 'Plaintext on disk'
$markers = @(
    $latin1.GetString([Text.Encoding]::ASCII.GetBytes('synthetic sample created by Defender Quarantine Extractor tests'))
    $latin1.GetString([Text.Encoding]::ASCII.GetBytes('contoso-sync.log'))
    $latin1.GetString([Text.Encoding]::Unicode.GetBytes('ContosoSyncUpdate</URI>'))
)
$leaks = @(foreach ($f in Get-ChildItem -LiteralPath $out -Recurse -File) {
    $hay = $latin1.GetString([IO.File]::ReadAllBytes($f.FullName)); foreach ($m in $markers) { if ($hay.Contains($m)) { $f.Name; break } }
})
Assert ($leaks.Count -eq 0) ("no recovered content in plaintext in any output ({0} files checked)" -f @(Get-ChildItem -LiteralPath $out -Recurse -File).Count)

Write-Host ''
Write-Host ('security: {0} passed, {1} failed' -f $script:Passed, $script:Failed) -ForegroundColor $(if ($script:Failed) { 'Red' } else { 'Green' })
exit $script:Failed
