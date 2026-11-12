<#
.SYNOPSIS
    Runs the test suite against synthetic Defender evidence. No modules or installs needed.

.DESCRIPTION
    1. Checks the committed single-file script matches the sources (build\Build.ps1 -Check).
    2. Generates synthetic evidence in eight collection layouts (tests\New-DemoEvidence.ps1).
    3. For every layout: loads it, recovers everything, verifies the archive and checks hashes, hash confirmation,
       timeline content and that no plaintext sample content reached the disk.
    4. Exercises password handling, single-file export, console mode and error paths.
    5. If 7-Zip is installed, has it independently test every archive.
    6. Runs the security suite (tests\Invoke-SecurityTests.ps1) against hostile, crafted evidence.

    Exit code is the number of failed checks.

.PARAMETER WorkDirectory
    Scratch folder for generated evidence and output. Defaults to dqe-tests in the user's temp folder, outside the repository. Deleted at the start.
#>
[CmdletBinding()]
param([string] $WorkDirectory)

$ErrorActionPreference = 'Stop'
if (-not $WorkDirectory) { $WorkDirectory = Join-Path ([IO.Path]::GetTempPath()) 'dqe-tests' }
$repo = Split-Path -Parent $PSScriptRoot
$tool = Join-Path $repo 'Defender-Quarantine-Extractor.ps1'
$script:Failed = 0; $script:Passed = 0

function Assert([bool]$cond, [string]$what) {
    if ($cond) { $script:Passed++; Write-Host "  ok    $what" -ForegroundColor DarkGreen }
    else { $script:Failed++; Write-Host "  FAIL  $what" -ForegroundColor Red }
}
function Section([string]$t) { Write-Host ''; Write-Host $t -ForegroundColor Cyan }

Section 'Build'
try { & (Join-Path $repo 'build\Build.ps1') -Check; Assert $true 'single-file script is up to date with src\' }
catch { Assert $false "single-file script is up to date with src\ ($($_.Exception.Message))" }
$bytes = [IO.File]::ReadAllBytes($tool)
Assert (-not ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)) 'script has no byte-order mark (safe to paste into ISE)'
Assert (@($bytes | Where-Object { $_ -gt 127 }).Count -eq 0) 'script is pure ASCII'
$tokens = $null; $errs = $null; $ast = [Management.Automation.Language.Parser]::ParseFile($tool, [ref]$tokens, [ref]$errs)
Assert ($errs.Count -eq 0) 'script parses'
Assert (-not ([IO.File]::ReadAllText($tool) -match '(?i)Add-Type\s+-TypeDefinition|Add-Type\s+-MemberDefinition|Add-Type\s+-Path')) 'script compiles no code (Add-Type only loads assemblies)'

Section 'Synthetic evidence'
if (Test-Path $WorkDirectory) { Remove-Item -LiteralPath $WorkDirectory -Recurse -Force }
$demo = Join-Path $WorkDirectory 'evidence'; $out = Join-Path $WorkDirectory 'output'
$gen = & (Join-Path $PSScriptRoot 'New-DemoEvidence.ps1') -OutputDirectory $demo
$X = $gen.Expected
Assert ($gen.Files -ge 20) "generated $($gen.Files) artifacts in 8 layouts"

$env:DQE_IMPORT_ONLY = '1'
try { . $tool } finally { Remove-Item Env:\DQE_IMPORT_ONLY }
. $DqeEngine
$script:Quiet = $true
$latin1 = [Text.Encoding]::GetEncoding(28591)
$markers = @(
    $latin1.GetString([Text.Encoding]::ASCII.GetBytes('synthetic sample created by Defender Quarantine Extractor tests'))
    $latin1.GetString([Text.Encoding]::ASCII.GetBytes('contoso-sync.log'))
    $latin1.GetString([Text.Encoding]::Unicode.GetBytes('ContosoSyncUpdate</URI>'))
)
function Test-NoPlaintext([string]$dir) {
    # The core promise: recovered content never reaches the disk unencrypted, in the archive or in the report.
    foreach ($f in Get-ChildItem -LiteralPath $dir -Recurse -File) {
        $hay = $latin1.GetString([IO.File]::ReadAllBytes($f.FullName))
        foreach ($m in $markers) { if ($hay.Contains($m)) { return $f.Name } }
    }
    $null
}

$layouts = @(
    @{ Name = 'liveresponse.zip';        Full = $true }
    @{ Name = 'liveresponse.zip.gz';     Full = $true }
    @{ Name = 'nested.zip';              Full = $true }
    @{ Name = 'protected-aes.zip';       Full = $true }
    @{ Name = 'protected-zipcrypto.zip'; Full = $true; Passwords = @('contoso-demo') }
    @{ Name = 'folder';                  Full = $true }
    @{ Name = 'quarantine-only';         Full = $false }
    @{ Name = 'flat';                    Full = $true }
)
foreach ($l in $layouts) {
    Section "Layout: $($l.Name)"
    $o = Join-Path $out ($l.Name -replace '\W', '_')
    try {
        $M = Dqe-Load @(Join-Path $demo $l.Name) $l.Passwords
        Assert ($M.Entries.Count -eq $X.Entries) "reads $($X.Entries) quarantine entries"
        Assert ($M.Rows.Count -eq $X.Rows) "lists $($X.Rows) quarantined resources"
        Assert (@($M.Rows | Where-Object { $_.Payload -eq 'File' }).Count -eq $X.RecoverableFiles) "finds $($X.RecoverableFiles) recoverable files"
        Assert (@($M.Rows | Where-Object { $_.Payload -eq 'Registry hive' }).Count -eq $X.RegistryHives) 'finds the registry hive'
        $sel = @($M.Rows | Where-Object { $_.Payload -eq 'File' -or $_.Payload -eq 'Registry hive' } | ForEach-Object { $_.Key })
        $R = Dqe-Generate $M @{ Selected = $sel; OutDir = $o; Password = 'infected'; Encryption = 'aes'; Raw = 'core'; PerSample = $true; Verify = $true
            CaseId = 'TEST'; Analyst = 'tests'; Title = "Test $($l.Name)"; Description = ''; Template = $DqeReportTemplate }
        Assert ($R.Samples -eq $X.RecoverableFiles -and $R.Hives -eq $X.RegistryHives) 'recovers every file and hive'
        Assert ($R.Verify.Bad -eq 0 -and $R.Verify.Checked -eq ($X.RecoverableFiles + $X.RegistryHives)) 'archive round trip verified'
        $exe = $R.SampleList | Where-Object { $_.name -eq 'ContosoSync.exe' }
        Assert ($exe.sha256 -eq $X.ExeSha256) 'recovered executable has the original SHA-256'
        Assert ($exe.type -eq 'PE32+ GUI (x64)') 'executable type detected'
        Assert (@($exe.streams | Where-Object { $_.kind -eq 'alternate data stream' -and $_.text -match 'HostUrl=https://files.contoso.example' }).Count -eq 1) 'Zone.Identifier stream recovered'
        Assert (($R.SampleList | Where-Object { $_.name -eq 'sync.ps1' }).sha256 -eq $X.ScriptSha256) 'recovered script has the original SHA-256'
        if ($l.Full) {
            Assert ($exe.hashCheck -eq 'match') 'executable hash confirmed against Defender records'
            Assert ($R.Events -ge 15) "timeline built ($($R.Events) events)"
        }
        Assert (Test-Path $R.Report) 'report written'
        Assert ((Get-ChildItem -LiteralPath $R.PerSampleDir -Filter *.zip).Count -eq $X.RecoverableFiles) 'one zip per file written'
        $leak = Test-NoPlaintext $o
        Assert (-not $leak) $(if ($leak) { "no plaintext sample content on disk (found in $leak)" } else { 'no plaintext sample content on disk' })
        Dqe-CloseSource $M.Src
    } catch { Assert $false "layout processed without error: $($_.Exception.Message)" }
}

Section 'Leak detector self-check'
$plant = Join-Path $out 'plant'; [void][IO.Directory]::CreateDirectory($plant)
[IO.File]::WriteAllText((Join-Path $plant 'x.txt'), 'prefix contoso-sync.log suffix')
Assert ((Test-NoPlaintext $plant) -eq 'x.txt') 'leak detector finds planted plaintext'
Remove-Item -LiteralPath $plant -Recurse -Force

Section 'Passwords and errors'
try { $M = Dqe-Load @(Join-Path $demo 'protected-zipcrypto.zip') @(); Dqe-CloseSource $M.Src; Assert $false 'unknown password is reported' }
catch { Assert ($_.Exception.Message -match 'password-protected') 'unknown password is reported clearly' }
try { [void](Dqe-Load @(Join-Path $demo 'missing.zip') @()); Assert $false 'missing source is reported' } catch { Assert ($_.Exception.Message -match 'not found') 'missing source is reported clearly' }
try { [void](Dqe-Load @($tool) @()); Assert $true 'non-Defender file loads without crashing' } catch { Assert $false "non-Defender file loads without crashing ($($_.Exception.Message))" }
$M = Dqe-Load @((Join-Path $demo 'folder'), (Join-Path $demo 'liveresponse.zip')) @()
Assert ($M.Entries.Count -eq 2 * $X.Entries) 'several sources load together'
Dqe-CloseSource $M.Src

Section 'Single-file export'
$M = Dqe-Load @(Join-Path $demo 'liveresponse.zip') @()
$row = $M.Rows | Where-Object { $_.Path -like '*ContosoSync.exe' }
$single = Join-Path $out 'single.zip'
$r1 = Dqe-ExportOne $M @{ Key = $row.Key; OutPath = $single; Password = 'infected'; Encryption = 'aes' }
Assert ($r1.Sha256 -eq $X.ExeSha256 -and (Test-Path $single)) 'single file exported, AES'
$r2 = Dqe-ExportOne $M @{ Key = $row.Key; OutPath = (Join-Path $out 'single-zc.zip'); Password = 'infected'; Encryption = 'zipcrypto' }
Assert ($r2.Sha256 -eq $X.ExeSha256) 'single file exported, ZipCrypto'
$back = Dqe-Load @(Join-Path $out 'single-zc.zip') @()
Assert ($null -ne $back.Src.Zips[0].Pw) 'ZipCrypto output re-opens with "infected"'
Dqe-CloseSource $back.Src; Dqe-CloseSource $M.Src

Section 'Console mode'
$co = Join-Path $out 'console'
$res = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $tool -Source (Join-Path $demo 'liveresponse.zip.gz') -OutputDirectory $co -CaseId CONSOLE -IncludeOriginals None 2>&1
$zip = Get-ChildItem -LiteralPath $co -Filter 'CONSOLE_*.zip' -ErrorAction SilentlyContinue
Assert ($LASTEXITCODE -eq 0 -and $zip.Count -eq 1) 'console run produces an archive'
Assert (@(Get-ChildItem -LiteralPath $co -Filter 'CONSOLE_*.html').Count -eq 1) 'console run produces a report'

$sevenZip = @("$env:ProgramFiles\7-Zip\7z.exe", "${env:ProgramFiles(x86)}\7-Zip\7z.exe") | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if ($sevenZip) {
    Section '7-Zip cross-check'
    foreach ($z in Get-ChildItem -LiteralPath $out -Recurse -Filter *.zip) {
        $t = & $sevenZip t -pinfected $z.FullName 2>&1 | Out-String
        Assert ($t -match 'Everything is Ok') "7-Zip opens $($z.Name)"
    }
}

Section 'Security tests (hostile evidence)'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Invoke-SecurityTests.ps1') -WorkDirectory (Join-Path $WorkDirectory 'security')
$secFailed = $LASTEXITCODE
Assert ($secFailed -eq 0) "security suite passed ($secFailed failed check(s))"

Write-Host ''
$color = if ($script:Failed) { 'Red' } else { 'Green' }
Write-Host ('{0} passed, {1} failed' -f $script:Passed, $script:Failed) -ForegroundColor $color
exit $script:Failed
