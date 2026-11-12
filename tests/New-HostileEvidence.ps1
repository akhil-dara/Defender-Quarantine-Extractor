<#
.SYNOPSIS
    Creates hostile, crafted evidence for the security tests.

.DESCRIPTION
    Evidence handed to the tool comes from compromised hosts, so every name, size and offset in it may be chosen by an
    attacker. This script writes inputs that try to break the tool's guarantees:

        traversal.zip        archive entry names that climb out of folders (../, absolute paths, drive letters)
        names\folder\        a collection whose threat name carries HTML and a spreadsheet formula prefix
        bombs\*.zip          decompression bombs, size fields that lie in both directions, deep nesting, a gzip bomb
        fuzz\NN\             corrupted copies of every Defender artifact (bit flips, truncation, absurd lengths)
        fuzz-zip\NN.zip      corrupted copies of a collection archive

    All payloads are harmless. Bombs are built by streaming zeros through a compressor, never by allocating them.

.PARAMETER OutputDirectory
    Where to write the evidence. Created if missing.

.PARAMETER FuzzRounds
    Number of corrupted variants to generate per fuzz target.
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string] $OutputDirectory, [int] $FuzzRounds = 30)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($OutputDirectory)
$rounds = $FuzzRounds
[void][IO.Directory]::CreateDirectory($root)
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$demo = Join-Path $PSScriptRoot 'New-DemoEvidence.ps1'

# ---------------------------------------------------------------- base evidence
& $demo -OutputDirectory (Join-Path $root 'base') | Out-Null
$baseFolder = Join-Path $root 'base\folder'
$baseZip = Join-Path $root 'base\liveresponse.zip'
$hostileThreat = '=HYPERLINK("http://contoso.example") <img src=x onerror=window.__dqePwned=1></script><script>window.__dqePwned=1</script>'
& $demo -OutputDirectory (Join-Path $root 'names') -FirstThreatName $hostileThreat | Out-Null

# ---------------------------------------------------------------- raw zip writer with full control of every field
function New-Deflated([byte[]]$data) {
    $ms = New-Object IO.MemoryStream
    $ds = New-Object IO.Compression.DeflateStream($ms, [IO.Compression.CompressionLevel]::Optimal, $true)
    $ds.Write($data, 0, $data.Length); $ds.Dispose(); , $ms.ToArray()
}
function New-DeflatedZeros([int64]$count) {
    # Streams zeros through the compressor so a bomb of hundreds of megabytes costs a few hundred kilobytes.
    $ms = New-Object IO.MemoryStream
    $ds = New-Object IO.Compression.DeflateStream($ms, [IO.Compression.CompressionLevel]::Optimal, $true)
    $chunk = New-Object byte[] 4194304; $left = $count
    while ($left -gt 0) { $n = [int][Math]::Min($chunk.Length, $left); $ds.Write($chunk, 0, $n); $left -= $n }
    $ds.Dispose(); , $ms.ToArray()
}
function Write-RawZip([string]$path, $entries) {
    # Each entry: @{ Name; Method (0/8); Data (stored bytes); CSize; USize } with CSize/USize free to lie.
    $fs = [IO.File]::Create($path); $bw = New-Object IO.BinaryWriter($fs); $cd = New-Object System.Collections.ArrayList
    foreach ($e in $entries) {
        $nb = [Text.Encoding]::UTF8.GetBytes($e.Name); $off = $fs.Position
        $cs = if ($null -ne $e.CSize) { $e.CSize } else { $e.Data.Length }; $us = $e.USize
        $bw.Write([uint32]0x04034b50); $bw.Write([uint16]20); $bw.Write([uint16]0x0800); $bw.Write([uint16]$e.Method)
        $bw.Write([uint16]0); $bw.Write([uint16]0x5B21); $bw.Write([uint32]0); $bw.Write([uint32]$cs); $bw.Write([uint32]$us)
        $bw.Write([uint16]$nb.Length); $bw.Write([uint16]0); $bw.Write($nb); $bw.Write($e.Data)
        [void]$cd.Add(@{ Nb = $nb; Method = $e.Method; CS = $cs; US = $us; Off = $off })
    }
    $cdOff = $fs.Position
    foreach ($c in $cd) {
        $bw.Write([uint32]0x02014b50); $bw.Write([uint16]20); $bw.Write([uint16]20); $bw.Write([uint16]0x0800); $bw.Write([uint16]$c.Method)
        $bw.Write([uint16]0); $bw.Write([uint16]0x5B21); $bw.Write([uint32]0); $bw.Write([uint32]$c.CS); $bw.Write([uint32]$c.US)
        $bw.Write([uint16]$c.Nb.Length); $bw.Write([uint16]0); $bw.Write([uint16]0); $bw.Write([uint16]0); $bw.Write([uint16]0)
        $bw.Write([uint32]0); $bw.Write([uint32]$c.Off); $bw.Write($c.Nb)
    }
    $cdLen = $fs.Position - $cdOff
    $bw.Write([uint32]0x06054b50); $bw.Write([uint16]0); $bw.Write([uint16]0); $bw.Write([uint16]$cd.Count); $bw.Write([uint16]$cd.Count)
    $bw.Write([uint32]$cdLen); $bw.Write([uint32]$cdOff); $bw.Write([uint16]0); $bw.Dispose(); $fs.Dispose()
}
function Get-BaseEntries {
    # The base collection's files, re-stored so they can be mixed with hostile entries in one archive.
    $z = [IO.Compression.ZipFile]::OpenRead($baseZip); $list = New-Object System.Collections.ArrayList
    try {
        foreach ($e in $z.Entries) {
            $s = $e.Open(); $m = New-Object IO.MemoryStream; $s.CopyTo($m); $s.Dispose(); $b = $m.ToArray()
            [void]$list.Add(@{ Name = $e.FullName; Method = 8; Data = (New-Deflated $b); USize = $b.Length })
        }
    } finally { $z.Dispose() }
    , $list
}
$D = 'C/ProgramData/Microsoft/Windows Defender'
function New-Text([string]$t) { $b = [Text.Encoding]::ASCII.GetBytes($t); @{ Method = 8; Data = (New-Deflated $b); USize = $b.Length } }

# ---------------------------------------------------------------- 1. path traversal in entry names
$tr = Get-BaseEntries
foreach ($n in @('../../../dqe-escape-1.txt', '..\..\..\dqe-escape-2.txt', 'C:/Windows/Temp/dqe-escape-3.txt', '/dqe-escape-4.txt',
                 "$D/Quarantine/../../../../../../dqe-escape-5.txt", "$D/Support/..\..\..\..\..\dqe-escape-6.log", '\\server\share\dqe-escape-7.txt')) {
    $e = New-Text 'escape attempt'; $e.Name = $n; [void]$tr.Add($e)
}
Write-RawZip (Join-Path $root 'traversal.zip') $tr

# ---------------------------------------------------------------- 1b. hostile text in names that end up in warnings
$nz = Get-BaseEntries
[void]$nz.Add(@{ Name = "$D/Support/x</script><script>window.__dqePwned=1</script><img src=x onerror=window.__dqePwned=1>/MPLog-20261030-000009.log"; Method = 12; Data = [byte[]](1, 2, 3, 4); USize = 4 })
Write-RawZip (Join-Path $root 'names-in-warnings.zip') $nz

# ---------------------------------------------------------------- 2. bombs and lying sizes
$bombs = Join-Path $root 'bombs'; [void][IO.Directory]::CreateDirectory($bombs)
$zeros300 = New-DeflatedZeros 300MB
# a "log" that inflates to 300 MB: over the log limit, must be skipped by its declared size without inflating
Write-RawZip (Join-Path $bombs 'ratio-log.zip') @(@{ Name = "$D/Support/MPLog-20261030-000000.log"; Method = 8; Data = $zeros300; USize = 300MB })
# the same stream declared as 1 MB: inflation must stop at the declared size
Write-RawZip (Join-Path $bombs 'understated.zip') @(@{ Name = "$D/Support/MPLog-20261030-000001.log"; Method = 8; Data = $zeros300; USize = 1MB })
# a tiny entry declaring 900 MB: no 900 MB allocation may happen
$tiny = New-Deflated ([Text.Encoding]::ASCII.GetBytes(('x' * 4096)))
Write-RawZip (Join-Path $bombs 'overstated.zip') @(@{ Name = "$D/Quarantine/ResourceData/AB/AB00000000000000000000000000000000000000"; Method = 8; Data = $tiny; USize = 900MB })
# a stored entry whose compressed size points far past the end of the file
Write-RawZip (Join-Path $bombs 'csize-past-end.zip') @(@{ Name = "$D/Quarantine/ResourceData/CD/CD00000000000000000000000000000000000000"; Method = 0; Data = $tiny; CSize = 1500MB; USize = 1500MB })
# an "entry" metadata file that inflates to 300 MB: over the metadata limit
Write-RawZip (Join-Path $bombs 'ratio-entry.zip') @(@{ Name = "$D/Quarantine/Entries/{11111111-2222-3333-4444-555555555555}"; Method = 8; Data = $zeros300; USize = 300MB })
# nesting eight archives deep, with a real collection at the bottom
$inner = [IO.File]::ReadAllBytes($baseZip)
for ($i = 1; $i -le 8; $i++) { $p = Join-Path $bombs ("nested-$i.zip"); Write-RawZip $p @(@{ Name = "level$i.zip"; Method = 0; Data = $inner; USize = $inner.Length }); $inner = [IO.File]::ReadAllBytes($p) }
# gzip of 1.2 GB of zeros: over the 1 GB item limit, must stop while decompressing
$gz = [IO.File]::Create((Join-Path $bombs 'bomb.zip.gz'))
$g = New-Object IO.Compression.GZipStream($gz, [IO.Compression.CompressionLevel]::Optimal)
$chunk = New-Object byte[] 8388608; for ($i = 0; $i -lt 150; $i++) { $g.Write($chunk, 0, $chunk.Length) }
$g.Dispose(); $gz.Dispose()

# a log full of block openers and no closers: quadratic for a backtracking block regex
$redos = Join-Path $root 'redos\C\ProgramData\Microsoft\Windows Defender\Support'; [void][IO.Directory]::CreateDirectory($redos)
$sb = New-Object Text.StringBuilder; for ($i = 0; $i -lt 200000; $i++) { [void]$sb.Append("Beginning threat actions`r`nBegin Resource Scan`r`nfile:") }
[IO.File]::WriteAllText((Join-Path $redos 'MPLog-20261030-000000.log'), $sb.ToString(), [Text.Encoding]::Unicode)

# ---------------------------------------------------------------- 3. fuzzing: corrupted artifacts and archives
$rng = New-Object Random 20261112
$artifacts = @(Get-ChildItem -LiteralPath $baseFolder -Recurse -File)
for ($r = 1; $r -le $rounds; $r++) {
    $dir = Join-Path $root ('fuzz\{0:D2}' -f $r)
    foreach ($f in $artifacts) {
        $b = [IO.File]::ReadAllBytes($f.FullName)
        switch ($rng.Next(4)) {
            0 { for ($k = 0; $k -lt 1 + $rng.Next(8); $k++) { $b[$rng.Next($b.Length)] = [byte]$rng.Next(256) } }
            1 { $b = $b[0..([Math]::Max(0, $rng.Next($b.Length) - 1))] }
            2 { $pos = ($rng.Next([Math]::Max(1, $b.Length - 4)) -band -4); $v = @(4294967280, 2147483647, 2147483648, 0)[$rng.Next(4)]; [Buffer]::BlockCopy([BitConverter]::GetBytes([uint32]$v), 0, $b, [Math]::Min($pos, $b.Length - 4), 4) }
            3 { for ($k = 0; $k -lt 64; $k++) { $b[$rng.Next($b.Length)] = [byte]$rng.Next(256) } }
        }
        $t = Join-Path $dir ($f.FullName.Substring($baseFolder.Length).TrimStart('\'))
        [void][IO.Directory]::CreateDirectory((Split-Path $t)); [IO.File]::WriteAllBytes($t, [byte[]]$b)
    }
    $zb = [IO.File]::ReadAllBytes($baseZip)
    $zdir = Join-Path $root 'fuzz-zip'; [void][IO.Directory]::CreateDirectory($zdir)
    for ($k = 0; $k -lt 1 + $rng.Next(16); $k++) { $zb[$rng.Next($zb.Length)] = [byte]$rng.Next(256) }
    if ($rng.Next(3) -eq 0) { $tail = $zb.Length - 22 - $rng.Next(64); if ($tail -gt 0) { $zb[$tail] = [byte]$rng.Next(256) } }
    [IO.File]::WriteAllBytes((Join-Path $zdir ('{0:D2}.zip' -f $r)), $zb)
}

[pscustomobject]@{ Root = $root; HostileThreat = $hostileThreat; FuzzRounds = $rounds }
