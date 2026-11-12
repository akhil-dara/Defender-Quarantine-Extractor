<#
.SYNOPSIS
    Creates synthetic Microsoft Defender evidence for tests, screenshots and demos.

.DESCRIPTION
    Builds a fictional host's Defender folder (WKS-CONTOSO-07, user CONTOSO\jdoe) byte-for-byte in Defender's own
    formats: RC4-sealed quarantine entries and payloads, DetectionHistory, scan results, AMSI captures and
    MPLog / MPDetection logs. Every payload is harmless: a PE file with headers but no code, a few lines of benign
    PowerShell, a scheduled-task XML and an empty registry hive. Nothing here is malware, so the files can be
    committed, shared and opened freely.

    The same evidence is written in several collection layouts, to exercise every input path:

        liveresponse.zip        C/ProgramData/Microsoft/Windows Defender/... as a collection tool produces it
        liveresponse.zip.gz     the same zip, gzip-wrapped as a Live Response download
        nested.zip              a zip holding the collection zip and a notes file
        protected-aes.zip       AES-256, password "infected"
        protected-zipcrypto.zip ZipCrypto, password "contoso-demo" (not in the automatic list)
        folder\                 the collection extracted
        quarantine-only\        just the Quarantine folder, as if copied on its own
        flat\                   every artifact in one folder, no directory structure

.PARAMETER OutputDirectory
    Where to write the layouts. Created if missing.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $OutputDirectory,
    # Threat name of the first detection. The security tests set it to hostile text (HTML, formula prefixes).
    [string] $FirstThreatName = 'Trojan:Win32/ContosoLoader.A'
)

$ErrorActionPreference = 'Stop'
$demoRoot = [IO.Path]::GetFullPath($OutputDirectory)   # captured first: the dot-sourced tool declares a parameter of the same name
$firstThreat = $FirstThreatName
$env:DQE_IMPORT_ONLY = '1'
try { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'Defender-Quarantine-Extractor.ps1') } finally { Remove-Item Env:\DQE_IMPORT_ONLY }
. $DqeEngine
$script:Quiet = $true
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem

# ---------------------------------------------------------------- byte builders
function New-Buf { New-Object System.Collections.Generic.List[byte] }
function Add-U16($l, [int]$v) { $l.AddRange([BitConverter]::GetBytes([uint16]$v)) }
function Add-U32($l, [int64]$v) { $l.AddRange([BitConverter]::GetBytes([uint32]$v)) }
function Add-U64($l, [int64]$v) { $l.AddRange([BitConverter]::GetBytes([uint64]$v)) }
function Add-Bytes($l, [byte[]]$b) { $l.AddRange($b) }
function Add-WStrZ($l, [string]$s) { $l.AddRange([Text.Encoding]::Unicode.GetBytes($s + [char]0)) }
function Add-Pad($l, [int]$align) { while (($l.Count % $align) -ne 0) { $l.Add(0) } }
function Get-Ft([string]$utc) { [DateTime]::SpecifyKind([DateTime]::Parse($utc, [Globalization.CultureInfo]::InvariantCulture), 'Utc').ToFileTimeUtc() }
function Get-Sha1Hex([byte[]]$b) { $h = New-Object Security.Cryptography.SHA1CryptoServiceProvider; (Dqe-Hex $h.ComputeHash($b)).ToUpper() }
function ConvertTo-Bytes($l) { , $l.ToArray() }

function New-Sealed([byte[]]$s1, [byte[]]$s2, [uint32]$version) {
    # 60-byte header + two sections, each RC4-encrypted on its own, exactly as Defender writes them.
    $h = New-Object byte[] 60
    $h[0] = 0xDB; $h[1] = 0xE8; $h[2] = 0xC5; $h[3] = 0x01
    [Buffer]::BlockCopy([BitConverter]::GetBytes($version), 0, $h, 4, 4)
    [Buffer]::BlockCopy([BitConverter]::GetBytes([uint32]$s1.Length), 0, $h, 0x28, 4)
    [Buffer]::BlockCopy([BitConverter]::GetBytes([uint32]$s2.Length), 0, $h, 0x2C, 4)
    if ($s1.Length -eq 0) { for ($i = 0x30; $i -lt 0x34; $i++) { $h[$i] = 0xFF } }
    $h[0x38] = 0xDB; $h[0x39] = 0xE8; $h[0x3A] = 0xC5; $h[0x3B] = 0x02
    $out = New-Buf
    Add-Bytes $out (Dqe-Rc4 $h 0 60)
    if ($s1.Length) { Add-Bytes $out (Dqe-Rc4 $s1 0 $s1.Length) }
    if ($s2.Length) { Add-Bytes $out (Dqe-Rc4 $s2 0 $s2.Length) }
    ConvertTo-Bytes $out
}

function New-Bag([object[]]$pairs) {
    # Property bag: [u32 key bytes][UTF-16 key][u32 type][value]
    $l = New-Buf
    for ($i = 0; $i -lt $pairs.Count; $i += 3) {
        $k = [Text.Encoding]::Unicode.GetBytes($pairs[$i] + [char]0); Add-U32 $l $k.Length; Add-Bytes $l $k
        $t = $pairs[$i + 1]; $v = $pairs[$i + 2]; Add-U32 $l $t
        switch ($t) {
            3 { Add-U32 $l $v }
            4 { Add-U64 $l $v }
            5 { $l.Add([byte]$(if ($v) { 1 } else { 0 })) }
            6 { $s = [Text.Encoding]::Unicode.GetBytes($v + [char]0); Add-U32 $l $s.Length; Add-Bytes $l $s }
            8 { $b = [byte[]]$v; Add-U32 $l $b.Length; Add-Bytes $l $b }
        }
    }
    ConvertTo-Bytes $l
}

# ---------------------------------------------------------------- harmless payloads
function New-DemoPe {
    # Valid DOS/PE32+ headers for a GUI program, one empty section, no code. It cannot run and does nothing.
    $b = New-Object byte[] 3072
    $b[0] = 0x4D; $b[1] = 0x5A; [Buffer]::BlockCopy([BitConverter]::GetBytes([uint32]0x80), 0, $b, 0x3C, 4)
    $stub = [Text.Encoding]::ASCII.GetBytes('This program cannot be run in DOS mode.'); [Buffer]::BlockCopy($stub, 0, $b, 0x4E, $stub.Length)
    $o = 0x80; $b[$o] = 0x50; $b[$o + 1] = 0x45
    [Buffer]::BlockCopy([BitConverter]::GetBytes([uint16]0x8664), 0, $b, $o + 4, 2)
    [Buffer]::BlockCopy([BitConverter]::GetBytes([uint16]1), 0, $b, $o + 6, 2)
    [Buffer]::BlockCopy([BitConverter]::GetBytes([uint32]1793433600), 0, $b, $o + 8, 4)
    [Buffer]::BlockCopy([BitConverter]::GetBytes([uint16]0xF0), 0, $b, $o + 20, 2)
    [Buffer]::BlockCopy([BitConverter]::GetBytes([uint16]0x22), 0, $b, $o + 22, 2)
    [Buffer]::BlockCopy([BitConverter]::GetBytes([uint16]0x20B), 0, $b, $o + 24, 2)
    [Buffer]::BlockCopy([BitConverter]::GetBytes([uint16]2), 0, $b, $o + 24 + 68, 2)
    $sec = [Text.Encoding]::ASCII.GetBytes('.rdata'); [Buffer]::BlockCopy($sec, 0, $b, $o + 24 + 0xF0, $sec.Length)
    $note = [Text.Encoding]::ASCII.GetBytes('Contoso Sync Agent 4.2 - synthetic sample created by Defender Quarantine Extractor tests. Harmless; contains no code.')
    [Buffer]::BlockCopy($note, 0, $b, 0x400, $note.Length)
    , $b
}
$script:ScriptText = @(
    '# Contoso Sync helper (synthetic sample for Defender Quarantine Extractor tests; harmless)'
    '$log = Join-Path $env:TEMP ''contoso-sync.log'''
    'Get-Service | Where-Object Status -eq ''Running'' | Select-Object -First 5 Name | Out-File $log'
    'Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version | Out-File $log -Append'
    'Write-Output ''sync complete'''
) -join "`r`n"
function New-DemoTaskXml {
    $x = '<?xml version="1.0" encoding="UTF-16"?>' + "`r`n" + '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><RegistrationInfo><Author>CONTOSO\jdoe</Author><URI>\ContosoSyncUpdate</URI></RegistrationInfo><Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers><Actions Context="Author"><Exec><Command>C:\Users\jdoe\AppData\Roaming\ContosoSync\ContosoSync.exe</Command><Arguments>--background</Arguments></Exec></Actions></Task>'
    , ([byte[]](0xFF, 0xFE) + [Text.Encoding]::Unicode.GetBytes($x))
}
function New-DemoHive { $b = New-Object byte[] 4096; $b[0] = 0x72; $b[1] = 0x65; $b[2] = 0x67; $b[3] = 0x66; , $b }

function New-StreamBlob([byte[]]$data, [string]$zone) {
    # BackupRead layout: security descriptor, data, optional Zone.Identifier alternate data stream.
    $l = New-Buf
    $sd = [byte[]](0x01, 0x00, 0x04, 0x84, 0x14, 0, 0, 0, 0x30, 0, 0, 0, 0, 0, 0, 0, 0x4C, 0, 0, 0, 0x01, 0x05, 0, 0, 0, 0, 0, 5, 0x15, 0, 0, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xE9, 0x03, 0, 0, 0x01, 0x01, 0, 0, 0, 0, 0, 5, 0x12, 0, 0, 0, 0x02, 0, 0x1C, 0, 0x01, 0, 0, 0, 0, 0, 0x14, 0, 0xFF, 0x01, 0x1F, 0, 0x01, 0x01, 0, 0, 0, 0, 0, 5, 0x12, 0, 0, 0)
    Add-U32 $l 3; Add-U32 $l 2; Add-U64 $l $sd.Length; Add-U32 $l 0; Add-Bytes $l $sd
    Add-U32 $l 1; Add-U32 $l 0; Add-U64 $l $data.Length; Add-U32 $l 0; Add-Bytes $l $data
    if ($zone) {
        $n = [Text.Encoding]::Unicode.GetBytes(':Zone.Identifier:$DATA'); $z = [Text.Encoding]::ASCII.GetBytes($zone)
        Add-U32 $l 4; Add-U32 $l 0; Add-U64 $l $z.Length; Add-U32 $l $n.Length; Add-Bytes $l $n; Add-Bytes $l $z
    }
    ConvertTo-Bytes $l
}

# ---------------------------------------------------------------- the story
$files = [ordered]@{}
function Add-File([string]$rel, [byte[]]$b) { $files[$rel] = $b }
$D = 'C/ProgramData/Microsoft/Windows Defender'

$pe = New-DemoPe; $ps1 = [Text.Encoding]::UTF8.GetBytes($script:ScriptText); $task = New-DemoTaskXml; $hive = New-DemoHive
$zone = "[ZoneTransfer]`r`nZoneId=3`r`nReferrerUrl=https://mail.contoso.example/`r`nHostUrl=https://files.contoso.example/share/Contoso_Invoice_0412.zip`r`n"
$payloads = @(
    @{ Name = 'pe';   Data = $pe;   Blob = (New-StreamBlob $pe $zone) }
    @{ Name = 'task'; Data = $task; Blob = (New-StreamBlob $task '') }
    @{ Name = 'ps1';  Data = $ps1;  Blob = (New-StreamBlob $ps1 '') }
    @{ Name = 'hive'; Data = $hive; Blob = $hive }
)
foreach ($p in $payloads) {
    $p.Id = Get-Sha1Hex $p.Blob; $p.H = Dqe-Hash $p.Data 0 $p.Data.Length
    Add-File "$D/Quarantine/ResourceData/$($p.Id.Substring(0,2))/$($p.Id)" (Dqe-Rc4 $p.Blob 0 $p.Blob.Length)
}
$Pay = @{}; foreach ($p in $payloads) { $Pay[$p.Name] = $p }

$exePath  = 'C:\Users\jdoe\AppData\Roaming\ContosoSync\ContosoSync.exe'
$taskPath = 'C:\Windows\System32\Tasks\ContosoSyncUpdate'
$runKey   = 'HKCU@S-1-5-21-1004336348-1177238915-682003330-1104\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\\ContosoSync'
$ps1Path  = 'C:\Users\jdoe\AppData\Roaming\ContosoSync\sync.ps1'
$threatA = $firstThreat; $threatB = 'Trojan:PowerShell/ContosoStager.B'
$tidA = 2147800421; $tidB = 2147800422
$entryA = [guid]'7B2D1C4E-5A60-4F1B-9C3D-21A0B4C5D6E7'; $entryB = [guid]'0E9F8A7B-6C5D-4E3F-8A1B-2C3D4E5F6A7B'
$scanA = [guid]'3C4D5E6F-7A8B-4C9D-8E0F-1A2B3C4D5E6F'; $scanB = [guid]'4D5E6F70-8192-4A3B-9C4D-5E6F708192A3'
$tA = '2026-10-30 09:42:17.412'; $tB = '2026-10-30 09:47:03.875'

function New-Field([int]$id, [int]$type, [byte[]]$data) { @{ Id = $id; Type = $type; Data = $data } }
function New-Resource([string]$path, [string]$type, $fields) { @{ Path = $path; Type = $type; Fields = $fields } }
function New-FileFields($p, [string]$physical, [string]$created, [string]$modified) {
    @(
        (New-Field 0x02 4 (Dqe-UnHex $p.Id))
        (New-Field 0x12 6 ([BitConverter]::GetBytes([uint64]$p.Data.Length)))
        (New-Field 0x11 6 ([BitConverter]::GetBytes([uint64](Get-Ft $modified))))
        (New-Field 0x10 6 ([BitConverter]::GetBytes([uint64](Get-Ft $modified))))
        (New-Field 0x0F 6 ([BitConverter]::GetBytes([uint64](Get-Ft $created))))
        (New-Field 0x0A 3 ([BitConverter]::GetBytes([uint32]0x20)))
        (New-Field 0x0C 2 ([Text.Encoding]::Unicode.GetBytes($physical + [char]0)))
        (New-Field 0x0D 5 ([BitConverter]::GetBytes([uint64]0x0000A1B2C3D4E5F6)))
    )
}
function New-Entry([guid]$id, [guid]$scan, [string]$time, [int64]$threatId, [string]$threat, $resources) {
    $s1 = New-Buf; Add-Bytes $s1 $id.ToByteArray(); Add-Bytes $s1 $scan.ToByteArray(); Add-U64 $s1 (Get-Ft $time); Add-U64 $s1 $threatId; Add-U32 $s1 1
    Add-Bytes $s1 ([Text.Encoding]::UTF8.GetBytes($threat + [char]0))
    $body = New-Buf; $offs = @(); $base = 4 + 4 * $resources.Count
    foreach ($r in $resources) {
        Add-Pad $body 4; $offs += ($base + $body.Count)
        Add-WStrZ $body $r.Path; Add-U16 $body $r.Fields.Count; Add-Bytes $body ([Text.Encoding]::ASCII.GetBytes($r.Type + [char]0))
        foreach ($f in $r.Fields) {
            while ((($base + $body.Count) % 4) -ne 0) { $body.Add(0) }
            Add-U16 $body $f.Data.Length; Add-U16 $body ($f.Id -bor ($f.Type -shl 12)); Add-Bytes $body $f.Data
        }
    }
    $s2 = New-Buf; Add-U32 $s2 $resources.Count; foreach ($o in $offs) { Add-U32 $s2 $o }; Add-Bytes $s2 (ConvertTo-Bytes $body)
    New-Sealed (ConvertTo-Bytes $s1) (ConvertTo-Bytes $s2) 0x00010001
}
$resA = @(
    (New-Resource ('\\?\' + $exePath) 'file' (New-FileFields $Pay.pe $exePath '2026-10-30 09:39:51.208' '2026-10-30 09:39:52.664'))
    (New-Resource ('\\?\' + $taskPath) 'file' (New-FileFields $Pay.task $taskPath '2026-10-30 09:40:05.031' '2026-10-30 09:40:05.031'))
    (New-Resource $runKey 'regkey' @((New-Field 0x0A 4 (Dqe-UnHex $Pay.hive.Id))))
    (New-Resource $taskPath 'taskscheduler' @((New-Field 0x0E 3 ([BitConverter]::GetBytes([uint32]0x80)))))
)
$resB = @((New-Resource ('\\?\' + $ps1Path) 'file' (New-FileFields $Pay.ps1 $ps1Path '2026-10-30 09:40:12.774' '2026-10-30 09:40:12.774')))
Add-File "$D/Quarantine/Entries/{$($entryA.ToString().ToUpper())}" (New-Entry $entryA $scanA $tA $tidA $threatA $resA)
Add-File "$D/Quarantine/Entries/{$($entryB.ToString().ToUpper())}" (New-Entry $entryB $scanB $tB $tidB $threatB $resB)

foreach ($pair in @(@($Pay.pe, $entryA), @($Pay.task, $entryA), @($Pay.hive, $entryA), @($Pay.ps1, $entryB))) {
    $p = $pair[0]; $s1 = New-Buf; Add-U64 $s1 $p.Blob.Length; Add-Bytes $s1 (Dqe-UnHex $p.Id); Add-U32 $s1 1
    Add-File "$D/Quarantine/Resources/$($p.Id.Substring(0,2))/$($p.Id)" (New-Sealed (ConvertTo-Bytes $s1) ($pair[1].ToByteArray()) 0x00010001)
}

# ---------------------------------------------------------------- DetectionHistory (plain TLV, 8-byte aligned)
function Add-Rec($l, [int]$type, [byte[]]$data) { Add-U32 $l $data.Length; Add-U32 $l $type; Add-Bytes $l $data; Add-Pad $l 8 }
function New-DetectionHistory([int64]$threatId, [guid]$detId, [string]$threat, $res, $p, [guid]$entry, [string]$time, [string]$process) {
    $l = New-Buf
    Add-Rec $l 8 ([BitConverter]::GetBytes([uint64]$threatId)); Add-Rec $l 0x1E $detId.ToByteArray()
    Add-Rec $l 0x15 ([Text.Encoding]::Unicode.GetBytes('Magic.Version:1.2' + [char]0)); Add-Rec $l 0x15 ([Text.Encoding]::Unicode.GetBytes($threat + [char]0))
    foreach ($v in 0, 5, 8, 0x70, 4, 3, 3, 2, 3, 6, 7) { Add-Rec $l 6 ([BitConverter]::GetBytes([uint32]$v)) }
    $bag = New-Bag @(
        'ThreatTrackingSha256', 6, $p.H.sha256; 'ThreatTrackingSigSeq', 4, 0x0000A1B2C3D4E5F6; 'ThreatTrackingId', 6, '6B1F0C2D-3E4F-4A5B-8C6D-7E8F9A0B1C2D'
        'ThreatTrackingStartTime', 4, (Get-Ft $time); 'ThreatTrackingThreatName', 6, $threat; 'ThreatTrackingSha1', 6, $p.H.sha1
        'ThreatTrackingSize', 4, $p.Data.Length; 'ThreatTrackingMD5', 6, $p.H.md5; 'ThreatTrackingScanFlags', 3, 19
        'ThreatTrackingThreatId', 3, ($threatId -band 0x7FFFFFFF); 'ThreatTrackingScanSource', 3, 3; 'ThreatTrackingScanType', 3, 1)
    foreach ($r in $res) {
        Add-Rec $l 0x15 ([Text.Encoding]::Unicode.GetBytes('Magic.Version:1.2' + [char]0))
        Add-Rec $l 0x15 ([Text.Encoding]::Unicode.GetBytes($r[0] + [char]0)); Add-Rec $l 0x15 ([Text.Encoding]::Unicode.GetBytes($r[1] + [char]0))
        Add-Rec $l 6 ([BitConverter]::GetBytes([uint32]0x10000002)); Add-Rec $l 6 ([BitConverter]::GetBytes([uint32]0x50F))
        $blob = New-Buf; Add-U32 $blob 1; Add-U32 $blob 0x14; Add-U32 $blob $bag.Length; Add-U32 $blob ($bag.Length + 20); Add-U32 $blob 0; Add-U32 $blob $bag.Length
        Add-Bytes $blob $bag; Add-Rec $l 0x28 (ConvertTo-Bytes $blob)
    }
    Add-Rec $l 0x0A ([BitConverter]::GetBytes([uint64](Get-Ft $time))); Add-Rec $l 5 ([BitConverter]::GetBytes([uint32]0)); Add-Rec $l 6 ([BitConverter]::GetBytes([uint32]0))
    Add-Rec $l 0x1E $entry.ToByteArray(); Add-Rec $l 6 ([BitConverter]::GetBytes([uint32]1)); Add-Rec $l 6 ([BitConverter]::GetBytes([uint32]2))
    Add-Rec $l 0x15 ([Text.Encoding]::Unicode.GetBytes('CONTOSO\jdoe' + [char]0)); Add-Rec $l 6 ([BitConverter]::GetBytes([uint32]3))
    Add-Rec $l 0x15 ([Text.Encoding]::Unicode.GetBytes($process + [char]0)); Add-Rec $l 6 ([BitConverter]::GetBytes([uint32]1))
    Add-Rec $l 0x0A ([BitConverter]::GetBytes([uint64]((Get-Ft $time) + 20000000)))
    ConvertTo-Bytes $l
}
$dhA = [guid]'A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D'; $dhB = [guid]'B2C3D4E5-F6A7-4B8C-9D0E-1F2A3B4C5D6E'
Add-File "$D/Scans/History/Service/DetectionHistory/02/$($dhA.ToString().ToUpper())" (New-DetectionHistory $tidA $dhA $threatA @(@('file', $exePath), @('file', $taskPath), @('regkey', ($runKey -replace '\\\\', '\')), @('taskscheduler', $taskPath)) $Pay.pe $entryA $tA 'C:\Windows\explorer.exe')
Add-File "$D/Scans/History/Service/DetectionHistory/02/$($dhB.ToString().ToUpper())" (New-DetectionHistory $tidB $dhB $threatB @(, @('file', $ps1Path)) $Pay.ps1 $entryB $tB 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe')

# ---------------------------------------------------------------- scan results
function New-ScanResult([guid]$scan, [string]$start, [string]$end, [string]$threat, $res) {
    $s1 = New-Buf; Add-Bytes $s1 $scan.ToByteArray(); Add-U64 $s1 (Get-Ft $start); Add-U32 $s1 0x00070004; Add-U32 $s1 0; Add-U32 $s1 0x2D1A; Add-U32 $s1 1; Add-U32 $s1 0x128; Add-U32 $s1 0x1C
    $s2 = New-Buf; Add-U64 $s2 (Get-Ft $start); Add-U64 $s2 (Get-Ft $end); Add-Bytes $s2 (New-Object byte[] 64)
    if ($threat) {
        Add-WStrZ $s2 $threat; Add-U32 $s2 0x00040208; Add-U32 $s2 5
        foreach ($r in $res) { Add-U64 $s2 ($r[0].Length + 1); Add-WStrZ $s2 $r[0]; Add-U64 $s2 ($r[1].Length + 1); Add-WStrZ $s2 $r[1]; Add-U32 $s2 0x00010002; Add-U32 $s2 0x125 }
    }
    Add-Bytes $s2 (New-Object byte[] 32)
    New-Sealed (ConvertTo-Bytes $s1) (ConvertTo-Bytes $s2) 0x586
}
Add-File "$D/Scans/History/Results/Resource/{$($scanA.ToString().ToUpper())}" (New-ScanResult $scanA '2026-10-30 09:42:15.902' '2026-10-30 09:42:17.410' $threatA @(@('file', $exePath), @('file', $taskPath), @('regkey', ($runKey -replace '\\\\', '\')), @('taskscheduler', $taskPath)))
Add-File "$D/Scans/History/Results/Resource/{$($scanB.ToString().ToUpper())}" (New-ScanResult $scanB '2026-10-30 09:47:02.611' '2026-10-30 09:47:03.870' $threatB @(, @('file', $ps1Path)))
$quick = @(@('5E6F7081-92A3-4B4C-8D5E-6F708192A3B4', '2026-10-29 03:11:40.000', '2026-10-29 03:14:02.000'), @('6F708192-A3B4-4C5D-9E6F-708192A3B4C5', '2026-10-30 03:12:05.000', '2026-10-30 03:15:48.000'))
foreach ($q in $quick) { Add-File "$D/Scans/History/Results/Quick/{$($q[0])}" (New-ScanResult ([guid]$q[0]) $q[1] $q[2] '' @()) }

# ---------------------------------------------------------------- scan history store: AMSI capture and scan context
$amsi = New-Bag @(
    'AMSISession', 4, 17421; 'Scenario', 3, 3; 'AMSIApp', 6, 'PowerShell_C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe_10.0.26100.1'
    'Content', 8, ([Text.Encoding]::Unicode.GetBytes($script:ScriptText)); 'AMSIContentName', 6, $ps1Path
    'AMSIOpProcName', 6, '\Device\HarddiskVolume3\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; 'AMSIPid', 3, 7316
    'AMSIPidCreationTime', 4, (Get-Ft '2026-10-30 09:46:58.120'); 'InternalAttributesCount', 4, 0)
$ctxBag = New-Bag @(
    'CONTEXT_DATA_FILEPATH', 6, ('\Device\HarddiskVolume3' + $exePath.Substring(2)); 'CONTEXT_DATA_FILENAME', 6, 'ContosoSync.exe'
    'CONTEXT_DATA_PROCESSNAME', 6, 'explorer.exe'; 'CONTEXT_DATA_PROCESS_ID', 3, 5124; 'CONTEXT_DATA_PROCESS_PPID', 6, 'pid:1088,ProcessStart:134380000000000000'
    'CONTEXT_DATA_HAS_MOTW_ADS', 5, $true; 'CONTEXT_DATA_SCANREASON', 3, 2; 'CONTEXT_DATA_FILE_AGE', 4, 145)
foreach ($pair in @(@('8C1D7E2A4B6F49E0A3C5D7F9B1E3A5C7', $amsi), @('2F4A6C8E0B1D43F5A7C9E1B3D5F7A9C1', $ctxBag))) {
    $bag = $pair[1]; $s2 = New-Buf; Add-U32 $s2 ($bag.Length + 4); Add-Bytes $s2 $bag
    Add-File "$D/Scans/History/Store/$($pair[0])" (New-Sealed (New-Object byte[] 0) (ConvertTo-Bytes $s2) 0x10)
}

# ---------------------------------------------------------------- logs
function New-Utf16Log([string[]]$lines) { , ([byte[]](0xFF, 0xFE) + [Text.Encoding]::Unicode.GetBytes(($lines -join "`r`n") + "`r`n")) }
$ver = 'Version: Product 4.18.26090.9 Service 4.18.26090.9 Engine 1.1.26090.9 AS 1.461.212.0 AV 1.461.212.0'
$hA = $Pay.pe.H; $hT = $Pay.task.H; $hB = $Pay.ps1.H
Add-File "$D/Support/MPDetection-20261028-071503.log" (New-Utf16Log @(
    "2026-10-28T07:15:03.118 Service started - Microsoft Defender Antivirus (77BDAF73-B396-481F-9042-AD358843EC24)"
    "2026-10-28T07:15:15.402 $ver"
    "2026-10-30T09:42:17.412 DETECTION $threatA file:$exePath  SHA1:$($hA.sha1) MD5:$($hA.md5) SHA256:$($hA.sha256)"
    "2026-10-30T09:42:17.412 DETECTION $threatA file:$taskPath  SHA1:$($hT.sha1) MD5:$($hT.md5) SHA256:$($hT.sha256)"
    "2026-10-30T09:42:17.412 DETECTION $threatA regkey:$($runKey -replace '\\\\', '\') "
    "2026-10-30T09:42:17.412 DETECTION $threatA taskscheduler:$taskPath  SHA1:$($hT.sha1) MD5:$($hT.md5) SHA256:$($hT.sha256)"
    "2026-10-30T09:47:03.875 DETECTION $threatB file:$ps1Path  SHA1:$($hB.sha1) MD5:$($hB.md5) SHA256:$($hB.sha256)"
))
$dev = '\Device\HarddiskVolume3'
Add-File "$D/Support/MPLog-20261028-071503.log" (New-Utf16Log @(
    "2026-10-28T07:15:15.402 $ver"
    "2026-10-29T03:11:40.002 Engine:Quick scan started"
    "2026-10-30T09:39:52.701 Engine:Setting original file name ""ContosoSync"" for ""$($exePath.ToLower())"", hr=0x0"
    "2026-10-30T09:40:12.790 [RTP] [Exclusion] C:\Tools\Legacy\agent.exe is discarded due to error 0x80070002"
    "2026-10-30T09:42:05.330 Engine:command line reported as lowfi: C:\Windows\System32\schtasks.exe(schtasks /create /tn ContosoSyncUpdate /sc onlogon /tr C:\Users\jdoe\AppData\Roaming\ContosoSync\ContosoSync.exe)"
    "2026-10-30T09:42:15.880 SDN:Issuing SDN query for $dev$($exePath.Substring(2)) ($dev$($exePath.Substring(2))) (sha1=$($hA.sha1), sha2=$($hA.sha256))"
    "2026-10-30T09:42:16.954 SDN:SDN query completed: 00000a3c"
    "2026-10-30T09:42:16.990 [RTP] [Mini-filter] Blocked file(#3): $dev$($exePath.Substring(2)). Process: $dev\Windows\explorer.exe, Status: 0x0, State: 16, ScanRequest #48211, FileId: 0x3000000012a4f, Reason: OnOpen, IoStatusBlockForNewFile: 0x2, DesiredAccess:0x120089, FileAttributes:0x20, ScanAttributes:0x10, AccessStateFlags:0x800, BackingFileInfo: 0x0, 0x0, 0x0:0\0x0:0"
    "2026-10-30T09:42:17.401 DETECTIONEVENT MPSOURCE_REALTIME $threatA file:$exePath SHA1:$($hA.sha1) SHA256:$($hA.sha256);"
    "2026-10-30T09:42:17.412 DETECTION_ADD#1 $threatA file:$exePath PropBag [length: 0, data: (null)]"
    "2026-10-30T09:42:17.415 Using SDA action MP_THREAT_ACTION_QUARANTINE(2), since failed to get action from PDA/UDA for threat (id - 0x8004c165, sev - 5, category - 8). hr = 0x80070002"
    "Beginning threat actions"
    "Start time:10-30-2026 09:42:17"
    "Threat Name:$threatA"
    "Threat ID:$tidA"
    "Action:quarantine"
    "Resource action complete:Quarantine"
    "Schema:file"
    "Path:$exePath"
    "Threat ID:$tidA"
    "Result:0"
    "Resource action complete:Quarantine"
    "Schema:file"
    "Path:$taskPath"
    "Threat ID:$tidA"
    "Result:0"
    "Resource action complete:Quarantine"
    "Schema:regkey"
    "Path:$($runKey -replace '\\\\', '\')"
    "Threat ID:$tidA"
    "Result:0"
    "Finished threat actions"
    "2026-10-30T09:42:18.020 DETECTION_CLEANEVENT MPSOURCE_REALTIME MP_THREAT_ACTION_QUARANTINE 0 $threatA file:$exePath;file:$taskPath;regkey:$($runKey -replace '\\\\', '\');taskscheduler:$taskPath;"
    "BEGIN BM telemetry"
    "GUID:{C0FFEE00-1234-4ABC-9DEF-0123456789AB}"
    "SignatureID:88123456789012"
    "SigSha:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c"
    "ThreatLevel:0"
    "ProcessID:7316"
    "ProcessCreationTime:134380047181200000"
    "SessionID:1"
    "CreationTime:10-30-2026 09:46:58"
    "ImagePath:C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    "Taint Info:Friendly: N; Reason: ; Modules: ; Parents: C:\Windows\explorer.exe:5124:1,"
    "Operations:None"
    "END BM telemetry"
    "2026-10-30T09:47:03.860 DETECTIONEVENT MPSOURCE_AMSI $threatB file:$ps1Path SHA1:$($hB.sha1) SHA256:$($hB.sha256);"
    "Begin Resource Scan"
    "Scan ID:{$($scanB.ToString().ToUpper())}"
    "Scan Source:17"
    "Start Time:10-30-2026 09:47:02"
    "End Time:10-30-2026 09:47:03"
    "Explicit resource to scan"
    "Resource Schema:file"
    "Resource Path:$ps1Path"
    "Result Count:1"
    "Threat Name:$threatB"
    "ID:$tidB"
    "Severity:5"
    "Number of Resources:1"
    "Resource Schema:file"
    "Resource Path:$ps1Path"
    "Extended Info - SigSeq:0000a1b2c3d4e5f7"
    "End Scan"
    "2026-10-30T09:47:04.112 DETECTION_CLEANEVENT MPSOURCE_AMSI MP_THREAT_ACTION_QUARANTINE 0 $threatB file:$ps1Path;"
    "2026-10-30T09:48:30.501 ProcessImageName: ContosoSync.exe, Pid: 0, TotalTime: 12, Count: 3, MaxTime: 9, MaxTimeFile: $dev$($exePath.Substring(2)), EstimatedImpact: 0%"
))
Add-File "$D/Scans/History/Service/History.Log" ([byte[]](0xFF, 0xFE) + [Text.Encoding]::Unicode.GetBytes($scanA.ToString().ToUpper() + "`r`n"))

# ---------------------------------------------------------------- write the layouts
$OutputDirectory = $demoRoot
[void][IO.Directory]::CreateDirectory($OutputDirectory)
function Write-Tree([string]$root, [scriptblock]$map) {
    foreach ($k in $files.Keys) { $rel = & $map $k; if (-not $rel) { continue }; $t = Join-Path $root $rel; [void][IO.Directory]::CreateDirectory((Split-Path $t)); [IO.File]::WriteAllBytes($t, $files[$k]) }
}
function New-PlainZip([string]$path, $entries) {
    if (Test-Path $path) { Remove-Item -LiteralPath $path -Force }
    $z = [IO.Compression.ZipFile]::Open($path, 'Create')
    try { foreach ($k in $entries.Keys) { $e = $z.CreateEntry($k); $s = $e.Open(); $s.Write($entries[$k], 0, $entries[$k].Length); $s.Dispose() } } finally { $z.Dispose() }
}
$lr = Join-Path $OutputDirectory 'liveresponse.zip'; New-PlainZip $lr $files
$gz = "$lr.gz"; $fs = [IO.File]::Create($gz); $g = New-Object IO.Compression.GZipStream($fs, [IO.Compression.CompressionMode]::Compress); $b = [IO.File]::ReadAllBytes($lr); $g.Write($b, 0, $b.Length); $g.Dispose(); $fs.Dispose()
New-PlainZip (Join-Path $OutputDirectory 'nested.zip') ([ordered]@{ 'WKS-CONTOSO-07/collection.zip' = $b; 'WKS-CONTOSO-07/notes.txt' = [Text.Encoding]::ASCII.GetBytes("Collected from WKS-CONTOSO-07 (synthetic).`r`n") })
foreach ($v in @(@('protected-aes.zip', 'aes', 'infected'), @('protected-zipcrypto.zip', 'zipcrypto', 'contoso-demo'))) {
    $p = Join-Path $OutputDirectory $v[0]; $z = Dqe-ZipOpen $p $v[1] $v[2]
    try { foreach ($k in $files.Keys) { [void](Dqe-ZipAdd $z $k $files[$k] ([DateTime]::new(2026, 10, 30, 10, 0, 0))) }; Dqe-ZipClose $z } finally { $z.Bw.Dispose() }
}
foreach ($d in 'folder', 'quarantine-only', 'flat') { $t = Join-Path $OutputDirectory $d; if (Test-Path $t) { Remove-Item -LiteralPath $t -Recurse -Force } }
Write-Tree (Join-Path $OutputDirectory 'folder') { param($k) $k }
Write-Tree (Join-Path $OutputDirectory 'quarantine-only') { param($k) if ($k -match '/Quarantine/(.*)$') { $Matches[1] } }
Write-Tree (Join-Path $OutputDirectory 'flat') { param($k) if ($k -notmatch '/Quarantine/Resources/' -and $k -notmatch 'History\.Log$') { Split-Path $k -Leaf } }

[pscustomobject]@{
    OutputDirectory = $OutputDirectory
    Files = $files.Count
    Expected = [pscustomobject]@{
        Entries = 2; Rows = 5; RecoverableFiles = 3; RegistryHives = 1
        ExeSha256 = $Pay.pe.H.sha256; ScriptSha256 = $Pay.ps1.H.sha256; TaskSha256 = $Pay.task.H.sha256; HiveSha256 = $Pay.hive.H.sha256
    }
}
