# =====================================================================================================================
#  ENGINE
#  Everything that reads evidence and writes output. It is kept in one script block so the window can load it into a
#  background runspace (keeping the interface responsive) while console mode dot-sources it directly.
#  Only .NET Framework types that ship with Windows are used. Add-Type is used for assembly loading only, never to
#  compile code, so the script runs where compiled or downloaded helpers are blocked.
# =====================================================================================================================
$DqeEngine = {
Set-StrictMode -Off
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.Numerics

$script:DqeVersion = '__DQE_VERSION__'
$script:Sync       = $null
$script:Notes      = New-Object System.Collections.ArrayList
$script:Latin1     = [Text.Encoding]::GetEncoding(28591)
$script:RcS = $null; $script:RcI = 0; $script:RcJ = 0
$script:KS  = New-Object byte[] 0; $script:KSLen = 0
$script:CtrBytes = New-Object byte[] 0; $script:CtrBlocks = 0
$script:CrcT = $null

# ---------------------------------------------------------------- plumbing
# Progress and messages go to a synchronized hashtable when the window is driving the engine, and to the console
# (Write-Host / Write-Progress) in console mode. Warnings and errors are also kept for the report's Notes section.

function Dqe-Log([string]$m, [string]$lvl = 'info') {
    $line = '{0}|{1}|{2}' -f (Get-Date).ToString('HH:mm:ss'), $lvl, $m
    if ($script:Sync) { [void]$script:Sync.Log.Add($line) }
    elseif (-not $script:Quiet) {
        $color = @{ info = 'Gray'; warn = 'Yellow'; error = 'Red' }[$lvl]
        Write-Host ('  {0}  {1}' -f (Get-Date).ToString('HH:mm:ss'), $m) -ForegroundColor $color
    }
    if ($lvl -ne 'info') { [void]$script:Notes.Add([ordered]@{ level = $lvl; text = $m }) }
}
function Dqe-Stage([string]$s, [double]$pct = -1) {
    if ($script:Sync) {
        if ($s) { $script:Sync.Stage = $s }
        if ($pct -ge 0) { $script:Sync.Pct = $pct }
        if ($script:Sync.Cancel) { throw 'Cancelled.' }
    } elseif (-not $script:Quiet) {
        if ($s) { $script:ConsoleStage = $s }
        if ($pct -ge 0) { $script:ConsolePct = [int][Math]::Min(100, $pct) }
        Write-Progress -Activity 'Defender Quarantine Extractor' -Status ([string]$script:ConsoleStage) -PercentComplete ([int]$script:ConsolePct)
    }
}
function Dqe-Hex([byte[]]$b, [int]$o = 0, [int]$n = -1) {
    if ($n -lt 0) { $n = $b.Length - $o }
    if ($n -le 0) { return '' }
    [BitConverter]::ToString($b, $o, $n).Replace('-', '')
}
function Dqe-UnHex([string]$h) {
    $n = [int]($h.Length / 2); $b = New-Object byte[] $n
    for ($i = 0; $i -lt $n; $i++) { $b[$i] = [Convert]::ToByte($h.Substring($i * 2, 2), 16) }
    , $b
}
function Dqe-Guid([byte[]]$b, [int]$o) {
    $g = New-Object byte[] 16; [Buffer]::BlockCopy($b, $o, $g, 0, 16)
    (New-Object Guid (, $g)).ToString().ToUpper()
}
function Dqe-Ft($v) {
    try {
        $l = [int64]$v
        if ($l -lt 119600064000000000 -or $l -gt 159017087999999999) { return '' }   # 1980 .. 2104
        [DateTime]::FromFileTimeUtc($l).ToString('yyyy-MM-dd HH:mm:ss.fff')
    } catch { '' }
}
function Dqe-Size([double]$n) {
    if ($n -ge 1GB) { return ('{0:N2} GB' -f ($n / 1GB)) }
    if ($n -ge 1MB) { return ('{0:N1} MB' -f ($n / 1MB)) }
    if ($n -ge 1KB) { return ('{0:N1} KB' -f ($n / 1KB)) }
    ('{0} B' -f [int64]$n)
}
function Dqe-SafeName([string]$s, [int]$max = 120) {
    $s = [regex]::Replace($s, '[\x00-\x1f<>:"/\\|?*]', '_').Trim().TrimEnd('.')
    if (-not $s) { $s = 'unnamed' }
    if ($s.Length -gt $max) {
        $ext = [IO.Path]::GetExtension($s); if ($ext.Length -gt 12) { $ext = '' }
        $s = $s.Substring(0, $max - $ext.Length) + $ext
    }
    $s
}
function Dqe-Leaf([string]$p) {
    $p = $p -replace '->\(.*\)$', ''
    $i = [Math]::Max($p.LastIndexOf('\'), $p.LastIndexOf('/'))
    if ($i -ge 0) { $p.Substring($i + 1) } else { $p }
}
function Dqe-Hash([byte[]]$b, [int]$o, [int]$n) {
    $r = [ordered]@{ md5 = ''; sha1 = ''; sha256 = '' }
    try { $h = New-Object Security.Cryptography.MD5CryptoServiceProvider; $r.md5 = (Dqe-Hex ($h.ComputeHash($b, $o, $n))).ToLower(); $h.Dispose() } catch { }
    try { $h = New-Object Security.Cryptography.SHA1CryptoServiceProvider; $r.sha1 = (Dqe-Hex ($h.ComputeHash($b, $o, $n))).ToLower(); $h.Dispose() } catch { }
    $h = New-Object Security.Cryptography.SHA256CryptoServiceProvider; $r.sha256 = (Dqe-Hex ($h.ComputeHash($b, $o, $n))).ToLower(); $h.Dispose()
    $r
}
function Dqe-FileSha256([string]$path) {
    $fs = [IO.File]::OpenRead($path)
    try { $h = New-Object Security.Cryptography.SHA256CryptoServiceProvider; (Dqe-Hex ($h.ComputeHash($fs))).ToLower() } finally { $fs.Dispose() }
}

# ---------------------------------------------------------------- byte XOR at native speed
# PowerShell loops manage roughly a million byte operations per second, far too slow for multi-megabyte payloads.
# System.Numerics.BigInteger implements XOR over whole byte arrays in native code, so buffers are XORed in 4 MB
# slices that way. A trailing zero byte keeps each slice positive so the round trip through BigInteger is lossless.
function Dqe-Xor([byte[]]$a, [int]$ao, [byte[]]$b, [int]$bo, [int]$len) {
    $out = New-Object byte[] $len
    if ($len -le 96) {
        for ($i = 0; $i -lt $len; $i++) { $out[$i] = $a[$ao + $i] -bxor $b[$bo + $i] }
        return , $out
    }
    $chunk = 4194304
    for ($p = 0; $p -lt $len; $p += $chunk) {
        $n = [Math]::Min($chunk, $len - $p)
        $x = New-Object byte[] ($n + 1); [Buffer]::BlockCopy($a, $ao + $p, $x, 0, $n)
        $y = New-Object byte[] ($n + 1); [Buffer]::BlockCopy($b, $bo + $p, $y, 0, $n)
        $bx = New-Object System.Numerics.BigInteger (, $x)
        $by = New-Object System.Numerics.BigInteger (, $y)
        $r = ([System.Numerics.BigInteger]::op_ExclusiveOr($bx, $by)).ToByteArray()
        [Buffer]::BlockCopy($r, 0, $out, $p, [Math]::Min($n, $r.Length))
    }
    , $out
}

# ---------------------------------------------------------------- Defender store cipher (RC4, fixed key)
# Defender obfuscates its quarantine and scan-history files with RC4 under a single 256-byte key embedded in
# mpengine.dll (published by ERNW in 2017 and used by every public tool since). The keystream is derived once, in a
# plain loop, and cached; every later decryption is a native XOR against the cached keystream.
function Dqe-KeyStream([int]$n) {
    if ($n -le $script:KSLen) { return }
    if (-not $script:RcS) {
        $key = Dqe-UnHex ('1E87781B8DBAA844CE69702C0C78B786A3F623B738F5EDF9AF83530FB3FC54FAA21EB9CF1331FD0F0DA954F687CB9E18' +
            '279697900E53FB317C9CBCE48E23D05371ECC15951B8F3649D7CA33ED68DC9047E82C9BAAD9799D0D458CB847CA9FFBE3C8A7752' +
            '33557DDE13A8B14087CC1BC8F10F6ECDD083A959CFF84A9D1D50755E3E191818AF23E2293558766D2C07E25712B2CA0B535ED8F6' +
            'C56CE73D24BDD0291771861A54B4C285A9A3DB7ACA6D224AEACD621DB9F2A22ED1E9E11D75BED7DC0ECB0A8E68A2FF1263408DC8' +
            '08DFFD164B116774CD0B9B8D05411ED6262E429BA495676B8398DB2F35D3C1B9CED52636F2765E1A95CB7CA4C3DDABDDBFF38253')
        $S = New-Object int[] 256
        for ($i = 0; $i -lt 256; $i++) { $S[$i] = $i }
        $j = 0
        for ($i = 0; $i -lt 256; $i++) { $j = ($j + $S[$i] + $key[$i]) -band 255; $t = $S[$i]; $S[$i] = $S[$j]; $S[$j] = $t }
        $script:RcS = $S; $script:RcI = 0; $script:RcJ = 0
    }
    if ($n -gt $script:KS.Length) {
        $nk = New-Object byte[] ([Math]::Max($n, 65536))
        if ($script:KSLen -gt 0) { [Buffer]::BlockCopy($script:KS, 0, $nk, 0, $script:KSLen) }
        $script:KS = $nk
    }
    $S = $script:RcS; $i = $script:RcI; $j = $script:RcJ; $ks = $script:KS; $k = $script:KSLen
    $big = ($n - $k) -gt 1048576
    while ($k -lt $n) {
        $stop = [Math]::Min($n, $k + 262144)
        for (; $k -lt $stop; $k++) {
            $i = ($i + 1) -band 255; $a = $S[$i]
            $j = ($j + $a) -band 255; $b = $S[$j]
            $S[$i] = $b; $S[$j] = $a
            $ks[$k] = $S[($a + $b) -band 255]
        }
        if ($big) { Dqe-Stage ('Preparing decryption  {0:N1} of {1:N1} MB' -f ($k / 1MB), ($n / 1MB)) }
    }
    $script:RcI = $i; $script:RcJ = $j; $script:KSLen = $n
}
function Dqe-Rc4([byte[]]$d, [int]$o, [int]$n) {
    Dqe-KeyStream $n
    $r = Dqe-Xor $d $o $script:KS 0 $n
    , $r
}
function Dqe-OpenSealed([byte[]]$b) {
    # Container used by Quarantine\Entries, Quarantine\Resources, Scans\History\Results and \Store:
    #   60-byte header (RC4, starts DB E8 C5 01; section lengths at 0x28 and 0x2C), then two sections, each RC4
    #   encrypted on its own with a fresh keystream.
    if ($b.Length -lt 60) { throw 'file shorter than header' }
    $h = Dqe-Rc4 $b 0 60
    if (-not ($h[0] -eq 0xDB -and $h[1] -eq 0xE8 -and $h[2] -eq 0xC5 -and $h[3] -eq 0x01)) { throw 'header signature not recognised' }
    $l1 = [int64][BitConverter]::ToUInt32($h, 0x28); $l2 = [int64][BitConverter]::ToUInt32($h, 0x2C)
    if (60 + $l1 + $l2 -gt $b.Length) { throw 'section sizes exceed file length' }
    $s1 = New-Object byte[] 0; $s2 = New-Object byte[] 0
    if ($l1 -gt 0) { $s1 = Dqe-Rc4 $b 60 ([int]$l1) }
    if ($l2 -gt 0) { $s2 = Dqe-Rc4 $b ([int](60 + $l1)) ([int]$l2) }
    @{ S1 = $s1; S2 = $s2 }
}

# =====================================================================================================================
#  SOURCES
#  A source is whatever the analyst points at:
#    * a collected .zip (any internal layout, optionally password-protected with ZipCrypto or AES)
#    * a gzip-compressed archive (.gz), which often wraps a .zip
#    * an extracted folder at any depth: the drive root, ProgramData, the Windows Defender folder, or Quarantine itself
#    * a flat folder where the Defender files were copied without their directory structure
#    * a single artifact file (an Entries file, a DetectionHistory file, an MPLog)
#    * several of the above at once
#  Everything is flattened into one item list. Nested .zip and .gz files are opened in memory. Each item knows how to
#  return its bytes on demand, so nothing is ever extracted to disk.
# =====================================================================================================================

$script:CommonPasswords = @('infected', 'malware', 'virus', 'password', '')

# Resource limits. Evidence comes from compromised hosts, so sizes declared inside it are never trusted on their own:
# every read is capped by what that kind of artifact can plausibly be, decompression stops at the data actually
# present, and archives opened in memory share one budget. Values are script-scoped so tests can lower them.
$script:MaxItemBytes  = 1GB     # largest single item read into memory (quarantined payloads can be large)
$script:MaxMetaBytes  = 64MB    # entries, resource index, detection history, scan results and store records
$script:MaxLogBytes   = 256MB   # MPLog / MPDetection / history logs
$script:MaxHeldBytes  = 2GB     # nested archives held open in memory at once
$script:MaxZipEntries = 500000  # entries listed from one archive
$script:HeldBytes     = 0
$script:UserPasswords   = @()

function Dqe-ReadFully($stream, [byte[]]$buf, [int64]$n) {
    # Stream.Read may return fewer bytes than asked for; loop until the buffer is full or the stream ends.
    $p = 0
    while ($p -lt $n) { $r = $stream.Read($buf, $p, [int]($n - $p)); if ($r -le 0) { break }; $p += $r }
    if ($p -lt $n) { throw 'unexpected end of data' }
}

function Dqe-CrcTable {
    # Standard CRC-32 (IEEE 802.3) lookup table, shared by the ZipCrypto cipher and CRC checks.
    if (-not $script:CrcT) {
        $t = New-Object long[] 256
        for ($i = 0; $i -lt 256; $i++) {
            [long]$c = $i
            for ($k = 0; $k -lt 8; $k++) { if ($c -band 1) { $c = 3988292384 -bxor ($c -shr 1) } else { $c = $c -shr 1 } }
            $t[$i] = $c
        }
        $script:CrcT = $t
    }
    , $script:CrcT
}

function Dqe-Crc32([byte[]]$b, [int]$o, [int]$n) {
    $T = Dqe-CrcTable; [long]$c = 4294967295
    for ($i = $o; $i -lt $o + $n; $i++) { $c = $T[($c -bxor $b[$i]) -band 255] -bxor ($c -shr 8) }
    $c -bxor 4294967295
}

function Dqe-ZcDecrypt([byte[]]$d, [int]$o, [int]$n, [byte[]]$pw) {
    # Traditional PKWARE ("ZipCrypto") decryption. Returns n plaintext bytes, including the 12-byte encryption header.
    # Pure PowerShell runs this at roughly 1 MB/s, which is why AES input and output are preferred.
    $T = Dqe-CrcTable; [long]$k0 = 305419896; [long]$k1 = 591751049; [long]$k2 = 878082192
    foreach ($c in $pw) {
        $k0 = $T[($k0 -bxor $c) -band 255] -bxor ($k0 -shr 8)
        $k1 = (($k1 + ($k0 -band 255)) * 134775813 + 1) -band 4294967295
        $k2 = $T[($k2 -bxor ($k1 -shr 24)) -band 255] -bxor ($k2 -shr 8)
    }
    $out = New-Object byte[] $n
    for ($i = 0; $i -lt $n; $i++) {
        $tt = ($k2 -bor 2) -band 65535
        $p = $d[$o + $i] -bxor ((($tt * ($tt -bxor 1)) -shr 8) -band 255)
        $out[$i] = $p
        $k0 = $T[($k0 -bxor $p) -band 255] -bxor ($k0 -shr 8)
        $k1 = (($k1 + ($k0 -band 255)) * 134775813 + 1) -band 4294967295
        $k2 = $T[($k2 -bxor ($k1 -shr 24)) -band 255] -bxor ($k2 -shr 8)
        if (($i -band 524287) -eq 524287) { Dqe-Stage ('Decrypting ZipCrypto input  {0:N1} of {1:N1} MB' -f ($i / 1MB), ($n / 1MB)) }
    }
    , $out
}

function Dqe-AesKeys([byte[]]$pw, [byte[]]$salt, [int]$keyLen) {
    # WinZip AE-1/AE-2 key derivation: PBKDF2-HMAC-SHA1, 1000 iterations -> encryption key, MAC key, 2-byte verifier.
    $kdf = New-Object Security.Cryptography.Rfc2898DeriveBytes($pw, $salt, 1000)
    try { , $kdf.GetBytes(2 * $keyLen + 2) } finally { $kdf.Dispose() }
}

function Dqe-Slice([byte[]]$b, [int]$o, [int]$n) {
    $r = New-Object byte[] $n; [Buffer]::BlockCopy($b, $o, $r, 0, $n); , $r
}

function Dqe-Inflate([byte[]]$data, [int]$o, [int]$n, [int64]$size, [int]$head = -1) {
    # Raw DEFLATE (zip method 8). With $head set, returns only the first bytes and tolerates truncated input.
    # Output grows with the data actually decompressed and stops at the declared size, so neither a size field that
    # lies upward (forcing a huge allocation) nor one that lies downward (a decompression bomb) costs more memory than
    # the smaller of the two.
    $ms = New-Object IO.MemoryStream($data, $o, $n)
    $ds = New-Object IO.Compression.DeflateStream($ms, [IO.Compression.CompressionMode]::Decompress)
    $want = if ($head -ge 0) { [int64][Math]::Min([int64]$head, $size) } else { $size }
    $out = New-Object IO.MemoryStream ([int][Math]::Min($want, 16MB))
    try {
        $buf = New-Object byte[] 262144; $p = [int64]0
        try {
            while ($p -lt $want) {
                $r = $ds.Read($buf, 0, [int][Math]::Min([int64]$buf.Length, $want - $p))
                if ($r -le 0) { break }
                $out.Write($buf, 0, $r); $p += $r
            }
        } catch { if ($head -lt 0) { throw } }
        if ($p -lt $want -and $head -lt 0) { throw 'compressed data ended early' }
        , $out.ToArray()
    } finally { $ds.Dispose(); $ms.Dispose(); $out.Dispose() }
}

function Dqe-Gunzip($stream, [string]$label) {
    $gz = New-Object IO.Compression.GZipStream($stream, [IO.Compression.CompressionMode]::Decompress, $true)
    $ms = New-Object IO.MemoryStream
    try {
        $buf = New-Object byte[] 1048576
        while (($r = $gz.Read($buf, 0, $buf.Length)) -gt 0) {
            # checked before writing, so the buffer never grows past the limit
            if ($ms.Length + $r -gt $script:MaxItemBytes) { throw ("$label expands to more than {0}; it was not opened." -f (Dqe-Size $script:MaxItemBytes)) }
            $ms.Write($buf, 0, $r)
        }
        , $ms.ToArray()
    } finally { $gz.Dispose(); $ms.Dispose() }
}

# ---------------------------------------------------------------- zip reader
# System.IO.Compression cannot read encrypted entries, so archives are read with this small reader instead.
# Supports Store and Deflate, ZipCrypto and WinZip AES (128/192/256), Zip64 sizes and offsets, UTF-8 and CP437 names.

function Dqe-ZipOpenReader($stream, [string]$label) {
    $len = $stream.Length
    if ($len -lt 22) { throw "$label is too small to be a zip archive." }
    $tail = [int][Math]::Min($len, 65557); $buf = New-Object byte[] $tail
    $stream.Position = $len - $tail; Dqe-ReadFully $stream $buf $tail
    $eo = -1
    for ($i = $tail - 22; $i -ge 0; $i--) {
        if ($buf[$i] -eq 0x50 -and $buf[$i + 1] -eq 0x4B -and $buf[$i + 2] -eq 5 -and $buf[$i + 3] -eq 6) { $eo = $i; break }
    }
    if ($eo -lt 0) { throw "$label is not a zip archive, or it is truncated (no central directory found)." }
    [int64]$cdSize = [BitConverter]::ToUInt32($buf, $eo + 12); [int64]$cdOff = [BitConverter]::ToUInt32($buf, $eo + 16)
    if ($eo -ge 20 -and [BitConverter]::ToUInt32($buf, $eo - 20) -eq 0x07064b50) {
        $z64 = [int64][BitConverter]::ToUInt64($buf, $eo - 20 + 8)
        if ($z64 + 56 -le $len) {
            $h = New-Object byte[] 56; $stream.Position = $z64; Dqe-ReadFully $stream $h 56
            if ([BitConverter]::ToUInt32($h, 0) -eq 0x06064b50) { $cdSize = [int64][BitConverter]::ToUInt64($h, 40); $cdOff = [int64][BitConverter]::ToUInt64($h, 48) }
        }
    }
    if ($cdOff + $cdSize -gt $len -or $cdSize -gt 512MB) { throw "$label is damaged: its central directory points past the end of the file." }
    $cd = New-Object byte[] $cdSize; $stream.Position = $cdOff; Dqe-ReadFully $stream $cd $cdSize
    $oem = $script:Latin1; try { $oem = [Text.Encoding]::GetEncoding(437) } catch { }
    $entries = New-Object System.Collections.ArrayList; $p = 0
    while ($p + 46 -le $cdSize -and [BitConverter]::ToUInt32($cd, $p) -eq 0x02014b50) {
        $flags = [int][BitConverter]::ToUInt16($cd, $p + 8); $method = [int][BitConverter]::ToUInt16($cd, $p + 10)
        $mt = [int][BitConverter]::ToUInt16($cd, $p + 12); $md = [int][BitConverter]::ToUInt16($cd, $p + 14)
        [int64]$crc = [BitConverter]::ToUInt32($cd, $p + 16)
        [int64]$cs = [BitConverter]::ToUInt32($cd, $p + 20); [int64]$us = [BitConverter]::ToUInt32($cd, $p + 24)
        $nl = [int][BitConverter]::ToUInt16($cd, $p + 28); $xl = [int][BitConverter]::ToUInt16($cd, $p + 30); $cl = [int][BitConverter]::ToUInt16($cd, $p + 32)
        [int64]$lho = [BitConverter]::ToUInt32($cd, $p + 42)
        $enc = if ($flags -band 0x800) { [Text.Encoding]::UTF8 } else { $oem }
        $name = $enc.GetString($cd, $p + 46, $nl)
        $xo = $p + 46 + $nl; $xe = $xo + $xl; $aes = $null
        while ($xo + 4 -le $xe) {
            $hid = [BitConverter]::ToUInt16($cd, $xo); $hs = [int][BitConverter]::ToUInt16($cd, $xo + 2); $d = $xo + 4; $de = $d + $hs
            if ($hid -eq 0x0001) {
                if ($us -eq 4294967295 -and $d + 8 -le $de) { $us = [int64][BitConverter]::ToUInt64($cd, $d); $d += 8 }
                if ($cs -eq 4294967295 -and $d + 8 -le $de) { $cs = [int64][BitConverter]::ToUInt64($cd, $d); $d += 8 }
                if ($lho -eq 4294967295 -and $d + 8 -le $de) { $lho = [int64][BitConverter]::ToUInt64($cd, $d) }
            } elseif ($hid -eq 0x9901 -and $hs -ge 7) {
                $aes = @{ Strength = [int]$cd[$xo + 8]; Method = [int][BitConverter]::ToUInt16($cd, $xo + 9) }
            }
            $xo = $de
        }
        $time = [DateTime]::UtcNow
        try { $time = New-Object DateTime ((($md -shr 9) -band 127) + 1980), ([Math]::Max(1, ($md -shr 5) -band 15)), ([Math]::Max(1, $md -band 31)), (($mt -shr 11) -band 31), (($mt -shr 5) -band 63), ((($mt -band 31) * 2) % 60) } catch { }
        $name = $name.Replace('\', '/')
        if (-not $name.EndsWith('/')) {
            [void]$entries.Add(@{ Name = $name; Flags = $flags; Method = $method; Crc = $crc; CSize = $cs; USize = $us; Lho = $lho; Aes = $aes; MTime = $mt; Time = $time })
            if ($entries.Count -gt $script:MaxZipEntries) { throw "$label lists more than $($script:MaxZipEntries) entries and was not opened." }
        }
        $p += 46 + $nl + $xl + $cl
    }
    @{ S = $stream; Label = $label; Entries = $entries; Pw = $null; Failed = $null; Warned = $false
       Encrypted = (@($entries | Where-Object { $_.Flags -band 1 }).Count -gt 0) }
}

function Dqe-ZipRaw($z, $e, [int64]$max = -1) {
    # Returns the stored (compressed, possibly encrypted) bytes of one entry, or only the first $max of them.
    $s = $z.S; $h = New-Object byte[] 30; $s.Position = $e.Lho; Dqe-ReadFully $s $h 30
    if ([BitConverter]::ToUInt32($h, 0) -ne 0x04034b50) { throw "the local header of $($e.Name) is damaged" }
    $do = $e.Lho + 30 + [BitConverter]::ToUInt16($h, 26) + [BitConverter]::ToUInt16($h, 28)
    $n = if ($max -ge 0) { [Math]::Min($max, $e.CSize) } else { $e.CSize }
    if ($n -gt $script:MaxItemBytes) { throw ("$($e.Name) is larger than {0} compressed" -f (Dqe-Size $script:MaxItemBytes)) }
    if ($do + $n -gt $s.Length) { throw "$($e.Name) is damaged: its data runs past the end of the archive" }   # checked before allocating
    $b = New-Object byte[] $n; $s.Position = $do; Dqe-ReadFully $s $b $n
    , $b
}

function Dqe-ZipUnlock($z) {
    # Finds the password of an encrypted archive: the analyst's passwords first, then the usual sample-sharing ones.
    # Each candidate is checked against the smallest encrypted entry: AES via its verifier and MAC, ZipCrypto via its
    # check byte and, for entries up to 1 MB, a full CRC-32 comparison.
    if ($z.Pw) { return }
    if ($z.Failed) { throw $z.Failed }
    $cands = New-Object System.Collections.ArrayList
    foreach ($c in (@($script:UserPasswords) + $script:CommonPasswords)) { if ($null -ne $c -and -not $cands.Contains([string]$c)) { [void]$cands.Add([string]$c) } }
    $probe = @($z.Entries | Where-Object { $_.Flags -band 1 } | Sort-Object { $_.CSize })[0]
    $raw = Dqe-ZipRaw $z $probe ([Math]::Min($probe.CSize, 1MB + 64))
    foreach ($c in $cands) {
        $pw = [Text.Encoding]::UTF8.GetBytes($c); $ok = $false
        try {
            if ($probe.Aes) {
                $kl = @{ 1 = 16; 2 = 24; 3 = 32 }[$probe.Aes.Strength]; $sl = $kl / 2
                $km = Dqe-AesKeys $pw (Dqe-Slice $raw 0 $sl) $kl
                if ($km[2 * $kl] -eq $raw[$sl] -and $km[2 * $kl + 1] -eq $raw[$sl + 1]) {
                    $ok = $true
                    if ($probe.CSize -le 1MB) {
                        $cl = $raw.Length - $sl - 12
                        $hm = New-Object Security.Cryptography.HMACSHA1 (, (Dqe-Slice $km $kl $kl)); $mac = $hm.ComputeHash($raw, $sl + 2, $cl); $hm.Dispose()
                        for ($i = 0; $i -lt 10; $i++) { if ($mac[$i] -ne $raw[$sl + 2 + $cl + $i]) { $ok = $false; break } }
                    }
                }
            } else {
                $hd = Dqe-ZcDecrypt $raw 0 12 $pw
                $chk = if ($probe.Flags -band 8) { ($probe.MTime -shr 8) -band 255 } else { ($probe.Crc -shr 24) -band 255 }
                if ($hd[11] -eq $chk) {
                    $ok = $true
                    if ($probe.CSize -le 1MB) {
                        $pt = Dqe-ZcDecrypt $raw 0 $raw.Length $pw
                        $plain = if ($probe.Method -eq 8) { Dqe-Inflate $pt 12 ($pt.Length - 12) $probe.USize } elseif ($probe.Method -eq 0) { Dqe-Slice $pt 12 ($pt.Length - 12) } else { $null }
                        if ($plain -and (Dqe-Crc32 $plain 0 $plain.Length) -ne $probe.Crc) { $ok = $false }
                    }
                }
            }
        } catch { $ok = $false }
        if ($ok) {
            $z.Pw = $pw
            Dqe-Log ('{0} is password-protected ({1}); opened it with {2}.' -f $z.Label, $(if ($probe.Aes) { 'AES' } else { 'ZipCrypto' }), $(if ($c) { 'the password "' + $c + '"' } else { 'an empty password' }))
            if (-not $probe.Aes) { Dqe-Log "ZipCrypto decryption is slow for large entries; reading $($z.Label) may take several minutes." }
            return
        }
    }
    $z.Failed = "$($z.Label) is password-protected and none of the passwords tried worked. Enter its password in the source password box (or -SourcePassword) and load again."
    throw $z.Failed
}

function Dqe-ZipEntryBytes($z, $e, [int]$head = -1) {
    # Returns the plaintext of one entry. With $head set, returns only its first bytes and reads as little as possible.
    $partial = $head -ge 0
    if (-not $partial -and $e.USize -gt $script:MaxItemBytes) { throw ("$($e.Name) declares {0}, more than the {1} limit" -f (Dqe-Size $e.USize), (Dqe-Size $script:MaxItemBytes)) }
    $method = $e.Method
    $want = if ($partial) { [int64][Math]::Min($e.CSize, [int64]$head * 8 + 65536) } else { -1 }
    $raw = Dqe-ZipRaw $z $e $want
    $data = $raw; $o = 0; $n = $raw.Length
    if ($e.Flags -band 1) {
        Dqe-ZipUnlock $z
        if ($e.Aes) {
            $method = $e.Aes.Method
            $kl = @{ 1 = 16; 2 = 24; 3 = 32 }[$e.Aes.Strength]; $sl = $kl / 2
            $km = Dqe-AesKeys $z.Pw (Dqe-Slice $raw 0 $sl) $kl
            if ($km[2 * $kl] -ne $raw[$sl] -or $km[2 * $kl + 1] -ne $raw[$sl + 1]) { throw "$($e.Name) uses a different password from the rest of $($z.Label)" }
            $cl = if ($partial -and $raw.Length -lt $e.CSize) { $raw.Length - $sl - 2 } else { $raw.Length - $sl - 12 }
            $ct = Dqe-Slice $raw ($sl + 2) $cl
            if (-not $partial) {
                $hm = New-Object Security.Cryptography.HMACSHA1 (, (Dqe-Slice $km $kl $kl)); $mac = $hm.ComputeHash($ct); $hm.Dispose()
                for ($i = 0; $i -lt 10; $i++) { if ($mac[$i] -ne $raw[$sl + 2 + $cl + $i]) { throw "$($e.Name) failed its integrity check (AES authentication code)" } }
            }
            $data = Dqe-AesCtr $ct (Dqe-Slice $km 0 $kl); $o = 0; $n = $data.Length
        } else {
            $data = Dqe-ZcDecrypt $raw 0 $raw.Length $z.Pw; $o = 12; $n = $data.Length - 12
        }
    }
    if ($method -eq 0) {
        if ($partial) { $n = [Math]::Min($n, $head) }
        if ($o -eq 0 -and $n -eq $data.Length) { return , $data }
        return , (Dqe-Slice $data $o $n)
    }
    if ($method -eq 8) { return , (Dqe-Inflate $data $o $n $e.USize $head) }
    $names = @{ 9 = 'Deflate64'; 12 = 'BZip2'; 14 = 'LZMA'; 93 = 'Zstandard'; 95 = 'XZ'; 98 = 'PPMd' }
    $mn = $names[$method]; if (-not $mn) { $mn = "method $method" }
    throw "$($e.Name) is compressed with $mn. Only Store and Deflate are supported; re-create the archive with standard zip compression."
}

# ---------------------------------------------------------------- building the item list

function Dqe-AddZipItems($src, $z, [string]$prefix, [int]$depth) {
    [void]$src.Zips.Add($z)
    if ($z.Encrypted) { Dqe-ZipUnlock $z }   # fail early and clearly when the password is unknown
    foreach ($e in $z.Entries) {
        $it = @{ Rel = $prefix + $e.Name.TrimStart('/'); Len = [int64]$e.USize; Time = $e.Time; Via = 'zip'; Zip = $z; Entry = $e; Full = $null; Bytes = $null }
        [void]$src.Items.Add($it)
        Dqe-MaybeExpand $src $it $depth
    }
}

function Dqe-MaybeExpand($src, $it, [int]$depth) {
    # Opens .zip and .gz items found inside a source, so collections that wrap other archives work without extraction.
    $lower = $it.Rel.ToLowerInvariant()
    $isZip = $lower.EndsWith('.zip'); $isGz = $lower.EndsWith('.gz') -or $lower.EndsWith('.gzip')
    if (-not ($isZip -or $isGz)) { return }
    if ($depth -ge 4) { Dqe-Log "$($it.Rel) is nested more than four archives deep and was not opened." 'warn'; return }
    if ($it.Len -gt 1GB) { Dqe-Log "$($it.Rel) is larger than 1 GB and was not opened. Extract it and load the folder instead." 'warn'; return }
    try {
        $z = $null
        if ($it.Via -eq 'file' -and $isZip) {
            $fs = [IO.File]::Open($it.Full, 'Open', 'Read', 'ReadWrite'); [void]$src.Handles.Add($fs)
            $z = Dqe-ZipOpenReader $fs $it.Rel
        } else {
            $bytes = Dqe-Read $it
            if ($isGz -or ($bytes.Length -gt 2 -and $bytes[0] -eq 0x1F -and $bytes[1] -eq 0x8B)) {
                $ms0 = New-Object IO.MemoryStream (, $bytes); $bytes = Dqe-Gunzip $ms0 $it.Rel; $ms0.Dispose()
            }
            if ($script:HeldBytes + $bytes.Length -gt $script:MaxHeldBytes) {
                Dqe-Log ("$($it.Rel) was not opened: nested archives in this source already hold {0} in memory. Extract the collection and load the folder instead." -f (Dqe-Size $script:HeldBytes)) 'warn'
                return
            }
            $script:HeldBytes += $bytes.Length
            if ($bytes.Length -ge 4 -and $bytes[0] -eq 0x50 -and $bytes[1] -eq 0x4B) {
                $ms = New-Object IO.MemoryStream (, $bytes); [void]$src.Handles.Add($ms)
                $z = Dqe-ZipOpenReader $ms $it.Rel
            } else {
                $inner = $it.Rel -replace '(?i)\.gz(ip)?$', ''
                [void]$src.Items.Add(@{ Rel = $inner; Len = [int64]$bytes.Length; Time = $it.Time; Via = 'mem'; Bytes = $bytes; Full = $null; Zip = $null; Entry = $null })
                $it.Kind = 'container'
                return
            }
        }
        $it.Kind = 'container'
        Dqe-AddZipItems $src $z ($it.Rel + '/') ($depth + 1)
    } catch {
        if ($_.Exception.Message -eq 'Cancelled.') { throw }
        Dqe-Log "Could not open $($it.Rel): $($_.Exception.Message)" 'warn'
    }
}

function Dqe-OpenSource([string[]]$paths) {
    $src = @{ Name = ''; Kind = ''; Items = (New-Object System.Collections.ArrayList); Handles = (New-Object System.Collections.ArrayList)
              Inputs = (New-Object System.Collections.ArrayList); Zips = (New-Object System.Collections.ArrayList) }
    $script:HeldBytes = 0
    $list = @($paths | ForEach-Object { if ($_) { ([string]$_).Trim().Trim('"') } } | Where-Object { $_ })
    if ($list.Count -eq 0) { throw 'No source was given. Choose a collected zip or a folder.' }
    $multi = $list.Count -gt 1
    try {
        foreach ($path in $list) {
            $full = $path; try { $full = [IO.Path]::GetFullPath($path) } catch { }
            $label = [IO.Path]::GetFileName($full.TrimEnd('\', '/')); if (-not $label) { $label = $full }
            $prefix = if ($multi) { (Dqe-SafeName $label 60) + '/' } else { '' }
            $info = [ordered]@{ path = $full; name = $label; kind = ''; size = 0; sha256 = '' }
            if ([IO.Directory]::Exists($full)) {
                $info.kind = 'folder'
                $root = $full.TrimEnd('\'); $stack = New-Object System.Collections.Stack; $stack.Push($root); $count = 0
                while ($stack.Count -gt 0) {
                    $dir = $stack.Pop()
                    try {
                        foreach ($sub in [IO.Directory]::GetDirectories($dir)) { $stack.Push($sub) }
                        foreach ($f in [IO.Directory]::GetFiles($dir)) {
                            $fi = New-Object IO.FileInfo $f
                            $it = @{ Rel = $prefix + $f.Substring($root.Length).TrimStart('\').Replace('\', '/'); Len = [int64]$fi.Length; Time = $fi.LastWriteTimeUtc; Via = 'file'; Full = $f; Bytes = $null; Zip = $null; Entry = $null }
                            [void]$src.Items.Add($it); $count++
                            Dqe-MaybeExpand $src $it 0
                        }
                    } catch [UnauthorizedAccessException] { Dqe-Log "Access denied to $dir." 'warn' }
                    catch { Dqe-Log "Could not read folder $dir : $($_.Exception.Message)" 'warn' }
                    if ($count -gt 400000) { throw "$label holds more than 400,000 files. Point at the collection or the Windows Defender folder instead." }
                    if (($count % 2000) -eq 1999) { Dqe-Stage ("Listing $label  ($count files)") }
                }
            } elseif ([IO.File]::Exists($full)) {
                $fi = New-Object IO.FileInfo $full; $info.size = $fi.Length
                $fs = [IO.File]::Open($full, 'Open', 'Read', 'ReadWrite'); [void]$src.Handles.Add($fs)
                $m = New-Object byte[] 4; $got = $fs.Read($m, 0, 4); $fs.Position = 0
                if ($got -ge 2 -and $m[0] -eq 0x1F -and $m[1] -eq 0x8B) {
                    $info.kind = 'gzip'
                    $bytes = Dqe-Gunzip $fs $label
                    $inner = $label -replace '(?i)\.gz(ip)?$', ''
                    if ($bytes.Length -ge 4 -and $bytes[0] -eq 0x50 -and $bytes[1] -eq 0x4B) {
                        $info.kind = 'zip inside gzip'
                        $ms = New-Object IO.MemoryStream (, $bytes); [void]$src.Handles.Add($ms)
                        Dqe-AddZipItems $src (Dqe-ZipOpenReader $ms $inner) $prefix 0
                    } else {
                        [void]$src.Items.Add(@{ Rel = $prefix + $inner; Len = [int64]$bytes.Length; Time = $fi.LastWriteTimeUtc; Via = 'mem'; Bytes = $bytes; Full = $null; Zip = $null; Entry = $null })
                    }
                } elseif ($got -ge 4 -and $m[0] -eq 0x50 -and $m[1] -eq 0x4B) {
                    $info.kind = 'zip'
                    Dqe-AddZipItems $src (Dqe-ZipOpenReader $fs $label) $prefix 0
                } else {
                    $info.kind = 'file'
                    [void]$src.Items.Add(@{ Rel = $prefix + $label; Len = [int64]$fi.Length; Time = $fi.LastWriteTimeUtc; Via = 'file'; Full = $full; Bytes = $null; Zip = $null; Entry = $null })
                }
            } else { throw "Path not found: $full" }
            [void]$src.Inputs.Add($info)
        }
    } catch { Dqe-CloseSource $src; throw }
    $src.Name = (@($src.Inputs | ForEach-Object { $_.name }) -join ', ')
    $src.Kind = if ($src.Inputs.Count -eq 1) { $src.Inputs[0].kind } else { 'multiple sources' }
    Dqe-Classify $src
    $src
}

function Dqe-CloseSource($src) {
    if ($src -and $src.Handles) { foreach ($h in $src.Handles) { try { $h.Dispose() } catch { } }; $src.Handles.Clear() }
}

function Dqe-ReadLimit([string]$kind) {
    if ($kind -in 'entry', 'resmeta', 'dh', 'result', 'store') { return $script:MaxMetaBytes }
    if ($kind -in 'mplog', 'mpdet', 'histlog', 'mpcmdrun') { return $script:MaxLogBytes }
    $script:MaxItemBytes
}

function Dqe-Read($it) {
    # Returns all bytes of an item, wherever it lives. Files are opened with sharing so live logs can be read.
    # The limit depends on what the item is, so a crafted "log" or "entry" cannot claim a payload-sized allocation.
    $limit = Dqe-ReadLimit ([string]$it.Kind)
    if ($it.Len -gt $limit) { throw ("$($it.Rel) is {0}, more than the {1} expected for this kind of file; it was skipped" -f (Dqe-Size $it.Len), (Dqe-Size $limit)) }
    if ($it.Via -eq 'mem') { return , $it.Bytes }
    if ($it.Via -eq 'zip') { return , (Dqe-ZipEntryBytes $it.Zip $it.Entry) }
    $fs = [IO.File]::Open($it.Full, 'Open', 'Read', 'ReadWrite')
    try { $b = New-Object byte[] $fs.Length; Dqe-ReadFully $fs $b $fs.Length; return , $b } finally { $fs.Dispose() }
}

function Dqe-ReadHead($it, [int]$n) {
    # Returns up to the first $n bytes of an item, reading as little as possible. Used to recognise renamed files.
    if ($it.Via -eq 'mem') { return , (Dqe-Slice $it.Bytes 0 ([Math]::Min($n, $it.Bytes.Length))) }
    if ($it.Via -eq 'zip') { return , (Dqe-ZipEntryBytes $it.Zip $it.Entry $n) }
    $fs = [IO.File]::Open($it.Full, 'Open', 'Read', 'ReadWrite')
    try { $b = New-Object byte[] $n; $r = $fs.Read($b, 0, $n); if ($r -lt $n) { return , (Dqe-Slice $b 0 $r) }; return , $b } finally { $fs.Dispose() }
}

# ---------------------------------------------------------------- recognising Defender artifacts
# First by path and name, which covers any collection that kept Defender's folder names. Files without an extension
# that are still unrecognised are then identified by content, which covers flattened copies and renamed files:
#   * Entries, Resources, Results, Store  -> RC4-sealed container with signature DB E8 C5 01, told apart by header fields
#   * ResourceData                        -> whole-file RC4; plaintext is a BackupRead stream or a registry hive
#   * DetectionHistory                    -> plain TLV file starting 08 00 00 00 08 00 00 00 with "Magic.Version"

function Dqe-Classify($src) {
    $g36 = '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}'; $guid = "\{?$g36\}?"
    $sniffed = 0
    foreach ($it in $src.Items) {
        if ($it.Kind) { continue }
        $r = $it.Rel; $leaf = Dqe-Leaf $r; $k = 'other'
        if     ($r -match "(?i)(^|/)Entries/\{$g36\}$")                                          { $k = 'entry' }
        elseif ($r -match '(?i)(^|/)ResourceData/[0-9A-F]{2}/[0-9A-F]{40}$')                       { $k = 'resdata' }
        elseif ($r -match '(?i)(^|/)Resources/[0-9A-F]{2}/[0-9A-F]{40}$')                          { $k = 'resmeta' }
        elseif ($r -match "(?i)(^|/)DetectionHistory/[^/]+/$guid$")                                 { $k = 'dh' }
        elseif ($r -match '(?i)(^|/)History/Store/[0-9A-F]{32}$')                                   { $k = 'store' }
        elseif ($r -match "(?i)(^|/)Results/[^/]+/$guid$")                                          { $k = 'result' }
        elseif ($r -match '(?i)(^|/)Scans/History/Service/[^/]+\.log$')                             { $k = 'histlog' }
        elseif ($leaf -match '(?i)^MPDetection-.*\.log$')                                           { $k = 'mpdet' }
        elseif ($leaf -match '(?i)^MPLog-.*\.log$')                                                 { $k = 'mplog' }
        elseif ($leaf -match '(?i)^MpCmdRun.*\.log$')                                               { $k = 'mpcmdrun' }
        elseif ($leaf -match '(?i)Windows Defender.*\.evtx$')                                       { $k = 'evtx' }
        elseif ($leaf -notmatch '\.' -or $leaf -match '(?i)\.(bin|dat)$') {
            if ($it.Len -ge 60 -and $it.Len -le $script:MaxItemBytes -and $sniffed -lt 50000) {
                $sniffed++
                if (($sniffed % 200) -eq 1) { Dqe-Stage ("Recognising artifacts by content ($sniffed checked)") }
                try { $k = Dqe-SniffArtifact $it $leaf } catch { if ($_.Exception.Message -eq 'Cancelled.') { throw } }
            }
        }
        $it.Kind = $k
        $it.ResId = if ($k -eq 'resdata') { if ($leaf -match '^[0-9A-Fa-f]{40}$') { $leaf.ToUpper() } else { $leaf } } else { '' }
    }
    $marked = $false
    foreach ($it in $src.Items) { $it.Marked = ($it.Rel -match '(?i)(^|/)Windows Defender/'); if ($it.Marked) { $marked = $true } }
    foreach ($it in $src.Items) { $it.InScope = ((-not $marked) -or $it.Marked -or ($it.Kind -ne 'other' -and $it.Kind -ne 'container')) }
}

function Dqe-SniffArtifact($it, [string]$leaf) {
    $h = Dqe-ReadHead $it 64
    if ($h.Length -lt 32) { return 'other' }
    if ([BitConverter]::ToUInt64($h, 0) -eq 0x0000000800000008 -and $h.Length -ge 64 -and
        [Text.Encoding]::Unicode.GetString($h, 0x30, 10) -eq 'Magic') { return 'dh' }
    $d = Dqe-Rc4 $h 0 $h.Length
    if ($d.Length -ge 60 -and $d[0] -eq 0xDB -and $d[1] -eq 0xE8 -and $d[2] -eq 0xC5 -and $d[3] -eq 0x01) {
        $v = [BitConverter]::ToUInt32($d, 4); $l1 = [BitConverter]::ToUInt32($d, 0x28)
        if ($v -eq 0x00010001) { if ($l1 -eq 32) { return 'resmeta' } else { return 'entry' } }
        if ($v -eq 0x586) { return 'result' }
        if ($l1 -eq 0) { return 'store' }
        return 'other'
    }
    if ($d[0] -eq 0x72 -and $d[1] -eq 0x65 -and $d[2] -eq 0x67 -and $d[3] -eq 0x66) { return 'resdata' }
    $sid = [BitConverter]::ToUInt32($d, 0); $attr = [BitConverter]::ToUInt32($d, 4); $nl = [BitConverter]::ToUInt32($d, 16)
    $sz = [BitConverter]::ToUInt64($d, 8)
    if ($sid -ge 1 -and $sid -le 11 -and $attr -lt 0x100 -and $nl -lt 1024 -and ($nl % 2) -eq 0 -and $sz -le [uint64]$it.Len) { return 'resdata' }
    'other'
}

# ---------------------------------------------------------------- Windows event log
# Defender's operational log is read with Get-WinEvent, which needs a real file. Logs inside an archive are therefore
# copied into the output but not parsed (extracting them to a temp folder would break the no-files-on-disk rule).

$script:EventNames = @{
    1000 = 'Scan started'; 1001 = 'Scan finished'; 1002 = 'Scan stopped'; 1005 = 'Scan failed'
    1006 = 'Malware found (legacy)'; 1007 = 'Action taken (legacy)'; 1008 = 'Action failed (legacy)'
    1009 = 'Restored from quarantine'; 1010 = 'Restore from quarantine failed'; 1011 = 'Deleted from quarantine'
    1012 = 'Delete from quarantine failed'; 1013 = 'History deleted'; 1015 = 'Suspicious behavior found'
    1116 = 'Threat detected'; 1117 = 'Action taken'; 1118 = 'Action failed'; 1119 = 'Action failed critically'
    1120 = 'Threat hashes'; 1121 = 'Attack surface reduction block'; 1122 = 'Attack surface reduction audit'
    1123 = 'Controlled folder access block'; 1124 = 'Controlled folder access audit'; 1125 = 'Network protection audit'
    1126 = 'Network protection block'; 1127 = 'Controlled folder access sector block'; 1129 = 'User allowed blocked file'
    2050 = 'Sample submitted'; 3002 = 'Real-time protection failure'; 5001 = 'Real-time protection disabled'
    5004 = 'Real-time protection configuration changed'; 5007 = 'Configuration changed'; 5008 = 'Engine failure'
    5010 = 'Spyware scanning disabled'; 5012 = 'Virus scanning disabled'; 5013 = 'Tamper protection blocked a change'
}
function Dqe-ReadDefenderEvents([string]$path, [string]$label) {
    $out = New-Object System.Collections.ArrayList
    $ids = @($script:EventNames.Keys | ForEach-Object { [int]$_ } | Sort-Object)
    $keep = 'Threat Name', 'Action Name', 'Path', 'Process Name', 'Detection User', 'Severity Name', 'Category Name', 'Error Description', 'ID', 'Old Value', 'New Value', 'Hashes', 'Feature Name', 'Reason', 'Scan Type', 'Scan Parameters'
    for ($c = 0; $c -lt $ids.Count; $c += 20) {
        $fh = @{ Id = $ids[$c..([Math]::Min($c + 19, $ids.Count - 1))] }
        $fh.Path = $path
        $evs = @()
        try { $evs = @(Get-WinEvent -FilterHashtable $fh -MaxEvents 20000 -ErrorAction Stop) }
        catch { if ($_.Exception.Message -notmatch 'No events were found') { Dqe-Log "Could not read the Defender event log ($label): $($_.Exception.Message)" 'warn'; return , $out } }
        foreach ($ev in $evs) {
            $data = [ordered]@{}
            try { $x = [xml]$ev.ToXml(); foreach ($n in @($x.Event.EventData.Data)) { if ($n -and $n.Name) { $data[[string]$n.Name] = [string]$n.'#text' } } } catch { }
            $parts = foreach ($k in $keep) { $v = $data[$k]; if ($v) { '{0}: {1}' -f $k, ($v -replace '^file:_', '' -replace '\s+', ' ') } }
            $lvl = ''; try { $lvl = $ev.LevelDisplayName } catch { }
            [void]$out.Add([ordered]@{ time = $ev.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss.fff'); id = $ev.Id; name = $script:EventNames[$ev.Id]
                level = $lvl; computer = $ev.MachineName; summary = (@($parts) -join ' | '); data = $data; source = $label })
        }
    }
    , $out
}

# ---------------------------------------------------------------- small readers
# Helpers for UTF-16 strings and for telling text from binary. Type detection uses magic numbers only; it never
# executes, loads or renders sample content.
function Dqe-WStrZ([byte[]]$b, [int]$o, [int]$end) {
    $p = $o
    while ($p + 1 -lt $end -and -not ($b[$p] -eq 0 -and $b[$p + 1] -eq 0)) { $p += 2 }
    @{ S = [Text.Encoding]::Unicode.GetString($b, $o, $p - $o); Next = $p + 2 }
}
function Dqe-LooksUtf16([byte[]]$b, [int]$o, [int]$n) {
    if ($n -lt 4 -or ($n % 2) -ne 0) { return $false }
    $pairs = [Math]::Min(96, [int]($n / 2)); $ok = 0
    for ($i = 0; $i -lt $pairs; $i++) {
        $lo = $b[$o + 2 * $i]; $hi = $b[$o + 2 * $i + 1]
        if ($hi -eq 0 -and (($lo -ge 32 -and $lo -lt 127) -or $lo -eq 9 -or $lo -eq 10 -or $lo -eq 13)) { $ok++ }
        elseif ($i -eq 0 -and $lo -eq 0xFF -and $hi -eq 0xFE) { $ok++ }
    }
    ($ok * 100 / $pairs) -ge 85
}
function Dqe-LooksAscii([byte[]]$b, [int]$o, [int]$n) {
    if ($n -lt 1) { return $false }
    $m = [Math]::Min(256, $n); $ok = 0
    for ($i = 0; $i -lt $m; $i++) { $c = $b[$o + $i]; if (($c -ge 32 -and $c -lt 127) -or $c -eq 9 -or $c -eq 10 -or $c -eq 13) { $ok++ } }
    ($ok * 100 / $m) -ge 92
}
function Dqe-Sniff([byte[]]$b, [int]$o, [int]$n) {
    $r = [ordered]@{ type = 'data'; ext = ''; pe = $null }
    if ($n -lt 4) { if ($n -eq 0) { $r.type = 'empty' }; return $r }
    $m4 = Dqe-Hex $b $o 4
    if ($b[$o] -eq 0x4D -and $b[$o + 1] -eq 0x5A) {
        $r.type = 'DOS/PE executable'; $r.ext = 'exe'
        if ($n -gt 0x40) {
            $lf = [int64][BitConverter]::ToUInt32($b, $o + 0x3C)
            if ($lf + 0x60 -lt $n -and $b[$o + $lf] -eq 0x50 -and $b[$o + $lf + 1] -eq 0x45) {
                $mach = [BitConverter]::ToUInt16($b, $o + $lf + 4); $ch = [BitConverter]::ToUInt16($b, $o + $lf + 22)
                $opt = [BitConverter]::ToUInt16($b, $o + $lf + 24); $sub = [BitConverter]::ToUInt16($b, $o + $lf + 24 + 68)
                $arch = switch ($mach) { 0x14c { 'x86' } 0x8664 { 'x64' } 0xAA64 { 'ARM64' } 0x1c4 { 'ARM' } default { '0x{0:X}' -f $mach } }
                $kind = if ($ch -band 0x2000) { 'DLL' } elseif ($sub -eq 1) { 'driver' } elseif ($sub -eq 3) { 'console' } else { 'GUI' }
                $r.type = '{0} {1} ({2})' -f $(if ($opt -eq 0x20b) { 'PE32+' } else { 'PE32' }), $kind, $arch
                if ($ch -band 0x2000) { $r.ext = 'dll' } elseif ($sub -eq 1) { $r.ext = 'sys' }
                $ts = [BitConverter]::ToUInt32($b, $o + $lf + 8)
                $r.pe = [ordered]@{ machine = $arch; kind = $kind; linkerTimestamp = ([DateTime]'1970-01-01').AddSeconds($ts).ToString('yyyy-MM-dd HH:mm:ss') }
            }
        }
        return $r
    }
    if     ($m4 -eq '504B0304')            { $r.type = 'ZIP container (zip / Office / jar / apk)'; $r.ext = 'zip' }
    elseif ($m4 -eq '25504446')            { $r.type = 'PDF document'; $r.ext = 'pdf' }
    elseif ($m4 -eq 'D0CF11E0')            { $r.type = 'OLE compound file (legacy Office / MSI)'; $r.ext = 'ole' }
    elseif ($m4 -eq '377ABCAF')            { $r.type = '7-Zip archive'; $r.ext = '7z' }
    elseif ($m4 -eq '52617221')            { $r.type = 'RAR archive'; $r.ext = 'rar' }
    elseif ($m4 -eq '4D534346')            { $r.type = 'Cabinet archive'; $r.ext = 'cab' }
    elseif ($m4 -eq '7F454C46')            { $r.type = 'ELF binary'; $r.ext = 'elf' }
    elseif ($m4 -eq '4C000000')            { $r.type = 'Windows shortcut (LNK)'; $r.ext = 'lnk' }
    elseif ($m4 -eq '7B5C7274')            { $r.type = 'RTF document'; $r.ext = 'rtf' }
    elseif ($m4 -eq '72656766')            { $r.type = 'Registry hive'; $r.ext = 'hiv' }
    elseif ($m4.StartsWith('1F8B'))        { $r.type = 'gzip stream'; $r.ext = 'gz' }
    elseif ($m4 -eq '89504E47')            { $r.type = 'PNG image'; $r.ext = 'png' }
    elseif ($m4.StartsWith('FFD8FF'))      { $r.type = 'JPEG image'; $r.ext = 'jpg' }
    elseif ($m4 -eq 'CAFEBABE')            { $r.type = 'Java class / Mach-O fat binary' }
    elseif (Dqe-LooksUtf16 $b $o ([Math]::Min($n, 512) -band -2)) {
        $head = [Text.Encoding]::Unicode.GetString($b, $o, [Math]::Min($n, 400) -band -2)
        if ($head -match '<\?xml|<Task\b') { $r.type = 'XML text (UTF-16)'; $r.ext = 'xml' } else { $r.type = 'Text (UTF-16)'; $r.ext = 'txt' }
    }
    elseif (Dqe-LooksAscii $b $o $n) {
        $head = $script:Latin1.GetString($b, $o, [Math]::Min($n, 400))
        if     ($head -match '^\s*(\xEF\xBB\xBF)?<\?xml')                         { $r.type = 'XML text'; $r.ext = 'xml' }
        elseif ($head -match '(?i)<html|<!doctype html|<script')                 { $r.type = 'HTML / script text'; $r.ext = 'html' }
        elseif ($head -match '^#!')                                              { $r.type = 'Script with shebang'; $r.ext = 'sh' }
        elseif ($head -match '(?i)\b(function|param\s*\(|\$[a-z_]+\s*=|Write-Host|Import-Module)') { $r.type = 'Script text (PowerShell-like)'; $r.ext = 'ps1' }
        else                                                                     { $r.type = 'Text'; $r.ext = 'txt' }
    }
    $r
}

# ---------------------------------------------------------------- quarantine entry
# Quarantine\Entries\{GUID}: one file per remediation.
#   Section 1: entry GUID, scan GUID, FILETIME, threat ID, threat name (UTF-8).
#   Section 2: resource count, offsets, then per resource: UTF-16 path, field count, resource type (file, regkey,
#              service, taskscheduler, ...), and 4-byte-aligned tagged fields. Field 0x02 (20 bytes) names the payload
#              under Quarantine\ResourceData; others carry timestamps, size and the physical path.
$script:FieldNames = @{
    0x02 = 'ResourceDataId'; 0x03 = 'ResourceDataId (registry)'; 0x0A = 'Flags'; 0x0C = 'PhysicalPath'; 0x0D = 'SigSeq'
    0x0F = 'CreationTime'; 0x10 = 'LastAccessTime'; 0x11 = 'LastWriteTime'; 0x12 = 'FileSize'
    0x1B = 'ServiceAccount'; 0x1C = 'ServiceDisplayName'
}
function Dqe-ParseEntry([byte[]]$b, [string]$rel) {
    $c = Dqe-OpenSealed $b; $d1 = $c.S1; $d2 = $c.S2
    if ($d1.Length -lt 52) { throw 'metadata section too short' }
    $q = 52; while ($q -lt $d1.Length -and $d1[$q] -ne 0) { $q++ }
    $e = [ordered]@{
        id = (Dqe-Guid $d1 0); scanId = (Dqe-Guid $d1 16); time = (Dqe-Ft ([BitConverter]::ToUInt64($d1, 32)))
        threatId = [string][BitConverter]::ToUInt64($d1, 40); threat = [Text.Encoding]::UTF8.GetString($d1, 52, $q - 52)
        source = $rel; resources = (New-Object System.Collections.ArrayList)
    }
    if ($d2.Length -lt 4) { return $e }
    $cnt = [int64][BitConverter]::ToUInt32($d2, 0)
    if ($cnt -gt 8192 -or 4 + 4 * $cnt -gt $d2.Length) { throw 'resource table is not valid' }
    for ($i = 0; $i -lt $cnt; $i++) {
        $o = [int][BitConverter]::ToUInt32($d2, 4 + 4 * $i)
        $end = if ($i -lt $cnt - 1) { [int][BitConverter]::ToUInt32($d2, 8 + 4 * $i) } else { $d2.Length }
        if ($o -ge $d2.Length -or $end -gt $d2.Length -or $end -le $o) { continue }
        $w = Dqe-WStrZ $d2 $o $end; $p = $w.Next
        $res = [ordered]@{ idx = $i; type = ''; path = ($w.S -replace '^\\\\\?\\', ''); resourceId = ''; size = ''; created = ''; modified = ''; accessed = ''; fields = (New-Object System.Collections.ArrayList) }
        if ($p + 2 -le $end) {
            $fc = [BitConverter]::ToUInt16($d2, $p); $p += 2
            $t0 = $p; while ($p -lt $end -and $d2[$p] -ne 0) { $p++ }
            $res.type = [Text.Encoding]::ASCII.GetString($d2, $t0, $p - $t0); $p++
            for ($f = 0; $f -lt $fc; $f++) {
                $p = ($p + 3) -band -4
                if ($p + 4 -gt $end) { break }
                $sz = [int][BitConverter]::ToUInt16($d2, $p); $tag = [int][BitConverter]::ToUInt16($d2, $p + 2)
                $fid = $tag -band 0xFFF; $fty = $tag -shr 12; $dp = $p + 4
                if ($dp + $sz -gt $end) { break }
                $name = $script:FieldNames[$fid]; if (-not $name) { $name = 'Field_0x{0:X2}' -f $fid }
                $val = ''
                if     ($fty -eq 1) { $val = $script:Latin1.GetString($d2, $dp, $sz).TrimEnd([char]0) }
                elseif ($fty -eq 2) { $val = [Text.Encoding]::Unicode.GetString($d2, $dp, $sz - ($sz % 2)).TrimEnd([char]0) }
                elseif ($fty -eq 3 -and $sz -ge 4) { $val = '0x{0:X}' -f [BitConverter]::ToUInt32($d2, $dp) }
                elseif ($fty -eq 6 -and $sz -ge 8) {
                    $u = [BitConverter]::ToUInt64($d2, $dp)
                    if ($fid -ge 0x0F -and $fid -le 0x11) { $val = Dqe-Ft $u } else { $val = [string]$u }
                }
                elseif ($fty -eq 5 -and $sz -eq 8) { $val = '0x{0:X}' -f [BitConverter]::ToUInt64($d2, $dp) }
                else { $val = Dqe-Hex $d2 $dp $sz }
                if ($fty -eq 4 -and $sz -eq 20) { $name = 'ResourceDataId'; $res.resourceId = $val }
                elseif ($fid -eq 0x0C -and $val) { $res.path = $val }
                elseif ($fid -eq 0x0F) { $res.created = $val } elseif ($fid -eq 0x10) { $res.accessed = $val }
                elseif ($fid -eq 0x11) { $res.modified = $val } elseif ($fid -eq 0x12) { $res.size = $val }
                [void]$res.fields.Add([ordered]@{ id = ('0x{0:X2}' -f $fid); name = $name; value = $val })
                $p = $dp + $sz
            }
        }
        [void]$e.resources.Add($res)
    }
    $e
}

# ---------------------------------------------------------------- property bags (DetectionHistory blobs, History\Store)
# Defender serialises key/value sets as: [uint32 key length][UTF-16 key][uint32 type][value]. Types seen: 3 DWORD,
# 4 QWORD, 5 BOOL, 6 length-prefixed UTF-16 string, 7 and 8 length-prefixed blobs (7 can hold a hex-encoded nested
# bag). Unknown types are skipped by probing for the next valid key, so a new field never breaks the whole record.
function Dqe-BagKeyAt([byte[]]$d, [int]$q, [int]$end) {
    if ($q -eq $end) { return $true }
    if ($q + 10 -gt $end) { return $false }
    $kl = [int64][BitConverter]::ToUInt32($d, $q)
    if ($kl -lt 4 -or $kl -gt 1024 -or ($kl % 2) -ne 0 -or $q + 4 + $kl + 4 -gt $end) { return $false }
    if ($d[$q + 4 + $kl - 1] -ne 0 -or $d[$q + 4 + $kl - 2] -ne 0) { return $false }
    $c = [BitConverter]::ToUInt16($d, $q + 4)
    ($c -ge 0x20 -and $c -lt 0x7F)
}
function Dqe-BlobValue($e, [byte[]]$d, [int]$o, [int]$n, [int]$depth) {
    $e.len = $n
    if ($n -eq 0) { $e.v = ''; return }
    if ($n -gt 64) { $e.sha256 = (Dqe-Hash $d $o $n).sha256 }
    if ($e.t -eq 7 -and $n -ge 16 -and $n -le 4194304 -and ($n % 2) -eq 0 -and $depth -lt 3) {
        $s = $script:Latin1.GetString($d, $o, $n)
        if ($s -match '^[0-9A-Fa-f]+$') {
            $inner = Dqe-UnHex $s
            if ([BitConverter]::ToUInt32($inner, 0) -eq $inner.Length -and (Dqe-BagKeyAt $inner 4 $inner.Length)) {
                $e.v = '(nested property bag)'; $e.c = (Dqe-ParseBag $inner 4 $inner.Length ($depth + 1)); return
            }
        }
    }
    if (Dqe-LooksUtf16 $d $o $n) { $e.v = [Text.Encoding]::Unicode.GetString($d, $o, $n).TrimEnd([char]0); $e.enc = 'utf-16'; return }
    if (Dqe-LooksAscii $d $o $n) { $e.v = $script:Latin1.GetString($d, $o, $n).TrimEnd([char]0); $e.enc = 'ascii'; return }
    $e.enc = 'hex'
    $e.v = if ($n -le 96) { Dqe-Hex $d $o $n } else { (Dqe-Hex $d $o 96) + '...' }
}
function Dqe-ParseBag([byte[]]$d, [int]$start, [int]$end, [int]$depth = 0) {
    $out = New-Object System.Collections.ArrayList; $q = $start
    while ($q + 10 -le $end) {
        if (-not (Dqe-BagKeyAt $d $q $end)) {
            [void]$out.Add([ordered]@{ k = '(unparsed remainder)'; t = -1; v = ((Dqe-Hex $d $q ([Math]::Min(64, $end - $q))) + '...'); len = ($end - $q) }); break
        }
        $kl = [int][BitConverter]::ToUInt32($d, $q)
        $e = [ordered]@{ k = [Text.Encoding]::Unicode.GetString($d, $q + 4, $kl - 2); t = 0; v = $null }
        $q += 4 + $kl; $t = [int64][BitConverter]::ToUInt32($d, $q); $q += 4; $e.t = $t
        $bad = $false
        if     ($t -eq 3 -and $q + 4 -le $end) { $e.v = [BitConverter]::ToUInt32($d, $q); $q += 4 }
        elseif ($t -eq 4 -and $q + 8 -le $end) {
            $u = [BitConverter]::ToUInt64($d, $q); $e.v = [string]$u; $ft = Dqe-Ft $u
            if ($ft -and ($e.k -match '(?i)time|date' -or $u -gt 126227808000000000)) { $e.ft = $ft }
            $q += 8
        }
        elseif ($t -eq 5 -and $q + 1 -le $end) { $e.v = ($d[$q] -ne 0); $q += 1 }
        elseif ($t -eq 6 -and $q + 4 -le $end) {
            $l = [int64][BitConverter]::ToUInt32($d, $q)
            if ($q + 4 + $l -gt $end) { $bad = $true } else { $e.v = [Text.Encoding]::Unicode.GetString($d, $q + 4, [int]($l - ($l % 2))).TrimEnd([char]0); $q += 4 + [int]$l }
        }
        elseif (($t -eq 7 -or $t -eq 8) -and $q + 4 -le $end) {
            $l = [int64][BitConverter]::ToUInt32($d, $q)
            if ($q + 4 + $l -gt $end) { $bad = $true } else { Dqe-BlobValue $e $d ($q + 4) ([int]$l) $depth; $q += 4 + [int]$l }
        }
        else {
            $found = $false
            foreach ($cand in 8, 4, 1, 0) {
                if ($q + $cand -le $end -and (Dqe-BagKeyAt $d ($q + $cand) $end)) { $e.v = Dqe-Hex $d $q $cand; $e.enc = 'hex'; $q += $cand; $found = $true; break }
            }
            if (-not $found -and $q + 4 -le $end) {
                $l = [int64][BitConverter]::ToUInt32($d, $q)
                if ($q + 4 + $l -le $end -and (Dqe-BagKeyAt $d ([int]($q + 4 + $l)) $end)) { Dqe-BlobValue $e $d ($q + 4) ([int]$l) $depth; $q += 4 + [int]$l; $found = $true }
            }
            if (-not $found) { $bad = $true }
        }
        if ($bad) { $e.v = '(value could not be decoded)'; [void]$out.Add($e); break }
        [void]$out.Add($e)
    }
    , $out
}

# ---------------------------------------------------------------- DetectionHistory
# Scans\History\Service\DetectionHistory\NN\{GUID}: plain (unencrypted) records of [uint32 size][uint32 type][data]
# padded to 8 bytes. Type 0x15 is a UTF-16 string, 0x1E a GUID, 0x0A a FILETIME, 0x28 a property-bag blob. A header
# block (threat ID, name, severity, category, status) is followed by one block per resource, each opening with a
# "Magic.Version" marker, then a trailer with times, the quarantine entry GUID, the user and the process.
$script:ThreatStatus = @{ 0 = 'Unknown'; 1 = 'Detected'; 2 = 'Cleaned'; 3 = 'Quarantined'; 4 = 'Removed'; 5 = 'Allowed'; 6 = 'Blocked'; 102 = 'QuarantineFailed'; 103 = 'RemoveFailed'; 104 = 'AllowFailed'; 105 = 'Abandoned'; 107 = 'BlockedFailed' }
function Dqe-ParseDetectionHistory([byte[]]$b, [string]$rel) {
    $items = New-Object System.Collections.ArrayList; $p = 0
    while ($p + 8 -le $b.Length) {
        $sz = [int64][BitConverter]::ToUInt32($b, $p); $ty = [int64][BitConverter]::ToUInt32($b, $p + 4)
        if ($sz -gt $b.Length - $p - 8) { break }
        $d = $p + 8; $v = $null; $kind = 'raw'
        if     ($ty -eq 0x15)                 { $kind = 'str';  $v = [Text.Encoding]::Unicode.GetString($b, $d, [int]($sz - ($sz % 2))).TrimEnd([char]0) }
        elseif ($ty -eq 0x1E -and $sz -eq 16) { $kind = 'guid'; $v = Dqe-Guid $b $d }
        elseif ($ty -eq 0x0A -and $sz -eq 8)  { $kind = 'time'; $v = Dqe-Ft ([BitConverter]::ToUInt64($b, $d)) }
        elseif ($ty -eq 0x28)                 { $kind = 'blob' }
        elseif ($sz -eq 4)                    { $kind = 'num';  $v = [BitConverter]::ToUInt32($b, $d) }
        elseif ($sz -eq 8)                    { $kind = 'num';  $v = [string][BitConverter]::ToUInt64($b, $d) }
        else                                  { $v = Dqe-Hex $b $d ([Math]::Min([int]$sz, 64)) }
        [void]$items.Add(@{ o = $p; t = $ty; n = [int]$sz; d = $d; kind = $kind; v = $v })
        $p = [int](($p + 8 + $sz + 7) -band -8)
    }
    if ($items.Count -lt 4) { throw 'not a DetectionHistory record' }
    $r = [ordered]@{ source = $rel; detectionId = ''; threatId = ''; threat = ''; severity = ''; category = ''; status = ''
        quarantineId = ''; firstTime = ''; lastTime = ''; hashes = (New-Object System.Collections.ArrayList)
        resources = (New-Object System.Collections.ArrayList); header = (New-Object System.Collections.ArrayList); tail = (New-Object System.Collections.ArrayList) }
    $n = $items.Count; $i = 0; $magicSeen = 0; $lastBlob = -1
    for ($x = 0; $x -lt $n; $x++) { if ($items[$x].kind -eq 'blob') { $lastBlob = $x } }
    $firstRes = $n
    for ($x = 0; $x -lt $n; $x++) {
        if ($items[$x].kind -eq 'str' -and $items[$x].v -like 'Magic.Version*') { $magicSeen++; if ($magicSeen -eq 2) { $firstRes = $x; break } }
    }
    # head
    $hn = 0
    for ($x = 0; $x -lt $firstRes; $x++) {
        $it = $items[$x]
        if ($x -eq 0 -and $it.kind -eq 'num') { $r.threatId = [string]$it.v; continue }
        if ($it.kind -eq 'guid' -and -not $r.detectionId) { $r.detectionId = $it.v; continue }
        if ($it.kind -eq 'str') { if ($it.v -like 'Magic.Version*') { $r.magic = $it.v } elseif (-not $r.threat) { $r.threat = $it.v }; continue }
        if ($it.kind -eq 'num') {
            $hn++; $label = 'Header value {0}' -f $hn
            if ($hn -eq 2) { $label = 'Severity'; $r.severity = [string]$it.v }
            elseif ($hn -eq 3) { $label = 'Category'; $r.category = [string]$it.v }
            elseif ($hn -eq 6) { $label = 'Threat status (inferred)'; $st = $script:ThreatStatus[[int]$it.v]; if ($st) { $r.status = $st } }
            [void]$r.header.Add([ordered]@{ name = $label; value = [string]$it.v })
        }
    }
    # resources
    $x = $firstRes
    while ($x -lt $n -and $x -le $lastBlob) {
        $it = $items[$x]
        if ($it.kind -eq 'str' -and $it.v -like 'Magic.Version*') {
            $res = [ordered]@{ type = ''; path = ''; values = (New-Object System.Collections.ArrayList); props = $null }
            $x++
            while ($x -lt $n -and -not ($items[$x].kind -eq 'str' -and $items[$x].v -like 'Magic.Version*')) {
                $c = $items[$x]
                if ($c.kind -eq 'str') { if (-not $res.type) { $res.type = $c.v } elseif (-not $res.path) { $res.path = $c.v } else { [void]$res.values.Add([string]$c.v) } }
                elseif ($c.kind -eq 'blob') {
                    $bs = $c.d + 24; $be = $c.d + $c.n
                    if (-not (Dqe-BagKeyAt $b $bs $be)) { for ($s = $c.d; $s -lt [Math]::Min($c.d + 96, $be); $s += 4) { if (Dqe-BagKeyAt $b $s $be) { $bs = $s; break } } }
                    $res.props = Dqe-ParseBag $b $bs $be 0
                    foreach ($pe in $res.props) {
                        if ($pe.k -match '^ThreatTracking(Sha256|Sha1|MD5)$' -and $pe.v) { [void]$r.hashes.Add(([string]$pe.v).ToLower()) }
                    }
                    $x++; break
                }
                elseif ($c.kind -eq 'num') { [void]$res.values.Add(('0x{0:X}' -f [uint64]$c.v)) }
                $x++
            }
            [void]$r.resources.Add($res)
        } else { $x++ }
    }
    # tail
    $times = New-Object System.Collections.ArrayList
    for ($x = [Math]::Max($lastBlob + 1, $firstRes); $x -lt $n; $x++) {
        $it = $items[$x]
        if ($it.kind -eq 'time') { if ($it.v) { [void]$times.Add($it.v); [void]$r.tail.Add([ordered]@{ name = 'Time'; value = $it.v }) } }
        elseif ($it.kind -eq 'guid') { $r.quarantineId = $it.v; [void]$r.tail.Add([ordered]@{ name = 'Quarantine entry id'; value = $it.v }) }
        elseif ($it.kind -eq 'str' -and $it.v) {
            $label = if ($it.v -match '\\[^\\]+\.\w{2,4}$') { 'Process' } else { 'Account' }
            [void]$r.tail.Add([ordered]@{ name = $label; value = $it.v })
        }
    }
    if ($times.Count -gt 0) { $sorted = @($times | Sort-Object); $r.firstTime = $sorted[0]; $r.lastTime = $sorted[-1] }
    $r
}

# ---------------------------------------------------------------- Scans\History\Results and \Store
# Results\<kind>\{GUID}: one file per scan, sealed. Section 1 holds the scan GUID and start time; section 2 the end
# time, a schema table and, when something was found, threat names and resource records ([qword chars][type]
# [qword chars][path]). They are matched by pattern because the surrounding layout varies between platform versions.
# Store\<32 hex>: sealed property bags. In practice these are AMSI captures (script content, host process, PID) and
# scan context records (file path, process, parent PID, Mark-of-the-Web flag).
function Dqe-ParseScanResult([byte[]]$b, [string]$rel) {
    $c = Dqe-OpenSealed $b; $s1 = $c.S1; $s2 = $c.S2
    $r = [ordered]@{ source = $rel; kind = ''; scanId = ''; start = ''; end = ''; threats = (New-Object System.Collections.ArrayList); resources = (New-Object System.Collections.ArrayList) }
    if ($rel -match '(?i)/Results/([^/]+)/') { $r.kind = $Matches[1] }
    if ($s1.Length -ge 24) { $r.scanId = Dqe-Guid $s1 0; $r.start = Dqe-Ft ([BitConverter]::ToUInt64($s1, 16)) }
    if ($s2.Length -ge 16) { $e = Dqe-Ft ([BitConverter]::ToUInt64($s2, 8)); if ($e) { $r.end = $e } }
    $txt = $script:Latin1.GetString($s2)
    foreach ($m in [regex]::Matches($txt, '(?:[A-Za-z]\x00){3,24}:\x00(?:[A-Za-z0-9]\x00){2,16}/\x00(?:[\x21-\x7e]\x00){2,80}')) {
        $name = [Text.Encoding]::Unicode.GetString($script:Latin1.GetBytes($m.Value))
        if (-not $r.threats.Contains($name)) { [void]$r.threats.Add($name) }
    }
    # resource records: [qword chars][schema wstr][qword chars][path wstr]
    foreach ($m in [regex]::Matches($txt, '([\x03-\x20])\x00{7}((?:[a-z]\x00){2,31})\x00\x00')) {
        $n1 = [int][char]$m.Groups[1].Value
        if ($m.Groups[2].Length / 2 + 1 -ne $n1) { continue }
        $po = $m.Index + $m.Length
        if ($po + 8 -gt $s2.Length) { continue }
        $n2 = [BitConverter]::ToUInt64($s2, $po)
        if ($n2 -lt 2 -or $n2 -gt 4096 -or $po + 8 + 2 * $n2 -gt $s2.Length) { continue }
        $pl = [int](2 * $n2)
        if ($s2[$po + 8 + $pl - 1] -ne 0 -or $s2[$po + 8 + $pl - 2] -ne 0) { continue }
        if (-not (Dqe-LooksUtf16 $s2 ($po + 8) ($pl - 2))) { continue }
        [void]$r.resources.Add([ordered]@{ type = [Text.Encoding]::Unicode.GetString($s2, $m.Groups[2].Index, $m.Groups[2].Length); path = [Text.Encoding]::Unicode.GetString($s2, $po + 8, $pl - 2) })
    }
    $r
}
function Dqe-ParseStore([byte[]]$b, [string]$rel) {
    $c = Dqe-OpenSealed $b; $d = $c.S2
    $start = 0
    if ($d.Length -ge 4 -and [BitConverter]::ToUInt32($d, 0) -eq $d.Length) { $start = 4 }
    $bag = Dqe-ParseBag $d $start $d.Length 0
    $r = [ordered]@{ source = $rel; id = (Dqe-Leaf $rel); kind = 'Property store'; props = $bag }
    $keys = @($bag | ForEach-Object { $_.k })
    if ($keys -contains 'AMSIApp' -or $keys -contains 'AMSISession') { $r.kind = 'AMSI capture' }
    elseif (@($keys | Where-Object { $_ -like 'CONTEXT_DATA_*' }).Count -gt 0) { $r.kind = 'Scan context' }
    $r
}

# ---------------------------------------------------------------- logs
# Support\MPDetection-*.log and MPLog-*.log are UTF-16 text. Single-line events are matched on keyword then widened to
# their line (anchored multi-line regexes over a 30 MB log are an order of magnitude slower). Multi-line blocks
# (threat actions, resource scans) are captured whole. Any line that mentions a recovered file's name or hash is kept
# as a "Mention" so the timeline shows the full story around each sample.
function Dqe-DecodeText([byte[]]$b) {
    if ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) { return [Text.Encoding]::Unicode.GetString($b, 2, ($b.Length - 2) -band -2) }
    if ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) { return [Text.Encoding]::UTF8.GetString($b, 3, $b.Length - 3) }
    if (Dqe-LooksUtf16 $b 0 ([Math]::Min($b.Length, 512) -band -2)) { return [Text.Encoding]::Unicode.GetString($b, 0, $b.Length -band -2) }
    [Text.Encoding]::UTF8.GetString($b)
}
function Dqe-BlockTime([string]$s) {
    if ($s -match '(\d\d)-(\d\d)-(\d{4})\s+(\d\d:\d\d:\d\d)') { return ('{0}-{1}-{2} {3}' -f $Matches[3], $Matches[1], $Matches[2], $Matches[4]) }
    ''
}
function Dqe-HitLines([string]$text, $rx, [int]$max) {
    $out = New-Object System.Collections.ArrayList; $last = -1
    foreach ($m in $rx.Matches($text)) {
        $ls = $text.LastIndexOf("`n", $m.Index) + 1
        if ($ls -eq $last) { continue }
        $last = $ls
        $le = $text.IndexOf("`n", $m.Index); if ($le -lt 0) { $le = $text.Length }
        [void]$out.Add($text.Substring($ls, $le - $ls).TrimEnd())
        if ($out.Count -ge $max) { break }
    }
    , $out
}
function Dqe-Blocks([string]$text, [string]$begin, [string]$end, [int]$maxBody = 65536) {
    # Returns the text between each $begin marker and the next $end marker. Located with IndexOf, which is linear, and
    # an unterminated block is abandoned after $maxBody characters, so a crafted log cannot make parsing quadratic.
    $out = New-Object System.Collections.ArrayList; $pos = 0; $cmp = [StringComparison]::Ordinal
    while ($pos -lt $text.Length) {
        $b = $text.IndexOf($begin, $pos, $cmp); if ($b -lt 0) { break }
        $bodyStart = $b + $begin.Length
        $window = [Math]::Min($maxBody, $text.Length - $bodyStart)
        $e = $text.IndexOf($end, $bodyStart, $window, $cmp)
        if ($e -lt 0) { $pos = $bodyStart; continue }
        [void]$out.Add($text.Substring($bodyStart, $e - $bodyStart).Trim())
        $pos = $e + $end.Length
        if ($out.Count -ge 5000) { break }
    }
    , $out
}

function Dqe-ParseLog([string]$text, [string]$name, $needleRx, $ctx) {
    $ev = $ctx.Events; $opt = [Text.RegularExpressions.RegexOptions]'Multiline'
    $ts = '^\uFEFF?(?<ts>\d{4}-\d\d-\d\d)T(?<tm>\d\d:\d\d:\d\d(?:\.\d+)?)\S*[ \t]+'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $add = {
        param($t, $k, $x, $d)
        if ($seen.Add("$t|$x")) { $o = [ordered]@{ t = $t; k = $k; src = $name; x = $x }; if ($d) { $o.d = $d }; [void]$ev.Add($o) }
    }
    foreach ($m in [regex]::Matches($text, $ts + '(?<rest>(?:DETECTIONEVENT|DETECTION_CLEANEVENT|DETECTION_ADD|DETECTION |\[RTP\] \[Mini-filter\] Blocked file|SDN:Issuing SDN query|Using SDA action)[^\r\n]*)', $opt)) {
        $rest = $m.Groups['rest'].Value; $t = $m.Groups['ts'].Value + ' ' + $m.Groups['tm'].Value
        $k = if ($rest.StartsWith('DETECTIONEVENT')) { 'Detection event' } elseif ($rest.StartsWith('DETECTION_CLEANEVENT')) { 'Remediation' }
             elseif ($rest.StartsWith('DETECTION_ADD')) { 'Detection added' } elseif ($rest.StartsWith('DETECTION ')) { 'Detection' }
             elseif ($rest.StartsWith('[RTP]')) { 'Blocked file' } elseif ($rest.StartsWith('SDN:')) { 'Cloud lookup' } else { 'Action selected' }
        & $add $t $k $rest $null
    }
    $lineRx = '^\uFEFF?(\d{4}-\d\d-\d\d)T(\d\d:\d\d:\d\d(?:\.\d+)?)\S*[ \t]+(.*)$'
    foreach ($line in (Dqe-HitLines $text ([regex]'Engine VFZ block|reported as lowfi:|\[Exclusion\]') 5000)) {
        $tm = [regex]::Match($line, $lineRx); if (-not $tm.Success) { continue }
        $rest = $tm.Groups[3].Value; $t = $tm.Groups[1].Value + ' ' + $tm.Groups[2].Value
        if ($rest.Contains('[Exclusion]')) { if ($ctx.Exclusions.Add($rest)) { & $add $t 'Exclusion' $rest $null } }
        elseif ($rest.Contains('lowfi:')) { & $add $t 'Low-fidelity signal' $rest $null }
        else { & $add $t 'Engine block' $rest $null }
    }
    foreach ($body in (Dqe-Blocks $text 'Beginning threat actions' 'Finished threat actions')) {
        $t = Dqe-BlockTime ([regex]::Match($body, 'Start time:[^\r\n]*').Value)
        $thr = [regex]::Match($body, 'Threat Name:([^\r\n]*)').Groups[1].Value; $act = [regex]::Match($body, '(?m)^Action:([^\r\n]*)').Groups[1].Value
        $cnt = [regex]::Matches($body, 'Resource action complete:').Count
        if ($body.Length -gt 6000) { $body = $body.Substring(0, 6000) + "`r`n..." }
        & $add $t 'Threat actions' ('{0}  action={1}  resources={2}' -f $thr, $act, $cnt) $body
    }
    foreach ($body in (Dqe-Blocks $text 'Begin Resource Scan' 'End Scan')) {
        if ($body -notmatch 'Threat Name:') { continue }
        $t = Dqe-BlockTime ([regex]::Match($body, 'Start Time:[^\r\n]*').Value)
        $thr = [regex]::Match($body, 'Threat Name:([^\r\n]*)').Groups[1].Value; $sid = [regex]::Match($body, 'Scan ID:([^\r\n]*)').Groups[1].Value
        if ($body.Length -gt 6000) { $body = $body.Substring(0, 6000) + "`r`n..." }
        & $add $t 'Scan with detection' ('{0}  scan {1}' -f $thr, $sid) $body
    }
    foreach ($m in [regex]::Matches($text, '(?:file|containerfile):(?<p>[^;\r\n]{0,2048}?)\s+SHA1:(?<s1>[0-9a-fA-F]{40})(?:\s+MD5:(?<m5>[0-9a-fA-F]{32}))?\s+SHA256:(?<s2>[0-9a-fA-F]{64})')) {
        $h2 = $m.Groups['s2'].Value.ToLower(); [void]$ctx.Hashes.Add($h2); [void]$ctx.Hashes.Add($m.Groups['s1'].Value.ToLower())
        $pth = $m.Groups['p'].Value.Trim().ToLower(); if ($pth -and $pth -notmatch '->\(' -and -not $ctx.PathHash.ContainsKey($pth)) { $ctx.PathHash[$pth] = $h2 }
    }
    foreach ($m in [regex]::Matches($text, 'FileName:[^\r\n]+\r?\n\s*SHA1:(?<s1>[0-9a-fA-F]{40})')) { [void]$ctx.Hashes.Add($m.Groups['s1'].Value.ToLower()) }
    $vms = [regex]::Matches($text, '(\d{4}-\d\d-\d\d)T(\d\d:\d\d:\d\d)\S*[ \t]+Version: Product (\S+) Service (\S+) Engine (\S+) AS (\S+) AV (\S+)')
    if ($vms.Count -gt 0) {
        $vm = $vms[$vms.Count - 1]; $stamp = $vm.Groups[1].Value + ' ' + $vm.Groups[2].Value
        if (-not $ctx.Version -or $stamp -gt $ctx.Version.asOf) {
            $ctx.Version = [ordered]@{ asOf = $stamp; product = $vm.Groups[3].Value; service = $vm.Groups[4].Value; engine = $vm.Groups[5].Value; antispyware = $vm.Groups[6].Value; antivirus = $vm.Groups[7].Value; source = $name }
        }
    }
    if ($needleRx) {
        $c = 0
        foreach ($line in (Dqe-HitLines $text $needleRx 4000)) {
            $tm = [regex]::Match($line, $lineRx)
            if (-not $tm.Success) { continue }
            if ($tm.Groups[3].Value.StartsWith('ProcessImageName:')) { continue }
            & $add ($tm.Groups[1].Value + ' ' + $tm.Groups[2].Value) 'Mention' $tm.Groups[3].Value $null
            $c++; if ($c -ge 400) { Dqe-Log "$name : more than 400 lines mention the quarantined items; the rest are only in the raw log." 'warn'; break }
        }
    }
}

# ---------------------------------------------------------------- encrypted zip writer (no temp files, nothing plain on disk)
# Each entry is compressed in memory (GZipStream, header and trailer stripped to leave raw DEFLATE and its CRC-32),
# encrypted in memory, and only then written. AES-256 follows the WinZip AE-2 specification: PBKDF2-SHA1 key
# derivation, AES-CTR with a little-endian counter starting at 1, and a 10-byte HMAC-SHA1 authentication code.
# The counter blocks are precomputed once so AES runs as a single native ECB call per entry.
function Dqe-EnsureCtr([int]$blocks) {
    if ($blocks -le $script:CtrBlocks) { return }
    $have = $script:CtrBlocks
    $nb = New-Object byte[] ($blocks * 16)
    if ($have -gt 0) { [Buffer]::BlockCopy($script:CtrBytes, 0, $nb, 0, $have * 16) }
    $add = $blocks - $have; $ints = New-Object int[] ($add * 4); $first = $have + 1
    for ($k = 0; $k -lt $add; $k++) { $ints[$k * 4] = $first + $k }
    [Buffer]::BlockCopy($ints, 0, $nb, $have * 16, $add * 16)
    $script:CtrBytes = $nb; $script:CtrBlocks = $blocks
}
function Dqe-AesCtr([byte[]]$data, [byte[]]$key) {
    $n = $data.Length
    if ($n -eq 0) { return , (New-Object byte[] 0) }
    $blocks = [int][Math]::Ceiling($n / 16); Dqe-EnsureCtr $blocks
    $aes = [Security.Cryptography.Aes]::Create()
    try {
        $aes.Mode = [Security.Cryptography.CipherMode]::ECB; $aes.Padding = [Security.Cryptography.PaddingMode]::None
        $aes.KeySize = $key.Length * 8; $aes.Key = $key
        $enc = $aes.CreateEncryptor(); $ks = $enc.TransformFinalBlock($script:CtrBytes, 0, $blocks * 16); $enc.Dispose()
    } finally { $aes.Dispose() }
    $r = Dqe-Xor $data 0 $ks 0 $n
    , $r
}
function Dqe-ZipCrypto([byte[]]$payload, [byte[]]$pw, [uint32]$crc) {
    # Legacy PKWARE encryption, for receivers whose tools cannot open AES. Weak by design; offered only for compatibility.
    $T = Dqe-CrcTable; [long]$k0 = 305419896; [long]$k1 = 591751049; [long]$k2 = 878082192
    foreach ($c in $pw) {
        $k0 = $T[($k0 -bxor $c) -band 255] -bxor ($k0 -shr 8)
        $k1 = (($k1 + ($k0 -band 255)) * 134775813 + 1) -band 4294967295
        $k2 = $T[($k2 -bxor ($k1 -shr 24)) -band 255] -bxor ($k2 -shr 8)
    }
    $n = $payload.Length; $out = New-Object byte[] ($n + 12)
    $hdr = New-Object byte[] 12; (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($hdr); $hdr[11] = [byte](($crc -shr 24) -band 255)
    $total = $n + 12
    for ($i = 0; $i -lt $total; $i++) {
        $p = if ($i -lt 12) { $hdr[$i] } else { $payload[$i - 12] }
        $tt = ($k2 -bor 2) -band 65535
        $out[$i] = $p -bxor ((($tt * ($tt -bxor 1)) -shr 8) -band 255)
        $k0 = $T[($k0 -bxor $p) -band 255] -bxor ($k0 -shr 8)
        $k1 = (($k1 + ($k0 -band 255)) * 134775813 + 1) -band 4294967295
        $k2 = $T[($k2 -bxor ($k1 -shr 24)) -band 255] -bxor ($k2 -shr 8)
        if (($i -band 262143) -eq 262143) { Dqe-Stage ('Legacy ZipCrypto  {0:N1} of {1:N1} MB' -f ($i / 1MB), ($total / 1MB)) }
    }
    , $out
}
function Dqe-ZipOpen([string]$path, [string]$mode, [string]$password) {
    $fs = New-Object IO.FileStream($path, [IO.FileMode]::Create, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None, 1048576)
    @{ Path = $path; Fs = $fs; Bw = (New-Object IO.BinaryWriter($fs)); Mode = $mode; Pw = [Text.Encoding]::UTF8.GetBytes($password); Entries = (New-Object System.Collections.ArrayList); Names = (New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)) }
}
function Dqe-ZipEntryName([string]$name) {
    # Names inside the output archive come partly from the evidence (original paths, archive entry names). Each
    # segment is cleaned, and empty, "." and ".." segments, drive letters and leading slashes are dropped, so no
    # extraction tool can be led to write outside its target folder.
    $parts = foreach ($seg in ($name -split '[\\/]+')) {
        if (-not $seg -or $seg -eq '.' -or $seg -eq '..') { continue }
        Dqe-SafeName $seg 120
    }
    $n = @($parts) -join '/'
    if (-not $n) { $n = 'unnamed' }
    if ($n.Length -gt 900) { $n = $n.Substring($n.Length - 900).TrimStart('/') }
    $n
}

function Dqe-ZipAdd($z, [string]$name, [byte[]]$data, [datetime]$time, [string]$sha256 = '') {
    $name = Dqe-ZipEntryName $name
    if (-not $z.Names.Add($name)) {
        $dot = $name.LastIndexOf('.'); $sl = $name.LastIndexOf('/'); $n2 = 2
        do { $cand = if ($dot -gt $sl) { $name.Substring(0, $dot) + "~$n2" + $name.Substring($dot) } else { "$name~$n2" }; $n2++ } while (-not $z.Names.Add($cand))
        $name = $cand
    }
    $n = $data.Length; [uint32]$crc = 0; $method = 0; $payload = $data
    if ($n -gt 0) {
        $ms = New-Object IO.MemoryStream
        $gz = New-Object IO.Compression.GZipStream($ms, [IO.Compression.CompressionLevel]::Optimal, $true)
        $gz.Write($data, 0, $n); $gz.Dispose()
        $g = $ms.GetBuffer(); $gl = [int]$ms.Length
        $crc = [BitConverter]::ToUInt32($g, $gl - 8)
        $hl = 10; $fl = $g[3]
        if ($fl -band 4) { $hl += 2 + [BitConverter]::ToUInt16($g, $hl) }
        if ($fl -band 8) { while ($g[$hl] -ne 0) { $hl++ }; $hl++ }
        if ($fl -band 16) { while ($g[$hl] -ne 0) { $hl++ }; $hl++ }
        if ($fl -band 2) { $hl += 2 }
        $dl = $gl - $hl - 8
        if ($dl -lt $n) { $method = 8; $payload = New-Object byte[] $dl; [Buffer]::BlockCopy($g, $hl, $payload, 0, $dl) }
        $ms.Dispose(); $g = $null
    }
    $nameB = [Text.Encoding]::UTF8.GetBytes($name)
    $extra = New-Object byte[] 0; $verNeed = 20; $hdrMethod = $method; [uint32]$hdrCrc = $crc
    if ($z.Mode -eq 'aes') {
        $salt = New-Object byte[] 16; (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($salt)
        $kdf = New-Object Security.Cryptography.Rfc2898DeriveBytes($z.Pw, $salt, 1000); $km = $kdf.GetBytes(66); $kdf.Dispose()
        $ek = New-Object byte[] 32; [Buffer]::BlockCopy($km, 0, $ek, 0, 32); $mk = New-Object byte[] 32; [Buffer]::BlockCopy($km, 32, $mk, 0, 32)
        $ct = Dqe-AesCtr $payload $ek
        $hm = New-Object Security.Cryptography.HMACSHA1 (, $mk); $mac = $hm.ComputeHash($ct); $hm.Dispose()
        $body = New-Object byte[] ($ct.Length + 28)
        [Buffer]::BlockCopy($salt, 0, $body, 0, 16); $body[16] = $km[64]; $body[17] = $km[65]
        [Buffer]::BlockCopy($ct, 0, $body, 18, $ct.Length); [Buffer]::BlockCopy($mac, 0, $body, 18 + $ct.Length, 10)
        $extra = [byte[]](0x01, 0x99, 0x07, 0x00, 0x02, 0x00, 0x41, 0x45, 0x03, $method, 0x00)
        $verNeed = 51; $hdrMethod = 99; $hdrCrc = 0; $ct = $null
    } else {
        $body = Dqe-ZipCrypto $payload $z.Pw $crc
    }
    $payload = $null
    $off = $z.Fs.Position
    if ($off + $body.Length + 4096 -gt 4294000000) { throw 'The archive would exceed the 4 GB zip limit. Reduce the raw export scope.' }
    $dosT = [uint16](($time.Hour -shl 11) -bor ($time.Minute -shl 5) -bor [int]($time.Second / 2))
    $yr = [Math]::Max(1980, [Math]::Min(2107, $time.Year)); $dosD = [uint16]((($yr - 1980) -shl 9) -bor ($time.Month -shl 5) -bor $time.Day)
    $bw = $z.Bw
    $bw.Write([uint32]0x04034b50); $bw.Write([uint16]$verNeed); $bw.Write([uint16]0x0801); $bw.Write([uint16]$hdrMethod)
    $bw.Write($dosT); $bw.Write($dosD); $bw.Write([uint32]$hdrCrc); $bw.Write([uint32]$body.Length); $bw.Write([uint32]$n)
    $bw.Write([uint16]$nameB.Length); $bw.Write([uint16]$extra.Length); $bw.Write($nameB); $bw.Write($extra)
    $dataOff = $z.Fs.Position
    $bw.Write($body)
    [void]$z.Entries.Add(@{ Name = $name; NameB = $nameB; Extra = $extra; Ver = $verNeed; Method = $hdrMethod; Real = $method; Crc = $hdrCrc; CSize = $body.Length; USize = $n; Off = $off; DataOff = $dataOff; T = $dosT; D = $dosD; Sha256 = $sha256 })
    $name
}
function Dqe-ZipClose($z) {
    $bw = $z.Bw; $cdOff = $z.Fs.Position
    foreach ($e in $z.Entries) {
        $bw.Write([uint32]0x02014b50); $bw.Write([uint16]$e.Ver); $bw.Write([uint16]$e.Ver); $bw.Write([uint16]0x0801); $bw.Write([uint16]$e.Method)
        $bw.Write([uint16]$e.T); $bw.Write([uint16]$e.D); $bw.Write([uint32]$e.Crc); $bw.Write([uint32]$e.CSize); $bw.Write([uint32]$e.USize)
        $bw.Write([uint16]$e.NameB.Length); $bw.Write([uint16]$e.Extra.Length); $bw.Write([uint16]0); $bw.Write([uint16]0); $bw.Write([uint16]0)
        $bw.Write([uint32]0); $bw.Write([uint32]$e.Off); $bw.Write($e.NameB); $bw.Write($e.Extra)
    }
    $cdSize = $z.Fs.Position - $cdOff
    if ($z.Entries.Count -gt 65000) { throw 'Too many files for a standard zip (limit 65,000). Reduce the raw export scope.' }
    $bw.Write([uint32]0x06054b50); $bw.Write([uint16]0); $bw.Write([uint16]0); $bw.Write([uint16]$z.Entries.Count); $bw.Write([uint16]$z.Entries.Count)
    $bw.Write([uint32]$cdSize); $bw.Write([uint32]$cdOff); $bw.Write([uint16]0)
    $bw.Flush(); $z.Fs.Flush()
}
function Dqe-ZipVerify($z) {
    # Proves the archive is usable before the analyst relies on it: every recovered file is read back from disk, its
    # authentication code checked, decrypted and inflated in memory, and its SHA-256 compared with the original.
    $bad = 0; $checked = 0
    if ($z.Mode -ne 'aes') { return @{ Checked = -1; Bad = 0 } }
    foreach ($e in $z.Entries) {
        if (-not $e.Sha256) { continue }
        $checked++
        try {
            $buf = New-Object byte[] $e.CSize; $z.Fs.Position = $e.DataOff; $p = 0
            while ($p -lt $buf.Length) { $r = $z.Fs.Read($buf, $p, $buf.Length - $p); if ($r -le 0) { break }; $p += $r }
            $salt = New-Object byte[] 16; [Buffer]::BlockCopy($buf, 0, $salt, 0, 16)
            $kdf = New-Object Security.Cryptography.Rfc2898DeriveBytes($z.Pw, $salt, 1000); $km = $kdf.GetBytes(66); $kdf.Dispose()
            if ($km[64] -ne $buf[16] -or $km[65] -ne $buf[17]) { throw 'password check value differs' }
            $ek = New-Object byte[] 32; [Buffer]::BlockCopy($km, 0, $ek, 0, 32); $mk = New-Object byte[] 32; [Buffer]::BlockCopy($km, 32, $mk, 0, 32)
            $cl = $buf.Length - 28; $ct = New-Object byte[] $cl; [Buffer]::BlockCopy($buf, 18, $ct, 0, $cl)
            $hm = New-Object Security.Cryptography.HMACSHA1 (, $mk); $mac = $hm.ComputeHash($ct); $hm.Dispose()
            for ($i = 0; $i -lt 10; $i++) { if ($mac[$i] -ne $buf[18 + $cl + $i]) { throw 'authentication code differs' } }
            $pt = Dqe-AesCtr $ct $ek
            if ($e.Real -eq 8) {
                $out = New-Object IO.MemoryStream
                $ds = New-Object IO.Compression.DeflateStream((New-Object IO.MemoryStream (, $pt)), [IO.Compression.CompressionMode]::Decompress)
                $ds.CopyTo($out); $ds.Dispose(); $pt = $out.ToArray(); $out.Dispose()
            }
            if ((Dqe-Hash $pt 0 $pt.Length).sha256 -ne $e.Sha256) { throw 'SHA-256 differs from the original' }
        } catch { $bad++; Dqe-Log "Archive check failed for $($e.Name): $($_.Exception.Message)" 'error' }
    }
    $z.Fs.Position = $z.Fs.Length
    @{ Checked = $checked; Bad = $bad }
}

# ---------------------------------------------------------------- phase 1: load
# Lists every source item, recognises Defender artifacts and reads the quarantine entries, which is enough to show
# what can be recovered. Payloads, history and logs are only decrypted in phase 2.
function Dqe-Load([string[]]$paths, [string[]]$passwords) {
    Dqe-Stage 'Indexing source' 2
    $script:Notes.Clear()
    $script:UserPasswords = @($passwords | Where-Object { $null -ne $_ })
    $src = Dqe-OpenSource $paths
    $by = @{}; foreach ($it in $src.Items) { if (-not $by.ContainsKey($it.Kind)) { $by[$it.Kind] = New-Object System.Collections.ArrayList }; [void]$by[$it.Kind].Add($it) }
    $resData = @{}; foreach ($it in @($by['resdata'])) { if ($it) { $id = $it.ResId; if (-not $resData.ContainsKey($id)) { $resData[$id] = $it } } }
    $entries = New-Object System.Collections.ArrayList; $rows = New-Object System.Collections.ArrayList; $used = @{}
    $list = @($by['entry'] | Where-Object { $_ }); $n = 0
    foreach ($it in $list) {
        $n++; Dqe-Stage ("Reading quarantine entry $n of $($list.Count)") (5 + 85 * $n / [Math]::Max(1, $list.Count))
        try {
            $e = Dqe-ParseEntry (Dqe-Read $it) $it.Rel; [void]$entries.Add($e)
            foreach ($r in $e.resources) {
                $payload = 'None'; $len = 0
                if ($r.resourceId) {
                    if ($resData.ContainsKey($r.resourceId)) { $used[$r.resourceId] = $true; $len = $resData[$r.resourceId].Len; $payload = if ($r.type -match '^(file|containerfile)$') { 'File' } else { 'Registry hive' } }
                    else { $payload = 'Missing' }
                }
                [void]$rows.Add(@{ Key = "$($e.id)|$($r.idx)"; Threat = $e.threat; Type = $r.type; Path = $r.path; Size = $len; Detected = $e.time; Payload = $payload; ResourceId = $r.resourceId })
            }
        } catch { Dqe-Log "Quarantine entry $($it.Rel) could not be read: $($_.Exception.Message)" 'warn' }
    }
    foreach ($id in $resData.Keys) {
        if (-not $used.ContainsKey($id)) { [void]$rows.Add(@{ Key = "orphan|$id"; Threat = '(no entry metadata)'; Type = 'orphan'; Path = $id; Size = $resData[$id].Len; Detected = ''; Payload = 'File'; ResourceId = $id }) }
    }
    $counts = [ordered]@{}
    foreach ($k in 'entry', 'resdata', 'dh', 'store', 'result', 'mpdet', 'mplog', 'evtx', 'container') { $counts[$k] = @($by[$k] | Where-Object { $_ }).Count }
    Dqe-Log ('Found {0} quarantine entr{1}, {2} stored payload(s), {3} detection history record(s), {4} scan record(s), {5} log(s){6}.' -f `
        $counts['entry'], $(if ($counts['entry'] -eq 1) { 'y' } else { 'ies' }), $counts['resdata'], $counts['dh'], ($counts['result'] + $counts['store']), ($counts['mpdet'] + $counts['mplog'] + $counts['evtx']),
        $(if ($counts['container']) { " across $($counts['container']) nested archive(s)" } else { '' }))
    if ($src.Items.Count -gt 0 -and ($counts['entry'] + $counts['resdata'] + $counts['dh'] + $counts['mpdet'] + $counts['mplog'] + $counts['evtx']) -eq 0) {
        Dqe-Log 'No Microsoft Defender artifacts were recognised in this source. Expected Quarantine, Scans\History or Support folders from ProgramData\Microsoft\Windows Defender.' 'warn'
    }
    Dqe-Stage 'Ready' 100
    # Warnings raised while loading (passwords, nesting, unreadable items) are kept for the report.
    @{ Src = $src; By = $by; ResData = $resData; Entries = $entries; Rows = $rows; Counts = $counts; LoadNotes = @($script:Notes) }
}

# ---------------------------------------------------------------- phase 2: generate
# Decrypts the selected payloads, decodes every other artifact, builds the timeline, writes the encrypted archive and
# the report, then verifies the archive. On any failure the partial archive is deleted.
function Dqe-Csv($rows, [string[]]$cols) {
    $sb = New-Object Text.StringBuilder; [void]$sb.AppendLine(($cols -join ','))
    foreach ($r in $rows) {
        [void]$sb.AppendLine((($cols | ForEach-Object {
            $v = ([string]$r[$_]).Replace("`r", ' ').Replace("`n", ' ')
            if ($v -match '^[=+\-@\t]') { $v = "'" + $v }   # stops spreadsheet formula execution from evidence text
            '"' + $v.Replace('"', '""') + '"'
        }) -join ','))
    }
    $sb.ToString()
}
function Dqe-Utf8([string]$s) { , ([Text.Encoding]::UTF8.GetBytes($s)) }
function Dqe-Generate($M, $O) {
    $src = $M.Src; $by = $M.By; $now = [DateTime]::UtcNow; $script:Notes.Clear()
    foreach ($n in @($M.LoadNotes)) { if ($n) { [void]$script:Notes.Add($n) } }
    $sel = New-Object 'System.Collections.Generic.HashSet[string]'; foreach ($k in $O.Selected) { [void]$sel.Add($k) }
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $first = [IO.Path]::GetFileNameWithoutExtension(($src.Inputs[0].name -replace '(?i)\.gz(ip)?$', ''))
    $baseName = Dqe-SafeName ($(if ($O.CaseId) { $O.CaseId } else { $first }) + '_defender-quarantine_' + $stamp) 100
    if (-not [IO.Directory]::Exists($O.OutDir)) { [void][IO.Directory]::CreateDirectory($O.OutDir) }
    $zipPath = Join-Path $O.OutDir ($baseName + '.zip'); $reportPath = Join-Path $O.OutDir ($baseName + '.html')
    $z = Dqe-ZipOpen $zipPath $O.Encryption $O.Password
    $perDir = $null; $perZips = New-Object System.Collections.ArrayList
    $ok = $false
    try {
        # ---- which payloads
        $jobs = New-Object System.Collections.ArrayList; $seenRes = @{}
        foreach ($e in $M.Entries) { foreach ($r in $e.resources) {
            if (-not $r.resourceId -or -not $sel.Contains("$($e.id)|$($r.idx)")) { continue }
            if (-not $M.ResData.ContainsKey($r.resourceId)) { continue }
            if ($seenRes.ContainsKey($r.resourceId)) { [void]$seenRes[$r.resourceId].Links.Add(@{ E = $e; R = $r }); continue }
            $j = @{ Id = $r.resourceId; Item = $M.ResData[$r.resourceId]; Links = (New-Object System.Collections.ArrayList) }; [void]$j.Links.Add(@{ E = $e; R = $r })
            $seenRes[$r.resourceId] = $j; [void]$jobs.Add($j)
        } }
        foreach ($id in $M.ResData.Keys) { if ($sel.Contains("orphan|$id")) { [void]$jobs.Add(@{ Id = $id; Item = $M.ResData[$id]; Links = (New-Object System.Collections.ArrayList) }) } }

        # ---- keystream: derived up front only for items whose length is known for certain (files on disk or already in
        # memory). Sizes declared inside a zip are not trusted for this; those items extend the keystream on demand, by
        # the number of bytes actually read.
        $maxLen = 65536
        foreach ($j in $jobs) { if ($j.Item.Via -ne 'zip' -and $j.Item.Len -gt $maxLen -and $j.Item.Len -le $script:MaxItemBytes) { $maxLen = $j.Item.Len } }
        foreach ($k in 'store', 'result', 'entry', 'resmeta') { foreach ($it in @($by[$k] | Where-Object { $_ })) { if ($it.Via -ne 'zip' -and $it.Len -gt $maxLen -and $it.Len -le $script:MaxMetaBytes) { $maxLen = $it.Len } } }
        Dqe-Log ('{0} item(s) selected.' -f $jobs.Count)
        Dqe-Stage 'Preparing decryption' 3
        Dqe-KeyStream ([int]$maxLen)

        # ---- payloads
        $samples = New-Object System.Collections.ArrayList; $hives = New-Object System.Collections.ArrayList
        $needles = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        Dqe-Log 'Recovering quarantined items.'
        $n = 0
        foreach ($j in $jobs) {
            $n++; Dqe-Stage ("Recovering payload $n of $($jobs.Count)") (20 + 30 * $n / [Math]::Max(1, $jobs.Count))
            try {
                $raw = Dqe-Read $j.Item; $dec = Dqe-Rc4 $raw 0 $raw.Length; $raw = $null
                $link = if ($j.Links.Count) { $j.Links[0] } else { $null }
                $origPath = if ($link) { $link.R.path } else { '' }
                $leaf = if ($origPath) { Dqe-SafeName (Dqe-Leaf $origPath) } else { $j.Id }
                $threat = if ($link) { $link.E.threat } else { '' }; $etime = if ($link) { $link.E.time } else { '' }
                $ftime = $now; if ($link -and $link.R.modified) { try { $ftime = [DateTime]::ParseExact($link.R.modified, 'yyyy-MM-dd HH:mm:ss.fff', $null) } catch { } }
                if ($dec.Length -ge 4 -and $dec[0] -eq 0x72 -and $dec[1] -eq 0x65 -and $dec[2] -eq 0x67 -and $dec[3] -eq 0x66) {
                    $h = Dqe-Hash $dec 0 $dec.Length
                    $zn = Dqe-ZipAdd $z ("registry/{0}_{1}.hiv" -f $j.Id.Substring(0, 8), (Dqe-SafeName $leaf 60)) $dec $now $h.sha256
                    [void]$hives.Add([ordered]@{ resourceId = $j.Id; type = $(if ($link) { $link.R.type } else { '' }); path = $origPath; threat = $threat; quarantined = $etime; size = $dec.Length; sha256 = $h.sha256; archivePath = $zn; source = $j.Item.Rel })
                    continue
                }
                # backup-stream container
                $streams = New-Object System.Collections.ArrayList; $p = 0; $main = $null; $valid = $true
                while ($p + 20 -le $dec.Length) {
                    $sid = [int64][BitConverter]::ToUInt32($dec, $p); $ssz = [BitConverter]::ToUInt64($dec, $p + 8); $nl = [int64][BitConverter]::ToUInt32($dec, $p + 16)
                    if ($sid -lt 1 -or $sid -gt 11 -or $nl -gt 1024 -or $p + 20 + $nl -gt $dec.Length) { if ($streams.Count -eq 0) { $valid = $false }; break }
                    $sname = if ($nl -gt 0) { [Text.Encoding]::Unicode.GetString($dec, $p + 20, [int]$nl) } else { '' }
                    $do = $p + 20 + [int]$nl; $avail = $dec.Length - $do; $trunc = $false
                    if ($ssz -gt $avail) { $ssz = $avail; $trunc = $true }
                    $st = @{ Id = [int]$sid; Name = $sname; Off = $do; Len = [int]$ssz; Trunc = $trunc }; [void]$streams.Add($st)
                    if ($sid -eq 1 -and -not $main) { $main = $st }
                    $p = $do + [int]$ssz
                }
                $s = [ordered]@{ resourceId = $j.Id; name = $leaf; path = $origPath; threat = $threat; quarantined = $etime
                    size = 0; md5 = ''; sha1 = ''; sha256 = ''; type = ''; pe = $null; hashCheck = 'no reference'; hashNote = ''; recordedSha256 = ''; recordedKind = ''
                    created = $(if ($link) { $link.R.created } else { '' }); modified = $(if ($link) { $link.R.modified } else { '' }); accessed = $(if ($link) { $link.R.accessed } else { '' })
                    archivePath = ''; sampleZip = ''; source = $j.Item.Rel; container = 'backup streams'; truncated = $false
                    entries = @($j.Links | ForEach-Object { $_.E.id }); streams = (New-Object System.Collections.ArrayList) }
                if (-not $valid -or -not $main) {
                    $s.container = 'unrecognised (whole decrypted blob exported)'; $buf = $dec; $bo = 0; $bl = $dec.Length
                    Dqe-Log "Payload $($j.Id): stream layout not recognised; exported the decrypted blob as-is." 'warn'
                } else { $bo = $main.Off; $bl = $main.Len; $s.truncated = $main.Trunc
                    if ($main.Trunc) { Dqe-Log "Payload $($j.Id): data stream is shorter than its header says; the recovered file is truncated." 'warn' } }
                $data = New-Object byte[] $bl; [Buffer]::BlockCopy($dec, $bo, $data, 0, $bl)
                $h = Dqe-Hash $data 0 $bl; $sn = Dqe-Sniff $data 0 $bl
                $s.size = $bl; $s.md5 = $h.md5; $s.sha1 = $h.sha1; $s.sha256 = $h.sha256; $s.type = $sn.type; $s.pe = $sn.pe
                if (-not $link -and $sn.ext) { $leaf = "$leaf.$($sn.ext)"; $s.name = $leaf }
                $s.archivePath = Dqe-ZipAdd $z ("samples/$leaf") $data $ftime $h.sha256
                if ($O.PerSample) {
                    if (-not $perDir) { $perDir = Join-Path $O.OutDir ($baseName + '_samples'); [void][IO.Directory]::CreateDirectory($perDir) }
                    $pzPath = Join-Path $perDir ((Dqe-SafeName ("{0}_{1}" -f $h.sha256.Substring(0, 12), $leaf) 90) + '.zip')
                    $pz = Dqe-ZipOpen $pzPath $O.Encryption $O.Password
                    try { [void](Dqe-ZipAdd $pz $leaf $data $ftime $h.sha256); Dqe-ZipClose $pz; if ($O.Verify) { $vr = Dqe-ZipVerify $pz; if ($vr.Bad) { throw 'archive verification failed' } } } finally { $pz.Bw.Dispose() }
                    $s.sampleZip = [IO.Path]::GetFileName($pzPath); [void]$perZips.Add([ordered]@{ file = $s.sampleZip; sha256 = (Dqe-FileSha256 $pzPath); size = (New-Object IO.FileInfo $pzPath).Length })
                }
                $data = $null; $eaHex = ''
                foreach ($st in $streams) {
                    if ($st -eq $main) { continue }
                    $label = switch ($st.Id) { 1 { 'data' } 2 { 'extended attributes' } 3 { 'security descriptor' } 4 { 'alternate data stream' } 5 { 'hard link' } 6 { 'property data' } 7 { 'object id' } 8 { 'reparse data' } 9 { 'sparse block' } 10 { 'TxF data' } default { "stream $($st.Id)" } }
                    $so = [ordered]@{ kind = $label; name = $st.Name; size = $st.Len; archivePath = ''; text = '' }
                    if ($st.Len -gt 0) {
                        $sb = New-Object byte[] $st.Len; [Buffer]::BlockCopy($dec, $st.Off, $sb, 0, $st.Len)
                        $suffix = if ($st.Id -eq 4) { 'ADS_' + (Dqe-SafeName ($st.Name -replace ':\$DATA$', '').Trim(':') 40) } elseif ($st.Id -eq 3) { 'security_descriptor.bin' } elseif ($st.Id -eq 2) { 'extended_attributes.bin' } else { "stream$($st.Id).bin" }
                        $so.archivePath = Dqe-ZipAdd $z ("samples/_streams/{0}__{1}" -f $leaf, $suffix) $sb $now
                        if ($st.Id -eq 2) {
                            $so.attributes = New-Object System.Collections.ArrayList; $q = 0
                            while ($q + 8 -le $sb.Length -and $so.attributes.Count -lt 64) {
                                $nx = [int64][BitConverter]::ToUInt32($sb, $q); $nlen = [int]$sb[$q + 5]; $vlen = [int][BitConverter]::ToUInt16($sb, $q + 6)
                                if ($q + 8 + $nlen + 1 + $vlen -gt $sb.Length) { break }
                                $vhex = (Dqe-Hex $sb ($q + 9 + $nlen) ([Math]::Min($vlen, 512))).ToLower()
                                [void]$so.attributes.Add([ordered]@{ name = [Text.Encoding]::ASCII.GetString($sb, $q + 8, $nlen); size = $vlen; value = $vhex })
                                $eaHex += '|' + $vhex
                                if ($nx -le 0) { break }; $q += [int]$nx
                            }
                        }
                        if ($st.Id -eq 4 -and $st.Len -le 8192) { if (Dqe-LooksUtf16 $sb 0 $st.Len) { $so.text = [Text.Encoding]::Unicode.GetString($sb) } elseif (Dqe-LooksAscii $sb 0 $st.Len) { $so.text = $script:Latin1.GetString($sb) } }
                    }
                    [void]$s.streams.Add($so)
                }
                $s.eaHex = $eaHex
                [void]$samples.Add($s)
                if ($leaf.Length -ge 6) { [void]$needles.Add($leaf) }
                [void]$needles.Add($h.sha256); if ($h.sha1) { [void]$needles.Add($h.sha1) }
            } catch {
                if ($_.Exception.Message -eq 'Cancelled.') { throw }
                Dqe-Log "Payload $($j.Id) could not be recovered: $($_.Exception.Message)" 'error'
            } finally { $dec = $null }
        }

        # ---- detection history, scan results, stores
        $ctx = @{ Events = (New-Object System.Collections.ArrayList); Hashes = (New-Object 'System.Collections.Generic.HashSet[string]'); PathHash = @{}; Exclusions = (New-Object 'System.Collections.Generic.HashSet[string]'); Version = $null }
        $history = New-Object System.Collections.ArrayList; $scans = New-Object System.Collections.ArrayList; $stores = New-Object System.Collections.ArrayList; $resMeta = New-Object System.Collections.ArrayList
        Dqe-Log ('Recovered {0} file(s) and {1} registry hive(s). Decoding scan history.' -f $samples.Count, $hives.Count)
        $work = @(@($by['dh']) + @($by['result']) + @($by['store']) + @($by['resmeta']) | Where-Object { $_ }); $n = 0
        foreach ($it in $work) {
            $n++; if (($n % 8) -eq 1) { Dqe-Stage ("Decoding scan history $n of $($work.Count)") (50 + 12 * $n / [Math]::Max(1, $work.Count)) }
            try {
                $b = Dqe-Read $it
                if ($it.Kind -eq 'dh') {
                    $d = Dqe-ParseDetectionHistory $b $it.Rel; [void]$history.Add($d)
                    foreach ($hh in $d.hashes) { [void]$ctx.Hashes.Add($hh); [void]$needles.Add($hh) }
                    foreach ($r in $d.resources) {
                        if ($r.type -eq 'file' -and $r.props) { $sh = ($r.props | Where-Object { $_.k -eq 'ThreatTrackingSha256' } | Select-Object -First 1); if ($sh -and $r.path -notmatch '->\(') { $ctx.PathHash[$r.path.ToLower()] = ([string]$sh.v).ToLower() } }
                        $lf = Dqe-Leaf $r.path; if ($r.type -eq 'file' -and $lf.Length -ge 6) { [void]$needles.Add($lf) }
                    }
                }
                elseif ($it.Kind -eq 'result') { [void]$scans.Add((Dqe-ParseScanResult $b $it.Rel)) }
                elseif ($it.Kind -eq 'store') {
                    $st = Dqe-ParseStore $b $it.Rel; [void]$stores.Add($st)
                    foreach ($pe in $st.props) {
                        if ($pe.len -gt 2000 -and ($pe.enc -eq 'utf-16' -or $pe.enc -eq 'ascii')) {
                            [void](Dqe-ZipAdd $z ("decoded/store/{0}_{1}.txt" -f $st.id, (Dqe-SafeName $pe.k 60)) (Dqe-Utf8 ([string]$pe.v)) $now)
                            if (([string]$pe.v).Length -gt 1500000) { $pe.v = ([string]$pe.v).Substring(0, 1500000); $pe.cut = $true }
                        }
                    }
                }
                elseif ($it.Kind -eq 'resmeta') {
                    $c = Dqe-OpenSealed $b
                    if ($c.S1.Length -ge 32) {
                        $rmo = [ordered]@{ resourceId = (Dqe-Hex $c.S1 8 20); storedSize = [string][BitConverter]::ToUInt64($c.S1, 0); refCount = [BitConverter]::ToUInt32($c.S1, 28); entries = (New-Object System.Collections.ArrayList); source = $it.Rel }
                        for ($q = 0; $q + 16 -le $c.S2.Length; $q += 16) { [void]$rmo.entries.Add((Dqe-Guid $c.S2 $q)) }
                        [void]$resMeta.Add($rmo)
                    }
                }
            } catch {
                if ($_.Exception.Message -eq 'Cancelled.') { throw }
                Dqe-Log "$($it.Rel) could not be decoded: $($_.Exception.Message)" 'warn'
            }
        }

        # ---- Windows event log (operational channel)
        $winEvents = New-Object System.Collections.ArrayList; $evtSkipped = 0
        foreach ($it in @($by['evtx'] | Where-Object { $_ })) {
            if ($it.Via -eq 'file') { Dqe-Stage ("Reading event log $(Dqe-Leaf $it.Rel)") 61; foreach ($x in (Dqe-ReadDefenderEvents $it.Full $it.Rel)) { [void]$winEvents.Add($x) } }
            else { $evtSkipped++ }
        }
        if ($evtSkipped) { Dqe-Log ('{0} Defender event log file(s) inside an archive were copied into the output but not parsed: Windows can only read event logs from a file on disk. Extract the collection and load the folder to include them.' -f $evtSkipped) 'warn' }
        foreach ($x in $winEvents) {
            [void]$ctx.Events.Add([ordered]@{ t = $x.time; k = 'Event ' + $x.id; src = 'Event log'; x = ('{0}. {1}' -f $x.name, $x.summary) })
            foreach ($v in $x.data.Values) { foreach ($hm in [regex]::Matches([string]$v, '\b[0-9A-Fa-f]{64}\b|\b[0-9A-Fa-f]{40}\b')) { [void]$ctx.Hashes.Add($hm.Value.ToLower()) } }
        }
        if ($winEvents.Count) { Dqe-Log ('Read {0} Defender event(s) from the Windows event log.' -f $winEvents.Count) }

        # ---- logs
        $needleRx = $null
        if ($needles.Count -gt 0) {
            $alts = @($needles | Select-Object -First 300 | ForEach-Object { [regex]::Escape($_) }) -join '|'
            $needleRx = New-Object regex ($alts, [Text.RegularExpressions.RegexOptions]'IgnoreCase')
        }
        Dqe-Log 'Reading Defender logs.'
        $logs = @(@($by['mpdet']) + @($by['mplog']) | Where-Object { $_ }); $n = 0
        foreach ($it in $logs) {
            $n++; Dqe-Stage ("Reading log $n of $($logs.Count): $(Dqe-Leaf $it.Rel)") (62 + 16 * $n / [Math]::Max(1, $logs.Count))
            try { $text = Dqe-DecodeText (Dqe-Read $it); Dqe-ParseLog $text (Dqe-Leaf $it.Rel) $needleRx $ctx; $text = $null }
            catch { if ($_.Exception.Message -eq 'Cancelled.') { throw }; Dqe-Log "$($it.Rel) could not be read: $($_.Exception.Message)" 'warn' }
        }

        # ---- hash cross-check and derived timeline rows
        foreach ($s in $samples) {
            $rec = $ctx.PathHash[([string]$s.path).ToLower()]
            $eh = [string]$s.eaHex; $s.Remove('eaHex')
            if ($ctx.Hashes.Contains($s.sha256)) { $s.hashCheck = 'match'; $s.hashNote = 'SHA-256 matches a hash recorded by Defender.' }
            elseif ($s.sha1 -and $ctx.Hashes.Contains($s.sha1)) { $s.hashCheck = 'match'; $s.hashNote = 'SHA-1 matches the hash recorded in the Defender log.' }
            if ($rec -and $rec -ne $s.sha256) {
                $s.recordedSha256 = $rec
                if ($eh -and $eh.Contains($rec)) { $s.recordedKind = 'code-integrity hash'; $s.hashNote = ([string]$s.hashNote + ' The SHA-256 Defender recorded for this path is the code-integrity hash stored in the file''s extended attributes, not the hash of the file content.').Trim() }
                elseif ($s.hashCheck -ne 'match') { $s.hashCheck = 'mismatch'; $s.hashNote = 'SHA-256 differs from the hash Defender recorded for this path.'; Dqe-Log "$($s.name): recovered SHA-256 differs from the hash Defender recorded for that path." 'warn' }
            }
            if ($s.created)  { [void]$ctx.Events.Add([ordered]@{ t = $s.created;  k = 'File created';  src = 'Quarantine entry'; x = $s.path }) }
            if ($s.modified) { [void]$ctx.Events.Add([ordered]@{ t = $s.modified; k = 'File modified'; src = 'Quarantine entry'; x = $s.path }) }
        }
        foreach ($e in $M.Entries) { if ($e.time) { [void]$ctx.Events.Add([ordered]@{ t = $e.time; k = 'Quarantined'; src = 'Quarantine entry'; x = ('{0}  ({1} resources)  entry {2}' -f $e.threat, $e.resources.Count, $e.id) }) } }
        foreach ($d in $history) { if ($d.firstTime) { [void]$ctx.Events.Add([ordered]@{ t = $d.firstTime; k = 'Detection history'; src = 'DetectionHistory'; x = ('{0}  {1}  detection {2}' -f $d.threat, $d.status, $d.detectionId) }) } }
        $timeline = @($ctx.Events | Sort-Object { $_.t })

        # ---- raw export
        $inventory = New-Object System.Collections.ArrayList; $rawKinds = 'entry', 'resdata', 'resmeta', 'dh', 'store', 'result', 'histlog', 'mplog', 'mpdet', 'evtx', 'mpcmdrun'
        $rawList = @($src.Items | Where-Object { $_.InScope -and $_.Kind -ne 'container' -and ($O.Raw -eq 'all' -or ($O.Raw -eq 'core' -and $rawKinds -contains $_.Kind)) })
        Dqe-Log ('Adding {0} original artifact(s) to the archive.' -f $rawList.Count)
        $rawTotal = 0; foreach ($it in $rawList) { $rawTotal += $it.Len }; $rawDone = 0; $rawSet = @{}
        foreach ($it in $rawList) {
            Dqe-Stage ('Adding original artifacts  {0} of {1}' -f (Dqe-Size $rawDone), (Dqe-Size $rawTotal)) (78 + 14 * $rawDone / [Math]::Max(1, $rawTotal))
            try { [void](Dqe-ZipAdd $z ('raw/' + $it.Rel) (Dqe-Read $it) $it.Time); $rawSet[$it.Rel] = $true }
            catch { if ($_.Exception.Message -match 'Cancelled|4 GB|65,000') { throw }; Dqe-Log "$($it.Rel) was not added to the archive: $($_.Exception.Message)" 'warn' }
            $rawDone += $it.Len
        }
        foreach ($it in $src.Items) { if ($it.InScope) { [void]$inventory.Add([ordered]@{ path = $it.Rel; size = $it.Len; kind = $it.Kind; modified = $it.Time.ToString('yyyy-MM-dd HH:mm:ss'); inArchive = [bool]$rawSet[$it.Rel] }) } }

        # ---- decoded outputs + report
        Dqe-Log 'Writing decoded artifacts and report.'
        Dqe-Stage 'Writing decoded artifacts' 93
        foreach ($in in $src.Inputs) {
            if ($in.kind -ne 'folder') { Dqe-Stage ("Hashing $($in.name)"); try { $in.sha256 = Dqe-FileSha256 $in.path } catch { } }
        }
        $srcHash = [string]$src.Inputs[0].sha256
        $meta = [ordered]@{ tool = 'Defender Quarantine Extractor'; version = $script:DqeVersion; generatedUtc = $now.ToString('yyyy-MM-dd HH:mm:ss')
            caseId = $O.CaseId; analyst = $O.Analyst; title = $O.Title; description = $O.Description
            source = $src.Name; sourceKind = $src.Kind; sourceSha256 = $srcHash; sources = $src.Inputs; archive = [IO.Path]::GetFileName($zipPath); encryption = $(if ($O.Encryption -eq 'aes') { 'AES-256 (WinZip AE-2)' } else { 'ZipCrypto (legacy)' })
            password = $O.Password; rawScope = $O.Raw; perSampleZips = [bool]$O.PerSample; defender = $ctx.Version }
        $data = [ordered]@{ meta = $meta; samples = $samples; hives = $hives; entries = $M.Entries; history = $history; timeline = $timeline
            stores = $stores; scans = $scans; resourceIndex = $resMeta; inventory = $inventory; events = $winEvents; notes = $script:Notes }
        [void](Dqe-ZipAdd $z 'decoded/quarantine_entries.json'  (Dqe-Utf8 (ConvertTo-Json $M.Entries -Depth 12)) $now)
        [void](Dqe-ZipAdd $z 'decoded/detection_history.json'   (Dqe-Utf8 (ConvertTo-Json @($history) -Depth 12)) $now)
        [void](Dqe-ZipAdd $z 'decoded/scan_results.json'        (Dqe-Utf8 (ConvertTo-Json @($scans) -Depth 12)) $now)
        [void](Dqe-ZipAdd $z 'decoded/scan_store.json'          (Dqe-Utf8 (ConvertTo-Json @($stores) -Depth 14)) $now)
        [void](Dqe-ZipAdd $z 'decoded/resource_index.json'      (Dqe-Utf8 (ConvertTo-Json @($resMeta) -Depth 6)) $now)
        if ($winEvents.Count) { [void](Dqe-ZipAdd $z 'decoded/event_log.json' (Dqe-Utf8 (ConvertTo-Json @($winEvents) -Depth 6)) $now) }
        [void](Dqe-ZipAdd $z 'decoded/samples.csv'  (Dqe-Utf8 (Dqe-Csv $samples @('name', 'path', 'threat', 'quarantined', 'size', 'type', 'md5', 'sha1', 'sha256', 'hashCheck', 'created', 'modified', 'accessed', 'resourceId', 'archivePath'))) $now)
        [void](Dqe-ZipAdd $z 'decoded/timeline.csv' (Dqe-Utf8 (Dqe-Csv $timeline @('t', 'k', 'src', 'x'))) $now)
        [void](Dqe-ZipAdd $z 'manifest.json' (Dqe-Utf8 (ConvertTo-Json ([ordered]@{ meta = $meta; samples = $samples; registryHives = $hives; notes = $script:Notes }) -Depth 8)) $now)

        Dqe-Stage 'Building report' 95
        $json = ConvertTo-Json $data -Depth 16 -Compress
        $jb = [Text.Encoding]::UTF8.GetBytes($json); $json = $null
        $key = New-Object byte[] 32; (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($key)
        $rep = [int][Math]::Ceiling($jb.Length / 32); $kb = New-Object byte[] ($rep * 32)
        [Buffer]::BlockCopy($key, 0, $kb, 0, 32); $filled = 32
        while ($filled -lt $kb.Length) { $c = [Math]::Min($filled, $kb.Length - $filled); [Buffer]::BlockCopy($kb, 0, $kb, $filled, $c); $filled += $c }
        $enc = Dqe-Xor $jb 0 $kb 0 $jb.Length; $jb = $null; $kb = $null
        # The report embeds its data XOR-masked with a random key and decodes it in the browser. This is not secrecy (the
        # key sits next to the data); it keeps captured script text and command lines from being matched by on-access
        # scanners, so the report itself is not quarantined on the analyst's machine.
        $html = $O.Template.Replace('/*DQE_KEY*/', [Convert]::ToBase64String($key)).Replace('/*DQE_DATA*/', [Convert]::ToBase64String($enc)); $enc = $null
        $titleText = [Net.WebUtility]::HtmlEncode($(if ($O.Title) { $O.Title } else { 'Defender quarantine extraction' }))
        $html = $html.Replace('<!--DQE_TITLE-->', $titleText)
        [void](Dqe-ZipAdd $z 'report.html' (Dqe-Utf8 ($html.Replace('/*DQE_ARCHIVES*/', 'null'))) $now)

        Dqe-Log 'Finalising archive.'
        Dqe-Stage 'Finalising archive' 97
        Dqe-ZipClose $z
        $verify = $null
        if ($O.Verify) { Dqe-Stage 'Verifying archive' 98; $verify = Dqe-ZipVerify $z; if ($verify.Bad) { throw "Archive verification failed for $($verify.Bad) of $($verify.Checked) files. See the log." } }
        $z.Bw.Dispose(); $z = $null
        $arch = [ordered]@{ bundle = [ordered]@{ file = [IO.Path]::GetFileName($zipPath); sha256 = (Dqe-FileSha256 $zipPath); size = (New-Object IO.FileInfo $zipPath).Length }
            samples = $perZips; verified = $(if ($verify) { $verify.Checked } else { -1 }); notes = $script:Notes }
        # "<" is escaped so evidence text inside this JSON can never close the surrounding script element.
        $archJson = (ConvertTo-Json $arch -Depth 6 -Compress).Replace('<', '\u003c').Replace('>', '\u003e').Replace('&', '\u0026').Replace([string][char]0x2028, '\u2028').Replace([string][char]0x2029, '\u2029')
        [IO.File]::WriteAllText($reportPath, $html.Replace('/*DQE_ARCHIVES*/', $archJson), (New-Object Text.UTF8Encoding $false))
        $ok = $true
        Dqe-Log ('Done. Archive {0}, SHA-256 {1}' -f (Dqe-Size $arch.bundle.size), $arch.bundle.sha256)
        Dqe-Stage 'Done' 100
        @{ Zip = $zipPath; Report = $reportPath; PerSampleDir = $perDir; Samples = $samples.Count; Hives = $hives.Count; Events = $timeline.Count; Verify = $verify
            Warnings = @($script:Notes | Where-Object { $_.level -ne 'info' }).Count; ZipSize = $arch.bundle.size; ZipSha256 = $arch.bundle.sha256
            Matches = @($samples | Where-Object { $_.hashCheck -eq 'match' }).Count; SampleList = $samples }
    } finally {
        if ($z) { try { $z.Bw.Dispose() } catch { } }
        if (-not $ok) { try { if ([IO.File]::Exists($zipPath)) { [IO.File]::Delete($zipPath) } } catch { } }
    }
}

# ---------------------------------------------------------------- single-file export
function Dqe-ExportOne($M, $A) {
    # One quarantined item -> one encrypted zip, verified. Used by "Save this file as zip" in the window.
    $id = ''; $leaf = ''
    if ($A.Key -like 'orphan|*') { $id = $A.Key.Substring(7); $leaf = $id }
    else {
        foreach ($e in $M.Entries) { foreach ($r in $e.resources) { if ("$($e.id)|$($r.idx)" -eq $A.Key) { $id = $r.resourceId; $leaf = Dqe-SafeName (Dqe-Leaf $r.path) } } }
    }
    if (-not $id -or -not $M.ResData.ContainsKey($id)) { throw 'This row has no stored payload to export.' }
    $it = $M.ResData[$id]
    Dqe-Stage 'Preparing decryption' 5
    $raw = Dqe-Read $it; $dec = Dqe-Rc4 $raw 0 $raw.Length; $raw = $null
    Dqe-Stage 'Recovering payload' 60
    $data = $dec
    if ($dec.Length -ge 4 -and $dec[0] -eq 0x72 -and $dec[1] -eq 0x65 -and $dec[2] -eq 0x67 -and $dec[3] -eq 0x66) { $leaf = "$leaf.hiv" }
    else {
        $p = 0
        while ($p + 20 -le $dec.Length) {
            $sid = [int64][BitConverter]::ToUInt32($dec, $p); $ssz = [BitConverter]::ToUInt64($dec, $p + 8); $nl = [int64][BitConverter]::ToUInt32($dec, $p + 16)
            if ($sid -lt 1 -or $sid -gt 11 -or $nl -gt 1024 -or $p + 20 + $nl -gt $dec.Length) { break }
            $do = $p + 20 + [int]$nl; if ($ssz -gt $dec.Length - $do) { $ssz = $dec.Length - $do }
            if ($sid -eq 1) { $data = New-Object byte[] ([int]$ssz); [Buffer]::BlockCopy($dec, $do, $data, 0, [int]$ssz); break }
            $p = $do + [int]$ssz
        }
        if ($A.Key -like 'orphan|*') { $x = (Dqe-Sniff $data 0 $data.Length).ext; if ($x) { $leaf = "$leaf.$x" } }
    }
    $h = Dqe-Hash $data 0 $data.Length
    Dqe-Stage 'Writing encrypted zip' 75
    $z = Dqe-ZipOpen $A.OutPath $A.Encryption $A.Password; $ok = $false
    try {
        [void](Dqe-ZipAdd $z $leaf $data ([DateTime]::UtcNow) $h.sha256); Dqe-ZipClose $z
        $v = Dqe-ZipVerify $z; if ($v.Bad) { throw 'Archive verification failed.' }
        $ok = $true
    } finally { $z.Bw.Dispose(); if (-not $ok) { try { [IO.File]::Delete($A.OutPath) } catch { } } }
    Dqe-Log ('Saved {0} ({1}) as {2}. SHA-256 of the file inside: {3}' -f $leaf, (Dqe-Size $data.Length), $A.OutPath, $h.sha256)
    Dqe-Stage 'Done' 100
    @{ Zip = $A.OutPath; Name = $leaf; Size = $data.Length; Sha256 = $h.sha256; Single = $true }
}

# ---------------------------------------------------------------- background job entry point (used by the window)
function Dqe-Job($Sync, [string]$Mode, $A) {
    $script:Sync = $Sync
    try {
        if ($Mode -eq 'load') {
            if ($Sync.Model) { Dqe-CloseSource $Sync.Model.Src }
            $Sync.Model = $null; $Sync.Model = Dqe-Load $A.Paths $A.Passwords
        } elseif ($Mode -eq 'single') { $Sync.Result = Dqe-ExportOne $Sync.Model $A }
        else { $Sync.Result = Dqe-Generate $Sync.Model $A }
        $Sync.State = 'done'
    } catch {
        $Sync.Error = $_.Exception.Message
        if ($_.Exception.Message -ne 'Cancelled.') { [void]$Sync.Log.Add(('{0}|error|{1}  [{2}]' -f (Get-Date).ToString('HH:mm:ss'), $_.Exception.Message, ($_.InvocationInfo.PositionMessage -split "`n")[0])) }
        $Sync.State = 'error'
    }
}
}
