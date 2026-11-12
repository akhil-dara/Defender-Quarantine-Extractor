# Microsoft Defender artifacts reference

What Defender Quarantine Extractor reads, where it lives, and how each format is laid out. Offsets are in bytes; all
integers are little-endian. Paths are relative to `C:\ProgramData\Microsoft\Windows Defender`.

## The RC4 layer

Quarantine and scan-history files are obfuscated with RC4 under one fixed 256-byte key embedded in `mpengine.dll`,
first published by ERNW. The key is the same on every installation. Files use it in two ways:

- **Whole-file**: the entire file is one RC4 stream (`Quarantine\ResourceData`).
- **Sealed container**: a 60-byte header and two sections, each encrypted as a separate RC4 stream starting from the
  beginning of the keystream (`Quarantine\Entries`, `Quarantine\Resources`, `Scans\History\Results`,
  `Scans\History\Store`).

### Sealed container header (60 bytes, after decryption)

| Offset | Size | Meaning |
|---|---|---|
| 0x00 | 4 | Signature `DB E8 C5 01` |
| 0x04 | 4 | Format version: `0x00010001` entries and resources, `0x00000586` scan results, `0x00000010` store |
| 0x28 | 4 | Section 1 length |
| 0x2C | 4 | Section 2 length |
| 0x30 | 8 | Section checksums (`FF FF FF FF` when section 1 is empty) |
| 0x38 | 4 | Trailer `DB E8 C5 02` |

## Quarantine

### `Quarantine\Entries\{GUID}`

One file per remediation (one threat, one or more resources).

Section 1:

| Offset | Size | Meaning |
|---|---|---|
| 0x00 | 16 | Entry GUID (the file name) |
| 0x10 | 16 | Scan GUID |
| 0x20 | 8 | Quarantine time, FILETIME (UTC) |
| 0x28 | 8 | Threat ID |
| 0x30 | 4 | Always 1 |
| 0x34 | n | Threat name, UTF-8, NUL-terminated |

Section 2: `uint32 count`, then `count` offsets (from the start of section 2), then one record per resource:

- path, UTF-16, NUL-terminated (files use the `\\?\` prefix)
- `uint16` field count
- resource type, ASCII, NUL-terminated: `file`, `regkey`, `service`, `taskscheduler`, `process`, `runkey`, ...
- fields, each aligned to 4 bytes: `uint16 size`, `uint16 tag` (low 12 bits id, high 4 bits type), data

| Type | Encoding |
|---|---|
| 1 | ANSI string |
| 2 | UTF-16 string |
| 3 | DWORD |
| 4 | 20-byte resource ID (the payload's file name under ResourceData) |
| 5 | 8 raw bytes |
| 6 | QWORD (FILETIME for ids 0x0F to 0x11) |

| Id | Field |
|---|---|
| 0x02, 0x0A | Resource ID (files use 0x02, registry and service payloads 0x0A) |
| 0x0C | Physical path |
| 0x0D | Signature sequence |
| 0x0F / 0x10 / 0x11 | Creation / last access / last write time |
| 0x12 | File size |
| 0x1B / 0x1C | Service account / display name |

### `Quarantine\ResourceData\XX\<40 hex>`

Whole-file RC4. The plaintext is either a registry hive (`regf`, for `regkey` and `service` resources) or a sequence
of Windows `BackupRead` streams (`WIN32_STREAM_ID`): `uint32 id`, `uint32 attributes`, `uint64 size`,
`uint32 name length`, UTF-16 name, data.

| Stream id | Meaning | Output |
|---|---|---|
| 1 | File data | `samples/<name>` |
| 2 | Extended attributes (`FILE_FULL_EA_INFORMATION` chain) | `samples/_streams/...extended_attributes.bin`, decoded in the report |
| 3 | Security descriptor | `samples/_streams/...security_descriptor.bin` |
| 4 | Alternate data stream, e.g. `:Zone.Identifier:$DATA` | `samples/_streams/...ADS_<name>`, text shown in the report |
| 5 to 11 | Link, property data, object id, reparse data, sparse block, TxF | kept as `stream<N>.bin` |

The extended attributes of signed binaries often include `$KERNEL.PURGE.SEC.FILEHASH`, the code-integrity hash
Defender reports as the file's SHA-256 in some records. The report labels that case instead of calling it a mismatch.

### `Quarantine\Resources\XX\<40 hex>`

Sealed. Section 1: `uint64` stored size, 20-byte resource ID, `uint32` reference count. Section 2: the GUIDs of the
entries that reference the payload.

## Scan history

### `Scans\History\Service\DetectionHistory\NN\{GUID}`

Not encrypted. A sequence of `uint32 size`, `uint32 type`, data, each padded to 8 bytes.

| Type | Data |
|---|---|
| 0x15 | UTF-16 string |
| 0x1E | GUID |
| 0x0A | FILETIME |
| 0x28 | Property bag (24-byte header, then key/value pairs) |
| other | 4- or 8-byte integers |

Layout: threat ID, detection GUID, `Magic.Version:1.2`, threat name, header integers (severity, category, status),
then per resource a `Magic.Version` marker, type, path, flags and a property bag with `ThreatTrackingSha256`,
`ThreatTrackingSha1`, `ThreatTrackingMD5`, `ThreatTrackingSize`, signature details and times. A trailer holds times,
the quarantine entry GUID, the user account and the process that triggered the detection.

### Property bags

Used inside DetectionHistory and the store: `uint32 key bytes`, UTF-16 key, `uint32 type`, value.

| Type | Value |
|---|---|
| 3 | DWORD |
| 4 | QWORD (often a FILETIME) |
| 5 | Byte boolean |
| 6 | `uint32` length, UTF-16 string |
| 7 | `uint32` length, blob (may be a hex-encoded nested bag) |
| 8 | `uint32` length, blob |

### `Scans\History\Results\<Quick|Resource|Full|...>\{GUID}`

Sealed, one per scan. Section 1: scan GUID and start time. Section 2: start and end time, a schema table, and for
scans that found something, the threat names and resource records (`uint64` character count, type, `uint64`
character count, path). The surrounding layout varies between platform versions, so records are located by pattern.

### `Scans\History\Store\<32 hex>`

Sealed; section 1 empty; section 2 is `uint32` total length followed by a property bag. Two kinds are common:

- **AMSI captures**: `AMSIApp`, `AMSIContentName`, `Content` (the full script text), `AMSIPid`, `AMSIOpProcName`,
  plus Defender research data such as MITRE technique lists.
- **Scan context**: `CONTEXT_DATA_FILEPATH`, `CONTEXT_DATA_PROCESSNAME`, `CONTEXT_DATA_PROCESS_PPID`,
  `CONTEXT_DATA_HAS_MOTW_ADS`, file age and scan reason.

## Logs

| File | Encoding | Used for |
|---|---|---|
| `Support\MPDetection-*.log` | UTF-16 | `DETECTION` lines with file hashes |
| `Support\MPLog-*.log` | UTF-16 | detection events, threat actions, resource scans, mini-filter blocks, cloud lookups, low-fidelity signals, exclusions, BM telemetry, platform versions |
| `Scans\History\Service\*.log` | UTF-16 | copied as-is |
| `Microsoft-Windows-Windows Defender%4Operational.evtx` | event log | events 1006 to 1015, 1116 to 1129, 2050, 3002, 5001 to 5013 |

## Recognising renamed or flattened files

When a collection loses Defender's folder names, files without an extension are identified by content:

| Signal | Artifact |
|---|---|
| Plain bytes `08 00 00 00 08 00 00 00` and `Magic` at 0x30 | DetectionHistory |
| RC4 header with version `0x00010001`, section 1 length 32 | Resources |
| RC4 header with version `0x00010001`, other length | Entries |
| RC4 header with version `0x586` | Results |
| RC4 header with empty section 1 | Store |
| Whole-file RC4 plaintext starts `regf` or a valid `WIN32_STREAM_ID` | ResourceData |
