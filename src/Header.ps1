<#
.SYNOPSIS
    Extracts files that Microsoft Defender quarantined, straight into a password-protected zip, with a full HTML report.

.DESCRIPTION
    Defender Quarantine Extractor reads Microsoft Defender / Defender for Endpoint artifacts from any collection,
    decrypts the quarantined files in memory and writes them directly into an AES-256 zip (password "infected" by
    default), ready for a sandbox or a colleague. Plaintext samples never touch the disk, so it runs on a workstation
    protected by Defender without exclusions and without switching protection off.

    Alongside the samples it decodes everything else Defender keeps about a detection: quarantine entries, the
    DetectionHistory records, scan results, AMSI script captures, MPLog and MPDetection logs and the operational event
    log. The result is an offline HTML report with a timeline, hashes cross-checked against Defender's own records,
    and every decoded field.

    Accepted input:
      * a collection archive (.zip) from any collection tool or script, or a manual copy, in any internal layout
      * a gzip-compressed archive (.gz), including a zip inside it
      * password-protected zips (ZipCrypto or AES); common sample passwords are tried automatically
      * zips nested inside zips or inside folders
      * an extracted folder at any level, or a folder of loose Defender files with no directory structure
      * several sources at once

    Run it with no parameters to open the window. Give -Source to run in the console, for scripting.

    Pure PowerShell: nothing is compiled (no Add-Type C#), nothing is installed, no temporary files are created and
    the evidence is never modified. It can be pasted into PowerShell ISE and run with F5.

.PARAMETER Source
    One or more collected archives (.zip, .gz) or folders. Giving this parameter runs in console mode.

.PARAMETER OutputDirectory
    Where the encrypted archive and the report are written. Defaults to the current directory.

.PARAMETER Password
    Password for the output archive. Defaults to "infected", the convention sandboxes and analysts expect.

.PARAMETER Encryption
    AES256 (default) or ZipCrypto. ZipCrypto is only for receivers whose tools cannot open AES archives; it is weak
    and, in pure PowerShell, much slower.

.PARAMETER IncludeOriginals
    Which original files to copy into the archive under raw/:
      Core  the files the tool analyses: quarantine store, detection and scan history, MPLog and MPDetection
            logs, event logs and history logs (default)
      All   everything in the source, including logs, traces and support files the tool does not analyse
      None  only recovered files and decoded results

.PARAMETER SourcePassword
    Password(s) for password-protected input archives. "infected", "malware", "virus" and "password" are always tried.

.PARAMETER CaseId
    Case or ticket reference. Used in the output file names and shown in the report.

.PARAMETER Analyst
    Analyst name shown in the report. Defaults to the current user name.

.PARAMETER Title
    Report title.

.PARAMETER Description
    Free-text description shown in the report.

.PARAMETER PerFileZip
    Also write each recovered file into its own encrypted zip, for sandboxes that take one sample per submission.

.PARAMETER SkipVerify
    Skip re-reading and verifying the written archive.

.PARAMETER OpenReport
    Open the HTML report in the default browser when done.

.EXAMPLE
    .\Defender-Quarantine-Extractor.ps1

    Opens the window. The same happens when the script is pasted into a new PowerShell ISE tab and run with F5.

.EXAMPLE
    .\Defender-Quarantine-Extractor.ps1 -Source .\WKS-0412_collection.zip -CaseId IR-2026-0412 -PerFileZip

    Recovers everything from a collection archive into IR-2026-0412_defender-quarantine_<time>.zip, writes the
    report next to it, and writes one zip per recovered file for sandbox submission.

.EXAMPLE
    .\Defender-Quarantine-Extractor.ps1 -Source D:\Evidence\host1, D:\Evidence\host2.zip -OutputDirectory D:\Cases\0412 -IncludeOriginals None

    Processes an extracted folder and a zip together, and keeps only the decoded results and recovered files.

.EXAMPLE
    Get-ChildItem D:\Collections\*.zip | ForEach-Object { .\Defender-Quarantine-Extractor.ps1 -Source $_.FullName -OutputDirectory D:\Out }

    Batch mode. Each run returns an object with the archive path, the report path and the counts.

.OUTPUTS
    In console mode, a PSCustomObject with Archive, ArchiveSha256, Report, Files, RegistryHives, TimelineEvents,
    Warnings and SampleZips.

.NOTES
    Name     : Defender-Quarantine-Extractor
    Version  : __DQE_VERSION__
    License  : Apache License 2.0
    Requires : Windows PowerShell 5.1 or PowerShell 7 on Windows, FullLanguage mode

    Use it only on evidence you are authorised to handle. Recovered files are live malware: open the archive only
    inside an analysis environment.

    Format research credits: ERNW quarantine-formats, knez/defender-dump, NUKIB/maldump,
    jklepsercyber/defender-detectionhistory-parser, fox-it/dissect.target.

.LINK
    __DQE_REPO__
#>
[CmdletBinding(DefaultParameterSetName = 'Window')]
param(
    [Parameter(ParameterSetName = 'Console', Mandatory = $true, Position = 0)]
    [Alias('Path', 'InputPath')]
    [string[]] $Source,

    [Parameter(ParameterSetName = 'Console')]
    [string] $OutputDirectory,

    [Parameter(ParameterSetName = 'Console')]
    [ValidateNotNullOrEmpty()]
    [string] $Password = 'infected',

    [Parameter(ParameterSetName = 'Console')]
    [ValidateSet('AES256', 'ZipCrypto')]
    [string] $Encryption = 'AES256',

    [Parameter(ParameterSetName = 'Console')]
    [ValidateSet('Core', 'All', 'None')]
    [string] $IncludeOriginals = 'Core',

    [Parameter(ParameterSetName = 'Console')]
    [string[]] $SourcePassword,

    [Parameter(ParameterSetName = 'Console')]
    [string] $CaseId,

    [Parameter(ParameterSetName = 'Console')]
    [string] $Analyst = $env:USERNAME,

    [Parameter(ParameterSetName = 'Console')]
    [string] $Title,

    [Parameter(ParameterSetName = 'Console')]
    [string] $Description,

    [Parameter(ParameterSetName = 'Console')]
    [switch] $PerFileZip,

    [Parameter(ParameterSetName = 'Console')]
    [switch] $SkipVerify,

    [Parameter(ParameterSetName = 'Console')]
    [switch] $OpenReport
)

Set-StrictMode -Off
