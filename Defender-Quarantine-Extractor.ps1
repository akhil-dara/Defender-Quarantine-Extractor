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
    Version  : 1.0.0
    License  : Apache License 2.0
    Requires : Windows PowerShell 5.1 or PowerShell 7 on Windows, FullLanguage mode

    Use it only on evidence you are authorised to handle. Recovered files are live malware: open the archive only
    inside an analysis environment.

    Format research credits: ERNW quarantine-formats, knez/defender-dump, NUKIB/maldump,
    jklepsercyber/defender-detectionhistory-parser, fox-it/dissect.target.

.LINK
    https://github.com/akhil-dara/Defender-Quarantine-Extractor
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

# =====================================================================================================================
#  EMBEDDED ASSETS
# =====================================================================================================================
$DqeEmblem = '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'

$DqeReportTemplate = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><!--DQE_TITLE--></title>
<style>
:root{
  --bg:#f5f4f0; --surface:#ffffff; --panel:#edebe5; --ink:#1b1d21; --muted:#59606c; --line:#d9d5cc;
  --accent:#8a4f00; --accent-soft:#fdf0d8; --danger:#a1242b; --ok:#1c6b3a; --warn:#8a5a00; --code:#f1efe9; --sel:#ffe2a8;
  --sans:"Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif;
  --mono:"Cascadia Mono","Cascadia Code",Consolas,"SFMono-Regular",Menlo,monospace;
}
@media (prefers-color-scheme: dark){ :root:not([data-theme="light"]){
  --bg:#14171c; --surface:#1b1f26; --panel:#171a20; --ink:#e6e9ee; --muted:#9aa3b2; --line:#2c333e;
  --accent:#e8a33d; --accent-soft:#2d2414; --danger:#ff8f86; --ok:#74d39c; --warn:#f0c060; --code:#10131a; --sel:#5a431a;
}}
:root[data-theme="dark"]{
  --bg:#14171c; --surface:#1b1f26; --panel:#171a20; --ink:#e6e9ee; --muted:#9aa3b2; --line:#2c333e;
  --accent:#e8a33d; --accent-soft:#2d2414; --danger:#ff8f86; --ok:#74d39c; --warn:#f0c060; --code:#10131a; --sel:#5a431a;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth; scroll-padding-top:16px}
@media (prefers-reduced-motion: reduce){ html{scroll-behavior:auto} *{transition:none!important} }
body{margin:0; background:var(--bg); color:var(--ink); font:14px/1.5 var(--sans); -webkit-text-size-adjust:100%}
::selection{background:var(--sel); color:var(--ink)}
a{color:var(--accent); text-underline-offset:2px}
:focus-visible{outline:2px solid var(--accent); outline-offset:2px; border-radius:3px}
.shell{display:grid; grid-template-columns:216px minmax(0,1fr); min-height:100vh}
nav{position:sticky; top:0; align-self:start; height:100vh; overflow:auto; background:var(--panel); border-right:1px solid var(--line); padding:20px 12px}
.brand{display:flex; gap:10px; align-items:center; padding:0 8px 16px}
.brand img{width:30px; height:30px; border-radius:7px}
.brand b{font-size:14px; font-weight:600; line-height:1.2}
.brand span{display:block; color:var(--muted); font-size:12px; font-weight:400}
nav a{display:flex; justify-content:space-between; gap:8px; padding:7px 10px; border-radius:6px; color:var(--ink); text-decoration:none; font-size:13px}
nav a:hover{background:var(--surface)}
nav a.on{background:var(--accent-soft); color:var(--accent); font-weight:600}
nav a i{font-style:normal; color:var(--muted); font-variant-numeric:tabular-nums; font-size:12px}
nav .tools{margin-top:16px; padding:12px 8px 0; border-top:1px solid var(--line); display:grid; gap:8px}
main{padding:28px 32px 80px; max-width:1500px; min-width:0}
h1{font-size:24px; line-height:1.25; font-weight:650; margin:0 0 4px; letter-spacing:-.01em; text-wrap:balance}
h2{font-size:17px; font-weight:650; margin:44px 0 4px; padding-top:4px}
h3{font-size:14px; font-weight:650; margin:22px 0 8px}
.sub{color:var(--muted); margin:0 0 14px; max-width:78ch}
.lede{color:var(--muted); margin:0 0 18px; max-width:80ch}
section{scroll-margin-top:12px}
.box{background:var(--surface); border:1px solid var(--line); border-radius:8px}
dl.kv{display:grid; grid-template-columns:max-content minmax(0,1fr); gap:6px 18px; margin:0; padding:14px 16px}
dl.kv dt{color:var(--muted); white-space:nowrap}
dl.kv dd{margin:0; min-width:0; overflow-wrap:anywhere}
.two{display:grid; grid-template-columns:repeat(auto-fit,minmax(340px,1fr)); gap:16px}
.facts{display:flex; flex-wrap:wrap; gap:6px 22px; padding:12px 16px; margin:0 0 16px; list-style:none; border-top:1px solid var(--line); border-bottom:1px solid var(--line)}
.facts b{font-variant-numeric:tabular-nums}
code,.m{font-family:var(--mono); font-size:12.5px}
.m{overflow-wrap:anywhere}
.tw{overflow:auto; border:1px solid var(--line); border-radius:8px; background:var(--surface); max-height:70vh}
table{border-collapse:collapse; width:100%; font-size:13px}
th{position:sticky; top:0; z-index:1; background:var(--panel); text-align:left; font-weight:600; color:var(--muted); padding:8px 12px; border-bottom:1px solid var(--line); white-space:nowrap}
td{padding:7px 12px; border-bottom:1px solid var(--line); vertical-align:top}
tr:last-child td{border-bottom:0}
tbody tr:hover td{background:color-mix(in srgb, var(--accent-soft) 45%, transparent)}
td.n,th.n{text-align:right; font-variant-numeric:tabular-nums; white-space:nowrap}
td.t{white-space:nowrap; font-family:var(--mono); font-size:12.5px; color:var(--muted)}
.tag{display:inline-block; padding:1px 8px; border-radius:999px; border:1px solid var(--line); font-size:12px; white-space:nowrap; color:var(--muted)}
.tag.ok{color:var(--ok); border-color:color-mix(in srgb,var(--ok) 45%,var(--line))}
.tag.bad{color:var(--danger); border-color:color-mix(in srgb,var(--danger) 45%,var(--line))}
.tag.warn{color:var(--warn); border-color:color-mix(in srgb,var(--warn) 45%,var(--line))}
.threat{color:var(--danger); font-weight:600}
.card{padding:16px; margin:0 0 14px}
.card > header{display:flex; flex-wrap:wrap; gap:8px 12px; align-items:baseline; margin-bottom:10px}
.card > header strong{font-size:15px; overflow-wrap:anywhere}
.hash{display:grid; grid-template-columns:64px minmax(0,1fr) auto; gap:4px 10px; align-items:center}
.hash span{color:var(--muted)}
button,.btn{font:inherit; font-size:12.5px; color:var(--ink); background:var(--surface); border:1px solid var(--line); border-radius:6px; padding:4px 10px; cursor:pointer; min-height:28px}
button:hover{border-color:var(--accent); color:var(--accent)}
button:active{transform:translateY(1px)}
button.done{color:var(--ok); border-color:var(--ok)}
.bar{display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin:0 0 10px}
input[type=search]{font:inherit; color:var(--ink); background:var(--surface); border:1px solid var(--line); border-radius:6px; padding:6px 10px; min-width:260px; flex:1 1 260px; max-width:460px}
input[type=search]::placeholder{color:var(--muted)}
.chip{user-select:none}
.chip[aria-pressed="true"]{background:var(--accent-soft); color:var(--accent); border-color:var(--accent)}
details{margin:6px 0}
summary{cursor:pointer; color:var(--accent); width:max-content; max-width:100%}
pre{margin:8px 0 0; padding:12px; background:var(--code); border:1px solid var(--line); border-radius:6px; overflow:auto; max-height:460px; font:12.5px/1.5 var(--mono); white-space:pre-wrap; overflow-wrap:anywhere; tab-size:4}
.note{padding:10px 14px; border-radius:8px; border:1px solid var(--line); background:var(--surface); margin:0 0 10px; max-width:100ch}
.note.warn{border-color:color-mix(in srgb,var(--warn) 50%,var(--line))}
.note.error{border-color:color-mix(in srgb,var(--danger) 55%,var(--line))}
.empty{padding:18px 16px; color:var(--muted)}
.count{color:var(--muted); font-weight:400; font-size:13px; margin-left:6px}
.muted{color:var(--muted)}
.nowrap{white-space:nowrap}
footer{margin-top:56px; color:var(--muted); font-size:12.5px; border-top:1px solid var(--line); padding-top:14px}
#boot{padding:48px 32px; color:var(--muted)}
*{scrollbar-color:var(--line) transparent; scrollbar-width:thin}
@media (max-width:860px){
  .shell{grid-template-columns:1fr}
  nav{position:static; height:auto; display:flex; flex-wrap:wrap; gap:4px; padding:12px; border-right:0; border-bottom:1px solid var(--line)}
  nav .brand{width:100%; padding-bottom:8px} nav .tools{display:flex; margin:0; padding:0; border:0}
  main{padding:20px 16px 60px} dl.kv{grid-template-columns:1fr; gap:0 0} dl.kv dd{margin-bottom:8px}
  .hash{grid-template-columns:1fr auto} .hash span{grid-column:1/-1}
}
@media print{
  nav,.bar,button{display:none!important} .shell{display:block} main{padding:0; max-width:none}
  .tw{max-height:none; overflow:visible} pre{max-height:none} body{background:#fff; color:#000; font-size:11px}
  details > *{display:block} h2{break-after:avoid} .card,tr{break-inside:avoid}
}
</style>
</head>
<body>
<div id="boot">Decoding report data...</div>
<div class="shell" id="app" hidden>
  <nav aria-label="Sections">
    <div class="brand"><img alt="" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAACXBIWXMAAAAAAAAAAQCEeRdzAAAQAElEQVR4nL1baawlV3GuqnP63vvue2/eeMbjQRGIQOJACJuMswDj2AoiC2tQRBQIWAkyJigJCpsShBfAJgnCNosUhc0sQSYCApiwJYqQQUQxjsGQEMSSiIglGHtm3nq37j7nVFRV5/Tt9/Ay9g+u3dPd797uPlX11V6NcB8+CACc9/IPMgAiAAEAyTkBODknAC/HsncIlQOoPOmxIwSivEfU+8mHU4KQGGJkCJGh7e1jAt1CAkiysW0sGwAkvYEd31d6PNyPi4Ro3ZPthXjdMtFy7BwqE5ToTLhsPjPAOwJUBrDeI6KcM5Cey1+FLDlK+jwhTwjWZ2aqC/EkxBfpLHf3+uEzZYA+v0849iRPBxlghMu+EiaI9AUFnnSvjJE9ojIAkYCZIbFImqENydCEBCQMQVIU2G8Zokg/ybmhAAsS5O+F+PvACH9GhPeJ7u2NaCFmKX2RsO9JX4geVEZ85REGwghvaND/VLysRLWBoXEIjUvgA4OPCZpgzBQmyP1jBAiCMDlWdZBr9zPjTBhRAOPvifi7IrxAXPRXjk2njXA7N31XvXcIw4pgoITbsZ3bJvcoCwwhQS1bi7o1QYhHqHTP4IPYAFS7IHtBi9kGOxYG6D4ZI9RGyL3vhgnl3N8b8QXa+yG+JL5I3bkifSFcCDWihdCVCmFl6GA0IBhVBCsD+d4JepQFMSUWIhdNgnkTYdEmmNfCDGOCIiMy1MFQogaxZyCLcRRkRFwiwtTlnpHg74r4fTDPlt0MWR/iRqxKPENdoK2bSN4bE4Tg8dDB6sjpfjwkGAsjBs550vVCYHCLJsZpHWHeEMybBLNFzMwgZYQQPxRGZCY0MUEVccmMxOBEPfRvZk9QECKGMiPirjyFvyfJF0gvCV4aNpFs0fMC8UG1JFygXqS9vuJhbeRgdUiwtuJwbeTceOjD2tCNxH5P5mE+raOfLmKc1IlndYTJkGC6IEWDIGPWGBOaVpiQkZFR0EZUmxGcMacVRogqCASg+MnsNQ4wwR8kvsDdCDeJF8kOsjUfHCBamDFUHTfCRcojL1JGWBs6WB97WB85Id6vr/iwtuLD0fXB+edsDN4DnNzJnfYPT+/Wt+wtAkwXye8tYtidBZitOFBmLCKMskosWoa6JWVC3UNE601FHCVwAZQJlB2pqpnaiGzYMxOwMOAupd634tmAiQ7rsRBXgcBYCS/fi7RXhqLzpNIWRqj0V5xfHbq4NnLhrLVq5ez16nXjoX+5GG5Z5k8dGdy8MXbXntqpr9yZhdn62OP6iNxkEcNkYSokarEQFWmzrVBmmIE0W8FQ6XcANTG4IC40Uyx6FpcGsR84eWXAPre2hH2RshCuxPWM2HJDGAsj8nfjAWbiPa4Oya2NXByPXDi04uGsteo5h8b+9Y7wIaqTeRWyzNWhe8XKsZXfOTwPl21N2w+sDihM64jTOrq9WYjTOvG8caoKwgBBwqKJdt5jiqBxXkdYkARQxZGbO1AGpP1M8Pv0Phu8QvzSiIlEHYwFxnI8ckr86qB8J5J3MPIo0qLVFUcrFYaVgQtrI4KN1erXD42rywaeLjCDpISfjjG9HBCiI3oTA5yNiA/ZWKtuWB25P94bx6t3Z+1nJoukzJvMg581Kc1lU2PJMG8FGcIEhmmdsrokRa/Q0kWQmWo5KtQXNPhO8tgjPgcvIl0hVAzY+oqDjbGDjVXT59XClCHheEA0HjocDSiOhy6tDCitDqk6NK5+ezykl1SEJ0QTlXAAjjG9t43pL1LiO+W5kfifvaO/QsQXMAM6R084sk6fXh/7f50u4lv35uHGyYzaWa2wx1mT3KxOvGhTmtWR5e9iJ3bnsvaoMYgEaIAREssmzzaXKFGn8l8iSRAE9HW/585Et0XHRYKHxh4Or3o4e93DkTVPh1Ycro8crg6RjWgfBQEZKb8wHtCzR5V7rvd4rvlk1hiegf+pbeIVTZtuTWKeOKkKEvHJNqZLPOLbqspdRY5+UxbsCE9srNKJ9ZH/78Va9YHpov3wZBG/Pq9TUJsg8UITaVonEsmvTto0rCg5JxlFMHfYJVOpiw8KE+QjAl9CX1ydWnzKCCBYXfFweOyU+AccHsCxQz5tZKu+OlKfvjoeukePR+7XhhU91SGejwCVSNysLsvnM6GNb2wjf058dmLwST4cg4gCCckRUET4UuT0W5V3F3pHf46AvyGsI4fnrjp/5XjkXn1W5FvrJn56XsfPzpv0tekiTkQ1lAEjD4NBC0SNRZc5oyzZpDIhxwSUY2ZfjF5JUiRLU8OX/bhAXQg2BlT40OMrDz+65n5+deQfNazofE/4GCR8kGZ2OT+1PA7uYOaPhxjf0Qb+co7ZKaaksU8JVuT3KOsiSM6hE/bExJ93hJ/3js7zji4lomcywANUYI4evzamx6+O/FUxpR+EyP9Zt+nL8zr9x+lJ+IZ3+I0QmeuWzXNI3BBBt8IMRz0EUI7rdcvuT0JZDWHFyIkNWHG4sVrxOYcHqw9/4PimytHxzogLnFTOen46pXRzYv5QZP5UirwpSU5ioJQYReSpZH7ZL8uXoh76QYymn+wYUJBzWxvCHznEV3lPTyOiZyPyExPiEfk5ET1w6OCBw4F7yuFVhLM3+OS0Tg/dm8fJZBHFVqh9EGbUEiSJgHP+oCEysiGgH+MLAjoXqL5fDF6O4sTMA3JIkBBYoswZAHw7xnRLSummENMXUuKTxlyNp31SDUhKuKWtsre0rdQDDAaFC3omaJUQQeWTOG2Fht+PGN9PiOc4h09whE8iol8GwHMZYMzAXrRudUQodks81WgWLXapk6XiWoSR+MD2nNXeMrv8A4381BhKdGdqIEwYVQ4q+TEI8aJCfHOI6ekxwZZkciJpK0qwWCCpbkRAjnoO6ITJ9j0Cceoss5C4zDqFKXKpScfqBBDRHLrjyIzAd0KAGwnxRu8l8sPDladPAuITJeCT9Rf1lXUPfOwqUWUjYvUSbCqAvVS3V7mReD+nr4YIgqpSKRn6E2+3IW2FiC5GxsRKjhj3hIiJgNUqICoBSpj6Af2Z6+LyThn3VZqEKZbVZfUS9QnZjVrETmjsBdj2DJvGwLx2zUfMli0FajZOCC9unxUBWQW66k6XCxSjmDdvF5fwigErTUFTgsgcVJ8zkqXaRcgsVZ/K4+MJcQyAQwCYqyIgDoDBAfDc5M5DBIyI0LLyDMYAXMcE05jwi21U9mJksQtKdMwslEcBVFRloeAyY5WahAlPjp2TSlMh3qpLCLyMBDVyyqlwV8PLxtEiqwzVTl6dALmz6PJ90goRE2l0+HHv6RnMEJDh24DwCGM9bwLDLiD+dNb67wHgGgAcsZCVvwEIPztErGKCT00W4WlRWCAckOghR3J6J1VLLc92cW4J6mRvtQpL5Ut0aMTbse9XfPqFD/uxlaEMmsax8mSlncXXm/6XKq34c/GEHuE8R/gMvTLFDyfm5zrvvgUM58YQ/xQAPuucu11uFFM8AYDnO+8+Asz/G2J4hHPuekZ8gXP4VE94Xp34tpQStlGMqglJwGJsZ6VcDYVGs6We2MtxOunL7zICEJcIMM7hPu71L+7kr880IKdCfEaAsMiKPPr/0DimF6r+ijnXKhBiktXvAxSzBAjIYjztac0yeYWhuQZAQ5pVRCOyUs5meBU8y3Kg2RFFblHaXrGnPNgXs7Ks+C6h3p1nVFj90poBHe/NUmeDBZC0WCkMsvtkxNT5biUJnDHDTrF8nGAP1R4ob8VzymVtydrluSzV40ydJjdCuVgRc6kSThbR6sr07/06R6ZL7dSS6bCsCHUdil69RO14CXj0pvmudlsLKy3JKZWWmMQW6fnCxCBSoEcC80WAcExvRHgRMBwyZjCQw2ch4M+ZjPiYQ7wQAB+rj2LxMFAnQ506ES5MKcvtp71mGfIy+3/PbvhAqdt3IOv7osy3ErQUjqo/1rvq3wpmrBStcQBKhCeHUpH5Spv4hsrhUwHgPEK4SfmHIGrwUmNsSoiqE+/OWiB0HiHnPgcANSTeDsyfbkK6LemNU7KfiJXtLbeTNu+DeseP8pMM98IXVBXoEV9aTQUrpW7flZaLjikdBovS0NDsTmJeTFKYRHFdsxqft1LBcwhxwQBf4cRiF1SWmbck5kArVmrPhYXK1wUhPBYAR4uWP2iVYEWC0dEttFu8rQzFhGQ25K86oe8Hw91UhfHAt/l8ydelDei5gowAsWvW4qIkOT9TjCnRwL8WgW8JkT+WouTmAsV8rRrOYibMYJnR0rjjtUB0Itbhg3IvTeRKGJ1l3ZW8e1DvbFJPqGWtRSU6bQexAZmWDiGljNzpeBeSat6SVaFARKO28qAkF0kApHV6w4tERMBQCfExpiEgBrEbmXEGhbwcbZeZ624QUQy0XqzZhKxBDEyuLXR+qdCkmpkjJV0PSrm96xKVPGTfhzMCCqKUiNJeyq7N3FxuNFhAZuU01uTDgiUiTTHVHWejbIzXdek3uiyrUorZVI+nGXJPf/Nzk3aMsm6XNSnCerosQtDI1D4WCZpG6kX9llkXpxQr0XWW0WxAR7ymisWt5WpKhmz2940aJ2U4r2nWQ8DapxMNFgFkI2MVoA6DGhlK3Cb2MXtQEyOhOLOo0GFxIWLgOtOcsZaVX29sZGR/nrUJD+UfLsRjaM+w6xsaPcWTlfMiaG/VkdJKylzLRk3/ZlUVCfYlCGkZJPFQqZ+NRBVwbGUdUoUqXNWAqgOpeh/SBCdB7RCPI8KxlNJuIvgeA4UM7dwwRs5zAzk4N5ugEbT8ZzezUEQeDFghwlGDE2y1URvMslbWAkgmVGgrUWtRhyRxgB1YgaBwSC/U6smyZR2lmsMYY4LvVw5+CZHOcY6OEaUfSt6gkZ6iYOmCLCgkj8AL7+k4AbwTES4AwA1gksTo1pjwbdHhx2KItVzjCEc5cZRKvt5CjaOEvrnUVAI0S+PpKAAek2tj4u9KVtaGRG1McdlDlPVnenIT1dSULRJU4mkJF7vQLpKpDcn3xQ1pGyqkb0ptAAAOeYKHOYIfEiFRwmgoz9FjF4IqtvcI4FJy9HTTURXrmBAuJOQLPdF3k4MvAeOUCH8lJn4PAOyA5WM5V8m+P5UJE91FQn4YImzIM9vI32xChCZE1G6RtNDaVNa/nCqxYD6rgJgl6hk/LVctu65yI91H5qaN0oX5kpTIs9U+QYg3OaepKlDMFWAzfj2/ohZ6IWDLHbuqeDIzMfhgR/TgzvtKXqvfY+pa8+YN8nSJbijc8UQnihdctPG2WtpigVmap7IpInrF0VKSK6G7t8GCZX+9WP4Cfem3Sd9+UcdUt1GaD//OXO0BwLpz9BTv8KqQWKUv7q9klD36GcVSqnFHEi9SfERO3nK/Rk1jCyi1AVV1LVrJ2kzhlzG9EY5R01yHT8vR6N6sTl+U+p/0C2QfLIDqkNz3aCV/8YoAzB4gc6b03q0La62oeSOtKZYa/A+byF8cenwyEZ7vHT3KBf6aR2a1GwAACtBJREFUFxyRGdwcIHfTHyXFMgRwzIlaMRTLQM5I7WIugVIJe6QEVFkUovD3DlPl8JEoZXgEWePNszrdvmgTLVpOJjxBQY/43hBFUQXf+XxlAprOx2WbWQcXWtYe3GwRaFb7NK3TB4bePxmAfeXwha3DlyQmYpRRh/4YVUG0uHsGJ4m6VYZ6EClRpfoql3VH3WX2dvqRClMxrN4ROWFA5S4hQs1nZov49zpfUCdaNCmJ0LRp2gotItRlWbyoeSpuUGv52fip20sZAaLzjQ0oSI19Uqc4mQfY3ms+srHi/pqQj3tHF3uX/jIk/hFJzpqDL/VQRuUUES5KKT2TWSUmLkvqhhbq9OoCck1K6VRi+BARflQNYQl8mSVtYiKQJkrwCMcd0R+o9We8c3sWPjqZR5jUMcpaS0/AOsdiCzISOlcPBxiQgyAxeNZRsSEEgZCNrESYLRxPFtHvzMLeZBHfcXjsLk8AG0NPV4bIL2ZGV6qjoqpSyAyR/2E4cFcCwrXM/K6UpB2W7UBXFxcHp7VBwX9DCG8gwseEkF5nDkOqyhiEFY5Qva737goAVus/mbVv35q0u7I2aakrWjMClkMUyzZZ3xv4XMvVWRXKTYOlDVjO7cjoikBssqA4WQTYnLTXro/9ixD5mPPu0mFM7wbAW4Pek0Me/YG6jVc7h9LheRYgPMuKV8tYXKuxncqXJClJ3vCJOqSrNfkVdyexAKAUfNvK4fmO8FLRrpjg9Mmd9rq9WQt7szZO5xGmOl6T9kl/OVS1hH9SG9BLFhQF4jqIbA5HDInM6TSo7efVJsHePPLuNPjNYbOzMfZXHF2v3paYcTBw1yfmR9vAF4sn01QoxhRmi/CMwcA9iRAfabGHldVKOpWzB02lhHEx8ddDTP8iEhOPmENpdAhBS/SVkzjBC8O2J+0VW9N2e3ee/M48BekSCwPK8ITZsuIGl/AvdPtu3LTEAD0EyMWLYD02kf7e3Ca+xgMKK8OId243b18b0u8NKrqIGR418PTOlMILtfdBUsqXBI6lFCiS+qwUQrWkm2sMmrnp0KO15SzKMxQIU63ylTiP1brKURhU9E5EsSVi+eMXfrS1+NvtSYs7M5kmSUp8GaLoEKCxjG0i/X5C5AsSS9YlPyjzeDqfpwZQGiMRJjLuJkMTOuXVyjwArwzoeQ86e/hfkpA45y4ZVPAtbuM1MXEFwK3aHIVfdEJrziRzTG7RWJkdXnaHtPod1SlKbkFYeYftoKKXEtIlVkCByZ3b9fNO77WwPQ24O4+8Nw86JyCDEmVsRqWviV3OcYoL3FcU5R4Ksj0QtyHcE8iZF0AZYIKBD6V7nEaD4Ace/29lgM8/fnj4iRhTW3l6IyJuLZpwPcgkGwsTVP80Ni8VHUlMSrHCKUOs0GoleZsjlha281g5wnbg3cXO0XXM0BDh4OROc/HJneZ729Pgt2cxbM8C7Ir+9zyARIIayRYmdNHukgm+b4+Wubd5A59kSFGgZLOAMyd9NtCe4aAKchykc+YJP1l5esWRNX+NOA/v4F0yqFC38T3iGTTvkIag2nuBfR5WUIOYh6Jz09LqGtZdkk6Wz8R7h+9j5oYQB9t7zSt/uFn/48ndxm9OQtieBtibBXGBqqoSBWoQ15aRuaX+9wUun04Fur5+nrCkHAtoiKsTWAlmeTByUPpsYtEIg9gnh3ytw9HhjdXqspiwqbx7t6SpdZuuQY2y2DGzmDULF/VjmVEpVMjDpYtKjpx3GCvCWFXuZZUjcaGtdO13Z+3rf3B6cc2pndadnoSwOWlha5qln63/ol2qgBHfG6juEY8HEdCfvC6ppBCsxpBSjvNFX6N2ZqyN1or+SpOOiOrLRYQb4+oy4Z/3/o1E6dxFk17EIYneVgAkEZ7kBnkRZXy+TKCSQV660wP3diK6lIFbQqx2Js3V399sLj+129Kdu006vRdgayLEB9jLuq8TZE1P/3susA/9QrMvDCh/0OQoj9d1tgClsSjtJmswllnCMjytvUBLWQmwvjwdxdNnrVVvkgDYEV26MsDHEeHvN238FkXAQE4So6geQeNdbcc77ymZvuO5A+9uAMRfzL2WanvS/tkPTtdvOSnE77R8arflzUmAnVkQ16zEl7khCd5U+n3XdzcvVPiDDNinChkFlpJmdaCYDZUgIOReZ6mTq/tyKcGb2zb+z9mHqvcD4mFAfNxo4G7zDl9VN/GtlKS7KwETWo4guu4w2HS5+xPn6A0y9GAFFp6c3Gmef7vpvDu5G9KpScub0yXxEpjpBFmJ/vqG70Dkd5AJ/i6Y0umKDvPkDF7q9xRsZEOOtRiai7FLjZLITKbgwLcxfXLRxMc+4KzhDYOKnhgTjCtHb3FDeHYT+WUt8q0S6Fh4S2kwcOdXnq5DgAtknfqOQEj/dsd2/fw7tpvvbO4Ff8dOG0TfhfjtWYTdWczQt9BXBiVtlnhJ/F1B/x4ZwHlfQuSONGRoukKHBG3yMT3Qfma+OutbaAP7NsTv1m06cfzI6DWHxtWrpZKM5E6MHNxSObo+hPhaLU17dwU5ukRnAywnTrvT5vW3b7VXntptYHsW/OZeCKenpvMi+aL34pot8MmD1FnvRXUL8XcH/7tHQP6nlMuEPOvZ5qKclCIPtJwKl4vaNCGFNnrXBIjzll9zbCPdeHS9euugoguEUCK8ZFD537ViER6SR4rUm5C+cHqvfckd281XN/da2NxrnUR52/MI21MNegz2mpwlmGqobkWbLvTtvUNwd9AvH383f1+OsJSTIuSuR6SjCl0InQe+FHpWhNBFxHkLOG9YJju/ujNtf/XYRnXxxri6wjv8mQSQCVfGfef0pL3qzp3mvVuTVqTst6cxbk/aqHCfm6vruzu1+nmCvEBfiLeo796lf6/vDHUxs9yMsj3Qbr8RLyqgtXzt9IRcQncdBHMdQeb/w6x2Mv2ddufh7w6P2w8ePVS9+PDa4JXynK1JuO7Ubvs3m9Ow2J21uDMNtDuPQSStcBdjt7CxeUnKLDstRs8IL0zv6/29EQ9n8tYYH7AHofeNzjmoKZTPcgpT7IAuSqNIS6lndYyHFjLT60Sy9R077ZvXRvX7ROmnddoSae7Ng98zwmMhWIgvCc5MCFcG9F+e2C95fU0mw/5MPv5MGAAHmKB/z6VlazYIAqQgqP2DXE3q1RTaBOOF1BMYRJ/zYLUgf0sYEBJ7eWVm3qQgEp4uLKlRPc9T4N2IvLw+00t0SulOJZ9zmTOR/Bkz4K6Y0NUQSnc4B7WlnqCVpV5KLYudVaRj7ZZNOh5UFCQcEkaGmILU7yX1trl/MXDLtFYgn6u93QtU7QFrf19g3//4M/1hnwnaHi0w66Y/DQn6GpsOT+USW0aBpNACXZ3cdBZKS5W860WI2ujLUSJhs+xF2uWlqX54a4FOJvx+Eg/39dXZzil03DCbUIjoys4dA+wNLqsv2uTpopH00dpa/ftaHyJ3c7JLK8QXVepye3W1+4Oc+0M83J93h/epg9bvrIuhzbLcbrIF2RfKDKllqW0ALbBI0lN6e8XT9PuQpY5X1EdeibMOVX/0/cdfooafBAN+LHEqJ3mfu+FgNdx+nUFHPCBI5ifN8NL06zq1NiHdf2tcSlmlorsP8sXY9cd6ftIMgH7yVIY0c3RYOkNiljVBzPNGUv8sC5bkqj+MJQMQpSnz45vFIIX4Lr/vTwndz8//A5SORvD8yym2AAAAAElFTkSuQmCC"><b>Defender Quarantine Extractor<span id="navcase"></span></b></div>
    <div id="navlinks"></div>
    <div class="tools">
      <button type="button" id="theme">Switch theme</button>
      <button type="button" onclick="window.print()">Print</button>
    </div>
  </nav>
  <main id="main"></main>
</div>
<script id="dqe-data" type="application/octet-stream">/*DQE_DATA*/</script>
<script>
(function(){
"use strict";
var KEY="/*DQE_KEY*/", ARCH=/*DQE_ARCHIVES*/;
function b64(s){var bin=atob(s),n=bin.length,u=new Uint8Array(n);for(var i=0;i<n;i++)u[i]=bin.charCodeAt(i);return u;}
var D;
try{
  var k=b64(KEY), raw=b64(document.getElementById("dqe-data").textContent.trim());
  for(var i=0;i<raw.length;i++) raw[i]^=k[i%k.length];
  D=JSON.parse(new TextDecoder("utf-8").decode(raw));
}catch(e){ document.getElementById("boot").textContent="This report could not decode its embedded data: "+e.message; return; }

function A(x){return Array.isArray(x)?x:(x==null||x===""?[]:[x]);}
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];});}
function size(n){n=Number(n)||0;if(n>=1073741824)return (n/1073741824).toFixed(2)+" GB";if(n>=1048576)return (n/1048576).toFixed(1)+" MB";if(n>=1024)return (n/1024).toFixed(1)+" KB";return n+" B";}
function num(n){return (Number(n)||0).toLocaleString("en-US");}
function leaf(p){p=String(p||"");var i=Math.max(p.lastIndexOf("\\"),p.lastIndexOf("/"));return i>=0?p.slice(i+1):p;}
var copyStore=[];
function copyBtn(text,label){copyStore.push(String(text==null?"":text));return '<button type="button" data-copy="'+(copyStore.length-1)+'">'+esc(label||"Copy")+'</button>';}
function longText(v,label){
  v=String(v==null?"":v);
  if(v.length<=260 && v.indexOf("\n")<0) return '<span class="m">'+esc(v)+'</span>';
  return '<details><summary>'+esc(label||"Show")+' ('+num(v.length)+' characters)</summary><div class="bar" style="margin:8px 0 0">'+copyBtn(v,"Copy text")+'</div><pre>'+esc(v)+'</pre></details>';
}
function kv(rows){var h='<dl class="kv">';rows.forEach(function(r){if(r&&r[1]!==""&&r[1]!=null)h+='<dt>'+esc(r[0])+'</dt><dd>'+(r[2]?r[1]:esc(r[1]))+'</dd>';});return h+'</dl>';}
function table(cols,rows,cls){
  if(!rows.length) return '<div class="box empty">Nothing to show.</div>';
  return '<div class="tw"><table'+(cls?' class="'+cls+'"':'')+'><thead><tr>'+cols.map(function(c){return '<th'+(c.n?' class="n"':'')+'>'+esc(c.h)+'</th>';}).join("")+'</tr></thead><tbody>'+
    rows.map(function(r){return '<tr>'+cols.map(function(c){return '<td'+(c.c?' class="'+c.c+'"':(c.n?' class="n"':''))+'>'+c.f(r)+'</td>';}).join("")+'</tr>';}).join("")+'</tbody></table></div>';
}
function bag(props){
  return table([
    {h:"Property",f:function(p){return '<span class="m">'+esc(p.k)+'</span>';}},
    {h:"Value",f:function(p){
      if(A(p.c).length) return '<details><summary>Nested properties ('+A(p.c).length+')</summary>'+bag(A(p.c))+'</details>';
      var v=p.v===true?"true":p.v===false?"false":p.v;
      var extra=(p.ft?' <span class="muted nowrap">= '+esc(p.ft)+' UTC</span>':'')+(p.cut?' <span class="tag warn">shortened here, full text is in the archive</span>':'');
      return longText(v,"Show value")+extra;
    }},
    {h:"Size",n:1,f:function(p){return p.len!=null?size(p.len):"";}},
    {h:"SHA-256",f:function(p){return p.sha256?'<span class="m muted">'+esc(p.sha256)+'</span>':"";}}
  ],A(props));
}

var M=D.meta||{}, S=A(D.samples), H=A(D.hives), E=A(D.entries), DH=A(D.history), T=A(D.timeline), ST=A(D.stores), SC=A(D.scans), INV=A(D.inventory), EV=A(D.events);
var NOTES=A(ARCH&&ARCH.notes?ARCH.notes:D.notes);
var resCount=E.reduce(function(a,e){return a+A(e.resources).length;},0);
var threats={}; E.forEach(function(e){if(e.threat)threats[e.threat]=1;}); DH.forEach(function(d){if(d.threat)threats[d.threat]=1;});
var threatList=Object.keys(threats);
var out=[], navs=[];
function sec(id,title,count,html,sub){
  navs.push([id,title,count]);
  out.push('<section id="'+id+'"><h2>'+esc(title)+(count!=null?'<span class="count">'+num(count)+'</span>':'')+'</h2>'+(sub?'<p class="sub">'+sub+'</p>':'')+html+'</section>');
}

/* ---- overview */
(function(){
  var h='<ul class="facts">'+
    '<li><b>'+num(S.length)+'</b> file'+(S.length===1?'':'s')+' recovered</li>'+
    '<li><b>'+num(H.length)+'</b> registry hive'+(H.length===1?'':'s')+'</li>'+
    '<li><b>'+num(E.length)+'</b> quarantine entr'+(E.length===1?'y':'ies')+', <b>'+num(resCount)+'</b> resources</li>'+
    '<li><b>'+num(DH.length)+'</b> detection history record'+(DH.length===1?'':'s')+'</li>'+
    '<li><b>'+num(T.length)+'</b> timeline events</li>'+
    '<li><b>'+num(ST.length)+'</b> scan store record'+(ST.length===1?'':'s')+'</li>'+
    (EV.length?'<li><b>'+num(EV.length)+'</b> event log entr'+(EV.length===1?'y':'ies')+'</li>':'')+'</ul>';
  if(threatList.length) h+='<p style="margin:0 0 16px">Threat name'+(threatList.length===1?'':'s')+': '+threatList.map(function(t){return '<span class="threat">'+esc(t)+'</span>';}).join(", ")+'</p>';
  var def=M.defender;
  h+='<div class="two"><div class="box">'+kv([
      ["Case ID",M.caseId],["Title",M.title],["Analyst",M.analyst],["Description",M.description],
      ["Generated",(M.generatedUtc||"")+" UTC"],["Tool",(M.tool||"")+" "+(M.version||"")]
    ])+'</div><div class="box">'+kv([
      ["Source",M.source],["Source type",M.sourceKind],
      ["Source SHA-256",M.sourceSha256&&A(M.sources).length<2?'<span class="m">'+esc(M.sourceSha256)+'</span>':"",1],
      ["Defender platform",def?def.product:""],["Engine",def?def.engine:""],["Security intelligence",def?def.antivirus+" (as of "+def.asOf+" UTC)":""]
    ])+'</div></div>';
  if(A(M.sources).length>1) h+='<h3>Sources</h3>'+table([
    {h:"Source",f:function(r){return '<span class="m">'+esc(r.path)+'</span>';}},{h:"Type",f:function(r){return esc(r.kind);}},
    {h:"Size",n:1,f:function(r){return r.size?size(r.size):"";}},{h:"SHA-256",f:function(r){return '<span class="m">'+esc(r.sha256)+'</span>';}}],A(M.sources));
  h+='<h3>Evidence archive</h3>';
  var rows=[["Archive",M.archive],["Encryption",M.encryption],["Password",'<code>'+esc(M.password)+'</code> '+copyBtn(M.password,"Copy"),1],["Original artifacts included",M.rawScope==="all"?"Everything in the source":M.rawScope==="core"?"Files the tool analyses":"None"]];
  if(ARCH&&ARCH.bundle){
    rows.push(["Archive size",size(ARCH.bundle.size)]);
    rows.push(["Archive SHA-256",'<span class="m">'+esc(ARCH.bundle.sha256)+'</span> '+copyBtn(ARCH.bundle.sha256,"Copy"),1]);
    if(ARCH.verified>=0) rows.push(["Verification",'<span class="tag ok">Passed, '+num(ARCH.verified)+' item'+(ARCH.verified===1?'':'s')+'</span>',1]);
  } else rows.push(["Archive SHA-256","Shown in the copy of this report saved next to the archive."]);
  h+='<div class="box">'+kv(rows)+'</div>';
  if(ARCH&&A(ARCH.samples).length){
    h+='<h3>Individual archives</h3>'+table([
      {h:"Zip",f:function(r){return '<span class="m">'+esc(r.file)+'</span>';}},{h:"Size",n:1,f:function(r){return size(r.size);}},
      {h:"SHA-256",f:function(r){return '<span class="m">'+esc(r.sha256)+'</span>';}}],A(ARCH.samples));
  }
  h+='<p class="sub" style="margin-top:14px">All times are UTC.</p>';
  out.push('<section id="overview"><h1>'+esc(M.title||"Defender quarantine extraction")+'</h1><p class="lede">'+esc(M.caseId?("Case "+M.caseId+" - "):"")+esc(M.source||"")+'</p>'+h+'</section>');
  navs.push(["overview","Overview",null]);
})();

/* ---- recovered files */
(function(){
  var h="";
  S.forEach(function(s){
    var chk=s.hashCheck==="match"?'<span class="tag ok">Matches Defender record</span>':s.hashCheck==="mismatch"?'<span class="tag bad">Differs from Defender record</span>':'<span class="tag">No Defender hash recorded</span>';
    h+='<article class="box card"><header><strong>'+esc(s.name)+'</strong><span class="threat">'+esc(s.threat)+'</span>'+chk+(s.truncated?'<span class="tag bad">Truncated</span>':'')+'</header>';
    h+='<div class="hash">'+
      '<span>SHA-256</span><span class="m">'+esc(s.sha256)+'</span>'+copyBtn(s.sha256)+
      (s.sha1?'<span>SHA-1</span><span class="m">'+esc(s.sha1)+'</span>'+copyBtn(s.sha1):'')+
      (s.md5?'<span>MD5</span><span class="m">'+esc(s.md5)+'</span>'+copyBtn(s.md5):'')+'</div>';
    if(s.hashNote) h+='<p class="muted" style="margin:8px 0 0; max-width:95ch">'+esc(s.hashNote)+'</p>';
    var pe=s.pe;
    h+=kv([["Original path",'<span class="m">'+esc(s.path)+'</span>',1],["Type",s.type],["Size",size(s.size)+" ("+num(s.size)+" bytes)"],
      ["PE link time",pe?pe.linkerTimestamp+" UTC":""],["Quarantined",s.quarantined?s.quarantined+" UTC":""],
      ["Created",s.created?s.created+" UTC":""],["Modified",s.modified?s.modified+" UTC":""],["Accessed",s.accessed?s.accessed+" UTC":""],
      ["Defender-recorded SHA-256",s.recordedSha256&&s.recordedSha256!==s.sha256?'<span class="m">'+esc(s.recordedSha256)+'</span>'+(s.recordedKind?' <span class="tag">'+esc(s.recordedKind)+'</span>':''):"",1],
      ["In archive",'<span class="m">'+esc(s.archivePath)+'</span>',1],["Single-file zip",s.sampleZip?'<span class="m">'+esc(s.sampleZip)+'</span>':"",1],
      ["Stored as",'<span class="m">'+esc(s.source)+'</span>',1],["Quarantine entry",A(s.entries).join(", ")]]).replace('class="kv"','class="kv" style="padding:12px 0 0"');
    var st=A(s.streams);
    if(st.length){
      h+='<h3>Other streams stored with the file</h3>'+table([
        {h:"Stream",f:function(r){return esc(r.kind)+(r.name?' <span class="m">'+esc(r.name)+'</span>':'');}},{h:"Size",n:1,f:function(r){return size(r.size);}},
        {h:"In archive",f:function(r){return '<span class="m">'+esc(r.archivePath)+'</span>';}},
        {h:"Content",f:function(r){
          var c=""; if(r.text) c+=longText(r.text,"Show text");
          var at=A(r.attributes); if(at.length) c+='<details><summary>'+at.length+' extended attribute'+(at.length===1?'':'s')+'</summary>'+table([
            {h:"Name",f:function(a){return '<span class="m">'+esc(a.name)+'</span>';}},{h:"Size",n:1,f:function(a){return num(a.size);}},{h:"Value (hex)",f:function(a){return longText(a.value,"Show hex");}}],at)+'</details>';
          return c;}}],st);
    }
    h+='</article>';
  });
  sec("files","Recovered files",S.length,h||'<div class="box empty">No file payloads were recovered. Check the Notes section and the quarantine entries below.</div>',
    "Files recovered from the Defender quarantine store.");
})();

/* ---- hives */
if(H.length) sec("hives","Quarantined registry data",H.length,table([
  {h:"Resource",f:function(r){return esc(r.type)+'<br><span class="m">'+esc(r.path)+'</span>';}},
  {h:"Threat",f:function(r){return '<span class="threat">'+esc(r.threat)+'</span>';}},
  {h:"Quarantined",c:"t",f:function(r){return esc(r.quarantined);}},{h:"Size",n:1,f:function(r){return size(r.size);}},
  {h:"SHA-256",f:function(r){return '<span class="m">'+esc(r.sha256)+'</span>';}},
  {h:"In archive",f:function(r){return '<span class="m">'+esc(r.archivePath)+'</span>';}}],H),
  "Registry keys and services removed by Defender, exported as registry hive files.");

/* ---- entries */
(function(){
  var h="";
  E.forEach(function(e){
    h+='<article class="box card"><header><strong class="threat">'+esc(e.threat)+'</strong><span class="muted">'+esc(e.time)+' UTC</span></header>'+
      kv([["Entry ID",'<span class="m">'+esc(e.id)+'</span>',1],["Scan ID",'<span class="m">'+esc(e.scanId)+'</span>',1],["Threat ID",e.threatId],["Stored as",'<span class="m">'+esc(e.source)+'</span>',1]]).replace('class="kv"','class="kv" style="padding:0 0 12px"')+
      table([
        {h:"Type",f:function(r){return '<span class="tag">'+esc(r.type)+'</span>';}},
        {h:"Path",f:function(r){return '<span class="m">'+esc(r.path)+'</span>';}},
        {h:"Size",n:1,f:function(r){return r.size?size(r.size):"";}},
        {h:"Payload ID",f:function(r){return '<span class="m muted">'+esc(r.resourceId)+'</span>';}},
        {h:"All fields",f:function(r){var f=A(r.fields);return f.length?'<details><summary>'+f.length+' field'+(f.length===1?'':'s')+'</summary>'+table([
          {h:"ID",f:function(x){return '<span class="m">'+esc(x.id)+'</span>';}},{h:"Name",f:function(x){return esc(x.name);}},{h:"Value",f:function(x){return longText(x.value,"Show value");}}],f)+'</details>':"";}}
      ],A(e.resources))+'</article>';
  });
  sec("entries","Quarantine entries",E.length,h||'<div class="box empty">No quarantine entry files were found in the source.</div>',
    "Each entry is one remediation: the threat, when it was quarantined, and every resource Defender removed with it.");
})();

/* ---- timeline */
(function(){
  var kinds={}; T.forEach(function(e){kinds[e.k]=(kinds[e.k]||0)+1;});
  var h='<div class="bar"><input type="search" id="tq" placeholder="Filter by text, path or hash" aria-label="Filter timeline">'+
    Object.keys(kinds).sort().map(function(k){return '<button type="button" class="chip" data-kind="'+esc(k)+'" aria-pressed="true">'+esc(k)+' <span class="muted">'+kinds[k]+'</span></button>';}).join("")+
    '<span class="muted" id="tcount"></span></div><div id="tl"></div>';
  sec("timeline","Timeline",T.length,T.length?h:'<div class="box empty">No dated events were found. Detection logs may be missing from the source.</div>',
    "Built from the quarantine entries, detection history, the MPLog and MPDetection logs and the event log, in time order.");
})();

/* ---- Windows event log */
(function(){
  if(!EV.length) return;
  var srt=EV.slice().sort(function(a,b){return String(a.time).localeCompare(String(b.time));});
  sec("events","Event log",EV.length,table([
    {h:"Time (UTC)",c:"t",f:function(e){return esc(e.time);}},
    {h:"Event",f:function(e){return '<span class="tag'+(/^(1006|1015|1116|1118|1119|1121|1123|1126|5001|5010|5012|5013)$/.test(String(e.id))?' bad':/^(1007|1117)$/.test(String(e.id))?' ok':'')+'">'+esc(e.id)+'</span> '+esc(e.name);}},
    {h:"Detail",f:function(e){var d=e.data||{},k=Object.keys(d);return '<span class="m">'+esc(e.summary)+'</span>'+(k.length?'<details><summary>All fields ('+k.length+')</summary>'+table([{h:"Field",f:function(x){return esc(x);}},{h:"Value",f:function(x){return longText(d[x],"Show value");}}],k)+'</details>':'');}},
    {h:"Source",f:function(e){return '<span class="muted nowrap">'+esc(e.source)+'</span>';}}],srt.slice(0,5000)),
    "Defender's operational event log: detections, actions, quarantine restores and deletions, attack surface reduction and configuration changes.");
})();

/* ---- detection history */
(function(){
  var h="";
  DH.forEach(function(d){
    h+='<article class="box card"><header><strong class="threat">'+esc(d.threat)+'</strong>'+(d.status?'<span class="tag">'+esc(d.status)+'</span>':'')+'<span class="muted">'+esc(d.firstTime)+(d.lastTime&&d.lastTime!==d.firstTime?' to '+esc(d.lastTime):'')+' UTC</span></header>'+
      kv([["Detection ID",'<span class="m">'+esc(d.detectionId)+'</span>',1],["Threat ID",d.threatId],["Severity",d.severity],["Category",d.category],
          ["Quarantine entry",d.quarantineId?'<span class="m">'+esc(d.quarantineId)+'</span>':"",1],["Stored as",'<span class="m">'+esc(d.source)+'</span>',1]]).replace('class="kv"','class="kv" style="padding:0 0 12px"');
    var tail=A(d.tail).concat(A(d.header));
    if(tail.length) h+='<details><summary>Accounts, processes, times and raw header values ('+tail.length+')</summary>'+table([{h:"Field",f:function(x){return esc(x.name);}},{h:"Value",f:function(x){return '<span class="m">'+esc(x.value)+'</span>';}}],tail)+'</details>';
    A(d.resources).forEach(function(r){
      h+='<h3><span class="tag">'+esc(r.type)+'</span> <span class="m" style="font-weight:400">'+esc(r.path)+'</span></h3>'+(A(r.props).length?'<details><summary>Threat tracking properties ('+A(r.props).length+')</summary>'+bag(r.props)+'</details>':'');
    });
    h+='</article>';
  });
  if(DH.length) sec("history","Detection history",DH.length,h,"Defender's own record of each detection, including the hashes and signature details it tracked per resource.");
})();

/* ---- stores */
(function(){
  if(!ST.length) return;
  var h="";
  ST.forEach(function(s){
    var p=A(s.props), get=function(k){for(var i=0;i<p.length;i++)if(p[i].k===k)return p[i].v;return "";};
    var title=s.kind==="AMSI capture"?(get("AMSIContentName")||get("AMSIApp")):s.kind==="Scan context"?(get("CONTEXT_DATA_FILEPATH")||get("CONTEXT_DATA_FILENAME")):"";
    h+='<article class="box card"><header><strong>'+esc(s.kind)+'</strong><span class="m muted">'+esc(s.id)+'</span></header>'+
      (title?'<p class="m" style="margin:0 0 10px">'+esc(title)+'</p>':'')+'<details><summary>'+p.length+' propert'+(p.length===1?'y':'ies')+'</summary>'+bag(p)+'</details></article>';
  });
  sec("stores","Script captures and scan context",ST.length,h,
    "Records from Defender's scan history store: script content it inspected through AMSI, and the context it kept for scanned files. Long values are collapsed; full text is also in the archive under decoded/store.");
})();

/* ---- scans */
(function(){
  if(!SC.length) return;
  var hit=SC.filter(function(s){return A(s.threats).length;}), rest=SC.filter(function(s){return !A(s.threats).length;});
  var cols=[
    {h:"Start",c:"t",f:function(s){return esc(s.start);}},{h:"End",c:"t",f:function(s){return esc(s.end);}},{h:"Kind",f:function(s){return esc(s.kind);}},
    {h:"Scan ID",f:function(s){return '<span class="m">'+esc(s.scanId)+'</span>';}},
    {h:"Threats",f:function(s){return A(s.threats).map(function(t){return '<span class="threat">'+esc(t)+'</span>';}).join("<br>");}},
    {h:"Resources",f:function(s){var r=A(s.resources);return r.length?'<details><summary>'+r.length+'</summary>'+r.map(function(x){return '<div><span class="tag">'+esc(x.type)+'</span> <span class="m">'+esc(x.path)+'</span></div>';}).join("")+'</details>':"";}}];
  var srt=function(a,b){return String(a.start).localeCompare(String(b.start));};
  var h=(hit.length?'<h3>Scans that found something</h3>'+table(cols,hit.sort(srt)):'<p class="sub">None of the stored scan results recorded a threat.</p>')+
    (rest.length?'<details style="margin-top:14px"><summary>'+rest.length+' scan'+(rest.length===1?'':'s')+' with no detection</summary>'+table(cols.slice(0,4),rest.sort(srt))+'</details>':'');
  sec("scans","Scan history",SC.length,h,"Stored scan results. Threat names and resources are read from the result records.");
})();

/* ---- inventory */
(function(){
  var kinds={entry:"Quarantine entry",resdata:"Quarantined payload",resmeta:"Payload index",dh:"Detection history",store:"Scan store",result:"Scan result",histlog:"History log",mpdet:"Detection log",mplog:"Protection log",evtx:"Event log",mpcmdrun:"MpCmdRun log",container:"Archive (opened)",other:"Other"};
  var inZip=INV.filter(function(r){return r.inArchive;}).length, total=INV.reduce(function(a,r){return a+(Number(r.size)||0);},0);
  var h='<div class="bar"><input type="search" id="iq" placeholder="Filter by path" aria-label="Filter source files"><span class="muted">'+num(inZip)+' of '+num(INV.length)+' copied into the archive under raw/ - '+size(total)+' in the source</span></div><div id="inv"></div>';
  window.__inv=function(q){
    q=(q||"").toLowerCase(); var rows=INV.filter(function(r){return !q||r.path.toLowerCase().indexOf(q)>=0;});
    document.getElementById("inv").innerHTML=table([
      {h:"Path in source",f:function(r){return '<span class="m">'+esc(r.path)+'</span>';}},{h:"Kind",f:function(r){return esc(kinds[r.kind]||r.kind);}},
      {h:"Size",n:1,f:function(r){return size(r.size);}},{h:"Modified",c:"t",f:function(r){return esc(r.modified);}},
      {h:"In archive",f:function(r){return r.inArchive?'<span class="tag ok">Copied</span>':'<span class="tag">Not copied</span>';}}],rows.slice(0,3000))+(rows.length>3000?'<p class="sub">Showing the first 3,000 of '+num(rows.length)+'. Use the filter to narrow.</p>':'');
  };
  sec("inventory","Source files",INV.length,h,"Every Defender artifact found in the source, and whether its original bytes were copied into the archive.");
})();

/* ---- notes */
(function(){
  var h=NOTES.length?NOTES.map(function(n){return '<div class="note '+esc(n.level)+'"><span class="tag '+(n.level==="error"?"bad":"warn")+'">'+esc(n.level==="error"?"Error":"Warning")+'</span> '+esc(n.text)+'</div>';}).join(""):'<div class="box empty">Everything in the source was read and decoded without warnings.</div>';
  sec("notes","Notes",NOTES.length||null,h,"Anything that could not be read, decoded or verified during this run.");
})();

document.getElementById("main").innerHTML=out.join("")+'<footer>Generated by <a href="https://github.com/akhil-dara/Defender-Quarantine-Extractor" target="_blank" rel="noopener noreferrer">'+esc(M.tool||"")+'</a> '+esc(M.version||"")+' on '+esc(M.generatedUtc||"")+' UTC.</footer>';
document.getElementById("navlinks").innerHTML=navs.map(function(n){return '<a href="#'+n[0]+'">'+esc(n[1])+(n[2]!=null?'<i>'+num(n[2])+'</i>':'')+'</a>';}).join("");
document.getElementById("navcase").textContent=M.caseId||"";
document.title=(M.caseId?M.caseId+" - ":"")+(M.title||"Defender quarantine extraction");
document.getElementById("boot").remove(); document.getElementById("app").hidden=false;
if(location.hash){var jump=document.getElementById(location.hash.slice(1)); if(jump){document.documentElement.style.scrollBehavior='auto'; jump.scrollIntoView({block:'start'}); setTimeout(function(){document.documentElement.style.scrollBehavior='';},0);}}

/* ---- timeline rendering + filters */
var off={};
function drawTimeline(){
  var el=document.getElementById("tl"); if(!el) return;
  var q=(document.getElementById("tq").value||"").toLowerCase();
  var rows=T.filter(function(e){return !off[e.k]&&(!q||(e.x+" "+e.src+" "+e.k+" "+(e.d||"")).toLowerCase().indexOf(q)>=0);});
  document.getElementById("tcount").textContent=rows.length===T.length?"":num(rows.length)+" of "+num(T.length)+" shown";
  el.innerHTML=rows.length?table([
    {h:"Time (UTC)",c:"t",f:function(e){return esc(e.t);}},
    {h:"Event",f:function(e){return '<span class="tag'+(/Detection|Blocked|block|Threat/.test(e.k)?' bad':/Remediation|Quarantined/.test(e.k)?' ok':'')+'">'+esc(e.k)+'</span>';}},
    {h:"Detail",f:function(e){return '<span class="m">'+esc(e.x)+'</span>'+(e.d?'<details><summary>Full block</summary><pre>'+esc(e.d)+'</pre></details>':'');}},
    {h:"Source",f:function(e){return '<span class="muted nowrap">'+esc(e.src)+'</span>';}}],rows.slice(0,5000)):'<div class="box empty">No events match. Clear the filter or turn an event type back on.</div>';
}
if(document.getElementById("tq")){
  document.getElementById("tq").addEventListener("input",drawTimeline);
  Array.prototype.forEach.call(document.querySelectorAll(".chip"),function(b){b.addEventListener("click",function(){var k=b.getAttribute("data-kind");off[k]=!off[k];b.setAttribute("aria-pressed",off[k]?"false":"true");drawTimeline();});});
  drawTimeline();
}
if(document.getElementById("iq")){ document.getElementById("iq").addEventListener("input",function(e){window.__inv(e.target.value);}); window.__inv(""); }

/* ---- copy, theme, nav highlight */
document.addEventListener("click",function(ev){
  var b=ev.target.closest?ev.target.closest("[data-copy]"):null; if(!b) return;
  var text=copyStore[Number(b.getAttribute("data-copy"))], old=b.textContent;
  var done=function(){b.textContent="Copied";b.classList.add("done");setTimeout(function(){b.textContent=old;b.classList.remove("done");},1400);};
  var legacy=function(){var t=document.createElement("textarea");t.value=text;t.style.position="fixed";t.style.opacity="0";document.body.appendChild(t);t.select();try{document.execCommand("copy");done();}catch(e){b.textContent="Copy failed";}document.body.removeChild(t);};
  if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(text).then(done,legacy);}else legacy();
});
document.getElementById("theme").addEventListener("click",function(){
  var r=document.documentElement, cur=r.getAttribute("data-theme")||(window.matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light");
  r.setAttribute("data-theme",cur==="dark"?"light":"dark");
});
if("IntersectionObserver" in window){
  var links={}; Array.prototype.forEach.call(document.querySelectorAll("#navlinks a"),function(a){links[a.getAttribute("href").slice(1)]=a;});
  var io=new IntersectionObserver(function(es){es.forEach(function(e){if(e.isIntersecting){Object.keys(links).forEach(function(k){links[k].classList.remove("on");});if(links[e.target.id])links[e.target.id].classList.add("on");}});},{rootMargin:"-10% 0px -80% 0px"});
  Array.prototype.forEach.call(document.querySelectorAll("main section"),function(s){io.observe(s);});
}
})();
</script>
</body>
</html>
'@

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

$script:DqeVersion = '1.0.0'
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

# =====================================================================================================================
#  WINDOW
#  WPF, declared in XAML and wired up with PowerShell script blocks. All long work runs in one background runspace
#  that holds the engine, so the window stays responsive and the derived keystream is reused between actions. The UI
#  thread polls a synchronized hashtable every 150 ms for progress, log lines and completion.
# =====================================================================================================================
$DqeXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Defender Quarantine Extractor" Width="1240" Height="860" MinWidth="640" MinHeight="420" WindowStartupLocation="CenterScreen"
        Background="#14171C" Foreground="#E6E9EE" FontFamily="Segoe UI" FontSize="13" AllowDrop="True" UseLayoutRounding="True" TextOptions.TextFormattingMode="Display">
  <Window.Resources>
    <SolidColorBrush x:Key="Bg" Color="#14171C"/><SolidColorBrush x:Key="Surface" Color="#1B1F26"/><SolidColorBrush x:Key="Field" Color="#10131A"/>
    <SolidColorBrush x:Key="Line" Color="#2C333E"/><SolidColorBrush x:Key="Ink" Color="#E6E9EE"/><SolidColorBrush x:Key="Muted" Color="#9AA3B2"/>
    <SolidColorBrush x:Key="Accent" Color="#E8A33D"/><SolidColorBrush x:Key="AccentInk" Color="#1A1305"/><SolidColorBrush x:Key="Hover" Color="#242A34"/>
    <SolidColorBrush x:Key="Sel" Color="#33290F"/><SolidColorBrush x:Key="Ok" Color="#74D39C"/><SolidColorBrush x:Key="Bad" Color="#FF8F86"/>
    <Style TargetType="TextBlock"><Setter Property="Foreground" Value="{StaticResource Ink}"/></Style>
    <Style x:Key="Label" TargetType="TextBlock"><Setter Property="Foreground" Value="{StaticResource Muted}"/><Setter Property="Margin" Value="0,8,0,3"/><Setter Property="FontSize" Value="12"/></Style>
    <Style x:Key="Cell" TargetType="TextBlock"><Setter Property="TextWrapping" Value="Wrap"/><Setter Property="Foreground" Value="{StaticResource Ink}"/></Style>
    <Style x:Key="Head" TargetType="TextBlock"><Setter Property="Foreground" Value="{StaticResource Ink}"/><Setter Property="FontSize" Value="14"/><Setter Property="FontWeight" Value="SemiBold"/></Style>
    <Style TargetType="TextBox">
      <Setter Property="Background" Value="{StaticResource Field}"/><Setter Property="Foreground" Value="{StaticResource Ink}"/><Setter Property="CaretBrush" Value="{StaticResource Ink}"/>
      <Setter Property="BorderBrush" Value="{StaticResource Line}"/><Setter Property="BorderThickness" Value="1"/><Setter Property="Padding" Value="7,4"/><Setter Property="MinHeight" Value="30"/><Setter Property="VerticalContentAlignment" Value="Center"/><Setter Property="SelectionBrush" Value="{StaticResource Accent}"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="TextBox">
        <Border x:Name="b" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1" CornerRadius="5"><ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}" VerticalAlignment="{TemplateBinding VerticalContentAlignment}"/></Border>
        <ControlTemplate.Triggers>
          <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="BorderBrush" Value="#46505F"/></Trigger>
          <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="b" Property="BorderBrush" Value="{StaticResource Accent}"/></Trigger>
          <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.55"/></Trigger>
        </ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter>
    </Style>
    <Style TargetType="Button">
      <Setter Property="Background" Value="{StaticResource Surface}"/><Setter Property="Foreground" Value="{StaticResource Ink}"/><Setter Property="BorderBrush" Value="{StaticResource Line}"/>
      <Setter Property="Padding" Value="14,7"/><Setter Property="MinHeight" Value="32"/><Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
        <Border x:Name="b" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1" CornerRadius="5">
          <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" Margin="{TemplateBinding Padding}" RecognizesAccessKey="True"/></Border>
        <ControlTemplate.Triggers>
          <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="{StaticResource Hover}"/><Setter TargetName="b" Property="BorderBrush" Value="#46505F"/></Trigger>
          <Trigger Property="IsPressed" Value="True"><Setter TargetName="b" Property="Background" Value="#10131A"/></Trigger>
          <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="b" Property="BorderBrush" Value="{StaticResource Accent}"/></Trigger>
          <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.45"/><Setter Property="Cursor" Value="Arrow"/></Trigger>
        </ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter>
    </Style>
    <Style x:Key="Primary" TargetType="Button">
      <Setter Property="Background" Value="{StaticResource Accent}"/><Setter Property="Foreground" Value="{StaticResource AccentInk}"/><Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Padding" Value="20,8"/><Setter Property="MinHeight" Value="36"/><Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
        <Border x:Name="b" Background="{TemplateBinding Background}" CornerRadius="5" BorderThickness="1" BorderBrush="{TemplateBinding Background}">
          <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" Margin="{TemplateBinding Padding}" RecognizesAccessKey="True"/></Border>
        <ControlTemplate.Triggers>
          <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="#F2B458"/></Trigger>
          <Trigger Property="IsPressed" Value="True"><Setter TargetName="b" Property="Background" Value="#C98A2C"/></Trigger>
          <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="b" Property="BorderBrush" Value="#FFFFFF"/></Trigger>
          <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.4"/><Setter Property="Cursor" Value="Arrow"/></Trigger>
        </ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter>
    </Style>
    <Style TargetType="CheckBox"><Setter Property="Foreground" Value="{StaticResource Ink}"/><Setter Property="Margin" Value="0,5,0,0"/><Setter Property="VerticalContentAlignment" Value="Center"/><Setter Property="Cursor" Value="Hand"/></Style>
    <Style TargetType="RadioButton"><Setter Property="Foreground" Value="{StaticResource Ink}"/><Setter Property="Margin" Value="0,6,0,0"/><Setter Property="VerticalContentAlignment" Value="Center"/><Setter Property="Cursor" Value="Hand"/></Style>
    <Style TargetType="ToolTip"><Setter Property="Background" Value="#242A34"/><Setter Property="Foreground" Value="#E6E9EE"/><Setter Property="BorderBrush" Value="#46505F"/><Setter Property="Padding" Value="8,5"/></Style>
    <Style TargetType="Thumb" x:Key="BarThumb"><Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Thumb"><Border CornerRadius="4" Background="#3A4350" Margin="2"/></ControlTemplate></Setter.Value></Setter></Style>
    <Style TargetType="ScrollBar">
      <Setter Property="Background" Value="Transparent"/><Setter Property="Width" Value="12"/><Setter Property="MinWidth" Value="12"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="ScrollBar">
        <Grid Background="Transparent"><Track x:Name="PART_Track" IsDirectionReversed="True"><Track.Thumb><Thumb Style="{StaticResource BarThumb}"/></Track.Thumb></Track></Grid>
      </ControlTemplate></Setter.Value></Setter>
      <Style.Triggers><Trigger Property="Orientation" Value="Horizontal">
        <Setter Property="Width" Value="Auto"/><Setter Property="MinWidth" Value="0"/><Setter Property="Height" Value="12"/><Setter Property="MinHeight" Value="12"/>
        <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="ScrollBar">
          <Grid Background="Transparent"><Track x:Name="PART_Track"><Track.Thumb><Thumb Style="{StaticResource BarThumb}"/></Track.Thumb></Track></Grid>
        </ControlTemplate></Setter.Value></Setter></Trigger></Style.Triggers>
    </Style>
    <Style TargetType="DataGridColumnHeader">
      <Setter Property="Background" Value="#171A20"/><Setter Property="Foreground" Value="{StaticResource Muted}"/><Setter Property="Padding" Value="10,8"/><Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="BorderBrush" Value="{StaticResource Line}"/><Setter Property="BorderThickness" Value="0,0,0,1"/><Setter Property="HorizontalContentAlignment" Value="Left"/>
      <Setter Property="ContentTemplate"><Setter.Value><DataTemplate><TextBlock Text="{Binding}" TextWrapping="Wrap"/></DataTemplate></Setter.Value></Setter>
    </Style>
    <Style TargetType="DataGridCell">
      <Setter Property="BorderThickness" Value="0"/><Setter Property="Foreground" Value="{StaticResource Ink}"/><Setter Property="FocusVisualStyle" Value="{x:Null}"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="DataGridCell"><Border Background="{TemplateBinding Background}" Padding="10,6"><ContentPresenter VerticalAlignment="Center"/></Border></ControlTemplate></Setter.Value></Setter>
      <Style.Triggers><Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="{StaticResource Sel}"/><Setter Property="Foreground" Value="{StaticResource Ink}"/></Trigger></Style.Triggers>
    </Style>
    <Style TargetType="DataGridRow">
      <Setter Property="Background" Value="Transparent"/>
      <Style.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="{StaticResource Hover}"/></Trigger>
        <Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="{StaticResource Sel}"/></Trigger></Style.Triggers>
    </Style>
    <Style TargetType="ProgressBar">
      <Setter Property="Height" Value="6"/><Setter Property="Foreground" Value="{StaticResource Accent}"/><Setter Property="Background" Value="#242A34"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="ProgressBar">
        <Grid><Border x:Name="PART_Track" Background="{TemplateBinding Background}" CornerRadius="3"/>
          <Border x:Name="PART_Indicator" Background="{TemplateBinding Foreground}" CornerRadius="3" HorizontalAlignment="Left"/></Grid>
      </ControlTemplate></Setter.Value></Setter>
    </Style>
  </Window.Resources>
  <!-- On small or highly scaled screens the layout keeps a usable minimum size and scrolls instead of clipping. -->
  <ScrollViewer x:Name="RootScroll" HorizontalScrollBarVisibility="Auto" VerticalScrollBarVisibility="Auto" Focusable="False">
  <Border Padding="20,16,20,16" MinWidth="780" MinHeight="520"
          Width="{Binding ViewportWidth, ElementName=RootScroll}" Height="{Binding ViewportHeight, ElementName=RootScroll}">
  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*" MinHeight="150"/><!-- list and options -->
      <RowDefinition Height="12"/><RowDefinition Height="0.22*" MinHeight="58" MaxHeight="420"/><!-- activity log --><RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <Grid Grid.Row="0" Margin="0,0,0,10">
      <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
      <Image x:Name="ImgEmblem" Width="34" Height="34" Margin="0,0,12,0" RenderOptions.BitmapScalingMode="HighQuality"/>
      <TextBlock Grid.Column="1" Text="Defender Quarantine Extractor" FontSize="18" FontWeight="SemiBold" VerticalAlignment="Center"/>
      <TextBlock x:Name="TxtVersion" Grid.Column="2" Foreground="{StaticResource Muted}" FontSize="12" VerticalAlignment="Center"/>
    </Grid>

    <Border Grid.Row="1" Background="{StaticResource Surface}" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="8" Padding="14,10" Margin="0,0,0,10">
      <Grid>
        <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
        <Grid.RowDefinitions><RowDefinition/><RowDefinition/><RowDefinition/></Grid.RowDefinitions>
        <TextBlock Text="Source" Style="{StaticResource Head}" VerticalAlignment="Center" Margin="0,0,14,0"/>
        <TextBox x:Name="TxtSource" Grid.Column="1" ToolTip="A collected .zip or .gz, an extracted folder at any level, or several separated by semicolons. You can also drop files or folders onto this window."/>
        <Button x:Name="BtnZip" Grid.Column="2" Content="Zip..." Margin="8,0,0,0" ToolTip="Choose one or more collected archives (.zip, .gz)."/>
        <Button x:Name="BtnFolder" Grid.Column="3" Content="Folder..." Margin="8,0,0,0" ToolTip="Choose an extracted collection, a Windows Defender folder, or a folder of loose Defender files."/>
        <Button x:Name="BtnLoad" Grid.Column="4" Grid.ColumnSpan="2" Content="Load" Margin="8,0,0,0" MinWidth="104" HorizontalAlignment="Right"/>
        <TextBlock Grid.Row="1" Text="Save to" Style="{StaticResource Head}" VerticalAlignment="Center" Margin="0,8,14,0"/>
        <TextBox x:Name="TxtOut" Grid.Row="1" Grid.Column="1" Margin="0,8,0,0" ToolTip="Folder for the encrypted archive and the report."/>
        <Button x:Name="BtnOut" Grid.Row="1" Grid.Column="2" Grid.ColumnSpan="2" Content="Choose folder..." Margin="8,8,0,0"/>
        <Grid Grid.Row="1" Grid.Column="4" Grid.ColumnSpan="2" Margin="8,8,0,0">
          <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
          <TextBlock Text="Zip password" Foreground="{StaticResource Muted}" FontSize="12" VerticalAlignment="Center" Margin="0,0,8,0"/>
          <TextBox x:Name="TxtSrcPw" Grid.Column="1" MinWidth="110" FontFamily="Consolas" ToolTip="Password of a protected input archive. Common sample passwords are tried automatically."/>
        </Grid>
        <TextBlock x:Name="TxtSummary" Grid.Row="2" Grid.Column="1" Grid.ColumnSpan="5" Foreground="{StaticResource Muted}" Margin="0,8,0,0" TextWrapping="Wrap"
                   Text="Select a collected archive or folder."/>
      </Grid>
    </Border>

    <Grid Grid.Row="2">
      <Grid.ColumnDefinitions><ColumnDefinition Width="*" MinWidth="360"/><ColumnDefinition Width="12"/><ColumnDefinition Width="300" MinWidth="240" MaxWidth="600"/></Grid.ColumnDefinitions>
      <GridSplitter Grid.Column="1" Width="12" HorizontalAlignment="Stretch" VerticalAlignment="Stretch" Background="Transparent" Cursor="SizeWE"
                    ResizeDirection="Columns" ResizeBehavior="PreviousAndNext" Focusable="False" ToolTip="Drag to resize"/>
      <Border Background="{StaticResource Surface}" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="8">
        <Grid>
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
          <Grid Margin="14,12,14,10">
            <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
            <TextBlock Text="Quarantined items" Style="{StaticResource Head}" VerticalAlignment="Center"/>
            <StackPanel Grid.Column="1" Orientation="Horizontal">
              <Button x:Name="BtnOne" Content="Save selected as zip..." Padding="10,4" MinHeight="26" Margin="0,0,12,0" IsEnabled="False"
                      ToolTip="Writes the selected item to its own archive, with the password and encryption set on the right. Also available by double-click or right-click."/>
              <Button x:Name="BtnAll" Content="Tick all" Padding="10,4" MinHeight="26"/>
              <Button x:Name="BtnNone" Content="Untick all" Padding="10,4" MinHeight="26" Margin="6,0,0,0"/>
            </StackPanel>
          </Grid>
          <DataGrid x:Name="Grid" Grid.Row="1" AutoGenerateColumns="False" CanUserAddRows="False" CanUserDeleteRows="False" HeadersVisibility="Column" SelectionMode="Single" SelectionUnit="FullRow"
                    Background="Transparent" RowBackground="Transparent" BorderThickness="0" GridLinesVisibility="Horizontal" HorizontalGridLinesBrush="#242A34"
                    RowHeaderWidth="0" IsReadOnly="False" CanUserResizeRows="False" CanUserResizeColumns="True" CanUserSortColumns="True" CanUserReorderColumns="True"
                    HorizontalScrollBarVisibility="Auto" VerticalScrollBarVisibility="Auto" ScrollViewer.CanContentScroll="True" EnableRowVirtualization="True">
            <DataGrid.Columns>
              <DataGridTemplateColumn Header="Export" Width="Auto" MinWidth="80" CanUserResize="False" CanUserSort="False" CanUserReorder="False">
                <DataGridTemplateColumn.CellTemplate><DataTemplate>
                  <CheckBox IsChecked="{Binding Sel, Mode=TwoWay, UpdateSourceTrigger=PropertyChanged}" IsEnabled="{Binding CanExport}" HorizontalAlignment="Center" Margin="0"/>
                </DataTemplate></DataGridTemplateColumn.CellTemplate>
              </DataGridTemplateColumn>
              <DataGridTextColumn Header="Threat" Binding="{Binding Threat}" IsReadOnly="True" Width="1.4*" MinWidth="130">
                <DataGridTextColumn.ElementStyle><Style TargetType="TextBlock" BasedOn="{StaticResource Cell}"><Setter Property="ToolTip" Value="{Binding Threat}"/></Style></DataGridTextColumn.ElementStyle>
              </DataGridTextColumn>
              <DataGridTextColumn Header="Type" Binding="{Binding Type}" IsReadOnly="True" Width="0.8*" MinWidth="106" ElementStyle="{StaticResource Cell}"/>
              <DataGridTextColumn Header="Original path" Binding="{Binding Path}" IsReadOnly="True" Width="2.4*" MinWidth="104">
                <DataGridTextColumn.ElementStyle><Style TargetType="TextBlock" BasedOn="{StaticResource Cell}"><Setter Property="ToolTip" Value="{Binding Path}"/></Style></DataGridTextColumn.ElementStyle>
              </DataGridTextColumn>
              <DataGridTextColumn Header="Size" Binding="{Binding SizeText}" SortMemberPath="SizeNum" IsReadOnly="True" Width="Auto" MinWidth="64"/>
              <DataGridTextColumn Header="Stored payload" Binding="{Binding Payload}" IsReadOnly="True" Width="0.8*" MinWidth="76" ElementStyle="{StaticResource Cell}"/>
              <DataGridTextColumn Header="Quarantined (UTC)" Binding="{Binding Detected}" IsReadOnly="True" Width="0.9*" MinWidth="104" ElementStyle="{StaticResource Cell}"/>
            </DataGrid.Columns>
          </DataGrid>
          <TextBlock x:Name="TxtEmpty" Grid.Row="1" Text="Nothing loaded yet. Quarantined files, registry keys and services will be listed here." Foreground="{StaticResource Muted}"
                     HorizontalAlignment="Center" VerticalAlignment="Center" TextWrapping="Wrap" MaxWidth="420" TextAlignment="Center"/>
        </Grid>
      </Border>

      <Border Grid.Column="2" Background="{StaticResource Surface}" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="8">
        <ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel Margin="14,12,14,14">
          <TextBlock Text="Case" Style="{StaticResource Head}"/>
          <Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="10"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
            <StackPanel><TextBlock Text="Case ID" Style="{StaticResource Label}"/><TextBox x:Name="TxtCase"/></StackPanel>
            <StackPanel Grid.Column="2"><TextBlock Text="Analyst" Style="{StaticResource Label}"/><TextBox x:Name="TxtAnalyst"/></StackPanel></Grid>
          <TextBlock Text="Title" Style="{StaticResource Label}"/><TextBox x:Name="TxtTitle"/>
          <TextBlock Text="Description" Style="{StaticResource Label}"/><TextBox x:Name="TxtDesc" AcceptsReturn="True" TextWrapping="Wrap" Height="52" VerticalScrollBarVisibility="Auto" VerticalContentAlignment="Top"/>

          <TextBlock Text="Archive" Style="{StaticResource Head}" Margin="0,16,0,0"/>
          <TextBlock Text="Password" Style="{StaticResource Label}"/><TextBox x:Name="TxtPassword" Text="infected" FontFamily="Consolas"/>
          <TextBlock Text="Encryption" Style="{StaticResource Label}"/>
          <RadioButton x:Name="RbAes" GroupName="enc" IsChecked="True" Content="AES-256" Margin="0"/>
          <RadioButton x:Name="RbZc" GroupName="enc" Content="ZipCrypto (legacy, slower)" Margin="0,4,0,0"/>
          <TextBlock Text="Original Defender artifacts to include" Style="{StaticResource Label}" Margin="0,10,0,4"/>
          <RadioButton x:Name="RbCore" GroupName="raw" IsChecked="True" Content="Files the tool analyses (recommended)" Margin="0" ToolTip="Quarantine store, detection and scan history, MPLog and MPDetection logs, event logs and history logs."/>
          <RadioButton x:Name="RbAll" GroupName="raw" Content="Everything in the source" Margin="0,4,0,0" ToolTip="Every file in the source, including logs, traces and support files the tool does not analyse."/>
          <RadioButton x:Name="RbNone" GroupName="raw" Content="None, recovered files and results only" Margin="0,4,0,0"/>
          <CheckBox x:Name="ChkPer" Content="Also write one archive per recovered file" Margin="0,12,0,0"/>
          <CheckBox x:Name="ChkVerify" Content="Verify the archive after writing" IsChecked="True"/>
          <CheckBox x:Name="ChkOpen" Content="Open the report when done" IsChecked="True"/>
        </StackPanel></ScrollViewer>
      </Border>
    </Grid>

    <GridSplitter Grid.Row="3" Height="12" HorizontalAlignment="Stretch" VerticalAlignment="Stretch" Background="Transparent" Cursor="SizeNS"
                  ResizeDirection="Rows" ResizeBehavior="PreviousAndNext" Focusable="False" ToolTip="Drag to resize the activity log"/>
    <Border Grid.Row="5" Margin="0,12,0,0">
      <Grid>
        <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
        <StackPanel VerticalAlignment="Center" Margin="0,0,16,0">
          <TextBlock x:Name="TxtStage" Text="Ready." TextTrimming="CharacterEllipsis"/>
          <ProgressBar x:Name="Bar" Minimum="0" Maximum="100" Value="0" Margin="0,7,0,0"/>
        </StackPanel>
        <Button x:Name="BtnReport" Grid.Column="1" Content="Open report" Visibility="Collapsed" Margin="0,0,8,0"/>
        <Button x:Name="BtnShow" Grid.Column="2" Content="Show in folder" Visibility="Collapsed" Margin="0,0,8,0"/>
        <Button x:Name="BtnCancel" Grid.Column="3" Content="Cancel" Visibility="Collapsed" Margin="0,0,8,0"/>
        <Button x:Name="BtnGo" Grid.Column="4" Content="Generate package" Style="{StaticResource Primary}" IsEnabled="False"/>
      </Grid>
    </Border>

    <Border Grid.Row="4" Background="{StaticResource Field}" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="8">
      <TextBox x:Name="TxtLog" IsReadOnly="True" BorderThickness="0" Background="Transparent" FontFamily="Consolas" FontSize="12" Foreground="{StaticResource Muted}"
               VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled" TextWrapping="Wrap" VerticalContentAlignment="Top" Padding="10,8" Text="Activity log"/>
    </Border>
  </Grid>
  </Border>
  </ScrollViewer>
</Window>
'@

function New-DqeWindow {
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml, System.Data, System.Windows.Forms
    $win = [Windows.Markup.XamlReader]::Parse($DqeXaml)
    $ui = @{ Win = $win }
    foreach ($n in 'ImgEmblem', 'TxtVersion', 'TxtSource', 'BtnZip', 'BtnFolder', 'BtnLoad', 'TxtSrcPw', 'TxtSummary', 'Grid', 'TxtEmpty', 'BtnAll', 'BtnNone', 'BtnOne',
        'TxtCase', 'TxtAnalyst', 'TxtTitle', 'TxtDesc', 'TxtPassword', 'RbAes', 'RbZc', 'RbCore', 'RbAll', 'RbNone', 'ChkPer', 'ChkVerify', 'ChkOpen', 'TxtOut', 'BtnOut',
        'TxtStage', 'Bar', 'BtnReport', 'BtnShow', 'BtnCancel', 'BtnGo', 'TxtLog') { $ui[$n] = $win.FindName($n) }
    $script:DqeUi = $ui
    $script:DqeSync = [hashtable]::Synchronized(@{ Log = [Collections.ArrayList]::Synchronized((New-Object Collections.ArrayList)); State = 'idle'; Pct = 0.0; Stage = ''; Cancel = $false; Model = $null; Result = $null; Error = $null })
    $script:DqeState = @{ Ps = $null; Handle = $null; Mode = ''; LogPos = 0; Table = $null; Rs = $null; Last = $null; LogText = (New-Object Text.StringBuilder) }

    try {
        $bmp = New-Object Windows.Media.Imaging.BitmapImage; $bmp.BeginInit()
        $bmp.StreamSource = New-Object IO.MemoryStream (, [Convert]::FromBase64String($DqeEmblem)); $bmp.CacheOption = 'OnLoad'; $bmp.EndInit()
        $ui.ImgEmblem.Source = $bmp; $win.Icon = $bmp
    } catch { }
    $ui.TxtVersion.Text = 'Version 1.0.0'
    $ui.TxtAnalyst.Text = $env:USERNAME
    $ui.TxtLog.Text = ''
    try {
        # WorkArea is in device-independent units, so it already reflects display scaling (125 %, 150 %, ...).
        $wa = [Windows.SystemParameters]::WorkArea
        $win.Width = [Math]::Min(1280, $wa.Width - 24); $win.Height = [Math]::Min(880, $wa.Height - 24)
        if ($wa.Width -lt 1100 -or $wa.Height -lt 720) { $win.WindowState = 'Maximized' }
    } catch { }

    # one background runspace for the whole session, so derived keystream is reused between actions
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState = 'MTA'; $rs.ThreadOptions = 'ReuseThread'; $rs.Open()
    $init = [powershell]::Create(); $init.Runspace = $rs; [void]$init.AddScript($DqeEngine.ToString()); [void]$init.Invoke(); $init.Dispose()
    $script:DqeState.Rs = $rs

    $script:DqeSay = { param([string]$m) [void]$script:DqeSync.Log.Add(('{0}|info|{1}' -f (Get-Date).ToString('HH:mm:ss'), $m)) }
    $script:DqeBusy = {
        param([bool]$busy)
        $u = $script:DqeUi; $loaded = [bool]$script:DqeSync.Model
        foreach ($n in 'BtnZip', 'BtnFolder', 'BtnLoad', 'TxtSource', 'TxtSrcPw', 'BtnAll', 'BtnNone') { $u[$n].IsEnabled = -not $busy }
        $u.BtnGo.IsEnabled = (-not $busy) -and $loaded
        $u.BtnCancel.Visibility = if ($busy) { 'Visible' } else { 'Collapsed' }
        if ($busy) { $u.BtnReport.Visibility = 'Collapsed'; $u.BtnShow.Visibility = 'Collapsed'; $u.BtnOne.IsEnabled = $false } else { & $script:DqeRowChanged }
    }
    $script:DqeStart = {
        param([string]$mode, $a)
        if ($script:DqeSync.State -eq 'running') { return }
        $S = $script:DqeSync; $S.State = 'running'; $S.Pct = 0.0; $S.Stage = 'Starting'; $S.Cancel = $false; $S.Error = $null; $S.Result = $null
        $ps = [powershell]::Create(); $ps.Runspace = $script:DqeState.Rs
        [void]$ps.AddScript('Dqe-Job $args[0] $args[1] $args[2]').AddArgument($S).AddArgument($mode).AddArgument($a)
        $script:DqeState.Ps = $ps; $script:DqeState.Mode = $mode; $script:DqeState.Handle = $ps.BeginInvoke()
        & $script:DqeBusy $true
    }
    $script:DqeRowChanged = {
        $u = $script:DqeUi; $r = $u.Grid.SelectedItem
        $can = $r -and $r['CanExport'] -and $script:DqeSync.State -ne 'running'
        $u.BtnOne.IsEnabled = [bool]$can
        $u.BtnOne.ToolTip = if (-not $r) { 'Select an item in the list first.' }
            elseif ($r['CanExport']) { 'Save {0} ({1}) to its own archive.' -f $r['Leaf'], $r['SizeText'] }
            else { 'This item has no stored content; Defender kept only its metadata.' }
    }
    $script:DqeLoad = {
        # Several sources can be given at once, separated by semicolons or new lines.
        $u = $script:DqeUi
        $paths = @($u.TxtSource.Text -split '[;\r\n]+' | ForEach-Object { $_.Trim().Trim('"') } | Where-Object { $_ })
        if ($paths.Count -eq 0) { $u.TxtSummary.Text = 'Enter or choose a zip or folder first.'; return }
        foreach ($p in $paths) { if (-not (Test-Path -LiteralPath $p)) { $u.TxtSummary.Text = "That path does not exist: $p"; return } }
        $u.TxtSource.Text = $paths -join '; '; $u.Grid.ItemsSource = $null; $u.TxtEmpty.Visibility = 'Visible'; $u.TxtEmpty.Text = 'Reading the source...'
        & $script:DqeSay ('Loading {0}' -f ($paths -join ', '))
        $pw = @(); if ($u.TxtSrcPw.Text) { $pw = @($u.TxtSrcPw.Text) }
        & $script:DqeStart 'load' @{ Paths = $paths; Passwords = $pw }
    }
    $script:DqeOnLoaded = {
        $u = $script:DqeUi; $M = $script:DqeSync.Model
        $t = New-Object Data.DataTable
        [void]$t.Columns.Add('Sel', [bool]); [void]$t.Columns.Add('CanExport', [bool])
        foreach ($c in 'Key', 'Threat', 'Type', 'Path', 'SizeText', 'Payload', 'Detected', 'Leaf') { [void]$t.Columns.Add($c, [string]) }
        [void]$t.Columns.Add('SizeNum', [int64])
        $files = 0; $hives = 0; $missing = 0
        foreach ($r in $M.Rows) {
            $can = ($r.Payload -eq 'File' -or $r.Payload -eq 'Registry hive')
            if ($r.Payload -eq 'File') { $files++ } elseif ($r.Payload -eq 'Registry hive') { $hives++ } elseif ($r.Payload -eq 'Missing') { $missing++ }
            $sz = if ($can) { if ($r.Size -ge 1MB) { '{0:N1} MB' -f ($r.Size / 1MB) } elseif ($r.Size -ge 1KB) { '{0:N1} KB' -f ($r.Size / 1KB) } else { "$($r.Size) B" } } else { '' }
            $pay = switch ($r.Payload) { 'None' { 'Metadata only' } 'Missing' { 'Missing in source' } default { $r.Payload } }
            $lf = ([string]$r.Path -replace '->\(.*\)$', ''); $i = $lf.LastIndexOf('\'); if ($i -ge 0) { $lf = $lf.Substring($i + 1) }
            $det = if ($r.Detected.Length -ge 19) { $r.Detected.Substring(0, 19) } else { $r.Detected }
            [void]$t.Rows.Add($can, $can, $r.Key, $r.Threat, $r.Type, $r.Path, $sz, $pay, $det, $lf, [int64]$r.Size)
        }
        $script:DqeState.Table = $t; $u.Grid.ItemsSource = $t.DefaultView
        $c = $M.Counts
        if ($t.Rows.Count -eq 0) {
            $u.TxtEmpty.Visibility = 'Visible'
            $u.TxtEmpty.Text = if ($M.Src.Items.Count -eq 0) { 'The source is empty.' } else { 'No quarantine entries or payloads were found in this source. Scan history and logs can still be exported with Generate package.' }
        } else { $u.TxtEmpty.Visibility = 'Collapsed' }
        $u.TxtSummary.Text = '{0} recoverable file(s), {1} registry hive(s) in {2} quarantine entr{3}{4}.   Also found: {5} detection history, {6} scan results, {7} scan store records, {8} logs{9}.' -f `
            $files, $hives, $c['entry'], $(if ($c['entry'] -eq 1) { 'y' } else { 'ies' }), $(if ($missing) { " ($missing payload(s) missing from the source)" } else { '' }), $c['dh'], $c['result'], $c['store'], ($c['mpdet'] + $c['mplog'] + $c['evtx']),
            $(if ($c['container']) { ", inside $($c['container']) nested archive(s)" } else { '' })
        $first = [string]$M.Src.Inputs[0].path
        if (-not $u.TxtOut.Text) {
            try { $u.TxtOut.Text = [IO.Path]::GetDirectoryName($first.TrimEnd('\')) } catch { }
        }
        if (-not $u.TxtTitle.Text) {
            $nm = [IO.Path]::GetFileNameWithoutExtension(([string]$M.Src.Inputs[0].name -replace '(?i)\.gz(ip)?$', ''))
            $u.TxtTitle.Text = 'Defender quarantine extraction - ' + $nm
        }
        & $script:DqeSay ('Loaded. {0} item(s) listed.' -f $t.Rows.Count)
    }
    $script:DqeArgs = {
        $u = $script:DqeUi
        if (-not $u.TxtPassword.Text) { $u.TxtStage.Text = 'Enter an archive password first.'; return $null }
        $out = $u.TxtOut.Text.Trim().Trim('"')
        if (-not $out) { $u.TxtStage.Text = 'Choose a folder to save to first.'; return $null }
        @{ OutDir = $out; Password = $u.TxtPassword.Text; Encryption = $(if ($u.RbZc.IsChecked) { 'zipcrypto' } else { 'aes' }) }
    }
    $script:DqeTick = {
        $u = $script:DqeUi; $S = $script:DqeSync; $st = $script:DqeState
        $n = $S.Log.Count
        if ($n -gt $st.LogPos) {
            for ($i = $st.LogPos; $i -lt $n; $i++) {
                $parts = ([string]$S.Log[$i]).Split('|', 3)
                [void]$st.LogText.AppendLine(('{0}  {1}{2}' -f $parts[0], $(if ($parts[1] -ne 'info') { $parts[1].ToUpper() + '  ' } else { '' }), $parts[2]))
            }
            $st.LogPos = $n; $u.TxtLog.Text = $st.LogText.ToString(); $u.TxtLog.ScrollToEnd()
        }
        if ($S.State -eq 'running') { $u.Bar.Value = [double]$S.Pct; $u.TxtStage.Text = [string]$S.Stage; return }
        if (-not $st.Ps) { return }
        try { [void]$st.Ps.EndInvoke($st.Handle) } catch { }
        $st.Ps.Dispose(); $st.Ps = $null; $mode = $st.Mode
        if ($S.State -eq 'error') {
            $u.Bar.Value = 0
            $u.TxtStage.Text = if ($S.Error -eq 'Cancelled.') { 'Cancelled. Nothing was kept.' } else { "Stopped: $($S.Error)" }
            if ($mode -eq 'load') { $u.TxtEmpty.Visibility = 'Visible'; $u.TxtEmpty.Text = 'The source could not be loaded. See the message below.' }
        } elseif ($mode -eq 'load') {
            $u.Bar.Value = 0; $u.TxtStage.Text = 'Loaded. Fill in the case details, then generate the package.'
            & $script:DqeOnLoaded
        } else {
            $R = $S.Result; $st.Last = $R; $u.Bar.Value = 100
            if ($R.Single) { $u.TxtStage.Text = 'Saved {0} as an encrypted zip.' -f $R.Name; $u.BtnShow.Visibility = 'Visible' }
            else {
                $u.TxtStage.Text = 'Done. {0} file(s), {1} registry hive(s), {2} timeline events.{3}' -f $R.Samples, $R.Hives, $R.Events, $(if ($R.Warnings) { "  $($R.Warnings) warning(s), see the report." } else { '' })
                $u.BtnReport.Visibility = 'Visible'; $u.BtnShow.Visibility = 'Visible'
                if ($u.ChkOpen.IsChecked) { try { Start-Process -FilePath $R.Report } catch { } }
            }
        }
        $S.State = 'idle'; & $script:DqeBusy $false
        if ($S.State -eq 'idle' -and $mode -ne 'load' -and $st.Last) { $u.BtnShow.Visibility = 'Visible'; if (-not $st.Last.Single) { $u.BtnReport.Visibility = 'Visible' } }
    }

    $ui.BtnZip.Add_Click({
        $d = New-Object Microsoft.Win32.OpenFileDialog; $d.Multiselect = $true; $d.Title = 'Choose the collected archive(s)'
        $d.Filter = 'Collected archives (*.zip;*.gz)|*.zip;*.gz;*.gzip|All files (*.*)|*.*'
        if ($d.ShowDialog($script:DqeUi.Win)) { $script:DqeUi.TxtSource.Text = $d.FileNames -join '; '; & $script:DqeLoad }
    })
    $ui.BtnFolder.Add_Click({
        $d = New-Object Windows.Forms.FolderBrowserDialog; $d.ShowNewFolderButton = $false
        $d.Description = 'Choose the extracted collection. Any level works: the collection root, ProgramData, Windows Defender, Quarantine, or a folder of loose Defender files.'
        if ($d.ShowDialog() -eq 'OK') { $script:DqeUi.TxtSource.Text = $d.SelectedPath; & $script:DqeLoad }
    })
    $ui.BtnOut.Add_Click({
        $d = New-Object Windows.Forms.FolderBrowserDialog; $d.Description = 'Choose where to save the archive and report'
        if ($script:DqeUi.TxtOut.Text -and (Test-Path -LiteralPath $script:DqeUi.TxtOut.Text)) { $d.SelectedPath = $script:DqeUi.TxtOut.Text }
        if ($d.ShowDialog() -eq 'OK') { $script:DqeUi.TxtOut.Text = $d.SelectedPath }
    })
    $ui.BtnLoad.Add_Click({ & $script:DqeLoad })
    $ui.TxtSource.Add_KeyDown({ param($s, $e) if ($e.Key -eq 'Return') { & $script:DqeLoad } })
    $win.Add_DragOver({ param($s, $e) if ($e.Data.GetDataPresent([Windows.DataFormats]::FileDrop)) { $e.Effects = 'Copy' } else { $e.Effects = 'None' }; $e.Handled = $true })
    $win.Add_Drop({ param($s, $e)
        if ($script:DqeSync.State -eq 'running') { return }
        $f = $e.Data.GetData([Windows.DataFormats]::FileDrop); if ($f) { $script:DqeUi.TxtSource.Text = @($f) -join '; '; & $script:DqeLoad } })
    $ui.BtnAll.Add_Click({ if ($script:DqeState.Table) { foreach ($r in $script:DqeState.Table.Rows) { if ($r['CanExport']) { $r['Sel'] = $true } } } })
    $ui.BtnNone.Add_Click({ if ($script:DqeState.Table) { foreach ($r in $script:DqeState.Table.Rows) { $r['Sel'] = $false } } })
    $ui.Grid.Add_SelectionChanged({ & $script:DqeRowChanged })
    $menu = New-Object Windows.Controls.ContextMenu
    $mItem = New-Object Windows.Controls.MenuItem; $mItem.Header = 'Save this item as zip...'; [void]$menu.Items.Add($mItem)
    $mItem.Add_Click({ $script:DqeUi.BtnOne.RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Primitives.ButtonBase]::ClickEvent))) })
    $menu.Add_Opened({ $this.Items[0].IsEnabled = $script:DqeUi.BtnOne.IsEnabled })
    $ui.Grid.ContextMenu = $menu
    $ui.Grid.Add_PreviewMouseRightButtonDown({
        param($s, $e)
        $d = $e.OriginalSource
        while ($d -and -not ($d -is [Windows.Controls.DataGridRow])) { $d = [Windows.Media.VisualTreeHelper]::GetParent($d) }
        if ($d) { $d.IsSelected = $true }
    })
    $ui.Grid.Add_MouseDoubleClick({ if ($script:DqeUi.BtnOne.IsEnabled) { $script:DqeUi.BtnOne.RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Primitives.ButtonBase]::ClickEvent))) } })
    $ui.BtnOne.Add_Click({
        $u = $script:DqeUi; $r = $u.Grid.SelectedItem; if (-not $r) { return }
        $a = & $script:DqeArgs; if (-not $a) { return }
        $d = New-Object Microsoft.Win32.SaveFileDialog; $d.Filter = 'Zip archive (*.zip)|*.zip'; $d.Title = 'Save this file as an encrypted zip'
        $d.FileName = ([regex]::Replace([string]$r['Leaf'], '[\x00-\x1f<>:"/\\|?*]', '_')) + '.zip'
        if (Test-Path -LiteralPath $a.OutDir) { $d.InitialDirectory = $a.OutDir }
        if (-not $d.ShowDialog($u.Win)) { return }
        $a.Key = [string]$r['Key']; $a.OutPath = $d.FileName
        & $script:DqeSay "Saving $($r['Leaf']) on its own."
        & $script:DqeStart 'single' $a
    })
    $ui.BtnGo.Add_Click({
        $u = $script:DqeUi; $a = & $script:DqeArgs; if (-not $a) { return }
        $a.Selected = @(); if ($script:DqeState.Table) { $a.Selected = @($script:DqeState.Table.Rows | Where-Object { $_['Sel'] } | ForEach-Object { [string]$_['Key'] }) }
        $a.CaseId = $u.TxtCase.Text.Trim(); $a.Analyst = $u.TxtAnalyst.Text.Trim(); $a.Title = $u.TxtTitle.Text.Trim(); $a.Description = $u.TxtDesc.Text.Trim()
        $a.Raw = if ($u.RbAll.IsChecked) { 'all' } elseif ($u.RbNone.IsChecked) { 'none' } else { 'core' }
        $a.PerSample = [bool]$u.ChkPer.IsChecked; $a.Verify = [bool]$u.ChkVerify.IsChecked; $a.Template = $DqeReportTemplate
        & $script:DqeSay ('Generating package with {0} item(s) ticked.' -f $a.Selected.Count)
        & $script:DqeStart 'generate' $a
    })
    $ui.BtnCancel.Add_Click({ $script:DqeSync.Cancel = $true; $script:DqeUi.TxtStage.Text = 'Cancelling...' })
    $ui.BtnReport.Add_Click({ $l = $script:DqeState.Last; if ($l -and $l.Report) { try { Start-Process -FilePath $l.Report } catch { } } })
    $ui.BtnShow.Add_Click({ $l = $script:DqeState.Last; if ($l -and $l.Zip) { try { Start-Process explorer.exe -ArgumentList ('/select,"{0}"' -f $l.Zip) } catch { } } })

    $timer = New-Object Windows.Threading.DispatcherTimer; $timer.Interval = [TimeSpan]::FromMilliseconds(150)
    $timer.Add_Tick({ try { & $script:DqeTick } catch { $script:DqeUi.TxtStage.Text = "Interface error: $($_.Exception.Message)" } })
    $script:DqeState.Timer = $timer
    $win.Add_ContentRendered({ $script:DqeState.Timer.Start() })
    $win.Add_Closed({
        try { $script:DqeState.Timer.Stop() } catch { }
        $script:DqeSync.Cancel = $true
        try { if ($script:DqeState.Ps) { $script:DqeState.Ps.Stop(); $script:DqeState.Ps.Dispose() } } catch { }
        try { if ($script:DqeSync.Model) { foreach ($h in $script:DqeSync.Model.Src.Handles) { $h.Dispose() } } } catch { }
        try { $script:DqeState.Rs.Close(); $script:DqeState.Rs.Dispose() } catch { }
    })
    $win
}

# =====================================================================================================================
#  CONSOLE MODE
# =====================================================================================================================
function Invoke-DqeConsole {
    # Runs the same engine as the window, in this session, and returns a summary object for scripting.
    param($P)
    . $DqeEngine
    $script:Sync = $null
    $paths = @(foreach ($s in $P.Source) {
        $r = Resolve-Path -LiteralPath $s -ErrorAction SilentlyContinue
        if (-not $r) { throw "Source not found: $s" }
        $r.ProviderPath
    })
    $out = if ($P.OutputDirectory) { $P.OutputDirectory } else { (Get-Location).ProviderPath }
    $out = [IO.Path]::GetFullPath($out)
    Write-Host ''
    Write-Host '  Defender Quarantine Extractor 1.0.0' -ForegroundColor Yellow
    Write-Host ('  Source : {0}' -f ($paths -join ', '))
    Write-Host ('  Output : {0}' -f $out)
    Write-Host ''
    $M = Dqe-Load $paths @($P.SourcePassword)
    try {
        $sel = @($M.Rows | Where-Object { $_.Payload -eq 'File' -or $_.Payload -eq 'Registry hive' } | ForEach-Object { $_.Key })
        $first = [IO.Path]::GetFileNameWithoutExtension(([string]$M.Src.Inputs[0].name -replace '(?i)\.gz(ip)?$', ''))
        $O = @{
            Selected = $sel; OutDir = $out; Password = $P.Password
            Encryption = $(if ($P.Encryption -eq 'ZipCrypto') { 'zipcrypto' } else { 'aes' })
            Raw = $P.IncludeOriginals.ToLowerInvariant(); PerSample = [bool]$P.PerFileZip; Verify = -not [bool]$P.SkipVerify
            CaseId = $P.CaseId; Analyst = $P.Analyst; Description = $P.Description; Template = $DqeReportTemplate
            Title = $(if ($P.Title) { $P.Title } else { 'Defender quarantine extraction - ' + $first })
        }
        $R = Dqe-Generate $M $O
    } finally {
        Dqe-CloseSource $M.Src
        Write-Progress -Activity 'Defender Quarantine Extractor' -Completed
    }
    Write-Host ''
    Write-Host ('  Archive : {0}' -f $R.Zip) -ForegroundColor Green
    Write-Host ('  Report  : {0}' -f $R.Report) -ForegroundColor Green
    Write-Host ('  Password: {0}' -f $P.Password)
    Write-Host ''
    if ($P.OpenReport) { Start-Process -FilePath $R.Report }
    [pscustomobject]@{
        Archive        = $R.Zip
        ArchiveSha256  = $R.ZipSha256
        Report         = $R.Report
        Files          = $R.Samples
        RegistryHives  = $R.Hives
        TimelineEvents = $R.Events
        Warnings       = $R.Warnings
        SampleZips     = $R.PerSampleDir
    }
}

# =====================================================================================================================
#  ENTRY POINT
#  Pasted into ISE, run from a file, or dot-sourced by the tests: the same file works in all three cases.
# =====================================================================================================================
if ($env:DQE_IMPORT_ONLY -eq '1') { return }

if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    Write-Error ("This session runs in {0} mode (typically enforced by AppLocker or WDAC). Defender Quarantine Extractor requires FullLanguage mode." -f $ExecutionContext.SessionState.LanguageMode)
    return
}

if ($PSBoundParameters.ContainsKey('Source')) {
    Invoke-DqeConsole @{
        Source = $Source; OutputDirectory = $OutputDirectory; Password = $Password; Encryption = $Encryption
        IncludeOriginals = $IncludeOriginals; SourcePassword = $SourcePassword; CaseId = $CaseId; Analyst = $Analyst
        Title = $Title; Description = $Description; PerFileZip = $PerFileZip; SkipVerify = $SkipVerify; OpenReport = $OpenReport
    }
    return
}

if ([Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA') {
    $DqeWindow = New-DqeWindow
    [void]$DqeWindow.ShowDialog()
} elseif ($PSCommandPath) {
    # WPF needs a single-threaded apartment. Some hosts run scripts on an MTA thread, so the window is opened on a
    # dedicated STA runspace in this same process instead.
    $sta = [runspacefactory]::CreateRunspace($Host)
    $sta.ApartmentState = 'STA'; $sta.ThreadOptions = 'ReuseThread'; $sta.Open()
    $ps = [powershell]::Create(); $ps.Runspace = $sta
    try { [void]$ps.AddCommand($PSCommandPath).Invoke() } finally { $ps.Dispose(); $sta.Close() }
} else {
    Write-Warning 'The window needs a single-threaded apartment. Run this in PowerShell ISE, or save it as a .ps1 file and run it.'
}
