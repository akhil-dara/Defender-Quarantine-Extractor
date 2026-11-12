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
    Write-Host '  Defender Quarantine Extractor __DQE_VERSION__' -ForegroundColor Yellow
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
