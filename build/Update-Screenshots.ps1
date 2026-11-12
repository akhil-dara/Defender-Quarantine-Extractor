<#
.SYNOPSIS
    Regenerates the README screenshots from synthetic evidence.

.DESCRIPTION
    Generates the demo evidence, maps it to a spare drive letter with subst (so no personal paths appear), drives the
    real window through a load and a package run, renders it at 2x, then captures the HTML report in dark and light
    themes with headless Microsoft Edge. Output goes to docs\images.

    Run from Windows PowerShell 5.1:  powershell -STA -File build\Update-Screenshots.ps1
#>
[CmdletBinding()]
param([string] $Drive = 'Q:')

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$images = Join-Path $repo 'docs\images'
$work = Join-Path ([IO.Path]::GetTempPath()) 'dqe-screenshots'   # scratch output stays outside the repository
if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { throw 'Run with powershell -STA.' }
if (Test-Path "$Drive\") { throw "$Drive is already in use. Pass -Drive with a free letter." }
if (Test-Path $work) { Remove-Item -LiteralPath $work -Recurse -Force }
[void][IO.Directory]::CreateDirectory($work); [void][IO.Directory]::CreateDirectory($images)

$caseDir = Join-Path $work 'Cases\IR-2026-0412'
& (Join-Path $repo 'tests\New-DemoEvidence.ps1') -OutputDirectory (Join-Path $caseDir 'evidence') | Out-Null
Rename-Item (Join-Path $caseDir 'evidence\liveresponse.zip') 'WKS-CONTOSO-07_collection.zip'
[void][IO.Directory]::CreateDirectory((Join-Path $caseDir 'out'))

subst $Drive $work
try {
    $env:DQE_IMPORT_ONLY = '1'; . (Join-Path $repo 'Defender-Quarantine-Extractor.ps1'); Remove-Item Env:\DQE_IMPORT_ONLY
    $w = New-DqeWindow; $u = $script:DqeUi; $S = $script:DqeSync
    $w.Width = 1280; $w.Height = 800; $w.Left = -4000; $w.Top = 0; $w.ShowInTaskbar = $false; $w.ShowActivated = $false; $w.WindowStartupLocation = 'Manual'

    function Pump([int]$ms) {
        $end = (Get-Date).AddMilliseconds($ms)
        while ((Get-Date) -lt $end) {
            $f = New-Object Windows.Threading.DispatcherFrame
            [void][Windows.Threading.Dispatcher]::CurrentDispatcher.BeginInvoke([Windows.Threading.DispatcherPriority]::Background, [Action] { $f.Continue = $false })
            [Windows.Threading.Dispatcher]::PushFrame($f); Start-Sleep -Milliseconds 15
        }
    }
    function Wait-Idle { Pump 300; $end = (Get-Date).AddMinutes(5); while ($S.State -eq 'running' -or $script:DqeState.Ps) { if ((Get-Date) -gt $end) { throw 'timeout' }; Pump 150 }; Pump 400 }
    function Save-Window([string]$name) {
        $w.UpdateLayout(); Pump 250
        $W2 = [int]$w.ActualWidth; $H2 = [int]$w.ActualHeight
        $rtb = New-Object Windows.Media.Imaging.RenderTargetBitmap(($W2 * 2), ($H2 * 2), 192, 192, [Windows.Media.PixelFormats]::Pbgra32)
        $dv = New-Object Windows.Media.DrawingVisual; $dc = $dv.RenderOpen(); $dc.DrawRectangle($w.Background, $null, (New-Object Windows.Rect 0, 0, $W2, $H2)); $dc.Close()
        $rtb.Render($dv); $rtb.Render($w.Content)
        $enc = New-Object Windows.Media.Imaging.PngBitmapEncoder; $enc.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($rtb))
        $fs = [IO.File]::Create((Join-Path $images $name)); $enc.Save($fs); $fs.Dispose()
    }

    $w.Show(); Pump 600
    Save-Window 'window-start.png'
    $u.TxtSource.Text = "$Drive\Cases\IR-2026-0412\evidence\WKS-CONTOSO-07_collection.zip"
    $u.TxtOut.Text = "$Drive\Cases\IR-2026-0412\out"
    & $script:DqeLoad; Wait-Idle
    $u.TxtCase.Text = 'IR-2026-0412'; $u.TxtAnalyst.Text = 'A. Analyst'; $u.TxtTitle.Text = 'WKS-CONTOSO-07 - loader and stager quarantined'
    $u.TxtDesc.Text = 'Phishing download quarantined by real-time protection; PowerShell stager blocked through AMSI.'
    $u.ChkPer.IsChecked = $true; $u.ChkOpen.IsChecked = $false
    $row = 0; for ($i = 0; $i -lt $script:DqeState.Table.Rows.Count; $i++) { if ($script:DqeState.Table.Rows[$i]['Leaf'] -eq 'ContosoSync.exe') { $row = $i } }
    $u.Grid.SelectedIndex = $row; Pump 300
    Save-Window 'window-loaded.png'
    $u.BtnGo.RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Primitives.ButtonBase]::ClickEvent))); Wait-Idle
    Save-Window 'window-done.png'
    $report = $script:DqeState.Last.Report
    $w.Close()

    $edge = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $edge) { Write-Warning 'Microsoft Edge not found; report screenshots skipped.'; return }
    $html = [IO.File]::ReadAllText($report)
    $shots = @(
        @{ Theme = 'dark';  Name = 'overview'; Section = '' }
        @{ Theme = 'dark';  Name = 'files';    Section = 'files' }
        @{ Theme = 'dark';  Name = 'timeline'; Section = 'timeline' }
        @{ Theme = 'dark';  Name = 'history';  Section = 'history' }
        @{ Theme = 'light'; Name = 'overview'; Section = '' }
    )
    foreach ($s in $shots) {
        # Each capture gets its own copy of the report: theme fixed, and every section but the wanted one hidden, so
        # no scrolling or timing is involved.
        $page = Join-Path $caseDir ("out\shot-{0}-{1}.html" -f $s.Name, $s.Theme)
        $css = if ($s.Section) { "<style>main > section{display:none} main > section#$($s.Section){display:block} main > section#$($s.Section) h2{margin-top:4px}</style>" } else { '' }
        $doc = $html.Replace('<html lang="en">', "<html lang=""en"" data-theme=""$($s.Theme)"">").Replace('</head>', "$css</head>")
        [IO.File]::WriteAllText($page, $doc, (New-Object Text.UTF8Encoding $false))
        $png = Join-Path $images ('report-{0}-{1}.png' -f $s.Name, $s.Theme)
        if (Test-Path $png) { Remove-Item -LiteralPath $png }
        $edgeArgs = @('--headless=new', '--disable-gpu', '--hide-scrollbars', '--force-device-scale-factor=2', '--window-size=1360,860',
                      "--user-data-dir=$work\edge-profile", "--screenshot=$png", ('file:///' + ($page -replace '\\', '/')))
        Start-Process -FilePath $edge -ArgumentList ($edgeArgs | ForEach-Object { '"' + $_ + '"' }) -Wait -WindowStyle Hidden
    }
} finally {
    subst $Drive /D 2>$null
}
Get-ChildItem $images -Filter *.png | Select-Object Name, Length
