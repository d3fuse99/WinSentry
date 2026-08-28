[CmdletBinding()]
param (
    [switch]$Silent = $false
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ChecksPath = Join-Path $ScriptDir "Checks.ps1"
$ConfigPath = Join-Path $ScriptDir "config.json"
$ReportPath = Join-Path $ScriptDir "Report.html"

if (Test-Path $ChecksPath) { . $ChecksPath } else { exit }

$config = if (Test-Path $ConfigPath) { Get-Content $ConfigPath -Raw | ConvertFrom-Json } else {
    [PSCustomObject]@{
        ScanSettings = [PSCustomObject]@{ TasksLimit = 15; HistorySnapshotFile = "last_scan.json" }
        ScoreWeights = [PSCustomObject]@{ Firewall=15; Defender=15; BitLocker=15; UAC=10; LsassPPL=15; PowerShellLogging=10; ControlledFolderAccess=10; NoUnsignedListeners=10 }
    }
}

if (-not $Silent) {
    Clear-Host
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "   WINSENTRY 2 - HARDENING & AUDIT" -ForegroundColor Yellow
    Write-Host "==========================================" -ForegroundColor Cyan
}

$rawOS = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
$OS = $rawOS -replace '^[^\x00-\x7F]+\s*', 'Microsoft '
$CPU = (Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue).Name
$RAM = [Math]::Round(((Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue | Measure-Object Capacity -Sum).Sum / 1GB), 0)

$Status = Get-SystemStatus
$Adv = Get-AdvancedSecurityAudit
$Admins = Get-LocalAdminsAudit
$Devices = Get-NetworkDevicesAudit
$Tasks = Get-PersistenceAudit -limit $config.ScanSettings.TasksLimit
$SuspiciousFiles = Get-SuspiciousFilesAudit

$Score = Calculate-SecurityScore -Status $Status -Adv $Adv -Weights $config.ScoreWeights

$CurrentScanPackage = [PSCustomObject]@{
    Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    Score     = $Score
    Status    = $Status
    Adv       = $Adv
    Admins    = $Admins
    Tasks     = $Tasks
}

$SnapshotFile = Join-Path $ScriptDir $config.ScanSettings.HistorySnapshotFile
$Diff = Compare-Snapshots -CurrentData $CurrentScanPackage -SnapshotFilePath $SnapshotFile

$CurrentScanPackage | ConvertTo-Json -Depth 6 | Set-Content -Path $SnapshotFile -Encoding UTF8

if (-not $Silent) {
    Write-Host "[+] Audit finished. Security Score: $Score/100" -ForegroundColor $(if ($Score -ge 80) {"Green"} elseif ($Score -ge 50) {"Yellow"} else {"Red"})
}

$ScoreClass = if ($Score -ge 80) { "ok" } elseif ($Score -ge 50) { "medium" } else { "warn" }

$DiffHtml = ""
if ($Diff.HasPrevious) {
    $diffItems = [System.Collections.Generic.List[string]]::new()
    
    if ($Diff.ScoreChange -ne 0) {
        $sign = if ($Diff.ScoreChange -gt 0) { "+$($Diff.ScoreChange)" } else { "$($Diff.ScoreChange)" }
        $diffItems.Add("<li>Score Delta: <b>$sign pts</b></li>")
    }
    foreach ($r in $Diff.Regressions) { $diffItems.Add("<li class='warn'><b>Security Regression:</b> $(Protect-HtmlString $r)</li>") }
    foreach ($p in $Diff.NewPorts) { $diffItems.Add("<li class='warn'><b>New Port Open:</b> $(Protect-HtmlString $p)</li>") }
    foreach ($p in $Diff.ClosedPorts) { $diffItems.Add("<li class='ok'><b>Port Closed:</b> $(Protect-HtmlString $p)</li>") }
    foreach ($a in $Diff.NewAdmins) { $diffItems.Add("<li class='warn'><b>New Admin Added:</b> $(Protect-HtmlString $a)</li>") }
    foreach ($t in $Diff.NewTasks) { $diffItems.Add("<li class='warn'><b>New Startup Task:</b> $(Protect-HtmlString $t)</li>") }

    if ($diffItems.Count -eq 0) {
        $DiffHtml = "<div class='diff-clean'>No suspicious delta detected since last scan. System baseline is stable.</div>"
    } else {
        $DiffHtml = "<ul class='diff-list'>" + ($diffItems -join "") + "</ul>"
    }
} else {
    $DiffHtml = "<div class='diff-clean'>Baseline snapshot created. Run the audit again later to track changes.</div>"
}

$PortRows = foreach ($p in $Adv.NetworkPortMap) {
    $sigBadge = if ($p.Signature -like "Valid*") { 
        "<span class='ok'>$(Protect-HtmlString $p.Signature)</span>" 
    } else { 
        "<span class='warn'>$(Protect-HtmlString $p.Signature)</span>" 
    }
    "<tr><td>$(Protect-HtmlString $p.LocalPort)</td><td>$(Protect-HtmlString $p.LocalAddress)</td><td>$(Protect-HtmlString $p.PID)</td><td>$(Protect-HtmlString $p.ProcessName)</td><td>$sigBadge</td></tr>"
}

$TaskRows = foreach ($t in $Tasks) {
    "<tr><td>$(Protect-HtmlString $t.TaskName)</td><td><code>$(Protect-HtmlString $t.Execute)</code></td></tr>"
}

$DeviceRows = foreach ($d in $Devices) {
    "<tr><td>$(Protect-HtmlString $d.IPAddress)</td><td>$(Protect-HtmlString $d.LinkLayerAddress)</td></tr>"
}

$FileRows = foreach ($f in $SuspiciousFiles) {
    "<li>$(Protect-HtmlString $f)</li>"
}

$AdminRows = foreach ($a in $Admins) {
    "<li>$(Protect-HtmlString $a)</li>"
}

$Html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>WinSentry 2 Dashboard</title>
    <style>
        body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0c10; color: #c9d1d9; padding: 30px; margin: 0; }
        .container { max-width: 1200px; margin: auto; }
        .header { text-align: center; margin-bottom: 25px; }
        h1 { color: #58a6ff; letter-spacing: 2px; margin: 0; font-size: 2.2em; }
        .meta { color: #8b949e; font-size: 0.85em; margin-top: 5px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 15px; }
        .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 18px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
        .full { grid-column: 1 / -1; }
        h2 { color: #79c0ff; font-size: 0.95em; text-transform: uppercase; border-bottom: 1px solid #21262d; padding-bottom: 8px; margin-top: 0; }
        .score-box { text-align: center; padding: 10px; }
        .score-val { font-size: 3.5em; font-weight: 800; }
        .ok { color: #3fb950; font-weight: bold; }
        .medium { color: #d29922; font-weight: bold; }
        .warn { color: #f85149; font-weight: bold; }
        .diff-clean { color: #3fb950; font-size: 0.9em; padding: 10px; border: 1px dashed #238636; border-radius: 6px; }
        .diff-list { list-style-type: none; padding-left: 0; font-size: 0.9em; margin: 0; }
        .diff-list li { padding: 6px 0; border-bottom: 1px solid #21262d; }
        .diff-list li:last-child { border-bottom: none; }
        table { width: 100%; border-collapse: collapse; font-size: 0.85em; margin-top: 5px; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #21262d; }
        th { color: #8b949e; }
        tr:hover { background: #1f242c; }
        code { background: #0d1117; padding: 2px 6px; border-radius: 4px; color: #ff7b72; font-size: 0.9em; word-break: break-all; }
        ul { margin: 0; padding-left: 20px; font-size: 0.9em; }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>WINSENTRY 2</h1>
        <div class="meta">$OS | CPU: $CPU | RAM: $RAM GB | Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</div>
    </div>

    <div class="grid">
        <div class="card score-box">
            <h2>SECURITY POSTURE SCORE</h2>
            <div class="score-val $ScoreClass">$Score<span style="font-size: 0.4em; color: #8b949e;">/100</span></div>
        </div>

        <div class="card">
            <h2>CORE DEFENSE</h2>
            <div>Firewall (All Profiles): <span class="$(if ($Status.Firewall){'ok'}else{'warn'})">$(if ($Status.Firewall){'ENABLED'}else{'DISABLED'})</span></div>
            <div>Real-Time Defender: <span class="$(if ($Status.Defender){'ok'}else{'warn'})">$(if ($Status.Defender){'ENABLED'}else{'DISABLED'})</span></div>
            <div>BitLocker (C:): <span class="$(if ($Status.BitLocker -eq 'ENCRYPTED'){'ok'}else{'warn'})">$($Status.BitLocker)</span></div>
            <div>UAC Level: <span class="$(if ($Status.UAC){'ok'}else{'warn'})">$(if ($Status.UAC){'OPTIMAL'}else{'BYPASSED/LOW'})</span></div>
            <div>LSASS Protection: <span class="$(if ($Adv.LsassProtection.Status -eq 'SECURE'){'ok'}else{'warn'})">$($Adv.LsassProtection.Status)</span></div>
            <div>Folder Guard (CFA): <span class="$(if ($Adv.ControlledFolderAccess.Status -eq 'ENABLED'){'ok'}else{'medium'})">$($Adv.ControlledFolderAccess.Status)</span></div>
            <div>ScriptBlock Logging: <span class="$(if ($Adv.PowerShellLogging.Status -eq 'SECURE'){'ok'}else{'medium'})">$($Adv.PowerShellLogging.Status)</span></div>
        </div>

        <div class="card">
            <h2>LOCAL ADMINISTRATORS</h2>
            <ul>$($AdminRows -join "")</ul>
        </div>

        <div class="card full">
            <h2>DELTA MONITORING (CHANGES SINCE LAST AUDIT)</h2>
            $DiffHtml
        </div>

        <div class="card full">
            <h2>ACTIVE LISTENING PORTS & BINARY INTEGRITY</h2>
            <table>
                <thead>
                    <tr><th>PORT</th><th>LOCAL ADDRESS</th><th>PID</th><th>PROCESS</th><th>SIGNATURE</th></tr>
                </thead>
                <tbody>$($PortRows -join "")</tbody>
            </table>
        </div>

        <div class="card full">
            <h2>PERSISTENCE & NON-STANDARD TASKS</h2>
            <table>
                <thead>
                    <tr><th>TASK NAME</th><th>COMMAND LINE</th></tr>
                </thead>
                <tbody>$($TaskRows -join "")</tbody>
            </table>
        </div>

        <div class="card">
            <h2>NETWORK NEIGHBORS (ARP)</h2>
            <table>
                <thead><tr><th>IP</th><th>MAC</th></tr></thead>
                <tbody>$($DeviceRows -join "")</tbody>
            </table>
        </div>

        <div class="card">
            <h2>EXECUTABLES IN TEMP & STARTUP</h2>
            <ul class="warn">$($FileRows -join "")</ul>
        </div>
    </div>
</div>
</body>
</html>
"@

[System.IO.File]::WriteAllText($ReportPath, $Html, [System.Text.Encoding]::UTF8)

if (-not $Silent) {
    Start-Process $ReportPath
}