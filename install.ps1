$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Friday -At 6pm
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSScriptRoot\Run-Audit.ps1`" -Silent"
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "WinSentry_Scheduled_Audit" -Trigger $Trigger -Action $Action -Settings $Settings -User "SYSTEM" -Force
Write-Host "[+] Scheduled background audit task registered successfully (Silent Mode)." -ForegroundColor Green