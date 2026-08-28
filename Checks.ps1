Add-Type -AssemblyName System.Web

Function Protect-HtmlString ([string]$InputString) {
    if ([string]::IsNullOrEmpty($InputString)) { return "" }
    return [System.Net.WebUtility]::HtmlEncode($InputString)
}

Function Get-SystemStatus {
    $fwProfiles = try { Get-NetFirewallProfile -Profile Domain,Public,Private -ErrorAction Stop } catch { $null }
    $firewall = if ($fwProfiles) { ($fwProfiles | Where-Object { -not $_.Enabled }).Count -eq 0 } else { $false }

    $defender = try { (Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled } catch { $false }
    
    $uac = try {
        $uacReg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction Stop
        ($uacReg.EnableLUA -eq 1) -and ($uacReg.ConsentPromptBehaviorAdmin -ne 0)
    } catch { $false }
    
    $bitlocker = "NOT ENCRYPTED"
    try {
        $bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
        if ($bl.VolumeStatus -eq "FullyEncrypted") { 
            $bitlocker = "ENCRYPTED" 
        }
    } catch {
        try {
            $wmiBl = Get-CimInstance -Namespace "Root\CIMv2\Security\MicrosoftVolumeEncryption" -ClassName "Win32_EncryptableVolume" -Filter "DriveLetter = 'C:'" -ErrorAction Stop
            if ($wmiBl.ProtectionStatus -eq 1) { 
                $bitlocker = "ENCRYPTED" 
            }
        } catch {
            $bitlocker = "NOT ENCRYPTED"
        }
    }

    $lastUpdate = try { 
        $fix = Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } | Sort-Object { [datetime]$_.InstalledOn } -Descending | Select-Object -First 1
        if ($fix) { [datetime]$fix.InstalledOn | Get-Date -Format "yyyy-MM-dd" } else { "Unknown" }
    } catch { "Unknown" }

    return [PSCustomObject]@{
        Firewall   = $firewall
        Defender   = $defender
        UAC        = $uac
        BitLocker  = $bitlocker
        LastUpdate = $lastUpdate
    }
}

Function Get-AdvancedSecurityAudit {
    $results = [Ordered]@{
        LsassProtection        = $null
        PowerShellLogging      = $null
        ControlledFolderAccess = $null
        NetworkPortMap         = @()
    }

    $results.LsassProtection = try {
        $lsa = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
        $isSecure = ($lsa.RunAsPPL -in 1,2) -or ($lsa.RunAsPPLBoot -in 1,2)
        [PSCustomObject]@{ Status = if ($isSecure) { "SECURE" } else { "VULNERABLE" } }
    } catch {
        [PSCustomObject]@{ Status = "ERROR" }
    }

    $results.PowerShellLogging = try {
        $psLog = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
        $isSecure = ($psLog.EnableScriptBlockLogging -eq 1)
        [PSCustomObject]@{ Status = if ($isSecure) { "SECURE" } else { "WARNING" } }
    } catch {
        [PSCustomObject]@{ Status = "WARNING" }
    }

    $results.ControlledFolderAccess = try {
        $cfa = (Get-MpPreference -ErrorAction Stop).EnableControlledFolderAccess
        $status = switch ($cfa) {
            1 { "ENABLED" }
            2 { "AUDIT_MODE" }
            Default { "DISABLED" }
        }
        [PSCustomObject]@{ Status = $status }
    } catch {
        [PSCustomObject]@{ Status = "DISABLED" }
    }

    $knownSystemProcs = @("System", "svchost", "lsass", "wininit", "services", "spoolsv", "csrss", "smss", "RuntimeBroker", "explorer", "dwm")

    $results.NetworkPortMap = try {
        $conns = Get-NetTCPConnection -State Listen -ErrorAction Stop
        
        $groupedConns = $conns | Group-Object LocalPort, OwningProcess
        $ports = foreach ($g in $groupedConns) {
            $first = $g.Group[0]
            $addresses = ($g.Group | Select-Object -ExpandProperty LocalAddress -Unique) -join ", "
            $pidVal = [int]$first.OwningProcess
            $procName = "System/Unknown"
            $procSigned = "Unknown"

            if ($pidVal -eq 4 -or $pidVal -eq 0) {
                $procName = "System"
                $procSigned = "Valid (OS Kernel)"
            } else {
                $p = Get-Process -Id $pidVal -ErrorAction SilentlyContinue
                if ($p) {
                    $procName = $p.Name
                    
                    if ($p.Path -and (Test-Path $p.Path)) {
                        $sig = Get-AuthenticodeSignature $p.Path -ErrorAction SilentlyContinue
                        if ($sig.Status -eq "Valid") {
                            $procSigned = "Valid"
                        } elseif ($p.Path -like "$env:SystemRoot\System32\*" -or $p.Path -like "$env:SystemRoot\SysWOW64\*") {
                            $procSigned = "Valid (System)"
                        } else {
                            $procSigned = $sig.Status.ToString()
                        }
                    } elseif ($procName -in $knownSystemProcs) {
                        $procSigned = "Valid (System)"
                    }
                }
            }

            [PSCustomObject]@{
                LocalPort    = [int]$first.LocalPort
                LocalAddress = $addresses
                PID          = $pidVal
                ProcessName  = $procName
                Signature    = $procSigned
            }
        }
        $ports | Sort-Object LocalPort -Unique
    } catch { @() }

    return [PSCustomObject]$results
}

Function Get-NetworkDevicesAudit {
    try {
        Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop | Where-Object {
            $_.State -ne "Unreachable" -and
            $_.IPAddress -notmatch '^(22[4-9]|23[0-9])\.' -and
            $_.IPAddress -ne "255.255.255.255" -and
            $_.IPAddress -ne "127.0.0.1" -and
            $_.LinkLayerAddress -and
            $_.LinkLayerAddress -ne "FF-FF-FF-FF-FF-FF"
        } | Select-Object IPAddress, LinkLayerAddress
    } catch { @() }
}

Function Get-LocalAdminsAudit {
    try {
        Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction Stop | Select-Object -ExpandProperty Name
    } catch { @() }
}

Function Get-PersistenceAudit ($limit = 15) {
    try {
        Get-ScheduledTask -ErrorAction Stop | Where-Object {
            $_.State -ne "Disabled" -and
            $_.Actions.Execute -and
            $_.Actions.Execute -notmatch '(?i)^(%windir%|%systemroot%|c:\\windows\\system32|c:\\windows\\syswow64)' -and
            $_.TaskPath -notlike "\Microsoft\Windows\*"
        } | Select-Object -First $limit | ForEach-Object {
            [PSCustomObject]@{
                TaskName = $_.TaskName
                Execute  = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join "; "
            }
        }
    } catch { @() }
}

Function Get-SuspiciousFilesAudit {
    $paths = @($env:TEMP, "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup")
    $files = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $paths) {
        if (Test-Path $p) {
            Get-ChildItem -Path $p -Include *.exe, *.bat, *.ps1, *.vbs, *.cmd -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { -not $_.Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint) } |
                ForEach-Object { $files.Add($_.FullName) }
        }
    }
    return $files
}

Function Calculate-SecurityScore ($Status, $Adv, $Weights) {
    $score = 0
    if ($Status.Firewall) { $score += $Weights.Firewall }
    if ($Status.Defender) { $score += $Weights.Defender }
    if ($Status.BitLocker -eq "ENCRYPTED") { $score += $Weights.BitLocker }
    if ($Status.UAC) { $score += $Weights.UAC }
    if ($Adv.LsassProtection.Status -eq "SECURE") { $score += $Weights.LsassPPL }
    if ($Adv.PowerShellLogging.Status -eq "SECURE") { $score += $Weights.PowerShellLogging }
    if ($Adv.ControlledFolderAccess.Status -eq "ENABLED") { $score += $Weights.ControlledFolderAccess }

    $suspiciousListeners = $Adv.NetworkPortMap | Where-Object { 
        $_.Signature -notlike "Valid*" -and $_.LocalAddress -notmatch '^(127\.0\.0\.1|::1)$'
    }
    if ($suspiciousListeners.Count -eq 0) { $score += $Weights.NoUnsignedListeners }

    return [Math]::Min(100, [Math]::Max(0, $score))
}

Function Compare-Snapshots ($CurrentData, $SnapshotFilePath) {
    $diff = [Ordered]@{
        HasPrevious = $false
        ScoreChange = 0
        NewPorts    = @()
        ClosedPorts = @()
        NewAdmins   = @()
        LostAdmins  = @()
        NewTasks    = @()
        Regressions = @()
    }

    if (-not (Test-Path $SnapshotFilePath)) {
        return $diff
    }

    $prev = try { Get-Content $SnapshotFilePath -Raw | ConvertFrom-Json } catch { $null }
    if (-not $prev) { return $diff }

    $diff.HasPrevious = $true
    $diff.ScoreChange = $CurrentData.Score - $prev.Score

    if ($prev.Status.Firewall -and -not $CurrentData.Status.Firewall) { $diff.Regressions += "Firewall was disabled" }
    if ($prev.Status.Defender -and -not $CurrentData.Status.Defender) { $diff.Regressions += "Real-time Defender was disabled" }
    if ($prev.Adv.LsassProtection.Status -eq "SECURE" -and $CurrentData.Adv.LsassProtection.Status -ne "SECURE") { $diff.Regressions += "LSASS PPL protection was lowered" }
    if ($prev.Adv.PowerShellLogging.Status -eq "SECURE" -and $CurrentData.Adv.PowerShellLogging.Status -ne "SECURE") { $diff.Regressions += "PowerShell logging was turned off" }

    $curPorts = $CurrentData.Adv.NetworkPortMap | ForEach-Object { "$($_.LocalPort):$($_.ProcessName)" }
    $oldPorts = $prev.Adv.NetworkPortMap | ForEach-Object { "$($_.LocalPort):$($_.ProcessName)" }
    $diff.NewPorts = @($curPorts | Where-Object { $_ -notin $oldPorts })
    $diff.ClosedPorts = @($oldPorts | Where-Object { $_ -notin $curPorts })

    $curAdmins = $CurrentData.Admins
    $oldAdmins = $prev.Admins
    $diff.NewAdmins = @($curAdmins | Where-Object { $_ -notin $oldAdmins })
    $diff.LostAdmins = @($oldAdmins | Where-Object { $_ -notin $curAdmins })

    $curTasks = $CurrentData.Tasks | ForEach-Object { $_.TaskName }
    $oldTasks = $prev.Tasks | ForEach-Object { $_.TaskName }
    $diff.NewTasks = @($curTasks | Where-Object { $_ -notin $oldTasks })

    return $diff
}