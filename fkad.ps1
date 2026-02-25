$DATE = Get-Date -Format "yyyyMMdd_HHmm"
$USER = $env:USERNAME
$OUT = "$env:USERPROFILE\Downloads\fkad-$DATE-$USER"
New-Item -ItemType Directory -Path $OUT -Force | Out-Null

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
    Write-Host "    Output: $OUT" -ForegroundColor DarkGray
    Write-Host ""
}

function Run {
    param($Label, $Block, $File)
    try {
        $result = & $Block
        $result | Out-File "$OUT\$File" -Encoding utf8
        Write-Host "[OK] $Label -> $File" -ForegroundColor Green
    } catch {
        Write-Host "[--] $Label failed: $_" -ForegroundColor DarkGray
    }
}

Banner

# --- Basic Recon ---
Run "Privileges"        { whoami /priv }                                          "whoami_priv.txt"
Run "Whoami All"        { whoami /all }                                           "whoami_all.txt"
Run "Env Variables"     { Get-ChildItem Env: | Format-Table -AutoSize }           "env_vars.txt"

# --- Network ---                      "netstat.txt"
Run "Hosts File"        { Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" } "hosts.txt"
Run "DNS Cache"         { ipconfig /displaydns }                                  "dns_cache.txt"
Run "Firewall Rules"    { netsh advfirewall firewall show rule name=all }         "firewall_rules.txt"

# --- Users & Groups ---
Run "Local Admins"      { net localgroup administrators }                         "local_admins.txt"                "local_groups.txt"
Run "Logged On Users"   { query user 2>$null }                                    "logged_on_users.txt"

# --- System ---
Run "Processes"         { Get-Process | Select-Object Name,Id,Path | Format-Table -AutoSize } "processes.txt"
Run "Services"          { Get-Service | Format-Table -AutoSize }                  "services.txt"
Run "Scheduled Tasks"   { Get-ScheduledTask | Format-Table -AutoSize }            "scheduled_tasks.txt"
Run "Startup Items"     { Get-CimInstance Win32_StartupCommand | Format-Table -AutoSize } "startup_items.txt"

# --- Security ---
Run "WSL"               { wsl --list --verbose 2>&1 }                            "wsl.txt"

# --- MSI Enum ---
Run "MSI Packages" {
    Get-WmiObject -Class Win32_Product |
    Where-Object { $_.Vendor -notin @("Microsoft Corporation","Microsoft","Python Software Foundation") } |
    Select-Object Name, Vendor, Version, PackageCache
} "msi_list.txt"

Write-Host ""

# fkmde
try {
    & { IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/fkxdr/fkmde/refs/heads/main/fkmde.ps1') } *>&1 | Out-File "$OUT\fkmde.txt" -Encoding utf8
    Write-Host "[OK] fkmde -> fkmde.txt" -ForegroundColor Green
} catch { Write-Host "[--] fkmde failed: $_" -ForegroundColor DarkGray }

# PrivescCheck
try {
    IEX (Invoke-RestMethod 'https://github.com/itm4n/PrivescCheck/releases/latest/download/PrivescCheck.ps1')
    Invoke-PrivescCheck -Extended -Audit -Report "$OUT\PrivescCheck_$($env:COMPUTERNAME)" -Format TXT | Out-Null
    Write-Host "[OK] PrivescCheck -> PrivescCheck_$($env:COMPUTERNAME).txt" -ForegroundColor Green
} catch { Write-Host "[--] PrivescCheck failed: $_" -ForegroundColor DarkGray }

# WinPEAS
try {
    & { IEX (iwr 'https://raw.githubusercontent.com/peass-ng/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1') } *>&1 | Out-File "$OUT\winpeas.txt" -Encoding utf8
    Write-Host "[OK] WinPEAS -> winpeas.txt" -ForegroundColor Green
} catch { Write-Host "[--] WinPEAS failed: $_" -ForegroundColor DarkGray }

# HardeningKitty
try {
    IEX (iwr 'https://raw.githubusercontent.com/scipag/HardeningKitty/master/HardeningKitty.ps1')
    Invoke-HardeningKitty -Mode Audit -Log -Report -ReportFile "$OUT\HardeningKitty.csv" | Out-Null
    Write-Host "[OK] HardeningKitty -> HardeningKitty.csv" -ForegroundColor Green
} catch { Write-Host "[--] HardeningKitty failed: $_" -ForegroundColor DarkGray }

# ScriptSentry
try {
    & { IEX (iwr 'https://raw.githubusercontent.com/techspence/ScriptSentry/main/ScriptSentry.ps1') } *>&1 | Out-File "$OUT\scriptsentry.txt" -Encoding utf8
    Write-Host "[OK] ScriptSentry -> scriptsentry.txt" -ForegroundColor Green
} catch { Write-Host "[--] ScriptSentry failed: $_" -ForegroundColor DarkGray }

# AppLocker Inspector
try {
    IEX (iwr 'https://raw.githubusercontent.com/techspence/AppLockerInspector/main/Invoke-AppLockerInspector.ps1')
    Invoke-AppLockerInspector -Verbose | Format-Table -Auto | Out-File "$OUT\applocker_inspector.txt" -Encoding utf8
    Write-Host "[OK] AppLocker Inspector -> applocker_inspector.txt" -ForegroundColor Green
} catch { Write-Host "[--] AppLocker Inspector failed: $_" -ForegroundColor DarkGray }

# PowerUpSQL
try {
    IEX (iwr 'https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1')
    Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded | Where-Object {$_.Status -eq "Accessible"} | Get-SQLServerPrivEscRowThreated | Out-File "$OUT\mssql_priv.txt" -Encoding utf8
    Write-Host "[OK] PowerUpSQL -> mssql_priv.txt" -ForegroundColor Green
} catch { Write-Host "[--] PowerUpSQL failed: $_" -ForegroundColor DarkGray }

Write-Host ""
Write-Host "[OK] Done. Output folder: $OUT" -ForegroundColor Green
Write-Host ""
