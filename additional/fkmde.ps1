param (
    [string]$Directory = "C:\Windows",
    [int]$Depth = 1
)

$MpPath = "C:\Program Files\Windows Defender\MpCmdRun.exe"

if (-Not (Test-Path -Path $MpPath)) {
    Write-Host "Error: MpCmdRun.exe not found at $MpPath" -ForegroundColor DarkRed
    exit 1
}

if (-Not (Test-Path -Path $Directory -PathType Container)) {
    Write-Host "Error: Directory '$Directory' not found." -ForegroundColor DarkRed
    exit 1
}

# Suppress Defender Security Center popup during scan
$keyPath = "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.Defender.SecurityCenter"
Reg.exe add $keyPath /v "Enabled" /t REG_DWORD /d "0" /f | Out-Null

try {
    $folders = Get-ChildItem -Path $Directory -Recurse -Directory -Depth ($Depth - 1) -ErrorAction SilentlyContinue | Sort-Object FullName
    Write-Host "Found $($folders.Count) folders in '$Directory' at depth $Depth." -ForegroundColor DarkGray
    Write-Host ""

    if ($folders.Count -eq 0) {
        Write-Host "No subfolders found." -ForegroundColor DarkYellow
        Reg.exe delete $keyPath /v "Enabled" /f | Out-Null
        exit 0
    }

    $processed = 0
    $total = $folders.Count
    $barWidth = 50

    foreach ($folder in $folders) {
        $output = & $MpPath -Scan -ScanType 3 -File "$($folder.FullName)\|*" 2>&1
        $processed++
        $pct = [math]::Round(($processed / $total) * 100, 2)
        $blocks = [int](($processed / $total) * $barWidth)
        $bar = ('#' * $blocks) + ('-' * ($barWidth - $blocks))
        Write-Host -NoNewline "`r[$bar] $processed/$total ($pct%)"

        if ($output -match "was skipped") {
            Write-Host "`n[EXCLUSION] $($folder.FullName)" -ForegroundColor DarkRed
        }
    }

    Write-Host ""
}
catch {
    Write-Host "`nError: $_" -ForegroundColor DarkRed
}

# Restore Defender popup
Reg.exe delete $keyPath /v "Enabled" /f | Out-Null
