# ============================================
#   HotZone Pro - One-Click Windows Builder
#   Paste this in PowerShell (Run as Admin):
#   irm https://raw.githubusercontent.com/Abdulnasserh/Hotzone/main/install.ps1 | iex
# ============================================

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "   HotZone Pro - Automated Installer" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# --- Step 1: Check/Install Python ---
Write-Host "[1/6] Checking Python..." -ForegroundColor Yellow
$python = $null
foreach ($cmd in @("python", "python3", "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match "Python 3") {
            $python = $cmd
            Write-Host "  Found: $ver" -ForegroundColor Green
            break
        }
    } catch {}
}

if (-not $python) {
    Write-Host "  Python not found. Installing Python 3.12..." -ForegroundColor Yellow
    $pyInstaller = "$env:TEMP\python-installer.exe"
    Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.12.4/python-3.12.4-amd64.exe" -OutFile $pyInstaller
    Start-Process -Wait -FilePath $pyInstaller -ArgumentList "/quiet", "InstallAllUsers=0", "PrependPath=1", "Include_test=0"
    Remove-Item $pyInstaller -Force
    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    $python = "python"
    Write-Host "  Python 3.12 installed!" -ForegroundColor Green
}

# --- Step 2: Check/Install Git ---
Write-Host "[2/6] Checking Git..." -ForegroundColor Yellow
$gitExists = Get-Command git -ErrorAction SilentlyContinue
if (-not $gitExists) {
    Write-Host "  Git not found. Installing Git..." -ForegroundColor Yellow
    $gitInstaller = "$env:TEMP\git-installer.exe"
    Invoke-WebRequest -Uri "https://github.com/git-for-windows/git/releases/download/v2.45.2.windows.1/Git-2.45.2-64-bit.exe" -OutFile $gitInstaller
    Start-Process -Wait -FilePath $gitInstaller -ArgumentList "/VERYSILENT", "/NORESTART", "/NOCANCEL", "/SP-", "/CLOSEAPPLICATIONS", "/RESTARTAPPLICATIONS"
    Remove-Item $gitInstaller -Force
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    Write-Host "  Git installed!" -ForegroundColor Green
} else {
    Write-Host "  Found: $(git --version)" -ForegroundColor Green
}

# --- Step 3: Clone repo ---
Write-Host "[3/6] Downloading HotZone Pro..." -ForegroundColor Yellow
$installDir = "$env:USERPROFILE\Desktop\HotZonePro-Build"
if (Test-Path $installDir) {
    Write-Host "  Updating existing folder..." -ForegroundColor Yellow
    Push-Location $installDir
    git pull origin main --force 2>&1 | Out-Null
    Pop-Location
} else {
    git clone "https://github.com/Abdulnasserh/Hotzone.git" $installDir
}
Set-Location $installDir
Write-Host "  Downloaded to: $installDir" -ForegroundColor Green

# --- Step 4: Install Python dependencies + Npcap ---
Write-Host "[4/7] Installing dependencies..." -ForegroundColor Yellow
& $python -m pip install --upgrade pip --quiet 2>&1 | Out-Null
& $python -m pip install -r requirements.txt --quiet 2>&1 | Out-Null
& $python -m pip install pyinstaller customtkinter --quiet 2>&1 | Out-Null
Write-Host "  All dependencies installed!" -ForegroundColor Green

# --- Step 4b: Install Npcap (required for ARP spoofing / network control) ---
Write-Host "[4b/7] Installing Npcap (network driver)..." -ForegroundColor Yellow
$npcapInstalled = Test-Path "C:\Windows\System32\Npcap"
if (-not $npcapInstalled) {
    $npcapUrl = "https://npcap.com/dist/npcap-1.80.exe"
    $npcapInstaller = "$env:TEMP\npcap-installer.exe"
    try {
        Invoke-WebRequest -Uri $npcapUrl -OutFile $npcapInstaller
        Start-Process -Wait -FilePath $npcapInstaller -ArgumentList "/S", "/winpcap_mode=yes"
        Remove-Item $npcapInstaller -Force -ErrorAction SilentlyContinue
        Write-Host "  Npcap installed!" -ForegroundColor Green
    } catch {
        Write-Host "  Npcap auto-install failed. Download manually: https://npcap.com" -ForegroundColor Yellow
    }
} else {
    Write-Host "  Npcap already installed!" -ForegroundColor Green
}

# --- Step 5: Build with PyInstaller ---
Write-Host "[5/7] Building HotZonePro.exe (this takes 2-5 minutes)..." -ForegroundColor Yellow
$ctkPath = & $python -c "import customtkinter; import os; print(os.path.dirname(customtkinter.__file__))"

& $python -m PyInstaller `
    --noconfirm --onedir --windowed --uac-admin `
    --name HotZonePro `
    --icon=hotzone.ico `
    --add-data "static;static" `
    --add-data "hotzone-admin.html;." `
    --add-data "$ctkPath;customtkinter" `
    --hidden-import "dnslib" `
    --hidden-import "scapy" `
    --hidden-import "PIL._tkinter_finder" `
    --collect-all uvicorn `
    --collect-all fastapi `
    --collect-all scapy `
    gui.py 2>&1 | Out-Null

if (-not (Test-Path "dist\HotZonePro\HotZonePro.exe")) {
    Write-Host "  BUILD FAILED! Check errors above." -ForegroundColor Red
    pause
    exit 1
}
Write-Host "  Build successful!" -ForegroundColor Green

# --- Step 6: Create shortcut on Desktop ---
Write-Host "[6/6] Creating Desktop shortcut..." -ForegroundColor Yellow
$desktopPath = [Environment]::GetFolderPath("Desktop")
$shortcutPath = "$desktopPath\HotZone Pro.lnk"
$exePath = "$installDir\dist\HotZonePro\HotZonePro.exe"

$WshShell = New-Object -ComObject WScript.Shell
$shortcut = $WshShell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $exePath
$shortcut.WorkingDirectory = "$installDir\dist\HotZonePro"
$shortcut.IconLocation = "$installDir\hotzone.ico"
$shortcut.Description = "HotZone Pro WiFi Voucher System"
$shortcut.Save()

Write-Host "  Shortcut created on Desktop!" -ForegroundColor Green

# --- Done ---
Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "   INSTALLATION COMPLETE!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "  EXE Location: $exePath" -ForegroundColor White
Write-Host "  Desktop Shortcut: HotZone Pro" -ForegroundColor White
Write-Host ""
Write-Host "  Right-click 'HotZone Pro' -> Run as Administrator" -ForegroundColor Yellow
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan

# Ask to launch now
$launch = Read-Host "Launch HotZone Pro now? (Y/N)"
if ($launch -eq "Y" -or $launch -eq "y") {
    Start-Process -Verb RunAs -FilePath $exePath
}
