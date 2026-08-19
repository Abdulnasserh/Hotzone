# ============================================
#   HotZone Pro - One-Click Windows Installer
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

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "  ERROR: Please run PowerShell as Administrator!" -ForegroundColor Red
    Write-Host "  Right-click PowerShell -> Run as Administrator" -ForegroundColor Yellow
    pause
    exit 1
}

# --- Step 1: Check/Install Python ---
Write-Host "[1/7] Checking Python..." -ForegroundColor Yellow
$python = $null
foreach ($cmd in @("python", "python3", "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe", "C:\Python312\python.exe")) {
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
    
    # Method 1: Try winget (built into Windows 10/11)
    $wingetExists = Get-Command winget -ErrorAction SilentlyContinue
    if ($wingetExists) {
        Write-Host "  Using Windows Package Manager (winget)..." -ForegroundColor Gray
        winget install Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements 2>&1 | Out-Null
    } else {
        # Method 2: Direct download from python.org
        Write-Host "  Downloading from python.org..." -ForegroundColor Gray
        $pyInstaller = "$env:TEMP\python-installer.exe"
        Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.12.4/python-3.12.4-amd64.exe" -OutFile $pyInstaller
        # /quiet = no GUI, InstallAllUsers=1 = system-wide, PrependPath=1 = add to PATH
        Start-Process -Wait -FilePath $pyInstaller -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=1", "Include_test=0"
        Remove-Item $pyInstaller -Force
    }
    
    # Refresh PATH so we can find python
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    
    # Find python after install
    foreach ($cmd in @("python", "C:\Program Files\Python312\python.exe", "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe")) {
        try {
            $ver = & $cmd --version 2>&1
            if ($ver -match "Python 3") { $python = $cmd; break }
        } catch {}
    }
    if (-not $python) {
        Write-Host "  ERROR: Python installation failed!" -ForegroundColor Red
        Write-Host "  Please install Python manually from https://www.python.org/downloads/" -ForegroundColor Yellow
        Write-Host "  Make sure to check 'Add Python to PATH' during install." -ForegroundColor Yellow
        pause
        exit 1
    }
    Write-Host "  Python 3.12 installed!" -ForegroundColor Green
}

# --- Step 2: Check/Install Git ---
Write-Host "[2/7] Checking Git..." -ForegroundColor Yellow
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

# --- Step 3: Kill any running HotZone instance + free port 8000 ---
Write-Host "[3/7] Stopping any running HotZone instance..." -ForegroundColor Yellow
Get-Process -Name "HotZonePro" -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process -Name "python*"    -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -like "*HotZone*" } | Stop-Process -Force
# Free port 8000 if something else holds it
$port8000 = netstat -ano | Select-String ":8000 " | Select-String "LISTENING"
if ($port8000) {
    $pid8000 = ($port8000 -split '\s+')[-1]
    if ($pid8000 -match '^\d+$') { Stop-Process -Id $pid8000 -Force -ErrorAction SilentlyContinue }
}
Start-Sleep -Seconds 2

# --- Step 4: Clone repo ---
Write-Host "[4/7] Downloading HotZone Pro source code..." -ForegroundColor Yellow
$installDir = "$env:USERPROFILE\Desktop\HotZonePro-Build"
if (Test-Path $installDir) {
    Write-Host "  Removing old folder and re-downloading fresh..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $installDir
}
Write-Host "  Downloading latest code..." -ForegroundColor Yellow
git clone --depth 1 --single-branch --branch main "https://github.com/Abdulnasserh/Hotzone.git" $installDir
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: Failed to download! Check internet connection." -ForegroundColor Red
    pause
    exit 1
}
Set-Location $installDir
Write-Host "  Downloaded to: $installDir" -ForegroundColor Green

# --- Step 4: Install Python dependencies ---
Write-Host "[5/7] Installing Python packages (this may take 1-2 minutes)..." -ForegroundColor Yellow
& $python -m pip install --upgrade pip 2>&1 | Out-Null
$pipResult = & $python -m pip install -r requirements.txt 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "  WARNING: Some packages may have failed:" -ForegroundColor Yellow
    Write-Host "  $pipResult" -ForegroundColor Gray
}
& $python -m pip install pyinstaller customtkinter 2>&1 | Out-Null
Write-Host "  All dependencies installed!" -ForegroundColor Green

# --- Step 5: Build .exe with PyInstaller ---
Write-Host "[6/7] Building HotZonePro.exe (this takes 3-5 minutes, please wait)..." -ForegroundColor Yellow
Write-Host "  ..." -ForegroundColor Gray

# Remove any stale .spec file from previous/Mac builds — it has hardcoded
# Mac paths that break the Windows build if PyInstaller picks it up.
if (Test-Path "HotZonePro.spec") { Remove-Item "HotZonePro.spec" -Force }
if (Test-Path "gui.spec")         { Remove-Item "gui.spec"         -Force }

$ctkPath = & $python -c "import customtkinter; import os; print(os.path.dirname(customtkinter.__file__))"

& $python -m PyInstaller `
    --noconfirm --onedir --windowed --uac-admin `
    --name HotZonePro `
    --icon=hotzone.ico `
    --add-data "static;static" `
    --add-data "hotzone-admin.html;." `
    --add-data "license_manager.py;." `
    --add-data "router_scraper.py;." `
    --add-data "$ctkPath;customtkinter" `
    --hidden-import "license_manager" `
    --hidden-import "router_scraper" `
    --hidden-import "PIL._tkinter_finder" `
    --collect-all uvicorn `
    --collect-all fastapi `
    gui.py

if (-not (Test-Path "dist\HotZonePro\HotZonePro.exe")) {
    Write-Host ""
    Write-Host "  BUILD FAILED!" -ForegroundColor Red
    Write-Host "  Check the error messages above." -ForegroundColor Red
    pause
    exit 1
}
Write-Host "  Build successful!" -ForegroundColor Green

# --- Step 6: Create Desktop shortcut ---
Write-Host "[7/7] Creating shortcuts..." -ForegroundColor Yellow
$desktopPath = [Environment]::GetFolderPath("Desktop")
$exePath     = "$installDir\dist\HotZonePro\HotZonePro.exe"

# Write a launcher .bat that always resolves the current .exe path
# so reinstalls don't leave stale shortcuts pointing to a deleted .exe
$launcherPath = "$env:APPDATA\HotZonePro\launch.bat"
@"
@echo off
set EXE=%USERPROFILE%\Desktop\HotZonePro-Build\dist\HotZonePro\HotZonePro.exe
if exist "%EXE%" (
    start "" "%EXE%"
) else (
    echo HotZone Pro not found. Please reinstall.
    pause
)
"@ | Set-Content -Path $launcherPath -Encoding ASCII

# Desktop shortcut → launcher .bat
$WshShell = New-Object -ComObject WScript.Shell
$shortcut = $WshShell.CreateShortcut("$desktopPath\HotZone Pro.lnk")
$shortcut.TargetPath    = $launcherPath
$shortcut.WorkingDirectory = "$env:APPDATA\HotZonePro"
$shortcut.IconLocation  = "$installDir\hotzone.ico"
$shortcut.Description   = "HotZone Pro WiFi Voucher System"
$shortcut.Save()
Write-Host "  Desktop shortcut created!" -ForegroundColor Green

# Startup shortcut → same launcher .bat (survives reinstalls)
$startupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
$WshShell2 = New-Object -ComObject WScript.Shell
$sc2 = $WshShell2.CreateShortcut("$startupPath\HotZone Pro.lnk")
$sc2.TargetPath    = $launcherPath
$sc2.WorkingDirectory = "$env:APPDATA\HotZonePro"
$sc2.Save()
Write-Host "  Auto-start on boot enabled!" -ForegroundColor Green

# --- Done ---
Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "   INSTALLATION COMPLETE!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "  App Location : $exePath" -ForegroundColor White
Write-Host "  Desktop Icon : HotZone Pro" -ForegroundColor White
Write-Host "  Auto-Start   : YES (runs on boot)" -ForegroundColor White
Write-Host ""
Write-Host "  HOW TO USE:" -ForegroundColor Cyan
Write-Host "  1. Double-click 'HotZone Pro' on Desktop" -ForegroundColor White
Write-Host "  2. Click 'Start Server'" -ForegroundColor White
Write-Host "  3. Browser opens automatically — click 'Washa System'" -ForegroundColor White
Write-Host "  4. Customers type http://<your-ip>:8000 to reach portal" -ForegroundColor White
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Ask to launch now
$launch = Read-Host "Launch HotZone Pro now? (Y/N)"
if ($launch -eq "Y" -or $launch -eq "y") {
    Start-Process -FilePath $launcherPath
}
