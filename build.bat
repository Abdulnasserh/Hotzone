@echo off
echo ============================================
echo   HotZone Pro - Windows Build Script
echo ============================================
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed!
    echo Download from: https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during install.
    pause
    exit /b 1
)

echo [1/4] Installing dependencies...
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller customtkinter

echo [2/4] Building executable...
for /f "delims=" %%i in ('python -c "import customtkinter; import os; print(os.path.dirname(customtkinter.__file__))"') do set CTK_PATH=%%i

pyinstaller --noconfirm --onedir --windowed --uac-admin --name HotZonePro --icon=hotzone.ico --add-data "static;static" --add-data "hotzone-admin.html;." --add-data "%CTK_PATH%;customtkinter" --hidden-import "dnslib" --hidden-import "PIL._tkinter_finder" --collect-all uvicorn --collect-all fastapi gui.py

echo [3/4] Build complete!
echo.
echo Output: dist\HotZonePro\HotZonePro.exe
echo.

:: Check if Inno Setup exists for installer
where iscc >nul 2>&1
if %errorlevel% equ 0 (
    echo [4/4] Creating installer...
    iscc installer.iss
    echo Installer: Output\HotZonePro_Setup.exe
) else (
    echo [4/4] Skipping installer (Inno Setup not found)
    echo You can run dist\HotZonePro\HotZonePro.exe directly.
)

echo.
echo ============================================
echo   BUILD DONE! 
echo ============================================
pause
