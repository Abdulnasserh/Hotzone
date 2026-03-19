#!/bin/bash
echo "🚀 Prepping Environment for macOS Build..."
pip3 install pyinstaller customtkinter
pip3 install -r requirements.txt
playwright install chromium

# ---------------------------------------------------------------------------
# Resolve paths for Playwright driver + browser binaries
# ---------------------------------------------------------------------------
PW_DRIVER=$(python3 -c "import playwright, os; print(os.path.join(os.path.dirname(playwright.__file__), 'driver'))")
echo "📍 Playwright driver path: $PW_DRIVER"

# Browsers installed by 'playwright install chromium' land in ~/Library/Caches/ms-playwright
BROWSERS_CACHE="$HOME/Library/Caches/ms-playwright"

# Find the chromium_headless_shell folder (e.g. chromium_headless_shell-1208)
HEADLESS_DIR=$(ls -d "$BROWSERS_CACHE"/chromium_headless_shell-* 2>/dev/null | head -1)
HEADLESS_NAME=$(basename "$HEADLESS_DIR")

if [ -z "$HEADLESS_DIR" ]; then
    echo "❌ Could not find chromium_headless_shell in $BROWSERS_CACHE"
    exit 1
fi
echo "📍 Headless shell path: $HEADLESS_DIR"

# Playwright at runtime looks for browsers at:
#   <playwright_package>/driver/package/.local-browsers/<browser_folder>/
DEST_BROWSERS="playwright/driver/package/.local-browsers/$HEADLESS_NAME"

echo "📦 Compiling HotZone Pro Application for Mac..."
pyinstaller --noconfirm --onedir --windowed \
    --name "HotZonePro" \
    --add-data "static:static" \
    --add-data "hotzone-admin.html:." \
    --add-data "$PW_DRIVER:playwright/driver" \
    --add-data "$HEADLESS_DIR:$DEST_BROWSERS" \
    gui.py

# Ensure the bundled chrome-headless-shell binary is executable
BUILT_SHELL=$(find dist/HotZonePro.app -name "chrome-headless-shell" -type f 2>/dev/null | head -1)
if [ -n "$BUILT_SHELL" ]; then
    chmod +x "$BUILT_SHELL"
    echo "✅ Made $BUILT_SHELL executable"
fi

# ---------------------------------------------------------------------------
# Fix PyInstaller macOS data packaging if needed
# ---------------------------------------------------------------------------
# Just make node binary executable if found
BUNDLED_NODE=$(find dist/HotZonePro.app -name "node" -path "*/driver/*" -type f 2>/dev/null | head -1)
if [ -n "$BUNDLED_NODE" ]; then
    chmod +x "$BUNDLED_NODE"
    echo "✅ Made $BUNDLED_NODE executable"
fi

echo "✅ Build complete! You can find the executable Mac App inside the 'dist' folder."

