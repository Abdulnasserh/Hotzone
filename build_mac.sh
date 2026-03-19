#!/bin/bash
echo "🚀 Prepping Environment for macOS Build..."
pip3 install pyinstaller customtkinter
pip3 install -r requirements.txt
playwright install chromium

echo "📦 Compiling HotZone Pro Application for Mac..."
pyinstaller --noconfirm --onedir --windowed \
    --name "HotZonePro" \
    --add-data "static:static" \
    --add-data "hotzone-admin.html:." \
    gui.py

echo "✅ Build complete! You can find the executable Mac App inside the 'dist' folder."
