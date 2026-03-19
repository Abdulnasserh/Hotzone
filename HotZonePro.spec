# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['gui.py'],
    pathex=[],
    binaries=[],
    datas=[('static', 'static'), ('hotzone-admin.html', '.'), ('/Library/Frameworks/Python.framework/Versions/3.14/lib/python3.14/site-packages/playwright/driver', 'playwright/driver'), ('/Users/abdul/Library/Caches/ms-playwright/chromium_headless_shell-1208', 'playwright/driver/package/.local-browsers/chromium_headless_shell-1208')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='HotZonePro',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='HotZonePro',
)
app = BUNDLE(
    coll,
    name='HotZonePro.app',
    icon=None,
    bundle_identifier=None,
)
