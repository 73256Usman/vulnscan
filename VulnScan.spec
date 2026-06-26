# VulnScan.spec
# PyInstaller build configuration
# Run with: pyinstaller VulnScan.spec

import os
from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

# Collect all hidden imports that PyInstaller might miss
hidden_imports = (
    collect_submodules("modules") +
    collect_submodules("tkinter") +
    collect_submodules("fpdf") +
    collect_submodules("requests") +
    [
        "modules.port_scanner",
        "modules.service_detector",
        "modules.cve_lookup",
        "modules.risk_assessor",
        "modules.database",
        "modules.reporter",
        "modules.target_validator",
        "modules.vt_checker",
        "modules.settings_manager",
        "tkinter",
        "tkinter.ttk",
        "tkinter.scrolledtext",
        "tkinter.messagebox",
        "tkinter.filedialog",
        "sqlite3",
        "fpdf",
        "requests",
        "json",
        "threading",
        "socket",
        "hashlib",
        "base64",
    ]
)

a = Analysis(
    ["scanner.py"],
    pathex=[os.getcwd()],
    binaries=[],
    datas=[],
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="VulnScan",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,        # no black terminal window
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="VulnScan",
)