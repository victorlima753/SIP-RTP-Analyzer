# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['v2\\app\\siprtp_v2_gui.py'],
    pathex=['C:\\Users\\Victor\\OneDrive\\Área de Trabalho\\Melhoria Wireshark\\v2\\app'],
    binaries=[],
    datas=[('C:\\Users\\Victor\\.cache\\codex-runtimes\\codex-primary-runtime\\dependencies\\python\\tcl', 'tcl')],
    hiddenimports=['siprtp_v2_core', 'siprtp_v2_db', 'siprtp_v2_export', 'siprtp_v2_performance', 'siprtp_v2_report', 'siprtp_v2_tk_runtime', 'tkinter', 'tkinter.filedialog', 'tkinter.messagebox', 'tkinter.ttk', '_tkinter'],
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
    name='SIPRTPAnalyzerV2',
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
    name='SIPRTPAnalyzerV2',
)
