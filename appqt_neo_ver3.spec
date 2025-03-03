# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['appqt_neo_ver3.py'],
    pathex=[],
    binaries=[],
    datas=[('C:\\Users\\Ankit Singh\\AppData\\Local\\Programs\\Python\\Python310\\Lib\\site-packages\\PyQt5\\Qt5\\plugins\\platforms', 'PyQt5\\Qt5\\plugins\\platforms')],
    hiddenimports=['PyQt5.QtCore', 'PyQt5.QtWidgets', 'PyQt5.QtGui'],
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
    a.binaries,
    a.datas,
    [],
    name='appqt_neo_ver3',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
