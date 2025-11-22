# -*- mode: python ; coding: utf-8 -*-
import sys
import os
import pyzbar

lib = []
zbarpath = os.path.dirname(pyzbar.__file__)
grab = []

if sys.platform.startswith("win"):
    grab.append("libiconv.dll")
    grab.append("libzbar-64.dll")
elif sys.platform == "darwin":
    grab.append("libiconv.dylib")
    grab.append("libzbar-64.dylib")
else:
    grab.append("libiconv.so")
    grab.append("libiconv.so.2")
    grab.append("libzbar-64.so")
    grab.append("libzbar-64.so.2")

for entry in grab:
    if os.path.exists(os.path.join(zbarpath, entry)):
        lib.append((os.path.join(zbarpath, entry), '.'))

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('docs', 'docs'),
        ('en_US.qm', '.'),
        ('ru_RU.qm', '.')
    ] + lib,
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
    name='main',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
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
    name='main',
)
