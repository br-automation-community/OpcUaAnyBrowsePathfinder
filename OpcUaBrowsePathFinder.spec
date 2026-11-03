# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path
project_dir = Path(SPECPATH)
a = Analysis(
    [str(project_dir / 'src' / 'gui_launcher.py')],
    pathex=[str(project_dir / 'src')],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name='OpcUaBrowsePathFinder',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
)
