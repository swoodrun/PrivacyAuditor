# -*- mode: python ; coding: utf-8 -*-
# AuditDashboard onefile 打包配置
# gen_report.py 位于 ../report/，通过 pathex 暴露给 PyInstaller，确保被真正内置。

a = Analysis(
    ['dashboard.py'],
    pathex=['.', '..', '../report'],
    binaries=[],
    datas=[('icon.ico', '.')],
    hiddenimports=['gen_report'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='AuditDashboard',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    icon='icon.ico',
)
