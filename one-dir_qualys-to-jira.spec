# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['qualys-to-jira.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('!DATA/jira_files/jira-data.json', '!DATA/jira_files'),
        ('!DATA/jira_files/QUAL_jira-query-task-template.json', '!DATA/jira_files'),
        ('!DATA/jira_files/QUAL_jira-query-subtask-template.json', '!DATA/jira_files'),
	('!DATA/data_files/mailing_data.json', '!DATA/data_files'),
	('!DATA/qualys_files/qualys-creds.txt', '!DATA/qualys_files'),
	('!DATA/qualys_files/qualys-last-processed-reports.txt', '!DATA/qualys_files')
    ],
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
    name='qualys-to-jira',
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
    name='qualys-to-jira',
)
