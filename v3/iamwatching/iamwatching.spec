# -*- mode: python ; coding: utf-8 -*-
# =============================================================================
# IamWatching v1.3.0 — PyInstaller spec
# Produces: dist/iamwatching  (single-file, no Python install required)
#
# Build:
#   pip install pyinstaller
#   pyinstaller --clean --noconfirm --onefile iamwatching.spec
# =============================================================================

import sys, os
from pathlib import Path

block_cipher = None

# ── Locate botocore data directory safely ─────────────────────────────────────
def _find_botocore_data():
    """Return (src, dest) tuple for botocore endpoint/service JSON files."""
    import importlib.util
    spec = importlib.util.find_spec('botocore')
    if spec and spec.submodule_search_locations:
        botocore_root = Path(list(spec.submodule_search_locations)[0])
        data_dir = botocore_root / 'data'
        if data_dir.exists():
            return (str(data_dir), 'botocore/data')
    return None

_botocore_data = _find_botocore_data()

# ── Hidden imports (lazy-loaded cloud SDK modules) ────────────────────────────
HIDDEN_IMPORTS = [
    'iamwatching.scanners.aws_scanner',
    'iamwatching.scanners.azure_scanner',
    'iamwatching.scanners.gcp_scanner',
    'iamwatching.handshake.verifier',
    'iamwatching.graph.importer',
    'iamwatching.patterns.matcher',
    'iamwatching.patterns.checks',
    'iamwatching.patterns.registry',
    'iamwatching.logging_module.logger',
    'iamwatching.logging_module',
    # AWS
    'aioboto3', 'aiobotocore', 'aiobotocore.session',
    'botocore', 'botocore.auth', 'botocore.endpoint',
    'botocore.handlers', 'botocore.parsers', 'botocore.serialize',
    'botocore.signers', 'botocore.utils', 'botocore.awsrequest',
    # Azure
    'azure.identity', 'azure.identity.aio',
    'azure.core', 'azure.mgmt.authorization', 'azure.mgmt.compute',
    'azure.mgmt.resource', 'azure.mgmt.web', 'msal',
    # GCP
    'google.auth', 'google.auth.transport', 'google.auth.transport.requests',
    'google.oauth2', 'google.oauth2.service_account',
    'google.cloud.functions_v1', 'google.cloud.run_v2',
    'google.cloud.compute_v1', 'google.api_core', 'googleapiclient',
    # Neo4j
    'neo4j', 'neo4j.io', 'neo4j.aio',
    # HTTP
    'aiohttp', 'aiohttp.connector', 'asyncio',
    # CLI
    'click', 'rich', 'rich.console', 'rich.logging', 'rich.table', 'rich.panel',
    # Crypto
    'cryptography', 'cryptography.hazmat', 'cryptography.hazmat.primitives',
    'cryptography.x509', 'OpenSSL', 'certifi', 'urllib3',
]

# ── datas ─────────────────────────────────────────────────────────────────────
DATAS = [
    ('README.md', '.'),
    ('docs/', 'docs/'),
    ('checks/', 'checks/'),      # bundled check YAML files
]
if _botocore_data:
    DATAS.append(_botocore_data)

a = Analysis(
    ['iamwatching/cli/main.py'],
    pathex=['.'],
    binaries=[],
    datas=DATAS,
    hiddenimports=HIDDEN_IMPORTS,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter', 'tkinter.ttk', 'matplotlib', 'scipy', 'numpy',
        'pandas', 'PIL', 'IPython', 'notebook', 'pytest', 'black',
        'ruff', 'mypy', 'moto', 'sphinx',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='iamwatching',
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
