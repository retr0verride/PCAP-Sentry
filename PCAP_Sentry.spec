# -*- mode: python ; coding: utf-8 -*-
import os
import sys
from PyInstaller.utils.hooks import (
    collect_data_files,
    collect_dynamic_libs,
    collect_submodules,
)


def _require_package(name):
    try:
        __import__(name)
    except Exception as exc:
        raise SystemExit(
            f"Missing required build dependency: {name}. Install it before building."
        ) from exc


def _filter_hiddenimports(items):
    return [item for item in items if ".tests" not in item]


def _filter_datas(items):
    filtered = []
    for src, dest in items:
        lower_src = src.lower()
        if "\\tests\\" in lower_src or "/tests/" in lower_src:
            continue
        filtered.append((src, dest))
    return filtered


def _collect_package(name):
    pkg_datas = _filter_datas(collect_data_files(name))
    pkg_bins = collect_dynamic_libs(name)
    pkg_hidden = _filter_hiddenimports(collect_submodules(name, on_error="ignore"))
    return pkg_datas, pkg_bins, pkg_hidden

npcap_dir = r"C:\Windows\System32\Npcap"
if os.path.isdir(npcap_dir):
    os.environ["PATH"] = npcap_dir + os.pathsep + os.environ.get("PATH", "")

datas = []
binaries = []
hiddenimports = []
tmp_ret = _collect_package('matplotlib')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = _collect_package('pandas')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
_require_package('scapy')
tmp_ret = _collect_package('scapy')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
_require_package('sklearn')
tmp_ret = _collect_package('sklearn')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
_require_package('joblib')
tmp_ret = _collect_package('joblib')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = _collect_package('tkinterdnd2')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]

hiddenimports += ['scapy', 'scapy.all', 'sklearn', 'joblib']


for icon_name in ("pcap_sentry.ico", "custom.ico"):
    icon_path = os.path.join("assets", icon_name)
    if os.path.exists(icon_path):
        datas.append((icon_path, "assets"))

# Explicitly include the active Python DLL to avoid runtime load errors.
py_dll_name = f"python{sys.version_info.major}{sys.version_info.minor}.dll"
py_dll_candidates = [
    os.path.join(sys.base_prefix, py_dll_name),
    os.path.join(sys.base_prefix, "DLLs", py_dll_name),
    os.path.join(os.path.dirname(sys.executable), py_dll_name),
]
for py_dll in py_dll_candidates:
    if os.path.exists(py_dll):
        binaries.append((py_dll, "."))
        break

# Include Npcap DLLs if available for packet capture support.
wpcap_path = r"C:\Windows\System32\Npcap\wpcap.dll"
packet_path = r"C:\Windows\System32\Npcap\Packet.dll"
if os.path.exists(wpcap_path):
    binaries.append((wpcap_path, "."))
if os.path.exists(packet_path):
    binaries.append((packet_path, "."))


a = Analysis(
    ['Python\\pcap_sentry_gui.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'matplotlib.tests',
        'pandas.tests',
        'pandas.tests.extension.base',
        'scapy.modules.krack',
        'matplotlib.backends.backend_qt',
        'matplotlib.backends.backend_qt5',
        'matplotlib.backends.backend_qt5agg',
        'matplotlib.backends.backend_qtagg',
        'matplotlib.backends.backend_qt5cairo',
        'matplotlib.backends.backend_qtcairo',
        'matplotlib.backends.qt_compat',
    ],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='PCAP_Sentry',
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
    version='version_info.txt',
    icon=[
        'assets\\custom.ico' if os.path.exists('assets\\custom.ico') else 'assets\\pcap_sentry.ico'
    ],
)
