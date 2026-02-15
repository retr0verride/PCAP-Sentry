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
    filtered = []
    for item in items:
        if ".tests" in item:
            continue
        if ".test" in item:
            continue
        if ".sphinxext" in item:
            continue
        if ".testing" in item or "._test" in item:
            continue
        if item.endswith(".conftest") or ".conftest." in item:
            continue
        filtered.append(item)
    return filtered


def _unique(sequence):
    seen = set()
    ordered = []
    for item in sequence:
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


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

# Ensure companion Python modules are bundled (try/except imports can fool PyInstaller)
hiddenimports += ['update_checker', 'threat_intelligence', 'enhanced_ml_trainer']

# Also add them as data files in case hiddenimports alone doesn't resolve them
for _companion in ('update_checker.py', 'threat_intelligence.py', 'enhanced_ml_trainer.py'):
    _companion_path = os.path.join('Python', _companion)
    if os.path.exists(_companion_path):
        datas.append((_companion_path, '.'))

datas = _unique(datas)
binaries = _unique(binaries)
hiddenimports = _unique(hiddenimports)


for icon_name in ("pcap_sentry.ico", "pcap_sentry_512.png", "pcap_sentry_256.png", "pcap_sentry_48.png", "custom.ico"):
    icon_path = os.path.join("assets", icon_name)
    if os.path.exists(icon_path):
        datas.append((icon_path, "assets"))

# Explicitly include the active Python DLL to avoid runtime load errors.
# Python 3.14+ requires extra care with onefile mode.
py_dll_name = f"python{sys.version_info.major}{sys.version_info.minor}.dll"
py_dll_candidates = [
    os.path.join(sys.base_prefix, py_dll_name),
    os.path.join(sys.base_prefix, "DLLs", py_dll_name),
    os.path.join(os.path.dirname(sys.executable), py_dll_name),
]
py_dll_found = None
for py_dll in py_dll_candidates:
    if os.path.exists(py_dll):
        py_dll_found = py_dll
        binaries.append((py_dll, "."))
        print(f"Including Python DLL: {py_dll}")
        break

if not py_dll_found:
    print(f"WARNING: Could not find {py_dll_name}! The EXE may not run.")
else:
    # Also add to datas as a fallback for Python 3.14+ compatibility
    datas.append((py_dll_found, "."))

# Bundle VC++ runtime DLLs so the app runs even if the redist is missing.
vc_runtime_dlls = [
    "vcruntime140.dll",
    "vcruntime140_1.dll",
    "msvcp140.dll",
    "msvcp140_1.dll",
    "msvcp140_2.dll",
    "concrt140.dll",
    "vccorlib140.dll",
]
system32_dir = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32")
for dll_name in vc_runtime_dlls:
    dll_path = os.path.join(system32_dir, dll_name)
    if os.path.exists(dll_path):
        binaries.append((dll_path, "."))

# Include Npcap DLLs if available for packet capture support.
wpcap_path = r"C:\Windows\System32\Npcap\wpcap.dll"
packet_path = r"C:\Windows\System32\Npcap\Packet.dll"
if os.path.exists(wpcap_path):
    binaries.append((wpcap_path, "."))
if os.path.exists(packet_path):
    binaries.append((packet_path, "."))


a = Analysis(
    ['Python\\pcap_sentry_gui.py'],
    pathex=['Python'],
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
    [],
    exclude_binaries=True,  # Changed to onedir mode for Python 3.14+ compatibility
    name='PCAP_Sentry',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='version_info.txt',
    icon=[
        'assets\\pcap_sentry.ico' if os.path.exists('assets\\pcap_sentry.ico') else 'assets\\custom.ico'
    ],
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='PCAP_Sentry',
)
