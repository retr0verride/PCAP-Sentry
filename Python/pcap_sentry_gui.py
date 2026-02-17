#!/usr/bin/env python3
# PCAP Sentry - Learn Malware Network Traffic Analysis (Beginner-Friendly Educational Tool)
# Copyright (C) 2026 industrial-dave
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import base64
import ctypes
import hashlib
import hmac
import io
import ipaddress
import json
import math
import os
import queue
import random
import re
import shutil
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone


class AnalysisCancelledError(Exception):
    """Raised when the user cancels a running analysis."""

    pass


import contextlib
import itertools
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont

# Import update checker
try:
    from update_checker import BackgroundUpdateChecker, UpdateChecker

    _update_checker_available = True
except ImportError as _uc_err:
    _update_checker_available = False
    # Log the failure so we can diagnose bundling issues
    import traceback as _tb

    print(f"[WARN] update_checker import failed: {_uc_err}")
    _tb.print_exc()

_sklearn_available = None
_tkinterdnd2_available = None
_threat_intel_available = None


def _check_threat_intel():
    global _threat_intel_available
    if _threat_intel_available is not None:
        return _threat_intel_available
    try:
        from threat_intelligence import ThreatIntelligence

        _threat_intel_available = True
        return True
    except ImportError:
        _threat_intel_available = False
        return False


def _utcnow():
    return datetime.now(timezone.utc)


def _init_error_logs():
    try:
        log_dir = _get_app_data_dir()
        for name in ("startup_errors.log", "app_errors.log"):
            log_path = os.path.join(log_dir, name)
            if not os.path.exists(log_path):
                with open(log_path, "a", encoding="utf-8") as handle:
                    handle.write("")
    except Exception:
        pass


def _write_startup_log(message, exc=None):
    try:
        log_dir = _get_app_data_dir()
        log_path = os.path.join(log_dir, "startup_errors.log")
        timestamp = _utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
        with open(log_path, "a", encoding="utf-8") as handle:
            handle.write(f"[{timestamp}] {message}\n")
            if exc is not None:
                handle.write(f"[{timestamp}] {type(exc).__name__}: {exc}\n")
    except Exception:
        pass


def _write_error_log(message, exc=None, tb=None):
    try:
        log_dir = _get_app_data_dir()
        log_path = os.path.join(log_dir, "app_errors.log")
        timestamp = _utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
        with open(log_path, "a", encoding="utf-8") as handle:
            handle.write(f"[{timestamp}] {message}\n")
            if exc is not None:
                handle.write(f"[{timestamp}] {type(exc).__name__}: {exc}\n")
            if tb is not None:
                formatted = "".join(traceback.format_exception(type(exc), exc, tb))
                handle.write(formatted)
                if not formatted.endswith("\n"):
                    handle.write("\n")
    except Exception:
        pass


def _handle_exception(exc_type, exc, tb):
    try:
        _write_error_log("Unhandled exception", exc, tb)
        if threading.current_thread() is threading.main_thread():
            _show_startup_error(
                "An unexpected error occurred. See app_errors.log in the app data folder.",
                exc,
            )
        else:
            # Schedule messagebox on the main thread to avoid tkinter threading crash
            try:
                root = tk._default_root
                if root:
                    root.after(
                        0,
                        lambda: _show_startup_error(
                            "An unexpected error occurred. See app_errors.log in the app data folder.",
                            exc,
                        ),
                    )
            except Exception:
                pass
    except Exception:
        # Last-resort fallback to prevent recursion in the exception handler
        try:
            sys.stderr.write(f"Exception in exception handler: {exc_type.__name__}: {exc}\n")
        except Exception:
            pass


def _show_startup_error(message, exc=None):
    _write_startup_log(message, exc)
    try:
        if tk._default_root is None:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("PCAP Sentry", message)
            root.destroy()
        else:
            messagebox.showerror("PCAP Sentry", message)
    except Exception:
        pass


def _check_sklearn():
    global _sklearn_available
    if _sklearn_available is not None:
        return _sklearn_available
    try:
        import joblib
        import sklearn.feature_extraction
        import sklearn.linear_model

        _sklearn_available = True
    except (ImportError, ModuleNotFoundError):
        _sklearn_available = False
    return _sklearn_available


def _check_tkinterdnd2():
    global _tkinterdnd2_available
    if _tkinterdnd2_available is not None:
        return _tkinterdnd2_available
    try:
        import tkinterdnd2

        _tkinterdnd2_available = True
    except (ImportError, ModuleNotFoundError):
        _tkinterdnd2_available = False
    return _tkinterdnd2_available


SIZE_SAMPLE_LIMIT = 50000
DEFAULT_MAX_ROWS = 200000
IOC_SET_LIMIT = 50000

# ── Thread lock for knowledge base read-modify-write operations ──────────
_kb_lock = threading.Lock()

# ── Common/well-known ports (shared across education, hints, analysis) ───
COMMON_PORTS = {22, 53, 80, 123, 443, 445, 3389, 25, 110, 143, 21, 8080}

PORT_DESCRIPTIONS = {
    22: "SSH — Secure remote terminal access",
    53: "DNS — Translates domain names to IP addresses",
    80: "HTTP — Unencrypted web traffic",
    123: "NTP — Time synchronization between computers",
    443: "HTTPS — Encrypted web traffic (standard for modern websites)",
    445: "SMB — Windows file sharing (often targeted by ransomware)",
    3389: "RDP — Remote Desktop (lets someone control a PC remotely)",
    25: "SMTP — Sending email",
    110: "POP3 — Downloading email from a mail server",
    143: "IMAP — Syncing email across devices",
    21: "FTP — File transfers (sends passwords in plain text!)",
    8080: "HTTP-Alt — Alternate web port, often used by proxies",
}

# Short-form descriptions for compact UI areas
PORT_DESCRIPTIONS_SHORT = {
    22: "SSH (Secure Shell)",
    53: "DNS (Domain Name System)",
    80: "HTTP (Unencrypted Web)",
    123: "NTP (Time Sync)",
    443: "HTTPS (Encrypted Web)",
    445: "SMB (Windows File Sharing)",
    3389: "RDP (Remote Desktop)",
    25: "SMTP (Email Sending)",
    110: "POP3 (Email Download)",
    143: "IMAP (Email Sync)",
    21: "FTP (File Transfer)",
    8080: "HTTP-Alt (Proxy/Alternate Web)",
}

# ── Education pattern descriptions (rebuilt every analysis → now a constant) ──
PATTERN_EDUCATION = {
    "high_volume": (
        "HIGH DATA VOLUME",
        "A large amount of data was moved in this conversation.\n"
        "      This could be a legitimate download, OR it could be\n"
        "      data being stolen (exfiltrated) from your network.\n"
        "      Key question: Is the data leaving your network\n"
        "      (outbound) or entering it (inbound)?  Outbound bulk\n"
        "      transfers to unknown hosts are especially concerning.",
    ),
    "long_duration": (
        "LONG-LIVED CONNECTION",
        "This connection stayed open for a very long time.\n"
        "      Persistent connections can indicate a backdoor or\n"
        "      Remote Access Tool (RAT) keeping a channel open so\n"
        "      an attacker can send commands whenever they want.",
    ),
    "many_packets": (
        "HIGH PACKET COUNT",
        "An unusually large number of messages were exchanged.\n"
        "      Could be normal (e.g., a video call) or could be\n"
        "      Command-and-Control (C2) chatter — an attacker\n"
        "      issuing many commands to compromised machines.",
    ),
    "small_packets": (
        "SMALL PACKET PATTERN (BEACONING)",
        "Lots of tiny packets were sent back and forth.\n"
        "      This is the hallmark of 'beaconing' — malware\n"
        "      sending periodic 'I'm alive' check-ins to its\n"
        "      controller.  Look for regular timing intervals\n"
        "      between these packets in Wireshark.",
    ),
    "large_packets": (
        "LARGE PACKET PATTERN",
        "Unusually large packets suggest bulk data movement.\n"
        "      Is data leaving (outbound) or entering (inbound)?\n"
        "      Outbound is more concerning — it could be stolen\n"
        "      files, database dumps, or credentials.",
    ),
    "unusual_port": (
        "NON-STANDARD PORT",
        "This conversation used a port not associated with any\n"
        "      common service.  Malware often picks random high\n"
        "      ports to evade basic firewall rules.",
    ),
    "beaconing": (
        "BEACONING DETECTED",
        "Messages were sent at regular intervals — like a clock.\n"
        "      This is one of the strongest malware indicators.\n"
        "      Legitimate software rarely sends data with such\n"
        "      precise, periodic timing.",
    ),
    "dns_tunnel": (
        "POSSIBLE DNS TUNNELING",
        "Data may be hidden inside DNS queries.  Attackers use\n"
        "      this clever technique to sneak data out of networks\n"
        "      that block most traffic but allow DNS (since every\n"
        "      network needs DNS to function).",
    ),
    "c2": (
        "COMMAND & CONTROL (C2)",
        "This looks like communication between malware and its\n"
        "      controller.  C2 traffic is how attackers remotely\n"
        "      operate compromised machines — issuing commands to\n"
        "      steal data, spread laterally, or launch attacks.",
    ),
    "exfiltration": (
        "DATA EXFILTRATION",
        "This pattern suggests data is being copied out of the\n"
        "      network.  This is often the attacker's end goal —\n"
        "      stealing intellectual property, customer records,\n"
        "      financial data, or credentials.",
    ),
    "scan": (
        "NETWORK SCANNING",
        "This looks like port scanning or network reconnaissance.\n"
        "      Attackers scan networks to find vulnerable services\n"
        "      before launching a targeted attack.  Think of it as\n"
        "      someone rattling every door handle in a building.",
    ),
    "ioc": (
        "KNOWN MALICIOUS ADDRESS (IoC MATCH)",
        "One of the IPs in this flow appears on a threat\n"
        "      intelligence blocklist.  This means security\n"
        "      researchers have already linked this address to\n"
        "      malware, phishing, botnets, or other attacks.",
    ),
}

# ── Regex for validating LLM model names before passing to subprocess ────
_MODEL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-/]{0,127}$")


def _is_valid_model_name(name: str) -> bool:
    """Validate that a model name contains only safe characters.

    Prevents shell-injection or path-traversal via model names passed
    to subprocess calls (e.g., ``ollama rm <model>``).
    """
    return bool(name and _MODEL_NAME_RE.fullmatch(name))


_EMBEDDED_VERSION = "2026.02.17-9"  # Stamped by update_version.ps1 at build time


def _compute_app_version():
    # In a frozen (PyInstaller) build, use the version stamped at build time.
    if getattr(sys, "frozen", False):
        return _EMBEDDED_VERSION
    # Prefer version_info.txt when running from source so UI matches release tags.
    try:
        root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
        version_path = os.path.join(root_dir, "version_info.txt")
        if os.path.exists(version_path):
            with open(version_path, encoding="utf-8") as handle:
                raw = handle.read()
            match = re.search(r"filevers=\((\d+),\s*(\d+),\s*(\d+),\s*(\d+)\)", raw)
            if match:
                year, month, day, build = (int(match.group(i)) for i in range(1, 5))
                return f"{year}.{month:02d}.{day:02d}-{build}"
    except Exception:
        pass
    # During development, compute dynamically from date + git commit count.
    today = datetime.now().date()
    date_str = today.strftime("%Y.%m.%d")
    try:
        since = today.strftime("%Y-%m-%dT00:00:00")
        result = subprocess.run(
            ["git", "log", "--oneline", f"--since={since}"],
            capture_output=True,
            text=True,
            timeout=3,
            cwd=os.path.dirname(os.path.abspath(__file__)),
        )
        count = len(result.stdout.strip().splitlines()) if result.returncode == 0 and result.stdout.strip() else 0
    except Exception:
        count = 0
    return f"{date_str}-{count}" if count > 1 else date_str


APP_VERSION = _compute_app_version()


def _get_pandas():
    import pandas as pd

    return pd


def _get_figure():
    from matplotlib.figure import Figure

    return Figure


def _get_figure_canvas():
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

    return FigureCanvasTkAgg


def _get_numpy():
    import numpy as np

    return np


def _get_scapy():
    try:
        from scapy.all import DNS, DNSQR, IP, TCP, UDP, PcapReader, Raw

        return DNS, DNSQR, IP, PcapReader, Raw, TCP, UDP
    except Exception as exc:
        _show_startup_error(
            "Scapy is required but was not found. Please reinstall PCAP Sentry or contact support.",
            exc,
        )
        raise exc


def _get_tls_support():
    try:
        from scapy.layers.tls.all import TLS
        from scapy.layers.tls.extensions import TLSExtALPN, TLSExtServerName
        from scapy.layers.tls.handshake import TLSClientHello

        return TLS, TLSClientHello, TLSExtServerName, TLSExtALPN
    except Exception:
        return None, None, None, None


def _format_tls_version(version):
    if version is None:
        return ""
    try:
        if isinstance(version, str):
            return version
        value = int(version)
    except Exception:
        return ""
    mapping = {
        0x0301: "1.0",
        0x0302: "1.1",
        0x0303: "1.2",
        0x0304: "1.3",
    }
    return mapping.get(value, f"0x{value:04x}")


def _extract_tls_metadata(pkt, tls_support):
    tls_layer, client_hello, ext_sni, ext_alpn = tls_support
    if tls_layer is None:
        return "", "", ""

    tls = pkt.getlayer(tls_layer)
    if tls is None:
        return "", "", ""

    tls_version = _format_tls_version(getattr(tls, "version", None))
    tls_sni = ""
    tls_alpn = ""

    ch = pkt.getlayer(client_hello) if client_hello is not None else None
    if ch is not None:
        if not tls_version:
            tls_version = _format_tls_version(getattr(ch, "version", None))
        extensions = getattr(ch, "ext", []) or []
        for ext in extensions:
            if ext_sni is not None and isinstance(ext, ext_sni):
                server_names = getattr(ext, "servernames", []) or []
                for server in server_names:
                    name = getattr(server, "servername", None)
                    if name:
                        if isinstance(name, bytes):
                            tls_sni = name.decode("utf-8", errors="ignore")
                        else:
                            tls_sni = str(name)
                        break
            if ext_alpn is not None and isinstance(ext, ext_alpn):
                protocols = getattr(ext, "alpn_protocols", []) or []
                if protocols:
                    cleaned = []
                    for proto in protocols:
                        if isinstance(proto, bytes):
                            cleaned.append(proto.decode("utf-8", errors="ignore"))
                        else:
                            cleaned.append(str(proto))
                    tls_alpn = ",".join(cleaned)
        return tls_sni, tls_version, tls_alpn

    return "", tls_version, ""


_sklearn_cache = None


def _get_sklearn():
    global _sklearn_cache
    if _sklearn_cache is not None:
        return _sklearn_cache
    from joblib import dump as _joblib_dump
    from joblib import load as _joblib_load
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.linear_model import LogisticRegression

    _sklearn_cache = (_joblib_dump, _joblib_load, DictVectorizer, LogisticRegression)
    return _sklearn_cache


def _get_tkinterdnd2():
    from tkinterdnd2 import DND_FILES, TkinterDnD

    return DND_FILES, TkinterDnD


def _get_app_base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def _get_app_icon_path(prefer_png=False):
    base_dir = _get_app_base_dir()
    candidates = []
    frozen_dir = getattr(sys, "_MEIPASS", None)
    if prefer_png:
        # Prefer high-res 256px PNG, fall back to 48px
        png_names = ["pcap_sentry_256.png", "pcap_sentry_48.png"]
    else:
        png_names = ["pcap_sentry.ico"]
    for ext in png_names:
        if frozen_dir:
            candidates.append(os.path.join(frozen_dir, "assets", ext))
            candidates.append(os.path.join(frozen_dir, ext))
        candidates.extend(
            [
                os.path.join(base_dir, "assets", ext),
                os.path.abspath(os.path.join(base_dir, "..", "assets", ext)),
                os.path.join(base_dir, ext),
            ]
        )
    for path in candidates:
        if os.path.exists(path):
            return path
    # Fallback: try ICO if PNG was requested but not found
    if prefer_png:
        return _get_app_icon_path(prefer_png=False)
    return None


def _set_app_icon(root):
    icon_path = _get_app_icon_path()
    if not icon_path:
        return
    try:
        root.iconbitmap(default=icon_path)
        root.iconbitmap(icon_path)
    except Exception:
        pass


APP_DATA_FALLBACK_NOTICE = None
APP_DATA_DIR = None


def _get_app_data_dir():
    global APP_DATA_FALLBACK_NOTICE
    global APP_DATA_DIR
    fallback_notice = None
    if getattr(sys, "frozen", False):
        base_dir = _get_app_base_dir()
        data_dir = os.path.join(base_dir, "data")
        if _is_writable_dir(base_dir):
            try:
                os.makedirs(data_dir, exist_ok=True)
                APP_DATA_DIR = data_dir
                return data_dir
            except OSError:
                fallback_notice = "App data folder in install directory is not writable."

    base_dir = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA") or os.path.expanduser("~")
    data_dir = os.path.join(base_dir, "PCAP_Sentry")
    os.makedirs(data_dir, exist_ok=True)
    APP_DATA_DIR = data_dir
    if fallback_notice:
        APP_DATA_FALLBACK_NOTICE = f"{fallback_notice} Using {data_dir} instead."
    return data_dir


def _is_writable_dir(path):
    try:
        return os.access(path, os.W_OK)
    except Exception:
        return False


KNOWLEDGE_BASE_FILE = os.path.join(_get_app_data_dir(), "pcap_knowledge_base_offline.json")
SETTINGS_FILE = os.path.join(_get_app_data_dir(), "settings.json")
MODEL_FILE = os.path.join(_get_app_data_dir(), "pcap_local_model.joblib")


# ── Secure credential helpers ────────────────────────────────────────────────
_KEYRING_SERVICE = "PCAP_Sentry"
_KEYRING_USERNAME_LLM = "llm_api_key"
_KEYRING_USERNAME_OTX = "otx_api_key"
_KEYRING_USERNAME_CHAT_KEY = "chat_encryption_key"
_KEYRING_USERNAME_KB_KEY = "kb_encryption_key"


def _keyring_available():
    """Check if the keyring module is available and functional."""
    try:
        import keyring

        return True
    except Exception:
        return False


def _store_api_key(key: str) -> None:
    """Store the LLM API key in the OS credential store, falling back to no-op."""
    if not key:
        _delete_api_key()
        return
    try:
        import keyring

        keyring.set_password(_KEYRING_SERVICE, _KEYRING_USERNAME_LLM, key)
    except Exception:
        pass  # Fallback: key stays in settings.json


def _store_otx_api_key(key: str) -> None:
    """Store the OTX API key in the OS credential store, falling back to no-op."""
    if not key:
        _delete_otx_api_key()
        return
    try:
        import keyring

        keyring.set_password(_KEYRING_SERVICE, _KEYRING_USERNAME_OTX, key)
    except Exception:
        pass  # Fallback: key stays in settings.json


def _load_api_key() -> str:
    """Load the LLM API key from the OS credential store, falling back to empty string."""
    try:
        import keyring

        val = keyring.get_password(_KEYRING_SERVICE, _KEYRING_USERNAME_LLM)
        return val or ""
    except Exception:
        return ""


def _load_otx_api_key() -> str:
    """Load the OTX API key from the OS credential store, falling back to empty string."""
    try:
        import keyring

        val = keyring.get_password(_KEYRING_SERVICE, _KEYRING_USERNAME_OTX)
        return val or ""
    except Exception:
        return ""


def _delete_api_key() -> None:
    """Remove the LLM API key from the OS credential store."""
    try:
        import keyring

        keyring.delete_password(_KEYRING_SERVICE, _KEYRING_USERNAME_LLM)
    except Exception:
        pass


def _delete_otx_api_key() -> None:
    """Remove the OTX API key from the OS credential store."""
    try:
        import keyring

        keyring.delete_password(_KEYRING_SERVICE, _KEYRING_USERNAME_OTX)
    except Exception:
        pass


# ── Data encryption helpers ──────────────────────────────────────────────────
def _get_or_create_encryption_key(username: str) -> bytes | None:
    """Get or create an encryption key stored in the OS credential store."""
    if not _keyring_available():
        return None
    try:
        import keyring
        from cryptography.fernet import Fernet

        # Try to load existing key
        key_str = keyring.get_password(_KEYRING_SERVICE, username)
        if key_str:
            return key_str.encode()

        # Generate new key
        new_key = Fernet.generate_key()
        keyring.set_password(_KEYRING_SERVICE, username, new_key.decode())
        return new_key
    except Exception:
        return None


def _encrypt_json(data: dict | list, username: str) -> str | None:
    """Encrypt JSON-serializable data. Returns base64-encoded encrypted string or None on error."""
    if data is None:
        return None
    try:
        from cryptography.fernet import Fernet
        import base64

        key = _get_or_create_encryption_key(username)
        if not key:
            return None

        cipher = Fernet(key)
        json_str = json.dumps(data)
        encrypted_bytes = cipher.encrypt(json_str.encode("utf-8"))
        return base64.b64encode(encrypted_bytes).decode("ascii")
    except Exception:
        return None


def _decrypt_json(encrypted_str: str, username: str) -> dict | list | None:
    """Decrypt base64-encoded encrypted JSON data. Returns parsed JSON or None on error."""
    if not encrypted_str:
        return None
    try:
        from cryptography.fernet import Fernet
        import base64

        key = _get_or_create_encryption_key(username)
        if not key:
            return None

        cipher = Fernet(key)
        encrypted_bytes = base64.b64decode(encrypted_str.encode("ascii"))
        decrypted_bytes = cipher.decrypt(encrypted_bytes)
        return json.loads(decrypted_bytes.decode("utf-8"))
    except Exception:
        return None


def _default_settings():
    return {
        "max_rows": DEFAULT_MAX_ROWS,
        "parse_http": True,
        "use_high_memory": False,
        "use_local_model": True,
        "use_multithreading": True,
        "turbo_parse": True,
        "backup_dir": os.path.dirname(KNOWLEDGE_BASE_FILE),
        "llm_provider": "ollama",
        "llm_model": "llama3",
        "llm_endpoint": "http://localhost:11434",
        "llm_auto_detect": True,
        "theme": "system",
        "offline_mode": False,
        "otx_api_key": "",
        "app_data_notice_shown": False,
    }


def load_settings():
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                defaults = _default_settings()
                defaults.update(data)
                # Prefer OS credential store for API keys
                if _keyring_available():
                    # Handle LLM API key
                    stored_key = _load_api_key()
                    if stored_key:
                        defaults["llm_api_key"] = stored_key
                    elif data.get("llm_api_key"):
                        # Migrate plaintext LLM key to keyring on first load
                        _store_api_key(data["llm_api_key"])
                        defaults["llm_api_key"] = data["llm_api_key"]
                    # Handle OTX API key
                    stored_otx_key = _load_otx_api_key()
                    if stored_otx_key:
                        defaults["otx_api_key"] = stored_otx_key
                    elif data.get("otx_api_key"):
                        # Migrate plaintext OTX key to keyring on first load
                        _store_otx_api_key(data["otx_api_key"])
                        defaults["otx_api_key"] = data["otx_api_key"]

                    # Decrypt chat_history if encrypted
                    encrypted_chat = data.get("chat_history_encrypted")
                    if encrypted_chat:
                        decrypted = _decrypt_json(encrypted_chat, _KEYRING_USERNAME_CHAT_KEY)
                        if decrypted is not None:
                            defaults["chat_history"] = decrypted
                    elif data.get("chat_history"):
                        # Migrate plaintext chat history on first load
                        defaults["chat_history"] = data["chat_history"]
                return defaults
    except Exception:
        pass
    return _default_settings()


def save_settings(settings):
    try:
        # Store API keys in OS credential store if available
        llm_api_key = settings.get("llm_api_key", "")
        otx_api_key = settings.get("otx_api_key", "")
        if _keyring_available():
            _store_api_key(llm_api_key)
            _store_otx_api_key(otx_api_key)
            # Remove plaintext keys from settings file
            settings = dict(settings)
            settings.pop("llm_api_key", None)
            settings.pop("otx_api_key", None)

            # Encrypt chat_history
            chat_history = settings.get("chat_history", [])
            if chat_history:
                encrypted = _encrypt_json(chat_history, _KEYRING_USERNAME_CHAT_KEY)
                if encrypted:
                    settings["chat_history_encrypted"] = encrypted
                    settings.pop("chat_history", None)
        # Use tempfile.mkstemp for atomic write (avoids symlink race on
        # a predictable ".tmp" path).
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(SETTINGS_FILE), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(settings, f, indent=2)
            os.replace(tmp, SETTINGS_FILE)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
    except Exception:
        pass


def _format_bytes(value):
    if value is None:
        return ""
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0 or unit == "TB":
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return None


def _default_kb():
    return {"safe": [], "malicious": [], "unsure": [], "ioc": {"ips": [], "domains": [], "hashes": []}}


def load_knowledge_base():
    with _kb_lock:
        try:
            if os.path.exists(KNOWLEDGE_BASE_FILE):
                with open(KNOWLEDGE_BASE_FILE, encoding="utf-8") as f:
                    content = f.read().strip()

                # Try to decrypt if keyring is available
                if _keyring_available() and content:
                    try:
                        # Check if content looks like encrypted data (base64)
                        if not content.startswith("{"):
                            decrypted = _decrypt_json(content, _KEYRING_USERNAME_KB_KEY)
                            if decrypted and isinstance(decrypted, dict):
                                data = decrypted
                            else:
                                # Decryption failed, try plain JSON
                                data = json.loads(content)
                        else:
                            # Looks like plain JSON, migrate to encrypted
                            data = json.loads(content)
                    except Exception:
                        # Fall back to plain JSON parsing
                        data = json.loads(content)
                else:
                    # No keyring, use plain JSON
                    data = json.loads(content)

                if isinstance(data, dict):
                    data.setdefault("safe", [])
                    data.setdefault("malicious", [])
                    data.setdefault("unsure", [])
                    ioc = data.setdefault("ioc", {})
                    ioc.setdefault("ips", [])
                    ioc.setdefault("domains", [])
                    ioc.setdefault("hashes", [])
                    return data
        except Exception:
            pass
        return _default_kb()


def save_knowledge_base(data):
    with _kb_lock:
        os.makedirs(os.path.dirname(KNOWLEDGE_BASE_FILE), exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(KNOWLEDGE_BASE_FILE), suffix=".tmp")
        try:
            # Encrypt KB data if keyring is available
            if _keyring_available():
                encrypted = _encrypt_json(data, _KEYRING_USERNAME_KB_KEY)
                if encrypted:
                    # Write encrypted string
                    with os.fdopen(fd, "w", encoding="utf-8") as f:
                        f.write(encrypted)
                else:
                    # Encryption failed, fall back to plain JSON
                    with os.fdopen(fd, "w", encoding="utf-8") as f:
                        json.dump(data, f, indent=2)
            else:
                # No keyring, write plain JSON
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
            os.replace(tmp_path, KNOWLEDGE_BASE_FILE)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)
            raise


def _backup_knowledge_base(max_backups=3):
    """Copy the knowledge base file to a timestamped backup, keeping only the most recent *max_backups* versions."""
    try:
        if not os.path.exists(KNOWLEDGE_BASE_FILE):
            return
        backup_dir = os.path.join(os.path.dirname(KNOWLEDGE_BASE_FILE), "kb_backups")
        os.makedirs(backup_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(backup_dir, f"pcap_knowledge_base_{ts}.json")
        shutil.copy2(KNOWLEDGE_BASE_FILE, backup_path)
        # Prune old backups – keep only the most recent max_backups files
        backups = sorted(
            [f for f in os.listdir(backup_dir) if f.startswith("pcap_knowledge_base_") and f.endswith(".json")],
        )
        while len(backups) > max_backups:
            oldest = backups.pop(0)
            with contextlib.suppress(OSError):
                os.remove(os.path.join(backup_dir, oldest))
    except Exception:
        pass  # Best-effort – never block shutdown


def _normalize_ioc_item(item):
    text = item.strip().lower()
    if not text:
        return None, None

    if text.startswith("http://") or text.startswith("https://"):
        text = text.split("://", 1)[1]
    if "/" in text:
        text = text.split("/", 1)[0]

    try:
        ipaddress.ip_address(text)
        return "ips", text
    except ValueError:
        pass

    if ":" in text and text.count(":") == 1:
        text = text.split(":", 1)[0]

    if "." in text:
        return "domains", text

    if all(c in "0123456789abcdef" for c in text) and len(text) in (32, 40, 64):
        return "hashes", text

    return None, None


def _parse_ioc_text(raw_text):
    iocs = {"ips": set(), "domains": set(), "hashes": set()}
    for line in raw_text.splitlines():
        cleaned = line.strip()
        if not cleaned or cleaned.startswith("#"):
            continue
        cleaned = cleaned.replace(",", " ")
        for token in cleaned.split():
            key, value = _normalize_ioc_item(token)
            if key:
                iocs[key].add(value)
    return iocs


def load_iocs_from_file(path):
    with open(path, encoding="utf-8") as f:
        raw = f.read()

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = None

    if isinstance(parsed, dict):
        iocs = {"ips": set(), "domains": set(), "hashes": set()}
        for key in ("ips", "domains", "hashes"):
            values = parsed.get(key, [])
            if isinstance(values, list):
                for item in values:
                    key_name, value = _normalize_ioc_item(str(item))
                    if key_name:
                        iocs[key_name].add(value)
        return iocs

    if isinstance(parsed, list):
        return _parse_ioc_text("\n".join(str(item) for item in parsed))

    return _parse_ioc_text(raw)


def merge_iocs_into_kb(kb, new_iocs):
    kb_ioc = kb.get("ioc", {})
    for key in ("ips", "domains", "hashes"):
        combined = set(kb_ioc.get(key, [])) | set(new_iocs.get(key, set()))
        kb["ioc"][key] = sorted(combined)
    return kb


def _safe_urlopen(url, data=None, headers=None, timeout=30, context=None):
    """
    Secure wrapper for urllib.request.urlopen that validates URL schemes.

    Only allows http:// and https:// schemes to prevent file:// and other
    dangerous protocols. Provides defense-in-depth against URL-based attacks.

    Args:
        url: URL string or Request object
        data: Optional POST data (bytes)
        headers: Optional dict of HTTP headers
        timeout: Request timeout in seconds (default: 30)
        context: Optional SSL context

    Returns:
        Response object from urllib.request.urlopen

    Raises:
        ValueError: If URL scheme is not http:// or https://
    """
    # Extract URL string from Request object if needed
    url_str = url.full_url if hasattr(url, "full_url") else str(url)
    url_lower = url_str.lower()

    # Validate scheme - only http(s) allowed
    if not (url_lower.startswith("http://") or url_lower.startswith("https://")):
        # Extract scheme for error message
        scheme = url_str.split(":", 1)[0] if ":" in url_str else "unknown"
        raise ValueError(
            f"Blocked unsafe URL scheme: {scheme}://\n"
            "Only http:// and https:// schemes are permitted.\n"
            "This prevents file:// and other potentially dangerous protocols."
        )

    # Restrict http:// to localhost only (prevent MitM on external connections)
    if url_lower.startswith("http://"):
        from urllib.parse import urlparse as _urlparse

        _host = (_urlparse(url_str).hostname or "").lower()
        _localhost = {"localhost", "127.0.0.1", "::1", "[::1]"}
        if _host not in _localhost:
            raise ValueError(
                f"Unencrypted http:// connections are only allowed to localhost.\n"
                f"Use https:// for external host: {_host}"
            )

    # Explicit file:// blocking (defense in depth)
    if "file:" in url_lower:
        raise ValueError(
            "file:// scheme is explicitly blocked for security.\n"
            "Local file access through URL schemes is not permitted."
        )

    # Build Request object if url is a string
    if isinstance(url, str):
        req = urllib.request.Request(url, data=data, headers=headers or {})
    else:
        req = url  # Already a Request object

    # Make the request with validated URL
    if context:
        return urllib.request.urlopen(req, timeout=timeout, context=context)  # nosec B310 - scheme validated above
    return urllib.request.urlopen(req, timeout=timeout)  # nosec B310 - scheme validated above


# Well-known malware / C2 ports used by common threats
MALWARE_PORTS = frozenset(
    {
        4444,
        5555,
        6666,
        6667,
        6668,
        6669,  # Meterpreter, IRC C2
        1337,
        31337,
        12345,
        27374,  # classic backdoors
        8443,
        8880,
        9001,
        9030,
        9050,
        9150,  # Tor, alt-HTTPS
        3127,
        3128,
        3389,  # proxy/RDP abuse
        1080,
        1099,  # SOCKS, RMI
        2222,
        5900,
        5985,
        5986,  # alt-SSH, VNC, WinRM
        8081,
        8888,
        9999,
        10000,  # common RAT/C2 ports
        20,
        69,  # FTP-data, TFTP
        445,
        139,
        135,  # SMB/NetBIOS/RPC abuse
    }
)

FEATURE_NAMES = [
    "packet_count",
    "avg_size",
    "median_size",
    "dns_query_count",
    "http_request_count",
    "unique_http_hosts",
    "tls_packet_count",
    "unique_tls_sni",
    "unique_src",
    "unique_dst",
    "proto_tcp",
    "proto_udp",
    "proto_other",
    "top_port_1",
    "top_port_2",
    "top_port_3",
    "top_port_4",
    "top_port_5",
    "flagged_ip_count",
    "flagged_domain_count",
    "avg_ip_risk_score",
    "avg_domain_risk_score",
    "malware_port_hits",
    "dns_per_packet_ratio",
    "bytes_per_unique_dst",
]


def _vector_from_features(features):
    proto = features.get("proto_ratio", {})
    top_ports = features.get("top_ports", [])

    def port_at(idx):
        return float(top_ports[idx]) if idx < len(top_ports) else 0.0

    pkt_count = float(features.get("packet_count", 0.0))

    return [
        pkt_count,
        float(features.get("avg_size", 0.0)),
        float(features.get("median_size", 0.0)),
        float(features.get("dns_query_count", 0.0)),
        float(features.get("http_request_count", 0.0)),
        float(features.get("unique_http_hosts", 0.0)),
        float(features.get("tls_packet_count", 0.0)),
        float(features.get("unique_tls_sni", 0.0)),
        float(features.get("unique_src", 0.0)),
        float(features.get("unique_dst", 0.0)),
        float(proto.get("TCP", 0.0)),
        float(proto.get("UDP", 0.0)),
        float(proto.get("Other", 0.0)),
        port_at(0),
        port_at(1),
        port_at(2),
        port_at(3),
        port_at(4),
        float(features.get("flagged_ip_count", 0.0)),
        float(features.get("flagged_domain_count", 0.0)),
        float(features.get("avg_ip_risk_score", 0.0)),
        float(features.get("avg_domain_risk_score", 0.0)),
        float(features.get("malware_port_hits", 0.0)),
        float(features.get("dns_query_count", 0)) / max(pkt_count, 1.0),
        (pkt_count * float(features.get("avg_size", 0.0))) / max(float(features.get("unique_dst", 1.0)), 1.0),
    ]


def _compute_normalizer(vectors):
    if not vectors:
        return None
    columns = list(zip(*vectors, strict=False))
    means = [sum(col) / len(col) for col in columns]
    stds = [statistics.pstdev(col) or 1.0 for col in columns]
    return {"mean": means, "std": stds}


def _normalize_vector(vector, normalizer):
    return [
        (value - mean) / std for value, mean, std in zip(vector, normalizer["mean"], normalizer["std"], strict=False)
    ]


def _vectorize_kb(kb):
    """Pre-compute feature vectors and normalized centroids for all KB entries (call once per analysis)."""
    safe_vectors = [_vector_from_features(entry["features"]) for entry in kb.get("safe", [])]
    mal_vectors = [_vector_from_features(entry["features"]) for entry in kb.get("malicious", [])]
    result = {"safe": safe_vectors, "malicious": mal_vectors}
    # Pre-compute normalized centroids for classify_vector to avoid re-normalizing every call
    if safe_vectors and mal_vectors:
        all_vectors = safe_vectors + mal_vectors
        normalizer = _compute_normalizer(all_vectors)
        safe_norm = [_normalize_vector(v, normalizer) for v in safe_vectors]
        mal_norm = [_normalize_vector(v, normalizer) for v in mal_vectors]
        cols_s = list(zip(*safe_norm, strict=False))
        cols_m = list(zip(*mal_norm, strict=False))
        result["_safe_centroid"] = [sum(c) / len(c) for c in cols_s]
        result["_mal_centroid"] = [sum(c) / len(c) for c in cols_m]
        result["_normalizer"] = normalizer
        # Per-cluster variance for Mahalanobis-like distance
        result["_safe_var"] = [max(statistics.pvariance(c), 1e-6) for c in cols_s]
        result["_mal_var"] = [max(statistics.pvariance(c), 1e-6) for c in cols_m]
    return result


def compute_baseline_from_kb(kb, kb_vectors=None):
    safe_vectors = (
        kb_vectors["safe"] if kb_vectors else [_vector_from_features(entry["features"]) for entry in kb.get("safe", [])]
    )
    if not safe_vectors:
        return None
    normalizer = _compute_normalizer(safe_vectors)
    return {"normalizer": normalizer, "vectors": safe_vectors}


def anomaly_score(vector, baseline):
    if baseline is None:
        return None, []
    normalizer = baseline["normalizer"]
    zscores = []
    for value, mean, std in zip(vector, normalizer["mean"], normalizer["std"], strict=False):
        z = abs(value - mean) / (std or 1.0)
        zscores.append(z)

    capped = [min(z, 4.0) for z in zscores]
    avg_score = sum(capped) / max(len(capped), 1) / 4.0 * 100.0
    # Use max z-score as secondary signal to avoid masking critical anomalies
    max_z = max(zscores) if zscores else 0.0
    max_score = min(max_z / 4.0, 1.0) * 100.0
    # Blend: 60% average + 40% max to catch single extreme outliers
    score = avg_score * 0.6 + max_score * 0.4

    # Critical outlier floor: if any z-score exceeds 6.0, impose a minimum
    # anomaly score to prevent extreme single-feature anomalies from being
    # masked by many normal features in the blend.
    if max_z > 6.0:
        critical_floor = min(75.0, max_z * 8.0)
        score = max(score, critical_floor)

    top = sorted(enumerate(zscores), key=lambda item: item[1], reverse=True)[:3]
    reasons = [f"{FEATURE_NAMES[idx]} z={value:.1f}" for idx, value in top if value > 0]
    return round(score, 1), reasons


def classify_vector(vector, kb, normalizer_cache=None, kb_vectors=None):
    safe_entries = kb.get("safe", [])
    mal_entries = kb.get("malicious", [])
    if not safe_entries or not mal_entries:
        return None

    # Use pre-computed centroids and normalizer from _vectorize_kb when available
    if kb_vectors and "_safe_centroid" in kb_vectors:
        normalizer = normalizer_cache if normalizer_cache is not None else kb_vectors["_normalizer"]
        target = _normalize_vector(vector, normalizer)
        safe_centroid = kb_vectors["_safe_centroid"]
        mal_centroid = kb_vectors["_mal_centroid"]
        safe_var = kb_vectors.get("_safe_var")
        mal_var = kb_vectors.get("_mal_var")
    else:
        # Fallback: compute on the fly
        safe_vectors = (
            kb_vectors["safe"] if kb_vectors else [_vector_from_features(entry["features"]) for entry in safe_entries]
        )
        mal_vectors = (
            kb_vectors["malicious"]
            if kb_vectors
            else [_vector_from_features(entry["features"]) for entry in mal_entries]
        )

        if normalizer_cache is not None:
            normalizer = normalizer_cache
        else:
            all_vectors = safe_vectors + mal_vectors
            normalizer = _compute_normalizer(all_vectors)

        safe_norm = [_normalize_vector(vec, normalizer) for vec in safe_vectors]
        mal_norm = [_normalize_vector(vec, normalizer) for vec in mal_vectors]
        target = _normalize_vector(vector, normalizer)

        def centroid(vectors):
            cols = list(zip(*vectors, strict=False))
            return [sum(col) / len(col) for col in cols]

        safe_centroid = centroid(safe_norm)
        mal_centroid = centroid(mal_norm)
        # Compute per-cluster variance for weighted distance
        cols_s = list(zip(*safe_norm, strict=False))
        cols_m = list(zip(*mal_norm, strict=False))
        safe_var = [max(statistics.pvariance(c), 1e-6) for c in cols_s]
        mal_var = [max(statistics.pvariance(c), 1e-6) for c in cols_m]

    # Variance-weighted (Mahalanobis-like) distance for more robust classification
    def weighted_distance(a, b, var):
        return math.sqrt(sum((x - y) ** 2 / v for x, y, v in zip(a, b, var, strict=False)))

    dist_safe = weighted_distance(target, safe_centroid, safe_var)
    dist_mal = weighted_distance(target, mal_centroid, mal_var)
    if dist_safe + dist_mal == 0:
        prob_mal = 0.5
    else:
        prob_mal = dist_safe / (dist_safe + dist_mal)
    score = round(prob_mal * 100.0, 1)
    return {
        "score": score,
        "dist_safe": dist_safe,
        "dist_mal": dist_mal,
        "normalizer": normalizer,
        "backend": "cpu",
    }


def _domain_matches(domain, ioc_domains):
    if domain in ioc_domains:
        return domain
    parts = domain.split(".")
    # Require at least 2 parts to avoid matching bare TLDs (e.g., "com", "net")
    for idx in range(1, len(parts)):
        candidate = ".".join(parts[idx:])
        if len(candidate.split(".")) >= 2 and candidate in ioc_domains:
            return candidate
    return None


def match_iocs(stats, iocs):
    matches = {"ips": set(), "domains": set()}
    ioc_ips = set(iocs.get("ips", []))
    ioc_domains = set(iocs.get("domains", []))

    if ioc_ips:
        matches["ips"].update(set(stats.get("unique_src_list", [])) & ioc_ips)
        matches["ips"].update(set(stats.get("unique_dst_list", [])) & ioc_ips)

    if ioc_domains:
        for domain in stats.get("dns_queries", []):
            match = _domain_matches(domain.lower(), ioc_domains)
            if match:
                matches["domains"].add(match)
        for domain in stats.get("http_hosts", []):
            match = _domain_matches(domain.lower(), ioc_domains)
            if match:
                matches["domains"].add(match)
        for domain in stats.get("tls_sni", []):
            match = _domain_matches(domain.lower(), ioc_domains)
            if match:
                matches["domains"].add(match)

    return {"ips": sorted(matches["ips"]), "domains": sorted(matches["domains"])}


def summarize_stats(stats):
    top_ports = stats.get("top_ports", [])
    proto = stats.get("protocol_counts", {})
    dns_count = stats.get("dns_query_count", 0)
    http_count = stats.get("http_request_count", 0)
    tls_count = stats.get("tls_packet_count", 0)
    return (
        f"Packets: {stats.get('packet_count', 0)}, "
        f"Avg Size: {stats.get('avg_size', 0):.1f}, "
        f"Top Ports: {top_ports}, "
        f"Protocols: {proto}, "
        f"DNS Queries: {dns_count}, "
        f"HTTP Requests: {http_count}, "
        f"TLS Packets: {tls_count}"
    )


def build_features(stats):
    total = stats.get("packet_count", 0) or 1
    proto_counts = stats.get("protocol_counts", {})
    proto_ratio = {k: v / total for k, v in proto_counts.items()}
    top_ports = [p for p, _ in stats.get("top_ports", [])]

    # Count how many top ports are known malware / C2 ports
    malware_port_hits = sum(1 for p in top_ports if p in MALWARE_PORTS)

    features = {
        "packet_count": stats.get("packet_count", 0),
        "avg_size": stats.get("avg_size", 0.0),
        "median_size": stats.get("median_size", 0.0),
        "proto_ratio": proto_ratio,
        "top_ports": top_ports,
        "dns_query_count": stats.get("dns_query_count", 0),
        "http_request_count": stats.get("http_request_count", 0),
        "unique_http_hosts": stats.get("unique_http_hosts", 0),
        "tls_packet_count": stats.get("tls_packet_count", 0),
        "unique_tls_sni": stats.get("unique_tls_sni", 0),
        "unique_src": stats.get("unique_src", 0),
        "unique_dst": stats.get("unique_dst", 0),
        "malware_port_hits": malware_port_hits,
    }

    # Add threat intelligence features if available
    if "threat_intel" in stats:
        intel = stats["threat_intel"]

        risky_ips = intel.get("risky_ips", [])
        risky_domains = intel.get("risky_domains", [])

        features["flagged_ip_count"] = len(risky_ips)
        features["flagged_domain_count"] = len(risky_domains)

        if risky_ips:
            avg_ip_risk = sum(ip["risk_score"] for ip in risky_ips) / len(risky_ips)
            features["avg_ip_risk_score"] = avg_ip_risk
        else:
            features["avg_ip_risk_score"] = 0.0

        if risky_domains:
            avg_domain_risk = sum(d["risk_score"] for d in risky_domains) / len(risky_domains)
            features["avg_domain_risk_score"] = avg_domain_risk
        else:
            features["avg_domain_risk_score"] = 0.0
    else:
        features["flagged_ip_count"] = 0
        features["flagged_domain_count"] = 0
        features["avg_ip_risk_score"] = 0.0
        features["avg_domain_risk_score"] = 0.0

    return features


def _vectorize_features(features):
    pkt_count = float(features.get("packet_count", 0))
    vector = {
        "packet_count": pkt_count,
        "avg_size": float(features.get("avg_size", 0.0)),
        "median_size": float(features.get("median_size", 0.0)),
        "dns_query_count": float(features.get("dns_query_count", 0)),
        "http_request_count": float(features.get("http_request_count", 0)),
        "unique_http_hosts": float(features.get("unique_http_hosts", 0)),
        "tls_packet_count": float(features.get("tls_packet_count", 0)),
        "unique_tls_sni": float(features.get("unique_tls_sni", 0)),
        "unique_src": float(features.get("unique_src", 0)),
        "unique_dst": float(features.get("unique_dst", 0)),
        "malware_port_hits": float(features.get("malware_port_hits", 0)),
        # Threat intelligence features
        "flagged_ip_count": float(features.get("flagged_ip_count", 0)),
        "flagged_domain_count": float(features.get("flagged_domain_count", 0)),
        "avg_ip_risk_score": float(features.get("avg_ip_risk_score", 0.0)),
        "avg_domain_risk_score": float(features.get("avg_domain_risk_score", 0.0)),
        # Derived ratios
        "dns_per_packet_ratio": float(features.get("dns_query_count", 0)) / max(pkt_count, 1.0),
    }

    proto_ratio = features.get("proto_ratio", {})
    if proto_ratio:
        for proto, ratio in proto_ratio.items():
            vector[f"proto_{proto}"] = float(ratio)

    top_ports = features.get("top_ports", [])
    if top_ports:
        for port in top_ports:
            vector[f"port_{int(port)}"] = 1.0

    return vector


def _train_local_model(kb):
    if not _check_sklearn():
        return None, "scikit-learn is not installed."

    _joblib_dump, _joblib_load, DictVectorizer, LogisticRegression = _get_sklearn()

    rows = []
    labels = []
    for label in ("safe", "malicious"):
        for entry in kb.get(label, []):
            rows.append(_vectorize_features(entry.get("features", {})))
            labels.append(label)

    if len(set(labels)) < 2 or len(labels) < 2:
        return None, "Need at least one safe and one malware sample to train."

    vectorizer = DictVectorizer(sparse=True)
    X = vectorizer.fit_transform(rows)

    model = LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
        random_state=42,
    )
    model.fit(X, labels)
    return {
        "backend": "cpu",
        "model": model,
        "vectorizer": vectorizer,
    }, None


# Machine-specific HMAC key for model integrity verification.
# A random 32-byte secret is generated on first use and persisted in the
# app data directory.  This is far stronger than deriving a key from
# predictable environment variables (COMPUTERNAME/USERNAME).
def _get_model_hmac_key() -> bytes:
    key_path = os.path.join(_get_app_data_dir(), ".model_hmac_key")
    if os.path.isfile(key_path):
        try:
            with open(key_path, "rb") as f:
                key = f.read()
            if len(key) == 32:
                return key
        except OSError:
            pass
    # Generate a new random key and persist it
    key = os.urandom(32)
    try:
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(key_path))
        closed = False
        try:
            os.write(fd, key)
            os.close(fd)
            closed = True
            os.replace(tmp, key_path)
        except BaseException:
            if not closed:
                with contextlib.suppress(OSError):
                    os.close(fd)
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
    except OSError:
        pass  # key is still usable in-memory for this session
    return key


_MODEL_HMAC_KEY = _get_model_hmac_key()


def _model_hmac_path():
    return MODEL_FILE + ".hmac"


def _write_model_hmac():
    """Compute and write HMAC-SHA256 for the saved model file."""
    h = hmac.new(_MODEL_HMAC_KEY, digestmod=hashlib.sha256)
    with open(MODEL_FILE, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    with open(_model_hmac_path(), "w", encoding="utf-8") as f:
        f.write(h.hexdigest())


def _verify_model_hmac():
    """Verify HMAC-SHA256 of the model file. Returns False if tampered or missing."""
    hmac_file = _model_hmac_path()
    if not os.path.exists(hmac_file):
        return False
    try:
        with open(hmac_file, encoding="utf-8") as f:
            expected = f.read().strip().lower()
        h = hmac.new(_MODEL_HMAC_KEY, digestmod=hashlib.sha256)
        with open(MODEL_FILE, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return hmac.compare_digest(h.hexdigest().lower(), expected)
    except Exception:
        return False


def _save_local_model(model_bundle):
    _joblib_dump, _joblib_load, _DictVectorizer, _LogisticRegression = _get_sklearn()
    _joblib_dump(model_bundle, MODEL_FILE)
    with contextlib.suppress(Exception):
        _write_model_hmac()


def _load_local_model():
    if not _check_sklearn() or not os.path.exists(MODEL_FILE):
        return None

    # Verify integrity before deserializing (pickle is dangerous with untrusted data)
    if not _verify_model_hmac():
        return None

    _joblib_dump, _joblib_load, _DictVectorizer, _LogisticRegression = _get_sklearn()
    try:
        meta = _joblib_load(MODEL_FILE)
    except Exception:
        return None

    # Type-check deserialized objects (defense-in-depth against pickle attacks)
    if not isinstance(meta, dict):
        return None
    model = meta.get("model")
    vectorizer = meta.get("vectorizer")
    if model is not None and not (hasattr(model, "predict") and hasattr(model, "predict_proba")):
        return None
    if vectorizer is not None and not (
        hasattr(vectorizer, "transform") and hasattr(vectorizer, "get_feature_names_out")
    ):
        return None

    return meta


def _predict_local_model(model_bundle, features):
    vectorizer = model_bundle.get("vectorizer")
    model = model_bundle.get("model")
    if vectorizer is None or model is None:
        return None, None

    row = _vectorize_features(features)
    X = vectorizer.transform([row])

    pred = model.predict(X)[0]
    proba = None
    if hasattr(model, "predict_proba"):
        probas = model.predict_proba(X)[0]
        class_index = list(model.classes_).index("malicious")
        proba = float(probas[class_index])
    return str(pred), proba


def similarity_score(target, entry, _target_ports=None, _target_proto=None):
    target_count = target.get("packet_count", 0)
    entry_count = entry.get("packet_count", 0)
    if not target_count or not entry_count:
        return 0.0

    # Use pre-computed sets when available to avoid repeated construction
    target_ports = _target_ports if _target_ports is not None else set(target.get("top_ports", []))
    entry_ports = set(entry.get("top_ports", []))
    ports_union = target_ports | entry_ports
    port_overlap = len(target_ports & entry_ports) / max(len(ports_union), 1)

    target_proto = _target_proto if _target_proto is not None else target.get("proto_ratio", {})
    entry_proto = entry.get("proto_ratio", {})
    proto_keys = set(target_proto) | set(entry_proto)
    proto_diff = sum(abs(target_proto.get(k, 0) - entry_proto.get(k, 0)) for k in proto_keys)
    proto_similarity = max(0.0, 1.0 - proto_diff)

    def similarity_metric(a, b):
        return 1.0 - min(abs(a - b) / max(a, b, 1.0), 1.0)

    size_similarity = similarity_metric(target.get("avg_size", 0.0), entry.get("avg_size", 0.0))
    count_similarity = similarity_metric(target_count, entry_count)
    dns_similarity = similarity_metric(target.get("dns_query_count", 0), entry.get("dns_query_count", 0))
    http_similarity = similarity_metric(target.get("http_request_count", 0), entry.get("http_request_count", 0))
    tls_similarity = similarity_metric(target.get("tls_packet_count", 0), entry.get("tls_packet_count", 0))
    dst_similarity = similarity_metric(target.get("unique_dst", 1), entry.get("unique_dst", 1))

    score = 100.0 * (
        0.25 * port_overlap
        + 0.20 * proto_similarity
        + 0.12 * size_similarity
        + 0.10 * count_similarity
        + 0.10 * dns_similarity
        + 0.08 * http_similarity
        + 0.08 * tls_similarity
        + 0.07 * dst_similarity
    )
    return round(score, 1)


def get_top_k_similar_entries(features, kb_entries, k=5):
    """Performance optimization: Only score top K entries using fast pre-filtering

    Pre-filter by packet count similarity to reduce full similarity calculations by 80-90%.
    Only score the most promising candidates.
    """
    if not kb_entries:
        return [], []

    target_pkt = features.get("packet_count", 0)
    if not target_pkt:
        return kb_entries[:k], [similarity_score(features, e["features"]) for e in kb_entries[:k]]

    # Fast pre-filter: select candidates with similar packet counts (within ±50%)
    candidates = []
    for entry in kb_entries:
        entry_pkt = entry["features"].get("packet_count", 0)
        # Widened pre-filter from ±50% to ±100% to avoid dropping valid matches
        # with different capture durations but similar traffic patterns
        if entry_pkt and abs(entry_pkt - target_pkt) < target_pkt * 1.0:
            candidates.append(entry)

    # Ensure at least 2*k candidates to avoid losing critical matches
    if len(candidates) < 2 * k:
        candidates = kb_entries

    # Pre-compute target sets once for all comparisons (P3 fix)
    target_ports = set(features.get("top_ports", []))
    target_proto = features.get("proto_ratio", {})

    # Score only candidates, then get top K
    if len(candidates) <= k:
        scores = [
            similarity_score(features, e["features"], _target_ports=target_ports, _target_proto=target_proto)
            for e in candidates
        ]
        sorted_indices = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
        return [candidates[i] for i in sorted_indices], [scores[i] for i in sorted_indices]

    # Score all candidates and take top K
    scores = [
        similarity_score(features, e["features"], _target_ports=target_ports, _target_proto=target_proto)
        for e in candidates
    ]
    top_indices = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:k]
    return [candidates[i] for i in top_indices], [scores[i] for i in top_indices]


def parse_http_payload(payload):
    if not payload or len(payload) < 14:  # Minimum GET / HTTP/1.1
        return "", "", ""

    # Fast check for HTTP methods
    first_bytes = payload[:8]
    if not (
        first_bytes.startswith(b"GET ")
        or first_bytes.startswith(b"POST")
        or first_bytes.startswith(b"HEAD")
        or first_bytes.startswith(b"PUT ")
        or first_bytes.startswith(b"DELETE")
        or first_bytes.startswith(b"PATCH")
        or first_bytes.startswith(b"OPTIONS")
        or first_bytes.startswith(b"CONNECT")
    ):
        return "", "", ""

    try:
        # Find end of first line
        line_end = payload.find(b"\r\n")
        if line_end < 0 or line_end > 200:  # Reasonable request line limit
            return "", "", ""

        request_line = payload[:line_end].decode("latin-1", errors="ignore")
        parts = request_line.split(" ", 2)
        if len(parts) < 2:
            return "", "", ""
        method = parts[0]
        path = parts[1]

        # Fast host header search
        host = ""
        host_idx = payload.find(b"\r\nHost:", 0, min(len(payload), 2000))
        if host_idx == -1:
            host_idx = payload.find(b"\r\nhost:", 0, min(len(payload), 2000))

        if host_idx != -1:
            host_start = host_idx + 7  # len("\r\nHost:")
            host_end = payload.find(b"\r\n", host_start)
            if host_end != -1:
                host_value = payload[host_start:host_end].strip()
                host = host_value.decode("latin-1", errors="ignore")
                # Remove port if present
                colon_idx = host.find(":")
                if colon_idx != -1:
                    host = host[:colon_idx]

        return host, path, method
    except Exception:
        return "", "", ""


# Pre-compiled regex patterns for HTTP credential extraction (P4 fix)
_RE_HTTP_BASIC = re.compile(r"(?i)\r\nAuthorization:\s*Basic\s+([A-Za-z0-9+/=]+)")
_RE_HTTP_NTLM = re.compile(r"(?i)\r\nAuthorization:\s*NTLM\s+([A-Za-z0-9+/=]+)")
_RE_HTTP_COOKIE = re.compile(r"(?i)\r\nCookie:\s*(.+?)\r\n")
_RE_HTTP_SET_COOKIE = re.compile(r"(?i)\r\nSet-Cookie:\s*(.+?)\r\n")
_RE_FORM_USER = re.compile(r"(?:user(?:name)?|login|email|acct)=([^&\r\n]+)", re.IGNORECASE)
_RE_FORM_PASS = re.compile(r"(?:pass(?:word)?|passwd|pw|secret)=([^&\r\n]+)", re.IGNORECASE)


def extract_credentials_and_hosts(file_path, use_high_memory=False):
    """Extract credentials, usernames, passwords, hostnames, MAC addresses from a PCAP file.

    Returns a dict with keys:
        credentials  - list of dicts {protocol, src, dst, field, value, detail}
        hosts        - dict mapping IP -> {mac: set, hostnames: set}
    """
    DNS, DNSQR, IP, PcapReader, Raw, TCP, UDP = _get_scapy()
    try:
        from scapy.layers.l2 import Ether
    except ImportError:
        Ether = None

    resolved_path, cleanup, _ = _resolve_pcap_source(file_path)

    credentials = []  # list of dicts
    hosts = {}  # ip -> {"mac": set(), "hostnames": set()}
    _seen_creds = set()  # dedup key
    # Bounded dict to avoid unbounded growth on large PCAPs with many FTP sessions.
    # Uses OrderedDict as a simple LRU; evicts oldest entries when full.
    from collections import OrderedDict

    _FTP_STATE_MAX = 2000
    ftp_state = OrderedDict()  # src_ip:src_port -> last USER value
    MAX_CREDS = 5000

    def _add_host(ip, mac=None, hostname=None):
        if ip not in hosts:
            hosts[ip] = {"mac": set(), "hostnames": set()}
        if mac and mac not in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
            hosts[ip]["mac"].add(mac)
        if hostname:
            hosts[ip]["hostnames"].add(hostname)

    def _add_cred(protocol, src, dst, field, value, detail=""):
        if len(credentials) >= MAX_CREDS:
            return
        key = (protocol, src, dst, field, value)
        if key in _seen_creds:
            return
        _seen_creds.add(key)
        credentials.append(
            {
                "protocol": protocol,
                "src": src,
                "dst": dst,
                "field": field,
                "value": value,
                "detail": detail,
            }
        )

    def _try_decode(data):
        if isinstance(data, bytes):
            return data.decode("utf-8", errors="replace").strip()
        return str(data).strip()

    def _parse_http_auth(payload, src, dst):
        """Extract HTTP Basic/Digest auth, form POST credentials, cookies."""
        try:
            text = payload.decode("latin-1", errors="ignore")
        except Exception:
            return
        # Authorization header (Basic) — uses pre-compiled regex
        auth_match = _RE_HTTP_BASIC.search(text)
        if auth_match:
            try:
                decoded = base64.b64decode(auth_match.group(1)).decode("utf-8", errors="replace")
                if ":" in decoded:
                    user, pw = decoded.split(":", 1)
                    _add_cred("HTTP-Basic", src, dst, "Username", user)
                    _add_cred("HTTP-Basic", src, dst, "Password", pw)
            except Exception:
                pass
        # NTLM in HTTP — uses pre-compiled regex
        ntlm_match = _RE_HTTP_NTLM.search(text)
        if ntlm_match:
            _add_cred("HTTP-NTLM", src, dst, "NTLM Token", ntlm_match.group(1)[:60] + "...", "NTLM auth exchange")
        # Form POST with common credential field names — uses pre-compiled regex
        if text.startswith(("POST ", "post ")):
            body_start = text.find("\r\n\r\n")
            if body_start != -1:
                body = text[body_start + 4 : body_start + 4 + 2000]
                for compiled_re in (_RE_FORM_USER, _RE_FORM_PASS):
                    for m in compiled_re.finditer(body):
                        field_name = m.group(0).split("=", 1)[0]
                        _add_cred("HTTP-POST", src, dst, field_name, m.group(1))
        # Cookie header — uses pre-compiled regex
        cookie_match = _RE_HTTP_COOKIE.search(text)
        if cookie_match:
            cookie_val = cookie_match.group(1).strip()
            if len(cookie_val) > 120:
                cookie_val = cookie_val[:120] + "..."
            _add_cred("HTTP-Cookie", src, dst, "Cookie", cookie_val)
        # Set-Cookie (server response) — uses pre-compiled regex
        set_cookie_match = _RE_HTTP_SET_COOKIE.search(text)
        if set_cookie_match:
            sc_val = set_cookie_match.group(1).strip()
            if len(sc_val) > 120:
                sc_val = sc_val[:120] + "..."
            _add_cred("HTTP-SetCookie", dst, src, "Set-Cookie", sc_val, "Server-issued session cookie")

    def _parse_ftp(line, src, dst, sport, dport):
        """Extract FTP USER/PASS commands."""
        text = _try_decode(line)
        upper = text.upper()
        conn_key = f"{src}:{sport}"
        if upper.startswith("USER "):
            user = text[5:].strip()
            ftp_state[conn_key] = user
            # Evict oldest entries to bound memory usage
            while len(ftp_state) > _FTP_STATE_MAX:
                ftp_state.popitem(last=False)
            _add_cred("FTP", src, dst, "Username", user)
        elif upper.startswith("PASS "):
            pw = text[5:].strip()
            user = ftp_state.get(conn_key, "")
            _add_cred("FTP", src, dst, "Password", pw, f"User: {user}" if user else "")

    def _parse_smtp(line, src, dst):
        """Extract SMTP AUTH credentials."""
        text = _try_decode(line)
        upper = text.upper()
        if upper.startswith("AUTH LOGIN") or upper.startswith("AUTH PLAIN"):
            parts = text.split()
            if len(parts) >= 3 and parts[1].upper() == "PLAIN":
                try:
                    decoded = base64.b64decode(parts[2]).decode("utf-8", errors="replace")
                    # AUTH PLAIN format: \x00user\x00pass
                    pieces = decoded.split("\x00")
                    pieces = [p for p in pieces if p]
                    if len(pieces) >= 2:
                        _add_cred("SMTP", src, dst, "Username", pieces[0])
                        _add_cred("SMTP", src, dst, "Password", pieces[1])
                    elif len(pieces) == 1:
                        _add_cred("SMTP", src, dst, "Auth-Data", pieces[0])
                except Exception:
                    pass
        elif upper.startswith("EHLO ") or upper.startswith("HELO "):
            hostname = text.split(None, 1)[1].strip() if len(text.split(None, 1)) > 1 else ""
            if hostname:
                _add_host(src, hostname=hostname)
                _add_cred("SMTP", src, dst, "EHLO/HELO", hostname, "Client hostname announcement")
        elif upper.startswith("MAIL FROM:"):
            sender = text[10:].strip().strip("<>")
            if sender:
                _add_cred("SMTP", src, dst, "MAIL FROM", sender)

    def _parse_pop3(line, src, dst):
        """Extract POP3 USER/PASS."""
        text = _try_decode(line)
        upper = text.upper()
        if upper.startswith("USER "):
            _add_cred("POP3", src, dst, "Username", text[5:].strip())
        elif upper.startswith("PASS "):
            _add_cred("POP3", src, dst, "Password", text[5:].strip())

    def _parse_imap(line, src, dst):
        """Extract IMAP LOGIN credentials."""
        text = _try_decode(line)
        # IMAP LOGIN: tag LOGIN user pass
        login_match = re.match(r"\S+\s+LOGIN\s+(\S+)\s+(\S+)", text, re.IGNORECASE)
        if login_match:
            _add_cred("IMAP", src, dst, "Username", login_match.group(1).strip('"'))
            _add_cred("IMAP", src, dst, "Password", login_match.group(2).strip('"'))

    def _parse_telnet_line(line, src, dst):
        """Heuristic extraction from telnet-like cleartext sessions."""
        text = _try_decode(line)
        lower = text.lower()
        if "login:" in lower or "username:" in lower:
            # This is a prompt; the actual username comes in a subsequent packet
            _add_cred("Telnet", dst, src, "Login Prompt", text.strip(), "Server login prompt")
        elif "password:" in lower:
            _add_cred("Telnet", dst, src, "Password Prompt", text.strip(), "Server password prompt")

    def _parse_snmp(payload, src, dst):
        """Extract SNMP community strings (v1/v2c)."""
        try:
            # SNMPv1/v2c community string is in a simple ASN.1 structure
            # Sequence -> Integer (version) -> OctetString (community)
            if len(payload) < 10:
                return
            if payload[0] != 0x30:  # ASN.1 SEQUENCE
                return
            idx = 2
            if payload[1] & 0x80:  # long form length
                num_len_bytes = payload[1] & 0x7F
                idx = 2 + num_len_bytes
            # Integer (version)
            if idx >= len(payload) or payload[idx] != 0x02:
                return
            idx += 1
            ver_len = payload[idx]
            idx += 1 + ver_len
            # OctetString (community)
            if idx >= len(payload) or payload[idx] != 0x04:
                return
            idx += 1
            comm_len = payload[idx]
            idx += 1
            if idx + comm_len > len(payload):
                return
            community = payload[idx : idx + comm_len].decode("utf-8", errors="replace")
            if community and community not in ("public", ""):
                _add_cred("SNMP", src, dst, "Community", community)
            elif community == "public":
                _add_cred("SNMP", src, dst, "Community", community, "Default/weak community string")
        except Exception:
            pass

    def _parse_kerberos(payload, src, dst):
        """Basic Kerberos principal extraction from AS-REQ."""
        try:
            # Look for common Kerberos realm/principal patterns in the payload
            text = payload.decode("utf-8", errors="ignore")
            # Kerberos principals often appear as name@REALM
            krb_match = re.findall(r"([a-zA-Z0-9_.+-]+@[A-Z0-9.\-]+)", text)
            for principal in krb_match[:3]:
                _add_cred("Kerberos", src, dst, "Principal", principal)
        except Exception:
            pass

    def _check_dhcp_hostname(payload, src, mac):
        """Extract hostname from DHCP options."""
        try:
            if len(payload) < 240:
                return
            # DHCP magic cookie at offset 236
            if payload[236:240] != b"\x63\x82\x53\x63":
                return
            idx = 240
            while idx < len(payload) - 1:
                opt_type = payload[idx]
                if opt_type == 0xFF:  # End
                    break
                if opt_type == 0:  # Padding
                    idx += 1
                    continue
                opt_len = payload[idx + 1]
                opt_data = payload[idx + 2 : idx + 2 + opt_len]
                if opt_type == 12:  # Hostname option
                    hostname = opt_data.decode("utf-8", errors="replace").strip()
                    if hostname:
                        _add_host(src if src != "0.0.0.0" else "DHCP-client", mac=mac, hostname=hostname)  # nosec B104 - comparing string, not binding
                idx += 2 + opt_len
        except Exception:
            pass

    try:
        if use_high_memory:
            try:
                with open(resolved_path, "rb") as handle:
                    pcap_bytes = handle.read()
                reader = PcapReader(io.BytesIO(pcap_bytes))
            except Exception:
                reader = PcapReader(resolved_path)
        else:
            reader = PcapReader(resolved_path)

        with reader as pcap:
            for pkt in pcap:
                # Extract MAC addresses from Ethernet layer
                if Ether is not None and pkt.haslayer(Ether):
                    ether = pkt.getlayer(Ether)
                    src_mac = ether.src
                    dst_mac = ether.dst
                else:
                    src_mac = None
                    dst_mac = None

                ip_layer = pkt.getlayer(IP)
                if ip_layer is None:
                    # Check for DHCP on non-IP (rare but possible)
                    continue

                src_ip = ip_layer.src
                dst_ip = ip_layer.dst

                # Record MAC -> IP mapping
                if src_mac:
                    _add_host(src_ip, mac=src_mac)
                if dst_mac:
                    _add_host(dst_ip, mac=dst_mac)

                tcp_layer = pkt.getlayer(TCP)
                udp_layer = pkt.getlayer(UDP) if tcp_layer is None else None
                raw_layer = pkt.getlayer(Raw)
                payload = bytes(raw_layer.load) if raw_layer and raw_layer.load else b""

                if tcp_layer is not None:
                    sport = int(tcp_layer.sport)
                    dport = int(tcp_layer.dport)

                    if payload:
                        # FTP (ports 21, 2121)
                        if dport in (21, 2121) or sport in (21, 2121):
                            for line in payload.split(b"\r\n"):
                                if line:
                                    _parse_ftp(line, src_ip, dst_ip, sport, dport)

                        # SMTP (ports 25, 465, 587)
                        elif dport in (25, 465, 587) or sport in (25, 465, 587):
                            for line in payload.split(b"\r\n"):
                                if line:
                                    _parse_smtp(line, src_ip, dst_ip)

                        # POP3 (port 110, 995)
                        elif dport in (110, 995) or sport in (110, 995):
                            for line in payload.split(b"\r\n"):
                                if line:
                                    _parse_pop3(line, src_ip, dst_ip)

                        # IMAP (port 143, 993)
                        elif dport in (143, 993) or sport in (143, 993):
                            for line in payload.split(b"\r\n"):
                                if line:
                                    _parse_imap(line, src_ip, dst_ip)

                        # Telnet (port 23)
                        elif dport == 23 or sport == 23:
                            for line in payload.split(b"\r\n"):
                                if line:
                                    _parse_telnet_line(line, src_ip, dst_ip)

                        # HTTP (ports 80, 8080, 8000, 8888)
                        elif dport in (80, 8080, 8000, 8888) or sport in (80, 8080, 8000, 8888):
                            _parse_http_auth(payload, src_ip, dst_ip)

                        # Kerberos (port 88)
                        elif dport == 88 or sport == 88:
                            _parse_kerberos(payload, src_ip, dst_ip)

                elif udp_layer is not None:
                    sport = int(udp_layer.sport)
                    dport = int(udp_layer.dport)

                    if payload:
                        # SNMP (port 161, 162)
                        if dport in (161, 162) or sport in (161, 162):
                            _parse_snmp(payload, src_ip, dst_ip)

                        # DHCP hostname extraction (ports 67, 68)
                        elif dport in (67, 68) or sport in (67, 68):
                            _check_dhcp_hostname(payload, src_ip, src_mac)

                        # Kerberos UDP
                        elif dport == 88 or sport == 88:
                            _parse_kerberos(payload, src_ip, dst_ip)

                # DNS hostname extraction (PTR records, etc.) — already parsed elsewhere
                dns_layer = pkt.getlayer(DNS)
                if dns_layer is not None:
                    try:
                        qd = dns_layer.qd
                        if isinstance(qd, DNSQR):
                            qname = qd.qname
                        elif qd:
                            qname = qd[0].qname
                        else:
                            qname = b""
                        if isinstance(qname, bytes):
                            dn = qname.decode("utf-8", errors="ignore").rstrip(".")
                        elif qname:
                            dn = str(qname).rstrip(".")
                        else:
                            dn = ""
                        if dn:
                            _add_host(dst_ip, hostname=dn)
                    except Exception:
                        pass

                if len(credentials) >= MAX_CREDS:
                    break

    finally:
        cleanup()

    # Convert sets to sorted lists for JSON-friendliness
    hosts_out = {}
    for ip, info in hosts.items():
        hosts_out[ip] = {
            "mac": sorted(info["mac"]),
            "hostnames": sorted(info["hostnames"]),
        }

    return {"credentials": credentials, "hosts": hosts_out}


def _maybe_reservoir_append(items, item, limit, seen_count):
    if limit <= 0:
        return
    if len(items) < limit:
        items.append(item)
        return
    j = random.randint(1, seen_count)
    if j <= limit:
        items[j - 1] = item


def _resolve_pcap_source(file_path, progress_cb=None):
    """Get the PCAP file path and size."""

    def cleanup():
        return None

    try:
        file_size = os.path.getsize(file_path)
    except OSError:
        file_size = 0
    return file_path, cleanup, file_size


def parse_pcap_path(
    file_path, max_rows=DEFAULT_MAX_ROWS, parse_http=True, progress_cb=None, use_high_memory=False, cancel_event=None
):
    DNS, DNSQR, IP, PcapReader, Raw, TCP, UDP = _get_scapy()
    tls_support = _get_tls_support()
    pd = _get_pandas()
    rows = []
    size_samples = []
    should_sample_rows = max_rows > 0
    resolved_path, cleanup, file_size = _resolve_pcap_source(file_path, progress_cb)
    start_time = _utcnow()
    last_progress_time = start_time
    # Scale progress check interval based on file size
    if file_size and file_size > 100_000_000:
        update_every = 5000
    elif file_size and file_size > 10_000_000:
        update_every = 2000
    else:
        update_every = 500

    # Use local variables for hot path
    packet_count = 0
    sum_size = 0
    dns_query_count = 0
    http_request_count = 0
    tls_packet_count = 0
    ioc_truncated = False

    proto_counts = Counter()
    port_counts = Counter()
    unique_src = set()
    unique_dst = set()
    dns_counter = Counter()
    dns_queries_set = set()
    http_hosts_set = set()
    unique_http_hosts = set()
    tls_sni_counter = Counter()
    tls_sni_set = set()

    if progress_cb and file_size:
        progress_cb(0.0, None, 0, file_size)

    try:
        if use_high_memory:
            try:
                with open(resolved_path, "rb") as handle:
                    pcap_bytes = handle.read()
                pcap_source = io.BytesIO(pcap_bytes)
                reader = PcapReader(pcap_source)
            except Exception:
                reader = PcapReader(resolved_path)
        else:
            reader = PcapReader(resolved_path)

        with reader as pcap:
            for pkt in pcap:
                ip_layer = pkt.getlayer(IP)
                if ip_layer is None:
                    continue

                packet_count += 1
                pkt_size = len(pkt)
                sum_size += pkt_size
                _maybe_reservoir_append(size_samples, pkt_size, SIZE_SAMPLE_LIMIT, packet_count)

                # Get transport layer once
                tcp_layer = pkt.getlayer(TCP)
                if tcp_layer is not None:
                    proto = "TCP"
                    sport = int(tcp_layer.sport)
                    dport = int(tcp_layer.dport)
                    udp_layer = None
                else:
                    udp_layer = pkt.getlayer(UDP)
                    if udp_layer is not None:
                        proto = "UDP"
                        sport = int(udp_layer.sport)
                        dport = int(udp_layer.dport)
                    else:
                        proto = "Other"
                        sport = 0
                        dport = 0

                proto_counts[proto] += 1
                if dport:
                    port_counts[dport] += 1

                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                unique_src.add(src_ip)
                unique_dst.add(dst_ip)

                # DNS parsing
                dns_query = ""
                dns_layer = pkt.getlayer(DNS)
                if dns_layer is not None:
                    try:
                        qd = dns_layer.qd
                        if isinstance(qd, DNSQR):
                            qname = qd.qname
                        elif qd:
                            qname = qd[0].qname
                        else:
                            qname = b""
                        if isinstance(qname, bytes):
                            dns_query = qname.decode("utf-8", errors="ignore").rstrip(".")
                        elif qname:
                            dns_query = str(qname).rstrip(".")
                    except Exception:
                        dns_query = ""

                if dns_query:
                    dns_query_count += 1
                    dns_counter[dns_query] += 1
                    if len(dns_queries_set) < IOC_SET_LIMIT:
                        dns_queries_set.add(dns_query)
                    elif dns_query not in dns_queries_set:
                        ioc_truncated = True

                # HTTP parsing - only if TCP and parse_http enabled
                http_host = ""
                http_path = ""
                http_method = ""
                if parse_http and tcp_layer is not None:
                    raw_layer = pkt.getlayer(Raw)
                    if raw_layer is not None and raw_layer.load:
                        http_host, http_path, http_method = parse_http_payload(bytes(raw_layer.load))

                tls_sni = ""
                tls_version = ""
                tls_alpn = ""
                if tcp_layer is not None:
                    tls_sni, tls_version, tls_alpn = _extract_tls_metadata(pkt, tls_support)
                if tls_sni or tls_version or tls_alpn:
                    tls_packet_count += 1
                if tls_sni:
                    tls_sni_counter[tls_sni] += 1
                    if len(tls_sni_set) < IOC_SET_LIMIT:
                        tls_sni_set.add(tls_sni)
                    elif tls_sni not in tls_sni_set:
                        ioc_truncated = True

                if http_host:
                    http_request_count += 1
                    unique_http_hosts.add(http_host)
                    if len(http_hosts_set) < IOC_SET_LIMIT:
                        http_hosts_set.add(http_host)
                    elif http_host not in http_hosts_set:
                        ioc_truncated = True

                # Reservoir sampling for rows
                if should_sample_rows:
                    row = {
                        "Time": float(pkt.time),
                        "Size": pkt_size,
                        "Proto": proto,
                        "Src": src_ip,
                        "Dst": dst_ip,
                        "SPort": sport,
                        "DPort": dport,
                        "DnsQuery": dns_query,
                        "HttpHost": http_host,
                        "HttpPath": http_path,
                        "HttpMethod": http_method,
                        "TlsSni": tls_sni,
                        "TlsVersion": tls_version,
                        "TlsAlpn": tls_alpn,
                    }
                    _maybe_reservoir_append(rows, row, max_rows, packet_count)

                # Progress updates
                if packet_count % update_every == 0:
                    now = _utcnow()
                    if (now - last_progress_time).total_seconds() >= 0.2:
                        elapsed = (now - start_time).total_seconds()
                        avg_size = sum_size / packet_count
                        if file_size:
                            progress = min(99.0, (sum_size / file_size) * 100.0)
                            est_total = file_size / avg_size
                            rate = packet_count / elapsed if elapsed > 0 else 0.0
                            eta = ((est_total - packet_count) / rate) if rate > 0 else None
                        else:
                            progress = None
                            eta = None

                        progress_cb(progress, eta, sum_size, file_size)
                        last_progress_time = now
                # Fast cancellation check (every 200 packets)
                elif cancel_event is not None and packet_count % 200 == 0 and cancel_event.is_set():
                    raise AnalysisCancelledError("Analysis cancelled by user.")
    finally:
        cleanup()

    # Build final stats
    avg_size = sum_size / packet_count if packet_count else 0.0
    median_size = float(statistics.median(size_samples)) if size_samples else 0.0
    top_ports = port_counts.most_common(5)

    final_stats = {
        "packet_count": int(packet_count),
        "avg_size": float(avg_size),
        "median_size": float(median_size),
        "protocol_counts": {k: int(v) for k, v in proto_counts.most_common()},
        "top_ports": [(int(p), int(c)) for p, c in top_ports],
        "unique_src": len(unique_src),
        "unique_dst": len(unique_dst),
        "dns_query_count": int(dns_query_count),
        "http_request_count": int(http_request_count),
        "unique_http_hosts": len(unique_http_hosts),
        "tls_packet_count": int(tls_packet_count),
        "unique_tls_sni": len(tls_sni_set),
        "top_dns": dns_counter.most_common(5),
        "top_tls_sni": tls_sni_counter.most_common(5),
        "unique_src_list": sorted(unique_src),
        "unique_dst_list": sorted(unique_dst),
        "dns_queries": sorted(dns_queries_set),
        "http_hosts": sorted(http_hosts_set),
        "tls_sni": sorted(tls_sni_set),
        "ioc_truncated": bool(ioc_truncated),
    }
    sample_info = {
        "sample_count": len(rows),
        "total_count": packet_count,
    }
    if progress_cb:
        progress_cb(100.0, 0, sum_size, file_size)
    return pd.DataFrame(rows), final_stats, sample_info


def _fast_parse_pcap_path(
    file_path, max_rows=DEFAULT_MAX_ROWS, parse_http=True, progress_cb=None, use_high_memory=False, cancel_event=None
):
    """Fast pcap parser using raw byte-level header parsing.

    Avoids full Scapy dissection on every packet.  Only creates Scapy ``IP()``
    objects for the small fraction of packets that need deep inspection (DNS,
    TLS ClientHello).  Typically 5-15x faster than *parse_pcap_path* for large
    captures (>50 MB).
    """
    DNS, DNSQR, IP, _PcapReader, _Raw, _TCP, _UDP = _get_scapy()
    # Note: Using PcapReader for both .pcap and .pcapng (more reliable than RawPcapNgReader)

    tls_support = _get_tls_support()
    pd = _get_pandas()

    rows = []
    size_samples = []
    should_sample_rows = max_rows > 0
    resolved_path, cleanup, file_size = _resolve_pcap_source(file_path, progress_cb)
    start_time = _utcnow()
    last_progress_time = start_time

    # Larger update interval for speed – checked every N packets
    update_every = 5000

    packet_count = 0
    sum_size = 0
    dns_query_count = 0
    http_request_count = 0
    tls_packet_count = 0
    ioc_truncated = False

    proto_counts = Counter()
    port_counts = Counter()
    unique_src = set()
    unique_dst = set()
    dns_counter = Counter()
    dns_queries_set = set()
    http_hosts_set = set()
    unique_http_hosts = set()
    tls_sni_counter = Counter()
    tls_sni_set = set()

    # Pre-bind for speed
    _unpack_HH = struct.Struct("!HH").unpack_from
    _unpack_H = struct.Struct("!H").unpack_from

    DNS_PORTS = frozenset({53, 5353, 5355})

    if progress_cb and file_size:
        progress_cb(0.0, None, 0, file_size)

    try:
        # Use PcapReader which handles both .pcap and .pcapng formats
        # Extract raw bytes for fast parsing (RawPcapNgReader can freeze on some files)
        reader = _PcapReader(resolved_path)
        linktype = 1  # Assume Ethernet (most common)

        with reader:
            for pkt in reader:
                # Get raw bytes from packet (pkt.original is already bytes)
                if hasattr(pkt, "original") and pkt.original:
                    raw_data = pkt.original
                else:
                    raw_data = bytes(pkt)

                data_len = len(raw_data)

                # ── Determine IP start offset based on link type ──
                if linktype == 1:  # Ethernet
                    if data_len < 34:
                        continue
                    eth_type = _unpack_H(raw_data, 12)[0]
                    if eth_type == 0x8100:  # 802.1Q VLAN
                        if data_len < 38:
                            continue
                        eth_type = _unpack_H(raw_data, 16)[0]
                        ip_start = 18
                    else:
                        ip_start = 14
                    if eth_type != 0x0800:  # Not IPv4
                        continue
                elif linktype == 101:  # Raw IP
                    ip_start = 0
                elif linktype == 113:  # Linux cooked capture
                    ip_start = 16
                else:
                    ip_start = 14  # fallback

                if data_len < ip_start + 20:
                    continue

                # ── Parse IP header ──
                ip_b0 = raw_data[ip_start]
                if (ip_b0 >> 4) != 4:  # Not IPv4
                    continue
                ip_ihl = (ip_b0 & 0x0F) * 4
                if ip_ihl < 20 or data_len < ip_start + ip_ihl:
                    continue

                packet_count += 1
                pkt_size = data_len
                sum_size += pkt_size
                _maybe_reservoir_append(size_samples, pkt_size, SIZE_SAMPLE_LIMIT, packet_count)

                ip_proto = raw_data[ip_start + 9]
                sb = raw_data[ip_start + 12 : ip_start + 16]
                db = raw_data[ip_start + 16 : ip_start + 20]
                src_ip = f"{sb[0]}.{sb[1]}.{sb[2]}.{sb[3]}"
                dst_ip = f"{db[0]}.{db[1]}.{db[2]}.{db[3]}"
                unique_src.add(src_ip)
                unique_dst.add(dst_ip)

                transport_start = ip_start + ip_ihl

                # ── Parse transport header ──
                if ip_proto == 6:  # TCP
                    proto = "TCP"
                    if data_len >= transport_start + 4:
                        sport, dport = _unpack_HH(raw_data, transport_start)
                    else:
                        sport = dport = 0
                elif ip_proto == 17:  # UDP
                    proto = "UDP"
                    if data_len >= transport_start + 4:
                        sport, dport = _unpack_HH(raw_data, transport_start)
                    else:
                        sport = dport = 0
                else:
                    proto = "Other"
                    sport = dport = 0

                proto_counts[proto] += 1
                if dport:
                    port_counts[dport] += 1

                # ── Deep inspection: DNS, HTTP, TLS ──
                dns_query = ""
                http_host = ""
                http_path = ""
                http_method = ""
                tls_sni = ""
                tls_version = ""
                tls_alpn = ""

                # -- DNS (use Scapy for reliable parsing) --
                if dport in DNS_PORTS or sport in DNS_PORTS:
                    try:
                        pkt_obj = IP(bytes(raw_data[ip_start:]))
                        dns_layer = pkt_obj.getlayer(DNS)
                        if dns_layer is not None:
                            qd = dns_layer.qd
                            if isinstance(qd, DNSQR):
                                qname = qd.qname
                            elif qd:
                                qname = qd[0].qname
                            else:
                                qname = b""
                            if isinstance(qname, bytes):
                                dns_query = qname.decode("utf-8", errors="ignore").rstrip(".")
                            elif qname:
                                dns_query = str(qname).rstrip(".")
                    except Exception:
                        pass

                # -- Compute TCP data offset once for HTTP + TLS --
                tcp_data_offset = None
                if ip_proto == 6 and data_len > transport_start + 12:
                    tcp_data_offset = (raw_data[transport_start + 12] >> 4) * 4

                # -- HTTP (parse directly from raw bytes – no Scapy needed) --
                if parse_http and tcp_data_offset is not None and data_len >= transport_start + 14:
                    payload_start = transport_start + tcp_data_offset
                    if data_len > payload_start + 14:
                        http_host, http_path, http_method = parse_http_payload(
                            bytes(raw_data[payload_start : payload_start + 2048])
                        )

                # -- TLS (only inspect likely TLS handshake packets) --
                if tcp_data_offset is not None and tls_support[0] is not None:
                    payload_start = transport_start + tcp_data_offset
                    if data_len > payload_start + 5:
                        content_type = raw_data[payload_start]
                        if content_type == 0x16:  # TLS Handshake
                            try:
                                pkt_obj = IP(bytes(raw_data[ip_start:]))
                                tls_sni, tls_version, tls_alpn = _extract_tls_metadata(pkt_obj, tls_support)
                            except Exception:
                                pass

                # ── Collect stats ──
                if dns_query:
                    dns_query_count += 1
                    dns_counter[dns_query] += 1
                    if len(dns_queries_set) < IOC_SET_LIMIT:
                        dns_queries_set.add(dns_query)
                    elif dns_query not in dns_queries_set:
                        ioc_truncated = True

                if tls_sni or tls_version or tls_alpn:
                    tls_packet_count += 1
                if tls_sni:
                    tls_sni_counter[tls_sni] += 1
                    if len(tls_sni_set) < IOC_SET_LIMIT:
                        tls_sni_set.add(tls_sni)
                    elif tls_sni not in tls_sni_set:
                        ioc_truncated = True

                if http_host:
                    http_request_count += 1
                    unique_http_hosts.add(http_host)
                    if len(http_hosts_set) < IOC_SET_LIMIT:
                        http_hosts_set.add(http_host)
                    elif http_host not in http_hosts_set:
                        ioc_truncated = True

                # ── Reservoir sampling ──
                if should_sample_rows:
                    # Extract timestamp from packet (PcapReader provides pkt.time)
                    if hasattr(pkt, "time") and pkt.time:
                        ts = float(pkt.time)
                    else:
                        # Fallback - use packet count as pseudo-timestamp
                        ts = float(packet_count)

                    row = {
                        "Time": ts,
                        "Size": pkt_size,
                        "Proto": proto,
                        "Src": src_ip,
                        "Dst": dst_ip,
                        "SPort": sport,
                        "DPort": dport,
                        "DnsQuery": dns_query,
                        "HttpHost": http_host,
                        "HttpPath": http_path,
                        "HttpMethod": http_method,
                        "TlsSni": tls_sni,
                        "TlsVersion": tls_version,
                        "TlsAlpn": tls_alpn,
                    }
                    _maybe_reservoir_append(rows, row, max_rows, packet_count)

                # ── Progress / cancel ──
                if packet_count % update_every == 0:
                    if progress_cb:
                        now = _utcnow()
                        if (now - last_progress_time).total_seconds() >= 0.15:
                            elapsed = (now - start_time).total_seconds()
                            avg_sz = sum_size / packet_count
                            if file_size:
                                progress = min(99.0, (sum_size / file_size) * 100.0)
                                est_total = file_size / avg_sz
                                rate = packet_count / elapsed if elapsed > 0 else 0.0
                                eta = ((est_total - packet_count) / rate) if rate > 0 else None
                            else:
                                progress = None
                                eta = None
                            progress_cb(progress, eta, sum_size, file_size)
                            last_progress_time = now
                # Fast cancellation check (every 200 packets)
                elif cancel_event is not None and packet_count % 200 == 0 and cancel_event.is_set():
                    raise AnalysisCancelledError("Analysis cancelled by user.")
    finally:
        cleanup()

    # ── Build final stats (same structure as parse_pcap_path) ──
    avg_size = sum_size / packet_count if packet_count else 0.0
    median_size = float(statistics.median(size_samples)) if size_samples else 0.0
    top_ports = port_counts.most_common(5)

    final_stats = {
        "packet_count": int(packet_count),
        "avg_size": float(avg_size),
        "median_size": float(median_size),
        "protocol_counts": {k: int(v) for k, v in proto_counts.most_common()},
        "top_ports": [(int(p), int(c)) for p, c in top_ports],
        "unique_src": len(unique_src),
        "unique_dst": len(unique_dst),
        "dns_query_count": int(dns_query_count),
        "http_request_count": int(http_request_count),
        "unique_http_hosts": len(unique_http_hosts),
        "tls_packet_count": int(tls_packet_count),
        "unique_tls_sni": len(tls_sni_set),
        "top_dns": dns_counter.most_common(5),
        "top_tls_sni": tls_sni_counter.most_common(5),
        "unique_src_list": sorted(unique_src),
        "unique_dst_list": sorted(unique_dst),
        "dns_queries": sorted(dns_queries_set),
        "http_hosts": sorted(http_hosts_set),
        "tls_sni": sorted(tls_sni_set),
        "ioc_truncated": bool(ioc_truncated),
    }
    sample_info = {
        "sample_count": len(rows),
        "total_count": packet_count,
    }
    if progress_cb:
        progress_cb(100.0, 0, sum_size, file_size)
    return pd.DataFrame(rows), final_stats, sample_info


def add_to_knowledge_base(label, stats, features, summary):
    kb = load_knowledge_base()
    entry = {
        "label": label,
        "stats": stats,
        "features": features,
        "summary": summary,
        "timestamp": _utcnow().isoformat().replace("+00:00", "Z"),
    }
    kb[label].append(entry)
    save_knowledge_base(kb)


def compute_flow_stats(df):
    pd = _get_pandas()
    if df.empty:
        return pd.DataFrame(columns=["Flow", "Packets", "Bytes", "Duration"])
    flow_cols = ["Src", "Dst", "Proto", "SPort", "DPort"]
    grouped = df.groupby(flow_cols, dropna=False)
    flow_df = grouped.agg(
        Packets=("Size", "count"),
        Bytes=("Size", "sum"),
        TimeMin=("Time", "min"),
        TimeMax=("Time", "max"),
    ).reset_index()
    flow_df["Duration"] = (flow_df["TimeMax"] - flow_df["TimeMin"]).astype(float)
    flow_df.drop(columns=["TimeMin", "TimeMax"], inplace=True)
    flow_df["Flow"] = (
        flow_df["Src"]
        + ":"
        + flow_df["SPort"].astype(str)
        + " -> "
        + flow_df["Dst"]
        + ":"
        + flow_df["DPort"].astype(str)
        + " ("
        + flow_df["Proto"]
        + ")"
    )
    return flow_df.sort_values("Bytes", ascending=False)


def detect_suspicious_flows(df, kb, max_items=8, flow_df=None):
    if df.empty:
        return []
    _get_pandas()
    if flow_df is None:
        flow_df = compute_flow_stats(df)  # already returns a new DataFrame
    else:
        flow_df = flow_df.copy()  # caller's DF — copy before mutating
    ioc_ips = set(kb.get("ioc", {}).get("ips", []))
    if ioc_ips:
        flow_df["ioc_match"] = flow_df["Src"].isin(ioc_ips) | flow_df["Dst"].isin(ioc_ips)
    else:
        flow_df["ioc_match"] = False

    if not flow_df["Bytes"].empty:
        high_bytes_threshold = float(flow_df["Bytes"].quantile(0.95))
    else:
        high_bytes_threshold = 0.0
    flow_df["high_volume"] = flow_df["Bytes"] >= high_bytes_threshold if high_bytes_threshold > 0 else False

    # Flag flows using known malware / C2 ports
    flow_df["malware_port"] = flow_df["DPort"].isin(MALWARE_PORTS) | flow_df["SPort"].isin(MALWARE_PORTS)

    # Flag flows with very high packet counts but low byte volume (possible beaconing)
    if not flow_df["Packets"].empty and len(flow_df) > 1:
        high_pkt_threshold = float(flow_df["Packets"].quantile(0.95))
        median_bytes = float(flow_df["Bytes"].median()) if not flow_df["Bytes"].empty else 0.0
        flow_df["beacon_like"] = (flow_df["Packets"] >= max(high_pkt_threshold, 6)) & (
            flow_df["Bytes"] < median_bytes * 2
        )
    else:
        flow_df["beacon_like"] = False

    suspicious = flow_df[
        flow_df["ioc_match"] | flow_df["high_volume"] | flow_df["malware_port"] | flow_df["beacon_like"]
    ]
    if suspicious.empty:
        return []

    suspicious = suspicious.sort_values(["ioc_match", "malware_port", "Bytes"], ascending=[False, False, False])
    results = []
    for _, row in suspicious.head(max_items).iterrows():
        reasons = []
        if bool(row["ioc_match"]):
            reasons.append("IoC IP match")
        if bool(row["malware_port"]):
            dport_val = int(row["DPort"])
            sport_val = int(row["SPort"])
            port_str = str(dport_val) if dport_val in MALWARE_PORTS else str(sport_val)
            reasons.append(f"Malware/C2 port ({port_str})")
        if bool(row.get("beacon_like", False)):
            reasons.append("Beacon-like pattern")
        if bool(row["high_volume"]):
            reasons.append("High volume")
        results.append(
            {
                "flow": row["Flow"],
                "bytes": _format_bytes(row["Bytes"]),
                "packets": int(row["Packets"]),
                "reason": "; ".join(reasons),
                "src": row["Src"],
                "dst": row["Dst"],
                "proto": row["Proto"],
                "sport": int(row["SPort"]),
                "dport": int(row["DPort"]),
            }
        )
    return results


def detect_behavioral_anomalies(df, stats, flow_df=None):
    """Run heuristic checks for common malware traffic patterns.

    Returns a list of dicts: [{\"type\": str, \"detail\": str, \"severity\": int (0-100)}]
    Each finding also carries a *risk_boost* that gets added to the overall risk score.
    """
    findings = []
    if df.empty:
        return findings

    _get_pandas()
    pkt_count = stats.get("packet_count", 0) or 1

    # ── 1. DNS Tunneling: very high DNS-to-packet ratio or long query names ──
    dns_count = stats.get("dns_query_count", 0)
    dns_ratio = dns_count / pkt_count
    if dns_ratio > 0.4 and dns_count > 50:
        findings.append(
            {
                "type": "dns_tunneling",
                "detail": f"DNS queries make up {dns_ratio:.0%} of packets ({dns_count} queries) — possible DNS tunneling",
                "severity": 70,
                "risk_boost": 20,
            }
        )
    dns_queries = stats.get("dns_queries", [])
    long_names = [q for q in dns_queries if len(q) > 60]
    if long_names:
        findings.append(
            {
                "type": "dns_long_names",
                "detail": f"{len(long_names)} DNS queries with names >60 chars — possible DNS exfiltration",
                "severity": 65,
                "risk_boost": 15,
            }
        )

    # ── 2. Beaconing detection via inter-arrival-time regularity ──
    if flow_df is None:
        flow_df = compute_flow_stats(df)
    if not flow_df.empty:
        # Reuse flow_df instead of re-grouping the entire DataFrame (P1 fix).
        # Only examine flows with enough packets to detect regularity.
        candidate_flows = flow_df[flow_df["Packets"] >= 8]
        beacons = []
        if not candidate_flows.empty:
            flow_cols = ["Src", "Dst", "Proto", "SPort", "DPort"]
            # Only re-group the subset of flows that passed the packet threshold
            flow_keys_set = set()
            for _, row in candidate_flows.iterrows():
                flow_keys_set.add(tuple(row[col] for col in flow_cols))
            # Filter df to only rows belonging to candidate flows before grouping
            if len(flow_keys_set) < len(df) * 0.5:  # Only filter when it saves work
                mask = df.set_index(flow_cols).index.isin(flow_keys_set)
                subset = df[mask]
            else:
                subset = df
            grouped = subset.groupby(flow_cols, dropna=False)
            for keys, group in grouped:
                if len(group) < 8:
                    continue
                times = group["Time"].sort_values().to_list()
                gaps = [b - a for a, b in itertools.pairwise(times) if b - a > 0]
                if len(gaps) < 6:
                    continue
                avg_gap = sum(gaps) / len(gaps)
                if avg_gap <= 0 or avg_gap > 3600:
                    continue
                std_gap = statistics.pstdev(gaps)
                cv = std_gap / avg_gap
                if cv < 0.25:  # very regular
                    flow_str = f"{keys[0]}:{keys[3]} -> {keys[1]}:{keys[4]} ({keys[2]})"
                    beacons.append((flow_str, avg_gap, len(group)))
        if beacons:
            beacons.sort(key=lambda x: x[2], reverse=True)
            top = beacons[0]
            findings.append(
                {
                    "type": "beaconing",
                    "detail": f"Regular callback pattern: {top[0]} — ~{top[1]:.1f}s interval, {top[2]} packets",
                    "severity": 75,
                    "risk_boost": 20,
                }
            )

    # ── 3. Port scanning: single source hitting many distinct destination ports ──
    if not df.empty and "DPort" in df.columns:
        src_port_counts = df.groupby("Src")["DPort"].nunique()
        scanners = src_port_counts[src_port_counts >= 20]
        if not scanners.empty:
            top_scanner = scanners.idxmax()
            n_ports = int(scanners.max())
            findings.append(
                {
                    "type": "port_scan",
                    "detail": f"{top_scanner} contacted {n_ports} distinct destination ports — possible port scan",
                    "severity": 60,
                    "risk_boost": 15,
                }
            )

    # ── 4. Known malware ports in heavy use ──
    top_ports = stats.get("top_ports", [])
    malware_hits = [(p, c) for p, c in top_ports if p in MALWARE_PORTS]
    if malware_hits:
        port_str = ", ".join(f"{p} ({c} pkts)" for p, c in malware_hits)
        findings.append(
            {
                "type": "malware_ports",
                "detail": f"Known malware/C2 ports in top traffic: {port_str}",
                "severity": 65,
                "risk_boost": 15,
            }
        )

    # ── 5. Data exfiltration: highly asymmetric upload (one host sends much more than receives) ──
    if not df.empty and len(df) > 20:
        src_bytes = df.groupby("Src")["Size"].sum()
        dst_bytes = df.groupby("Dst")["Size"].sum()
        for src_ip in src_bytes.index:
            sent = float(src_bytes.get(src_ip, 0))
            received = float(dst_bytes.get(src_ip, 0))
            if sent > 1_000_000 and received > 0 and sent / max(received, 1) > 10:
                findings.append(
                    {
                        "type": "data_exfil",
                        "detail": f"{src_ip} sent {_format_bytes(sent)} but received only {_format_bytes(received)} — possible data exfiltration",
                        "severity": 70,
                        "risk_boost": 15,
                    }
                )
                break  # only report the worst offender

    # ── 6. Excessive failed connections (many small SYN-only packets to same dest) ──
    if not df.empty and "Proto" in df.columns:
        tcp_df = df[df["Proto"] == "TCP"]
        if len(tcp_df) > 10:
            small_tcp = tcp_df[tcp_df["Size"] <= 80]
            if len(small_tcp) > len(tcp_df) * 0.5 and len(small_tcp) > 50:
                findings.append(
                    {
                        "type": "syn_flood",
                        "detail": f"{len(small_tcp)} of {len(tcp_df)} TCP packets are ≤80 bytes — possible SYN flood or scan",
                        "severity": 55,
                        "risk_boost": 10,
                    }
                )

    return findings


def _empty_figure(message):
    Figure = _get_figure()
    fig = Figure(figsize=(6, 4), dpi=100)
    ax = fig.add_subplot(111)
    ax.text(0.5, 0.5, message, ha="center", va="center")
    ax.set_axis_off()
    return fig


def _plot_scatter(df):
    if df.empty:
        return _empty_figure("No data")
    Figure = _get_figure()
    fig = Figure(figsize=(7, 4), dpi=100)
    ax = fig.add_subplot(111)
    time_base = df["Time"].min()
    colors = {"TCP": "tab:blue", "UDP": "tab:orange", "Other": "tab:green"}
    for proto, group in df.groupby("Proto"):
        ax.scatter(group["Time"] - time_base, group["Size"], s=6, alpha=0.6, label=proto, c=colors.get(proto))
    ax.set_title("Traffic Spikes")
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Packet Size")
    ax.legend(loc="best")
    return fig


def _plot_port_hist(df):
    if df.empty:
        return _empty_figure("No data")
    Figure = _get_figure()
    fig = Figure(figsize=(7, 4), dpi=100)
    ax = fig.add_subplot(111)
    for proto, group in df.groupby("Proto"):
        values = group["DPort"]
        values = values[values > 0]
        if not values.empty:
            ax.hist(values, bins=50, alpha=0.5, label=proto)
    ax.set_title("Common Destination Ports")
    ax.set_xlabel("DPort")
    ax.set_ylabel("Count")
    ax.legend(loc="best")
    return fig


def _plot_proto_pie(df):
    if df.empty:
        return _empty_figure("No data")
    Figure = _get_figure()
    fig = Figure(figsize=(6, 4), dpi=100)
    ax = fig.add_subplot(111)
    counts = df["Proto"].value_counts()
    ax.pie(counts.values, labels=counts.index, autopct="%1.1f%%")
    ax.set_title("Protocol Share")
    return fig


def _plot_top_dns(df):
    dns_queries = [q for q in df["DnsQuery"] if q]
    if not dns_queries:
        return _empty_figure("No DNS queries")
    Figure = _get_figure()
    fig = Figure(figsize=(7, 4), dpi=100)
    ax = fig.add_subplot(111)
    top_dns = Counter(dns_queries).most_common(10)
    labels = [q for q, _ in top_dns]
    values = [c for _, c in top_dns]
    ax.bar(labels, values)
    ax.set_title("DNS Query Frequency")
    ax.set_ylabel("Count")
    ax.tick_params(axis="x", rotation=45)
    return fig


def _plot_top_http(df):
    http_hosts = [h for h in df["HttpHost"] if h]
    if not http_hosts:
        return _empty_figure("No HTTP hosts")
    Figure = _get_figure()
    fig = Figure(figsize=(7, 4), dpi=100)
    ax = fig.add_subplot(111)
    top_hosts = Counter(http_hosts).most_common(10)
    labels = [h for h, _ in top_hosts]
    values = [c for _, c in top_hosts]
    ax.bar(labels, values)
    ax.set_title("HTTP Host Frequency")
    ax.set_ylabel("Count")
    ax.tick_params(axis="x", rotation=45)
    return fig


def _plot_top_tls_sni(df):
    tls_sni = [s for s in df["TlsSni"] if s]
    if not tls_sni:
        return _empty_figure("No TLS SNI")
    Figure = _get_figure()
    fig = Figure(figsize=(7, 4), dpi=100)
    ax = fig.add_subplot(111)
    top_sni = Counter(tls_sni).most_common(10)
    labels = [s for s, _ in top_sni]
    values = [c for _, c in top_sni]
    ax.bar(labels, values)
    ax.set_title("TLS SNI Frequency")
    ax.set_ylabel("Count")
    ax.tick_params(axis="x", rotation=45)
    return fig


def _plot_top_flows(df, flow_df=None):
    if flow_df is None:
        flow_df = compute_flow_stats(df)
    if flow_df.empty:
        return _empty_figure("No flows")
    Figure = _get_figure()
    fig = Figure(figsize=(7, 4), dpi=100)
    ax = fig.add_subplot(111)
    top = flow_df.head(10)
    ax.bar(top["Flow"], top["Bytes"])
    ax.set_title("Flow Volume")
    ax.set_ylabel("Bytes")
    ax.tick_params(axis="x", rotation=45)
    return fig


def _add_chart_tab(notebook, title, fig):
    frame = ttk.Frame(notebook)
    notebook.add(frame, text=title)
    FigureCanvasTkAgg = _get_figure_canvas()
    canvas = FigureCanvasTkAgg(fig, master=frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)


# ── Hover Tooltip ──────────────────────────────────────────
class _HelpTooltip:
    """Shows a tooltip popup when the user hovers over a widget."""

    def __init__(self, widget, text, wrap_length=380, colors=None):
        self.widget = widget
        self.text = text
        self.wrap_length = wrap_length
        self.colors = colors
        self.tip_window = None
        self._after_id = None
        widget.bind("<Enter>", self._schedule_show)
        widget.bind("<Leave>", self._hide)
        widget.bind("<ButtonPress>", self._hide)

    def _schedule_show(self, event=None):
        """Show tooltip after a brief delay to avoid flicker."""
        self._cancel()
        self._after_id = self.widget.after(350, self._show)

    def _cancel(self):
        if self._after_id:
            self.widget.after_cancel(self._after_id)
            self._after_id = None

    def _show(self, event=None):
        if self.tip_window:
            return
        try:
            x = self.widget.winfo_rootx() + 16
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
        except tk.TclError:
            return  # widget was destroyed before tooltip fired
        tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        with contextlib.suppress(Exception):
            tw.wm_attributes("-topmost", True)
        # Outer border frame for clean edge
        tt_border = self.colors["tooltip_border"] if self.colors else "#4b5563"
        tt_bg = self.colors["tooltip_bg"] if self.colors else "#1e293b"
        tt_fg = self.colors["tooltip_fg"] if self.colors else "#e2e8f0"
        border = tk.Frame(tw, bg=tt_border, padx=1, pady=1)
        border.pack(fill=tk.BOTH, expand=True)
        label = tk.Label(
            border,
            text=self.text,
            justify=tk.LEFT,
            background=tt_bg,
            foreground=tt_fg,
            wraplength=self.wrap_length,
            font=("Segoe UI", 10),
            padx=10,
            pady=8,
        )
        label.pack()
        self.tip_window = tw

    def _hide(self, event=None):
        self._cancel()
        if self.tip_window:
            self.tip_window.destroy()
            self.tip_window = None


class PCAPSentryApp:
    def __init__(self, root):
        self.root = root
        self.base_title = f"PCAP Sentry v{APP_VERSION}"

        self.settings = load_settings()

        # Initialize offline_mode_var early so _get_window_title() can use it
        self.offline_mode_var = tk.BooleanVar(value=self.settings.get("offline_mode", False))

        self.root_title = self._get_window_title()
        self.root.title(self.root_title)

        # Restore window geometry from last session
        saved_geometry = self.settings.get("window_geometry", "1200x950")
        self.root.geometry(saved_geometry)

        self.theme_var = tk.StringVar(value=self.settings.get("theme", "system"))
        self.colors = {}
        self._apply_theme()

        self.font_title = tkfont.Font(family="Segoe UI", size=24, weight="bold")
        self.font_subtitle = tkfont.Font(family="Segoe UI", size=11)

        self.max_rows_var = tk.IntVar(value=self.settings.get("max_rows", DEFAULT_MAX_ROWS))
        self.parse_http_var = tk.BooleanVar(value=self.settings.get("parse_http", True))
        self.use_high_memory_var = tk.BooleanVar(value=self.settings.get("use_high_memory", False))
        self.use_local_model_var = tk.BooleanVar(value=self.settings.get("use_local_model", False))
        self.use_multithreading_var = tk.BooleanVar(value=self.settings.get("use_multithreading", True))
        self.turbo_parse_var = tk.BooleanVar(value=self.settings.get("turbo_parse", True))
        self.llm_provider_var = tk.StringVar(value=self.settings.get("llm_provider", "disabled"))
        self.llm_model_var = tk.StringVar(value=self.settings.get("llm_model", "llama3"))
        self.llm_endpoint_var = tk.StringVar(value=self.settings.get("llm_endpoint", "http://localhost:11434"))
        self.llm_api_key_var = tk.StringVar(value=self.settings.get("llm_api_key", ""))
        self.otx_api_key_var = tk.StringVar(value=self.settings.get("otx_api_key", ""))
        self.llm_test_status_var = tk.StringVar(value="Not tested")
        self.llm_test_status_label = None
        self.llm_header_indicator = None
        self.llm_header_label = None
        self.status_var = tk.StringVar(value="Ready")
        self.progress_percent_var = tk.StringVar(value="")
        self._progress_target = 0.0
        self._progress_current = 0.0
        self._progress_animating = False
        self._progress_anim_id = None
        self._progress_indeterminate = False
        self._initializing = False
        self._init_start_time = 0
        self._init_counter_id = None
        self._shutting_down = False
        self._cancel_event = threading.Event()
        self.sample_note_var = tk.StringVar(value="")
        self.ioc_path_var = tk.StringVar()
        self.ioc_summary_var = tk.StringVar(value="")
        self.unsure_count_var = tk.StringVar(value="0 items")
        self.backup_dir_var = tk.StringVar(value=self.settings.get("backup_dir", os.path.dirname(KNOWLEDGE_BASE_FILE)))
        self.safe_path_var = None
        self.mal_path_var = None
        self.target_path_var = None
        self.safe_browse = None
        self.safe_add_button = None
        self.mal_browse = None
        self.mal_add_button = None

        self.current_df = None
        self.current_stats = None
        self.current_sample_info = None
        self.current_verdict = None
        self.current_risk_score = None
        self.packet_base_time = None
        self.busy_count = 0
        self.busy_widgets = []
        self.widget_states = {}
        self.overlay = None
        self.overlay_label = None
        self.overlay_progress = None
        self.overlay_percent_label = None
        self.bg_canvas = None
        self.label_safe_button = None
        self.label_unsure_button = None
        self.label_mal_button = None
        self.llm_suggestion_frame = None
        self.llm_suggestion_label = None
        self.llm_suggestion_accept = None
        self._pending_llm_suggestion = None
        self.target_drop_area = None
        self.why_text = None
        self.education_text = None
        self.copy_filters_button = None
        self.wireshark_filters = []
        self.packet_table = None
        self.packet_columns = None
        self.packet_column_menu = None
        self.packet_column_vars = None
        self.packet_hint_text = None
        self.packet_proto_var = None
        self.packet_src_var = None
        self.packet_dst_var = None
        self.packet_sport_var = None
        self.packet_dport_var = None
        self.packet_time_min_var = None
        self.packet_time_max_var = None
        self.packet_size_min_var = None
        self.packet_size_max_var = None
        self.packet_dns_http_only_var = None

        # Chat state
        self.chat_history = []
        self.chat_text = None
        self.chat_entry_var = tk.StringVar(value="")
        self.chat_entry = None
        self.chat_send_button = None
        self.chat_clear_button = None
        self.chat_disabled_var = tk.StringVar(value="")

        # Extracted Info tab state
        self.cred_table = None
        self.host_table = None
        self.cred_count_var = None
        self.host_count_var = None
        self.extracted_data = None

        # Undo support for KB labeling
        self._last_kb_label = None  # "safe" or "malicious"
        self._last_kb_entry = None  # the entry dict that was appended

        # Performance optimization: caching for analysis pipeline
        self.kb_cache = None  # Cache for loaded knowledge base
        self.normalizer_cache = None  # Cache for vector normalizer
        self.threat_intel_cache = None  # Cache for TI enrichment results
        self.threat_intel_cache_time = 0  # Timestamp for cache validity

        self._build_background()
        self._build_menu_bar()
        self._build_header()
        self._build_tabs()
        self._build_status()

        # Restore chat history from last session
        self.chat_history = self.settings.get("chat_history", [])
        if self.chat_history and hasattr(self, "chat_text") and self.chat_text:
            self.root.after(500, self._restore_chat_history)

        if APP_DATA_FALLBACK_NOTICE and not self.settings.get("app_data_notice_shown"):
            self.root.after(200, self._show_app_data_notice)

        # Backup knowledge base on close
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        # Run startup checks in background (wrapped in try-except for safety)
        try:
            self.root.after(200, self._check_internet_and_set_offline)
        except Exception:
            pass  # Don't crash if internet check can't be scheduled

        try:
            self.root.after(400, self._auto_detect_llm)
        except Exception:
            pass  # Don't crash if LLM auto-detect can't be scheduled

    def _on_close(self):
        """Handle window close – cancel timers, backup KB, persist all state, then destroy."""
        self._shutting_down = True

        # Signal all background operations to stop
        self._cancel_event.set()

        # Cancel all pending after() callbacks
        self._reset_progress()
        if self._bg_draw_pending is not None:
            try:
                self.root.after_cancel(self._bg_draw_pending)
                self._bg_draw_pending = None
            except Exception:
                pass

        # Stop animations
        self._logo_spinning = False

        # Save complete settings and state snapshot before destroying window
        try:
            # Get current window geometry
            window_geometry = self.root.geometry()

            # Get selected tab index
            selected_tab_index = 0
            try:
                if hasattr(self, "notebook") and self.notebook:
                    tab_map = [self.analyze_tab, self.train_tab, self.kb_tab, self.chat_tab]
                    current_tab = self.notebook.select()
                    for idx, tab in enumerate(tab_map):
                        if str(tab) == current_tab:
                            selected_tab_index = idx
                            break
            except Exception:
                pass

            # Capture chat history (limit to last 100 messages to avoid file bloat)
            chat_history_snapshot = self.chat_history[-100:] if len(self.chat_history) > 100 else self.chat_history

            # Capture last used file paths
            last_safe_path = self.safe_path_var.get().strip() if self.safe_path_var else ""
            last_mal_path = self.mal_path_var.get().strip() if self.mal_path_var else ""
            last_target_path = self.target_path_var.get().strip() if self.target_path_var else ""

            settings_snapshot = {
                "max_rows": int(self.max_rows_var.get()),
                "parse_http": bool(self.parse_http_var.get()),
                "use_high_memory": bool(self.use_high_memory_var.get()),
                "use_local_model": bool(self.use_local_model_var.get()),
                "use_multithreading": bool(self.use_multithreading_var.get()),
                "turbo_parse": bool(self.turbo_parse_var.get()),
                "offline_mode": bool(self.offline_mode_var.get()),
                "backup_dir": self.backup_dir_var.get().strip(),
                "llm_provider": self.llm_provider_var.get().strip().lower() or "disabled",
                "llm_model": self.llm_model_var.get().strip() or "llama3",
                "llm_endpoint": self.llm_endpoint_var.get().strip() or "http://localhost:11434",
                "llm_api_key": self.llm_api_key_var.get().strip(),
                "otx_api_key": self.otx_api_key_var.get().strip(),
                "llm_auto_detect": self.settings.get("llm_auto_detect", True),
                "theme": self.theme_var.get().strip().lower() or "system",
                "app_data_notice_shown": bool(self.settings.get("app_data_notice_shown")),
                "window_geometry": window_geometry,
                "selected_tab": selected_tab_index,
                "chat_history": chat_history_snapshot,
                "last_safe_path": last_safe_path,
                "last_mal_path": last_mal_path,
                "last_target_path": last_target_path,
            }
        except Exception:
            settings_snapshot = self.settings

        # Perform file I/O in a background thread but wait briefly so
        # settings and KB backup are actually written before the process exits.
        def _cleanup_thread():
            try:
                _backup_knowledge_base()
                save_settings(settings_snapshot)
            except Exception:
                pass  # Best effort, don't block shutdown

        cleanup = threading.Thread(target=_cleanup_thread, daemon=True)
        cleanup.start()
        cleanup.join(timeout=2)  # Wait up to 2 s for save to finish

        self.root.destroy()

    # ── Local-server process names keyed by display / provider id ──
    _LOCAL_SERVER_PROCESS_MAP = {
        "ollama": (["ollama.exe", "ollama app.exe"], "Ollama"),
        "lm studio": (["lms.exe", "LM Studio.exe"], "LM Studio"),
        "gpt4all": (["chat.exe"], "GPT4All"),
        "jan": (["jan.exe", "Jan.exe"], "Jan"),
        "localai": (["local-ai.exe"], "LocalAI"),
        "koboldcpp": (["koboldcpp.exe"], "KoboldCpp"),
        "text-gen-webui": (
            ["python.exe"],  # too generic – skip auto-kill
            "text-gen-webui",
        ),
        "vllm": (["python.exe"], "vLLM"),
    }

    def _resolve_active_local_server(self):
        """Return (process_names, display_name) for the currently configured
        local LLM server, or *None* if the provider is disabled / cloud."""
        provider = self.llm_provider_var.get().strip().lower()
        endpoint = self.llm_endpoint_var.get().strip().lower()

        if provider == "disabled" or not endpoint:
            return None

        # Cloud endpoints – nothing to stop
        if not any(h in endpoint for h in ("localhost", "127.0.0.1", "0.0.0.0", "[::1]")):  # nosec B104 - comparing hostnames, not binding
            return None

        # Match by provider id first
        if provider == "ollama":
            return self._LOCAL_SERVER_PROCESS_MAP["ollama"]

        # Match by endpoint port for openai_compatible providers
        _PORT_MAP = {
            "1234": "lm studio",
            "4891": "gpt4all",
            "1337": "jan",
            "8080": "localai",
            "5001": "koboldcpp",
        }
        for port, key in _PORT_MAP.items():
            if f":{port}" in endpoint:
                return self._LOCAL_SERVER_PROCESS_MAP.get(key)

        return None

    def _maybe_stop_llm_server(self):
        """If a local LLM server is active, ask the user whether to stop it."""
        info = self._resolve_active_local_server()
        if info is None:
            return

        process_names, display_name = info

        # Don't offer to kill generic processes like python.exe
        if all(p.lower() == "python.exe" for p in process_names):
            return

        answer = messagebox.askyesno(
            "Stop LLM Server?",
            f"{display_name} is configured as the active LLM server.\n\n"
            f"Would you like to stop the {display_name} server as well?",
            default=messagebox.NO,
        )
        if not answer:
            return

        for proc in process_names:
            with contextlib.suppress(Exception):
                subprocess.run(
                    ["taskkill", "/F", "/T", "/IM", proc],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )

    def _get_window_title(self):
        """Generate window title with mode indicator"""
        if self.offline_mode_var.get():
            return f"{self.base_title} [OFFLINE MODE]"
        return f"{self.base_title} [ONLINE]"

    def _help_icon(self, parent, text, side=tk.LEFT, padx=(0, 6), **pack_kw):
        """Create a small '?' label with a hover tooltip explaining a feature."""
        lbl = tk.Label(
            parent,
            text="\u24d8",
            font=("Segoe UI", 11),
            fg=self.colors["accent"],
            bg=self.colors["bg"],
            cursor="question_arrow",
            padx=1,
            pady=0,
        )
        lbl.pack(side=side, padx=padx, **pack_kw)
        _HelpTooltip(lbl, text, colors=self.colors)
        return lbl

    def _help_icon_grid(self, parent, text, row, column, **grid_kw):
        """Create a small '?' label placed via grid with a hover tooltip."""
        lbl = tk.Label(
            parent,
            text="\u24d8",
            font=("Segoe UI", 11),
            fg=self.colors["accent"],
            bg=self.colors["bg"],
            cursor="question_arrow",
            padx=1,
            pady=0,
        )
        lbl.grid(row=row, column=column, padx=(2, 6), **grid_kw)
        _HelpTooltip(lbl, text, colors=self.colors)
        return lbl

    def _show_app_data_notice(self):
        window = tk.Toplevel(self.root)
        window.title("App Data Location")
        window.resizable(False, False)
        window.configure(bg=self.colors["bg"])
        self._set_dark_titlebar(window)

        frame = ttk.Frame(window, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text=APP_DATA_FALLBACK_NOTICE, wraplength=380, justify="left").pack(anchor="w")
        dont_show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame, text="Don't show this again", variable=dont_show_var).pack(anchor="w", pady=(10, 0))

        def close_notice():
            if dont_show_var.get():
                self.settings["app_data_notice_shown"] = True
                save_settings(self.settings)
            window.destroy()

        button_row = ttk.Frame(frame)
        button_row.pack(fill=tk.X, pady=(12, 0))
        ttk.Button(button_row, text="Open folder", command=self._open_app_data_dir).pack(side=tk.LEFT)
        ttk.Button(button_row, text="Copy path", command=self._copy_app_data_dir).pack(side=tk.LEFT, padx=6)
        ttk.Button(button_row, text="OK", command=close_notice).pack(side=tk.RIGHT)
        window.transient(self.root)
        window.grab_set()

    def _open_app_data_dir(self):
        if not APP_DATA_DIR:
            messagebox.showerror("App Data Location", "App data folder is unavailable.")
            return
        try:
            os.startfile(APP_DATA_DIR)
        except OSError as exc:
            messagebox.showerror("App Data Location", f"Failed to open folder: {exc}")

    def _copy_app_data_dir(self):
        if not APP_DATA_DIR:
            messagebox.showerror("App Data Location", "App data folder is unavailable.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(APP_DATA_DIR)

    def _start_logo_spin(self):
        """Begin spinning the header logo (called when processing starts)."""
        if self._logo_spinning or not self._spin_src_img:
            return
        self._logo_spinning = True
        self.root.after(50, self._animate_logo_spin)

    def _stop_logo_spin(self):
        """Stop spinning and reset the logo to its static frame."""
        self._logo_spinning = False
        if self._brand_label and self._header_icon_image:
            self._spin_index = 0
            # Reset to first frame if generated, otherwise use static image
            if self._spin_frames:
                self._brand_label.configure(image=self._spin_frames[0])
            else:
                self._brand_label.configure(image=self._header_icon_image)

    def _animate_logo_spin(self):
        """Advance one frame of the vertical-axis spin animation."""
        if self._shutting_down or not self._logo_spinning or not self._brand_label:
            return

        # Generate animation frames on first use to avoid startup delay
        if not self._spin_frames_generated and self._spin_src_img:
            self._generate_spin_frames()

        if not self._spin_frames:
            return

        try:
            self._spin_index = (self._spin_index + 1) % len(self._spin_frames)
            self._brand_label.configure(image=self._spin_frames[self._spin_index])
            self.root.after(50, self._animate_logo_spin)
        except tk.TclError:
            # Widget destroyed during shutdown
            return

    def _update_init_counter(self):
        """Update the initialization counter showing elapsed seconds."""
        if not self._initializing or self._shutting_down:
            return

        elapsed = int(time.time() - self._init_start_time)
        self.status_var.set(f"Initializing... {elapsed}s")
        self._init_counter_id = self.root.after(1000, self._update_init_counter)

    def _stop_init_counter(self):
        """Stop the initialization counter."""
        if self._init_counter_id is not None:
            self.root.after_cancel(self._init_counter_id)
            self._init_counter_id = None
        self._initializing = False

    def _generate_spin_frames(self):
        """Generate logo spin animation frames on demand to avoid startup delay."""
        if self._spin_frames_generated or not self._spin_src_img:
            return

        try:
            from PIL import Image, ImageTk
            import math as _math

            src = self._spin_src_img
            num_frames = 36
            self._spin_frames = []

            for i in range(num_frames):
                angle = 2 * _math.pi * i / num_frames
                scale_x = abs(_math.cos(angle))
                w = max(int(self._brand_icon_size * scale_x), 1)
                h = self._brand_icon_size
                squeezed = src.resize((w, h), Image.LANCZOS)
                if _math.cos(angle) < 0:
                    squeezed = squeezed.transpose(Image.FLIP_LEFT_RIGHT)
                canvas = Image.new("RGBA", (self._brand_icon_size, self._brand_icon_size), (0, 0, 0, 0))
                canvas.paste(squeezed, ((self._brand_icon_size - w) // 2, 0))
                self._spin_frames.append(ImageTk.PhotoImage(canvas))

            self._spin_frames_generated = True
        except Exception:
            pass

    def _build_menu_bar(self):
        """Create the application menu bar with File, Edit, and Help menus."""
        # Configure menu colors to match theme
        menu_bg = self.colors.get("panel", "#161b22")
        menu_fg = self.colors.get("text", "#e6edf3")
        menu_active_bg = self.colors.get("accent", "#58a6ff")
        menu_active_fg = self.colors.get("bg", "#0d1117")

        menubar = tk.Menu(
            self.root,
            bg=menu_bg,
            fg=menu_fg,
            activebackground=menu_active_bg,
            activeforeground=menu_active_fg,
            borderwidth=0,
            relief=tk.FLAT,
        )
        self.root.config(menu=menubar)

        # File Menu
        file_menu = tk.Menu(
            menubar,
            tearoff=0,
            bg=menu_bg,
            fg=menu_fg,
            activebackground=menu_active_bg,
            activeforeground=menu_active_fg,
            borderwidth=1,
            relief=tk.FLAT,
        )
        menubar.add_cascade(label="File", menu=file_menu)

        file_menu.add_command(
            label="Open PCAP...", command=lambda: self._browse_file(self.target_path_var), accelerator="Ctrl+O"
        )
        file_menu.add_separator()
        file_menu.add_command(label="Import IoC Feed...", command=self._browse_ioc)
        file_menu.add_separator()
        file_menu.add_command(label="Preferences...", command=self._open_preferences, accelerator="Ctrl+,")
        file_menu.add_command(label="LLM Settings...", command=self._open_llm_settings)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_close, accelerator="Alt+F4")

        # Edit Menu
        edit_menu = tk.Menu(
            menubar,
            tearoff=0,
            bg=menu_bg,
            fg=menu_fg,
            activebackground=menu_active_bg,
            activeforeground=menu_active_fg,
            borderwidth=1,
            relief=tk.FLAT,
        )
        menubar.add_cascade(label="Edit", menu=edit_menu)

        edit_menu.add_command(label="Undo", command=self._edit_undo, accelerator="Ctrl+Z")
        edit_menu.add_command(label="Redo", command=self._edit_redo, accelerator="Ctrl+Y")
        edit_menu.add_separator()
        edit_menu.add_command(label="Cut", command=self._edit_cut, accelerator="Ctrl+X")
        edit_menu.add_command(label="Copy", command=self._edit_copy, accelerator="Ctrl+C")
        edit_menu.add_command(label="Paste", command=self._edit_paste, accelerator="Ctrl+V")
        edit_menu.add_separator()
        edit_menu.add_command(label="Select All", command=self._edit_select_all, accelerator="Ctrl+A")
        edit_menu.add_separator()
        edit_menu.add_command(label="Clear All Fields", command=self._clear_input_fields, accelerator="Ctrl+L")

        # Help Menu
        help_menu = tk.Menu(
            menubar,
            tearoff=0,
            bg=menu_bg,
            fg=menu_fg,
            activebackground=menu_active_bg,
            activeforeground=menu_active_fg,
            borderwidth=1,
            relief=tk.FLAT,
        )
        menubar.add_cascade(label="Help", menu=help_menu)

        if _update_checker_available:
            help_menu.add_command(label="Check for Updates...", command=self._check_for_updates_ui)
            help_menu.add_separator()

        help_menu.add_command(label="User Manual", command=self._open_user_manual)
        help_menu.add_command(label="View Logs...", command=self._open_logs_folder)
        help_menu.add_separator()
        help_menu.add_command(label="About PCAP Sentry", command=self._show_about)

        # Bind keyboard shortcuts
        self.root.bind("<Control-z>", lambda _: self._edit_undo())
        self.root.bind("<Control-y>", lambda _: self._edit_redo())
        self.root.bind("<Control-o>", lambda _: self._browse_file(self.target_path_var))
        self.root.bind("<Control-l>", lambda _: self._clear_input_fields())
        self.root.bind("<Control-comma>", lambda _: self._open_preferences())

    def _build_header(self):
        header = ttk.Frame(self.root)
        header.pack(fill=tk.X, padx=20, pady=(18, 10))

        top_row = ttk.Frame(header)
        top_row.pack(fill=tk.X)

        title_block = ttk.Frame(top_row)
        title_block.pack(side=tk.LEFT)

        # App icon + title + subtitle stacked, with logo spanning full height
        brand_row = ttk.Frame(title_block)
        brand_row.pack(anchor=tk.W)

        # Load the app icon as the brand image (prefer PNG for clarity)
        self._header_icon_image = None
        self._brand_icon_size = 0
        self._spin_frames = []
        self._spin_frames_generated = False
        self._spin_index = 0
        self._spin_src_img = None
        self._logo_spinning = False
        icon_path = _get_app_icon_path(prefer_png=True)
        if icon_path:
            try:
                from PIL import Image, ImageTk

                src = Image.open(icon_path).convert("RGBA")
                self._brand_icon_size = 70
                src = src.resize((self._brand_icon_size, self._brand_icon_size), Image.LANCZOS)
                self._spin_src_img = src
                # Create initial static frame only - defer animation generation
                self._header_icon_image = ImageTk.PhotoImage(src)
            except Exception:
                pass
        self._brand_label = None
        if self._header_icon_image:
            self._brand_label = ttk.Label(
                brand_row,
                image=self._header_icon_image,
            )
            self._brand_label.pack(side=tk.LEFT, padx=(0, 14))
            # Logo starts static; spinning is triggered by _set_busy

        # Title + subtitle stacked to the right of the icon
        text_col = ttk.Frame(brand_row)
        text_col.pack(side=tk.LEFT)
        ttk.Label(
            text_col,
            text="PCAP Sentry",
            font=self.font_title,
        ).pack(anchor=tk.W)
        ttk.Label(
            text_col,
            text=f"Learn Malware Network Traffic Analysis  \u2022  v{APP_VERSION}",
            style="Hint.TLabel",
        ).pack(anchor=tk.W)

        # Online/Offline status indicator pill
        _llm_ind_bg = self.colors.get("panel", "#161b22")
        _llm_ind_border = self.colors.get("border", "#21262d")
        self.online_header_indicator = tk.Frame(
            top_row,
            bg=_llm_ind_bg,
            highlightbackground=_llm_ind_border,
            highlightthickness=1,
            padx=8,
            pady=4,
        )
        self.online_header_indicator.pack(side=tk.RIGHT, padx=(0, 4))
        self.online_header_label = tk.Button(
            self.online_header_indicator,
            text="Online",
            font=("Segoe UI", 9),
            fg=self.colors.get("success", "#3fb950"),
            bg=_llm_ind_bg,
            bd=0,
            relief=tk.FLAT,
            activebackground=_llm_ind_bg,
            activeforeground=self.colors.get("accent", "#58a6ff"),
            cursor="hand2",
            command=self._toggle_online_mode,
            width=9,
        )
        self.online_header_label.pack()
        self._update_online_header_indicator()

        # LLM status indicator pill
        self.llm_header_indicator = tk.Frame(
            top_row,
            bg=_llm_ind_bg,
            highlightbackground=_llm_ind_border,
            highlightthickness=1,
            padx=8,
            pady=4,
        )
        self.llm_header_indicator.pack(side=tk.RIGHT, padx=(0, 4))
        self.llm_header_label = tk.Button(
            self.llm_header_indicator,
            text="LLM: off",
            font=("Segoe UI", 9),
            fg=self.colors.get("muted", "#8b949e"),
            bg=_llm_ind_bg,
            bd=0,
            relief=tk.FLAT,
            activebackground=_llm_ind_bg,
            activeforeground=self.colors.get("accent", "#58a6ff"),
            cursor="hand2",
            command=self._test_llm_connection,
            width=8,
        )
        self.llm_header_label.pack()
        self._update_llm_header_indicator()

        # (subtitle is now part of brand_row text column above)

        toolbar = ttk.Frame(header, padding=(0, 14, 0, 0))
        toolbar.pack(fill=tk.X)

        ttk.Label(toolbar, text="Max packets for visuals:").pack(side=tk.LEFT)
        self._help_icon(
            toolbar,
            "Limits how many packets are loaded for charts and the packet table. "
            "Higher values give a more complete picture but use more memory and take longer. "
            "This does NOT affect the analysis verdict — all packets are always scored.",
        )
        ttk.Spinbox(toolbar, from_=10000, to=500000, increment=10000, textvariable=self.max_rows_var, width=8).pack(
            side=tk.LEFT, padx=6
        )
        ttk.Checkbutton(toolbar, text="Parse HTTP payloads", variable=self.parse_http_var).pack(side=tk.LEFT, padx=6)
        self._help_icon(
            toolbar,
            "When enabled, the parser extracts HTTP request details (method, host, path) "
            "from unencrypted web traffic. This gives you more information in the Packets tab "
            "but may slow parsing slightly on very large captures.",
        )

        # Accent separator
        accent = ttk.Separator(self.root, orient=tk.HORIZONTAL)
        accent.pack(fill=tk.X, padx=20, pady=(0, 4))

    def _build_tabs(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=16, pady=(4, 6))

        self.train_tab = ttk.Frame(notebook)
        self.analyze_tab = ttk.Frame(notebook)
        self.kb_tab = ttk.Frame(notebook)
        self.chat_tab = ttk.Frame(notebook)

        notebook.add(self.analyze_tab, text="  \U0001f50d  Analyze  ")
        notebook.add(self.train_tab, text="  \U0001f9e0  Train  ")
        notebook.add(self.kb_tab, text="  \U0001f4da  Knowledge Base  ")
        notebook.add(self.chat_tab, text="  \U0001f4ac  Chat  ")

        self._build_train_tab()
        self._build_analyze_tab()
        self._build_kb_tab()
        self._build_chat_tab()

        # Restore last selected tab from settings
        saved_tab_index = self.settings.get("selected_tab", 0)
        tab_map = [self.analyze_tab, self.train_tab, self.kb_tab, self.chat_tab]
        if 0 <= saved_tab_index < len(tab_map):
            notebook.select(tab_map[saved_tab_index])
        else:
            notebook.select(self.analyze_tab)

        # Store notebook reference for later use
        self.notebook = notebook

        notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

    def _build_status(self):
        # Separator above status
        ttk.Separator(self.root, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=16)
        status = ttk.Frame(self.root, padding=(16, 8))
        status.pack(fill=tk.X)
        # Progress bar — wider for clarity
        self.progress = ttk.Progressbar(status, mode="indeterminate", length=340)
        self.progress.pack(side=tk.LEFT, padx=(0, 8))
        # Percent label (hidden when idle — populated by _set_progress)
        self._progress_pct_label = ttk.Label(
            status,
            textvariable=self.progress_percent_var,
            font=("Segoe UI", 10, "bold"),
            width=5,
            anchor="w",
        )
        self._progress_pct_label.pack(side=tk.LEFT, padx=(0, 4))
        # Cancel button (hidden by default)
        self.cancel_button = ttk.Button(
            status,
            text="\u2715  Cancel",
            width=9,
            command=self._request_cancel,
        )
        self.cancel_button.pack(side=tk.LEFT, padx=(4, 0))
        self.cancel_button.pack_forget()  # hidden until busy
        # Status message
        status_label = ttk.Label(status, textvariable=self.status_var, font=("Segoe UI", 11))
        status_label.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        # Note: Bottom-right status label disabled per user request
        # ttk.Label(status, textvariable=self.sample_note_var, style="Hint.TLabel").pack(side=tk.RIGHT)

    def _open_preferences(self):
        window = tk.Toplevel(self.root)
        window.title("Preferences")
        window.resizable(True, True)
        window.geometry("750x650")
        window.minsize(700, 600)
        window.configure(bg=self.colors["bg"])
        self._set_dark_titlebar(window)

        # Scrollable container
        canvas = tk.Canvas(window, bg=self.colors["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(window, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind("<Configure>", lambda _: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Enable mouse wheel scrolling (widget-scoped, not global)
        def _on_mousewheel(event):
            try:
                canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
            except tk.TclError:
                pass  # Widget destroyed, ignore scroll event

        def _bind_mousewheel(_event):
            canvas.bind("<MouseWheel>", _on_mousewheel)

        def _unbind_mousewheel(_event):
            canvas.unbind("<MouseWheel>")

        canvas.bind("<Enter>", _bind_mousewheel)
        canvas.bind("<Leave>", _unbind_mousewheel)

        frame = ttk.Frame(scrollable_frame, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Preferences", style="Heading.TLabel").grid(
            row=0, column=0, sticky="w", columnspan=3, pady=(0, 8)
        )

        ttk.Label(frame, text="Theme:").grid(row=1, column=0, sticky="w", pady=4)
        theme_combo = ttk.Combobox(frame, textvariable=self.theme_var, values=["system", "dark", "light"], width=10)
        theme_combo.state(["readonly"])
        theme_combo.grid(row=1, column=1, sticky="w", pady=4)
        ttk.Label(frame, text="(applies after restart)", style="Hint.TLabel").grid(row=1, column=2, sticky="w", pady=4)

        ttk.Label(frame, text="Max packets for visuals:").grid(row=2, column=0, sticky="w", pady=4)
        max_rows_spin = ttk.Spinbox(
            frame,
            from_=10000,
            to=500000,
            increment=10000,
            textvariable=self.max_rows_var,
            width=10,
        )
        max_rows_spin.grid(row=2, column=1, sticky="w", pady=4)
        self._help_icon_grid(
            frame,
            "Controls how many packets are loaded for charts and the packet table. "
            "Higher values give a more complete picture but use more RAM. "
            "This does NOT affect the analysis verdict.",
            row=2,
            column=2,
            sticky="w",
        )

        ttk.Checkbutton(
            frame, text="Parse HTTP payloads", variable=self.parse_http_var, style="Quiet.TCheckbutton"
        ).grid(row=3, column=0, sticky="w", pady=4, columnspan=2)
        self._help_icon_grid(
            frame,
            "Extracts HTTP request details (method, host, URL path) from unencrypted "
            "web traffic. Useful for seeing exactly what URLs were visited. "
            "May slightly slow parsing on very large captures.",
            row=3,
            column=2,
            sticky="w",
        )

        ttk.Checkbutton(
            frame,
            text="High memory mode (load PCAP into RAM)",
            variable=self.use_high_memory_var,
            style="Quiet.TCheckbutton",
        ).grid(row=4, column=0, sticky="w", pady=4, columnspan=2)
        self._help_icon_grid(
            frame,
            "Loads the entire PCAP file into RAM before parsing. "
            "This is faster for smaller files (under ~500 MB) but uses more memory. "
            "For very large captures, leave this off to use streaming mode instead.",
            row=4,
            column=2,
            sticky="w",
        )

        ttk.Checkbutton(
            frame,
            text="Turbo parse (fast raw parsing for large files)",
            variable=self.turbo_parse_var,
            style="Quiet.TCheckbutton",
        ).grid(row=5, column=0, sticky="w", pady=4, columnspan=2)
        self._help_icon_grid(
            frame,
            "Parses IP/TCP/UDP headers directly from raw bytes instead of full "
            "Scapy dissection. Typically 5-15\u00d7 faster for large captures (>50 MB). "
            "Only uses Scapy for DNS and TLS ClientHello packets that need deep inspection. "
            "Disable if you see missing data in results.",
            row=5,
            column=2,
            sticky="w",
        )

        ttk.Checkbutton(
            frame, text="Enable local ML model", variable=self.use_local_model_var, style="Quiet.TCheckbutton"
        ).grid(row=6, column=0, sticky="w", pady=4, columnspan=2)
        self._help_icon_grid(
            frame,
            "Uses a locally trained machine learning model (scikit-learn) for an additional "
            "verdict alongside the heuristic/knowledge-base scoring. Requires scikit-learn to be "
            "installed and at least some labeled training data in the knowledge base.",
            row=6,
            column=2,
            sticky="w",
        )

        # OTX API Key
        ttk.Label(frame, text="AlienVault OTX API Key:").grid(row=7, column=0, sticky="w", pady=4)

        # Entry and button on same row
        otx_key_row = ttk.Frame(frame)
        otx_key_row.grid(row=7, column=1, sticky="w", pady=4)
        otx_key_entry = ttk.Entry(otx_key_row, textvariable=self.otx_api_key_var, width=40, show="\u2022")
        otx_key_entry.pack(side=tk.LEFT, padx=(0, 4))
        self._add_clear_x(otx_key_entry, self.otx_api_key_var)
        verify_btn = ttk.Button(otx_key_row, text="Verify", style="Secondary.TButton", command=self._verify_otx_key)
        verify_btn.pack(side=tk.LEFT, padx=(0, 4))

        # Status label on row below
        self._otx_verify_label = tk.Label(
            frame,
            text=" ",
            font=("Segoe UI", 9),
            anchor="w",
            width=30,
            bg=self.colors.get("bg", "#0d1117"),
            fg=self.colors.get("muted", "#8b949e"),
        )
        self._otx_verify_label.grid(row=8, column=1, sticky="w", pady=(0, 4))

        self._help_icon_grid(
            frame,
            "Optional API key for AlienVault OTX threat intelligence. "
            "Provides higher rate limits and more detailed threat data. "
            "Get your free key at otx.alienvault.com. Leave blank to use public endpoints.",
            row=7,
            column=2,
            sticky="w",
        )

        offline_check = ttk.Checkbutton(
            frame,
            text="Offline mode (disable threat intelligence & cloud LLMs)",
            variable=self.offline_mode_var,
            style="Quiet.TCheckbutton",
            command=self._on_offline_mode_changed,
        )
        offline_check.grid(row=9, column=0, sticky="w", pady=4, columnspan=2)
        self._help_icon_grid(
            frame,
            "Disables online threat intelligence lookups (AlienVault OTX, AbuseIPDB, etc.) "
            "and cloud LLM providers. "
            "Analysis will be faster and work without an internet connection, but you lose the "
            "ability to check IPs/domains against live public threat feeds "
            "and cannot use cloud-based LLM providers. Configure LLM settings via File → LLM Settings. "
            "Use the LLM button in the header to quickly toggle LLM on/off.",
            row=9,
            column=2,
            sticky="w",
        )

        ttk.Checkbutton(
            frame,
            text="Multithreaded analysis (faster, uses more CPU)",
            variable=self.use_multithreading_var,
            style="Quiet.TCheckbutton",
        ).grid(row=10, column=0, sticky="w", pady=4, columnspan=2)
        self._help_icon_grid(
            frame,
            "Runs analysis tasks in parallel using multiple threads. "
            "This can significantly speed up analysis on multi-core systems. "
            "Disable if you experience stability issues or want to reduce CPU usage.",
            row=10,
            column=2,
            sticky="w",
        )

        # Backup directory row with improved spacing

        ttk.Label(frame, text="Backup directory:").grid(row=11, column=0, sticky="w", pady=4)
        backup_entry = ttk.Entry(frame, textvariable=self.backup_dir_var, width=60)
        backup_entry.grid(row=11, column=1, sticky="ew", pady=4, columnspan=5)
        self._add_clear_x(backup_entry, self.backup_dir_var)
        frame.grid_columnconfigure(1, weight=1)

        # Button row under backup directory
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=12, column=1, columnspan=5, sticky="w", pady=(4, 4))
        ttk.Button(button_frame, text="Browse", style="Secondary.TButton", command=self._browse_backup_dir).pack(
            side=tk.LEFT, padx=(0, 4)
        )
        ttk.Button(button_frame, text="Save", command=lambda: self._save_preferences(window)).pack(
            side=tk.LEFT, padx=(0, 4)
        )
        ttk.Button(button_frame, text="Cancel", style="Secondary.TButton", command=window.destroy).pack(side=tk.LEFT)

        # Reset to defaults button
        ttk.Button(frame, text="Reset to Defaults", style="Danger.TButton", command=self._reset_preferences).grid(
            row=13, column=1, columnspan=5, sticky="w", pady=(4, 0)
        )

        window.grab_set()

    def _save_preferences(self, window):
        self._save_settings_from_vars()
        self.root_title = self._get_window_title()
        self.root.title(self.root_title)
        window.destroy()

    def _save_settings_from_vars(self):
        # Preserve state data that shouldn't be overwritten by preferences dialog
        settings = {
            "max_rows": int(self.max_rows_var.get()),
            "parse_http": bool(self.parse_http_var.get()),
            "use_high_memory": bool(self.use_high_memory_var.get()),
            "use_local_model": bool(self.use_local_model_var.get()),
            "use_multithreading": bool(self.use_multithreading_var.get()),
            "turbo_parse": bool(self.turbo_parse_var.get()),
            "offline_mode": bool(self.offline_mode_var.get()),
            "backup_dir": self.backup_dir_var.get().strip(),
            "llm_provider": self.llm_provider_var.get().strip().lower() or "disabled",
            "llm_model": self.llm_model_var.get().strip() or "llama3",
            "llm_endpoint": self.llm_endpoint_var.get().strip() or "http://localhost:11434",
            "llm_api_key": self.llm_api_key_var.get().strip(),
            "otx_api_key": self.otx_api_key_var.get().strip(),
            "llm_auto_detect": self.settings.get("llm_auto_detect", True),
            "theme": self.theme_var.get().strip().lower() or "system",
            "app_data_notice_shown": bool(self.settings.get("app_data_notice_shown")),
            # Preserve window state and chat history from current settings
            "window_geometry": self.settings.get("window_geometry", "1200x950"),
            "selected_tab": self.settings.get("selected_tab", 0),
            "chat_history": self.settings.get("chat_history", []),
            "last_safe_path": self.settings.get("last_safe_path", ""),
            "last_mal_path": self.settings.get("last_mal_path", ""),
            "last_target_path": self.settings.get("last_target_path", ""),
        }
        self.settings = settings
        save_settings(settings)
        if hasattr(self, "_sync_chat_controls"):
            self._sync_chat_controls()

    def _reset_preferences(self):
        confirm = messagebox.askyesno(
            "Preferences",
            "Reset preferences to defaults?",
        )
        if not confirm:
            return

        defaults = _default_settings()
        self.max_rows_var.set(defaults["max_rows"])
        self.parse_http_var.set(defaults["parse_http"])
        self.use_high_memory_var.set(defaults["use_high_memory"])
        self.use_local_model_var.set(defaults["use_local_model"])
        self.use_multithreading_var.set(defaults.get("use_multithreading", True))
        self.turbo_parse_var.set(defaults.get("turbo_parse", True))
        self.offline_mode_var.set(defaults.get("offline_mode", False))
        self.backup_dir_var.set(defaults["backup_dir"])
        self.llm_provider_var.set(defaults.get("llm_provider", "disabled"))
        self.llm_model_var.set(defaults.get("llm_model", "llama3"))
        self.llm_endpoint_var.set(defaults.get("llm_endpoint", "http://localhost:11434"))
        self.llm_api_key_var.set(defaults.get("llm_api_key", ""))
        self.otx_api_key_var.set(defaults.get("otx_api_key", ""))
        self.theme_var.set(defaults["theme"])
        self._save_settings_from_vars()

    def _open_user_manual(self):
        """Open the user manual in the default web browser."""
        import webbrowser

        manual_url = "https://github.com/industrial-dave/PCAP-Sentry/blob/main/USER_MANUAL.md"
        webbrowser.open(manual_url)

    def _open_logs_folder(self):
        """Open the logs folder in Windows Explorer."""
        app_data_dir = _get_app_data_dir()
        if os.path.exists(app_data_dir):
            os.startfile(app_data_dir)
        else:
            messagebox.showinfo("Logs", f"Logs folder not found:\n{app_data_dir}")

    def _show_about(self):
        """Show the About dialog."""
        about_window = tk.Toplevel(self.root)
        about_window.title("About PCAP Sentry")
        about_window.resizable(False, False)
        about_window.geometry("500x400")
        about_window.configure(bg=self.colors["bg"])
        self._set_dark_titlebar(about_window)

        frame = ttk.Frame(about_window, padding=30)
        frame.pack(fill=tk.BOTH, expand=True)

        # Title
        ttk.Label(
            frame,
            text="PCAP Sentry",
            font=("Segoe UI", 18, "bold"),
        ).pack(pady=(0, 5))

        ttk.Label(
            frame,
            text=f"Version {APP_VERSION}",
            style="Hint.TLabel",
        ).pack(pady=(0, 20))

        # Description
        desc_text = (
            "Learn Malware Network Traffic Analysis\n"
            "Beginner-Friendly Educational Tool\n\n"
            "PCAP Sentry analyzes PCAP/PCAPNG files for signs of malicious activity, "
            "providing heuristic signals, behavioral anomaly detection, and threat intelligence "
            "integration to help triage suspicious network traffic."
        )
        desc_label = ttk.Label(frame, text=desc_text, wraplength=440, justify=tk.CENTER)
        desc_label.pack(pady=(0, 20))

        # Links frame
        links_frame = ttk.Frame(frame)
        links_frame.pack(pady=10)

        def open_link(url):
            import webbrowser

            webbrowser.open(url)

        github_btn = ttk.Button(
            links_frame,
            text="GitHub Repository",
            command=lambda: open_link("https://github.com/industrial-dave/PCAP-Sentry"),
        )
        github_btn.pack(pady=5)

        manual_btn = ttk.Button(
            links_frame,
            text="User Manual",
            command=lambda: open_link("https://github.com/industrial-dave/PCAP-Sentry/blob/main/USER_MANUAL.md"),
        )
        manual_btn.pack(pady=5)

        # License
        ttk.Label(
            frame,
            text="See LICENSE.txt for license terms",
            style="Hint.TLabel",
        ).pack(pady=(20, 0))

        # Close button
        ttk.Button(frame, text="Close", command=about_window.destroy).pack(pady=(20, 0))

        about_window.grab_set()

    def _check_for_updates_ui(self):
        """Handle "Check for Updates" button click."""
        if not _update_checker_available:
            messagebox.showwarning("Updates", "Update checker is not available.")
            return

        def show_result(result):
            """Callback after update check completes – called from background thread."""
            # Schedule on main thread so Tkinter calls are safe
            self.root.after(0, lambda: self._show_update_result(result))

        # Run update check in background
        checker_thread = BackgroundUpdateChecker(APP_VERSION, callback=show_result)
        checker_thread.start()

    def _show_update_result(self, result):
        """Display update check result (always runs on the main thread)."""
        if not result.get("success"):
            error_msg = result.get("error", "Unknown error")

            # Handle specific error cases with helpful messages
            if "404" in str(error_msg) or "HTTP 404" in str(error_msg):
                messagebox.showinfo(
                    "Check for Updates",
                    "No releases have been published yet.\n\n"
                    "This is normal for development builds. Once a release\n"
                    "is published on GitHub, update checking will work.",
                )
            elif "Network error" in str(error_msg) or "URLError" in str(error_msg):
                messagebox.showerror(
                    "Check for Updates",
                    f"Network connection failed:\n{error_msg}\n\nPlease check your internet connection and try again.",
                )
            elif "Blocked unsafe URL scheme" in str(error_msg):
                messagebox.showerror(
                    "Check for Updates",
                    f"Security error:\n{error_msg}\n\nThe update URL failed security validation.",
                )
            elif "HTTP" in str(error_msg):
                messagebox.showerror(
                    "Check for Updates",
                    f"GitHub API error:\n{error_msg}\n\nGitHub may be temporarily unavailable. Try again later.",
                )
            else:
                messagebox.showerror(
                    "Check for Updates",
                    f"Failed to check for updates:\n{error_msg}\n\n"
                    "If this persists, check your network connection\n"
                    "or visit the GitHub releases page manually.",
                )
            return

        if result.get("available"):
            latest = result.get("latest", "unknown")
            current = result.get("current", "unknown")
            notes = result.get("release_notes", "No release notes available.")

            # Show update available dialog
            window = tk.Toplevel(self.root)
            window.title("Update Available")
            window.resizable(True, True)
            window.geometry("600x450")
            window.configure(bg=self.colors["bg"])
            self._set_dark_titlebar(window)

            frame = ttk.Frame(window, padding=16)
            frame.pack(fill=tk.BOTH, expand=True)

            ttk.Label(
                frame,
                text="A new version is available!",
                font=("Segoe UI", 13, "bold"),
            ).pack(anchor="w", pady=(0, 10))

            ttk.Label(frame, text=f"Current version: {current}").pack(anchor="w", pady=(0, 5))
            ttk.Label(frame, text=f"Available version: {latest}").pack(anchor="w", pady=(0, 15))

            # Button frame at bottom FIRST (pack order matters — bottom before expanding middle)
            button_frame = ttk.Frame(frame)
            button_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(10, 0))

            def on_download():
                self._download_and_install_update(latest)
                window.destroy()

            ttk.Button(button_frame, text="Download & Update", command=on_download).pack(side=tk.LEFT, padx=6)
            ttk.Button(button_frame, text="Later", style="Secondary.TButton", command=window.destroy).pack(side=tk.LEFT)

            # Release notes in the middle (expands to fill remaining space)
            ttk.Label(frame, text="Release Notes:", font=("Segoe UI", 11, "bold")).pack(anchor="w")
            text_frame = ttk.Frame(frame)
            text_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 0))

            scrollbar = ttk.Scrollbar(text_frame)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

            text_widget = tk.Text(text_frame, wrap=tk.WORD, yscrollcommand=scrollbar.set, height=10)
            text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.config(command=text_widget.yview)
            self._style_text(text_widget)

            text_widget.insert(tk.END, notes)
            text_widget.config(state=tk.DISABLED)

            window.grab_set()
        else:
            current = result.get("current", "unknown")
            notes = result.get("release_notes", "")

            if notes and notes.strip():
                # Show a richer dialog with the changelog for the current version
                window = tk.Toplevel(self.root)
                window.title("Check for Updates")
                window.resizable(True, True)
                window.geometry("550x350")
                window.configure(bg=self.colors["bg"])
                self._set_dark_titlebar(window)

                frame = ttk.Frame(window, padding=16)
                frame.pack(fill=tk.BOTH, expand=True)

                ttk.Label(
                    frame,
                    text=f"You are running the latest version ({current})",
                    font=("Segoe UI", 12, "bold"),
                ).pack(anchor="w", pady=(0, 12))

                ttk.Label(
                    frame,
                    text="What's in this release:",
                    font=("Segoe UI", 11, "bold"),
                ).pack(anchor="w")

                text_frame = ttk.Frame(frame)
                text_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 15))

                scrollbar = ttk.Scrollbar(text_frame)
                scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

                text_widget = tk.Text(text_frame, wrap=tk.WORD, yscrollcommand=scrollbar.set, height=10)
                text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
                scrollbar.config(command=text_widget.yview)
                self._style_text(text_widget)

                text_widget.insert(tk.END, notes)
                text_widget.config(state=tk.DISABLED)

                ttk.Button(frame, text="OK", command=window.destroy).pack(anchor="e")
                window.grab_set()
            else:
                messagebox.showinfo(
                    "Check for Updates",
                    f"You are running the latest version ({current}).",
                )

    def _download_and_install_update(self, version):
        """Download and install the update."""
        # Back up the knowledge base before updating so user data is preserved
        with contextlib.suppress(Exception):
            _backup_knowledge_base()

        # Create progress UI on the main thread first
        progress_window = tk.Toplevel(self.root)
        progress_window.title("Downloading Update")
        progress_window.resizable(False, False)
        progress_window.geometry("400x120")
        progress_window.configure(bg=self.colors["bg"])
        self._set_dark_titlebar(progress_window)

        frame = ttk.Frame(progress_window, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Downloading update...", font=("Segoe UI", 11)).pack(anchor="w", pady=(0, 10))
        progress_bar = ttk.Progressbar(frame, mode="indeterminate", length=350)
        progress_bar.pack(fill=tk.X, pady=(0, 10))
        progress_bar.start(12)  # Pulse until first real update
        status_label = ttk.Label(frame, text="Connecting...", font=("Segoe UI", 10))
        status_label.pack(anchor="w")

        # Smooth animation state for download progress
        _dl_anim = {"current": 0.0, "target": 0.0, "started": False, "anim_id": None}

        def _cleanup_progress_window():
            """Safely destroy progress window after canceling animation."""
            if _dl_anim["anim_id"] is not None:
                try:
                    self.root.after_cancel(_dl_anim["anim_id"])
                except Exception:
                    pass
                _dl_anim["anim_id"] = None
            try:
                progress_window.destroy()
            except Exception:
                pass

        def _animate_dl():
            """Ease-out interpolation for download progress bar."""
            # Check if progress window still exists
            try:
                if not progress_bar.winfo_exists():
                    _dl_anim["anim_id"] = None
                    return
            except tk.TclError:
                _dl_anim["anim_id"] = None
                return

            diff = _dl_anim["target"] - _dl_anim["current"]
            if abs(diff) < 0.3:
                _dl_anim["current"] = _dl_anim["target"]
                progress_bar["value"] = _dl_anim["target"]
                _dl_anim["anim_id"] = None
                return
            step = diff * 0.15
            if abs(step) < 0.15:
                step = 0.15 if diff > 0 else -0.15
            _dl_anim["current"] += step
            progress_bar["value"] = _dl_anim["current"]
            _dl_anim["anim_id"] = self.root.after(16, _animate_dl)

        def download_in_background():
            try:
                checker = UpdateChecker(APP_VERSION)
                if not checker.fetch_latest_release():
                    self.root.after(
                        0,
                        lambda: (
                            _cleanup_progress_window(),
                            messagebox.showerror(
                                "Download Failed",
                                "Failed to fetch release information from GitHub.",
                            ),
                        ),
                    )
                    return

                if not checker.download_url:
                    self.root.after(
                        0,
                        lambda: (
                            _cleanup_progress_window(),
                            messagebox.showerror(
                                "Download Failed", "No installer or executable found in the latest release."
                            ),
                        ),
                    )
                    return

                update_dir = checker.get_update_dir()
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                is_installer = getattr(checker, "download_is_installer", False)
                if is_installer:
                    exe_name = f"PCAP_Sentry_Setup_{version}_{timestamp}.exe"
                else:
                    exe_name = f"PCAP_Sentry_{version}_{timestamp}.exe"
                dest_path = os.path.join(update_dir, exe_name)

                def progress_callback(downloaded, total):
                    if total > 0:
                        progress = int((downloaded / total) * 100)

                        def _update_dl(p=progress, dl=downloaded, t=total):
                            if not _dl_anim["started"]:
                                # Switch from indeterminate to determinate on first update
                                progress_bar.stop()
                                progress_bar.configure(mode="determinate", maximum=100)
                                _dl_anim["started"] = True
                            _dl_anim["target"] = p
                            dl_mb = dl / (1024 * 1024)
                            t_mb = t / (1024 * 1024)
                            status_label.config(text=f"{p}%  ({dl_mb:.1f} / {t_mb:.1f} MB)")
                            if _dl_anim["anim_id"] is None:
                                _animate_dl()

                        self.root.after(0, _update_dl)

                if checker.download_update(dest_path, progress_callback=progress_callback):
                    _write_error_log(f"Update download successful: {dest_path}")

                    def on_success():
                        _cleanup_progress_window()
                        if is_installer:
                            # Installer handles placing files in the right
                            # Program Files directory – just launch it.
                            messagebox.showinfo(
                                "Update Ready",
                                "The installer has been downloaded.\n\n"
                                "The installer will now launch to update all files\n"
                                "(executable, documentation, runtime libraries).\n\n"
                                "PCAP Sentry will close. After the installer completes,\n"
                                "you can relaunch PCAP Sentry from your Start menu or desktop.",
                            )
                            if checker.launch_installer(dest_path):
                                self.root.after(100, self._on_close)
                            else:
                                error_reason = getattr(checker, "_last_error", "Unknown error")
                                _write_error_log(f"Installer launch failed: {error_reason}")
                                messagebox.showerror(
                                    "Installer Launch Failed",
                                    f"Failed to launch the installer.\n\n"
                                    f"Error: {error_reason}\n\n"
                                    f"Installer saved to:\n{dest_path}\n\n"
                                    f"Please run the installer manually.",
                                )
                        else:
                            # Standalone EXE – replace the currently running
                            # executable after app exit, then relaunch.
                            current_exe = sys.executable
                            if checker.replace_executable(dest_path, current_exe):
                                messagebox.showinfo(
                                    "Update Ready",
                                    "The update will be applied after PCAP Sentry closes.\n\n"
                                    "PCAP Sentry will now close and restart with the new version.",
                                )
                                # Force quit immediately after user closes the messagebox
                                self.root.after(100, self._on_close)
                            else:
                                reason = getattr(checker, "_last_error", "Unknown error")
                                _write_error_log(f"Executable replacement failed: {reason}")
                                messagebox.showerror(
                                    "Update Failed",
                                    f"Could not apply the update automatically.\n\n"
                                    f"Error: {reason}\n\n"
                                    f"Update saved to:\n{dest_path}\n\n"
                                    f"Please install it manually.",
                                )

                    self.root.after(0, on_success)
                else:
                    download_error = getattr(checker, "_last_error", "Unknown error")
                    _write_error_log(f"Update download failed: {download_error}")
                    self.root.after(
                        0,
                        lambda: (
                            _cleanup_progress_window(),
                            messagebox.showerror(
                                "Download Failed", f"Failed to download the update.\n\nError: {download_error}"
                            ),
                        ),
                    )

            except Exception as e:
                _write_error_log("Update download exception", e, sys.exc_info()[2])
                self.root.after(
                    0,
                    lambda exc=e: (
                        _cleanup_progress_window(),
                        messagebox.showerror("Update Error", f"An error occurred during update: {exc!s}"),
                    ),
                )

        download_thread = threading.Thread(target=download_in_background, daemon=True)
        download_thread.start()

    def _browse_backup_dir(self):
        path = filedialog.askdirectory()
        if path:
            self.backup_dir_var.set(path)

    def _edit_undo(self):
        """Undo last action in focused widget."""
        try:
            widget = self.root.focus_get()
            if widget and hasattr(widget, "edit_undo"):
                widget.edit_undo()
        except Exception:
            pass

    def _edit_redo(self):
        """Redo last undone action in focused widget."""
        try:
            widget = self.root.focus_get()
            if widget and hasattr(widget, "edit_redo"):
                widget.edit_redo()
        except Exception:
            pass

    def _edit_cut(self):
        """Cut selected text from focused widget."""
        try:
            widget = self.root.focus_get()
            if widget and hasattr(widget, "selection_get"):
                widget.event_generate("<<Cut>>")
        except Exception:
            pass

    def _edit_copy(self):
        """Copy selected text from focused widget."""
        try:
            widget = self.root.focus_get()
            if widget and hasattr(widget, "selection_get"):
                widget.event_generate("<<Copy>>")
        except Exception:
            pass

    def _edit_paste(self):
        """Paste text into focused widget."""
        try:
            widget = self.root.focus_get()
            if widget and hasattr(widget, "insert"):
                widget.event_generate("<<Paste>>")
        except Exception:
            pass

    def _edit_select_all(self):
        """Select all text in focused widget."""
        try:
            widget = self.root.focus_get()
            if widget and hasattr(widget, "select_range"):
                # For Entry widgets
                widget.select_range(0, tk.END)
            elif widget and hasattr(widget, "tag_add"):
                # For Text widgets
                widget.tag_add(tk.SEL, "1.0", tk.END)
                widget.mark_set(tk.INSERT, "1.0")
                widget.see(tk.INSERT)
        except Exception:
            pass

    def _clear_input_fields(self):
        if self.safe_path_var is not None:
            self.safe_path_var.set("")
        if self.mal_path_var is not None:
            self.mal_path_var.set("")
        if self.target_path_var is not None:
            self.target_path_var.set("")
        if self.ioc_path_var is not None:
            self.ioc_path_var.set("")

    def _build_chat_tab(self):
        container = ttk.Frame(self.chat_tab, padding=14)
        container.pack(fill=tk.BOTH, expand=True)

        header = ttk.Frame(container)
        header.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(header, text="Chat Assistant", style="Heading.TLabel").pack(side=tk.LEFT)
        self._help_icon(
            header, "Ask questions about the current analysis or general usage. Chat uses the configured LLM provider."
        )

        disabled_label = ttk.Label(container, textvariable=self.chat_disabled_var, style="Hint.TLabel")
        disabled_label.pack(anchor=tk.W, pady=(0, 6))

        self.chat_text = tk.Text(container, height=18, wrap=tk.WORD)
        self._style_text(self.chat_text)
        self.chat_text.configure(state=tk.DISABLED)
        self.chat_text.tag_configure("user", foreground=self.colors.get("accent", "#58a6ff"))
        self.chat_text.tag_configure("assistant", foreground=self.colors.get("text", "#e6edf3"))
        self.chat_text.tag_configure("system", foreground=self.colors.get("muted", "#8b949e"))
        self.chat_text.pack(fill=tk.BOTH, expand=True)

        input_frame = ttk.Frame(container)
        input_frame.pack(fill=tk.X, pady=(8, 0))
        self.chat_entry = ttk.Entry(input_frame, textvariable=self.chat_entry_var, width=80)
        self.chat_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.chat_send_button = ttk.Button(input_frame, text="Send", command=self._send_chat_message)
        self.chat_send_button.pack(side=tk.LEFT, padx=6)
        self.chat_clear_button = ttk.Button(
            input_frame, text="Clear", style="Secondary.TButton", command=self._clear_chat
        )
        self.chat_clear_button.pack(side=tk.LEFT)

        self.chat_entry.bind("<Return>", lambda _e: self._send_chat_message())
        self._sync_chat_controls()

    def _sync_chat_controls(self):
        enabled = self._llm_is_enabled()
        if not enabled:
            self.chat_disabled_var.set("Chat is disabled. Configure an LLM provider in File → LLM Settings.")
        else:
            self.chat_disabled_var.set("")

        state = "normal" if enabled else "disabled"
        if self.chat_entry is not None:
            self.chat_entry.configure(state=state)
        if self.chat_send_button is not None:
            self.chat_send_button.configure(state=state)
        if self.chat_clear_button is not None:
            self.chat_clear_button.configure(state=state)

    def _append_chat_message(self, role, text):
        if self.chat_text is None:
            return
        self.chat_text.configure(state=tk.NORMAL)
        prefix = "User: " if role == "user" else "Assistant: "
        tag = "user" if role == "user" else "assistant"
        if role == "system":
            prefix = "System: "
            tag = "system"
        self.chat_text.insert(tk.END, f"{prefix}{text}\n", tag)
        self.chat_text.see(tk.END)
        self.chat_text.configure(state=tk.DISABLED)

    def _clear_chat(self):
        self.chat_history = []
        if self.chat_text is None:
            return
        self.chat_text.configure(state=tk.NORMAL)
        self.chat_text.delete("1.0", tk.END)
        self.chat_text.configure(state=tk.DISABLED)

    def _restore_chat_history(self):
        """Restore chat history from saved settings on startup."""
        if self.chat_text is None or not self.chat_history:
            return
        try:
            for msg in self.chat_history:
                role = msg.get("role", "user")
                content = msg.get("content", "")
                if content:
                    self._append_chat_message(role, content)
        except Exception:
            pass  # Don't crash if history restoration fails

    def _build_chat_context(self):
        if self.current_stats is None:
            return {"status": "no_analysis"}
        return {
            "status": "analysis_loaded",
            "verdict": self.current_verdict,
            "risk_score": self.current_risk_score,
            "packet_count": self.current_stats.get("packet_count"),
            "avg_size": self.current_stats.get("avg_size"),
            "median_size": self.current_stats.get("median_size"),
            "protocol_counts": self.current_stats.get("protocol_counts", {}),
            "top_ports": self.current_stats.get("top_ports", []),
            "dns_query_count": self.current_stats.get("dns_query_count"),
            "http_request_count": self.current_stats.get("http_request_count"),
            "tls_packet_count": self.current_stats.get("tls_packet_count"),
            "top_dns": self.current_stats.get("top_dns", []),
            "top_tls_sni": self.current_stats.get("top_tls_sni", []),
        }

    def _request_llm_chat(self, user_message):
        provider = self.llm_provider_var.get().strip().lower()
        if provider == "ollama":
            return self._request_ollama_chat(user_message)
        if provider == "openai_compatible":
            return self._request_openai_compat_chat(
                [
                    {"role": "system", "content": "You are a PCAP Sentry assistant. Answer clearly and concisely."},
                    {"role": "user", "content": self._build_openai_chat_prompt(user_message)},
                ]
            )
        raise ValueError(f"Unsupported LLM provider: {provider}")

    def _request_ollama_chat(self, user_message):
        endpoint = self._normalize_ollama_endpoint(self.llm_endpoint_var.get() or "http://localhost:11434")
        model = self.llm_model_var.get().strip() or "llama3"
        url = endpoint.rstrip("/") + "/api/chat"
        context = self._build_chat_context()

        messages = [
            {
                "role": "system",
                "content": (
                    "You are a PCAP Sentry assistant. Answer clearly and concisely. "
                    "If no analysis is loaded, say so and answer in general terms.\n\n"
                    f"Context JSON:\n{json.dumps(context, indent=2)}"
                ),
            },
        ]
        for msg in self.chat_history[-6:]:
            role = msg.get("role")
            if role in ("user", "assistant"):
                messages.append({"role": role, "content": msg.get("content", "")})
        messages.append({"role": "user", "content": user_message})

        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
        }
        data = json.dumps(payload).encode("utf-8")
        raw = self._llm_http_request(url, data, timeout=30)

        response = json.loads(raw)
        content = response.get("message", {}).get("content", "")
        if not content:
            raise ValueError("LLM response was empty.")
        return content.strip()

    def _build_openai_chat_prompt(self, user_message):
        context = self._build_chat_context()
        history_lines = []
        for msg in self.chat_history[-6:]:
            role = msg.get("role")
            content = msg.get("content", "")
            if role == "user":
                history_lines.append(f"User: {content}")
            elif role == "assistant":
                history_lines.append(f"Assistant: {content}")

        history_block = "\n".join(history_lines)
        return f"Context JSON:\n{json.dumps(context, indent=2)}\n\nConversation:\n{history_block}\nUser: {user_message}"

    def _normalize_openai_endpoint(self, endpoint):
        base = endpoint.strip().rstrip("/")
        if base.endswith("/v1"):
            base = base[:-3]
        return base

    def _normalize_ollama_endpoint(self, endpoint):
        base = endpoint.strip().rstrip("/")
        if base.endswith("/v1"):
            base = base[:-3]
        return base

    _LLM_MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MB safety cap

    @staticmethod
    def _llm_http_request(url, data, timeout=30, max_retries=2, api_key=""):
        """Send an HTTP POST to an LLM endpoint with automatic retry on transient errors."""
        # Only allow http:// and https:// schemes (block file://, ftp://, etc.)
        url_lower = url.lower()
        if not (url_lower.startswith("http://") or url_lower.startswith("https://")):
            raise RuntimeError(
                f"Unsupported URL scheme: {url.split(':', 1)[0]}://\nOnly http:// and https:// endpoints are supported."
            )
        # Block sending data (PCAP analysis, sensitive network info) over
        # plain HTTP to non-local hosts, even without an API key.
        if url_lower.startswith("http://"):
            from urllib.parse import urlparse

            host = urlparse(url).hostname or ""
            if host not in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):  # nosec B104 - security check comparing hostnames, not binding
                raise RuntimeError(
                    f"Refusing to send data over unencrypted HTTP to remote host '{host}'.\n"
                    "Please use an https:// endpoint for remote LLM servers."
                )
        max_bytes = PCAPSentryApp._LLM_MAX_RESPONSE_BYTES
        last_exc = None
        for attempt in range(1 + max_retries):
            headers = {"Content-Type": "application/json"}
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
            req = urllib.request.Request(url, data=data, headers=headers)
            try:
                with _safe_urlopen(req, timeout=timeout) as resp:
                    raw = resp.read(max_bytes + 1)
                    if len(raw) > max_bytes:
                        raise RuntimeError(f"LLM response exceeded {max_bytes // (1024 * 1024)} MB limit.")
                    return raw.decode("utf-8")
            except urllib.error.HTTPError as exc:
                body = ""
                with contextlib.suppress(Exception):
                    body = exc.read().decode("utf-8", errors="replace")
                # Retry on 5xx server errors only
                if exc.code >= 500 and attempt < max_retries:
                    time.sleep(1.0 * (attempt + 1))
                    last_exc = RuntimeError(
                        f"LLM connection failed ({url}): HTTP {exc.code} {exc.reason}. {body}".strip()
                    )
                    continue
                raise RuntimeError(f"LLM connection failed ({url}): HTTP {exc.code} {exc.reason}. {body}".strip())
            except (urllib.error.URLError, OSError) as exc:
                if attempt < max_retries:
                    time.sleep(1.0 * (attempt + 1))
                    last_exc = RuntimeError(f"LLM connection failed ({url}): {exc}")
                    continue
                raise RuntimeError(f"LLM connection failed ({url}): {exc}")
        raise last_exc  # should not reach here

    def _request_openai_compat_chat(self, messages, temperature=0.3):
        endpoint = self._normalize_openai_endpoint(self.llm_endpoint_var.get() or "http://localhost:1234")
        model = self.llm_model_var.get().strip() or "local-model"
        api_key = self.llm_api_key_var.get().strip()
        url = endpoint + "/v1/chat/completions"
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": 400,
        }
        data = json.dumps(payload).encode("utf-8")
        raw = self._llm_http_request(url, data, timeout=30, api_key=api_key)

        response = json.loads(raw)
        choices = response.get("choices", [])
        if not choices:
            raise ValueError("LLM response contained no choices.")
        message = choices[0].get("message", {})
        content = message.get("content", "")
        if not content:
            raise ValueError("LLM response was empty.")
        return content.strip()

    def _send_chat_message(self):
        if not self._llm_is_enabled():
            messagebox.showwarning("Chat", "Chat is disabled. Configure an LLM provider in File → LLM Settings first.")
            return
        message = self.chat_entry_var.get().strip()
        if not message:
            return
        self.chat_entry_var.set("")
        self.chat_history.append({"role": "user", "content": message})
        # Cap chat history to prevent unbounded memory growth
        _MAX_CHAT_HISTORY = 50
        if len(self.chat_history) > _MAX_CHAT_HISTORY:
            self.chat_history = self.chat_history[-_MAX_CHAT_HISTORY:]
        self._append_chat_message("user", message)
        self.sample_note_var.set("Chat: thinking...")

        if self.chat_entry is not None:
            self.chat_entry.configure(state=tk.DISABLED)
        if self.chat_send_button is not None:
            self.chat_send_button.configure(state=tk.DISABLED)

        def task():
            return self._request_llm_chat(message)

        def done(reply):
            self.sample_note_var.set("")
            self.chat_history.append({"role": "assistant", "content": reply})
            self._append_chat_message("assistant", reply)
            if self.chat_entry is not None:
                self.chat_entry.configure(state=tk.NORMAL)
            if self.chat_send_button is not None:
                self.chat_send_button.configure(state=tk.NORMAL)

        def failed(err):
            self.sample_note_var.set("")
            _write_error_log("Chat request failed", err)
            self._append_chat_message("system", f"Chat error: {err}")
            if self.chat_entry is not None:
                self.chat_entry.configure(state=tk.NORMAL)
            if self.chat_send_button is not None:
                self.chat_send_button.configure(state=tk.NORMAL)

        self._run_task(task, done, on_error=failed, message="Chatting...")

    def _build_train_tab(self):
        container = ttk.Frame(self.train_tab, padding=14)
        container.pack(fill=tk.BOTH, expand=True)

        safe_frame = ttk.LabelFrame(container, text="  Known Safe PCAP  ", padding=12)
        safe_frame.pack(fill=tk.X, pady=10)
        self._help_icon(
            safe_frame,
            "Add a PCAP file that you KNOW contains only normal, harmless traffic "
            "(e.g., regular web browsing or office network traffic). The app learns what 'normal' "
            "looks like so it can spot abnormal patterns in future analyses. The more safe examples "
            "you add, the smarter the detection becomes.",
        )

        self.safe_path_var = tk.StringVar(value=self.settings.get("last_safe_path", ""))
        self.safe_entry = ttk.Entry(safe_frame, textvariable=self.safe_path_var, width=90)
        self.safe_entry.pack(side=tk.LEFT, padx=6)
        self._add_clear_x(self.safe_entry, self.safe_path_var)
        self.safe_browse = ttk.Button(
            safe_frame, text="Browse", style="Secondary.TButton", command=lambda: self._browse_file(self.safe_path_var)
        )
        self.safe_browse.pack(side=tk.LEFT, padx=6)
        self.safe_add_button = ttk.Button(safe_frame, text="Add to Safe", command=lambda: self._train("safe"))
        self.safe_add_button.pack(side=tk.LEFT, padx=6)
        self.undo_safe_button = ttk.Button(
            safe_frame,
            text="↩ Undo",
            style="Secondary.TButton",
            command=lambda: self._undo_last_kb_entry("safe"),
            state=tk.DISABLED,
        )
        self.undo_safe_button.pack(side=tk.LEFT, padx=6)

        ttk.Label(container, text="\u2913  You can also drag and drop a .pcap file here", style="Hint.TLabel").pack(
            anchor=tk.W, padx=16, pady=(0, 4)
        )

        mal_frame = ttk.LabelFrame(container, text="  Known Malware PCAP  ", padding=12)
        mal_frame.pack(fill=tk.X, pady=10)
        self._help_icon(
            mal_frame,
            "Add a PCAP file that contains KNOWN malicious traffic "
            "(e.g., malware samples from malware-traffic-analysis.net). This teaches the app "
            "what attack patterns look like. You can find free malicious PCAP samples at:\n\n"
            "  malware-traffic-analysis.net\n"
            "  netresec.com/?page=PcapFiles\n"
            "  cyberdefenders.org",
        )

        self.mal_path_var = tk.StringVar(value=self.settings.get("last_mal_path", ""))
        self.mal_entry = ttk.Entry(mal_frame, textvariable=self.mal_path_var, width=90)
        self.mal_entry.pack(side=tk.LEFT, padx=6)
        self._add_clear_x(self.mal_entry, self.mal_path_var)
        self.mal_browse = ttk.Button(
            mal_frame, text="Browse", style="Secondary.TButton", command=lambda: self._browse_file(self.mal_path_var)
        )
        self.mal_browse.pack(side=tk.LEFT, padx=6)
        self.mal_add_button = ttk.Button(mal_frame, text="Add to Malware", command=lambda: self._train("malicious"))
        self.mal_add_button.pack(side=tk.LEFT, padx=6)
        self.undo_mal_button = ttk.Button(
            mal_frame,
            text="↩ Undo",
            style="Secondary.TButton",
            command=lambda: self._undo_last_kb_entry("malicious"),
            state=tk.DISABLED,
        )
        self.undo_mal_button.pack(side=tk.LEFT, padx=6)

        ttk.Label(container, text="\u2913  You can also drag and drop a .pcap file here", style="Hint.TLabel").pack(
            anchor=tk.W, padx=16, pady=(0, 4)
        )

    def _build_analyze_tab(self):
        # Create a scrollable container using Canvas
        canvas = tk.Canvas(self.analyze_tab, bg=self.colors["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.analyze_tab, orient=tk.VERTICAL, command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        def on_frame_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def on_canvas_configure(event):
            # Make the scrollable_frame width match the canvas width
            canvas_width = event.width
            scrollable_frame.configure(width=canvas_width)
            canvas.itemconfig(canvas_window_id, width=canvas_width)

        scrollable_frame.bind("<Configure>", on_frame_configure)

        canvas_window_id = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind("<Configure>", on_canvas_configure)

        # Pack the canvas and scrollbar - canvas should expand
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Bind mousewheel to canvas for scrolling (widget-scoped, not global)
        def _on_mousewheel(event):
            try:
                canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
            except tk.TclError:
                pass  # Widget destroyed, ignore scroll event

        def _bind_mousewheel(_event):
            canvas.bind("<MouseWheel>", _on_mousewheel)

        def _unbind_mousewheel(_event):
            canvas.unbind("<MouseWheel>")

        canvas.bind("<Enter>", _bind_mousewheel)
        canvas.bind("<Leave>", _unbind_mousewheel)

        # Use scrollable_frame as container
        container = scrollable_frame

        file_frame = ttk.LabelFrame(container, text="  Target PCAP  ", padding=12)
        file_frame.pack(fill=tk.X, padx=16, pady=(8, 0))
        self.target_drop_area = file_frame
        self._help_icon(
            file_frame,
            "Select the PCAP file you want to analyze. A PCAP (Packet Capture) file "
            "records network traffic — every message sent between computers on a network. "
            "You can capture your own with Wireshark, or download samples to practice with.\n\n"
            "Supported formats: .pcap and .pcapng files.",
        )

        self.target_path_var = tk.StringVar(value=self.settings.get("last_target_path", ""))
        self.target_entry = ttk.Entry(file_frame, textvariable=self.target_path_var, width=90)
        self.target_entry.pack(side=tk.LEFT, padx=(0, 8))
        self._add_clear_x(self.target_entry, self.target_path_var)
        target_browse = ttk.Button(
            file_frame,
            text="Browse",
            style="Secondary.TButton",
            command=lambda: self._browse_file(self.target_path_var),
        )
        target_browse.pack(side=tk.LEFT, padx=(0, 8))
        self.analyze_button = ttk.Button(file_frame, text="\U0001f50d  Analyze", command=self._analyze)
        self.analyze_button.pack(side=tk.LEFT)

        ttk.Label(
            container, text="\u2913  You can also drag and drop a .pcap file anywhere on this tab", style="Hint.TLabel"
        ).pack(anchor=tk.W, padx=20, pady=(4, 8))

        # Label buttons frame - for marking captures
        label_frame = ttk.LabelFrame(container, text="  Label Current Capture  ", padding=12)
        label_frame.pack(fill=tk.X, padx=16, pady=(8, 0))
        self._help_icon(
            label_frame,
            "After analyzing a PCAP, you can label it as 'Safe', 'Malicious', or 'Unsure' to "
            "add it to the knowledge base. This is how the app learns from YOUR judgment. "
            "Over time, this improves detection accuracy for traffic similar to what you've labeled.\n\n"
            "Tip: Only label captures you're confident about as Safe or Malicious. "
            "Use 'Unsure' for captures you want to review later. "
            "Mislabeling teaches the app wrong patterns.",
        )
        self.label_safe_button = ttk.Button(
            label_frame,
            text="Mark as Safe",
            style="Success.TButton",
            command=lambda: self._label_current("safe"),
            state=tk.DISABLED,
        )
        self.label_safe_button.pack(side=tk.LEFT, padx=(0, 8))
        self.label_mal_button = ttk.Button(
            label_frame,
            text="Mark as Malicious",
            style="Warning.TButton",
            command=lambda: self._label_current("malicious"),
            state=tk.DISABLED,
        )
        self.label_mal_button.pack(side=tk.LEFT, padx=(0, 8))
        self.label_unsure_button = ttk.Button(
            label_frame,
            text="Mark Unsure",
            style="Secondary.TButton",
            command=lambda: self._label_current("unsure"),
            state=tk.DISABLED,
        )
        self.label_unsure_button.pack(side=tk.LEFT, padx=(0, 8))

        self.undo_kb_button = ttk.Button(
            label_frame,
            text="Undo Last",
            style="Secondary.TButton",
            command=self._undo_last_kb_entry,
            state=tk.DISABLED,
        )
        self.undo_kb_button.pack(side=tk.LEFT)

        # LLM suggestion banner (hidden until analysis completes with LLM enabled)
        self.llm_suggestion_frame = tk.Frame(
            container,
            bg=self.colors.get("panel", "#161b22"),
            highlightbackground=self.colors.get("accent", "#58a6ff"),
            highlightthickness=1,
            padx=10,
            pady=8,
        )
        # Not packed yet – shown after analysis if LLM provides a suggestion

        self.results_notebook = ttk.Notebook(container)
        self.results_notebook.pack(fill=tk.BOTH, expand=True, padx=16, pady=(12, 8))

        self.results_tab = ttk.Frame(self.results_notebook)
        self.why_tab = ttk.Frame(self.results_notebook)
        self.education_tab = ttk.Frame(self.results_notebook)
        self.packets_tab = ttk.Frame(self.results_notebook)
        self.extracted_tab = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.results_tab, text="  Results  ")
        self.results_notebook.add(self.why_tab, text="  Why  ")
        self.results_notebook.add(self.education_tab, text="  Education  ")
        self.results_notebook.add(self.packets_tab, text="  Packets  ")
        self.results_notebook.add(self.extracted_tab, text="  \U0001f511  Extracted Info  ")

        result_frame = ttk.LabelFrame(self.results_tab, text="  Results  ", padding=12)
        result_frame.pack(fill=tk.BOTH, expand=True)
        self._help_icon(
            result_frame,
            "The analysis results summary showing:\n\n"
            "  Risk Score: 0-100 rating (higher = more suspicious)\n"
            "  Verdict: Safe / Suspicious / Malicious\n"
            "  Signals: Which detection methods fired\n"
            "  Similarity: How close this traffic matches known samples\n\n"
            "Check the 'Why' tab for reasoning and 'Education' for learning.",
        )

        self.result_text = tk.Text(result_frame, height=12)
        self._style_text(self.result_text)
        self.result_text.pack(fill=tk.BOTH, expand=True)

        flow_frame = ttk.LabelFrame(self.results_tab, text="  Flow Summary  ", padding=12)
        flow_frame.pack(fill=tk.BOTH, expand=True, pady=(8, 0))
        self._help_icon(
            flow_frame,
            "A 'flow' is a conversation between two hosts (identified by their IP addresses "
            "and port numbers) using a specific protocol (TCP/UDP).\n\n"
            "Each row shows one conversation with:\n"
            "  Flow: Source IP:Port \u2192 Destination IP:Port (Protocol)\n"
            "  Packets: How many messages were exchanged\n"
            "  Bytes: Total data transferred\n"
            "  Duration: How long the conversation lasted\n\n"
            "Flows with high byte counts or long durations are worth investigating first.",
        )

        flow_cols = ("Flow", "Packets", "Bytes", "Duration")
        self.flow_table = ttk.Treeview(flow_frame, columns=flow_cols, show="headings", height=8)
        for col in flow_cols:
            self.flow_table.heading(col, text=col)
            self.flow_table.column(col, width=220 if col == "Flow" else 90, anchor=tk.W)
        self._make_treeview_sortable(self.flow_table)
        self.flow_table.pack(fill=tk.BOTH, expand=True)

        why_frame = ttk.LabelFrame(self.why_tab, text="  Why This Verdict Was Reached  ", padding=12)
        why_frame.pack(fill=tk.BOTH, expand=True)
        self._help_icon(
            why_frame,
            "Shows the specific evidence behind the verdict:\n\n"
            "  [A] ML Pattern Match — Did traffic match known malware patterns?\n"
            "  [B] Baseline Anomaly — Does it deviate from normal behavior?\n"
            "  [C] IoC Check — Were known-bad IPs or domains contacted?\n"
            "  [D-I] Traffic Details — Ports, DNS, HTTP, TLS, packet sizes\n\n"
            "Use the Wireshark filters at the bottom to investigate further.",
        )

        self.why_text = tk.Text(why_frame, height=12)
        self._style_text(self.why_text)
        self.why_text.insert(
            tk.END,
            "Run an analysis on a PCAP file to see the\n"
            "analytical reasoning behind the verdict.\n\n"
            "This tab shows the evidence and data points\n"
            "that contributed to the risk score.",
        )
        self.why_text.pack(fill=tk.BOTH, expand=True)

        why_controls = ttk.Frame(self.why_tab)
        why_controls.pack(fill=tk.X, pady=(6, 0))
        self.copy_filters_button = ttk.Button(
            why_controls, text="Copy Wireshark Filters", command=self._copy_wireshark_filters, state=tk.DISABLED
        )
        self.copy_filters_button.pack(side=tk.RIGHT)
        self._help_icon(
            why_controls,
            "Copies all auto-generated Wireshark display filters to your clipboard. "
            "Open Wireshark, load the same PCAP file, and paste a filter into the display "
            "filter bar to isolate the suspicious traffic identified by the analysis.",
            side=tk.RIGHT,
        )

        edu_frame = ttk.LabelFrame(
            self.education_tab, text="  Beginner's Guide: Why This Traffic Matters  ", padding=12
        )
        edu_frame.pack(fill=tk.BOTH, expand=True)
        self._help_icon(
            edu_frame,
            "A beginner-friendly breakdown of the analysis results. This tab:\n\n"
            "  - Explains each finding in plain English\n"
            "  - Points out specific suspicious IPs, ports, and flows\n"
            "  - Provides Wireshark filters to investigate each flow\n"
            "  - Includes a glossary of attack patterns\n"
            "  - Links to free learning resources\n\n"
            "Content updates automatically each time you analyze a new PCAP.",
        )

        self.education_text = tk.Text(edu_frame, height=12, wrap=tk.WORD)
        self._style_text(self.education_text)
        self.education_text.insert(
            tk.END,
            "Run an analysis on a PCAP file to see a beginner-friendly\n"
            "explanation of what was found and why it matters.\n\n"
            "This tab breaks down each finding in plain English,\n"
            "explains common attack patterns, and links you to\n"
            "free online resources to keep learning.",
        )
        edu_scroll = ttk.Scrollbar(edu_frame, orient=tk.VERTICAL, command=self.education_text.yview)
        self.education_text.configure(yscrollcommand=edu_scroll.set)
        edu_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.education_text.pack(fill=tk.BOTH, expand=True)

        self._build_extracted_tab()

        packet_filters = ttk.LabelFrame(self.packets_tab, text="  Packet Filters  ", padding=12)
        packet_filters.pack(fill=tk.X, pady=8)

        self.packet_proto_var = tk.StringVar(value="Any")
        self.packet_src_var = tk.StringVar()
        self.packet_dst_var = tk.StringVar()
        self.packet_sport_var = tk.StringVar()
        self.packet_dport_var = tk.StringVar()
        self.packet_time_min_var = tk.StringVar()
        self.packet_time_max_var = tk.StringVar()
        self.packet_size_min_var = tk.StringVar()
        self.packet_size_max_var = tk.StringVar()
        self.packet_dns_http_only_var = tk.BooleanVar(value=False)

        ttk.Label(packet_filters, text="Protocol:").grid(row=0, column=0, sticky="w")
        proto_combo = ttk.Combobox(
            packet_filters,
            textvariable=self.packet_proto_var,
            values=["Any", "TCP", "UDP", "Other"],
            width=8,
        )
        proto_combo.state(["readonly"])
        proto_combo.grid(row=0, column=1, sticky="w", padx=(4, 12))

        ttk.Label(packet_filters, text="Src IP:").grid(row=0, column=2, sticky="w")
        ttk.Entry(packet_filters, textvariable=self.packet_src_var, width=18).grid(
            row=0, column=3, sticky="w", padx=(4, 12)
        )
        ttk.Label(packet_filters, text="Dst IP:").grid(row=0, column=4, sticky="w")
        ttk.Entry(packet_filters, textvariable=self.packet_dst_var, width=18).grid(
            row=0, column=5, sticky="w", padx=(4, 12)
        )

        ttk.Label(packet_filters, text="Src Port:").grid(row=1, column=0, sticky="w", pady=6)
        ttk.Entry(packet_filters, textvariable=self.packet_sport_var, width=10).grid(
            row=1, column=1, sticky="w", padx=(4, 12), pady=6
        )
        ttk.Label(packet_filters, text="Dst Port:").grid(row=1, column=2, sticky="w", pady=6)
        ttk.Entry(packet_filters, textvariable=self.packet_dport_var, width=10).grid(
            row=1, column=3, sticky="w", padx=(4, 12), pady=6
        )
        time_frame = ttk.Frame(packet_filters)
        time_frame.grid(row=1, column=4, columnspan=4, sticky="w", pady=6)
        ttk.Label(time_frame, text="Time (s):").pack(side=tk.LEFT)
        ttk.Entry(time_frame, textvariable=self.packet_time_min_var, width=6).pack(side=tk.LEFT, padx=(4, 2))
        ttk.Label(time_frame, text="to").pack(side=tk.LEFT, padx=(2, 2))
        ttk.Entry(time_frame, textvariable=self.packet_time_max_var, width=6).pack(side=tk.LEFT, padx=(2, 0))

        ttk.Label(packet_filters, text="Size (bytes):").grid(row=2, column=0, sticky="w")
        ttk.Entry(packet_filters, textvariable=self.packet_size_min_var, width=8).grid(
            row=2, column=1, sticky="w", padx=(4, 4)
        )
        ttk.Label(packet_filters, text="to").grid(row=2, column=2, sticky="w")
        ttk.Entry(packet_filters, textvariable=self.packet_size_max_var, width=8).grid(
            row=2, column=3, sticky="w", padx=(4, 12)
        )
        ttk.Checkbutton(
            packet_filters,
            text="DNS/HTTP only",
            variable=self.packet_dns_http_only_var,
            style="Quiet.TCheckbutton",
        ).grid(row=2, column=4, sticky="w")

        ttk.Button(packet_filters, text="Apply", command=self._apply_packet_filters).grid(
            row=2, column=6, sticky="e", padx=(12, 4)
        )
        ttk.Button(packet_filters, text="Reset", command=self._reset_packet_filters).grid(row=2, column=7, sticky="w")

        packet_filters.grid_columnconfigure(8, weight=1)
        self._help_icon_grid(
            packet_filters,
            "Filter the packet table to isolate specific traffic. You can filter by:\n\n"
            "  Protocol: TCP, UDP, or other\n"
            "  Source/Destination IP: The sending/receiving computer\n"
            "  Source/Destination Port: The service being used\n"
            "  Time range: When the traffic occurred\n"
            "  Packet size: How big each message was\n"
            "  DNS/HTTP only: Show only name lookups and web requests\n\n"
            "Tip: Use these filters to zoom in on suspicious flows from the Education tab.",
            row=0,
            column=9,
            sticky="e",
        )

        # Place the packet table directly in the packets_tab for guaranteed visibility
        packet_table_frame = ttk.Frame(self.packets_tab)
        packet_table_frame.pack(fill=tk.BOTH, expand=True, pady=6)
        packet_cols = (
            "UTC Time",
            "RelTime",
            "Proto",
            "Src",
            "SPort",
            "Dst",
            "DPort",
            "Size",
            "DnsQuery",
            "HttpMethod",
            "HttpHost",
            "HttpPath",
            "TlsSni",
            "TlsVersion",
            "TlsAlpn",
        )
        self.packet_table = ttk.Treeview(
            packet_table_frame,
            columns=packet_cols,
            show="headings",
            height=10,
            style="Packet.Treeview",
        )
        self.packet_columns = list(packet_cols)
        self.packet_table.configure(displaycolumns=self.packet_columns)
        for col in packet_cols:
            heading = self._packet_column_label(col)
            self.packet_table.heading(col, text=heading)
            self.packet_table.column(col, width=90, anchor=tk.W, stretch=False)
        self._make_treeview_sortable(self.packet_table)

        packet_table_frame.columnconfigure(0, weight=1)
        packet_table_frame.rowconfigure(0, weight=1)
        self.packet_table.grid(row=0, column=0, sticky="nsew")

        packet_scroll = ttk.Scrollbar(packet_table_frame, orient=tk.VERTICAL, command=self.packet_table.yview)
        packet_scroll.grid(row=0, column=1, sticky="ns")
        packet_scroll_x = ttk.Scrollbar(packet_table_frame, orient=tk.HORIZONTAL, command=self.packet_table.xview)
        packet_scroll_x.grid(row=1, column=0, sticky="ew")
        self.packet_table.configure(yscrollcommand=packet_scroll.set, xscrollcommand=packet_scroll_x.set)
        self._init_packet_column_menu()
        self.packet_table.bind("<Button-3>", self._show_packet_column_menu)

        hint_frame = ttk.LabelFrame(self.packets_tab, text="  C2 / Exfil Hints  ", padding=12)
        hint_frame.pack(fill=tk.BOTH, expand=False, pady=8)
        self._help_icon(
            hint_frame,
            "Automated hints about possible Command & Control (C2) or Data Exfiltration patterns:\n\n"
            "  C2: Malware 'phoning home' to an attacker's server for instructions. "
            "Look for small, regular outbound messages to uncommon destinations.\n\n"
            "  Exfiltration: Data being stolen from the network. "
            "Look for large outbound transfers to unfamiliar external IPs.",
        )
        self.packet_hint_text = tk.Text(hint_frame, height=6)
        self._style_text(self.packet_hint_text)
        self.packet_hint_text.insert(tk.END, "Run analysis to see packet-level hints.")
        self.packet_hint_text.pack(fill=tk.BOTH, expand=True)

        self.charts_button = ttk.Button(container, text="Open Charts", command=self._open_charts, state=tk.DISABLED)
        self.charts_button.pack(side=tk.RIGHT, anchor=tk.E, pady=10)
        self._help_icon(
            container,
            "Opens visual charts of the analyzed traffic including:\n\n"
            "  Timeline: When traffic occurred during the capture\n"
            "  Ports: Which network services were used\n"
            "  Protocols: TCP vs UDP vs other breakdown\n"
            "  DNS: Most-queried domain names\n"
            "  HTTP: Most-visited web hosts\n"
            "  TLS: Encrypted connection destinations\n"
            "  Flows: Largest conversations by data volume",
            side=tk.RIGHT,
        )

        widgets = [
            self.safe_browse,
            self.safe_add_button,
            self.mal_browse,
            self.mal_add_button,
            target_browse,
            self.analyze_button,
            self.charts_button,
            self.label_safe_button,
            self.label_mal_button,
        ]
        self.busy_widgets.extend([widget for widget in widgets if widget is not None])

        self._setup_drag_drop()

    def _make_treeview_sortable(self, tree):
        """Make all columns in a Treeview sortable by clicking the header,
        and add a right-click context menu with alignment options."""
        for col in tree["columns"]:
            tree.heading(col, command=lambda _col=col: self._treeview_sort_column(tree, _col, False))
        # Attach right-click alignment menu
        tree.bind("<Button-3>", lambda event, t=tree: self._show_column_align_menu(event, t))

    def _show_column_align_menu(self, event, tree):
        """Show a right-click context menu on column headers with alignment options."""
        region = tree.identify_region(event.x, event.y)
        if region != "heading":
            return
        col_id = tree.identify_column(event.x)  # returns '#1', '#2', etc.
        if not col_id or col_id == "#0":
            return
        # Convert '#N' to column name
        col_index = int(col_id.replace("#", "")) - 1
        columns = list(tree["columns"])
        if col_index < 0 or col_index >= len(columns):
            return
        col_name = columns[col_index]

        # Unicode arrow characters for column menu
        arrows = "\u25b2\u25bc"
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(
            label=f"\u2550  Column: {tree.heading(col_name, 'text').rstrip(' ' + arrows)}", state=tk.DISABLED
        )
        menu.add_separator()
        menu.add_command(label="\u25c0  Align Left", command=lambda: self._set_column_align(tree, col_name, tk.W))
        menu.add_command(
            label="\u25c6  Align Center", command=lambda: self._set_column_align(tree, col_name, tk.CENTER)
        )
        menu.add_command(label="\u25b6  Align Right", command=lambda: self._set_column_align(tree, col_name, tk.E))
        menu.add_separator()
        menu.add_command(label="\u25c0  Align ALL Left", command=lambda: self._set_all_columns_align(tree, tk.W))
        menu.add_command(label="\u25c6  Align ALL Center", command=lambda: self._set_all_columns_align(tree, tk.CENTER))
        menu.add_command(label="\u25b6  Align ALL Right", command=lambda: self._set_all_columns_align(tree, tk.E))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _set_column_align(self, tree, col_name, anchor):
        """Set the alignment of a single column."""
        tree.column(col_name, anchor=anchor)

    def _set_all_columns_align(self, tree, anchor):
        """Set the alignment of all columns in a Treeview."""
        for col in tree["columns"]:
            tree.column(col, anchor=anchor)

    def _treeview_sort_column(self, tree, col, reverse):
        """Sort a Treeview column. Detects numeric values automatically."""
        data = []
        for iid in tree.get_children(""):
            val = tree.set(iid, col)
            # Try numeric sort first
            try:
                sort_key = float(val.replace(",", ""))
            except (ValueError, AttributeError):
                sort_key = val.lower() if isinstance(val, str) else val
            data.append((sort_key, iid))

        data.sort(key=lambda t: t[0], reverse=reverse)

        for idx, (_, iid) in enumerate(data):
            tree.move(iid, "", idx)

        # Toggle sort direction on next click; update header with arrow indicator
        arrow = " \u25bc" if reverse else " \u25b2"
        # Reset all other column headings (remove arrows)
        for c in tree["columns"]:
            heading_text = tree.heading(c, "text")
            heading_text = heading_text.rstrip(" \u25b2\u25bc")
            tree.heading(c, text=heading_text, command=lambda _c=c: self._treeview_sort_column(tree, _c, False))
        # Set current column heading with arrow
        current_text = tree.heading(col, "text").rstrip(" \u25b2\u25bc")
        tree.heading(col, text=current_text + arrow, command=lambda: self._treeview_sort_column(tree, col, not reverse))

    def _build_extracted_tab(self):
        """Build the Extracted Info tab for credentials, hosts, and MAC addresses."""
        container = ttk.Frame(self.extracted_tab, padding=12)
        container.pack(fill=tk.BOTH, expand=True)

        # -- Key Findings summary panel --
        summary_frame = ttk.LabelFrame(container, text="  \U0001f6a8  Key Findings  ", padding=12)
        summary_frame.pack(fill=tk.X, pady=(0, 12))

        summary_text_frame = ttk.Frame(summary_frame)
        summary_text_frame.pack(fill=tk.BOTH, expand=True)

        self.extracted_summary_text = tk.Text(summary_text_frame, height=8, wrap=tk.WORD)
        self._style_text(self.extracted_summary_text)
        self.extracted_summary_text.insert(tk.END, "Run an analysis to see extracted credentials and host information.")
        # Configure highlight tags for the summary
        self.extracted_summary_text.tag_configure("heading", font=("Segoe UI", 12, "bold"))
        self.extracted_summary_text.tag_configure(
            "username_tag", foreground=self.colors["accent"], font=("Consolas", 11, "bold")
        )
        self.extracted_summary_text.tag_configure(
            "password_tag", foreground=self.colors["danger"], font=("Consolas", 11, "bold")
        )
        self.extracted_summary_text.tag_configure(
            "hostname_tag", foreground=self.colors["success"], font=("Consolas", 11, "bold")
        )
        self.extracted_summary_text.tag_configure("label_dim", foreground=self.colors["muted"], font=("Segoe UI", 10))
        self.extracted_summary_text.tag_configure("separator", foreground=self.colors["border_light"])

        summary_scrollbar = ttk.Scrollbar(
            summary_text_frame, orient=tk.VERTICAL, command=self.extracted_summary_text.yview
        )
        self.extracted_summary_text.configure(yscrollcommand=summary_scrollbar.set)
        self.extracted_summary_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        summary_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # -- Credentials table --
        cred_frame = ttk.LabelFrame(container, text="  All Extracted Items  ", padding=12)
        cred_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 0))
        self._help_icon(
            cred_frame,
            "All credentials and auth tokens found in UNENCRYPTED traffic.\n\n"
            "Row colors:\n"
            "  \u2588 Red — Passwords / secrets\n"
            "  \u2588 Blue — Usernames / accounts\n"
            "  \u2588 Green — Computer names / hostnames\n"
            "  \u2588 Yellow — Cookies / tokens\n\n"
            "Supported: FTP, HTTP, SMTP, POP3, IMAP, Telnet, SNMP, Kerberos",
        )

        cred_cols = ("Type", "Protocol", "Source", "Destination", "Value", "Detail")
        cred_table_frame = ttk.Frame(cred_frame)
        cred_table_frame.pack(fill=tk.BOTH, expand=True)

        self.cred_table = ttk.Treeview(
            cred_table_frame,
            columns=cred_cols,
            show="headings",
            height=10,
        )
        col_widths = {"Type": 105, "Protocol": 90, "Source": 130, "Destination": 130, "Value": 250, "Detail": 160}
        for col in cred_cols:
            self.cred_table.heading(col, text=col)
            self.cred_table.column(col, width=col_widths.get(col, 120), anchor=tk.W, stretch=True)

        # Color tags for credential rows
        self.cred_table.tag_configure("password", foreground=self.colors["danger"], font=("Consolas", 10, "bold"))
        self.cred_table.tag_configure("username", foreground=self.colors["accent"], font=("Consolas", 10, "bold"))
        self.cred_table.tag_configure("hostname", foreground=self.colors["success"], font=("Consolas", 10))
        self.cred_table.tag_configure("cookie", foreground=self.colors["warning"], font=("Consolas", 10))
        self.cred_table.tag_configure("other", font=("Consolas", 10))
        self._make_treeview_sortable(self.cred_table)

        cred_scroll_y = ttk.Scrollbar(cred_table_frame, orient=tk.VERTICAL, command=self.cred_table.yview)
        cred_scroll_x = ttk.Scrollbar(cred_table_frame, orient=tk.HORIZONTAL, command=self.cred_table.xview)
        self.cred_table.configure(yscrollcommand=cred_scroll_y.set, xscrollcommand=cred_scroll_x.set)

        self.cred_table.grid(row=0, column=0, sticky="nsew")
        cred_scroll_y.grid(row=0, column=1, sticky="ns")
        cred_scroll_x.grid(row=1, column=0, sticky="ew")
        cred_table_frame.columnconfigure(0, weight=1)
        cred_table_frame.rowconfigure(0, weight=1)

        cred_controls = ttk.Frame(cred_frame)
        cred_controls.pack(fill=tk.X, pady=(8, 0))
        self.cred_count_var = tk.StringVar(value="No credentials extracted yet.")
        ttk.Label(cred_controls, textvariable=self.cred_count_var, style="Hint.TLabel").pack(side=tk.LEFT)
        ttk.Button(cred_controls, text="Copy All", style="Secondary.TButton", command=self._copy_extracted_creds).pack(
            side=tk.RIGHT, padx=4
        )

        # -- Hosts / MAC / Hostname section --
        host_frame = ttk.LabelFrame(container, text="  Hosts \u2014 IP / MAC / Computer Name  ", padding=8)
        host_frame.pack(fill=tk.BOTH, expand=True, pady=(6, 0))
        self._help_icon(
            host_frame,
            "Every IP address seen in the capture, along with:\n\n"
            "  MAC address \u2014 The hardware address of the network interface\n"
            "  Computer Name \u2014 Names learned from DNS, DHCP, SMTP EHLO, NetBIOS\n\n"
            "MAC addresses are only available for traffic on the same Layer-2\n"
            "segment as the capture point.",
        )

        host_cols = ("IP Address", "MAC Address(es)", "Computer / Hostname")
        host_table_frame = ttk.Frame(host_frame)
        host_table_frame.pack(fill=tk.BOTH, expand=True)

        self.host_table = ttk.Treeview(
            host_table_frame,
            columns=host_cols,
            show="headings",
            height=8,
        )
        host_col_widths = {"IP Address": 150, "MAC Address(es)": 200, "Computer / Hostname": 350}
        for col in host_cols:
            self.host_table.heading(col, text=col)
            self.host_table.column(col, width=host_col_widths.get(col, 150), anchor=tk.W, stretch=True)

        self.host_table.tag_configure("has_name", foreground=self.colors["success"], font=("Consolas", 10, "bold"))
        self.host_table.tag_configure("no_name", font=("Consolas", 10))
        self._make_treeview_sortable(self.host_table)

        host_scroll_y = ttk.Scrollbar(host_table_frame, orient=tk.VERTICAL, command=self.host_table.yview)
        host_scroll_x = ttk.Scrollbar(host_table_frame, orient=tk.HORIZONTAL, command=self.host_table.xview)
        self.host_table.configure(yscrollcommand=host_scroll_y.set, xscrollcommand=host_scroll_x.set)

        self.host_table.grid(row=0, column=0, sticky="nsew")
        host_scroll_y.grid(row=0, column=1, sticky="ns")
        host_scroll_x.grid(row=1, column=0, sticky="ew")
        host_table_frame.columnconfigure(0, weight=1)
        host_table_frame.rowconfigure(0, weight=1)

        host_controls = ttk.Frame(host_frame)
        host_controls.pack(fill=tk.X, pady=(4, 0))
        self.host_count_var = tk.StringVar(value="No host data extracted yet.")
        ttk.Label(host_controls, textvariable=self.host_count_var, style="Hint.TLabel").pack(side=tk.LEFT)
        ttk.Button(host_controls, text="Copy All", style="Secondary.TButton", command=self._copy_extracted_hosts).pack(
            side=tk.RIGHT, padx=4
        )

    @staticmethod
    def _classify_cred_field(field_str):
        """Classify a credential field as username, password, hostname, cookie, or other."""
        f = field_str.lower()
        if any(kw in f for kw in ("password", "pass ", "passwd", "secret", "pw")):
            return "password", "\U0001f534 PASSWORD"
        if any(kw in f for kw in ("username", "user", "login", "account", "email", "acct", "mail from", "principal")):
            return "username", "\U0001f535 USERNAME"
        if any(kw in f for kw in ("ehlo", "helo", "hostname", "computer", "host")):
            return "hostname", "\U0001f7e2 COMPUTER"
        if any(kw in f for kw in ("cookie", "set-cookie", "token", "ntlm", "auth-data")):
            return "cookie", "\U0001f7e1 TOKEN"
        if "community" in f:
            return "password", "\U0001f534 SECRET"
        if "prompt" in f:
            return "other", "\u2753 PROMPT"
        return "other", "\u2796 OTHER"

    def _populate_extracted_tab(self, extracted_data):
        """Populate the Extracted Info tab with results from extract_credentials_and_hosts()."""
        creds = extracted_data.get("credentials", [])
        hosts = extracted_data.get("hosts", {})

        # ── Build Key Findings summary ──
        self.extracted_summary_text.delete("1.0", tk.END)

        usernames = []
        passwords = []
        computernames = set()

        for cred in creds:
            cat, _ = self._classify_cred_field(cred.get("field", ""))
            if cat == "username":
                usernames.append(cred)
            elif cat == "password":
                passwords.append(cred)
            elif cat == "hostname":
                name_val = cred.get("value", "")
                if name_val:
                    computernames.add(name_val)

        # Also gather hostnames from the host table
        for ip, info in hosts.items():
            for h in info.get("hostnames", []):
                computernames.add(h)

        t = self.extracted_summary_text
        if not creds and not computernames:
            t.insert(tk.END, "No credentials or computer names found.\n\n", "label_dim")
            t.insert(
                tk.END, "This is normal for captures that only contain encrypted (TLS/SSL) traffic.\n", "label_dim"
            )
        else:
            # Usernames
            t.insert(tk.END, "\U0001f464  USERNAMES FOUND", "heading")
            if usernames:
                t.insert(tk.END, f"  ({len(usernames)})\n", "label_dim")
                for u in usernames:
                    t.insert(tk.END, f"    {u['value']}", "username_tag")
                    t.insert(tk.END, f"  ({u['protocol']}  {u['src']} \u2192 {u['dst']})\n", "label_dim")
            else:
                t.insert(tk.END, "  \u2014 none \u2014\n", "label_dim")

            t.insert(tk.END, "\n")

            # Passwords
            t.insert(tk.END, "\U0001f511  PASSWORDS / SECRETS FOUND", "heading")
            if passwords:
                t.insert(tk.END, f"  ({len(passwords)})\n", "label_dim")
                for p in passwords:
                    t.insert(tk.END, f"    {p['value']}", "password_tag")
                    detail = p.get("detail", "")
                    extra = f"  {detail}" if detail else ""
                    t.insert(tk.END, f"  ({p['protocol']}  {p['src']} \u2192 {p['dst']}{extra})\n", "label_dim")
            else:
                t.insert(tk.END, "  \u2014 none \u2014\n", "label_dim")

            t.insert(tk.END, "\n")

            # Computer names
            t.insert(tk.END, "\U0001f4bb  COMPUTER / HOST NAMES", "heading")
            sorted_names = sorted(computernames)
            if sorted_names:
                t.insert(tk.END, f"  ({len(sorted_names)})\n", "label_dim")
                for name in sorted_names:
                    t.insert(tk.END, f"    {name}\n", "hostname_tag")
            else:
                t.insert(tk.END, "  \u2014 none \u2014\n", "label_dim")

        # ── Credentials table ──
        self.cred_table.delete(*self.cred_table.get_children())

        for cred in creds:
            cat, type_label = self._classify_cred_field(cred.get("field", ""))
            self.cred_table.insert(
                "",
                tk.END,
                values=(
                    type_label,
                    cred.get("protocol", ""),
                    cred.get("src", ""),
                    cred.get("dst", ""),
                    cred.get("value", ""),
                    cred.get("detail", ""),
                ),
                tags=(cat,),
            )

        if creds:
            n_user = len([c for c in creds if self._classify_cred_field(c.get("field", ""))[0] == "username"])
            n_pass = len([c for c in creds if self._classify_cred_field(c.get("field", ""))[0] == "password"])
            self.cred_count_var.set(
                f"{len(creds)} item(s)  |  {n_user} username(s)  |  {n_pass} password(s)  |  "
                f"{len(computernames)} computer name(s)"
            )
        else:
            self.cred_count_var.set("No credentials or auth data found in cleartext traffic.")

        # ── Host table ──
        self.host_table.delete(*self.host_table.get_children())

        def _ip_sort_key(ip_str):
            try:
                return ipaddress.ip_address(ip_str).packed
            except Exception:
                return ip_str.encode()

        for ip in sorted(hosts.keys(), key=_ip_sort_key):
            info = hosts[ip]
            macs = ", ".join(info.get("mac", []))
            hostnames = ", ".join(info.get("hostnames", []))
            tag = "has_name" if hostnames else "no_name"
            self.host_table.insert("", tk.END, values=(ip, macs, hostnames), tags=(tag,))

        self.host_count_var.set(
            f"{len(hosts)} unique IP(s), "
            f"{sum(len(v.get('mac', [])) for v in hosts.values())} MAC(s), "
            f"{sum(len(v.get('hostnames', [])) for v in hosts.values())} hostname(s)"
        )

    def _copy_extracted_creds(self):
        """Copy all extracted credentials to clipboard as tab-separated text."""
        lines = ["Type\tProtocol\tSource\tDestination\tValue\tDetail"]
        for item in self.cred_table.get_children():
            vals = self.cred_table.item(item, "values")
            lines.append("\t".join(str(v) for v in vals))
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(lines))
        self.status_var.set(f"Copied {len(lines) - 1} credential row(s) to clipboard.")

    def _copy_extracted_hosts(self):
        """Copy all extracted host info to clipboard as tab-separated text."""
        lines = ["IP Address\tMAC Address(es)\tComputer / Hostname"]
        for item in self.host_table.get_children():
            vals = self.host_table.item(item, "values")
            lines.append("\t".join(str(v) for v in vals))
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(lines))
        self.status_var.set(f"Copied {len(lines) - 1} host row(s) to clipboard.")

    def _build_kb_tab(self):
        container = ttk.Frame(self.kb_tab, padding=14)
        container.pack(fill=tk.BOTH, expand=True)

        header = ttk.Frame(container)
        header.pack(fill=tk.X, pady=(0, 8))
        self.kb_summary_var = tk.StringVar(value="")
        ttk.Label(header, textvariable=self.kb_summary_var).pack(side=tk.LEFT)
        self._help_icon(
            header,
            "The Knowledge Base stores patterns from PCAPs you've labeled as safe or malicious. "
            "It's the app's memory — the more examples you add, the better it detects threats.\n\n"
            "  Refresh: Reload the KB from disk\n"
            "  Backup: Save a copy of your KB to a file\n"
            "  Restore: Load a previously saved KB backup\n"
            "  Reset: Erase all learned patterns (cannot be undone!)",
        )
        ttk.Button(header, text="Refresh", style="Secondary.TButton", command=self._refresh_kb).pack(side=tk.RIGHT)
        ttk.Button(header, text="Reset Knowledge Base", style="DangerMuted.TButton", command=self._reset_kb).pack(
            side=tk.RIGHT, padx=6
        )
        ttk.Button(header, text="Restore", style="Secondary.TButton", command=self._restore_kb).pack(
            side=tk.RIGHT, padx=6
        )
        ttk.Button(header, text="Backup", style="Secondary.TButton", command=self._backup_kb).pack(
            side=tk.RIGHT, padx=6
        )

        # Unsure items review section
        unsure_frame = ttk.LabelFrame(container, text="  Unsure Items  ", padding=12)
        unsure_frame.pack(fill=tk.X, pady=8)
        self._help_icon(
            unsure_frame,
            "Items marked as 'Unsure' are stored here for review. "
            "Review them when you have more information or context to make a confident decision.\n\n"
            "You can reclassify unsure items as Safe or Malicious, or keep them unsure for later.",
        )
        ttk.Button(unsure_frame, text="Review Unsure Items", command=self._review_unsure_items).pack(side=tk.LEFT)
        self.unsure_count_var = tk.StringVar(value="0 items")
        ttk.Label(unsure_frame, textvariable=self.unsure_count_var).pack(side=tk.LEFT, padx=(12, 0))

        ioc_frame = ttk.LabelFrame(container, text="  IoC Feed  ", padding=12)
        ioc_frame.pack(fill=tk.X, pady=8)
        self._help_icon(
            ioc_frame,
            "IoC = Indicator of Compromise. These are lists of known-bad IP addresses, "
            "domains, and file hashes maintained by security researchers.\n\n"
            "Import a CSV or text file containing IoCs, and the app will check every analyzed "
            "PCAP against this list. Any traffic to/from a listed address gets flagged.\n\n"
            "Free IoC sources:\n"
            "  AlienVault OTX (otx.alienvault.com)\n"
            "  Abuse.ch (abuse.ch)\n"
            "  CIRCL (circl.lu)",
        )
        ttk.Label(ioc_frame, text="IoC file:").pack(side=tk.LEFT)
        ioc_entry = ttk.Entry(ioc_frame, textvariable=self.ioc_path_var, width=70)
        ioc_entry.pack(side=tk.LEFT, padx=6)
        ttk.Button(
            ioc_frame, text="\u2715", width=2, style="Secondary.TButton", command=lambda: self.ioc_path_var.set("")
        ).pack(side=tk.LEFT)
        ttk.Button(ioc_frame, text="Browse", style="Secondary.TButton", command=self._browse_ioc).pack(
            side=tk.LEFT, padx=6
        )
        ttk.Button(ioc_frame, text="Import", command=self._load_ioc_file).pack(side=tk.LEFT, padx=6)
        ttk.Button(ioc_frame, text="Clear", style="Secondary.TButton", command=self._clear_iocs).pack(
            side=tk.LEFT, padx=6
        )

    def _reset_packet_filters(self):
        if self.packet_proto_var is None:
            return
        self.packet_proto_var.set("Any")
        self.packet_src_var.set("")
        self.packet_dst_var.set("")
        self.packet_sport_var.set("")
        self.packet_dport_var.set("")
        self.packet_time_min_var.set("")
        self.packet_time_max_var.set("")
        self.packet_size_min_var.set("")
        self.packet_size_max_var.set("")
        self.packet_dns_http_only_var.set(False)
        self._apply_packet_filters()

    def _apply_packet_filters(self):
        if self.current_df is None or self.packet_table is None:
            return

        df = self.current_df
        if df.empty:
            self._update_packet_table(df)
            return

        pd = _get_pandas()
        mask = pd.Series(True, index=df.index)

        # Apply packet filters using a combined mask (avoids full DataFrame copy)
        proto_filter = self.packet_proto_var.get() if self.packet_proto_var else "Any"
        if proto_filter != "Any" and "Proto" in df.columns:
            mask &= df["Proto"] == proto_filter

        src_filter = self.packet_src_var.get() if self.packet_src_var else ""
        if src_filter and "Src" in df.columns:
            mask &= df["Src"].astype(str).str.contains(src_filter, na=False, regex=False)

        dst_filter = self.packet_dst_var.get() if self.packet_dst_var else ""
        if dst_filter and "Dst" in df.columns:
            mask &= df["Dst"].astype(str).str.contains(dst_filter, na=False, regex=False)

        sport_filter = self.packet_sport_var.get() if self.packet_sport_var else ""
        if sport_filter and "SPort" in df.columns:
            try:
                sport_val = int(sport_filter)
                mask &= df["SPort"] == sport_val
            except ValueError:
                pass

        dport_filter = self.packet_dport_var.get() if self.packet_dport_var else ""
        if dport_filter and "DPort" in df.columns:
            try:
                dport_val = int(dport_filter)
                mask &= df["DPort"] == dport_val
            except ValueError:
                pass

        base_time = self.packet_base_time if self.packet_base_time is not None else 0.0

        time_min = self.packet_time_min_var.get() if self.packet_time_min_var else ""
        if time_min and "Time" in df.columns:
            try:
                time_min_val = float(time_min)
                mask &= (df["Time"] - base_time) >= time_min_val
            except ValueError:
                pass

        time_max = self.packet_time_max_var.get() if self.packet_time_max_var else ""
        if time_max and "Time" in df.columns:
            try:
                time_max_val = float(time_max)
                mask &= (df["Time"] - base_time) <= time_max_val
            except ValueError:
                pass

        size_min = self.packet_size_min_var.get() if self.packet_size_min_var else ""
        if size_min and "Size" in df.columns:
            try:
                size_min_val = int(size_min)
                mask &= df["Size"] >= size_min_val
            except ValueError:
                pass

        size_max = self.packet_size_max_var.get() if self.packet_size_max_var else ""
        if size_max and "Size" in df.columns:
            try:
                size_max_val = int(size_max)
                mask &= df["Size"] <= size_max_val
            except ValueError:
                pass

        dns_http_only = self.packet_dns_http_only_var.get() if self.packet_dns_http_only_var else False
        if dns_http_only:
            mask &= (df["DnsQuery"].fillna("").astype(str) != "") | (df["HttpHost"].fillna("").astype(str) != "")

        # Copy only the filtered subset, not the entire DataFrame
        result = df.loc[mask].copy()
        if self.packet_base_time is not None and "Time" in result.columns:
            result["RelTime"] = result["Time"] - self.packet_base_time
        else:
            result["RelTime"] = 0.0

        self._update_packet_table(result)

    def _update_packet_table(self, df):
        if self.packet_table is None:
            return
        self.packet_table.delete(*self.packet_table.get_children())

        if df is None or df.empty:
            return

        columns = [
            "UTC Time",
            "RelTime",
            "Proto",
            "Src",
            "SPort",
            "Dst",
            "DPort",
            "Size",
            "DnsQuery",
            "HttpMethod",
            "HttpHost",
            "HttpPath",
            "TlsSni",
            "TlsVersion",
            "TlsAlpn",
        ]
        # Ensure all expected columns exist in the DataFrame
        for col in [c for c in columns if c not in ("UTC Time", "RelTime")]:
            if col not in df.columns:
                df[col] = ""
        # Limit to 500 rows and notify user if truncated (P5 fix)
        total_rows = len(df)
        display_limit = 500
        display_df = df.head(display_limit)
        rows_for_size = []
        for row in display_df.itertuples(index=False):
            row_dict = row._asdict()
            values = [self._format_packet_table_value(row_dict, col) for col in columns]
            self.packet_table.insert("", tk.END, values=values)
            rows_for_size.append(values)
        self._autosize_packet_table(columns, rows_for_size)
        # Show truncation notice if applicable
        if total_rows > display_limit:
            self.sample_note_var.set(f"Showing {display_limit} of {total_rows:,} packets (use filters to narrow)")
        else:
            self.sample_note_var.set("")

    def _format_packet_table_value(self, row, col):
        # Always use 'Time' for 'UTC Time' display
        if col == "UTC Time":
            try:
                time_val = row.get("Time", None)
                if time_val is not None:
                    value = datetime.fromtimestamp(float(time_val), timezone.utc)
                    return value.strftime("%Y-%m-%d %H:%M:%SZ")
                return ""
            except Exception:
                return ""
        value = row.get(col, "")
        if col == "RelTime":
            try:
                return f"{float(value):.3f}"
            except Exception:
                return ""
        return "" if value is None else str(value)

    def _autosize_packet_table(self, columns, rows):
        if self.packet_table is None:
            return

        try:
            font = tkfont.nametofont(self.packet_table.cget("font"))
        except Exception:
            return

        padding = 14
        min_width = 70
        max_widths = {
            "UTC Time": 170,
            "RelTime": 90,
            "Src": 200,
            "Dst": 200,
            "DnsQuery": 260,
            "HttpMethod": 120,
            "HttpHost": 260,
            "HttpPath": 360,
            "TlsSni": 260,
            "TlsVersion": 120,
            "TlsAlpn": 200,
        }

        for index, col in enumerate(columns):
            width = font.measure(col) + padding
            for row in rows:
                if index >= len(row):
                    continue
                candidate = font.measure(str(row[index])) + padding
                width = max(width, candidate)
            width = max(width, min_width)
            width = min(width, max_widths.get(col, 220))
            self.packet_table.column(col, width=width, anchor=tk.W, stretch=False)

    def _init_packet_column_menu(self):
        if self.packet_table is None:
            return
        self.packet_column_menu = tk.Menu(self.root, tearoff=0)
        self.packet_column_vars = {}
        for col in self.packet_columns or []:
            self.packet_column_vars[col] = tk.BooleanVar(value=True)

    def _rebuild_packet_column_menu(self):
        if self.packet_column_menu is None or self.packet_column_vars is None:
            return
        self.packet_column_menu.delete(0, tk.END)
        for col in self.packet_columns or []:
            label = self._packet_column_label(col)
            self.packet_column_menu.add_checkbutton(
                label=label,
                variable=self.packet_column_vars[col],
                command=lambda name=col: self._toggle_packet_column(name),
            )

    def _toggle_packet_column(self, column):
        if self.packet_table is None or self.packet_column_vars is None:
            return
        visible = [col for col in self.packet_columns or [] if self.packet_column_vars[col].get()]
        if not visible:
            self.packet_column_vars[column].set(True)
            return
        self.packet_table.configure(displaycolumns=visible)

    def _show_packet_column_menu(self, event):
        if self.packet_table is None or self.packet_column_menu is None:
            return
        if self.packet_table.identify_region(event.x, event.y) != "heading":
            return
        self._rebuild_packet_column_menu()

        # Add alignment options for the clicked column
        col_id = self.packet_table.identify_column(event.x)
        if col_id and col_id != "#0":
            col_index = int(col_id.replace("#", "")) - 1
            columns = list(self.packet_table["columns"])
            if 0 <= col_index < len(columns):
                col_name = columns[col_index]
                self.packet_column_menu.add_separator()
                heading_text = self.packet_table.heading(col_name, "text").rstrip(" \u25b2\u25bc")
                self.packet_column_menu.add_command(label=f"\u2550  Align: {heading_text}", state=tk.DISABLED)
                self.packet_column_menu.add_command(
                    label="\u25c0  Align Left",
                    command=lambda: self._set_column_align(self.packet_table, col_name, tk.W),
                )
                self.packet_column_menu.add_command(
                    label="\u25c6  Align Center",
                    command=lambda: self._set_column_align(self.packet_table, col_name, tk.CENTER),
                )
                self.packet_column_menu.add_command(
                    label="\u25b6  Align Right",
                    command=lambda: self._set_column_align(self.packet_table, col_name, tk.E),
                )
                self.packet_column_menu.add_separator()
                self.packet_column_menu.add_command(
                    label="\u25c0  Align ALL Left", command=lambda: self._set_all_columns_align(self.packet_table, tk.W)
                )
                self.packet_column_menu.add_command(
                    label="\u25c6  Align ALL Center",
                    command=lambda: self._set_all_columns_align(self.packet_table, tk.CENTER),
                )
                self.packet_column_menu.add_command(
                    label="\u25b6  Align ALL Right",
                    command=lambda: self._set_all_columns_align(self.packet_table, tk.E),
                )

        try:
            self.packet_column_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.packet_column_menu.grab_release()

    def _packet_column_label(self, column):
        labels = {
            "Proto": "Protocol",
            "DnsQuery": "DNS Query",
            "HttpMethod": "HTTP Method",
            "HttpHost": "HTTP Host",
            "HttpPath": "HTTP Path",
            "TlsSni": "TLS SNI",
            "TlsVersion": "TLS Ver",
            "TlsAlpn": "ALPN",
        }
        return labels.get(column, column)

    def _update_packet_hints(self, df, stats, flow_df=None):
        if self.packet_hint_text is None:
            return

        hint_lines = ["Focus areas for C2 / exfil review:"]

        if flow_df is None:
            flow_df = compute_flow_stats(df)
        if not flow_df.empty:
            flow_df["Duration"] = flow_df["Duration"].fillna(0.0)
            long_lived = flow_df[flow_df["Duration"] >= 60.0]
            if not long_lived.empty:
                top_flow = long_lived.sort_values("Bytes", ascending=False).head(1)
                row = top_flow.iloc[0]
                hint_lines.append(
                    f"- Long-lived flow: {row['Flow']} ({row['Duration']:.1f}s, {_format_bytes(row['Bytes'])})"
                )

            if not flow_df["Bytes"].empty:
                high_bytes_threshold = float(flow_df["Bytes"].quantile(0.95))
                large_flows = flow_df[flow_df["Bytes"] >= high_bytes_threshold]
                if not large_flows.empty:
                    row = large_flows.sort_values("Bytes", ascending=False).iloc[0]
                    hint_lines.append(f"- Large transfer: {row['Flow']} ({_format_bytes(row['Bytes'])})")

        beacon_flow = None
        if not df.empty:
            flow_cols = ["Src", "Dst", "Proto", "SPort", "DPort"]
            grouped = df.groupby(flow_cols, dropna=False)
            for keys, group in grouped:
                if len(group) < 6:
                    continue
                times = sorted(group["Time"].tolist())
                gaps = [b - a for a, b in itertools.pairwise(times) if b - a > 0]
                if len(gaps) < 5:
                    continue
                avg_gap = sum(gaps) / len(gaps)
                if avg_gap <= 0:
                    continue
                std_gap = statistics.pstdev(gaps)
                cv = std_gap / avg_gap if avg_gap else 0.0
                if cv < 0.35:
                    flow_str = f"{keys[0]}:{keys[3]} -> {keys[1]}:{keys[4]} ({keys[2]})"
                    beacon_flow = (flow_str, avg_gap)
                    break

        if beacon_flow:
            hint_lines.append(f"- Beaconing-like cadence: {beacon_flow[0]} (~{beacon_flow[1]:.2f}s interval)")
        else:
            hint_lines.append("- Beaconing cadence: not obvious in top flows")

        top_ports = stats.get("top_ports", [])
        if top_ports:
            unusual_ports = [str(port) for port, _ in top_ports if port not in COMMON_PORTS]
            malware_flagged = [str(port) for port, _ in top_ports if port in MALWARE_PORTS]
            if malware_flagged:
                hint_lines.append(f"- ⚠ Known malware/C2 ports: {', '.join(malware_flagged)}")
            if unusual_ports:
                hint_lines.append(f"- Unusual top ports: {', '.join(unusual_ports)}")

        if stats.get("dns_query_count", 0) == 0 and stats.get("http_request_count", 0) == 0:
            hint_lines.append("- No DNS/HTTP observed: focus on raw TCP/UDP flows")

        tls_count = stats.get("tls_packet_count", 0)
        if tls_count:
            top_sni = stats.get("top_tls_sni", [])
            if top_sni:
                sni_text = ", ".join(f"{host} ({count})" for host, count in top_sni)
                hint_lines.append(f"- TLS SNI observed: {sni_text}")
            else:
                hint_lines.append(f"- TLS packets observed: {tls_count}")

        self.packet_hint_text.delete("1.0", tk.END)
        self.packet_hint_text.insert(tk.END, "\n".join(hint_lines))

    def _build_wireshark_filters(self, stats, ioc_matches, verdict, suspicious_flows=None):
        if verdict == "Likely Safe":
            return []

        filters = []
        domains = ioc_matches.get("domains", [])
        ips = ioc_matches.get("ips", [])
        top_ports = stats.get("top_ports", [])

        for domain in domains[:3]:
            filters.append(f'dns.qry.name == "{domain}"')
            filters.append(f'http.host == "{domain}"')

        for ip in ips[:3]:
            filters.append(f"ip.addr == {ip}")

        # Add filters for known malware ports found in traffic
        malware_port_hits = [p for p, _ in top_ports if p in MALWARE_PORTS]
        if malware_port_hits:
            port_str = ", ".join(str(p) for p in malware_port_hits[:5])
            filters.append(f"tcp.port in {{{port_str}}} or udp.port in {{{port_str}}}")
        elif top_ports:
            port_values = [str(port) for port, _ in top_ports[:3]]
            if port_values:
                filters.append(f"tcp.port in {{{', '.join(port_values)}}} or udp.port in {{{', '.join(port_values)}}}")

        if stats.get("http_request_count", 0):
            filters.append("http.request")
        if stats.get("dns_query_count", 0):
            filters.append("dns")

        for item in (suspicious_flows or [])[:3]:
            src = item.get("src")
            dst = item.get("dst")
            proto = str(item.get("proto", "")).lower()
            sport = item.get("sport")
            dport = item.get("dport")
            if not src or not dst:
                continue
            if proto in ("tcp", "udp"):
                parts = [f"ip.src == {src}", f"ip.dst == {dst}"]
                if isinstance(sport, int) and sport > 0:
                    parts.append(f"{proto}.srcport == {sport}")
                if isinstance(dport, int) and dport > 0:
                    parts.append(f"{proto}.dstport == {dport}")
                filters.append(" and ".join(parts))
            else:
                filters.append(f"ip.src == {src} and ip.dst == {dst}")

        return filters

    def _copy_wireshark_filters(self):
        if not self.wireshark_filters:
            messagebox.showinfo("Wireshark Filters", "No filters available for this capture.")
            return
        text = "\n".join(self.wireshark_filters)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Wireshark Filters", "Filters copied to clipboard.")

    def _browse_file(self, var):
        path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")])
        if path:
            var.set(path)

    def _browse_ioc(self):
        path = filedialog.askopenfilename(filetypes=[("IoC files", "*.json;*.txt"), ("All files", "*.*")])
        if path:
            self.ioc_path_var.set(path)

    def _request_cancel(self):
        """Called when the user clicks the cancel (X) button."""
        self._cancel_event.set()
        self.status_var.set("Cancelling...")
        self.cancel_button.configure(state=tk.DISABLED)

    def _set_busy(self, busy=True, message="Working..."):
        if busy:
            self.busy_count += 1
            if self.busy_count == 1:
                self._cancel_event.clear()
                # self.status_var.set(message)  # Disabled automatic status messages
                self._reset_progress()
                # Don't start progress animation yet - wait for first real update
                self.progress.configure(mode="indeterminate")
                self._progress_indeterminate = True
                self.progress_percent_var.set("")
                self.root.configure(cursor="watch")
                self.root.title(f"{self.root_title} - Working...")
                # Start initialization counter instead of animations
                self._initializing = True
                self._init_start_time = time.time()
                self._update_init_counter()
                # Don't start logo spin yet - will start when progress arrives
                # Batch widget state changes for better performance
                self.widget_states = {w: str(w["state"]) for w in self.busy_widgets}
                for widget in self.busy_widgets:
                    try:
                        widget.configure(state=tk.DISABLED)
                    except tk.TclError:
                        pass  # Widget may be destroyed
                # Show cancel button
                self.cancel_button.configure(state=tk.NORMAL)
                self.cancel_button.pack(side=tk.LEFT, padx=(4, 0))
            else:
                pass  # self.status_var.set(message)  # Disabled automatic status messages
        else:
            self.busy_count = max(0, self.busy_count - 1)
            if self.busy_count == 0:
                self._stop_init_counter()
                self._stop_logo_spin()
                self._reset_progress()
                self.root.configure(cursor="")
                self.root_title = self._get_window_title()
                self.root.title(self.root_title)
                # Batch widget state restoration
                for widget in self.busy_widgets:
                    prior = self.widget_states.get(widget, "normal")
                    try:
                        widget.configure(state=prior)
                    except tk.TclError:
                        pass  # Widget may be destroyed
                # Hide cancel button
                self.cancel_button.pack_forget()

    def _reset_progress(self):
        self.progress.stop()
        self.progress.configure(mode="determinate", maximum=100)
        self.progress["value"] = 0
        self.progress_percent_var.set("")
        self._progress_target = 0.0
        self._progress_current = 0.0
        self._progress_animating = False
        self._progress_indeterminate = False
        if self._progress_anim_id is not None:
            self.root.after_cancel(self._progress_anim_id)
            self._progress_anim_id = None

    def _set_progress(self, percent, eta_seconds=None, label=None, processed=None, total=None):
        if percent is None:
            # No percentage — stay at current position
            if label:
                self.status_var.set(label)
                if self.busy_count > 0:
                    short_label = label.split(" \u2014 ")[0] if " \u2014 " in label else label
                    self.root.title(f"{self.root_title} - {short_label}")
            return

        # Transition from initialization to active progress on first real update
        if self._progress_indeterminate:
            # Stop initialization counter if running
            if self._initializing:
                self._stop_init_counter()
            # Start animations now that analysis has begun
            self.progress.start(12)  # Start progress bar animation
            self._start_logo_spin()  # Start logo spinning
            self.progress.stop()
            self.progress.configure(mode="determinate", maximum=100)
            self._progress_indeterminate = False
            self._progress_current = 0.0

        percent_value = min(max(percent, 0.0), 100.0)

        # Set target and kick off smooth animation
        self._progress_target = percent_value
        # Update displayed percentage text immediately for responsiveness
        self.progress_percent_var.set(f"{percent_value:.0f}%")

        if not self._progress_animating:
            self._progress_animating = True
            self._animate_progress()

        if label:
            status_text = f"{label} {percent:.0f}%"
            if processed is not None and total:
                status_text = f"{label} {percent:.0f}% ({_format_bytes(processed)} / {_format_bytes(total)})"
            if eta_seconds is not None and eta_seconds > 0:
                eta_min, eta_sec = divmod(int(eta_seconds), 60)
                if eta_min > 0:
                    status_text += f" — ~{eta_min}m {eta_sec}s remaining"
                else:
                    status_text += f" — ~{eta_sec}s remaining"
            self.status_var.set(status_text)
            if self.busy_count > 0:
                short_label = label.split(" \u2014 ")[0] if " \u2014 " in label else label
                self.root.title(f"{self.root_title} - {percent:.0f}% {short_label}")

    def _animate_progress(self):
        """Smoothly interpolate the progress bar toward _progress_target."""
        if self._shutting_down:
            self._progress_animating = False
            self._progress_anim_id = None
            return
        target = self._progress_target
        current = self._progress_current
        diff = target - current

        if abs(diff) < 0.2:
            # Close enough – snap to target
            self._progress_current = target
            self.progress["value"] = target
            self._progress_animating = False
            self._progress_anim_id = None
            return

        # Ease-out interpolation: move 15% of remaining distance per tick
        # This gives a smooth deceleration as the bar approaches its target
        step = diff * 0.15
        # Ensure minimum movement to avoid stalling
        if abs(step) < 0.15:
            step = 0.15 if diff > 0 else -0.15

        new_val = current + step
        self._progress_current = new_val
        self.progress["value"] = new_val

        self._progress_animating = True
        self._progress_anim_id = self.root.after(16, self._animate_progress)  # ~60fps

    def _apply_theme(self):
        theme = self._resolve_theme()
        if theme == "light":
            self.colors = {
                "bg": "#f0f2f5",
                "panel": "#ffffff",
                "panel_alt": "#f7f8fa",
                "text": "#1a1d23",
                "muted": "#6b7280",
                "accent": "#2563eb",
                "accent_alt": "#1d4ed8",
                "accent_hover": "#3b82f6",
                "accent_subtle": "#dbeafe",
                "border": "#e2e5ea",
                "border_light": "#eef0f4",
                "danger": "#dc2626",
                "danger_hover": "#b91c1c",
                "success": "#16a34a",
                "success_hover": "#15803d",
                "warning": "#d97706",
                "warning_hover": "#b45309",
                "neon": "#7c3aed",
                "neon_alt": "#0891b2",
                "bg_wave": "#dde4f0",
                "bg_node": "#c5d0e0",
                "bg_hex": "#bfc9d8",
                "tab_selected_fg": "#ffffff",
                "header_gradient": "#1e3a5f",
                "shadow": "#00000012",
                "tooltip_bg": "#1e293b",
                "tooltip_fg": "#e2e8f0",
                "tooltip_border": "#4b5563",
            }
        else:
            self.colors = {
                "bg": "#0d1117",
                "panel": "#161b22",
                "panel_alt": "#1c2333",
                "text": "#e6edf3",
                "muted": "#8b949e",
                "accent": "#58a6ff",
                "accent_alt": "#388bfd",
                "accent_hover": "#79c0ff",
                "accent_subtle": "#122d4f",
                "border": "#21262d",
                "border_light": "#30363d",
                "danger": "#f85149",
                "danger_hover": "#da3633",
                "success": "#3fb950",
                "success_hover": "#2ea043",
                "warning": "#d29922",
                "warning_hover": "#bb8009",
                "neon": "#bc8cff",
                "neon_alt": "#39d2c0",
                "bg_wave": "#1b2a3f",
                "bg_node": "#223551",
                "bg_hex": "#142133",
                "tab_selected_fg": "#ffffff",
                "header_gradient": "#0d1117",
                "shadow": "#00000030",
                "tooltip_bg": "#1e293b",
                "tooltip_fg": "#e2e8f0",
                "tooltip_border": "#4b5563",
            }

        self.root.configure(bg=self.colors["bg"])
        self._set_dark_titlebar()
        style = ttk.Style(self.root)
        with contextlib.suppress(tk.TclError):
            style.theme_use("clam")

        bg = self.colors["bg"]
        panel = self.colors["panel"]
        panel_alt = self.colors["panel_alt"]
        text = self.colors["text"]
        muted = self.colors["muted"]
        accent = self.colors["accent"]
        accent_alt = self.colors["accent_alt"]
        accent_hover = self.colors["accent_hover"]
        accent_subtle = self.colors["accent_subtle"]
        border = self.colors["border"]
        border_light = self.colors["border_light"]
        tab_selected_fg = self.colors["tab_selected_fg"]

        style.configure("TFrame", background=bg)
        style.configure("TLabel", background=bg, foreground=text, font=("Segoe UI", 11))
        style.configure("Hint.TLabel", background=bg, foreground=muted, font=("Segoe UI", 10))
        style.configure("Heading.TLabel", background=bg, foreground=text, font=("Segoe UI", 13, "bold"))

        # ── Buttons ──────────────────────────────────────────────
        _btn_font = ("Segoe UI", 11)

        # Primary action button
        style.configure(
            "TButton",
            background=accent,
            foreground="#ffffff",
            bordercolor=accent_alt,
            focusthickness=0,
            focuscolor=accent,
            padding=(16, 8),
            font=_btn_font,
        )
        style.map(
            "TButton",
            background=[("active", accent_hover), ("disabled", border)],
            foreground=[("disabled", muted)],
            bordercolor=[("active", accent_hover)],
        )

        # Subtle / secondary button
        style.configure(
            "Secondary.TButton",
            background=panel_alt,
            foreground=text,
            bordercolor=border_light,
            focusthickness=0,
            padding=(14, 7),
            font=_btn_font,
        )
        style.map(
            "Secondary.TButton",
            background=[("active", accent_subtle), ("disabled", border)],
            foreground=[("active", accent), ("disabled", muted)],
            bordercolor=[("active", accent)],
        )

        # Danger button
        style.configure(
            "Danger.TButton",
            background=self.colors["danger"],
            foreground="#ffffff",
            bordercolor=self.colors["danger"],
            focusthickness=0,
            padding=(14, 7),
            font=_btn_font,
        )
        style.map(
            "Danger.TButton",
            background=[("active", self.colors["danger_hover"]), ("disabled", border)],
            foreground=[("disabled", muted)],
        )

        # Muted danger button (less prominent destructive actions)
        style.configure(
            "DangerMuted.TButton",
            background=panel_alt,
            foreground=self.colors["danger"],
            bordercolor=border_light,
            focusthickness=0,
            padding=(14, 7),
            font=_btn_font,
        )
        style.map(
            "DangerMuted.TButton",
            background=[("active", self.colors["danger"]), ("disabled", border)],
            foreground=[("active", "#ffffff"), ("disabled", muted)],
            bordercolor=[("active", self.colors["danger"])],
        )

        # Clear-field button (small red circle with ✕)
        style.configure(
            "ClearField.TButton",
            background=self.colors["danger"],
            foreground="#ffffff",
            bordercolor=self.colors["danger"],
            focusthickness=0,
            padding=(4, 2),
            font=("Segoe UI", 9, "bold"),
            relief="flat",
        )
        style.map(
            "ClearField.TButton",
            background=[("active", self.colors["danger_hover"]), ("disabled", border)],
            foreground=[("disabled", muted)],
            bordercolor=[("active", self.colors["danger_hover"])],
        )

        # Success button (e.g. Mark as Safe)
        style.configure(
            "Success.TButton",
            background=self.colors["success"],
            foreground="#ffffff",
            bordercolor=self.colors["success"],
            focusthickness=0,
            padding=(14, 7),
            font=_btn_font,
        )
        style.map(
            "Success.TButton",
            background=[("active", self.colors["success_hover"]), ("disabled", border)],
            foreground=[("disabled", muted)],
        )

        # Warning button (e.g. Mark as Malicious)
        style.configure(
            "Warning.TButton",
            background=self.colors["warning"],
            foreground="#ffffff",
            bordercolor=self.colors["warning"],
            focusthickness=0,
            padding=(14, 7),
            font=_btn_font,
        )
        style.map(
            "Warning.TButton",
            background=[("active", self.colors["warning_hover"]), ("disabled", border)],
            foreground=[("disabled", muted)],
        )

        # ── Checkbuttons ─────────────────────────────────────────
        style.configure("TCheckbutton", background=bg, foreground=text, font=("Segoe UI", 11))
        style.map("TCheckbutton", foreground=[("disabled", muted)])
        style.configure("Quiet.TCheckbutton", background=bg, foreground=text, font=("Segoe UI", 11))
        style.map(
            "Quiet.TCheckbutton",
            background=[("active", bg), ("focus", bg)],
            foreground=[("active", text), ("disabled", muted)],
        )

        # ── Radiobuttons ─────────────────────────────────────────
        style.configure("TRadiobutton", background=bg, foreground=text, font=("Segoe UI", 11))
        style.map(
            "TRadiobutton",
            background=[("active", bg), ("focus", bg)],
            foreground=[("active", text), ("disabled", muted)],
        )

        # ── LabelFrame ───────────────────────────────────────────
        style.configure(
            "TLabelframe", background=bg, foreground=text, bordercolor=border_light, relief="groove", borderwidth=1
        )
        style.configure("TLabelframe.Label", background=bg, foreground=accent, font=("Segoe UI", 11, "bold"))

        # ── Notebook / Tabs ──────────────────────────────────────
        style.configure("TNotebook", background=bg, bordercolor=border, tabmargins=[2, 6, 2, 0])
        style.configure(
            "TNotebook.Tab", background=panel_alt, foreground=muted, padding=(18, 9), font=("Segoe UI", 11, "bold")
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", accent), ("active", accent_subtle)],
            foreground=[("selected", tab_selected_fg), ("active", text)],
            expand=[("selected", [0, 0, 0, 2])],
        )

        # ── Entry / Spinbox / Combobox ───────────────────────────
        _field_padding = 6
        style.configure(
            "TEntry",
            fieldbackground=panel,
            foreground=text,
            bordercolor=border_light,
            insertcolor=text,
            padding=_field_padding,
        )
        style.map(
            "TEntry",
            bordercolor=[("focus", accent)],
        )
        style.configure(
            "TSpinbox",
            fieldbackground=panel,
            foreground=text,
            bordercolor=border_light,
            insertcolor=text,
            padding=_field_padding,
            arrowsize=14,
        )
        style.map(
            "TSpinbox",
            bordercolor=[("focus", accent)],
        )

        style.configure(
            "TCombobox",
            fieldbackground=panel,
            foreground=text,
            bordercolor=border_light,
            padding=_field_padding,
            arrowsize=14,
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", panel)],
            foreground=[("readonly", text)],
            selectbackground=[("readonly", accent_subtle)],
            selectforeground=[("readonly", text)],
            bordercolor=[("focus", accent), ("readonly", border_light)],
        )

        self.root.option_add("*TCombobox*Listbox.background", panel)
        self.root.option_add("*TCombobox*Listbox.foreground", text)
        self.root.option_add("*TCombobox*Listbox.selectBackground", accent_subtle)
        self.root.option_add("*TCombobox*Listbox.selectForeground", text)
        self.root.option_add("*TCombobox*Listbox.font", ("Segoe UI", 11))

        # ── Treeview ─────────────────────────────────────────────
        style.configure(
            "Treeview",
            background=panel,
            fieldbackground=panel,
            foreground=text,
            bordercolor=border,
            rowheight=32,
            font=("Segoe UI", 11),
        )
        style.configure(
            "Treeview.Heading",
            background=panel_alt,
            foreground=text,
            font=("Segoe UI", 11, "bold"),
            padding=8,
            bordercolor=border_light,
            relief="flat",
        )
        style.map(
            "Treeview",
            background=[("selected", accent_subtle)],
            foreground=[("selected", accent)],
        )
        style.map(
            "Treeview.Heading",
            background=[("active", accent_subtle)],
            foreground=[("active", accent)],
        )

        style.configure(
            "Packet.Treeview",
            background=panel,
            fieldbackground=panel,
            foreground=text,
            bordercolor=border,
            rowheight=28,
            font=("Consolas", 11),
        )
        style.configure(
            "Packet.Treeview.Heading",
            background=panel_alt,
            foreground=text,
            bordercolor=border_light,
            relief="flat",
            font=("Segoe UI", 10, "bold"),
            padding=6,
        )
        style.map(
            "Packet.Treeview",
            background=[("selected", accent_subtle)],
            foreground=[("selected", accent)],
        )
        style.map(
            "Packet.Treeview.Heading",
            background=[("active", accent_subtle), ("pressed", accent_subtle)],
            foreground=[("active", accent), ("pressed", accent)],
            bordercolor=[("active", accent), ("pressed", accent)],
            relief=[("active", "flat"), ("pressed", "flat")],
        )

        # ── Scrollbar ────────────────────────────────────────────
        style.configure(
            "TScrollbar",
            background=panel_alt,
            troughcolor=bg,
            bordercolor=bg,
            arrowcolor=muted,
            gripcount=0,
            width=10,
        )
        style.map(
            "TScrollbar",
            background=[("active", border_light), ("disabled", bg)],
            arrowcolor=[("active", text), ("disabled", border)],
        )

        # ── Progressbar ──────────────────────────────────────────
        style.configure(
            "TProgressbar",
            background=accent,
            troughcolor=panel_alt,
            bordercolor=border_light,
            lightcolor=accent,
            darkcolor=accent,
            thickness=14,
        )

        style.configure("TSeparator", background=border)

    def _set_dark_titlebar(self, window=None):
        """Force the Windows title bar to use dark mode via DWM."""
        if not sys.platform.startswith("win"):
            return
        try:
            import ctypes

            target = window or self.root
            hwnd = ctypes.windll.user32.GetParent(target.winfo_id())
            DWMWA_USE_IMMERSIVE_DARK_MODE = 20
            value = ctypes.c_int(1)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ctypes.byref(value), ctypes.sizeof(value)
            )
        except Exception:
            pass

    def _resolve_theme(self):
        theme = "system"
        if hasattr(self, "theme_var"):
            theme = self.theme_var.get().strip().lower() or "system"
        else:
            theme = self.settings.get("theme", "system")

        if theme == "system":
            return self._detect_system_theme()
        if theme in ("dark", "light"):
            return theme
        return "dark"

    def _detect_system_theme(self):
        if sys.platform.startswith("win"):
            try:
                import winreg

                key_path = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                    value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
                return "light" if value else "dark"
            except Exception:
                return "dark"
        return "dark"

    def _build_background(self):
        canvas = tk.Canvas(self.root, highlightthickness=0, bd=0, bg=self.colors["bg"])
        canvas.place(x=0, y=0, relwidth=1, relheight=1)
        canvas.tk.call("lower", canvas._w)
        canvas.bind("<Configure>", self._schedule_draw_background)
        self.bg_canvas = canvas
        self._bg_draw_pending = None

    def _schedule_draw_background(self, event=None):
        if self._shutting_down:
            return
        if self._bg_draw_pending is not None:
            self.root.after_cancel(self._bg_draw_pending)
        # Increased delay to reduce redraw frequency during resizing
        self._bg_draw_pending = self.root.after(150, self._draw_background)

    def _draw_background(self, _event=None):
        self._bg_draw_pending = None
        if self._shutting_down or self.bg_canvas is None:
            return
        w = self.bg_canvas.winfo_width()
        h = self.bg_canvas.winfo_height()
        if w <= 1 or h <= 1:
            return

        self.bg_canvas.delete("all")

        theme = self._resolve_theme()

        if theme == "dark":
            # Optimized gradient with fewer rectangles (8 instead of 32)
            steps = 8
            for i in range(steps):
                ratio = i / max(steps - 1, 1)
                r = int(13 + (18 - 13) * ratio)
                g = int(17 + (23 - 17) * ratio)
                b = int(23 + (33 - 23) * ratio)
                color = f"#{r:02x}{g:02x}{b:02x}"
                y0 = int(h * i / steps)
                y1 = int(h * (i + 1) / steps)
                self.bg_canvas.create_rectangle(0, y0, w, y1, fill=color, outline="")

            # Reduced dot grid density for better performance
            dot_color = "#161d28"
            for x in range(60, w, 80):
                for y in range(60, h, 80):
                    self.bg_canvas.create_oval(x, y, x + 1, y + 1, fill=dot_color, outline="")
        else:
            # Light theme: optimized gradient (8 instead of 16 steps)
            steps = 8
            for i in range(steps):
                ratio = i / max(steps - 1, 1)
                r = int(240 + (235 - 240) * ratio)
                g = int(242 + (238 - 242) * ratio)
                b = int(245 + (242 - 245) * ratio)
                color = f"#{r:02x}{g:02x}{b:02x}"
                y0 = int(h * i / steps)
                y1 = int(h * (i + 1) / steps)
                self.bg_canvas.create_rectangle(0, y0, w, y1, fill=color, outline=color)

            # Very subtle dot pattern
            dot_color = "#d8dce3"
            for x in range(40, w, 60):
                for y in range(40, h, 60):
                    self.bg_canvas.create_oval(x, y, x + 2, y + 2, fill=dot_color, outline=dot_color)

    def _setup_drag_drop(self):
        if not _check_tkinterdnd2():
            print("WARNING: tkinterdnd2 not available - drag/drop disabled")
            return

        DND_FILES, _TkinterDnD = _get_tkinterdnd2()

        def bind_drop(widget, setter, widget_name="unknown"):
            if widget is None:
                return
            try:
                widget.drop_target_register(DND_FILES)

                def on_drop(event):
                    try:
                        path = self._extract_drop_path(event.data)
                        if path:
                            setter(path)
                            return "copy"
                        return "none"
                    except Exception as e:
                        print(f"Drop error: {e}")
                        return "none"

                widget.dnd_bind("<<Drop>>", on_drop)
            except (tk.TclError, AttributeError) as e:
                print(f"Drag/drop setup failed for {widget_name}: {e}")
                return

        bind_drop(self.safe_entry, self.safe_path_var.set, "safe_entry")
        bind_drop(self.mal_entry, self.mal_path_var.set, "mal_entry")
        bind_drop(self.target_entry, self.target_path_var.set, "target_entry")
        if self.target_drop_area is not None:
            bind_drop(self.target_drop_area, self.target_path_var.set, "target_drop_area")
        bind_drop(self.analyze_tab, self.target_path_var.set, "analyze_tab")
        bind_drop(self.result_text, self.target_path_var.set, "result_text")

    _ALLOWED_DROP_EXTENSIONS = {
        ".pcap",
        ".pcapng",
        ".cap",
        ".pcap.gz",
        ".pcapng.gz",
    }

    def _extract_drop_path(self, data):
        if not data:
            return ""

        def normalize(text):
            if not text:
                return ""
            text = text.strip().strip('"')
            if text.startswith("{") and text.endswith("}"):
                text = text[1:-1]
            if text.startswith("file://"):
                from urllib.parse import unquote, urlparse

                parsed = urlparse(text)
                path = unquote(parsed.path or "")
                if sys.platform.startswith("win") and path.startswith("/"):
                    path = path[1:]
                text = path or text
            # Canonicalize to prevent traversal and validate extension
            try:
                text = os.path.realpath(text)
            except Exception:
                return ""
            lower = text.lower()
            if not any(lower.endswith(ext) for ext in self._ALLOWED_DROP_EXTENSIONS):
                return ""
            return text

        try:
            parts = self.root.tk.splitlist(data)
            for part in parts:
                candidate = normalize(part)
                if candidate:
                    return candidate
        except Exception:
            pass
        return normalize(data)

    def _add_clear_x(self, entry, var):
        """Place a small red ✕ inside the right edge of an Entry widget."""
        x_label = tk.Label(
            entry,
            text="\u2715",
            font=("Segoe UI", 9),
            fg=self.colors["danger"],
            bg=self.colors["panel"],
            cursor="hand2",
            bd=0,
            padx=0,
            pady=0,
            highlightthickness=0,
        )
        x_label.place(relx=1.0, rely=0.5, anchor="e", x=-4, y=-1)
        x_label.bind("<Button-1>", lambda _: var.set(""))
        x_label.bind("<Enter>", lambda _: x_label.configure(fg=self.colors["danger_hover"]))
        x_label.bind("<Leave>", lambda _: x_label.configure(fg=self.colors["danger"]))
        return x_label

    def _style_text(self, widget):
        widget.configure(
            background=self.colors["panel"],
            foreground=self.colors["text"],
            insertbackground=self.colors["text"],
            selectbackground=self.colors["accent_subtle"],
            selectforeground=self.colors["text"],
            borderwidth=0,
            relief="flat",
            highlightthickness=1,
            highlightbackground=self.colors["border_light"],
            highlightcolor=self.colors["accent"],
            font=("Consolas", 11),
            padx=10,
            pady=8,
            spacing1=2,
            spacing3=2,
        )

        # Add mouse wheel scrolling support
        def _on_mousewheel(event):
            try:
                widget.yview_scroll(int(-1 * (event.delta / 120)), "units")
            except tk.TclError:
                pass  # Widget destroyed, ignore scroll event

        def _bind_mousewheel(_event):
            widget.bind("<MouseWheel>", _on_mousewheel)

        def _unbind_mousewheel(_event):
            widget.unbind("<MouseWheel>")

        widget.bind("<Enter>", _bind_mousewheel)
        widget.bind("<Leave>", _unbind_mousewheel)

    def _show_overlay(self, message):
        pass

    def _update_overlay_message(self, message):
        pass

    def _hide_overlay(self):
        pass

    def _run_task(self, func, on_success, on_error=None, message="Working...", progress_label=None):
        self._set_busy(True, message)
        q = queue.Queue()
        last_progress_time = [0.0]  # Mutable to allow closure modification
        last_progress_value = [0.0]

        def progress_cb(percent, eta_seconds=None, processed=None, total=None, label=None):
            # Check for cancellation on every progress update
            if self._cancel_event.is_set():
                raise AnalysisCancelledError("Analysis cancelled by user.")

            # Light throttling to prevent excessive updates while maintaining responsiveness
            current_time = time.time()
            time_delta = current_time - last_progress_time[0]
            progress_delta = abs(percent - last_progress_value[0])

            # Send update if: significant change (>1%), enough time passed (>150ms), or final (100%)
            should_update = percent >= 100 or progress_delta >= 1.0 or time_delta >= 0.15

            if should_update:
                last_progress_time[0] = current_time
                last_progress_value[0] = percent
                q.put(
                    (
                        "progress",
                        {
                            "percent": percent,
                            "eta": eta_seconds,
                            "processed": processed,
                            "total": total,
                            "label": label,
                        },
                    )
                )

        def worker():
            try:
                if progress_label:
                    result = func(progress_cb)
                else:
                    result = func()
                # Respect cancel even for tasks that don't check cancel_event
                if self._cancel_event.is_set():
                    q.put(("cancelled",))
                else:
                    q.put(("ok", result))
            except AnalysisCancelledError:
                q.put(("cancelled",))
            except Exception as exc:
                import traceback as _tb

                # If cancelled, don't report the error
                if self._cancel_event.is_set():
                    q.put(("cancelled",))
                else:
                    q.put(("err", exc, _tb.format_exc()))

        threading.Thread(target=worker, daemon=True).start()

        def check():
            if self._shutting_down:
                return
            done = False
            cancelled = False
            payload = None
            error = None
            error_tb = None
            latest_progress = None
            try:
                for _ in range(10):  # Process batch of messages without blocking
                    msg = q.get_nowait()
                    status = msg[0]
                    if status == "progress":
                        latest_progress = msg[1]
                    elif status == "ok":
                        done = True
                        payload = msg[1]
                        break
                    elif status == "cancelled":
                        done = True
                        cancelled = True
                        break
                    elif status == "err":
                        done = True
                        error = msg[1]
                        error_tb = msg[2] if len(msg) > 2 else None
                        break
            except queue.Empty:
                pass

            if latest_progress is not None:
                lbl = latest_progress.get("label") or progress_label
                self._set_progress(
                    latest_progress.get("percent"),
                    latest_progress.get("eta"),
                    lbl,
                    processed=latest_progress.get("processed"),
                    total=latest_progress.get("total"),
                )

            if done:
                if cancelled or self._cancel_event.is_set():
                    self._set_busy(False)
                    self.status_var.set("Analysis cancelled.")
                    self._reset_progress()
                else:
                    # Smoothly animate to 100% before clearing
                    self._set_progress(100, label="Complete \u2713")
                    self.root.after(800, lambda: self._finish_task(error, payload, error_tb, on_success, on_error))
            else:
                # Poll at 100ms for smooth progress updates
                interval = 30 if self._cancel_event.is_set() else 100
                self.root.after(interval, check)

        self.root.after(100, check)

    def _finish_task(self, error, payload, error_tb, on_success, on_error):
        """Called after the 100% progress hold to clean up and deliver results."""
        if self._shutting_down:
            return
        self._set_busy(False)
        if error is None:
            on_success(payload)
        elif on_error:
            on_error(error)
        else:
            detail = f"{error}\n\n{error_tb}" if error_tb else str(error)
            messagebox.showerror("Error", detail)

    def _reset_kb(self):
        if os.path.exists(KNOWLEDGE_BASE_FILE):
            wants_backup = messagebox.askyesno(
                "Knowledge Base",
                "Would you like to back up the knowledge base before resetting?",
            )
            if wants_backup and not self._backup_kb():
                return

        confirm = messagebox.askyesno(
            "Knowledge Base",
            "Are you sure you want to reset the knowledge base?",
        )
        if not confirm:
            return

        if os.path.exists(KNOWLEDGE_BASE_FILE):
            os.remove(KNOWLEDGE_BASE_FILE)
        self._refresh_kb()
        messagebox.showinfo("Knowledge Base", "Knowledge base reset.")

    def _backup_kb(self):
        kb = load_knowledge_base()
        default_name = f"pcap_knowledge_base_backup_{_utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        initial_dir = self.backup_dir_var.get().strip() or os.path.dirname(KNOWLEDGE_BASE_FILE)
        path = filedialog.asksaveasfilename(
            title="Backup Knowledge Base",
            defaultextension=".json",
            initialfile=default_name,
            initialdir=initial_dir,
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return False
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(kb, f, indent=2)
        except Exception as exc:
            messagebox.showerror("Knowledge Base", f"Backup failed: {exc}")
            return False
        self.backup_dir_var.set(os.path.dirname(path))
        self._save_settings_from_vars()
        messagebox.showinfo("Knowledge Base", "Backup saved.")
        return True

    def _restore_kb(self):
        initial_dir = self.backup_dir_var.get().strip() or os.path.dirname(KNOWLEDGE_BASE_FILE)
        path = filedialog.askopenfilename(
            title="Restore Knowledge Base",
            initialdir=initial_dir,
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("Backup format is invalid.")
            data.setdefault("safe", [])
            data.setdefault("malicious", [])
            data.setdefault("ioc", {"ips": [], "domains": [], "hashes": []})
            save_knowledge_base(data)
        except Exception as exc:
            messagebox.showerror("Knowledge Base", f"Restore failed: {exc}")
            return
        self.backup_dir_var.set(os.path.dirname(path))
        self._save_settings_from_vars()
        self._refresh_kb()
        messagebox.showinfo("Knowledge Base", "Knowledge base restored.")

    def _load_ioc_file(self):
        path = self.ioc_path_var.get().strip()
        if not path:
            messagebox.showwarning("Missing file", "Please select an IoC file.")
            return
        if not os.path.exists(path):
            messagebox.showwarning("Missing file", "IoC file not found.")
            return

        def task():
            return load_iocs_from_file(path)

        def done(iocs):
            try:
                kb = load_knowledge_base()
                merge_iocs_into_kb(kb, iocs)
                save_knowledge_base(kb)
                self._refresh_kb()
                self.ioc_path_var.set("")
                messagebox.showinfo("IoC Feed", "IoCs imported successfully.")
            except Exception as e:
                _write_error_log("Error importing IoCs", e, sys.exc_info()[2])
                messagebox.showerror("Error", f"Failed to import IoCs: {e!s}")

        self._run_task(task, done, message="Importing IoCs...")

    def _clear_iocs(self):
        try:
            kb = load_knowledge_base()
            kb["ioc"] = {"ips": [], "domains": [], "hashes": []}
            save_knowledge_base(kb)
            self._refresh_kb()
            messagebox.showinfo("IoC Feed", "IoCs cleared.")
        except Exception as e:
            _write_error_log("Error clearing IoCs", e, sys.exc_info()[2])
            messagebox.showerror("Error", f"Failed to clear IoCs: {e!s}")

    def _review_unsure_items(self):
        """Open a window to review and reclassify unsure items."""
        kb = load_knowledge_base()
        unsure_items = kb.get("unsure", [])

        if not unsure_items:
            messagebox.showinfo("Unsure Items", "No unsure items to review.")
            return

        # Create review window
        review_window = tk.Toplevel(self.root)
        review_window.title("Review Unsure Items")
        review_window.geometry("900x600")
        review_window.transient(self.root)

        # Header
        header = ttk.Frame(review_window, padding=10)
        header.pack(fill=tk.X)
        ttk.Label(header, text=f"Reviewing {len(unsure_items)} unsure item(s)", font=("Segoe UI", 12, "bold")).pack(
            side=tk.LEFT
        )

        # Main content with scrollbar
        main_frame = ttk.Frame(review_window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        canvas = tk.Canvas(main_frame, highlightthickness=0)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind("<Configure>", lambda _: canvas.configure(scrollregion=canvas.bbox("all")))

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Track items to remove/reclassify
        items_to_process = []

        def reclassify(index, new_label):
            """Reclassify an unsure item to safe or malicious."""
            item = unsure_items[index]
            items_to_process.append(("reclassify", index, new_label, item))

        def delete_item(index):
            """Remove an unsure item without reclassifying."""
            items_to_process.append(("delete", index, None, None))

        # Create review cards for each unsure item
        for idx, item in enumerate(unsure_items):
            card = ttk.LabelFrame(scrollable_frame, text=f"  Item {idx + 1}  ", padding=12)
            card.pack(fill=tk.X, pady=8, padx=4)

            # Display summary info
            summary = item.get("summary", "No summary available")
            info_text = tk.Text(card, height=6, wrap=tk.WORD, font=("Segoe UI", 10))
            info_text.insert("1.0", summary)
            info_text.configure(state=tk.DISABLED)
            info_text.pack(fill=tk.X, pady=(0, 8))

            # Buttons for reclassification
            button_frame = ttk.Frame(card)
            button_frame.pack(fill=tk.X)

            ttk.Button(
                button_frame, text="Mark as Safe", style="Success.TButton", command=lambda i=idx: reclassify(i, "safe")
            ).pack(side=tk.LEFT, padx=(0, 4))
            ttk.Button(
                button_frame,
                text="Mark as Malicious",
                style="Warning.TButton",
                command=lambda i=idx: reclassify(i, "malicious"),
            ).pack(side=tk.LEFT, padx=(0, 4))
            ttk.Button(
                button_frame, text="Delete", style="Secondary.TButton", command=lambda i=idx: delete_item(i)
            ).pack(side=tk.LEFT, padx=(0, 4))

        # Bottom buttons
        bottom_frame = ttk.Frame(review_window, padding=10)
        bottom_frame.pack(fill=tk.X, side=tk.BOTTOM)

        def apply_changes():
            """Apply all reclassifications and close the window."""
            if not items_to_process:
                review_window.destroy()
                return

            try:
                # Reload KB to ensure we have latest data
                kb = load_knowledge_base()
                unsure = kb.get("unsure", [])

                # Process items in reverse order to maintain indices
                for action, index, new_label, item in sorted(items_to_process, key=lambda x: x[1], reverse=True):
                    if index < len(unsure):
                        if action == "reclassify":
                            # Remove from unsure and add to new category
                            removed_item = unsure.pop(index)
                            kb[new_label].append(removed_item)
                        elif action == "delete":
                            # Just remove from unsure
                            unsure.pop(index)

                save_knowledge_base(kb)
                self._refresh_kb()
                messagebox.showinfo("Review Complete", f"Processed {len(items_to_process)} item(s).")
                review_window.destroy()
            except Exception as e:
                _write_error_log("Error applying unsure item changes", e, sys.exc_info()[2])
                messagebox.showerror("Error", f"Failed to apply changes: {e!s}")

        ttk.Button(bottom_frame, text="Apply Changes", command=apply_changes).pack(side=tk.RIGHT, padx=(4, 0))
        ttk.Button(bottom_frame, text="Cancel", style="Secondary.TButton", command=review_window.destroy).pack(
            side=tk.RIGHT
        )

    def _llm_is_enabled(self):
        provider = self.llm_provider_var.get().strip().lower()
        return provider not in ("", "disabled")

    def _request_llm_label(self, stats, summary):
        provider = self.llm_provider_var.get().strip().lower()
        if provider == "ollama":
            return self._request_ollama_label(stats, summary)
        if provider == "openai_compatible":
            return self._request_openai_compat_label(stats, summary)
        raise ValueError(f"Unsupported LLM provider: {provider}")

    @staticmethod
    def _build_llm_summary_stats(stats):
        """Build the summary-stats dict sent to LLM providers (single source of truth)."""
        return {
            "packet_count": stats.get("packet_count"),
            "avg_size": stats.get("avg_size"),
            "median_size": stats.get("median_size"),
            "protocol_counts": stats.get("protocol_counts", {}),
            "top_ports": stats.get("top_ports", []),
            "unique_src": stats.get("unique_src"),
            "unique_dst": stats.get("unique_dst"),
            "dns_query_count": stats.get("dns_query_count"),
            "http_request_count": stats.get("http_request_count"),
            "tls_packet_count": stats.get("tls_packet_count"),
            "top_dns": stats.get("top_dns", []),
            "top_tls_sni": stats.get("top_tls_sni", []),
        }

    @staticmethod
    def _parse_llm_label_response(content):
        """Parse and validate LLM label JSON response (shared by Ollama & OpenAI paths)."""
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError(f"LLM response was not valid JSON: {exc}")

        if not isinstance(parsed, dict):
            raise ValueError("LLM response was not a JSON object.")

        label = str(parsed.get("label", "")).strip().lower()
        if label not in ("safe", "malicious"):
            raise ValueError("LLM label must be 'safe' or 'malicious'.")

        confidence = parsed.get("confidence", None)
        if confidence is not None:
            try:
                confidence = float(confidence)
            except (TypeError, ValueError):
                confidence = None

        rationale = str(parsed.get("rationale", "")).strip()
        return {"label": label, "confidence": confidence, "rationale": rationale}

    def _request_ollama_label(self, stats, summary):
        endpoint = self._normalize_ollama_endpoint(self.llm_endpoint_var.get() or "http://localhost:11434")
        model = self.llm_model_var.get().strip() or "llama3"
        url = endpoint.rstrip("/") + "/api/generate"
        summary_stats = self._build_llm_summary_stats(stats)
        prompt = (
            "You are a cybersecurity assistant. Decide whether the capture should be labeled "
            "'safe' or 'malicious' for a training knowledge base. "
            "Return ONLY JSON with keys: label (safe/malicious), confidence (0-1), rationale (1-2 sentences).\n\n"
            f"Summary stats JSON:\n{json.dumps(summary_stats, indent=2)}\n\n"
            f"Human summary:\n{summary}\n"
        )
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
        }
        data = json.dumps(payload).encode("utf-8")
        raw = self._llm_http_request(url, data, timeout=20)

        response = json.loads(raw)
        content = response.get("response", "")
        if not content:
            raise ValueError("LLM response was empty.")

        return self._parse_llm_label_response(content)

    def _request_openai_compat_label(self, stats, summary):
        summary_stats = self._build_llm_summary_stats(stats)
        messages = [
            {
                "role": "system",
                "content": "You are a cybersecurity assistant. Return ONLY JSON with keys: label (safe/malicious), "
                "confidence (0-1), rationale (1-2 sentences).",
            },
            {
                "role": "user",
                "content": f"Summary stats JSON:\n{json.dumps(summary_stats, indent=2)}\n\nHuman summary:\n{summary}\n",
            },
        ]
        content = self._request_openai_compat_chat(messages, temperature=0.2)
        return self._parse_llm_label_response(content)

    def _llm_is_ready(self):
        """Return True only if LLM is enabled AND connection was verified."""
        if not self._llm_is_enabled():
            return False
        return self.llm_test_status_var.get().strip() in ("OK", "Auto")

    def _confirm_llm_label(self, intended_label, stats, summary, on_apply):
        if not self._llm_is_ready():
            on_apply(intended_label)
            return

        self.sample_note_var.set("LLM: checking...")

        def task():
            return self._request_llm_label(stats, summary)

        def done(suggestion):
            self.sample_note_var.set("")
            suggested_label = suggestion.get("label") if suggestion else None
            if suggested_label not in ("safe", "malicious"):
                messagebox.showwarning("LLM Suggestion", "LLM did not return a valid label. Using selected label.")
                on_apply(intended_label)
                return

            confidence = suggestion.get("confidence")
            conf_text = f"{confidence:.2f}" if isinstance(confidence, (int, float)) else "n/a"
            rationale = suggestion.get("rationale", "").strip()
            if suggested_label == intended_label:
                detail = f"LLM agrees with your label: {suggested_label}\nConfidence: {conf_text}\n"
                if rationale:
                    detail += f"Rationale: {rationale}\n"
                messagebox.showinfo("LLM Suggestion", detail)
                on_apply(intended_label)
                return

            prompt = f"LLM suggests: {suggested_label}\nConfidence: {conf_text}\n"
            if rationale:
                prompt += f"Rationale: {rationale}\n"
            prompt += f"\nUse suggested label instead of '{intended_label}'?"
            choice = messagebox.askyesnocancel("LLM Suggestion", prompt)
            if choice is None:
                return
            on_apply(suggested_label if choice else intended_label)

        def failed(err):
            self.sample_note_var.set("")
            prompt = f"LLM suggestion failed: {err}\n\nDo you still want to mark this capture as '{intended_label}'?"
            choice = messagebox.askyesno("LLM Suggestion Failed", prompt)
            if choice:
                on_apply(intended_label)

        self._run_task(task, done, on_error=failed, message="Contacting LLM...")

    def _set_llm_test_status(self, text, color):
        try:
            self.llm_test_status_var.set(text)
            if self.llm_test_status_label is not None:
                self.llm_test_status_label.configure(fg=color, bg=self.colors.get("bg", "#0d1117"))
            self._update_llm_header_indicator()
        except Exception:
            pass  # Don't crash if LLM status update fails

    def _update_llm_header_indicator(self):
        try:
            if self.llm_header_label is None:
                return
            provider = self.llm_provider_var.get().strip().lower()
            status = self.llm_test_status_var.get().strip()
            bg = self.colors.get("panel", "#161b22")
            if provider in ("", "disabled"):
                text = "LLM: off"
                fg = self.colors.get("muted", "#8b949e")
                border = self.colors.get("border", "#21262d")
            elif status == "OK":
                text = "\u2714 LLM"
                fg = self.colors.get("success", "#3fb950")
                border = self.colors.get("success", "#3fb950")
            elif status == "FAIL":
                text = "\u2718 LLM"
                fg = self.colors.get("danger", "#f85149")
                border = self.colors.get("danger", "#f85149")
            elif status == "Auto":
                text = "\u2714 LLM"
                fg = self.colors.get("accent", "#58a6ff")
                border = self.colors.get("accent", "#58a6ff")
            elif "Testing" in status or "testing" in status:
                text = "\u25cf LLM"
                fg = self.colors.get("warning", "#d29922")
                border = self.colors.get("warning", "#d29922")
            else:
                text = "\u25cb LLM"
                fg = self.colors.get("muted", "#8b949e")
                border = self.colors.get("border", "#21262d")
            self.llm_header_label.configure(text=text, fg=fg, bg=bg)
            self.llm_header_indicator.configure(bg=bg, highlightbackground=border)
        except Exception:
            pass  # Don't crash if LLM header update fails

    def _update_online_header_indicator(self):
        """Update the online/offline indicator in the header."""
        if self.online_header_label is None:
            return
        is_offline = self.offline_mode_var.get()
        bg = self.colors.get("panel", "#161b22")
        if is_offline:
            text = "Offline"
            fg = self.colors.get("warning", "#d29922")
            border = self.colors.get("warning", "#d29922")
        else:
            text = "\u2714 Online"
            fg = self.colors.get("success", "#3fb950")
            border = self.colors.get("success", "#3fb950")
        self.online_header_label.configure(text=text, fg=fg, bg=bg)
        self.online_header_indicator.configure(bg=bg, highlightbackground=border)

    def _toggle_llm(self):
        """Toggle LLM on/off using the header button."""
        current_provider = self.llm_provider_var.get().strip().lower()

        if current_provider in ("", "disabled"):
            # Turn LLM on - restore last used provider or default to "disabled"
            last_provider = getattr(self, "_last_llm_provider", None)
            if last_provider and last_provider not in ("", "disabled"):
                self.llm_provider_var.set(last_provider)
            else:
                # No previous provider, open settings dialog
                messagebox.showinfo(
                    "LLM Settings",
                    "LLM is currently disabled. Please configure an LLM provider in File → LLM Settings.",
                    parent=self.root,
                )
                return
        else:
            # Turn LLM off - save current provider and set to disabled
            self._last_llm_provider = current_provider
            self.llm_provider_var.set("disabled")

        # Save settings and update indicator
        self._save_settings_from_vars()
        self._update_llm_header_indicator()

    def _toggle_online_mode(self):
        """Toggle online/offline mode using the header button."""
        current_offline = self.offline_mode_var.get()
        self.offline_mode_var.set(not current_offline)

        # Save settings and update indicators
        self._save_settings_from_vars()
        self._update_online_header_indicator()
        self._update_llm_header_indicator()  # LLM status may depend on offline mode

        # Update window title to reflect offline status
        self.root_title = self._get_window_title()
        self.root.title(self.root_title)

    def _on_offline_mode_changed(self):
        """Called when offline mode checkbox is toggled in preferences."""
        # Update indicators to reflect current state
        self._update_online_header_indicator()
        self._update_llm_header_indicator()  # LLM status may depend on offline mode

        # Update window title to reflect offline status
        self.root_title = self._get_window_title()
        self.root.title(self.root_title)

    _PROBE_MAX_BYTES = 5 * 1024 * 1024  # 5 MB safety cap for probe responses

    def _probe_ollama(self, endpoint):
        base = self._normalize_ollama_endpoint(endpoint)
        url = base.rstrip("/") + "/api/tags"
        req = urllib.request.Request(url, headers={"Content-Type": "application/json"})
        with _safe_urlopen(req, timeout=1.5) as resp:
            raw = resp.read(self._PROBE_MAX_BYTES + 1)
            if len(raw) > self._PROBE_MAX_BYTES:
                raise RuntimeError("Probe response exceeded size limit.")
            raw = raw.decode("utf-8")
        payload = json.loads(raw)
        models = payload.get("models", []) if isinstance(payload, dict) else []
        if not models:
            return None
        model_name = models[0].get("name") if isinstance(models[0], dict) else None
        return model_name

    def _list_ollama_models(self, endpoint):
        base = self._normalize_ollama_endpoint(endpoint)
        url = base.rstrip("/") + "/api/tags"
        req = urllib.request.Request(url, headers={"Content-Type": "application/json"})
        with _safe_urlopen(req, timeout=3) as resp:
            raw = resp.read(self._PROBE_MAX_BYTES + 1)
            if len(raw) > self._PROBE_MAX_BYTES:
                raise RuntimeError("Probe response exceeded size limit.")
            raw = raw.decode("utf-8")
        payload = json.loads(raw)
        models = payload.get("models", []) if isinstance(payload, dict) else []
        return [m.get("name") for m in models if isinstance(m, dict) and m.get("name")]

    def _probe_openai_compat(self, endpoint, api_key=""):
        url = endpoint.rstrip("/") + "/v1/models"
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        req = urllib.request.Request(url, headers=headers)
        with _safe_urlopen(req, timeout=3) as resp:
            raw = resp.read(self._PROBE_MAX_BYTES + 1)
            if len(raw) > self._PROBE_MAX_BYTES:
                raise RuntimeError("Probe response exceeded size limit.")
            raw = raw.decode("utf-8")
        payload = json.loads(raw)
        models = payload.get("data", []) if isinstance(payload, dict) else []
        if not models:
            return None
        model_id = models[0].get("id") if isinstance(models[0], dict) else None
        return model_id

    def _list_openai_compat_models(self, endpoint, api_key=""):
        base = self._normalize_openai_endpoint(endpoint)
        url = base.rstrip("/") + "/v1/models"
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        req = urllib.request.Request(url, headers=headers)
        with _safe_urlopen(req, timeout=5) as resp:
            raw = resp.read(self._PROBE_MAX_BYTES + 1)
            if len(raw) > self._PROBE_MAX_BYTES:
                raise RuntimeError("Probe response exceeded size limit.")
            raw = raw.decode("utf-8")
        payload = json.loads(raw)
        models = payload.get("data", []) if isinstance(payload, dict) else []
        return [m.get("id") for m in models if isinstance(m, dict) and m.get("id")]

    def _select_best_model(self, available_models, provider):
        """Select the best/recommended model from available models based on provider and preferences."""
        if not available_models:
            return None

        # Define recommended models by priority for each provider type
        # Patterns to match against (case-insensitive, partial matches)
        ollama_preferences = [
            # Reasoning models (best for analysis)
            "deepseek-r1",
            "qwq",
            "qwen-qwq",
            # Large capable models
            "llama3.3",
            "llama3.2",
            "llama3.1",
            "llama3",
            "mistral-nemo",
            "gemma2",
            "phi4",
            # Fallback to any available
        ]

        cloud_preferences = {
            # OpenAI
            "openai": ["gpt-4o", "gpt-4-turbo", "gpt-4", "gpt-3.5-turbo"],
            # Claude via OpenRouter
            "anthropic": ["claude-3.5-sonnet", "claude-3-opus", "claude-3-sonnet"],
            # Google
            "gemini": ["gemini-2.0-flash-exp", "gemini-1.5-pro", "gemini-1.5-flash"],
            # Mistral
            "mistral": ["mistral-large", "mistral-medium", "mistral-small"],
            # DeepSeek
            "deepseek": ["deepseek-chat", "deepseek-reasoner"],
            # Groq
            "groq": ["llama-3.3-70b", "llama-3.1-70b", "mixtral-8x7b"],
            # Together AI
            "together": ["meta-llama/Llama-3.3-70B", "meta-llama/Llama-3.1-70B"],
            # OpenRouter
            "openrouter": ["anthropic/claude-3.5-sonnet", "google/gemini-2.0-flash"],
            # Perplexity
            "perplexity": ["llama-3.1-sonar-large", "llama-3.1-sonar-small"],
        }

        # Determine which preference list to use
        endpoint = self.llm_endpoint_var.get().strip().lower()
        preferences = ollama_preferences

        if provider == "openai_compatible" and endpoint:
            # Try to detect cloud provider from endpoint
            for key, prefs in cloud_preferences.items():
                if key in endpoint:
                    preferences = prefs
                    break

        # Try to match preferences in order
        for pref in preferences:
            pref_lower = pref.lower()
            for model in available_models:
                model_lower = model.lower()
                if pref_lower in model_lower:
                    return model

        # If no preference matched, return the first model
        return available_models[0]

    def _refresh_llm_models(self, combo=None):
        provider = self.llm_provider_var.get().strip().lower()
        endpoint = self.llm_endpoint_var.get().strip()
        if provider == "ollama" and not endpoint:
            endpoint = "http://localhost:11434"
            self.llm_endpoint_var.set(endpoint)
        if provider == "disabled" or not endpoint:
            if combo is not None:
                combo["values"] = []
            return

        def _dedupe_names(names):
            unique = []
            seen = set()
            for name in names:
                key = str(name).strip()
                if not key:
                    continue
                if key in seen:
                    continue
                seen.add(key)
                unique.append(key)
            return unique

        def worker():
            try:
                if provider == "ollama":
                    names = self._list_ollama_models(endpoint)
                    if names:
                        return names
                    # Try to start Ollama and retry once if no models are returned.
                    try:
                        subprocess.Popen(
                            ["ollama", "serve"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                        )
                        time.sleep(1.2)
                        return self._list_ollama_models(endpoint)
                    except Exception:
                        return []
                if provider == "openai_compatible":
                    api_key = self.llm_api_key_var.get().strip()
                    return self._list_openai_compat_models(endpoint, api_key=api_key)
            except Exception:
                pass
            return []

        def apply(names):
            names = _dedupe_names(names)
            if combo is not None:
                try:
                    if not combo.winfo_exists():
                        return
                    combo["values"] = names
                    if names and not self.llm_model_var.get().strip():
                        self.llm_model_var.set(names[0])
                except tk.TclError:
                    return

        def apply_with_best_model(names, select_best=False):
            """Apply model list and optionally select the best model for the provider."""
            names = _dedupe_names(names)
            if combo is not None:
                try:
                    if not combo.winfo_exists():
                        return
                    combo["values"] = names

                    if select_best and names:
                        # Try to select the best/recommended model for this provider
                        selected = self._select_best_model(names, provider)
                        if selected:
                            self.llm_model_var.set(selected)
                    elif names and not self.llm_model_var.get().strip():
                        self.llm_model_var.set(names[0])
                except tk.TclError:
                    return

        def run():
            names = worker()
            # Check if this refresh was triggered by a server change
            select_best = getattr(self, "_llm_server_just_changed", False)
            if select_best:
                self._llm_server_just_changed = False
            self.root.after(0, lambda: apply_with_best_model(names, select_best) if select_best else apply(names))

        threading.Thread(target=run, daemon=True).start()

    def _detect_llm_server(self, server_var, servers, model_combo):
        """Scan local LLM server ports for running instances (skip cloud providers)."""
        hint = getattr(self, "_detect_hint_label", None)

        if hint:
            hint.configure(
                text="Scanning...",
                fg=self.colors.get("accent", "#58a6ff"),
            )

        def _scan():
            found = []
            # Cloud providers set (skip during local port scan)
            _CLOUD_NAMES = {
                "OpenAI",
                "Google Gemini",
                "Mistral AI",
                "Groq",
                "Together AI",
                "OpenRouter",
                "Perplexity",
                "DeepSeek",
            }
            for name, (prov, endpoint) in servers.items():
                if name in ("Disabled", "Custom") or not endpoint:
                    continue
                if name in _CLOUD_NAMES:
                    continue  # skip cloud — no local port to scan
                try:
                    if prov == "ollama":
                        model_id = self._probe_ollama(endpoint)
                    else:
                        model_id = self._probe_openai_compat(endpoint)
                    if model_id:
                        found.append((name, prov, endpoint, model_id))
                except Exception:
                    pass
            return found

        def _apply(found):
            if not found:
                if hint:
                    hint.configure(
                        text="No servers found",
                        fg=self.colors.get("warning", "#d29922"),
                    )
                return
            # Auto-select the first found server
            name, prov, endpoint, model_id = found[0]
            server_var.set(name)
            self.llm_provider_var.set(prov)
            self.llm_endpoint_var.set(endpoint)
            self.llm_model_var.set(model_id)
            self._refresh_llm_models(model_combo)
            if hint:
                others = ", ".join(n for n, _, _, _ in found[1:])
                msg = f"Found {name}"
                if others:
                    msg += f" (also: {others})"
                hint.configure(
                    text=msg,
                    fg=self.colors.get("success", "#3fb950"),
                )

        def _run():
            results = _scan()
            self.root.after(0, lambda: _apply(results))

        threading.Thread(target=_run, daemon=True).start()

    def _verify_otx_key(self):
        """Verify the OTX API key by making a test request."""
        label = getattr(self, "_otx_verify_label", None)
        if not label:
            return

        key = self.otx_api_key_var.get().strip()
        if not key:
            label.configure(text="No key provided", fg=self.colors.get("warning", "#d29922"))
            return

        label.configure(text="Verifying...", fg=self.colors.get("accent", "#58a6ff"))

        def _test():
            try:
                # Check if requests is available
                try:
                    import requests
                except ImportError:
                    return False, "requests library not available"

                url = "https://otx.alienvault.com/api/v1/user/me"
                headers = {"X-OTX-API-KEY": key}
                response = requests.get(url, headers=headers, timeout=5)

                if response.status_code == 200:
                    data = response.json()
                    username = data.get("username", "User")
                    return True, username
                if response.status_code == 403:
                    return False, "Invalid API key"
                return False, f"HTTP {response.status_code}"
            except requests.exceptions.Timeout:
                return False, "Connection timeout"
            except requests.exceptions.ConnectionError:
                return False, "Connection failed"
            except Exception as e:
                error_msg = str(e).split("\n")[0][:40]  # First line, max 40 chars
                return False, error_msg

        def _apply(result):
            success, message = result
            if success:
                label.configure(text=f"✓ Valid ({message})", fg=self.colors.get("success", "#3fb950"))
            else:
                label.configure(text=f"✗ {message}", fg=self.colors.get("danger", "#f85149"))

        def _run():
            result = _test()
            self.root.after(0, lambda: _apply(result))

        threading.Thread(target=_run, daemon=True).start()

    def _verify_llm_api_key(self):
        """Verify the LLM API key by making a test request."""
        label = getattr(self, "_llm_verify_label", None)
        if not label:
            return

        key = self.llm_api_key_var.get().strip()
        if not key:
            label.configure(text="No key provided", fg=self.colors.get("warning", "#d29922"))
            return

        provider = self.llm_provider_var.get().strip().lower()
        if provider in ("disabled", "ollama", ""):
            label.configure(text="Verification not needed for local providers", fg=self.colors.get("muted", "#8b949e"))
            return

        label.configure(text="Verifying...", fg=self.colors.get("accent", "#58a6ff"))

        def _test():
            try:
                # Check if requests is available
                try:
                    import requests
                except ImportError:
                    return False, "requests library not available"

                # Test based on provider
                if provider == "openai":
                    # Test OpenAI API
                    url = "https://api.openai.com/v1/models"
                    headers = {"Authorization": f"Bearer {key}"}
                    response = requests.get(url, headers=headers, timeout=10)
                    if response.status_code == 200:
                        return True, "OpenAI API key valid"
                    if response.status_code == 401:
                        return False, "Invalid API key"
                    return False, f"HTTP {response.status_code}"

                if provider == "google":
                    # Test Google Gemini API
                    url = f"https://generativelanguage.googleapis.com/v1beta/models?key={key}"
                    response = requests.get(url, timeout=10)
                    if response.status_code == 200:
                        return True, "Google API key valid"
                    if response.status_code == 400:
                        return False, "Invalid API key"
                    return False, f"HTTP {response.status_code}"

                if provider == "anthropic":
                    # Test Anthropic API
                    url = "https://api.anthropic.com/v1/messages"
                    headers = {
                        "x-api-key": key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    }
                    # Small test request
                    data = {
                        "model": "claude-3-haiku-20240307",
                        "max_tokens": 1,
                        "messages": [{"role": "user", "content": "Hi"}],
                    }
                    response = requests.post(url, headers=headers, json=data, timeout=10)
                    if response.status_code == 200:
                        return True, "Anthropic API key valid"
                    if response.status_code == 401:
                        return False, "Invalid API key"
                    return False, f"HTTP {response.status_code}"

                # Generic OpenAI-compatible test
                endpoint = self.llm_endpoint_var.get().strip()
                if not endpoint:
                    return False, "No endpoint configured"
                url = f"{endpoint}/v1/models" if not endpoint.endswith("/v1/models") else endpoint
                headers = {"Authorization": f"Bearer {key}"}
                response = requests.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    return True, f"{provider.title()} API key valid"
                if response.status_code == 401:
                    return False, "Invalid API key"
                return False, f"HTTP {response.status_code}"

            except requests.exceptions.Timeout:
                return False, "Connection timeout"
            except requests.exceptions.ConnectionError:
                return False, "Connection failed"
            except Exception as e:
                error_msg = str(e).split("\n")[0][:40]  # First line, max 40 chars
                return False, error_msg

        def _apply(result):
            success, message = result
            if success:
                label.configure(text=f"✓ {message}", fg=self.colors.get("success", "#3fb950"))
            else:
                label.configure(text=f"✗ {message}", fg=self.colors.get("danger", "#f85149"))

        def _run():
            result = _test()
            self.root.after(0, lambda: _apply(result))

        threading.Thread(target=_run, daemon=True).start()

    def _open_model_manager(self):
        """Open a window to add/remove Ollama models."""
        provider = self.llm_provider_var.get().strip().lower()
        if provider != "ollama":
            messagebox.showwarning(
                "Model Manager", "Model management is only available when LLM provider is set to Ollama."
            )
            return

        window = tk.Toplevel(self.root)
        window.title("Manage Ollama Models")
        window.resizable(False, False)
        window.configure(bg=self.colors["bg"])
        self._set_dark_titlebar(window)

        frame = ttk.Frame(window, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Manage Ollama Models", style="Heading.TLabel").pack(anchor="w", pady=(0, 4))
        ttk.Label(
            frame,
            text="Add or remove locally installed Ollama models.",
            style="Hint.TLabel",
            wraplength=500,
        ).pack(anchor="w", pady=(0, 12))

        # ── Installed Models Section ──
        installed_frame = ttk.LabelFrame(frame, text=" Installed Models ", padding=12)
        installed_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 12))

        # Listbox with scrollbar
        list_frame = ttk.Frame(installed_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        model_listbox = tk.Listbox(
            list_frame,
            bg=self.colors.get("card_bg", "#161b22"),
            fg=self.colors.get("fg", "#c9d1d9"),
            font=("Consolas", 10),
            selectmode=tk.SINGLE,
            height=10,
            width=50,
            yscrollcommand=scrollbar.set,
            highlightthickness=0,
            borderwidth=1,
            relief=tk.SOLID,
        )
        model_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=model_listbox.yview)

        status_label = ttk.Label(installed_frame, text="Loading...", style="Hint.TLabel")
        status_label.pack(pady=(8, 0))

        def refresh_models():
            """Load installed models into the listbox."""
            model_listbox.delete(0, tk.END)
            status_label.config(text="Loading...")

            def worker():
                try:
                    # Ensure ollama serve is running
                    try:
                        subprocess.Popen(
                            ["ollama", "serve"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                        )
                        time.sleep(0.5)
                    except Exception:
                        pass

                    models = self._list_ollama_models("http://localhost:11434")
                    return models if models else []
                except Exception as e:
                    return str(e)

            def apply(result):
                if isinstance(result, str):
                    status_label.config(text=f"Error: {result[:60]}")
                    return
                if not result:
                    status_label.config(text="No models installed")
                else:
                    status_label.config(text=f"{len(result)} model(s) installed")
                    for model in sorted(result):
                        model_listbox.insert(tk.END, model)

            def run():
                result = worker()
                window.after(0, lambda: apply(result))

            threading.Thread(target=run, daemon=True).start()

        # Remove button
        remove_btn_frame = ttk.Frame(installed_frame)
        remove_btn_frame.pack(pady=(8, 0))

        def remove_selected():
            selection = model_listbox.curselection()
            if not selection:
                messagebox.showwarning("Remove Model", "Select a model to remove.")
                return
            model_name = model_listbox.get(selection[0])

            if not _is_valid_model_name(model_name):
                messagebox.showwarning("Remove Model", "Invalid model name.")
                return

            confirm = messagebox.askyesno(
                "Remove Model",
                f"Remove model '{model_name}'?\n\nThis will free up disk space but the model will need to be re-downloaded if you want to use it again.",
            )
            if not confirm:
                return

            def task():
                with contextlib.suppress(Exception):
                    subprocess.Popen(
                        ["ollama", "serve"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    )
                result = subprocess.run(
                    ["ollama", "rm", model_name],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                if result.returncode != 0:
                    detail = (result.stderr or result.stdout or "Unknown error").strip()
                    raise RuntimeError(detail)
                return True

            def done(_):
                refresh_models()
                messagebox.showinfo("Remove Model", f"Removed model '{model_name}'.")

            def failed(err):
                messagebox.showerror(
                    "Remove Model",
                    f"Failed to remove model. Ensure Ollama is installed and running.\n\nDetails: {err}",
                )

            self._run_task(task, done, on_error=failed, message="Removing model...")

        ttk.Button(remove_btn_frame, text="Remove Selected", style="Danger.TButton", command=remove_selected).pack(
            side=tk.LEFT
        )
        ttk.Button(remove_btn_frame, text="Refresh", style="Secondary.TButton", command=refresh_models).pack(
            side=tk.LEFT, padx=(8, 0)
        )

        # ── Add Model Section ──
        add_frame = ttk.LabelFrame(frame, text=" Add Model ", padding=12)
        add_frame.pack(fill=tk.BOTH, pady=(0, 12))

        ttk.Label(
            add_frame,
            text="Select a suggested model or enter a custom name:",
            style="Hint.TLabel",
        ).pack(anchor="w", pady=(0, 8))

        # Suggested models dropdown
        model_var = tk.StringVar()
        model_combo = ttk.Combobox(add_frame, textvariable=model_var, width=45, state="readonly")
        model_combo["values"] = [f"{name} — {desc}" for name, desc in self._OLLAMA_SUGGESTED_MODELS]
        model_combo.current(0)
        model_combo.pack(fill=tk.X, pady=(0, 8))

        # Custom entry
        custom_frame = ttk.Frame(add_frame)
        custom_frame.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(custom_frame, text="Or custom:").pack(side=tk.LEFT)
        custom_entry = ttk.Entry(custom_frame, width=35)
        custom_entry.pack(side=tk.LEFT, padx=(8, 0))

        def add_model():
            custom_text = custom_entry.get().strip()
            if custom_text:
                model_to_add = custom_text
            else:
                selected = model_combo.get()
                # Extract model name (before " — ")
                model_to_add = selected.split(" — ")[0] if " — " in selected else selected

            if not model_to_add:
                messagebox.showwarning("Add Model", "Enter or select a model name.")
                return

            # Validate model name
            if not _is_valid_model_name(model_to_add):
                messagebox.showwarning(
                    "Add Model", "Invalid model name. Only letters, digits, '.', ':', '-', '_', '/' are allowed."
                )
                return

            confirm = messagebox.askyesno(
                "Add Model",
                f"Download and install model '{model_to_add}'?\n\nThis may take several minutes and use significant bandwidth.",
            )
            if not confirm:
                return

            def task(progress_cb):
                # Ensure ollama serve is running
                with contextlib.suppress(Exception):
                    subprocess.Popen(
                        ["ollama", "serve"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    )
                time.sleep(1)

                progress_cb(0, label=f"Pulling {model_to_add}...")

                # Use the Ollama REST API to pull with streaming progress
                endpoint = self._normalize_ollama_endpoint("http://localhost:11434")
                url = endpoint.rstrip("/") + "/api/pull"
                body = json.dumps({"name": model_to_add, "stream": True}).encode("utf-8")
                req = urllib.request.Request(
                    url,
                    data=body,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                try:
                    resp = _safe_urlopen(req, timeout=1800)
                except Exception as exc:
                    raise RuntimeError(
                        f"Could not connect to Ollama.\nEnsure 'ollama serve' is running.\n\nDetails: {exc}"
                    )

                for line in resp:
                    if not line:
                        continue
                    try:
                        msg = json.loads(line.decode("utf-8"))
                    except Exception:
                        continue

                    status = msg.get("status", "")
                    if status:
                        progress_cb(None, label=status or f"Pulling {model_to_add}...")

                if "error" in msg:
                    raise RuntimeError(msg["error"])

                return True

            def done(_):
                refresh_models()
                messagebox.showinfo("Add Model", f"Successfully installed model '{model_to_add}'.")
                custom_entry.delete(0, tk.END)

            def failed(err):
                messagebox.showerror(
                    "Add Model",
                    f"Failed to download model.\n\nDetails: {err}",
                )

            self._run_task(task, done, on_error=failed, message=f"Downloading {model_to_add}...")

        ttk.Button(add_frame, text="Download & Install", command=add_model).pack(anchor="w")

        # ── Close Button ──
        ttk.Button(frame, text="Close", style="Secondary.TButton", command=window.destroy).pack(pady=(0, 0))

        # Load models on open
        refresh_models()

        window.transient(self.root)
        window.grab_set()

    # -- Ollama model download after install --------------------------------

    _OLLAMA_SUGGESTED_MODELS = [
        ("llama3.2:3b", "3B — fast, good for most tasks (~2 GB)"),
        ("llama3.2:1b", "1B — ultra-light, minimal RAM (~1 GB)"),
        ("llama3.1:8b", "8B — higher quality, needs ~5 GB RAM (~4.7 GB)"),
        ("deepseek-r1:1.5b", "1.5B — compact reasoning model (~1.1 GB)"),
        ("deepseek-r1:7b", "7B — strong reasoning & analysis (~4.7 GB)"),
        ("deepseek-r1:14b", "14B — top-tier reasoning, needs ~9 GB RAM (~9 GB)"),
        ("qwen2.5:3b", "3B — multilingual, strong reasoning (~1.9 GB)"),
        ("phi4-mini:3.8b", "3.8B — Microsoft, strong on analysis (~2.4 GB)"),
        ("mistral:7b", "7B — solid all-rounder (~4.1 GB)"),
        ("gemma3:4b", "4B — Google, fast & capable (~3.3 GB)"),
    ]

    def _offer_ollama_model_download(self):
        """Show a dialog to pick and download an Ollama model right after install."""
        window = tk.Toplevel(self.root)
        window.title("Download Ollama Model")
        window.resizable(False, False)
        window.configure(bg=self.colors["bg"])
        self._set_dark_titlebar(window)

        frame = ttk.Frame(window, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Download a Model", style="Heading.TLabel").pack(anchor="w", pady=(0, 4))
        ttk.Label(
            frame,
            text="Ollama needs at least one model to work. Select a model below or enter a custom name.",
            style="Hint.TLabel",
            wraplength=460,
        ).pack(anchor="w", pady=(0, 12))

        selected_var = tk.StringVar()

        for model_name, desc in self._OLLAMA_SUGGESTED_MODELS:
            row = ttk.Frame(frame)
            row.pack(fill=tk.X, pady=2)

            rb = ttk.Radiobutton(
                row,
                variable=selected_var,
                value=model_name,
                text="",
            )
            rb.pack(side=tk.LEFT)

            name_lbl = ttk.Label(row, text=model_name, font=("Segoe UI", 11, "bold"))
            name_lbl.pack(side=tk.LEFT)
            # Clicking the name also selects the radio button
            name_lbl.bind("<Button-1>", lambda _, v=model_name: selected_var.set(v))

            desc_lbl = ttk.Label(row, text=f"  {desc}", style="Hint.TLabel")
            desc_lbl.pack(side=tk.LEFT)
            desc_lbl.bind("<Button-1>", lambda _, v=model_name: selected_var.set(v))

        # Pre-select the first model
        selected_var.set(self._OLLAMA_SUGGESTED_MODELS[0][0])

        ttk.Separator(frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=(8, 4))

        # Custom model name entry
        custom_row = ttk.Frame(frame)
        custom_row.pack(fill=tk.X, pady=4)
        custom_rb = ttk.Radiobutton(
            custom_row,
            text="",
            variable=selected_var,
            value="__custom__",
        )
        custom_rb.pack(side=tk.LEFT)
        ttk.Label(custom_row, text="Custom:", font=("Segoe UI", 11, "bold")).pack(side=tk.LEFT)
        custom_entry = ttk.Entry(custom_row, width=25)
        custom_entry.pack(side=tk.LEFT, padx=(8, 0))
        custom_entry.bind("<FocusIn>", lambda _: selected_var.set("__custom__"))

        # Link to Ollama model library
        link_label = tk.Label(
            frame,
            text="\U0001f517  Browse models at ollama.com/library",
            fg=self.colors.get("accent", "#58a6ff"),
            bg=self.colors.get("bg", "#0d1117"),
            font=("Segoe UI", 10, "underline"),
            cursor="hand2",
        )
        link_label.pack(anchor="w", pady=(8, 0))
        link_label.bind("<Button-1>", lambda _: self._open_url("https://ollama.com/library"))

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=(16, 0))

        def _do_download():
            choice = selected_var.get()
            if choice == "__custom__":
                choice = custom_entry.get().strip()
            if not choice:
                messagebox.showwarning("Ollama", "Enter or select a model name.")
                return
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:\-/]*", choice):
                messagebox.showwarning(
                    "Ollama", "Invalid model name. Only letters, digits, '.', ':', '-', '_', '/' are allowed."
                )
                return
            window.destroy()
            self._pull_ollama_model(choice)

        def _skip():
            window.destroy()
            messagebox.showinfo(
                "Ollama",
                "You can download models later from the LLM model dropdown "
                "or by running 'ollama pull <model>' in a terminal.",
            )

        ttk.Button(btn_frame, text="Download", command=_do_download).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Skip", style="Secondary.TButton", command=_skip).pack(side=tk.LEFT, padx=(8, 0))

        window.transient(self.root)
        window.grab_set()

    def _pull_ollama_model(self, model_name):
        """Pull (download) an Ollama model with progress feedback."""

        def task(progress_cb):
            # Ensure ollama serve is running
            with contextlib.suppress(Exception):
                subprocess.Popen(
                    ["ollama", "serve"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            time.sleep(1)  # Give serve a moment to start

            progress_cb(0, label=f"Pulling {model_name}...")

            # Use the Ollama REST API to pull with streaming progress
            endpoint = self._normalize_ollama_endpoint("http://localhost:11434")
            url = endpoint.rstrip("/") + "/api/pull"
            body = json.dumps({"name": model_name, "stream": True}).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                resp = _safe_urlopen(req, timeout=1800)  # 30 min timeout
            except Exception as exc:
                raise RuntimeError(
                    f"Could not connect to Ollama at {endpoint}.\nEnsure 'ollama serve' is running.\n\nDetails: {exc}"
                )

            last_status = ""
            try:
                for raw_line in resp:
                    line = raw_line.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    try:
                        msg = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    status = msg.get("status", "")
                    total = msg.get("total", 0)
                    completed = msg.get("completed", 0)

                    if msg.get("error"):
                        raise RuntimeError(msg["error"])

                    if total and total > 0:
                        pct = (completed / total) * 100
                        done_mb = completed / (1024 * 1024)
                        total_mb = total / (1024 * 1024)
                        progress_cb(
                            pct,
                            label=f"{status} — {done_mb:.1f} / {total_mb:.1f} MB",
                        )
                    elif status != last_status:
                        progress_cb(None, label=status or f"Pulling {model_name}...")
                    last_status = status
            finally:
                resp.close()

            # Stop the headless serve we started
            with contextlib.suppress(Exception):
                subprocess.run(
                    ["taskkill", "/F", "/IM", "ollama.exe"],
                    capture_output=True,
                    timeout=5,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )

            return model_name

        def done(result_name):
            self.status_var.set(f"\u2714 Downloaded Ollama model: {result_name}")
            # Auto-configure the LLM settings
            self.llm_provider_var.set("ollama")
            self.llm_endpoint_var.set("http://localhost:11434")
            self.llm_model_var.set(result_name)
            messagebox.showinfo(
                "Ollama",
                f"Model '{result_name}' downloaded successfully!\n\nLLM settings have been configured automatically.",
            )

        def failed(err):
            self.status_var.set("Model download failed")
            messagebox.showerror(
                "Ollama",
                f"Failed to download model '{model_name}'.\n\n"
                f"You can try manually: ollama pull {model_name}\n\n"
                f"Error: {err}",
            )

        self._run_task(
            task, done, on_error=failed, message=f"Downloading {model_name}...", progress_label=f"Pulling {model_name}"
        )
        self.cancel_button.pack_forget()

    def _open_install_llm_dialog(self):
        """Open a dialog to install a local LLM server."""
        _SERVERS = [
            {
                "name": "Ollama",
                "desc": "Headless CLI server \u2014 no desktop app needed. Best for automation.",
                "check": lambda: self._is_program_installed("ollama", ["--version"]),
                "winget": "Ollama.Ollama",
                "url": "https://ollama.com/download/OllamaSetup.exe",
                "homepage": "https://ollama.com/download",
                "silent_flag": "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-",
            },
            {
                "name": "LM Studio",
                "desc": "Desktop app with model browser. Download models in-app.",
                "check": lambda: self._is_path_installed(
                    [
                        os.path.expandvars(r"%LOCALAPPDATA%\LM-Studio\LM Studio.exe"),
                        os.path.expandvars(r"%LOCALAPPDATA%\Programs\LM-Studio\LM Studio.exe"),
                    ]
                ),
                "winget": "Element.LMStudio",
                "url": None,
                "homepage": "https://lmstudio.ai/download",
                "silent_flag": None,
            },
            {
                "name": "GPT4All",
                "desc": "Desktop app with built-in model library. Easy setup.",
                "check": lambda: self._is_path_installed(
                    [
                        os.path.expandvars(r"%LOCALAPPDATA%\nomic.ai\GPT4All\bin\chat.exe"),
                        os.path.expandvars(r"%PROGRAMFILES%\GPT4All\bin\chat.exe"),
                    ]
                ),
                "winget": "Nomic.GPT4All",
                "url": "https://gpt4all.io/installers/gpt4all-installer-win64.exe",
                "homepage": "https://gpt4all.io",
                "silent_flag": "/S",
            },
            {
                "name": "Jan",
                "desc": "Desktop app with chat UI. Download models in-app.",
                "check": lambda: self._is_path_installed(
                    [
                        os.path.expandvars(r"%LOCALAPPDATA%\Programs\jan\Jan.exe"),
                    ]
                ),
                "winget": "Jan.Jan",
                "url": None,
                "homepage": "https://jan.ai/download",
                "silent_flag": None,
            },
        ]

        window = tk.Toplevel(self.root)
        window.title("Manage LLM Servers")
        window.resizable(False, False)
        window.configure(bg=self.colors["bg"])
        self._set_dark_titlebar(window)

        frame = ttk.Frame(window, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Manage LLM Servers", style="Heading.TLabel").pack(anchor="w", pady=(0, 4))
        ttk.Label(
            frame,
            text="Select a local LLM server to install. These run on your machine for fully offline AI analysis.",
            style="Hint.TLabel",
            wraplength=460,
        ).pack(anchor="w", pady=(0, 12))

        status_vars = []
        install_buttons = []
        uninstall_buttons = []

        for _idx, srv in enumerate(_SERVERS):
            row_frame = ttk.Frame(frame)
            row_frame.pack(fill=tk.X, pady=4)

            # Left: name + description
            info = ttk.Frame(row_frame)
            info.pack(side=tk.LEFT, fill=tk.X, expand=True)
            ttk.Label(info, text=srv["name"], font=("Segoe UI", 11, "bold")).pack(anchor="w")
            ttk.Label(info, text=srv["desc"], style="Hint.TLabel").pack(anchor="w")

            # Right: status + install/uninstall buttons
            btn_frame = ttk.Frame(row_frame)
            btn_frame.pack(side=tk.RIGHT)

            status_var = tk.StringVar(value="Checking...")
            status_vars.append(status_var)
            status_lbl = tk.Label(
                btn_frame,
                textvariable=status_var,
                fg=self.colors.get("muted", "#8b949e"),
                bg=self.colors.get("bg", "#0d1117"),
                font=("Segoe UI", 9),
            )
            status_lbl.pack(side=tk.LEFT, padx=(0, 8))

            uninstall_btn = ttk.Button(
                btn_frame,
                text="Uninstall",
                style="Danger.TButton",
                command=lambda s=srv: (window.destroy(), self._uninstall_llm_server(s)),
            )
            uninstall_btn.pack_forget()  # shown only when installed
            uninstall_buttons.append(uninstall_btn)

            install_btn = ttk.Button(
                btn_frame,
                text="Install",
                command=lambda s=srv: (window.destroy(), self._install_llm_server(s)),
            )
            install_btn.pack(side=tk.LEFT)
            install_buttons.append(install_btn)

            ttk.Separator(frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=4)

        # Check installed status in background
        def _check_all():
            results = []
            for srv in _SERVERS:
                try:
                    installed = srv["check"]()
                except Exception:
                    installed = False
                results.append(installed)
            return results

        def _apply_checks(results):
            for i, installed in enumerate(results):
                if installed:
                    status_vars[i].set("\u2714 Installed")
                    # Find the status label widget and color it green
                    parent = install_buttons[i].master
                    for child in parent.winfo_children():
                        if isinstance(child, tk.Label):
                            child.configure(fg=self.colors.get("success", "#3fb950"))
                    install_buttons[i].pack_forget()
                    uninstall_buttons[i].pack(side=tk.LEFT)
                else:
                    status_vars[i].set("Not installed")
                    uninstall_buttons[i].pack_forget()
                    install_buttons[i].pack(side=tk.LEFT)

        def _run_checks():
            results = _check_all()
            self.root.after(0, lambda: _apply_checks(results))

        threading.Thread(target=_run_checks, daemon=True).start()

        ttk.Button(frame, text="Close", style="Secondary.TButton", command=window.destroy).pack(anchor="e", pady=(8, 0))
        window.transient(self.root)
        window.grab_set()

    @staticmethod
    def _is_program_installed(cmd, args):
        """Check if a CLI program is available."""
        try:
            result = subprocess.run(
                [cmd, *args],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            return result.returncode == 0
        except Exception:
            return False

    @staticmethod
    def _is_path_installed(paths):
        """Check if any of the given file paths exist."""
        return any(os.path.isfile(p) for p in paths)

    def _install_llm_server(self, server_info):
        """Install a local LLM server via winget or direct download with progress in main window."""
        name = server_info["name"]
        winget_id = server_info["winget"]
        download_url = server_info["url"]
        homepage = server_info["homepage"]
        silent_flag = server_info["silent_flag"]

        def task(progress_cb):
            # Prefer direct download (shows real progress bar) over winget
            if download_url and silent_flag:
                tmp_dir = None
                try:
                    tmp_dir = tempfile.mkdtemp(prefix=f"{name.lower().replace(' ', '_')}_")
                    installer_path = os.path.join(tmp_dir, f"{name}_setup.exe")

                    progress_cb(0, label=f"Downloading {name}...")

                    req = urllib.request.Request(
                        download_url,
                        headers={"User-Agent": "PCAP-Sentry/1.0"},
                    )
                    resp = _safe_urlopen(req, timeout=120)
                    _MAX_INSTALLER_BYTES = 500 * 1024 * 1024  # 500 MB cap
                    try:
                        total_size = int(resp.headers.get("Content-Length", 0))
                        if total_size > _MAX_INSTALLER_BYTES:
                            raise RuntimeError(f"Installer too large ({total_size} bytes).")
                        downloaded = 0
                        dl_start_time = time.time()
                        last_speed_time = dl_start_time
                        last_speed_bytes = 0
                        current_speed = 0.0
                        with open(installer_path, "wb") as f:
                            while True:
                                chunk = resp.read(65536)
                                if not chunk:
                                    break
                                f.write(chunk)
                                downloaded += len(chunk)
                                if downloaded > _MAX_INSTALLER_BYTES:
                                    raise RuntimeError("Installer download exceeded 500 MB limit.")
                                # Calculate download speed (update every 0.5s)
                                now = time.time()
                                speed_interval = now - last_speed_time
                                if speed_interval >= 0.5:
                                    current_speed = (downloaded - last_speed_bytes) / speed_interval
                                    last_speed_bytes = downloaded
                                    last_speed_time = now
                                speed_mb = current_speed / (1024 * 1024)
                                if total_size > 0:
                                    pct = (downloaded / total_size) * 100
                                    dl_mb = downloaded / (1024 * 1024)
                                    total_mb = total_size / (1024 * 1024)
                                    # Calculate ETA
                                    eta_str = ""
                                    if current_speed > 0:
                                        remaining = total_size - downloaded
                                        eta_secs = remaining / current_speed
                                        if eta_secs < 60:
                                            eta_str = f" — {eta_secs:.0f}s left"
                                        else:
                                            eta_str = f" — {eta_secs / 60:.1f}m left"
                                    speed_str = f" ({speed_mb:.1f} MB/s)" if current_speed > 0 else ""
                                    progress_cb(
                                        pct,
                                        label=f"Downloading {name} — {dl_mb:.1f} / {total_mb:.1f} MB{speed_str}{eta_str}",
                                    )
                                else:
                                    dl_mb = downloaded / (1024 * 1024)
                                    speed_str = f" ({speed_mb:.1f} MB/s)" if current_speed > 0 else ""
                                    progress_cb(None, label=f"Downloading {name} — {dl_mb:.1f} MB{speed_str}")
                    finally:
                        resp.close()

                    progress_cb(None, label=f"Installing {name}...")
                    # Run installer elevated via ShellExecuteExW so UAC
                    # grants admin rights and the installer runs truly silent
                    rc = self._run_elevated(
                        installer_path,
                        silent_flag,
                        progress_cb,
                        name,
                    )
                    if rc == 0:
                        # Kill Ollama desktop app if it auto-launched
                        if "ollama" in name.lower():
                            for pn in ["ollama app.exe", "Ollama.exe"]:
                                with contextlib.suppress(Exception):
                                    subprocess.run(
                                        ["taskkill", "/F", "/IM", pn],
                                        capture_output=True,
                                        timeout=5,
                                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                                    )
                        return "download"
                except Exception:
                    progress_cb(None, label="Download failed, trying winget...")

                finally:
                    if tmp_dir:
                        shutil.rmtree(tmp_dir, ignore_errors=True)

            # Fallback: winget (no real progress but shows elapsed time)
            progress_cb(None, label=f"Installing {name} via winget...")
            try:
                proc = subprocess.Popen(
                    [
                        "winget",
                        "install",
                        "-e",
                        "--id",
                        winget_id,
                        "--accept-package-agreements",
                        "--accept-source-agreements",
                        "-h",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                line_q = queue.Queue()

                def _reader():
                    try:
                        for ln in proc.stdout:
                            line_q.put(ln)
                    except Exception:
                        pass
                    line_q.put(None)

                threading.Thread(target=_reader, daemon=True).start()

                winget_start = time.time()
                while True:
                    try:
                        line = line_q.get(timeout=0.5)
                    except queue.Empty:
                        elapsed = int(time.time() - winget_start)
                        progress_cb(None, label=f"Installing {name} via winget ({elapsed}s)")
                        continue
                    if line is None:
                        break
                    parts = line.split("\r")
                    for raw_part in parts:
                        part = raw_part.strip()
                        if not part:
                            continue
                        pct = self._extract_percent(part)
                        if pct is not None:
                            progress_cb(pct, label=f"Installing {name}")
                        else:
                            progress_cb(None, label=f"Installing {name} - {part}")
                proc.wait()
                if proc.returncode == 0:
                    # Kill Ollama desktop app if it auto-launched
                    if "ollama" in name.lower():
                        for pn in ["ollama app.exe", "Ollama.exe"]:
                            with contextlib.suppress(Exception):
                                subprocess.run(
                                    ["taskkill", "/F", "/IM", pn],
                                    capture_output=True,
                                    timeout=5,
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                                )
                    return "winget"
            except FileNotFoundError:
                pass
            except Exception:
                pass

            return None

        def _on_done(method):
            try:
                installed = server_info["check"]()
            except Exception:
                installed = False

            if installed or method is not None:
                self.status_var.set(f"\u2714 {name} installed")
                # Kill the Ollama desktop app if it auto-launched during install
                if "ollama" in name.lower():
                    for proc_name in ["ollama app.exe", "Ollama.exe"]:
                        with contextlib.suppress(Exception):
                            subprocess.run(
                                ["taskkill", "/F", "/IM", proc_name],
                                capture_output=True,
                                timeout=5,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                            )
                # Remove auto-start shortcut that some servers (e.g. Ollama) add
                try:
                    startup_lnk = os.path.join(
                        os.environ.get("APPDATA", ""),
                        "Microsoft",
                        "Windows",
                        "Start Menu",
                        "Programs",
                        "Startup",
                        f"{name}.lnk",
                    )
                    if os.path.isfile(startup_lnk):
                        os.remove(startup_lnk)
                except Exception:
                    pass
                # Also check for Ollama-specific startup entry
                if "ollama" in name.lower():
                    try:
                        ollama_lnk = os.path.join(
                            os.environ.get("APPDATA", ""),
                            "Microsoft",
                            "Windows",
                            "Start Menu",
                            "Programs",
                            "Startup",
                            "Ollama.lnk",
                        )
                        if os.path.isfile(ollama_lnk):
                            os.remove(ollama_lnk)
                    except Exception:
                        pass
                    # Remove registry auto-start entry if present
                    try:
                        import winreg

                        key = winreg.OpenKey(
                            winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Run",
                            0,
                            winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE,
                        )
                        try:
                            winreg.QueryValueEx(key, "Ollama")
                            winreg.DeleteValue(key, "Ollama")
                        except FileNotFoundError:
                            pass
                        finally:
                            winreg.CloseKey(key)
                    except Exception:
                        pass
                if "ollama" in name.lower():
                    if messagebox.askyesno(
                        name,
                        f"{name} installed successfully!\n\n"
                        f"Would you like to download a model now?\n"
                        f"Ollama needs at least one model to work.",
                    ):
                        self.root.after(100, self._offer_ollama_model_download)
                    else:
                        messagebox.showinfo(
                            name,
                            "You can download models later from the LLM model dropdown "
                            "or by running 'ollama pull <model>' in a terminal.",
                        )
                else:
                    messagebox.showinfo(
                        name,
                        f"{name} installed successfully.\n\n"
                        f"Select '{server_info['name']}' from the LLM server dropdown, "  # nosec B608 - UI message, not SQL
                        f"refresh models, and test the connection.",
                    )
            else:
                self.status_var.set(f"{name}: manual install needed")
                messagebox.showinfo(
                    name,
                    f"{name} could not be installed automatically.\n\n"
                    f"Please download it manually from:\n{homepage}\n\n"  # nosec B608 - UI message, not SQL
                    f"After installing, select it from the LLM server dropdown.",
                )

        def _on_failed(err):
            self.status_var.set(f"{name} install failed")
            messagebox.showerror(
                name,
                f"Failed to install {name}.\n\nYou can download it manually from:\n{homepage}\n\nError: {err}",
            )

        self._run_task(
            task, _on_done, on_error=_on_failed, message=f"Installing {name}...", progress_label=f"Installing {name}"
        )
        # Hide cancel button — LLM install cannot be cleanly cancelled
        self.cancel_button.pack_forget()

    def _uninstall_llm_server(self, server_info):
        """Uninstall an LLM server via winget."""
        name = server_info["name"]
        winget_id = server_info["winget"]

        if not messagebox.askyesno(
            f"Uninstall {name}",
            f"Are you sure you want to uninstall {name}?\n\n"
            f"This will remove the server application.\n"
            f"Downloaded models may remain in your user profile.",
        ):
            return

        def task(progress_cb):
            # Kill running processes first (Ollama specifically)
            if "ollama" in name.lower():
                for proc_name in ["ollama.exe", "ollama app.exe"]:
                    with contextlib.suppress(Exception):
                        subprocess.run(
                            ["taskkill", "/F", "/IM", proc_name],
                            capture_output=True,
                            timeout=5,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                        )
                time.sleep(1)

            progress_cb(None, label=f"Uninstalling {name} via winget...")
            try:
                proc = subprocess.Popen(
                    ["winget", "uninstall", "--id", winget_id, "-e", "--silent", "--accept-source-agreements"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                line_q = queue.Queue()

                def _reader():
                    try:
                        for ln in proc.stdout:
                            line_q.put(ln)
                    except Exception:
                        pass
                    line_q.put(None)

                threading.Thread(target=_reader, daemon=True).start()

                start_t = time.time()
                while True:
                    try:
                        line = line_q.get(timeout=0.5)
                    except queue.Empty:
                        elapsed = int(time.time() - start_t)
                        progress_cb(None, label=f"Uninstalling {name} ({elapsed}s)")
                        continue
                    if line is None:
                        break
                    part = line.strip()
                    if part:
                        progress_cb(None, label=f"Uninstalling {name} — {part}")
                proc.wait()
                return proc.returncode == 0
            except FileNotFoundError:
                return False
            except Exception:
                return False

        def _on_done(success):
            # Re-check if still installed
            try:
                still_installed = server_info["check"]()
            except Exception:
                still_installed = False

            if not still_installed:
                self.status_var.set(f"{name} uninstalled")
                # Remove auto-start shortcut if it exists
                try:
                    startup_lnk = os.path.join(
                        os.environ.get("APPDATA", ""),
                        "Microsoft",
                        "Windows",
                        "Start Menu",
                        "Programs",
                        "Startup",
                        f"{name}.lnk",
                    )
                    if os.path.isfile(startup_lnk):
                        os.remove(startup_lnk)
                except Exception:
                    pass
                messagebox.showinfo(
                    name,
                    f"{name} has been uninstalled.\n\n"
                    f"Note: Downloaded models may still exist in your\n"
                    f"user profile and can be deleted manually.",
                )
            else:
                self.status_var.set(f"{name} uninstall incomplete")
                messagebox.showwarning(
                    name,
                    f"{name} could not be fully uninstalled.\n\n"
                    f"You may need to uninstall it manually from\n"
                    f"Windows Settings > Apps.",
                )

        def _on_failed(err):
            self.status_var.set(f"{name} uninstall failed")
            messagebox.showerror(
                name,
                f"Failed to uninstall {name}.\n\nError: {err}",
            )

        self._run_task(
            task,
            _on_done,
            on_error=_on_failed,
            message=f"Uninstalling {name}...",
            progress_label=f"Uninstalling {name}",
        )
        self.cancel_button.pack_forget()

    @staticmethod
    def _extract_percent(text):
        """Extract a percentage value from a line of text (e.g. '45%' or 'Progress: 72%')."""
        m = re.search(r"(\d{1,3})%", text)
        if m:
            val = int(m.group(1))
            if 0 <= val <= 100:
                return val
        return None

    def _run_elevated(self, exe_path, params, progress_cb=None, name=""):
        """Run an installer elevated (UAC) and wait for it to finish.

        Uses ShellExecuteExW with the 'runas' verb so Windows shows a single
        UAC prompt, then the installer runs with admin rights fully silent.
        Returns the process exit code, or -1 on failure.
        """
        from ctypes import wintypes

        class SHELLEXECUTEINFO(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("fMask", ctypes.c_ulong),
                ("hwnd", wintypes.HANDLE),
                ("lpVerb", ctypes.c_wchar_p),
                ("lpFile", ctypes.c_wchar_p),
                ("lpParameters", ctypes.c_wchar_p),
                ("lpDirectory", ctypes.c_wchar_p),
                ("nShow", ctypes.c_int),
                ("hInstApp", wintypes.HINSTANCE),
                ("lpIDList", ctypes.c_void_p),
                ("lpClass", ctypes.c_wchar_p),
                ("hkeyClass", wintypes.HKEY),
                ("dwHotKey", wintypes.DWORD),
                ("hIconOrMonitor", wintypes.HANDLE),
                ("hProcess", wintypes.HANDLE),
            ]

        SEE_MASK_NOCLOSEPROCESS = 0x00000040
        SW_HIDE = 0

        sei = SHELLEXECUTEINFO()
        sei.cbSize = ctypes.sizeof(sei)
        sei.fMask = SEE_MASK_NOCLOSEPROCESS
        sei.hwnd = None
        sei.lpVerb = "runas"
        sei.lpFile = exe_path
        sei.lpParameters = params
        sei.lpDirectory = None
        sei.nShow = SW_HIDE
        sei.hProcess = None

        if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei)):
            return -1

        if not sei.hProcess:
            return -1

        # Poll until the elevated process finishes, updating progress
        inst_start = time.time()
        while True:
            wait_result = ctypes.windll.kernel32.WaitForSingleObject(
                sei.hProcess,
                500,  # 500 ms timeout
            )
            if wait_result == 0:  # WAIT_OBJECT_0 — process finished
                break
            elapsed = int(time.time() - inst_start)
            if progress_cb:
                progress_cb(None, label=f"Installing {name} ({elapsed}s)")

        exit_code = wintypes.DWORD()
        ctypes.windll.kernel32.GetExitCodeProcess(
            sei.hProcess,
            ctypes.byref(exit_code),
        )
        ctypes.windll.kernel32.CloseHandle(sei.hProcess)
        return exit_code.value

    def _check_internet_and_set_offline(self):
        """Check internet connectivity at startup; auto-enable offline mode if unreachable."""
        try:
            if self.offline_mode_var.get():
                return  # Already offline, nothing to check

            def _probe():
                try:
                    req = urllib.request.Request(
                        "https://www.google.com",
                        method="HEAD",
                        headers={"User-Agent": "PCAP-Sentry/connectivity-check"},
                    )
                    _safe_urlopen(req, timeout=4)
                    return True
                except Exception:
                    return False

            def _apply(online):
                try:
                    if self._shutting_down:
                        return
                    if not online and not self.offline_mode_var.get():
                        self.offline_mode_var.set(True)
                        self._save_settings_from_vars()
                        self.root_title = self._get_window_title()
                        self.root.title(self.root_title)
                        self.status_var.set("No internet detected — offline mode enabled automatically.")
                except Exception:
                    pass  # Don't crash startup if we can't set offline mode

            def _run():
                try:
                    online = _probe()
                    if not self._shutting_down:
                        self.root.after(0, lambda: _apply(online))
                except Exception:
                    pass  # Don't crash startup

            threading.Thread(target=_run, daemon=True).start()
        except Exception:
            pass  # Don't crash startup if internet check fails to initialize

    def _auto_detect_llm(self):
        try:
            provider = self.llm_provider_var.get().strip().lower()
            endpoint = self.llm_endpoint_var.get().strip()

            # Only auto-detect for local LLM providers (not disabled or cloud services)
            if provider in ("disabled", ""):
                return

            # Skip cloud services (non-localhost endpoints)
            if endpoint:
                # Parse endpoint to check if it's local
                from urllib.parse import urlparse

                parsed = urlparse(endpoint)
                hostname = parsed.hostname or ""
                is_local = (
                    hostname in ("localhost", "127.0.0.1", "")
                    or hostname.startswith("192.168.")
                    or hostname.startswith("10.")
                )
                if not is_local:
                    return  # Skip cloud/remote endpoints

            # If LLM is configured with local provider, verify it works and update model if needed
            if provider in ("ollama", "openai_compatible"):
                self._verify_and_update_llm_at_startup()
                return

            # Skip auto-detect if user explicitly disabled it
            if not self.settings.get("llm_auto_detect", True):
                return

            ports = [1234, 8000, 8080, 5000, 5001]

            def worker():
                try:
                    ollama_base = "http://localhost:11434"
                    model_name = self._probe_ollama(ollama_base)
                    if model_name:
                        return {"provider": "ollama", "endpoint": ollama_base, "model": model_name}
                except Exception:
                    pass
                for port in ports:
                    base = f"http://localhost:{port}"
                    try:
                        model_id = self._probe_openai_compat(base)
                    except Exception:
                        continue
                    if model_id:
                        return {"provider": "openai_compatible", "endpoint": base, "model": model_id}
                return None

            def apply_result(result):
                try:
                    if self._shutting_down or not result:
                        return
                    self.llm_provider_var.set(result["provider"])
                    self.llm_endpoint_var.set(result["endpoint"])
                    self.llm_model_var.set(result["model"])
                    self._set_llm_test_status("Auto", self.colors.get("accent", "#58a6ff"))
                    self._save_settings_from_vars()
                except Exception:
                    pass  # Don't crash if we can't apply auto-detected LLM settings

            def run():
                try:
                    result = worker()
                    if result and not self._shutting_down:
                        self.root.after(0, lambda: apply_result(result))
                except Exception:
                    pass  # Don't crash startup

            threading.Thread(target=run, daemon=True).start()
        except Exception:
            pass  # Don't crash startup if LLM auto-detect fails to initialize

    def _verify_and_update_llm_at_startup(self):
        """Verify that a configured LLM is reachable at startup and update model name if needed."""
        try:

            def worker():
                try:
                    provider = self.llm_provider_var.get().strip().lower()
                    endpoint = self.llm_endpoint_var.get().strip()

                    if provider == "ollama":
                        if not endpoint:
                            endpoint = "http://localhost:11434"
                        # Try to probe Ollama and get actual model name
                        model_name = self._probe_ollama(endpoint)
                        if model_name:
                            return {"success": True, "model": model_name}
                        return {"success": False}
                    if provider == "openai_compatible" and endpoint:
                        # Try to probe OpenAI-compatible endpoint and get model
                        api_key = self.llm_api_key_var.get().strip()
                        model_id = self._probe_openai_compat(endpoint, api_key=api_key)
                        if model_id:
                            return {"success": True, "model": model_id}
                        return {"success": False}
                except Exception:
                    pass
                return {"success": False}

            def apply_result(result):
                try:
                    # Check if shutting down or root still exists before updating UI
                    if self._shutting_down or not self.root or not self.root.winfo_exists():
                        return
                    if result.get("success"):
                        # Update model name if detected
                        if "model" in result:
                            self.llm_model_var.set(result["model"])
                            self._save_settings_from_vars()
                        self._set_llm_test_status("Auto", self.colors.get("accent", "#58a6ff"))
                    else:
                        self._set_llm_test_status("Not tested", self.colors.get("muted", "#8b949e"))
                except Exception:
                    pass

            def run():
                try:
                    result = worker()
                    if not self._shutting_down:
                        self.root.after(0, lambda: apply_result(result))
                except Exception:
                    pass

            threading.Thread(target=run, daemon=True).start()
        except Exception:
            pass  # Don't crash startup if LLM verification fails

    def _verify_llm_at_startup(self):
        """Verify that a configured LLM is reachable at startup."""
        try:

            def worker():
                try:
                    provider = self.llm_provider_var.get().strip().lower()
                    endpoint = self.llm_endpoint_var.get().strip()

                    if provider == "ollama":
                        if not endpoint:
                            endpoint = "http://localhost:11434"
                        # Try to probe Ollama
                        self._probe_ollama(endpoint)
                        return True
                    if provider == "openai_compatible" and endpoint:
                        # Try to probe OpenAI-compatible endpoint
                        api_key = self.llm_api_key_var.get().strip()
                        self._probe_openai_compat(endpoint, api_key=api_key)
                        return True
                except Exception:
                    pass
                return False

            def apply_result(success):
                try:
                    # Check if shutting down or root still exists before updating UI
                    if self._shutting_down or not self.root or not self.root.winfo_exists():
                        return
                    if success:
                        self._set_llm_test_status("Auto", self.colors.get("accent", "#58a6ff"))
                    else:
                        self._set_llm_test_status("Not tested", self.colors.get("muted", "#8b949e"))
                except Exception:
                    pass

            def run():
                try:
                    success = worker()
                    if not self._shutting_down:
                        self.root.after(0, lambda: apply_result(success))
                except Exception:
                    pass

            threading.Thread(target=run, daemon=True).start()
        except Exception:
            pass  # Don't crash startup

    def _open_llm_settings(self):
        """Open LLM configuration dialog."""
        window = tk.Toplevel(self.root)
        window.title("LLM Settings")
        window.resizable(True, True)
        window.geometry("800x650")
        window.minsize(750, 600)
        window.configure(bg=self.colors["bg"])
        self._set_dark_titlebar(window)

        # Scrollable container
        canvas = tk.Canvas(window, bg=self.colors["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(window, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind("<Configure>", lambda _: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Enable mouse wheel scrolling (widget-scoped, not global)
        def _on_mousewheel(event):
            try:
                canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
            except tk.TclError:
                pass  # Widget destroyed, ignore scroll event

        def _bind_mousewheel(_event):
            canvas.bind("<MouseWheel>", _on_mousewheel)

        def _unbind_mousewheel(_event):
            canvas.unbind("<MouseWheel>")

        canvas.bind("<Enter>", _bind_mousewheel)
        canvas.bind("<Leave>", _unbind_mousewheel)

        frame = ttk.Frame(scrollable_frame, padding=24)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="LLM Settings", style="Heading.TLabel").grid(
            row=0, column=0, sticky="w", columnspan=3, pady=(0, 12)
        )

        # Manage LLM servers button
        ttk.Label(frame, text="LLM servers:").grid(row=1, column=0, sticky="w", pady=6)
        install_frame = ttk.Frame(frame)
        install_frame.grid(row=1, column=1, sticky="w", pady=6)
        ttk.Button(
            install_frame,
            text="Manage LLM Servers\u2026",
            style="Secondary.TButton",
            command=self._open_install_llm_dialog,
        ).pack(side=tk.LEFT)
        self._help_icon_grid(
            frame,
            "Opens a dialog to install or uninstall a local LLM server (Ollama, LM Studio, GPT4All, or Jan).",
            row=1,
            column=2,
            sticky="w",
        )

        # --- Unified LLM server dropdown ---
        # Cloud providers that need an API key
        _CLOUD_PROVIDERS = {
            "OpenAI",
            "Google Gemini",
            "Mistral AI",
            "Groq",
            "Together AI",
            "OpenRouter",
            "Perplexity",
            "DeepSeek",
        }
        _CLOUD_ICON = " \u2601"  # ☁

        def _cloud(name):
            return name + _CLOUD_ICON if name in _CLOUD_PROVIDERS else name

        def _strip_cloud(name):
            return name.replace(_CLOUD_ICON, "") if name.endswith(_CLOUD_ICON) else name

        _LLM_SERVERS = {
            "Disabled": ("disabled", ""),
            # --- Local servers ---
            "Ollama": ("ollama", "http://localhost:11434"),
            "LM Studio": ("openai_compatible", "http://localhost:1234"),
            "LocalAI": ("openai_compatible", "http://localhost:8080"),
            "vLLM": ("openai_compatible", "http://localhost:8000"),
            "text-gen-webui": ("openai_compatible", "http://localhost:5000"),
            "GPT4All": ("openai_compatible", "http://localhost:4891"),
            "Jan": ("openai_compatible", "http://localhost:1337"),
            "KoboldCpp": ("openai_compatible", "http://localhost:5001"),
            "Custom": ("openai_compatible", ""),
            # --- Cloud providers (API key required) ---
            "OpenAI": ("openai_compatible", "https://api.openai.com"),
            "Google Gemini": ("openai_compatible", "https://generativelanguage.googleapis.com/v1beta/openai"),
            "Mistral AI": ("openai_compatible", "https://api.mistral.ai"),
            "Groq": ("openai_compatible", "https://api.groq.com/openai"),
            "Together AI": ("openai_compatible", "https://api.together.xyz"),
            "OpenRouter": ("openai_compatible", "https://openrouter.ai/api"),
            "Perplexity": ("openai_compatible", "https://api.perplexity.ai"),
            "DeepSeek": ("openai_compatible", "https://api.deepseek.com"),
        }

        # Reverse-map saved settings to display name
        def _resolve_display_name():
            prov = self.llm_provider_var.get().strip().lower()
            ep = self.llm_endpoint_var.get().strip().rstrip("/")
            if prov == "disabled":
                return "Disabled"
            if prov == "ollama":
                return "Ollama"
            # Match by endpoint
            for name, (p, default_ep) in _LLM_SERVERS.items():
                if p == "openai_compatible" and default_ep and ep == default_ep.rstrip("/"):
                    return _cloud(name)
            return "Custom"

        _llm_server_var = tk.StringVar(value=_resolve_display_name())

        def _get_server_values():
            """Return LLM server names, filtering out cloud providers when offline."""
            if self.offline_mode_var.get():
                return [n for n in _LLM_SERVERS if n not in _CLOUD_PROVIDERS]
            return [_cloud(n) for n in _LLM_SERVERS]

        ttk.Label(frame, text="LLM server:").grid(row=2, column=0, sticky="w", pady=6)
        provider_frame = ttk.Frame(frame)
        provider_frame.grid(row=2, column=1, sticky="w", pady=6)
        llm_provider_combo = ttk.Combobox(
            provider_frame,
            textvariable=_llm_server_var,
            values=_get_server_values(),
            width=20,
        )
        llm_provider_combo.state(["readonly"])
        llm_provider_combo.pack(side=tk.LEFT)
        detect_btn = ttk.Button(
            provider_frame,
            text="Detect",
            style="Secondary.TButton",
            command=lambda: self._detect_llm_server(_llm_server_var, _LLM_SERVERS, llm_model_combo),
        )
        detect_btn.pack(side=tk.LEFT, padx=(6, 0))
        self._detect_hint_label = tk.Label(
            provider_frame,
            text="",
            anchor="w",
            fg=self.colors.get("muted", "#8b949e"),
            bg=self.colors.get("bg", "#0d1117"),
            font=("Segoe UI", 9),
        )
        self._detect_hint_label.pack(side=tk.LEFT, padx=(8, 0))
        self._help_icon_grid(
            frame,
            "Select the LLM server to use. Local servers run offline on your machine. "
            "Cloud providers (marked with \u2601) require an API key and an internet connection. "
            "For Anthropic Claude, use OpenRouter which supports it via an OpenAI-compatible API. "
            "Click Detect to scan for running local servers. "
            "Select 'Disabled' to turn off LLM features.",
            row=2,
            column=2,
            sticky="w",
        )

        # --- API key row (shown for cloud providers) ---
        api_key_label = ttk.Label(frame, text="API key:")
        api_key_frame = ttk.Frame(frame)
        api_key_entry = ttk.Entry(api_key_frame, textvariable=self.llm_api_key_var, width=34, show="\u2022")
        api_key_entry.pack(side=tk.LEFT)
        api_key_show_var = tk.BooleanVar(value=False)

        def _toggle_key_visibility():
            api_key_entry.configure(show="" if api_key_show_var.get() else "\u2022")

        api_key_show_btn = ttk.Checkbutton(
            api_key_frame,
            text="Show",
            variable=api_key_show_var,
            command=_toggle_key_visibility,
            style="Quiet.TCheckbutton",
        )
        api_key_show_btn.pack(side=tk.LEFT, padx=(6, 0))
        verify_api_btn = ttk.Button(
            api_key_frame,
            text="Verify",
            style="Secondary.TButton",
            command=self._verify_llm_api_key,
        )
        verify_api_btn.pack(side=tk.LEFT, padx=(6, 0))
        api_key_hint = tk.Label(
            api_key_frame,
            text="",
            anchor="w",
            fg=self.colors.get("muted", "#8b949e"),
            bg=self.colors.get("bg", "#0d1117"),
            font=("Segoe UI", 8),
        )
        api_key_hint.pack(side=tk.LEFT, padx=(8, 0))

        # API key signup links per provider
        _API_KEY_URLS = {
            "OpenAI": "https://platform.openai.com/api-keys",
            "Google Gemini": "https://aistudio.google.com/apikey",
            "Mistral AI": "https://console.mistral.ai/api-keys",
            "Groq": "https://console.groq.com/keys",
            "Together AI": "https://api.together.xyz/settings/api-keys",
            "OpenRouter": "https://openrouter.ai/settings/keys",
            "Perplexity": "https://www.perplexy.ai/settings/api",
            "DeepSeek": "https://platform.deepseek.com/api_keys",
        }

        def _update_api_key_hint(name):
            url = _API_KEY_URLS.get(name, "")
            if url:
                api_key_hint.configure(text=f"Get key: {url}", cursor="hand2")
                api_key_hint.bind("<Button-1>", lambda _: __import__("webbrowser").open(url))
            else:
                api_key_hint.configure(text="", cursor="")
                api_key_hint.unbind("<Button-1>")

        # Verification status label
        self._llm_verify_label = tk.Label(
            frame,
            text=" ",
            font=("Segoe UI", 9),
            anchor="w",
            width=40,
            bg=self.colors.get("bg", "#0d1117"),
            fg=self.colors.get("muted", "#8b949e"),
        )

        def _show_api_key_row(visible):
            if visible:
                api_key_label.grid(row=3, column=0, sticky="w", pady=6)
                api_key_frame.grid(row=3, column=1, sticky="w", pady=6)
                self._llm_verify_label.grid(row=4, column=1, sticky="w", pady=(0, 4))
            else:
                api_key_label.grid_remove()
                api_key_frame.grid_remove()
                self._llm_verify_label.grid_remove()

        def _on_server_selected(*_):
            raw = _llm_server_var.get()
            name = _strip_cloud(raw)
            prov, ep = _LLM_SERVERS.get(name, ("disabled", ""))
            self.llm_provider_var.set(prov)
            if ep:
                self.llm_endpoint_var.set(ep)
            is_cloud = name in _CLOUD_PROVIDERS
            _show_api_key_row(is_cloud)
            _update_api_key_hint(name)
            _set_llm_fields_state()
            # Clear current model selection and refresh model list when changing servers
            self.llm_model_var.set("")
            if prov != "disabled":
                self._llm_server_just_changed = True
                self._refresh_llm_models(llm_model_combo)
            self._detect_hint_label.configure(text="")

        llm_provider_combo.bind("<<ComboboxSelected>>", _on_server_selected)

        # Initial visibility
        _show_api_key_row(_resolve_display_name() in _CLOUD_PROVIDERS and not self.offline_mode_var.get())
        _update_api_key_hint(_resolve_display_name())

        ttk.Label(frame, text="LLM model:").grid(row=5, column=0, sticky="w", pady=6)
        model_frame = ttk.Frame(frame)
        model_frame.grid(row=5, column=1, sticky="w", pady=6)
        llm_model_combo = ttk.Combobox(model_frame, textvariable=self.llm_model_var, width=42)
        llm_model_combo.pack(side=tk.LEFT)
        refresh_btn = ttk.Button(
            model_frame,
            text="\u21bb",
            width=3,
            style="Secondary.TButton",
            command=lambda: self._refresh_llm_models(llm_model_combo),
        )
        refresh_btn.pack(side=tk.LEFT, padx=(6, 0))
        self._help_icon_grid(
            frame,
            "Model name for the selected provider. Click \u21bb to detect available models.",
            row=5,
            column=2,
            sticky="w",
        )
        self._refresh_llm_models(llm_model_combo)

        # Manage Models button (below model field)
        manage_models_frame = ttk.Frame(frame)
        manage_models_frame.grid(row=6, column=1, sticky="w", pady=(0, 6))
        manage_models_btn = ttk.Button(
            manage_models_frame,
            text="Manage Models",
            style="Secondary.TButton",
            command=self._open_model_manager,
        )
        manage_models_btn.pack(side=tk.LEFT)

        ttk.Label(frame, text="LLM endpoint:").grid(row=7, column=0, sticky="w", pady=6)
        endpoint_frame = ttk.Frame(frame)
        endpoint_frame.grid(row=7, column=1, sticky="w", pady=6)
        llm_endpoint_entry = ttk.Entry(endpoint_frame, textvariable=self.llm_endpoint_var, width=34)
        llm_endpoint_entry.pack(side=tk.LEFT)
        self._help_icon_grid(
            frame,
            "API base URL for the LLM server. Auto-filled when you pick a server above. "
            "Edit this for custom ports or remote servers.",
            row=7,
            column=2,
            sticky="w",
        )

        ttk.Label(frame, text="Test LLM:").grid(row=8, column=0, sticky="w", pady=6)
        test_frame = ttk.Frame(frame)
        test_frame.grid(row=8, column=1, sticky="w", pady=6)
        ttk.Button(
            test_frame, text="Test Connection", style="Secondary.TButton", command=self._test_llm_connection
        ).pack(side=tk.LEFT)
        llm_test_status_label = tk.Label(
            test_frame,
            textvariable=self.llm_test_status_var,
            fg=self.colors.get("muted", "#8b949e"),
            bg=self.colors.get("bg", "#0d1117"),
            font=("Segoe UI", 10, "bold"),
            padx=8,
        )
        llm_test_status_label.pack(side=tk.LEFT)
        self._help_icon_grid(
            frame, "Sends a small test request to verify the current LLM settings.", row=8, column=2, sticky="w"
        )

        def _set_llm_fields_state(*_):
            provider = self.llm_provider_var.get().strip().lower()
            state = "normal" if provider != "disabled" else "disabled"
            llm_model_combo.configure(state=state)
            llm_endpoint_entry.configure(state=state)
            refresh_btn.configure(state=state)
            detect_btn.configure(state=state)
            is_ollama = provider == "ollama"
            manage_models_btn.configure(state=("normal" if (state == "normal" and is_ollama) else "disabled"))
            if state == "disabled":
                self._set_llm_test_status("Disabled", self.colors.get("muted", "#8b949e"))
                # Clear model list when disabled
                self._refresh_llm_models(llm_model_combo)
            else:
                if not self.llm_test_status_var.get():
                    self._set_llm_test_status("Not tested", self.colors.get("muted", "#8b949e"))
                # Refresh model list for active provider
                self._refresh_llm_models(llm_model_combo)

        llm_model_combo.bind("<<ComboboxSelected>>", _set_llm_fields_state)
        llm_model_combo.bind("<KeyRelease>", _set_llm_fields_state)
        _set_llm_fields_state()

        # Button row
        frame.grid_columnconfigure(1, weight=1)
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=8, column=0, columnspan=3, sticky="e", pady=(24, 0))
        ttk.Button(button_frame, text="Save", command=lambda: self._save_llm_settings(window)).pack(
            side=tk.LEFT, padx=2
        )
        ttk.Button(button_frame, text="Close", style="Secondary.TButton", command=window.destroy).pack(
            side=tk.LEFT, padx=2
        )

        window.grab_set()

    def _save_llm_settings(self, window):
        """Save LLM settings and close dialog."""
        self._save_settings_from_vars()
        self._update_llm_header_indicator()
        messagebox.showinfo("LLM Settings", "LLM settings saved successfully.", parent=window)
        window.destroy()

    def _test_llm_connection(self):
        if not self._llm_is_enabled():
            messagebox.showwarning(
                "LLM Test", "LLM provider is disabled. Configure an LLM provider in File → LLM Settings first."
            )
            self._set_llm_test_status("Disabled", self.colors.get("muted", "#8b949e"))
            return

        self._set_llm_test_status("Testing...", self.colors.get("muted", "#8b949e"))

        def task():
            provider = self.llm_provider_var.get().strip().lower()
            endpoint = self.llm_endpoint_var.get().strip()

            if provider == "ollama":
                if not endpoint:
                    endpoint = "http://localhost:11434"
                try:
                    model_name = self._probe_ollama(endpoint)
                    return {"success": True, "model": model_name}
                except Exception:
                    # Try to start Ollama and retry
                    try:
                        subprocess.Popen(
                            ["ollama", "serve"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                        )
                        time.sleep(1.2)
                        model_name = self._probe_ollama(endpoint)
                        return {"success": True, "model": model_name}
                    except Exception:
                        raise
            elif provider == "openai_compatible":
                if not endpoint:
                    raise ValueError("OpenAI-compatible endpoint is required")
                api_key = self.llm_api_key_var.get().strip()
                model_id = self._probe_openai_compat(endpoint, api_key=api_key)
                return {"success": True, "model": model_id}
            else:
                raise ValueError(f"Unsupported LLM provider: {provider}")

        def done(result):
            self._set_llm_test_status("OK", self.colors.get("success", "#3fb950"))

        def failed(err):
            self._set_llm_test_status("FAIL", self.colors.get("danger", "#f85149"))
            _write_error_log("LLM test failed", err)

            provider = self.llm_provider_var.get().strip().lower()
            endpoint = self.llm_endpoint_var.get().strip() or "http://localhost:11434"
            if provider == "ollama" and endpoint.rstrip("/").endswith("/v1"):
                messagebox.showerror(
                    "LLM Test",
                    "LLM test failed. The Ollama endpoint should not include /v1.\n\nUse: http://localhost:11434",
                )
                return
            if provider == "ollama" and "HTTP Error 404" in str(err):
                try:
                    model_id = self._probe_openai_compat(self._normalize_openai_endpoint(endpoint))
                except Exception:
                    model_id = None
                if model_id:
                    messagebox.showerror(
                        "LLM Test",
                        "LLM test failed with 404. The endpoint looks OpenAI-compatible.\n\n"
                        "Try setting LLM provider to 'openai_compatible'.",
                    )
                    return

            messagebox.showerror("LLM Test", f"LLM test failed: {err}")

        self._run_task(task, done, on_error=failed)

    def _apply_label_to_kb(self, label, stats, features, summary, title, message):
        # Move ALL KB operations to background thread to prevent UI freeze
        def kb_task():
            # Step 1: Add to knowledge base (I/O operation)
            add_to_knowledge_base(label, stats, features, summary)
            # Step 2: Reload KB to get the updated version (I/O operation)
            kb = load_knowledge_base()
            return kb

        def kb_done(kb):
            # Update UI on main thread after KB operations complete
            self._last_kb_label = label
            self._last_kb_entry = kb[label][-1] if kb[label] else None
            self._sync_undo_buttons()
            self._refresh_kb()
            messagebox.showinfo(title, message)

            # Train model in background to avoid UI freeze
            if self.use_local_model_var.get():

                def train_task():
                    return _train_local_model(kb)

                def train_done(result):
                    model_bundle, err = result
                    if model_bundle is None:
                        messagebox.showinfo("Local Model", err or "Local model training skipped.")
                    else:
                        _save_local_model(model_bundle)
                        self.status_var.set("Local model updated.")

                def train_failed(exc):
                    messagebox.showwarning("Local Model", f"Model training failed: {exc}")

                self._run_task(train_task, train_done, on_error=train_failed, message="Training local model...")

        def kb_failed(exc):
            messagebox.showerror("Error", f"Failed to save to knowledge base: {exc}")

        self._run_task(kb_task, kb_done, on_error=kb_failed, message="Saving to knowledge base...")

    def _train(self, label):
        path = self.safe_path_var.get() if label == "safe" else self.mal_path_var.get()
        if not path:
            messagebox.showwarning("Missing file", "Please select a PCAP file.")
            return

        def task(progress_cb=None):
            return parse_pcap_path(
                path,
                max_rows=self.max_rows_var.get(),
                parse_http=self.parse_http_var.get(),
                progress_cb=progress_cb,
                use_high_memory=self.use_high_memory_var.get(),
            )

        def done(result):
            try:
                _df, stats, _ = result
                if stats.get("packet_count", 0) == 0:
                    messagebox.showwarning("No data", "No IP packets found in this capture.")
                    return
                features = build_features(stats)
                summary = summarize_stats(stats)

                def apply_label(final_label):
                    self._apply_label_to_kb(
                        final_label,
                        stats,
                        features,
                        summary,
                        "Training",
                        f"Added {final_label} PCAP to knowledge base.",
                    )
                    if label == "safe":
                        self.safe_path_var.set("")
                    else:
                        self.mal_path_var.set("")

                self._confirm_llm_label(label, stats, summary, apply_label)
            except Exception as e:
                _write_error_log(f"Error training with {label} PCAP", e, sys.exc_info()[2])
                messagebox.showerror("Error", f"Failed to train with PCAP: {e!s}")

        self._run_task(task, done, message="Parsing PCAP...", progress_label="Parsing PCAP")

    def _label_current(self, label):
        if self.current_stats is None:
            messagebox.showwarning("Missing data", "Analyze a PCAP first.")
            return
        try:
            # Ensure the app data directory exists
            data_dir = _get_app_data_dir()
            os.makedirs(data_dir, exist_ok=True)

            features = build_features(self.current_stats)
            summary = summarize_stats(self.current_stats)

            def apply_label(final_label):
                self._apply_label_to_kb(
                    final_label,
                    self.current_stats,
                    features,
                    summary,
                    "Knowledge Base",
                    f"Current capture saved as {final_label}.",
                )

            self._confirm_llm_label(label, self.current_stats, summary, apply_label)
        except Exception as e:
            _write_error_log(f"Error labeling current capture as {label}", e, sys.exc_info()[2])
            messagebox.showerror("Error", f"Failed to label capture: {e!s}")

    # ------------------------------------------------------------------
    # Post-analysis LLM label suggestion (non-blocking)
    # ------------------------------------------------------------------
    def _hide_llm_suggestion(self):
        """Hide the LLM suggestion banner."""
        self._pending_llm_suggestion = None
        if self.llm_suggestion_frame is not None:
            self.llm_suggestion_frame.pack_forget()

    def _request_llm_suggestion_async(self, stats):
        """After analysis, ask the LLM for a label suggestion in the background."""
        self._hide_llm_suggestion()

        if not self._llm_is_ready():
            return

        summary = summarize_stats(stats)

        def worker():
            try:
                suggestion = self._request_llm_label(stats, summary)
                if suggestion and suggestion.get("label") in ("safe", "malicious"):
                    self.root.after(0, lambda s=suggestion: self._on_llm_suggestion(s))
            except Exception:
                pass  # Silently ignore — the suggestion is optional

        threading.Thread(target=worker, daemon=True).start()

    def _on_llm_suggestion(self, suggestion):
        """Called on the main thread when the LLM suggestion arrives."""
        # Only show if we still have analysis results (user hasn't started a new one)
        if self.current_stats is None:
            return
        self._pending_llm_suggestion = suggestion
        self._show_llm_suggestion(suggestion)

    def _show_llm_suggestion(self, suggestion):
        """Display the LLM suggestion banner with label, rationale, and accept button."""
        frame = self.llm_suggestion_frame
        if frame is None:
            return

        # Clear previous contents
        for w in frame.winfo_children():
            w.destroy()

        label = suggestion.get("label", "")
        confidence = suggestion.get("confidence")
        rationale = suggestion.get("rationale", "").strip()
        conf_text = f"{confidence:.0%}" if isinstance(confidence, (int, float)) else ""

        # Icon + label
        if label == "safe":
            icon = "\u2705"
            label_color = self.colors.get("success", "#3fb950")
            label_display = "Safe"
        else:
            icon = "\u26a0\ufe0f"
            label_color = self.colors.get("danger", "#f85149")
            label_display = "Malicious"

        header_text = f"{icon}  LLM suggests: {label_display}"
        if conf_text:
            header_text += f"  ({conf_text} confidence)"

        header = tk.Label(
            frame,
            text=header_text,
            fg=label_color,
            bg=self.colors.get("panel", "#161b22"),
            font=("Segoe UI Semibold", 11),
        )
        header.pack(side=tk.LEFT, padx=(0, 10))

        if rationale:
            reason = tk.Label(
                frame,
                text=rationale,
                fg=self.colors.get("fg", "#c9d1d9"),
                bg=self.colors.get("panel", "#161b22"),
                font=("Segoe UI", 10),
                wraplength=500,
                justify=tk.LEFT,
            )
            reason.pack(side=tk.LEFT, padx=(0, 10), fill=tk.X, expand=True)

        accept_btn = ttk.Button(
            frame,
            text=f"Accept \u2192 Mark as {label_display}",
            style="Success.TButton" if label == "safe" else "Warning.TButton",
            command=self._accept_llm_suggestion,
        )
        accept_btn.pack(side=tk.RIGHT, padx=(6, 0))

        dismiss_btn = ttk.Button(
            frame, text="\u2715", style="Secondary.TButton", command=self._hide_llm_suggestion, width=3
        )
        dismiss_btn.pack(side=tk.RIGHT, padx=(4, 0))

        frame.pack(fill=tk.X, pady=(0, 4))

    def _accept_llm_suggestion(self):
        """Apply the LLM-suggested label to the knowledge base (skips re-confirmation)."""
        suggestion = self._pending_llm_suggestion
        if suggestion is None or self.current_stats is None:
            return

        label = suggestion.get("label")
        if label not in ("safe", "malicious"):
            return

        self._hide_llm_suggestion()

        # Apply directly — no need to re-ask the LLM since this IS the LLM suggestion
        try:
            data_dir = _get_app_data_dir()
            os.makedirs(data_dir, exist_ok=True)
            features = build_features(self.current_stats)
            summary = summarize_stats(self.current_stats)
            self._apply_label_to_kb(
                label,
                self.current_stats,
                features,
                summary,
                "Knowledge Base",
                f"Current capture saved as {label} (LLM suggestion accepted).",
            )
        except Exception as e:
            _write_error_log(f"Error accepting LLM suggestion as {label}", e, sys.exc_info()[2])
            messagebox.showerror("Error", f"Failed to label capture: {e!s}")

    def _sync_undo_buttons(self):
        """Enable or disable all undo buttons based on current undo state."""
        has_undo = self._last_kb_label is not None and self._last_kb_entry is not None
        # Analyze tab undo button
        self.undo_kb_button.config(state=tk.NORMAL if has_undo else tk.DISABLED)
        # Train tab undo buttons
        self.undo_safe_button.config(state=tk.NORMAL if has_undo and self._last_kb_label == "safe" else tk.DISABLED)
        self.undo_mal_button.config(state=tk.NORMAL if has_undo and self._last_kb_label == "malicious" else tk.DISABLED)

    def _undo_last_kb_entry(self, filter_label=None):
        """Remove the most recently added knowledge base entry.

        If filter_label is provided, only undo if the last entry matches that label.
        """
        if self._last_kb_label is None or self._last_kb_entry is None:
            messagebox.showinfo("Undo", "Nothing to undo.")
            return

        # If called from a label-specific button, only undo matching entries
        if filter_label is not None and self._last_kb_label != filter_label:
            messagebox.showinfo("Undo", "Nothing to undo.")
            return

        label = self._last_kb_label
        entry = self._last_kb_entry

        kb = load_knowledge_base()
        entries = kb.get(label, [])

        # Find and remove the matching entry (compare by timestamp)
        ts = entry.get("timestamp")
        removed = False
        for i in range(len(entries) - 1, -1, -1):
            if entries[i].get("timestamp") == ts:
                entries.pop(i)
                removed = True
                break

        if removed:
            save_knowledge_base(kb)
            # Re-train local model if enabled
            if self.use_local_model_var.get():
                model_bundle, _err = _train_local_model(kb)
                if model_bundle is not None:
                    _save_local_model(model_bundle)
            self._refresh_kb()
            messagebox.showinfo("Undo", f"Removed last '{label}' entry from the knowledge base.")
        else:
            messagebox.showwarning("Undo", "Could not find the entry to remove. It may have already been deleted.")

        # Clear undo state
        self._last_kb_label = None
        self._last_kb_entry = None
        self._sync_undo_buttons()

    # ------------------------------------------------------------------
    # Education tab content builder
    # ------------------------------------------------------------------
    def _build_education_content(
        self,
        verdict,
        risk_score,
        stats,
        classifier_result,
        anomaly_result,
        anomaly_reasons,
        ioc_matches,
        ioc_available,
        ioc_count,
        suspicious_flows,
        threat_intel_findings,
    ):
        """Build beginner-friendly educational content based on analysis findings."""
        lines = []

        # ── Header ──
        lines.append("=" * 60)
        lines.append("  BEGINNER'S GUIDE: UNDERSTANDING YOUR RESULTS")
        lines.append("=" * 60)
        lines.append("")
        lines.append(f"  Overall Verdict : {verdict}")
        lines.append(f"  Risk Score      : {risk_score}/100")
        lines.append("")

        # ── What the verdict means ──
        lines.append("-" * 60)
        lines.append("  WHAT DOES THE VERDICT MEAN?")
        lines.append("-" * 60)
        lines.append("")
        if verdict == "Likely Malicious":
            lines.append(
                "  The analysis found strong signs that this network traffic is\n"
                "  related to malicious activity — such as malware communicating\n"
                "  with a remote server, data being stolen, or a known-bad IP\n"
                "  address being contacted.\n"
                "\n"
                "  Think of it like a smoke alarm going off in several rooms at\n"
                "  once. One alarm could be a false alarm, but many alarms\n"
                "  together strongly suggest a real fire."
            )
        elif "Suspicious" in verdict:
            lines.append(
                "  Something in this traffic looks unusual, but there isn't\n"
                "  enough evidence to say it's definitely malicious. It's like\n"
                "  finding an unlocked door — it might be nothing, or it might\n"
                "  mean someone was there.\n"
                "\n"
                "  Analysts call this the 'gray area.' The next step is always\n"
                "  to gather more context before making a decision."
            )
        else:
            lines.append(
                "  This traffic looks like normal, everyday network activity -\n"
                "  web browsing, DNS lookups, email, etc. No red flags were\n"
                "  detected by any of the checks.\n"
                "\n"
                "  Knowing what NORMAL looks like is actually one of the most\n"
                "  important skills in cybersecurity. The better you understand\n"
                "  normal patterns, the faster you'll spot something abnormal."
            )
        lines.append("")

        # ── Risk Score explained ──
        lines.append("-" * 60)
        lines.append("  HOW RISK SCORES WORK")
        lines.append("-" * 60)
        lines.append("")
        lines.append(
            "  The risk score (0-100) is a weighted combination of several\n"
            "  independent checks. Each check contributes a portion:\n"
            "\n"
            "    Machine Learning Model   ~50% of the score\n"
            "    Baseline Anomaly Check   ~30% of the score\n"
            "    Threat Intel (IoC) Match ~20% of the score\n"
            "\n"
            "  No single check decides the verdict alone. This layered\n"
            "  approach is called 'defense in depth' - even if one check\n"
            "  misses something, another may catch it."
        )
        lines.append("")

        # ── What was found — dynamic section ──
        lines.append("-" * 60)
        lines.append("  WHAT WAS FOUND IN THIS CAPTURE")
        lines.append("-" * 60)
        lines.append("")

        # -- Ports --
        top_ports = stats.get("top_ports", [])
        unusual_ports = [p for p, _ in top_ports if p not in COMMON_PORTS] if top_ports else []
        if top_ports:
            lines.append("  [PORTS]  What network services were used?")
            lines.append("")
            lines.append(
                "    Every program that talks over a network uses a 'port'\n"
                "    number.  Standard services use well-known ports (e.g.\n"
                "    443 for HTTPS).  If traffic appears on a port that\n"
                "    doesn't match any known service, it could be malware\n"
                "    trying to fly under the radar."
            )
            lines.append("")
            for port, count in top_ports[:10]:
                desc = PORT_DESCRIPTIONS.get(port, "Unknown / non-standard service")
                flag = "  ** UNUSUAL **" if port not in COMMON_PORTS else ""
                lines.append(f"      Port {port:>5} : {desc} ({count} packets){flag}")
            if unusual_ports:
                lines.append("")
                lines.append(
                    "    Ports marked UNUSUAL are not associated with any common\n"
                    "    service.  Malware frequently picks random high ports to\n"
                    "    avoid basic firewall rules.  Ask: 'What program in my\n"
                    "    network would use this port?'  If you can't answer,\n"
                    "    investigate further."
                )
            lines.append("")

        # -- DNS --
        dns_count = stats.get("dns_query_count", 0)
        top_dns = stats.get("top_dns", [])
        if dns_count:
            lines.append("  [DNS]  Domain name lookups")
            lines.append("")
            lines.append(
                "    DNS is the Internet's phone book.  Before your computer\n"
                "    can visit 'example.com' it asks a DNS server 'What IP\n"
                "    address is example.com?'  Even encrypted traffic exposes\n"
                "    these lookups, making DNS a goldmine for investigators."
            )
            lines.append("")
            if top_dns:
                lines.append("    Most-queried domains in this capture:")
                for domain, count in top_dns[:8]:
                    lines.append(f"      {domain}  ({count} lookups)")
                lines.append("")
                lines.append(
                    "    Red flags to watch for:\n"
                    "      - Random-looking names like 'x8k3j.xyz' may be\n"
                    "        DGA domains (Domain Generation Algorithm) used\n"
                    "        by malware to find its command server.\n"
                    "      - One domain queried hundreds of times could mean\n"
                    "        DNS tunneling — hiding data inside DNS requests."
                )
            lines.append("")

        # -- HTTP --
        http_count = stats.get("http_request_count", 0)
        http_hosts = stats.get("http_hosts", [])
        if http_count:
            lines.append("  [HTTP]  Unencrypted web traffic")
            lines.append("")
            lines.append(
                "    HTTP sends data in plain text — anyone between the\n"
                "    sender and receiver can read it.  Most modern sites use\n"
                "    HTTPS instead.  Finding HTTP traffic is always worth\n"
                "    a closer look."
            )
            lines.append("")
            if http_hosts:
                lines.append(f"    Hosts contacted via HTTP: {', '.join(http_hosts[:5])}")
                lines.append("")
            lines.append(
                "    Why it matters:\n"
                "      Malware sometimes uses plain HTTP to send stolen data\n"
                "      or receive commands because it's simpler to set up.\n"
                "      In Wireshark, filtering on 'http' lets you read the\n"
                "      actual URLs and payloads in the clear."
            )
            lines.append("")

        # -- TLS/HTTPS --
        tls_count = stats.get("tls_packet_count", 0)
        tls_sni = stats.get("tls_sni", [])
        if tls_count:
            lines.append("  [HTTPS / TLS]  Encrypted web traffic")
            lines.append("")
            lines.append(
                "    TLS encrypts the content so you can't read it, BUT the\n"
                "    initial 'handshake' reveals the destination server name\n"
                "    (called SNI — Server Name Indication).  You can always\n"
                "    see WHERE encrypted traffic is going, even if you can't\n"
                "    see WHAT it contains."
            )
            if tls_sni:
                lines.append("")
                lines.append(f"    Destinations seen (SNI): {', '.join(tls_sni[:5])}")
            lines.append("")

        # -- Packet sizes --
        avg_size = stats.get("avg_size", 0.0)
        median_size = stats.get("median_size", 0.0)
        lines.append("  [PACKET SIZES]  What the data sizes tell us")
        lines.append("")
        lines.append(f"    Average packet size  : {avg_size:.0f} bytes")
        lines.append(f"    Median packet size   : {median_size:.0f} bytes")
        lines.append("")
        if median_size and median_size < 120:
            lines.append(
                "    !! Many small packets detected.\n"
                "    This is a classic 'beaconing' pattern: malware sends\n"
                "    tiny, regular check-in messages to its controller.\n"
                "    Think of it like a spy regularly tapping a phone to\n"
                "    say 'I'm still here.' In Wireshark, try:\n"
                "      frame.len < 120"
            )
        elif avg_size and avg_size > 1200:
            lines.append(
                "    !! Unusually large packets detected.\n"
                "    Large packets can mean data exfiltration - an attacker\n"
                "    copying files out of the network.  Check which hosts\n"
                "    are sending the big packets and where they're going.\n"
                "    In Wireshark, try:\n"
                "      frame.len > 1200"
            )
        else:
            lines.append(
                "    Sizes look normal for typical web/network traffic.\n"
                "    Normal browsing mixes small packets (TCP ACKs, ~54 B)\n"
                "    with larger data packets (500-1,500 B)."
            )
        lines.append("")

        # -- IoC matches --
        if ioc_available and ioc_count:
            lines.append("  [THREAT INTEL]  Known-bad addresses contacted")
            lines.append("")
            lines.append(
                "    'IoC' stands for Indicator of Compromise.  Security\n"
                "    researchers maintain public lists of IP addresses and\n"
                "    domains that are linked to malware, phishing, botnets,\n"
                "    and other attacks.  Traffic to/from these addresses is\n"
                "    a serious red flag."
            )
            lines.append("")
            if ioc_matches.get("domains"):
                lines.append(f"    Matched domains: {', '.join(ioc_matches['domains'][:5])}")
            if ioc_matches.get("ips"):
                lines.append(f"    Matched IPs    : {', '.join(ioc_matches['ips'][:5])}")
            lines.append("")
            lines.append(
                "    What to do next:\n"
                "      1. Search each address on VirusTotal.com\n"
                "      2. Check AbuseIPDB.com for abuse reports\n"
                "      3. Note WHEN the traffic happened (business hours?)\n"
                "      4. Determine if any internal systems talked to it"
            )
            lines.append("")

        # -- Suspicious flows --
        if suspicious_flows:
            lines.append("  [SUSPICIOUS FLOWS]  Conversations that stand out")
            lines.append("")
            lines.append(
                "    These are specific network conversations (flows) that\n"
                "    triggered one or more heuristic red flags. Each flow is\n"
                "    a pair of hosts communicating over a specific protocol\n"
                "    and port. Below, every flagged flow is broken down with\n"
                "    the actual IPs, ports, and the reason it was flagged."
            )
            lines.append("")

            # Build a lookup of IoC IPs and domains for cross-referencing
            ioc_ip_set = set()
            if ioc_matches:
                ioc_ip_set = set(ioc_matches.get("ips", []))
                set(ioc_matches.get("domains", []))

            # Build a lookup of threat-intel flagged IPs/domains
            threat_ip_info = {}
            threat_domain_info = {}
            if threat_intel_findings.get("threat_intel"):
                intel = threat_intel_findings["threat_intel"]
                for ip_info in intel.get("risky_ips", []):
                    threat_ip_info[ip_info["ip"]] = ip_info
                for d_info in intel.get("risky_domains", []):
                    threat_domain_info[d_info["domain"]] = d_info

            # Build a mapping from IPs to DNS names seen in this capture
            top_dns = stats.get("top_dns", [])
            # Also check http_hosts and tls_sni for associations
            http_hosts = stats.get("http_hosts", [])
            tls_sni = stats.get("tls_sni", [])

            for idx, item in enumerate(suspicious_flows, 1):
                src_ip = item.get("src", "?")
                dst_ip = item.get("dst", "?")
                sport = item.get("sport", "?")
                dport = item.get("dport", "?")
                proto = item.get("proto", "?")

                lines.append("    " + "~" * 52)
                lines.append(f"    FLAGGED FLOW #{idx}")
                lines.append("    " + "~" * 52)
                lines.append("")

                # -- Specific traffic details --
                lines.append(f"      Source      : {src_ip}  (port {sport})")
                lines.append(f"      Destination : {dst_ip}  (port {dport})")
                lines.append(f"      Protocol    : {proto}")
                lines.append(f"      Data moved  : {item['bytes']}  in  {item['packets']} packets")
                lines.append("")

                # -- Describe the destination port --
                dport_int = int(dport) if str(dport).isdigit() else None
                if dport_int and dport_int in PORT_DESCRIPTIONS_SHORT:
                    lines.append(f"      Port {dport} is: {PORT_DESCRIPTIONS_SHORT[dport_int]}")
                elif dport_int and dport_int not in COMMON_PORTS:
                    lines.append(f"      Port {dport} is NOT a standard service port.")
                    lines.append(f"      Ask yourself: 'What program would use port {dport}?'")
                    lines.append("      If you can't answer, this is suspicious.")
                lines.append("")

                # -- Why it was flagged --
                raw = item["reason"].lower()
                matched_labels = []
                matched_explanations = []
                for key, (lbl, expl) in PATTERN_EDUCATION.items():
                    if key in raw:
                        matched_labels.append(lbl)
                        matched_explanations.append(expl)
                if not matched_labels:
                    matched_labels.append("FLAGGED BY HEURISTIC ANALYSIS")
                    matched_explanations.append(
                        "This flow was flagged by automated analysis.\n"
                        "      Review it manually in Wireshark for more context."
                    )

                lines.append("      Detection reason(s):")
                for i, (lbl, expl) in enumerate(zip(matched_labels, matched_explanations, strict=False)):
                    lines.append(f"        {i + 1}. {lbl}")
                    lines.append(f"           {expl}")
                    lines.append("")

                # -- Cross-reference with IoC data --
                src_is_ioc = src_ip in ioc_ip_set
                dst_is_ioc = dst_ip in ioc_ip_set
                if src_is_ioc or dst_is_ioc:
                    lines.append("      !! IoC BLOCKLIST MATCH:")
                    if src_is_ioc:
                        lines.append(f"         Source IP {src_ip} is on a known threat blocklist.")
                    if dst_is_ioc:
                        lines.append(f"         Destination IP {dst_ip} is on a known threat blocklist.")
                    lines.append("         This means security researchers have previously linked")
                    lines.append("         this address to malicious activity (malware, phishing,")
                    lines.append("         botnets, etc.).")
                    lines.append("")

                # -- Cross-reference with online threat intel --
                for ip_addr in [src_ip, dst_ip]:
                    if ip_addr in threat_ip_info:
                        ti = threat_ip_info[ip_addr]
                        risk = ti.get("risk_score", 0)
                        sev = "HIGH" if risk > 70 else "MEDIUM" if risk > 40 else "LOW"
                        lines.append(f"      !! ONLINE THREAT INTEL for {ip_addr}:")
                        lines.append(f"         Risk score: {risk:.0f}/100 ({sev})")
                        sources = ti.get("sources", {})
                        if sources.get("otx", {}).get("pulse_count"):
                            lines.append(f"         AlienVault OTX: {sources['otx']['pulse_count']} threat pulses")
                        if sources.get("abuseipdb", {}).get("abuse_confidence_score"):
                            lines.append(
                                f"         AbuseIPDB confidence: {sources['abuseipdb']['abuse_confidence_score']}%"
                            )
                        lines.append("")

                # -- Wireshark filter to isolate this exact flow --
                lines.append("      How to investigate this flow in Wireshark:")
                filter_parts = []
                if src_ip != "?":
                    filter_parts.append(f"ip.addr == {src_ip}")
                if dst_ip != "?":
                    filter_parts.append(f"ip.addr == {dst_ip}")
                if filter_parts:
                    wireshark_filter = " && ".join(filter_parts)
                    lines.append(f"        Filter: {wireshark_filter}")
                if dport_int:
                    proto_filter = "tcp" if proto == "TCP" else "udp" if proto == "UDP" else proto.lower()
                    lines.append(f"        Or:     {proto_filter}.port == {dport}")
                lines.append("")
                lines.append("        Steps:")
                lines.append("          1. Open the PCAP in Wireshark")
                lines.append("          2. Paste the filter above into the display filter bar")
                lines.append("          3. Right-click a packet -> Follow -> TCP/UDP Stream")
                lines.append("          4. Look at the payload — can you read any text?")
                lines.append("             Readable text in unexpected places = red flag")
                lines.append("          5. Check the timing — are packets evenly spaced?")
                lines.append("             Regular intervals = possible beaconing")
                lines.append("")

            # -- Summary of all flagged IPs for quick lookup --
            all_flagged_ips = set()
            for item in suspicious_flows:
                all_flagged_ips.add(item.get("src", "?"))
                all_flagged_ips.add(item.get("dst", "?"))
            all_flagged_ips.discard("?")
            if all_flagged_ips:
                lines.append("    " + "-" * 52)
                lines.append("    QUICK REFERENCE: ALL FLAGGED IP ADDRESSES")
                lines.append("    " + "-" * 52)
                lines.append("")
                lines.append("    Look up each of these on VirusTotal or AbuseIPDB:")
                lines.append("")
                for ip in sorted(all_flagged_ips):
                    notes = []
                    if ip in ioc_ip_set:
                        notes.append("IoC blocklist match")
                    if ip in threat_ip_info:
                        risk = threat_ip_info[ip].get("risk_score", 0)
                        notes.append(f"threat intel risk {risk:.0f}/100")
                    note_str = f"  ({', '.join(notes)})" if notes else ""
                    lines.append(f"      {ip}{note_str}")
                    lines.append(f"        https://www.virustotal.com/gui/ip-address/{ip}")
                    lines.append(f"        https://www.abuseipdb.com/check/{ip}")
                    lines.append("")

        # -- Threat intelligence online findings --
        if threat_intel_findings.get("threat_intel"):
            intel = threat_intel_findings["threat_intel"]
            if intel.get("risky_ips") or intel.get("risky_domains"):
                lines.append("  [ONLINE THREAT INTEL]  What public databases say")
                lines.append("")
                lines.append(
                    "    Multiple free, community-run databases track malicious\n"
                    "    infrastructure.  When an IP or domain shows up on these\n"
                    "    lists, it means security researchers have already linked\n"
                    "    it to attacks."
                )
                lines.append("")
                if intel.get("risky_ips"):
                    for ip_info in intel["risky_ips"][:5]:
                        risk = ip_info["risk_score"]
                        sev = "HIGH" if risk > 70 else "MEDIUM" if risk > 40 else "LOW"
                        lines.append(f"    IP {ip_info['ip']} — risk {risk:.0f}/100 ({sev})")
                if intel.get("risky_domains"):
                    for d_info in intel["risky_domains"][:5]:
                        risk = d_info["risk_score"]
                        sev = "HIGH" if risk > 70 else "MEDIUM" if risk > 40 else "LOW"
                        lines.append(f"    Domain {d_info['domain']} — risk {risk:.0f}/100 ({sev})")
                lines.append("")

        # ── Common attack patterns glossary ──
        lines.append("-" * 60)
        lines.append("  COMMON ATTACK PATTERNS (GLOSSARY)")
        lines.append("-" * 60)
        lines.append("")
        glossary = [
            (
                "Beaconing",
                "Malware sends small messages to its controller at\n"
                "    regular intervals (e.g., every 60 seconds) to say\n"
                "    'I'm still alive — send me commands.'  The regular\n"
                "    timing is the key giveaway.",
            ),
            (
                "Command & Control (C2)",
                "After infecting a machine, malware connects back to\n"
                "    the attacker's server to receive instructions.  This\n"
                "    two-way channel lets the attacker steal data, move\n"
                "    laterally, or deploy ransomware — all remotely.",
            ),
            (
                "Data Exfiltration",
                "The unauthorized transfer of data out of a network.\n"
                "    Attackers compress, encrypt, and upload stolen data\n"
                "    to external servers.  Look for large outbound\n"
                "    transfers to unfamiliar destinations.",
            ),
            (
                "DNS Tunneling",
                "Hiding data inside DNS queries/responses.  Since DNS\n"
                "    is almost never blocked, attackers abuse it to sneak\n"
                "    data past firewalls.  Long, random-looking subdomain\n"
                "    names are a telltale sign.",
            ),
            (
                "Port Scanning",
                "An attacker probes a target by connecting to many ports\n"
                "    in rapid succession to discover which services are\n"
                "    running.  It's the digital equivalent of checking\n"
                "    every window and door for an opening.",
            ),
            (
                "Lateral Movement",
                "Once inside a network, attackers move from machine to\n"
                "    machine looking for valuable data.  Watch for unusual\n"
                "    SMB (port 445) or RDP (port 3389) traffic between\n"
                "    internal hosts.",
            ),
            (
                "DGA (Domain Generation Algorithm)",
                "Malware automatically generates random domain names to\n"
                "    find its C2 server.  The domains look like nonsense\n"
                "    (e.g., 'jk8xf2.xyz').  Researchers reverse-engineer\n"
                "    these algorithms to predict and block them.",
            ),
            (
                "Man-in-the-Middle (MitM)",
                "An attacker secretly relays and potentially alters\n"
                "    communications between two parties.  This is one\n"
                "    reason HTTPS matters — encryption prevents tampering.",
            ),
        ]
        for term, desc in glossary:
            lines.append(f"  {term}")
            lines.append(f"    {desc}")
            lines.append("")

        # ── Quick Wireshark tips ──
        lines.append("-" * 60)
        lines.append("  WIRESHARK QUICK-START FOR BEGINNERS")
        lines.append("-" * 60)
        lines.append("")
        lines.append(
            "  Wireshark is a free tool that lets you inspect every\n"
            "  packet in a capture file.  Here are the most useful\n"
            "  display filters to get started:\n"
            "\n"
            "    ip.addr == 1.2.3.4          Traffic to/from a specific IP\n"
            "    tcp.port == 443             All HTTPS traffic\n"
            "    dns                         All DNS queries\n"
            "    http.request               All HTTP requests (readable!)\n"
            "    tcp.flags.syn == 1          Connection attempts only\n"
            "    frame.len < 100            Very small packets (beaconing?)\n"
            "    frame.len > 1200           Very large packets (exfil?)\n"
            "    tls.handshake.type == 1    TLS Client Hellos (see SNI)\n"
            "\n"
            "  Tip: Right-click any packet -> Follow -> TCP Stream to\n"
            "  reconstruct the full conversation between two hosts."
        )
        lines.append("")

        # ── Free online resources ──
        lines.append("-" * 60)
        lines.append("  FREE RESOURCES TO KEEP LEARNING")
        lines.append("-" * 60)
        lines.append("")
        resources = [
            (
                "Wireshark Official Docs & Wiki",
                "https://www.wireshark.org/docs/",
                "The definitive guide to Wireshark — filters, protocol\n    dissectors, capture techniques, and more.",
            ),
            (
                "SANS Internet Storm Center (ISC)",
                "https://isc.sans.edu/",
                "Daily threat diaries written by professional analysts.\n"
                "    Great for learning what real-world attacks look like.",
            ),
            (
                "Malware Traffic Analysis",
                "https://www.malware-traffic-analysis.net/",
                "Free PCAP samples of real malware traffic with detailed\n"
                "    write-ups.  Perfect for practicing analysis skills.",
            ),
            (
                "VirusTotal",
                "https://www.virustotal.com/",
                "Upload files, URLs, IPs, or domains to check them\n"
                "    against 70+ antivirus engines and community reports.",
            ),
            (
                "AbuseIPDB",
                "https://www.abuseipdb.com/",
                "Community database of reported malicious IP addresses.\n"
                "    Look up any suspicious IP from your captures here.",
            ),
            (
                "Shodan",
                "https://www.shodan.io/",
                "A search engine for Internet-connected devices.  Find\n"
                "    out what services an IP is running and whether it's\n"
                "    been flagged as malicious.",
            ),
            (
                "MITRE ATT&CK Framework",
                "https://attack.mitre.org/",
                "A knowledge base of adversary tactics, techniques, and\n"
                "    procedures.  The industry standard for categorizing\n"
                "    how attacks work (e.g., T1071 = Application Layer Protocol).",
            ),
            (
                "CyberDefenders",
                "https://cyberdefenders.org/",
                "Free, hands-on Blue Team challenges including PCAP\n"
                "    analysis labs.  Great for building practical skills.",
            ),
            (
                "TryHackMe — Intro to Network Analysis",
                "https://tryhackme.com/",
                "Interactive, browser-based cybersecurity training with\n"
                "    guided rooms on Wireshark and traffic analysis.",
            ),
            (
                "PCAP Samples from Netresec",
                "https://www.netresec.com/?page=PcapFiles",
                "Curated list of publicly available PCAP files for\n    practicing with real network captures.",
            ),
            (
                "AlienVault OTX (Open Threat Exchange)",
                "https://otx.alienvault.com/",
                "Free community-driven threat intelligence platform.\n"
                "    Search for IoCs and subscribe to 'pulses' from\n"
                "    security researchers around the world.",
            ),
        ]
        for name, url, desc in resources:
            lines.append(f"  {name}")
            lines.append(f"    {url}")
            lines.append(f"    {desc}")
            lines.append("")

        # ── Next steps ──
        lines.append("-" * 60)
        lines.append("  RECOMMENDED NEXT STEPS")
        lines.append("-" * 60)
        lines.append("")
        if verdict == "Likely Malicious":
            lines.append(
                "  1. Open this PCAP in Wireshark and apply the filters from\n"
                "     the Why tab to isolate the malicious conversations.\n"
                "  2. Look up every flagged IP/domain on VirusTotal and\n"
                "     AbuseIPDB to confirm they're truly malicious.\n"
                "  3. Check MITRE ATT&CK to classify the attack technique.\n"
                "  4. Document your findings — practice writing a short\n"
                "     incident summary (who, what, when, where, how).\n"
                "  5. Label this capture as 'Malicious' in the Train tab so\n"
                "     the ML model learns from it."
            )
        elif "Suspicious" in verdict:
            lines.append(
                "  1. Open this PCAP in Wireshark and examine the flagged\n"
                "     flows manually.\n"
                "  2. Research any unfamiliar IP addresses or domains using\n"
                "     VirusTotal, AbuseIPDB, or Shodan.\n"
                "  3. Consider the context: Is this traffic expected for the\n"
                "     device or network segment it came from?\n"
                "  4. If you determine it's safe, label it as such in the\n"
                "     Train tab to reduce future false positives.\n"
                "  5. If still unsure, compare it against a known-malicious\n"
                "     PCAP from malware-traffic-analysis.net."
            )
        else:
            lines.append(
                "  1. Label this capture as 'Safe' in the Train tab to help\n"
                "     build a stronger baseline of normal traffic.\n"
                "  2. Download a malicious PCAP from malware-traffic-\n"
                "     analysis.net and analyze it to see the difference.\n"
                "  3. Try the CyberDefenders or TryHackMe challenges to\n"
                "     practice identifying threats in a guided environment.\n"
                "  4. Learn 5 Wireshark filters from the list above — they\n"
                "     cover 80% of real-world analysis tasks."
            )
        lines.append("")
        lines.append("=" * 60)
        lines.append("  Happy learning!  Cybersecurity is a journey, not a")
        lines.append("  destination.  Every PCAP you analyze makes you better.")
        lines.append("=" * 60)

        return "\n".join(lines)

    def _build_result_output_lines(
        self,
        risk_score,
        verdict,
        classifier_result,
        anomaly_result,
        anomaly_reasons,
        ioc_matches,
        ioc_count,
        ioc_available,
        stats,
        safe_scores,
        mal_scores,
        suspicious_flows,
        threat_intel_findings,
        use_local_model,
        features,
        behavioral_findings=None,
    ):
        """Build the Results tab text lines (can run off main thread)."""
        output_lines = [
            f"Risk Score: {risk_score}/100",
            f"Verdict: {verdict}",
            "",
            "Signals:",
        ]

        if classifier_result is None:
            output_lines.append("- Classifier: not enough labeled data")
        else:
            output_lines.append(f"- Classifier risk: {classifier_result['score']} (centroid distance)")

        if anomaly_result is None:
            output_lines.append("- Baseline anomaly: no safe baseline available")
        else:
            reasons = ", ".join(anomaly_reasons) if anomaly_reasons else "no standout outliers"
            output_lines.append(f"- Baseline anomaly: {anomaly_result} ({reasons})")

        if ioc_available:
            if ioc_count:
                output_lines.append(
                    f"- IoC matches: {ioc_count} (domains: {len(ioc_matches['domains'])}, ips: {len(ioc_matches['ips'])})"
                )
                if ioc_matches["domains"]:
                    output_lines.append(f"  Domains: {', '.join(ioc_matches['domains'][:5])}")
                if ioc_matches["ips"]:
                    output_lines.append(f"  IPs: {', '.join(ioc_matches['ips'][:5])}")
            else:
                output_lines.append("- IoC matches: none")
        else:
            output_lines.append("- IoC feed: not loaded")

        if stats.get("ioc_truncated"):
            output_lines.append("- Note: IoC scan truncated due to large unique set")

        output_lines.append("")
        output_lines.append("Heuristic Similarity")
        output_lines.append(summarize_stats(stats))

        if not safe_scores and not mal_scores:
            output_lines.append("Knowledge base is empty. Add safe/malware PCAPs to enable scoring.")
        else:
            best_safe = max(safe_scores) if safe_scores else 0.0
            best_mal = max(mal_scores) if mal_scores else 0.0
            output_lines.append(f"Best safe match: {best_safe}")
            output_lines.append(f"Best malware match: {best_mal}")
            # A5 fix: Label as "Heuristic Assessment" to distinguish from primary verdict
            if best_mal - best_safe >= 10:
                output_lines.append("Heuristic Assessment: Leans Malicious")
            elif best_safe - best_mal >= 10:
                output_lines.append("Heuristic Assessment: Leans Safe")
            else:
                output_lines.append("Heuristic Assessment: Inconclusive")

        if use_local_model:
            output_lines.append("")
            output_lines.append("Local Model Verdict")
            if not _check_sklearn():
                output_lines.append("Local model unavailable (scikit-learn not installed).")
            else:
                model_bundle = _load_local_model()
                if model_bundle is None:
                    output_lines.append("Local model not trained yet. Add labeled PCAPs.")
                else:
                    label, proba = _predict_local_model(model_bundle, features)
                    backend = model_bundle.get("backend", "cpu")
                    if label:
                        output_lines.append(f"Verdict: Likely {label.title()}")
                    if proba is not None:
                        output_lines.append(f"Malicious confidence: {proba:.2%}")
                    output_lines.append(f"Backend: {backend.upper()}")

        if threat_intel_findings.get("threat_intel"):
            output_lines.append("")
            output_lines.append("Online Threat Intelligence")
            intel_data = threat_intel_findings["threat_intel"]

            if intel_data.get("risky_ips"):
                output_lines.append("Flagged IPs (from public threat feeds):")
                for ip_info in intel_data["risky_ips"][:5]:
                    output_lines.append(f"  - {ip_info['ip']}: risk score {ip_info['risk_score']:.0f}/100")
                    if ip_info.get("sources", {}).get("otx"):
                        otx_info = ip_info["sources"]["otx"]
                        if otx_info.get("pulse_count"):
                            output_lines.append(f"    (AlienVault OTX: {otx_info['pulse_count']} pulses)")

            if intel_data.get("risky_domains"):
                output_lines.append("Flagged Domains (from public threat feeds):")
                for domain_info in intel_data["risky_domains"][:5]:
                    output_lines.append(f"  - {domain_info['domain']}: risk score {domain_info['risk_score']:.0f}/100")
                    if domain_info.get("sources", {}).get("urlhaus"):
                        urlhaus = domain_info["sources"]["urlhaus"]
                        if urlhaus.get("found"):
                            output_lines.append(f"    (URLhaus: {urlhaus.get('url_count', 0)} malicious URLs)")

        output_lines.append("")
        output_lines.append("Suspicious Flows (heuristic)")
        if not suspicious_flows:
            output_lines.append("No suspicious flows detected.")
        else:
            for item in suspicious_flows:
                output_lines.append(f"- {item['flow']} | {item['reason']} | {item['bytes']} | {item['packets']} pkts")

        if behavioral_findings:
            output_lines.append("")
            output_lines.append("Behavioral Anomalies")
            for finding in behavioral_findings:
                severity = finding.get("severity", 0)
                level = "HIGH" if severity >= 70 else "MEDIUM" if severity >= 50 else "LOW"
                output_lines.append(f"- [{level}] {finding['detail']}")
        elif behavioral_findings is not None:
            output_lines.append("")
            output_lines.append("Behavioral Anomalies")
            output_lines.append("No behavioral anomalies detected.")

        return output_lines

    def _build_why_lines(
        self,
        verdict,
        risk_score,
        classifier_result,
        anomaly_result,
        anomaly_reasons,
        ioc_matches,
        ioc_count,
        ioc_available,
        stats,
        suspicious_flows,
        threat_intel_findings,
        wireshark_filters,
        behavioral_findings=None,
    ):
        """Build the Why tab text lines (can run off main thread)."""
        why_lines = [
            "========================================",
            "  WHY THIS VERDICT WAS REACHED",
            "========================================",
            "",
            f"Verdict: {verdict}  |  Risk Score: {risk_score}/100",
            "",
            "This tab explains the analytical reasoning behind the",
            "verdict. For definitions, tutorials, and learning resources",
            "see the Education tab.",
            "",
            "----------------------------------------",
            "VERDICT REASONING",
            "----------------------------------------",
        ]

        if verdict == "Likely Malicious":
            why_lines.append("Multiple independent checks flagged this traffic. When several")
            why_lines.append("signals agree (ML match + IoC hits + unusual patterns), confidence")
            why_lines.append("in a malicious classification is high.")
        elif verdict == "Suspicious (IoC Match)":
            why_lines.append("Traffic contacted addresses that appear on known threat intelligence")
            why_lines.append("feeds. IoC matches alone don't prove compromise but warrant immediate")
            why_lines.append("investigation.")
        elif verdict == "Suspicious":
            why_lines.append("Some patterns deviate from normal baselines, but no single check")
            why_lines.append("produced a definitive result. Manual review is recommended.")
        elif verdict == "Likely Safe":
            why_lines.append("All checks returned within normal ranges. No known-bad addresses")
            why_lines.append("were contacted and traffic patterns match established baselines.")

        why_lines.append("")
        why_lines.append("----------------------------------------")
        why_lines.append("EVIDENCE SUMMARY")
        why_lines.append("----------------------------------------")
        why_lines.append("")

        why_lines.append("[A] ML PATTERN MATCH")
        if classifier_result is None:
            why_lines.append("    Result: Not enough training data yet.")
        else:
            score_val = classifier_result["score"]
            if score_val > 70:
                why_lines.append(f"    Result: HIGH MATCH (score: {score_val})")
            elif score_val > 40:
                why_lines.append(f"    Result: PARTIAL MATCH (score: {score_val})")
            else:
                why_lines.append(f"    Result: LOW MATCH (score: {score_val})")
        why_lines.append("")

        why_lines.append("[B] BASELINE ANOMALY DETECTION")
        if anomaly_result is None:
            why_lines.append("    Result: No baseline available.")
        else:
            reasons = ", ".join(anomaly_reasons) if anomaly_reasons else "nothing unusual"
            if isinstance(anomaly_result, (int, float)) and anomaly_result >= 40:
                why_lines.append(f"    Result: ANOMALOUS — deviates from baseline (score: {anomaly_result})")
                why_lines.append(f"    Reasons: {reasons}")
            elif isinstance(anomaly_result, (int, float)):
                why_lines.append(f"    Result: NORMAL — fits within baseline (score: {anomaly_result})")
                why_lines.append(f"    Details: {reasons}")
            else:
                why_lines.append(f"    Result: {anomaly_result}")
                why_lines.append(f"    Details: {reasons}")
        why_lines.append("")

        why_lines.append("[C] INDICATOR OF COMPROMISE (IoC) CHECK")
        if ioc_available:
            if ioc_count:
                domain_ct = len(ioc_matches["domains"])
                ip_ct = len(ioc_matches["ips"])
                why_lines.append(f"    Result: {ioc_count} MATCHES FOUND")
                why_lines.append(f"    Breakdown: {domain_ct} domain(s) and {ip_ct} IP(s) matched")
                if ioc_matches["domains"]:
                    why_lines.append(f"    Domains: {', '.join(ioc_matches['domains'][:5])}")
                if ioc_matches["ips"]:
                    why_lines.append(f"    IPs: {', '.join(ioc_matches['ips'][:5])}")
            else:
                why_lines.append("    Result: No matches against any blocklists.")
        else:
            why_lines.append("    Result: Threat feeds not loaded.")
        why_lines.append("")

        why_lines.append("[D] BEHAVIORAL HEURISTICS")
        if behavioral_findings:
            why_lines.append(f"    Result: {len(behavioral_findings)} anomaly(ies) detected")
            for finding in behavioral_findings:
                severity = finding.get("severity", 0)
                level = "HIGH" if severity >= 70 else "MEDIUM" if severity >= 50 else "LOW"
                why_lines.append(f"    [{level}] {finding['detail']}")
        else:
            why_lines.append("    Result: No behavioral anomalies detected.")
        why_lines.append("")

        why_lines.append("----------------------------------------")
        why_lines.append("TRAFFIC DETAILS")
        why_lines.append("----------------------------------------")
        why_lines.append("")

        top_ports = stats.get("top_ports", [])
        if top_ports:
            unusual = [(p, c) for p, c in top_ports if p not in COMMON_PORTS]
            why_lines.append("[D] PORTS")
            for port, count in top_ports[:10]:
                flag = " << UNUSUAL" if port not in COMMON_PORTS else ""
                why_lines.append(f"      Port {port}: {count} packet(s){flag}")
            if unusual:
                why_lines.append(f"    {len(unusual)} non-standard port(s) detected.")
            why_lines.append("")

        dns_count = stats.get("dns_query_count", 0)
        if dns_count:
            why_lines.append("[E] DNS")
            top_dns = stats.get("top_dns", [])
            if top_dns:
                for domain, count in top_dns[:8]:
                    why_lines.append(f"      {domain} — {count} lookup(s)")
            else:
                why_lines.append(f"    Total DNS queries: {dns_count}")
            why_lines.append("")

        http_count = stats.get("http_request_count", 0)
        http_hosts = stats.get("http_hosts", [])
        if http_count:
            why_lines.append("[F] HTTP (unencrypted)")
            if http_hosts:
                why_lines.append(f"    Hosts: {', '.join(http_hosts[:5])}")
            else:
                why_lines.append(f"    Requests: {http_count}")
            why_lines.append("")

        tls_count = stats.get("tls_packet_count", 0)
        tls_sni = stats.get("tls_sni", [])
        if tls_count:
            why_lines.append("[G] HTTPS/TLS (encrypted)")
            if tls_sni:
                why_lines.append(f"    SNI destinations: {', '.join(tls_sni[:5])}")
            else:
                why_lines.append(f"    TLS packets: {tls_count}")
            why_lines.append("")

        avg_size = stats.get("avg_size", 0.0)
        median_size = stats.get("median_size", 0.0)
        why_lines.append("[H] PACKET SIZES")
        why_lines.append(f"    Average: {avg_size:.1f} bytes  |  Median: {median_size:.1f} bytes")
        if median_size and median_size < 120:
            why_lines.append("    !! Many small packets — possible beaconing pattern.")
        elif avg_size and avg_size > 1200:
            why_lines.append("    !! Unusually large packets — possible data exfiltration.")
        else:
            why_lines.append("    Sizes are within normal range.")
        why_lines.append("")

        if threat_intel_findings.get("threat_intel"):
            intel_data = threat_intel_findings["threat_intel"]
            if intel_data.get("risky_ips") or intel_data.get("risky_domains"):
                why_lines.append("[I] ONLINE THREAT INTELLIGENCE")
                if intel_data.get("risky_ips"):
                    for ip_info in intel_data["risky_ips"][:3]:
                        risk = ip_info["risk_score"]
                        why_lines.append(f"    IP: {ip_info['ip']} — {risk:.0f}/100")
                if intel_data.get("risky_domains"):
                    for domain_info in intel_data["risky_domains"][:3]:
                        risk = domain_info["risk_score"]
                        why_lines.append(f"    Domain: {domain_info['domain']} — {risk:.0f}/100")
                why_lines.append("")

        why_lines.append("----------------------------------------")
        why_lines.append("SUSPICIOUS FLOWS")
        why_lines.append("----------------------------------------")
        why_lines.append("")
        if not suspicious_flows:
            why_lines.append("No flows were flagged as suspicious.")
        else:
            why_lines.append(f"{len(suspicious_flows)} suspicious flow(s) detected:")
            why_lines.append("")
            for idx, item in enumerate(suspicious_flows, 1):
                why_lines.append(f"  #{idx}: {item['flow']}")
                why_lines.append(f"      Reason: {item['reason']}  |  {item['bytes']}  |  {item['packets']} pkts")
                why_lines.append("")
            why_lines.append("See the Education tab for detailed explanations of each pattern.")
        why_lines.append("")

        if wireshark_filters:
            unique_filters = list(dict.fromkeys(wireshark_filters))
            why_lines.append("")
            why_lines.append("----------------------------------------")
            why_lines.append("STEP 5: INVESTIGATE IN WIRESHARK")
            why_lines.append("----------------------------------------")
            why_lines.append("")
            why_lines.append("Paste into Wireshark's display filter bar to isolate relevant packets.")
            why_lines.append("(Or click 'Copy Wireshark Filters' below to copy all of them.)")
            why_lines.append("")
            for filt in unique_filters:
                why_lines.append(f"  {filt}")
            why_lines.append("")
            why_lines.append("See the Education tab for a full Wireshark filter quick-reference.")

        return why_lines

    def _analyze(self):
        path = self.target_path_var.get()
        if not path:
            messagebox.showwarning("Missing file", "Please select a PCAP file.")
            return

        # Hide any previous LLM suggestion banner
        self._hide_llm_suggestion()

        # Read tkinter variables on main thread before launching worker
        max_rows = max(100, min(self.max_rows_var.get(), 2_000_000))  # S6: clamp to sane range
        parse_http = self.parse_http_var.get()
        use_high_memory = self.use_high_memory_var.get()
        offline_mode = self.offline_mode_var.get()
        use_local_model = self.use_local_model_var.get()
        use_multithreading = self.use_multithreading_var.get()
        turbo_parse = self.turbo_parse_var.get()
        kb = self._get_knowledge_base()
        normalizer_cache = self.normalizer_cache
        cancel_event = self._cancel_event

        # Choose parser: turbo (raw byte parsing) or standard (full Scapy)
        _parser = _fast_parse_pcap_path if turbo_parse else parse_pcap_path

        def _safe_extract(p, high_mem):
            try:
                return extract_credentials_and_hosts(p, use_high_memory=high_mem)
            except Exception as e:
                print(f"[DEBUG] Credential extraction failed: {e}")
                return {"credentials": [], "hosts": {}}

        def _core_analysis(df, stats, extracted, sample_info, t_start, progress_cb=None):
            """Shared analysis logic used by both sequential and multithreaded paths."""

            def _report(pct, label="Analyzing..."):
                if progress_cb:
                    progress_cb(pct, label=label)

            def _do_threat_intel():
                if offline_mode or not _check_threat_intel():
                    return {}
                try:
                    from threat_intelligence import ThreatIntelligence

                    otx_key = self.settings.get("otx_api_key", "").strip() or None
                    ti = ThreatIntelligence(otx_api_key=otx_key)
                    if ti.is_available():
                        print("[DEBUG] Enriching stats with threat intelligence...")

                        # Report incremental progress during TI enrichment (32-44%)
                        def _ti_progress(fraction):
                            _report(32 + fraction * 12)

                        return ti.enrich_stats(stats, progress_cb=_ti_progress)
                except Exception as e:
                    print(f"[DEBUG] Threat intelligence enrichment failed: {e}")
                return {}

            if use_multithreading:
                # ── Pre-compute KB vectors once for reuse ──
                kb_vectors = _vectorize_kb(kb)

                # ── Parallel Phase 2: Threat intel + IoC + baseline + flows ──
                _report(32, label="Phase 2: Threat Intelligence & Flow Analysis")
                with ThreadPoolExecutor(max_workers=4) as pool:
                    f_ti = pool.submit(_do_threat_intel)
                    f_ioc = pool.submit(match_iocs, stats, kb.get("ioc", {}))
                    f_base = pool.submit(compute_baseline_from_kb, kb, kb_vectors)
                    f_flows = pool.submit(
                        lambda: (
                            compute_flow_stats(df),
                            None,  # placeholder
                        )
                    )

                    threat_intel_findings = f_ti.result()
                    if threat_intel_findings:
                        stats.update(threat_intel_findings)
                    ioc_matches = f_ioc.result()
                    baseline = f_base.result()
                    flow_df_early, _ = f_flows.result()

                _report(45, label="Phase 2: Detecting Suspicious Flows")
                suspicious_flows = detect_suspicious_flows(df, kb, flow_df=flow_df_early)
                behavioral_findings = detect_behavioral_anomalies(df, stats, flow_df=flow_df_early)

                t_p2 = time.time()
                print(f"[TIMING] Phase 2 parallel (intel+ioc+baseline+flows): {t_p2 - t_start:.2f}s")

                # ── Parallel Phase 3: Scoring ──
                _report(50, label="Phase 3: Building Feature Vectors")
                features = build_features(stats)
                vector = _vector_from_features(features)

                _report(55, label="Phase 3: ML Classification & Similarity Scoring")
                with ThreadPoolExecutor(max_workers=3) as pool:
                    f_safe = pool.submit(lambda: get_top_k_similar_entries(features, kb["safe"], k=5))
                    f_mal = pool.submit(lambda: get_top_k_similar_entries(features, kb["malicious"], k=5))
                    f_classify = pool.submit(
                        lambda: classify_vector(vector, kb, normalizer_cache=normalizer_cache, kb_vectors=kb_vectors)
                    )

                    _, safe_scores = f_safe.result()
                    _, mal_scores = f_mal.result()
                    classifier_result = f_classify.result()

                _report(62, label="Phase 3: Anomaly Detection")
                anomaly_result, anomaly_reasons = anomaly_score(vector, baseline)
                t_p3 = time.time()
                print(f"[TIMING] Phase 3 parallel (scoring): {t_p3 - t_p2:.2f}s")
            else:
                # ── Pre-compute KB vectors once for reuse ──
                kb_vectors = _vectorize_kb(kb)

                # ── Sequential path ──
                _report(32, label="Phase 2: Threat Intelligence Enrichment")
                threat_intel_findings = _do_threat_intel()
                if threat_intel_findings:
                    stats.update(threat_intel_findings)

                _report(38, label="Phase 2: IoC Matching")
                ioc_matches = match_iocs(stats, kb.get("ioc", {}))
                _report(42, label="Phase 2: Computing Baseline")
                baseline = compute_baseline_from_kb(kb, kb_vectors=kb_vectors)
                _report(46, label="Phase 2: Flow Analysis")
                flow_df_early = compute_flow_stats(df)
                _report(48, label="Phase 2: Behavioral Detection")
                suspicious_flows = detect_suspicious_flows(df, kb, flow_df=flow_df_early)
                behavioral_findings = detect_behavioral_anomalies(df, stats, flow_df=flow_df_early)

                _report(52, label="Phase 3: Building Feature Vectors")
                features = build_features(stats)
                vector = _vector_from_features(features)
                _report(56, label="Phase 3: Similarity Scoring")
                _, safe_scores = get_top_k_similar_entries(features, kb["safe"], k=5)
                _, mal_scores = get_top_k_similar_entries(features, kb["malicious"], k=5)
                _report(60, label="Phase 3: ML Classification")
                classifier_result = classify_vector(
                    vector, kb, normalizer_cache=normalizer_cache, kb_vectors=kb_vectors
                )
                _report(64, label="Phase 3: Anomaly Detection")
                anomaly_result, anomaly_reasons = anomaly_score(vector, baseline)
                t_p3 = time.time()
                print(f"[TIMING] Sequential analysis: {t_p3 - t_start:.2f}s")

            # ── Risk scoring (same for both paths) ──
            _report(68, label="Phase 4: Computing Risk Score")
            ioc_count = len(ioc_matches["ips"]) + len(ioc_matches["domains"])
            ioc_available = any(kb.get("ioc", {}).get(key) for key in ("ips", "domains", "hashes"))
            ioc_score = min(100.0, 80.0 + (ioc_count - 1) * 5.0) if ioc_count else 0.0

            # Behavioral heuristic score (aggregated from individual findings)
            behavioral_score = 0.0
            if behavioral_findings:
                behavioral_score = min(100.0, sum(f.get("risk_boost", 0) for f in behavioral_findings))

            # Weighted risk scoring with dynamic weights
            risk_components = []
            if classifier_result is not None:
                risk_components.append((classifier_result["score"], 0.35))
            if anomaly_result is not None:
                risk_components.append((anomaly_result, 0.20))
            if ioc_available:
                risk_components.append((ioc_score, 0.25))
            if behavioral_findings:
                risk_components.append((behavioral_score, 0.20))

            if risk_components:
                total_weight = sum(w for _, w in risk_components)
                risk_score = round(sum(s * w for s, w in risk_components) / total_weight, 1)
                # A2 fix: When only 1 component is available, cap the score to reduce
                # misleading high-confidence verdicts from a single signal source.
                if len(risk_components) == 1:
                    risk_score = min(risk_score, 65.0)
            else:
                risk_score = 0.0

            # Hard escalation: IoC matches or critical behavioral findings floor the score
            if ioc_count >= 2 and risk_score < 60:
                risk_score = max(risk_score, 60.0)
            if behavioral_score >= 40 and risk_score < 45:
                risk_score = max(risk_score, 45.0)

            if risk_score >= 70:
                verdict = "Likely Malicious"
            elif risk_score >= 40:
                verdict = "Suspicious"
            else:
                verdict = "Likely Safe"
            if ioc_count and verdict == "Likely Safe":
                verdict = "Suspicious (IoC Match)"

            # ── Text generation ──
            _report(75, label="Phase 4: Generating Wireshark Filters")
            wireshark_filters = self._build_wireshark_filters(
                stats, ioc_matches, verdict, suspicious_flows=suspicious_flows
            )

            _report(80, label="Phase 4: Building Analysis Report")
            if use_multithreading:
                with ThreadPoolExecutor(max_workers=3) as pool:
                    f_output = pool.submit(
                        self._build_result_output_lines,
                        risk_score,
                        verdict,
                        classifier_result,
                        anomaly_result,
                        anomaly_reasons,
                        ioc_matches,
                        ioc_count,
                        ioc_available,
                        stats,
                        safe_scores,
                        mal_scores,
                        suspicious_flows,
                        threat_intel_findings,
                        use_local_model,
                        features,
                        behavioral_findings,
                    )
                    f_why = pool.submit(
                        self._build_why_lines,
                        verdict,
                        risk_score,
                        classifier_result,
                        anomaly_result,
                        anomaly_reasons,
                        ioc_matches,
                        ioc_count,
                        ioc_available,
                        stats,
                        suspicious_flows,
                        threat_intel_findings,
                        wireshark_filters,
                        behavioral_findings,
                    )
                    f_edu = pool.submit(
                        self._build_education_content,
                        verdict,
                        risk_score,
                        stats,
                        classifier_result,
                        anomaly_result,
                        anomaly_reasons,
                        ioc_matches,
                        ioc_available,
                        ioc_count,
                        suspicious_flows,
                        threat_intel_findings,
                    )
                    output_lines = f_output.result()
                    why_lines = f_why.result()
                    edu_content = f_edu.result()
            else:
                output_lines = self._build_result_output_lines(
                    risk_score,
                    verdict,
                    classifier_result,
                    anomaly_result,
                    anomaly_reasons,
                    ioc_matches,
                    ioc_count,
                    ioc_available,
                    stats,
                    safe_scores,
                    mal_scores,
                    suspicious_flows,
                    threat_intel_findings,
                    use_local_model,
                    features,
                    behavioral_findings,
                )
                _report(85, label="Phase 4: Generating Explanation")
                why_lines = self._build_why_lines(
                    verdict,
                    risk_score,
                    classifier_result,
                    anomaly_result,
                    anomaly_reasons,
                    ioc_matches,
                    ioc_count,
                    ioc_available,
                    stats,
                    suspicious_flows,
                    threat_intel_findings,
                    wireshark_filters,
                    behavioral_findings,
                )
                _report(90, label="Phase 4: Generating Educational Content")
                edu_content = self._build_education_content(
                    verdict,
                    risk_score,
                    stats,
                    classifier_result,
                    anomaly_result,
                    anomaly_reasons,
                    ioc_matches,
                    ioc_available,
                    ioc_count,
                    suspicious_flows,
                    threat_intel_findings,
                )

            if wireshark_filters:
                output_lines.append("- Wireshark filters: see Why tab")

            _report(95, label="Finalizing Results")
            t_end = time.time()
            mode = "multithreaded" if use_multithreading else "sequential"
            print(f"[TIMING] Total worker processing ({mode}): {t_end - t_start:.2f}s")

            return {
                "empty": False,
                "df": df,
                "stats": stats,
                "extracted_data": extracted,
                "threat_intel_findings": threat_intel_findings,
                "classifier_result": classifier_result,
                "flow_df_early": flow_df_early,
                "suspicious_flows": suspicious_flows,
                "behavioral_findings": behavioral_findings,
                "output_lines": output_lines,
                "why_lines": why_lines,
                "edu_content": edu_content,
                "wireshark_filters": wireshark_filters if wireshark_filters else [],
                "risk_score": risk_score,
                "verdict": verdict,
                "sample_info": sample_info,
            }

        def task(progress_cb=None):
            t_start = time.time()

            # Wrapper to add phase labels to parsing progress
            def phase1_progress_cb(percent, eta_seconds=None, processed=None, total=None, label=None):
                if progress_cb:
                    # Override label during Phase 1 parsing to show descriptive text
                    if label is None and percent < 100:
                        label = "Phase 1: Parsing Packets"
                    progress_cb(percent, eta_seconds, processed, total, label)

            if use_multithreading:
                # ── Phase 1: Parse + extract in parallel ──
                with ThreadPoolExecutor(max_workers=2) as pool:
                    parse_future = pool.submit(
                        _parser,
                        path,
                        max_rows=max_rows,
                        parse_http=parse_http,
                        progress_cb=phase1_progress_cb,
                        use_high_memory=use_high_memory,
                        cancel_event=cancel_event,
                    )
                    extract_future = pool.submit(lambda: _safe_extract(path, use_high_memory))
                    parse_result = parse_future.result()
                    extracted = extract_future.result()
            else:
                parse_result = _parser(
                    path,
                    max_rows=max_rows,
                    parse_http=parse_http,
                    progress_cb=phase1_progress_cb,
                    use_high_memory=use_high_memory,
                    cancel_event=cancel_event,
                )
                extracted = _safe_extract(path, use_high_memory)

            (df, stats, sample_info) = parse_result
            t_p1 = time.time()
            print(f"[TIMING] Phase 1 (parse + extract): {t_p1 - t_start:.2f}s")

            if stats.get("packet_count", 0) == 0:
                return {"empty": True, "extracted_data": extracted}

            return _core_analysis(df, stats, extracted, sample_info, t_p1, progress_cb)

        def done(result):
            if result.get("empty"):
                messagebox.showwarning("No data", "No IP packets found in this capture.")
                self.label_safe_button.configure(state=tk.DISABLED)
                self.label_unsure_button.configure(state=tk.DISABLED)
                self.label_mal_button.configure(state=tk.DISABLED)
                return

            df = result["df"]
            stats = result["stats"]
            sample_info = result["sample_info"]
            extracted_data = result["extracted_data"]
            flow_df_early = result["flow_df_early"]
            output_lines = result["output_lines"]
            why_lines = result["why_lines"]
            edu_content = result["edu_content"]
            wireshark_filters = result["wireshark_filters"]
            classifier_result = result["classifier_result"]
            self.current_verdict = result.get("verdict")
            self.current_risk_score = result.get("risk_score")

            self.current_df = df
            self.current_stats = stats
            self.current_sample_info = sample_info
            if not df.empty and "Time" in df.columns:
                self.packet_base_time = float(df["Time"].min())
            else:
                self.packet_base_time = None

            # Cache normalizer if available
            if classifier_result and self.normalizer_cache is None and "normalizer" in classifier_result:
                self.normalizer_cache = classifier_result.get("normalizer")

            self.wireshark_filters = wireshark_filters

            # Update UI text widgets
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert(tk.END, "\n".join(output_lines))

            if self.why_text is not None:
                self.why_text.delete("1.0", tk.END)
                self.why_text.insert(tk.END, "\n".join(why_lines))

            if self.education_text is not None:
                self.education_text.delete("1.0", tk.END)
                self.education_text.insert(tk.END, edu_content)

            if self.copy_filters_button is not None:
                if wireshark_filters:
                    self.copy_filters_button.configure(state=tk.NORMAL)
                else:
                    self.copy_filters_button.configure(state=tk.DISABLED)

            if hasattr(self, "results_notebook") and hasattr(self, "results_tab"):
                try:
                    self.results_notebook.select(self.results_tab)
                except Exception:
                    pass
            self._apply_packet_filters()

            self._update_packet_hints(df, stats, flow_df=flow_df_early)

            self.status_var.set("Done")

            # Clear and populate flow table efficiently
            self.flow_table.delete(*self.flow_table.get_children())
            for _, row in flow_df_early.head(25).iterrows():
                self.flow_table.insert(
                    "",
                    tk.END,
                    values=(
                        row["Flow"],
                        int(row["Packets"]),
                        int(row["Bytes"]),
                        f"{row['Duration']:.2f}",
                    ),
                )

            self.charts_button.configure(state=tk.NORMAL)
            self.label_safe_button.configure(state=tk.NORMAL)
            self.label_unsure_button.configure(state=tk.NORMAL)
            self.label_mal_button.configure(state=tk.NORMAL)

            self.extracted_data = extracted_data
            self._populate_extracted_tab(extracted_data)

            # Keep the file path populated so the user can re-analyze if needed

            # Fire LLM label suggestion in background (non-blocking)
            self._request_llm_suggestion_async(stats)

        self._run_task(task, done, message="Analyzing PCAP...", progress_label="Analyzing PCAP")

    def _open_charts(self):
        if self.current_df is None:
            return
        window = tk.Toplevel(self.root)
        window.title("PCAP Charts")
        window.geometry("1000x800")
        window.configure(bg=self.colors["bg"])
        self._set_dark_titlebar(window)

        notebook = ttk.Notebook(window)
        notebook.pack(fill=tk.BOTH, expand=True)

        _add_chart_tab(notebook, "Timeline", _plot_scatter(self.current_df))
        _add_chart_tab(notebook, "Ports", _plot_port_hist(self.current_df))
        _add_chart_tab(notebook, "Protocols", _plot_proto_pie(self.current_df))
        _add_chart_tab(notebook, "DNS", _plot_top_dns(self.current_df))
        _add_chart_tab(notebook, "HTTP", _plot_top_http(self.current_df))
        _add_chart_tab(notebook, "TLS", _plot_top_tls_sni(self.current_df))
        _add_chart_tab(notebook, "Flows", _plot_top_flows(self.current_df))

    def _get_knowledge_base(self):
        """Get knowledge base with caching to avoid repeated JSON loads"""
        if self.kb_cache is None:
            self.kb_cache = load_knowledge_base()
        return self.kb_cache

    def _invalidate_caches(self):
        """Invalidate all performance caches when KB changes"""
        self.kb_cache = None
        self.normalizer_cache = None
        self.threat_intel_cache = None

    def _refresh_kb(self):
        kb = load_knowledge_base()
        self.kb_cache = kb  # Update cache with fresh KB
        unsure_count = len(kb.get("unsure", []))
        self.kb_summary_var.set(
            f"Safe entries: {len(kb['safe'])} | Unsure entries: {unsure_count} | Malware entries: {len(kb['malicious'])}"
        )
        self.unsure_count_var.set(f"{unsure_count} item{'s' if unsure_count != 1 else ''}")
        ioc = kb.get("ioc", {})
        ioc_counts = f"IoCs: {len(ioc.get('domains', []))} domains, {len(ioc.get('ips', []))} ips"
        self.ioc_summary_var.set(ioc_counts)
        # Invalidate derived caches but keep kb_cache (we just refreshed it)
        self.normalizer_cache = None
        self.threat_intel_cache = None

    def _on_tab_changed(self, _event):
        self.sample_note_var.set("")


def _acquire_single_instance():
    """Prevent multiple instances using a Windows named mutex.

    Returns the mutex handle if this is the first instance, or ``None``
    if another instance is already running (brings it to the foreground).
    """
    MUTEX_NAME = "Local\\PCAP_Sentry_SingleInstance"
    ERROR_ALREADY_EXISTS = 183

    # Import wintypes submodule for type annotations
    import ctypes.wintypes

    try:
        mutex = ctypes.windll.kernel32.CreateMutexW(None, False, MUTEX_NAME)
        if ctypes.windll.kernel32.GetLastError() == ERROR_ALREADY_EXISTS:
            # Another instance exists – try to bring its window forward
            # Walk windows looking for our title
            EnumWindows = ctypes.windll.user32.EnumWindows
            GetWindowTextW = ctypes.windll.user32.GetWindowTextW
            SetForegroundWindow = ctypes.windll.user32.SetForegroundWindow
            ShowWindow = ctypes.windll.user32.ShowWindow
            SW_RESTORE = 9
            buf = ctypes.create_unicode_buffer(256)

            @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM)
            def _enum_cb(hwnd, _lparam):
                GetWindowTextW(hwnd, buf, 256)
                if "PCAP Sentry" in buf.value:
                    ShowWindow(hwnd, SW_RESTORE)
                    SetForegroundWindow(hwnd)
                    return False  # stop enumeration
                return True

            EnumWindows(_enum_cb, 0)
            return None
        return mutex
    except Exception:
        # Non-Windows or permission issue – allow running
        return True


def main():
    mutex = _acquire_single_instance()
    if mutex is None:
        sys.exit(0)

    _init_error_logs()
    sys.excepthook = _handle_exception
    if _check_tkinterdnd2():
        _DND_FILES, TkinterDnD = _get_tkinterdnd2()
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()
    root.report_callback_exception = _handle_exception
    _set_app_icon(root)
    PCAPSentryApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
