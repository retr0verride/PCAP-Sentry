import io
import ipaddress
import json
import math
import os
import queue
import random
import shutil
import statistics
import sys
import tempfile
import threading
import time
import traceback
import zipfile
from collections import Counter
from datetime import datetime, timezone

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont

# Import update checker
try:
    from update_checker import BackgroundUpdateChecker, UpdateChecker
    _update_checker_available = True
except ImportError:
    _update_checker_available = False

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
    _write_error_log("Unhandled exception", exc, tb)
    _show_startup_error(
        "An unexpected error occurred. See app_errors.log in the app data folder.",
        exc,
    )


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
        import sklearn.feature_extraction
        import sklearn.linear_model
        import joblib
        _sklearn_available = True
    except Exception:
        _sklearn_available = False
    return _sklearn_available


def _check_tkinterdnd2():
    global _tkinterdnd2_available
    if _tkinterdnd2_available is not None:
        return _tkinterdnd2_available
    try:
        import tkinterdnd2
        _tkinterdnd2_available = True
    except Exception:
        _tkinterdnd2_available = False
    return _tkinterdnd2_available

SIZE_SAMPLE_LIMIT = 50000
DEFAULT_MAX_ROWS = 200000
IOC_SET_LIMIT = 50000
APP_VERSION = "2026.02.11-2"


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
        from scapy.all import DNS, DNSQR, IP, PcapReader, Raw, TCP, UDP
        return DNS, DNSQR, IP, PcapReader, Raw, TCP, UDP
    except Exception as exc:
        _show_startup_error(
            "Scapy is required but was not found. Please reinstall PCAP Sentry or "
            "contact support.",
            exc,
        )
        raise exc


def _get_tls_support():
    try:
        from scapy.layers.tls.all import TLS
        from scapy.layers.tls.handshake import TLSClientHello
        from scapy.layers.tls.extensions import TLSExtALPN, TLSExtServerName
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


def _get_sklearn():
    from joblib import dump as _joblib_dump
    from joblib import load as _joblib_load
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.linear_model import LogisticRegression
    return _joblib_dump, _joblib_load, DictVectorizer, LogisticRegression


def _get_tkinterdnd2():
    from tkinterdnd2 import DND_FILES, TkinterDnD
    return DND_FILES, TkinterDnD


def _get_app_base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def _get_app_icon_path():
    base_dir = _get_app_base_dir()
    candidates = []
    frozen_dir = getattr(sys, "_MEIPASS", None)
    if frozen_dir:
        candidates.append(os.path.join(frozen_dir, "assets", "pcap_sentry.ico"))
        candidates.append(os.path.join(frozen_dir, "pcap_sentry.ico"))
    candidates.extend(
        [
            os.path.join(base_dir, "assets", "pcap_sentry.ico"),
            os.path.abspath(os.path.join(base_dir, "..", "assets", "pcap_sentry.ico")),
            os.path.join(base_dir, "pcap_sentry.ico"),
        ]
    )
    for path in candidates:
        if os.path.exists(path):
            return path
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


def _default_settings():
    return {
        "max_rows": DEFAULT_MAX_ROWS,
        "parse_http": True,
        "use_high_memory": False,
        "use_local_model": False,
        "backup_dir": os.path.dirname(KNOWLEDGE_BASE_FILE),
        "theme": "system",
        "app_data_notice_shown": False,
    }


def load_settings():
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                defaults = _default_settings()
                defaults.update(data)
                return defaults
    except Exception:
        pass
    return _default_settings()


def save_settings(settings):
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)


def _format_bytes(value):
    if value is None:
        return ""
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0 or unit == "TB":
            return f"{size:.1f} {unit}"
        size /= 1024.0


def _default_kb():
    return {"safe": [], "malicious": [], "ioc": {"ips": [], "domains": [], "hashes": []}}


def load_knowledge_base():
    try:
        if os.path.exists(KNOWLEDGE_BASE_FILE):
            with open(KNOWLEDGE_BASE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                data.setdefault("safe", [])
                data.setdefault("malicious", [])
                ioc = data.setdefault("ioc", {})
                ioc.setdefault("ips", [])
                ioc.setdefault("domains", [])
                ioc.setdefault("hashes", [])
                return data
    except Exception:
        pass
    return _default_kb()


def save_knowledge_base(data):
    os.makedirs(os.path.dirname(KNOWLEDGE_BASE_FILE), exist_ok=True)
    with open(KNOWLEDGE_BASE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


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
    with open(path, "r", encoding="utf-8") as f:
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


FEATURE_NAMES = [
    "packet_count",
    "avg_size",
    "dns_query_count",
    "http_request_count",
    "unique_http_hosts",
    "proto_tcp",
    "proto_udp",
    "proto_other",
    "top_port_1",
    "top_port_2",
    "top_port_3",
    "top_port_4",
    "top_port_5",
]


def _vector_from_features(features):
    proto = features.get("proto_ratio", {})
    top_ports = features.get("top_ports", [])
    port_at = lambda idx: float(top_ports[idx]) if idx < len(top_ports) else 0.0

    return [
        float(features.get("packet_count", 0.0)),
        float(features.get("avg_size", 0.0)),
        float(features.get("dns_query_count", 0.0)),
        float(features.get("http_request_count", 0.0)),
        float(features.get("unique_http_hosts", 0.0)),
        float(proto.get("TCP", 0.0)),
        float(proto.get("UDP", 0.0)),
        float(proto.get("Other", 0.0)),
        port_at(0),
        port_at(1),
        port_at(2),
        port_at(3),
        port_at(4),
    ]


def _compute_normalizer(vectors):
    if not vectors:
        return None
    columns = list(zip(*vectors))
    means = [sum(col) / len(col) for col in columns]
    stds = [statistics.pstdev(col) or 1.0 for col in columns]
    return {"mean": means, "std": stds}


def _normalize_vector(vector, normalizer):
    return [
        (value - mean) / std
        for value, mean, std in zip(vector, normalizer["mean"], normalizer["std"])
    ]


def compute_baseline_from_kb(kb):
    safe_vectors = [_vector_from_features(entry["features"]) for entry in kb.get("safe", [])]
    if not safe_vectors:
        return None
    normalizer = _compute_normalizer(safe_vectors)
    return {"normalizer": normalizer, "vectors": safe_vectors}


def anomaly_score(vector, baseline):
    if baseline is None:
        return None, []
    normalizer = baseline["normalizer"]
    zscores = []
    for value, mean, std in zip(vector, normalizer["mean"], normalizer["std"]):
        z = abs(value - mean) / (std or 1.0)
        zscores.append(z)

    capped = [min(z, 4.0) for z in zscores]
    score = sum(capped) / max(len(capped), 1) / 4.0 * 100.0

    top = sorted(enumerate(zscores), key=lambda item: item[1], reverse=True)[:3]
    reasons = [f"{FEATURE_NAMES[idx]} z={value:.1f}" for idx, value in top if value > 0]
    return round(score, 1), reasons


def classify_vector(vector, kb, normalizer_cache=None):
    safe_entries = kb.get("safe", [])
    mal_entries = kb.get("malicious", [])
    if not safe_entries or not mal_entries:
        return None

    # OPTIMIZATION: Use cached normalizer if provided, otherwise compute and return it
    if normalizer_cache is not None:
        normalizer = normalizer_cache
    else:
        safe_vectors = [_vector_from_features(entry["features"]) for entry in safe_entries]
        mal_vectors = [_vector_from_features(entry["features"]) for entry in mal_entries]
        all_vectors = safe_vectors + mal_vectors
        normalizer = _compute_normalizer(all_vectors)

    safe_vectors = [_vector_from_features(entry["features"]) for entry in safe_entries]
    mal_vectors = [_vector_from_features(entry["features"]) for entry in mal_entries]

    safe_norm = [_normalize_vector(vec, normalizer) for vec in safe_vectors]
    mal_norm = [_normalize_vector(vec, normalizer) for vec in mal_vectors]
    target = _normalize_vector(vector, normalizer)

    def centroid(vectors):
        cols = list(zip(*vectors))
        return [sum(col) / len(col) for col in cols]

    def distance(a, b):
        return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))

    safe_centroid = centroid(safe_norm)
    mal_centroid = centroid(mal_norm)
    dist_safe = distance(target, safe_centroid)
    dist_mal = distance(target, mal_centroid)
    if dist_safe + dist_mal == 0:
        prob_mal = 0.5
    else:
        prob_mal = dist_safe / (dist_safe + dist_mal)
    score = round(prob_mal * 100.0, 1)
    return {"score": score, "dist_safe": dist_safe, "dist_mal": dist_mal, "normalizer": normalizer}


def _domain_matches(domain, ioc_domains):
    if domain in ioc_domains:
        return domain
    parts = domain.split(".")
    for idx in range(1, len(parts)):
        candidate = ".".join(parts[idx:])
        if candidate in ioc_domains:
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
    
    features = {
        "packet_count": stats.get("packet_count", 0),
        "avg_size": stats.get("avg_size", 0.0),
        "proto_ratio": proto_ratio,
        "top_ports": top_ports,
        "dns_query_count": stats.get("dns_query_count", 0),
        "http_request_count": stats.get("http_request_count", 0),
        "unique_http_hosts": stats.get("unique_http_hosts", 0),
    }
    
    # Add threat intelligence features if available
    if "threat_intel" in stats:
        intel = stats["threat_intel"]
        
        # Count flagged indicators
        risky_ips = intel.get("risky_ips", [])
        risky_domains = intel.get("risky_domains", [])
        
        features["flagged_ip_count"] = len(risky_ips)
        features["flagged_domain_count"] = len(risky_domains)
        
        # Calculate average risk scores
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
    
    return features


def _vectorize_features(features):
    vector = {
        "packet_count": float(features.get("packet_count", 0)),
        "avg_size": float(features.get("avg_size", 0.0)),
        "dns_query_count": float(features.get("dns_query_count", 0)),
        "http_request_count": float(features.get("http_request_count", 0)),
        "unique_http_hosts": float(features.get("unique_http_hosts", 0)),
        # Threat intelligence features
        "flagged_ip_count": float(features.get("flagged_ip_count", 0)),
        "flagged_domain_count": float(features.get("flagged_domain_count", 0)),
        "avg_ip_risk_score": float(features.get("avg_ip_risk_score", 0.0)),
        "avg_domain_risk_score": float(features.get("avg_domain_risk_score", 0.0)),
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


def _save_local_model(model_bundle):
    _joblib_dump, _joblib_load, DictVectorizer, LogisticRegression = _get_sklearn()
    _joblib_dump(model_bundle, MODEL_FILE)


def _load_local_model():
    if not _check_sklearn() or not os.path.exists(MODEL_FILE):
        return None
    
    _joblib_dump, _joblib_load, DictVectorizer, LogisticRegression = _get_sklearn()
    try:
        meta = _joblib_load(MODEL_FILE)
    except Exception:
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


def similarity_score(target, entry):
    target_count = target.get("packet_count", 0)
    entry_count = entry.get("packet_count", 0)
    if not target_count or not entry_count:
        return 0.0

    target_ports = set(target.get("top_ports", []))
    entry_ports = set(entry.get("top_ports", []))
    ports_union = target_ports | entry_ports
    port_overlap = len(target_ports & entry_ports) / max(len(ports_union), 1)

    target_proto = target.get("proto_ratio", {})
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

    score = 100.0 * (
        0.3 * port_overlap
        + 0.25 * proto_similarity
        + 0.15 * size_similarity
        + 0.1 * count_similarity
        + 0.1 * dns_similarity
        + 0.1 * http_similarity
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
        if entry_pkt and abs(entry_pkt - target_pkt) < target_pkt * 0.5:
            candidates.append(entry)
    
    # If pre-filter eliminated too many, use all
    if not candidates:
        candidates = kb_entries
    
    # Score only candidates, then get top K
    if len(candidates) <= k:
        scores = [similarity_score(features, e["features"]) for e in candidates]
        sorted_indices = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
        return [candidates[i] for i in sorted_indices], [scores[i] for i in sorted_indices]
    
    # Score all candidates and take top K
    scores = [similarity_score(features, e["features"]) for e in candidates]
    top_indices = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:k]
    return [candidates[i] for i in top_indices], [scores[i] for i in top_indices]


def parse_http_payload(payload):
    if not payload or len(payload) < 14:  # Minimum GET / HTTP/1.1
        return "", "", ""
    
    # Fast check for common HTTP methods
    first_bytes = payload[:5]
    if not (first_bytes.startswith(b"GET ") or first_bytes.startswith(b"POST") or first_bytes.startswith(b"HEAD")):
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


def _maybe_reservoir_append(items, item, limit, seen_count):
    if limit <= 0:
        return
    if len(items) < limit:
        items.append(item)
        return
    j = random.randint(1, seen_count)
    if j <= limit:
        items[j - 1] = item


def _extract_first_pcap_from_zip(zip_path):
    with zipfile.ZipFile(zip_path) as zf:
        candidates = [
            name
            for name in zf.namelist()
            if name.lower().endswith((".pcap", ".pcapng")) and not name.endswith("/")
        ]
        if not candidates:
            raise ValueError("Zip file does not contain a .pcap/.pcapng file.")
        member = candidates[0]
        temp_dir = tempfile.mkdtemp()
        zf.extract(member, path=temp_dir)
        extracted_path = os.path.join(temp_dir, member)
        file_size = zf.getinfo(member).file_size
        return extracted_path, temp_dir, file_size


def _resolve_pcap_source(file_path):
    if zipfile.is_zipfile(file_path):
        extracted_path, temp_dir, file_size = _extract_first_pcap_from_zip(file_path)

        def cleanup():
            shutil.rmtree(temp_dir, ignore_errors=True)

        return extracted_path, cleanup, file_size

    def cleanup():
        return None

    try:
        file_size = os.path.getsize(file_path)
    except OSError:
        file_size = 0
    return file_path, cleanup, file_size


def parse_pcap_path(file_path, max_rows=DEFAULT_MAX_ROWS, parse_http=True, progress_cb=None, use_high_memory=False):
    DNS, DNSQR, IP, PcapReader, Raw, TCP, UDP = _get_scapy()
    tls_support = _get_tls_support()
    pd = _get_pandas()
    rows = []
    size_samples = []
    should_sample_rows = max_rows > 0
    resolved_path, cleanup, file_size = _resolve_pcap_source(file_path)
    start_time = _utcnow()
    last_progress_time = start_time
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
                if progress_cb and packet_count % update_every == 0:
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
        "unique_src": int(len(unique_src)),
        "unique_dst": int(len(unique_dst)),
        "dns_query_count": int(dns_query_count),
        "http_request_count": int(http_request_count),
        "unique_http_hosts": int(len(unique_http_hosts)),
        "tls_packet_count": int(tls_packet_count),
        "unique_tls_sni": int(len(tls_sni_set)),
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
        Duration=("Time", lambda x: float(x.max() - x.min())),
    ).reset_index()
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


def detect_suspicious_flows(df, kb, max_items=8):
    if df.empty:
        return []
    pd = _get_pandas()
    flow_df = compute_flow_stats(df).copy()
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

    suspicious = flow_df[flow_df["ioc_match"] | flow_df["high_volume"]]
    if suspicious.empty:
        return []

    suspicious = suspicious.sort_values(["ioc_match", "Bytes"], ascending=[False, False])
    results = []
    for _, row in suspicious.head(max_items).iterrows():
        reasons = []
        if bool(row["ioc_match"]):
            reasons.append("IoC IP match")
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


def _plot_top_flows(df):
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


class PCAPSentryApp:
    def __init__(self, root):
        self.root = root
        self.base_title = f"PCAP Sentry v{APP_VERSION}"
        
        self.settings = load_settings()
        
        # Initialize offline_mode_var early so _get_window_title() can use it
        self.offline_mode_var = tk.BooleanVar(value=self.settings.get("offline_mode", False))
        
        self.root_title = self._get_window_title()
        self.root.title(self.root_title)
        self.root.geometry("1200x950")

        self.theme_var = tk.StringVar(value=self.settings.get("theme", "system"))
        self.colors = {}
        self._apply_theme()

        self.font_title = tkfont.Font(family="Segoe UI", size=18, weight="bold")
        self.font_subtitle = tkfont.Font(family="Segoe UI", size=10)

        self.max_rows_var = tk.IntVar(value=self.settings.get("max_rows", DEFAULT_MAX_ROWS))
        self.parse_http_var = tk.BooleanVar(value=self.settings.get("parse_http", True))
        self.use_high_memory_var = tk.BooleanVar(value=self.settings.get("use_high_memory", False))
        self.use_local_model_var = tk.BooleanVar(value=self.settings.get("use_local_model", False))
        self.status_var = tk.StringVar(value="Ready")
        self.progress_percent_var = tk.StringVar(value="")
        self.sample_note_var = tk.StringVar(value="")
        self.ioc_path_var = tk.StringVar()
        self.ioc_summary_var = tk.StringVar(value="")
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
        self.label_mal_button = None
        self.target_drop_area = None
        self.why_text = None
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

        # Performance optimization: caching for analysis pipeline
        self.kb_cache = None  # Cache for loaded knowledge base
        self.normalizer_cache = None  # Cache for vector normalizer
        self.threat_intel_cache = None  # Cache for TI enrichment results
        self.threat_intel_cache_time = 0  # Timestamp for cache validity

        self._build_background()

        self._build_header()
        self._build_tabs()
        self._build_status()
        if APP_DATA_FALLBACK_NOTICE and not self.settings.get("app_data_notice_shown"):
            self.root.after(200, self._show_app_data_notice)

    def _get_window_title(self):
        """Generate window title with mode indicator"""
        if self.offline_mode_var.get():
            return f"{self.base_title} [OFFLINE MODE]"
        else:
            return f"{self.base_title} [ONLINE]"

    def _show_app_data_notice(self):
        window = tk.Toplevel(self.root)
        window.title("App Data Location")
        window.resizable(False, False)

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

    def _build_header(self):
        header = tk.Frame(self.root, bg=self.colors["bg"])
        header.pack(fill=tk.X, padx=12, pady=(12, 6))

        top_row = tk.Frame(header, bg=self.colors["bg"])
        top_row.pack(fill=tk.X)

        title_block = tk.Frame(top_row, bg=self.colors["bg"])
        title_block.pack(side=tk.LEFT)

        tk.Label(
            title_block,
            text="PCAP Sentry",
            font=self.font_title,
            fg=self.colors["text"],
            bg=self.colors["bg"],
        ).pack(anchor=tk.W)
        tk.Label(
            title_block,
            text=f"Malware Analysis Console (v{APP_VERSION})",
            font=self.font_subtitle,
            fg=self.colors["muted"],
            bg=self.colors["bg"],
        ).pack(anchor=tk.W)

        toolbar = ttk.Frame(header, padding=(0, 10, 0, 0))
        toolbar.pack(fill=tk.X)

        ttk.Label(toolbar, text="Max packets for visuals:").pack(side=tk.LEFT)
        ttk.Spinbox(toolbar, from_=10000, to=500000, increment=10000, textvariable=self.max_rows_var, width=8).pack(
            side=tk.LEFT, padx=6
        )
        ttk.Checkbutton(toolbar, text="Parse HTTP payloads", variable=self.parse_http_var).pack(side=tk.LEFT, padx=6)
        
        # Add update checker button if available
        if _update_checker_available:
            ttk.Button(toolbar, text="Check for Updates", command=self._check_for_updates_ui).pack(side=tk.RIGHT, padx=6)
        
        ttk.Button(toolbar, text="Preferences", command=self._open_preferences).pack(side=tk.RIGHT, padx=6)

        accent = tk.Frame(self.root, bg=self.colors["accent_alt"], height=2)
        accent.pack(fill=tk.X, padx=12, pady=(0, 8))

    def _build_tabs(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        self.train_tab = ttk.Frame(notebook)
        self.analyze_tab = ttk.Frame(notebook)
        self.kb_tab = ttk.Frame(notebook)

        notebook.add(self.analyze_tab, text="Analyze")
        notebook.add(self.train_tab, text="Train")
        notebook.add(self.kb_tab, text="Knowledge Base")

        self._build_train_tab()
        self._build_analyze_tab()
        self._build_kb_tab()

        notebook.select(self.analyze_tab)

        notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

    def _build_status(self):
        status = ttk.Frame(self.root, padding=10)
        status.pack(fill=tk.X)
        self.progress = ttk.Progressbar(status, mode="indeterminate", length=180)
        self.progress.pack(side=tk.LEFT, padx=6)
        ttk.Label(status, textvariable=self.progress_percent_var, style="Hint.TLabel").pack(side=tk.LEFT)
        # Status message
        status_label = ttk.Label(status, textvariable=self.status_var, font=("TkDefaultFont", 11, "bold"))
        status_label.pack(side=tk.LEFT, padx=12, fill=tk.X, expand=True)
        ttk.Label(status, textvariable=self.sample_note_var).pack(side=tk.RIGHT)

    def _open_preferences(self):
        window = tk.Toplevel(self.root)
        window.title("Preferences")
        window.resizable(False, False)

        frame = ttk.Frame(window, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Defaults", style="Hint.TLabel").grid(row=0, column=0, sticky="w", columnspan=3)

        ttk.Label(frame, text="Theme:").grid(row=1, column=0, sticky="w", pady=6)
        theme_combo = ttk.Combobox(frame, textvariable=self.theme_var, values=["system", "dark", "light"], width=10)
        theme_combo.state(["readonly"])
        theme_combo.grid(row=1, column=1, sticky="w", pady=6)
        ttk.Label(frame, text="(applies after restart)", style="Hint.TLabel").grid(
            row=1, column=2, sticky="w", pady=6
        )

        ttk.Label(frame, text="Max packets for visuals:").grid(row=2, column=0, sticky="w", pady=6)
        max_rows_spin = ttk.Spinbox(
            frame,
            from_=10000,
            to=500000,
            increment=10000,
            textvariable=self.max_rows_var,
            width=10,
        )
        max_rows_spin.grid(row=2, column=1, sticky="w", pady=6)

        ttk.Checkbutton(frame, text="Parse HTTP payloads", variable=self.parse_http_var, style="Quiet.TCheckbutton").grid(
            row=3, column=0, sticky="w", pady=6, columnspan=2
        )

        ttk.Checkbutton(
            frame,
            text="High memory mode (load PCAP into RAM)",
            variable=self.use_high_memory_var,
            style="Quiet.TCheckbutton"
        ).grid(row=4, column=0, sticky="w", pady=6, columnspan=2)
        ttk.Label(frame, text="(best for faster parsing of smaller files)", style="Hint.TLabel").grid(
            row=4, column=2, sticky="w", pady=6
        )

        ttk.Checkbutton(
            frame,
            text="Enable local ML model",
            variable=self.use_local_model_var,
            style="Quiet.TCheckbutton"
        ).grid(row=5, column=0, sticky="w", pady=6, columnspan=2)

        ttk.Checkbutton(
            frame,
            text="Offline mode (disable threat intelligence)",
            variable=self.offline_mode_var,
            style="Quiet.TCheckbutton"
        ).grid(row=6, column=0, sticky="w", pady=6, columnspan=2)
        ttk.Label(frame, text="(faster analysis, no internet required)", style="Hint.TLabel").grid(
            row=6, column=2, sticky="w", pady=6
        )

        # Backup directory row with improved spacing

        ttk.Label(frame, text="Backup directory:").grid(row=7, column=0, sticky="w", pady=6)
        backup_entry = ttk.Entry(frame, textvariable=self.backup_dir_var, width=60)
        backup_entry.grid(row=7, column=1, sticky="ew", pady=6)
        frame.grid_columnconfigure(1, weight=1)
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=7, column=2, columnspan=4, sticky="e", pady=6)
        ttk.Button(button_frame, text="X", width=2, command=lambda: self.backup_dir_var.set("")).pack(side=tk.LEFT, padx=0)
        ttk.Button(button_frame, text="Browse", command=self._browse_backup_dir).pack(side=tk.LEFT, padx=0)
        ttk.Button(button_frame, text="Save", command=lambda: self._save_preferences(window)).pack(side=tk.LEFT, padx=0)
        ttk.Button(button_frame, text="Cancel", command=window.destroy).pack(side=tk.LEFT, padx=0)
        ttk.Button(frame, text="Reset to Defaults", command=self._reset_preferences).grid(row=8, column=0, columnspan=6, sticky="e", pady=(10, 0))

        window.grab_set()

    def _save_preferences(self, window):
        self._save_settings_from_vars()
        self.root_title = self._get_window_title()
        self.root.title(self.root_title)
        window.destroy()

    def _save_settings_from_vars(self):
        settings = {
            "max_rows": int(self.max_rows_var.get()),
            "parse_http": bool(self.parse_http_var.get()),
            "use_high_memory": bool(self.use_high_memory_var.get()),
            "use_local_model": bool(self.use_local_model_var.get()),
            "offline_mode": bool(self.offline_mode_var.get()),
            "backup_dir": self.backup_dir_var.get().strip(),
            "theme": self.theme_var.get().strip().lower() or "system",
            "app_data_notice_shown": bool(self.settings.get("app_data_notice_shown")),
        }
        self.settings = settings
        save_settings(settings)

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
        self.offline_mode_var.set(defaults.get("offline_mode", False))
        self.backup_dir_var.set(defaults["backup_dir"])
        self.theme_var.set(defaults["theme"])
        self._save_settings_from_vars()

    def _check_for_updates_ui(self):
        """Handle "Check for Updates" button click."""
        if not _update_checker_available:
            messagebox.showwarning("Updates", "Update checker is not available.")
            return

        def show_result(result):
            """Callback after update check completes."""
            if not result.get("success"):
                messagebox.showerror(
                    "Check for Updates",
                    f"Failed to check for updates: {result.get('error', 'Unknown error')}",
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
                window.geometry("600x400")

                frame = ttk.Frame(window, padding=16)
                frame.pack(fill=tk.BOTH, expand=True)

                ttk.Label(
                    frame,
                    text=f"A new version is available!",
                    font=("TkDefaultFont", 12, "bold"),
                ).pack(anchor="w", pady=(0, 10))

                ttk.Label(
                    frame, text=f"Current version: {current}"
                ).pack(anchor="w", pady=(0, 5))
                ttk.Label(
                    frame, text=f"Available version: {latest}"
                ).pack(anchor="w", pady=(0, 15))

                ttk.Label(frame, text="Release Notes:", font=("TkDefaultFont", 10, "bold")).pack(anchor="w")
                text_frame = ttk.Frame(frame)
                text_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 15))

                scrollbar = ttk.Scrollbar(text_frame)
                scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

                text_widget = tk.Text(
                    text_frame, wrap=tk.WORD, yscrollcommand=scrollbar.set, height=10
                )
                text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
                scrollbar.config(command=text_widget.yview)

                text_widget.insert(tk.END, notes)
                text_widget.config(state=tk.DISABLED)

                button_frame = ttk.Frame(frame)
                button_frame.pack(fill=tk.X)

                def on_download():
                    self._download_and_install_update(latest)
                    window.destroy()

                ttk.Button(button_frame, text="Download & Update", command=on_download).pack(side=tk.LEFT, padx=6)
                ttk.Button(button_frame, text="Later", command=window.destroy).pack(side=tk.LEFT)

                window.grab_set()
            else:
                current = result.get("current", "unknown")
                messagebox.showinfo(
                    "Check for Updates",
                    f"You are running the latest version ({current}).",
                )

        # Run update check in background
        checker_thread = BackgroundUpdateChecker(APP_VERSION, callback=show_result)
        checker_thread.start()

        messagebox.showinfo("Check for Updates", "Checking for updates...")

    def _download_and_install_update(self, version):
        """Download and install the update."""
        def download_in_background():
            try:
                checker = UpdateChecker(APP_VERSION)
                if not checker.fetch_latest_release():
                    messagebox.showerror(
                        "Download Failed",
                        "Failed to fetch release information from GitHub.",
                    )
                    return

                if not checker.download_url:
                    messagebox.showerror(
                        "Download Failed", "No executable found in the latest release."
                    )
                    return

                update_dir = checker.get_update_dir()
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                exe_name = f"PCAP_Sentry_{version}_{timestamp}.exe"
                dest_path = os.path.join(update_dir, exe_name)

                # Show progress dialog
                progress_window = tk.Toplevel(self.root)
                progress_window.title("Downloading Update")
                progress_window.resizable(False, False)
                progress_window.geometry("400x100")

                frame = ttk.Frame(progress_window, padding=16)
                frame.pack(fill=tk.BOTH, expand=True)

                ttk.Label(frame, text="Downloading update...").pack(anchor="w", pady=(0, 10))
                progress_bar = ttk.Progressbar(frame, mode="determinate", length=350)
                progress_bar.pack(fill=tk.X, pady=(0, 10))
                status_label = ttk.Label(frame, text="0%")
                status_label.pack(anchor="w")

                def progress_callback(downloaded, total):
                    if total > 0:
                        progress = int((downloaded / total) * 100)
                        progress_bar["value"] = progress
                        status_label.config(text=f"{progress}%")
                        progress_window.update()

                if checker.download_update(dest_path, progress_callback=progress_callback):
                    progress_window.destroy()

                    # Launch the installer
                    if checker.launch_installer(dest_path):
                        messagebox.showinfo(
                            "Update Downloaded",
                            f"Update installer has been launched.\n\n"
                            f"The application will need to be restarted to complete the installation.",
                        )
                        # Optionally quit the app
                        quit_now = messagebox.askyesno(
                            "Update",
                            "Would you like to close PCAP Sentry now?",
                        )
                        if quit_now:
                            self.root.quit()
                    else:
                        messagebox.showerror(
                            "Download Complete",
                            f"Update downloaded to: {dest_path}\n\n"
                            f"Please run it manually to complete the installation.",
                        )
                else:
                    progress_window.destroy()
                    messagebox.showerror(
                        "Download Failed", "Failed to download the update."
                    )

            except Exception as e:
                messagebox.showerror(
                    "Update Error", f"An error occurred during update: {str(e)}"
                )

        download_thread = threading.Thread(target=download_in_background, daemon=True)
        download_thread.start()

    def _browse_backup_dir(self):
        path = filedialog.askdirectory()
        if path:
            self.backup_dir_var.set(path)

    def _clear_input_fields(self):
        if self.safe_path_var is not None:
            self.safe_path_var.set("")
        if self.mal_path_var is not None:
            self.mal_path_var.set("")
        if self.target_path_var is not None:
            self.target_path_var.set("")
        if self.ioc_path_var is not None:
            self.ioc_path_var.set("")

    def _build_train_tab(self):
        container = ttk.Frame(self.train_tab, padding=10)
        container.pack(fill=tk.BOTH, expand=True)

        safe_frame = ttk.LabelFrame(container, text="Known Safe PCAP", padding=10)
        safe_frame.pack(fill=tk.X, pady=8)

        self.safe_path_var = tk.StringVar()
        self.safe_entry = ttk.Entry(safe_frame, textvariable=self.safe_path_var, width=90)
        self.safe_entry.pack(side=tk.LEFT, padx=6)
        ttk.Button(safe_frame, text="X", width=2, command=lambda: self.safe_path_var.set("")).pack(
            side=tk.LEFT
        )
        self.safe_browse = ttk.Button(safe_frame, text="Browse", command=lambda: self._browse_file(self.safe_path_var))
        self.safe_browse.pack(
            side=tk.LEFT, padx=6
        )
        self.safe_add_button = ttk.Button(safe_frame, text="Add to Safe", command=lambda: self._train("safe"))
        self.safe_add_button.pack(side=tk.LEFT, padx=6)

        ttk.Label(container, text="Tip: Drag and drop a .pcap file into the path field.", style="Hint.TLabel").pack(
            anchor=tk.W, padx=6
        )
        ttk.Label(
            container,
            text="Note: Large PCAP files can take a few minutes to parse.",
            style="Hint.TLabel",
        ).pack(anchor=tk.W, padx=6)

        mal_frame = ttk.LabelFrame(container, text="Known Malware PCAP", padding=10)
        mal_frame.pack(fill=tk.X, pady=8)

        self.mal_path_var = tk.StringVar()
        self.mal_entry = ttk.Entry(mal_frame, textvariable=self.mal_path_var, width=90)
        self.mal_entry.pack(side=tk.LEFT, padx=6)
        ttk.Button(mal_frame, text="X", width=2, command=lambda: self.mal_path_var.set("")).pack(side=tk.LEFT)
        self.mal_browse = ttk.Button(mal_frame, text="Browse", command=lambda: self._browse_file(self.mal_path_var))
        self.mal_browse.pack(
            side=tk.LEFT, padx=6
        )
        self.mal_add_button = ttk.Button(mal_frame, text="Add to Malware", command=lambda: self._train("malicious"))
        self.mal_add_button.pack(
            side=tk.LEFT, padx=6
        )

    def _build_analyze_tab(self):
        # Create a scrollable container using Canvas
        canvas = tk.Canvas(self.analyze_tab, bg=self.colors.get("bg", "white"), highlightthickness=0)
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
        
        # Bind mousewheel to canvas for scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        # Use scrollable_frame as container
        container = scrollable_frame

        file_frame = ttk.LabelFrame(container, text="Target PCAP", padding=10)
        file_frame.pack(fill=tk.X, padx=10, pady=4)
        self.target_drop_area = file_frame

        self.target_path_var = tk.StringVar()
        self.target_entry = ttk.Entry(file_frame, textvariable=self.target_path_var, width=90)
        self.target_entry.pack(side=tk.LEFT, padx=6)
        ttk.Button(file_frame, text="X", width=2, command=lambda: self.target_path_var.set("")).pack(
            side=tk.LEFT
        )
        target_browse = ttk.Button(file_frame, text="Browse", command=lambda: self._browse_file(self.target_path_var))
        target_browse.pack(
            side=tk.LEFT, padx=6
        )
        self.analyze_button = ttk.Button(file_frame, text="Analyze", command=self._analyze)
        self.analyze_button.pack(side=tk.LEFT, padx=6)

        ttk.Label(container, text="Tip: Drag and drop a .pcap file into the path field.", style="Hint.TLabel").pack(
            anchor=tk.W, padx=6
        )

        opts_frame = ttk.Frame(container, padding=(0, 8))
        opts_frame.pack(fill=tk.X)
        ttk.Label(
            opts_frame,
            text="Heuristic + knowledge base scoring only.",
            style="Hint.TLabel",
        ).pack(side=tk.LEFT)

        # Label buttons frame - for marking captures
        label_frame = ttk.LabelFrame(container, text="Label Current Capture", padding=10)
        label_frame.pack(fill=tk.X, pady=6)
        self.label_safe_button = ttk.Button(
            label_frame,
            text="Mark as Safe",
            command=lambda: self._label_current("safe"),
            state=tk.DISABLED,
        )
        self.label_safe_button.pack(side=tk.LEFT, padx=6)
        self.label_mal_button = ttk.Button(
            label_frame,
            text="Mark as Malicious",
            command=lambda: self._label_current("malicious"),
            state=tk.DISABLED,
        )
        self.label_mal_button.pack(side=tk.LEFT, padx=6)
        ttk.Label(label_frame, text="Adds this capture to the knowledge base.", style="Hint.TLabel").pack(
            side=tk.LEFT, padx=6
        )

        self.results_notebook = ttk.Notebook(container)
        self.results_notebook.pack(fill=tk.BOTH, expand=True, pady=8)

        self.results_tab = ttk.Frame(self.results_notebook)
        self.why_tab = ttk.Frame(self.results_notebook)
        self.packets_tab = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.results_tab, text="Results")
        self.results_notebook.add(self.why_tab, text="Why")
        self.results_notebook.add(self.packets_tab, text="Packets")

        result_frame = ttk.LabelFrame(self.results_tab, text="Results", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True)

        self.result_text = tk.Text(result_frame, height=12)
        self._style_text(self.result_text)
        self.result_text.pack(fill=tk.BOTH, expand=True)

        why_frame = ttk.LabelFrame(self.why_tab, text="Why This Looks Malicious", padding=10)
        why_frame.pack(fill=tk.BOTH, expand=True)

        self.why_text = tk.Text(why_frame, height=12)
        self._style_text(self.why_text)
        self.why_text.insert(tk.END, "Run analysis to see explanations.")
        self.why_text.pack(fill=tk.BOTH, expand=True)

        why_controls = ttk.Frame(self.why_tab)
        why_controls.pack(fill=tk.X, pady=(6, 0))
        self.copy_filters_button = ttk.Button(
            why_controls, text="Copy Wireshark Filters", command=self._copy_wireshark_filters, state=tk.DISABLED
        )
        self.copy_filters_button.pack(side=tk.RIGHT)

        packet_filters = ttk.LabelFrame(self.packets_tab, text="Packet Filters", padding=10)
        packet_filters.pack(fill=tk.X, pady=6)

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
        ttk.Button(packet_filters, text="Reset", command=self._reset_packet_filters).grid(
            row=2, column=7, sticky="w"
        )

        packet_filters.grid_columnconfigure(8, weight=1)


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

        hint_frame = ttk.LabelFrame(self.packets_tab, text="C2 / Exfil Hints", padding=10)
        hint_frame.pack(fill=tk.BOTH, expand=False, pady=6)
        self.packet_hint_text = tk.Text(hint_frame, height=6)
        self._style_text(self.packet_hint_text)
        self.packet_hint_text.insert(tk.END, "Run analysis to see packet-level hints.")
        self.packet_hint_text.pack(fill=tk.BOTH, expand=True)

        flow_frame = ttk.LabelFrame(container, text="Flow Summary", padding=10)
        flow_frame.pack(fill=tk.BOTH, expand=True, pady=8)

        columns = ("Flow", "Packets", "Bytes", "Duration")
        self.flow_table = ttk.Treeview(flow_frame, columns=columns, show="headings", height=8)
        for col in columns:
            self.flow_table.heading(col, text=col)
            self.flow_table.column(col, width=220 if col == "Flow" else 90, anchor=tk.W)
        self.flow_table.pack(fill=tk.BOTH, expand=True)

        self.charts_button = ttk.Button(container, text="Open Charts", command=self._open_charts, state=tk.DISABLED)
        self.charts_button.pack(anchor=tk.E)

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

    def _build_kb_tab(self):
        container = ttk.Frame(self.kb_tab, padding=10)
        container.pack(fill=tk.BOTH, expand=True)

        header = ttk.Frame(container)
        header.pack(fill=tk.X)
        self.kb_summary_var = tk.StringVar(value="")
        ttk.Label(header, textvariable=self.kb_summary_var).pack(side=tk.LEFT)
        ttk.Button(header, text="Refresh", command=self._refresh_kb).pack(side=tk.RIGHT)
        ttk.Button(header, text="Reset Knowledge Base", command=self._reset_kb).pack(side=tk.RIGHT, padx=6)
        ttk.Button(header, text="Restore", command=self._restore_kb).pack(side=tk.RIGHT, padx=6)
        ttk.Button(header, text="Backup", command=self._backup_kb).pack(side=tk.RIGHT, padx=6)

        ioc_frame = ttk.LabelFrame(container, text="IoC Feed", padding=10)
        ioc_frame.pack(fill=tk.X, pady=6)
        ttk.Label(ioc_frame, text="IoC file:").pack(side=tk.LEFT)
        ioc_entry = ttk.Entry(ioc_frame, textvariable=self.ioc_path_var, width=70)
        ioc_entry.pack(side=tk.LEFT, padx=6)
        ttk.Button(ioc_frame, text="X", width=2, command=lambda: self.ioc_path_var.set("")).pack(side=tk.LEFT)
        ttk.Button(ioc_frame, text="Browse", command=self._browse_ioc).pack(side=tk.LEFT, padx=6)
        ttk.Button(ioc_frame, text="Import", command=self._load_ioc_file).pack(side=tk.LEFT, padx=6)
        ttk.Button(ioc_frame, text="Clear", command=self._clear_iocs).pack(side=tk.LEFT, padx=6)

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
            print("[DEBUG] No current_df or packet_table available.")
            return

        df = self.current_df.copy()
        print(f"[DEBUG] DataFrame columns: {list(df.columns)}")
        print(f"[DEBUG] DataFrame row count before filter: {len(df)}")
        if df.empty:
            print("[DEBUG] DataFrame is empty before filtering.")
            self._update_packet_table(df)
            return

        # Always use the original base time from the full DataFrame
        if self.packet_base_time is not None and "Time" in df.columns:
            df["RelTime"] = df["Time"] - self.packet_base_time
        else:
            df["RelTime"] = 0.0

        # Apply packet filters
        proto_filter = self.packet_proto_var.get() if self.packet_proto_var else "Any"
        if proto_filter != "Any" and "Proto" in df.columns:
            df = df[df["Proto"] == proto_filter]

        src_filter = self.packet_src_var.get() if self.packet_src_var else ""
        if src_filter and "Src" in df.columns:
            df = df[df["Src"].astype(str).str.contains(src_filter, na=False)]

        dst_filter = self.packet_dst_var.get() if self.packet_dst_var else ""
        if dst_filter and "Dst" in df.columns:
            df = df[df["Dst"].astype(str).str.contains(dst_filter, na=False)]

        sport_filter = self.packet_sport_var.get() if self.packet_sport_var else ""
        if sport_filter and "SPort" in df.columns:
            try:
                sport_val = int(sport_filter)
                df = df[df["SPort"] == sport_val]
            except ValueError:
                pass

        dport_filter = self.packet_dport_var.get() if self.packet_dport_var else ""
        if dport_filter and "DPort" in df.columns:
            try:
                dport_val = int(dport_filter)
                df = df[df["DPort"] == dport_val]
            except ValueError:
                pass

        time_min = self.packet_time_min_var.get() if self.packet_time_min_var else ""
        if time_min and "RelTime" in df.columns:
            try:
                time_min_val = float(time_min)
                df = df[df["RelTime"] >= time_min_val]
            except ValueError:
                pass

        time_max = self.packet_time_max_var.get() if self.packet_time_max_var else ""
        if time_max and "RelTime" in df.columns:
            try:
                time_max_val = float(time_max)
                df = df[df["RelTime"] <= time_max_val]
            except ValueError:
                pass

        size_min = self.packet_size_min_var.get() if self.packet_size_min_var else ""
        if size_min and "Size" in df.columns:
            try:
                size_min_val = int(size_min)
                df = df[df["Size"] >= size_min_val]
            except ValueError:
                pass

        size_max = self.packet_size_max_var.get() if self.packet_size_max_var else ""
        if size_max and "Size" in df.columns:
            try:
                size_max_val = int(size_max)
                df = df[df["Size"] <= size_max_val]
            except ValueError:
                pass

        dns_http_only = self.packet_dns_http_only_var.get() if self.packet_dns_http_only_var else False
        if dns_http_only:
            dns_filter = (df["DnsQuery"].astype(str) != "") | (df["HttpHost"].astype(str) != "")
            df = df[dns_filter]

        print(f"[DEBUG] DataFrame row count after filter: {len(df)}")
        self._update_packet_table(df)

    def _update_packet_table(self, df):
        if self.packet_table is None:
            return
        for row in self.packet_table.get_children():
            self.packet_table.delete(row)

        if df is None or df.empty:
            print("[DEBUG] _update_packet_table: DataFrame is empty at insert stage.")
            return

        print(f"[DEBUG] _update_packet_table: self.packet_table id={id(self.packet_table)}")
        print(f"[DEBUG] _update_packet_table: DataFrame row count before insert: {len(df)}")
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
        # Debug: print first 3 rows' keys and values
        for i, (_, row) in enumerate(df.head(3).iterrows()):
            print(f"[DEBUG] Row {i} keys: {list(row.keys())}")
            print(f"[DEBUG] Row {i} values: {list(row.values)}")
        rows_for_size = []
        row_count = 0
        for idx, (_, row) in enumerate(df.head(500).iterrows()):
            values = [self._format_packet_table_value(row, col) for col in columns]
            print(f"[DEBUG] Insert row {idx}: {values}")
            self.packet_table.insert("", tk.END, values=values)
            rows_for_size.append(values)
            row_count += 1
        print(f"[DEBUG] Inserted {row_count} rows into packet table.")
        self._autosize_packet_table(columns, rows_for_size)

    def _format_packet_table_value(self, row, col):
        # Always use 'Time' for 'UTC Time' display
        if col == "UTC Time":
            try:
                time_val = row.get("Time", None)
                if time_val is not None:
                    value = datetime.fromtimestamp(float(time_val), timezone.utc)
                    return value.strftime("%Y-%m-%d %H:%M:%SZ")
                else:
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
                if candidate > width:
                    width = candidate
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
        visible = [
            col
            for col in self.packet_columns or []
            if self.packet_column_vars[col].get()
        ]
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

    def _update_packet_hints(self, df, stats):
        if self.packet_hint_text is None:
            return

        hint_lines = ["Focus areas for C2 / exfil review:"]

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
                    hint_lines.append(
                        f"- Large transfer: {row['Flow']} ({_format_bytes(row['Bytes'])})"
                    )

        beacon_flow = None
        if not df.empty:
            flow_cols = ["Src", "Dst", "Proto", "SPort", "DPort"]
            grouped = df.groupby(flow_cols, dropna=False)
            for keys, group in grouped:
                if len(group) < 6:
                    continue
                times = sorted(group["Time"].tolist())
                gaps = [b - a for a, b in zip(times, times[1:]) if b - a > 0]
                if len(gaps) < 5:
                    continue
                avg_gap = sum(gaps) / len(gaps)
                if avg_gap <= 0:
                    continue
                std_gap = statistics.pstdev(gaps)
                cv = std_gap / avg_gap if avg_gap else 0.0
                if cv < 0.2:
                    flow_str = f"{keys[0]}:{keys[3]} -> {keys[1]}:{keys[4]} ({keys[2]})"
                    beacon_flow = (flow_str, avg_gap)
                    break

        if beacon_flow:
            hint_lines.append(f"- Beaconing-like cadence: {beacon_flow[0]} (~{beacon_flow[1]:.2f}s interval)")
        else:
            hint_lines.append("- Beaconing cadence: not obvious in top flows")

        top_ports = stats.get("top_ports", [])
        if top_ports:
            common_ports = {22, 53, 80, 123, 443, 445, 3389}
            unusual_ports = [str(port) for port, _ in top_ports if port not in common_ports]
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
            filters.append(f"dns.qry.name == \"{domain}\"")
            filters.append(f"http.host == \"{domain}\"")

        for ip in ips[:3]:
            filters.append(f"ip.addr == {ip}")

        if top_ports:
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
        path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        if path:
            var.set(path)

    def _browse_ioc(self):
        path = filedialog.askopenfilename(filetypes=[("IoC files", "*.json;*.txt"), ("All files", "*.*")])
        if path:
            self.ioc_path_var.set(path)

    def _set_busy(self, busy=True, message="Working..."):
        if busy:
            self.busy_count += 1
            if self.busy_count == 1:
                self.status_var.set(message)
                self._reset_progress()
                self.progress.start(10)
                self.root.configure(cursor="watch")
                self.root.title(f"{self.root_title} - Working...")
                self.widget_states = {w: str(w["state"]) for w in self.busy_widgets}
                for widget in self.busy_widgets:
                    widget.configure(state=tk.DISABLED)
            else:
                self.status_var.set(message)
        else:
            self.busy_count = max(0, self.busy_count - 1)
            if self.busy_count == 0:
                self._reset_progress()
                self.status_var.set("Ready")
                self.root.configure(cursor="")
                self.root_title = self._get_window_title()
                self.root.title(self.root_title)
                for widget in self.busy_widgets:
                    prior = self.widget_states.get(widget, "normal")
                    widget.configure(state=prior)

    def _reset_progress(self):
        self.progress.stop()
        self.progress.configure(mode="indeterminate", maximum=100)
        self.progress["value"] = 0
        self.progress_percent_var.set("")


    def _set_determinate_progress(self, percent):
        """Set progress bar to determinate mode with specific percentage."""
        self.progress.stop()
        self.progress.configure(mode="determinate", maximum=100)
        self.progress["value"] = percent
        self.progress_percent_var.set(f"{int(percent)}%")
        self.root.update_idletasks()

    def _set_progress(self, percent, eta_seconds=None, label=None, processed=None, total=None):
        if percent is None:
            self.progress_percent_var.set("")
            return
        self.progress.stop()
        self.progress.configure(mode="determinate", maximum=100)
        percent_value = min(max(percent, 0.0), 100.0)
        self.progress["value"] = percent_value
        self.progress_percent_var.set(f"{percent_value:.0f}%")
        if label:
            status_text = f"{label} {percent:.0f}%"
            if processed is not None and total:
                status_text = f"{label} {percent:.0f}% ({_format_bytes(processed)} / {_format_bytes(total)})"
            self.status_var.set(status_text)

    def _apply_theme(self):
        theme = self._resolve_theme()
        if theme == "light":
            self.colors = {
                "bg": "#f5f7fb",
                "panel": "#ffffff",
                "text": "#12141a",
                "muted": "#5d6776",
                "accent": "#2b7cbf",
                "accent_alt": "#1f5f95",
                "border": "#d7dbe2",
                "danger": "#b84a3f",
                "neon": "#a02f8f",
                "neon_alt": "#2a88a6",
                "bg_wave": "#dbe3ef",
                "bg_node": "#c9d3e3",
                "bg_hex": "#c2ccdb",
            }
        else:
            self.colors = {
                "bg": "#0a0c11",
                "panel": "#111621",
                "text": "#e6e6e6",
                "muted": "#9aa3b2",
                "accent": "#3fa9f5",
                "accent_alt": "#2b7cbf",
                "border": "#222938",
                "danger": "#e76f51",
                "neon": "#c235a8",
                "neon_alt": "#2aa5c9",
                "bg_wave": "#1b2a3f",
                "bg_node": "#223551",
                "bg_hex": "#142133",
            }

        self.root.configure(bg=self.colors["bg"])
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("TFrame", background=self.colors["bg"])
        style.configure("TLabel", background=self.colors["bg"], foreground=self.colors["text"])
        style.configure("Hint.TLabel", background=self.colors["bg"], foreground=self.colors["muted"])
        style.configure(
            "TButton",
            background=self.colors["accent"],
            foreground=self.colors["text"],
            bordercolor=self.colors["border"],
            focusthickness=1,
            focuscolor=self.colors["accent_alt"],
            padding=6,
        )
        style.map(
            "TButton",
            background=[("active", self.colors["accent_alt"]), ("disabled", self.colors["border"])],
            foreground=[("disabled", self.colors["muted"])],
        )

        style.configure("TCheckbutton", background=self.colors["bg"], foreground=self.colors["text"])
        style.map("TCheckbutton", foreground=[("disabled", self.colors["muted"])])
        style.configure("Quiet.TCheckbutton", background=self.colors["bg"], foreground=self.colors["text"])
        style.map(
            "Quiet.TCheckbutton",
            background=[("active", self.colors["bg"]), ("focus", self.colors["bg"])],
            foreground=[("active", self.colors["text"]), ("disabled", self.colors["muted"])],
        )

        style.configure("TLabelframe", background=self.colors["bg"], foreground=self.colors["text"])
        style.configure("TLabelframe.Label", background=self.colors["bg"], foreground=self.colors["text"])

        style.configure("TNotebook", background=self.colors["bg"], bordercolor=self.colors["border"])
        style.configure("TNotebook.Tab", background=self.colors["panel"], foreground=self.colors["text"], padding=6)
        style.map(
            "TNotebook.Tab",
            background=[("selected", self.colors["accent_alt"]), ("active", self.colors["accent"])]
        )

        style.configure(
            "TEntry",
            fieldbackground=self.colors["panel"],
            foreground=self.colors["text"],
            bordercolor=self.colors["border"],
            insertcolor=self.colors["text"],
        )
        style.configure(
            "TSpinbox",
            fieldbackground=self.colors["panel"],
            foreground=self.colors["text"],
            bordercolor=self.colors["border"],
            insertcolor=self.colors["text"],
        )

        style.configure(
            "Treeview",
            background=self.colors["panel"],
            fieldbackground=self.colors["panel"],
            foreground=self.colors["text"],
            bordercolor=self.colors["border"],
        )
        style.configure(
            "Treeview.Heading",
            background=self.colors["bg"],
            foreground=self.colors["text"],
        )
        style.map(
            "Treeview",
            background=[("selected", self.colors["accent_alt"])],
            foreground=[("selected", self.colors["text"])],
        )
        style.configure(
            "Packet.Treeview",
            background=self.colors["panel"],
            fieldbackground=self.colors["panel"],
            foreground=self.colors["text"],
            bordercolor=self.colors["border"],
        )
        style.configure(
            "Packet.Treeview.Heading",
            background=self.colors["bg"],
            foreground=self.colors["text"],
            bordercolor=self.colors["border"],
            relief="flat",
        )
        style.map(
            "Packet.Treeview",
            background=[("selected", self.colors["accent_alt"])],
            foreground=[("selected", self.colors["text"])],
        )
        style.map(
            "Packet.Treeview.Heading",
            background=[("active", self.colors["bg"]), ("pressed", self.colors["bg"])],
            bordercolor=[("active", self.colors["accent_alt"]), ("pressed", self.colors["accent_alt"])],
            relief=[("active", "solid"), ("pressed", "solid")],
        )

        style.configure(
            "TProgressbar",
            background=self.colors["accent"],
            troughcolor=self.colors["panel"],
            bordercolor=self.colors["border"],
        )

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
        canvas.bind("<Configure>", self._draw_background)
        self.bg_canvas = canvas

    def _draw_background(self, _event=None):
        if self.bg_canvas is None:
            return
        w = self.bg_canvas.winfo_width()
        h = self.bg_canvas.winfo_height()
        if w <= 1 or h <= 1:
            return

        self.bg_canvas.delete("all")

        # Base gradient
        steps = 18
        for i in range(steps):
            ratio = i / max(steps - 1, 1)
            r = int(10 + (20 - 10) * ratio)
            g = int(12 + (16 - 12) * ratio)
            b = int(18 + (26 - 18) * ratio)
            color = f"#{r:02x}{g:02x}{b:02x}"
            y0 = int(h * i / steps)
            y1 = int(h * (i + 1) / steps)
            self.bg_canvas.create_rectangle(0, y0, w, y1, fill=color, outline=color)

        # Neon horizon glow
        glow_y = int(h * 0.65)
        self.bg_canvas.create_oval(-w * 0.2, glow_y - h * 0.1, w * 1.2, glow_y + h * 0.4,
                       fill="", outline=self.colors["neon"], width=1)
        self.bg_canvas.create_oval(-w * 0.1, glow_y - h * 0.05, w * 1.1, glow_y + h * 0.3,
                       fill="", outline=self.colors["neon_alt"], width=1)

        # Grid lines
        grid_color = "#141b26"
        for x in range(0, w, 60):
            self.bg_canvas.create_line(x, glow_y, x, h, fill=grid_color)
        for y in range(glow_y, h, 40):
            self.bg_canvas.create_line(0, y, w, y, fill=grid_color)

        # Diagonal neon accents
        self.bg_canvas.create_line(0, glow_y - 80, w, glow_y + 120, fill=self.colors["neon_alt"], width=1)
        self.bg_canvas.create_line(0, glow_y - 120, w, glow_y + 80, fill=self.colors["neon"], width=1)

        # PCAP-style waveform
        wave_color = self.colors.get("bg_wave", "#1b2a3f")
        points = []
        step = max(40, w // 18)
        amplitude = max(18, h // 22)
        baseline = int(h * 0.28)
        for x in range(0, w + step, step):
            offset = ((x // step) % 2) * 2 - 1
            y = baseline + offset * amplitude
            points.extend([x, y])
        if len(points) >= 4:
            self.bg_canvas.create_line(*points, fill=wave_color, width=2)

        # Packet nodes
        node_color = self.colors.get("bg_node", "#223551")
        for x in range(80, w, 220):
            self.bg_canvas.create_oval(x, baseline - 6, x + 10, baseline + 4, outline=node_color, width=2)

        # Hex dump motif
        hex_color = self.colors.get("bg_hex", "#142133")
        hex_rows = min(6, max(2, h // 140))
        hex_cols = min(6, max(3, w // 200))
        hex_text = "4f 52 4f 4c 2d 50 43 41 50"
        for row in range(hex_rows):
            for col in range(hex_cols):
                x = 40 + col * 180
                y = int(h * 0.72) + row * 22
                self.bg_canvas.create_text(x, y, anchor="w", text=hex_text, fill=hex_color, font=("Consolas", 9))

    def _setup_drag_drop(self):
        if not _check_tkinterdnd2():
            return
        
        DND_FILES, TkinterDnD = _get_tkinterdnd2()

        def bind_drop(widget, setter):
            if widget is None:
                return
            try:
                widget.drop_target_register(DND_FILES)
                widget.dnd_bind("<<Drop>>", lambda e: setter(self._extract_drop_path(e.data)))
            except tk.TclError:
                return

        bind_drop(self.safe_entry, self.safe_path_var.set)
        bind_drop(self.mal_entry, self.mal_path_var.set)
        bind_drop(self.target_entry, self.target_path_var.set)
        if self.target_drop_area is not None:
            bind_drop(self.target_drop_area, self.target_path_var.set)
        bind_drop(self.analyze_tab, self.target_path_var.set)
        bind_drop(self.result_text, self.target_path_var.set)
        bind_drop(self.flow_table, self.target_path_var.set)

    def _extract_drop_path(self, data):
        if not data:
            return ""

        def normalize(text):
            if not text:
                return ""
            text = text.strip().strip("\"")
            if text.startswith("{") and text.endswith("}"):
                text = text[1:-1]
            if text.startswith("file://"):
                from urllib.parse import unquote, urlparse

                parsed = urlparse(text)
                path = unquote(parsed.path or "")
                if sys.platform.startswith("win") and path.startswith("/"):
                    path = path[1:]
                text = path or text
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

    def _style_text(self, widget):
        widget.configure(
            background=self.colors["panel"],
            foreground=self.colors["text"],
            insertbackground=self.colors["text"],
            selectbackground=self.colors["accent_alt"],
            selectforeground=self.colors["text"],
            borderwidth=1,
            relief="solid",
        )

    def _show_overlay(self, message):
        pass

    def _update_overlay_message(self, message):
        pass

    def _hide_overlay(self):
        pass

    def _run_task(self, func, on_success, on_error=None, message="Working...", progress_label=None):
        self._set_busy(True, message)
        q = queue.Queue()

        def progress_cb(percent, eta_seconds=None, processed=None, total=None):
            q.put(
                (
                    "progress",
                    {
                        "percent": percent,
                        "eta": eta_seconds,
                        "processed": processed,
                        "total": total,
                    },
                )
            )

        def worker():
            try:
                if progress_label:
                    q.put(("ok", func(progress_cb)))
                else:
                    q.put(("ok", func()))
            except Exception as exc:
                q.put(("err", exc))

        threading.Thread(target=worker, daemon=True).start()

        def check():
            done = False
            payload = None
            error = None
            latest_progress = None
            try:
                for _ in range(50):
                    status, item = q.get_nowait()
                    if status == "progress":
                        latest_progress = item
                    elif status == "ok":
                        done = True
                        payload = item
                        break
                    elif status == "err":
                        done = True
                        error = item
                        break
            except queue.Empty:
                pass

            if latest_progress is not None:
                self._set_progress(
                    latest_progress.get("percent"),
                    latest_progress.get("eta"),
                    progress_label,
                    processed=latest_progress.get("processed"),
                    total=latest_progress.get("total"),
                )

            if done:
                self._set_busy(False)
                if error is None:
                    on_success(payload)
                else:
                    if on_error:
                        on_error(error)
                    else:
                        messagebox.showerror("Error", str(error))
            else:
                self.root.after(100, check)

        self.root.after(100, check)

    def _reset_kb(self):
        if os.path.exists(KNOWLEDGE_BASE_FILE):
            wants_backup = messagebox.askyesno(
                "Knowledge Base",
                "Would you like to back up the knowledge base before resetting?",
            )
            if wants_backup:
                if not self._backup_kb():
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
            with open(path, "r", encoding="utf-8") as f:
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
                _write_error_log(f"Error importing IoCs", e, sys.exc_info()[2])
                messagebox.showerror("Error", f"Failed to import IoCs: {str(e)}")

        self._run_task(task, done, message="Importing IoCs...")

    def _clear_iocs(self):
        try:
            kb = load_knowledge_base()
            kb["ioc"] = {"ips": [], "domains": [], "hashes": []}
            save_knowledge_base(kb)
            self._refresh_kb()
            messagebox.showinfo("IoC Feed", "IoCs cleared.")
        except Exception as e:
            _write_error_log(f"Error clearing IoCs", e, sys.exc_info()[2])
            messagebox.showerror("Error", f"Failed to clear IoCs: {str(e)}")

    def _train(self, label):
        path = self.safe_path_var.get() if label == "safe" else self.mal_path_var.get()
        if not path:
            messagebox.showwarning("Missing file", "Please select a PCAP or ZIP file.")
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
                df, stats, _ = result
                if stats.get("packet_count", 0) == 0:
                    messagebox.showwarning("No data", "No IP packets found in this capture.")
                    return
                features = build_features(stats)
                summary = summarize_stats(stats)
                add_to_knowledge_base(label, stats, features, summary)
                if self.use_local_model_var.get():
                    kb = load_knowledge_base()
                    model_bundle, err = _train_local_model(kb)
                    if model_bundle is None:
                        messagebox.showinfo("Local Model", err or "Local model training skipped.")
                    else:
                        _save_local_model(model_bundle)
                messagebox.showinfo("Training", f"Added {label} PCAP to knowledge base.")
                self._refresh_kb()
                if label == "safe":
                    self.safe_path_var.set("")
                else:
                    self.mal_path_var.set("")
            except Exception as e:
                _write_error_log(f"Error training with {label} PCAP", e, sys.exc_info()[2])
                messagebox.showerror("Error", f"Failed to train with PCAP: {str(e)}")

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
            add_to_knowledge_base(label, self.current_stats, features, summary)
            if self.use_local_model_var.get():
                kb = load_knowledge_base()
                model_bundle, err = _train_local_model(kb)
                if model_bundle is None:
                    messagebox.showinfo("Local Model", err or "Local model training skipped.")
                else:
                    _save_local_model(model_bundle)
            self._refresh_kb()
            messagebox.showinfo("Knowledge Base", f"Current capture saved as {label}.")
        except Exception as e:
            _write_error_log(f"Error labeling current capture as {label}", e, sys.exc_info()[2])
            messagebox.showerror("Error", f"Failed to label capture: {str(e)}")

    def _analyze(self):
        path = self.target_path_var.get()
        if not path:
            messagebox.showwarning("Missing file", "Please select a PCAP or ZIP file.")
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
            df, stats, sample_info = result
            if stats.get("packet_count", 0) == 0:
                messagebox.showwarning("No data", "No IP packets found in this capture.")
                self.label_safe_button.configure(state=tk.DISABLED)
                self.label_mal_button.configure(state=tk.DISABLED)
                return

            self.current_df = df
            self.current_stats = stats
            self.current_sample_info = sample_info
            # Store the base time for packet filtering
            if not df.empty and "Time" in df.columns:
                self.packet_base_time = float(df["Time"].min())
            else:
                self.packet_base_time = None

            # Enrich stats with threat intelligence data for better ML features (single pass)
            threat_intel_findings = {}
            if not self.offline_mode_var.get() and _check_threat_intel():
                self._set_determinate_progress(35)
                self.status_var.set("Enriching with threat intelligence...")
                self.root.update_idletasks()
                try:
                    from threat_intelligence import ThreatIntelligence
                    ti = ThreatIntelligence()
                    if ti.is_available():
                        print("[DEBUG] Enriching stats with threat intelligence...")
                        threat_intel_findings = ti.enrich_stats(stats)
                        stats.update(threat_intel_findings)  # Merge findings into stats
                        self.current_stats = stats
                except Exception as e:
                    print(f"[DEBUG] Threat intelligence enrichment failed: {e}")

            t1 = time.time()
            self._set_determinate_progress(50)
            self.status_var.set("Building features...")
            self.root.update_idletasks()
            
            features = build_features(stats)
            vector = _vector_from_features(features)
            kb = self._get_knowledge_base()  # Use cached KB instead of reloading
            t2 = time.time()
            print(f"[TIMING] Feature building: {t2-t1:.2f}s")
            
            self._set_determinate_progress(60)
            self.status_var.set("Computing risk scores...")
            self.root.update_idletasks()
            
            # OPTIMIZATION: Use top-K similar entries instead of scoring all KB entries
            safe_entries, safe_scores = get_top_k_similar_entries(features, kb["safe"], k=5)
            mal_entries, mal_scores = get_top_k_similar_entries(features, kb["malicious"], k=5)

            t3 = time.time()
            print(f"[TIMING] Score calculation: {t3-t2:.2f}s")
            
            baseline = compute_baseline_from_kb(kb)
            anomaly_result, anomaly_reasons = anomaly_score(vector, baseline)
            classifier_result = classify_vector(vector, kb, normalizer_cache=self.normalizer_cache)
            # OPTIMIZATION: Cache the normalizer for subsequent analyses with same KB
            if classifier_result and self.normalizer_cache is None and "normalizer" in classifier_result:
                self.normalizer_cache = classifier_result.get("normalizer")

            ioc_matches = match_iocs(stats, kb.get("ioc", {}))
            ioc_count = len(ioc_matches["ips"]) + len(ioc_matches["domains"])
            ioc_available = any(kb.get("ioc", {}).get(key) for key in ("ips", "domains", "hashes"))
            if ioc_count:
                ioc_score = min(100.0, 75.0 + (ioc_count - 1) * 5.0)
            else:
                ioc_score = 0.0

            risk_components = []
            if classifier_result is not None:
                risk_components.append((classifier_result["score"], 0.5))
            if anomaly_result is not None:
                risk_components.append((anomaly_result, 0.3))
            if ioc_available:
                risk_components.append((ioc_score, 0.2))

            if risk_components:
                total_weight = sum(weight for _, weight in risk_components)
                risk_score = sum(score * weight for score, weight in risk_components) / total_weight
                risk_score = round(risk_score, 1)
            else:
                risk_score = 0.0

            if risk_score >= 70:
                verdict = "Likely Malicious"
            elif risk_score >= 40:
                verdict = "Suspicious"
            else:
                verdict = "Likely Safe"
            if ioc_count and verdict == "Likely Safe":
                verdict = "Suspicious (IoC Match)"

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
                if best_mal - best_safe >= 10:
                    output_lines.append("Verdict: Likely Malicious")
                elif best_safe - best_mal >= 10:
                    output_lines.append("Verdict: Likely Safe")
                else:
                    output_lines.append("Verdict: Suspicious / Inconclusive")

            if self.use_local_model_var.get():
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

            # Add threat intelligence findings if available
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

            t4 = time.time()
            self._set_determinate_progress(80)
            self.status_var.set("Detecting suspicious flows...")
            self.root.update_idletasks()
            
            suspicious_flows = detect_suspicious_flows(df, kb)
            t5 = time.time()
            print(f"[TIMING] Suspicious flows detection: {t5-t4:.2f}s")
            
            output_lines.append("")
            output_lines.append("Suspicious Flows (heuristic)")
            if not suspicious_flows:
                output_lines.append("No suspicious flows detected.")
            else:
                for item in suspicious_flows:
                    output_lines.append(
                        f"- {item['flow']} | {item['reason']} | {item['bytes']} | {item['packets']} pkts"
                    )

            wireshark_filters = self._build_wireshark_filters(
                stats, ioc_matches, verdict, suspicious_flows=suspicious_flows
            )
            if wireshark_filters:
                output_lines.append("- Wireshark filters: see Why tab")

            why_lines = [
                "Summary",
                f"- Verdict: {verdict} (risk {risk_score}/100)",
                "",
                "What this means:",
            ]
            
            # Add simple explanation based on verdict
            if verdict == "Likely Malicious":
                why_lines.append("This traffic exhibits strong indicators of malware or unauthorized access.")
                why_lines.append("Review IOC matches, suspicious ports, and unusual traffic patterns below.")
            elif verdict == "Suspicious (IoC Match)":
                why_lines.append("This traffic matches known malicious IPs or domains from threat feeds.")
                why_lines.append("The behavior and connections are flagged as potentially harmful.")
            elif verdict == "Suspicious":
                why_lines.append("This traffic shows unusual patterns that warrant further investigation.")
                why_lines.append("While not definitively malicious, review the signals below for concerns.")
            elif verdict == "Likely Safe":
                why_lines.append("This traffic appears to be normal and benign.")
                why_lines.append("No significant malicious indicators were detected.")
            
            why_lines.append("")
            why_lines.append("Signals that drove the score:")

            if classifier_result is None:
                why_lines.append("- Classifier: not enough labeled data")
            else:
                why_lines.append(
                    f"- Classifier risk: {classifier_result['score']} (closer to malware centroid)")

            if anomaly_result is None:
                why_lines.append("- Baseline anomaly: no safe baseline available")
            else:
                reasons = ", ".join(anomaly_reasons) if anomaly_reasons else "no standout outliers"
                why_lines.append(f"- Baseline anomaly: {anomaly_result} ({reasons})")

            if ioc_available:
                if ioc_count:
                    why_lines.append(
                        f"- IoC matches: {ioc_count} (domains: {len(ioc_matches['domains'])}, ips: {len(ioc_matches['ips'])})"
                    )
                else:
                    why_lines.append("- IoC matches: none")
            else:
                why_lines.append("- IoC feed: not loaded")

            why_lines.append("")
            why_lines.append("Traffic clues to review:")

            top_ports = stats.get("top_ports", [])
            if top_ports:
                port_text = ", ".join(f"{port} ({count})" for port, count in top_ports)
                why_lines.append(f"- Top destination ports: {port_text}")
                common_ports = {22, 53, 80, 123, 443, 445, 3389}
                unusual_ports = [str(port) for port, _ in top_ports if port not in common_ports]
                if unusual_ports:
                    why_lines.append(f"  Non-standard ports among top ports: {', '.join(unusual_ports)}")

            dns_count = stats.get("dns_query_count", 0)
            if dns_count:
                top_dns = stats.get("top_dns", [])
                if top_dns:
                    dns_text = ", ".join(f"{domain} ({count})" for domain, count in top_dns)
                    why_lines.append(f"- Top DNS queries: {dns_text}")
                else:
                    why_lines.append(f"- DNS queries observed: {dns_count}")

            http_count = stats.get("http_request_count", 0)
            http_hosts = stats.get("http_hosts", [])
            if http_count:
                if http_hosts:
                    why_lines.append(f"- HTTP hosts: {', '.join(http_hosts[:5])}")
                else:
                    why_lines.append(f"- HTTP requests observed: {http_count}")

            tls_count = stats.get("tls_packet_count", 0)
            tls_sni = stats.get("tls_sni", [])
            if tls_count:
                if tls_sni:
                    why_lines.append(f"- TLS SNI observed: {', '.join(tls_sni[:5])}")
                else:
                    why_lines.append(f"- TLS packets observed: {tls_count}")

            avg_size = stats.get("avg_size", 0.0)
            median_size = stats.get("median_size", 0.0)
            why_lines.append(f"- Avg packet size: {avg_size:.1f} bytes; median: {median_size:.1f} bytes")
            if median_size and median_size < 120:
                why_lines.append("  Many small packets can indicate beaconing or C2 check-ins.")
            elif avg_size and avg_size > 1200:
                why_lines.append("  Larger packets can indicate bulk data transfer or exfiltration.")

            # Add threat intelligence findings to why
            if threat_intel_findings.get("threat_intel"):
                intel_data = threat_intel_findings["threat_intel"]
                if intel_data.get("risky_ips") or intel_data.get("risky_domains"):
                    why_lines.append("")
                    why_lines.append("Online threat intelligence (public feeds):")
                    if intel_data.get("risky_ips"):
                        for ip_info in intel_data["risky_ips"][:3]:
                            why_lines.append(f"  - {ip_info['ip']} flagged by threat feeds (risk: {ip_info['risk_score']:.0f}/100)")
                    if intel_data.get("risky_domains"):
                        for domain_info in intel_data["risky_domains"][:3]:
                            why_lines.append(f"  - {domain_info['domain']} flagged by threat feeds (risk: {domain_info['risk_score']:.0f}/100)")

            why_lines.append("")
            why_lines.append("Suspicious flows to review:")
            if not suspicious_flows:
                why_lines.append("- None flagged by heuristics.")
            else:
                for item in suspicious_flows:
                    why_lines.append(
                        f"- {item['flow']} | {item['reason']} | {item['bytes']} | {item['packets']} pkts"
                    )

            if wireshark_filters:
                unique_filters = list(dict.fromkeys(wireshark_filters))
                self.wireshark_filters = unique_filters
                why_lines.append("")
                why_lines.append("Wireshark filters to start with:")
                for filt in unique_filters:
                    why_lines.append(f"- {filt}")
            else:
                self.wireshark_filters = []

            if self.why_text is not None:
                self.why_text.delete("1.0", tk.END)
                self.why_text.insert(tk.END, "\n".join(why_lines))

            if self.copy_filters_button is not None:
                if self.wireshark_filters:
                    self.copy_filters_button.configure(state=tk.NORMAL)
                else:
                    self.copy_filters_button.configure(state=tk.DISABLED)

            self.result_text.delete("1.0", tk.END)
            self.result_text.insert(tk.END, "\n".join(output_lines))

            print(f"[DEBUG] _analyze: self.packet_table id={id(self.packet_table)} before apply_packet_filters")
            # Select Results tab before updating table
            if hasattr(self, 'results_notebook') and hasattr(self, 'results_tab'):
                try:
                    self.results_notebook.select(self.results_tab)
                    self.results_tab.update_idletasks()
                    self.results_tab.update()
                    print(f"[DEBUG] Selected results_tab")
                except Exception as e:
                    print(f"[DEBUG] Could not switch to results tab: {e}")
            if self.packet_table is not None:
                try:
                    parent = self.packet_table.nametowidget(self.packet_table.winfo_parent())
                    print(f"[DEBUG] packet_table parent: {parent}")
                    print(f"[DEBUG] packet_table is mapped: {self.packet_table.winfo_ismapped()}")
                except Exception as e:
                    print(f"[DEBUG] Could not get packet_table parent or visibility: {e}")
            self._apply_packet_filters()
            self._update_packet_hints(df, stats)
            
            self._set_determinate_progress(100)
            self.status_var.set("Done")
            self.root.update_idletasks()
            
            # Switch to Results tab to show analysis
            if hasattr(self, 'results_notebook') and hasattr(self, 'results_tab'):
                try:
                    self.results_notebook.select(self.results_tab)
                    print(f"[DEBUG] Selected results_tab for final view")
                except Exception as e:
                    print(f"[DEBUG] Could not switch to results tab: {e}")

            for row in self.flow_table.get_children():
                self.flow_table.delete(row)
            flow_df = compute_flow_stats(df)
            for _, row in flow_df.head(25).iterrows():
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
            self.label_mal_button.configure(state=tk.NORMAL)
            self.target_path_var.set("")
            
            t_end = time.time()
            print(f"[TIMING] Total result processing: {t_end-t_start:.2f}s")

        self._run_task(task, done, message="Analyzing PCAP...", progress_label="Analyzing PCAP")

    def _open_charts(self):
        if self.current_df is None:
            return
        window = tk.Toplevel(self.root)
        window.title("PCAP Charts")
        window.geometry("1000x800")

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
        self.kb_summary_var.set(f"Safe entries: {len(kb['safe'])} | Malware entries: {len(kb['malicious'])}")
        ioc = kb.get("ioc", {})
        ioc_counts = f"IoCs: {len(ioc.get('domains', []))} domains, {len(ioc.get('ips', []))} ips"
        self.ioc_summary_var.set(ioc_counts)
        # Invalidate classifier cache when KB changes
        self.normalizer_cache = None
        # Only update kb_text if it exists (may not be initialized in all contexts)
        if hasattr(self, 'kb_text') and self.kb_text:
            self.kb_text.delete("1.0", tk.END)
            if kb["safe"] or kb["malicious"] or any(ioc.get(key) for key in ("domains", "ips", "hashes")):
                self.kb_text.insert(tk.END, json.dumps(kb, indent=2))
            else:
                self.kb_text.insert(tk.END, "Knowledge base is empty.")

    def _on_tab_changed(self, _event):
        self.sample_note_var.set("")


def main():
    _init_error_logs()
    sys.excepthook = _handle_exception
    if _check_tkinterdnd2():
        DND_FILES, TkinterDnD = _get_tkinterdnd2()
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()
    root.report_callback_exception = _handle_exception
    _set_app_icon(root)
    app = PCAPSentryApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
