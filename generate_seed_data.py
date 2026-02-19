"""
generate_seed_data.py  --  PCAP Sentry offline seed-model builder
================================================================
Run this ONCE at development time (with the venv active) to produce:
  assets/pcap_sentry_seed_data.json     -- compact seed feature rows
  assets/pcap_sentry_baseline_model.pkl -- pre-trained RandomForest
  assets/pcap_sentry_baseline_model.pkl.sha256 -- integrity hash

Usage:
  cd "U:\\PCAP Sentry"
  .venv\\Scripts\\Activate.ps1
  python generate_seed_data.py

The generated files are committed to the repo and bundled by PyInstaller.
On first launch (no user model yet) the app copies the baseline .pkl to
APP_DATA_DIR so analysis works immediately.
Every time the user retrains, the model is rebuilt from seed rows + their
own KB entries together, so accuracy improves over time.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

import numpy as np

# ── Output paths ──────────────────────────────────────────────────────────────
ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
SEED_JSON = os.path.join(ASSETS_DIR, "pcap_sentry_seed_data.json")
MODEL_PKL = os.path.join(ASSETS_DIR, "pcap_sentry_baseline_model.pkl")

RNG = np.random.default_rng(20260219)


# ── Feature-vector helpers ────────────────────────────────────────────────────

MALWARE_PORTS = {
    4444,
    5555,
    6666,
    6667,
    6668,
    6669,
    1337,
    31337,
    12345,
    27374,
    8443,
    8880,
    9001,
    9030,
    9050,
    9150,
    3127,
    3128,
    3389,
    1080,
    1099,
    2222,
    5900,
    5985,
    5986,
    8081,
    8888,
    9999,
}

COMMON_SAFE_PORTS = [80, 443, 53, 25, 587, 993, 143, 22, 21]
COMMON_MAL_PORTS = [4444, 1337, 6667, 9001, 3389, 5900, 1080]


def _row(
    packet_count: float,
    avg_size: float,
    median_size: float,
    dns_query_count: float,
    http_request_count: float,
    unique_http_hosts: float,
    tls_packet_count: float,
    unique_tls_sni: float,
    unique_src: float,
    unique_dst: float,
    malware_port_hits: float,
    flagged_ip_count: float,
    flagged_domain_count: float,
    avg_ip_risk_score: float,
    avg_domain_risk_score: float,
    proto_TCP: float = 0.0,
    proto_UDP: float = 0.0,
    proto_ICMP: float = 0.0,
    proto_ARP: float = 0.0,
    top_ports: list[int] | None = None,
) -> dict[str, float]:
    pkt = max(packet_count, 1.0)
    vec: dict[str, float] = {
        "packet_count": packet_count,
        "avg_size": avg_size,
        "median_size": median_size,
        "dns_query_count": dns_query_count,
        "http_request_count": http_request_count,
        "unique_http_hosts": unique_http_hosts,
        "tls_packet_count": tls_packet_count,
        "unique_tls_sni": unique_tls_sni,
        "unique_src": unique_src,
        "unique_dst": unique_dst,
        "malware_port_hits": malware_port_hits,
        "flagged_ip_count": flagged_ip_count,
        "flagged_domain_count": flagged_domain_count,
        "avg_ip_risk_score": avg_ip_risk_score,
        "avg_domain_risk_score": avg_domain_risk_score,
        "dns_per_packet_ratio": dns_query_count / pkt,
        "proto_TCP": proto_TCP,
        "proto_UDP": proto_UDP,
        "proto_ICMP": proto_ICMP,
        "proto_ARP": proto_ARP,
    }
    for port in top_ports or []:
        vec[f"port_{int(port)}"] = 1.0
    return vec


def _jitter(value: float, low: float, high: float) -> float:
    """Return value * uniform(low, high)."""
    return float(value * RNG.uniform(low, high))


def _ii(lo: float, hi: float) -> float:
    return float(RNG.uniform(lo, hi))


# ── Safe traffic profiles  ────────────────────────────────────────────────────


def _safe_web_browsing(n: int = 15) -> list[dict]:
    rows = []
    for _ in range(n):
        pkts = _ii(2000, 40000)
        rows.append(
            _row(
                packet_count=pkts,
                avg_size=_ii(500, 1200),
                median_size=_ii(400, 1000),
                dns_query_count=_ii(20, 200),
                http_request_count=_ii(10, 150),
                unique_http_hosts=_ii(8, 60),
                tls_packet_count=_ii(300, pkts * 0.6),
                unique_tls_sni=_ii(5, 50),
                unique_src=_ii(1, 4),
                unique_dst=_ii(10, 80),
                malware_port_hits=0.0,
                flagged_ip_count=0.0,
                flagged_domain_count=0.0,
                avg_ip_risk_score=0.0,
                avg_domain_risk_score=0.0,
                proto_TCP=_ii(0.60, 0.82),
                proto_UDP=_ii(0.08, 0.20),
                proto_ICMP=_ii(0.00, 0.02),
                top_ports=[80, 443, 53],
            )
        )
    return rows


def _safe_office_work(n: int = 15) -> list[dict]:
    rows = []
    for _ in range(n):
        pkts = _ii(3000, 30000)
        rows.append(
            _row(
                packet_count=pkts,
                avg_size=_ii(400, 900),
                median_size=_ii(350, 800),
                dns_query_count=_ii(30, 300),
                http_request_count=_ii(5, 80),
                unique_http_hosts=_ii(3, 30),
                tls_packet_count=_ii(500, pkts * 0.55),
                unique_tls_sni=_ii(3, 25),
                unique_src=_ii(1, 8),
                unique_dst=_ii(5, 60),
                malware_port_hits=0.0,
                flagged_ip_count=0.0,
                flagged_domain_count=0.0,
                avg_ip_risk_score=0.0,
                avg_domain_risk_score=0.0,
                proto_TCP=_ii(0.55, 0.80),
                proto_UDP=_ii(0.10, 0.25),
                proto_ICMP=0.0,
                top_ports=[80, 443, 25, 587, 993],
            )
        )
    return rows


def _safe_streaming(n: int = 12) -> list[dict]:
    rows = []
    for _ in range(n):
        pkts = _ii(10000, 100000)
        rows.append(
            _row(
                packet_count=pkts,
                avg_size=_ii(900, 1400),
                median_size=_ii(800, 1380),
                dns_query_count=_ii(5, 50),
                http_request_count=_ii(1, 20),
                unique_http_hosts=_ii(1, 8),
                tls_packet_count=_ii(pkts * 0.60, pkts * 0.90),
                unique_tls_sni=_ii(1, 10),
                unique_src=1.0,
                unique_dst=_ii(1, 6),
                malware_port_hits=0.0,
                flagged_ip_count=0.0,
                flagged_domain_count=0.0,
                avg_ip_risk_score=0.0,
                avg_domain_risk_score=0.0,
                proto_TCP=_ii(0.80, 0.97),
                proto_UDP=_ii(0.02, 0.12),
                proto_ICMP=0.0,
                top_ports=[443],
            )
        )
    return rows


def _safe_file_transfer(n: int = 10) -> list[dict]:
    rows = []
    for _ in range(n):
        pkts = _ii(5000, 50000)
        rows.append(
            _row(
                packet_count=pkts,
                avg_size=_ii(900, 1450),
                median_size=_ii(850, 1450),
                dns_query_count=_ii(2, 30),
                http_request_count=_ii(0, 10),
                unique_http_hosts=_ii(0, 4),
                tls_packet_count=_ii(pkts * 0.3, pkts * 0.7),
                unique_tls_sni=_ii(0, 5),
                unique_src=_ii(1, 3),
                unique_dst=_ii(1, 5),
                malware_port_hits=0.0,
                flagged_ip_count=0.0,
                flagged_domain_count=0.0,
                avg_ip_risk_score=0.0,
                avg_domain_risk_score=0.0,
                proto_TCP=_ii(0.75, 0.98),
                proto_UDP=_ii(0.01, 0.10),
                proto_ICMP=0.0,
                top_ports=[21, 22, 443],
            )
        )
    return rows


def _safe_voip(n: int = 10) -> list[dict]:
    rows = []
    for _ in range(n):
        pkts = _ii(5000, 80000)
        rows.append(
            _row(
                packet_count=pkts,
                avg_size=_ii(60, 250),
                median_size=_ii(60, 200),
                dns_query_count=_ii(5, 50),
                http_request_count=_ii(0, 10),
                unique_http_hosts=_ii(0, 5),
                tls_packet_count=_ii(0, pkts * 0.2),
                unique_tls_sni=_ii(0, 5),
                unique_src=_ii(1, 4),
                unique_dst=_ii(1, 10),
                malware_port_hits=0.0,
                flagged_ip_count=0.0,
                flagged_domain_count=0.0,
                avg_ip_risk_score=0.0,
                avg_domain_risk_score=0.0,
                proto_TCP=_ii(0.20, 0.45),
                proto_UDP=_ii(0.50, 0.78),
                proto_ICMP=_ii(0.00, 0.02),
                top_ports=[5060, 443, 80],
            )
        )
    return rows


# ── Malicious traffic profiles ────────────────────────────────────────────────


def _mal_port_scan(n: int = 12) -> list[dict]:
    rows = []
    for _ in range(n):
        pkts = _ii(8000, 300000)
        rows.append(
            _row(
                packet_count=pkts,
                avg_size=_ii(40, 80),
                median_size=_ii(40, 64),
                dns_query_count=_ii(0, 5),
                http_request_count=_ii(0, 3),
                unique_http_hosts=_ii(0, 2),
                tls_packet_count=0.0,
                unique_tls_sni=0.0,
                unique_src=_ii(1, 3),
                unique_dst=_ii(50, 65535),
                malware_port_hits=float(int(_ii(5, 18))),
                flagged_ip_count=0.0,
                flagged_domain_count=0.0,
                avg_ip_risk_score=0.0,
                avg_domain_risk_score=0.0,
                proto_TCP=_ii(0.88, 1.00),
                proto_UDP=_ii(0.00, 0.08),
                proto_ICMP=_ii(0.00, 0.05),
                top_ports=[22, 23, 80, 443, 445, 3389, 8080, 4444],
            )
        )
    return rows


def _mal_ddos(n: int = 10) -> list[dict]:
    rows = []
    for _ in range(n):
        pkts = _ii(50000, 600000)
        rows.append(
            _row(
                packet_count=pkts,
                avg_size=_ii(64, 1500),
                median_size=_ii(64, 600),
                dns_query_count=_ii(0, 20),
                http_request_count=_ii(0, 100),
                unique_http_hosts=_ii(0, 5),
                tls_packet_count=0.0,
                unique_tls_sni=0.0,
                unique_src=_ii(100, 10000),
                unique_dst=_ii(1, 4),
                malware_port_hits=0.0,
                flagged_ip_count=float(int(_ii(2, 20))),
                flagged_domain_count=0.0,
                avg_ip_risk_score=_ii(40, 90),
                avg_domain_risk_score=0.0,
                proto_TCP=_ii(0.40, 0.70),
                proto_UDP=_ii(0.25, 0.55),
                proto_ICMP=_ii(0.00, 0.30),
                top_ports=[80, 443, 53],
            )
        )
    return rows


def _mal_c2_beacon(n: int = 12) -> list[dict]:
    rows = []
    for _ in range(n):
        pkts = _ii(300, 6000)
        rows.append(
            _row(
                packet_count=pkts,
                avg_size=_ii(150, 600),
                median_size=_ii(140, 580),
                dns_query_count=_ii(1, 20),
                http_request_count=_ii(0, 10),
                unique_http_hosts=_ii(0, 2),
                tls_packet_count=_ii(pkts * 0.3, pkts * 0.8),
                unique_tls_sni=_ii(0, 2),
                unique_src=1.0,
                unique_dst=_ii(1, 3),
                malware_port_hits=float(int(_ii(1, 4))),
                flagged_ip_count=float(int(_ii(1, 3))),
                flagged_domain_count=0.0,
                avg_ip_risk_score=_ii(60, 95),
                avg_domain_risk_score=0.0,
                proto_TCP=_ii(0.70, 0.98),
                proto_UDP=_ii(0.01, 0.10),
                proto_ICMP=0.0,
                top_ports=[4444, 1337, 9001, 8443],
            )
        )
    return rows


def _mal_dns_tunneling(n: int = 10) -> list[dict]:
    rows = []
    for _ in range(n):
        pkts = _ii(2000, 20000)
        dns = _ii(pkts * 0.35, pkts * 0.75)
        rows.append(
            _row(
                packet_count=pkts,
                avg_size=_ii(200, 500),
                median_size=_ii(150, 450),
                dns_query_count=dns,
                http_request_count=_ii(0, 5),
                unique_http_hosts=_ii(0, 2),
                tls_packet_count=_ii(0, pkts * 0.05),
                unique_tls_sni=0.0,
                unique_src=_ii(1, 3),
                unique_dst=_ii(1, 4),
                malware_port_hits=0.0,
                flagged_ip_count=0.0,
                flagged_domain_count=float(int(_ii(1, 5))),
                avg_ip_risk_score=0.0,
                avg_domain_risk_score=_ii(50, 85),
                proto_TCP=_ii(0.10, 0.30),
                proto_UDP=_ii(0.65, 0.88),
                proto_ICMP=0.0,
                top_ports=[53],
            )
        )
    return rows


def _mal_ransomware_smb(n: int = 10) -> list[dict]:
    rows = []
    for _ in range(n):
        pkts = _ii(5000, 80000)
        rows.append(
            _row(
                packet_count=pkts,
                avg_size=_ii(300, 1400),
                median_size=_ii(250, 1200),
                dns_query_count=_ii(0, 30),
                http_request_count=_ii(0, 5),
                unique_http_hosts=0.0,
                tls_packet_count=0.0,
                unique_tls_sni=0.0,
                unique_src=_ii(1, 5),
                unique_dst=_ii(10, 500),
                malware_port_hits=float(int(_ii(2, 6))),
                flagged_ip_count=0.0,
                flagged_domain_count=0.0,
                avg_ip_risk_score=0.0,
                avg_domain_risk_score=0.0,
                proto_TCP=_ii(0.80, 1.00),
                proto_UDP=_ii(0.00, 0.08),
                proto_ICMP=_ii(0.00, 0.05),
                top_ports=[445, 139, 3389],
            )
        )
    return rows


def _mal_brute_force_ssh(n: int = 10) -> list[dict]:
    rows = []
    for _ in range(n):
        pkts = _ii(10000, 150000)
        rows.append(
            _row(
                packet_count=pkts,
                avg_size=_ii(60, 200),
                median_size=_ii(60, 180),
                dns_query_count=_ii(0, 10),
                http_request_count=0.0,
                unique_http_hosts=0.0,
                tls_packet_count=_ii(0, pkts * 0.1),
                unique_tls_sni=0.0,
                unique_src=_ii(1, 5),
                unique_dst=_ii(1, 10),
                malware_port_hits=float(int(_ii(1, 3))),
                flagged_ip_count=float(int(_ii(0, 3))),
                flagged_domain_count=0.0,
                avg_ip_risk_score=_ii(0, 60),
                avg_domain_risk_score=0.0,
                proto_TCP=_ii(0.90, 1.00),
                proto_UDP=0.0,
                proto_ICMP=0.0,
                top_ports=[22, 2222],
            )
        )
    return rows


def _mal_malware_dropper(n: int = 10) -> list[dict]:
    rows = []
    for _ in range(n):
        pkts = _ii(200, 5000)
        rows.append(
            _row(
                packet_count=pkts,
                avg_size=_ii(700, 1450),
                median_size=_ii(600, 1450),
                dns_query_count=_ii(1, 15),
                http_request_count=_ii(1, 8),
                unique_http_hosts=_ii(1, 4),
                tls_packet_count=_ii(0, pkts * 0.3),
                unique_tls_sni=_ii(0, 3),
                unique_src=1.0,
                unique_dst=_ii(1, 4),
                malware_port_hits=float(int(_ii(1, 4))),
                flagged_ip_count=float(int(_ii(1, 4))),
                flagged_domain_count=float(int(_ii(0, 3))),
                avg_ip_risk_score=_ii(50, 95),
                avg_domain_risk_score=_ii(0, 80),
                proto_TCP=_ii(0.80, 1.00),
                proto_UDP=_ii(0.00, 0.10),
                proto_ICMP=0.0,
                top_ports=[80, 443, 8080, 8888],
            )
        )
    return rows


def _mal_data_exfil(n: int = 10) -> list[dict]:
    rows = []
    for _ in range(n):
        pkts = _ii(1000, 30000)
        rows.append(
            _row(
                packet_count=pkts,
                avg_size=_ii(800, 1450),
                median_size=_ii(750, 1450),
                dns_query_count=_ii(0, 10),
                http_request_count=_ii(0, 20),
                unique_http_hosts=_ii(0, 2),
                tls_packet_count=_ii(pkts * 0.5, pkts * 0.9),
                unique_tls_sni=_ii(0, 2),
                unique_src=1.0,
                unique_dst=_ii(1, 3),
                malware_port_hits=float(int(_ii(0, 3))),
                flagged_ip_count=float(int(_ii(0, 3))),
                flagged_domain_count=0.0,
                avg_ip_risk_score=_ii(0, 70),
                avg_domain_risk_score=0.0,
                proto_TCP=_ii(0.75, 1.00),
                proto_UDP=_ii(0.00, 0.10),
                proto_ICMP=0.0,
                top_ports=[443, 8443, 9001, 5985],
            )
        )
    return rows


# ── Build dataset ─────────────────────────────────────────────────────────────


def build_dataset() -> tuple[list[dict], list[str]]:
    safe_rows = (
        _safe_web_browsing(15) + _safe_office_work(15) + _safe_streaming(12) + _safe_file_transfer(10) + _safe_voip(10)
    )
    mal_rows = (
        _mal_port_scan(12)
        + _mal_ddos(10)
        + _mal_c2_beacon(12)
        + _mal_dns_tunneling(10)
        + _mal_ransomware_smb(10)
        + _mal_brute_force_ssh(10)
        + _mal_malware_dropper(10)
        + _mal_data_exfil(10)
    )
    rows = safe_rows + mal_rows
    labels = ["safe"] * len(safe_rows) + ["malicious"] * len(mal_rows)
    print(f"  Safe: {len(safe_rows)}  |  Malicious: {len(mal_rows)}  |  Total: {len(rows)}")
    return rows, labels


# ── Train & save ──────────────────────────────────────────────────────────────


def train_and_save(rows: list[dict], labels: list[str]) -> None:
    from joblib import dump as joblib_dump
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_extraction import DictVectorizer

    os.makedirs(ASSETS_DIR, exist_ok=True)

    # Save seed data JSON
    seed_data = [{"features": r, "label": lbl} for r, lbl in zip(rows, labels)]
    with open(SEED_JSON, "w", encoding="utf-8") as f:
        json.dump(seed_data, f, separators=(",", ":"))
    print(f"  Seed data → {SEED_JSON}  ({os.path.getsize(SEED_JSON) // 1024} KB)")

    # Train
    vectorizer = DictVectorizer(sparse=True)
    X = vectorizer.fit_transform(rows)
    clf = RandomForestClassifier(
        n_estimators=120,
        max_depth=14,
        class_weight="balanced",
        random_state=20260219,
        n_jobs=-1,
    )
    clf.fit(X, labels)

    bundle = {"model": clf, "vectorizer": vectorizer, "backend": "cpu", "source": "seed"}
    joblib_dump(bundle, MODEL_PKL)

    # SHA-256 integrity hash (not HMAC — the per-machine HMAC is added at load time)
    sha = hashlib.sha256()
    with open(MODEL_PKL, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha.update(chunk)
    with open(MODEL_PKL + ".sha256", "w", encoding="utf-8") as f:
        f.write(sha.hexdigest())

    size_kb = os.path.getsize(MODEL_PKL) // 1024
    print(f"  Baseline model → {MODEL_PKL}  ({size_kb} KB)")
    print(f"  SHA-256 → {sha.hexdigest()[:16]}…")


# ── Quick self-test ───────────────────────────────────────────────────────────


def self_test(rows: list[dict], labels: list[str]) -> None:
    from joblib import load as joblib_load

    bundle = joblib_load(MODEL_PKL)
    vect = bundle["vectorizer"]
    clf = bundle["model"]

    correct = 0
    for row, true_label in zip(rows, labels):
        pred = clf.predict(vect.transform([row]))[0]
        if pred == true_label:
            correct += 1
    acc = correct / len(labels) * 100
    print(f"  Training-set accuracy (sanity check): {acc:.1f}%  ({correct}/{len(labels)})")
    if acc < 85:
        print("  WARNING: accuracy below 85% — check feature profiles")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n[1/3] Building seed dataset…")
    rows, labels = build_dataset()

    print("[2/3] Training RandomForest and saving assets…")
    train_and_save(rows, labels)

    print("[3/3] Self-test…")
    self_test(rows, labels)

    print("\nDone. Commit assets/ and rebuild the installer.\n")
