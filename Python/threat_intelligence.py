#!/usr/bin/env python3
# PCAP Sentry - Malware Analysis and Education Console for Network Packet Captures
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

"""
Threat Intelligence Integration Module for PCAP Sentry

Integrates with free/public threat intelligence sources:
- AlienVault OTX (Open Threat Exchange)
- AbuseIPDB (free tier)
- URLhaus
- Public DNS blacklists
"""

import json
import re
import time
from typing import Dict, List, Optional
import ipaddress
import threading
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Timeouts (connect, read) in seconds
_CONNECT_TIMEOUT = 2.0
_READ_TIMEOUT = 3.0
_REQUEST_TIMEOUT = (_CONNECT_TIMEOUT, _READ_TIMEOUT)

# Max concurrent network requests
_MAX_WORKERS = 6

# Maximum response size from external APIs (2 MB)
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class ThreatIntelligence:
    """Threat intelligence checker using free/public APIs"""

    def __init__(self, otx_api_key: Optional[str] = None):
        self.otx_base_url = "https://otx.alienvault.com/api/v1"
        self.otx_api_key = otx_api_key
        self.abuseipdb_base_url = "https://api.abuseipdb.com/api/v2"
        self.urlhaus_base_url = "https://urlhaus-api.abuse.ch/v1"
        self._cache = {}  # Thread-safe cache to avoid repeated lookups
        self._cache_lock = threading.Lock()
        self.cache_ttl = 3600  # 1 hour
        self._max_cache_size = 500
        # Reusable HTTP session for connection pooling (keep-alive)
        self._session: Optional[requests.Session] = None
        self._session_lock = threading.Lock()

    def _get_session(self) -> "requests.Session":
        """Lazy-init a shared session for connection pooling."""
        if self._session is None:
            with self._session_lock:
                if self._session is None:
                    s = requests.Session()
                    s.headers.update({"Accept": "application/json"})
                    # Allow connection reuse across hosts
                    adapter = requests.adapters.HTTPAdapter(
                        pool_connections=8, pool_maxsize=12, max_retries=0,
                    )
                    s.mount("https://", adapter)
                    # Block http:// to prevent accidental plaintext requests
                    # or redirect downgrades from HTTPS → HTTP.
                    class _BlockHTTPAdapter(requests.adapters.HTTPAdapter):
                        def send(self, *args, **kwargs):
                            raise ConnectionError(
                                "HTTP requests are blocked; use HTTPS only."
                            )
                    s.mount("http://", _BlockHTTPAdapter())
                    self._session = s
        return self._session

    def is_available(self) -> bool:
        """Check if threat intelligence is available"""
        return REQUESTS_AVAILABLE

    def check_ip_reputation(self, ip: str) -> Dict:
        """
        Check IP reputation using free public sources.
        Skips private/reserved IPs automatically.
        Returns dict with reputation data.
        """
        if not self.is_available():
            return {"available": False}

        if not self._is_routable_ip(ip):
            return {"valid": False}

        # Check cache first
        cache_key = f"ip:{ip}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        result = {
            "valid": True,
            "ip": ip,
            "sources": {}
        }

        # Run OTX and AbuseIPDB checks concurrently
        with ThreadPoolExecutor(max_workers=2) as pool:
            f_otx = pool.submit(self._check_otx_ip, ip)
            f_abuse = pool.submit(self._check_abuseipdb_ip, ip)

        otx_data = f_otx.result()
        if otx_data:
            result["sources"]["otx"] = otx_data
        abuse_data = f_abuse.result()
        if abuse_data:
            result["sources"]["abuseipdb"] = abuse_data

        # Calculate overall risk score
        result["risk_score"] = self._calculate_ip_risk(result["sources"])

        # Cache the result
        self._cache_put(cache_key, result)
        return result

    def _cache_get(self, key: str):
        """Thread-safe cache read with TTL expiry."""
        with self._cache_lock:
            if key in self._cache:
                data, timestamp = self._cache[key]
                if time.time() - timestamp < self.cache_ttl:
                    return data
                del self._cache[key]
        return None

    def _cache_put(self, key: str, value):
        """Thread-safe cache write with size eviction."""
        now = time.time()
        with self._cache_lock:
            # Evict expired entries if cache is at capacity
            if len(self._cache) >= self._max_cache_size:
                expired = [k for k, (_, ts) in self._cache.items() if now - ts >= self.cache_ttl]
                for k in expired:
                    del self._cache[k]
                # If still full, remove oldest entry
                if len(self._cache) >= self._max_cache_size:
                    oldest_key = min(self._cache, key=lambda k: self._cache[k][1])
                    del self._cache[oldest_key]
            self._cache[key] = (value, now)

    def _safe_json(self, response) -> dict:
        """Parse JSON from a requests response with a size limit to prevent OOM."""
        content_length = response.headers.get("Content-Length")
        if content_length and int(content_length) > _MAX_RESPONSE_BYTES:
            raise RuntimeError(f"Response too large: {content_length} bytes")
        raw = response.content
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise RuntimeError(f"Response too large: {len(raw)} bytes")
        return response.json()

    def check_domain_reputation(self, domain: str) -> Dict:
        """
        Check domain reputation using free public sources
        """
        if not self.is_available():
            return {"available": False}

        # Basic domain validation
        if not domain or len(domain) > 253 or not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.\-]*\.[a-zA-Z]{2,}$', domain):
            return {"valid": False}
        # Enforce per-label max length (RFC 1035)
        if any(len(label) > 63 for label in domain.split(".")):
            return {"valid": False}

        cache_key = f"domain:{domain}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        result = {
            "domain": domain,
            "sources": {}
        }

        # Run OTX and URLhaus checks concurrently
        with ThreadPoolExecutor(max_workers=2) as pool:
            f_otx = pool.submit(self._check_otx_domain, domain)
            f_url = pool.submit(self._check_urlhaus, domain)

        otx_data = f_otx.result()
        if otx_data:
            result["sources"]["otx"] = otx_data
        url_data = f_url.result()
        if url_data:
            result["sources"]["urlhaus"] = url_data

        # Calculate overall risk score
        result["risk_score"] = self._calculate_domain_risk(result["sources"])

        self._cache_put(cache_key, result)
        return result

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _is_routable_ip(self, ip: str) -> bool:
        """Check that IP is a valid, globally-routable address worth querying."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        # Skip private, loopback, link-local, multicast, reserved, etc.
        return addr.is_global

    def _check_otx_ip(self, ip: str) -> Optional[Dict]:
        """Check IP against AlienVault OTX (free, API key optional for enhanced data)"""
        try:
            safe_ip = urllib.parse.quote(ip, safe='')
            url = f"{self.otx_base_url}/indicators/IPv4/{safe_ip}/general"
            headers = {}
            if self.otx_api_key:
                headers["X-OTX-API-KEY"] = self.otx_api_key
            
            response = self._get_session().get(url, headers=headers, timeout=_REQUEST_TIMEOUT)

            if response.status_code == 200:
                data = self._safe_json(response)
                result = {}
                
                # Basic reputation data
                if data.get("reputation"):
                    result["reputation"] = data["reputation"]
                
                # Pulse count and tags
                if data.get("pulse_info"):
                    pulse_info = data["pulse_info"]
                    result["pulse_count"] = pulse_info.get("count", 0)
                    
                    # With API key, get detailed pulse information
                    if self.otx_api_key and pulse_info.get("pulses"):
                        pulses = pulse_info["pulses"][:3]  # Top 3 pulses
                        result["pulses"] = [{
                            "name": p.get("name"),
                            "tags": p.get("tags", [])[:5],  # Top 5 tags
                            "malware_families": p.get("malware_families", [])[:3],
                            "attack_ids": p.get("attack_ids", [])[:3]
                        } for p in pulses]
                
                # Additional metadata
                if data.get("alexa"):
                    result["alexa_rank"] = data["alexa"]
                if data.get("country_name"):
                    result["country"] = data["country_name"]
                
                return result if result else None
            return None
        except Exception as e:
            print(f"[DEBUG] OTX IP check failed: {e}")
            return None

    def _check_otx_domain(self, domain: str) -> Optional[Dict]:
        """Check domain against AlienVault OTX (API key optional for enhanced data)"""
        try:
            safe_domain = urllib.parse.quote(domain, safe='')
            url = f"{self.otx_base_url}/indicators/domain/{safe_domain}/general"
            headers = {}
            if self.otx_api_key:
                headers["X-OTX-API-KEY"] = self.otx_api_key
            
            response = self._get_session().get(url, headers=headers, timeout=_REQUEST_TIMEOUT)

            if response.status_code == 200:
                data = self._safe_json(response)
                result = {}
                
                # Basic reputation data
                if data.get("reputation"):
                    result["reputation"] = data["reputation"]
                
                # Pulse count and tags
                if data.get("pulse_info"):
                    pulse_info = data["pulse_info"]
                    result["pulse_count"] = pulse_info.get("count", 0)
                    
                    # With API key, get detailed pulse information
                    if self.otx_api_key and pulse_info.get("pulses"):
                        pulses = pulse_info["pulses"][:3]  # Top 3 pulses
                        result["pulses"] = [{
                            "name": p.get("name"),
                            "tags": p.get("tags", [])[:5],
                            "malware_families": p.get("malware_families", [])[:3]
                        } for p in pulses]
                
                # Additional metadata
                if data.get("alexa"):
                    result["alexa_rank"] = data["alexa"]
                if data.get("whois"):
                    result["whois"] = data["whois"]
                
                return result if result else None
            return None
        except Exception as e:
            print(f"[DEBUG] OTX domain check failed: {e}")
            return None

    def _check_abuseipdb_ip(self, ip: str) -> Optional[Dict]:
        """
        Check IP against AbuseIPDB (free tier, limited requests).
        Note: Requires API key – returns None when no key is configured.
        """
        # This endpoint requires an API key; skip for truly free access.
        return None

    def _check_urlhaus(self, domain: str) -> Optional[Dict]:
        """Check domain against URLhaus malware URL database"""
        try:
            url = f"{self.urlhaus_base_url}/host/"
            data = {"host": domain}
            response = self._get_session().post(url, data=data, timeout=_REQUEST_TIMEOUT)

            if response.status_code == 200:
                result = self._safe_json(response)
                if result.get("query_status") == "ok" and result.get("urls"):
                    return {
                        "found": True,
                        "url_count": len(result["urls"]),
                        "urls": [{"url": u["url"], "threat": u.get("threat")} for u in result["urls"][:5]]
                    }
                elif result.get("query_status") == "ok":
                    return {"found": False}
            return None
        except Exception as e:
            print(f"[DEBUG] URLhaus check failed: {e}")
            return None

    def _calculate_ip_risk(self, sources: Dict) -> float:
        """Calculate overall IP risk score (0-100)"""
        risk_score = 0.0

        if "otx" in sources:
            otx_rep = sources["otx"].get("reputation", 0)
            # OTX reputation may be a dict or numeric
            if isinstance(otx_rep, dict):
                otx_rep = otx_rep.get("threat_score", 0) or 0
            if otx_rep:
                risk_score += min(float(otx_rep) * 10, 100.0)

        if "abuseipdb" in sources:
            abuse_rep = sources["abuseipdb"].get("reputation", 0)
            if isinstance(abuse_rep, (int, float)):
                risk_score += abuse_rep

        # Cap at 100
        return min(100.0, risk_score)

    def _calculate_domain_risk(self, sources: Dict) -> float:
        """Calculate overall domain risk score (0-100)"""
        risk_score = 0.0

        if "otx" in sources:
            otx_rep = sources["otx"].get("reputation", 0)
            if isinstance(otx_rep, dict):
                otx_rep = otx_rep.get("threat_score", 0) or 0
            if otx_rep:
                risk_score += min(float(otx_rep) * 10, 100.0)

        if "urlhaus" in sources and sources["urlhaus"].get("found"):
            risk_score += 75  # High risk if found in URLhaus

        return min(100.0, risk_score)

    def enrich_stats(self, stats: Dict, progress_cb=None) -> Dict:
        """
        Enrich analysis statistics with threat intelligence.
        progress_cb(fraction) is called with 0.0-1.0 to report progress.

        All IP and domain lookups run concurrently for speed.
        Private/bogon IPs are automatically skipped.
        """
        if not self.is_available():
            return stats

        enriched = stats.copy()
        enriched["threat_intel"] = {}

        t0 = time.time()

        # ── Collect work items ──
        all_ips = set(stats.get("unique_src_list", []))
        all_ips.update(stats.get("unique_dst_list", []))
        # Pre-filter: skip private/bogon IPs before submitting work
        ip_list = [ip for ip in list(all_ips)[:20] if self._is_routable_ip(ip)]

        domains: set = set()
        domains.update(stats.get("dns_queries", []))
        domains.update(stats.get("http_hosts", []))
        domains.update(stats.get("tls_sni", []))
        domain_list = list(domains)[:20]

        total_items = len(ip_list) + len(domain_list)
        if total_items == 0:
            if progress_cb:
                progress_cb(1.0)
            return enriched

        completed = 0
        progress_lock = threading.Lock()

        def _advance_progress():
            nonlocal completed
            with progress_lock:
                completed += 1
                if progress_cb and total_items:
                    progress_cb(completed / total_items)

        # ── Concurrent lookups ──
        ip_risks: List[Dict] = []
        domain_risks: List[Dict] = []
        results_lock = threading.Lock()

        def _check_ip(ip):
            try:
                rep = self.check_ip_reputation(ip)
                if rep.get("risk_score", 0) > 30:
                    with results_lock:
                        ip_risks.append({
                            "ip": ip,
                            "risk_score": rep["risk_score"],
                            "sources": rep["sources"],
                        })
            except Exception as e:
                print(f"[DEBUG] Error enriching IP {ip}: {e}")
            finally:
                _advance_progress()

        def _check_domain(domain):
            try:
                rep = self.check_domain_reputation(domain)
                if rep.get("risk_score", 0) > 30:
                    with results_lock:
                        domain_risks.append({
                            "domain": domain,
                            "risk_score": rep["risk_score"],
                            "sources": rep["sources"],
                        })
            except Exception as e:
                print(f"[DEBUG] Error enriching domain {domain}: {e}")
            finally:
                _advance_progress()

        workers = min(_MAX_WORKERS, total_items)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = []
            for ip in ip_list:
                futures.append(pool.submit(_check_ip, ip))
            for domain in domain_list:
                futures.append(pool.submit(_check_domain, domain))
            # Wait for all to finish
            for f in as_completed(futures):
                pass  # exceptions already handled inside workers

        if ip_risks:
            enriched["threat_intel"]["risky_ips"] = sorted(
                ip_risks, key=lambda x: x["risk_score"], reverse=True,
            )
        if domain_risks:
            enriched["threat_intel"]["risky_domains"] = sorted(
                domain_risks, key=lambda x: x["risk_score"], reverse=True,
            )

        elapsed = time.time() - t0
        print(f"[TIMING] Threat intel enrichment: {elapsed:.2f}s "
              f"({len(ip_list)} IPs, {len(domain_list)} domains, "
              f"{workers} workers)")

        return enriched


def check_online_reputation(ip: str = None, domain: str = None) -> Dict:
    """
    Convenience function to check reputation of IP or domain
    """
    ti = ThreatIntelligence()
    result = {}

    if ip:
        result["ip"] = ti.check_ip_reputation(ip)
    if domain:
        result["domain"] = ti.check_domain_reputation(domain)

    return result


if __name__ == "__main__":
    # Test the module
    if REQUESTS_AVAILABLE:
        ti = ThreatIntelligence()

        # Test IP check
        print("Testing IP reputation check...")
        ip_result = ti.check_ip_reputation("8.8.8.8")
        print(json.dumps(ip_result, indent=2))

        # Test domain check
        print("\nTesting domain reputation check...")
        domain_result = ti.check_domain_reputation("google.com")
        print(json.dumps(domain_result, indent=2))
    else:
        print("requests library not available. Install with: pip install requests")
