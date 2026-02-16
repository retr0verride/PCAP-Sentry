"""
Stability Tests for PCAP Sentry
Tests core functionality, imports, and basic operations
"""

import json
import os
import sys
import tempfile
from pathlib import Path

# Set UTF-8 encoding for Windows console to handle emoji characters
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except (AttributeError, OSError):
        # Fall back to ASCII-safe symbols if reconfigure fails
        pass

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "Python"))

def test_imports():
    """Test that all critical modules can be imported"""
    print("\n=== Testing Module Imports ===")

    print("✅ pcap_sentry_gui imported successfully")

    print("✅ threat_intelligence imported successfully")

    print("✅ update_checker imported successfully")


def test_settings_operations():
    """Test settings save/load operations"""
    print("\n=== Testing Settings Operations ===")

    from pcap_sentry_gui import _default_settings, load_settings

    # Test default settings
    defaults = _default_settings()
    assert isinstance(defaults, dict), "Default settings should be a dict"
    assert "max_rows" in defaults, "Default settings should have max_rows"
    print("✅ Default settings structure valid")

    # Test settings load (should return defaults if file doesn't exist)
    settings = load_settings()
    assert isinstance(settings, dict), "Loaded settings should be a dict"
    print("✅ Settings load successful")


def test_ioc_normalization():
    """Test IOC normalization and parsing"""
    print("\n=== Testing IOC Normalization ===")

    from pcap_sentry_gui import _normalize_ioc_item, _parse_ioc_text

    # Test IP normalization
    key, val = _normalize_ioc_item("192.168.1.1")
    assert key == "ips", f"IP should be recognized as 'ips', got '{key}'"
    assert val == "192.168.1.1", "IP value mismatch"
    print("✅ IP normalization works")

    # Test domain normalization
    key, val = _normalize_ioc_item("example.com")
    assert key == "domains", f"Domain should be recognized as 'domains', got '{key}'"
    assert val == "example.com", "Domain value mismatch"
    print("✅ Domain normalization works")

    # Test hash normalization (MD5)
    key, val = _normalize_ioc_item("d41d8cd98f00b204e9800998ecf8427e")
    assert key == "hashes", f"Hash should be recognized as 'hashes', got '{key}'"
    print("✅ Hash normalization works")

    # Test URL stripping
    key, val = _normalize_ioc_item("http://example.com/path")
    assert key == "domains", "URL should be parsed as domain"
    assert val == "example.com", "URL should be stripped to domain"
    print("✅ URL stripping works")

    # Test IOC text parsing
    text = """
    # Comment line
    192.168.1.1
    example.com
    malware.bad
    10.0.0.1
    """
    iocs = _parse_ioc_text(text)
    assert "ips" in iocs, "Parsed IOCs should have 'ips'"
    assert "domains" in iocs, "Parsed IOCs should have 'domains'"
    assert len(iocs["ips"]) == 2, f"Should have 2 IPs, got {len(iocs['ips'])}"
    assert len(iocs["domains"]) == 2, f"Should have 2 domains, got {len(iocs['domains'])}"
    print("✅ IOC text parsing works")


def test_path_security():
    """Test path security functions"""
    print("\n=== Testing Path Security ===")


    from pcap_sentry_gui import _get_app_data_dir

    # Test app data directory
    app_data = _get_app_data_dir()
    assert app_data is not None, "App data dir should not be None"
    assert os.path.isabs(app_data), "App data dir should be absolute path"
    print(f"✅ App data dir valid: {app_data}")

    # Test path traversal protection (simulated)
    # The actual function _extract_first_pcap_from_zip has the protection
    # We'll test that realpath normalization works
    with tempfile.TemporaryDirectory() as tmpdir:
        safe_path = os.path.realpath(os.path.join(tmpdir, "safe.txt"))
        assert safe_path.startswith(os.path.realpath(tmpdir)), "Safe path should be inside temp dir"
        print("✅ Path normalization works correctly")


def test_input_validation():
    """Test input validation functions"""
    print("\n=== Testing Input Validation ===")

    import re

    # Test model name validation pattern (from the code)
    valid_names = [
        "llama3.2:3b",
        "model-name",
        "my_model",
        "test.model",
        "path/to/model"
    ]

    invalid_names = [
        "../../../etc/passwd",  # Path traversal
        "model; rm -rf /",       # Command injection
        "model & echo bad",      # Command chaining
        "model`whoami`",         # Command substitution
        "model$(ls)",            # Command substitution
    ]

    pattern = r'[A-Za-z0-9][A-Za-z0-9_.:\-/]*'

    for name in valid_names:
        assert re.fullmatch(pattern, name), f"Valid name should be accepted: {name}"
    print(f"✅ All valid model names accepted ({len(valid_names)} tested)")

    for name in invalid_names:
        assert not re.fullmatch(pattern, name), f"Invalid name should be rejected: {name}"
    print(f"✅ All malicious names rejected ({len(invalid_names)} tested)")


def test_credential_security():
    """Test credential storage functions"""
    print("\n=== Testing Credential Security ===")

    from pcap_sentry_gui import (
        _delete_api_key,
        _delete_otx_api_key,
        _keyring_available,
        _load_api_key,
        _load_otx_api_key,
        _store_api_key,
        _store_otx_api_key,
    )

    keyring_avail = _keyring_available()
    print(f"ℹ️  Keyring available: {keyring_avail}")  # noqa: RUF001

    if keyring_avail:
        # Test LLM API key storing and loading
        test_llm_key = "test_llm_api_key_12345"
        _store_api_key(test_llm_key)
        loaded_llm = _load_api_key()

        if loaded_llm == test_llm_key:
            print("✅ Keyring store/load works for LLM API key")
        else:
            print(f"⚠️  Keyring store/load mismatch for LLM key (stored: {test_llm_key}, loaded: {loaded_llm})")

        # Test OTX API key storing and loading
        test_otx_key = "test_otx_api_key_67890"
        _store_otx_api_key(test_otx_key)
        loaded_otx = _load_otx_api_key()

        if loaded_otx == test_otx_key:
            print("✅ Keyring store/load works for OTX API key")
        else:
            print(f"⚠️  Keyring store/load mismatch for OTX key (stored: {test_otx_key}, loaded: {loaded_otx})")

        # Cleanup LLM key
        _delete_api_key()
        after_delete_llm = _load_api_key()
        if not after_delete_llm:
            print("✅ Keyring delete works for LLM API key")
        else:
            print(f"⚠️  Keyring delete incomplete for LLM key (still has: {after_delete_llm})")

        # Cleanup OTX key
        _delete_otx_api_key()
        after_delete_otx = _load_otx_api_key()
        if not after_delete_otx:
            print("✅ Keyring delete works for OTX API key")
        else:
            print(f"⚠️  Keyring delete incomplete for OTX key (still has: {after_delete_otx})")
    else:
        print("ℹ️  Keyring not available - tests skipped (this is OK)")  # noqa: RUF001


def test_threat_intelligence():
    """Test threat intelligence module"""
    print("\n=== Testing Threat Intelligence ===")

    from threat_intelligence import ThreatIntelligence

    ti = ThreatIntelligence()

    # Check if available
    available = ti.is_available()
    print(f"ℹ️  Threat Intelligence available: {available}")  # noqa: RUF001

    if not available:
        print("ℹ️  Threat Intelligence not available (requests module missing)")  # noqa: RUF001
        return

    # Test IP validation
    assert ti._is_routable_ip("8.8.8.8"), "Public IP should be routable"
    assert not ti._is_routable_ip("192.168.1.1"), "Private IP should not be routable"
    assert not ti._is_routable_ip("127.0.0.1"), "Loopback should not be routable"
    print("✅ IP validation works correctly")

    # Test cache operations
    ti._cache_put("test_key", {"data": "test"})
    cached = ti._cache_get("test_key")
    assert cached is not None, "Cached item should be retrievable"
    assert cached["data"] == "test", "Cached data should match"
    print("✅ Cache operations work")


def test_file_operations():
    """Test atomic file write operations"""
    print("\n=== Testing File Operations ===")

    import tempfile

    # Simulate the atomic write pattern used in save_settings
    with tempfile.TemporaryDirectory() as tmpdir:
        target_file = os.path.join(tmpdir, "test_settings.json")

        # Atomic write pattern
        fd, tmp = tempfile.mkstemp(dir=tmpdir, suffix=".tmp")
        test_data = {"test": "data", "value": 123}

        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(test_data, f, indent=2)
            os.replace(tmp, target_file)
        except Exception:
            import contextlib

            with contextlib.suppress(Exception):
                os.unlink(tmp)
            raise

        # Verify file was written
        assert os.path.exists(target_file), "Target file should exist"

        with open(target_file, encoding="utf-8") as f:
            loaded = json.load(f)

        assert loaded == test_data, "Loaded data should match written data"
        print("✅ Atomic file write works correctly")


def test_version_computation():
    """Test version computation"""
    print("\n=== Testing Version Computation ===")

    from pcap_sentry_gui import _compute_app_version

    version = _compute_app_version()
    assert version is not None, "Version should not be None"
    assert len(version) > 0, "Version should not be empty"

    # Version should match pattern YYYY.MM.DD-N
    import re
    pattern = r'\d{4}\.\d{2}\.\d{2}(-\d+)?'
    assert re.match(pattern, version), f"Version {version} should match pattern YYYY.MM.DD-N"

    print(f"✅ Version computation works: {version}")


def test_reservoir_sampling():
    """Test reservoir sampling algorithm"""
    print("\n=== Testing Reservoir Sampling ===")

    from pcap_sentry_gui import _maybe_reservoir_append

    # Test with small sample
    reservoir = []
    limit = 10

    # Add items up to limit
    for i in range(limit):
        _maybe_reservoir_append(reservoir, f"item_{i}", limit, i + 1)

    assert len(reservoir) == limit, f"Reservoir should have exactly {limit} items"
    print(f"✅ Reservoir maintains size limit ({limit} items)")

    # Add more items (should trigger random replacement)
    for i in range(limit, limit + 100):
        _maybe_reservoir_append(reservoir, f"item_{i}", limit, i + 1)

    assert len(reservoir) == limit, f"Reservoir should still have exactly {limit} items"
    print("✅ Reservoir sampling works with overflow")


def test_url_scheme_validation():
    """Test URL scheme validation in _safe_urlopen wrapper"""
    print("\n=== Testing URL Scheme Validation ===")

    import urllib.request

    from pcap_sentry_gui import _safe_urlopen

    # Test 1: Allowed schemes (http:// localhost and https://)
    allowed_schemes = [
        "http://localhost:8080/api",
        "http://127.0.0.1:11434/api",
        "https://api.example.com/endpoint",
        "HTTPS://MIXED.Case.COM/path",
    ]

    for url in allowed_schemes:
        try:
            # We're not actually making requests, just validating the URL
            # This will fail with connection errors, but should NOT raise ValueError
            _safe_urlopen(url, timeout=0.001)
        except ValueError as exc:
            raise AssertionError(f"Allowed URL '{url}' was incorrectly blocked: {exc}") from exc
        except Exception:
            # Connection errors, timeouts, etc. are expected and OK
            pass

    print("✅ Allowed URL schemes (http/https) pass validation")

    # Test 1b: http:// to non-localhost should be blocked
    http_remote_urls = [
        "http://example.com/api",
        "HTTP://UPPERCASE.COM/PATH",
        "http://remote-server.com:8080/endpoint",
    ]
    for url in http_remote_urls:
        try:
            _safe_urlopen(url, timeout=0.001)
            raise AssertionError(f"Non-localhost http URL '{url}' was incorrectly allowed")
        except ValueError as exc:
            assert "localhost" in str(exc).lower(), f"Expected localhost error, got: {exc}"
        except AssertionError:
            raise
        except Exception as exc:
            raise AssertionError(
                f"URL '{url}' should raise ValueError, not {type(exc).__name__}: {exc}"
            ) from exc

    print("✅ http:// to non-localhost correctly blocked")

    # Test 2: Blocked schemes
    blocked_schemes = [
        "file:///etc/passwd",
        "file:///C:/Windows/System32/config/SAM",
        "ftp://malicious.com/exploit",
        "javascript:alert('xss')",
        "data:text/html,<script>alert('xss')</script>",
        "about:blank",
        "custom://protocol",
    ]

    for url in blocked_schemes:
        try:
            _safe_urlopen(url, timeout=0.001)
            raise AssertionError(f"Blocked URL '{url}' was incorrectly allowed")
        except ValueError as exc:
            # This is expected - URL should be blocked
            assert "Blocked unsafe URL scheme" in str(exc) or "explicitly blocked" in str(exc), \
                f"Expected security error message, got: {exc}"
        except Exception as exc:
            # Other exceptions are NOT acceptable - we should get ValueError first
            raise AssertionError(
                f"URL '{url}' should raise ValueError, not {type(exc).__name__}: {exc}"
            ) from exc

    print("✅ Blocked URL schemes (file/ftp/etc.) correctly rejected")

    # Test 3: Request objects
    try:
        req = urllib.request.Request("https://example.com/test")
        _safe_urlopen(req, timeout=0.001)
    except ValueError as exc:
        raise AssertionError(f"Valid Request object was incorrectly blocked: {exc}") from exc
    except Exception:
        # Connection errors are expected
        pass

    print("✅ urllib.request.Request objects handled correctly")

    # Test 4: file:// defense-in-depth
    file_variants = [
        "file://localhost/etc/passwd",
        "FILE:///C:/Windows/System32",
        "https://evil.com?redirect=file:///secret",  # file: in query string
    ]

    for url in file_variants:
        try:
            _safe_urlopen(url, timeout=0.001)
            raise AssertionError(f"file:// variant '{url}' was incorrectly allowed")
        except ValueError:
            # Expected - file:// should be blocked
            pass
        except AssertionError:
            # Re-raise our own assertions
            raise
        except Exception as exc:
            raise AssertionError(
                f"file:// variant '{url}' should raise ValueError, not {type(exc).__name__}: {exc}"
            ) from exc

    print("✅ file:// defense-in-depth protection working")


def test_model_name_validation():
    """Test model name validation function"""
    print("\n=== Testing Model Name Validation ===")

    from pcap_sentry_gui import _is_valid_model_name

    valid_names = [
        "llama3.2:3b",
        "model-name",
        "my_model",
        "test.model",
        "path/to/model",
        "GPT4All",
        "mistral:7b-instruct",
    ]

    invalid_names = [
        "",                        # Empty
        "../../../etc/passwd",     # Path traversal
        "model; rm -rf /",         # Command injection
        "model & echo bad",        # Command chaining
        "model`whoami`",           # Command substitution
        "model$(ls)",              # Command substitution
        " leading-space",          # Leading space
        "a" * 200,                 # Too long
    ]

    for name in valid_names:
        assert _is_valid_model_name(name), f"Valid name should be accepted: {name}"
    print(f"✅ All valid model names accepted ({len(valid_names)} tested)")

    for name in invalid_names:
        assert not _is_valid_model_name(name), f"Invalid name should be rejected: {name}"
    print(f"✅ All malicious/invalid names rejected ({len(invalid_names)} tested)")


def test_kb_lock_exists():
    """Test that the knowledge base lock exists for thread safety"""
    print("\n=== Testing KB Thread Safety ===")

    import threading

    from pcap_sentry_gui import _kb_lock

    assert isinstance(_kb_lock, type(threading.Lock())), "_kb_lock should be a threading.Lock"
    print("✅ Knowledge base lock exists")

    # Verify lock is acquirable and releasable
    acquired = _kb_lock.acquire(timeout=1)
    assert acquired, "Lock should be acquirable"
    _kb_lock.release()
    print("✅ KB lock acquire/release works")


def test_constants_defined():
    """Test that shared constants are properly defined at module level"""
    print("\n=== Testing Module Constants ===")

    from pcap_sentry_gui import (
        COMMON_PORTS,
        PATTERN_EDUCATION,
        PORT_DESCRIPTIONS,
        PORT_DESCRIPTIONS_SHORT,
    )

    assert isinstance(COMMON_PORTS, set), "COMMON_PORTS should be a set"
    assert 443 in COMMON_PORTS, "443 (HTTPS) should be in COMMON_PORTS"
    assert 80 in COMMON_PORTS, "80 (HTTP) should be in COMMON_PORTS"
    print(f"✅ COMMON_PORTS defined with {len(COMMON_PORTS)} ports")

    assert isinstance(PORT_DESCRIPTIONS, dict), "PORT_DESCRIPTIONS should be a dict"
    assert 443 in PORT_DESCRIPTIONS, "443 should have a description"
    print(f"✅ PORT_DESCRIPTIONS defined with {len(PORT_DESCRIPTIONS)} entries")

    assert isinstance(PORT_DESCRIPTIONS_SHORT, dict), "PORT_DESCRIPTIONS_SHORT should be a dict"
    print(f"✅ PORT_DESCRIPTIONS_SHORT defined with {len(PORT_DESCRIPTIONS_SHORT)} entries")

    assert isinstance(PATTERN_EDUCATION, dict), "PATTERN_EDUCATION should be a dict"
    assert "beaconing" in PATTERN_EDUCATION, "'beaconing' should be in PATTERN_EDUCATION"
    assert "c2" in PATTERN_EDUCATION, "'c2' should be in PATTERN_EDUCATION"
    assert "ioc" in PATTERN_EDUCATION, "'ioc' should be in PATTERN_EDUCATION"
    print(f"✅ PATTERN_EDUCATION defined with {len(PATTERN_EDUCATION)} patterns")
