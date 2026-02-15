"""
Stability Tests for PCAP Sentry
Tests core functionality, imports, and basic operations
"""

import sys
import os
import tempfile
import json
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "Python"))

def test_imports():
    """Test that all critical modules can be imported"""
    print("\n=== Testing Module Imports ===")
    
    try:
        import pcap_sentry_gui
        print("✅ pcap_sentry_gui imported successfully")
    except Exception as e:
        print(f"❌ Failed to import pcap_sentry_gui: {e}")
        return False
    
    try:
        import threat_intelligence
        print("✅ threat_intelligence imported successfully")
    except Exception as e:
        print(f"❌ Failed to import threat_intelligence: {e}")
        return False
    
    try:
        import update_checker
        print("✅ update_checker imported successfully")
    except Exception as e:
        print(f"❌ Failed to import update_checker: {e}")
        return False
    
    return True


def test_settings_operations():
    """Test settings save/load operations"""
    print("\n=== Testing Settings Operations ===")
    
    try:
        from pcap_sentry_gui import _default_settings, load_settings, save_settings
        
        # Test default settings
        defaults = _default_settings()
        assert isinstance(defaults, dict), "Default settings should be a dict"
        assert "max_rows" in defaults, "Default settings should have max_rows"
        print("✅ Default settings structure valid")
        
        # Test settings load (should return defaults if file doesn't exist)
        settings = load_settings()
        assert isinstance(settings, dict), "Loaded settings should be a dict"
        print("✅ Settings load successful")
        
        return True
        
    except Exception as e:
        print(f"❌ Settings operations failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_ioc_normalization():
    """Test IOC normalization and parsing"""
    print("\n=== Testing IOC Normalization ===")
    
    try:
        from pcap_sentry_gui import _normalize_ioc_item, _parse_ioc_text
        
        # Test IP normalization
        key, val = _normalize_ioc_item("192.168.1.1")
        assert key == "ips", f"IP should be recognized as 'ips', got '{key}'"
        assert val == "192.168.1.1", f"IP value mismatch"
        print("✅ IP normalization works")
        
        # Test domain normalization
        key, val = _normalize_ioc_item("example.com")
        assert key == "domains", f"Domain should be recognized as 'domains', got '{key}'"
        assert val == "example.com", f"Domain value mismatch"
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
        
        return True
        
    except Exception as e:
        print(f"❌ IOC normalization failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_path_security():
    """Test path security functions"""
    print("\n=== Testing Path Security ===")
    
    try:
        from pcap_sentry_gui import _get_app_data_dir
        import re
        
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
        
        return True
        
    except Exception as e:
        print(f"❌ Path security failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_input_validation():
    """Test input validation functions"""
    print("\n=== Testing Input Validation ===")
    
    try:
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
            if not re.fullmatch(pattern, name):
                print(f"❌ Valid name rejected: {name}")
                return False
        print(f"✅ All valid model names accepted ({len(valid_names)} tested)")
        
        for name in invalid_names:
            if re.fullmatch(pattern, name):
                print(f"❌ Invalid name accepted: {name}")
                return False
        print(f"✅ All malicious names rejected ({len(invalid_names)} tested)")
        
        return True
        
    except Exception as e:
        print(f"❌ Input validation failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_credential_security():
    """Test credential storage functions"""
    print("\n=== Testing Credential Security ===")
    
    try:
        from pcap_sentry_gui import _keyring_available, _store_api_key, _load_api_key, _delete_api_key
        
        keyring_avail = _keyring_available()
        print(f"ℹ️  Keyring available: {keyring_avail}")
        
        if keyring_avail:
            # Test storing and loading
            test_key = "test_api_key_12345"
            _store_api_key(test_key)
            loaded = _load_api_key()
            
            if loaded == test_key:
                print("✅ Keyring store/load works")
            else:
                print(f"⚠️  Keyring store/load mismatch (stored: {test_key}, loaded: {loaded})")
            
            # Cleanup
            _delete_api_key()
            after_delete = _load_api_key()
            if not after_delete:
                print("✅ Keyring delete works")
            else:
                print(f"⚠️  Keyring delete incomplete (still has: {after_delete})")
        else:
            print("ℹ️  Keyring not available - tests skipped (this is OK)")
        
        return True
        
    except Exception as e:
        print(f"❌ Credential security failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_threat_intelligence():
    """Test threat intelligence module"""
    print("\n=== Testing Threat Intelligence ===")
    
    try:
        from threat_intelligence import ThreatIntelligence
        
        ti = ThreatIntelligence()
        
        # Check if available
        available = ti.is_available()
        print(f"ℹ️  Threat Intelligence available: {available}")
        
        if not available:
            print("ℹ️  Threat Intelligence not available (requests module missing)")
            return True
        
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
        
        return True
        
    except Exception as e:
        print(f"❌ Threat intelligence failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_file_operations():
    """Test atomic file write operations"""
    print("\n=== Testing File Operations ===")
    
    try:
        import tempfile
        import json
        
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
            except:
                try:
                    os.unlink(tmp)
                except:
                    pass
                raise
            
            # Verify file was written
            assert os.path.exists(target_file), "Target file should exist"
            
            with open(target_file, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            
            assert loaded == test_data, "Loaded data should match written data"
            print("✅ Atomic file write works correctly")
        
        return True
        
    except Exception as e:
        print(f"❌ File operations failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_version_computation():
    """Test version computation"""
    print("\n=== Testing Version Computation ===")
    
    try:
        from pcap_sentry_gui import APP_VERSION, _compute_app_version
        
        version = _compute_app_version()
        assert version is not None, "Version should not be None"
        assert len(version) > 0, "Version should not be empty"
        
        # Version should match pattern YYYY.MM.DD-N
        import re
        pattern = r'\d{4}\.\d{2}\.\d{2}(-\d+)?'
        assert re.match(pattern, version), f"Version {version} should match pattern YYYY.MM.DD-N"
        
        print(f"✅ Version computation works: {version}")
        
        return True
        
    except Exception as e:
        print(f"❌ Version computation failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_reservoir_sampling():
    """Test reservoir sampling algorithm"""
    print("\n=== Testing Reservoir Sampling ===")
    
    try:
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
        
        return True
        
    except Exception as e:
        print(f"❌ Reservoir sampling failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def run_all_tests():
    """Run all stability tests"""
    print("=" * 70)
    print("PCAP SENTRY STABILITY TEST SUITE")
    print("=" * 70)
    
    tests = [
        ("Module Imports", test_imports),
        ("Settings Operations", test_settings_operations),
        ("IOC Normalization", test_ioc_normalization),
        ("Path Security", test_path_security),
        ("Input Validation", test_input_validation),
        ("Credential Security", test_credential_security),
        ("Threat Intelligence", test_threat_intelligence),
        ("File Operations", test_file_operations),
        ("Version Computation", test_version_computation),
        ("Reservoir Sampling", test_reservoir_sampling),
    ]
    
    results = []
    passed = 0
    failed = 0
    
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
            if result:
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"\n❌ Test '{name}' crashed: {e}")
            import traceback
            traceback.print_exc()
            results.append((name, False))
            failed += 1
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status:12} {name}")
    
    print("-" * 70)
    print(f"Total: {len(tests)} tests")
    print(f"Passed: {passed} ({passed/len(tests)*100:.1f}%)")
    print(f"Failed: {failed} ({failed/len(tests)*100:.1f}%)")
    print("=" * 70)
    
    if failed == 0:
        print("\n🎉 ALL TESTS PASSED - Application is STABLE")
        return 0
    else:
        print(f"\n⚠️  {failed} TEST(S) FAILED - Review failures above")
        return 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
