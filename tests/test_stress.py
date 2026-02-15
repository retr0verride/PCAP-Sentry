"""
Stress Tests for PCAP Sentry
Tests performance, memory usage, and edge cases
"""

import sys
import os
import time
import traceback
import tracemalloc
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "Python"))


def format_size(bytes_val):
    """Format bytes to human readable"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.2f} TB"


def test_large_ioc_parsing():
    """Test parsing large IOC lists"""
    print("\n=== Stress Test: Large IOC Parsing ===")
    
    try:
        from pcap_sentry_gui import _parse_ioc_text
        
        tracemalloc.start()
        start_mem = tracemalloc.get_traced_memory()[0]
        start_time = time.time()
        
        # Generate large IOC list
        large_text = []
        for i in range(10000):
            large_text.append(f"192.168.{i//256}.{i%256}")
            large_text.append(f"domain{i}.example.com")
        
        text = "\n".join(large_text)
        
        # Parse
        iocs = _parse_ioc_text(text)
        
        end_time = time.time()
        end_mem = tracemalloc.get_traced_memory()[0]
        tracemalloc.stop()
        
        duration = end_time - start_time
        mem_used = end_mem - start_mem
        
        print(f"✅ Parsed 20,000 IOCs in {duration:.3f}s")
        print(f"   Memory used: {format_size(mem_used)}")
        print(f"   IPs found: {len(iocs.get('ips', []))}")
        print(f"   Domains found: {len(iocs.get('domains', []))}")
        
        assert len(iocs['ips']) > 0, "Should parse IPs"
        assert len(iocs['domains']) > 0, "Should parse domains"
        
        return True
        
    except Exception as e:
        print(f"❌ Large IOC parsing failed: {e}")
        traceback.print_exc()
        return False


def test_reservoir_sampling_performance():
    """Test reservoir sampling with large datasets"""
    print("\n=== Stress Test: Reservoir Sampling Performance ===")
    
    try:
        from pcap_sentry_gui import _maybe_reservoir_append
        
        tracemalloc.start()
        start_mem = tracemalloc.get_traced_memory()[0]
        start_time = time.time()
        
        reservoir = []
        limit = 1000
        
        # Simulate 1 million packets
        for i in range(1_000_000):
            _maybe_reservoir_append(reservoir, f"packet_{i}", limit, i + 1)
        
        end_time = time.time()
        end_mem = tracemalloc.get_traced_memory()[0]
        tracemalloc.stop()
        
        duration = end_time - start_time
        mem_used = end_mem - start_mem
        throughput = 1_000_000 / duration
        
        print(f"✅ Processed 1M items in {duration:.3f}s")
        print(f"   Throughput: {throughput:,.0f} items/sec")
        print(f"   Memory used: {format_size(mem_used)}")
        print(f"   Reservoir size: {len(reservoir)} (limit: {limit})")
        
        assert len(reservoir) == limit, f"Reservoir should be exactly {limit}"
        assert throughput > 100_000, "Should process >100K items/sec"
        
        return True
        
    except Exception as e:
        print(f"❌ Reservoir sampling stress test failed: {e}")
        traceback.print_exc()
        return False


def test_counter_performance():
    """Test Counter performance with many unique items"""
    print("\n=== Stress Test: Counter Performance ===")
    
    try:
        from collections import Counter
        
        tracemalloc.start()
        start_mem = tracemalloc.get_traced_memory()[0]
        start_time = time.time()
        
        # Simulate packet counting
        proto_counts = Counter()
        port_counts = Counter()
        
        for i in range(1_000_000):
            proto_counts["TCP"] += 1
            port_counts[i % 65536] += 1  # All possible ports
        
        end_time = time.time()
        end_mem = tracemalloc.get_traced_memory()[0]
        tracemalloc.stop()
        
        duration = end_time - start_time
        mem_used = end_mem - start_mem
        throughput = 1_000_000 / duration
        
        print(f"✅ 1M counter updates in {duration:.3f}s")
        print(f"   Throughput: {throughput:,.0f} updates/sec")
        print(f"   Memory used: {format_size(mem_used)}")
        print(f"   Unique ports tracked: {len(port_counts)}")
        
        assert throughput > 500_000, "Should process >500K updates/sec"
        
        return True
        
    except Exception as e:
        print(f"❌ Counter performance failed: {e}")
        traceback.print_exc()
        return False


def test_set_operations():
    """Test set operations performance"""
    print("\n=== Stress Test: Set Operations ===")
    
    try:
        tracemalloc.start()
        start_mem = tracemalloc.get_traced_memory()[0]
        start_time = time.time()
        
        # Simulate unique IP/domain tracking
        unique_ips = set()
        unique_domains = set()
        
        for i in range(100_000):
            unique_ips.add(f"192.168.{i//256}.{i%256}")
            unique_domains.add(f"host{i}.example.com")
        
        end_time = time.time()
        end_mem = tracemalloc.get_traced_memory()[0]
        tracemalloc.stop()
        
        duration = end_time - start_time
        mem_used = end_mem - start_mem
        throughput = 200_000 / duration  # 2 ops per iteration
        
        print(f"✅ 200K set operations in {duration:.3f}s")
        print(f"   Throughput: {throughput:,.0f} ops/sec")
        print(f"   Memory used: {format_size(mem_used)}")
        print(f"   Unique IPs: {len(unique_ips):,}")
        print(f"   Unique domains: {len(unique_domains):,}")
        
        assert len(unique_ips) == 100_000, "Should have 100K unique IPs"
        assert len(unique_domains) == 100_000, "Should have 100K unique domains"
        
        return True
        
    except Exception as e:
        print(f"❌ Set operations failed: {e}")
        traceback.print_exc()
        return False


def test_edge_cases():
    """Test edge cases and boundary conditions"""
    print("\n=== Stress Test: Edge Cases ===")
    
    try:
        from pcap_sentry_gui import _normalize_ioc_item, _parse_ioc_text
        
        # Empty strings
        key, val = _normalize_ioc_item("")
        assert key is None, "Empty string should return None"
        print("✅ Empty string handled")
        
        # Whitespace only
        key, val = _normalize_ioc_item("   ")
        assert key is None, "Whitespace only should return None"
        print("✅ Whitespace handled")
        
        # Very long domain (exceed RFC limits)
        long_domain = "a" * 300 + ".com"
        key, val = _normalize_ioc_item(long_domain)
        # Should still parse but might be invalid
        print(f"✅ Long domain handled (key={key})")
        
        # Special characters
        special = "test@#$%.com"
        key, val = _normalize_ioc_item(special)
        print(f"✅ Special chars handled (key={key})")
        
        # IPv6 (should not parse as we use ipaddress which supports it)
        ipv6 = "2001:0db8:85a3::8a2e:0370:7334"
        key, val = _normalize_ioc_item(ipv6)
        # ipaddress module will recognize this
        print(f"✅ IPv6 handled (key={key})")
        
        # Malformed IOCs
        malformed = [
            "not.an.ip.address",
            "999.999.999.999",
            "domain.",
            ".domain",
            "hash_with_invalid_chars!!!",
        ]
        for item in malformed:
            key, val = _normalize_ioc_item(item)
            # Should not crash
        print(f"✅ Malformed IOCs handled gracefully")
        
        return True
        
    except Exception as e:
        print(f"❌ Edge cases failed: {e}")
        traceback.print_exc()
        return False


def test_concurrent_operations():
    """Test thread safety of cache operations"""
    print("\n=== Stress Test: Concurrent Operations ===")
    
    try:
        from threat_intelligence import ThreatIntelligence
        import threading
        
        ti = ThreatIntelligence()
        errors = []
        
        def worker(worker_id):
            try:
                for i in range(100):
                    key = f"worker_{worker_id}_item_{i}"
                    value = {"data": f"test_{i}"}
                    
                    # Write
                    ti._cache_put(key, value)
                    
                    # Read
                    result = ti._cache_get(key)
                    if result is None or result["data"] != f"test_{i}":
                        errors.append(f"Worker {worker_id} cache mismatch at {i}")
                        
            except Exception as e:
                errors.append(f"Worker {worker_id} error: {e}")
        
        # Run 10 workers concurrently
        threads = []
        start_time = time.time()
        
        for i in range(10):
            t = threading.Thread(target=worker, args=(i,))
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
        
        duration = time.time() - start_time
        
        if errors:
            print(f"❌ Thread safety issues detected:")
            for error in errors[:5]:  # Show first 5 errors
                print(f"   {error}")
            return False
        else:
            print(f"✅ 10 threads, 1000 ops completed in {duration:.3f}s")
            print(f"   No race conditions detected")
            return True
        
    except Exception as e:
        print(f"❌ Concurrent operations failed: {e}")
        traceback.print_exc()
        return False


def test_memory_cleanup():
    """Test that memory is properly released"""
    print("\n=== Stress Test: Memory Cleanup ===")
    
    try:
        import gc
        
        # Force garbage collection
        gc.collect()
        
        tracemalloc.start()
        start_mem = tracemalloc.get_traced_memory()[0]
        
        # Create large temporary structures
        large_list = [f"item_{i}" for i in range(1_000_000)]
        large_dict = {f"key_{i}": f"value_{i}" for i in range(100_000)}
        
        peak_mem = tracemalloc.get_traced_memory()[1]
        
        # Delete and collect
        del large_list
        del large_dict
        gc.collect()
        
        end_mem = tracemalloc.get_traced_memory()[0]
        tracemalloc.stop()
        
        allocated = peak_mem - start_mem
        released = peak_mem - end_mem
        release_pct = (released / allocated) * 100 if allocated > 0 else 0
        
        print(f"✅ Memory allocated: {format_size(allocated)}")
        print(f"   Memory released: {format_size(released)} ({release_pct:.1f}%)")
        
        assert release_pct > 80, "Should release >80% of allocated memory"
        
        return True
        
    except Exception as e:
        print(f"❌ Memory cleanup failed: {e}")
        traceback.print_exc()
        return False


def run_stress_tests():
    """Run all stress tests"""
    print("=" * 70)
    print("PCAP SENTRY STRESS TEST SUITE")
    print("=" * 70)
    
    tests = [
        ("Large IOC Parsing", test_large_ioc_parsing),
        ("Reservoir Sampling Performance", test_reservoir_sampling_performance),
        ("Counter Performance", test_counter_performance),
        ("Set Operations", test_set_operations),
        ("Edge Cases", test_edge_cases),
        ("Concurrent Operations", test_concurrent_operations),
        ("Memory Cleanup", test_memory_cleanup),
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
            traceback.print_exc()
            results.append((name, False))
            failed += 1
    
    # Summary
    print("\n" + "=" * 70)
    print("STRESS TEST SUMMARY")
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
        print("\n🎉 ALL STRESS TESTS PASSED - Application is ROBUST")
        return 0
    else:
        print(f"\n⚠️  {failed} STRESS TEST(S) FAILED - Review failures above")
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(run_stress_tests())
