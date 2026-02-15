"""
Simple test script for the update system
"""
import sys
sys.path.insert(0, "Python")

from update_checker import UpdateChecker

def test_update_checker():
    """Test the simplified update checker."""
    print("=" * 60)
    print("Testing PCAP Sentry Update System")
    print("=" * 60)
    
    # Test with current version
    checker = UpdateChecker("2026.02.14-4")
    
    print("\n1. Fetching latest release from GitHub...")
    if checker.fetch_latest_release():
        print(f"   ✓ Success!")
        print(f"   Current version: {checker.current_version}")
        print(f"   Latest version: {checker.latest_version}")
        print(f"   Download URL: {checker.download_url}")
        print(f"   Is installer: {getattr(checker, 'download_is_installer', False)}")
        
        print("\n2. Checking if update is available...")
        if checker.is_update_available():
            print(f"   ✓ Update available: {checker.latest_version}")
        else:
            print(f"   ✓ Already on latest version")
        
        print("\n3. Release notes preview:")
        notes = checker.release_notes or "No release notes"
        preview = notes[:200] + "..." if len(notes) > 200 else notes
        print(f"   {preview}")
        
        print("\n4. SHA-256 checksums:")
        expected = getattr(checker, "_expected_sha256", {})
        if expected:
            print(f"   ✓ Found {len(expected)} checksums")
            for filename, hash_val in list(expected.items())[:3]:
                print(f"   - {filename}: {hash_val[:16]}...")
        else:
            print("   ⚠ No checksums available")
        
        print("\n" + "=" * 60)
        print("✓ Update system is working correctly!")
        print("=" * 60)
        return True
    else:
        error = getattr(checker, "_last_error", "Unknown error")
        print(f"   ✗ Failed: {error}")
        print("\n" + "=" * 60)
        print("✗ Update system test failed")
        print("=" * 60)
        return False

if __name__ == "__main__":
    try:
        success = test_update_checker()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n✗ Test crashed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
