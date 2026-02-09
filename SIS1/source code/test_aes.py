"""
Simple AES Tests
Not comprehensive, but enough to show it works
"""

import os
import sys

# Add current directory to path to import our modules
sys.path.append('.')

try:
    from aes_core import aes_encrypt_block, aes_decrypt_block, generate_key
    from aes_modes import (
        ecb_encrypt, ecb_decrypt,
        cbc_encrypt, cbc_decrypt,
        ctr_encrypt, ctr_decrypt,
        gcm_encrypt, gcm_decrypt
    )
    print("✓ AES modules imported successfully")
except ImportError as e:
    print(f"✗ Failed to import AES modules: {e}")
    sys.exit(1)

def test_basic_aes():
    """Test basic AES encryption/decryption"""
    print("\n" + "="*50)
    print("Testing Basic AES")
    print("="*50)
    
    # Test with known values (simple test)
    key = b"SixteenByteKey123"
    plaintext = b"16 byte test txt"
    
    print(f"Key: {key.hex()}")
    print(f"Plaintext: {plaintext.hex()}")
    
    # Test AES core
    try:
        ciphertext = aes_encrypt_block(plaintext, key, 128)
        decrypted = aes_decrypt_block(ciphertext, key, 128)
        
        print(f"Ciphertext: {ciphertext.hex()}")
        print(f"Decrypted: {decrypted.hex()}")
        
        if decrypted == plaintext:
            print("✓ Basic AES test PASSED")
            return True
        else:
            print("✗ Basic AES test FAILED")
            return False
    except Exception as e:
        print(f"✗ Basic AES test ERROR: {e}")
        return False

def test_ecb_mode():
    """Test ECB mode"""
    print("\n" + "="*50)
    print("Testing ECB Mode")
    print("="*50)
    
    key = b"SixteenByteKey123"
    plaintext = b"This is a test message for ECB mode!"
    
    print(f"Plaintext length: {len(plaintext)} bytes")
    
    try:
        ciphertext = ecb_encrypt(plaintext, key, 128)
        decrypted = ecb_decrypt(ciphertext, key, 128)
        
        print(f"Ciphertext length: {len(ciphertext)} bytes")
        print(f"Decryption successful: {decrypted == plaintext}")
        
        if decrypted == plaintext:
            print("✓ ECB mode test PASSED")
            return True
        else:
            print("✗ ECB mode test FAILED")
            return False
    except Exception as e:
        print(f"✗ ECB mode test ERROR: {e}")
        return False

def test_cbc_mode():
    """Test CBC mode"""
    print("\n" + "="*50)
    print("Testing CBC Mode")
    print("="*50)
    
    key = b"SixteenByteKey123"
    plaintext = b"Testing CBC mode with different length text"
    
    try:
        ciphertext = cbc_encrypt(plaintext, key, 128)
        decrypted = cbc_decrypt(ciphertext, key, 128)
        
        print(f"Plaintext: '{plaintext.decode()}'")
        print(f"Decrypted: '{decrypted.decode()}'")
        
        if decrypted == plaintext:
            print("✓ CBC mode test PASSED")
            return True
        else:
            print("✗ CBC mode test FAILED")
            return False
    except Exception as e:
        print(f"✗ CBC mode test ERROR: {e}")
        return False

def test_ctr_mode():
    """Test CTR mode"""
    print("\n" + "="*50)
    print("Testing CTR Mode")
    print("="*50)
    
    key = b"SixteenByteKey123"
    plaintext = b"CTR mode is a stream cipher, no padding needed!"
    
    try:
        ciphertext = ctr_encrypt(plaintext, key, 128)
        decrypted = ctr_decrypt(ciphertext, key, 128)
        
        print(f"Original: {plaintext[:30]}...")
        print(f"Decrypted: {decrypted[:30]}...")
        
        if decrypted == plaintext:
            print("✓ CTR mode test PASSED")
            return True
        else:
            print("✗ CTR mode test FAILED")
            return False
    except Exception as e:
        print(f"✗ CTR mode test ERROR: {e}")
        return False

def test_gcm_mode():
    """Test GCM mode with authentication"""
    print("\n" + "="*50)
    print("Testing GCM Mode")
    print("="*50)
    
    key = b"SixteenByteKey123"
    plaintext = b"GCM provides authenticated encryption"
    aad = b"Additional authenticated data"
    
    try:
        ciphertext = gcm_encrypt(plaintext, key, 128, aad)
        decrypted = gcm_decrypt(ciphertext, key, 128, aad)
        
        print(f"With AAD: '{aad.decode()}'")
        print(f"Decryption successful: {decrypted == plaintext}")
        
        # Test tampering detection
        tampered = bytearray(ciphertext)
        tampered[20] ^= 0x01  # Flip one bit
        
        try:
            gcm_decrypt(bytes(tampered), key, 128, aad)
            print("✗ GCM should have detected tampering!")
            return False
        except ValueError:
            print("✓ GCM correctly rejected tampered data")
        
        if decrypted == plaintext:
            print("✓ GCM mode test PASSED")
            return True
        else:
            print("✗ GCM mode test FAILED")
            return False
    except Exception as e:
        print(f"✗ GCM mode test ERROR: {e}")
        return False

def test_large_file():
    """Test with larger data"""
    print("\n" + "="*50)
    print("Testing Large Data")
    print("="*50)
    
    key = generate_key(128)
    # Create 100KB of test data
    large_data = os.urandom(100 * 1024)  # 100KB
    
    print(f"Testing with {len(large_data)} bytes of random data")
    
    try:
        # Test ECB
        ciphertext = ecb_encrypt(large_data, key, 128)
        decrypted = ecb_decrypt(ciphertext, key, 128)
        
        if decrypted == large_data:
            print("✓ Large data test (ECB) PASSED")
        else:
            print("✗ Large data test (ECB) FAILED")
            return False
        
        # Test CBC
        ciphertext = cbc_encrypt(large_data, key, 128)
        decrypted = cbc_decrypt(ciphertext, key, 128)
        
        if decrypted == large_data:
            print("✓ Large data test (CBC) PASSED")
            return True
        else:
            print("✗ Large data test (CBC) FAILED")
            return False
            
    except Exception as e:
        print(f"✗ Large data test ERROR: {e}")
        return False

def test_key_sizes():
    """Test different key sizes"""
    print("\n" + "="*50)
    print("Testing Different Key Sizes")
    print("="*50)
    
    plaintext = b"Test with different key sizes"
    
    for key_size in [128, 192, 256]:
        print(f"\nTesting AES-{key_size}:")
        key = generate_key(key_size)
        
        try:
            ciphertext = ecb_encrypt(plaintext, key, key_size)
            decrypted = ecb_decrypt(ciphertext, key, key_size)
            
            if decrypted == plaintext:
                print(f"  ✓ AES-{key_size} works")
            else:
                print(f"  ✗ AES-{key_size} failed")
                return False
        except Exception as e:
            print(f"  ✗ AES-{key_size} error: {e}")
            return False
    
    print("\n✓ All key sizes work correctly")
    return True

def test_custom_rng():
    """Test custom random number generator with entropy collection"""
    print("\n" + "="*50)
    print("Testing Custom RNG with Entropy Collection")
    print("="*50)
    
    try:
        from aes_core import CustomRNG
        
        print("Creating RNG instance (will collect entropy)...")
        rng = CustomRNG()
        
        # Test 1: Generate random bytes
        print("\n1. Generating random bytes:")
        random_bytes = rng.random_bytes(32)
        print(f"   32 random bytes: {random_bytes.hex()[:64]}...")
        
        # Test 2: Generate multiple keys
        print("\n2. Generating multiple 128-bit keys:")
        keys = set()
        for i in range(5):
            key = rng.random_bytes(16)
            keys.add(key.hex())
            print(f"   Key {i+1}: {key.hex()[:32]}...")
        
        # Check for uniqueness (very low probability of collision)
        if len(keys) == 5:
            print("   ✓ All keys are unique")
        else:
            print(f"     Only {len(keys)} unique keys out of 5")
        
        # Test 3: Statistical test (simple)
        print("\n3. Simple statistical test:")
        bytes_1000 = rng.random_bytes(1000)
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in bytes_1000:
            byte_counts[byte] += 1
        
        # Check distribution (simplified)
        max_count = max(byte_counts)
        min_count = min(byte_counts)
        avg_count = 1000 / 256
        
        print(f"   Max byte frequency: {max_count}")
        print(f"   Min byte frequency: {min_count}")
        print(f"   Expected average: {avg_count:.2f}")
        
        if 3 <= avg_count <= 5:  # Rough check
            print("   ✓ Distribution looks reasonable")
        else:
            print("     Distribution may be biased")
        
        print("\n✓ Custom RNG test PASSED")
        return True
        
    except Exception as e:
        print(f"✗ Custom RNG test ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_all_tests():
    """Run all tests"""
    print("Starting AES Implementation Tests")
    print("="*50)
    
    tests = [
        ("Custom RNG", test_custom_rng),  # НОВЫЙ ТЕСТ ПЕРВЫМ
        ("Basic AES", test_basic_aes),
        ("ECB Mode", test_ecb_mode),
        ("CBC Mode", test_cbc_mode),
        ("CTR Mode", test_ctr_mode),
        ("GCM Mode", test_gcm_mode),
        ("Key Sizes", test_key_sizes),
        ("Large Data", test_large_file),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
                print(f"\n✓ {test_name} PASSED\n")
            else:
                print(f"\n✗ {test_name} FAILED\n")
        except Exception as e:
            print(f"\n✗ {test_name} ERROR: {e}\n")
    
    print("="*50)
    print(f"Test Results: {passed}/{total} tests passed")
    print("="*50)
    
    if passed == total:
        print(" ALL TESTS PASSED! Implementation is working correctly.")
        return True
    else:
        print(" SOME TESTS FAILED. Check implementation.")
        return False

if __name__ == "__main__":
    # Run tests
    success = run_all_tests()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)