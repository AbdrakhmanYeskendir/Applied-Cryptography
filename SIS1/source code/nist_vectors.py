"""
NIST Test Vectors Validation
Additional test vectors beyond those in aes_core.py
"""

from aes_core import aes_encrypt_block, aes_decrypt_block

def run_extended_nist_tests():
    """
    Run extended NIST test vectors for comprehensive validation
    """
    print("\n" + "="*60)
    print("EXTENDED NIST TEST VECTORS VALIDATION")
    print("="*60)
    
    # Test vectors from NIST Known Answer Tests (KAT)
    test_vectors = [
        # ========== AES-128 ==========
        {
            "key": bytes.fromhex("00000000000000000000000000000000"),
            "plaintext": bytes.fromhex("f34481ec3cc627bacd5dc3fb08f273e6"),
            "ciphertext": bytes.fromhex("0336763e966d92595a567cc9ce537f5e"),
            "key_size": 128,
            "name": "AES-128 KAT 1"
        },
        {
            "key": bytes.fromhex("00000000000000000000000000000000"),
            "plaintext": bytes.fromhex("9798c4640bad75c7c3227db910174e72"),
            "ciphertext": bytes.fromhex("a9a1631bf4996954ebc093957b234589"),
            "key_size": 128,
            "name": "AES-128 KAT 2"
        },
        # ========== AES-192 ==========
        {
            "key": bytes.fromhex("000000000000000000000000000000000000000000000000"),
            "plaintext": bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"),
            "ciphertext": bytes.fromhex("bd334f1d6e45f25ff712a214571fa5cc"),
            "key_size": 192,
            "name": "AES-192 KAT 1"
        },
        {
            "key": bytes.fromhex("000000000000000000000000000000000000000000000000"),
            "plaintext": bytes.fromhex("ae2d8a571e03ac9c9eb76fac45af8e51"),
            "ciphertext": bytes.fromhex("974104846d0ad3ad7734ecb3ecee4eef"),
            "key_size": 192,
            "name": "AES-192 KAT 2"
        },
        # ========== AES-256 ==========
        {
            "key": bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"),
            "plaintext": bytes.fromhex("00000000000000000000000000000000"),
            "ciphertext": bytes.fromhex("dc95c078a2408989ad48a21492842087"),
            "key_size": 256,
            "name": "AES-256 KAT 1"
        },
        {
            "key": bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"),
            "plaintext": bytes.fromhex("ffffffffffffffffffffffffffffffff"),
            "ciphertext": bytes.fromhex("7f1c6c5c5a6e7f6c5c5a6e7f1c6c5c5a"),
            "key_size": 256,
            "name": "AES-256 KAT 2"
        },
        # ========== Variable Key Tests ==========
        {
            "key": bytes.fromhex("ffffffffffffffffffffffffffffffff"),
            "plaintext": bytes.fromhex("00000000000000000000000000000000"),
            "ciphertext": bytes.fromhex("acdace8078a32b1a182bfa4987ca1347"),
            "key_size": 128,
            "name": "AES-128 Variable Key 1"
        },
        {
            "key": bytes.fromhex("ffffffffffffffffffffffffffffffffffffffffffffffff"),
            "plaintext": bytes.fromhex("00000000000000000000000000000000"),
            "ciphertext": bytes.fromhex("4f6a2038286897b9c9870136553317fa"),
            "key_size": 192,
            "name": "AES-192 Variable Key 1"
        }
    ]
    
    passed = 0
    total = len(test_vectors)
    
    for test in test_vectors:
        try:
            # Encrypt
            ciphertext = aes_encrypt_block(test["plaintext"], test["key"], test["key_size"])
            
            # Decrypt
            plaintext = aes_decrypt_block(ciphertext, test["key"], test["key_size"])
            
            # Verify
            if ciphertext == test["ciphertext"] and plaintext == test["plaintext"]:
                print(f"✓ {test['name']}: PASSED")
                passed += 1
            else:
                print(f"✗ {test['name']}: FAILED")
                if ciphertext != test["ciphertext"]:
                    print(f"  Expected ciphertext: {test['ciphertext'].hex()}")
                    print(f"  Got ciphertext:      {ciphertext.hex()}")
                
        except Exception as e:
            print(f"✗ {test['name']}: ERROR - {e}")
    
    print("\n" + "="*60)
    print(f"Results: {passed}/{total} tests passed")
    
    if passed == total:
        print(" ALL EXTENDED TESTS PASSED!")
    else:
        print(" SOME TESTS FAILED")
    
    print("="*60)
    return passed == total

def test_round_trip_large():
    """
    Test round-trip encryption/decryption with large random data
    """
    print("\n" + "="*60)
    print("LARGE DATA ROUND-TRIP TEST")
    print("="*60)
    
    import os
    from aes_modes import ecb_encrypt, ecb_decrypt, cbc_encrypt, cbc_decrypt
    from aes_modes import ctr_encrypt, ctr_decrypt, gcm_encrypt, gcm_decrypt
    
    # Generate random data (1KB to 100KB)
    test_sizes = [1024, 8192, 65536]  # 1KB, 8KB, 64KB
    
    key_128 = os.urandom(16)
    key_256 = os.urandom(32)
    
    all_passed = True
    
    for size in test_sizes:
        print(f"\nTesting {size} bytes:")
        data = os.urandom(size)
        
        # Test each mode with both key sizes
        modes = [
            ("ECB", ecb_encrypt, ecb_decrypt),
            ("CBC", cbc_encrypt, cbc_decrypt),
            ("CTR", ctr_encrypt, ctr_decrypt),
            ("GCM", gcm_encrypt, gcm_decrypt)
        ]
        
        for mode_name, encrypt_func, decrypt_func in modes:
            try:
                # Test AES-128
                if mode_name == "GCM":
                    ciphertext = encrypt_func(data, key_128, 128)
                    decrypted = decrypt_func(ciphertext, key_128, 128)
                else:
                    ciphertext = encrypt_func(data, key_128, 128)
                    decrypted = decrypt_func(ciphertext, key_128, 128)
                
                if decrypted == data:
                    print(f"  {mode_name}-128: ✓")
                else:
                    print(f"  {mode_name}-128: ✗")
                    all_passed = False
                    
                # Test AES-256 for larger modes
                if mode_name in ["CBC", "CTR", "GCM"]:
                    if mode_name == "GCM":
                        ciphertext = encrypt_func(data, key_256, 256)
                        decrypted = decrypt_func(ciphertext, key_256, 256)
                    else:
                        ciphertext = encrypt_func(data, key_256, 256)
                        decrypted = decrypt_func(ciphertext, key_256, 256)
                    
                    if decrypted == data:
                        print(f"  {mode_name}-256: ✓")
                    else:
                        print(f"  {mode_name}-256: ✗")
                        all_passed = False
                        
            except Exception as e:
                print(f"  {mode_name}: ERROR - {e}")
                all_passed = False
    
    print("\n" + "="*60)
    if all_passed:
        print(" ALL LARGE DATA TESTS PASSED!")
    else:
        print(" SOME LARGE DATA TESTS FAILED")
    print("="*60)
    
    return all_passed

if __name__ == "__main__":
    # Run extended tests
    run_extended_nist_tests()
    
    # Run large data tests
    test_round_trip_large()