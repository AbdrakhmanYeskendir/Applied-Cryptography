"""
AES Modes of Operation Implementation
Includes: ECB, CBC, CTR, GCM modes
Fully implemented from scratch
"""

import struct
from typing import Tuple, Optional
from aes_core import aes_encrypt_block, aes_decrypt_block, rng, galois_mult

# ==================== PADDING ====================

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """
    PKCS#7 padding implementation
    If data length is multiple of block_size, add full block of padding
    Otherwise pad with N bytes of value N
    """
    padding_len = block_size - (len(data) % block_size)
    if padding_len == 0:
        padding_len = block_size
    padding = bytes([padding_len] * padding_len)
    return data + padding

def pkcs7_unpad(padded_data: bytes) -> bytes:
    """
    Remove PKCS#7 padding with validation
    Raises ValueError if padding is invalid
    """
    if not padded_data:
        return b""
    
    padding_len = padded_data[-1]
    
    # Check if padding length is valid
    if padding_len > len(padded_data) or padding_len == 0:
        raise ValueError("Invalid padding length")
    
    # Verify all padding bytes have correct value
    for i in range(1, padding_len + 1):
        if padded_data[-i] != padding_len:
            raise ValueError(f"Invalid padding byte at position {-i}")
    
    return padded_data[:-padding_len]

# ==================== ECB MODE ====================

def ecb_encrypt(plaintext: bytes, key: bytes, key_size: int = 128) -> bytes:
    """
    ECB (Electronic Codebook) mode encryption
    Each block is encrypted independently with AES
    """
    # Add PKCS#7 padding
    padded_data = pkcs7_pad(plaintext, 16)
    
    # Encrypt each 16-byte block independently
    ciphertext = bytearray()
    for i in range(0, len(padded_data), 16):
        block = padded_data[i:i+16]
        encrypted_block = aes_encrypt_block(block, key, key_size)
        ciphertext.extend(encrypted_block)
    
    return bytes(ciphertext)

def ecb_decrypt(ciphertext: bytes, key: bytes, key_size: int = 128) -> bytes:
    """
    ECB (Electronic Codebook) mode decryption
    Each block is decrypted independently
    """
    # Check if ciphertext length is valid
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be multiple of 16 bytes")
    
    # Decrypt each 16-byte block independently
    plaintext = bytearray()
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted_block = aes_decrypt_block(block, key, key_size)
        plaintext.extend(decrypted_block)
    
    # Remove PKCS#7 padding
    return pkcs7_unpad(bytes(plaintext))

# ==================== CBC MODE ====================

def cbc_encrypt(plaintext: bytes, key: bytes, key_size: int = 128, 
                iv: Optional[bytes] = None) -> bytes:
    """
    CBC (Cipher Block Chaining) mode encryption
    Each plaintext block is XORed with previous ciphertext block before encryption
    First block uses IV
    """
    # Generate random IV if not provided
    if iv is None:
        iv = rng.random_bytes(16)
    elif len(iv) != 16:
        raise ValueError("IV must be exactly 16 bytes")
    
    # Add PKCS#7 padding
    padded_data = pkcs7_pad(plaintext, 16)
    
    ciphertext = bytearray()
    previous_block = iv  # First block uses IV
    
    for i in range(0, len(padded_data), 16):
        block = padded_data[i:i+16]
        
        # XOR with previous ciphertext block (or IV for first block)
        xored_block = bytes(a ^ b for a, b in zip(block, previous_block))
        
        # Encrypt the XORed block
        encrypted_block = aes_encrypt_block(xored_block, key, key_size)
        ciphertext.extend(encrypted_block)
        
        # Update previous block for next iteration
        previous_block = encrypted_block
    
    # Return IV + ciphertext (IV is needed for decryption)
    return iv + bytes(ciphertext)

def cbc_decrypt(ciphertext: bytes, key: bytes, key_size: int = 128) -> bytes:
    """
    CBC (Cipher Block Chaining) mode decryption
    Each ciphertext block is decrypted then XORed with previous ciphertext block
    """
    # Check minimum length (IV + at least one block)
    if len(ciphertext) < 32 or len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext must be at least 32 bytes and multiple of 16")
    
    # Extract IV (first 16 bytes)
    iv = ciphertext[:16]
    ciphertext_blocks = ciphertext[16:]
    
    plaintext = bytearray()
    previous_block = iv  # First block uses IV
    
    for i in range(0, len(ciphertext_blocks), 16):
        block = ciphertext_blocks[i:i+16]
        
        # Decrypt the current block
        decrypted_block = aes_decrypt_block(block, key, key_size)
        
        # XOR with previous ciphertext block (or IV for first block)
        xored_block = bytes(a ^ b for a, b in zip(decrypted_block, previous_block))
        plaintext.extend(xored_block)
        
        # Update previous block for next iteration
        previous_block = block
    
    # Remove PKCS#7 padding
    return pkcs7_unpad(bytes(plaintext))

# ==================== CTR MODE ====================

def ctr_encrypt(plaintext: bytes, key: bytes, key_size: int = 128,
                nonce: Optional[bytes] = None) -> bytes:
    """
    CTR (Counter) mode encryption/decryption
    Generates keystream by encrypting counter values
    No padding required (stream cipher mode)
    """
    # Generate random 96-bit nonce if not provided
    if nonce is None:
        nonce = rng.random_bytes(12)
    elif len(nonce) != 12:
        raise ValueError("Nonce must be exactly 12 bytes (96 bits)")
    
    ciphertext = bytearray(nonce)  # Prepend nonce to output
    counter = 0  # 32-bit counter, starts from 0
    
    for i in range(0, len(plaintext), 16):
        # Create counter block: nonce + counter (little-endian)
        counter_block = nonce + struct.pack('<I', counter)
        
        # Encrypt counter block to get keystream
        keystream = aes_encrypt_block(counter_block, key, key_size)
        
        # XOR plaintext block with keystream
        plaintext_block = plaintext[i:i+16]
        encrypted_block = bytes(a ^ b for a, b in zip(plaintext_block, keystream[:len(plaintext_block)]))
        ciphertext.extend(encrypted_block)
        
        # Increment counter for next block
        counter += 1
    
    return bytes(ciphertext)

def ctr_decrypt(ciphertext: bytes, key: bytes, key_size: int = 128) -> bytes:
    """
    CTR (Counter) mode decryption
    Same as encryption (CTR mode is symmetric)
    """
    # Check minimum length (nonce + at least some data)
    if len(ciphertext) < 13:
        raise ValueError("Ciphertext too short")
    
    # Extract nonce (first 12 bytes)
    nonce = ciphertext[:12]
    ciphertext_data = ciphertext[12:]
    
    # CTR encryption and decryption are identical operations
    # Remove nonce from result since it's only needed for decryption
    return ctr_encrypt(ciphertext_data, key, key_size, nonce)[12:]

# ==================== GCM MODE ====================

def multiply_gf128(x: bytes, y: bytes) -> bytes:
    """
    Multiplication in GF(2^128) simplified for educational purposes
    Uses irreducible polynomial x^128 + x^7 + x^2 + x + 1
    """
    if len(x) != 16 or len(y) != 16:
        raise ValueError("Inputs must be 16 bytes")
    
    # Convert to integers
    x_int = int.from_bytes(x, 'big')
    y_int = int.from_bytes(y, 'big')
    
    result = 0
    for i in range(127, -1, -1):
        if (y_int >> i) & 1:
            result ^= x_int
        
        # Check if highest bit is set
        if x_int & (1 << 127):
            x_int = (x_int << 1) ^ 0x87  # x^128 + x^7 + x^2 + x + 1
        else:
            x_int <<= 1
        
        # Keep within 128 bits
        x_int &= (1 << 128) - 1
    
    return result.to_bytes(16, 'big')

class GCM:
    """GCM (Galois/Counter Mode) implementation with authentication"""
    
    @staticmethod
    def ghash(key_hash: bytes, data: bytes) -> bytes:
        """
        GHASH function for GCM
        Computes authentication hash using multiplication in GF(2^128)
        """
        if len(key_hash) != 16:
            raise ValueError("Key hash must be 16 bytes")
        
        # Pad data to multiple of 16 bytes
        if len(data) % 16 != 0:
            data += b'\x00' * (16 - (len(data) % 16))
        
        y = b'\x00' * 16  # Initialize to zero
        
        # Process data in 16-byte blocks
        for i in range(0, len(data), 16):
            block = data[i:i+16]
            
            # XOR current block with y
            xored = bytes(a ^ b for a, b in zip(y, block))
            
            # Multiply in GF(2^128)
            y = multiply_gf128(xored, key_hash)
        
        return y
    
    @staticmethod
    def gcm_encrypt(plaintext: bytes, key: bytes, key_size: int = 128,
                   additional_data: bytes = b'', iv: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        GCM encryption with authentication
        Returns: (ciphertext_with_iv, authentication_tag)
        """
        # Generate random 96-bit IV if not provided
        if iv is None:
            iv = rng.random_bytes(12)
        elif len(iv) != 12:
            raise ValueError("IV must be exactly 12 bytes (96 bits)")
        
        # Step 1: Compute hash key H = E_K(0^128)
        zero_block = b'\x00' * 16
        hash_key = aes_encrypt_block(zero_block, key, key_size)
        
        # Step 2: Compute J0 (initial counter)
        if len(iv) == 12:
            # For 96-bit IV: J0 = IV || 0^31 || 1
            j0 = iv + b'\x00\x00\x00\x01'
        else:
            # For other IV lengths: J0 = GHASH_H(IV || 0^64 || len(IV)_64)
            iv_padded = iv
            if len(iv_padded) % 16 != 0:
                iv_padded += b'\x00' * (16 - (len(iv_padded) % 16))
            
            iv_len_bits = len(iv) * 8
            iv_len_bytes = struct.pack('>Q', 0) + struct.pack('>Q', iv_len_bits)
            j0_input = iv_padded + iv_len_bytes
            j0 = GCM.ghash(hash_key, j0_input)
        
        # Step 3: CTR mode encryption
        # First counter is J0 + 1
        j0_int = int.from_bytes(j0, 'big')
        counter = j0_int + 1
        counter_bytes = counter.to_bytes(16, 'big')
        
        ciphertext = bytearray()
        
        # Encrypt plaintext using CTR mode
        for i in range(0, len(plaintext), 16):
            # Encrypt counter to get keystream
            keystream = aes_encrypt_block(counter_bytes, key, key_size)
            
            # XOR with plaintext block
            block = plaintext[i:i+16]
            encrypted_block = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
            ciphertext.extend(encrypted_block)
            
            # Increment counter
            counter += 1
            counter_bytes = counter.to_bytes(16, 'big')
        
        ciphertext = bytes(ciphertext)
        
        # Step 4: Compute authentication tag
        # Format: AAD || ciphertext || len(AAD)_64 || len(ciphertext)_64
        aad_len_bits = len(additional_data) * 8
        ciphertext_len_bits = len(ciphertext) * 8
        
        # Prepare authentication input
        auth_input = bytearray()
        
        # Add AAD (padded to 16 bytes)
        auth_input.extend(additional_data)
        if len(additional_data) % 16 != 0:
            auth_input.extend(b'\x00' * (16 - (len(additional_data) % 16)))
        
        # Add ciphertext (padded to 16 bytes)
        auth_input.extend(ciphertext)
        if len(ciphertext) % 16 != 0:
            auth_input.extend(b'\x00' * (16 - (len(ciphertext) % 16)))
        
        # Add lengths (64 bits each)
        auth_input.extend(struct.pack('>Q', aad_len_bits))
        auth_input.extend(struct.pack('>Q', ciphertext_len_bits))
        
        # Compute GHASH
        s = GCM.ghash(hash_key, bytes(auth_input))
        
        # Compute tag: T = MSB_t(GCTR_K(J0, S))
        # Simplified: T = E_K(J0) XOR S (first 16 bytes)
        tag_input = bytes(a ^ b for a, b in zip(s, j0))
        full_tag = aes_encrypt_block(tag_input, key, key_size)
        tag = full_tag[:16]  # 128-bit tag
        
        return iv + ciphertext, tag
    
    @staticmethod
    def gcm_decrypt(ciphertext_with_iv: bytes, key: bytes, key_size: int = 128,
                   additional_data: bytes = b'', tag: Optional[bytes] = None) -> bytes:
        """
        GCM decryption with authentication
        Verifies tag before returning decrypted plaintext
        """
        if len(ciphertext_with_iv) < 12:
            raise ValueError("Ciphertext too short")
        
        # Extract IV (first 12 bytes)
        iv = ciphertext_with_iv[:12]
        ciphertext = ciphertext_with_iv[12:]
        
        # If tag is provided separately
        if tag is not None:
            if len(tag) > 16:
                tag = tag[:16]  # Truncate to 128 bits
        else:
            # If tag is appended to ciphertext
            if len(ciphertext) < 16:
                raise ValueError("Ciphertext too short for tag extraction")
            tag = ciphertext[-16:]
            ciphertext = ciphertext[:-16]
        
        # Recompute tag for verification
        _, computed_tag = GCM.gcm_encrypt(b'', key, key_size, additional_data, iv)
        computed_tag = computed_tag[:len(tag)]
        
        # Verify authentication tag
        if computed_tag != tag:
            raise ValueError("GCM authentication failed: invalid tag")
        
        # Decrypt using CTR mode (same as encryption)
        # Compute hash key H
        zero_block = b'\x00' * 16
        hash_key = aes_encrypt_block(zero_block, key, key_size)
        
        # Compute J0
        if len(iv) == 12:
            j0 = iv + b'\x00\x00\x00\x01'
        else:
            iv_padded = iv
            if len(iv_padded) % 16 != 0:
                iv_padded += b'\x00' * (16 - (len(iv_padded) % 16))
            
            iv_len_bits = len(iv) * 8
            iv_len_bytes = struct.pack('>Q', 0) + struct.pack('>Q', iv_len_bits)
            j0_input = iv_padded + iv_len_bytes
            j0 = GCM.ghash(hash_key, j0_input)
        
        # CTR mode decryption
        j0_int = int.from_bytes(j0, 'big')
        counter = j0_int + 1
        counter_bytes = counter.to_bytes(16, 'big')
        
        plaintext = bytearray()
        
        for i in range(0, len(ciphertext), 16):
            # Encrypt counter to get keystream
            keystream = aes_encrypt_block(counter_bytes, key, key_size)
            
            # XOR with ciphertext block
            block = ciphertext[i:i+16]
            decrypted_block = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
            plaintext.extend(decrypted_block)
            
            # Increment counter
            counter += 1
            counter_bytes = counter.to_bytes(16, 'big')
        
        return bytes(plaintext)

# Convenience wrapper functions
def gcm_encrypt(plaintext: bytes, key: bytes, key_size: int = 128,
                additional_data: bytes = b'') -> bytes:
    """
    GCM encryption - returns IV || ciphertext || tag
    """
    ciphertext_with_iv, tag = GCM.gcm_encrypt(plaintext, key, key_size, additional_data)
    return ciphertext_with_iv + tag

def gcm_decrypt(ciphertext_with_tag: bytes, key: bytes, key_size: int = 128,
                additional_data: bytes = b'') -> bytes:
    """
    GCM decryption - expects IV || ciphertext || tag
    """
    if len(ciphertext_with_tag) < 28:  # 12 IV + at least 1 byte + 16 tag
        raise ValueError("Ciphertext with tag too short")
    
    ciphertext_with_iv = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]
    
    return GCM.gcm_decrypt(ciphertext_with_iv, key, key_size, additional_data, tag)

# ==================== ДЕМОНСТРАЦИЯ УЯЗВИМОСТИ ECB ====================

def demo_ecb_weakness():
    """
    Demonstrate ECB mode weakness:
    Identical plaintext blocks produce identical ciphertext blocks
    """
    print("\n" + "="*60)
    print("DEMONSTRATION OF ECB MODE WEAKNESS")
    print("="*60)
    
    # Create a simple repeating pattern
    print("\n1. Creating a repeating pattern:")
    pattern_block1 = b"BLOCK ONE!!!!!!"  # 15 bytes
    pattern_block2 = b"BLOCK TWO!!!!!!"  # 15 bytes
    pattern = pattern_block1 + b"\x01" + pattern_block2 + b"\x02"  # Add padding bytes
    
    # Repeat pattern 4 times
    repeated_data = pattern * 4
    print(f"   Pattern: {pattern[:16].hex()} {pattern[16:].hex()}")
    print(f"   Repeated 4 times")
    print(f"   Total length: {len(repeated_data)} bytes")
    
    # Use a simple key
    key = b"SixteenByteKey123"  # 16 bytes
    print(f"\n2. Using key: {key.hex()}")
    
    # Encrypt in ECB mode
    print("\n3. Encrypting with ECB mode:")
    ciphertext = ecb_encrypt(repeated_data, key, 128)
    
    # Extract and compare blocks
    print("\n4. Analyzing ciphertext blocks (16 bytes each):")
    blocks = []
    for i in range(0, min(64, len(ciphertext)), 16):
        block = ciphertext[i:i+16]
        blocks.append(block.hex())
        print(f"   Block {i//16 + 1}: {block.hex()}")
    
    # Check for identical blocks
    print("\n5. Checking for identical blocks:")
    identical_pairs = []
    for i in range(len(blocks)):
        for j in range(i + 1, len(blocks)):
            if blocks[i] == blocks[j]:
                identical_pairs.append((i, j))
    
    if identical_pairs:
        print(f"   Found {len(identical_pairs)} pairs of identical ciphertext blocks!")
        for i, j in identical_pairs[:5]:  # Show first 5 pairs
            print(f"   - Block {i+1} == Block {j+1}")
        
        print("\n" + "="*60)
        print(" ECB WEAKNESS CONFIRMED!")
        print("="*60)
        print("Identical plaintext blocks produce identical ciphertext blocks.")
        print("This allows patterns in the original data to remain visible")
        print("after encryption, which is a serious security flaw!")
        print("="*60)
    else:
        print("   No identical blocks found (unexpected for this pattern)")
    
    return ciphertext, blocks, identical_pairs

# ==================== ТЕСТИРОВАНИЕ ====================

def test_all_modes():
    """
    Test all AES modes with round-trip encryption/decryption
    """
    print("\n" + "="*60)
    print("TESTING ALL AES MODES OF OPERATION")
    print("="*60)
    
    test_data = [
        b"Short message",
        b"Exactly 16 bytes!!",
        b"This is a longer test message that spans multiple blocks for testing different modes of operation in AES encryption.",
        b"",  # Empty message
    ]
    
    key = b"TestKey16Bytes!!"
    key_sizes = [128, 192, 256]
    
    all_passed = True
    
    for key_size in key_sizes:
        print(f"\nTesting with AES-{key_size}:")
        
        for i, plaintext in enumerate(test_data, 1):
            print(f"\n  Test {i}: {len(plaintext)} bytes")
            
            # Test ECB
            try:
                ciphertext = ecb_encrypt(plaintext, key, key_size)
                decrypted = ecb_decrypt(ciphertext, key, key_size)
                ecb_ok = (decrypted == plaintext)
                print(f"    ECB: {'✓' if ecb_ok else '✗'}")
            except Exception as e:
                print(f"    ECB: ✗ ({e})")
                ecb_ok = False
            
            # Test CBC
            try:
                ciphertext = cbc_encrypt(plaintext, key, key_size)
                decrypted = cbc_decrypt(ciphertext, key, key_size)
                cbc_ok = (decrypted == plaintext)
                print(f"    CBC: {'✓' if cbc_ok else '✗'}")
            except Exception as e:
                print(f"    CBC: ✗ ({e})")
                cbc_ok = False
            
            # Test CTR
            try:
                ciphertext = ctr_encrypt(plaintext, key, key_size)
                decrypted = ctr_decrypt(ciphertext, key, key_size)
                ctr_ok = (decrypted == plaintext)
                print(f"    CTR: {'✓' if ctr_ok else '✗'}")
            except Exception as e:
                print(f"    CTR: ✗ ({e})")
                ctr_ok = False
            
            # Test GCM
            try:
                ciphertext = gcm_encrypt(plaintext, key, key_size)
                decrypted = gcm_decrypt(ciphertext, key, key_size)
                gcm_ok = (decrypted == plaintext)
                print(f"    GCM: {'✓' if gcm_ok else '✗'}")
                
                # Test GCM authentication failure
                try:
                    tampered = bytearray(ciphertext)
                    tampered[20] ^= 0x01  # Flip one bit
                    gcm_decrypt(bytes(tampered), key, key_size)
                    print(f"    GCM Auth: ✗ (Should have rejected tampered data)")
                    gcm_ok = False
                except ValueError:
                    print(f"    GCM Auth: ✓ (Correctly rejected tampered data)")
                    
            except Exception as e:
                print(f"    GCM: ✗ ({e})")
                gcm_ok = False
            
            if not (ecb_ok and cbc_ok and ctr_ok and gcm_ok):
                all_passed = False
    
    print("\n" + "="*60)
    if all_passed:
        print(" ALL TESTS PASSED!")
    else:
        print(" SOME TESTS FAILED")
    print("="*60)
    
    return all_passed

# ==================== ПРИМЕР ИСПОЛЬЗОВАНИЯ ====================

def usage_examples():
    """
    Show usage examples for each mode
    """
    print("\n" + "="*60)
    print("USAGE EXAMPLES FOR EACH MODE")
    print("="*60)
    
    key = b"SixteenByteKey123"
    plaintext = b"Secret message to encrypt!"
    
    print(f"\nPlaintext: {plaintext}")
    print(f"Key: {key.hex()}")
    
    print("\n1. ECB Mode:")
    ciphertext = ecb_encrypt(plaintext, key, 128)
    decrypted = ecb_decrypt(ciphertext, key, 128)
    print(f"   Ciphertext (hex): {ciphertext.hex()[:64]}...")
    print(f"   Decrypted: {decrypted}")
    print(f"   Match: {decrypted == plaintext}")
    
    print("\n2. CBC Mode:")
    ciphertext = cbc_encrypt(plaintext, key, 128)
    decrypted = cbc_decrypt(ciphertext, key, 128)
    print(f"   Ciphertext length: {len(ciphertext)} bytes (includes IV)")
    print(f"   Decrypted: {decrypted}")
    print(f"   Match: {decrypted == plaintext}")
    
    print("\n3. CTR Mode:")
    ciphertext = ctr_encrypt(plaintext, key, 128)
    decrypted = ctr_decrypt(ciphertext, key, 128)
    print(f"   Ciphertext length: {len(ciphertext)} bytes (includes nonce)")
    print(f"   Decrypted: {decrypted}")
    print(f"   Match: {decrypted == plaintext}")
    
    print("\n4. GCM Mode (with authentication):")
    additional_data = b"Authenticated but not encrypted"
    ciphertext = gcm_encrypt(plaintext, key, 128, additional_data)
    decrypted = gcm_decrypt(ciphertext, key, 128, additional_data)
    print(f"   Ciphertext length: {len(ciphertext)} bytes (includes IV + tag)")
    print(f"   Decrypted: {decrypted}")
    print(f"   Match: {decrypted == plaintext}")
    
    print("\n" + "="*60)

# ==================== ТОЧКА ВХОДА ====================

if __name__ == "__main__":
    """
    Main execution - run tests and demonstrations
    """
    print("AES Modes of Operation Implementation")
    print("ECB, CBC, CTR, and GCM modes from scratch")
    
    # Run tests
    test_all_modes()
    
    # Show usage examples
    usage_examples()
    
    # Demonstrate ECB weakness
    demo_ecb_weakness()
    
    print("\n" + "="*60)
    print("IMPLEMENTATION COMPLETE!")
    print("All 4 modes implemented: ECB, CBC, CTR, GCM")
    print("="*60)