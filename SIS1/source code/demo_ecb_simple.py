"""
Simple ECB Weakness Demonstration
Shows that identical blocks produce identical ciphertext
"""

from aes_modes import ecb_encrypt

def simple_ecb_demo():
    """Simple demonstration of ECB weakness"""
    print("="*60)
    print("Simple ECB Mode Weakness Demonstration")
    print("="*60)
    
    # Simple repeating pattern
    print("\n1. Creating a simple repeating pattern...")
    block1 = b"AAAAAAAABBBBBBBB"  # 16 bytes
    block2 = b"CCCCCCCCDDDDDDDD"  # 16 bytes
    
    # Repeat pattern
    data = block1 + block2 + block1 + block2
    
    print(f"   Pattern: {block1.hex()} {block2.hex()}")
    print(f"   Repeated: {data.hex()}")
    
    # Simple key
    key = b"K" * 16
    print(f"\n2. Using key: {key.hex()}")
    
    # Encrypt
    print("\n3. Encrypting with ECB mode...")
    encrypted = ecb_encrypt(data, key, 128)
    
    # Show blocks
    print("\n4. Encrypted blocks (16 bytes each):")
    blocks = []
    for i in range(0, len(encrypted), 16):
        block = encrypted[i:i+16]
        blocks.append(block.hex())
        print(f"   Block {i//16 + 1}: {block.hex()}")
    
    # Check for identical blocks
    print("\n5. Analysis:")
    if blocks[0] == blocks[2]:
        print(f"   ✓ Block 1 == Block 3 (identical)")
    else:
        print(f"   ✗ Block 1 != Block 3")
    
    if blocks[1] == blocks[3]:
        print(f"   ✓ Block 2 == Block 4 (identical)")
    else:
        print(f"   ✗ Block 2 != Block 4")
    
    print("\n" + "="*60)
    print("Conclusion:")
    print("ECB mode encrypts identical plaintext blocks to")
    print("identical ciphertext blocks, revealing data patterns!")
    print("="*60)
    
    return blocks

if __name__ == "__main__":
    simple_ecb_demo()