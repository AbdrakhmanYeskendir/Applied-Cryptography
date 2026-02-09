"""
ECB Mode Weakness Visualization
Demonstrates why ECB should not be used for images
"""

import os
import struct
from aes_modes import ecb_encrypt, ecb_decrypt
from aes_core import generate_key

def create_test_image(width=64, height=64):
    """
    Create a simple test image with visible patterns
    Returns bytes in simple RGB format
    """
    print(f"Creating test image: {width}x{height} pixels")
    
    # Simple pattern: alternating stripes
    pixels = bytearray()
    for y in range(height):
        for x in range(width):
            if (x // 8) % 2 == 0:  # Vertical stripes
                r = 255 if (y // 8) % 2 == 0 else 0
                g = 0
                b = 255 if (y // 16) % 2 == 0 else 128
            else:
                r = 0
                g = 255 if (x // 16) % 2 == 0 else 128
                b = 255 if (y // 8) % 2 == 0 else 0
            
            pixels.append(r)  # Red
            pixels.append(g)  # Green
            pixels.append(b)  # Blue
    
    return bytes(pixels), width, height

def encrypt_image_ecb(image_data, key):
    """
    Encrypt image data using ECB mode
    """
    print(f"Encrypting {len(image_data)} bytes with ECB...")
    return ecb_encrypt(image_data, key, 128)

def analyze_patterns(original, encrypted, block_size=16):
    """
    Analyze patterns in original vs encrypted data
    """
    print("\n" + "="*60)
    print("PATTERN ANALYSIS")
    print("="*60)
    
    # Split into blocks
    orig_blocks = []
    enc_blocks = []
    
    for i in range(0, min(len(original), len(encrypted)), block_size):
        orig_block = original[i:i+block_size]
        enc_block = encrypted[i:i+block_size]
        
        if len(orig_block) == block_size and len(enc_block) == block_size:
            orig_blocks.append(orig_block)
            enc_blocks.append(enc_block)
    
    print(f"Total blocks: {len(orig_blocks)}")
    
    # Find identical blocks in original
    orig_identical = {}
    for i, block1 in enumerate(orig_blocks):
        for j, block2 in enumerate(orig_blocks[i+1:], i+1):
            if block1 == block2:
                if i not in orig_identical:
                    orig_identical[i] = []
                orig_identical[i].append(j)
    
    print(f"\nOriginal image has {len(orig_identical)} unique blocks with duplicates")
    
    # Check if ECB preserves patterns
    ecb_preserves = 0
    ecb_changes = 0
    
    for i, duplicates in orig_identical.items():
        for j in duplicates:
            if enc_blocks[i] == enc_blocks[j]:
                ecb_preserves += 1
            else:
                ecb_changes += 1
    
    print(f"\nECB Pattern Preservation Analysis:")
    print(f"  Blocks where pattern preserved: {ecb_preserves}")
    print(f"  Blocks where pattern changed: {ecb_changes}")
    
    if ecb_preserves > ecb_changes:
        print(f"  ⚠️  ECB PRESERVES {ecb_preserves/(ecb_preserves+ecb_changes)*100:.1f}% OF PATTERNS!")
    else:
        print(f"  ✓ ECB changes most patterns")
    
    # Find most common encrypted blocks (indicates common plaintext patterns)
    block_counts = {}
    for block in enc_blocks:
        block_hex = block.hex()
        block_counts[block_hex] = block_counts.get(block_hex, 0) + 1
    
    # Show top 5 most common encrypted blocks
    common_blocks = sorted(block_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    print(f"\nMost common encrypted blocks (indicate repeated plaintext):")
    for block_hex, count in common_blocks:
        if count > 1:
            print(f"  Block {block_hex[:16]}... appears {count} times")
    
    return orig_identical, block_counts

def save_to_ppm(image_data, width, height, filename):
    """
    Save image data to PPM format (simple image format)
    """
    with open(filename, 'wb') as f:
        # PPM header
        f.write(f"P6\n{width} {height}\n255\n".encode())
        # Image data
        f.write(image_data)
    
    print(f"Saved to {filename}")

def demonstrate_ecb_weakness():
    """
    Main demonstration function
    """
    print("="*60)
    print("ECB MODE WEAKNESS DEMONSTRATION")
    print("="*60)
    print("This shows why ECB should not be used for structured data like images.")
    print("Identical plaintext blocks produce identical ciphertext blocks,")
    print("making patterns visible even after encryption.\n")
    
    # Generate key
    key = generate_key(128)
    print(f"Using key: {key.hex()[:32]}...")
    
    # Create test image
    image_data, width, height = create_test_image(64, 64)
    
    # Save original
    save_to_ppm(image_data, width, height, "original_image.ppm")
    
    # Encrypt with ECB
    encrypted = encrypt_image_ecb(image_data, key)
    
    # Save encrypted as "image" (will show patterns)
    save_to_ppm(encrypted[:len(image_data)], width, height, "ecb_encrypted.ppm")
    
    # Decrypt to verify
    decrypted = ecb_decrypt(encrypted, key, 128)
    save_to_ppm(decrypted[:len(image_data)], width, height, "decrypted_image.ppm")
    
    # Analyze patterns
    analyze_patterns(image_data, encrypted)
    
    print("\n" + "="*60)
    print("DEMONSTRATION COMPLETE")
    print("="*60)
    print("Created 3 PPM files:")
    print("  1. original_image.ppm - Original test pattern")
    print("  2. ecb_encrypted.ppm - ECB encrypted (patterns visible!)")
    print("  3. decrypted_image.ppm - Decrypted (should match original)")
    print("\nOpen with any image viewer that supports PPM format.")
    print("GIMP, Photoshop, or online converters work well.")
    print("\nObservation: ECB encrypted image will show faint patterns")
    print("of the original due to identical blocks encrypting identically.")

def simple_text_demo():
    """
    Simple text-based demonstration
    """
    print("\n" + "="*60)
    print("SIMPLE TEXT DEMONSTRATION")
    print("="*60)
    
    # Create text with repeating pattern
    pattern = b"PATTERN" * 4  # 28 bytes
    padding = b"X" * 4        # Pad to 32 bytes (2 blocks)
    text = pattern + padding
    
    key = b"S" * 16  # Simple key
    
    print(f"Text: {text}")
    print(f"Pattern 'PATTERN' repeated 4 times")
    print(f"Key: {key.hex()}")
    
    # Encrypt
    encrypted = ecb_encrypt(text, key, 128)
    
    print(f"\nEncrypted (hex):")
    for i in range(0, len(encrypted), 16):
        block = encrypted[i:i+16]
        print(f"  Block {i//16 + 1}: {block.hex()}")
    
    # Analyze
    blocks = [encrypted[i:i+16] for i in range(0, len(encrypted), 16)]
    
    print(f"\nAnalysis:")
    for i in range(len(blocks)):
        for j in range(i+1, len(blocks)):
            if blocks[i] == blocks[j]:
                print(f"  Block {i+1} == Block {j+1} (identical!)")
    
    print("\nConclusion: Repeating plaintext patterns")
    print("result in repeating ciphertext patterns with ECB.")

if __name__ == "__main__":
    # Run both demonstrations
    simple_text_demo()
    print("\n")
    demonstrate_ecb_weakness()