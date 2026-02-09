AES Implementation - Student Project
Project Overview
Complete implementation of AES-128/192/256 block cipher with multiple modes of operation (ECB, CBC, CTR, GCM) from scratch for educational purposes. Developed as part of Applied Cryptography course assignment.

Features
AES Core: Full implementation according to FIPS 197

Modes of Operation: ECB, CBC, CTR, GCM (AEAD with authentication)

Custom RNG: Mersenne Twister with entropy collection from 5+ sources

GUI Application: Tkinter-based desktop application

Comprehensive Testing: NIST test vectors and functional tests

Educational Demonstrations: ECB weakness visualization with images

Project Structure
text
aes_project/
├── aes_core.py          # Core AES implementation (S-box, key expansion, etc.)
├── aes_modes.py         # Modes of operation (ECB, CBC, CTR, GCM)
├── aes_gui.py           # Graphical user interface
├── test_aes.py          # Comprehensive test suite
├── demo_ecb_simple.py   # ECB weakness demonstration
├── ecb_image_demo.py    # Image encryption demo
├── nist_vectors.py      # NIST test validation
├── run_all_tests.py     # Test runner
├── README.md            # This file
└── requirements.txt     # Dependencies
Quick Start
Prerequisites
Python 3.8 or higher

Tkinter (usually included with Python)

Run GUI Application
text
python aes_gui.py
Run All Tests
text
python run_all_tests.py
Demonstrate ECB Weakness
text
python ecb_image_demo.py
GUI Usage Guide
1. Setup
Select key size: 128, 192, or 256 bits

Select mode: ECB, CBC, CTR, or GCM

Enter key (hex format) or click "Generate"

2. Encrypt Text
Type text in Input area

Click "Encrypt →"

View hex output in Output area

3. Decrypt Text
Paste hex ciphertext in Input area

Click "← Decrypt"

View decrypted text

4. File Operations
Encrypt File: Click "Encrypt File..." button

Decrypt File: Click "Decrypt File..." button

5. Educational Features
Test: Quick test with sample data

Show ECB Weakness: Explanation of ECB mode vulnerability

Generate: Create random key using custom RNG

Testing
Run All Tests
text
python test_aes.py
Test Categories
Custom RNG: Tests entropy collection and random generation

Basic AES: Core encryption/decryption

ECB Mode: Electronic Codebook mode

CBC Mode: Cipher Block Chaining mode

CTR Mode: Counter mode (stream cipher)

GCM Mode: Authenticated encryption

Key Sizes: 128, 192, 256-bit keys

Large Data: 100KB file encryption

NIST Validation
text
python -c "from aes_core import validate_nist_test_vectors; validate_nist_test_vectors()"
Educational Demonstrations
ECB Mode Weakness
Run to see why ECB should not be used for structured data:

text
python demo_ecb_simple.py
python ecb_image_demo.py
Creates PPM images showing:

Original patterned image

ECB encrypted image (patterns visible!)

Decrypted image (matches original)

RNG Entropy Collection
The custom RNG demonstrates:

Multiple entropy sources collection

Real-time entropy quality analysis

User input timing measurement (required by assignment)

Security Disclaimer
WARNING: This implementation is for EDUCATIONAL PURPOSES ONLY.

DO NOT use for:

Protecting sensitive data

Production systems

Any real-world security applications

Always use professionally audited cryptographic libraries like:

PyCryptodome (Python)

Bouncy Castle (Java)

OpenSSL (C/C++)

Technical Details
AES Implementation
S-box: Precomputed lookup tables (FIPS 197)

Key Expansion: Full for 128/192/256 bits (44/52/60 words)

Transformations: SubBytes, ShiftRows, MixColumns, AddRoundKey

Galois Field: GF(2^8) multiplication with irreducible polynomial

Random Number Generation
Algorithm: Mersenne Twister (MT19937)

Entropy Sources:

System time (nanoseconds)
User input timing (REQUIRED by assignment)
Process ID
System randomness
Object memory addresses
Seed Size: 64-bit mixed entropy

Modes of Operation
Mode	Description	Padding	Authentication
ECB	Electronic Codebook	PKCS#7	No
CBC	Cipher Block Chaining	PKCS#7	No
CTR	Counter Mode	None	No
GCM	Galois/Counter Mode	None	Yes (128-bit tag)
Troubleshooting
Common Issues
"ModuleNotFoundError: No module named 'tkinter'"

text
# Ubuntu/Debian:
sudo apt-get install python3-tk

# macOS:
brew install python-tk

# Windows: Usually included
"Invalid key length"

Use correct key sizes: 16 bytes (128-bit), 24 bytes (192-bit), or 32 bytes (256-bit)

Enter in hex format (e.g., 00112233445566778899aabbccddeeff)

GUI not responding

Ensure all files are in same directory

Check Python version (3.8+ required)

Platform Support
Windows: Fully supported

macOS: Requires Tkinter installation

Linux: Requires python3-tk package

Performance Notes
Expected performance on modern CPU:

AES-128: ~10-50 MB/s (Python implementation)

File encryption: Depends on size and mode

Memory usage: Minimal (streaming for large files)

Note: This is an educational implementation, not optimized for speed.

Learning Resources
References
FIPS 197: Advanced Encryption Standard (AES)

NIST SP 800-38A: Recommendation for Block Cipher Modes of Operation

NIST SP 800-38D: Recommendation for GCM Mode

Code Examples
python
# Basic encryption example
from aes_modes import cbc_encrypt, cbc_decrypt

key = b"SixteenByteKey123"
plaintext = b"Secret message"

# Encrypt
ciphertext = cbc_encrypt(plaintext, key, 128)

# Decrypt
decrypted = cbc_decrypt(ciphertext, key, 128)
assert decrypted == plaintext  # Should pass
Student Information
Course: Applied Cryptography
Assignment: Student Independent Study 1
Purpose: Educational implementation of AES from scratch
Constraint: No cryptographic libraries permitted - all code written from scratch

License
Educational Use Only - Not for commercial or production use. See assignment guidelines for academic integrity requirements.

Project Status: Complete - All requirements implemented and tested

requirements.txt:

# AES Implementation - Requirements
# No external dependencies required for basic functionality
# All code uses Python standard library