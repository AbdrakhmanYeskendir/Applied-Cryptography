"""
Run All Tests Script
Executes all test suites in correct order
"""

import sys
import os

def run_all_tests():
    """Run all test suites"""
    print("="*70)
    print("AES IMPLEMENTATION - COMPREHENSIVE TEST SUITE")
    print("="*70)
    
    tests = [
        ("Core AES Tests", "test_aes.py"),
        ("NIST Test Vectors", "nist_vectors.py"),
        ("ECB Weakness Demo", "demo_ecb_simple.py"),
        ("Image ECB Demo", "ecb_image_demo.py")
    ]
    
    all_passed = True
    
    for test_name, test_file in tests:
        print(f"\n{'='*40}")
        print(f"Running: {test_name}")
        print(f"{'='*40}")
        
        if os.path.exists(test_file):
            try:
                # Run the test script
                exec(open(test_file).read())
                print(f"\n✓ {test_name} completed")
            except Exception as e:
                print(f"\n✗ {test_name} failed: {e}")
                all_passed = False
        else:
            print(f"\n  {test_file} not found, skipping")
    
    print(f"\n{'='*70}")
    if all_passed:
        print(" ALL TESTS COMPLETED SUCCESSFULLY!")
    else:
        print(" SOME TESTS FAILED")
    print("="*70)
    
    return all_passed

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)