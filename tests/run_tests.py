#!/usr/bin/env python
"""
Simple test runner for Copy-Request parsing tests
"""
import sys
import os
import subprocess
from types import ModuleType

# Mock Java modules before any imports
class MockPrintWriter:
    def __init__(self, stream, autoflush=True):
        pass
    def println(self, msg): pass
    def print(self, msg): pass

# Create mock modules
java_io = ModuleType('java.io')
java_io.PrintWriter = MockPrintWriter
sys.modules['java.io'] = java_io
sys.modules['java'] = ModuleType('java')
sys.modules['java.util'] = ModuleType('java.util')
sys.modules['javax.swing'] = ModuleType('javax.swing')
sys.modules['java.awt'] = ModuleType('java.awt')
sys.modules['java.awt.datatransfer'] = ModuleType('java.awt.datatransfer')
sys.modules['burp'] = ModuleType('burp')

def run_tests():
    test_dir = os.path.dirname(os.path.abspath(__file__))
    
    print("Running Copy-Request Parser Tests")
    print("=" * 40)
    
    # Run individual test files
    test_files = [
        "test_request_tree.py",
        "test_javascript_parser.py", 
        "test_tree_general.py",
        "test_integration.py"
    ]
    
    total_passed = 0
    total_failed = 0
    
    for test_file in test_files:
        test_path = os.path.join(test_dir, test_file)
        if os.path.exists(test_path):
            print(f"\nRunning {test_file}...")
            try:
                result = subprocess.run([sys.executable, test_path], 
                                      capture_output=True, text=True, cwd=test_dir)
                if result.returncode == 0:
                    print(f"PASS {test_file}")
                    total_passed += 1
                else:
                    print(f"FAIL {test_file}")
                    print(result.stderr)
                    total_failed += 1
            except Exception as e:
                print(f"ERROR {test_file}: {e}")
                total_failed += 1
    
    print("\n" + "=" * 40)
    print(f"Results: {total_passed} passed, {total_failed} failed")
    
    return total_failed == 0

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)