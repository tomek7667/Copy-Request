#!/usr/bin/env python
import sys
import os
import unittest
from io import StringIO

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Mock Burp dependencies
class MockPrintWriter:
    def __init__(self, stream, autoflush=True):
        self.stream = stream
    def println(self, msg): pass
    def print(self, msg): pass

class MockCallbacks:
    def getStdout(self): return StringIO()
    def getStderr(self): return StringIO()

# Mock Java classes
sys.modules['java.io'] = type('MockModule', (), {'PrintWriter': MockPrintWriter})()

if __name__ == '__main__':
    # Change to tests directory
    test_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(test_dir)
    
    # Run tests individually to avoid conflicts
    test_files = [
        'test_content_type_converter.py',
        'test_header_filtering.py',
        'test_tree_general.py', 
        'test_request_tree.py',
        'test_javascript_parser.py',
        'test_advanced_copy.py',
        'test_integration.py'
    ]
    
    total_tests = 0
    total_failures = 0
    total_errors = 0
    
    for test_file in test_files:
        if os.path.exists(test_file):
            print(f"Running {test_file}...")
            # Import and run the test module
            import subprocess
            result = subprocess.run([sys.executable, test_file], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"PASS {test_file}")
                # Count tests from stderr output
                if 'Ran' in result.stderr:
                    test_count = int(result.stderr.split('Ran ')[1].split(' test')[0])
                    total_tests += test_count
            else:
                print(f"FAIL {test_file}")
                total_failures += 1
                print(result.stderr)
    
    print(f"\nRan {total_tests} tests")
    if total_failures > 0:
        print(f"FAILED (failures={total_failures})")
        sys.exit(1)
    else:
        print("OK")
        sys.exit(0)