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
    # Discover and run tests
    loader = unittest.TestLoader()
    suite = loader.discover('tests', pattern='test_*.py')
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)