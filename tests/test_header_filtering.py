import unittest
import sys
import os
from types import ModuleType

# Mock Java modules
class MockPrintWriter:
    def __init__(self, stream, autoflush=True): pass
    def println(self, msg): pass

java_io = ModuleType('java.io')
java_io.PrintWriter = MockPrintWriter
sys.modules['java.io'] = java_io

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tree_general import TreeGeneral, DEFAULT_SKIP_HEADERS, ALWAYS_INCLUDE_HEADERS

class MockUrl:
    def __init__(self):
        self.protocol = "https"
        self.host = "example.com"
        self.port = 443
        self.path = "/test"
        self.query = "param=value"
    
    def __str__(self):
        return "https://example.com:443/test?param=value"

class TestHeaderFiltering(unittest.TestCase):
    def setUp(self):
        self.sample_request = """GET /test?param=value HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Accept: text/html
Authorization: Bearer token123
Content-Type: application/json
Cookie: session=abc123
Accept-Language: en-US
Connection: keep-alive

"""
        self.mock_url = MockUrl()

    def test_default_header_filtering_enabled(self):
        """Test that default header filtering excludes common headers but keeps important ones"""
        tree = TreeGeneral(self.sample_request, self.mock_url, enable_header_filtering=True)
        
        # Should exclude default skip headers
        self.assertNotIn("User-Agent", tree.headers)
        self.assertNotIn("Accept", tree.headers)
        self.assertNotIn("Accept-Language", tree.headers)
        self.assertNotIn("Connection", tree.headers)
        self.assertNotIn("Host", tree.headers)
        
        # Should always include important headers
        self.assertIn("Authorization", tree.headers)
        self.assertIn("Content-Type", tree.headers)
        self.assertIn("Cookie", tree.headers)

    def test_header_filtering_disabled(self):
        """Test that disabling header filtering includes all headers"""
        tree = TreeGeneral(self.sample_request, self.mock_url, enable_header_filtering=False)
        
        # Should include all headers when filtering is disabled
        self.assertIn("User-Agent", tree.headers)
        self.assertIn("Accept", tree.headers)
        self.assertIn("Authorization", tree.headers)
        self.assertIn("Content-Type", tree.headers)
        self.assertIn("Cookie", tree.headers)
        self.assertIn("Accept-Language", tree.headers)
        self.assertIn("Connection", tree.headers)
        self.assertIn("Host", tree.headers)

    def test_custom_skip_headers(self):
        """Test custom header filtering with specific headers to skip"""
        custom_skip = ["User-Agent", "Accept"]
        tree = TreeGeneral(self.sample_request, self.mock_url, 
                          custom_skip_headers=custom_skip, enable_header_filtering=True)
        
        # Should exclude custom skip headers
        self.assertNotIn("User-Agent", tree.headers)
        self.assertNotIn("Accept", tree.headers)
        
        # Should include headers not in custom skip list
        self.assertIn("Accept-Language", tree.headers)
        self.assertIn("Connection", tree.headers)
        self.assertIn("Host", tree.headers)
        
        # Should always include important headers even if in skip list
        self.assertIn("Authorization", tree.headers)
        self.assertIn("Content-Type", tree.headers)
        self.assertIn("Cookie", tree.headers)

    def test_always_include_headers_override(self):
        """Test that always-include headers are never filtered out"""
        # Try to skip Authorization header (should be ignored)
        custom_skip = ["Authorization", "Content-Type", "Cookie", "User-Agent"]
        tree = TreeGeneral(self.sample_request, self.mock_url,
                          custom_skip_headers=custom_skip, enable_header_filtering=True)
        
        # Always-include headers should still be present
        self.assertIn("Authorization", tree.headers)
        self.assertIn("Content-Type", tree.headers)
        self.assertIn("Cookie", tree.headers)
        
        # Other headers should be filtered
        self.assertNotIn("User-Agent", tree.headers)

if __name__ == '__main__':
    unittest.main()