import unittest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tree_general import TreeGeneral

class MockURL:
    def __init__(self, url_string):
        parts = url_string.split('://')
        self.protocol = parts[0]
        rest = parts[1]
        if '?' in rest:
            path_part, query_part = rest.split('?', 1)
            self.query = query_part
        else:
            path_part = rest
            self.query = None
        
        if '/' in path_part:
            domain_port, path = path_part.split('/', 1)
            self.path = '/' + path
        else:
            domain_port = path_part
            self.path = '/'
            
        if ':' in domain_port:
            self.host, port_str = domain_port.split(':')
            self.port = int(port_str)
        else:
            self.host = domain_port
            self.port = 443 if self.protocol == 'https' else 80

class TestTreeGeneral(unittest.TestCase):
    def test_method_extraction(self):
        request_data = "POST /api/test HTTP/1.1\nHost: example.com\n\n"
        url = MockURL("https://example.com/api/test")
        
        tree = TreeGeneral(request_data, url)
        self.assertEqual(tree.method, "POST")

    def test_headers_parsing(self):
        request_data = "GET /test HTTP/1.1\nHost: example.com\nUser-Agent: TestAgent\nContent-Type: application/json\n\n"
        url = MockURL("https://example.com/test")
        
        tree = TreeGeneral(request_data, url)
        self.assertEqual(tree.headers["Host"], "example.com")
        self.assertEqual(tree.headers["User-Agent"], "TestAgent")
        self.assertEqual(tree.headers["Content-Type"], "application/json")

    def test_authorization_extraction(self):
        request_data = "GET /test HTTP/1.1\nHost: example.com\nAuthorization: Bearer abc123\n\n"
        url = MockURL("https://example.com/test")
        
        tree = TreeGeneral(request_data, url)
        self.assertEqual(tree.Authorization, "Bearer abc123")

    def test_cookies_parsing(self):
        request_data = "GET /test HTTP/1.1\nHost: example.com\nCookie: session=abc123; user=john\n\n"
        url = MockURL("https://example.com/test")
        
        tree = TreeGeneral(request_data, url)
        self.assertIsNotNone(tree.cookies)
        self.assertEqual(tree.cookies["session"], "abc123")
        self.assertEqual(tree.cookies["user"], "john")

    def test_http_version_extraction(self):
        request_data = "GET /test HTTP/1.1\nHost: example.com\n\n"
        url = MockURL("https://example.com/test")
        
        tree = TreeGeneral(request_data, url)
        self.assertEqual(tree.httpVersion, "1.1")

if __name__ == '__main__':
    unittest.main()