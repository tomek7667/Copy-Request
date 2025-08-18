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
sys.modules['java'] = ModuleType('java')

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from request_tree import RequestTree

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

class MockCallbacks:
    def getStdout(self): return None
    def getStderr(self): return None

class TestRequestTree(unittest.TestCase):
    def setUp(self):
        self.callbacks = MockCallbacks()

    def test_get_request_parsing(self):
        data = {
            "request_data": "GET /api/test?param1=value1 HTTP/1.1\nHost: example.com\nCookie: session=abc123\n\n",
            "url": MockURL("https://example.com/api/test?param1=value1")
        }
        tree = RequestTree(data, self.callbacks)
        
        self.assertEqual(tree.general.method, "GET")
        self.assertEqual(tree.general.url.path, "/api/test")
        self.assertIsNotNone(tree.general.cookies)
        self.assertEqual(tree.general.cookies["session"], "abc123")

    def test_post_json_parsing(self):
        data = {
            "request_data": 'POST /api/login HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{"username":"test","password":"pass"}',
            "url": MockURL("https://example.com/api/login")
        }
        tree = RequestTree(data, self.callbacks)
        
        self.assertEqual(tree.general.method, "POST")
        self.assertIsNotNone(tree.application_json)
        self.assertEqual(tree.application_json["username"], "test")

    def test_post_form_parsing(self):
        data = {
            "request_data": "POST /api/form HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\nkey1=value1&key2=value%202",
            "url": MockURL("https://example.com/api/form")
        }
        tree = RequestTree(data, self.callbacks)
        
        self.assertEqual(tree.general.method, "POST")
        self.assertIsNotNone(tree.application_x_www_form_urlencoded)
        self.assertEqual(tree.application_x_www_form_urlencoded["key1"], "value1")
        self.assertEqual(tree.application_x_www_form_urlencoded["key2"], "value 2")

if __name__ == '__main__':
    unittest.main()