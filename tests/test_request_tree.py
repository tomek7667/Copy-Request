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

    def _multipart_request(self, parts):
        boundary = "----WebKitFormBoundaryTEST"
        lines = []
        for part in parts:
            lines.append("--" + boundary)
            lines.extend(part)
        lines.append("--" + boundary + "--")
        lines.append("")
        body = "\n".join(lines)
        return {
            "request_data": "POST /upload HTTP/1.1\nHost: example.com\nContent-Type: multipart/form-data; boundary=" + boundary + "\n\n" + body,
            "url": MockURL("https://example.com/upload")
        }

    def test_multipart_parsing_fields_and_files(self):
        import base64
        data = self._multipart_request([
            ['Content-Disposition: form-data; name="title"', "", "my upload"],
            # a field literally named "file" must not be mistaken for a file upload
            ['Content-Disposition: form-data; name="file"', "", "not a file"],
            ['Content-Disposition: form-data; name="attachment"; filename="notes.txt"', "Content-Type: text/plain", "", "hello world"],
        ])
        tree = RequestTree(data, self.callbacks)

        self.assertEqual(tree.general.headers["Content-Type"], "multipart/form-data")
        self.assertEqual(tree.multipart_form_data, {"title": "my upload", "file": "not a file"})
        self.assertEqual(len(tree.files), 1)
        self.assertEqual(tree.files[0]["for"], "attachment")
        self.assertEqual(tree.files[0]["filename"], "notes.txt")
        self.assertEqual(tree.files[0]["contentType"], "text/plain")
        self.assertEqual(base64.b64decode(tree.files[0]["data"]).decode(), "hello world")

    def test_multipart_parsing_multiline_values(self):
        import base64
        data = self._multipart_request([
            ['Content-Disposition: form-data; name="text"', "", "line 1", "", "line 3"],
            ['Content-Disposition: form-data; name="f"; filename="a.csv"', "Content-Type: text/csv", "", "a,b", "1,2", ""],
        ])
        tree = RequestTree(data, self.callbacks)

        self.assertEqual(tree.multipart_form_data["text"], "line 1\n\nline 3")
        # trailing newline inside the file content is preserved
        self.assertEqual(base64.b64decode(tree.files[0]["data"]).decode(), "a,b\n1,2\n")

    def test_multipart_file_without_content_type(self):
        data = self._multipart_request([
            ['Content-Disposition: form-data; name="f"; filename="blob.bin"', "", "xyz"],
        ])
        tree = RequestTree(data, self.callbacks)

        self.assertEqual(tree.files[0]["contentType"], "application/octet-stream")
        self.assertEqual(tree.multipart_form_data, {})

if __name__ == '__main__':
    unittest.main()