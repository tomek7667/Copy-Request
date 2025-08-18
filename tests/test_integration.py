import unittest
import sys
import os
import threading
import time
import http.server
import socketserver
import json
from urllib.parse import parse_qs
from types import ModuleType

# Mock Java modules
class MockPrintWriter:
    def __init__(self, stream, autoflush=True): pass
    def println(self, msg): pass

java_io = ModuleType('java.io')
java_io.PrintWriter = MockPrintWriter
java_util = ModuleType('java.util')
java_util.ArrayList = list
java_awt = ModuleType('java.awt')
java_awt.Toolkit = type('Toolkit', (), {'getDefaultToolkit': lambda: type('obj', (), {'getSystemClipboard': lambda: None, 'getSystemSelection': lambda: None})()})
java_awt_datatransfer = ModuleType('java.awt.datatransfer')
java_awt_datatransfer.StringSelection = type('StringSelection', (), {})
javax_swing = ModuleType('javax.swing')
javax_swing.JMenuItem = type('JMenuItem', (), {})
javax_swing.JOptionPane = type('JOptionPane', (), {})

sys.modules['java.io'] = java_io
sys.modules['java.util'] = java_util
sys.modules['java.awt'] = java_awt
sys.modules['java.awt.datatransfer'] = java_awt_datatransfer
sys.modules['javax.swing'] = javax_swing
sys.modules['java'] = ModuleType('java')
burp = ModuleType('burp')
burp.IBurpExtender = type('IBurpExtender', (), {})
burp.IContextMenuFactory = type('IContextMenuFactory', (), {})
burp.IHttpRequestResponse = type('IHttpRequestResponse', (), {})
sys.modules['burp'] = burp

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from request_tree import RequestTree
from adapters.javascript_parser import JavascriptParser

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

class TestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        response = {"method": "GET", "path": self.path, "query": self.path.split('?')[1] if '?' in self.path else ""}
        self.wfile.write(json.dumps(response).encode())
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode()
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        response = {"method": "POST", "body": body, "content_type": self.headers.get('Content-Type')}
        self.wfile.write(json.dumps(response).encode())
    
    def log_message(self, format, *args):
        pass  # Suppress server logs

clipboard_data = None
def mock_copy_clipboard(self, data):
    global clipboard_data
    clipboard_data = data

JavascriptParser.copy_clipboard = mock_copy_clipboard

class TestIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = 8888
        cls.server = socketserver.TCPServer(("", cls.port), TestHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(0.1)  # Give server time to start

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.callbacks = MockCallbacks()
        global clipboard_data
        clipboard_data = None

    def test_end_to_end_get_request(self):
        data = {
            "request_data": f"GET /test?param1=value1 HTTP/1.1\nHost: localhost:{self.port}\nUser-Agent: Test\n\n",
            "url": MockURL(f"http://localhost:{self.port}/test?param1=value1")
        }
        
        tree = RequestTree(data, self.callbacks)
        parser = JavascriptParser([tree], self.callbacks)
        
        self.assertIsNotNone(clipboard_data)
        self.assertIn("const request_1 = async", clipboard_data)
        self.assertIn("constructUrl", clipboard_data)
        self.assertIn(f"localhost:{self.port}", clipboard_data)

    def test_end_to_end_post_json(self):
        json_body = '{"username":"test","password":"pass"}'
        data = {
            "request_data": f"POST /login HTTP/1.1\nHost: localhost:{self.port}\nContent-Type: application/json\n\n{json_body}",
            "url": MockURL(f"http://localhost:{self.port}/login")
        }
        
        tree = RequestTree(data, self.callbacks)
        parser = JavascriptParser([tree], self.callbacks)
        
        self.assertIn("JSON.stringify(body)", clipboard_data)
        self.assertIn("test", clipboard_data)

    def test_generated_code_syntax(self):
        data = {
            "request_data": f"GET /simple HTTP/1.1\nHost: localhost:{self.port}\n\n",
            "url": MockURL(f"http://localhost:{self.port}/simple")
        }
        
        tree = RequestTree(data, self.callbacks)
        parser = JavascriptParser([tree], self.callbacks)
        
        # Basic syntax checks
        self.assertIn("const ", clipboard_data)
        self.assertIn("async ", clipboard_data)
        self.assertIn("await ", clipboard_data)
        self.assertIn("fetch(", clipboard_data)
        # Check for balanced braces
        self.assertEqual(clipboard_data.count('{'), clipboard_data.count('}'))

if __name__ == '__main__':
    unittest.main()