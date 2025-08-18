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

from adapters.javascript_parser import JavascriptParser

class MockRequestTree:
    def __init__(self, method="GET", headers=None, cookies=None, auth=None, url_data=None, body_type=None, body_data=None, files=None):
        self.general = type('obj', (object,), {
            'method': method,
            'headers': headers or {},
            'cookies': cookies,
            'Authorization': auth,
            'url': type('obj', (object,), url_data or {
                'parameters': {},
                'path': '/test',
                'protocol': 'https',
                'domain': 'example.com',
                'port': 443
            })()
        })()
        
        self.application_json = body_data if body_type == 'json' else None
        self.application_x_www_form_urlencoded = body_data if body_type == 'form' else None
        self.multipart_form_data = body_data if body_type == 'multipart' else None
        self.files = files

class MockCallbacks:
    def getStdout(self): return None
    def getStderr(self): return None

# Mock clipboard
clipboard_data = None
def mock_copy_clipboard(self, data):
    global clipboard_data
    clipboard_data = data

JavascriptParser.copy_clipboard = mock_copy_clipboard

class TestJavascriptParser(unittest.TestCase):
    def setUp(self):
        self.callbacks = MockCallbacks()
        global clipboard_data
        clipboard_data = None

    def test_get_request_generation(self):
        tree = MockRequestTree(
            method="GET",
            headers={"User-Agent": "Test"},
            cookies={"session": "abc123"}
        )
        
        JavascriptParser([tree], self.callbacks, None, True)
        
        self.assertIsNotNone(clipboard_data)
        self.assertIn("const request_1 = async", clipboard_data)
        self.assertIn("constructUrl", clipboard_data)
        self.assertIn("fetch(", clipboard_data)

    def test_post_json_generation(self):
        tree = MockRequestTree(
            method="POST",
            headers={"Content-Type": "application/json"},
            auth="Bearer token123",
            body_type="json",
            body_data={"username": "test"}
        )
        
        JavascriptParser([tree], self.callbacks, None, True)
        
        self.assertIn("JSON.stringify(body)", clipboard_data)
        self.assertIn("Authorization: authorization", clipboard_data)

    def test_post_form_generation(self):
        tree = MockRequestTree(
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body_type="form",
            body_data={"key1": "value1"}
        )
        
        JavascriptParser([tree], self.callbacks, None, True)
        
        self.assertIn("constructXWwwFormUrlencoded", clipboard_data)
        self.assertIn("body: stringifiedBody", clipboard_data)

    def test_multipart_generation(self):
        tree = MockRequestTree(
            method="POST",
            headers={"Content-Type": "multipart/form-data"},
            body_type="multipart",
            body_data={"field1": "value1"},
            files=[{"for": "file", "filename": "test.txt", "contentType": "text/plain", "data": "dGVzdA=="}]
        )
        
        JavascriptParser([tree], self.callbacks, None, True)
        
        self.assertIn("new FormData()", clipboard_data)
        self.assertIn("atob(file[\"data\"])", clipboard_data)

if __name__ == '__main__':
    unittest.main()