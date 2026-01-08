#!/usr/bin/env python
"""
Integration test for the advanced copy feature.
This test verifies that the advanced copy feature correctly converts content types.
"""
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

from request_tree import RequestTree
from adapters.javascript_parser import JavascriptParser
from adapters.python_parser import PythonParser

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

# Mock clipboard
clipboard_data = None
def mock_copy_clipboard(self, data):
    global clipboard_data
    clipboard_data = data

JavascriptParser.copy_clipboard = mock_copy_clipboard
PythonParser.copy_clipboard = mock_copy_clipboard

class TestAdvancedCopy(unittest.TestCase):
    
    def setUp(self):
        self.callbacks = MockCallbacks()
        global clipboard_data
        clipboard_data = None
    
    def test_advanced_json_to_form_javascript(self):
        """Test advanced copy: JSON to form-urlencoded in JavaScript."""
        data = {
            "request_data": 'POST /api/login HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{"username":"testuser","password":"secret123"}',
            "url": MockURL("https://example.com/api/login")
        }
        
        # Create request tree with conversion
        tree = RequestTree(data, self.callbacks, None, True, "application/x-www-form-urlencoded")
        
        # Verify conversion happened
        self.assertIsNone(tree.application_json)
        self.assertIsNotNone(tree.application_x_www_form_urlencoded)
        self.assertEqual(tree.application_x_www_form_urlencoded["username"], "testuser")
        self.assertEqual(tree.general.headers["Content-Type"], "application/x-www-form-urlencoded")
        
        # Generate JavaScript code
        JavascriptParser([tree], self.callbacks, None, True)
        
        # Verify generated code
        self.assertIsNotNone(clipboard_data)
        self.assertIn("constructXWwwFormUrlencoded", clipboard_data)
        self.assertIn("stringifiedBody", clipboard_data)
        self.assertNotIn("JSON.stringify", clipboard_data)
    
    def test_advanced_form_to_json_javascript(self):
        """Test advanced copy: form-urlencoded to JSON in JavaScript."""
        data = {
            "request_data": "POST /api/submit HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\nfield1=value1&field2=value2",
            "url": MockURL("https://example.com/api/submit")
        }
        
        # Create request tree with conversion
        tree = RequestTree(data, self.callbacks, None, True, "application/json")
        
        # Verify conversion happened
        self.assertIsNone(tree.application_x_www_form_urlencoded)
        self.assertIsNotNone(tree.application_json)
        self.assertEqual(tree.application_json["field1"], "value1")
        self.assertEqual(tree.general.headers["Content-Type"], "application/json")
        
        # Generate JavaScript code
        JavascriptParser([tree], self.callbacks, None, True)
        
        # Verify generated code
        self.assertIsNotNone(clipboard_data)
        self.assertIn("JSON.stringify", clipboard_data)
        # Utility function is always included, but should use JSON.stringify in request
        self.assertIn("body: JSON.stringify(body)", clipboard_data)
    
    def test_advanced_json_to_form_python(self):
        """Test advanced copy: JSON to form-urlencoded in Python."""
        data = {
            "request_data": 'POST /api/login HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{"email":"test@example.com","token":"abc123"}',
            "url": MockURL("https://example.com/api/login")
        }
        
        # Create request tree with conversion
        tree = RequestTree(data, self.callbacks, None, True, "application/x-www-form-urlencoded")
        
        # Generate Python code
        PythonParser([tree], self.callbacks, None, True)
        
        # Verify generated code
        self.assertIsNotNone(clipboard_data)
        self.assertIn("construct_x_www_form_urlencoded", clipboard_data)
        self.assertIn("stringified_body", clipboard_data)
        self.assertNotIn("json=body", clipboard_data)
    
    def test_advanced_form_to_json_python(self):
        """Test advanced copy: form-urlencoded to JSON in Python."""
        data = {
            "request_data": "POST /api/data HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\nname=John&age=30",
            "url": MockURL("https://example.com/api/data")
        }
        
        # Create request tree with conversion
        tree = RequestTree(data, self.callbacks, None, True, "application/json")
        
        # Generate Python code
        PythonParser([tree], self.callbacks, None, True)
        
        # Verify generated code - should use json=body parameter
        self.assertIsNotNone(clipboard_data)
        self.assertIn("json=body", clipboard_data)

if __name__ == '__main__':
    unittest.main()
