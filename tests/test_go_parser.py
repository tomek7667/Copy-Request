import unittest
import sys
import os
import shutil
import subprocess
import tempfile
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

from adapters.go_parser import GoParser
from request_tree import RequestTree

GO_AVAILABLE = shutil.which("go") is not None
GOFMT_AVAILABLE = shutil.which("gofmt") is not None


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


class MockURL:
    def __init__(self, protocol, host, port, path, query):
        self.protocol = protocol
        self.host = host
        self.port = port
        self.path = path
        self.query = query

    def __str__(self):
        base = "%s://%s:%d%s" % (self.protocol, self.host, self.port, self.path)
        if self.query:
            return base + "?" + self.query
        return base


class MockCallbacks:
    def getStdout(self): return None
    def getStderr(self): return None


# Mock clipboard
clipboard_data = None
def mock_copy_clipboard(self, data):
    global clipboard_data
    clipboard_data = data

GoParser.copy_clipboard = mock_copy_clipboard


def gofmt(code):
    """Returns (formatted_code, stderr) from gofmt, or None if gofmt is not installed."""
    if not GOFMT_AVAILABLE:
        return None
    proc = subprocess.run(["gofmt"], input=code.encode("utf-8"), capture_output=True)
    return proc.stdout.decode("utf-8"), proc.stderr.decode("utf-8"), proc.returncode


def go_vet(code):
    """Writes the code to a temporary module and runs `go vet`. Returns (returncode, output)."""
    tmp = tempfile.mkdtemp(prefix="copy-request-go-")
    try:
        with open(os.path.join(tmp, "go.mod"), "w", newline="\n") as f:
            f.write("module copyrequest\n\ngo 1.21\n")
        with open(os.path.join(tmp, "main.go"), "w", newline="\n") as f:
            f.write(code)
        env = dict(os.environ)
        env.setdefault("GOFLAGS", "-mod=mod")
        proc = subprocess.run(["go", "vet", "./..."], cwd=tmp, capture_output=True, env=env)
        return proc.returncode, proc.stdout.decode("utf-8") + proc.stderr.decode("utf-8")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


class TestGoParser(unittest.TestCase):
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
        GoParser([tree], self.callbacks, None, True)

        self.assertIsNotNone(clipboard_data)
        self.assertIn("func request_1(", clipboard_data)
        self.assertIn("constructUrl(urlObject)", clipboard_data)
        self.assertIn("return doRequest(method, requestUrl, h, nil)", clipboard_data)
        self.assertIn('h["Cookie"] = constructCookies(cookies)', clipboard_data)
        self.assertIn('cookies_1 := map[string]string{', clipboard_data)
        self.assertIn('"session": "abc123",', clipboard_data)

    def test_post_json_generation(self):
        tree = MockRequestTree(
            method="POST",
            headers={"Content-Type": "application/json"},
            auth="Bearer token123",
            body_type="json",
            body_data={"username": "test", "nested": {"a": [1, 2, {"b": None}]}, "flag": True, "ratio": 1.5}
        )
        GoParser([tree], self.callbacks, None, True)

        self.assertIn("body map[string]interface{},", clipboard_data)
        self.assertIn("constructJsonBody(body)", clipboard_data)
        self.assertIn('h["Authorization"] = authorization', clipboard_data)
        self.assertIn('authorization_1 := "Bearer token123"', clipboard_data)
        self.assertIn("body_1 := map[string]interface{}{", clipboard_data)
        # "flag" is alone in its alignment section (a multi-line value follows), so no padding
        self.assertIn('"flag": true,', clipboard_data)
        # "ratio" and "username" form one section and are aligned like gofmt does
        self.assertIn('"ratio":    1.5,', clipboard_data)
        self.assertIn('"username": "test",', clipboard_data)
        self.assertIn('"b": nil,', clipboard_data)
        self.assertIn("[]interface{}{", clipboard_data)

    def test_post_form_generation(self):
        tree = MockRequestTree(
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body_type="form",
            body_data={"key1": "value1"}
        )
        GoParser([tree], self.callbacks, None, True)

        self.assertIn("body map[string]string,", clipboard_data)
        self.assertIn("constructXWwwFormUrlencoded(body)", clipboard_data)
        self.assertIn("body_1 := map[string]string{", clipboard_data)

    def test_multipart_generation(self):
        tree = MockRequestTree(
            method="POST",
            headers={"Content-Type": "multipart/form-data"},
            body_type="multipart",
            body_data={"field1": "value1"},
            files=[{"for": "file", "filename": "test.txt", "contentType": "text/plain", "data": "dGVzdA=="}]
        )
        GoParser([tree], self.callbacks, None, True)

        self.assertIn("constructMultipartBody(body, files)", clipboard_data)
        self.assertIn('h["Content-Type"] = contentType', clipboard_data)
        self.assertIn("file_1 := FileObject{", clipboard_data)
        self.assertIn('Filename:    "test.txt",', clipboard_data)
        self.assertIn("files_1 := []FileObject{file_1}", clipboard_data)
        self.assertIn('// data_1 := fileToBase64("test.txt")', clipboard_data)

    def test_imports_and_utils_present(self):
        tree = MockRequestTree(method="GET")
        GoParser([tree], self.callbacks, None, True)

        self.assertTrue(clipboard_data.startswith("package main\n"))
        for imp in ['"net/http"', '"net/url"', '"mime/multipart"', '"encoding/json"', '"encoding/base64"', '"sync"']:
            self.assertIn(imp, clipboard_data)
        for fn in ["func constructUrl(", "func constructCookies(", "func constructXWwwFormUrlencoded(",
                   "func constructJsonBody(", "func constructMultipartBody(", "func doRequest(",
                   "func readWordlist(", "func fileToBase64(", "func executeParallelRequests("]:
            self.assertIn(fn, clipboard_data)
        self.assertIn("type UrlObject struct", clipboard_data)
        self.assertIn("type FileObject struct", clipboard_data)

    def test_configuration_constants(self):
        tree = MockRequestTree(method="GET")
        GoParser([tree], self.callbacks, None, True)

        self.assertIn('PROXY_URL = ""', clipboard_data)
        self.assertIn("INSECURE_SKIP_VERIFY = false", clipboard_data)
        self.assertIn("REQUEST_TIMEOUT = 30 * time.Second", clipboard_data)
        self.assertIn("return http.ErrUseLastResponse", clipboard_data)

    def test_main_function_generated(self):
        tree = MockRequestTree(method="GET")
        GoParser([tree], self.callbacks, None, True)

        self.assertIn("func main() {", clipboard_data)
        self.assertIn("res_1, data_1, err := request_1(", clipboard_data)
        self.assertIn('fmt.Println("request_1 failed:", err)', clipboard_data)
        self.assertIn('// wordlist := readWordlist("rockyou.txt")', clipboard_data)
        self.assertIn("// for _, payload := range wordlist {", clipboard_data)

    def test_url_struct_literal(self):
        tree = MockRequestTree(method="GET", url_data={
            'parameters': {"q": "a b", "page": "1"},
            'path': '/search',
            'protocol': 'http',
            'domain': 'localhost',
            'port': 3001
        })
        GoParser([tree], self.callbacks, None, True)

        self.assertIn("url_1 := UrlObject{", clipboard_data)
        self.assertIn('Protocol: "http",', clipboard_data)
        self.assertIn('Domain:   "localhost",', clipboard_data)
        self.assertIn("Port:     3001,", clipboard_data)
        self.assertIn('Path:     "/search",', clipboard_data)
        self.assertIn("Parameters: map[string]string{", clipboard_data)
        self.assertIn('"page": "1",', clipboard_data)
        self.assertIn('"q":    "a b",', clipboard_data)

    def test_empty_parameters_are_aligned_with_other_fields(self):
        tree = MockRequestTree(method="GET")
        GoParser([tree], self.callbacks, None, True)

        self.assertIn('Protocol:   "https",', clipboard_data)
        self.assertIn("Parameters: map[string]string{},", clipboard_data)

    def test_common_headers_extracted(self):
        tree1 = MockRequestTree(method="GET", headers={"X-Common": "1", "X-Only-1": "a"})
        tree2 = MockRequestTree(method="GET", headers={"X-Common": "1", "X-Only-2": "b"})
        GoParser([tree1, tree2], self.callbacks, None, True)

        self.assertIn("commonHeaders := map[string]string{", clipboard_data)
        self.assertIn('"X-Common": "1",', clipboard_data)
        self.assertIn("func request_2(", clipboard_data)
        self.assertIn("res_2, data_2, err := request_2(", clipboard_data)
        # X-Common lives only in commonHeaders
        self.assertEqual(clipboard_data.count('"X-Common": "1",'), 1)

    def test_string_escaping(self):
        tree = MockRequestTree(method="GET", headers={"X-Quote": 'say "hi"\\now'})
        GoParser([tree], self.callbacks, None, True)

        self.assertIn('"X-Quote": "say \\"hi\\"\\\\now",', clipboard_data)

    def test_nil_passed_for_missing_arguments(self):
        tree = MockRequestTree(method="GET")
        GoParser([tree], self.callbacks, None, True)

        call = clipboard_data.split("res_1, data_1, err := request_1(")[1].split(")")[0]
        self.assertIn("nil,\n\t\t\"\",\n\t\tnil,\n\t\tnil,\n\t\tcommonHeaders,", call)

    def _full_tree_set(self):
        boundary = "----WebKitFormBoundaryabc"
        multipart_body = "\n".join([
            "--" + boundary, 'Content-Disposition: form-data; name="field1"', "", "value1",
            "--" + boundary, 'Content-Disposition: form-data; name="file"; filename="hello.txt"', "Content-Type: text/plain", "", "hello world",
            "--" + boundary + "--", ""])
        reqs = [
            {"request_data": "GET /echo?q=1&x=a%20b HTTP/1.1\nHost: localhost:3001\nUser-Agent: UA\nCookie: a=1; b=2\nAuthorization: Bearer tok\n\n",
             "url": MockURL("http", "localhost", 3001, "/echo", "q=1&x=a%20b")},
            {"request_data": 'POST /json HTTP/1.1\nHost: localhost:3001\nContent-Type: application/json\nX-Custom: yes\n\n{"a": 1, "b": "abc", "c": [1, 2, 3], "d": {"test": "t\\"q"}, "e": null, "f": true, "g": 1.5}',
             "url": MockURL("http", "localhost", 3001, "/json", None)},
            {"request_data": "POST /form HTTP/1.1\nHost: localhost:3001\nContent-Type: application/x-www-form-urlencoded\nCookie: s=1\n\nuser=admin&pass=p%40ss",
             "url": MockURL("http", "localhost", 3001, "/form", None)},
            {"request_data": "POST /upload HTTP/1.1\nHost: localhost:3001\nContent-Type: multipart/form-data; boundary=" + boundary + "\n\n" + multipart_body,
             "url": MockURL("http", "localhost", 3001, "/upload", None)},
        ]
        return [RequestTree(r, self.callbacks, None, True) for r in reqs]

    def test_end_to_end_from_raw_requests(self):
        GoParser(self._full_tree_set(), self.callbacks, None, True)

        self.assertIn("func request_4(", clipboard_data)
        self.assertIn('"x": "a b",', clipboard_data)
        self.assertIn('"pass": "p@ss",', clipboard_data)
        self.assertIn('Data:        "aGVsbG8gd29ybGQ=",', clipboard_data)
        self.assertEqual(clipboard_data.count('{'), clipboard_data.count('}'))

    @unittest.skipUnless(GOFMT_AVAILABLE, "gofmt not installed")
    def test_generated_code_is_gofmt_clean(self):
        GoParser(self._full_tree_set(), self.callbacks, None, True)

        formatted, stderr, returncode = gofmt(clipboard_data)
        self.assertEqual(returncode, 0, stderr)
        self.assertEqual(formatted, clipboard_data)

    @unittest.skipUnless(GO_AVAILABLE, "go toolchain not installed")
    def test_generated_code_passes_go_vet(self):
        GoParser(self._full_tree_set(), self.callbacks, None, True)

        returncode, output = go_vet(clipboard_data)
        self.assertEqual(returncode, 0, output)

    @unittest.skipUnless(GO_AVAILABLE, "go toolchain not installed")
    def test_single_get_request_passes_go_vet(self):
        tree = MockRequestTree(method="GET")
        GoParser([tree], self.callbacks, None, True)

        returncode, output = go_vet(clipboard_data)
        self.assertEqual(returncode, 0, output)


if __name__ == '__main__':
    unittest.main()
