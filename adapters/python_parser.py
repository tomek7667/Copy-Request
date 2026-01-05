import json
import hashlib
from java.io import PrintWriter # type: ignore
from request_tree import RequestTree
from u_parser import Parser

IMPORTS = """import requests
import urllib.parse
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any
"""

UTILS = """
class UrlObject:
    \"\"\"URL builder for flexible request construction.\"\"\"
    def __init__(
        self,
        domain: str,
        protocol: str = "http",
        port: int = 80,
        path: str = "/",
        parameters: Optional[Dict[str, Any]] = None,
    ):
        self.domain = domain
        self.protocol = protocol
        self.port = port
        self.path = path
        self.parameters = parameters or {}

    def __str__(self):
        p = urllib.parse.urlencode(self.parameters)
        if not p:
            return f"{self.protocol}://{self.domain}:{self.port}{self.path}"
        return f"{self.protocol}://{self.domain}:{self.port}{self.path}?{p}"
    
    def update_params(self, **kwargs):
        \"\"\"Update URL parameters dynamically.\"\"\"
        self.parameters.update(kwargs)
        return self
    
    def update_path(self, path: str):
        \"\"\"Update URL path.\"\"\"
        self.path = path
        return self


def construct_cookies(cookie_object: Dict[str, str]) -> str:
    \"\"\"Construct cookie header from dictionary.\"\"\"
    return "; ".join(f"{k}={v}" for k, v in cookie_object.items())


def construct_x_www_form_urlencoded(body: Dict[str, Any]) -> str:
    \"\"\"Encode body as application/x-www-form-urlencoded.\"\"\"
    return urllib.parse.urlencode(body)


def execute_parallel_requests(request_func, payloads: List[Any], max_workers: int = 10):
    \"\"\"
    Execute requests in parallel for load testing or fuzzing.
    
    Args:
        request_func: The request function to call
        payloads: List of payloads/parameters to test
        max_workers: Maximum number of concurrent threads
    
    Returns:
        List of (payload, response) tuples
    \"\"\"
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_payload = {executor.submit(request_func, payload): payload 
                            for payload in payloads}
        for future in as_completed(future_to_payload):
            payload = future_to_payload[future]
            try:
                response = future.result()
                results.append((payload, response))
            except Exception as e:
                results.append((payload, f"Error: {str(e)}"))
    return results
"""

class PythonParser(Parser):
	def __init__(self, request_trees, callbacks, custom_skip_headers=None, enable_header_filtering=True):
		self.callbacks = callbacks
		self.stdout = PrintWriter(callbacks.getStdout(), True)
		self.stderr = PrintWriter(callbacks.getStderr(), True)

		self.functions = [self._get_function_code(request_trees[i], i + 1) for i in range(len(request_trees))]
		self.common_headers = self._get_common_headers()
		self._filter_common_headers()
		self.main = """def main():
    \"\"\"
    Main function with all request parameters at the top for easy modification.
    Customize variables below before running.
    \"\"\"
    # ============================================
    # CONFIGURATION - Modify these as needed
    # ============================================
    common_headers = """ + json.dumps(self.common_headers) + """
    
    # For load testing, set max_workers (default: 10 threads)
    # max_workers = 50
    
    # For fuzzing, prepare your payload list
    # payloads = ["' OR '1'='1", "admin' --", "<script>alert(1)</script>"]
    
    # ============================================
    # REQUEST EXECUTION
    # ============================================
"""
		for i in range(len(self.functions)):
			_i = str(i + 1)
			[_, method, headers, body, url, cookies, authorization, files] = self.functions[i]
			self.main += "    \n"
			self.main += "    # Request " + _i + " - Modify these variables\n"
			self.main += "    method_" + _i + " = \"" + method + "\"\n"
			self.main += "    headers_" + _i + " = " + json.dumps(headers) + "\n"
			if body is not None:
				self.main += "    body_" + _i + " = " + json.dumps(body) + "\n"
			self.main += "    url_" + _i + " = UrlObject(\n"
			self.main += "        domain=\"" + url["domain"] + "\",\n"
			self.main += "        protocol=\"" + url["protocol"] + "\",\n"
			self.main += "        port=" + str(url["port"]) + ",\n"
			self.main += "        path=\"" + url["path"] + "\",\n"
			self.main += "        parameters=" + json.dumps(url["parameters"]) + ",\n"
			self.main += "    )\n"
			if cookies is not None:
				self.main += "    cookies_" + _i + " = " + json.dumps(cookies) + "\n"
			if authorization is not None:
				self.main += "    authorization_" + _i + " = \"" + authorization + "\"  # Modify token/credentials here\n"
			if files is not None:
				for j in range(len(files)):
					_j = str(j + 1)
					self.main += "    # data_" + _j + " = base64.b64encode(open(\"" + files[j]["filename"] + "\", \"rb\").read()).decode()\n"
					self.main += "    file_" + _j + " = " + json.dumps(files[j]) + "\n"
				self.main += "    files_" + _i + " = ["
				files_variables = ", ".join(["file_" + str(j + 1) for j in range(len(files))])
				self.main += files_variables + "]\n"
			
			self.main += "    \n"
			self.main += "    # Execute request " + _i + "\n"
			self.main += "    res_" + _i + " = request_" + _i + "(\n"
			self.main += "        url_object=url_" + _i + ",\n"
			self.main += "        method=method_" + _i + ",\n"
			self.main += "        headers=headers_" + _i + ",\n"
			if cookies is not None:
				self.main += "        cookies=cookies_" + _i + ",\n"
			else:
				self.main += "        cookies=None,\n"
			if authorization is not None:
				self.main += "        authorization=authorization_" + _i + ",\n"
			else:
				self.main += "        authorization=None,\n"
			if body is not None:
				self.main += "        body=body_" + _i + ",\n"
			else:
				self.main += "        body=None,\n"
			if files is not None:
				self.main += "        files=files_" + _i + ",\n"
			else:
				self.main += "        files=None,\n"
			self.main += "        common_headers=common_headers,\n"
			self.main += "    )\n"
			self.main += "    print(f\"Request " + _i + " completed: {len(str(res_" + _i + "))} bytes\")\n"
			self.main += "    # Uncomment to see full response:\n"
			self.main += "    # print(res_" + _i + ")\n"

		self.main += """
    # ============================================
    # ADVANCED USAGE EXAMPLES (Uncomment to use)
    # ============================================
    
    # Example 1: Fuzzing with payloads
    # payloads = ["admin", "root", "test"]
    # for payload in payloads:
    #     body_1["username"] = payload  # Inject payload
    #     res = request_1(url_1, method_1, headers_1, cookies_1, authorization_1, body_1, None, common_headers)
    #     print(f"Payload: {payload}, Status: {res}")
    
    # Example 2: Load testing with threading
    # def make_request(iteration):
    #     return request_1(url_1, method_1, headers_1, cookies_1, authorization_1, body_1, None, common_headers)
    # 
    # results = execute_parallel_requests(make_request, range(100), max_workers=20)
    # print(f"Completed {len(results)} requests")
    
    # Example 3: Multiple requests in sequence
    # for i in range(10):
    #     url_1.update_params(id=i)  # Dynamically update URL params
    #     res = request_1(url_1, method_1, headers_1, cookies_1, authorization_1, body_1, None, common_headers)
    #     print(f"Request {i}: {res[:100]}...")


if __name__ == "__main__":
    main()
"""
		
		code = IMPORTS + "\n" + UTILS + "\n" + "\n".join(
			[func[0] for func in self.functions]
		) + "\n" + self.main
		self.copy_clipboard(code)


	def _get_common_headers(self):
		values = []
		hashes = []
		for arr in self.functions:
			headers = arr[2]
			for header_name in headers:
				header_value = headers[header_name]
				hsh = hashlib.sha256((header_name + header_value).encode('utf-8'))
				if hsh not in hashes:
					hashes.append(hsh)
					values.append((header_name, header_value))
		common_headers = {}
		for c in values:
			header_name, header_value = c
			common_headers[header_name] = header_value
		return common_headers


	def _filter_common_headers(self):
		for arr in self.functions:
			headers = arr[2]
			for common_header in self.common_headers:
				if common_header in headers and headers[common_header] == self.common_headers[common_header]:
					del headers[common_header]


	def _get_function_code(self, request_tree, i):
		code = "def request_" + str(i) + "(\n"
		# Args
		arg_cookie = request_tree.general.cookies
		arg_authorization = request_tree.general.Authorization
		arg_body = self._extract_body(request_tree)
		arg_url = {
			"parameters": request_tree.general.url.parameters,
			"path": request_tree.general.url.path,
			"protocol": request_tree.general.url.protocol,
			"domain": request_tree.general.url.domain,
			"port": request_tree.general.url.port
		}
		arg_method = request_tree.general.method
		arg_headers = request_tree.general.headers
		arg_files = request_tree.files
		code += "    url_object: UrlObject,\n"
		code += "    method: str = \"GET\",\n"
		code += "    headers: Optional[Dict[str, str]] = None,\n"
		code += "    cookies: Optional[Dict[str, str]] = None,\n"
		code += "    authorization: Optional[str] = None,\n"
		code += "    body: Optional[Any] = None,\n"
		code += "    files: Optional[List[Dict[str, str]]] = None,\n"
		code += "    common_headers: Optional[Dict[str, str]] = None,\n"
		code += "    timeout: int = 30,\n"
		code += "    verify_ssl: bool = True,\n"
		code += "    proxies: Optional[Dict[str, str]] = None,\n"
		code += ") -> requests.Response:\n"
		code += "    \"\"\"\n"
		code += "    Execute HTTP request with flexible configuration.\n"
		code += "    \n"
		code += "    Args:\n"
		code += "        timeout: Request timeout in seconds (default: 30)\n"
		code += "        verify_ssl: Verify SSL certificates (default: True, set False for testing)\n"
		code += "        proxies: Proxy configuration, e.g., {'http': 'http://proxy:8080', 'https': 'https://proxy:8080'}\n"
		code += "    \"\"\"\n"
		code += "    headers = headers or {}\n"
		code += "    common_headers = common_headers or {}\n"
		code += "    u = str(url_object)\n"
		if arg_cookie is not None:
			code += "    stringified_cookies = construct_cookies(cookies) if cookies else \"\"\n"
		if request_tree.application_json is not None:
			pass
		elif request_tree.application_x_www_form_urlencoded is not None:
			code += "    stringified_body = construct_x_www_form_urlencoded(body) if body else \"\"\n"
		elif request_tree.multipart_form_data is not None:
			code += "    files_data = []\n"
			code += "    if files:\n"
			code += "        for file in files:\n"
			code += "            content = base64.b64decode(file[\"data\"])\n"
			code += "            content_type = file[\"contentType\"]\n"
			code += "            file_name = file[\"filename\"]\n"
			code += "            name = file[\"for\"]\n"
			code += "            files_data.append((name, (file_name, content, content_type)))\n"
			code += "    form_data = body\n"
		code += "    h = {**common_headers, **headers}\n"
		if arg_authorization is not None:
			code += "    if authorization:\n"
			code += "        h[\"Authorization\"] = authorization\n"
		if arg_cookie is not None:
			code += "    if cookies:\n"
			code += "        h[\"Cookie\"] = stringified_cookies\n"
		code += "    \n"
		
		# Build the request
		if request_tree.multipart_form_data is not None:
			# Remove Content-Type for multipart as requests will set it with boundary
			code += "    if \"Content-Type\" in h:\n"
			code += "        del h[\"Content-Type\"]\n"
			code += "    response = requests.request(\n"
			code += "        url=u,\n"
			code += "        method=method,\n"
			code += "        headers=h,\n"
			code += "        files=files_data if files else None,\n"
			code += "        data=form_data,\n"
			code += "        allow_redirects=False,\n"
			code += "        timeout=timeout,\n"
			code += "        verify=verify_ssl,\n"
			code += "        proxies=proxies,\n"
			code += "    )\n"
			code += "    # Return response object for flexibility\n"
			code += "    return response\n"
			code += "    # Uncomment based on expected response type:\n"
			code += "    # return response.json()\n"
			code += "    # return response.text\n"
			code += "    # return response.content\n"
		elif request_tree.application_json is not None:
			code += "    response = requests.request(\n"
			code += "        url=u,\n"
			code += "        method=method,\n"
			code += "        headers=h,\n"
			code += "        json=body,\n"
			code += "        allow_redirects=False,\n"
			code += "        timeout=timeout,\n"
			code += "        verify=verify_ssl,\n"
			code += "        proxies=proxies,\n"
			code += "    )\n"
			code += "    return response\n"
		elif request_tree.application_x_www_form_urlencoded is not None:
			code += "    response = requests.request(\n"
			code += "        url=u,\n"
			code += "        method=method,\n"
			code += "        headers=h,\n"
			code += "        data=stringified_body if body else None,\n"
			code += "        allow_redirects=False,\n"
			code += "        timeout=timeout,\n"
			code += "        verify=verify_ssl,\n"
			code += "        proxies=proxies,\n"
			code += "    )\n"
			code += "    return response\n"
		else:
			code += "    response = requests.request(\n"
			code += "        url=u,\n"
			code += "        method=method,\n"
			code += "        headers=h,\n"
			code += "        allow_redirects=False,\n"
			code += "        timeout=timeout,\n"
			code += "        verify=verify_ssl,\n"
			code += "        proxies=proxies,\n"
			code += "    )\n"
			code += "    return response\n"
		return [
			code,
			arg_method,
			arg_headers,
			arg_body,
			arg_url,
			arg_cookie,
			arg_authorization,
			arg_files,
		]


	def _extract_body(self, request_tree):
		if request_tree.application_json is not None:
			return request_tree.application_json
		elif request_tree.application_x_www_form_urlencoded is not None:
			return request_tree.application_x_www_form_urlencoded
		elif request_tree.multipart_form_data is not None:
			return request_tree.multipart_form_data
		else:
			return None

