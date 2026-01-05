import json
import hashlib
from java.io import PrintWriter # type: ignore
from request_tree import RequestTree
from u_parser import Parser

IMPORTS = """import requests
import urllib.parse
import socket
import base64
import urllib3.util.connection as urllib3_cn

def _allowed_gai_family():
    return socket.AF_INET

urllib3_cn.allowed_gai_family = _allowed_gai_family
"""

UTILS = """
class UrlObject:
    def __init__(
        self,
        domain: str,
        protocol: str = "http",
        port: int = 80,
        path: str = "/",
        parameters: dict[str, int | str | list[str]] = {},
    ):
        self.domain = domain
        self.protocol = protocol
        self.port = port
        self.path = path
        self.parameters = parameters

    def __str__(self):
        p = str(urllib.parse.urlencode(self.parameters))
        if len(p) == 0:
            return f"{self.protocol}://{self.domain}:{self.port}{self.path}"
        else:
            return f"{self.protocol}://{self.domain}:{self.port}{self.path}?{p}"


def construct_cookies(cookie_object):
    cookies_arr: list[str] = []
    for key, value in cookie_object.items():
        cookies_arr.append(f"{key}={value}")
    return "; ".join(cookies_arr)

def construct_x_www_form_urlencoded(body):
    return urllib.parse.urlencode(body)
"""

class PythonParser(Parser):
	def __init__(self, request_trees, callbacks, custom_skip_headers=None, enable_header_filtering=True):
		self.callbacks = callbacks
		self.stdout = PrintWriter(callbacks.getStdout(), True)
		self.stderr = PrintWriter(callbacks.getStderr(), True)

		self.functions = [self._get_function_code(request_trees[i], i + 1) for i in range(len(request_trees))]
		self.common_headers = self._get_common_headers()
		self._filter_common_headers()
		self.main = "def main():\n"
		self.main += "    common_headers = " + json.dumps(self.common_headers) + "\n"
		self.main += """    # wordlist = open("rockyou.txt", "r").read().split("\\n")
    # l = len(wordlist)
    # for i in range(l):
"""
		for i in range(len(self.functions)):
			_i = str(i + 1)
			[_, method, headers, body, url, cookies, authorization, files] = self.functions[i]
			self.main += "    method_" + _i + " = \"" + method + "\"\n"
			self.main += "    headers_" + _i + " = " + json.dumps(headers) + "\n"
			if body is not None:
				self.main += "    body_" + _i + " = " + json.dumps(body) + "\n"
			self.main += "    url_" + _i + " = UrlObject(\n"
			self.main += "        path=\"" + url["path"] + "\",\n"
			self.main += "        protocol=\"" + url["protocol"] + "\",\n"
			self.main += "        port=" + str(url["port"]) + ",\n"
			self.main += "        domain=\"" + url["domain"] + "\",\n"
			self.main += "        parameters=" + json.dumps(url["parameters"]) + ",\n"
			self.main += "    )\n"
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
			self.main += "    # print(\"res_" + _i + " = \", res_" + _i + ")\n"

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
		code += "    url_object: UrlObject,\n"
		code += "    method: str = \"GET\",\n"
		code += "    headers: dict[str, str] = {},\n"
		code += "    cookies: dict[str, str] = None,\n"
		code += "    authorization: str = None,\n"
		code += "    body: any = None,\n"
		code += "    files: list[dict[str, str]] = None,\n"
		code += "    common_headers: dict[str, str] = {},\n"
		code += ") -> requests.Response:\n"
		code += "    u = str(url_object)\n"
		if arg_cookie is not None:
			code += "    stringified_cookies = construct_cookies(cookies)\n"
		if request_tree.application_json is not None:
			pass
		elif request_tree.application_x_www_form_urlencoded is not None:
			code += "    stringified_body = construct_x_www_form_urlencoded(body)\n"
		elif request_tree.multipart_form_data is not None:
			code += "    files_data = []\n"
			code += "    for file in files:\n"
			code += "        content = base64.b64decode(file[\"data\"])\n"
			code += "        content_type = file[\"contentType\"]\n"
			code += "        file_name = file[\"filename\"]\n"
			code += "        name = file[\"for\"]\n"
			code += "        files_data.append((name, (file_name, content, content_type)))\n"
			code += "    form_data = body\n"
		code += "    h = {**common_headers, **headers}\n"
		if arg_authorization is not None:
			code += "    h[\"Authorization\"] = authorization\n"
		if arg_cookie is not None:
			code += "    h[\"Cookie\"] = stringified_cookies\n"
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
			code += "        files=files_data,\n"
			code += "        data=form_data,\n"
			code += "        allow_redirects=False,\n"
			code += "    )\n"
			code += "    data = response.json()\n"
			code += "    # data = response.text\n"
			code += "    # with open(\"file_" + str(i) + "\", \"wb\") as f:\n"
			code += "    #     f.write(response.content)\n"
		elif request_tree.application_json is not None:
			code += "    response = requests.request(\n"
			code += "        url=u,\n"
			code += "        method=method,\n"
			code += "        headers=h,\n"
			code += "        json=body,\n"
			code += "        allow_redirects=False,\n"
			code += "    )\n"
			code += "    data = response.json()\n"
			code += "    # data = response.text\n"
		elif request_tree.application_x_www_form_urlencoded is not None:
			code += "    response = requests.request(\n"
			code += "        url=u,\n"
			code += "        method=method,\n"
			code += "        headers=h,\n"
			code += "        data=stringified_body,\n"
			code += "        allow_redirects=False,\n"
			code += "    )\n"
			code += "    # data = response.json()\n"
			code += "    data = response.text\n"
		else:
			code += "    response = requests.request(\n"
			code += "        url=u,\n"
			code += "        method=method,\n"
			code += "        headers=h,\n"
			code += "        allow_redirects=False,\n"
			code += "    )\n"
			code += "    # data = response.json()\n"
			code += "    data = response.text\n"
		code += "    return data\n"
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

