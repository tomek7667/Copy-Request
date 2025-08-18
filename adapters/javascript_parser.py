import json
import hashlib
from java.io import PrintWriter # type: ignore
from request_tree import RequestTree
from u_parser import Parser

IMPORTS = """
const fs = require("fs");
"""[1:-1]

UTILS = """
const constructUrl = ({
	parameters,
	path,
	protocol,
	domain,
	port,
}) => {
	const urlSearchParams = new URLSearchParams();
	for (const key in parameters) {
		const value = parameters[key];
		urlSearchParams.set(key, value);
	}
	const parametersStr = urlSearchParams.toString();
	if (parametersStr === "") {
		return `${protocol}://${domain}:${port}${path}`;
	} else {
		return `${protocol}://${domain}:${port}${path}?${parametersStr}`;
	}
}

const constructCookies = (cookieObject) => {
	const cookiesArr = [];
	for (const cookieName in cookieObject) {
		const cookieValue = cookieObject[cookieName];
		cookiesArr.push(`${cookieName}=${cookieValue}`);
	}
	const stringifiedCookies = cookiesArr.join("; ");
	return stringifiedCookies;
}

const constructXWwwFormUrlencoded = (bodyObject) => {
	const formBody = [];
	for (const property in bodyObject) {
		const encodedKey = encodeURIComponent(property);
		const encodedValue = encodeURIComponent(bodyObject[property]);
		const joined = `${encodedKey}=${encodedValue}`;
		formBody.push(joined);
	}
	const stringifiedBody = formBody.join("&");
	return stringifiedBody;
}
"""[1:-1]

class JavascriptParser(Parser):
	def __init__(self, request_trees, callbacks):
		self.callbacks = callbacks
		self.stdout = PrintWriter(callbacks.getStdout(), True)
		self.stderr = PrintWriter(callbacks.getStderr(), True)

		self.imports = ""
		self.functions = [self._get_function_code(request_trees[i], i + 1) for i in range(len(request_trees))]
		self.common_headers = self._get_common_headers()
		self._filter_common_headers()
		self.main = "const main = async () => {\n"
		self.main += "\tconst commonHeaders = " + json.dumps(self.common_headers) + ";"
		self.main +="""
	// const wordlist = fs.readFilesync("rockyou.txt", "utf-8").split("\\n")
	// const len = wordlist.length;
	// for (let i = 0; i < len; i++) {\n"""
		for i in range(len(self.functions)):
			_i = str(i + 1)
			[_, method, headers, body, url, cookies, authorization, files] = self.functions[i]
			self.main += "\tconst method_" + _i + " = \"" + method + "\";\n"
			self.main += "\tconst headers_" + _i  + " = " + json.dumps(headers) + ";\n"
			if body is not None:
				self.main += "\tconst body_" + _i + " = " + json.dumps(body) + ";\n"
			self.main += "\tconst url_" + _i + " = " + json.dumps(url) + ";\n"
			if cookies is not None:
				self.main += "\tconst cookies_" + _i + " = " + json.dumps(cookies) + ";\n"
			if authorization is not None:
				self.main += "\tconst authorization_" + _i + " = \"" + authorization + "\";\n"
			if files is not None:
				for j in range(len(files)):
					_j = str(j + 1)
					self.main += "\t// const data_" + _j + " = btoa(fs.readFileSync(\"" + files[j]["filename"] + "\", \"utf-8\"));\n"
					self.main += "\tconst file_" + _j + " = " + json.dumps(files[j]) + ";\n"
				self.main += "\tconst files_" + _i + " = ["
				files_variables = ", ".join(["file_" + str(j + 1) for j in range(len(files))])
				self.main += files_variables + "];\n"
			self.main += "\tawait request_" + _i + "("
			self.main += "url_" + _i + ", "
			self.main += "method_" + _i + ", "
			self.main += "headers_" + _i + ", "
			if cookies is not None:
				self.main += "cookies_" + _i + ", "
			else:
				self.main += "undefined, "
			if authorization is not None:
				self.main += "authorization_" + _i + ", "
			else:
				self.main += "undefined, "
			if body is not None:
				self.main += "body_" + _i + ", "
			else:
				self.main += "undefined, "
			if files is not None:
				self.main += "files_" + _i + ", "
			else:
				self.main += "undefined, "
			self.main += "commonHeaders);\n"

		self.main += """\t// }
}

(async () => {
	await main()
})();
"""
		
		code = IMPORTS + "\n\n" + UTILS + "\n\n" + "\n".join(
			[func[0] for func in self.functions]
		) + "\n\n" + self.main
		self.copy_clipboard(code)


	def _get_common_headers(self):
		values = []
		hashes = []
		for arr in self.functions:
			headers = arr[2]
			for header_name in headers:
				header_value = headers[header_name]
				hsh = hashlib.sha256(header_name + header_value)
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
		code = "const request_" + str(i) + " = async (\n"
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
		code += "\turlObject,\n"
		code += "\tmethod,\n"
		code += "\theaders,\n"
		code += "\tcookies,\n"
		code += "\tauthorization,\n"
		code += "\tbody,\n"
		code += "\tfiles,\n"
		code += "\tcommonHeaders,\n"
		code += ") => {\n"
		code += "\tconst url = constructUrl(urlObject);\n"
		if arg_cookie is not None:
			code += "\tconst stringifiedCookies = constructCookies(cookies);\n"
		if request_tree.application_json is not None:
			pass
		elif request_tree.application_x_www_form_urlencoded is not None:
			code += "\tconst stringifiedBody = constructXWwwFormUrlencoded(body);\n"
		elif request_tree.multipart_form_data is not None:
			code += "\tconst formData = new FormData();\n"
			code += "\tfor (const file of files) {\n"
			code += "\t\tconst content = atob(file[\"data\"]);\n"
			code += "\t\tconst contentType = file[\"contentType\"];\n"
			code += "\t\tconst blob = new Blob([content], { type: contentType });\n"
			code += "\t\tconst fileName = file[\"filename\"];\n"
			code += "\t\tconst name = file[\"for\"];\n"
			code += "\t\tformData.append(name, blob, fileName);\n"
			code += "\t}\n"
			code += "\tfor (const key in body) {\n"
			code += "\t\tconst value = body[key];\n"
			code += "\t\tformData.append(key, value);\n"
			code += "\t}\n"
			# Removing content type so formData is adding multipart with the boundary
			code += "\tdelete headers[\"Content-Type\"];\n"
			code += "\tdelete commonHeaders[\"Content-Type\"];\n"
		code += "\t\n"
		code += "\tconst response = await fetch(\n"
		code += "\t\turl,\n"
		code += "\t\t{\n"
		code += "\t\t\tmethod,\n"
		# when multipart form data is set, we do not want "Content-Type" header, as it should be set automatically by fetch due to boundaries
		if request_tree.multipart_form_data is not None:
			code += "\t\t\tbody: formData,\n"
			code += "\t\t\theaders: {\n"
			code += "\t\t\t\t...commonHeaders,\n"
			code += "\t\t\t\t...headers,\n"
			if arg_authorization is not None:
				code += "\t\t\t\tAuthorization: authorization,\n"
			if arg_cookie is not None:
				code += "\t\t\t\tCookie: stringifiedCookies,\n"
			code += "\t\t\t}\n"
			code += "\t\t}\n"
			code += "\t);\n"
			code += "\tconst data = await response.json();\n"
			code += "\t// const data = await response.text();\n"
			code += "\t// const buffer = await response.arrayBuffer();\n"
			code += "\t// fs.writeFileSync(\"file_" + str(i) + "\", buffer);\n"
		elif request_tree.application_json is not None:
			code += "\t\t\tbody: JSON.stringify(body),\n"
			code += "\t\t\theaders: {\n"
			code += "\t\t\t\t...commonHeaders,\n"
			code += "\t\t\t\t...headers,\n"
			if arg_authorization is not None:
				code += "\t\t\t\tAuthorization: authorization,\n"
			if arg_cookie is not None:
				code += "\t\t\t\tCookie: stringifiedCookies,\n" 
			code += "\t\t\t}\n"
			code += "\t\t}\n"
			code += "\t);\n"
			code += "\tconst data = await response.json();\n"
			code += "\t// const data = await response.text();\n"
			code += "\treturn data;\n"
		elif request_tree.application_x_www_form_urlencoded is not None:
			code += "\t\t\tbody: stringifiedBody,\n"
			code += "\t\t\theaders: {\n"
			code += "\t\t\t\t...commonHeaders,\n"
			code += "\t\t\t\t...headers,\n"
			if arg_authorization is not None:
				code += "\t\t\t\tAuthorization: authorization,\n"
			if arg_cookie is not None:
				code += "\t\t\t\tCookie: stringifiedCookies,\n" 
			code += "\t\t\t}\n"
			code += "\t\t}\n"
			code += "\t);\n"
			code += "\t// const data = await response.json();\n"
			code += "\tconst data = await response.text();\n"
			code += "\treturn data;\n"
		else:
			code += "\t\t\theaders: {\n"
			code += "\t\t\t\t...commonHeaders,\n"
			code += "\t\t\t\t...headers,\n"
			if arg_authorization is not None:
				code += "\t\t\t\tAuthorization: authorization,\n"
			if arg_cookie is not None:
				code += "\t\t\t\tCookie: stringifiedCookies,\n" 
			code += "\t\t\t}\n"
			code += "\t\t}\n"
			code += "\t);\n"
			code += "\t// const data = await response.json();\n"
			code += "\tconst data = await response.text();\n"
			code += "\treturn data;\n"
		code += "}\n"
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
	
	# TODO: Create stringify method that will json.dumps with correct indentation. can be done in u_parser.py

