import json
from java.io import PrintWriter
from request_tree import RequestTree
from u_parser import Parser


class JavascriptParser(Parser):
	def __init__(self, request_trees, callbacks):
		self.callbacks = callbacks
		self.stdout = PrintWriter(callbacks.getStdout(), True)
		self.stderr = PrintWriter(callbacks.getStderr(), True)

		self.imports = ""
		self.functions = [self._get_function_code(request_trees[i], i + 1) for i in range(len(request_trees))]
		self.main = ""

	
	def _get_function_code(self, request_tree, i):
		code = "const request_" + str(i) + " = async ({\n"
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
		# func arguments
		code += "\turlObject: " + json.dumps(arg_url) + ",\n"
		code += "\tmethod: \"" + arg_method + "\",\n"
		if arg_cookie is not None:
			code += "\tcookies: " + json.dumps(arg_cookie) + ",\n"
		if arg_authorization is not None:
			code += "\tauthorization: \"" + arg_authorization + "\",\n"
		if arg_body is not None:
			code += "\tbody: " + json.dumps(arg_body) + ",\n"
		code += "}) => {\n"
		code += "\tconst url = constructUrl(urlObject);\n"
		if arg_cookie is not None:
			# TODO: refactor to be a utils functions at the top, just called here later. Similarly with url form and multipart.
			code += "\tconst cookiesArr = [];\n"
			code += "\tfor (const cookieName in cookies) {\n"
			code += "\t\tconst cookieValue = cookies[cookieName];\n"
			code += "\t\tcookiesArr.push(`${cookieName}=${cookieValue}`);\n"
			code += "\t}\n"
			code += "\tconst stringifiedCookies = cookiesArr.join(\"; \");\n"
		if request_tree.application_json is not None:
			code += "\tconst body = " + json.dumps(arg_body) + ";\n"
		elif request_tree.application_x_www_form_urlencoded is not None:
			# TODO: url encode etc.
			code += "\tconst body = " + json.dumps(arg_body) + ";\n"
			code += "\tconst formBody = [];\n"
			code += "\tfor (const property in body) {\n"
			code += "\t\tconst encodedKey = encodeURIComponent(property);\n"
			code += "\t\tconst encodedValue = encodeURIComponent(body[property]);\n"
			code += "\t\tconst joined = `${encodedKey}=${encodedValue}`;\n"
			code += "\t\tformBody.push(joined);\n"
			code += "\t};\n"
			code += "const stringifiedBody = formBody.join(\"&\");\n"
			pass
		elif request_tree.multipart_form_data is not None:
			raise Exception("not implemented yet")
		code += "\t\n"
		code += "\tconst response = await fetch(\n"
		code += "\t\turl,\n"
		code += "\t\t{\n"
		code += "\t\t\tmethod,\n"
		# when multipart form data is set, we do not want "Content-Type" header, as it should be set automatically by fetch due to boundaries
		if request_tree.multipart_form_data is not None:
			# TODO
			pass
		elif request_tree.application_json is not None:
			# TODO
			pass
		elif request_tree.application_x_www_form_urlencoded is not None:
			# TODO:
			pass
		else:
			_headers_str = json.dumps(request_tree.general.headers)
			code += "\t\t\theaders: {\n"
			code += "\t\t\t\t..." + _headers_str + ",\n"
			if arg_cookie is not None:
				code += "\t\t\tCookie: stringifiedCookies,\n"
			if arg_authorization is not None:
				_authorization_str = request_tree.general.headers["Authorization"].split(" ")[0]
				code += "\t\t\t\tAuthorization: `" + _authorization_str + " ${authorization}`,\n"
			code += "\t});\n"
		# code += "\t\t\t"
		# code += "\t\t\t"

		code += "}\n"
		print("!!!current func code:")
		print(code)
		print("!!!end code")


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

