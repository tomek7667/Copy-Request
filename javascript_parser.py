import json
import base64
from java.io import PrintWriter
from u_parser import Parser
from common import *


class JavascriptParser(Parser):
	def __init__(self, callbacks):
		self.callbacks = callbacks
		self.stdout = PrintWriter(callbacks.getStdout(), True)
		self.stderr = PrintWriter(callbacks.getStderr(), True)


	def parse(self, requests):
		function_names = []
		function_codes = []
		imports = []
		for i in range(len(requests)):
			request_number = i + 1
			data = requests[i]
			
			request_data = data['request_data']
			url = data['url']
			variables = []
			
			# Currently response data is not used. May be None
			# TODO: Add comments in the generated code where needed to provide example response 
			response_data = data['response_data']

			val = self.get_headers(request_data, request_number)
			is_multipart = val["is_multipart"]
			cookie_variable = val['cookie_variable'][0]
			cookie_variable_name = val['cookie_variable'][1]
			headers_variable = val['headers_variable'][0]
			headers_variable_name = val['headers_variable'][1]


			body_value = None
			if len(request_data.split('\n\n')) > 0:
				body_value = "\n\n".join(request_data.split('\n\n')[1:])
				if body_value.strip() == '':
					body_value = None
			[url_variable, url_variable_name] = self.get_url_variable(request_number, url)
			variables.append(url_variable)
			if cookie_variable is not None:
				variables.append(cookie_variable)
			if headers_variable is not None:
				variables.append(headers_variable)
			if is_multipart and self.is_import_present('fs', imports):
				imports.append(('fs', 'fs'))

			first_header_info = self.get_first_header_info(request_data)
			method = first_header_info['method']
			version = first_header_info['version']
			[function_code, function_name] = self.get_function_code(request_number, variables, method, url_variable_name, headers_variable_name, body_value, is_multipart)
			function_codes.append(function_code)
			function_names.append(function_name)
	
		full_code = ""
		import_code = self.get_imports_code(imports)
		main_code = self.get_main_code(function_names)
		function_codes.append(main_code)
		code = '\n'.join(function_codes)

		full_code += import_code
		full_code += code
		self.copy_clipboard(full_code)


	def is_import_present(self, import_name, imports):
		for import_tuple in imports:
			name, npm_name = import_tuple
			if name == import_name:
				return True
		return False


	def get_imports_code(self, imports):
		code = ""
		for import_tuple in imports:
			name, npm_name = import_tuple
			code += "const " + name + " = require(\"{npm_name}\");\n"
		return code


	def get_function_code(self, request_number, variables, method, url_variable_name, headers_variable_name=None, body_value=None, is_multipart=False):
		function_name = 'sendRequest_' + str(request_number)
		code = 'const ' + function_name + ' = async () => {\n'
		for variable in variables:
			code += '\tconst ' + variable + '\n'
		code += '\n'
		body_name = ''

		if is_multipart and body_value is not None:
			form_data_variable = "data_" + self.random_string()
			code += "\tconst " + form_data_variable + " = new FormData();\n"
			# splitter is e.g.: "------WebKitFormBoundaryTbarTOSsRsscN0su"
			splitter = body_value.split("\n")[0]
			for body_part in body_value.split(splitter)[1:]:
				body_part = body_part.strip()
				if body_part == "--" or body_part == "":
					break
				content_disposition = body_part.split("\n")[0]
				content_disposition_name = content_disposition.split('name="')[1].split('"')[0]
				content_type = body_part.split("\n")[1]
				rp = self.random_string()
				if content_type is None or content_type.strip() == "":
					value = "".join(body_part.split("\n")[1:]).strip()
					value_variable_name = 'value_' + rp
					code += '\tconst ' + value_variable_name + ' = `' + value + '`;\n'
					code += '\t' + form_data_variable + '.append(`' + content_disposition_name + '`, ' + value_variable_name + ');\n'
				else:
					file_name = content_disposition.split('filename="')[1].split('"')[0]
					content = u"\n".join(body_part.split("\n")[3:]).encode('utf-8')
					content_type_value = content_type.split(":")[1].strip()
					file_name_variable_name = 'fileName_' + rp
					content_variable_name = 'content_' + rp
					content_type_variable_name = 'contentType_' + rp
					blob_variable_name = 'blob_' + rp
					code += '\tconst ' + file_name_variable_name + ' = `' + file_name + '`;\n'
					code += '\t// const ' + content_variable_name + ' = readFileSync(' + file_name_variable_name + ', "utf-8");\n'
					code += '\tconst ' + content_variable_name + ' = atob("' + base64.b64encode(content).decode() + '");\n'
					code += '\tconst ' + content_type_variable_name + ' = `' + content_type_value + '`;\n'
					code += '\tconst ' + blob_variable_name + ' = new Blob([' + content_variable_name + '], { type: ' + content_type_variable_name + ' });\n';
					code += '\t' + form_data_variable + '.append(`' + content_disposition_name + '`, ' + blob_variable_name + ', ' + file_name_variable_name + ');\n';
				code += '\n'
			code += '\tconst response = await fetch(' + url_variable_name + ', {\n'
			code += '\t\tmethod: "' + method + '",\n'
			if headers_variable_name is not None:
				code += '\t\theaders: {\n\t\t\t...' + headers_variable_name + ',\n\t\t\t'
				code += '"Content-Type": undefined,\n\t},\n\t'
			code += '\t\tbody: ' + form_data_variable + ',\n'
			code += '\t});\n\n'
			response_text_variable_name = 'responseText_' + self.random_string() + '_' + str(request_number)
			code += '\tconst ' + response_text_variable_name + ' = await response.text();\n'
			code += '\tconsole.log(`' + response_text_variable_name + ':`);\n'
			code += '\tconsole.log(' + response_text_variable_name + ');\n'
			code += '};\n\n'

		else:
			if body_value is not None:
				body_name = 'body_' + self.random_string() + '_' + str(request_number)
				code += '\tconst ' + body_name + ' = `' + body_value + '`;\n'
			code += '\tconst response = await fetch(' + url_variable_name + ', {\n'
			code += '\t\tmethod: \'' + method + '\',\n'
			if headers_variable_name is not None:
				code += '\t\theaders: ' + headers_variable_name + ',\n'
			if body_value is not None:
				code += '\t\tbody: ' + body_name + '\n'
			code += '\t});\n'
			code += '\n'
			response_text_variable_name = 'responseText_' + self.random_string() + '_' + str(request_number)
			code += '\tconst ' + response_text_variable_name + ' = await response.text();\n'
			code += '\tconsole.log(`' + response_text_variable_name + ':`);\n'
			code += '\tconsole.log(' + response_text_variable_name + ');\n'
			code += '};\n\n'

		return [code, function_name]


	def get_main_code(self, functionNames):
		code = 'const main = async () => {\n'
		for functionName in functionNames:
			code += '\tawait ' + functionName + '();\n'
		code += '}\n\n'
		code += '(() => main())();\n'
		# TODO: For loop in the comment and additional main function in the comment
		return code


	def get_headers(self, raw_data, request_number=0):
		# Remove GET /  and Host:  from the request header
		headers = raw_data.split('\n\n')[0].split('\n')[2:]
		
		# Change array of "key: value" to json
		headers = [header.split(': ') for header in headers]
		headers = {header[0]: header[1] for header in headers}

		# Replace cookies with variable cookie_{request_numer}
		cookie_variable_name = 'cookie_' + self.random_string() + '_' + str(request_number)
		cookie_variable = None
		if 'Cookie' in headers:
			variable_value = headers['Cookie']
			headers['Cookie'] = cookie_variable_name
			cookie_variable = cookie_variable_name + ' = `' + variable_value + '`;'
		
		headers_variable_name = 'headers_' + self.random_string() + '_' + str(request_number)
		headers_variable = None
		if len(headers) > 0:
			variable_name = headers_variable_name
			variable_value = json.dumps(headers, indent=4).replace('"' + cookie_variable_name + '"', cookie_variable_name).replace('\n', '\n\t')
			headers_variable = variable_name + ' = ' + variable_value + ';'
		is_multipart = "Content-Type" in headers and headers["Content-Type"].startswith("multipart/form-data")
		return {			
			"cookie_variable": [cookie_variable, cookie_variable_name],
			"headers_variable": [headers_variable, headers_variable_name],
			"is_multipart": is_multipart
		}


	def get_url_variable(self, request_number, url):
		variable_name = 'url_' + self.random_string() + '_' + str(request_number)
		variable_value = str(url)
		return [variable_name + ' = `' + variable_value + '`;', variable_name]

