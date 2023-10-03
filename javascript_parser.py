import json
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
		for i in range(len(requests)):
			request_number = i + 1
			data = requests[i]
			
			request_data = data['request_data']
			url = data['url']
			variables = []
			
			# Currently response data is not used. May be None
			# TODO: Add comments in the generated code where needed to provide example response 
			response_data = data['response_data']

			val = self.getHeaders(request_data, request_number)
			cookie_variable = val['cookie_variable'][0]
			cookie_variable_name = val['cookie_variable'][1]
			headers_variable = val['headers_variable'][0]
			headers_variable_name = val['headers_variable'][1]

			body_value = request_data.split('\n\n')[1]
			if body_value.strip() == '':
				body_value = None

			[url_variable, url_variable_name] = self.getUrlVariable(request_number, url)

			variables.append(url_variable)
			if cookie_variable is not None:
				variables.append(cookie_variable)
			if headers_variable is not None:
				variables.append(headers_variable)

			first_header_info = self.getFirstHeaderInfo(request_data)
			method = first_header_info['method']
			version = first_header_info['version']
			[function_code, function_name] = self.getFunctionCode(request_number, variables, method, url_variable_name, headers_variable_name, body_value)
			function_codes.append(function_code)
			function_names.append(function_name)
		
		main_code = self.getMainCode(function_names)
		function_codes.append(main_code)
		code = '\n'.join(function_codes)
		self.copyClipboard(code)

	def getFunctionCode(self, request_number, variables, method, url_variable_name, headers_variable_name=None, body_value=None):
		function_name = 'sendRequest_' + str(request_number)
		code = 'const ' + function_name + ' = async () => {\n'
		for variable in variables:
			code += '\tconst ' + variable + '\n'
		
		code += '\n'
		if body_value is not None:
			body_name = 'body_' + self.randomString() + '_' + str(request_number)
			code += '\tconst ' + body_name + ' = `' + body_value + '`;\n'
		code += '\tconst response = await fetch(' + url_variable_name + ', {\n'
		code += '\t\tmethod: \'' + method + '\',\n'
		if headers_variable_name is not None:
			code += '\t\theaders: ' + headers_variable_name + ',\n'
		if body_value is not None:
			code += '\t\tbody: ' + body_name + '\n'
		code += '\t});\n'
		code += '\n'
		response_text_variable_name = 'responseText_' + self.randomString() + '_' + str(request_number)
		code += '\tconst ' + response_text_variable_name + ' = await response.text();\n'
		code += '\tconsole.log(`' + response_text_variable_name + ':`);\n'
		code += '\tconsole.log(' + response_text_variable_name + ');\n'
		code += '};\n\n'

		return [code, function_name]

	def getMainCode(self, functionNames):
		code = 'const main = async () => {\n'
		for functionName in functionNames:
			code += '\tawait ' + functionName + '();\n'
		code += '}\n\n'
		code += '(() => main())();\n'
		return code
	
	def getHeaders(self, raw_data, request_number=0):
		# Remove GET /  and Host:  from the request header
		headers = raw_data.split('\n\n')[0].split('\n')[2:]
		
		# Change array of "key: value" to json
		headers = [header.split(': ') for header in headers]
		headers = {header[0]: header[1] for header in headers}

		# Replace cookies with variable cookie_{request_numer}
		cookie_variable_name = 'cookie_' + self.randomString() + '_' + str(request_number)
		cookie_variable = None
		if 'Cookie' in headers:
			variable_value = headers['Cookie']
			headers['Cookie'] = cookie_variable_name
			cookie_variable = cookie_variable_name + ' = `' + variable_value + '`;'
		
		headers_variable_name = 'headers_' + self.randomString() + '_' + str(request_number)
		headers_variable = None
		if len(headers) > 0:
			variable_name = headers_variable_name
			variable_value = json.dumps(headers, indent=4).replace('"' + cookie_variable_name + '"', cookie_variable_name).replace('\n', '\n\t')
			headers_variable = variable_name + ' = ' + variable_value + ';'

		return {			
			"cookie_variable": [cookie_variable, cookie_variable_name],
			"headers_variable": [headers_variable, headers_variable_name]
		}

	def getUrlVariable(self, request_number, url):
		variable_name = 'url_' + self.randomString() + '_' + str(request_number)
		variable_value = str(url)
		return [variable_name + ' = `' + variable_value + '`;', variable_name]
