import json
from java.io import PrintWriter
from u_parser import Parser
from common import *

class JavascriptParser(Parser):
	def __init__(self, callbacks):
		self.callbacks = callbacks
		self.stdout = PrintWriter(callbacks.getStdout(), True)
		self.stderr = PrintWriter(callbacks.getStderr(), True)
		if DEBUG:
			print('JavascriptParser::__init__: Initialized')

	def parse(self, requests, request_number=0):
		for i in range(len(requests)):
			data = requests[i]
			
			self.request_data = data['request_data']
			self.url = data['url']
			self.variables = []
			
			# Currently response data is not used. May be None
			# TODO: Add comments in the generated code where needed to provide example response 
			self.response_data = data['response_data']

			headers = self.getHeaders(self.request_data, request_number)
			self.variables.extend(headers['variables'])

			first_header_info = self.getFirstHeaderInfo(self.request_data)
			self.method = first_header_info['method']
			self.version = first_header_info['version']
			if DEBUG:
				print('JavascriptParser::parse: url', self.url)
				print('JavascriptParser::parse: method', self.method)
				print('JavascriptParser::parse: version', self.version)
				print('JavascriptParser::parse: variables', self.variables)

			with open('xd.js', 'w+') as f:
				f.write(self.getCode())
				f.close()

	def getCode(self):
		code = ''
		for variable in self.variables:
			code += variable + '\n'
		return code
	
	def getHeaders(self, raw_data, request_number=0):
		# Remove GET /  and Host:  from the request header
		headers = raw_data.split('\n\n')[0].split('\n')[2:]
		if DEBUG:
			print('Parser::extractHeaders: headers', headers)
		
		# Change array of "key: value" to json
		headers = [header.split(': ') for header in headers]
		headers = {header[0]: header[1] for header in headers}
		# Replace cookies with variable cookie_{request_numer}
		cookie_variable_name = 'cookie_' + self.randomString() + '_' + str(request_number)
		cookie_variable = None
		if 'Cookie' in headers:
			print('Parser::extractHeaders: headers', headers['Cookie'])
			variable_value = headers['Cookie']
			headers['Cookie'] = cookie_variable_name
			print('Parser::extractHeaders: headers', headers['Cookie'])
			cookie_variable = cookie_variable_name + ' = `' + variable_value + '`;'
		
		headers_variable_name = 'headers_' + self.randomString() + '_' + str(request_number)
		headers_variable = None
		if len(headers) > 0:
			variable_name = headers_variable_name
			variable_value = json.dumps(headers, indent=4).replace('"' + cookie_variable_name + '"', cookie_variable_name)
			headers_variable = variable_name + ' = ' + variable_value + ';'

		return {			
			"variables": [
				cookie_variable, headers_variable
			]
		}
