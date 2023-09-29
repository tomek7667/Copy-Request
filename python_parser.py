from java.io import PrintWriter
from u_parser import Parser
from common import *

class PythonParser(Parser):
	def __init__(self, callbacks):
		self.callbacks = callbacks
		self.stdout = PrintWriter(callbacks.getStdout(), True)
		self.stderr = PrintWriter(callbacks.getStderr(), True)
		if DEBUG:
			print('PythonParser::__init__: Initialized')

	def parse(self, data):
		self.request_data = data['request_data']
		
		# Currently response data is not used. May be None
		# TODO: Add comments in the generated code where needed to provide example response 
		self.response_data = data['response_data']


		request_headers = self.getHeaders(self.request_data)
		

