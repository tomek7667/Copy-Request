from burp import IBurpExtender, IContextMenuFactory, IHttpRequestResponse
from python_parser import PythonParser
from javascript_parser import JavascriptParser
from java.io import PrintWriter
from java.util import ArrayList
from javax.swing import JMenuItem
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
from javax.swing import JOptionPane
import json
import subprocess
import tempfile
import threading
import time
import re

VERSION="0.0.0"
EXT_NAME="Copy Request"

class BurpExtender(IBurpExtender, IContextMenuFactory, IHttpRequestResponse):
	def toString(self):
		return EXT_NAME+" v" + VERSION

	def registerExtenderCallbacks(self, callbacks):
		callbacks.setExtensionName(EXT_NAME)
		stdout = PrintWriter(callbacks.getStdout(), True)
		stderr = PrintWriter(callbacks.getStderr(), True)
		self.stdout = stdout
		self.stderr = stderr
		self.helpers = callbacks.getHelpers()
		self.callbacks = callbacks
		callbacks.registerContextMenuFactory(self)

		# Load parsers
		self.pythonParser = PythonParser(stdout, stderr)
		self.javascriptParser = JavascriptParser(stdout, stderr)

		print(self.toString() + " loaded successfully!")

	def createMenuItems(self, invocation):
		self.context = invocation
		menuList = ArrayList()

		menuList.add(JMenuItem("as javascript fetch",
				actionPerformed=self.copyJS))
		menuList.add(JMenuItem("as python requests",
				actionPerformed=self.copyPY))

		return menuList

	def copyJS(self, event):
		print("copyJS", str(event))
		data = self.getRequestData()
		self.javascriptParser.parse(data)

	def copyPY(self, event):
		print("copyPY", str(event))
		data = self.getRequestData()
		self.pythonParser.parse(data)

	def getRequestData(self):
		# TODO: support multiple requests
		http_traffic = self.context.getSelectedMessages()[0]
		http_request = http_traffic.getRequest()
		http_response = http_traffic.getResponse()

		request_data = self.bytesToString(http_request)
		response_data = self.bytesToString(http_response)

		print("request_data", request_data)
		print("response_data", response_data)
		return [request_data, response_data]


	def bytesToString(self, data):
		data = self.helpers.bytesToString(data).replace('\r\n', '\n')
		return data