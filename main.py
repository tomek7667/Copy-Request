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

VERSION="1.0.0"
EXT_NAME="Copy Request"

class BurpExtender(IBurpExtender, IContextMenuFactory, IHttpRequestResponse):
	def toString(self):
		return EXT_NAME + " v" + VERSION

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
		self.pythonParser = PythonParser(callbacks)
		self.javascriptParser = JavascriptParser(callbacks)

		print("BurpExtender::registerExtenderCallbacks: " + self.toString() + " loaded successfully!")

	def createMenuItems(self, invocation):
		self.context = invocation
		menuList = ArrayList()

		menuList.add(JMenuItem("as javascript fetch",
				actionPerformed=self.copyJS))
		menuList.add(JMenuItem("as python requests (Not yet)",
				actionPerformed=self.copyPY))

		return menuList

	def copyJS(self, event):
		data = self.getRequestsData()
		self.javascriptParser.parse(data)

	def copyPY(self, event):
		data = self.getRequestsData()
		self.pythonParser.parse(data)

	def getRequestsData(self):
		http_traffic = self.context.getSelectedMessages()

		requests = []
		for message in http_traffic:
			http_request = message.getRequest()
			http_response = message.getResponse()
			url = message.getUrl()

			request_data = self.bytesToString(http_request)
			response_data = self.bytesToString(http_response)

			requests.append({
				"request_data": request_data,
				"response_data": response_data,
				"url": url
			})

		return requests


	def bytesToString(self, data):
		if data is None:
			return None
		data = self.helpers.bytesToString(data).replace('\r\n', '\n')
		return data

