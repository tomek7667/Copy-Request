from burp import IBurpExtender, IContextMenuFactory, IHttpRequestResponse # type: ignore
from adapters.javascript_parser import JavascriptParser
from adapters.python_parser import PythonParser
from java.io import PrintWriter # type: ignore
from java.util import ArrayList # type: ignore
from javax.swing import JMenuItem, JMenu # type: ignore
from java.awt import Toolkit # type: ignore
from java.awt.datatransfer import StringSelection # type: ignore
from javax.swing import JOptionPane # type: ignore
import json
import subprocess
import tempfile
import threading
import time
import re

from request_tree import RequestTree

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

		print("BurpExtender::registerExtenderCallbacks: " + self.toString() + " loaded successfully!")


	def createMenuItems(self, invocation):
		self.context = invocation
		menu_list = ArrayList()

		menu_list.add(JMenuItem("as javascript fetch",
				actionPerformed=self.copy_js_default))
		
		advanced_menu = JMenu("more...")
		advanced_menu.add(JMenuItem("as javascript fetch (no filtering)",
				actionPerformed=self.copy_js_no_filter))
		advanced_menu.add(JMenuItem("as javascript fetch (custom filtering)",
				actionPerformed=self.copy_js_custom))
		advanced_menu.add(JMenuItem("as python requests",
				actionPerformed=self.copy_python_default))
		advanced_menu.add(JMenuItem("as python requests (no filtering)",
				actionPerformed=self.copy_python_no_filter))
		advanced_menu.add(JMenuItem("as python requests (custom filtering)",
				actionPerformed=self.copy_python_custom))
		
		menu_list.add(advanced_menu)

		return menu_list

	def copy_js_default(self, event):
		self._copy_js_with_filtering(True, None)

	def copy_js_no_filter(self, event):
		self._copy_js_with_filtering(False, None)

	def copy_js_custom(self, event):
		custom_headers = JOptionPane.showInputDialog(
			None,
			"Enter headers to skip (comma-separated):\nExample: User-Agent,Accept,Host",
			"Custom Header Filtering",
			JOptionPane.PLAIN_MESSAGE
		)
		if custom_headers:
			headers_list = [h.strip() for h in custom_headers.split(',') if h.strip()]
			self._copy_js_with_filtering(True, headers_list)
		else:
			self._copy_js_with_filtering(True, None)

	def _copy_js_with_filtering(self, enable_filtering, custom_skip_headers):
		requests = self.getRequestsData()
		request_trees = []
		for request in requests:
			rt = RequestTree(request, self.callbacks, custom_skip_headers, enable_filtering)
			request_trees.append(rt)
		JavascriptParser(request_trees, self.callbacks, custom_skip_headers, enable_filtering)


	def copy_python_default(self, event):
		self._copy_python_with_filtering(True, None)

	def copy_python_no_filter(self, event):
		self._copy_python_with_filtering(False, None)

	def copy_python_custom(self, event):
		custom_headers = JOptionPane.showInputDialog(
			None,
			"Enter headers to skip (comma-separated):\nExample: User-Agent,Accept,Host",
			"Custom Header Filtering",
			JOptionPane.PLAIN_MESSAGE
		)
		if custom_headers:
			headers_list = [h.strip() for h in custom_headers.split(',') if h.strip()]
			self._copy_python_with_filtering(True, headers_list)
		else:
			self._copy_python_with_filtering(True, None)

	def _copy_python_with_filtering(self, enable_filtering, custom_skip_headers):
		requests = self.getRequestsData()
		request_trees = []
		for request in requests:
			rt = RequestTree(request, self.callbacks, custom_skip_headers, enable_filtering)
			request_trees.append(rt)
		self.pythonParser = PythonParser(request_trees, self.callbacks, custom_skip_headers, enable_filtering)


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

