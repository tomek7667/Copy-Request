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

# Supported languages for code generation
SUPPORTED_LANGUAGES = ['js', 'python']


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
		advanced_menu.add(JMenuItem("Advanced...",
				actionPerformed=self.copy_advanced))
		
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


	def copy_advanced(self, event):
		"""Show advanced dialog to select language and target content-type."""
		from content_type_converter import ContentTypeConverter
		
		# Get supported content types
		supported_types = ContentTypeConverter.get_supported_conversions()
		content_type_options = "\n".join([str(i+1) + ". " + ct for i, ct in enumerate(supported_types)])
		
		# Show dialog to select target content type
		user_input = JOptionPane.showInputDialog(
			None,
			"Advanced Copy Options:\n\n" +
			"Select target Content-Type (enter number):\n" + content_type_options +
			"\n\nSelect language (js/python):\nExample: 1,js or 2,python",
			"Advanced Copy",
			JOptionPane.PLAIN_MESSAGE
		)
		
		if not user_input:
			return
		
		# Parse user input
		parts = [p.strip() for p in user_input.split(',')]
		if len(parts) != 2:
			JOptionPane.showMessageDialog(
				None,
				"Invalid input. Please use format: number,language\nExample: 1,js",
				"Error",
				JOptionPane.ERROR_MESSAGE
			)
			return
		
		try:
			content_type_index = int(parts[0]) - 1
			language = parts[1].lower()
			
			if content_type_index < 0 or content_type_index >= len(supported_types):
				raise ValueError("Invalid content type selection")
			
			if language not in SUPPORTED_LANGUAGES:
				raise ValueError("Language must be one of: " + ", ".join(SUPPORTED_LANGUAGES))
			
			target_content_type = supported_types[content_type_index]
			
			# Get requests and create request trees with conversion
			requests = self.getRequestsData()
			request_trees = []
			for request in requests:
				rt = RequestTree(request, self.callbacks, None, True, target_content_type)
				request_trees.append(rt)
			
			# Generate code in selected language
			if language == 'js':
				JavascriptParser(request_trees, self.callbacks, None, True)
			else:
				PythonParser(request_trees, self.callbacks, None, True)
				
		except (ValueError, IndexError) as e:
			JOptionPane.showMessageDialog(
				None,
				"Invalid input: " + str(e),
				"Error",
				JOptionPane.ERROR_MESSAGE
			)


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

