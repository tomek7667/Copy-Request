from burp import IBurpExtender, IContextMenuFactory, IHttpRequestResponse
from java.io import PrintWriter
from java.util import ArrayList
from javax.swing import JMenuItem
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
from javax.swing import JOptionPane
import random
import string
from common import *

class Parser:
	def get_first_header_info(self, raw_data):
		record = raw_data.split('\n\n')[0].split('\n')[0]
		[method, _, version] = record.split(' ')
		return {
			'method': method,
			'version': version
		}

	def random_string(self, length=4):
		return ''.join(random.choice(string.ascii_letters) for _ in range(length))

	def copy_clipboard(self, data):
		system_clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
		transfer_text = StringSelection(data)
		system_clipboard.setContents(transfer_text, None)
		if Toolkit.getDefaultToolkit().getSystemSelection() is not None:
			system_selection = Toolkit.getDefaultToolkit().getSystemSelection()
			system_selection.setContents(transfer_text, None)
