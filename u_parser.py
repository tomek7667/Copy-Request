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
	def getFirstHeaderInfo(self, raw_data):
		record = raw_data.split('\n\n')[0].split('\n')[0]
		[method, _, version] = record.split(' ')
		return {
			'method': method,
			'version': version
		}

	def randomString(self, length=4):
		return ''.join(random.choice(string.ascii_letters) for _ in range(length))

	def copyClipboard(self, data):
		systemClipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
		transferText = StringSelection(data)
		systemClipboard.setContents(transferText, None)
		if Toolkit.getDefaultToolkit().getSystemSelection() is not None:
			systemSelection = Toolkit.getDefaultToolkit().getSystemSelection()
			systemSelection.setContents(transferText, None)
