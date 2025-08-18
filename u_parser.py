from burp import IBurpExtender, IContextMenuFactory, IHttpRequestResponse # type: ignore
from java.io import PrintWriter # type: ignore
from java.util import ArrayList # type: ignore
from javax.swing import JMenuItem # type: ignore
from java.awt import Toolkit # type: ignore
from java.awt.datatransfer import StringSelection # type: ignore
from javax.swing import JOptionPane # type: ignore
import random
import string

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

