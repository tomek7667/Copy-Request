from java.io import PrintWriter # type: ignore
from java.awt import Toolkit # type: ignore
from java.awt.datatransfer import StringSelection # type: ignore
import random
import string
import json

try:
	string_types = (str, unicode)  # Python 2 / Jython
except NameError:
	string_types = (str,)

try:
	integer_types = (int, long)  # Python 2 / Jython
except NameError:
	integer_types = (int,)

# (null, true, false) spellings per target language
JSON_LITERALS = ("null", "true", "false")
PYTHON_LITERALS = ("None", "True", "False")


class Parser:
	def stringify(self, obj, indent_level=1, indent_str="\t", literals=JSON_LITERALS):
		"""Serializes dicts/lists/scalars as a multi-line object literal (same layout as
		json.dumps(indent=...)) whose nested lines are indented so the literal can be
		embedded at `indent_level` of the generated code.

		`literals` selects how None/True/False are spelled, so the same routine
		produces valid JavaScript (JSON) and valid Python literals.
		Works on Jython 2.7 as well.
		"""
		null_literal, true_literal, false_literal = literals
		current = indent_str * indent_level
		inner = indent_str * (indent_level + 1)
		if obj is None:
			return null_literal
		if obj is True:
			return true_literal
		if obj is False:
			return false_literal
		if isinstance(obj, dict):
			if not obj:
				return "{}"
			lines = []
			for key in obj:
				value = self.stringify(obj[key], indent_level + 1, indent_str, literals)
				lines.append(inner + json.dumps(str(key) if not isinstance(key, string_types) else key) + ": " + value)
			return "{\n" + ",\n".join(lines) + "\n" + current + "}"
		if isinstance(obj, (list, tuple)):
			if not obj:
				return "[]"
			lines = [inner + self.stringify(item, indent_level + 1, indent_str, literals) for item in obj]
			return "[\n" + ",\n".join(lines) + "\n" + current + "]"
		if isinstance(obj, integer_types):
			return str(obj)
		if isinstance(obj, float):
			return repr(obj)
		if isinstance(obj, string_types):
			return json.dumps(obj)
		return json.dumps(str(obj))



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

