import json
from java.io import PrintWriter
from tree_general import TreeGeneral

class RequestTree:
	def __init__(self, data, callbacks):
		self.callbacks = callbacks
		self.stdout = PrintWriter(callbacks.getStdout(), True)
		self.stderr = PrintWriter(callbacks.getStderr(), True)
		self.general = TreeGeneral(data["request_data"], data["url"])
		content_type = self.general.headers["Content-Type"] if "Content-Type" in self.general.headers else None
		if content_type is None:
			pass
		elif content_type == "application/json":
			# TODO: Parse json params
			pass
		elif content_type == "application/x-www-form-urlencoded":
			# TODO: Parse x-www-form-urlencoded params
			pass
		elif content_type == "multipart/form-data":
			# TODO: Parse multipart params
			# TODO: Parse self.files
			pass
		else:
			print("Unsupported content type: " + content_type)

		print("loaded request tree")
		print(self.to_json())

	
	def to_json(self):
		return json.dumps({
			"general": self.general.to_json()
		}, indent=4)

