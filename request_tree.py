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

		self.application_json = None
		self.application_x_www_form_urlencoded = None
		self.multipart_form_data = None
		if content_type is None:
			pass
		elif content_type == "application/json":
			data = data["request_data"].split(
				"\n\n"
			)
			data = "\n\n".join(
				data[1:]
			)	
			self.application_json = json.loads(data)
		elif content_type == "application/x-www-form-urlencoded":
			# TODO: Parse x-www-form-urlencoded params
			pass
		elif content_type == "multipart/form-data":
			# TODO: Parse multipart params
			# TODO: Parse self.files
			pass
		else:
			print("Unsupported content type: " + content_type)

		print("loaded request tree:")
		print(self.to_json())

	
	def to_json(self):
		return json.dumps({
			"general": self.general.to_json(),
			"application/json": self.application_json,
		}, indent=4)

