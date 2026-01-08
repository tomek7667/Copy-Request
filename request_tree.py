import json
import base64
from java.io import PrintWriter # type: ignore
from tree_general import TreeGeneral
from content_type_converter import ContentTypeConverter

class RequestTree:
	def __init__(self, data, callbacks, custom_skip_headers=None, enable_header_filtering=True, target_content_type=None):
		self.callbacks = callbacks
		self.stdout = PrintWriter(callbacks.getStdout(), True)
		self.stderr = PrintWriter(callbacks.getStderr(), True)
		self.general = TreeGeneral(data["request_data"], data["url"], custom_skip_headers, enable_header_filtering)
		content_type = self.general.headers["Content-Type"] if "Content-Type" in self.general.headers else None
		self.target_content_type = target_content_type
		self.original_content_type = content_type
		if content_type is not None and "multipart/form-data" in content_type:
			content_type = "multipart/form-data"
			self.general.headers["Content-Type"] = content_type

		self.application_json = None
		self.application_x_www_form_urlencoded = None
		self.multipart_form_data = None
		self.files = None
		if content_type is None:
			pass
		elif content_type == "application/json":
			self.application_json = {}
			data = data["request_data"].split(
				"\n\n"
			)
			data = "\n\n".join(
				data[1:]
			)	
			self.application_json = json.loads(data)
		elif content_type == "application/x-www-form-urlencoded":
			self.application_x_www_form_urlencoded = {}
			data = data["request_data"].split(
				"\n\n"
			)
			data = "\n\n".join(
				data[1:]
			)
			for pair in data.split("&"):
				key = self._url_decode(
					pair.split("=")[0]
				)
				value = self._url_decode(
					pair.split("=")[1]
				)
				self.application_x_www_form_urlencoded[key] = value

			pass
		elif content_type == "multipart/form-data":
			self.files = []
			self.multipart_form_data = {}
			data = data["request_data"].split(
				"\n\n"
			)
			data = "\n\n".join(
				data[1:]
			)
			splitter = data.split("\n")[0]
			for item in data.split(splitter)[1:-1]:
				param_name = item.split('Content-Disposition: form-data; name="')[1].split('"')[0]
				if "filename" in item.split(param_name)[1]:
					_file_content_type = item.split("Content-Type: ")[1].split("\n")[0]
					_file_name = item.split(param_name)[1].split('filename="')[1].split('"')[0]
					value = "\n".join(
						item.split("\n")[4:-2]
					)
					_file = {
						"for": param_name,
						"filename": _file_name,
						"contentType": _file_content_type,
						"data": base64.b64encode(
							value.encode("utf-8"),
						).decode()
					}
					self.files.append(_file)
				else:
					value = "\n".join(
						item.split("\n")[3:-1]
					)
					self.multipart_form_data[param_name] = value
		else:
			print("Unsupported content type: " + content_type)

		# Apply content-type conversion if target_content_type is specified
		if self.target_content_type is not None and self.target_content_type != content_type:
			self._apply_content_type_conversion()

		print("loaded request tree:")
		print(self.to_json())


	def _url_decode(self, s):
		encoded = str(s)
		result = ""
		i = 0
		while i < len(encoded):
			c = encoded[i]
			if c == '%':
				if i + 2 < len(encoded):
					url_value = int(
						encoded[i+1:i+3],
						16
					)
					result += chr(url_value)
					i += 3
				else:
					result += c
					i += 1
			else:
				result += c
				i += 1
		return result


	def _apply_content_type_conversion(self):
		"""Convert body from original content type to target content type."""
		# Get the current body data
		original_body = None
		if self.application_json is not None:
			original_body = self.application_json
			from_type = "application/json"
		elif self.application_x_www_form_urlencoded is not None:
			original_body = self.application_x_www_form_urlencoded
			from_type = "application/x-www-form-urlencoded"
		elif self.multipart_form_data is not None:
			original_body = self.multipart_form_data
			from_type = "multipart/form-data"
		else:
			# No body to convert
			return
		
		# Convert the body
		converted_body = ContentTypeConverter.convert(
			original_body, 
			from_type, 
			self.target_content_type
		)
		
		# Clear old body data
		self.application_json = None
		self.application_x_www_form_urlencoded = None
		self.multipart_form_data = None
		
		# Set new body data
		if self.target_content_type == "application/json":
			self.application_json = converted_body
		elif self.target_content_type == "application/x-www-form-urlencoded":
			self.application_x_www_form_urlencoded = converted_body
		elif self.target_content_type == "multipart/form-data":
			self.multipart_form_data = converted_body
		
		# Update the Content-Type header
		self.general.headers["Content-Type"] = self.target_content_type
		print("Converted body from " + from_type + " to " + self.target_content_type)


	def to_json(self):
		return json.dumps({
			"general": self.general.to_json(),
			"application/json": self.application_json,
			"application/x-www-form-urlencoded": self.application_x_www_form_urlencoded,
			"multipart/form-data": self.multipart_form_data,
			"files": self.files
		}, indent=4)


	def __repr__(self):
		return self.to_json()

