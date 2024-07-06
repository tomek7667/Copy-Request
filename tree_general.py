from tree_url import TreeUrl


class TreeGeneral:
	def __init__(self, request_data, url):
		rd = str(request_data).split("\n")
		self.method = self._get_method(rd)
		self.headers = self._get_headers(rd)
		self.Authorization = self._get_authorization(self.headers)
		self.httpVersion = self._get_http_version(rd)
		self.url = TreeUrl(url)


	def _get_method(self, rd):
		return rd[0].split(" ")[0]

	
	def _get_http_version(self, rd):
		return rd[0].split("/")[-1]


	def _get_headers(self, rd):
		headers = {}
		headers_raw = "\n".join(rd[1:]).split("\n\n")[0]
		for header_line in headers_raw.split("\n"):
			header_name = header_line.split(":")[0].strip()
			header_value = ":".join(
				header_line.split(":")[1:]
			).strip()
			headers[header_name] = header_value
		return headers


	def _get_authorization(self, headers):
		return headers["Authorization"] if "Authorization" in headers else None


	def to_json(self):
		return {
			"method": self.method,
			"headers": self.headers,
			"Authorization": self.Authorization,
			"httpVersion": self.httpVersion,
			"url": self.url.to_json()
		}

