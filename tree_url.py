class TreeUrl:
	def __init__(self, url):
		self.url = url
		self.raw = str(url)
		self.port = url.port
		self.path = str(url.path)
		self.protocol = str(url.protocol)
		self.domain = str(url.host)
		self.parameters = self._get_parameters(
			str(url.query)
		)


	def _get_parameters(self, query):
		parameters = {}
		params = query.split("&")
		for param in params:
			key, value = param.split("=")
			parameters[key] = value
		return parameters


	def to_json(self):
		return {
			"raw": self.raw,
			"parameters": self.parameters,
			"path": self.path,
			"protocol": self.protocol,
			"domain": self.domain,
			"port": self.port
		}

