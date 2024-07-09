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
			if param.strip() == "":
				continue
			param_split = param.split("=")
			key = self._url_decode(param_split[0])
			value = self._url_decode(
				"=".join(
					param_split[1:]
				)
			)
			parameters[key] = value
		return parameters


	def _url_decode(self, s):
		encoded = str(s)
		result = ""
		i = 0
		while i < len(encoded):
			c = encoded[i]
			if c == '%':
				url_value = int(
					encoded[i+1:i+3],
					16
				)
				result += chr(url_value)
				i += 3
			else:
				result += c
				i += 1
		return result


	def to_json(self):
		return {
			"raw": self.raw,
			"parameters": self.parameters,
			"path": self.path,
			"protocol": self.protocol,
			"domain": self.domain,
			"port": self.port
		}

