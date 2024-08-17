from tree_url import TreeUrl


skip_headers = [
    "Content-Length"
]

class TreeGeneral:
	def __init__(self, request_data, url):
		rd = request_data.split(u"\n")
		self.method = self._get_method(rd)
		self.headers = self._get_headers(rd)
		self.Authorization = self._get_authorization(self.headers)
		self.httpVersion = self._get_http_version(rd)
		self.cookies = self._get_cookies(self.headers)
		self.url = TreeUrl(url)


	def _get_method(self, rd):
		return str(rd[0].split(u" ")[0])

	
	def _get_http_version(self, rd):
		return str(rd[0].split(u"/")[-1])


	def _get_headers(self, rd):
		headers = {}
		headers_raw = u"\n".join(rd[1:]).split(u"\n\n")[0]
		for header_line in headers_raw.split(u"\n"):
			header_name = header_line.split(u":")[0].strip()
			if header_name in skip_headers:
				continue
			header_value = u":".join(
				header_line.split(u":")[1:]
			).strip()
			headers[header_name] = header_value
		return headers


	def _get_authorization(self, headers):
		return headers[u"Authorization"] if u"Authorization" in headers else None


	def _get_cookies(self, headers):
		if u"Cookie" not in headers:
			return None
		else:
			cookies_raw = headers[u"Cookie"]
			_cookies = {}
			for cookie in cookies_raw.split(u";"):
				cookie = cookie.strip()
				if len(cookie) == 0:
					continue
				cookie_name = cookie.split(u"=")[0]
				cookie_value = u"=".join(cookie.split(u"=")[1:])
				_cookies[cookie_name] = cookie_value
			return _cookies


	def to_json(self):
		return {
			"method": self.method,
			"headers": self.headers,
			"Authorization": self.Authorization,
			"httpVersion": self.httpVersion,
			"cookies": self.cookies,
			"url": self.url.to_json()
		}

