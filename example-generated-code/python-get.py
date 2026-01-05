import requests
import urllib.parse
import socket
import urllib3.util.connection as urllib3_cn

def _allowed_gai_family():
    return socket.AF_INET

urllib3_cn.allowed_gai_family = _allowed_gai_family


class UrlObject:
    def __init__(
        self,
        domain: str,
        protocol: str = "http",
        port: int = 80,
        path: str = "/",
        parameters: dict[str, int | str | list[str]] = {},
    ):
        self.domain = domain
        self.protocol = protocol
        self.port = port
        self.path = path
        self.parameters = parameters

    def __str__(self):
        p = str(urllib.parse.urlencode(self.parameters))
        if len(p) == 0:
            return f"{self.protocol}://{self.domain}:{self.port}{self.path}"
        else:
            return f"{self.protocol}://{self.domain}:{self.port}{self.path}?{p}"


def construct_cookies(cookie_object):
    cookies_arr: list[str] = []
    for key, value in cookie_object.items():
        cookies_arr.append(f"{key}={value}")
    return "; ".join(cookies_arr)

def construct_x_www_form_urlencoded(body):
    return urllib.parse.urlencode(body)

def request_1(
    url_object: UrlObject,
    method: str = "GET",
    headers: dict[str, str] = {},
    cookies: dict[str, str] = None,
    authorization: str = None,
    body: any = None,
    files: list[dict[str, str]] = None,
    common_headers: dict[str, str] = {},
) -> requests.Response:
    u = str(url_object)
    h = {**common_headers, **headers}
    
    response = requests.request(
        url=u,
        method=method,
        headers=h,
        allow_redirects=False,
    )
    # data = response.json()
    data = response.text
    return data

def main():
    common_headers = {"Sec-Ch-Ua": "\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\"", "Sec-Ch-Ua-Platform": "\"macOS\"", "Sec-Ch-Ua-Mobile": "?0"}
    # wordlist = open("rockyou.txt", "r").read().split("\n")
    # l = len(wordlist)
    # for i in range(l):
    method_1 = "GET"
    headers_1 = {}
    url_1 = UrlObject(
        path="/",
        protocol="https",
        port=443,
        domain="example.com",
        parameters={},
    )
    res_1 = request_1(
        url_object=url_1,
        method=method_1,
        headers=headers_1,
        cookies=None,
        authorization=None,
        body=None,
        files=None,
        common_headers=common_headers,
    )
    # print("res_1 = ", res_1)

if __name__ == "__main__":
    main()
