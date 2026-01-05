import requests
import urllib.parse
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any


class UrlObject:
    """URL builder for flexible request construction."""
    def __init__(
        self,
        domain: str,
        protocol: str = "http",
        port: int = 80,
        path: str = "/",
        parameters: Optional[Dict[str, Any]] = None,
    ):
        self.domain = domain
        self.protocol = protocol
        self.port = port
        self.path = path
        self.parameters = parameters or {}

    def __str__(self):
        p = urllib.parse.urlencode(self.parameters)
        if not p:
            return f"{self.protocol}://{self.domain}:{self.port}{self.path}"
        return f"{self.protocol}://{self.domain}:{self.port}{self.path}?{p}"
    
    def update_params(self, **kwargs):
        """Update URL parameters dynamically."""
        self.parameters.update(kwargs)
        return self
    
    def update_path(self, path: str):
        """Update URL path."""
        self.path = path
        return self


def construct_cookies(cookie_object: Dict[str, str]) -> str:
    """Construct cookie header from dictionary."""
    return "; ".join(f"{k}={v}" for k, v in cookie_object.items())


def construct_x_www_form_urlencoded(body: Dict[str, Any]) -> str:
    """Encode body as application/x-www-form-urlencoded."""
    return urllib.parse.urlencode(body)


def execute_parallel_requests(request_func, payloads: List[Any], max_workers: int = 10):
    """
    Execute requests in parallel for load testing or fuzzing.
    
    Args:
        request_func: The request function to call
        payloads: List of payloads/parameters to test
        max_workers: Maximum number of concurrent threads
    
    Returns:
        List of (payload, response) tuples
    """
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

def request_1(
    url_object: UrlObject,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    authorization: Optional[str] = None,
    body: Optional[Any] = None,
    files: Optional[List[Dict[str, str]]] = None,
    common_headers: Optional[Dict[str, str]] = None,
    timeout: int = 30,
    verify_ssl: bool = True,
    proxies: Optional[Dict[str, str]] = None,
) -> requests.Response:
    """
    Execute HTTP request with flexible configuration.
    
    Args:
        timeout: Request timeout in seconds (default: 30)
        verify_ssl: Verify SSL certificates (default: True, set False for testing)
        proxies: Proxy configuration, e.g., {'http': 'http://proxy:8080', 'https': 'https://proxy:8080'}
    """
    headers = headers or {}
    common_headers = common_headers or {}
    u = str(url_object)
    stringified_cookies = construct_cookies(cookies) if cookies else ""
    stringified_body = construct_x_www_form_urlencoded(body) if body else ""
    h = {**common_headers, **headers}
    if cookies:
        h["Cookie"] = stringified_cookies
    
    response = requests.request(
        url=u,
        method=method,
        headers=h,
        data=stringified_body if body else None,
        allow_redirects=False,
        timeout=timeout,
        verify=verify_ssl,
        proxies=proxies,
    )
    return response

def main():
    """
    Main function with all request parameters at the top for easy modification.
    Customize variables below before running.
    """
    # ============================================
    # CONFIGURATION - Modify these as needed
    # ============================================
    common_headers = {"Content-Type": "application/x-www-form-urlencoded", "Sec-Ch-Ua": "\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\"", "Sec-Ch-Ua-Platform": "\"macOS\"", "Sec-Ch-Ua-Mobile": "?0"}
    
    # For load testing, set max_workers (default: 10 threads)
    # max_workers = 50
    
    # For fuzzing, prepare your payload list
    # payloads = ["' OR '1'='1", "admin' --", "<script>alert(1)</script>"]
    
    # ============================================
    # REQUEST EXECUTION
    # ============================================
    
    # Request 1 - Modify these variables
    method_1 = "POST"
    headers_1 = {}
    body_1 = {"a": "1", "b": "2"}
    url_1 = UrlObject(
        domain="jsonplaceholder.typicode.com",
        protocol="https",
        port=443,
        path="/todos",
        parameters={},
    )
    cookies_1 = {"c": "123"}
    
    # Execute request 1
    res_1 = request_1(
        url_object=url_1,
        method=method_1,
        headers=headers_1,
        cookies=cookies_1,
        authorization=None,
        body=body_1,
        files=None,
        common_headers=common_headers,
    )
    print(f"Request 1 completed: {len(str(res_1))} bytes")
    # Uncomment to see full response:
    # print(res_1)

    # ============================================
    # ADVANCED USAGE EXAMPLES (Uncomment to use)
    # ============================================
    
    # Example 1: Fuzzing with payloads
    # payloads = ["admin", "root", "test"]
    # for payload in payloads:
    #     body_1["username"] = payload  # Inject payload
    #     res = request_1(url_1, method_1, headers_1, cookies_1, authorization_1, body_1, None, common_headers)
    #     print(f"Payload: {payload}, Status: {res}")
    
    # Example 2: Load testing with threading
    # def make_request(iteration):
    #     return request_1(url_1, method_1, headers_1, cookies_1, authorization_1, body_1, None, common_headers)
    # 
    # results = execute_parallel_requests(make_request, range(100), max_workers=20)
    # print(f"Completed {len(results)} requests")
    
    # Example 3: Multiple requests in sequence
    # for i in range(10):
    #     url_1.update_params(id=i)  # Dynamically update URL params
    #     res = request_1(url_1, method_1, headers_1, cookies_1, authorization_1, body_1, None, common_headers)
    #     print(f"Request {i}: {res[:100]}...")


if __name__ == "__main__":
    main()
