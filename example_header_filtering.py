#!/usr/bin/env python3
"""
Example demonstrating the header filtering functionality.
This shows how different filtering options affect the generated code.
"""

import sys
import os
from types import ModuleType

# Mock Java modules for standalone execution
class MockPrintWriter:
    def __init__(self, stream, autoflush=True): pass
    def println(self, msg): pass

java_io = ModuleType('java.io')
java_io.PrintWriter = MockPrintWriter
sys.modules['java.io'] = java_io

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tree_general import TreeGeneral

class MockUrl:
    def __init__(self):
        self.protocol = "https"
        self.host = "api.example.com"
        self.port = 443
        self.path = "/api/users"
        self.query = "page=1&limit=10"
    
    def __str__(self):
        return "https://api.example.com:443/api/users?page=1&limit=10"

def main():
    # Sample HTTP request with many headers
    sample_request = """GET /api/users?page=1&limit=10 HTTP/1.1
Host: api.example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
Content-Type: application/json
Cookie: session_id=abc123; user_pref=dark_mode
Connection: keep-alive
Cache-Control: no-cache
Pragma: no-cache
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin

"""

    mock_url = MockUrl()
    
    print("=== Header Filtering Examples ===\n")
    
    # Example 1: No filtering (include all headers)
    print("1. NO FILTERING (all headers included):")
    tree_no_filter = TreeGeneral(sample_request, mock_url, enable_header_filtering=False)
    print(f"   Headers included: {list(tree_no_filter.headers.keys())}")
    print(f"   Total headers: {len(tree_no_filter.headers)}\n")
    
    # Example 2: Default filtering
    print("2. DEFAULT FILTERING (recommended):")
    tree_default = TreeGeneral(sample_request, mock_url, enable_header_filtering=True)
    print(f"   Headers included: {list(tree_default.headers.keys())}")
    print(f"   Total headers: {len(tree_default.headers)}")
    print("   Note: Browser headers filtered out, but Authorization/Content-Type/Cookie kept\n")
    
    # Example 3: Custom filtering
    print("3. CUSTOM FILTERING (only skip User-Agent and Accept):")
    custom_skip = ["User-Agent", "Accept"]
    tree_custom = TreeGeneral(sample_request, mock_url, 
                             custom_skip_headers=custom_skip, enable_header_filtering=True)
    print(f"   Headers included: {list(tree_custom.headers.keys())}")
    print(f"   Total headers: {len(tree_custom.headers)}")
    print("   Note: Only User-Agent and Accept filtered out\n")
    
    # Example 4: Try to filter important headers (should be ignored)
    print("4. CUSTOM FILTERING (trying to skip Authorization - should be ignored):")
    custom_skip_auth = ["Authorization", "Content-Type", "User-Agent"]
    tree_custom_auth = TreeGeneral(sample_request, mock_url,
                                  custom_skip_headers=custom_skip_auth, enable_header_filtering=True)
    print(f"   Headers included: {list(tree_custom_auth.headers.keys())}")
    print(f"   Total headers: {len(tree_custom_auth.headers)}")
    print("   Note: Authorization and Content-Type kept despite being in skip list\n")

if __name__ == "__main__":
    main()