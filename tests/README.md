# Copy-Request Tests

Unit tests for the Copy-Request parsing process with different scenarios.

## Running Tests

```bash
# Run all tests
python tests/run_tests.py

# Run specific test
python tests/test_request_tree.py
python tests/test_javascript_parser.py
python tests/test_python_parser.py
python tests/test_go_parser.py
python tests/test_tree_general.py
python tests/test_header_filtering.py
python tests/test_integration.py
```

The Go parser tests additionally run `gofmt` and `go vet` on the generated code when a Go toolchain is on `PATH`. Those two tests are skipped otherwise.

## Test Coverage

-   **test_request_tree.py** - Tests HTTP request parsing into abstract structure
-   **test_tree_general.py** - Tests HTTP header/method/cookie parsing
-   **test_header_filtering.py** - Tests default/custom/disabled header filtering
-   **test_javascript_parser.py** - Tests JavaScript code generation from parsed requests
-   **test_python_parser.py** - Tests Python code generation from parsed requests
-   **test_go_parser.py** - Tests Go code generation, gofmt formatting and `go vet` compilation
-   **test_integration.py** - End-to-end tests with mock server

## Test Scenarios

-   GET requests with query parameters
-   POST requests with JSON bodies (including nested objects, arrays, null, booleans and floats)
-   POST requests with form-urlencoded bodies
-   POST requests with multipart/form-data and file uploads
-   Cookie parsing
-   Authorization header handling
-   Common header extraction across multiple selected requests
-   Generated JavaScript code syntax validation
-   Generated Go code compiles (`go vet`) and is `gofmt` clean
