# Copy-Request Tests

Unit tests for the Copy-Request parsing process with different scenarios.

## Running Tests

```bash
# Run all tests
python tests/run_tests.py

# Run specific test
python tests/test_request_tree.py
python tests/test_javascript_parser.py
python tests/test_tree_general.py
python tests/test_integration.py
```

## Test Coverage

-   **test_request_tree.py** - Tests HTTP request parsing into abstract structure
-   **test_javascript_parser.py** - Tests JavaScript code generation from parsed requests
-   **test_tree_general.py** - Tests HTTP header/method/cookie parsing
-   **test_integration.py** - End-to-end tests with mock server

## Test Scenarios

-   GET requests with query parameters
-   POST requests with JSON bodies
-   POST requests with form-urlencoded bodies
-   POST requests with multipart/form-data
-   Cookie parsing
-   Authorization header handling
-   Generated JavaScript code syntax validation
