# Advanced Copy Feature - Example Usage

This document demonstrates the usage of the Advanced Copy feature.

## Example 1: Converting JSON to form-urlencoded

### Original Request (JSON)
```http
POST /api/login HTTP/1.1
Host: example.com
Content-Type: application/json

{"username":"testuser","password":"secret123"}
```

### Using Advanced Copy
1. Right-click the request in Burp Suite
2. Select: `Extensions > Copy Request > more > Advanced...`
3. Enter: `2,js` (for x-www-form-urlencoded + JavaScript)

### Generated Code (JavaScript)
The extension will generate JavaScript code that sends the same data but as `application/x-www-form-urlencoded`:

```javascript
// Content-Type is automatically changed to application/x-www-form-urlencoded
// Body is converted from JSON to form-encoded format
const body_1 = {"username": "testuser", "password": "secret123"};
// The code will use constructXWwwFormUrlencoded(body) to encode it
```

---

## Example 2: Converting form-urlencoded to JSON

### Original Request (form-urlencoded)
```http
POST /api/submit HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

field1=value1&field2=value2
```

### Using Advanced Copy
1. Right-click the request in Burp Suite
2. Select: `Extensions > Copy Request > more > Advanced...`
3. Enter: `1,python` (for JSON + Python)

### Generated Code (Python)
The extension will generate Python code that sends the same data but as `application/json`:

```python
# Content-Type is automatically changed to application/json
# Body is converted from form-encoded to JSON format
body_1 = {"field1": "value1", "field2": "value2"}

# The code will use json=body to send as JSON
response = requests.request(
    url=url,
    method=method,
    headers=h,
    json=body,
    ...
)
```

---

## Use Cases

1. **API Testing**: Test how an API behaves when receiving different content-types
2. **CTF Challenges**: Quickly convert request formats for challenge solving
3. **Bypass Filters**: Sometimes WAFs or security filters handle different content-types differently
4. **Development**: Quickly test different serialization formats

---

## Supported Conversions

| From | To |
|------|-----|
| application/json | application/x-www-form-urlencoded |
| application/x-www-form-urlencoded | application/json |

---

## Dialog Format

When prompted, enter: `<content-type-number>,<language>`

- Content-Type Numbers:
  - `1` = application/json
  - `2` = application/x-www-form-urlencoded

- Languages:
  - `js` = JavaScript
  - `python` = Python

Examples:
- `1,js` - Convert to JSON, output JavaScript
- `2,python` - Convert to form-urlencoded, output Python
