# Copy-Request

[![Unit tests](https://github.com/tomek7667/Copy-Request/actions/workflows/test.yml/badge.svg)](https://github.com/tomek7667/Copy-Request/actions/workflows/test.yml)

Copy your request from Burp to its programmatic equivalent in chosen language.

The extension is currently in development so only manual installation is possible rather than from the BApp store, as this requires [some extensive process](https://portswigger.net/burp/documentation/desktop/extensions/creating/bapp-store-submitting-extensions) to get it deployed there, and further updates are pretty painful.

## Manual Installation

0. Ensure that you have `jython` in burp settings in `Python environment` section selected. If you don', follow [burp Installing Jython or JRuby](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/troubleshooting#you-need-to-configure-jython-or-jruby) tutorial.
1. Clone the repository: `git clone https://github.com/tomek7667/Copy-Request.git`
2. Obtain path to the `main.py` file: `<current working director>/Copy-Request/main.py`
3. Open `Extensions` tab in Burp, and hit `Add` button.
4. Choose `Extension type` to be `Python`
5. Paste the path from `step 2.` into `Extension file` field and click `Next`.

## Usage

If everything succeeded, you should be able to Right-Click any **request** in burp and see `Extensions > Copy Request` with the following options:

-   **as javascript fetch** - Default option with recommended header filtering
-   **as python requests (Not yet)** - Python implementation (coming soon)
-   **more** - Expandable menu with additional options:
    -   **as javascript fetch (no filtering)** - Includes all headers from the original request
    -   **as javascript fetch (custom filtering)** - Prompts you to specify which headers to exclude
    -   **as python requests** - Python implementation with default filtering
    -   **as python requests (no filtering)** - Python implementation with all headers
    -   **as python requests (custom filtering)** - Python implementation with custom header filtering
    -   **Advanced...** - Convert request to a different content-type and language

## Advanced Copy Feature

The **Advanced...** option allows you to copy a request with a different content-type than the original. This is useful for testing how APIs handle different content-types or for CTF challenges.

When you select **Advanced...**, you'll be prompted to:
1. Select a target content-type (e.g., `application/json` or `application/x-www-form-urlencoded`)
2. Choose the output language (`js` for JavaScript or `python` for Python)

The extension will automatically:
-   Convert the request body from the original content-type to the target content-type
-   Update the `Content-Type` header accordingly
-   Generate code in your chosen language

**Example usage:**
```
Input: 1,js
```
This converts to `application/json` (option 1) and generates JavaScript code.

**Supported conversions:**
-   JSON ↔ x-www-form-urlencoded

## Header Filtering

The header filtering system helps generate cleaner, more maintainable code:

-   **Default filtering**: Excludes common browser headers like `User-Agent`, `Accept`, `Host`, etc., but always includes important headers like `Authorization`, `Content-Type`, and `Cookie`
-   **No filtering**: Includes all headers from the original request
-   **Custom filtering**: Allows you to specify which headers to exclude via input dialog

Important headers (`Authorization`, `Content-Type`, `Cookie`) are never filtered out, even in custom filtering mode.

If you have any issues installing/using the extension, please open a new issue and try to describe your issue as accurately and reproducibly as possible. I would love to make the extension most usable and comfortable for you. Also if you found anything in the README that is not clear enough feel free to open new issue and I will try to address it to best of my abillity.

## Supported languages

-   [x] JS
-   [ ] Python
-   [ ] Go

## Roadmap

-   [x] Copy GET/HEAD requests
-   [x] Refactor code to construct an abstract structure that will descripe the request, like the forms etc. Then just pass the abstract structure to different parsers that will generate the code needed to call the requests.
-   JS
    -   [x] Copied request is a separate function that is called in main function asynchronously
    -   [x] POST request with Content-Type: `application/json`
    -   [x] Variable'ized cookie, url and body of a request
    -   [x] POST request with Content-Type `application/x-www-form-urlencoded`
    -   [x] POST request with Content-Type `multipart/form-data` that will support selecting a file at `"<path_to_file>"`. In JS via `new FormData()`
    -   [x] Commented generated code, commented loop with the request with example array or loaded from a file wordlist
    -   [x] Create an express JS server that will allow to test manually each request
    -   [x] Some unit tests that verify the parsing process with different scenarios
    -   [x] CI pipeline that runs the unit tests.
    -   [x] Add optional headers filtering
-   Python/Go
    -   [ ] Same roadmap as for JS. Will be filled when JS roadmap is finished.

## Test Server

A comprehensive test server is included to test and log requests made by your generated JavaScript code:

1. Install dependencies: `npm install`
2. Start the server: `npm start`
3. Run your generated code pointing to `http://localhost:3001`
4. Check server console for logged request details

See [TEST-SERVER.md](TEST-SERVER.md) for detailed instructions.

If you have any ideas or improvements that you would like to see in the extension, please open a new issue and I would love to implement it!

### Refactor object

Second point in roadmap example abstract object for parsers:

```json
{
	"general": {
		"method": "GET",
		"headers": {
			"Content-Type": "application/json"
		},
		"Authorization": "Bearer abc",
		"httpVersion": "1.1",
		"url": {
			"raw": "https://example.com/abc/def?param1=value1",
			"parameters": {
				"param1": "value1"
			},
			"path": "/abc/def",
			"protocol": "https",
			"domain": "example.com",
			"port": 443
		},
		"cookies": {
			"key": "value"
		}
	},
	"application/json": {
		"param1": "value1"
	},
	"application/x-www-form-urlencoded": {
		"param1": "value1"
	},
	"multipart/form-data": {
		"param1": "value1"
	},
	"files": [
		{
			"for": "file",
			"filename": "bump.js",
			"contentType": "application/json",
			"data": "base64_data"
		}
	]
}
```

### Notes

Features in code:

-   arguments to generated functions have default values of:
    -   Cookies as one argument as dict: `{ "a": "1", "b": "2" }`
    -   Authorization value _(only after `=`)_
    -   Body as one argument as dict: `{ "a": "1", "b": "2" }`
    -   Url as a dict constructed from: `{ "parameters": { "a": "b"}, "path": "/a/b/", "protocol": "https", "domain": "example.com", "port": 443 }`
    -   Method as a string: `"GET"`
    -   _files to be considered_
-   when `multipart/form-data` trim Content-Type from headers, files are not passed through the arguments, but already in the function, as `atob` and in the comment the `fs.readFileSync`.
-   imports at the beginning of the file
-   interpolating all values
-   add utility function/s (e.g. construct url)
