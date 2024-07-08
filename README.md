# Copy-Request

Copy your request from Burp to its programmatic equivalent in chosen language.

The extension is currently in development so only manual installation is possible rather than from the BApp store, as this requires [some extensive process](https://portswigger.net/burp/documentation/desktop/extensions/creating/bapp-store-submitting-extensions) to get it deployed there, and further updates are pretty painful.

## Manual Installation

0. Ensure that you have `jython` in burp settings in `Python environment` section selected. If you don', follow [burp Installing Jython or JRuby](https://portswigger.net/burp/documentation/desktop/extensions/installing-extensions) tutorial. 
1. Clone the repository: `git clone https://github.com/tomek7667/Copy-Request.git`
2. Obtain path to the `main.py` file: `<current working director>/Copy-Request/main.py`
3. Open `Extensions` tab in Burp, and hit `Add` button. 
4. Choose `Extension type` to be `Python`
5. Paste the path from `step 2.` into `Extension file` field and click `Next`.

If everything succeeded, you should be able to Right-Click any **request** in burp and click `Extensions > Copy Request > as <language>` button. It will result in the generated code being loaded to your clipboard.
If you have any issues installing/using the extension, please open a new issue and try to describe your issue as accurately and reproducibly as possible. I would love to make the extension most usable and comfortable for you. Also if you found anything in the README that is not clear enough feel free to open new issue and I will try to address it to best of my abillity.

## Supported languages

- [x] JS 
- [ ] Python
- [ ] Go

## Roadmap 

- [x] Copy GET/HEAD requests
- [x] Refactor code to construct an abstract structure that will descripe the request, like the forms etc. Then just pass the abstract structure to different parsers that will generate the code needed to call the requests.
- JS 
    - [x] Copied request is a separate function that is called in main function asynchronously
    - [x] POST request with Content-Type: `application/json`
    - [x] Variable'ized cookie, url and body of a request
    - [x] POST request with Content-Type `application/x-www-form-urlencoded`
    - [x] POST request with Content-Type `multipart/form-data` that will support selecting a file at `"<path_to_file>"`. In JS via `new FormData()`
    - [x] Commented generated code, commented loop with the request with example array or loaded from a file wordlist
    - [ ] Some unit tests that verify the parsing process with different scenarios
    - [ ] CI pipeline that runs the unit tests.
    - [ ] Add optional headers filtering
- Python/Go
    - [ ] Same roadmap as for JS. Will be filled when JS roadmap is finished.

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

- arguments to generated functions have default values of:
    - Cookies as one argument as dict: `{ "a": "1", "b": "2" }`
    - Authorization value *(only after `=`)*
    - Body as one argument as dict: `{ "a": "1", "b": "2" }`
    - Url as a dict constructed from: `{ "parameters": { "a": "b"}, "path": "/a/b/", "protocol": "https", "domain": "example.com", "port": 443 }`
    - Method as a string: `"GET"`
    - *files to be considered*
- when `multipart/form-data` trim Content-Type from headers, files are not passed through the arguments, but already in the function, as `atob` and in the comment the `fs.readFileSync`.
- imports at the beginning of the file
- interpolating all values
- add utility function/s (e.g. construct url)

