import json
import math
import hashlib
from java.io import PrintWriter # type: ignore
from request_tree import RequestTree
from u_parser import Parser

try:
	string_types = (str, unicode)  # Python 2 / Jython
except NameError:
	string_types = (str,)

try:
	integer_types = (int, long)  # Python 2 / Jython
except NameError:
	integer_types = (int,)


IMPORTS = """package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)
"""

UTILS = """
// Configuration
const (
	// Set to e.g. "http://127.0.0.1:8080" to route traffic through Burp.
	PROXY_URL = ""
	// Set to true to accept self-signed certificates.
	INSECURE_SKIP_VERIFY = false
	// Request timeout.
	REQUEST_TIMEOUT = 30 * time.Second
)

type UrlObject struct {
	Protocol   string
	Domain     string
	Port       int
	Path       string
	Parameters map[string]string
}

type FileObject struct {
	For         string
	Filename    string
	ContentType string
	Data        string // base64 encoded content
}

type Result struct {
	Response *http.Response
	Body     []byte
	Err      error
}

var httpClient = newHttpClient()

func newHttpClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: INSECURE_SKIP_VERIFY},
	}
	if PROXY_URL != "" {
		proxyUrl, err := url.Parse(PROXY_URL)
		if err != nil {
			panic(err)
		}
		transport.Proxy = http.ProxyURL(proxyUrl)
	}
	return &http.Client{
		Transport: transport,
		Timeout:   REQUEST_TIMEOUT,
		// Do not follow redirects, so the raw response can be inspected.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func constructUrl(urlObject UrlObject) string {
	query := url.Values{}
	for key, value := range urlObject.Parameters {
		query.Set(key, value)
	}
	result := fmt.Sprintf("%s://%s:%d%s", urlObject.Protocol, urlObject.Domain, urlObject.Port, urlObject.Path)
	encoded := query.Encode()
	if encoded != "" {
		result += "?" + encoded
	}
	return result
}

func constructCookies(cookieObject map[string]string) string {
	cookies := make([]string, 0, len(cookieObject))
	for name, value := range cookieObject {
		cookies = append(cookies, name+"="+value)
	}
	return strings.Join(cookies, "; ")
}

func constructXWwwFormUrlencoded(bodyObject map[string]string) string {
	form := url.Values{}
	for key, value := range bodyObject {
		form.Set(key, value)
	}
	return form.Encode()
}

func constructJsonBody(body interface{}) (io.Reader, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(data), nil
}

// constructMultipartBody returns the body reader and the Content-Type header (with boundary).
func constructMultipartBody(body map[string]string, files []FileObject) (io.Reader, string, error) {
	buffer := &bytes.Buffer{}
	writer := multipart.NewWriter(buffer)
	for _, file := range files {
		content, err := base64.StdEncoding.DecodeString(file.Data)
		if err != nil {
			return nil, "", err
		}
		header := make(map[string][]string)
		header["Content-Disposition"] = []string{fmt.Sprintf(`form-data; name="%s"; filename="%s"`, file.For, file.Filename)}
		header["Content-Type"] = []string{file.ContentType}
		part, err := writer.CreatePart(header)
		if err != nil {
			return nil, "", err
		}
		if _, err := part.Write(content); err != nil {
			return nil, "", err
		}
	}
	for key, value := range body {
		if err := writer.WriteField(key, value); err != nil {
			return nil, "", err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, "", err
	}
	return buffer, writer.FormDataContentType(), nil
}

func mergeHeaders(headerMaps ...map[string]string) map[string]string {
	merged := map[string]string{}
	for _, headers := range headerMaps {
		for key, value := range headers {
			merged[key] = value
		}
	}
	return merged
}

func doRequest(method string, requestUrl string, headers map[string]string, body io.Reader) (*http.Response, []byte, error) {
	req, err := http.NewRequest(method, requestUrl, body)
	if err != nil {
		return nil, nil, err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	response, err := httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return response, nil, err
	}
	return response, data, nil
}

// fileToBase64 reads a file from disk and returns its base64 encoded content.
func fileToBase64(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(content)
}

// readWordlist reads a newline separated file into a slice of strings.
func readWordlist(path string) []string {
	content, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	lines := strings.Split(strings.ReplaceAll(string(content), "\\r\\n", "\\n"), "\\n")
	wordlist := make([]string, 0, len(lines))
	for _, line := range lines {
		if line != "" {
			wordlist = append(wordlist, line)
		}
	}
	return wordlist
}

// executeParallelRequests runs requestFunc for every payload using at most maxWorkers goroutines.
func executeParallelRequests(requestFunc func(payload string) (*http.Response, []byte, error), payloads []string, maxWorkers int) map[string]Result {
	results := make(map[string]Result, len(payloads))
	var mutex sync.Mutex
	var waitGroup sync.WaitGroup
	semaphore := make(chan struct{}, maxWorkers)
	for _, payload := range payloads {
		waitGroup.Add(1)
		semaphore <- struct{}{}
		go func(payload string) {
			defer waitGroup.Done()
			defer func() { <-semaphore }()
			response, body, err := requestFunc(payload)
			mutex.Lock()
			results[payload] = Result{Response: response, Body: body, Err: err}
			mutex.Unlock()
		}(payload)
	}
	waitGroup.Wait()
	return results
}
"""


class GoParser(Parser):
	def __init__(self, request_trees, callbacks, custom_skip_headers=None, enable_header_filtering=True):
		self.callbacks = callbacks
		self.stdout = PrintWriter(callbacks.getStdout(), True)
		self.stderr = PrintWriter(callbacks.getStderr(), True)

		self.functions = [self._get_function_code(request_trees[i], i + 1) for i in range(len(request_trees))]
		self.common_headers = self._get_common_headers()
		self._filter_common_headers()
		self.main = "func main() {\n"
		self.main += "\tcommonHeaders := " + self.to_go_literal(self.common_headers, "map[string]string", 1) + "\n"
		self.main += "\n"
		self.main += "\t// wordlist := readWordlist(\"rockyou.txt\")\n"
		self.main += "\t// for _, payload := range wordlist {\n"
		for i in range(len(self.functions)):
			_i = str(i + 1)
			[_, method, headers, body, url, cookies, authorization, files, body_kind] = self.functions[i]
			self.main += "\tmethod_" + _i + " := " + self.go_string(method) + "\n"
			self.main += "\theaders_" + _i + " := " + self.to_go_literal(headers, "map[string]string", 1) + "\n"
			if body is not None:
				if body_kind == "json":
					self.main += "\tbody_" + _i + " := " + self.to_go_literal(body, "map[string]interface{}", 1) + "\n"
				else:
					self.main += "\tbody_" + _i + " := " + self.to_go_literal(body, "map[string]string", 1) + "\n"
			self.main += "\turl_" + _i + " := UrlObject{\n"
			self.main += self.align_key_values([
				("Protocol", self.go_string(url["protocol"])),
				("Domain", self.go_string(url["domain"])),
				("Port", str(url["port"])),
				("Path", self.go_string(url["path"])),
				("Parameters", self.to_go_literal(url["parameters"], "map[string]string", 2)),
			], 2) + "\n"
			self.main += "\t}\n"
			if cookies is not None:
				self.main += "\tcookies_" + _i + " := " + self.to_go_literal(cookies, "map[string]string", 1) + "\n"
			if authorization is not None:
				self.main += "\tauthorization_" + _i + " := " + self.go_string(authorization) + "\n"
			if files is not None:
				for j in range(len(files)):
					_j = str(j + 1)
					self.main += "\t// data_" + _j + " := fileToBase64(" + self.go_string(files[j]["filename"]) + ")\n"
					self.main += "\tfile_" + _j + " := FileObject{\n"
					self.main += "\t\tFor:         " + self.go_string(files[j]["for"]) + ",\n"
					self.main += "\t\tFilename:    " + self.go_string(files[j]["filename"]) + ",\n"
					self.main += "\t\tContentType: " + self.go_string(files[j]["contentType"]) + ",\n"
					self.main += "\t\tData:        " + self.go_string(files[j]["data"]) + ",\n"
					self.main += "\t}\n"
				files_variables = ", ".join(["file_" + str(j + 1) for j in range(len(files))])
				self.main += "\tfiles_" + _i + " := []FileObject{" + files_variables + "}\n"

			self.main += "\tres_" + _i + ", data_" + _i + ", err := request_" + _i + "(\n"
			self.main += "\t\turl_" + _i + ",\n"
			self.main += "\t\tmethod_" + _i + ",\n"
			self.main += "\t\theaders_" + _i + ",\n"
			if cookies is not None:
				self.main += "\t\tcookies_" + _i + ",\n"
			else:
				self.main += "\t\tnil,\n"
			if authorization is not None:
				self.main += "\t\tauthorization_" + _i + ",\n"
			else:
				self.main += "\t\t\"\",\n"
			if body is not None:
				self.main += "\t\tbody_" + _i + ",\n"
			else:
				self.main += "\t\tnil,\n"
			if files is not None:
				self.main += "\t\tfiles_" + _i + ",\n"
			else:
				self.main += "\t\tnil,\n"
			self.main += "\t\tcommonHeaders,\n"
			self.main += "\t)\n"
			self.main += "\tif err != nil {\n"
			self.main += "\t\tfmt.Println(\"request_" + _i + " failed:\", err)\n"
			self.main += "\t\treturn\n"
			self.main += "\t}\n"
			self.main += "\tfmt.Println(res_" + _i + ".Status, len(data_" + _i + "))\n"
			self.main += "\t// fmt.Println(string(data_" + _i + "))\n"
			self.main += "\t// os.WriteFile(\"file_" + _i + "\", data_" + _i + ", 0644)\n"
		self.main += "\t// }\n"
		self.main += "}\n"

		code = IMPORTS + UTILS + "\n" + "\n".join(
			[func[0] for func in self.functions]
		) + "\n" + self.main
		self.copy_clipboard(code)


	def go_string(self, value):
		"""Returns a Go interpreted string literal. JSON string escaping is a subset of Go's."""
		if value is None:
			return '""'
		if not isinstance(value, string_types):
			value = str(value)
		return json.dumps(value)


	def align_key_values(self, pairs, indent):
		"""Renders (key, value) pairs the way gofmt aligns composite literal entries.

		Consecutive single-line entries form a section whose values are aligned to
		the longest key. A multi-line value (or a big jump in key length, see
		go/printer exprList) breaks the section.
		"""
		inner = "\t" * indent
		sections = []
		current = []
		prev_size = 0
		lnsum = 0.0
		count = 0
		for key, value in pairs:
			size = 0 if "\n" in value else len(key)
			use_ff = True
			if prev_size > 0 and size > 0:
				if count == 0 or (prev_size <= 40 and size <= 40):
					use_ff = False
				else:
					geomean = math.exp(lnsum / float(count))
					ratio = float(size) / geomean
					use_ff = 2.5 * ratio <= 1 or 2.5 <= ratio
			if use_ff and current:
				sections.append(current)
				current = []
				lnsum = 0.0
				count = 0
			current.append((key, value))
			if size > 0:
				lnsum += math.log(float(size))
				count += 1
			prev_size = size
		if current:
			sections.append(current)

		lines = []
		for section in sections:
			single = [k for k, v in section if "\n" not in v]
			width = max([len(k) for k in single]) if single else 0
			for key, value in section:
				if "\n" in value or len(section) == 1:
					padding = " "
				else:
					padding = " " * (width - len(key) + 1)
				lines.append(inner + key + ":" + padding + value + ",")
		return "\n".join(lines)


	def to_go_literal(self, value, go_type, indent=0):
		"""Converts a python value to a Go composite literal of the given type.

		go_type is one of: map[string]string, map[string]interface{}, []interface{}, []string
		"""
		tabs = "\t" * indent
		inner = "\t" * (indent + 1)
		if go_type == "map[string]string":
			if not value:
				return "map[string]string{}"
			pairs = [(self.go_string(key), self.go_string(value[key])) for key in sorted(value.keys())]
			return "map[string]string{\n" + self.align_key_values(pairs, indent + 1) + "\n" + tabs + "}"
		if go_type == "map[string]interface{}":
			if not value:
				return "map[string]interface{}{}"
			pairs = [(self.go_string(key), self._go_value(value[key], indent + 1)) for key in sorted(value.keys())]
			return "map[string]interface{}{\n" + self.align_key_values(pairs, indent + 1) + "\n" + tabs + "}"
		if go_type == "[]interface{}":
			if not value:
				return "[]interface{}{}"
			lines = [inner + self._go_value(item, indent + 1) + "," for item in value]
			return "[]interface{}{\n" + "\n".join(lines) + "\n" + tabs + "}"
		if go_type == "[]string":
			if not value:
				return "[]string{}"
			lines = [inner + self.go_string(item) + "," for item in value]
			return "[]string{\n" + "\n".join(lines) + "\n" + tabs + "}"
		raise ValueError("Unsupported go type: " + go_type)


	def _go_value(self, value, indent):
		if value is None:
			return "nil"
		if value is True:
			return "true"
		if value is False:
			return "false"
		if isinstance(value, dict):
			return self.to_go_literal(value, "map[string]interface{}", indent)
		if isinstance(value, (list, tuple)):
			return self.to_go_literal(list(value), "[]interface{}", indent)
		if isinstance(value, integer_types):
			return str(value)
		if isinstance(value, float):
			return repr(value)
		return self.go_string(value)


	def _get_common_headers(self):
		values = []
		hashes = []
		for arr in self.functions:
			headers = arr[2]
			for header_name in headers:
				header_value = headers[header_name]
				hsh = hashlib.sha256((header_name + header_value).encode('utf-8')).hexdigest()
				if hsh not in hashes:
					hashes.append(hsh)
					values.append((header_name, header_value))
		common_headers = {}
		for c in values:
			header_name, header_value = c
			common_headers[header_name] = header_value
		return common_headers


	def _filter_common_headers(self):
		for arr in self.functions:
			headers = arr[2]
			for common_header in self.common_headers:
				if common_header in headers and headers[common_header] == self.common_headers[common_header]:
					del headers[common_header]


	def _body_kind(self, request_tree):
		if request_tree.application_json is not None:
			return "json"
		elif request_tree.application_x_www_form_urlencoded is not None:
			return "form"
		elif request_tree.multipart_form_data is not None:
			return "multipart"
		return None


	def _get_function_code(self, request_tree, i):
		body_kind = self._body_kind(request_tree)
		arg_cookie = request_tree.general.cookies
		arg_authorization = request_tree.general.Authorization
		arg_body = self._extract_body(request_tree)
		arg_url = {
			"parameters": request_tree.general.url.parameters,
			"path": request_tree.general.url.path,
			"protocol": request_tree.general.url.protocol,
			"domain": request_tree.general.url.domain,
			"port": request_tree.general.url.port
		}
		arg_method = request_tree.general.method
		arg_headers = request_tree.general.headers
		arg_files = request_tree.files

		if body_kind == "json":
			body_type = "map[string]interface{}"
		else:
			body_type = "map[string]string"

		code = "func request_" + str(i) + "(\n"
		code += "\turlObject UrlObject,\n"
		code += "\tmethod string,\n"
		code += "\theaders map[string]string,\n"
		code += "\tcookies map[string]string,\n"
		code += "\tauthorization string,\n"
		code += "\tbody " + body_type + ",\n"
		code += "\tfiles []FileObject,\n"
		code += "\tcommonHeaders map[string]string,\n"
		code += ") (*http.Response, []byte, error) {\n"
		code += "\trequestUrl := constructUrl(urlObject)\n"
		code += "\th := mergeHeaders(commonHeaders, headers)\n"
		if arg_authorization is not None:
			code += "\tif authorization != \"\" {\n"
			code += "\t\th[\"Authorization\"] = authorization\n"
			code += "\t}\n"
		if arg_cookie is not None:
			code += "\tif cookies != nil {\n"
			code += "\t\th[\"Cookie\"] = constructCookies(cookies)\n"
			code += "\t}\n"

		if body_kind == "json":
			code += "\tjsonBody, err := constructJsonBody(body)\n"
			code += "\tif err != nil {\n"
			code += "\t\treturn nil, nil, err\n"
			code += "\t}\n"
			code += "\treturn doRequest(method, requestUrl, h, jsonBody)\n"
		elif body_kind == "form":
			code += "\tformBody := strings.NewReader(constructXWwwFormUrlencoded(body))\n"
			code += "\treturn doRequest(method, requestUrl, h, formBody)\n"
		elif body_kind == "multipart":
			code += "\tmultipartBody, contentType, err := constructMultipartBody(body, files)\n"
			code += "\tif err != nil {\n"
			code += "\t\treturn nil, nil, err\n"
			code += "\t}\n"
			# Content-Type must carry the generated boundary
			code += "\th[\"Content-Type\"] = contentType\n"
			code += "\treturn doRequest(method, requestUrl, h, multipartBody)\n"
		else:
			code += "\treturn doRequest(method, requestUrl, h, nil)\n"
		code += "}\n"
		return [
			code,
			arg_method,
			arg_headers,
			arg_body,
			arg_url,
			arg_cookie,
			arg_authorization,
			arg_files,
			body_kind,
		]


	def _extract_body(self, request_tree):
		if request_tree.application_json is not None:
			return request_tree.application_json
		elif request_tree.application_x_www_form_urlencoded is not None:
			return request_tree.application_x_www_form_urlencoded
		elif request_tree.multipart_form_data is not None:
			return request_tree.multipart_form_data
		else:
			return None
