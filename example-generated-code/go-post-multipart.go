package main

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
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
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

func request_1(
	urlObject UrlObject,
	method string,
	headers map[string]string,
	cookies map[string]string,
	authorization string,
	body map[string]string,
	files []FileObject,
	commonHeaders map[string]string,
) (*http.Response, []byte, error) {
	requestUrl := constructUrl(urlObject)
	h := mergeHeaders(commonHeaders, headers)
	if cookies != nil {
		h["Cookie"] = constructCookies(cookies)
	}
	multipartBody, contentType, err := constructMultipartBody(body, files)
	if err != nil {
		return nil, nil, err
	}
	h["Content-Type"] = contentType
	return doRequest(method, requestUrl, h, multipartBody)
}

func main() {
	commonHeaders := map[string]string{
		"Content-Type":       "multipart/form-data",
		"Cookie":             "c=123",
		"Sec-Ch-Ua":          "\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\"",
		"Sec-Ch-Ua-Mobile":   "?0",
		"Sec-Ch-Ua-Platform": "\"macOS\"",
	}

	// wordlist := readWordlist("rockyou.txt")
	// for _, payload := range wordlist {
	method_1 := "POST"
	headers_1 := map[string]string{}
	body_1 := map[string]string{
		"title": "my upload",
	}
	url_1 := UrlObject{
		Protocol:   "https",
		Domain:     "jsonplaceholder.typicode.com",
		Port:       443,
		Path:       "/upload",
		Parameters: map[string]string{},
	}
	cookies_1 := map[string]string{
		"c": "123",
	}
	// data_1 := fileToBase64("notes.txt")
	file_1 := FileObject{
		For:         "file",
		Filename:    "notes.txt",
		ContentType: "text/plain",
		Data:        "aGVsbG8gd29ybGQK",
	}
	files_1 := []FileObject{file_1}
	res_1, data_1, err := request_1(
		url_1,
		method_1,
		headers_1,
		cookies_1,
		"",
		body_1,
		files_1,
		commonHeaders,
	)
	if err != nil {
		fmt.Println("request_1 failed:", err)
		return
	}
	fmt.Println(res_1.Status, len(data_1))
	// fmt.Println(string(data_1))
	// os.WriteFile("file_1", data_1, 0644)
	// }
}
