package main

import (
	"bufio"
	"bytes"
	cryptorand "crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

const maxRawRequestSize = 5 << 20 // 5 MB

const maxFingerprintBody = 1 << 20 // 1 MB

// commonMethods is used by -ma (and -m ALL).
var commonMethods = []string{
	http.MethodGet,
	http.MethodPost,
	http.MethodPut,
	http.MethodPatch,
	http.MethodDelete,
	http.MethodHead,
	http.MethodOptions,
	http.MethodTrace,
}

// hopByHopHeaders are managed by the HTTP transport and cannot be replayed
// verbatim from a raw request.
var hopByHopHeaders = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"proxy-connection":    true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

type Result struct {
	Method        string
	URL           string
	Header        string
	StatusCode    int
	ContentLength int64
	Matches       []string
}

type Header struct {
	Name  string
	Value string
}

type RawRequest struct {
	Method  string
	Target  string
	Proto   string
	Host    string
	Headers []Header
	Body    []byte
}

type RequestSpec struct {
	URL     *url.URL
	Host    string
	Headers []Header
	Body    []byte
}

type responseInfo struct {
	StatusCode    int
	ContentLength int64
	URL           string
	Matches       []string
}

func main() {
	urlPtr := flag.String("url", "", "Target URL (required unless -r is used)")
	headersFilePtr := flag.String("headers", "", "File containing headers to fuzz, one per line (optional with -r to replay the raw request as-is)")
	methodPtr := flag.String("m", "", "HTTP method(s): POST, GET,POST,PUT, or ALL (default GET when -r is not used)")
	allMethodsPtr := flag.Bool("ma", false, "Test all common HTTP methods (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE)")
	rawPtr := flag.String("r", "", "Path to a raw HTTP request file (copy the full request from Burp Repeater)")
	schemePtr := flag.String("scheme", "auto", "Scheme used with -r when the request target is relative: auto, http, or https")
	proxyPtr := flag.String("proxy", "", "Proxy server IP:PORT or URL (e.g., 127.0.0.1:8080)")
	insecurePtr := flag.Bool("k", false, "Skip TLS certificate verification")
	timeoutPtr := flag.Duration("timeout", 15*time.Second, "Per-request timeout")
	concurrencyPtr := flag.Int("c", 10, "Number of concurrent requests")
	noCachePtr := flag.Bool("nb", false, "Disable the cachebuster query parameter")
	showAllPtr := flag.Bool("all", false, "Show every result (disable deduplication by status code + content length)")
	lfiPtr := flag.Bool("lfi", false, "Fuzz with the LFI wordlist + fingerprints (config: ~/.config/headerpwn)")
	rcePtr := flag.Bool("rce", false, "Fuzz with the RCE wordlist + fingerprints (incl. log4shell $collabplz OOB)")
	ssrfPtr := flag.Bool("ssrf", false, "Fuzz with the SSRF wordlist + fingerprints ($collabplz OOB, google.com whitelist bypass)")
	sstiPtr := flag.Bool("ssti", false, "Fuzz with the SSTI wordlist + fingerprints")
	xxePtr := flag.Bool("xxe", false, "Fuzz with the XXE wordlist + fingerprints ($collabplz OOB)")
	redirectPtr := flag.Bool("redirect", false, "Fuzz with the open-redirect wordlist (google.com as whitelisted domain)")
	listPtr := flag.Bool("list", false, "List bug-class wordlists/fingerprints in the config directory and exit")
	oobPtr := flag.String("oob", "", "Replace the $collabplz OOB marker with this domain (e.g. abc123.oast.pro); inside Burp it is auto-replaced")
	verbosePtr := flag.Bool("v", false, "Print per-request errors")
	quietPtr := flag.Bool("q", false, "Suppress banner")
	flag.Parse()
	log.SetFlags(0)
	// Print tool banner

	if !*quietPtr {
		log.Print(`


	   __               __                      
	  / /  ___ ___  ___/ /__ _______ _    _____ 
	 / _ \/ -_) _ \/ _  / -_) __/ _ \ |/|/ / _ \
	/_//_/\__/\_,_/\_,_/\__/_/ / .__/__,__/_//_/
	                          /_/               
    
`)
	}

	selected := make([]string, 0)
	if *lfiPtr {
		selected = append(selected, "lfi")
	}
	if *rcePtr {
		selected = append(selected, "rce")
	}
	if *xxePtr {
		selected = append(selected, "xxe")
	}
	if *ssrfPtr {
		selected = append(selected, "ssrf")
	}
	if *sstiPtr {
		selected = append(selected, "ssti")
	}
	if *redirectPtr {
		selected = append(selected, "redirect")
	}

	if *listPtr {
		if err := listCollections(); err != nil {
			fatal("Error listing collections: %v", err)
		}
		return
	}

	// Mandatory config layout: ~/.config/headerpwn/{wordlists,fingerprints}
	if _, err := ensureConfigFiles(); err != nil {
		if len(selected) > 0 {
			fatal("Error preparing config directory: %v", err)
		}
		fmt.Fprintf(os.Stderr, "warning: could not prepare config directory: %v\n", err)
	}

	if *oobPtr != "" {
		oob := strings.TrimSpace(*oobPtr)
		if oob == "" || strings.ContainsAny(oob, " \t\r\n") {
			fatal("Error: -oob must be a single hostname/URL without spaces")
		}
		*oobPtr = oob
	}

	switch *schemePtr {
	case "auto", "http", "https":
	default:
		fatal("Error: -scheme must be auto, http, or https")
	}

	if *concurrencyPtr < 1 {
		fatal("Error: -c must be greater than 0")
	}

	if *urlPtr == "" && *rawPtr == "" {
		fatal("Please provide a target using -url or a raw request using -r")
	}

	var raw *RawRequest
	if *rawPtr != "" {
		data, err := readRawRequestFile(*rawPtr)
		if err != nil {
			fatal("Error reading raw request: %v", err)
		}
		raw, err = parseRawRequest(data)
		if err != nil {
			fatal("Error parsing raw request: %v", err)
		}
	}

	collectionHeaders := make([]string, 0)
	var fingerprints []fingerprintRule
	for _, name := range selected {
		collection, err := loadCollection(name, *oobPtr)
		if err != nil {
			fatal("Error loading collection %q: %v", name, err)
		}
		collectionHeaders = append(collectionHeaders, collection.Headers...)
		fingerprints = append(fingerprints, collection.Fingerprints...)
	}

	headers := make([]string, 0)
	headers = append(headers, collectionHeaders...)
	if *headersFilePtr != "" {
		parsedHeaders, err := readHeadersFromFile(*headersFilePtr)
		if err != nil {
			fatal("Error reading headers: %v", err)
		}
		headers = append(headers, parsedHeaders...)
	}
	if len(headers) == 0 {
		if raw == nil {
			fatal("Please provide -headers, a bug-class flag (-lfi, -rce, -ssrf, -ssti, -xxe, -redirect), or -r")
		}
		headers = []string{""}
	}

	if containsCollabMarker(headers) && *oobPtr == "" {
		fmt.Fprintln(os.Stderr, "note: payloads contain $collabplz; Burp auto-replaces it with a Collaborator domain, or set -oob <domain> outside Burp")
	}

	warnUnsupportedFuzzHeaders(headers)

	methods := resolveMethods(*methodPtr, *allMethodsPtr, raw)

	spec, err := buildRequestSpec(raw, *urlPtr, *schemePtr)
	if err != nil {
		fatal("Error: %v", err)
	}

	client, err := newHTTPClient(*proxyPtr, *insecurePtr, *timeoutPtr)
	if err != nil {
		fatal("Error creating HTTP client: %v", err)
	}

	var wg sync.WaitGroup
	results := make(chan Result)
	sem := make(chan struct{}, *concurrencyPtr)

	for _, method := range methods {
		for _, header := range headers {
			wg.Add(1)
			go func(method, header string) {
				defer wg.Done()

				sem <- struct{}{}
				defer func() { <-sem }()

				response, err := doRequest(client, spec, method, header, !*noCachePtr, fingerprints)
				if err != nil {
					if *verbosePtr {
						fmt.Fprintf(os.Stderr, "[error] %s %q: %v\n", method, header, err)
					}
					return
				}

				results <- Result{
					Method:        method,
					URL:           response.URL,
					Header:        header,
					StatusCode:    response.StatusCode,
					ContentLength: response.ContentLength,
					Matches:       response.Matches,
				}
			}(method, header)
		}
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	collected := make([]Result, 0)
	for result := range results {
		collected = append(collected, result)
	}

	printResults(collected, *showAllPtr)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func resolveMethods(methodArg string, allMethods bool, raw *RawRequest) []string {
	if allMethods {
		return append([]string(nil), commonMethods...)
	}

	if strings.TrimSpace(methodArg) != "" {
		methods, err := parseMethods(methodArg)
		if err != nil {
			fatal("Error: %v", err)
		}
		return methods
	}

	if raw != nil {
		return []string{raw.Method}
	}

	return []string{http.MethodGet}
}

func parseMethods(arg string) ([]string, error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return nil, errors.New("empty HTTP method")
	}

	if strings.EqualFold(arg, "ALL") {
		return append([]string(nil), commonMethods...), nil
	}

	seen := make(map[string]bool)
	methods := make([]string, 0)
	for _, part := range strings.Split(arg, ",") {
		method := strings.ToUpper(strings.TrimSpace(part))
		if method == "" {
			continue
		}
		if !validMethodToken(method) {
			return nil, fmt.Errorf("invalid HTTP method %q", part)
		}
		if !seen[method] {
			seen[method] = true
			methods = append(methods, method)
		}
	}

	if len(methods) == 0 {
		return nil, errors.New("no valid HTTP method provided")
	}

	return methods, nil
}

func validMethodToken(method string) bool {
	if method == "" {
		return false
	}
	for _, c := range method {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", c):
		default:
			return false
		}
	}
	return true
}

func readHeadersFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	headers := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if err := validateHeaderLine(line); err != nil {
			return nil, fmt.Errorf("%s: %w", filename, err)
		}
		headers = append(headers, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return headers, nil
}

func readRawRequestFile(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxRawRequestSize {
		return nil, fmt.Errorf("%s is too large (max %d bytes)", filename, maxRawRequestSize)
	}

	data, err := io.ReadAll(io.LimitReader(file, maxRawRequestSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxRawRequestSize {
		return nil, fmt.Errorf("%s is too large (max %d bytes)", filename, maxRawRequestSize)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%s is empty", filename)
	}

	return data, nil
}

// parseRawRequest parses a raw HTTP/1.x or HTTP/2 request as copied from
// Burp Repeater: request line, headers, blank line, then body.
func parseRawRequest(data []byte) (*RawRequest, error) {
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	separatorLen := 4
	if headerEnd == -1 {
		headerEnd = bytes.Index(data, []byte("\n\n"))
		separatorLen = 2
	}

	headerBytes := data
	var body []byte
	if headerEnd >= 0 {
		headerBytes = data[:headerEnd]
		body = data[headerEnd+separatorLen:]
	}

	text := strings.ReplaceAll(string(headerBytes), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return nil, errors.New("empty raw request")
	}

	requestLine := strings.TrimSpace(lines[0])
	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("invalid request line %q", requestLine)
	}

	raw := &RawRequest{
		Method: strings.ToUpper(parts[0]),
		Target: parts[1],
		Body:   body,
	}
	if !validMethodToken(raw.Method) {
		return nil, fmt.Errorf("invalid HTTP method %q in request line", parts[0])
	}
	if len(parts) == 3 {
		raw.Proto = parts[2]
	}

	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Support obsolete header folding (continuation lines).
		if (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) && len(raw.Headers) > 0 {
			raw.Headers[len(raw.Headers)-1].Value += " " + strings.TrimSpace(line)
			continue
		}

		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("invalid header line %q", line)
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, fmt.Errorf("invalid header line %q", line)
		}
		value = strings.TrimSpace(value)

		if strings.EqualFold(name, "Host") {
			raw.Host = value
			continue
		}

		raw.Headers = append(raw.Headers, Header{Name: name, Value: value})
	}

	return raw, nil
}

func buildRequestSpec(raw *RawRequest, targetURL, scheme string) (*RequestSpec, error) {
	spec := &RequestSpec{}

	if targetURL != "" {
		parsed, err := normalizeURL(targetURL, scheme)
		if err != nil {
			return nil, fmt.Errorf("invalid -url: %w", err)
		}
		spec.URL = parsed
	}

	if raw == nil {
		if spec.URL == nil {
			return nil, errors.New("a target URL (-url) or raw request (-r) is required")
		}
		return spec, nil
	}

	spec.Headers = raw.Headers
	spec.Body = raw.Body

	if spec.URL != nil {
		// -url replaces the destination. The raw Host header is intentionally
		// not preserved so the request goes to the host the user asked for.
		return spec, nil
	}

	parsed, err := rawRequestURL(raw, scheme)
	if err != nil {
		return nil, err
	}
	spec.URL = parsed
	spec.Host = raw.Host

	return spec, nil
}

func normalizeURL(rawURL, scheme string) (*url.URL, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, errors.New("empty URL")
	}

	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		if scheme == "" || scheme == "auto" {
			scheme = "https"
		}
		rawURL = scheme + "://" + rawURL
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("unsupported URL scheme %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, errors.New("URL has no host")
	}

	return parsed, nil
}

func rawRequestURL(raw *RawRequest, scheme string) (*url.URL, error) {
	target := raw.Target
	if target == "" {
		return nil, errors.New("raw request has an empty request target")
	}
	if target == "*" {
		return nil, errors.New("asterisk-form request target (*) is not supported; provide -url")
	}
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return url.Parse(target)
	}
	if !strings.HasPrefix(target, "/") {
		return nil, fmt.Errorf("unsupported request target %q", target)
	}
	if raw.Host == "" {
		return nil, errors.New("raw request has no Host header; add one or provide -url")
	}

	selectedScheme := scheme
	if selectedScheme == "" || selectedScheme == "auto" {
		selectedScheme = inferScheme(raw.Host, raw.Proto)
	}

	parsed, err := url.Parse(selectedScheme + "://" + raw.Host + target)
	if err != nil {
		return nil, err
	}
	if parsed.Host == "" {
		return nil, errors.New("could not determine the target host from the raw request")
	}

	return parsed, nil
}

func inferScheme(host, proto string) string {
	upperProto := strings.ToUpper(proto)
	if strings.Contains(upperProto, "HTTP/2") || strings.Contains(upperProto, "HTTP/3") {
		return "https"
	}

	if idx := strings.LastIndex(host, ":"); idx >= 0 {
		switch host[idx+1:] {
		case "80":
			return "http"
		case "443":
			return "https"
		}
	}

	return "https"
}

func newHTTPClient(proxy string, insecure bool, timeout time.Duration) (*http.Client, error) {
	proxyFunc := http.ProxyFromEnvironment

	if proxy != "" {
		proxyAddress := proxy
		if !strings.Contains(proxyAddress, "://") {
			proxyAddress = "http://" + proxyAddress
		}

		proxyURL, err := url.Parse(proxyAddress)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy: %w", err)
		}
		switch proxyURL.Scheme {
		case "http", "https", "socks5", "socks5h":
		default:
			return nil, fmt.Errorf("unsupported proxy scheme %q", proxyURL.Scheme)
		}
		if proxyURL.Host == "" {
			return nil, errors.New("proxy has no host")
		}

		proxyFunc = http.ProxyURL(proxyURL)
	}

	transport := &http.Transport{
		Proxy:               proxyFunc,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: insecure}, // #nosec G402 -- opt-in via -k
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		// Do not follow redirects: a 3xx is itself a finding (open redirect,
		// SSRF callback, auth bypass) and must be visible in the output.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func doRequest(client *http.Client, spec *RequestSpec, method, fuzzHeader string, useCacheBuster bool, fingerprints []fingerprintRule) (*responseInfo, error) {
	target := *spec.URL
	if useCacheBuster {
		query := target.Query()
		query.Set("cachebuster", generateCacheBuster())
		target.RawQuery = query.Encode()
	}

	var body io.Reader
	if len(spec.Body) > 0 {
		body = bytes.NewReader(spec.Body)
	}

	req, err := http.NewRequest(method, target.String(), body)
	if err != nil {
		return nil, err
	}

	if spec.Host != "" {
		req.Host = spec.Host
	}

	for _, header := range spec.Headers {
		if hopByHopHeaders[strings.ToLower(header.Name)] {
			continue
		}
		if strings.EqualFold(header.Name, "Content-Length") {
			// The Go HTTP client derives Content-Length from the body.
			continue
		}
		req.Header.Add(header.Name, header.Value)
	}

	if fuzzHeader != "" {
		if err := applyFuzzHeader(req, fuzzHeader); err != nil {
			return nil, err
		}
	}

	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	// Body is only buffered when fingerprints are active (capped at 1 MB).
	var bodyBytes []byte
	if len(fingerprints) > 0 {
		bodyBytes, _ = io.ReadAll(io.LimitReader(response.Body, maxFingerprintBody+1))
	}

	contentLength := response.ContentLength
	if contentLength < 0 {
		if bodyBytes != nil {
			contentLength = int64(len(bodyBytes))
			_, _ = io.Copy(io.Discard, response.Body)
		} else {
			n, err := io.Copy(io.Discard, response.Body)
			if err != nil {
				return nil, err
			}
			contentLength = n
		}
	} else if _, err := io.Copy(io.Discard, response.Body); err != nil {
		return nil, err
	}

	var matches []string
	if len(bodyBytes) > 0 {
		for _, rule := range fingerprints {
			if rule.Re.Match(bodyBytes) {
				matches = append(matches, rule.Name)
			}
		}
	}

	return &responseInfo{
		StatusCode:    response.StatusCode,
		ContentLength: contentLength,
		URL:           target.String(),
		Matches:       matches,
	}, nil
}

func validateHeaderLine(line string) error {
	name, _, ok := strings.Cut(line, ":")
	if !ok || strings.TrimSpace(name) == "" {
		return fmt.Errorf("invalid header line %q (expected \"Name: value\")", line)
	}
	return nil
}

func applyFuzzHeader(req *http.Request, line string) error {
	name, value, ok := strings.Cut(line, ":")
	name = strings.TrimSpace(name)
	if !ok || name == "" {
		return fmt.Errorf("invalid header line %q (expected \"Name: value\")", line)
	}
	value = strings.TrimSpace(value)

	switch {
	case strings.EqualFold(name, "Host"):
		req.Host = value
	case strings.EqualFold(name, "Content-Length"):
		// Managed by the HTTP client; cannot be fuzzed here.
	default:
		req.Header.Set(name, value)
	}

	return nil
}

func warnUnsupportedFuzzHeaders(headers []string) {
	for _, line := range headers {
		name, _, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "content-length", "transfer-encoding":
			fmt.Fprintln(os.Stderr, "note: Content-Length and Transfer-Encoding are managed by the HTTP client and cannot be fuzzed")
			return
		}
	}
}

func generateCacheBuster() string {
	b := make([]byte, 8)
	if _, err := cryptorand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

type resultKey struct {
	StatusCode    int
	ContentLength int64
	Matches       string
}

// dedupeResults keeps only the first result for each unique
// status code + content length + fingerprint match combination.
func dedupeResults(results []Result) []Result {
	seen := make(map[resultKey]struct{}, len(results))
	unique := make([]Result, 0, len(results))

	for _, result := range results {
		key := resultKey{
			StatusCode:    result.StatusCode,
			ContentLength: result.ContentLength,
			Matches:       strings.Join(result.Matches, ","),
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, result)
	}

	return unique
}

func sortResults(results []Result) {
	sort.SliceStable(results, func(i, j int) bool {
		matchedI, matchedJ := len(results[i].Matches) > 0, len(results[j].Matches) > 0
		if matchedI != matchedJ {
			return matchedI
		}
		if results[i].StatusCode != results[j].StatusCode {
			return results[i].StatusCode < results[j].StatusCode
		}
		return results[i].ContentLength < results[j].ContentLength
	})
}

func pluralSuffix(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}

func printResults(results []Result, showAll bool) {
	blue := color.New(color.FgBlue).SprintFunc()
	magenta := color.New(color.FgMagenta).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	whiteOnRed := color.New(color.FgWhite, color.BgRed, color.Bold).SprintFunc()
	uniqueStatus := color.New(color.FgBlack, color.BgYellow, color.Bold).SprintFunc()
	matchStyle := color.New(color.FgBlack, color.BgHiRed, color.Bold).SprintFunc()

	// Status frequency is computed on all results so a common status code
	// (e.g. repeated 200s) is not mistaken for a unique one after dedupe.
	statusCounts := make(map[int]int, len(results))
	for _, result := range results {
		statusCounts[result.StatusCode]++
	}

	displayed := results
	if !showAll {
		displayed = dedupeResults(results)
	}
	sortResults(displayed)

	statusStyle := func(statusCode int) func(...interface{}) string {
		if statusCounts[statusCode] == 1 {
			return uniqueStatus
		}
		switch {
		case statusCode >= 500:
			return whiteOnRed
		case statusCode >= 400:
			return red
		case statusCode >= 300:
			return yellow
		default:
			return green
		}
	}

	for _, result := range displayed {
		methodOutput := blue(fmt.Sprintf("[%s]", result.Method))
		statusOutput := statusStyle(result.StatusCode)(fmt.Sprintf("[%d]", result.StatusCode))
		contentLengthOutput := magenta(fmt.Sprintf("[CL: %d]", result.ContentLength))
		headerOutput := cyan(fmt.Sprintf("[%s]", result.Header))

		displayURL := result.URL
		if parsedURL, err := url.Parse(result.URL); err == nil {
			query := parsedURL.Query()
			query.Del("cachebuster")
			parsedURL.RawQuery = query.Encode()
			displayURL = parsedURL.String()
		}
		urlOutput := yellow(fmt.Sprintf("[%s]", displayURL))

		matchOutput := ""
		if len(result.Matches) > 0 {
			matchOutput = " " + matchStyle(fmt.Sprintf("[MATCH: %s]", strings.Join(result.Matches, ", ")))
		}

		resultOutput := fmt.Sprintf("%s %s %s %s %s%s", methodOutput, statusOutput, contentLengthOutput, headerOutput, urlOutput, matchOutput)
		fmt.Println(resultOutput)
	}

	if len(results) == 0 {
		fmt.Println("No results received")
		return
	}

	fmt.Println()
	if showAll || len(displayed) == len(results) {
		fmt.Printf("[+] %d requests -> %d results\n", len(results), len(displayed))
	} else {
		fmt.Printf("[+] %d requests -> %d unique result%s (duplicate status/length combinations hidden, use -all to show all)\n", len(results), len(displayed), pluralSuffix(len(displayed)))
	}

	statusCodes := make([]int, 0, len(statusCounts))
	for statusCode := range statusCounts {
		statusCodes = append(statusCodes, statusCode)
	}
	sort.Ints(statusCodes)

	fmt.Print("[+] Status codes: ")
	for i, statusCode := range statusCodes {
		if i > 0 {
			fmt.Print(" ")
		}
		fmt.Print(statusStyle(statusCode)(fmt.Sprintf("[%d]", statusCode)))
	}
	fmt.Println()

	matchCount := 0
	for _, result := range results {
		if len(result.Matches) > 0 {
			matchCount++
		}
	}
	if matchCount > 0 {
		fmt.Printf("[+] Fingerprint matches: %d request(s) hit a fingerprint (rows marked [MATCH: ...])\n", matchCount)
	}
}
