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
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
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
	Method          string
	URL             string
	Header          string
	StatusCode      int
	ContentLength   int64
	Matches         []string
	MatchClasses    []string
	ResponseHeaders string
	Duration        time.Duration
	POC             string
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

// multiFlag collects a repeatable string flag (e.g. -header).
type multiFlag []string

func (m *multiFlag) String() string {
	return strings.Join(*m, ", ")
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

type responseInfo struct {
	StatusCode      int
	ContentLength   int64
	URL             string
	Matches         []string
	MatchClasses    []string
	ResponseHeaders string
	Duration        time.Duration
}

var (
	// Flag pointers shared with helper functions (runScan, smuggling/cache probes).
	concurrencyPtr = flag.Int("c", 10, "Number of concurrent requests")
	noCachePtr     = flag.Bool("nb", false, "Disable the cachebuster query parameter")
	verbosePtr     = flag.Bool("v", false, "Print per-request errors")
	insecurePtr    = flag.Bool("k", false, "Skip TLS certificate verification")
	timeoutPtr     = flag.Duration("timeout", 15*time.Second, "Per-request timeout")
	outputPtr      = flag.String("o", "", "Save scan results to a file (one line per result, with POC)")
	outputValidPtr = flag.String("ore", "", "Save only valid candidates (response regex match) to a file")
)

func main() {
	urlPtr := flag.String("url", "", "Target URL (required unless -r is used)")
	listTargetsPtr := flag.String("l", "", "File containing a list of target URLs, one per line (each line may include its own port)")
	headersFilePtr := flag.String("headers", "", "File containing headers to fuzz, one per line (optional with -r to replay the raw request as-is)")
	methodPtr := flag.String("m", "", "HTTP method(s): POST, GET,POST,PUT, or ALL (default GET when -r is not used)")
	allMethodsPtr := flag.Bool("ma", false, "Test all common HTTP methods (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE)")
	rawPtr := flag.String("r", "", "Path to a raw HTTP request file (copy the full request from Burp Repeater)")
	schemePtr := flag.String("scheme", "auto", "Scheme used with -r when the request target is relative: auto, http, or https")
	proxyPtr := flag.String("proxy", "", "Proxy server IP:PORT or URL (e.g., 127.0.0.1:8080)")
	showAllPtr := flag.Bool("all", false, "Show every result (disable deduplication by status code + content length + fingerprint match set)")
	portPtr := flag.String("port", "", "Override target port(s), comma-separated (e.g. 80,443,8080)")
	var extraHeaderArgs multiFlag
	flag.Var(&extraHeaderArgs, "header", "Extra header sent with every request (repeatable), e.g. -header 'Cookie: session=abc'")
	silentPtr := flag.Bool("silent", false, "Only print fingerprint-matched candidates (no live results, summary, or Content-Length section)")
	respPtr := flag.Bool("resp", false, "Fuzz response-header reflection: markers reflected into response headers (incl. encoded CRLF)")
	hostPtr := flag.Bool("host", false, "Fuzz Host header attacks: Host/override headers reflected into absolute URLs (password reset / cache poisoning)")
	authPtr := flag.Bool("auth", false, "Fuzz auth-bypass headers: compare status codes against a no-header baseline (X-Original-URL, X-Forwarded-For, ...)")
	timingPtr := flag.Bool("timing", false, "Report timing anomalies (slow responses) as candidates - hint for blind SQLi/SSRF/smuggling")
	smugglePtr := flag.Bool("smuggle", false, "Probe for HTTP request smuggling (CL.TE / TE.CL) via raw TCP differential")
	cachePtr := flag.Bool("cache", false, "Probe for web cache poisoning via unkeyed headers (paired-request differential)")
	pocPtr := flag.Bool("poc", false, "Print a ready-to-run single-line curl command for every candidate")
	lfiPtr := flag.Bool("lfi", false, "Fuzz with the LFI wordlist + fingerprints (config: ~/.config/headerpwn)")
	sqliPtr := flag.Bool("sqli", false, "Fuzz with the error-based SQLi wordlist + fingerprints (152 nuclei SQLi patterns, all DBMS)")
	rcePtr := flag.Bool("rce", false, "Fuzz with the RCE wordlist + fingerprints (incl. log4shell $collabplz OOB)")
	ssrfPtr := flag.Bool("ssrf", false, "Fuzz with the SSRF wordlist + fingerprints ($collabplz OOB, google.com whitelist bypass)")
	sstiPtr := flag.Bool("ssti", false, "Fuzz with the SSTI wordlist + fingerprints (includes the 7*1000 = 7000 arithmetic probe)")
	xssPtr := flag.Bool("xss", false, "Fuzz with the XSS wordlist + fingerprints (unencoded script reflection)")
	xxePtr := flag.Bool("xxe", false, "Fuzz with the XXE wordlist + fingerprints ($collabplz OOB)")
	redirectPtr := flag.Bool("redirect", false, "Fuzz with the open-redirect wordlist (google.com as whitelisted domain)")
	listPtr := flag.Bool("list", false, "List bug-class wordlists/fingerprints in the config directory and exit")
	oobPtr := flag.String("oob", "", "Replace the $collabplz OOB marker with this domain (e.g. abc123.oast.pro); inside Burp it is auto-replaced")
	quietPtr := flag.Bool("q", false, "Suppress banner")
	flag.Parse()
	log.SetFlags(0)
	// Print tool banner

	if !*quietPtr && !*silentPtr {
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
	if *sqliPtr {
		selected = append(selected, "sqli")
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
	if *xssPtr {
		selected = append(selected, "xss")
	}
	if *redirectPtr {
		selected = append(selected, "redirect")
	}
	if *respPtr {
		selected = append(selected, "resp")
	}
	if *hostPtr {
		selected = append(selected, "host")
	}
	if *authPtr {
		selected = append(selected, "auth")
	}

	if *listPtr {
		if err := listCollections(); err != nil {
			fatal("Error listing collections: %v", err)
		}
		return
	}

	extraHeaders, err := parseExtraHeaders(extraHeaderArgs)
	if err != nil {
		fatal("Error: %v", err)
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

	var targetPorts []int
	if *portPtr != "" {
		var err error
		targetPorts, err = parsePorts(*portPtr)
		if err != nil {
			fatal("Error: %v", err)
		}
	}

	if *urlPtr == "" && *rawPtr == "" && *listTargetsPtr == "" {
		fatal("Please provide a target using -url, a raw request using -r, or a target list using -l")
	}
	if *listTargetsPtr != "" && *rawPtr != "" {
		fatal("Error: -l and -r cannot be combined")
	}
	if *listTargetsPtr != "" && *urlPtr != "" {
		fatal("Error: -l and -url cannot be combined")
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
			fatal("Please provide -headers, a bug-class flag (-lfi, -sqli, -rce, -ssrf, -ssti, -xxe, -xss, -redirect, -resp, -host, -auth), or -r")
		}
		headers = []string{""}
	}

	if containsCollabMarker(headers) && *oobPtr == "" {
		fmt.Fprintln(os.Stderr, "note: payloads contain $collabplz; Burp auto-replaces it with a Collaborator domain, or set -oob <domain> outside Burp")
	}

	if *authPtr {
		// Baseline request without any fuzz header, so auth-bypass headers can
		// be compared against the normal (unauthenticated) response.
		headers = append([]string{""}, headers...)
	}

	warnUnsupportedFuzzHeaders(headers)

	methods := resolveMethods(*methodPtr, *allMethodsPtr, raw)

	client, err := newHTTPClient(*proxyPtr, *insecurePtr, *timeoutPtr)
	if err != nil {
		fatal("Error creating HTTP client: %v", err)
	}

	ports := targetPorts
	if len(ports) == 0 {
		ports = []int{0}
	}

	targets := []string{}
	if *listTargetsPtr != "" {
		var err error
		targets, err = readTargetsFile(*listTargetsPtr)
		if err != nil {
			fatal("Error reading targets: %v", err)
		}
	} else if *urlPtr != "" {
		targets = []string{*urlPtr}
	} else if raw != nil {
		// Raw-request replay without -url/-l: one iteration using the raw Host.
		targets = []string{""}
	}

	for _, target := range targets {
		for _, port := range ports {
			if raw != nil && target == "" && port > 0 {
				// Let the port override also drive the scheme inference for raw
				// relative targets (80 -> http, 443 -> https).
				raw.Host = hostWithPort(raw.Host, port)
			}

			spec, err := buildRequestSpec(raw, target, *schemePtr, port)
			if err != nil {
				fatal("Error: %v", err)
			}

			if port > 0 {
				spec.URL.Host = hostWithPort(spec.URL.Host, port)
				if spec.Host != "" {
					spec.Host = hostWithPort(spec.Host, port)
				}
			}

			for _, header := range extraHeaders {
				setSpecHeader(spec, header)
			}

			label := ""
			switch {
			case len(targets) > 1 && len(ports) > 1:
				label = fmt.Sprintf("%s (port %d)", target, port)
			case len(targets) > 1:
				label = target
			case len(ports) > 1:
				label = fmt.Sprintf("port %d", port)
			}

			runScan(client, spec, headers, methods, fingerprints, *showAllPtr, *silentPtr, *timingPtr, *authPtr, *pocPtr, label)

			if *smugglePtr {
				runSmuggleProbes(spec, *insecurePtr, *timeoutPtr)
			}
			if *cachePtr {
				runCacheProbes(client, spec, *timeoutPtr)
			}
		}
	}
}

// runScan fuzzes every header against every method for a single target spec,
// streams results, then prints the summary and candidate block.
func runScan(client *http.Client, spec *RequestSpec, headers, methods []string, fingerprints []fingerprintRule, showAll, silent, timing, auth, poc bool, label string) {
	if label != "" {
		fmt.Printf("\n[+] %s\n", label)
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
					Method:          method,
					URL:             response.URL,
					Header:          header,
					StatusCode:      response.StatusCode,
					ContentLength:   response.ContentLength,
					Matches:         response.Matches,
					MatchClasses:    response.MatchClasses,
					ResponseHeaders: response.ResponseHeaders,
					Duration:        response.Duration,
					POC:             buildCurlPOC(spec, method, header, response.URL),
				}
			}(method, header)
		}
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	collected := make([]Result, 0)
	liveSeen := make(map[resultKey]struct{})
	for result := range results {
		collected = append(collected, result)

		if silent {
			continue
		}

		// Stream results as they finish. In the default mode, identical
		// status + content-length + fingerprint combinations are printed once.
		if !showAll {
			key := resultKey{
				StatusCode:    result.StatusCode,
				ContentLength: result.ContentLength,
				Matches:       strings.Join(result.Matches, ","),
			}
			if _, exists := liveSeen[key]; exists {
				continue
			}
			liveSeen[key] = struct{}{}
		}
		printLiveResult(result)
	}

	if auth {
		markAuthCandidates(collected)
	}

	if *outputPtr != "" {
		if err := writeResultsFile(*outputPtr, collected, showAll, label, false); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not write -o file: %v\n", err)
		}
	}
	if *outputValidPtr != "" {
		if err := writeResultsFile(*outputValidPtr, collected, showAll, label, true); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not write -ore file: %v\n", err)
		}
	}

	printResults(collected, showAll, silent, timing, poc)
}

// writeResultsFile appends the results to a file. When validOnly is true, only
// results with a fingerprint regex match are written - a regex match is the
// definition of a valid candidate (a 500 alone is not; SQLi can be valid without
// an error status when a DBMS error signature matches).
func writeResultsFile(path string, results []Result, showAll bool, label string, validOnly bool) error {
	displayed := results
	if !showAll {
		displayed = dedupeResults(results)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	if label != "" {
		fmt.Fprintf(f, "\n[+] %s\n", label)
	}
	for _, r := range displayed {
		if validOnly && len(r.Matches) == 0 {
			continue
		}
		fmt.Fprintln(f, formatPlainResult(r))
		if r.POC != "" {
			fmt.Fprintf(f, "  POC: %s\n", r.POC)
		}
	}
	return nil
}

// formatPlainResult renders a result as a color-free single line with the
// cachebuster stripped from the URL.
func formatPlainResult(r Result) string {
	displayURL := r.URL
	if parsed, err := url.Parse(r.URL); err == nil {
		query := parsed.Query()
		query.Del("cachebuster")
		parsed.RawQuery = query.Encode()
		displayURL = parsed.String()
	}
	match := ""
	if len(r.Matches) > 0 {
		match = " [MATCH: " + strings.Join(r.Matches, ", ") + "]"
	}
	return fmt.Sprintf("[%s] [%d] [CL: %d] [%s] [%s]%s", r.Method, r.StatusCode, r.ContentLength, r.Header, displayURL, match)
}

func parsePorts(value string) ([]int, error) {
	seen := make(map[int]bool)
	ports := make([]int, 0)
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port %q (must be 1-65535)", part)
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		ports = append(ports, n)
	}
	if len(ports) == 0 {
		return nil, errors.New("-port requires at least one port")
	}
	return ports, nil
}

// readTargetsFile reads one target URL per line; each line may carry its own
// port (e.g. https://example.com:8443). Blank lines and # comments are ignored.
func readTargetsFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	targets := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimRight(scanner.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, errors.New("no targets found in file")
	}
	return targets, nil
}

// markAuthCandidates flags results whose status code changed from a blocked
// baseline (401/403/redirect) to an allowed one (2xx/3xx) when an auth-bypass
// header was present.
func markAuthCandidates(results []Result) {
	baselineByMethod := make(map[string]Result)
	for _, r := range results {
		if r.Header == "" {
			if _, ok := baselineByMethod[r.Method]; !ok {
				baselineByMethod[r.Method] = r
			}
		}
	}
	for i := range results {
		r := &results[i]
		if r.Header == "" {
			continue
		}
		base, ok := baselineByMethod[r.Method]
		if !ok {
			continue
		}
		if !isBlockedStatus(base.StatusCode) {
			continue
		}
		if isAllowedStatus(r.StatusCode) && r.StatusCode != base.StatusCode {
			r.Matches = appendUnique(r.Matches, "auth-bypass")
			r.MatchClasses = appendUnique(r.MatchClasses, "auth")
		}
	}
}

func appendUnique(list []string, value string) []string {
	for _, v := range list {
		if v == value {
			return list
		}
	}
	return append(list, value)
}

func isBlockedStatus(code int) bool {
	switch code {
	case http.StatusUnauthorized, http.StatusForbidden,
		http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect:
		return true
	}
	return false
}

func isAllowedStatus(code int) bool {
	return code >= 200 && code < 400
}

// runSmuggleProbes performs raw-TCP CL.TE / TE.CL differential probes against the
// target. It sends a deliberately ambiguous request followed by a normal one and
// compares the follow-up response to a two-request baseline.
func runSmuggleProbes(spec *RequestSpec, insecure bool, timeout time.Duration) {
	useTLS := spec.URL.Scheme == "https"
	host := spec.URL.Hostname()
	port := spec.URL.Port()
	if port == "" {
		if useTLS {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(host, port)
	hostHeader := spec.URL.Host
	if spec.Host != "" {
		hostHeader = spec.Host
	}

	base := smuggleBaseline(addr, useTLS, insecure, timeout, hostHeader)
	clte := smuggleProbe(addr, useTLS, insecure, timeout, hostHeader, true)
	tecl := smuggleProbe(addr, useTLS, insecure, timeout, hostHeader, false)

	fmt.Println()
	fmt.Println("[+] Smuggling probes")
	found := false
	inconclusive := false
	if r := evalSmuggle("CL.TE", base, clte); r != "" {
		fmt.Println("    " + r)
		found = true
	} else if len(base) < 2 || len(clte) < 2 {
		inconclusive = true
	}
	if r := evalSmuggle("TE.CL", base, tecl); r != "" {
		fmt.Println("    " + r)
		found = true
	} else if len(base) < 2 || len(tecl) < 2 {
		inconclusive = true
	}
	if inconclusive {
		fmt.Println("    some probes inconclusive (connection closed before a follow-up response)")
	}
	if !found {
		fmt.Println("    no CL.TE / TE.CL discrepancy detected")
	}
}

func smuggleDial(addr string, useTLS, insecure bool, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	if useTLS {
		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: insecure})
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, err
		}
		return tlsConn, nil
	}
	return conn, nil
}

func smuggleBaseline(addr string, useTLS, insecure bool, timeout time.Duration, hostHeader string) []string {
	conn, err := smuggleDial(addr, useTLS, insecure, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	req := "GET / HTTP/1.1\r\nHost: " + hostHeader + "\r\nConnection: keep-alive\r\n\r\n"
	conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(req + req)); err != nil {
		return nil
	}
	return readStatuses(conn, timeout)
}

func smuggleProbe(addr string, useTLS, insecure bool, timeout time.Duration, hostHeader string, clte bool) []string {
	conn, err := smuggleDial(addr, useTLS, insecure, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	var req1 string
	if clte {
		req1 = "POST / HTTP/1.1\r\nHost: " + hostHeader + "\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED"
	} else {
		req1 = "POST / HTTP/1.1\r\nHost: " + hostHeader + "\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n"
	}
	req2 := "GET / HTTP/1.1\r\nHost: " + hostHeader + "\r\n\r\n"
	conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(req1 + req2)); err != nil {
		return nil
	}
	return readStatuses(conn, timeout)
}

func readStatuses(conn net.Conn, timeout time.Duration) []string {
	conn.SetReadDeadline(time.Now().Add(timeout))
	data, _ := io.ReadAll(conn)
	re := regexp.MustCompile(`HTTP/\d(?:\.\d)?\s+(\d{3})`)
	matches := re.FindAllStringSubmatch(string(data), -1)
	statuses := make([]string, 0, len(matches))
	for _, m := range matches {
		statuses = append(statuses, m[1])
	}
	return statuses
}

func evalSmuggle(name string, baseline, probe []string) string {
	if len(baseline) >= 2 && len(probe) >= 2 && probe[1] != baseline[1] {
		return fmt.Sprintf("[%s] CANDIDATE: follow-up status %s vs baseline %s - confirm manually",
			name, strings.Join(probe, ","), strings.Join(baseline, ","))
	}
	return ""
}

// runCacheProbes checks whether common "unkeyed" headers are reflected into the
// response and then served from cache for a second request with a different
// value - the signature of web cache poisoning.
func runCacheProbes(client *http.Client, spec *RequestSpec, timeout time.Duration) {
	probes := []string{
		"X-Forwarded-Host", "X-Forwarded-For", "X-Forwarded-Scheme",
		"X-Forwarded-Proto", "X-Forwarded-Port", "X-Forwarded-Server",
		"X-Host", "X-Original-URL", "X-Rewrite-URL", "Referer", "User-Agent",
	}
	fmt.Println()
	fmt.Println("[+] Cache poisoning probes")
	found := false
	for _, header := range probes {
		marker1 := "hdrpwn-cache-1"
		marker2 := "hdrpwn-cache-2"
		bodyA, hdrA, err := cacheProbe(client, spec, header, marker1)
		if err != nil {
			continue
		}
		if !strings.Contains(bodyA, marker1) && !strings.Contains(hdrA, marker1) {
			continue // header is not reflected at all
		}
		bodyB, hdrB, err := cacheProbe(client, spec, header, marker2)
		if err != nil {
			continue
		}
		if strings.Contains(bodyB, marker1) || strings.Contains(hdrB, marker1) {
			fmt.Printf("    [CACHE] %s unkeyed - response for %q served for %q (cache poisoning likely)\n", header, marker1, marker2)
			found = true
		}
	}
	if !found {
		fmt.Println("    no unkeyed header detected")
	}
}

func cacheProbe(client *http.Client, spec *RequestSpec, header, value string) (string, string, error) {
	target := *spec.URL
	var body io.Reader
	if len(spec.Body) > 0 {
		body = bytes.NewReader(spec.Body)
	}
	req, err := http.NewRequest(http.MethodGet, target.String(), body)
	if err != nil {
		return "", "", err
	}
	if spec.Host != "" {
		req.Host = spec.Host
	}
	for _, h := range spec.Headers {
		if hopByHopHeaders[strings.ToLower(h.Name)] {
			continue
		}
		if strings.EqualFold(h.Name, "Content-Length") {
			continue
		}
		req.Header.Add(h.Name, h.Value)
	}
	req.Header.Set(header, value)

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxFingerprintBody+1))
	if resp.ContentLength < 0 {
		_, _ = io.Copy(io.Discard, resp.Body)
	}

	var sb strings.Builder
	for name, values := range resp.Header {
		for _, v := range values {
			sb.WriteString(name + ": " + v + "\n")
		}
	}
	return string(bodyBytes), sb.String(), nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// buildCurlPOC renders a ready-to-run single-line curl command that reproduces
// the request for a result (method, URL without cachebuster, extra headers,
// fuzz header, and body). Values are shell-quoted so the command has no line
// breaks and can be pasted directly into a terminal.
func buildCurlPOC(spec *RequestSpec, method, fuzzHeader, resultURL string) string {
	parts := []string{"curl"}
	if *insecurePtr {
		parts = append(parts, "-k")
	}
	// -i shows the response status line and headers, so a POC always reveals the
	// finding whether it lives in the status code, a header, or the body.
	parts = append(parts, "-s", "-i")
	if method != "" && method != http.MethodGet {
		parts = append(parts, "-X", method)
	}

	displayURL := resultURL
	if parsed, err := url.Parse(resultURL); err == nil {
		query := parsed.Query()
		query.Del("cachebuster")
		parsed.RawQuery = query.Encode()
		displayURL = parsed.String()
	}
	parts = append(parts, shQuote(displayURL))

	seen := make(map[string]bool)
	for _, h := range spec.Headers {
		seen[strings.ToLower(h.Name)] = true
		parts = append(parts, "-H", shQuote(h.Name+": "+h.Value))
	}
	if spec.Host != "" && !seen["host"] {
		parts = append(parts, "-H", shQuote("Host: "+spec.Host))
	}
	if fuzzHeader != "" {
		parts = append(parts, "-H", shQuote(fuzzHeader))
	}
	if len(spec.Body) > 0 {
		parts = append(parts, "--data-binary", shQuote(string(spec.Body)))
	}
	return strings.Join(parts, " ")
}

// shQuote wraps a string in single quotes, escaping embedded single quotes with
// the standard '"'"' trick so the result is a valid single-line shell argument.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
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

func buildRequestSpec(raw *RawRequest, targetURL, scheme string, port int) (*RequestSpec, error) {
	spec := &RequestSpec{}

	if targetURL != "" {
		parsed, err := normalizeURL(targetURL, scheme, port)
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

func normalizeURL(rawURL, scheme string, port int) (*url.URL, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, errors.New("empty URL")
	}

	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		if scheme == "" || scheme == "auto" {
			switch port {
			case 80:
				scheme = "http"
			default:
				scheme = "https"
			}
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
	start := time.Now()
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
	var matchClasses []string
	headerBlock := ""
	if len(fingerprints) > 0 {
		var sb strings.Builder
		for name, values := range response.Header {
			for _, value := range values {
				sb.WriteString(name)
				sb.WriteString(": ")
				sb.WriteString(value)
				sb.WriteString("\n")
			}
		}
		headerBlock = sb.String()
	}
	if len(bodyBytes) > 0 || len(headerBlock) > 0 {
		suppressed := false
		for _, rule := range fingerprints {
			if !rule.Negative {
				continue
			}
			target := bodyBytes
			if rule.Target == "headers" {
				target = []byte(headerBlock)
			}
			if rule.Re.Match(target) {
				suppressed = true
				break
			}
		}
		if !suppressed {
			for _, rule := range fingerprints {
				if rule.Negative {
					continue
				}
				target := bodyBytes
				if rule.Target == "headers" {
					target = []byte(headerBlock)
				}
				if rule.Re.Match(target) {
					matches = append(matches, rule.Name)
					matchClasses = append(matchClasses, rule.Class)
				}
			}
		}
	}

	return &responseInfo{
		StatusCode:      response.StatusCode,
		ContentLength:   contentLength,
		URL:             target.String(),
		Matches:         matches,
		MatchClasses:    matchClasses,
		ResponseHeaders: headerBlock,
		Duration:        time.Since(start),
	}, nil
}

func validateHeaderLine(line string) error {
	name, _, ok := strings.Cut(line, ":")
	if !ok || strings.TrimSpace(name) == "" {
		return fmt.Errorf("invalid header line %q (expected \"Name: value\")", line)
	}
	return nil
}

// parseExtraHeaders validates -header values (repeatable, and a single value may
// contain several "Name: value" lines separated by newlines). Hop-by-hop and
// body-managed headers are rejected because the HTTP client owns them.
func parseExtraHeaders(values []string) ([]Header, error) {
	headers := make([]Header, 0, len(values))
	for _, value := range values {
		for _, line := range strings.Split(value, "\n") {
			line = strings.TrimSpace(strings.TrimRight(line, "\r"))
			if line == "" {
				continue
			}
			name, headerValue, ok := strings.Cut(line, ":")
			name = strings.TrimSpace(name)
			headerValue = strings.TrimSpace(headerValue)
			if !ok || name == "" {
				return nil, errors.New("invalid -header value (expected \"Name: value\")")
			}
			if !validHeaderName(name) {
				return nil, fmt.Errorf("invalid -header name %q", name)
			}
			lowerName := strings.ToLower(name)
			if lowerName == "content-length" || hopByHopHeaders[lowerName] {
				return nil, fmt.Errorf("-header %q is managed by the HTTP client and cannot be overridden", name)
			}
			if strings.ContainsAny(headerValue, "\r\n\x00") {
				return nil, fmt.Errorf("invalid value for -header %q", name)
			}
			headers = append(headers, Header{Name: name, Value: headerValue})
		}
	}
	return headers, nil
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			continue
		}
		if strings.ContainsRune("!#$%&'*+-.^_`|~", r) {
			continue
		}
		return false
	}
	return true
}

// setSpecHeader adds an extra header to the request spec. A later -header with
// the same name replaces an earlier one (and any raw-request header of the same
// name). Host is special-cased because it is carried in spec.Host.
func setSpecHeader(spec *RequestSpec, header Header) {
	if strings.EqualFold(header.Name, "Host") {
		spec.Host = header.Value
		return
	}
	headers := make([]Header, 0, len(spec.Headers)+1)
	for _, existing := range spec.Headers {
		if !strings.EqualFold(existing.Name, header.Name) {
			headers = append(headers, existing)
		}
	}
	headers = append(headers, header)
	spec.Headers = headers
}

// hostWithPort replaces or appends the given port to a host[:port] value,
// preserving IPv6 literals.
func hostWithPort(host string, port int) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if hostname, _, err := net.SplitHostPort(host); err == nil {
		return net.JoinHostPort(hostname, strconv.Itoa(port))
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return net.JoinHostPort(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"), strconv.Itoa(port))
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
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

var (
	statusGreen    = color.New(color.FgGreen).SprintFunc()
	statusYellow   = color.New(color.FgYellow).SprintFunc()
	statusRed      = color.New(color.FgRed).SprintFunc()
	statusWhiteRed = color.New(color.FgWhite, color.BgRed, color.Bold).SprintFunc()
)

func statusStyleFor(statusCode int) func(...interface{}) string {
	switch {
	case statusCode >= 500:
		return statusWhiteRed
	case statusCode >= 400:
		return statusRed
	case statusCode >= 300:
		return statusYellow
	default:
		return statusGreen
	}
}

// printLiveResult prints a result as soon as its request finishes, so output
// streams during the scan instead of waiting for all requests to complete.
func printLiveResult(result Result) {
	blue := color.New(color.FgBlue).SprintFunc()
	magenta := color.New(color.FgMagenta).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	matchStyle := color.New(color.FgBlack, color.BgHiRed, color.Bold).SprintFunc()

	displayURL := result.URL
	if parsedURL, err := url.Parse(result.URL); err == nil {
		query := parsedURL.Query()
		query.Del("cachebuster")
		parsedURL.RawQuery = query.Encode()
		displayURL = parsedURL.String()
	}

	matchOutput := ""
	if len(result.Matches) > 0 {
		matchOutput = " " + matchStyle(fmt.Sprintf("[MATCH: %s]", strings.Join(result.Matches, ", ")))
	}

	fmt.Printf("%s %s %s %s %s%s\n",
		blue(fmt.Sprintf("[%s]", result.Method)),
		statusStyleFor(result.StatusCode)(fmt.Sprintf("[%d]", result.StatusCode)),
		magenta(fmt.Sprintf("[CL: %d]", result.ContentLength)),
		cyan(fmt.Sprintf("[%s]", result.Header)),
		yellow(fmt.Sprintf("[%s]", displayURL)),
		matchOutput)
}

func printResults(results []Result, showAll, silent, timing, poc bool) {
	displayed := results
	if !showAll {
		displayed = dedupeResults(results)
	}
	sortResults(displayed)

	if silent {
		// -silent: only fingerprint-matched candidates, nothing else.
		printCandidateSummary(results, displayed, true, timing, poc)
		return
	}

	uniqueStatus := color.New(color.FgBlack, color.BgYellow, color.Bold).SprintFunc()

	// Status frequency is computed on all results so a common status code
	// (e.g. repeated 200s) is not mistaken for a unique one after dedupe.
	statusCounts := make(map[int]int, len(results))
	for _, result := range results {
		statusCounts[result.StatusCode]++
	}

	statusStyle := func(statusCode int) func(...interface{}) string {
		if statusCounts[statusCode] == 1 {
			return uniqueStatus
		}
		return statusStyleFor(statusCode)
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

	printCandidateSummary(results, displayed, false, timing, poc)
}

var candidateClassOrder = []struct {
	key   string
	label string
}{
	{"rce", "RCE"},
	{"sqli", "SQLi"},
	{"ssti", "SSTI"},
	{"xxe", "XXE"},
	{"xss", "XSS"},
	{"ssrf", "SSRF"},
	{"resp", "RESP"},
	{"host", "HOST"},
	{"auth", "AUTH"},
}

// maxNoisyContentLengthCandidates is the cutoff above which Content-Length
// deviations are treated as noise unless a fingerprint also matched.
const maxNoisyContentLengthCandidates = 5

// printCandidateSummary highlights the interesting subset of the scan: results
// whose fingerprint matched one of the high-signal bug classes, plus results
// whose Content-Length deviates from the most common length (baseline).
func printCandidateSummary(results, displayed []Result, silent, timing, poc bool) {
	if len(results) == 0 {
		return
	}

	classTotal := make(map[string]int, len(candidateClassOrder))
	for _, result := range results {
		seen := make(map[string]struct{}, len(result.MatchClasses))
		for _, class := range result.MatchClasses {
			if _, ok := seen[class]; ok {
				continue
			}
			seen[class] = struct{}{}
			classTotal[class]++
		}
	}

	classRows := make(map[string][]Result, len(candidateClassOrder))
	for _, result := range displayed {
		seen := make(map[string]struct{}, len(result.MatchClasses))
		for _, class := range result.MatchClasses {
			if _, ok := seen[class]; ok {
				continue
			}
			seen[class] = struct{}{}
			classRows[class] = append(classRows[class], result)
		}
	}

	if silent {
		// -silent: print only the fingerprint-matched candidates, nothing else.
		hasClasses := false
		for _, class := range candidateClassOrder {
			if classTotal[class.key] > 0 {
				hasClasses = true
				break
			}
		}
		if !hasClasses {
			return
		}
		fmt.Println("[+] Candidates")
		for _, class := range candidateClassOrder {
			if classTotal[class.key] == 0 {
				continue
			}
			rows := classRows[class.key]
			fmt.Printf("    [%s] %d request(s) matched a fingerprint (%d unique row(s))\n", class.label, classTotal[class.key], len(rows))
			for _, result := range rows {
				matchOutput := ""
				if len(result.Matches) > 0 {
					matchOutput = fmt.Sprintf(" [MATCH: %s]", strings.Join(result.Matches, ", "))
				}
				fmt.Printf("      [%d] [CL: %d] [%s]%s\n",
					result.StatusCode, result.ContentLength, result.Header, matchOutput)
				if poc && result.POC != "" {
					fmt.Printf("        POC: %s\n", result.POC)
				}
			}
		}
		return
	}

	baseline, baselineCount := modeContentLength(results)
	clTotal := 0
	for _, result := range results {
		if result.ContentLength != baseline {
			clTotal++
		}
	}
	clRows := make([]Result, 0, len(displayed))
	for _, result := range displayed {
		if result.ContentLength != baseline {
			clRows = append(clRows, result)
		}
	}

	hasClasses := false
	for _, class := range candidateClassOrder {
		if classTotal[class.key] > 0 {
			hasClasses = true
			break
		}
	}

	var timingAnomalies []Result
	var timingMedian, timingThreshold time.Duration
	if timing {
		timingAnomalies, timingMedian, timingThreshold = collectTimingAnomalies(results, displayed)
	}
	if !hasClasses && len(clRows) == 0 && len(timingAnomalies) == 0 {
		return
	}

	fmt.Println()
	fmt.Println("[+] Candidates")
	if baselineCount > 0 {
		fmt.Printf("    Content-Length baseline: %d bytes (most common across %d responses)\n", baseline, baselineCount)
	}

	for _, class := range candidateClassOrder {
		if classTotal[class.key] == 0 {
			continue
		}
		rows := classRows[class.key]
		fmt.Printf("    [%s] %d request(s) matched a fingerprint (%d unique row(s))\n", class.label, classTotal[class.key], len(rows))
		printCandidateRows(rows, baseline, poc)
	}

	// A large number of Content-Length deviations is usually page noise or a
	// WAF/rate-limit response, not a useful signal. Only show the section when
	// deviations are few; rows with a fingerprint match are always listed in
	// their class section above.
	if clTotal > maxNoisyContentLengthCandidates {
		fmt.Printf("    [Content-Length] %d request(s) differ from baseline - skipped (>%d without a fingerprint match is too noisy)\n",
			clTotal, maxNoisyContentLengthCandidates)
	} else if len(clRows) > 0 {
		sort.SliceStable(clRows, func(i, j int) bool {
			di := absInt64(clRows[i].ContentLength - baseline)
			dj := absInt64(clRows[j].ContentLength - baseline)
			if di != dj {
				return di > dj
			}
			return clRows[i].ContentLength < clRows[j].ContentLength
		})
		fmt.Printf("    [Content-Length] %d request(s) differ from baseline (%d unique row(s))\n", clTotal, len(clRows))
		printCandidateRows(clRows, baseline, poc)
	}

	if len(timingAnomalies) > 0 {
		printTimingCandidates(timingAnomalies, timingMedian, timingThreshold, poc)
	}
}

// collectTimingAnomalies flags responses that are significantly slower than the
// median - a hint for blind SQLi / SSRF / request-smuggling timing probes.
// It iterates ALL results (not the deduplicated set) so a slow response is never
// hidden by deduplication.
func collectTimingAnomalies(results, displayed []Result) ([]Result, time.Duration, time.Duration) {
	median := medianDuration(results)
	threshold := 3 * median
	if threshold < time.Second {
		threshold = time.Second
	}

	anomalies := make([]Result, 0)
	for _, result := range results {
		if result.Duration > threshold {
			anomalies = append(anomalies, result)
		}
	}
	sort.SliceStable(anomalies, func(i, j int) bool {
		return anomalies[i].Duration > anomalies[j].Duration
	})
	return anomalies, median, threshold
}

func printTimingCandidates(anomalies []Result, median, threshold time.Duration, poc bool) {
	fmt.Printf("    [Timing] %d request(s) slower than baseline (median %s, threshold %s)\n",
		len(anomalies), median.Round(time.Millisecond), threshold.Round(time.Millisecond))
	for _, result := range anomalies {
		matchOutput := ""
		if len(result.Matches) > 0 {
			matchOutput = fmt.Sprintf(" [MATCH: %s]", strings.Join(result.Matches, ", "))
		}
		fmt.Printf("      [%d] [%s] [%s]%s\n",
			result.StatusCode, result.Duration.Round(time.Millisecond), result.Header, matchOutput)
		if poc && result.POC != "" {
			fmt.Printf("        POC: %s\n", result.POC)
		}
	}
}

func medianDuration(results []Result) time.Duration {
	if len(results) == 0 {
		return 0
	}
	durations := make([]time.Duration, len(results))
	for i, result := range results {
		durations[i] = result.Duration
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	return durations[(len(durations)-1)/2]
}

func printCandidateRows(rows []Result, baseline int64, poc bool) {
	for _, result := range rows {
		matchOutput := ""
		if len(result.Matches) > 0 {
			matchOutput = fmt.Sprintf(" [MATCH: %s]", strings.Join(result.Matches, ", "))
		}
		fmt.Printf("      [%d] [CL: %d] (%+d) [%s]%s\n",
			result.StatusCode, result.ContentLength, result.ContentLength-baseline, result.Header, matchOutput)
		if poc && result.POC != "" {
			fmt.Printf("        POC: %s\n", result.POC)
		}
	}
}

func modeContentLength(results []Result) (int64, int) {
	counts := make(map[int64]int, len(results))
	for _, result := range results {
		counts[result.ContentLength]++
	}
	var mode int64
	best := 0
	for length, count := range counts {
		if count > best || (count == best && length < mode) {
			mode = length
			best = count
		}
	}
	return mode, best
}

func absInt64(value int64) int64 {
	if value < 0 {
		return -value
	}
	return value
}
