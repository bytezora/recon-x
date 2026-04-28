package hostheader

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bytezora/recon-x/internal/finding"
	"github.com/bytezora/recon-x/internal/httpclient"
)

type Result struct {
	URL        string
	Header     string
	Payload    string
	Evidence   string
	Vulnerable bool
}

func (r Result) ToFinding() finding.Finding {
	return finding.Finding{
		Type:               "hostheader",
		Severity:           finding.Medium,
		Confidence:         finding.Likely,
		Title:              "Host Header Injection — header: " + r.Header,
		AffectedURL:        r.URL,
		Evidence:           r.Evidence,
		Reason:             "Injected host header value reflected in response or caused redirect",
		Remediation:        "Validate the Host header against a whitelist of allowed hostnames. Do not use the Host header for generating links without validation.",
		ManualVerification: true,
	}
}

var injectHeaders = []string{
	"Host",
	"X-Forwarded-Host",
	"X-Host",
	"X-Forwarded-Server",
	"X-HTTP-Host-Override",
	"Forwarded",
}

func randHex(n int) string {
	const chars = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

func testURL(client *http.Client, rawURL string) []Result {
	canary := fmt.Sprintf("attacker-%s.com", randHex(6))
	var results []Result

	for _, hdr := range injectHeaders {
		req, err := http.NewRequest("GET", rawURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; recon-x)")
		if hdr == "Host" {
			req.Host = canary
		} else {
			req.Header.Set(hdr, canary)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		body := string(data)

		if strings.Contains(body, canary) {
			results = append(results, Result{
				URL:        rawURL,
				Header:     hdr,
				Payload:    canary,
				Evidence:   fmt.Sprintf("canary %q reflected in response body", canary),
				Vulnerable: true,
			})
			continue
		}

		if loc := resp.Header.Get("Location"); strings.Contains(loc, canary) {
			results = append(results, Result{
				URL:        rawURL,
				Header:     hdr,
				Payload:    canary,
				Evidence:   fmt.Sprintf("canary %q found in Location redirect: %s", canary, loc),
				Vulnerable: true,
			})
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
					key := r.URL + "|" + r.Header
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
