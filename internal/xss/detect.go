package xss

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bytezora/recon-x/internal/finding"
	"github.com/bytezora/recon-x/internal/httpclient"
)

type Result struct {
	URL       string
	Param     string
	Payload   string
	Evidence  string
	Context   string // "script", "attribute", "html", "header"
	Reflected bool
}

func (r Result) ToFinding() finding.Finding {
	return finding.Finding{
		Type:               "xss",
		Severity:           finding.High,
		Confidence:         finding.Likely,
		Title:              "Reflected XSS — parameter: " + r.Param,
		AffectedURL:        r.URL,
		Evidence:           r.Evidence,
		Reason:             "User input reflected unencoded in HTTP response context: " + r.Context,
		Remediation:        "Use output encoding appropriate for context (HTML, JS, attribute). Implement Content-Security-Policy headers.",
		ManualVerification: true,
	}
}

var xssPayloads = []string{
	`<script>alert(1)</script>`,
	`"><svg onload=alert(1)>`,
	`'><img src=x onerror=alert(1)>`,
	`<body onload=alert(1)>`,
}

func randHex(n int) string {
	const chars = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

func detectContext(body, canary string) string {
	idx := strings.Index(body, canary)
	if idx < 0 {
		return "html"
	}
	before := body[:idx]
	lastOpen := strings.LastIndex(before, "<script")
	lastClose := strings.LastIndex(before, "</script>")
	if lastOpen > lastClose {
		return "script"
	}
	lastEq := strings.LastIndex(before, `="`)
	lastEqSingle := strings.LastIndex(before, `='`)
	if lastEq > strings.LastIndex(before, `>`) || lastEqSingle > strings.LastIndex(before, `>`) {
		return "attribute"
	}
	return "html"
}

func fetchBody(client *http.Client, req *http.Request) string {
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return string(data)
}

func testURL(client *http.Client, rawURL string) []Result {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	params := parsed.Query()
	var results []Result
	seen := map[string]bool{}

	testReflected := func(testURLStr, param, payload, canary string) {
		key := testURLStr + "|" + param
		if seen[key] {
			return
		}
		req, err := http.NewRequest("GET", testURLStr, nil)
		if err != nil {
			return
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; recon-x)")
		body := fetchBody(client, req)
		if body == "" {
			return
		}
		if strings.Contains(body, canary) {
			seen[key] = true
			ctx := detectContext(body, canary)
			results = append(results, Result{
				URL:       rawURL,
				Param:     param,
				Payload:   payload,
				Evidence:  fmt.Sprintf("canary %q reflected unencoded in response (context: %s)", canary, ctx),
				Context:   ctx,
				Reflected: true,
			})
		}
	}

	for param := range params {
		canary := "<xss-" + randHex(6) + ">"
		testParams := cloneParams(params)
		testParams.Set(param, canary)
		testU := *parsed
		testU.RawQuery = testParams.Encode()
		testReflected(testU.String(), param, canary, canary)

		for _, payload := range xssPayloads {
			testParams2 := cloneParams(params)
			testParams2.Set(param, payload)
			testU2 := *parsed
			testU2.RawQuery = testParams2.Encode()
			key := testU2.String() + "|" + param + "|" + payload
			if seen[key] {
				continue
			}
			req, err := http.NewRequest("GET", testU2.String(), nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; recon-x)")
			body := fetchBody(client, req)
			if body != "" && strings.Contains(body, payload) {
				seen[key] = true
				ctx := detectContext(body, payload)
				results = append(results, Result{
					URL:       rawURL,
					Param:     param,
					Payload:   payload,
					Evidence:  fmt.Sprintf("XSS payload %q reflected in response (context: %s)", payload, ctx),
					Context:   ctx,
					Reflected: true,
				})
			}
		}
	}

	headerTests := []string{"Referer", "User-Agent", "X-Forwarded-For"}
	for _, hdr := range headerTests {
		canary := "<xss-" + randHex(6) + ">"
		req, err := http.NewRequest("GET", rawURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set(hdr, canary)
		body := fetchBody(client, req)
		if body != "" && strings.Contains(body, canary) {
			results = append(results, Result{
				URL:       rawURL,
				Param:     hdr,
				Payload:   canary,
				Evidence:  fmt.Sprintf("header %q value reflected unencoded in response body", hdr),
				Context:   "header",
				Reflected: true,
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
