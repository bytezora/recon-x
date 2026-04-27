package cors

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bytezora/recon-x/internal/finding"
	"github.com/bytezora/recon-x/internal/httpclient"
)

type Result struct {
	URL        string `json:"url"`
	Origin     string `json:"origin"`
	ACAO       string `json:"acao"`
	ACAC       string `json:"acac"`
	Vulnerable bool   `json:"vulnerable"`
}

func Scan(targets []string, threads int, onFound func(Result)) []Result {
	client := httpclient.New(10*time.Second, false)
	var (
		mu      sync.Mutex
		results []Result
		wg      sync.WaitGroup
		sem     = make(chan struct{}, threads)
	)
	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()
			for _, r := range scanTarget(client, target) {
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
				if onFound != nil {
					onFound(r)
				}
			}
		}(t)
	}
	wg.Wait()
	return results
}

func scanTarget(client *http.Client, target string) []Result {
	origins := []string{
		"https://evil.com",
		"null",
		evilPrefix(target),
	}
	var results []Result
	for _, origin := range origins {
		req, err := http.NewRequest("GET", target, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Origin", origin)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")
		if acao == "" {
			continue
		}
		vuln := false
		if (acao == origin || acao == "null") && origin == "null" {
			vuln = true
		} else if acao == origin {
			vuln = true
		} else if acao == "*" && acac == "true" {
			vuln = true
		}
		if vuln {
			results = append(results, Result{
				URL:        target,
				Origin:     origin,
				ACAO:       acao,
				ACAC:       acac,
				Vulnerable: true,
			})
		}
	}
	return results
}

func evilPrefix(target string) string {
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	parts := strings.SplitN(target, "/", 2)
	host := parts[0]
	return "https://evil" + host
}

func (r Result) ToFinding() finding.Finding {
evidence := "Access-Control-Allow-Origin: " + r.ACAO
if r.ACAC == "true" {
evidence += " | Access-Control-Allow-Credentials: true"
}
reason := "Server reflects arbitrary Origin header in ACAO response"
if r.ACAC == "true" {
reason = "Server reflects arbitrary Origin AND sends ACAC: true — allows cross-origin requests with credentials (cookies, auth headers)"
}

sev := finding.Medium
conf := finding.Likely
if r.ACAC == "true" {
sev = finding.High
conf = finding.Confirmed
}

return finding.Finding{
Type:               "cors",
Severity:           sev,
Confidence:         conf,
Title:              "CORS Misconfiguration — " + r.URL,
AffectedURL:        r.URL,
Evidence:           evidence,
Reason:             reason,
Remediation:        "Whitelist only trusted origins. Never reflect arbitrary Origin header. Set ACAC: true only with explicit safe origin whitelist.",
ManualVerification: r.ACAC != "true",
}
}
