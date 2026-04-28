package jwt

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"sync"

	"github.com/bytezora/recon-x/internal/finding"
	"github.com/bytezora/recon-x/internal/httpcheck"
)

type Result struct {
	URL       string
	Token     string
	Algorithm string
	Claims    map[string]interface{}
	Issue     string
	Evidence  string
	Severity  string
}

func (r Result) ToFinding() finding.Finding {
	sev := finding.Medium
	conf := finding.Likely
	switch r.Severity {
	case "critical":
		sev = finding.Critical
		conf = finding.Confirmed
	case "high":
		sev = finding.High
	}
	return finding.Finding{
		Type:               "jwt",
		Severity:           sev,
		Confidence:         conf,
		Title:              "JWT Security Issue: " + r.Issue,
		AffectedURL:        r.URL,
		Evidence:           r.Evidence,
		Reason:             r.Issue,
		Remediation:        "Use strong algorithms (RS256/ES256). Always verify signature. Include exp claim. Avoid sensitive data in payload.",
		ManualVerification: r.Severity != "critical",
	}
}

var jwtRegex = regexp.MustCompile(`[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+`)

var sensitiveClaims = []string{"password", "secret", "key", "token", "ssn", "passwd", "pwd", "apikey", "api_key"}

func ExtractTokens(body string) []string {
	matches := jwtRegex.FindAllString(body, -1)
	var tokens []string
	seen := map[string]bool{}
	for _, m := range matches {
		if seen[m] {
			continue
		}
		parts := strings.Split(m, ".")
		if len(parts) != 3 {
			continue
		}
		if _, err := DecodeSegment(parts[0]); err == nil {
			seen[m] = true
			tokens = append(tokens, m)
		}
	}
	return tokens
}

func DecodeSegment(seg string) (map[string]interface{}, error) {
	// Try RawURLEncoding first (no padding)
	data, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		// Add padding and try standard URL encoding
		switch len(seg) % 4 {
		case 2:
			seg += "=="
		case 3:
			seg += "="
		}
		data, err = base64.URLEncoding.DecodeString(seg)
		if err != nil {
			return nil, err
		}
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func analyzeToken(rawURL, token string) []Result {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}

	header, err := DecodeSegment(parts[0])
	if err != nil {
		return nil
	}
	payload, err := DecodeSegment(parts[1])
	if err != nil {
		return nil
	}

	alg, _ := header["alg"].(string)
	var results []Result

	if strings.ToLower(alg) == "none" || alg == "" {
		results = append(results, Result{
			URL:       rawURL,
			Token:     truncate(token, 50) + "...",
			Algorithm: alg,
			Claims:    payload,
			Issue:     "alg:none — JWT signature not verified",
			Evidence:  "JWT header specifies alg=none, meaning any forged token will be accepted",
			Severity:  "critical",
		})
	}

	if _, hasExp := payload["exp"]; !hasExp {
		results = append(results, Result{
			URL:       rawURL,
			Token:     truncate(token, 50) + "...",
			Algorithm: alg,
			Claims:    payload,
			Issue:     "Missing exp claim — JWT never expires",
			Evidence:  "JWT payload has no 'exp' field; token is valid indefinitely",
			Severity:  "medium",
		})
	}

	for _, key := range sensitiveClaims {
		for claimKey, claimVal := range payload {
			if strings.Contains(strings.ToLower(claimKey), key) {
				evidence := "Sensitive field in JWT payload: " + claimKey
				if s, ok := claimVal.(string); ok && len(s) > 0 {
					evidence += " = " + truncate(s, 20)
				}
				results = append(results, Result{
					URL:       rawURL,
					Token:     truncate(token, 50) + "...",
					Algorithm: alg,
					Claims:    payload,
					Issue:     "Sensitive data in JWT payload: " + claimKey,
					Evidence:  evidence,
					Severity:  "medium",
				})
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

func Analyze(httpResults []httpcheck.Result, threads int, onFound func(Result)) []Result {
	if threads <= 0 {
		threads = 10
	}

	var (
		mu      sync.Mutex
		results []Result
		wg      sync.WaitGroup
		sem     = make(chan struct{}, threads)
		seen    = make(map[string]bool)
	)

	for _, h := range httpResults {
		if h.Body == "" {
			continue
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(hr httpcheck.Result) {
			defer func() { <-sem; wg.Done() }()
			tokens := ExtractTokens(hr.Body)
			for _, tok := range tokens {
				for _, r := range analyzeToken(hr.URL, tok) {
					key := hr.URL + "|" + truncate(tok, 30) + "|" + r.Issue
					mu.Lock()
					if !seen[key] {
						seen[key] = true
						results = append(results, r)
						if onFound != nil {
							onFound(r)
						}
					}
					mu.Unlock()
				}
			}
		}(h)
	}
	wg.Wait()
	return results
}
