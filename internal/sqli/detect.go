package sqli

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Result struct {
	URL      string
	Param    string
	Payload  string
	Evidence string
	Detected bool
}

var sqlErrors = []string{
	"mysql_fetch", "syntax error", "ORA-", "pg_query", "SQLite",
	"sql syntax", "You have an error in your SQL syntax",
	"Warning: mysql", "Unclosed quotation", "Microsoft OLE DB",
	"ODBC SQL",
}

var payloads = []string{
	"'", `"`, "1' OR '1'='1", "1 AND 1=2",
}

func Detect(baseURLs []string, threads int, onFound func(Result)) []Result {
	if threads <= 0 {
		threads = 30
	}
	client := &http.Client{
		Timeout: 6 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyFromEnvironment,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var (
		mu      sync.Mutex
		results []Result
		wg      sync.WaitGroup
		sem     = make(chan struct{}, threads)
	)

	for _, rawURL := range baseURLs {
		sem <- struct{}{}
		wg.Add(1)
		go func(rawURL string) {
			defer func() { <-sem; wg.Done() }()
			found := testURL(client, rawURL)
			if len(found) > 0 {
				mu.Lock()
				for _, r := range found {
					results = append(results, r)
					if onFound != nil {
						onFound(r)
					}
				}
				mu.Unlock()
			}
		}(rawURL)
	}
	wg.Wait()
	return results
}

func testURL(client *http.Client, rawURL string) []Result {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}

	params := parsed.Query()
	if len(params) == 0 {
		params.Set("id", "1")
	}

	var results []Result
	for param := range params {
		for _, payload := range payloads {
			testParams := url.Values{}
			for k, v := range params {
				testParams[k] = v
			}
			testParams.Set(param, payload)

			testURL := *parsed
			testURL.RawQuery = testParams.Encode()

			resp, err := client.Get(testURL.String())
			if err != nil {
				continue
			}
			data, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
			resp.Body.Close()
			body := string(data)

			for _, errStr := range sqlErrors {
				if strings.Contains(body, errStr) {
					results = append(results, Result{
						URL:      rawURL,
						Param:    param,
						Payload:  payload,
						Evidence: errStr,
						Detected: true,
					})
					goto nextParam
				}
			}
		}
	nextParam:
	}
	return results
}
