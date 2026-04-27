package sqli

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bytezora/recon-x/internal/httpclient"
)

type Result struct {
	URL        string
	Param      string
	Payload    string
	Evidence   string
	Confidence string
	Detected   bool
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

func getBaseline(client *http.Client, rawURL string) string {
	resp, err := client.Get(rawURL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func bodyDiffers(baseline, body string) bool {
	h := sha256.Sum256([]byte(body))
	return hex.EncodeToString(h[:]) != baseline
}

func Detect(baseURLs []string, threads int, onFound func(Result)) []Result {
	if threads <= 0 {
		threads = 30
	}
	client := httpclient.New(10*time.Second, false)

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

	baseline := getBaseline(client, rawURL)

	var results []Result
	for param := range params {
		for _, payload := range payloads {
			testParams := url.Values{}
			for k, v := range params {
				testParams[k] = v
			}
			testParams.Set(param, payload)

			testURLCopy := *parsed
			testURLCopy.RawQuery = testParams.Encode()

			resp, err := client.Get(testURLCopy.String())
			if err != nil {
				continue
			}
			data, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
			resp.Body.Close()
			body := string(data)

			differs := bodyDiffers(baseline, body)

			for _, errStr := range sqlErrors {
				if strings.Contains(body, errStr) {
					confidence := "medium"
					if differs {
						confidence = "high"
					}
					results = append(results, Result{
						URL:        rawURL,
						Param:      param,
						Payload:    payload,
						Evidence:   errStr,
						Confidence: confidence,
						Detected:   true,
					})
					goto nextParam
				}
			}
		}
	nextParam:
	}
	return results
}
