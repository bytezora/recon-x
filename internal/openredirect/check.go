package openredirect

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bytezora/recon-x/internal/httpclient"
)

var params = []string{
	"url", "redirect", "next", "redir", "return", "returnUrl",
	"goto", "forward", "dest", "destination", "target", "to",
	"return_to", "back", "callback", "link", "redirect_uri", "continue",
	"ref", "referer", "u", "r",
}

const testDomain = "evil.com"

type Result struct {
	BaseURL   string `json:"base_url"`
	Param     string `json:"param"`
	Location  string `json:"location"`
	Confirmed bool   `json:"confirmed"`
}

func Check(baseURLs []string, threads int, onFound func(Result)) []Result {
	client := httpclient.New(10*time.Second, false)
	seen := make(map[string]bool)
	var deduped []string
	for _, u := range baseURLs {
		if !seen[u] {
			seen[u] = true
			deduped = append(deduped, u)
		}
	}

	type job struct{ baseURL, param string }
	var jobs []job
	for _, u := range deduped {
		for _, p := range params {
			jobs = append(jobs, job{u, p})
		}
	}

	var results []Result
	mu := sync.Mutex{}
	sem := make(chan struct{}, threads)
	wg := sync.WaitGroup{}

	for _, j := range jobs {
		sem <- struct{}{}
		wg.Add(1)
		go func(baseURL, param string) {
			defer func() { <-sem; wg.Done() }()
			r := testParam(client, baseURL, param)
			if r == nil {
				return
			}
			mu.Lock()
			results = append(results, *r)
			mu.Unlock()
			if onFound != nil {
				onFound(*r)
			}
		}(j.baseURL, j.param)
	}
	wg.Wait()
	return results
}

func testParam(client *http.Client, baseURL, param string) *Result {
	sep := "?"
	if strings.Contains(baseURL, "?") {
		sep = "&"
	}

	for _, payload := range []string{"https://evil.com", "//evil.com"} {
		testURL := fmt.Sprintf("%s%s%s=%s", baseURL, sep, param, url.QueryEscape(payload))

		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; recon-x/1.3)")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			continue
		}

		loc := resp.Header.Get("Location")
		if loc == "" {
			continue
		}

		if strings.Contains(strings.ToLower(loc), testDomain) {
			return &Result{
				BaseURL:   baseURL,
				Param:     param,
				Location:  loc,
				Confirmed: true,
			}
		}
	}
	return nil
}
