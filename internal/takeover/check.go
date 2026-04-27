package takeover

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Result struct {
	Subdomain  string `json:"subdomain"`
	CNAME      string `json:"cname"`
	Service    string `json:"service"`
	Vulnerable bool   `json:"vulnerable"`
}

var fingerprints = map[string]string{
	"github.io":               "There isn't a GitHub Pages site here",
	"herokuapp.com":           "No such app",
	"netlify.app":             "Not Found - Request ID",
	"netlify.com":             "Not Found - Request ID",
	"s3.amazonaws.com":        "NoSuchBucket",
	"storage.googleapis.com":  "NoSuchBucket",
	"azurewebsites.net":       "404 Web Site not found",
	"cloudapp.net":            "404 Web Site not found",
	"fastly.net":              "Fastly error: unknown domain",
	"wpengine.com":            "The site you were looking for couldn't be found",
	"zendesk.com":             "Help Center Closed",
	"freshdesk.com":           "There is no helpdesk here",
	"readme.io":               "Project doesnt exist",
	"surge.sh":                "project not found",
	"fly.dev":                 "404 Not Found",
	"pantheon.io":             "The site you were looking for couldn't be found",
}

var client = &http.Client{
	Timeout: 8 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

func Check(subdomains []string, threads int, onFound func(Result)) []Result {
	var (
		mu      sync.Mutex
		results []Result
		wg      sync.WaitGroup
		sem     = make(chan struct{}, threads)
	)
	for _, sub := range subdomains {
		wg.Add(1)
		sem <- struct{}{}
		go func(sub string) {
			defer wg.Done()
			defer func() { <-sem }()
			r := checkOne(sub)
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
			if onFound != nil {
				onFound(r)
			}
		}(sub)
	}
	wg.Wait()
	return results
}

func checkOne(sub string) Result {
	r := Result{Subdomain: sub}
	cname, err := net.LookupCNAME(sub)
	if err != nil {
		return r
	}
	cname = strings.TrimSuffix(cname, ".")
	if cname == sub || cname == sub+"." {
		return r
	}
	r.CNAME = cname
	for svc, fp := range fingerprints {
		if strings.Contains(cname, svc) {
			r.Service = svc
			resp, err := client.Get("http://" + cname)
			if err != nil {
				resp2, err2 := client.Get("https://" + cname)
				if err2 != nil {
					break
				}
				defer resp2.Body.Close()
				body, _ := io.ReadAll(resp2.Body)
				if strings.Contains(string(body), fp) {
					r.Vulnerable = true
				}
				break
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if strings.Contains(string(body), fp) {
				r.Vulnerable = true
			}
			break
		}
	}
	return r
}
