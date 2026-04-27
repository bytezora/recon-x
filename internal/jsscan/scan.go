// Package jsscan extracts JavaScript file URLs from HTTP responses,
// then scans those files for API endpoints and potential secrets.
package jsscan

import (
"crypto/tls"
"io"
"net/http"
"regexp"
"strings"
"sync"
"time"
)

// Finding represents a discovered endpoint or secret in a JS file.
type Finding struct {
Source string // URL of the JS file
Kind   string // "endpoint" or "secret"
Label  string // secret type label or "endpoint"
Value  string // the matched value
}

var (
reScriptSrc = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+\.js[^"']*)["']`)
reEndpoint  = regexp.MustCompile(`["'](/(?:api|v\d|graphql|rest|service)[a-zA-Z0-9/_\-.?=&]{2,64})["']`)

secretPatterns = []struct {
label string
re    *regexp.Regexp
}{
{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
{"API Key", regexp.MustCompile(`(?i)["']?api[_-]?key["']?\s*[:=]\s*["']([a-zA-Z0-9_\-]{16,64})["']`)},
{"Secret", regexp.MustCompile(`(?i)["']?secret["']?\s*[:=]\s*["']([a-zA-Z0-9_\-]{16,64})["']`)},
{"Token", regexp.MustCompile(`(?i)["']?(?:access[_-]?)?token["']?\s*[:=]\s*["']([a-zA-Z0-9_\-.]{16,128})["']`)},
{"Password", regexp.MustCompile(`(?i)["']?pass(?:word)?["']?\s*[:=]\s*["']([^"']{8,64})["']`)},
{"Bearer Token", regexp.MustCompile(`Bearer\s+[a-zA-Z0-9\-._~+/]{20,}=*`)},
{"MongoDB URI", regexp.MustCompile(`mongodb(?:\+srv)?://[^\s"']{10,}`)},
{"PostgreSQL URI", regexp.MustCompile(`postgres(?:ql)?://[^\s"']{10,}`)},
{"Private Key", regexp.MustCompile(`-----BEGIN (?:RSA |EC )?PRIVATE KEY-----`)},
}
)

const (
fetchTimeout = 10 * time.Second
bodyLimit    = 1024 * 1024
)

var client = &http.Client{
Timeout: fetchTimeout,
Transport: &http.Transport{
TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
Proxy:           http.ProxyFromEnvironment,
},
}

// Scan finds JS files referenced in the given HTML bodies and scans them.
func Scan(pages map[string]string, threads int, onFound func(Finding)) []Finding {
jsURLs := make(map[string]bool)
for pageURL, body := range pages {
base := baseOf(pageURL)
for _, m := range reScriptSrc.FindAllStringSubmatch(body, -1) {
src := m[1]
if strings.HasPrefix(src, "http") {
jsURLs[src] = true
} else if strings.HasPrefix(src, "/") {
jsURLs[base+src] = true
}
}
}

results := make([]Finding, 0, 32)
mu      := sync.Mutex{}
sem     := make(chan struct{}, threads)
wg      := sync.WaitGroup{}
seen := make(map[string]bool)
seenMu := sync.Mutex{}

for jsURL := range jsURLs {
sem <- struct{}{}
wg.Add(1)

go func(u string) {
defer func() { <-sem; wg.Done() }()

body := fetchJS(u)
if body == "" {
return
}

var found []Finding

for _, m := range reEndpoint.FindAllStringSubmatch(body, -1) {
key := "endpoint:" + m[1]
seenMu.Lock()
dup := seen[key]
if !dup {
seen[key] = true
}
seenMu.Unlock()
if !dup {
found = append(found, Finding{Source: u, Kind: "endpoint", Label: "endpoint", Value: m[1]})
}
}

for _, sp := range secretPatterns {
for _, m := range sp.re.FindAllString(body, -1) {
val := m
if len(val) > 80 {
val = val[:80] + "..."
}
key := sp.label + ":" + val
seenMu.Lock()
dup := seen[key]
if !dup {
seen[key] = true
}
seenMu.Unlock()
if !dup {
found = append(found, Finding{Source: u, Kind: "secret", Label: sp.label, Value: val})
}
}
}

if len(found) == 0 {
return
}

mu.Lock()
results = append(results, found...)
mu.Unlock()

if onFound != nil {
for _, f := range found {
onFound(f)
}
}
}(jsURL)
}

wg.Wait()
return results
}

func fetchJS(url string) string {
resp, err := client.Get(url)
if err != nil {
return ""
}
defer resp.Body.Close()

if resp.StatusCode != http.StatusOK {
return ""
}

ct := resp.Header.Get("Content-Type")
if !strings.Contains(ct, "javascript") && !strings.Contains(ct, "text") {
return ""
}

data, _ := io.ReadAll(io.LimitReader(resp.Body, bodyLimit))
return string(data)
}

func baseOf(pageURL string) string {
sep := strings.Index(pageURL, "://")
if sep == -1 {
return pageURL
}
rest := pageURL[sep+3:]
if idx := strings.Index(rest, "/"); idx != -1 {
return pageURL[:sep+3+idx]
}
return pageURL
}
