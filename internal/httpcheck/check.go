package httpcheck

import (
"fmt"
"io"
"net/http"
"strings"
"sync"
"time"

"github.com/bytezora/recon-x/internal/httpclient"
"github.com/bytezora/recon-x/internal/portscan"
)

const bodyLimit = 512 * 1024

var httpPorts = map[int]bool{
80: true, 443: true,
3000: true, 4000: true, 5000: true,
8000: true, 8001: true, 8008: true,
8080: true, 8443: true, 8888: true,
4443: true, 7443: true,
9000: true, 9090: true,
9200: true, 9300: true,
5601: true,
15672: true,
}

var secHeaders = []string{
"Strict-Transport-Security",
"Content-Security-Policy",
"X-Frame-Options",
"X-Content-Type-Options",
"Referrer-Policy",
"Permissions-Policy",
}

type Result struct {
URL            string
Host           string
Port           int
StatusCode     int
Title          string
Server         string
Tech           []string
Redirect       string
MissingHeaders []string
Headers        http.Header `json:"-"`
Body           string      `json:"-"`
}

func Check(ports []portscan.Result, threads int) []Result {
results := make([]Result, 0, 16)
mu      := sync.Mutex{}
sem     := make(chan struct{}, threads)
wg      := sync.WaitGroup{}

client := httpclient.New(10*time.Second, false)

for _, p := range ports {
if !httpPorts[p.Port] {
continue
}
sem <- struct{}{}
wg.Add(1)

go func(port portscan.Result) {
defer func() { <-sem; wg.Done() }()

scheme := schemeFor(port.Port)
url    := fmt.Sprintf("%s://%s:%d", scheme, port.Host, port.Port)

if r := probe(client, url, port.Host, port.Port); r != nil {
mu.Lock()
results = append(results, *r)
mu.Unlock()
}
}(p)
}

wg.Wait()
return results
}

func schemeFor(port int) string {
switch port {
case 443, 8443, 4443, 7443, 9300:
return "https"
}
return "http"
}

func probe(client *http.Client, url, host string, port int) *Result {
resp, err := client.Get(url)
if err != nil {
return nil
}
defer resp.Body.Close()

body := readBody(resp.Body)

return &Result{
URL:            url,
Host:           host,
Port:           port,
StatusCode:     resp.StatusCode,
Title:          extractTitle(body),
Server:         resp.Header.Get("Server"),
Tech:           detectTech(resp.Header, body),
Redirect:       resp.Header.Get("Location"),
MissingHeaders: checkSecHeaders(resp.Header),
Headers:        resp.Header,
Body:           body,
}
}

func checkSecHeaders(h http.Header) []string {
var missing []string
for _, name := range secHeaders {
if h.Get(name) == "" {
missing = append(missing, name)
}
}
return missing
}

func readBody(r io.Reader) string {
data, _ := io.ReadAll(io.LimitReader(r, bodyLimit))
return string(data)
}

func extractTitle(body string) string {
low := strings.ToLower(body)
s   := strings.Index(low, "<title>")
e   := strings.Index(low, "</title>")
if s == -1 || e <= s+7 {
return ""
}
title := strings.TrimSpace(body[s+7 : e])
if len(title) > 80 {
return title[:80] + "..."
}
return title
}

func detectTech(h http.Header, body string) []string {
tech := make([]string, 0, 4)
add  := func(t string) { tech = append(tech, t) }

srv := strings.ToLower(h.Get("Server"))
xpb := strings.ToLower(h.Get("X-Powered-By"))
b   := strings.ToLower(body)

switch {
case strings.Contains(srv, "nginx"):    add("Nginx")
case strings.Contains(srv, "apache"):   add("Apache")
case strings.Contains(srv, "iis"):      add("IIS")
case strings.Contains(srv, "caddy"):    add("Caddy")
case strings.Contains(srv, "gunicorn"): add("Gunicorn")
}

switch {
case strings.Contains(xpb, "php"):     add("PHP")
case strings.Contains(xpb, "asp.net"): add("ASP.NET")
case strings.Contains(xpb, "express"): add("Express.js")
case strings.Contains(xpb, "next.js"): add("Next.js")
}

if h.Get("CF-Ray") != ""           { add("Cloudflare") }
if h.Get("X-Amz-Request-Id") != "" { add("AWS") }

if strings.Contains(b, "wp-content") || strings.Contains(b, "wordpress") { add("WordPress") }
if strings.Contains(b, "drupal")  { add("Drupal") }
if strings.Contains(b, "joomla")  { add("Joomla") }

if strings.Contains(b, "react")   { add("React") }
if strings.Contains(b, "vue.js")  { add("Vue.js") }
if strings.Contains(b, "angular") { add("Angular") }
if strings.Contains(b, "jquery")  { add("jQuery") }
if strings.Contains(b, "laravel") { add("Laravel") }
if strings.Contains(b, "django")  { add("Django") }
if strings.Contains(b, "fastapi") { add("FastAPI") }

return tech
}
