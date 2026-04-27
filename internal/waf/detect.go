// Package waf detects Web Application Firewalls from HTTP response headers,
// cookies, and body content.
package waf

import (
"net/http"
"strings"
)

// Result holds a WAF detection for a specific host.
type Result struct {
Host string
URL  string
WAF  string
}

type detector func(h http.Header, cookies, body string) bool

var vendors = []struct {
name    string
matches detector
}{
{"Cloudflare", func(h http.Header, _, _ string) bool {
return h.Get("CF-Ray") != "" || h.Get("cf-cache-status") != ""
}},
{"Akamai", func(h http.Header, _, _ string) bool {
return h.Get("X-Check-Cacheable") != "" ||
strings.Contains(h.Get("Server"), "AkamaiGHost")
}},
{"Imperva / Incapsula", func(h http.Header, cookies, _ string) bool {
return h.Get("X-Iinfo") != "" ||
strings.Contains(cookies, "incap_ses") ||
strings.Contains(cookies, "visid_incap")
}},
{"Sucuri", func(h http.Header, _, _ string) bool {
return h.Get("X-Sucuri-ID") != "" || h.Get("X-Sucuri-Cache") != ""
}},
{"AWS CloudFront / WAF", func(h http.Header, _, _ string) bool {
return h.Get("X-AMZ-CF-ID") != "" || h.Get("x-amzn-requestid") != "" || h.Get("X-Amzn-Trace-Id") != ""
}},
{"F5 BIG-IP", func(h http.Header, cookies, _ string) bool {
return h.Get("X-WA-Info") != "" ||
strings.Contains(cookies, "BIGipServer") ||
strings.Contains(h.Get("Server"), "BigIP")
}},
{"Barracuda", func(h http.Header, cookies, _ string) bool {
return strings.Contains(cookies, "barra_counter_session") ||
strings.Contains(cookies, "BNI__BARRACUDA_LB_COOKIE")
}},
{"ModSecurity", func(h http.Header, _, _ string) bool {
return h.Get("X-Engine") == "mod_security" ||
strings.Contains(h.Get("Server"), "mod_security")
}},
{"Fastly", func(h http.Header, _, _ string) bool {
return h.Get("X-Fastly-Request-ID") != "" || h.Get("Fastly-Restarts") != ""
}},
{"Varnish", func(h http.Header, _, body string) bool {
return strings.Contains(h.Get("X-Varnish"), " ") ||
strings.Contains(body, "Varnish cache server")
}},
}

// Detect checks response headers, cookies, and body for known WAF signatures.
// Returns all matching WAFs (a host may trigger multiple signatures).
func Detect(host, url string, h http.Header, body string) []Result {
cookies := strings.Join(h["Set-Cookie"], "; ")
var results []Result
for _, v := range vendors {
if v.matches(h, cookies, body) {
results = append(results, Result{Host: host, URL: url, WAF: v.name})
}
}
return results
}
