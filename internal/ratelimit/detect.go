package ratelimit

import (
	"net/http"

	"github.com/bytezora/recon-x/internal/httpcheck"
)

type Result struct {
	URL    string
	Header string
	Value  string
}

var rateLimitHeaders = []string{
	"X-RateLimit-Limit",
	"X-RateLimit-Remaining",
	"X-RateLimit-Reset",
	"X-Rate-Limit-Limit",
	"RateLimit-Limit",
	"RateLimit-Remaining",
	"Retry-After",
	"X-Ratelimit-Limit",
	"X-Throttle-Limit",
}

func Detect(httpResults []httpcheck.Result) []Result {
	var results []Result
	for _, h := range httpResults {
		if h.Headers == nil {
			continue
		}
		for _, name := range rateLimitHeaders {
			if val := h.Headers.Get(name); val != "" {
				canonical := http.CanonicalHeaderKey(name)
				results = append(results, Result{
					URL:    h.URL,
					Header: canonical,
					Value:  val,
				})
			}
		}
	}
	return results
}
