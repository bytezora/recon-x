package httpclient

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

var (
	globalRetries int
	globalLimiter *rate.Limiter
)

func SetRetries(n int) { globalRetries = n }

func SetRate(rps int) {
	if rps > 0 {
		globalLimiter = rate.NewLimiter(rate.Limit(rps), rps)
	}
}

type resilientTransport struct {
	base    http.RoundTripper
	retries int
	limiter *rate.Limiter
}

func (t *resilientTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.limiter != nil {
		ctx, cancel := context.WithTimeout(req.Context(), 30*time.Second)
		defer cancel()
		t.limiter.Wait(ctx)
	}
	if t.retries <= 0 || req.Body != nil && req.Body != http.NoBody {
		return t.base.RoundTrip(req)
	}
	var (
		resp *http.Response
		err  error
	)
	for i := 0; i <= t.retries; i++ {
		if i > 0 {
			time.Sleep(time.Duration(1<<uint(i-1)) * time.Second)
		}
		resp, err = t.base.RoundTrip(req.Clone(req.Context()))
		if err == nil {
			return resp, nil
		}
	}
	return resp, err
}

func New(timeout time.Duration, followRedirects bool) *http.Client {
	base := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Proxy:           http.ProxyFromEnvironment,
	}
	wrapped := &resilientTransport{
		base:    base,
		retries: globalRetries,
		limiter: globalLimiter,
	}
	client := &http.Client{Timeout: timeout, Transport: wrapped}
	if !followRedirects {
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client
}
