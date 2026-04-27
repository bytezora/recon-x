package buckets

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bytezora/recon-x/internal/httpclient"
)

type Result struct {
	Bucket   string `json:"bucket"`
	Provider string `json:"provider"`
	URL      string `json:"url"`
	Status   string `json:"status"`
	Code     int    `json:"code"`
}

var suffixes = []string{
	"", "-backup", "-backups", "-assets", "-static", "-media",
	"-dev", "-development", "-staging", "-prod", "-production",
	"-data", "-logs", "-files", "-public", "-archive",
	"-uploads", "-images", "-test", "-web", "-app", "-api",
	"-config", "-deploy", "-release", "-build",
}

func classify(code int) string {
	switch {
	case code == 200 || code == 206:
		return "public"
	case code == 403 || code == 401 || code == 405:
		return "exists"
	default:
		return ""
	}
}

func probe(client *http.Client, name, provider, urlFmt string) *Result {
	u := fmt.Sprintf(urlFmt, name)
	resp, err := client.Head(u)
	if err != nil {
		return nil
	}
	resp.Body.Close()
	s := classify(resp.StatusCode)
	if s == "" {
		return nil
	}
	return &Result{Bucket: name, Provider: provider, URL: u, Status: s, Code: resp.StatusCode}
}

func Enum(target string, threads int, onFound func(Result)) []Result {
	client := httpclient.New(10*time.Second, false)
	base := strings.ToLower(strings.SplitN(target, ".", 2)[0])

	names := make([]string, 0, len(suffixes))
	for _, s := range suffixes {
		names = append(names, base+s)
	}

	type job struct {
		name     string
		provider string
		urlFmt   string
	}

	var jobs []job
	for _, name := range names {
		jobs = append(jobs,
			job{name, "AWS S3", "https://%s.s3.amazonaws.com"},
			job{name, "GCS", "https://storage.googleapis.com/%s"},
			job{name, "Azure", "https://%s.blob.core.windows.net"},
		)
	}

	var results []Result
	mu := sync.Mutex{}
	sem := make(chan struct{}, threads)
	wg := sync.WaitGroup{}

	for _, j := range jobs {
		sem <- struct{}{}
		wg.Add(1)
		go func(j job) {
			defer func() { <-sem; wg.Done() }()
			r := probe(client, j.name, j.provider, j.urlFmt)
			if r == nil {
				return
			}
			mu.Lock()
			results = append(results, *r)
			mu.Unlock()
			if onFound != nil {
				onFound(*r)
			}
		}(j)
	}

	wg.Wait()
	return results
}
