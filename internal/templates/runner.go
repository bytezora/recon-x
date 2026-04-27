package templates

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bytezora/recon-x/internal/httpclient"
)

func Run(tmpls []Template, targets []string, threads int, onMatch func(Match)) []Match {
	client := httpclient.New(10*time.Second, true)
	type job struct {
		tpl    Template
		target string
	}
	var jobs []job
	for _, t := range tmpls {
		for _, target := range targets {
			jobs = append(jobs, job{t, target})
		}
	}

	var (
		mu      sync.Mutex
		matches []Match
		wg      sync.WaitGroup
		sem     = make(chan struct{}, threads)
	)

	for _, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(j job) {
			defer wg.Done()
			defer func() { <-sem }()
			m := runOne(client, j.tpl, j.target)
			if m == nil {
				return
			}
			mu.Lock()
			matches = append(matches, *m)
			mu.Unlock()
			if onMatch != nil {
				onMatch(*m)
			}
		}(j)
	}
	wg.Wait()
	return matches
}

func runOne(client *http.Client, t Template, target string) *Match {
	target = strings.TrimRight(target, "/")
	rawURL := fmt.Sprintf("%s%s", target, t.Request.Path)
	method := t.Request.Method
	if method == "" {
		method = "GET"
	}

	var body io.Reader
	if t.Request.Body != "" {
		body = strings.NewReader(t.Request.Body)
	}

	req, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		return nil
	}
	for k, v := range t.Request.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	respStr := string(respBody)

	for _, matcher := range t.Matchers {
		switch matcher.Type {
		case "status":
			for _, code := range matcher.Status {
				if resp.StatusCode == code {
					return &Match{
						TemplateID: t.ID,
						Name:       t.Name,
						Severity:   t.Severity,
						Tags:       t.Tags,
						URL:        rawURL,
						Matched:    fmt.Sprintf("status:%d", resp.StatusCode),
					}
				}
			}
		case "word":
			for _, word := range matcher.Words {
				if strings.Contains(respStr, word) {
					return &Match{
						TemplateID: t.ID,
						Name:       t.Name,
						Severity:   t.Severity,
						Tags:       t.Tags,
						URL:        rawURL,
						Matched:    word,
					}
				}
			}
		}
	}
	return nil
}
