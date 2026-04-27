package graphql

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Result struct {
	URL           string   `json:"url"`
	Endpoint      string   `json:"endpoint"`
	Introspection bool     `json:"introspection"`
	Types         []string `json:"types,omitempty"`
}

var paths = []string{
	"/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql", "/v2/graphql",
	"/query", "/api/query", "/graphiql", "/playground", "/altair",
	"/graphql/console", "/api/v1/graphql", "/api/v2/graphql", "/gql",
}

var client = &http.Client{
	Timeout: 8 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

func Probe(baseURLs []string, threads int, onFound func(Result)) []Result {
	var (
		mu      sync.Mutex
		results []Result
		wg      sync.WaitGroup
		sem     = make(chan struct{}, threads)
	)
	for _, u := range baseURLs {
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()
			for _, r := range probeOne(u) {
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

func probeOne(baseURL string) []Result {
	base := strings.TrimRight(baseURL, "/")
	var results []Result
	for _, p := range paths {
		endpoint := base + p
		if !isGraphQL(endpoint) {
			continue
		}
		r := Result{URL: baseURL, Endpoint: endpoint}
		types, ok := introspect(endpoint)
		if ok {
			r.Introspection = true
			r.Types = types
		}
		results = append(results, r)
	}
	return results
}

func isGraphQL(endpoint string) bool {
	resp, err := client.Get(endpoint)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if resp.StatusCode == 400 {
		return true
	}
	return strings.Contains(s, `"data"`) || strings.Contains(s, `"errors"`) || strings.Contains(s, `"__schema"`)
}

func introspect(endpoint string) ([]string, bool) {
	query := `{"query":"{ __schema { types { name } } }"}`
	req, err := http.NewRequest("POST", endpoint, bytes.NewBufferString(query))
	if err != nil {
		return nil, false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Data struct {
			Schema struct {
				Types []struct {
					Name string `json:"name"`
				} `json:"types"`
			} `json:"__schema"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, false
	}
	var types []string
	for _, t := range result.Data.Schema.Types {
		if !strings.HasPrefix(t.Name, "__") {
			types = append(types, t.Name)
		}
	}
	if len(types) == 0 {
		return nil, false
	}
	return types, true
}
