package ghsearch

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bytezora/recon-x/internal/httpclient"
)

type Finding struct {
	Repo    string `json:"repo"`
	Path    string `json:"path"`
	URL     string `json:"url"`
	Keyword string `json:"keyword"`
}

var keywords = []string{
	"password", "api_key", "apikey", "secret", "token",
	"private_key", "aws_access_key", "db_password",
}

type ghItem struct {
	Path    string `json:"path"`
	HTMLURL string `json:"html_url"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
}

type ghResponse struct {
	Items []ghItem `json:"items"`
}

func Search(target, token string, onFound func(Finding)) []Finding {
	base := strings.SplitN(target, ".", 2)[0]
	queries := []string{
		fmt.Sprintf("org:%s", base),
		fmt.Sprintf("%q", target),
	}

	client := httpclient.New(15*time.Second, true)
	var all []Finding
	seen := make(map[string]bool)

	for _, q := range queries {
		for _, kw := range keywords {
			encoded := url.QueryEscape(q + " " + kw)
			req, err := http.NewRequest("GET",
				"https://api.github.com/search/code?q="+encoded+"&per_page=10", nil)
			if err != nil {
				continue
			}
			req.Header.Set("Accept", "application/vnd.github.v3+json")
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}

			resp, err := client.Do(req)
			if err != nil {
				time.Sleep(3 * time.Second)
				continue
			}
			if resp.StatusCode >= 400 {
				resp.Body.Close()
				time.Sleep(3 * time.Second)
				continue
			}

			var result ghResponse
			json.NewDecoder(resp.Body).Decode(&result)
			resp.Body.Close()

			for _, item := range result.Items {
				key := item.Repository.FullName + "/" + item.Path
				if seen[key] {
					continue
				}
				seen[key] = true
				f := Finding{
					Repo:    item.Repository.FullName,
					Path:    item.Path,
					URL:     item.HTMLURL,
					Keyword: kw,
				}
				all = append(all, f)
				if onFound != nil {
					onFound(f)
				}
			}

			if token == "" {
				time.Sleep(8 * time.Second)
			} else {
				time.Sleep(2 * time.Second)
			}
		}
	}

	return all
}
