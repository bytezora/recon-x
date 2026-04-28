package wayback

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/bytezora/recon-x/internal/httpclient"
)

type Result struct {
	URL        string
	Timestamp  string
	StatusCode string
}

var interestingExts = map[string]bool{
	".php": true, ".asp": true, ".aspx": true, ".jsp": true,
	".json": true, ".xml": true, ".conf": true, ".bak": true,
	".sql": true, ".env": true, ".yml": true, ".yaml": true,
	".log": true, ".txt": true, ".key": true, ".pem": true,
}

func isInteresting(rawURL string) bool {
	if strings.Contains(rawURL, "?") {
		return true
	}
	lower := strings.ToLower(rawURL)
	for ext := range interestingExts {
		if strings.HasSuffix(lower, ext) || strings.Contains(lower, ext+"?") || strings.Contains(lower, ext+"&") {
			return true
		}
	}
	return false
}

func Fetch(domain string, onFound func(Result)) []Result {
	client := httpclient.New(30*time.Second, true)

	apiURL := fmt.Sprintf(
		"http://web.archive.org/cdx/search/cdx?url=*.%s&output=json&fl=original,timestamp,statuscode&collapse=urlkey&limit=5000",
		domain,
	)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; recon-x)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil
	}

	var rows [][]string
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil
	}

	seen := map[string]bool{}
	var results []Result

	for i, row := range rows {
		if i == 0 {
			continue
		}
		if len(row) < 3 {
			continue
		}
		rawURL := row[0]
		timestamp := row[1]
		statusCode := row[2]

		if !isInteresting(rawURL) {
			continue
		}
		if seen[rawURL] {
			continue
		}
		seen[rawURL] = true

		r := Result{
			URL:        rawURL,
			Timestamp:  timestamp,
			StatusCode: statusCode,
		}
		results = append(results, r)
		if onFound != nil {
			onFound(r)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].URL < results[j].URL
	})

	return results
}
