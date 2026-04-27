// Package crtsh queries the Certificate Transparency log at crt.sh
// to passively discover subdomains without sending any DNS traffic.
package crtsh

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const apiURL = "https://crt.sh/?q=%%.%s&output=json"

type entry struct {
	NameValue string `json:"name_value"`
}

// Lookup returns unique subdomains for domain found in CT logs.
func Lookup(domain string) ([]string, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(fmt.Sprintf(apiURL, domain))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var entries []entry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	results := make([]string, 0, len(entries))

	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			if name == "" || strings.HasPrefix(name, "*") || seen[name] {
				continue
			}
			if strings.HasSuffix(name, "."+domain) || name == domain {
				seen[name] = true
				results = append(results, name)
			}
		}
	}

	return results, nil
}
