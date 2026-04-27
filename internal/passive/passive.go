package passive

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bytezora/recon-x/internal/httpclient"
)

type Source func(domain string) ([]string, error)

func All() []Source {
	return []Source{CertSpotter, HackerTarget, AlienVaultOTX, URLScan}
}

func Gather(domain string) []string {
	seen := make(map[string]bool)
	var results []string
	for _, fn := range All() {
		names, err := fn(domain)
		if err != nil {
			continue
		}
		for _, n := range names {
			n = strings.ToLower(strings.TrimSpace(n))
			if n != "" && strings.HasSuffix(n, domain) && !seen[n] {
				seen[n] = true
				results = append(results, n)
			}
		}
	}
	return results
}

func CertSpotter(domain string) ([]string, error) {
	client := httpclient.New(10*time.Second, true)
	resp, err := client.Get("https://api.certspotter.com/v1/issuances?domain=" + domain + "&include_subdomains=true&expand=dns_names")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var items []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, err
	}
	var out []string
	for _, item := range items {
		out = append(out, item.DNSNames...)
	}
	return out, nil
}

func HackerTarget(domain string) ([]string, error) {
	client := httpclient.New(10*time.Second, true)
	resp, err := client.Get("https://api.hackertarget.com/hostsearch/?q=" + domain)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var buf strings.Builder
	b := make([]byte, 4096)
	for {
		n, e := resp.Body.Read(b)
		buf.Write(b[:n])
		if e != nil {
			break
		}
	}
	var out []string
	for _, line := range strings.Split(buf.String(), "\n") {
		parts := strings.SplitN(line, ",", 2)
		if len(parts) >= 1 && parts[0] != "" {
			out = append(out, parts[0])
		}
	}
	return out, nil
}

func AlienVaultOTX(domain string) ([]string, error) {
	client := httpclient.New(10*time.Second, true)
	resp, err := client.Get(fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	var out []string
	for _, r := range result.PassiveDNS {
		out = append(out, r.Hostname)
	}
	return out, nil
}

func URLScan(domain string) ([]string, error) {
	client := httpclient.New(10*time.Second, true)
	resp, err := client.Get("https://urlscan.io/api/v1/search/?q=domain:" + domain + "&size=100")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result struct {
		Results []struct {
			Page struct {
				Domain string `json:"domain"`
			} `json:"page"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	var out []string
	for _, r := range result.Results {
		out = append(out, r.Page.Domain)
	}
	return out, nil
}
