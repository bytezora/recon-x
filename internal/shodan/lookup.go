package shodan

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/bytezora/recon-x/internal/httpclient"
)

type Result struct {
	IP        string
	ISP       string
	Country   string
	Ports     []int
	Vulns     []string
	Hostnames []string
}

type shodanHostResponse struct {
	IPStr     string                 `json:"ip_str"`
	ISP       string                 `json:"isp"`
	Country   string                 `json:"country_name"`
	Ports     []int                  `json:"ports"`
	Vulns     map[string]interface{} `json:"vulns"`
	Hostnames []string               `json:"hostnames"`
}

type shodanDNSResponse map[string]string

func Lookup(ips []string, apiKey string, threads int, onFound func(Result)) []Result {
	if apiKey == "" {
		return nil
	}
	if threads <= 0 {
		threads = 5
	}

	client := httpclient.New(30*time.Second, true)

	var (
		mu      sync.Mutex
		results []Result
		wg      sync.WaitGroup
		sem     = make(chan struct{}, threads)
	)

	for _, ip := range ips {
		sem <- struct{}{}
		wg.Add(1)
		go func(ip string) {
			defer func() { <-sem; wg.Done() }()

			apiURL := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ip, apiKey)
			req, err := http.NewRequest("GET", apiURL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; recon-x)")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != 200 {
				return
			}

			data, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
			if err != nil {
				return
			}

			var host shodanHostResponse
			if err := json.Unmarshal(data, &host); err != nil {
				return
			}

			var vulnList []string
			for cve := range host.Vulns {
				vulnList = append(vulnList, cve)
			}

			r := Result{
				IP:        host.IPStr,
				ISP:       host.ISP,
				Country:   host.Country,
				Ports:     host.Ports,
				Vulns:     vulnList,
				Hostnames: host.Hostnames,
			}

			mu.Lock()
			results = append(results, r)
			if onFound != nil {
				onFound(r)
			}
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	return results
}

func ResolveDomain(domain, apiKey string) []string {
	if apiKey == "" {
		return nil
	}

	client := httpclient.New(15*time.Second, true)
	apiURL := fmt.Sprintf("https://api.shodan.io/dns/resolve?hostnames=%s&key=%s", domain, apiKey)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil
	}

	var result shodanDNSResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}

	var ips []string
	for _, ip := range result {
		if ip != "" {
			ips = append(ips, ip)
		}
	}
	return ips
}
