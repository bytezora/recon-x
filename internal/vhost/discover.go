package vhost

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/bytezora/recon-x/internal/httpcheck"
)

type Result struct {
	IP        string `json:"ip"`
	Host      string `json:"host"`
	VHost     string `json:"vhost"`
	Status    int    `json:"status"`
	Length    int    `json:"length"`
	Different bool   `json:"different"`
}

var prefixes = []string{
	"admin", "api", "dev", "staging", "internal", "test", "preprod", "portal", "dashboard",
	"vpn", "mail", "smtp", "ftp", "backup", "old", "beta", "uat", "corp", "intranet",
	"secure", "git", "jenkins", "jira", "confluence", "wiki", "docs", "help", "support",
	"monitor", "metrics", "kibana", "grafana", "prometheus", "elastic", "db", "database",
	"mysql", "redis", "rabbitmq", "kafka", "app", "apps", "mobile", "cdn", "assets",
	"static", "img", "media", "uploads", "files",
}

func Discover(httpResults []httpcheck.Result, threads int, onFound func(Result)) []Result {
	type target struct {
		ip   string
		host string
		port int
		tls  bool
	}
	seen := map[string]bool{}
	var targets []target
	for _, h := range httpResults {
		ips, err := net.LookupHost(h.Host)
		if err != nil || len(ips) == 0 {
			continue
		}
		ip := ips[0]
		key := ip
		if seen[key] {
			continue
		}
		seen[key] = true
		targets = append(targets, target{ip: ip, host: h.Host, port: h.Port, tls: h.Port == 443 || h.Port == 8443})
	}

	var (
		mu      sync.Mutex
		results []Result
		wg      sync.WaitGroup
		sem     = make(chan struct{}, threads)
	)

	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t target) {
			defer wg.Done()
			defer func() { <-sem }()
			baseStatus, baseLen := getBaseline(t.ip, t.host, t.port, t.tls)
			for _, prefix := range prefixes {
				vhost := prefix + "." + t.host
				status, length := probeVHost(t.ip, vhost, t.port, t.tls)
				diff := status != baseStatus || abs(length-baseLen) > 100
				if diff {
					r := Result{
						IP:        t.ip,
						Host:      t.host,
						VHost:     vhost,
						Status:    status,
						Length:    length,
						Different: true,
					}
					mu.Lock()
					results = append(results, r)
					mu.Unlock()
					if onFound != nil {
						onFound(r)
					}
				}
			}
		}(t)
	}
	wg.Wait()
	return results
}

func makeClient() *http.Client {
	return &http.Client{
		Timeout: 6 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyFromEnvironment,
		},
	}
}

func getBaseline(ip, host string, port int, useTLS bool) (int, int) {
	return probeVHost(ip, host, port, useTLS)
}

func probeVHost(ip, host string, port int, useTLS bool) (int, int) {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/", scheme, ip, port)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, 0
	}
	req.Host = host
	c := makeClient()
	resp, err := c.Do(req)
	if err != nil {
		return 0, 0
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, len(body)
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}


