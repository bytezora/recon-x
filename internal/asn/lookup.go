package asn

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type Result struct {
	IP        string `json:"ip"`
	ASN       string `json:"asn"`
	BGPPrefix string `json:"bgp_prefix"`
	Country   string `json:"country"`
	Org       string `json:"org"`
}

func Lookup(ips []string, threads int, onFound func(Result)) []Result {
	deduped := dedup(ips)
	var (
		mu      sync.Mutex
		results []Result
		wg      sync.WaitGroup
		sem     = make(chan struct{}, threads)
	)
	for _, ip := range deduped {
		if isPrivate(ip) {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			r, err := lookupOne(ip)
			if err != nil {
				return
			}
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
			if onFound != nil {
				onFound(r)
			}
		}(ip)
	}
	wg.Wait()
	return results
}

func lookupOne(ip string) (Result, error) {
	conn, err := net.DialTimeout("tcp", "whois.cymru.com:43", 10*time.Second)
	if err != nil {
		return Result{}, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(conn, "begin\nverbose\n%s\nend\n", ip)
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "AS") || (len(line) > 0 && line[0] >= '0' && line[0] <= '9') {
			parts := strings.SplitN(line, "|", 7)
			if len(parts) < 5 {
				continue
			}
			r := Result{
				IP:        strings.TrimSpace(parts[1]),
				ASN:       strings.TrimSpace(parts[0]),
				BGPPrefix: strings.TrimSpace(parts[2]),
				Country:   strings.TrimSpace(parts[3]),
			}
			if len(parts) >= 7 {
				r.Org = strings.TrimSpace(parts[6])
			}
			return r, nil
		}
	}
	return Result{IP: ip}, nil
}

func dedup(ips []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, ip := range ips {
		if !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	return out
}

func isPrivate(ip string) bool {
	private := []string{"10.", "127.", "169.254.", "::1"}
	for _, p := range private {
		if strings.HasPrefix(ip, p) {
			return true
		}
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	ranges := []string{"172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168."}
	for _, r := range ranges {
		if strings.HasPrefix(ip, r) {
			return true
		}
	}
	return false
}
