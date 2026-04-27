// Package subdomain performs DNS-based subdomain enumeration
// by brute-forcing a wordlist against the target domain.
package subdomain

import (
	"context"
	_ "embed"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed wordlist.txt
var defaultWordlist string

const dnsTimeout = 5 * time.Second

// Result holds a discovered subdomain and its resolved IP addresses.
type Result struct {
	Subdomain string
	IPs       []string
	Source    string // "dns" or "crtsh"
}

// Enumerate resolves every wordlist entry against target using concurrent
// goroutines capped at threads. Pass wordlistFile="" to use the embedded list.
// onFound is called (thread-safe) for each resolved host.
func Enumerate(target string, threads int, wordlistFile string, onFound func(Result)) []Result {
	words := loadWords(wordlistFile)
	results := make([]Result, 0, 32)
	mu       := sync.Mutex{}
	sem      := make(chan struct{}, threads)
	wg       := sync.WaitGroup{}
	resolver := newResolver()

	for _, word := range words {
		host := fmt.Sprintf("%s.%s", word, target)
		sem <- struct{}{}
		wg.Add(1)

		go func(h string) {
			defer func() { <-sem; wg.Done() }()

			ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
			defer cancel()
			ips, err := resolver.LookupHost(ctx, h)
			if err != nil || len(ips) == 0 {
				return
			}

			r := Result{Subdomain: h, IPs: ips, Source: "dns"}
			mu.Lock()
			results = append(results, r)
			mu.Unlock()

			if onFound != nil {
				onFound(r)
			}
		}(host)
	}

	wg.Wait()
	return results
}

// AddPassive merges crt.sh results into a result slice, skipping duplicates.
func AddPassive(existing []Result, names []string, onFound func(Result)) []Result {
	seen := make(map[string]bool, len(existing))
	for _, r := range existing {
		seen[r.Subdomain] = true
	}

	resolver := newResolver()

	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true

		ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
		ips, err := resolver.LookupHost(ctx, name)
		cancel()
		if err != nil {
			ips = []string{}
		}

		r := Result{Subdomain: name, IPs: ips, Source: "crtsh"}
		existing = append(existing, r)

		if onFound != nil {
			onFound(r)
		}
	}

	return existing
}

func loadWords(path string) []string {
	if path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			return strings.Fields(string(data))
		}
		fmt.Fprintf(os.Stderr, "[warn] wordlist %q unreadable: %v — using embedded list\n", path, err)
	}
	return strings.Fields(defaultWordlist)
}

// newResolver returns a net.Resolver that always dials Google DNS over UDP.
func newResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}
}
