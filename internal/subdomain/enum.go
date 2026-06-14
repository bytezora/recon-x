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

type Result struct {
	Subdomain string
	IPs       []string
	Source    string
}

func Enumerate(target string, threads int, wordlistFile string, resolverAddr string, onFound func(Result)) []Result {
	words := loadWords(wordlistFile)
	results := make([]Result, 0, 32)
	mu := sync.Mutex{}
	sem := make(chan struct{}, threads)
	wg := sync.WaitGroup{}
	resolver := newResolver(resolverAddr)

	isWildcard, wildcardIPs := DetectWildcard(target, resolverAddr)

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
	if isWildcard {
		results = wildcardFilter(results, wildcardIPs)
	}
	return results
}

func AddPassive(existing []Result, names []string, resolverAddr string, onFound func(Result)) []Result {
	return AddNames(existing, names, resolverAddr, "crtsh", onFound)
}

func AddSeedFile(existing []Result, path string, target string, resolverAddr string, onFound func(Result)) []Result {
	names := loadSeedNames(path, target)
	return AddNames(existing, names, resolverAddr, "seed", onFound)
}

func AddNames(existing []Result, names []string, resolverAddr string, source string, onFound func(Result)) []Result {
	seen := make(map[string]bool, len(existing))
	for _, r := range existing {
		seen[strings.ToLower(r.Subdomain)] = true
	}

	resolver := newResolver(resolverAddr)

	for _, name := range names {
		name = normalizeSeedName(name, "")
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true

		ips, err := func() ([]string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
			defer cancel()
			return resolver.LookupHost(ctx, name)
		}()
		if err != nil {
			ips = []string{}
		}

		r := Result{Subdomain: name, IPs: ips, Source: source}
		existing = append(existing, r)

		if onFound != nil {
			onFound(r)
		}
	}

	return existing
}

func loadSeedNames(path string, target string) []string {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[warn] subdomain file %q unreadable: %v\n", path, err)
		return nil
	}
	lines := strings.Split(string(data), "\n")
	names := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := normalizeSeedName(fields[0], target)
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

func normalizeSeedName(name string, target string) string {
	name = strings.TrimSpace(strings.TrimSuffix(name, "."))
	name = strings.ToLower(name)
	if name == "" {
		return ""
	}
	target = strings.TrimSpace(strings.TrimSuffix(strings.ToLower(target), "."))
	if target != "" && !strings.Contains(name, ".") {
		name = name + "." + target
	}
	return name
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

func newResolver(addr string) *net.Resolver {
	if addr == "" {
		return net.DefaultResolver
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", addr)
		},
	}
}
