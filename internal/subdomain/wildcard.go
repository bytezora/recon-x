package subdomain

import (
	"context"
	"fmt"
	"math/rand"
)

// DetectWildcard checks if the domain has wildcard DNS by resolving a random subdomain.
// Returns (true, wildcardIPs) if wildcard is detected.
func DetectWildcard(domain string, resolverAddr string) (bool, []string) {
	resolver := newResolver(resolverAddr)
	randSub := fmt.Sprintf("probe-%s.%s", randHex8(), domain)

	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()

	ips, err := resolver.LookupHost(ctx, randSub)
	if err != nil || len(ips) == 0 {
		return false, nil
	}
	return true, ips
}

func randHex8() string {
	const chars = "0123456789abcdef"
	b := make([]byte, 8)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

func wildcardFilter(results []Result, wildcardIPs []string) []Result {
	if len(wildcardIPs) == 0 {
		return results
	}
	wildcardSet := make(map[string]bool, len(wildcardIPs))
	for _, ip := range wildcardIPs {
		wildcardSet[ip] = true
	}

	filtered := results[:0]
	for _, r := range results {
		// allWildcard: assume true only when IPs exist (no-IP entries are kept as-is)
		allWildcard := len(r.IPs) > 0
		for _, ip := range r.IPs {
			if !wildcardSet[ip] {
				allWildcard = false // at least one real (non-wildcard) IP found
				break
			}
		}
		if !allWildcard {
			filtered = append(filtered, r)
		}
	}
	return filtered
}
