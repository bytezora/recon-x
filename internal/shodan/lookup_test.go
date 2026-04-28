package shodan

import (
	"testing"
)

func TestLookup_EmptyAPIKey(t *testing.T) {
	results := Lookup([]string{"1.2.3.4"}, "", 5, nil)
	if results != nil {
		t.Error("expected nil result with empty API key")
	}
}

func TestResolveDomain_EmptyAPIKey(t *testing.T) {
	ips := ResolveDomain("example.com", "")
	if ips != nil {
		t.Error("expected nil IPs with empty API key")
	}
}
