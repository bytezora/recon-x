package portscan

import (
	"net"
	"sync/atomic"
	"testing"

	"github.com/bytezora/recon-x/internal/subdomain"
)

func TestScanDedupesNetworkProbeByIPPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var accepts int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&accepts, 1)
			_, _ = conn.Write([]byte("unit-test 1.0\n"))
			_ = conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	results := Scan([]subdomain.Result{
		{Subdomain: "www.example.test", IPs: []string{"127.0.0.1"}},
		{Subdomain: "api.example.test", IPs: []string{"127.0.0.1"}},
	}, []int{port}, 4, nil)

	_ = ln.Close()
	<-done

	if got := atomic.LoadInt32(&accepts); got != 1 {
		t.Fatalf("network probes = %d, want 1", got)
	}
	if len(results) != 2 {
		t.Fatalf("results len = %d, want 2", len(results))
	}
	hosts := map[string]bool{}
	for _, r := range results {
		hosts[r.Host] = true
		if r.Port != port || r.IP != "127.0.0.1" || r.State != "open" {
			t.Fatalf("unexpected result: %+v", r)
		}
	}
	if !hosts["www.example.test"] || !hosts["api.example.test"] {
		t.Fatalf("expected both host aliases, got %+v", hosts)
	}
}
