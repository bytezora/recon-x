// Package portscan performs concurrent TCP port scanning
// across a list of resolved subdomains, with optional banner grabbing.
package portscan

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/bytezora/recon-x/internal/banner"
	"github.com/bytezora/recon-x/internal/subdomain"
)

const dialTimeout = 2 * time.Second

// Result represents a single open TCP port on a discovered host.
type Result struct {
	Host   string
	Port   int
	IP     string
	Banner string
}

// Scan dials every (ip, port) pair derived from subs, capped at threads
// concurrent goroutines. onFound is called for each open port found.
func Scan(subs []subdomain.Result, ports []int, threads int, onFound func(Result)) []Result {
	results := make([]Result, 0, 64)
	mu      := sync.Mutex{}
	sem     := make(chan struct{}, threads)
	wg      := sync.WaitGroup{}

	for _, sub := range subs {
		for _, port := range ports {
			for _, ip := range sub.IPs {
				sem <- struct{}{}
				wg.Add(1)

				go func(host, addr string, p int) {
					defer func() { <-sem; wg.Done() }()

					conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", addr, p), dialTimeout)
					if err != nil {
						return
					}
					bannerStr := banner.GrabConn(conn, p)
					conn.Close()

					r := Result{
						Host:   host,
						Port:   p,
						IP:     addr,
						Banner: bannerStr,
					}

					mu.Lock()
					results = append(results, r)
					mu.Unlock()

					if onFound != nil {
						onFound(r)
					}
				}(sub.Subdomain, ip, port)
			}
		}
	}

	wg.Wait()
	return results
}
