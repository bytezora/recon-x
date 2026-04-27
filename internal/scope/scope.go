package scope

import (
	"bufio"
	"net"
	"os"
	"strings"
)

type Scope struct {
	wildcards []string
	exact     []string
	cidrs     []*net.IPNet
}

func Load(path string) (*Scope, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s := &Scope{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "*.") {
			s.wildcards = append(s.wildcards, strings.ToLower(line[2:]))
		} else if _, cidr, err := net.ParseCIDR(line); err == nil {
			s.cidrs = append(s.cidrs, cidr)
		} else {
			s.exact = append(s.exact, strings.ToLower(line))
		}
	}
	return s, sc.Err()
}

func (s *Scope) InScope(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, e := range s.exact {
		if h == e {
			return true
		}
	}
	for _, w := range s.wildcards {
		if h == w || strings.HasSuffix(h, "."+w) {
			return true
		}
	}
	if ip := net.ParseIP(h); ip != nil {
		for _, cidr := range s.cidrs {
			if cidr.Contains(ip) {
				return true
			}
		}
	}
	return false
}
