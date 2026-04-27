package banner

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

type FingerprintResult struct {
	Service  string
	Version  string
	Category string
	Raw      string
}

var (
	compiledOnce sync.Once
	compiled     []*regexp.Regexp
)

func compileAll() {
	compiledOnce.Do(func() {
		compiled = make([]*regexp.Regexp, len(Signatures))
		for i, s := range Signatures {
			r, err := regexp.Compile(`(?i)` + s.Pattern)
			if err != nil {
				compiled[i] = nil
				continue
			}
			compiled[i] = r
		}
	})
}

func Fingerprint(ip string, port int) FingerprintResult {
	compileAll()

	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return FingerprintResult{}
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(4 * time.Second))
	raw := readBanner(conn)
	if raw == "" {
		conn2, err2 := net.DialTimeout("tcp", addr, 3*time.Second)
		if err2 == nil {
			defer conn2.Close()
			conn2.SetDeadline(time.Now().Add(4 * time.Second))
			fmt.Fprintf(conn2, "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: recon-x\r\n\r\n", ip)
			raw = readResponse(conn2)
		}
	}

	if raw == "" {
		return FingerprintResult{}
	}

	return matchSignatures(raw)
}

func FingerprintBanner(raw string) FingerprintResult {
	compileAll()
	if raw == "" {
		return FingerprintResult{}
	}
	return matchSignatures(raw)
}

func matchSignatures(raw string) FingerprintResult {
	for i, s := range Signatures {
		r := compiled[i]
		if r == nil {
			continue
		}
		m := r.FindStringSubmatch(raw)
		if m == nil {
			continue
		}
		ver := ""
		if s.Version == "extract" && len(m) > 1 && m[1] != "" {
			ver = m[1]
		}
		return FingerprintResult{
			Service:  s.Service,
			Version:  ver,
			Category: s.Category,
			Raw:      raw,
		}
	}
	return FingerprintResult{Raw: raw}
}

func readBanner(conn net.Conn) string {
	buf := make([]byte, 2048)
	n, _ := conn.Read(buf)
	if n == 0 {
		return ""
	}
	return strings.TrimSpace(string(buf[:n]))
}

func readResponse(conn net.Conn) string {
	var sb strings.Builder
	scanner := bufio.NewScanner(io.LimitReader(conn, 32*1024))
	for scanner.Scan() {
		line := scanner.Text()
		sb.WriteString(line)
		sb.WriteString("\n")
	}
	return sb.String()
}
