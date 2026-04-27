package tlscheck

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"time"
)

type Result struct {
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	Expiry      string   `json:"expiry"`
	DaysLeft    int      `json:"days_left"`
	Proto       string   `json:"proto"`
	CipherSuite string   `json:"cipher_suite"`
	SANs        []string `json:"sans"`
	Issues      []string `json:"issues"`
}

var weakProtos = map[uint16]bool{
	tls.VersionTLS10: true,
	tls.VersionTLS11: true,
}

var weakCiphers = map[uint16]bool{
	0x0004: true, // TLS_RSA_WITH_RC4_128_MD5
	tls.TLS_RSA_WITH_RC4_128_SHA:         true,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:    true,
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:   true,
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA: true,
}

type Target struct {
	Host string
	Port int
}

func Check(targets []Target, threads int, onFound func(Result)) []Result {
	var results []Result
	mu  := sync.Mutex{}
	sem := make(chan struct{}, threads)
	wg  := sync.WaitGroup{}

	for _, t := range targets {
		sem <- struct{}{}
		wg.Add(1)
		go func(host string, port int) {
			defer func() { <-sem; wg.Done() }()
			r := analyze(host, port)
			if r == nil {
				return
			}
			mu.Lock()
			results = append(results, *r)
			mu.Unlock()
			if onFound != nil {
				onFound(*r)
			}
		}(t.Host, t.Port)
	}
	wg.Wait()
	return results
}

func analyze(host string, port int) *Result {
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec
		ServerName:         host,
		MinVersion:         tls.VersionTLS10,
	})
	if err != nil {
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	certs := state.PeerCertificates
	if len(certs) == 0 {
		return nil
	}

	cert := certs[0]
	now := time.Now()
	daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)

	r := &Result{
		Host:        host,
		Port:        port,
		Expiry:      cert.NotAfter.Format("2006-01-02"),
		DaysLeft:    daysLeft,
		Proto:       protoName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		SANs:        cert.DNSNames,
	}

	if now.After(cert.NotAfter) {
		r.Issues = append(r.Issues, "certificate EXPIRED")
	} else if daysLeft < 14 {
		r.Issues = append(r.Issues, fmt.Sprintf("expires in %d days (critical)", daysLeft))
	} else if daysLeft < 30 {
		r.Issues = append(r.Issues, fmt.Sprintf("expires in %d days", daysLeft))
	}

	if weakProtos[state.Version] {
		r.Issues = append(r.Issues, "weak protocol: "+r.Proto)
	}

	if weakCiphers[state.CipherSuite] {
		r.Issues = append(r.Issues, "weak cipher: "+r.CipherSuite)
	}

	if !certMatchesHost(cert, host) {
		r.Issues = append(r.Issues, "SAN mismatch for "+host)
	}

	if isSelfSigned(cert) {
		r.Issues = append(r.Issues, "self-signed certificate")
	}

	return r
}

func certMatchesHost(cert *x509.Certificate, host string) bool {
	return cert.VerifyHostname(host) == nil
}

func isSelfSigned(cert *x509.Certificate) bool {
	return cert.Subject.String() == cert.Issuer.String()
}

func protoName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
