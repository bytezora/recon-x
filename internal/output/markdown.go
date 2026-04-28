package output

import (
	"fmt"
	"os"
	"time"

	"github.com/bytezora/recon-x/internal/adminpanel"
	"github.com/bytezora/recon-x/internal/asn"
	"github.com/bytezora/recon-x/internal/axfr"
	"github.com/bytezora/recon-x/internal/buckets"
	"github.com/bytezora/recon-x/internal/bypass"
	"github.com/bytezora/recon-x/internal/cmdi"
	"github.com/bytezora/recon-x/internal/cors"
	"github.com/bytezora/recon-x/internal/defaultcreds"
	"github.com/bytezora/recon-x/internal/dirbust"
	"github.com/bytezora/recon-x/internal/emailsec"
	"github.com/bytezora/recon-x/internal/favicon"
	"github.com/bytezora/recon-x/internal/ghsearch"
	"github.com/bytezora/recon-x/internal/graphql"
	"github.com/bytezora/recon-x/internal/hostheader"
	"github.com/bytezora/recon-x/internal/httpcheck"
	"github.com/bytezora/recon-x/internal/jsscan"
	"github.com/bytezora/recon-x/internal/jwt"
	"github.com/bytezora/recon-x/internal/lfi"
	"github.com/bytezora/recon-x/internal/openredirect"
	"github.com/bytezora/recon-x/internal/portscan"
	"github.com/bytezora/recon-x/internal/ratelimit"
	"github.com/bytezora/recon-x/internal/screenshot"
	"github.com/bytezora/recon-x/internal/shodan"
	"github.com/bytezora/recon-x/internal/sqli"
	"github.com/bytezora/recon-x/internal/ssrf"
	"github.com/bytezora/recon-x/internal/subdomain"
	"github.com/bytezora/recon-x/internal/takeover"
	"github.com/bytezora/recon-x/internal/templates"
	"github.com/bytezora/recon-x/internal/tlscheck"
	"github.com/bytezora/recon-x/internal/vhost"
	"github.com/bytezora/recon-x/internal/vulns"
	"github.com/bytezora/recon-x/internal/waf"
	"github.com/bytezora/recon-x/internal/wayback"
	"github.com/bytezora/recon-x/internal/whois"
	"github.com/bytezora/recon-x/internal/xss"
	"github.com/bytezora/recon-x/internal/xxe"
)

type MarkdownData struct {
	Target       string
	Subdomains   []subdomain.Result
	Ports        []portscan.Result
	HTTP         []httpcheck.Result
	Vulns        []vulns.Match
	WAFs         []waf.Result
	DirHits      []dirbust.Hit
	JSFindings   []jsscan.Finding
	GHFindings   []ghsearch.Finding
	Buckets      []buckets.Result
	TLS          []tlscheck.Result
	Redirects    []openredirect.Result
	AXFR         []axfr.Result
	WHOIS        *whois.Result
	Screenshots  []screenshot.Result
	Takeover     []takeover.Result
	CORS         []cors.Result
	Bypass       []bypass.Result
	VHosts       []vhost.Result
	Favicons     []favicon.Result
	ASN          []asn.Result
	GraphQL      []graphql.Result
	EmailSec     *emailsec.Result
	AdminPanel   []adminpanel.Result
	SQLi         []sqli.Result
	DefaultCreds []defaultcreds.Result
	RateLimit    []ratelimit.Result
	Templates    []templates.Match
	XSS          []xss.Result
	SSRF         []ssrf.Result
	LFI          []lfi.Result
	HostHeader   []hostheader.Result
	JWT          []jwt.Result
	Wayback      []wayback.Result
	Shodan       []shodan.Result
	XXE          []xxe.Result
	CmdI         []cmdi.Result
}

func WriteMarkdown(path string, data MarkdownData) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := func(format string, args ...interface{}) {
		fmt.Fprintf(f, format+"\n", args...)
	}

	w("# recon-x Scan Report: %s", data.Target)
	w("**Generated:** %s", time.Now().Format(time.RFC3339))
	w("")

	w("## Summary")
	w("")
	w("| Module | Count |")
	w("|--------|-------|")
	w("| Subdomains | %d |", len(data.Subdomains))
	w("| Open Ports | %d |", len(data.Ports))
	w("| HTTP Endpoints | %d |", len(data.HTTP))
	w("| Vulnerabilities (CVE) | %d |", len(data.Vulns))
	w("| WAFs Detected | %d |", len(data.WAFs))
	w("| Dir Hits | %d |", len(data.DirHits))
	w("| JS Findings | %d |", len(data.JSFindings))
	w("| GitHub Findings | %d |", len(data.GHFindings))
	w("| Buckets | %d |", len(data.Buckets))
	w("| TLS Issues | %d |", len(data.TLS))
	w("| Open Redirects | %d |", len(data.Redirects))
	w("| Takeovers | %d |", len(data.Takeover))
	w("| CORS Issues | %d |", len(data.CORS))
	w("| 403 Bypasses | %d |", len(data.Bypass))
	w("| VHosts | %d |", len(data.VHosts))
	w("| Admin Panels | %d |", len(data.AdminPanel))
	w("| SQLi | %d |", len(data.SQLi))
	w("| Default Creds | %d |", len(data.DefaultCreds))
	w("| Templates | %d |", len(data.Templates))
	w("| XSS | %d |", len(data.XSS))
	w("| SSRF | %d |", len(data.SSRF))
	w("| LFI | %d |", len(data.LFI))
	w("| Host Header Injection | %d |", len(data.HostHeader))
	w("| JWT Issues | %d |", len(data.JWT))
	w("| Wayback URLs | %d |", len(data.Wayback))
	w("| Shodan Results | %d |", len(data.Shodan))
	w("| XXE | %d |", len(data.XXE))
	w("| CMDi | %d |", len(data.CmdI))
	w("")

	if len(data.Subdomains) > 0 {
		w("## Subdomains")
		w("")
		w("| Subdomain | IPs | Source |")
		w("|-----------|-----|--------|")
		for _, s := range data.Subdomains {
			ips := ""
			for i, ip := range s.IPs {
				if i > 0 {
					ips += ", "
				}
				ips += ip
			}
			w("| %s | %s | %s |", s.Subdomain, ips, s.Source)
		}
		w("")
	}

	if len(data.Ports) > 0 {
		w("## Open Ports")
		w("")
		w("| Host | Port | Banner |")
		w("|------|------|--------|")
		for _, p := range data.Ports {
			w("| %s | %d | %s |", p.Host, p.Port, p.Banner)
		}
		w("")
	}

	if len(data.Vulns) > 0 {
		w("## Vulnerabilities")
		w("")
		w("| CVE | Host | Port | Severity | CVSS | Description |")
		w("|-----|------|------|----------|------|-------------|")
		for _, v := range data.Vulns {
			w("| %s | %s | %d | %s | %.1f | %s |", v.CVE, v.Host, v.Port, v.Severity, v.CVSS, v.Description)
		}
		w("")
	}

	if len(data.SQLi) > 0 {
		w("## SQL Injection")
		w("")
		w("| URL | Param | Method | Evidence |")
		w("|-----|-------|--------|----------|")
		for _, s := range data.SQLi {
			if s.Detected {
				w("| %s | %s | %s | %s |", s.URL, s.Param, s.Method, s.Evidence)
			}
		}
		w("")
	}

	if len(data.XSS) > 0 {
		w("## Cross-Site Scripting (XSS)")
		w("")
		w("| URL | Param | Context | Evidence |")
		w("|-----|-------|---------|----------|")
		for _, x := range data.XSS {
			if x.Reflected {
				w("| %s | %s | %s | %s |", x.URL, x.Param, x.Context, x.Evidence)
			}
		}
		w("")
	}

	if len(data.SSRF) > 0 {
		w("## Server-Side Request Forgery (SSRF)")
		w("")
		w("| URL | Param | Payload | Evidence |")
		w("|-----|-------|---------|----------|")
		for _, s := range data.SSRF {
			if s.Detected {
				w("| %s | %s | %s | %s |", s.URL, s.Param, s.Payload, s.Evidence)
			}
		}
		w("")
	}

	if len(data.LFI) > 0 {
		w("## Local File Inclusion (LFI)")
		w("")
		w("| URL | Param | OS | Evidence |")
		w("|-----|-------|----|----------|")
		for _, l := range data.LFI {
			if l.Detected {
				w("| %s | %s | %s | %s |", l.URL, l.Param, l.OS, l.Evidence)
			}
		}
		w("")
	}

	if len(data.XXE) > 0 {
		w("## XML External Entity (XXE)")
		w("")
		w("| URL | Evidence |")
		w("|-----|----------|")
		for _, x := range data.XXE {
			if x.Detected {
				w("| %s | %s |", x.URL, x.Evidence)
			}
		}
		w("")
	}

	if len(data.CmdI) > 0 {
		w("## OS Command Injection")
		w("")
		w("| URL | Param | Method | Evidence |")
		w("|-----|-------|--------|----------|")
		for _, c := range data.CmdI {
			if c.Detected {
				w("| %s | %s | %s | %s |", c.URL, c.Param, c.Method, c.Evidence)
			}
		}
		w("")
	}

	if len(data.HostHeader) > 0 {
		w("## Host Header Injection")
		w("")
		w("| URL | Header | Evidence |")
		w("|-----|--------|----------|")
		for _, h := range data.HostHeader {
			if h.Vulnerable {
				w("| %s | %s | %s |", h.URL, h.Header, h.Evidence)
			}
		}
		w("")
	}

	if len(data.JWT) > 0 {
		w("## JWT Issues")
		w("")
		w("| URL | Algorithm | Issue | Severity |")
		w("|-----|-----------|-------|----------|")
		for _, j := range data.JWT {
			w("| %s | %s | %s | %s |", j.URL, j.Algorithm, j.Issue, j.Severity)
		}
		w("")
	}

	if len(data.CORS) > 0 {
		w("## CORS Misconfigurations")
		w("")
		w("| URL | Origin | ACAO |")
		w("|-----|--------|------|")
		for _, c := range data.CORS {
			if c.Vulnerable {
				w("| %s | %s | %s |", c.URL, c.Origin, c.ACAO)
			}
		}
		w("")
	}

	if len(data.Takeover) > 0 {
		w("## Subdomain Takeovers")
		w("")
		w("| Subdomain | CNAME | Service |")
		w("|-----------|-------|---------|")
		for _, t := range data.Takeover {
			if t.Vulnerable {
				w("| %s | %s | %s |", t.Subdomain, t.CNAME, t.Service)
			}
		}
		w("")
	}

	if len(data.Wayback) > 0 {
		w("## Wayback Machine URLs")
		w("")
		w("| URL | Timestamp | Status |")
		w("|-----|-----------|--------|")
		for _, wb := range data.Wayback {
			w("| %s | %s | %s |", wb.URL, wb.Timestamp, wb.StatusCode)
		}
		w("")
	}

	if len(data.Shodan) > 0 {
		w("## Shodan Results")
		w("")
		w("| IP | ISP | Country | Ports | Vulns |")
		w("|----|-----|---------|-------|-------|")
		for _, s := range data.Shodan {
			ports := fmt.Sprintf("%v", s.Ports)
			vulnCount := fmt.Sprintf("%d", len(s.Vulns))
			w("| %s | %s | %s | %s | %s |", s.IP, s.ISP, s.Country, ports, vulnCount)
		}
		w("")
	}

	if data.WHOIS != nil {
		w("## WHOIS")
		w("")
		w("| Field | Value |")
		w("|-------|-------|")
		w("| Registrar | %s |", data.WHOIS.Registrar)
		w("| Country | %s |", data.WHOIS.Country)
		w("| Created | %s |", data.WHOIS.Created)
		w("| Expires | %s |", data.WHOIS.Expires)
		w("")
	}

	if data.EmailSec != nil {
		w("## Email Security")
		w("")
		w("| Check | Result |")
		w("|-------|--------|")
		w("| SPF | %s |", data.EmailSec.SPF)
		w("| DMARC | %s |", data.EmailSec.DMARC)
		w("| Spoofable | %v |", data.EmailSec.Spoofable)
		w("")
	}

	if len(data.DefaultCreds) > 0 {
		w("## Default Credentials")
		w("")
		w("| URL | Username | Password |")
		w("|-----|----------|----------|")
		for _, d := range data.DefaultCreds {
			if d.Found {
				w("| %s | %s | %s |", d.URL, d.Username, d.Password)
			}
		}
		w("")
	}

	w("---")
	w("*Generated by recon-x — scan only authorized targets*")
	return nil
}
