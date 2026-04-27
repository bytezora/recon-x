# recon-x

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go&logoColor=white)
![Version](https://img.shields.io/badge/version-1.5.0-39ff14?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-555?style=flat-square)

Web recon tool I wrote in Go. One command — passive subdomain discovery, port scan, CVE matching, WAF detection, dir brute-force, JS secret extraction, GitHub dorking, cloud bucket enumeration, TLS analysis, open redirect detection, DNS zone transfer, WHOIS lookup, and HTTP screenshots. Outputs a self-contained HTML report and optional JSON.

---

## Install

```bash
go install github.com/bytezora/recon-x@latest
```

or build from source:

```bash
git clone https://github.com/bytezora/recon-x && cd recon-x
go build -o recon-x .
```

---

## Usage

```bash
recon-x -target example.com
recon-x -target example.com -output report.html -json out.json -threads 100
recon-x -target example.com -no-passive -ports 80,443,8080,8443
recon-x -target example.com -github-token ghp_xxxx
```

```
-target         domain to scan                     (required)
-output         html report path                   (default: report.html)
-json           json output                        (optional)
-wordlist       custom subdomain wordlist
-ports          comma-separated ports
-threads        concurrency                        (default: 50)
-no-passive     skip crt.sh lookup
-github-token   GitHub PAT for code search dorking (optional)
-version        print version
```

---

## What runs

```
 1. crt.sh passive recon
 2. DNS subdomain brute-force
 3. TCP port scan → banner grab → CVE match
 4. HTTP fingerprint → tech stack → WAF detection
 5. Directory brute-force (~80 paths)
 6. JS scraping → endpoints + secrets
 7. GitHub dorking → leaked keys/tokens in code
 8. Cloud bucket enum → S3 / GCS / Azure
 9. TLS analysis → weak ciphers, expiring certs, SAN mismatch
10. Open redirect detection → 22 params × 2 payloads
11. DNS zone transfer (AXFR) → full zone leak attempt
12. WHOIS lookup → registrar, org, country, dates
13. HTTP screenshots → headless browser, embedded in report
14. Subdomain takeover → CNAME dangling DNS check
15. CORS scan → origin reflection, wildcard+credentials
16. 403 bypass → path tricks, header injection
17. Virtual host discovery → Host header bruteforce
18. Favicon hash → Shodan MurmurHash3 fingerprint
19. ASN lookup → BGP prefix, org, country
20. GraphQL probe → endpoint discovery, introspection dump
21. Email security → SPF / DMARC / DKIM, spoofability
22. Admin panel discovery → 50+ real paths, records 200/301/302/401/403
23. SQLi detection → reflection + error-based, zero exploitation
24. Default credentials → 15 common pairs, login form detection
25. Rate limit headers → X-RateLimit-*, Retry-After detection
    → self-contained HTML report + optional JSON
```

---

## Terminal UI

![Terminal](assets/terminal.png)

---

## Report

Self-contained HTML, dark terminal style. Tabbed — subdomains, ports, HTTP, CVE, WAF, dirs, JS secrets, GitHub leaks, cloud buckets, TLS, open redirects, AXFR, WHOIS, screenshots, takeover, CORS, 403 bypass, vhosts, favicon, ASN, GraphQL, email security, admin panels, sqli, default creds, rate limit.

![Report](assets/report.png)

---

## CVE detection

190+ signatures across 48 products — Apache, nginx, OpenSSH, Tomcat, WebLogic, Spring, Log4j, Redis, MongoDB, Elasticsearch, WordPress, Drupal, Jenkins, GitLab, Fortinet, Citrix, F5, Kubernetes and more.

Matches on banner strings, HTTP headers, response bodies and version endpoints (`/actuator/info`, `/_cluster/stats`, etc.). DB is SHA-256 protected.

WAF vendors: Cloudflare, Akamai, Imperva, AWS WAF, F5, Barracuda, ModSecurity, Fortinet, Radware.

---

## License

MIT · use only on targets you have permission to scan.
