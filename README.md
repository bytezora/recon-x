# recon-x

![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go&logoColor=white)
![Version](https://img.shields.io/badge/version-2.0.0-39ff14?style=flat-square)
![Release](https://img.shields.io/github/v/release/bytezora/recon-x?style=flat-square&color=39ff14)
![License](https://img.shields.io/badge/License-MIT-555?style=flat-square)

Web recon tool I wrote in Go. One command — passive subdomain discovery, port scan, CVE matching, WAF detection, dir brute-force, JS secret extraction, GitHub dorking, cloud bucket enumeration, TLS analysis, open redirect detection, DNS zone transfer, WHOIS lookup, HTTP screenshots, and YAML template scanning. Outputs a self-contained HTML report and optional JSON/SARIF.

---

## Install

```bash
go install github.com/bytezora/recon-x@latest
```

or via Docker:

```bash
docker pull ghcr.io/bytezora/recon-x:latest
docker run --rm -v $(pwd):/out ghcr.io/bytezora/recon-x:latest -target example.com -output /out/report.html
```

or download a pre-built binary from [Releases](https://github.com/bytezora/recon-x/releases/latest) (Linux, macOS, Windows).

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
recon-x -target example.com -proxy http://127.0.0.1:8080
recon-x -target example.com -scope-file scope.txt -sarif results.sarif
recon-x -target example.com -notify-slack https://hooks.slack.com/... -notify-telegram TOKEN@CHATID
recon-x -target example.com -resume
recon-x -target example.com -config recon.yaml
recon-x -target example.com -retries 3 -rate 30 -modules subdomain,portscan,vulns
recon-x -target example.com -output-dir ./results -verbose
```

```
-target              domain to scan                              (required)
-output              html report path                            (default: report.html)
-json                json output                                 (optional)
-sarif               SARIF 2.1.0 output path for CI/CD          (optional)
-wordlist            custom subdomain wordlist
-dir-wordlist        custom paths wordlist for dir brute
-ports               comma-separated ports
-threads             concurrency                                 (default: 50)
-no-passive          skip crt.sh lookup
-github-token        GitHub PAT for code search dorking          (optional)
-proxy               HTTP/HTTPS proxy URL                        (optional, e.g. http://127.0.0.1:8080)
-scope-file          path to scope file, one entry per line      (optional, *.example.com or 10.0.0.0/8)
-notify-slack        Slack incoming webhook URL for alerts       (optional)
-notify-telegram     Telegram TOKEN@CHATID for alerts            (optional)
-resume              resume interrupted scan from state file     (optional)
-config              path to YAML config file                    (optional)
-modules             comma-separated modules to run              (optional, default: all)
-output-dir          directory for all output files              (optional)
-retries             HTTP retry count                            (default: 2)
-rate                max HTTP requests per second                (default: 50)
-silent              suppress non-critical output
-verbose             enable verbose output
-version             print version
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
26. Template scan → 20 built-in YAML templates + custom templates
    → self-contained HTML report + optional JSON + optional SARIF
```

---

## Terminal UI

![Terminal](assets/terminal.png)

---

## Report

Self-contained HTML, dark terminal style. Tabbed — subdomains, ports, HTTP, CVE, WAF, dirs, JS secrets, GitHub leaks, cloud buckets, TLS, open redirects, AXFR, WHOIS, screenshots, takeover, CORS, 403 bypass, vhosts, favicon, ASN, GraphQL, email security, admin panels, sqli, default creds, rate limit, templates.

![Report](assets/report.png)

---

## CVE detection

190+ signatures across 48 products — Apache, nginx, OpenSSH, Tomcat, WebLogic, Spring, Log4j, Redis, MongoDB, Elasticsearch, WordPress, Drupal, Jenkins, GitLab, Fortinet, Citrix, F5, Kubernetes and more.

Matches on banner strings, HTTP headers, response bodies and version endpoints (`/actuator/info`, `/_cluster/stats`, etc.). DB is SHA-256 protected.

WAF vendors: Cloudflare, Akamai, Imperva, AWS WAF, F5, Barracuda, ModSecurity, Fortinet, Radware.

---

## What's New in v2.0.0

- **Template engine** — 20 built-in YAML templates covering exposed configs, debug endpoints, admin panels, and misconfigurations. Custom templates supported via `-config` or `templates:` field.
- **Rate limiting** — global HTTP rate limiter (`-rate`, default 50 req/s) prevents bans during large scans.
- **Retry logic** — automatic HTTP retries on transient failures (`-retries`, default 2).
- **Config file** — full YAML config (`-config recon.yaml`) for targets, modules, tokens, templates, output paths, rate/retries.
- **Module selection** — run only specific modules with `-modules subdomain,portscan,vulns` to speed up targeted scans.
- **Output directory** — `--output-dir ./results` auto-organises HTML, JSON, and SARIF into one directory.
- **Silent / Verbose modes** — `-silent` suppresses informational output; `-verbose` enables extra detail.
- **Shared HTTP client** — all 14 scan modules use a single pool-aware client with configurable follow-redirect behaviour.

---

## License

MIT · use only on targets you have permission to scan.
