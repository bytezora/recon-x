# recon-x

[![Release](https://img.shields.io/github/v/release/bytezora/recon-x?style=flat-square)](https://github.com/bytezora/recon-x/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/bytezora/recon-x/build.yml?style=flat-square)](https://github.com/bytezora/recon-x/actions)
![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8?style=flat-square&logo=go)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)

Attack-surface scanner for bug bounty and pentest recon. One command runs 35 modules — passive OSINT, DNS, ports, HTTP, CVE matching, WAF, TLS, CORS, SQLi, XSS, SSRF, LFI, Host Header Injection, JWT analysis, Wayback Machine, Shodan, XXE, Command Injection, GraphQL, templates — and outputs a self-contained HTML report plus JSON, SARIF and Markdown.

> Findings are indicators, not confirmed vulnerabilities. Scan only authorized targets.

![Terminal](assets/terminal.png)

---

## Install

```bash
# go install
go install github.com/bytezora/recon-x@latest

# docker
docker run --rm ghcr.io/bytezora/recon-x:latest -target example.com

# pre-built binary
# download from Releases ↓
```

[→ Releases with binaries for Linux / macOS / Windows](https://github.com/bytezora/recon-x/releases)

---

## Usage

```bash
# full scan
recon-x -target example.com

# specific modules only
recon-x -target example.com -modules subdomain,port,http,sqli,xss,ssrf,lfi

# with Burp proxy + GitHub token
recon-x -target example.com -proxy http://127.0.0.1:8080 -github-token ghp_xxx

# output to JSON, SARIF and Markdown
recon-x -target example.com -json out.json -sarif out.sarif -markdown report.md

# compare with previous scan (diff report)
recon-x -target example.com -json new.json -diff old.json

# Shodan passive recon
recon-x -target example.com -shodan-key YOUR_SHODAN_KEY

# resume interrupted scan
recon-x -target example.com -resume

# pipe from file
cat targets.txt | recon-x
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-target` | | Target domain |
| `-output` | `report.html` | HTML output path |
| `-json` | | JSON output path |
| `-sarif` | | SARIF 2.1.0 output path |
| `-markdown` | | Markdown report output path |
| `-diff` | | Compare with previous JSON scan file |
| `-modules` | all | Comma-separated module names |
| `-ports` | 17 common | Custom port list |
| `-threads` | `50` | Concurrency |
| `-rate` | `50` | Max requests/sec |
| `-retries` | `2` | HTTP retries |
| `-resolver` | system DNS | Custom DNS resolver (`1.1.1.1:53`) |
| `-proxy` | | HTTP/HTTPS proxy (Burp, ZAP) |
| `-github-token` | | GitHub token for dorking |
| `-shodan-key` | | Shodan API key for passive recon |
| `-scope-file` | | In-scope entries, one per line |
| `-config` | | YAML config file |
| `-resume` | | Continue from last completed step |
| `-notify-slack` | | Slack webhook for critical alerts |
| `-notify-telegram` | | `TOKEN@CHATID` for Telegram alerts |
| `-wordlist` | embedded | Subdomain wordlist |
| `-dir-wordlist` | embedded | Directory brute-force wordlist |
| `-output-dir` | | Directory for all output files |
| `-silent` | | Suppress non-critical output |
| `-verbose` | | Verbose output |
| `-version` | | Print version |

---

## Modules

| # | Name | Description |
|---|------|-------------|
| 1 | passive | crt.sh, CertSpotter, HackerTarget, AlienVault, URLScan |
| 2 | subdomain | DNS brute-force + wildcard DNS detection |
| 3 | port | TCP scan + banner grab |
| 4 | http | HTTP fingerprint, tech stack, WAF, CVE match |
| 5 | dir | Directory brute-force |
| 6 | js | JS scraping — endpoints and secrets |
| 7 | github | GitHub code search dorking |
| 8 | buckets | S3 / GCS / Azure Blob exposure check |
| 9 | tls | Cert expiry, weak ciphers, SAN mismatch |
| 10 | redirect | Open redirect (22 params × 2 payloads) |
| 11 | axfr | DNS zone transfer |
| 12 | whois | WHOIS lookup |
| 13 | screenshot | Headless screenshot, embedded in report |
| 14 | takeover | Subdomain takeover via dangling CNAME |
| 15 | cors | CORS misconfiguration |
| 16 | bypass | 403 bypass — path tricks + header injection |
| 17 | vhost | Virtual host discovery |
| 18 | favicon | MurmurHash3 fingerprint (Shodan-style) |
| 19 | asn | ASN / BGP prefix lookup |
| 20 | graphql | GraphQL probe + introspection |
| 21 | email | SPF / DMARC / DKIM, spoofability |
| 22 | admin | Admin panel discovery (50+ paths) |
| 23 | sqli | SQLi — error-based + time-based + boolean-blind + POST/JSON |
| 24 | creds | Default credentials check |
| 25 | ratelimit | Rate-limit header detection |
| 26 | templates | 54 built-in YAML templates + custom |
| 27 | xss | Reflected XSS — URL params + headers, context detection |
| 28 | ssrf | SSRF — AWS metadata, loopback injection in URL params |
| 29 | lfi | Path Traversal / LFI — Linux & Windows file signatures |
| 30 | hostheader | Host Header Injection — 6 header variants, canary reflection |
| 31 | jwt | JWT analysis — alg:none, missing exp, sensitive claims |
| 32 | wayback | Wayback Machine — historical endpoints via CDX API |
| 33 | shodan | Shodan passive recon — open ports, banners, vulns (API key required) |
| 34 | xxe | XXE — XML external entity injection via POST endpoints |
| 35 | cmdi | Command Injection — error-based, time-based, output-based |

---

## CVE matching

190+ signatures — Apache, nginx, OpenSSH, Tomcat, Spring, Log4j, Redis, WordPress, Jenkins, GitLab, Kubernetes, Fortinet, Citrix, F5 and more. Matches on banners, headers, response bodies. Each match tagged `high / medium / low` confidence. Database is SHA-256 integrity-protected.

WAF fingerprinting: Cloudflare, Akamai, Imperva, AWS WAF, F5, Barracuda, ModSecurity, Fortinet.

---

## Output

```
report.html   self-contained dark report, tabbed, all 35 modules
report.md     Markdown report — CI-friendly, readable in GitHub
out.json      machine-readable, full results
out.sarif     SARIF 2.1.0 — GitHub Code Scanning / Defect Dojo
diff.txt      delta between two scans — new/resolved findings
```

![Report](assets/report.png)

---

## Config file

```yaml
target: example.com
threads: 100
rate: 30
retries: 3
resolver: 1.1.1.1:53
modules: [subdomain, port, http, tls, sqli, xss, ssrf, lfi, admin, cors]
github_token: ghp_xxxx
shodan_key: YOUR_SHODAN_KEY
output_dir: ./results
notify_slack: https://hooks.slack.com/...
notify_telegram: TOKEN@CHATID
templates:
  - ./custom-templates/
```

---

MIT · authorized targets only