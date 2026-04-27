```
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗      ██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║      ╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║       ╚███╔╝ 
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║       ██╔██╗ 
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║      ██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝      ╚═╝  ╚═╝
```

**recon-x** is a fast, all-in-one web reconnaissance tool written in Go.  
It chains passive discovery, DNS brute-force, port scanning, service banner grabbing,
HTTP fingerprinting, WAF detection, CVE matching, directory brute-force, and JS secret
extraction into a single binary — with a live terminal UI and a clean report output.

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-555?style=flat-square)
![Version](https://img.shields.io/badge/version-1.2.1-39ff14?style=flat-square)

---

## What it does

```
Step 1  Passive recon     Query crt.sh Certificate Transparency logs
Step 2  DNS brute-force   Resolve subdomain wordlist against target
Step 3  Port scan         Concurrent TCP dial + service banner grab + CVE matching
Step 4  HTTP fingerprint  Status codes, page titles, tech stack, WAF detection
Step 5  Dir brute-force   Probe ~80 common paths for exposed endpoints and files
Step 6  JS scraping       Extract API endpoints and secrets from JavaScript files
        Report            HTML report (Lucida Console, monotone) + optional JSON
```

Everything runs concurrently inside each step.
A medium-sized target typically finishes in under 90 seconds.

---

## Report

The HTML report is self-contained with a dark terminal aesthetic using **Lucida Console** font.
No external dependencies, no CDN calls. Tabbed layout — no scrolling required.

![Report overview](docs/assets/report-full.png)

![CVE matches](docs/assets/report-cve.png)

**Tabs:**
- **Subdomains** — resolved hosts with IPs, source (crt.sh / DNS brute-force)
- **Open Ports** — service banners per host/port
- **HTTP** — status codes, titles, server headers, detected technologies, missing security headers
- **CVE** — matches linked to NVD with CVSS score and severity
- **WAF** — detected vendors (Cloudflare, Akamai, Imperva, AWS WAF, F5, Barracuda, ModSec)
- **Paths** — directory brute-force hits with redirect destinations
- **JS** — API endpoints and secrets extracted from JavaScript files

---

## Installation

**Requirements:** Go 1.21 or newer.

```bash
# Install directly (recommended)
go install github.com/bytezora/recon-x@latest

# Build from source
git clone https://github.com/bytezora/recon-x
cd recon-x
go build -o recon-x .
```

---

## Usage

```
recon-x [flags]

Flags:
  -target      string   Target domain, e.g. example.com         (required)
  -output      string   HTML report path            (default: report.html)
  -json        string   JSON output path            (optional)
  -wordlist    string   Custom wordlist file         (default: embedded ~100)
  -ports       string   Comma-separated port list   (default: common 17 ports)
  -threads     int      Concurrent goroutines        (default: 50)
  -no-passive           Skip crt.sh passive recon
  -version              Print version and exit
  -db-hash              Print CVE database integrity hash and exit
```

### Examples

```bash
# Basic scan
recon-x -target example.com

# Save both HTML and JSON reports
recon-x -target example.com -output report.html -json report.json

# Custom wordlist, more threads
recon-x -target example.com -wordlist wordlists/big.txt -threads 100

# Targeted port list, skip passive recon
recon-x -target example.com -no-passive -ports 80,443,8080,8443

# Full scan with all outputs
recon-x -target example.com -output report.html -json report.json -threads 100
```

---

## Terminal UI

recon-x uses [bubbletea](https://github.com/charmbracelet/bubbletea) for a live
terminal interface. Each step updates in real time as findings come in.

```
╭──────────────────────────────────────────────────────╮
│  recon-x  ·  example.com                             │
│                                                      │
│  ✓  01. Passive recon    (crt.sh)        18 found    │
│  ✓  02. DNS brute-force  (wordlist)      12 found    │
│  ✓  03. Port scan        (TCP + CVE)     31 found    │
│  ⠸  04. HTTP fingerprint (WAF detect)   ...          │
│  ○  05. Directory brute  (path enum)                 │
│  ○  06. JS scraping      (secrets)                   │
│                                                      │
│  ⬡ api.example.com:443                               │
│  ⬡ dev.example.com:80                                │
│  ⚠ CVE-2021-41773  Path traversal — Apache/2.4.49   │
╰──────────────────────────────────────────────────────╯
```

---

## CVE Detection

Signature-based matching against a database of **190+ CVEs** across 48 products.
No API calls, no rate limits — fully offline.

| Category | Products |
|---|---|
| Web servers | Apache HTTP, nginx, IIS, lighttpd |
| SSH / FTP | OpenSSH, vsftpd, ProFTPD |
| Mail | Exim, Zimbra, Roundcube |
| Application servers | Tomcat, WebLogic, JBoss, GlassFish |
| Databases | MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch |
| CMS / Frameworks | WordPress, Drupal, Joomla, Magento |
| CI/CD | Jenkins, GitLab, Nexus, Harbor |
| Network / Security | F5 BIG-IP, Citrix ADC, Fortinet FortiOS, Pulse/Ivanti |
| Monitoring | Grafana, Kibana, Prometheus |
| Middleware | Apache Struts, Spring, Log4j, ActiveMQ, Zookeeper |
| Cloud / Container | Kubernetes, VMware vCenter |
| Other | Confluence, Jira, Solr, Keycloak, ColdFusion, OpenSSL |

Detection uses banner strings, HTTP headers, response bodies, and version endpoint probing
(`/actuator/info`, `/api/v4/version`, `/_cluster/stats`, `/solr/admin/info/system`).

The CVE database is SHA-256 protected — tampered signatures are caught at startup.

---

## WAF Detection

| Vendor |
|---|
| Cloudflare · Akamai · Imperva / Incapsula · Sucuri |
| AWS WAF · F5 BIG-IP ASM · Barracuda · ModSecurity |
| Citrix NetScaler · Fortinet FortiWeb · Radware |

---

## Project structure

```
recon-x/
├── main.go                      Entry point, flag parsing, TUI, pipeline
├── ui/
│   └── model.go                 Bubbletea TUI — 6-step live progress view
├── internal/
│   ├── banner/grab.go           TCP banner grabbing (Redis, MySQL, PG, Mongo, Memcached, ZK, ActiveMQ)
│   ├── crtsh/lookup.go          crt.sh Certificate Transparency passive recon
│   ├── dirbust/bust.go          Concurrent HTTP path brute-force
│   ├── httpcheck/check.go       HTTP probe + tech fingerprinting + security headers
│   ├── jsscan/scan.go           JS file discovery + secret/endpoint extraction
│   ├── output/json.go           JSON report serialization
│   ├── portscan/scan.go         Concurrent TCP port scanner
│   ├── report/report.go         HTML report generator
│   ├── subdomain/enum.go        DNS resolver + passive result merge
│   ├── vulns/
│   │   ├── match.go             190+ CVE database + banner/header/body detection engine
│   │   ├── probe.go             HTTP version endpoint probing
│   │   └── integrity.go         SHA-256 database integrity check
│   └── waf/detect.go            WAF fingerprinting from headers/cookies/body
```

---

## Notes

- Only use this tool against targets you have **explicit written permission** to scan.
- crt.sh queries are passive and leave no trace on the target.
- TLS verification is disabled for HTTP probing — intentional for self-signed certificates on internal hosts.
- CVE matching is signature-based. Always verify findings manually.

---

## License

MIT — see [LICENSE](LICENSE).  
Copyright © 2026 [bytezora](https://github.com/bytezora)
