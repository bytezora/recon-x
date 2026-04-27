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
![Version](https://img.shields.io/badge/version-1.2.0-39ff14?style=flat-square)

---

## Why I built this

Most recon workflows require running 4–5 separate tools, piping output between them,
and stitching results together manually. recon-x does all of that in one command
and produces a clean report you can actually share.

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
```

### Examples

```bash
# Basic scan
recon-x -target example.com

# Save both HTML and JSON
recon-x -target example.com -output report.html -json report.json

# Custom wordlist, more threads
recon-x -target example.com -wordlist wordlists/big.txt -threads 100

# Targeted port list, no passive recon
recon-x -target example.com -no-passive -ports 80,443,8080,8443

# Full scan, all outputs
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

## Report

The HTML report is self-contained, uses **Lucida Console** font, and has a clean
monotone dark terminal aesthetic. No external dependencies, no CDN calls.

Sections:
- Summary cards — subdomain count, open ports, HTTP services, CVE matches
- Subdomains — with resolved IPs and crt.sh / DNS source
- Open ports — with service banners
- HTTP services — status codes, titles, server headers, detected technologies
- CVE matches — linked to NVD, matched from banner strings
- WAF detection — Cloudflare, Akamai, Imperva, AWS WAF, F5, and more
- Directory brute-force — filtered to status codes worth investigating
- JS findings — API endpoints and secrets extracted from JavaScript files

The JSON output mirrors the same structure and is suitable for integration
with your own tooling or further processing.

---

## Detection capabilities

| Category         | What it detects                                                       |
|------------------|-----------------------------------------------------------------------|
| Web servers      | Nginx, Apache, IIS, Caddy, Gunicorn                                   |
| Languages        | PHP, ASP.NET, Express.js, Next.js                                     |
| CDN / Cloud      | Cloudflare, AWS                                                       |
| CMS              | WordPress, Drupal, Joomla                                             |
| Frameworks       | React, Vue.js, Angular, jQuery, Laravel, Django, FastAPI              |
| WAF vendors      | Cloudflare, Akamai, Imperva, Sucuri, AWS WAF, F5, Barracuda, ModSec  |
| CVE matching     | Apache 2.4.49/50, OpenSSH < 8, vsftpd 2.3.4, Exim, IIS, nginx, Redis |
| JS secrets       | AWS keys, API keys, tokens, passwords, Bearer tokens, DB URIs         |

---

## Project structure

```
recon-x/
├── main.go                      Entry point, flag parsing, TUI, pipeline
├── ui/
│   └── model.go                 Bubbletea TUI — 6-step live progress view
├── internal/
│   ├── banner/
│   │   └── grab.go              TCP banner grabbing (raw socket read)
│   ├── crtsh/
│   │   └── lookup.go            crt.sh Certificate Transparency passive recon
│   ├── dirbust/
│   │   ├── bust.go              Concurrent HTTP path brute-force
│   │   └── paths.txt            Embedded wordlist (~80 common paths)
│   ├── httpcheck/
│   │   └── check.go             HTTP probe + tech fingerprinting
│   ├── jsscan/
│   │   └── scan.go              JS file discovery + secret/endpoint extraction
│   ├── output/
│   │   └── json.go              JSON report serialization
│   ├── portscan/
│   │   └── scan.go              Concurrent TCP port scanner
│   ├── report/
│   │   └── report.go            HTML report generator
│   ├── subdomain/
│   │   ├── enum.go              DNS resolver + passive result merge
│   │   └── wordlist.txt         Embedded wordlist (~100 prefixes)
│   ├── vulns/
│   │   └── match.go             Banner-to-CVE matching (10 entries)
│   └── waf/
│       └── detect.go            WAF fingerprinting from headers/cookies/body
```

---

## Notes

- Only use this tool against targets you have **explicit written permission** to scan.
- crt.sh queries are passive and leave no trace on the target.
- TLS verification is disabled for HTTP probing — this is intentional so
  self-signed certificates on internal hosts do not block discovery.
- Port scan timeout is 2 seconds per connection.
- JS scanning only fetches files — it does not execute JavaScript.
- CVE matching is signature-based (banner regex). Always verify findings manually.

---

## License

MIT — see [LICENSE](LICENSE).  
Copyright © 2026 [bytezora](https://github.com/bytezora)
