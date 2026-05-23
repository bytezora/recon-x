# recon-x

<p align="center">
  <img src="assets/logo.png" alt="recon-x logo" width="480"/>
</p>

<p align="center">
  <a href="https://github.com/bytezora/recon-x/releases"><img src="https://img.shields.io/github/v/release/bytezora/recon-x?style=flat-square" alt="Release"></a>
  <a href="https://github.com/bytezora/recon-x/actions"><img src="https://img.shields.io/github/actions/workflow/status/bytezora/recon-x/build.yml?style=flat-square" alt="CI"></a>
  <img src="https://img.shields.io/badge/Go-1.25%2B-00ADD8?style=flat-square&logo=go" alt="Go 1.25+">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"></a>
</p>

<p align="center">
  <b>Fast attack-surface reconnaissance with CVE evidence, Nmap import, SARIF, Markdown and self-contained HTML reports.</b>
</p>

`recon-x` is an authorized security reconnaissance tool for bug bounty, pentest and DevSecOps workflows. One command runs 35 modules across passive OSINT, DNS, ports, HTTP, CVE matching, WAF, TLS, CORS, SQLi, XSS, SSRF, LFI, Host Header Injection, JWT analysis, Wayback Machine, Shodan, XXE, Command Injection, GraphQL and custom templates.

> Findings are indicators, not confirmed vulnerabilities. Scan only authorized targets.

<p align="center">
  <img src="assets/terminal.png" alt="recon-x terminal CVE assurance workflow" width="960"/>
  <br/>
  <sub>High-precision CVE workflow with Nmap XML import, live NVD enrichment and public-service assurance.</sub>
</p>

---

## Contents

- [Highlights](#highlights)
- [Current Snapshot](#current-snapshot)
- [Screenshots](#screenshots)
- [Install](#install)
- [Usage](#usage)
- [Flags](#flags)
- [Modules](#modules)
- [CVE matching](#cve-matching)
- [Output](#output)
- [Config file](#config-file)
- [Documentation](#documentation)
- [Safety](#safety)

## Highlights

| Area | Capability |
|------|------------|
| Discovery | Passive OSINT, subdomain brute-force, vhost discovery, ASN, WHOIS, Wayback and Shodan enrichment |
| Network | TCP ports, banner grabbing, Nmap XML import, HTTP probing, TLS checks and screenshots |
| Web checks | CORS, open redirect, SQLi, XSS, SSRF, LFI, XXE, Command Injection, JWT and Host Header Injection |
| CVE intelligence | 177 offline CVE signatures across 48 products, live NVD enrichment, CISA KEV, FIRST EPSS and strict precision profiles |
| Evidence | CVE proof mode against ground truth and real-domain assurance reports for public service/version CVEs |
| Reporting | Self-contained HTML, JSON, Markdown, SARIF and scan-to-scan diffing |

## Current Snapshot

| Metric | Value |
|--------|------:|
| Recon modules | 35 |
| Built-in YAML templates | 54 |
| Offline CVE signatures | 177 |
| CVE product families | 48 |
| Default TCP ports | 17 |
| Output formats | HTML, JSON, Markdown, SARIF |
| CVE proof workflows | Ground-truth evidence + real-domain assurance |

## Screenshots

<p align="center">
  <img src="assets/report.png" alt="recon-x HTML report CVE evidence dashboard" width="980"/>
  <br/>
  <sub>Self-contained HTML report with CVE priorities, CPE evidence, strict policy diagnostics and reproducibility data.</sub>
</p>

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

# live CVE enrichment with NVD + CISA KEV + FIRST EPSS
recon-x -target example.com -cve-live -nvd-api-key YOUR_NVD_API_KEY

# high-precision CVE mode using Nmap service detection
nmap -sV -oX nmap.xml example.com
recon-x -target example.com -nmap-xml nmap.xml -skip-portscan -cve-live -cve-profile strict

# prove CVE accuracy against a ground-truth lab dataset
recon-x -target lab.local -nmap-xml nmap.xml -skip-portscan -cve-live -cve-profile strict -json scan.json
recon-x -cve-evidence docs/cve-evidence-example.json -cve-evidence-scan scan.json -cve-evidence-report evidence.json -cve-evidence-markdown evidence.md

# evaluate whether a real domain scan is strong enough for a 90% public-service CVE claim
recon-x -cve-assurance scan.json -cve-assurance-report assurance.json -cve-assurance-markdown assurance.md

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
| `-cve-live` | | Enrich detected CPEs from live NVD, CISA KEV and FIRST EPSS feeds |
| `-nvd-api-key` | | NVD API key for higher CVE enrichment rate limits |
| `-cve-timeout` | `45` | Timeout in seconds for live CVE enrichment |
| `-nmap-xml` | | Import Nmap XML (`-oX`) service/version/CPE results |
| `-skip-portscan` | | Skip built-in TCP scan, useful when importing Nmap XML |
| `-cve-profile` | `balanced` | CVE precision profile: `balanced`, `strict`, `broad`, `kev` |
| `-cve-min-confidence` | | Minimum CVE confidence: `low`, `medium`, `high`, `confirmed` |
| `-cve-require-version` | | Report CVEs only when product version evidence exists |
| `-cve-only-kev` | | Report only CISA KEV known-exploited CVEs |
| `-cve-min-cvss` | `0` | Minimum CVSS for CVE reporting |
| `-cve-evidence` | | Ground-truth JSON file for CVE accuracy proof mode |
| `-cve-evidence-scan` | | Recon-x JSON report to compare with `-cve-evidence` |
| `-cve-evidence-report` | `cve-evidence.json` | Machine-readable evidence report |
| `-cve-evidence-markdown` | | Human-readable evidence report |
| `-cve-evidence-threshold` | `0.90` | Minimum precision and recall required for PASS |
| `-cve-assurance` | | Recon-x JSON report to evaluate 90% CVE claim readiness for an authorized domain |
| `-cve-assurance-report` | `cve-assurance.json` | Machine-readable assurance report |
| `-cve-assurance-markdown` | | Human-readable assurance report |
| `-cve-assurance-threshold` | `0.90` | Minimum evidence coverage required for public-service CVE assurance |
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

177 offline signatures across 48 product families — Apache, nginx, OpenSSH, Tomcat, Spring, Log4j, Redis, WordPress, Jenkins, GitLab, Kubernetes, Fortinet, Citrix, F5 and more. Matches on banners, headers, response bodies and version-probe endpoints. Each detected service is normalized into a product/version/CPE fingerprint where possible.

Optional live enrichment (`-cve-live`) queries NVD CVE data by CPE and enriches matches with CISA Known Exploited Vulnerabilities and FIRST EPSS probability/percentile. Results include source, CPE, product, version, confidence and priority (`P0`–`P3`). The embedded database remains SHA-256 integrity-protected for offline use.

For higher precision, import Nmap service/version output with `-nmap-xml` and use `-cve-profile strict`. The strict profile suppresses low-confidence product-only CVE guesses and keeps confirmed or high-confidence versioned matches. Reports include CVE policy diagnostics: before/after counts, filtered CVEs, NVD match counts, KEV/EPSS enrichment counts and NVD errors.

### CVE evidence mode

Claims like "90% CVE accuracy" are only valid against a known ground-truth dataset. `-cve-evidence` compares a recon-x JSON scan with an expected CVE list and produces reproducible proof: TP/FP/FN, precision, recall, F1, dataset SHA-256, scan SHA-256 and CVE DB hash. The command exits with code `0` only when both precision and recall meet the threshold; otherwise it exits with code `2`, which makes it CI-friendly.

Ground truth format:

```json
{
  "name": "local vulnerable lab",
  "source": "Docker lab + vendor advisories",
  "cases": [
    {
      "name": "Apache httpd 2.4.49",
      "host": "lab.local",
      "port": 8080,
      "product": "apache",
      "version": "2.4.49",
      "expected_cves": ["CVE-2021-41773", "CVE-2021-42013"]
    }
  ]
}
```

This mode is intentionally strict: findings outside the listed cases count as false positives unless `scope_unknown_as_fp` is set to `false` in the truth file.

### CVE assurance mode for real domains

`-cve-assurance` works on any recon-x JSON scan and answers a different question: is this scan strong enough to make a high-confidence 90% claim for **publicly visible service/version CVEs**? It checks version coverage, CPE coverage, live NVD coverage, NVD errors, strict CVE filtering and finding confidence. It also explicitly marks **whole-domain all-CVE 90%** as not provable from external unauthenticated scanning alone.

This is the correct workflow for real domains:

```bash
nmap -sV -oX nmap.xml example.com
recon-x -target example.com -nmap-xml nmap.xml -skip-portscan -cve-live -cve-profile strict -cve-require-version -json scan.json
recon-x -cve-assurance scan.json -cve-assurance-report assurance.json -cve-assurance-markdown assurance.md
```

If the assurance report fails, it lists exactly what is missing: version evidence, CPE evidence, NVD enrichment, stricter policy, or internal evidence such as SBOM/package inventory/authenticated context.

See [docs/CVE_EVIDENCE.md](docs/CVE_EVIDENCE.md) for the full proof methodology and CI-friendly PASS/FAIL workflow.

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
cve_live: true
nvd_api_key: YOUR_NVD_API_KEY
cve_timeout: 45
nmap_xml: ./nmap.xml
skip_portscan: true
cve_profile: strict
cve_require_version: true
cve_min_confidence: high
output_dir: ./results
notify_slack: https://hooks.slack.com/...
notify_telegram: TOKEN@CHATID
templates:
  - ./custom-templates/
```

---

## Documentation

- [CVE evidence methodology](docs/CVE_EVIDENCE.md)
- [CVE evidence example](docs/cve-evidence-example.json)
- [Roadmap](docs/ROADMAP.md)

## Safety

`recon-x` is built for authorized security testing. Keep scans inside an approved scope, use rate limits where needed, and validate findings manually before reporting impact.

---

MIT · authorized targets only
