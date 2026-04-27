# recon-x Roadmap — World-Scale Security Tool

> **Goal:** Evolve recon-x from a CLI recon scanner into the world's most trusted open-source reconnaissance platform — used by bug bounty hunters, red teams, and enterprises globally.
> Comparable targets: Nuclei, Amass, httpx, Burp Suite Pro.

---

## Current State — v1.6.0 ✅

- 25-step automated recon pipeline
- CVE matching engine (8 000+ CVEs)
- TLS, CORS, SQLi, WAF, takeover, AXFR, GraphQL, favicon, ASN, vhost, 403 bypass
- Proxy support, SARIF output, scope management, Slack/Telegram alerts, resume
- HTML + JSON report, GitHub Release binaries, Docker image

---

## Phase 1 — v2.0 · Template Engine + Community Core
> **Milestone:** Users can write their own detection modules without touching Go code.

| Feature | Details |
|---|---|
| **Template engine** | YAML-based templates (like Nuclei). `id`, `info`, `http.method`, `matchers`, `extractors`. Community can submit PRs with new templates. |
| **Template hub** | `/templates/` folder in repo — 200+ detection templates on release (CVEs, misconfigs, exposures, tech fingerprints) |
| **Matcher types** | `word`, `regex`, `status`, `binary`, `dsl` — same logic as Nuclei for familiarity |
| **Extractor types** | `regex`, `xpath`, `json`, `kval` (header value) |
| **Severity levels** | `info`, `low`, `medium`, `high`, `critical` |
| **Tags & filters** | `--tags cve,sqli` — run only matching templates |
| **`-tl` template list** | Print all loaded templates with metadata |
| **CVE template auto-sync** | Weekly CI job: fetch NVD feed → auto-generate YAML templates → PR |

---

## Phase 2 — v2.1 · Passive Intel Integration
> **Milestone:** Recon without sending a single packet to the target.

| Feature | Details |
|---|---|
| **Shodan API** | `--shodan <key>` — query host IPs, open ports, banners without touching target |
| **VirusTotal API** | `--vt <key>` — passive subdomain enumeration from VT |
| **SecurityTrails API** | `--st <key>` — historical DNS, subdomain history |
| **crt.sh v2** | Cert Transparency wildcard expansion + org-based search |
| **BGP/ASN expansion** | From ASN → all prefixes → all IPs in org range (passive) |
| **Wayback Machine** | `waybackurls`-style URL harvesting for JS analysis and param discovery |
| **GitHub dorking v2** | Paginated search across org, detect secrets with entropy scoring |

---

## Phase 3 — v2.2 · Protocol Depth
> **Milestone:** Not just HTTP — real infrastructure coverage.

| Feature | Details |
|---|---|
| **gRPC probe** | Detect gRPC endpoints, list services via reflection |
| **WebSocket probe** | Detect WS endpoints, send test frames, check for info leakage |
| **MQTT/Redis/Memcached banner** | Detect exposed IoT/cache services on non-standard ports |
| **IPv6 support** | Full dual-stack scanning — IPv6-only hosts often missed by tools |
| **HTTP/2 & HTTP/3 (QUIC)** | Fingerprint protocol version, check for downgrade attacks |
| **SMTP open relay** | Test MX records for open relay misconfiguration |
| **FTP anon login** | Check FTP if port 21 is open |
| **SMB/NetBIOS banner** | Detect Windows file sharing exposure on port 445 |

---

## Phase 4 — v2.5 · Enterprise & CI/CD Grade
> **Milestone:** Enterprise security teams adopt recon-x in their pipelines.

| Feature | Details |
|---|---|
| **Config file** | `recon-x.yaml` — all flags as YAML, checked into repo, used in CI |
| **Rate limiting & retries** | Per-module configurable: `--rate 50/s`, `--retries 3`, exponential backoff |
| **False positive filtering** | Baseline scan → diff next scan → only report new findings |
| **SQLite state & dedup** | Persistent SQLite DB per target — never report same finding twice |
| **Multi-target mode** | `-targets targets.txt` — scan hundreds of domains, parallel workers |
| **Team reporting** | Defect Dojo API integration, Jira ticket auto-creation on critical |
| **SARIF v2.1 enrichment** | Rule metadata, fingerprints, fix suggestions in every SARIF result |
| **JUnit XML output** | For Jenkins/GitLab CI test result visualization |
| **GitHub Actions official action** | `uses: bytezora/recon-x-action@v1` in `.github/workflows/` |
| **Scheduled scans** | `--cron "0 2 * * *"` — daemonize, run nightly, diff reports |

---

## Phase 5 — v3.0 · Platform — Web UI + API + Distributed
> **Milestone:** recon-x becomes a platform, not just a CLI tool.

| Feature | Details |
|---|---|
| **REST API server** | `recon-x server --port 8080` — submit scans via HTTP, poll results |
| **Web dashboard** | React SPA — scan history, diff view, finding trends, asset inventory |
| **Distributed scanning** | Worker nodes via Redis queue — scan 1000 subdomains in parallel across VPS |
| **Asset inventory DB** | PostgreSQL backend — track all hosts, ports, services across scans over time |
| **Continuous monitoring** | Watch mode — alert when new subdomains appear or findings change |
| **User accounts & teams** | JWT auth, team workspaces, finding assignment |
| **Plugin SDK** | Go SDK for external plugins — `recon-x-plugin-nuclei`, `recon-x-plugin-ffuf` |
| **Cloud deployment** | Helm chart for Kubernetes, Terraform module for AWS/GCP one-click deploy |

---

## Phase 6 — v3.5 · AI-Augmented Recon
> **Milestone:** AI reduces noise, prioritizes critical findings, generates exploit PoCs.

| Feature | Details |
|---|---|
| **LLM false-positive filter** | Send response body to local LLM (Ollama/llama3) — classify true/false positive |
| **Finding explanation** | Auto-generate human-readable finding descriptions with remediation steps |
| **Attack path generation** | Chain findings: subdomain takeover + CORS + XSS = account takeover path |
| **PoC generator** | For SQLi/SSRF/redirect — auto-generate curl PoC and Burp request |
| **Scope suggestion** | From ASN/WHOIS — suggest what else is in scope |

---

## Community & Ecosystem Milestones

| Milestone | Target |
|---|---|
| 🌟 500 GitHub stars | v2.0 release + template hub launch |
| 🌟 1 000 stars | Featured on awesome-bugbounty-tools, trickest, projectdiscovery blog mention |
| 🌟 2 500 stars | Active contributors, 500+ templates, HackerOne / Bugcrowd tool list |
| 🌟 5 000 stars | Conference talk (DEF CON / Black Hat Arsenal), Docker pulls 10k+ |
| 🌟 10 000 stars | Enterprise sponsorship, hosted SaaS version |

---

## Immediate Next Steps (post-v1.6.0)

1. **Template engine v1** — most impactful feature, unlocks community contributions
2. **`recon-x-templates` repo** — separate repo for community templates (like `nuclei-templates`)
3. **`recon-x-action`** — GitHub Actions marketplace listing
4. **Discord/community** — open community server for bug bounty hunters
5. **Blog post** — "How I built a Nuclei alternative in Go" — drives traffic and stars
6. **Submit to:** awesome-security, awesome-bugbounty-tools, projectdiscovery community
