# recon-x Scan Profiles

Profiles make recon-x useful by default while keeping risky checks explicit.

## safe

Low-impact attack-surface mapping:

- passive discovery
- DNS subdomain resolution
- TCP port scan
- HTTP fingerprinting
- TLS, WHOIS, email security, ASN, favicon and Wayback checks

Use it for early recon and broad external visibility checks.

## standard

The default product workflow:

- everything in `safe`
- directory and JS discovery
- GitHub dorking
- cloud bucket checks
- screenshots
- takeover, CORS, vhost, GraphQL, admin-panel and template checks

Use it for normal authorized recon and reporting.

## active

Authorized active testing:

- everything in `standard`
- open redirect, 403 bypass
- SQLi, XSS, SSRF, LFI, XXE, Command Injection
- default credential checks
- host-header and JWT analysis

Use it only when the target owner has approved active validation.

## proof

The proof profile is active testing with stricter CVE evidence defaults:

- CVE profile becomes `strict`
- minimum CVE confidence becomes `high`
- version evidence is required unless explicitly overridden

Use it for staging, labs and reproducible evidence workflows.

## ci

Deterministic automation mode:

- no interactive TUI
- JSON, SARIF and Markdown outputs are enabled by default
- focused module set that works well in build logs

Use it in GitHub Actions, GitLab CI, Jenkins and scheduled monitoring jobs.

## full

Compatibility profile that enables every module. Prefer `standard`, `active` or `proof` for new workflows.
