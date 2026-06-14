# CI, Baselines and Automation

`recon-x` is built to run as a deterministic CI gate.

## Recommended pull-request check

```bash
recon-x scan repo . --profile ci --scanners secrets,deps,config,routes --project acme-api --fail-on high
```

The `ci` profile enables non-interactive output and writes JSON, SARIF and Markdown artifacts when an output directory is provided.

## GitHub Action

```yaml
name: recon-x

on:
  pull_request:
  push:
    branches: [main]

jobs:
  recon-x:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: bytezora/recon-x@main
        with:
          mode: repo
          repo: .
          profile: ci
          scanners: secrets,deps,config,routes
          project: acme-api
          fail-on: high
```

For external attack-surface scans:

```yaml
- uses: bytezora/recon-x@main
  with:
    mode: domain
    target: example.com
    profile: ci
    scanners: dns,http,tls,cve
    project: acme-api
    fail-on: high
```

When `project` is set, the action stores workspace metadata under the uploaded artifact directory so the scan can later be imported into a server/RBAC platform.

## Baselines

Baselines suppress findings that already existed in a previous recon-x JSON report:

```bash
recon-x scan repo . --profile ci --output-dir baseline
recon-x scan repo . --profile ci --baseline baseline/scan.json --fail-on high --output-dir latest
```

Every structured finding gets a stable `fingerprint`, so CI can focus on new issues instead of repeatedly failing on accepted legacy risk.

## Allowlist

Create `.reconxignore` when a finding is intentionally accepted:

```text
fingerprint:rx1:0123456789abcdef
type:repo-routes
cve:CVE-2024-0001
contains:staging.example.com
```

## Pre-commit

This repository includes `.pre-commit-hooks.yaml`.

```yaml
repos:
  - repo: https://github.com/bytezora/recon-x
    rev: main
    hooks:
      - id: recon-x-source
```

Run it locally:

```bash
pre-commit install
pre-commit run recon-x-source --all-files
```

## Exit codes

Use `--fail-on critical|high|medium|low|info|none`.

`--fail-on none` disables build failure while still producing artifacts.
