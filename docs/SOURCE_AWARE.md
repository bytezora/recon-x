# Source-Aware Scanning

`recon-x scan repo` inspects a local source repository and emits the same finding model used by domain scans: stable fingerprints, severity, confidence, remediation text, JSON, Markdown, SARIF and HTML.

It is designed for local development, pull requests and build pipelines. It does not execute exploits or mutate the target application.

## Quick start

```bash
recon-x scan repo . --profile ci --output-dir results/source
recon-x scan repo . --url http://localhost:3000 --scanners routes,config
recon-x scan repo . --profile ci --project acme-api --output-dir results/source
```

## Scanners

| Scanner   | Purpose                                                                                                                                    |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `secrets` | Detects common API keys, provider tokens, private keys and database URLs. Evidence is redacted unless `--show-secrets` is set.             |
| `deps`    | Reads dependency manifests such as `package.json`, `go.mod`, `requirements.txt`, `pyproject.toml`, Maven, Gradle, Ruby and Composer files. |
| `config`  | Flags risky production settings such as debug mode, wildcard CORS, disabled TLS verification and broad bind addresses.                     |
| `routes`  | Discovers application routes from Express, Nest-style decorators, Django, Flask/FastAPI and Go HTTP handlers.                              |

Use `--scanners all` or omit `--scanners` to run the full source-aware set.

## Output

With `--profile ci --output-dir results/source`, recon-x writes:

```text
results/source/report.html
results/source/report.md
results/source/scan.json
results/source/scan.sarif
```

View the report locally:

```bash
recon-x report serve results/source/scan.json
```

Import the scan into a local project inventory:

```bash
recon-x project init acme-api --name "Acme API"
recon-x project import acme-api results/source/scan.json
recon-x project show acme-api
```

## Baseline workflow

Use a previous `scan.json` to suppress known findings and only fail CI on new risk:

```bash
recon-x scan repo . --profile ci --output-dir baseline
recon-x scan repo . --profile ci --baseline baseline/scan.json --fail-on high --output-dir latest
```

Allowlist intentional findings with `.reconxignore`.

## Safety model

Secrets are redacted by default. Use `--show-secrets` only in a controlled local environment. For CI, keep redaction enabled and store artifacts according to your organization's security policy.
