# Contributing

Thanks for helping improve recon-x.

## Development

Use Go 1.25 or newer.

```bash
go test ./...
go vet ./...
go build ./...
```

Keep changes focused and include tests when touching detection logic, CVE matching, parsing or report output.

## Detection Changes

When adding a new detector or CVE matcher:

- keep payloads safe by default
- document confidence levels
- include evidence in JSON and reports
- add unit tests for positive and negative cases
- avoid claiming confirmed vulnerabilities unless active verification proves it safely

## CVE Accuracy

Use the evidence workflow when changing CVE matching:

```bash
recon-x -cve-evidence ground-truth.json -cve-evidence-scan scan.json
```

For real domains without ground truth, use:

```bash
recon-x -cve-assurance scan.json
```

## Pull Requests

Before opening a pull request, run:

```bash
go test ./...
go vet ./...
go build ./...
```
