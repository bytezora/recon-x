# Contributing to recon-x

## Adding Templates

Templates are the fastest way to contribute. Place YAML files in `internal/templates/builtins/` or submit them to `templates/community/` for custom template packs.

Template format:

```yaml
id: your-template-id
info:
  name: Human readable name
  severity: info|low|medium|high|critical
  tags: [exposure, config, cve]

http:
  - method: GET
    path:
      - "{{BaseURL}}/your-path"
    matchers:
      - type: word
        words:
          - "string to match in body"
        condition: and
```

## Adding Modules

1. Create `internal/yourmodule/` package with an exported `Result` struct and main function
2. Add a step in `internal/engine/engine.go`
3. Add result field to `engine.Results`
4. Wire into `internal/report/report.go` HTML template

## Bug Reports

Open an issue with:
- recon-x version (`recon-x -version`)
- target type (don't share actual targets)
- expected vs actual behavior
- relevant output

## Pull Requests

- Keep PRs focused — one feature or fix per PR
- `go vet ./...` must pass
- `go test ./...` must pass
- No comments in Go code (build directives `//go:embed` are fine)
