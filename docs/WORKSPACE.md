# Workspace Projects

`recon-x` can store scan inventory under a local workspace directory. The default is `.reconx/`.

This is the bridge between the CLI scanner and a future RBAC platform: a project groups scans, current risk summaries and scan artifacts behind one stable project id.

## Quick start

```bash
recon-x project init acme-api --name "Acme API"
recon-x scan repo . --profile ci --project acme-api --output-dir results/source
recon-x scan domain example.com --profile ci --project acme-api --output-dir results/domain
recon-x project list
recon-x project show acme-api
```

## Commands

```bash
recon-x project init <project-id> [--name "Display Name"]
recon-x project import <project-id> <scan.json> [--name "Display Name"]
recon-x project list
recon-x project show <project-id>
recon-x project export <project-id> --output project.json
```

Project ids are lowercase slugs using letters, numbers, dots, dashes or underscores.

## Layout

```text
.reconx/
  projects/
    acme-api/
      project.json
      audit.jsonl
      scans/
        20260615T010203Z-0123456789.json
```

`project.json` stores:

- project id and display name
- latest scan id, target and target type
- scan count
- latest severity counts
- fingerprint triage state
- project quotas
- source/domain readiness flags
- scan metadata and copied raw scan JSON paths

## CI inventory

Use `--project` to automatically import the generated `scan.json`:

```bash
recon-x scan repo . --profile ci --project acme-api --store-dir .reconx --output-dir results/source
```

When `--project` is set, recon-x ensures JSON output exists even outside the `ci` profile because workspace import needs a machine-readable scan report.

## RBAC mapping

In a server-backed edition, this local model maps directly to:

| Local workspace         | RBAC platform                |
| ----------------------- | ---------------------------- |
| workspace root          | organization or tenant       |
| project id              | project resource             |
| scan metadata           | scan job/run                 |
| copied scan JSON        | immutable artifact           |
| finding fingerprint     | triage item id               |
| latest severity summary | dashboard/project risk state |

Keep project ids stable. They are intended to become API route keys and permission scopes.

## Local API

Serve the workspace over the built-in bearer-token API:

```bash
recon-x api serve --api-token dev-owner:owner:* --api-listen 127.0.0.1:8090
```

Then query projects and findings:

```bash
curl -H "Authorization: Bearer dev-owner" http://127.0.0.1:8090/v1/projects
curl -H "Authorization: Bearer dev-owner" http://127.0.0.1:8090/v1/projects/acme-api/findings
```

Triage and governance data is stored locally too:

```bash
curl -X PATCH -H "Authorization: Bearer dev-owner" -H "Content-Type: application/json" \
  -d '{"status":"accepted","note":"tracked exception"}' \
  http://127.0.0.1:8090/v1/projects/acme-api/findings/rx1:0123456789abcdef

curl -X PUT -H "Authorization: Bearer dev-owner" -H "Content-Type: application/json" \
  -d '{"max_scans":50,"max_findings_per_scan":500}' \
  http://127.0.0.1:8090/v1/projects/acme-api/quota

curl -H "Authorization: Bearer dev-owner" http://127.0.0.1:8090/v1/projects/acme-api/audit
```
