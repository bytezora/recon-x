# Local API Server

`recon-x api serve` exposes the local workspace through an RBAC-ready REST API.

The API is intentionally backed by the same `.reconx/` project inventory used by the CLI. That keeps the worker/scanner core and the future server product aligned.

## Start

```bash
recon-x api serve --api-token dev-owner:owner:* --api-listen 127.0.0.1:8090
```

Token format:

```text
token:role[:project1|project2|*]
```

Examples:

```bash
recon-x api serve --api-token owner-secret:owner:*
recon-x api serve --api-token viewer-secret:viewer:acme-api
recon-x api serve --api-token ci-secret:ci-bot:acme-api
```

`RECONX_API_TOKEN` can be used instead of `--api-token`.

## Roles

Built-in roles:

| Role      | Intended use                                                |
| --------- | ----------------------------------------------------------- |
| `owner`   | Full local API access                                       |
| `admin`   | Manage projects, scans, findings and baselines              |
| `analyst` | Run/read scans and triage findings                          |
| `viewer`  | Read-only access                                            |
| `ci-bot`  | CI worker token for scan creation/import and artifact reads |

## Endpoints

```text
GET  /healthz
GET  /v1/roles
GET  /v1/projects
POST /v1/projects
GET  /v1/projects/{project_id}
GET  /v1/projects/{project_id}/scans
POST /v1/projects/{project_id}/scans/import
GET  /v1/projects/{project_id}/scans/{scan_id}
GET  /v1/projects/{project_id}/scans/{scan_id}/artifact
GET  /v1/projects/{project_id}/findings
GET  /v1/projects/{project_id}/findings/{fingerprint}
PATCH /v1/projects/{project_id}/findings/{fingerprint}
GET  /v1/projects/{project_id}/quota
PUT  /v1/projects/{project_id}/quota
GET  /v1/projects/{project_id}/audit
```

## Examples

```bash
curl -H "Authorization: Bearer dev-owner" http://127.0.0.1:8090/healthz
curl -H "Authorization: Bearer dev-owner" http://127.0.0.1:8090/v1/projects
curl -H "Authorization: Bearer dev-owner" http://127.0.0.1:8090/v1/projects/acme-api/findings
```

Triage a finding:

```bash
curl -X PATCH \
  -H "Authorization: Bearer dev-owner" \
  -H "Content-Type: application/json" \
  -d '{"status":"accepted","assignee":"jasur","note":"known risk until migration"}' \
  http://127.0.0.1:8090/v1/projects/acme-api/findings/rx1:0123456789abcdef
```

Set project quota:

```bash
curl -X PUT \
  -H "Authorization: Bearer dev-owner" \
  -H "Content-Type: application/json" \
  -d '{"max_scans":50,"max_findings_per_scan":500}' \
  http://127.0.0.1:8090/v1/projects/acme-api/quota
```

Read audit events:

```bash
curl -H "Authorization: Bearer dev-owner" \
  http://127.0.0.1:8090/v1/projects/acme-api/audit
```

Create a project:

```bash
curl -X POST \
  -H "Authorization: Bearer dev-owner" \
  -H "Content-Type: application/json" \
  -d '{"id":"acme-api","name":"Acme API"}' \
  http://127.0.0.1:8090/v1/projects
```

Import an existing scan:

```bash
curl -X POST \
  -H "Authorization: Bearer dev-owner" \
  -H "Content-Type: application/json" \
  -d '{"scan_path":"results/source/scan.json","profile":"ci"}' \
  http://127.0.0.1:8090/v1/projects/acme-api/scans/import
```

## Security notes

- The API requires bearer tokens.
- Bind to `127.0.0.1` for local development.
- Do not expose the local API publicly without TLS, proper identity, audit logging and server-side quota enforcement.
- Raw scan artifacts may contain sensitive target metadata; keep artifact access behind `artifact:read`.
- Triage, quota changes and scan imports are written to the project audit log.
