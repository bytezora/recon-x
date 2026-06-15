# RBAC-Ready Platform Path

`recon-x` now has the scanner core, project inventory, RBAC policy engine and local REST API needed for a future RBAC product. The next platform layer should keep the CLI engine as the worker and replace the local JSON workspace with a database-backed API, users, roles and job queue.

Implemented local building blocks:

- `internal/workspace`: projects, scans, artifacts and latest risk summaries
- `internal/rbac`: roles, permissions, scoped decisions and tests
- `internal/apiserver`: bearer-token REST API over the workspace
- persistent finding triage state keyed by fingerprint
- project quotas for scan and finding limits
- append-only project audit logs in JSONL

## Core entities

| Entity       | Purpose                                                    |
| ------------ | ---------------------------------------------------------- |
| Organization | Tenant boundary for billing, limits and audit policy       |
| User         | Human or service account identity                          |
| Project      | Permission boundary that maps to `recon-x project <id>`    |
| Membership   | User-to-organization or user-to-project role binding       |
| Role         | Named permission set such as owner, admin, analyst, viewer |
| Scan         | Job/run created from `scan domain` or `scan repo`          |
| Artifact     | Immutable `scan.json`, SARIF, Markdown or HTML report      |
| Finding      | Fingerprinted triage item from a scan                      |
| BaselineRule | Suppression rule from `.reconxignore` or UI policy         |
| AuditEvent   | Append-only security and admin activity log                |
| Quota        | Limit for scans, targets, concurrency and retention        |

## Recommended roles

| Role    | Permissions                                                    |
| ------- | -------------------------------------------------------------- |
| Owner   | Manage billing, users, projects, policies and all scans        |
| Admin   | Manage projects, run scans, triage findings and edit baselines |
| Analyst | Run scans, view artifacts, triage findings                     |
| Viewer  | Read projects, scans and reports                               |
| CI Bot  | Create scans and upload artifacts for assigned projects        |

These roles are implemented in `internal/rbac`.

## Permission model

Use resource-scoped permissions:

```text
project:read
project:update
scan:create
scan:read
scan:cancel
finding:triage
baseline:update
artifact:read
member:invite
member:update
quota:update
audit:read
```

Every permission check should include:

- organization id
- project id when available
- actor id
- action
- resource id

## API shape

```text
POST   /v1/projects
GET    /v1/projects
GET    /v1/projects/{project_id}
POST   /v1/projects/{project_id}/scans
GET    /v1/projects/{project_id}/scans
GET    /v1/projects/{project_id}/scans/{scan_id}
GET    /v1/projects/{project_id}/scans/{scan_id}/artifacts/{artifact_id}
GET    /v1/projects/{project_id}/findings
PATCH  /v1/projects/{project_id}/findings/{fingerprint}
PUT    /v1/projects/{project_id}/baseline-rules
GET    /v1/projects/{project_id}/quota
PUT    /v1/projects/{project_id}/quota
GET    /v1/audit-events
```

The local API currently implements the read/import subset:

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

## Database migration path

Start by importing `.reconx/projects/*/project.json` into relational tables:

```text
organizations
users
projects
memberships
scans
artifacts
findings
baseline_rules
audit_events
quotas
```

Store raw scan artifacts in object storage or a filesystem-backed artifact store. Store normalized finding summaries in the database using `fingerprint` as the stable logical key.

## Worker model

The API should enqueue scan jobs and invoke the existing CLI engine with explicit profiles:

```bash
recon-x scan repo <path> --profile ci --project <project-id> --output-dir <run-dir>
recon-x scan domain <target> --profile ci --project <project-id> --output-dir <run-dir>
```

Keep active/proof profiles behind explicit authorization controls. RBAC should prevent accidental active testing by default.

## Product guardrails

- Secrets remain redacted by default.
- Raw secret viewing should require a separate privileged permission and audited reason.
- `active` and `proof` scans should require project admin or owner approval.
- CI bot tokens should only create scans and upload artifacts.
- Baseline edits should be audited.
- Quotas should limit concurrent scans and retention per organization.
