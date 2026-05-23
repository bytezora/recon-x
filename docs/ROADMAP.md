# Roadmap

This roadmap tracks the larger work that would turn recon-x from a fast recon scanner into a fuller vulnerability-management platform.

## Next Product Milestones

1. Verification mode
   - Add safe validation flows for high-confidence findings so reports can separate indicators from confirmed vulnerabilities.

2. Asset inventory and risk scoring
   - Maintain host, service, technology and owner inventory.
   - Score risk by CVSS, exposure, KEV/EPSS and business criticality.

3. Scan history and baseline analytics
   - Store results in SQLite or PostgreSQL.
   - Show new, resolved and recurring findings across scans.

4. DevSecOps integrations
   - Add ready-made GitHub Actions, GitLab CI and Jenkins examples.
   - Export to Jira, DefectDojo and SIEM pipelines.

5. Distributed scanning
   - Split orchestrator and worker nodes.
   - Support large scopes through a queue such as NATS, RabbitMQ or SQS.

6. Plugin system
   - Provide a stable SDK for custom modules.
   - Version plugin APIs and verify template/plugin integrity.

7. Governance
   - Add RBAC, audit logs, encrypted secrets and policy guardrails.
   - Support allowed scopes, rate caps and safer payload profiles.

8. Evidence quality
   - Store raw request/response snippets, timestamps, module versions and replay commands where appropriate.

9. Discovery depth
   - Add JS runtime crawling, form discovery, auth-aware crawling and REST/GraphQL schema discovery.

10. Operational maturity
    - Add performance profiles, health checks, self diagnostics, retry/backoff telemetry and SLO metrics.
