# CrowdStrike Falcon API — reference notes

Captured from the Falcon API reference site's top-level catalog on
2026-10-05. This is an **index of collections** (category names +
operation counts), not endpoint-level schemas — unlike the Hadrian
capture in this folder, there's no request/response detail here yet.
Treat any collection not already wired into `collectors/falcon_*.py` as
unconfirmed: pull its real endpoint reference before building against it,
the same rule as Hadrian's unconfirmed `risks` schema.

Relevant files: [`collectors/falcon_client.py`](../collectors/falcon_client.py),
[`collectors/falcon_hosts.py`](../collectors/falcon_hosts.py),
[`collectors/falcon_spotlight.py`](../collectors/falcon_spotlight.py),
[`collectors/falcon_alerts.py`](../collectors/falcon_alerts.py),
[`collectors/falcon_identity.py`](../collectors/falcon_identity.py).

## What secops-dash already uses

Five collections out of the ~100+ in the full catalog, confirmed working
end-to-end against the live tenant (see the Oct 2026 API-client smoke
test — Hosts/Host Group scopes granted and tested; Alerts, Spotlight
Vulnerabilities, and Identity Protection scopes requested but not yet
granted on the API client as of that test):

| Collection (catalog name) | Used by | Endpoints called |
|---|---|---|
| OAuth2 | `falcon_client.py` | `POST /oauth2/token` |
| Hosts | `falcon_hosts.py` | `GET /devices/queries/devices-scroll/v1`, `POST /devices/entities/devices/v2` |
| Host Group | `falcon_hosts.py` | `GET /devices/combined/host-groups/v1` |
| Discover | `falcon_hosts.py` (optional, unmanaged assets) | `GET /discover/queries/hosts/v1`, `GET /discover/entities/hosts/v1` |
| Spotlight Vulnerabilities | `falcon_spotlight.py` | `GET /spotlight/combined/vulnerabilities/v1` |
| Alerts | `falcon_alerts.py` | `GET /alerts/queries/alerts/v2`, `POST /alerts/entities/alerts/v2` |
| Identity Protection | `falcon_identity.py` | `POST /identity-protection/combined/graphql/v1` |

## Full catalog, by domain

Operation counts as shown on the reference site; `←used` marks
collections already wired into a collector.

### Endpoint Security
Alerts (10) ←used · Hosts (16) ←used · Detects (4) · Sensor Download (13) ·
Host Group (9) ←used · Host Migration (10) · Discover (13) ←used (unmanaged assets) ·
Device Content (2) · Mobile Enrollment (2) · Quarantine (6) · Sensor Usage (2) ·
Seraphic (21)

### Real-Time Response
Real Time Response (23) · Real Time Response Admin (20) · Real Time Response Audit (1)

### Threat Intelligence
Intel (27) · Intelligence Feeds (3) · Intelligence Indicator Graph (2) · IOC (17) ·
IOCs (4) · Recon (26) · MalQuery (9) · Tailored Intelligence (5) ·
Falcon Intelligence Sandbox (15) · ThreatGraph (6) · CAO Hunting (7)

### Cloud & Container Security
Cloud Security (7) · CSPM Registration (40) · Cloud Security Assets (5) ·
Cloud Security Compliance (2) · Cloud Security Detections (4) · Cloud Security Risks (1) ·
Cloud Policies (30) · Cloud AWS/Azure/Google Cloud/OCI Registration (7/17/9/7) ·
Cloud Security Registration Combined (1) · Cloud Connect AWS (9) · D4C Registration (21) ·
Cloud Snapshots (8) · Scanning Orchestrator (8) · Container Images (13) ·
Container Vulnerabilities (10) · Container Alerts (3) · Container Detections (7) ·
Container Image Compliance (11) · Container Packages (7) · Drift Indicators (5) ·
Unidentified Containers (3) · Kubernetes Protection (64) ·
Kubernetes Container Compliance (10) · Falcon Container (19) ·
Image Assessment Policies (11)

### Vulnerability Management
Spotlight Vulnerabilities (4) ←used · Spotlight Evaluation Logic (4) ·
Spotlight Vulnerability Metadata (1) · Exposure Management (12) ·
Serverless Vulnerabilities (1)

### Identity & Access
Identity Protection (8) ←used · Falcon ID (4) · User Management (33) ·
API Clients (7) · Access Scopes (2) · Audit (4) · MSSP / Flight Control (30) ·
OAuth2 (2) ←used · Installation Tokens (9) · Certificate Based Exclusions (6) ·
Zero Trust Assessment (3) · Federated Connections (3)

#### `api-clients` collection detail (confirmed from the raw OpenAPI spec, 2026-10-05)

Relevant to the "where do I add scopes to our API client" problem:

| Method | Path | Summary |
|---|---|---|
| GET | `/api-clients/entities/accessible-scopes/v1` | Get all available scopes for customer |
| GET | `/api-clients/entities/api-clients/v1` | Get API Client(s) by ID (includes granted scopes) |
| POST | `/api-clients/entities/api-clients/v1` | Create new API Client |
| DELETE | `/api-clients/entities/api-clients/v1` | Delete API Client(s) by ID |
| PATCH | `/api-clients/entities/api-clients/v1` | Update an API Client (secret unaffected) |
| POST | `/api-clients/entities/api-clients-actions/v1` | Reset an API Client's secret |
| GET | `/api-clients/queries/api-clients/v1` | List all API client IDs for the customer |

**Console navigation — tried and ruled out (as of 2026-10-05):**
- README's documented path "Support and resources → API clients and keys" — that literal label no longer exists in the current console.
- "Support and resources → Resources and tools → Access credentials" (has a "New" badge) — looked promising but is for *CrowdStrike's own* outbound auth to other systems, not for managing the API clients that call *into* Falcon.
- Self-service check via `GET /api-clients/entities/api-clients/v1` using the existing client's own credentials — also `403 access denied, scope not permitted`; the client isn't scoped to manage/read API clients either, so this can't be resolved purely over the API with the current client.
- Next thing to try: the console's own **Sitemap** page (under Support and resources → Resources and tools) — built for exactly this "which page has this feature" problem; not yet confirmed to contain it.

### Data Pipelines & SIEM
NGSIEM (86) · Event Streams (2) · FDR (5) · Foundry LogScale (9) ·
Foundry Lookup Files (2) · Correlation Rules (18) · Correlation Rules Admin (2) ·
Custom Storage (18)

### Policy & Configuration
Prevention Policy (10) · Device Control Policies (18) · Response Policies (10) ·
Sensor Update Policy (19) · Firewall Management (33) · Firewall Policies (10) ·
Custom IOA (20) · IOA Exclusions (14) · Application Abuse Exclusions (9) ·
ML Exclusions (15) · Sensor Visibility Exclusions (5) · Content Update Policies (11) ·
Admission Control Policies (15) · Profile Groups (9) · Configuration Assessment (2) ·
Configuration Assessment Evaluation Logic (1) · Delivery Settings (2)

### Workflows & Automation
Scheduled Reports (3) · Report Executions (4) · Workflows (21) ·
On Demand Scan / ODS (17) · Quick Scan (4) · Quick Scan Pro (6) ·
IT Automation (42) · FaaS Execution (1)

### Application Security
ASPM (53) · Code Security (15) · SaaS Security (36) · API Integrations (3)

### Data Protection
Data Protection Configuration (52)

### File Integrity & Change Monitoring
FileVantage (31) · Sample Uploads (11) · Downloads (4)

### Network Security
Network Scan Scans/Networks/Templates/Zones/Scanners/Scan Runs/Scan Run Reports/
Global Configs/Detections (6/6/6/7/4/5/1/2/4) · Network Containment (5)

### Case & Incident Management
Case Management (55) · Message Center (9) · Falcon Complete Dashboard (17)

### Knowledge & AI
Knowledge Bases (5) · Knowledge Base Files (6) · Knowledge Base Audit Events (3) ·
Agent Templates (2) · Agent Versions (2) · Models (2) · Spans (2) · Tools (2) ·
Agents (5) · Skills (6) · Agent Invocation (4) · Stream (1) · AIDR (33)

### Deployment & Updates
Deployments (6) · Serverless Exports (4)

### Also listed (not a REST collection)
Falcon MCP Server — gives AI assistants (e.g. Claude) direct Falcon access over
MCP; separate integration path from secops-dash's REST collectors, not used here.
SDKs exist for Python, PowerShell, Go, TypeScript, Rust, Ruby — secops-dash
talks to the raw REST API directly (`http_client.py` + `FalconClient`)
rather than any of these.

## Possibly worth a future collector (unconfirmed — pull real docs first)

Flagged only because they'd fit secops-dash's existing site/vuln model, not
because anything's been verified about their schemas:

- **Exposure Management** (12 ops, separate from Spotlight Vulnerabilities) —
  may cover more than the unmanaged-asset slice `falcon_hosts.py` already
  pulls via Discover; worth checking for overlap before adding.
- **Recon** (26 ops) — brand/credential/dark-web monitoring, same shape as
  Hadrian's leaked-credentials category — could feed `email_events` or a
  new table, parallel to Hadrian rather than duplicating it.
- **FileVantage** (31 ops) — file integrity monitoring; could become its own
  `security_alerts`-shaped source if there's a compliance need for it.
- **Real Time Response / Network Containment** — write-path (containment,
  command execution), a different product shape than this read-only
  reporting pipeline; would need a new design, not a bolt-on collector.
