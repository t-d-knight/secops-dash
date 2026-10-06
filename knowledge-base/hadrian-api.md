# Hadrian API — reference notes

Captured from the Hadrian API docs site (behind the customer login, so not
linkable) on 2026-10-05, so the `hadrian` collector has a durable reference
instead of depending on console access every time it needs rechecking.

Relevant files: [`collectors/hadrian.py`](../collectors/hadrian.py),
the `hadrian:` block in [`config.yaml.example`](../config.yaml.example).

## Status for secops-dash

- **Confirmed and wired up**: auth, base URL, `GET /organizations/{organizationId}/assets`
  (full response schema), the pagination contract, array query-param
  encoding, error shape. See §3 and §2 below.
- **Confirmed path, unconfirmed item schema**: `GET /organizations/{organizationId}/risks`
  — the path and required permission (`risks:read`) are confirmed by the
  endpoint index in §4, but no response schema for a single Risk object has
  been published to us. `risks.fields` in `config.yaml.example` is still a
  placeholder carried over from before this doc existed — **do not set
  `collectors.hadrian.risks` live / enable that feed until the real field
  names are pulled from that endpoint's own reference page** (not just the
  index entry below).
- **Not implemented**: everything outside Assets/Risks (CVEs, Insights,
  Leaked Credentials, Risk Comments, Shared Resources, write-back
  endpoints, …) — inventoried in §4 for future reference. Nothing in
  `collectors/hadrian.py` calls any of it today.

---

## 1. Basics

### Authentication

Every request carries an API key in the `X-Api-Key` header. The key
belongs to the user who created it and carries that account's org/team
permissions — a request with a missing, expired, or revoked key is
rejected outright (`401`).

Create, rotate, and revoke keys in personal settings. A key is shown only
once, at creation. Treat it like a password: server-side only, in a
secrets manager (here: `secrets.yaml`, gitignored, `chmod 600`), never in
source control.

What an operation can do depends on the org role and team memberships of
the key's owning user — see §1.3 Permissions.

### Base URL & versioning

```
https://api.hadrian.io
```

HTTPS only. v2 is the default and documented version, served at the bare
base URL above or equivalently under an explicit `/v2` prefix — pin the
`/v2` prefix if an integration needs to stay on this contract across a
future version bump. v1 is no longer supported.

### Permissions

A key carries the org role + team memberships of the user who created it.
Each endpoint page lists the specific permission(s) it needs (e.g.
`assets:read`, `risks:write`); a `403` means the key authenticated fine
but that account lacks the permission the operation requires.

### Quickstart

```python
import requests

organization_id = "your-organization-id"
api_key = "YOUR_API_KEY"
url = f"https://api.hadrian.io/organizations/{organization_id}/assets"

response = requests.get(
    url,
    headers={"X-Api-Key": api_key},
    params={"offset": 0, "pageSize": 50},
)
response.raise_for_status()

for asset in response.json()["items"]:
    print(asset["assetType"], asset["value"])
```

The organization id is part of the URL when logged in to the platform, or
from `GET /users/me/organizations`.

---

## 2. Conventions (hold across the whole API)

### Pagination

Most paginated collections use `offset` + `pageSize`. **`offset` is a
zero-based page index, not a row offset** — start at `0`, increment by
`1` per page. Do **not** increment by `pageSize` (or by the row count of
the page you just got): that skips pages while still returning `200`s,
silently dropping data. Stop when a page returns fewer items than
`pageSize`. Responses also echo `offset`, `pageSize`, and (if
`includeTotalCount=true` was sent) `totalCount`.

> This is exactly the footgun `collectors/hadrian.py`'s generic
> `pagination: {type: ...}` config guards against — see the comment on
> `assets.pagination` in `config.yaml.example`. Its `type: offset` mode
> increments by row count (built for a different, row-offset-style vendor
> API) and must **not** be used against Hadrian; `type: page` increments
> by 1 and is what's configured.

Reference loop (works for any paginated endpoint — path is a parameter):

```python
import requests

BASE_URL = "https://api.hadrian.io"
FIRST_PAGE_INDEX = 0
MAX_PAGES = 500  # nothing in the spec bounds a collection; the client must

def fetch_all_pages(path, api_key, page_size=100, params=None):
    session = requests.Session()
    session.headers.update({"X-Api-Key": api_key, "Accept": "application/json"})
    items = []
    page_index = FIRST_PAGE_INDEX
    while page_index < FIRST_PAGE_INDEX + MAX_PAGES:
        query = dict(params or {})
        query["offset"] = page_index
        query["pageSize"] = page_size
        response = session.get(BASE_URL + path, params=query)
        response.raise_for_status()
        page = response.json()["items"]
        items.extend(page)
        if len(page) < page_size:
            return items
        page_index += 1
    raise RuntimeError("Stopped after %d pages" % MAX_PAGES)
```

If an endpoint doesn't list pagination params, it returns the whole
collection in one response. A few endpoints use `page`/`per_page`
instead — always follow what that endpoint's own page says.

### Array query parameters

`string[]`-typed params accept either form (pick one per param per
request; values combine with OR):

| Form | Example |
|---|---|
| Repeated name | `riskSeverity=Critical&riskSeverity=High` |
| Indexed name | `riskSeverity[0]=Critical&riskSeverity[1]=High` |

`requests` in Python repeats the name automatically for a list value
(`params={"riskSeverity": ["Critical", "High"]}`). With cURL, pass `-g`
(`--globoff`) when the URL has the indexed form, or it reads `[0]` as a
glob range and rejects the URL:

```bash
curl -g -X GET "https://api.hadrian.io/organizations/{organizationId}/risks?riskSeverity[0]=Critical&riskSeverity[1]=High" \
  -H "X-Api-Key: YOUR_API_KEY"
```

### Errors

Problem-document shape (RFC 7807-ish), every field optional, some errors
have no body at all — parse defensively, fall back to the HTTP status:

```json
{ "type": "string", "title": "string", "status": 0, "detail": "string", "instance": "string" }
```

No stable machine-readable error code — branch on HTTP status, show
`detail` when present, log the full body. Never match on `title`/`detail`
text.

| Status | Meaning |
|---|---|
| 400 Bad Request | Malformed value/body. Retrying unchanged repeats it. |
| 401 Unauthorized | Missing/bad `X-Api-Key`. Retrying doesn't help until the key is replaced. |
| 403 Forbidden | Key is valid; account lacks the permission the op requires. |
| 404 Not Found | No resource at those path identifiers. Same request → same result. |
| 422 Unprocessable Content | Parsed, but rejected. See below. |

**422 / validation errors**: same problem-document shape, no guaranteed
field-by-field payload. Log the full body for diagnosis; don't depend on
undocumented members; show `detail` to users when present, else the
status.

### Running in production

- **Retries**: retry idempotent requests (GET/PUT/DELETE) on transient
  failure. Never auto-retry POST — no idempotency key is provided, so a
  timed-out POST may have already created something; check current state
  before retrying.
- **Backoff**: retry `429` and transient `5xx` with exponential backoff +
  jitter, bounded attempts. `Retry-After`/rate-limit headers are **not**
  part of the contract — the client owns its own delay policy.
- **Content types**: send `Accept: application/json` explicitly. Export
  endpoints return `text/csv` (or no body) — check `Content-Type` before
  choosing a parser, and stream large exports rather than loading them
  whole.

---

## 3. Confirmed endpoint — List assets

`GET /organizations/{organizationId}/assets` — permission `assets:read`.

**Path params**: `organizationId` (string, required).

**Query params** (paginated — see §2):

| Name | Type | Notes |
|---|---|---|
| `parentId` | uuid | Deprecated |
| `assetTypes` | string[] | Deprecated. `Domain`, `Certificate`, `Port`, `IP`, `Service`, `Path`, `IpInstance` |
| `platformAssetTypes` | string[] | `Domain`, `StaticIp`, `DynamicIp`, `Service`, `HttpService`, `PathGroup`, `HtmlPathGroup`, `Certificate` |
| `assetAvailability` | string | `Available`, `Unavailable` |
| `approvalStates` | string[] | Deprecated. `Approved`, `Unapproved`, `Disapproved` |
| `scanningStates` | string[] | `Off`, `Passive`, `Active` |
| `from` / `to` | string | `yyyy-MM-dd HH:mm:ss` |
| `importType` | string | `Manual` or `System` — set by Hadrian, not writable via this API |
| `offset` / `pageSize` | int32 | Page index / page size — see §2 |
| `sorts` | object[] | `{field (required), sortOrder}` |
| `includeTotalCount` | bool | Include `totalCount` in the response |

**200 response**:

```json
{
  "totalCount": 0,
  "offset": 0,
  "pageSize": 0,
  "items": [
    {
      "assetId": "string",
      "value": "string",
      "assetParentIds": ["string"],
      "organizationId": "string",
      "importType": "Manual",
      "assetType": "Domain",
      "platformAssetType": "Domain",
      "tags": [{ "tagId": "string", "name": "string", "tagAssignmentMethod": "Automatic" }],
      "properties": [{ "key": "string", "storageUri": "string", "schema": "string", "type": "string", "value": "string" }],
      "approvalState": "Approved",
      "scanningState": "Off",
      "isAvailable": true,
      "detectedOnUtc": "yyyy-MM-dd HH:mm:ss",
      "lastSeenAtUtc": "yyyy-MM-dd HH:mm:ss",
      "lastUpdatedAtUtc": "yyyy-MM-dd HH:mm:ss",
      "source": "string",
      "services": [
        {
          "assetId": "string",
          "value": "string",
          "port": 0,
          "ipAsset": { "assetId": "string", "value": "string" },
          "domainAsset": { "assetId": "string", "value": "string" }
        }
      ]
    }
  ]
}
```

Errors: `400`, `401`, `403` — all the problem-document shape from §2.

**What `collectors/hadrian.py` does with this**: `assetId`→`id`,
`value`→`name`, `platformAssetType`→`type`, `detectedOnUtc`→`first_seen`,
`lastSeenAtUtc`→`last_seen` via the configurable field map. `ip` and
`ports` are **not** flat fields on this schema, so they're derived in
code instead: an IP comes from `value` itself when `platformAssetType` is
`StaticIp`/`DynamicIp`, or from `services[].ipAsset.value`; ports come
from `services[].port`. `technologies` isn't in this response at all —
per the "Working with assets" guide blurb, it apparently only shows up on
the single-asset `GET` endpoint, which isn't documented here yet (see
§5).

---

## 4. Endpoint index (everything else)

Inventory only — none of this is called by `collectors/hadrian.py` today.
Paths are relative to the base URL; `{organizationId}` is a path param on
every `/organizations/{organizationId}/...` route.

### CVEs — permission `cves:read`

| Method | Path | Summary |
|---|---|---|
| GET | `/cves` | Paginated CVEs by part/vendor/product/version, sorted by CVE ID desc |
| GET | `/cves/{id}` | One CVE by id |
| GET | `/cves/count` | Count of CVEs for a part/vendor/product/version tuple |
| GET | `/organizations/{organizationId}/cves` | Potential CVEs for the org |
| GET | `/organizations/{organizationId}/cves/{cveId}/assets` | Org assets potentially affected by a CVE |

Org-specific CVE matching, independent of secops-dash's own KEV/EPSS/NVD
enrichment pipeline (`kev_sync.py`/`epss_sync.py`/`nvd_enrich.py`) — not
currently cross-referenced with it.

### Insights — permission `insights:read`

Noteworthy-change feed (new risks, leaked creds, scanning gaps), filtered
by the caller's asset access; coverage gaps are org-wide aggregates.

| Method | Path | Summary |
|---|---|---|
| GET | `/organizations/{organizationId}/insights` | All insight summaries the caller can see |
| GET | `/organizations/{organizationId}/insights/geographic-ip-distribution` | Detail |
| GET | `/organizations/{organizationId}/insights/new-important-risks` | Detail |
| GET | `/organizations/{organizationId}/insights/new-leaked-credentials` | Detail |
| GET | `/organizations/{organizationId}/insights/new-subdomains` | Detail |
| GET | `/organizations/{organizationId}/insights/newly-exposed-services` | Detail + 7-snapshot trend (org-wide callers) |
| GET | `/organizations/{organizationId}/insights/non-standard-port-protocol` | Detail |
| GET | `/organizations/{organizationId}/insights/scanning-coverage-gap` | Org-wide aggregate (same for every caller); `newlyFoundOnly` limits to domains found in the last 7 days |

### Leaked Credentials — permission `assets:read`

| Method | Path | Summary |
|---|---|---|
| GET | `/organizations/{organizationId}/leaked-credentials` | All leaked credentials |
| GET | `/organizations/{organizationId}/leaked-credentials/export` | CSV export |
| GET | `/organizations/{organizationId}/leaked-credentials/groups/found-on` | Grouped by found date |
| GET | `/organizations/{organizationId}/leaked-credentials/groups/related-assets` | Grouped by related asset |
| GET | `/organizations/{organizationId}/leaked-credentials/groups/types` | Grouped by type |

### Organizations Shared Resources — permission `secure-share:write`

Manage externally-shared resources (revoke / resend). Recipients read
through **Shared Resources** below.

| Method | Path | Summary |
|---|---|---|
| DELETE | `/organizations/{organizationId}/shared-resources/{sharedResourceId}` | Revoke a shared resource |
| POST | `/organizations/{organizationId}/shared-resources/{sharedResourceId}/resend-link` | Resend the share link |

### Risk Comments — `risks:read` (read), `risks:comment` (write)

| Method | Path | Summary |
|---|---|---|
| GET | `/organizations/{organizationId}/risks/{id}/comments` | All comments on a risk |
| POST | `/organizations/{organizationId}/risks/{id}/comments` | Add a comment |
| DELETE | `/organizations/{organizationId}/risks/{id}/comments/{commentId}` | Delete a comment |

### Risk Shared Resources — `risks:read`, `secure-share:write`

Share a risk outside the org; recipient side is **Shared Risks** below.

| Method | Path | Summary |
|---|---|---|
| GET | `/organizations/{organizationId}/risks/shared-resources` | Risks shared by the org |
| POST | `/organizations/{organizationId}/risks/shared-resources` | Share a risk with one or more emails |
| GET | `/organizations/{organizationId}/risks/shared-resources/history` | Sharing history |

### Risks — `risks:read`, `risks:write`, `statistics:read`

The endpoint secops-dash's `risks` feed is configured against but not yet
field-mapped (see Status, above):

| Method | Path | Summary |
|---|---|---|
| GET | `/organizations/{organizationId}/risks` | **List risks for the org — this is the one `collectors/hadrian.py` calls; item schema still unconfirmed** |
| GET | `/organizations/{organizationId}/risks/{riskId}` | Single risk, full detail |
| GET | `/organizations/{organizationId}/risks/{riskId}/discovery-path` | Asset chain Hadrian followed to find it |
| GET | `/organizations/{organizationId}/risks/{riskId}/traces` | Parsed `risk_trace` actions |
| GET | `/organizations/{organizationId}/risks/assets/{assetId}` | Risks for a given asset |
| PATCH | `/organizations/{organizationId}/risks/{id}/severity` | Update severity |
| PATCH | `/organizations/{organizationId}/risks/{riskId}/ignored-status` | Update ignored status |
| PATCH | `/organizations/{organizationId}/risks/{riskId}/promote` | Promote a potential/unpatched-tech risk to verified |
| PATCH | `/organizations/{organizationId}/risks/{riskId}/risk-lead` | Update risk lead |
| PATCH | `/organizations/{organizationId}/risks/{riskId}/status` | Update status |
| PATCH | `/organizations/{organizationId}/risks/close-and-validate` | Validate + close multiple risks |
| PATCH | `/organizations/{organizationId}/risks/ignored-status` | Bulk update ignored status |
| PATCH | `/organizations/{organizationId}/risks/risk-lead` | Bulk update risk lead |
| PATCH | `/organizations/{organizationId}/risks/severity/batch` | Bulk update severity |
| GET | `/organizations/{organizationId}/risks/export` *(deprecated)* | CSV export |
| POST | `/organizations/{organizationId}/risks/export` | CSV export |
| GET | `/organizations/{organizationId}/risks/groups/categories` | Count by category |
| GET | `/organizations/{organizationId}/risks/groups/found-on` | Count by found period |
| GET | `/organizations/{organizationId}/risks/groups/ignored-on` | Count by ignored period |
| GET | `/organizations/{organizationId}/risks/groups/related-asset` | Count by related asset |
| GET | `/organizations/{organizationId}/risks/groups/resolved-on` | Count by resolved period |
| GET | `/organizations/{organizationId}/risks/groups/risk-lead` | Count by risk lead |
| GET | `/organizations/{organizationId}/risks/groups/scanning-credential` | Count by scanning credential |
| GET | `/organizations/{organizationId}/risks/groups/severity` | Count by severity |
| GET | `/organizations/{organizationId}/risks/groups/source` | Count by source |
| GET | `/organizations/{organizationId}/risks/groups/status` | Grouped by status |
| GET | `/organizations/{organizationId}/risks/groups/tags` | Grouped by related-asset tags |
| GET | `/organizations/{organizationId}/risks/groups/title` | Grouped by title: count, distinct severities, representative category, latest last-seen |
| GET | `/organizations/{organizationId}/risks/risks-with-assets` | Risks with related assets |
| GET | `/organizations/{organizationId}/risks/mean-remediation-times` | Mean remediation time by severity |
| GET | `/organizations/{organizationId}/risks/statistics` | Risk statistics |
| GET | `/risks/categories` | List of risk categories (no org scope) |

> The `/groups/*` and `PATCH .../status` etc. endpoints confirm a Risk
> has (at least) `severity`, `status`, `ignoredStatus`, `riskLead`,
> `category`, `source`, `tags` (via related asset), and a
> `scanningCredential` concept — but not their exact JSON key spelling or
> types. Don't guess field names in `config.yaml.example`'s `risks.fields`
> from this table; pull the actual `GET .../risks` or `GET .../risks/{riskId}`
> reference page.

### Shared Resources (recipient-side, no org scope)

No specific permission documented — reachability is still bounded by what
the key's user can access.

| Method | Path | Summary |
|---|---|---|
| GET | `/shared-resources/{sharedResourceId}` | Open a shared resource |
| GET | `/shared-resources/{sharedResourceId}/comments` | Comments on it |
| POST | `/shared-resources/{sharedResourceId}/comments` | Add a comment as a contributor |
| POST | `/shared-resources/{sharedResourceId}/resend-link` | Resend the link |

### Shared Risks (recipient-side)

| Method | Path | Summary |
|---|---|---|
| GET | `/organizations/{organizationId}/shared-resources/risks/{riskId}` | Read a shared risk |
| PATCH | `/organizations/{organizationId}/shared-resources/risks/{riskId}` | Update a shared risk |

---

## 5. Open questions / next doc to pull

1. **Risk object schema** — the fields `collectors/hadrian.py`'s `risks`
   feed needs (status, severity, cvss, cves, asset linkage, timestamps,
   …). Pull the reference page for `GET /organizations/{organizationId}/risks`
   or `GET /organizations/{organizationId}/risks/{riskId}`, same way the
   assets page was captured in §3.
2. **Single-asset GET schema** (`GET /organizations/{organizationId}/assets/{assetId}`,
   implied by the "Working with assets" guide but not in this capture) —
   needed if `technologies` should get wired up on the `external_assets`
   table.
3. Whether `/organizations/{organizationId}/cves` is worth cross-referencing
   against the existing KEV/EPSS/NVD enrichment, or left alone as
   Hadrian's own view.
