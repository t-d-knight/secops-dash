# Grafana access for remediation teams (design)

**Status:** proposal, not built. Decisions needed are at the end.

## Goal

Technicians in the applications, infrastructure and database teams use Grafana during the day to find and fix
what the reports point at, from data that's at most a night old. They sign in with Entra ID, and access
follows their existing role-based Entra groups. The cyber team keeps the full view.

## Who needs what

| Audience | Dashboards | Needs | Must not see |
| --- | --- | --- | --- |
| Cyber team | All | Everything | – |
| Infrastructure | Servers, Server patch compliance, Vulnerability Management | Servers, patch state, missing fixes, hosts carrying a CVE | Identity risk, USB activity, email, alerts |
| Applications | Server patch compliance, Vulnerability Management (Servers for app servers) | Their servers' patch state, application CVEs and fixes | As above |
| Database | Servers (database and middleware panels), Vulnerability Management | Database and middleware products on servers | As above |

All three remediation teams need the same data, just filtered differently. The Team filter on the patch
compliance dashboard and the drill-downs already do that filtering, so one shared remediation view is
enough to start with.

## The constraint that shapes the design

In Grafana OSS, **dashboard and folder permissions don't protect data.** Any signed-in viewer can send any SQL
through any data source in their organisation (the query API, the panel inspector), and per-data-source
permissions are a Grafana Enterprise feature. Hiding the identity or USB dashboards from a technician still
leaves those tables readable.

So the control has to sit in two places that Grafana can't get around:

1. **A separate Grafana organisation** for remediation teams. Orgs are fully separate: their own dashboards,
   folders and data sources. A user who isn't in the cyber team's org can't reach its data source at all.
2. **A read-only Postgres login with grants on only what the remediation dashboards read.** The data source in
   the remediation org uses it, so even raw SQL can only reach those tables.

## Design

```
Entra ID                               Grafana                                  PostgreSQL
--------                               -------                                  ----------
Enterprise app "Grafana"               Org 1  SecOps       (cyber team)         login grafana_ro      (all tables, read)
  user assignment required               every dashboard                        login grafana_remediation
  app roles: Viewer / Editor / Admin     data source -> grafana_ro                (grants below only)
  assigned groups:                     Org 2  Remediation  (technicians)
    cyber team       -> Editor/Admin     Servers, Patch compliance,
    infra / apps / DB groups -> Viewer   Vulnerability Management
                                         data source -> grafana_remediation
```

- **Who can sign in** is decided in Entra: on the enterprise app, turn on *Assignment required* and assign only
  the cyber team group and the remediation teams' role-based groups. Anyone else is refused before they reach
  Grafana. `allowed_groups` in Grafana is a second check.
- **Grafana role** (Viewer/Editor/Admin) comes from **app roles** on the app registration, assigned per group. App
  roles reach the token as a `roles` claim. That avoids the group-claim limit, where users in many groups get
  no group list in the token.
- **Which org** a user lands in: new users go to the Remediation org (`auto_assign_org_id`), the
  least-privileged default. Cyber team members are added to the SecOps org by an admin. That's a handful of
  people who rarely change. Newer Grafana releases can map Entra groups or roles to orgs automatically
  (`org_mapping`); check the release you upgrade to.
- **Teams inside Grafana** (applications, infrastructure, database) aren't needed at first, since they all see
  the same dashboards. Syncing an Entra group's membership into a Grafana team automatically ("team sync") is
  an Enterprise feature in OSS. If team-specific folders are wanted later, a small script using Graph (group
  members) and the Grafana API could keep teams in step.
- **Dashboards** are pushed to both orgs from the same JSON by `push_dashboards.py`, using one service-account
  token per org, because service accounts belong to one org. The Remediation org gets only the three
  dashboards.

### Grafana configuration (`grafana.ini`, values are placeholders)

```ini
[server]
root_url = https://<grafana-host>/

[auth.azuread]
enabled = true
name = Entra ID
allow_sign_up = true
auto_login = false
client_id = <application (client) id>
client_secret = $__file{/etc/grafana/azuread.secret}
scopes = openid email profile
auth_url = https://login.microsoftonline.com/<tenant id>/oauth2/v2.0/authorize
token_url = https://login.microsoftonline.com/<tenant id>/oauth2/v2.0/token
allowed_groups = <cyber group object id> <infra group object id> <apps group object id> <db group object id>
role_attribute_strict = true          # no app role -> no access, instead of defaulting to Viewer
use_pkce = true

[users]
auto_assign_org = true
auto_assign_org_id = <Remediation org id>
auto_assign_org_role = Viewer

[auth]
disable_login_form = false            # keep the local admin login until SSO is proven, then turn it off
```

The app registration needs a redirect URI of `https://<grafana-host>/login/azuread`. Create the app roles with
values `Viewer`, `Editor` and `Admin` (Grafana reads those names), then assign groups to roles on the
enterprise app.

### The remediation database login

Read-only, and granted only the objects the three dashboards read. This list was generated from the dashboard
SQL; regenerate it whenever those dashboards change.

```sql
CREATE ROLE grafana_remediation LOGIN PASSWORD '<from secrets>';
GRANT CONNECT ON DATABASE secops_dashboard TO grafana_remediation;
GRANT USAGE ON SCHEMA public TO grafana_remediation;
GRANT SELECT ON
    assets, dim_site, host_insights, host_patch_status, vuln_findings, sla_policy,
    dash_asset_risk, dash_nvd_coverage, dash_patch_impact, dash_vuln_kev_epss, dash_vuln_site_summary,
    daily_epss_metrics, daily_kev_metrics, daily_mttr_metrics, daily_product_metrics, daily_site_metrics,
    daily_sla_metrics, daily_vuln_flow_metrics,
    lm_devices, lm_device_patch, server_patch_compliance, server_patch_compliance_status
  TO grafana_remediation;
ALTER ROLE grafana_remediation SET statement_timeout = '60s';
```

Not granted, so they stay cyber-only: identity and Entra tables, removable media, email and DMARC, alerts,
the impact action log, collector runs and configuration.

Two catches:
- The `dash_*` tables are rebuilt every night (drop and rename), which loses their grants. The rebuild has to
  re-grant them, or use `ALTER DEFAULT PRIVILEGES` for the role that owns them.
- `assets` covers workstations as well as servers, including the last logged-on user. The servers report
  already gives remediation teams that for servers. If workstation logons are too much, grant a view limited
  to servers instead of the table, and point the dashboards at it.

## Before rolling out

- **Upgrade Grafana.** The install runs 10.2.6, which is out of support. A security team's dashboards
  shouldn't sit on an unsupported release, and newer versions add `org_mapping` for Entra. Re-test the
  drill-down links after upgrading: Grafana 11+ changed the full-screen panel URL.
- **Remove unused plugins.** Performance Co-Pilot is installed and unsigned.
- **Try it with one group first.** Sign in as a member of the infrastructure group and check that the
  SecOps org isn't offered, and that a raw query against an identity table is refused by Postgres.

## Decisions needed

1. **One Remediation org for all three teams**, or one per team? One is simpler, and the data is the same.
2. **`assets` or a servers-only view** for the remediation login? The difference is workstation last-logon
   names.
3. **Upgrade first, or SSO on 10.2 and upgrade after?** Upgrading first avoids configuring org placement
   twice.
4. **Which Entra groups** map to Viewer, and who in the cyber team gets Editor or Admin.
