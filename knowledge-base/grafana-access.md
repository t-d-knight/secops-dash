# Grafana access for remediation teams

**Status:** the database and dashboard side is built and tested (`remediation_access.py`,
`grafana/push_dashboards.py`). The Grafana and Entra side is configuration, set out in the rollout steps
below.

## Goal

Technicians in the applications, infrastructure and database teams use Grafana during the day to find and fix
what the reports point at, from data that's at most a night old. They sign in with Entra ID, and access
follows their role-based groups. The cyber team keeps the full view.

## Decisions

| Question | Decision |
| --- | --- |
| One org for remediation teams, or one per team? | **One "Remediation" org.** The teams need the same data; the Team filter and drill-downs narrow it down. |
| What the technicians' data covers | **Servers, domain controllers, cloud and external assets, and machines with no sensor.** Not managed workstations, so no workstation last-logon names. |
| Grafana version | **Upgrade before SSO.** 10.2.6 is out of support, and newer releases can assign orgs from Entra. |
| Groups | On-prem role groups are nested, and Entra app assignment doesn't follow nesting. See [Nested groups](#nested-groups). |

## Who sees what

| Audience | Grafana org | Dashboards | Can't reach |
| --- | --- | --- | --- |
| Cyber team | SecOps (main) | All | – |
| Infrastructure, applications, database | Remediation | Servers, Server patch compliance, Vulnerability Management | Identity risk, USB activity, email, alerts, action log, managed workstations |

## Why two orgs and a separate database login

In Grafana OSS, **dashboard and folder permissions don't protect data.** Any signed-in viewer can send any SQL
through any data source in their org (the query API, the panel inspector), and per-data-source permissions
are a Grafana Enterprise feature. So the control sits where Grafana can't get around it:

1. **A separate Grafana org.** Orgs have their own dashboards, folders and data sources. A technician isn't a
   member of the SecOps org, so its data source can't be reached.
2. **A Postgres login that can read only the `remediation` schema.** The Remediation org's data source uses it.
   The schema holds one view per table the three dashboards read, named like the table, with the login's
   `search_path` set to `remediation, public`. The dashboards' SQL runs unchanged, and nothing in `public` is
   granted. The `assets` view drops managed workstations.

`remediation_access.py` maintains the views. Every script's schema check sets them aside and rebuilds them
within one transaction, and the nightly `dash_*` rebuild swaps them with its tables. `tests/run_e2e.py`
runs every query of the three dashboards as a restricted role. It also checks that identity, alerts,
email, the action log and the raw `assets` table are refused, and that no managed workstation is visible.
If a dashboard starts reading a new table, that test fails until the table is added to
`remediation_access.OBJECTS`.

```
Entra ID                                 Grafana                                   PostgreSQL
--------                                 -------                                   ----------
Enterprise app "Grafana"                 Org: SecOps (cyber team)                  existing read login (everything)
  assignment required                      all dashboards, existing data source
  app roles Viewer / Editor / Admin      Org: Remediation (technicians)            grafana_remediation
  flat groups assigned (see below)         3 dashboards, data source ->              schema remediation only
                                           grafana_remediation
```

## Rollout

1. **Upgrade Grafana** to a supported release. Afterwards, re-test the drill-down links: Grafana 11+ changed
   the full-screen panel URL.
2. **Database (DBA):**
   ```sql
   CREATE ROLE grafana_remediation LOGIN PASSWORD '<new password>';
   GRANT CONNECT ON DATABASE secops_dashboard TO grafana_remediation;
   ALTER ROLE grafana_remediation SET search_path = remediation, public;
   ALTER ROLE grafana_remediation SET statement_timeout = '60s';
   REVOKE CREATE ON SCHEMA public FROM PUBLIC;   -- already the default from Postgres 15
   ```
   Then set `grafana.remediation_role: "grafana_remediation"` in `config.yaml`. The next script run creates the
   views. To check, run `ensure_schema` by hand: it's silent when the views were built, and prints a line if
   the role is missing or something failed.
3. **Grafana:** create the org **Remediation**. In it:
   - add a PostgreSQL data source that logs in as `grafana_remediation`;
   - create a service account with the Editor role, and put its token in `secrets.yaml` as
     `grafana.remediation_api_token`.

   Then run `grafana/push_dashboards.py --config config.yaml`. Lines tagged `[grafana:remediation]` show the
   three dashboards arriving, and `deploy.sh` keeps them up to date from then on.
4. **Entra:**
   - Create an app registration "Grafana", with redirect URI `https://<grafana-host>/login/azuread`.
   - Create app roles with the values `Viewer`, `Editor` and `Admin`; Grafana reads those names.
   - On its enterprise app, turn on **Assignment required** and assign the groups below to roles.
5. **Grafana config** (`grafana.ini`, placeholders):
   ```ini
   [server]
   root_url = https://<grafana-host>/

   [auth.azuread]
   enabled = true
   name = Entra ID
   allow_sign_up = true
   client_id = <application (client) id>
   client_secret = $__file{/etc/grafana/azuread.secret}
   scopes = openid email profile
   auth_url = https://login.microsoftonline.com/<tenant id>/oauth2/v2.0/authorize
   token_url = https://login.microsoftonline.com/<tenant id>/oauth2/v2.0/token
   role_attribute_strict = true          # no app role -> no access, instead of defaulting to Viewer
   use_pkce = true

   [users]
   auto_assign_org = true
   auto_assign_org_id = <Remediation org id>   # new users land in the least-privileged org
   auto_assign_org_role = Viewer
   ```
   Add cyber team members to the SecOps org by hand. They're few and rarely change. If the upgraded Grafana
   supports `org_mapping` for Entra, use that instead. Keep the local admin login until SSO is proven.
6. **Test with one technician:**
   - They sign in, land in Remediation, see three dashboards, and the drill-downs work.
   - The SecOps org isn't offered to them.
   - As the database login itself, `SELECT 1 FROM identity_entities` is refused.

   Then add the rest of the groups.

To withdraw the database access, unset `remediation_role` and run `DROP SCHEMA remediation CASCADE`.

## Nested groups

Entra Connect syncs on-prem groups and their membership, nested groups included. But **assigning a group to
an enterprise app only covers its direct members**: people who are in it only through a nested group don't
get access, and don't get the app role. Group claims in the token have their own nesting rules, and their
own limit when a user is in many groups. That's why this design uses app roles, not group claims.

Options, simplest first:

1. **One flat on-prem group per access level.** For example: remediation viewers, SecOps viewers, SecOps
   admins. A scheduled script fills each one with the *expanded* membership of the role groups that should
   have that access (`Get-ADGroupMember -Recursive`, then add and remove the difference), and Entra Connect
   syncs it. Assign those flat groups to the app. Access stays driven by the role groups, it's auditable in
   AD, and Entra sees only direct members.
2. **Entra dynamic groups** built from group membership (`memberOf` rules). They avoid the script, but check
   that the feature is available in the tenant and supports synced groups before relying on it.
3. **Cloud-only groups maintained by hand.** Fine for a pilot; it drifts once people change roles.

Whichever is chosen, test with a user who is in a role group only through nesting, before calling SSO done.
