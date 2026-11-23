# robots_fighting.md

This is the coordination file for everyone changing this repo or the live install, people and AI agents
alike. Read it before you start and before you push or deploy. If you disagree with a change someone else
made, **write it here instead of silently reverting it**.

The standing rules are in [AGENTS.md](AGENTS.md) and [CONTRIBUTING.md](CONTRIBUTING.md). This file is for
who is doing what right now, and what they found.

> **This file is committed.** Keep it generic like the rest of the repo: placeholders, no real hostnames,
> accounts, sites or production figures (the pre-commit check scans it). Real-world context belongs in
> your untracked `NEXT-STEPS.local.md`.

## Before you push
1. `git fetch origin` and compare `main` with your `HEAD`. If `main` has moved, rebase or merge, then
   rerun the checks below before pushing.
2. Never force-push `main`. Don't delete or rewrite someone else's branch.
3. One concern per commit, and the message says which areas from the table below it touches.
4. `tools/check_identifiers.py` is clean. Run `tests/run_e2e.py` for collectors, rollups, reports or
   dashboard queries.
5. **If your change moves report numbers** (rollups, report queries, measure definitions, classification):
   run `tests/demo_samples.py` before and after **on the same day**, and paste the figures that changed
   into the log. The demo data uses a fixed seed but dates relative to today, so runs on different days
   can't be compared.
6. Every new threshold or number in a report or measure is labelled **policy** (and who set it) or
   **assumed** (and why). Record it in `config.yaml.example` or the ops guide's "Reading the numbers"
   section.

## Before you deploy or touch the live install
- Claim the **Live install** row below first. One person or agent deploys at a time.
- Diff the server copy against yours before replacing anything, and keep the dated `.bak`. If the server
  has changes that aren't in git, stop and record them here. Don't overwrite them.
- Don't deploy or run anything heavy while the nightly collector holds `logs/.collector.lock`.
- Afterwards, log what was deployed (commit hash) and what you checked.

## Who's working on what
Claim the area you're editing. Add yourself, a date and a note, and remove your row when you're done.
A claim older than 14 days with no log entry can be taken over, but say so in the log first.

| Area (files) | Claimed by | Since | Notes |
|---|---|---|---|
| Live install: deploys, server config, crontab, Grafana pushes | unclaimed | | |
| Schema (`db_schema.py`) | unclaimed | | Every collector and report depends on it |
| Rollups (`rollup_daily_metrics.py`, `impact.py`) | unclaimed | | Changes move every trend line |
| Weekly report (`exec_report.py`) | unclaimed | | Large file; reporting review in CONTRIBUTING "Writing reports" |
| Scorecard / impact / servers report / action pack | unclaimed | | |
| Report comparison samples and review note | unclaimed | | |
| Grafana dashboards (`grafana/`) | unclaimed | | |
| Collectors (`collectors/<name>.py`, one row each when claimed) | unclaimed | | |
| Falcon tag sync (`tools/falcon_tag_sync.py`), the only vendor writer | unclaimed | | Changes need the owner's say-so (AGENTS.md rule 4) |
| Migration scripts (branch `migration-scripts`) | unclaimed | | Two commits not on `main` yet |

## State of the repo when this file was written
- 2026-11-11: local and remote `main` identical at `c26f43d`. Branch `migration-scripts` is two commits
  ahead of its base and not merged.

## Log (newest first; add yours at the top)
Each entry heading is `### YYYY-MM-DD, <who> for <whom>: <what>`. In the entry:
- **Status:** local / pushed / deployed (with the commit). Say "local" plainly if it isn't pushed.
- **Changed:** what moved and which areas it touched.
- **Verified:** the checks you ran and what they showed.
- **Not verified / open:** what you didn't check, what's still wrong, and what you suspect but haven't
  proved. Don't claim an improvement the evidence doesn't show.

Keep entries short and link to the commit for detail. When the log passes about 300 lines, move entries
older than a month to `docs/robots_fighting-archive.md`.

### 2026-11-24, Claude for TK: ops guide accuracy pass, new overview doc
- **Status:** pushed. Docs only, nothing to deploy.
- **Changed:** ops guide: the Remediation Grafana org is marked as not switched on yet. Per-team Servers
  copies are noted as depending on the Falcon tag sync, which isn't on cron. Azure Log Analytics is added
  to the sources table. New `knowledge-base/overview.md` covers what the tool is, what it does, how it
  works and what it enables, linked from the readme and ops guide. Readme diagram now says 9 dashboards.
- **Verified:** guide schedule against `crontab.example`, dashboard list against `grafana/`, sources
  against `collectors/`, per-team split against `server_report.py`. `check_identifiers.py` clean.
- **Not verified / open:** whether any `Team-` tags exist on the live tenant (if they do, some per-team
  folders will already be populated). When the tag sync or the Remediation org goes live, update the
  ops guide and the overview's "Built but not switched on yet" section.

### 2026-11-23, Claude for TK: Hadrian risks ignored in the console no longer count as open
- **Status:** pushed, not deployed. Takes effect on the first Hadrian run after deploy (every risk is
  re-read each night, so the existing rows flip then).
- **Why:** when Hadrian can't validate a fix itself (e.g. it can't read the version), the only way to close
  the risk in its console is Ignore. Live API check: that's `activityStatus: Ignored` with `riskVisibility`
  still `Visible`. The collector only knew Open/Closed, so these fell through to OPEN, were re-confirmed
  every night and showed as unresolved in the weekly report.
- **Changed:** collector `hadrian`: Ignored -> SUPPRESSED (accepted risk). An Ignored risk with a comment
  starting `Validated:` (configurable, case-insensitive) -> FIXED, dated by the earliest such comment (TK:
  fixes checked by hand get that comment; the evidence stays in Hadrian). Comments are read
  (`GET .../risks/{id}/comments`, `risks:read`) for Ignored risks only; if that fails, they stay SUPPRESSED
  and the run is `partial`. An unrecognised `activityStatus` stays OPEN and is counted in stats. New stats
  `risks_by_state`, `risks_validated_by_comment`. Workflow in the ops guide ("Reading the numbers"). This
  replaces an interim rule pushed the same day (e289ed8: Ignored + NotFound -> FIXED): the rescan isn't
  evidence when Hadrian can't validate the fix.
- **Verified:** e2e, all passed, 166 checks (5 new: Validated comment -> FIXED dated by the earliest one;
  "validation required" / "Not validated:" notes -> SUPPRESSED; stats). The mock's comments follow the
  response shape seen live. The weekly report's external section counts only OPEN/REOPENED as open.
- **Not verified / open:** the comment-read failure path (no test). The live run after deploy: until
  `Validated:` comments are added in Hadrian, the existing ignored risks show as accepted risk, not fixed.
  Fix dates before the rollups' recompute window don't change earlier weeks' "fixed" counts. Considered
  and rejected: counting accepted risk as "resolved" (CONTRIBUTING "Keep outcomes separate"). Later idea:
  show accepted risk as its own outflow ("Risk accepted") next to Fixed.

### 2026-11-23, Claude for TK: Spotlight full pull survives dropped cursors; catch-up stays short
- **Status:** pushed (358965e). Deployed 2026-11-23 by TK with `deploy.sh` (output not reviewed here).
  Crontab reinstalled from `crontab.example` the same day after a diff (only functional change: the
  Monday 13:00 publish; previous crontab saved to `logs/crontab.bak-20261123`). Before the deploy, a
  catch-up that had started an old-code full Spotlight pull was killed, so that day's `collector_runs`
  row for it stays `running`. The weekly and servers reports for that week had already been generated and
  the 07:30 publish had run.
- **Why:** from 2026-11-21 Falcon expired the `after` cursor ("Search context expired") part-way through
  most weekly full open-vuln pulls. The retry restarted the whole multi-hour pull and failed again, the run
  overran into the morning, every job waiting on the collector lock (weekly reports, publish, backup)
  slipped, and the 10:00 catch-up re-ran the same full pull and held the lock again.
- **Changed:** collector `falcon_spotlight`: the full pull goes by `created_timestamp` windows (1 day
  default); a window that loses its cursor is halved and re-pulled; vanished vulns are expired only if all
  windows finished and the total is within 5% of Falcon's own count. If a window still fails at the
  minimum width, the run falls back to an incremental + closed pull, expires nothing and reports
  `partial` (alerted, not retried by the catch-up). `collect.py --catch-up` / `run_collector.sh
  --catch-up` never do a full pull. `falcon_client`: `cursor_retry_wait` configurable. `crontab.example`:
  second Monday publish at 13:00. Example config, readme, ops guide.
- **Verified:** e2e, all passed, 161 checks (7 new: windowed full pull and expiry, window split on a
  dropped cursor, fallback to incremental with nothing expired, total cross-check, catch-up incremental
  only). Mock only: it implements the window filter and the 404 the way the live logs show them.
- **Not verified / open:** against the real API: that Spotlight's combined endpoint honours
  `created_timestamp:>=` / `<` bounds as the mock does (if not, the total cross-check stops any expiry and
  the run goes `partial`), that `meta.pagination.total` is an exact count for millions of records, and
  whether Falcon's cursor drops are about time, load or record count (a catch-up dropped one after well
  under an hour). The first full pull after deploy (next Saturday, or the next night if the last good full
  is 8+ days old) is the real test: look for `full_pull_windows`, `full_pull_splits` and `falcon_total` in
  its stats. Full pulls are still long, so a full-pull Monday still delays the weekly reports. The first
  new-code full pull is the night of 23-24 Nov 2026 (forced: the last good full is 8+ days old).

### 2026-11-20, Claude for TK: doc catch-up before leave
- **Status:** pushed, docs only. Nothing to deploy.
- **Changed:** readme: feed table adds `checkpoint_hec_flow` and `logicmonitor`; eight dashboards, not seven,
  with the preview dashboard listed; clone URL; a "Notifications" section (what alerts, config keys, test
  command); how to check what's deployed. Ops guide: LogicMonitor and mail-flow sources, monthly scorecard
  in reports and schedule, patch compliance and preview dashboards, drill-downs, and a short "While the owner
  is away" section (nobody else operates or fixes it; check freshness before quoting; don't touch the server).
  Statuses below for f3f85e4 and 2053c10 corrected to pushed.
- **Verified:** alert triggers, thresholds and `deploy.sh` steps read from `notify.py`, `config.yaml.example`
  and `deploy.sh`; cron times from `crontab.example`. Identifier check (pre-commit hook).
- **Not verified / open:** deployed commit unknown: no deploy has been logged here since 2026-11-16, so every entry from then on says "not
  deployed".

### 2026-11-19, Claude for TK: Remediation org access (restricted DB views, two-org dashboard push)
- **Status:** pushed (f3f85e4), not deployed. Inactive until `grafana.remediation_role` is set and the
  role exists.
- **Changed:** Schema (`db_schema.py`: sets the `remediation` schema aside before the DDL and rebuilds it last,
  in the same transaction), rollups (`rollup_daily_metrics.py`: the `dash_*` swap drops and recreates its
  remediation views), new `remediation_access.py`, `grafana/push_dashboards.py` (pushes the three remediation
  dashboards to a second org with `grafana.remediation_api_token`), e2e, example configs, readme section 9,
  ops guide access table, `knowledge-base/grafana-access.md` (decisions, rollout, nested groups).
  Decisions (TK): one Remediation org; servers, cloud, external and unsensored machines, not managed
  workstations; upgrade Grafana first.
- **Verified:** e2e, all passed, 154 checks. As a restricted role: 72 queries from the three dashboards run;
  identity, alerts, email, action log and `public.assets` are refused; no managed workstation is visible;
  access survives `ensure_schema` and the `dash_*` rebuild. Two-org push tested against a local fake Grafana
  (main got 9 dashboards, remediation 3, each with its own data source).
- **Not verified / open:** a real Grafana with two orgs; prod's Postgres version (the `REVOKE CREATE ON
  SCHEMA public` step matters below 15); Entra setup. The `set_aside` / rebuild runs on every script start:
  cheap (22 views), but it does mean DDL on every collector run while the role is configured.

### 2026-11-19, Claude for TK: Preview dashboard; Grafana access design for remediation teams
- **Status:** pushed (2053c10), not deployed. `deploy.sh` pushes the new dashboard with the rest.
- **Changed:** Grafana dashboards. New `secops-preview` ("SecOps preview: new visuals"): feed health as a
  status-history grid (last run per collector per day; an `EdgeBlocked` error shows as "Blocked by vendor"),
  patch status by team as stacked bars, critical+high opened vs fixed per week as bars, and annotations (Patch
  Tuesday, first data per feed, impact action log) on an open critical+high trend. `dashboard()` takes
  `annotations`. Docs: `knowledge-base/grafana-access.md`, a design for Entra SSO with a separate Remediation
  org and a restricted Postgres login. Nothing is built for that yet; the decisions are listed in the doc.
- **Verified:** every preview query and annotation runs on the demo DB; the team bands sum to each team's
  server count. e2e passes, 234 dashboard queries. The grant list in the doc is generated from the Servers,
  Patch compliance and Vulnerability Management dashboard SQL.
- **Not verified / open:** rendering in Grafana 10.2.6 (status-history and barchart options). The demo has one
  night of collector runs and almost no team data, so the preview only means much on prod. Annotation queries
  aren't covered by e2e (they're dashboard-level, not panels).

### 2026-11-19, Claude for TK: Drill-downs on four more dashboards
- **Status:** pushed (7a2bfcb), not deployed.
- **Changed:** Grafana dashboards, e2e. Generic helpers in `build_dashboards.py` (`drill_links`, `focus_case`,
  `textbox_var`, `site_links`); patch compliance moved onto them, and its "Top missing fixes" counts now drill
  too (new hidden `pfix`). New "behind a number" panels: Servers (OS-version counts, top missing fixes,
  applications), Vulnerability Management (KEV CVE -> hosts; top products -> hosts, live, 30-day last-seen
  window = `reporting.days_last_seen` default), Worklist (sensors not reporting / missing a sensor by site;
  Hadrian triage title -> assets). Overview site scorecard: the site and its counts open the matching dashboard
  filtered to that site. Every drill panel says how to export CSV (Inspect -> Data).
- **Verified:** demo DB: 210 linked cells, 0 mismatches where the cell is a server/host/asset count, and no
  non-zero cell opens an empty list. e2e passes, 229 dashboard queries.
- **Not verified / open:** clicking in Grafana 10.2.6 (as for the patch compliance drill). If prod's
  `reporting.days_last_seen` isn't 30, the product drill's window should follow it. Product drill is live,
  the table is last night's snapshot, so totals can differ by a day's churn.

### 2026-11-19, Claude for TK: Patch compliance drill-down
- **Status:** pushed, not deployed (needs the rebuilt dashboard imported into Grafana).
- **Changed:** Grafana dashboards (`build_dashboards.py`, `secops-patch-compliance.json`), e2e. Counts in
  "By patch group" and "By team" are links that reopen the dashboard with hidden textbox variables
  `pgroup` / `focus` set and the new "Servers behind a number" panel full screen (`viewPanel=<id>`). Each
  focus (`PC_FOCUS`) is the same condition its column counts.
- **Verified:** on the demo DB, every group and team cell's count equals the drill panel's row count
  (32 cells, 0 mismatches; thin data, one group, nothing overdue). e2e passes, 226 dashboard queries.
- **Not verified / open:** clicking in a real Grafana. Prod is 10.2.6 (pre-Scenes), so a numeric
  `viewPanel` should work; `${__data.fields[...]:percentencode}` and `${site:queryparam}` with "All" are
  untested there.

### 2026-11-19, Claude for TK: Sample reports refreshed
- **Status:** pushed, not deployed (samples only, nothing to deploy).
- **Changed:** Report comparison samples. All seven `reports/sample-*` files were regenerated with
  `tests/demo_samples.py` (week 46, as at 19 Nov).
- **Verified:** with the fixed seed, current-state counts are unchanged from the previous samples. Only dates
  and period activity moved: week 46, alerts 32/34, opened findings +199%, critical MTTR 0.9 d (95%),
  impact Day 0 = 5 Oct, with action-log outcomes split into remediated, accepted and done-without-evidence.
  `check_identifiers.py` clean.
- **Not verified / open:** nothing beyond the usual: samples aren't checked against prod.

### 2026-11-18, Claude for TK: Servers report per owner team
- **Status:** pushed, not deployed.
- **Changed:** Servers report (`server_report.py`), publishing (`publish.py`), tests, docs. After the region set,
  the weekly run writes one copy per `FalconGroupingTags/Team-<Name>` tag found on active servers, plus
  `Unassigned` (no Team- tag), to `reports/servers-<date>/owners/<Name>/`. Pages 1-3 and the workbook are cut
  to that team; page 4 (No sensor) stays region-only because unmanaged machines carry no tags. A server with
  two teams is in both. `publish.py` sends them to `Servers/Owners/<Name>/<date> <Name> Servers Report.*`; the
  region copy stays in `Servers/Weekly/`. `--no-teams` gives the old behaviour.
- **Verified:** `tests/run_e2e.py` all passed (new section: folders per tag, two-team server in both, untagged DC
  in Unassigned, region unchanged, publish paths and `--sets servers` dry run). `tests/demo_samples.py` before
  and after on the same day: the region Servers sample differs only in its title ("Whole region" added); no
  numbers moved. Identifier check clean.
- **Not verified / open:** PDF rendering per team (e2e runs `--no-pdf`); run time with many teams on the live
  install (one Chromium render each). Teams come from Falcon tags, so they're as current as the last tag
  sync plus the next `falcon_hosts` pull.

### 2026-11-17, Claude for TK: HEC collectors stop for the day on a CDN block
- **Status:** pushed (c05c95c), not deployed. Includes `tools/hec_probe.py`, the support-ready probe.
- **Changed:** collectors (`checkpoint_hec`, `checkpoint_hec_flow`), tests. An HTML 403 from Check Point's CDN
  (CloudFront in front of the API) now writes `logs/.hec-blocked` (local date + CloudFront request ID).
  The flow collector's other worker threads stop at once, and both collectors skip without calling the API
  for the rest of that local day, so the 10:00 catch-up doesn't add to the block. The next night's run tries
  again and clears the marker. Config `checkpoint_hec.block_marker` overrides the path.
- **Verified:** `tests/run_e2e.py` all passed, with a new edge-block section against the mock (marker
  contents, one request before stopping, flow workers stop, same-day skip sends nothing, next day recovers).
  Identifier check clean.
- **Not verified / open:** the real block page's request ID line is matched from a truncated paste
  (`Request ID: ...`; the `x-amz-cf-id` header is tried first). Skipped runs still record `error`, so the
  catch-up's Pushover alert repeats the reason; intended, but say if it's noise. Request volume (the likely
  cause) is unchanged: throttling `checkpoint_hec_flow` is still to do.

### 2026-11-16, Claude for TK: server patch compliance dashboard
- **Status:** pushed to `main`. Not deployed (owner pulls and deploys on the separate network).
- **Changed:** `lm_devices.team` from new `collectors.logicmonitor.team_property` (normalised "A, B"); tag sync reads
  it, `falcon_tag_sync.team_property` kept as a fallback. Views `server_patch_compliance` (one row per active Falcon
  server: SCCM schedule state from LogicMonitor + status from Falcon's last confirmed patch) and
  `server_patch_compliance_status` (sort order, on-track, judged). New dashboard `secops-patch-compliance`
  (Team variable; tiles, status, by patch group, by team, overdue, behind, top fixes, schedule problems, all
  servers). `dashboard()` takes extra template variables. Ops guide "Reading the numbers" row, readme table.
  Touches: collectors, schema, Grafana (new dashboard only; the others regenerate unchanged), tools, tests, docs.
- **Verified:** `tests/run_e2e.py` all pass (new section: overdue, behind, reboot pending, in window, stale
  deployment, teams combined; dashboard SQL now also runs template-variable queries). Every panel query run against
  real Falcon + LogicMonitor data in a throwaway local database (since dropped); fixed the per-group summary picking
  a stray old window.
- **Not verified / open:** thresholds are **assumed** (35 days = monthly cycle, 45 days = stale deployment), no
  policy yet. Not looked at in a running Grafana. No trend over time yet (needs a nightly snapshot). Falcon's
  "last patch confirmed" as proof of patching in the window is unconfirmed: spot-check a few overdue servers.

### 2026-11-16, Claude for TK: LogicMonitor collector and Falcon server tag sync
- **Status:** pushed to `main` in two commits (impact outcomes; LogicMonitor collector + tag sync). Not deployed:
  the live install is on a separate network; the owner pulls and deploys. Claims on schema, impact and Grafana from
  2026-11-11 released.
- **Changed:** `collectors/logicmonitor.py` (new, read-only, LMv1) -> `lm_devices` + view `lm_device_patch`
  (schema); SCCM update group, tier/subgroup and current deployment window from custom properties; only
  `keep_properties` stored, credential-like names always dropped. `tools/falcon_tag_sync.py` (new): the one vendor
  writer, approved by the owner today and recorded in AGENTS.md rule 4. Adds/removes only `Patch-*` / `Team-*`
  grouping tags on Falcon servers; dry run by default, `--host` pilot, `max_changes` cap, refuses stale
  LogicMonitor data, own API client (Hosts: Write). `FalconClient.patch` added for it. Config/secrets examples,
  readme, commented daily cron line. Touches: collectors, schema, tools, tests, docs.
- **Verified:** `tests/run_e2e.py` all pass on a local Postgres 18 container (new LogicMonitor and tag-sync sections:
  paging, LMv1 signature, site via Falcon twin, timezone, property allowlist, retire, plan/cap/pilot/apply/stale).
  Read-only collector run and tag-sync dry run against the real APIs into a throwaway local database (since dropped):
  join to Falcon servers works for nearly all SCCM-grouped devices; duplicate LogicMonitor entries resolved by the
  merge rule. Identifier check clean.
- **Not verified / open:** the Falcon tag PATCH request shape and allowed tag characters (mock only; pilot with
  `--host` first). SCCM raw times assumed local (`patch_timezone`). `Patch-None` may include SCCM-sync misses, not
  only ungrouped servers.

### 2026-11-16, Claude for TK: impact outcomes now e2e-verified
- **Status:** committed and pushed with the entry below's work (first of the two commits).
- **Verified:** `tests/run_e2e.py` all pass including "impact action log outcomes" (10 cases + report render).
- **Not verified / open:** `tests/demo_samples.py` before/after comparison still not run; the live workbook headings
  note in the 2026-11-11 entry still applies.

### 2026-11-11, Claude for TK: impact report keeps outcomes separate (redesign step 1)
- **Status:** local, uncommitted. Claims held on impact, schema and Grafana until the e2e suite has run.
- **Changed:** one shared rule, `impact_spec.OUTCOME_SQL`, used by both the report and the dashboard. Every action
  is exactly one of: remediated (Done + closed date + ticket ref or evidence), Done with no evidence, risk accepted,
  risk accepted needing review (review date passed, or approver/date missing), or open. Impact report page 1 swaps
  "Resolved" for a factual headline plus Remediated / Risk accepted / Open / Awaiting owner tiles, and its table
  shows the outcome. The Grafana impact stats and table follow the same rule. The action log gains Evidence,
  Approved by, Reason accepted and Review date columns (`db_schema` ADD COLUMN IF NOT EXISTS, template and loader).
  Older workbooks still load. Demo data covers every outcome. Ops guide "Reading the numbers" gains the policy row.
  Touches: impact, schema, Grafana (impact dashboard only), tests.
- **Verified:** syntax; `build_html` rendered from fake actions without a DB (headline and tiles reconcile to
  10 items); template headings; dashboard JSON regenerated (only `secops-impact.json` changed); identifier check clean.
- **Not verified / open:** `tests/run_e2e.py` (new "impact action log outcomes" section: the SQL rule over 10 cases,
  plus a report render) and `tests/demo_samples.py` before/after. Both need Postgres; waiting on a container engine
  on the Mac. On the live action log workbook, the four new column headings have to be added by hand (the
  loader doesn't edit the workbook). Until then, existing accepted risks show as "approver or review date missing"
  and Done items with no ticket ref as "no evidence". That's intended, but expect the first report to show more
  attention items than before.

### 2026-11-11, Codex for TK: report redesign comparison spike
- **Status:** local only; no push or deployment. Comparison artifacts are untracked under `spikes/report-redesign-2026-11-11/`.
- **Changed:** added static alternatives for weekly executive page 1, impact outcomes and scorecard context; no report logic changed. Claimed and released the sample/report area during this spike.
- **Verified:** compared displayed values and dates with committed fictional `reports/sample-*` artifacts; impact statuses reconcile to 10 actions and scorecard retains nine measures. `tools/check_identifiers.py --all` is clean.
- **Not verified / open:** browser/print rendering, snapshot-measure denominators, and whether the proposed layouts answer reviewers' needs. No DB, vendor API, generator or e2e suite used.

### 2026-11-11, Claude for TK: coordination file added
- **Status:** pushed to `main` (docs commit "Agent rules, coordination file and report-writing rules").
- **Changed:** added this file, adapted from the fireground-sim project's version, plus AGENTS.md
  (rules and a brief to hand on, imported by CLAUDE.md) and "Writing reports" in CONTRIBUTING.md.
  Linked from the readme. Docs only, no code touched.
- **Note:** TK does most of the work here. These docs set out what should happen and how things should
  behave; adopt the process as people join, not before.
- **Verified:** identifier check clean.
- **Open:** the sample-report comparison in rule 5 hasn't been tried as a before/after check yet.
  Confirm it's practical the first time a report change needs it.
