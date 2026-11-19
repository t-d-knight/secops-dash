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
