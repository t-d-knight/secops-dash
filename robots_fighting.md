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
| Grafana dashboards (`grafana/`) | unclaimed | | |
| Collectors (`collectors/<name>.py`, one row each when claimed) | unclaimed | | |
| LogicMonitor collector (planned) | unclaimed | | Waiting on an API token; patch-tier mapping drafted |
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
