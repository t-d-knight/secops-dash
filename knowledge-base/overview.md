# SecOps Dashboard -- Overview

What the SecOps Dashboard is, what it does, how it works, and what it lets a security team do that it
couldn't before. It's written for anyone deciding whether to adopt it or rely on it. For day-to-day use
and how to read the numbers, see the [ops guide](ops-guide.md). For setup and internals, see the
[readme](../readme.md).

## What it is

The SecOps Dashboard is a reporting layer over the security tools an organisation already runs. Each
night it reads data from those tools, works out which site every record belongs to, and keeps it all in
one database. Dashboards, reports and action lists are then built from that one copy.

It doesn't replace any of those tools, and it doesn't change anything in them. It only reads.

## The problem it solves

Each security tool has its own console, its own way of counting and its own view of the estate. On their
own, they can't easily answer the questions management and sites actually ask:

- **Where are we exposed?** Each console shows its own slice: vulnerabilities in one place, missing
  sensors in another, risky accounts, email threats and internet-facing risks in others again. None of
  them split the picture by site.
- **Are we getting better?** Consoles show today's state. Trends, fix rates and before-and-after
  comparisons have to be built by hand, usually in a spreadsheet, and rarely the same way twice.
- **Who needs to do what?** A console can list 10,000 findings. It can't tell a site's ICT contact which
  20 accounts and machines are theirs to fix this month, or tell a server team which of their servers have
  missed a patch cycle.

Without a tool like this, those answers come from manual exports that take hours, go stale quickly and
don't agree with each other.

## What it does

**Brings the data together.** It collects from endpoint protection (sensor coverage, vulnerabilities,
patching, alerts, identity risk, removable media), external attack surface management, email security,
DMARC, server inventory, and optionally Microsoft Entra ID and Azure Log Analytics. Public exploit data
(CISA KEV, FIRST EPSS, NVD) is added so every vulnerability carries the same "is this being exploited"
context, whichever tool found it. The full list of sources is in the
[ops guide](ops-guide.md#what-it-does).

**Maps everything to a site.** Every record (host, account, finding, email) is matched to the site that
owns it, by tag, AD OU, domain, hostname or IP address, and the tool records which rule matched. Anything
it can't place is shown as "Ungrouped", so gaps in the mapping are visible rather than hidden.

**Keeps history.** A snapshot per site is saved every night. That's what makes trend lines,
week-on-week comparisons, Patch Tuesday fix-rate cohorts and a "Day 0 against now" programme impact view
possible.

**Produces outputs for each audience:**

| Output | For | How often |
| --- | --- | --- |
| Grafana dashboards (9) | Cyber team | Live, refreshed nightly |
| Weekly and quarterly security reports (PDF) | Cyber management, executives, each site | Weekly, quarterly |
| Servers report (PDF and Excel) | Infrastructure, applications and database teams | Weekly |
| Action packs (Excel) | Each site's ICT contacts | Monthly |
| Security scorecard (PDF) | Cyber management, each site | Monthly |
| Programme impact report (PDF) | Cyber management, leadership | Monthly or on demand |
| Pushover alerts | The tool's owner (failures) and the cyber team (identity detections digest) | As needed |

Reports are published to each site's file share or SharePoint folder automatically.

## How it does it

```
 Security tools ──► Nightly collection ──► Site mapping ──► Database ──► Nightly snapshots
 (read-only APIs)    (each feed on its own)  (one site per     (current      │
                                              record, and why)  state)       ▼
                                                              Dashboards, reports, action packs, alerts
```

It runs on a single Linux server: Python for collection and reports, PostgreSQL for storage, Grafana OSS
for dashboards, and a headless browser to turn reports into PDFs. Everything runs from cron, with no
manual steps.

The design choices that matter for trusting its output:

- **One database, one set of numbers.** Every dashboard and report reads from the same store, so they
  always agree with each other.
- **One vulnerability model.** Endpoint vulnerabilities and external risks go through the same SLA,
  known-exploited and time-to-fix logic, so they can be compared like for like.
- **Feeds fail on their own.** If one vendor's API is down, the others still collect. Every run is
  recorded, and a feed that has gone stale is flagged on the dashboards and in an alert, rather than
  showing up as a suspiciously quiet week.
- **Reports wait for the data.** Reports and publishing wait for the night's collection to finish, so a
  slow night delays a report rather than sending one built on half the data.
- **It recovers by itself.** A morning catch-up run finishes anything the night run didn't (after a
  reboot or power loss, for example). Long vulnerability pulls are split into small date windows, so a
  dropped connection costs one window, not the whole pull.
- **It says when it's unsure.** Thresholds that haven't been agreed as policy are labelled "assumed" in
  the ops guide. Report text states facts; decisions and asks are left to people.

## What it enables

- **Per-site accountability.** Every site and owner team sees its own position and its own list of
  things to fix, and management can see where remediation is stuck.
- **Measuring change, not just state.** Fix rates, time to fix, Patch Tuesday cohorts and a Day 0
  baseline show whether the security programme is working, not just how many findings are open today.
- **Prioritising by real risk.** Known-exploited (KEV) and likely-to-be-exploited (EPSS) vulnerabilities
  rise to the top, so effort goes to the fixes that matter most, across endpoints and the internet-facing
  estate alike.
- **Finding coverage gaps.** Machines with no sensor, sensors that have stopped reporting, servers with no
  patch group or owner, and records that can't be placed at a site are all listed by name.
- **Evidence for leadership.** Weekly, quarterly and impact reports give executives and the board
  consistent, repeatable figures, with trends and caveats, instead of one-off exports.
- **Less manual reporting.** Regular reporting that would otherwise be built by hand each week and month
  is generated and delivered overnight.
- **Server patch compliance against the schedule.** Servers are checked against their own SCCM patch
  group and window, per owner team, rather than one blanket age threshold.
- **Closing the loop on accepted risk.** Logged actions and accepted risks need evidence, an approver and
  a review date, and show as due for review when that date passes.

## What it needs to run

- One Linux server (VM is fine) with PostgreSQL, Grafana OSS and Python.
- A read-only API credential for each security tool it collects from.
- Somewhere to publish reports: a file share or SharePoint.
- Pushover (or similar) for alerts, and optionally a dead-man's-switch check so a dead server still gets
  noticed.
- Backups: a daily database dump on the server, plus an optional copy to an off-box share.

Setup, per-feed configuration and the schedule are in the [readme](../readme.md).

## How it handles the data

- **Read-only.** Collectors use read-only API scopes and never change anything in a vendor tool. The one
  exception is an optional tag sync that copies server owner and patch-group tags into the endpoint
  console. It touches only those tags, has its own credential, and does nothing unless run with
  `--apply`.
- **Credentials kept apart.** Secrets live in a separate file readable only by the service account, never
  in the code or in git.
- **Audience-based access.** The more named detail an output carries, the narrower its audience. Grafana is
  for the cyber team only, because any Grafana viewer can query all of the data. Region reports carry
  no person names, and site reports mask them. Action packs, which name accounts and USB activity, go only to that site's ICT contacts.
  The full table is in the [ops guide](ops-guide.md#access-and-data-handling).
- **Stays internal.** Data stays on the server, the site folders and internal backup storage.
- **Code kept generic.** The code holds no organisation-specific detail. Sites, domains and credentials
  are set in local, untracked configuration, and a pre-commit check blocks real identifiers from being
  committed.

## Built but not switched on yet

These exist in the code but aren't in day-to-day use yet:

- **A restricted Grafana view for remediation teams** (servers, patching and vulnerabilities only, through
  a database login that can't read anything else). See [grafana-access.md](grafana-access.md).
- **The scheduled Falcon tag sync**, which per-team Servers reports depend on. Until it runs, servers
  without an owner tag are reported as "Unassigned".
- **Microsoft Entra ID and Azure Log Analytics feeds**, which are optional and need their own app
  registration.

## Limits

It isn't real-time (data is as of last night), it isn't a SIEM or incident tool, it doesn't patch, block
or raise tickets, and it only sees what the underlying tools see. The full list, and the caveats to check
before quoting a number, are in the [ops guide](ops-guide.md#what-it-doesnt-do).

## Keeping it running

- Each change to collectors, the schema or dashboards is tested end to end against mock versions of
  every vendor API, and every SQL query in every dashboard is executed as part of that test.
- `deploy.sh` updates the server from git, keeps dated backups of anything it replaces, applies schema
  changes and pushes dashboards.
- Weekly maintenance prunes old data, vacuums the database and rotates logs.
- The [readme](../readme.md#11-hit-by-a-bus-notes) has hand-over notes for whoever maintains it next.
