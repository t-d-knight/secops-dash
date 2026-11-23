# SecOps Dashboard -- Operations Guide

For cyber staff and cyber management: what the tool does, what it doesn't, what it produces, who each output is for, and how to read it. Setup and internals are in the [readme](../readme.md).

## What it is and who it's for

The SecOps Dashboard puts the organisation's security data in one place, split by site, and turns it into dashboards, reports and action lists. It reads from the security tools already in use each night; it doesn't replace any of them.

It answers three questions the vendor consoles can't answer on their own:

- **Where are we exposed, per site?** Vulnerabilities, missing sensors, risky accounts, email threats and internet-facing risks, all mapped to the site that owns them.
- **Is it getting better or worse?** Daily snapshots give trend lines, fix rates and Patch Tuesday cohorts, not just today's count.
- **What should someone do next?** Ranked lists of the fixes, hosts and accounts that matter most, for the people who can act on them.

| Audience | What they use | How often |
| --- | --- | --- |
| Cyber team (analysts, engineers) | Grafana dashboards, the Worklist, Pushover alerts | Daily |
| Cyber management | Weekly region report, quarterly reports, programme impact report | Weekly, monthly, quarterly |
| Site ICT contacts | Their site's weekly report and monthly action pack | Weekly, monthly |
| Infrastructure, applications and database teams | Weekly Servers report (PDF and Excel) | Weekly |
| Executives and the board | Quarterly reports, with a cover note written by cyber management | Quarterly |

Grafana is for the cyber team. Remediation teams can be given a separate, restricted view (servers, patching and vulnerabilities only) once it's rolled out: see [grafana-access.md](grafana-access.md). Everyone else gets reports, delivered to their site's file share or SharePoint folder.

## What it does

Every night it pulls from each tool's API, works out which site every record belongs to, and stores it in one database. Each feed is pulled on its own, so one vendor's API being down doesn't stop the others.

```
 Security tools ──► Nightly collection ──► Database ──┬──► Grafana dashboards (cyber team, live)
 (Falcon, Hadrian,   (01:00, each feed     (current     ├──► Reports via file share / SharePoint
  Check Point,        on its own; every     state +      │    (managers, sites, server teams)
  DMARC, KEV/EPSS/    record tagged to      daily        └──► Pushover alerts
  NVD)                a site)               snapshots)        (failures, identity digest)
```

Everything downstream reads from the one database, so the dashboards and reports always agree with each other.

| Source | What it brings in |
| --- | --- |
| CrowdStrike Falcon: hosts and Discover | Sensor coverage, sensors not reporting (silent past their type's limit, or broken on a machine still in use), devices found on the network with no sensor |
| Falcon Exposure Management (Spotlight) | Endpoint vulnerabilities, with severity, fix, and how long each has been open |
| Falcon patch status and system insights | Last confirmed patch, pending reboots, uptime, disk, CPU and memory for servers |
| Falcon alerts | Endpoint and identity detections, open and unassigned, time to close |
| Falcon Identity Protection | Risky, stale, weak-password and no-MFA accounts |
| Falcon removable media | Files written to USB per person, PC and drive; USB scans and what they find |
| Hadrian | Internet-facing assets and external risks |
| Check Point Harmony Email | Phishing, malware and DLP events, per recipient site; how much mail each site receives and what the Microsoft and Check Point filters did with it |
| LogicMonitor | Server inventory, owner team and SCCM patch schedule, used for server patch compliance and per-team Servers reports |
| DMARC reports | Whether mail from our domains passes SPF and DKIM, and who's failing |
| Microsoft Entra ID (optional) | Risky users, risk detections, MFA registration |
| CISA KEV, FIRST EPSS, NVD | Which vulnerabilities are known to be exploited, how likely exploitation is, and plain-English descriptions |

The vulnerability feeds (Falcon endpoint and Hadrian external) share one model. SLA, known-exploited (KEV), exploit likelihood (EPSS) and time-to-fix work the same way for both.

After collection, a nightly rollup saves a snapshot per site. Those snapshots are what the trend lines, week-on-week comparisons and Patch Tuesday cohorts are built from.

## What it doesn't do

It reports on security; it doesn't act on anything. Know these limits before quoting a number from it.

- **It isn't real-time.** Data is as of last night's run. For anything happening now, use the vendor console (Falcon, Hadrian, Check Point).
- **It isn't a SIEM or an incident tool.** Alerts are counted and listed here so nothing is missed, but triage and response happen in Falcon.
- **It doesn't patch, fix or block anything.** It shows what needs doing and who should do it. Remediation stays with the teams that own the systems.
- **It doesn't raise tickets.** Action packs and reports go to people; logging them in the service desk is still a human step.
- **It only sees what the tools see.** A device with no Falcon sensor has no vulnerabilities on record and isn't patch-tracked. The "No sensor" lists exist to close that gap, not to measure what's behind it.
- **It doesn't replace the vendor consoles.** When a number here and a console disagree, the console is the source of truth for that moment. Check the dashboard's data freshness first.
- **It doesn't give sites their own dashboards.** Grafana OSS can't restrict data per viewer, so sites get reports instead.

## What you get

The tool produces three kinds of output: live dashboards for the cyber team, scheduled reports for everyone else, and alerts when something needs a look.

**Reports**

| Report | For | When | Format | What's in it |
| --- | --- | --- | --- | --- |
| Weekly security report | Cyber team, cyber management, each site | Mondays | PDF, region plus one per site | Six pages: endpoint vulnerabilities, external attack surface, email, alerts and identity, estate, removable media, with trends against last week |
| Quarterly security report | Cyber management, executives | 1 Jan, Apr, Jul, Oct | PDF, region plus one per site | The same six pages over the last quarter |
| Servers report | Infrastructure, applications and database teams; each server owner team | Mondays | PDF plus Excel workbook: region, plus one per owner team and one for servers with no owner (`Servers/Owners/<Team>/`) | Patching and reboots, longest-unpatched servers, domain controllers, top missing fixes, disk, and (region only) servers with no sensor |
| Action pack | Each site's ICT contacts | 1st of the month | Excel, one per site | Named lists to work through: stale and weak-password accounts, no MFA, sensors not reporting, missing sensors, external risks, USB activity |
| Security scorecard | Cyber management, each site | 1st of the month | PDF, one page per site; the region copy adds a by-site table | Nine measures, start against end of last month. Direction only; no targets have been set yet |
| Programme impact report | Cyber management, leadership | 1st of the month, or on demand | PDF | What has changed since the programme started: Day 0 against now, Patch Tuesday fix rates, the action log |

Reports are published to each site's folder the morning they're made.

**Grafana dashboards (cyber team)**

| Dashboard | Use it for |
| --- | --- |
| SecOps Overview | Site scorecard across every feed, trends, data freshness |
| Cyber Team Worklist | The daily to-do list: feed health, detections awaiting triage, stale and unmanaged endpoints, Hadrian triage |
| Vulnerability Management | SLA, known-exploited vulnerabilities, worst devices, top fixes, time to fix |
| Endpoint & Identity | Sensor coverage, alerts, USB activity, risky accounts |
| Email & External Exposure | Email threats, DMARC, internet-facing assets and risks |
| Servers | The live version of the Servers report |
| Server patch compliance | Servers against their SCCM patch schedule, per owner team: on track, overdue, missed cycles. Click a count to list the servers behind it |
| Programme impact | The live version of the impact report |
| SecOps preview | Trial panels before they move into the dashboards above. Don't quote numbers from it |

On most dashboards, many count panels can be clicked to list the hosts, accounts or findings behind it. Every dashboard filters by site, and the dashboards link to each other, keeping the site you picked.

**Alerts (Pushover)**

- The nightly run failing or running too long, a report failing, or a feed going stale.
- A feed that still connects but has brought in nothing new for a few days (for example DMARC reports no longer arriving), which usually means the source has stopped sending.
- A nightly identity digest. Falcon's identity detections may only show in a separate (child CID) console, so this digest is how they get seen.

## How to use it

Start each day on the Worklist, each week with the reports, and each quarter with the trends.

**Cyber team: daily**

1. Open the **Cyber Team Worklist**. Check feed health first: a feed marked stale means today's numbers are missing something.
2. Work the **detections awaiting triage** queue, including identity detections from the nightly digest.
3. Look at new **stale or unmanaged endpoints**. A sensor that's stopped checking in, or a real machine with no sensor, is a gap in coverage.
4. Triage new **Hadrian** external risks. Confirmed ones count towards the external SLA.

**Cyber team: weekly**

1. Read Monday's **region report** before it's discussed. Check any big week-on-week jump against the caveats in the next section.
2. Use **Vulnerability Management** to pick the week's push: the top fixes by hosts affected, and anything known-exploited.
3. Follow up with sites and teams on items that have sat in their reports for more than a cycle.

**Cyber management**

- **Weekly:** the region report gives posture at a glance. Lead with rates and direction (fixed within SLA, Patch Tuesday cohorts, new versus fixed), not the raw open count.
- **Monthly:** the programme impact report shows what the programme has changed since Day 0, for leadership updates.
- **Quarterly:** the quarterly reports are the base for board and executive papers. The numbers come from the tool; the cover note, top risks and asks are written by a person.
- **Escalation:** use the per-site and per-team breakdowns to show where remediation is stuck and why. Missing ownership or capacity is a management issue, not a reporting one.

**Site ICT contacts**

- **Weekly report:** where your site stands and which way it's moving.
- **Monthly action pack:** the named list to work through. Each tab says what to do with its rows.
- Questions about a number, or a row that's wrong (a decommissioned PC, a known exception): tell the cyber team, so it's fixed at the source rather than ignored each month.

**Infrastructure, applications and database teams**

- **Servers report**, Mondays. Each owner team also gets its own copy under `Servers/Owners/<Team>/`, cut to the servers carrying its Falcon `Team-` tag (from LogicMonitor); servers with no owner are in `Servers/Owners/Unassigned/`. A server with two owner teams is in both. In the region copy, use the workbook's filters (Site, OU, product) to cut it to your own servers. The "No sensor" page lists servers to bring under Falcon, or to record why they can't be.

## Reading the numbers

The open vulnerability count is the least useful number in the tool. Read rates and direction instead, and check these points before quoting anything.

| What you see | What's behind it | Read it as |
| --- | --- | --- |
| Open vulnerabilities jump sharply | Each Patch Tuesday adds hundreds of new findings per Windows host within a week, and more hosts being assessed adds findings without anything new being released. | Look at fixes within 7, 14 and 30 days (Patch Tuesday cohorts), and new versus fixed. "Opened" already leaves out hosts that were newly assessed. |
| SLA compliance looks low | A tight SLA (for example critical in 2 days) is hard to meet where workstations patch on a monthly cycle. | State the gap once rather than showing a permanently red tile; compare asset classes, where internet-facing fixes are often fastest. |
| Ages and time-to-fix look odd | Every finding's age starts when its feed was first enabled. | Treat age and time-to-fix as provisional for the first few months after a feed goes live. |
| A device in Discover with no sensor | Much of Discover's unmanaged list isn't a missing endpoint: duplicates of managed hosts, service accounts, appliances, disabled or stale AD accounts. | Only the validated classes (domain controllers, servers and workstations with active AD accounts, cloud instances) are real machines to fix. Network-only devices are counted until identified. |
| A big "Ungrouped" site | Records the tool couldn't match to a site by tag, OU, domain, hostname or IP. | A mapping gap to fix, not a site. |
| External risks marked "unverified" | Hadrian's "Potential" risks, not yet confirmed. | Shown separately. Only confirmed risks count towards SLA. |
| Fewer alerts than the Falcon console | Informational alerts are left out of counts. | Counts are low severity and up. |
| Impact action log outcomes | Each logged item is counted once: remediated, Done with no evidence, risk accepted, or open. **Policy:** "Done" counts as remediated only with a closed date plus a ticket ref or evidence note. An accepted risk needs an approver and a review date, and shows as due for review once that date passes or if either is missing. | Accepted risk is not remediation: the exposure remains. To move an item out of "no evidence" or "due for review", fill in the Evidence, Approved by, Reason accepted and Review date columns of the action log workbook. |
| Server patch compliance: on track or not | The schedule (SCCM patch group, window, deadline) and team come from LogicMonitor; "patched" is Falcon's last confirmed patch date. Patched means a patch confirmed after the group's current window opened. **Assumed** (no agreed policy yet): with no current window (no patch group, not in LogicMonitor, window not started), 35 days without a patch is a missed monthly cycle; a window that opened 45+ days ago is a stale deployment and is judged on the 35-day rule. | Servers still inside their window, or with no patch data, aren't judged. A server several teams manage counts under each team. "No patch group" may mean patched some other way: confirm before calling it unpatched. |
| USB history is short | Falcon only keeps the raw events about 7 days. | History starts when the USB feed was enabled and builds nightly. |

If a dashboard shows a feed as stale, its numbers are from the last good pull. Check data freshness on the SecOps Overview before acting on a surprising figure.

## Schedule and when things go wrong

Data is collected overnight and is normally complete by mid-morning. Reports go out on Monday mornings and on the 1st of the month. Times are the server's local time; the full schedule is in [crontab.example](../crontab.example).

| When | What runs |
| --- | --- |
| 01:00 daily | Collection from every source, then the nightly rollups |
| 03:30 Mondays | Weekly security reports, region and every site |
| 03:45 Mondays | Servers report |
| 03:30, 1 Jan, Apr, Jul, Oct | Quarterly security reports |
| 04:00, 04:15 and 04:30, 1st of the month | Action packs, security scorecards, programme impact report |
| 07:30 daily | New reports published to the file share |
| 13:00 Mondays | Publish again, in case a slow night meant the 07:30 run went before the weekly reports |
| 09:00 daily | Database backup, with an optional off-site copy |
| 10:00 daily | Catch-up: finishes anything the night run didn't (never a full vulnerability pull) |
| 10:00 Sundays | Database maintenance |

Reports and publishing wait for the night's collection to finish, so a slow night delays them rather than sending half-collected data. With `open_pull: incremental`, the full vulnerability pull runs once a week (Saturday by default) and other nights only pull what changed. The full pull goes in small date windows, so when Falcon drops it part-way only one window is re-pulled. If it still can't finish, that night falls back to pulling only what changed, nothing is marked as gone, and you get a 'partial' alert; the next night tries the full pull again.

**If something looks wrong**

- **A number looks off:** check data freshness on the SecOps Overview. A stale feed explains most surprises.
- **A report didn't arrive:** reports wait for collection, so a late night run means late reports. A failed report raises an alert.
- **A feed is stale for more than a day:** usually an expired API key, a changed permission or a vendor outage. The alert says which feed.

All failures alert the tool's owner by Pushover (`notify:` in config). What triggers an alert is listed in the [readme](../readme.md#notifications).

## While the owner is away

The tool runs itself: collection, reports, publishing, backups and maintenance are all on cron. Nobody else operates or fixes it. If something breaks, it waits for the owner, and alerts still go only to the owner.

Keep using the outputs as normal: the Worklist and dashboards each day, the reports when they arrive.

- **Check data freshness before quoting a number.** If a feed has gone stale, its figures are from the last good pull. Say so if you share that week's report, and use the vendor console for anything current.
- **A report that doesn't arrive just doesn't arrive.** It gets regenerated when the owner is back.
- **Don't touch the server, its config, the crontab or the Grafana dashboards**, and don't deploy. A half-fix is harder to unpick than a gap of a couple of weeks.

## Access and data handling

The more named detail an output carries, the narrower its audience. Forward reports only to the people listed here.

| Output | Contains | Who may see it |
| --- | --- | --- |
| Grafana dashboards (SecOps org) | Everything, including names, hosts and accounts | Cyber team only. Any viewer can query all of the data, which is why sites don't get access. |
| Grafana dashboards (Remediation org) | Servers, cloud and external assets, unsensored machines, their patching and vulnerabilities | Infrastructure, applications and database teams. Its database login can't read identity, USB, email, alerts or managed workstations. |
| Region weekly and quarterly reports | Counts and trends; no person names | Cyber team, cyber management, IT leadership, executives |
| Site weekly and quarterly reports | That site's counts; email addresses and people's names masked | That site's ICT contacts and management |
| Action packs | Full account names, people, hosts, USB activity | That site's ICT contacts only |
| Servers report | Server names, OUs, last logged-on accounts | Infrastructure, applications and database teams |

- Everything stays on internal systems: the dashboard server, the site folders, and backups on internal storage.
- USB activity names people. Treat action pack USB tabs as you would an HR matter: check with the site before acting on one person's activity.
- The code is kept separate from the data. Nothing that identifies the organisation's internal systems or people goes into this repository (see [CONTRIBUTING.md](../CONTRIBUTING.md)).
