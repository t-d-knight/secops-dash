#!/usr/bin/env python3
"""
Servers report for the infrastructure, applications and database teams: the
Servers dashboard as a PDF (four pages) plus an Excel workbook with the full
server list and one tab per view, for teams that don't use Grafana.

  Page 1  Patching    headline tiles, by site, how long since servers were patched
  Page 2  Servers     the longest-unpatched servers, and every domain controller
  Page 3  What to fix top missing fixes, applications, database / middleware, disk
  Page 4  No sensor   DCs, servers and cloud instances Falcon Discover found with
                      no sensor (validated classes only -- discovery_classes.py)

Point-in-time ("as at" the run date), whole region with a Site column. Patch
dates are Falcon's "last patch confirmed" (falcon_patches); vulnerability
counts come from the nightly rollup (dash_asset_risk). Falcon's patch tracking
has a start date: a server with nothing confirmed since then shows the days
since that date, marked "+" -- it may be longer.

    python3 server_report.py --config config.yaml            # -> reports/servers-YYYY-MM-DD/Servers.{html,pdf,xlsx}
    python3 server_report.py --config config.yaml --out-dir /tmp/x --no-pdf

Writes into reports/ (gitignored): host names, OUs and last-login accounts.
"""
import argparse
import datetime as dt
import html
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

from openpyxl import Workbook

import config as config_mod
import discovery_classes as dc
import exec_report as er
from action_pack import HEADER_FILL, HEADER_FONT, write_sheet
from db import pg_connect

SRV = ("FROM assets a LEFT JOIN host_patch_status p ON p.aid = a.source_asset_id "
       "LEFT JOIN host_insights i ON i.aid = a.source_asset_id "
       "LEFT JOIN dash_asset_risk r ON r.source = 'falcon_spotlight' AND r.source_asset_id = a.source_asset_id "
       "WHERE a.source = 'falcon' AND NOT a.retired AND a.product_type IN ('server','domain_controller') "
       "AND a.last_seen > now() - interval '7 days'")
DAYS_PATCHED = "floor(EXTRACT(EPOCH FROM now() - p.last_patch_confirmed) / 86400)::int"
DAYS_UP = "floor(EXTRACT(EPOCH FROM now() - a.last_reboot) / 86400)::int"
SRV_FINDINGS = ("FROM vuln_findings vf JOIN assets a ON a.source = 'falcon' AND a.source_asset_id = vf.source_asset_id "
                "AND a.product_type IN ('server','domain_controller') AND NOT a.retired "
                "AND a.last_seen > now() - interval '7 days' "
                "WHERE vf.source = 'falcon_spotlight' AND vf.state IN ('OPEN','REOPENED') "
                "AND vf.severity IN ('critical','high')")
DB_FAMILIES = ("Microsoft SQL & Data Platform", "PostgreSQL", "MySQL / MariaDB", "Oracle Database",
               "Java Runtime (JRE/JDK)", "Apache Tomcat", "Microsoft .NET Core / ASP.NET",
               "Java / Middleware - Log4j", "Apache HTTP Server", "Microsoft Sharepoint")
# Discover classes that are confirmed machines in the infrastructure team's
# patch: enabled AD accounts that logged on in the last 60 days (DC / server
# OS), or instances the cloud provider reports. vmware_nic / network_device are
# only seen on the wire and may be appliances -- counted, not listed.
NO_SENSOR = ("domain_controller_no_sensor", "server_no_sensor", "cloud_no_sensor")
RED, ORANGE = er.SEVERITY_COLOR["critical"], er.SEVERITY_COLOR["high"]


def qall(cur, sql: str, **params) -> List[Tuple]:
    cur.execute(sql, params)
    return cur.fetchall()


def fetch(cur) -> Dict[str, Any]:
    d: Dict[str, Any] = {}
    d["floor"] = qall(cur, "SELECT min(last_patch_confirmed)::date FROM host_patch_status")[0][0]
    d["tiles"] = qall(cur, f"""
        SELECT count(*), count(*) FILTER (WHERE p.last_patch_confirmed < now() - interval '35 days'),
               count(*) FILTER (WHERE p.last_patch_confirmed < now() - interval '90 days'),
               count(*) FILTER (WHERE p.reboot_required),
               count(*) FILTER (WHERE a.last_reboot < now() - interval '35 days'),
               count(*) FILTER (WHERE i.os_is_eol),
               count(*) FILTER (WHERE r.open_kev_count > 0),
               count(*) FILTER (WHERE p.last_patch_confirmed IS NULL)
        {SRV}""")[0]
    d["by_site"] = qall(cur, f"""
        SELECT a.site_label, count(*),
               count(*) FILTER (WHERE p.last_patch_confirmed < now() - interval '35 days'),
               count(*) FILTER (WHERE p.last_patch_confirmed < now() - interval '90 days'),
               count(*) FILTER (WHERE p.reboot_required),
               count(*) FILTER (WHERE a.last_reboot < now() - interval '35 days'),
               count(*) FILTER (WHERE i.os_is_eol),
               count(*) FILTER (WHERE r.open_kev_count > 0)
        {SRV} GROUP BY 1 ORDER BY 3 DESC, 2 DESC""")
    d["bands"] = qall(cur, f"""
        SELECT band, count(*) FROM (
          SELECT CASE WHEN p.last_patch_confirmed IS NULL THEN 6
                      WHEN {DAYS_PATCHED} <= 7 THEN 1 WHEN {DAYS_PATCHED} <= 35 THEN 2
                      WHEN {DAYS_PATCHED} <= 90 THEN 3 WHEN {DAYS_PATCHED} <= 180 THEN 4 ELSE 5 END AS band
          {SRV}) x GROUP BY 1 ORDER BY 1""")
    servers_cols = f"""
        a.hostname, a.site_label, a.os_version, a.kernel_version, {DAYS_PATCHED}, p.last_patch_confirmed::date,
        p.reboot_required, p.pending_patches, {DAYS_UP}, a.last_reboot::date,
        r.open_critical, r.open_high, r.open_kev_count, i.os_is_eol,
        CASE WHEN a.product_type = 'domain_controller' THEN 'Domain controller' ELSE 'Server' END,
        i.form_factor, a.model, i.disk_used_pct, i.disk_free_gb, i.cpu_avg_pct, i.mem_avg_pct,
        array_to_string(a.ous, ' / '), a.last_login_user"""
    d["servers"] = qall(cur, f"SELECT {servers_cols} {SRV} "
                             "ORDER BY p.last_patch_confirmed NULLS FIRST, r.open_kev_count DESC NULLS LAST")
    d["dcs"] = [s for s in d["servers"] if s[14] == "Domain controller"]
    d["by_os"] = qall(cur, f"""
        SELECT a.os_version, count(*),
               percentile_disc(0.5) WITHIN GROUP (ORDER BY {DAYS_PATCHED}),
               count(*) FILTER (WHERE p.last_patch_confirmed < now() - interval '35 days'),
               count(*) FILTER (WHERE p.last_patch_confirmed < now() - interval '90 days'),
               count(*) FILTER (WHERE p.reboot_required),
               count(*) FILTER (WHERE a.last_reboot < now() - interval '35 days'),
               count(*) FILTER (WHERE p.last_patch_confirmed IS NULL)
        {SRV} GROUP BY 1 ORDER BY 2 DESC""")
    d["fixes"] = qall(cur, f"""
        SELECT vf.fix_title, max(vf.product_family), count(DISTINCT vf.source_asset_id),
               count(*), count(*) FILTER (WHERE vf.severity = 'critical')
        {SRV_FINDINGS} AND vf.fix_title IS NOT NULL GROUP BY 1 ORDER BY 3 DESC, 4 DESC LIMIT 50""")
    d["apps"] = qall(cur, f"""
        SELECT vf.product_family, count(DISTINCT vf.source_asset_id),
               count(*) FILTER (WHERE vf.severity = 'critical'), count(*) FILTER (WHERE vf.severity = 'high')
        {SRV_FINDINGS} AND vf.product_family NOT LIKE 'Microsoft Windows OS%%'
        GROUP BY 1 ORDER BY 2 DESC LIMIT 40""")
    d["db"] = qall(cur, f"""
        SELECT x.hostname, x.site_label, x.products, x.crit, x.high,
               floor(EXTRACT(EPOCH FROM now() - p.last_patch_confirmed) / 86400)::int
        FROM (SELECT a.source_asset_id, a.hostname, a.site_label,
                     string_agg(DISTINCT vf.product_family, ', ') AS products,
                     count(*) FILTER (WHERE vf.severity = 'critical') AS crit,
                     count(*) FILTER (WHERE vf.severity = 'high') AS high
              {SRV_FINDINGS} AND vf.product_family = ANY(%(fam)s) GROUP BY 1, 2, 3) x
        LEFT JOIN host_patch_status p ON p.aid = x.source_asset_id
        ORDER BY x.crit DESC, x.high DESC""", fam=list(DB_FAMILIES))
    d["disk"] = [s for s in d["servers"] if s[17] is not None and s[17] >= 85]
    d["disk"].sort(key=lambda s: -s[17])
    d["no_sensor"] = qall(cur, f"""
        SELECT COALESCE(hostname, '(no hostname)'), site_label, {dc.sql_case()}, os_version,
               last_seen::date, ad_created::date, array_to_string(ips, ', '), description,
               array_to_string(ous, ' / '), domain, {dc.sql_case(part=1)}
        FROM assets WHERE source = 'falcon_unmanaged' AND NOT retired AND discovery_class IN {dc.sql_in(NO_SENSOR)}
        ORDER BY CASE discovery_class WHEN 'domain_controller_no_sensor' THEN 1 WHEN 'server_no_sensor' THEN 2
                                      ELSE 3 END, site_label, hostname""")
    d["no_sensor_by_site"] = qall(cur, f"""
        SELECT site_label, count(*) FILTER (WHERE discovery_class = 'domain_controller_no_sensor'),
               count(*) FILTER (WHERE discovery_class = 'server_no_sensor'),
               count(*) FILTER (WHERE discovery_class = 'cloud_no_sensor'), count(*)
        FROM assets WHERE source = 'falcon_unmanaged' AND NOT retired AND discovery_class IN {dc.sql_in(NO_SENSOR)}
        GROUP BY 1 ORDER BY 5 DESC, 1""")
    d["unverified"] = qall(cur, """
        SELECT count(*) FILTER (WHERE discovery_class = 'vmware_nic'),
               count(*) FILTER (WHERE discovery_class = 'network_device')
        FROM assets WHERE source = 'falcon_unmanaged' AND NOT retired""")[0]
    return d


# -------------------------------------------------------------------- PDF
def _days(n: Optional[int], last: Optional[dt.date], floor: Optional[dt.date]) -> str:
    """'406+' when the last confirmed patch is at (or within a few days of) the
    start of Falcon's tracking: nothing confirmed since, so maybe longer."""
    if n is None:
        return "&ndash;"
    return f"{n:,}+" if floor and last and (last - floor).days <= 7 else f"{n:,}"


def _cell_days(n: Optional[int], last=None, floor=None) -> str:
    color = RED if (n or 0) > 90 else (ORANGE if (n or 0) > 35 else er.INK)
    return f'<td class="num" style="color:{color}">{_days(n, last, floor)}</td>'


def _num(v: Any, red_from: Optional[float] = None) -> str:
    if v is None:
        return '<td class="num">&ndash;</td>'
    style = f' style="color:{RED}"' if red_from is not None and v >= red_from else ""
    return f'<td class="num"{style}>{int(v):,}</td>'


def header(as_at: dt.date, page: str) -> str:
    return f"""<header>
  <div><h1>Servers &mdash; patching and health</h1>
       <div class="period">As at {as_at:%d %b %Y} &middot; Page {page}</div></div>
  <div class="meta">Generated {dt.datetime.now():%Y-%m-%d %H:%M}<br>secops-dashboard</div>
</header>"""


def build_html(d: Dict[str, Any], as_at: dt.date) -> str:
    n, p35, p90, reboot, up35, eol, kev_srv, unknown = d["tiles"]
    floor = d["floor"]
    pct = lambda x: er.pct(x, n)
    tiles = "".join([
        er.tile("Active servers", f"{n:,}", er.INK, "servers and domain controllers seen in the last 7 days"),
        er.tile("Not patched in 35+ days", f"{p35:,}", ORANGE if p35 else er.GOOD,
                f"{pct(p35)} of servers -- missed at least one monthly cycle"),
        er.tile("Not patched in 90+ days", f"{p90:,}", RED if p90 else er.GOOD,
                f"{pct(p90)} of servers -- three or more cycles"),
        er.tile("Reboot pending", f"{reboot:,}", ORANGE if reboot else er.GOOD,
                "patched, but the update isn't applied until a restart"),
        er.tile("Up 35+ days", f"{up35:,}", ORANGE if up35 else er.GOOD,
                "not restarted for a month: cumulative updates can't have applied"),
        er.tile("With known-exploited (KEV) vulns", f"{kev_srv:,}", RED if kev_srv else er.GOOD,
                f"{eol:,} on an unsupported OS"),
    ])
    site_rows = "".join(
        f'<tr><td>{html.escape(s)}</td>{_num(t)}{_num(a35, 1)}{_num(a90, 1)}{_num(rb)}{_num(u35)}{_num(e, 1)}{_num(k, 1)}</tr>'
        for s, t, a35, a90, rb, u35, e, k in d["by_site"])
    band_names = {1: "Within 7 days", 2: "8-35 days", 3: "36-90 days", 4: "91-180 days",
                  5: "Over 180 days", 6: "Never / unknown"}
    band_rows = "".join(f'<tr><td>{band_names[b]}</td>{_num(c)}<td class="num">{pct(c)}</td></tr>'
                        for b, c in d["bands"])
    os_rows = "".join(
        f'<tr><td>{html.escape(o or "unknown")}</td>{_num(t)}{_cell_days(med)}{_num(a35, 1)}{_num(a90, 1)}</tr>'
        for o, t, med, a35, a90, rb, u35, nd in d["by_os"])
    floor_note = (f"Falcon's patch tracking starts {floor:%d %b %Y}: a server with nothing confirmed since then "
                  f"shows the days since that date with a <b>+</b> -- it may be longer." if floor else "")

    worst = sorted([s for s in d["servers"] if s[4] is not None and s[4] > 35], key=lambda s: -s[4])[:40]
    no_data = [s for s in d["servers"] if s[4] is None]
    no_data_note = (f"{len(no_data)} server{'s' if len(no_data) != 1 else ''} have no patch data from Falcon "
                    f"({', '.join(sorted({s[2] or 'unknown OS' for s in no_data}))}) -- Falcon's patch status covers "
                    f"Windows; listed in the workbook." if no_data else "")
    dc_attention = [s for s in d["dcs"] if s[13] or s[4] is None or s[4] > 35]
    worst_rows = "".join(
        f'<tr><td>{html.escape(s[0] or "")}</td><td>{html.escape(s[1])}</td><td>{html.escape(s[2] or "")}</td>'
        f'{_cell_days(s[4], s[5], floor)}{_cell_days(s[8])}{_num(s[10])}{_num(s[12], 1)}</tr>' for s in worst)
    dc_rows = "".join(
        f'<tr><td>{html.escape(s[0] or "")}</td><td>{html.escape(s[1])}</td><td>{html.escape(s[2] or "")}'
        f'{" <b style=color:" + RED + ">(unsupported)</b>" if s[13] else ""}</td><td>{html.escape(s[3] or "")}</td>'
        f'{_cell_days(s[4], s[5], floor)}<td>{"yes" if s[6] else ""}</td>{_cell_days(s[8])}{_num(s[10])}{_num(s[12], 1)}</tr>'
        for s in dc_attention)
    fix_rows = "".join(
        f'<tr><td>{html.escape((f or "")[:110])}</td><td>{html.escape(fam or "")}</td>{_num(srv)}{_num(tot)}{_num(c)}</tr>'
        for f, fam, srv, tot, c in d["fixes"][:15])
    app_rows = "".join(f'<tr><td>{html.escape(f or "")}</td>{_num(s)}{_num(c)}{_num(h)}</tr>'
                       for f, s, c, h in d["apps"][:12])
    db_rows = "".join(
        f'<tr><td>{html.escape(h or "")}</td><td>{html.escape(s)}</td><td>{html.escape((pr or "")[:70])}</td>'
        f'{_num(c)}{_num(hi)}{_cell_days(days)}</tr>' for h, s, pr, c, hi, days in d["db"][:15])
    disk_rows = "".join(
        f'<tr><td>{html.escape(s[0] or "")}</td><td>{html.escape(s[1])}</td>{_num(s[17], 95)}'
        f'<td class="num">{s[18] if s[18] is not None else "&ndash;"}</td></tr>' for s in d["disk"][:15])
    ns = d["no_sensor"]
    ns_dc = sum(1 for r in ns if r[2] == dc.DISCOVERY_CLASSES["domain_controller_no_sensor"][0])
    ns_srv = sum(1 for r in ns if r[2] == dc.DISCOVERY_CLASSES["server_no_sensor"][0])
    ns_tiles = "".join([
        er.tile("Domain controllers, no sensor", f"{ns_dc:,}", RED if ns_dc else er.GOOD,
                "a DC without a sensor is a blind spot over every account"),
        er.tile("Windows servers, no sensor", f"{ns_srv:,}", ORANGE if ns_srv else er.GOOD,
                "enabled AD account, logged on in the last 60 days"),
        er.tile("Cloud instances, no sensor", f"{len(ns) - ns_dc - ns_srv:,}",
                ORANGE if len(ns) - ns_dc - ns_srv else er.GOOD, "reported by the cloud provider"),
    ])
    ns_site_rows = "".join(f'<tr><td>{html.escape(s)}</td>{_num(a, 1)}{_num(b)}{_num(c)}{_num(t)}</tr>'
                           for s, a, b, c, t in d["no_sensor_by_site"])
    ns_rows = "".join(
        f'<tr><td>{html.escape(r[0])}</td><td>{html.escape(r[1])}</td><td>{html.escape(r[2])}</td>'
        f'<td>{html.escape(r[3] or "")}</td><td>{r[4] or "&ndash;"}</td><td>{html.escape((r[7] or "")[:60])}</td></tr>'
        for r in ns[:40])
    vm_nic, net_dev = d["unverified"]
    ns_note = (f"Showing {min(len(ns), 40)} of {len(ns)}; the full list (IPs, OU, AD created) is in the workbook. "
               if len(ns) > 40 else "")
    ns_note += (f"Not listed: {vm_nic:,} VMware network interfaces and {net_dev:,} other devices seen only on the "
                "network -- possibly VMs without a sensor, possibly appliances; on the Endpoint &amp; Identity "
                "dashboard until identified.")
    foot = ("secops-dashboard. Whole region, servers and domain controllers with a sensor seen in the last 7 days. "
            "Last patch = Falcon's last patch confirmed (Exposure Management &gt; Patches); uptime from the "
            "sensor's last reboot; vulnerabilities from the last nightly rollup. Full lists in the Excel workbook "
            "with this report, and live on the Servers dashboard.")

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Servers -- patching and health -- {as_at}</title>
<style>
{er.page_css()}
</style></head><body>
<div class="page">
{header(as_at, "1 of 4 &mdash; Patching")}
<h2>Headline</h2>
<div class="tiles tiles-3">{tiles}</div>
<h2>By site</h2>
<table><tr><th>Site</th><th class="num">Servers</th><th class="num">Not patched 35+ d</th><th class="num">90+ d</th>
<th class="num">Reboot pending</th><th class="num">Up 35+ d</th><th class="num">Unsupported OS</th>
<th class="num">With KEV</th></tr>{site_rows}</table>
<div class="row"><div class="col">
<h2>How long since servers were patched</h2>
<table><tr><th>Last confirmed patch</th><th class="num">Servers</th><th class="num">Share</th></tr>{band_rows}</table>
<p class="legend-row">{floor_note}</p>
</div><div class="col">
<h2>By OS version</h2>
<table><tr><th>OS</th><th class="num">Servers</th><th class="num">Median days since patched</th>
<th class="num">35+ d</th><th class="num">90+ d</th></tr>{os_rows}</table>
</div></div>
<footer>Page 1 of 4 &mdash; {foot}</footer>
</div>

<div class="page">
{header(as_at, "2 of 4 &mdash; Servers")}
<h2>Longest without a patch &mdash; top {len(worst)}</h2>
<table><tr><th>Server</th><th>Site</th><th>OS</th><th class="num">Days since patched</th>
<th class="num">Days up</th><th class="num">Crit</th><th class="num">KEV</th></tr>
{worst_rows or '<tr><td colspan="7" class="empty">Every server patched in the last 35 days.</td></tr>'}</table>
<p class="legend-row">{no_data_note}</p>
<h2>Domain controllers needing attention &mdash; {len(dc_attention)} of {len(d["dcs"])}</h2>
<table><tr><th>DC</th><th>Site</th><th>OS</th><th>Build</th><th class="num">Days since patched</th>
<th>Reboot pending</th><th class="num">Days up</th><th class="num">Crit</th><th class="num">KEV</th></tr>
{dc_rows or '<tr><td colspan="9" class="empty">Every DC patched in the last 35 days and on a supported OS.</td></tr>'}</table>
<p class="legend-row">Not patched in 35+ days or on an unsupported OS; every DC is in the workbook. {floor_note}</p>
<footer>Page 2 of 4 &mdash; {foot}</footer>
</div>

<div class="page">
{header(as_at, "3 of 4 &mdash; What to fix")}
<h2>Top missing fixes on servers</h2>
<table><tr><th>Fix</th><th>Product</th><th class="num">Servers</th><th class="num">Crit/high findings</th>
<th class="num">Critical</th></tr>{fix_rows}</table>
<div class="row"><div class="col">
<h2>Applications on servers (not the OS)</h2>
<table><tr><th>Product family</th><th class="num">Servers</th><th class="num">Crit</th><th class="num">High</th></tr>{app_rows}</table>
</div><div class="col">
<h2>Disk 85%+ full</h2>
<table><tr><th>Server</th><th>Site</th><th class="num">Disk %</th><th class="num">Free GB</th></tr>
{disk_rows or '<tr><td colspan="4" class="empty">No server disk over 85%.</td></tr>'}</table>
</div></div>
<h2>Database and middleware servers &mdash; most critical first</h2>
<table><tr><th>Server</th><th>Site</th><th>Products with crit/high</th><th class="num">Crit</th><th class="num">High</th>
<th class="num">Days since patched</th></tr>{db_rows}</table>
<footer>Page 3 of 4 &mdash; {foot}</footer>
</div>

<div class="page">
{header(as_at, "4 of 4 &mdash; No sensor")}
<h2>Servers with no Falcon sensor</h2>
<div class="tiles tiles-3">{ns_tiles}</div>
<p class="legend-row">Found by Falcon Discover and confirmed as real, in-use machines: not patch-tracked, not
vulnerability-scanned and not protected, so they appear nowhere else in this report. Install a sensor, or record
why it can't have one (vendor-supported system, being decommissioned).</p>
<h2>By site</h2>
<table><tr><th>Site</th><th class="num">DCs</th><th class="num">Servers</th><th class="num">Cloud</th>
<th class="num">Total</th></tr>
{ns_site_rows or '<tr><td colspan="5" class="empty">Every known server has a sensor.</td></tr>'}</table>
<h2>Machines &mdash; domain controllers first</h2>
<table><tr><th>Name</th><th>Site</th><th>Class</th><th>OS</th><th>Last AD logon</th><th>AD description</th></tr>
{ns_rows or '<tr><td colspan="6" class="empty">None.</td></tr>'}</table>
<p class="legend-row">{ns_note}</p>
<footer>Page 4 of 4 &mdash; secops-dashboard. Falcon Discover's unmanaged assets, classified nightly
(DCs and servers: enabled AD computer accounts with a server OS and a logon in the last 60 days; a name already
on a managed host is excluded). Full list in the Excel workbook.</footer>
</div>
</body></html>"""


# ------------------------------------------------------------------ Excel
def build_workbook(d: Dict[str, Any], as_at: dt.date) -> Workbook:
    wb = Workbook()
    ws = wb.active
    ws.title = "Summary"
    n, p35, p90, reboot, up35, eol, kev_srv, unknown = d["tiles"]
    ws.append([f"Servers -- patching and health, as at {as_at:%d %b %Y}"])
    ws["A1"].font = HEADER_FONT
    ws["A1"].fill = HEADER_FILL
    for row in (("Active servers (seen in 7 days)", n), ("Not patched in 35+ days", p35),
                ("Not patched in 90+ days", p90), ("Reboot pending", reboot), ("Up 35+ days", up35),
                ("Unsupported OS", eol), ("With known-exploited (KEV) vulnerabilities", kev_srv),
                ("No patch date from Falcon", unknown),
                ("Servers / DCs / cloud instances with no Falcon sensor", len(d["no_sensor"]))):
        ws.append(list(row))
    ws.append([])
    if d["floor"]:
        ws.append([f"Falcon's patch tracking starts {d['floor']:%d %b %Y}: a last-patch date equal to it means "
                   "nothing confirmed since then (it may be longer)."])
    ws.append(["Last patch = Falcon's last patch confirmed (Exposure Management > Patches). Vulnerability counts "
               "from the last nightly rollup. Every tab has filters: cut to your team's servers by Site, OU or "
               "Products."])
    ws.column_dimensions["A"].width = 48

    server_cols = ["Server", "Site", "OS", "Build", "Days since patched", "Last patch confirmed", "Reboot pending",
                   "Pending patches", "Days up", "Last reboot", "Critical", "High", "KEV", "Unsupported OS", "Type",
                   "Form factor", "Model", "Disk used %", "Disk free GB", "CPU avg %", "Memory avg %", "OU",
                   "Last login"]
    write_sheet(wb, "All servers", server_cols, d["servers"])
    write_sheet(wb, "Not patched 35+ days", server_cols, [s for s in d["servers"] if s[4] is None or s[4] > 35])
    write_sheet(wb, "Reboot and uptime", server_cols,
                sorted([s for s in d["servers"] if s[6] or (s[8] or 0) > 35], key=lambda s: -(s[8] or 0)))
    write_sheet(wb, "Domain controllers", server_cols, d["dcs"])
    write_sheet(wb, "By OS version", ["OS", "Servers", "Median days since patched", "Not patched 35+ days",
                                      "Not patched 90+ days", "Reboot pending", "Up 35+ days", "No patch data"],
                d["by_os"])
    write_sheet(wb, "Top missing fixes", ["Fix", "Product", "Servers", "Crit/high findings", "Critical"], d["fixes"])
    write_sheet(wb, "Applications", ["Product family", "Servers", "Critical", "High"], d["apps"])
    write_sheet(wb, "Database & middleware", ["Server", "Site", "Products with crit/high", "Critical", "High",
                                              "Days since patched"], d["db"])
    write_sheet(wb, "Disk 85%+ full", server_cols, d["disk"])
    write_sheet(wb, "No sensor", ["Name", "Site", "Class", "OS", "Last AD logon", "AD account created", "IPs",
                                  "AD description", "OU", "Domain", "What to do"], d["no_sensor"])
    return wb


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--out-dir", help="default: reports/servers-YYYY-MM-DD")
    ap.add_argument("--pdf", action=argparse.BooleanOptionalAction, default=None,
                    help="also write a PDF (default: reporting.pdf in config, else on)")
    args = ap.parse_args()
    print(f"[{dt.datetime.now().astimezone().isoformat(timespec='seconds')}] server_report start: "
          f"{' '.join(sys.argv[1:])}", flush=True)

    cfg = config_mod.load_config(args.config)
    rep = cfg.get("reporting") or {}
    as_at = dt.date.today()
    out_dir = args.out_dir or os.path.join(cfg.get("_config_dir", "."), "reports", f"servers-{as_at.isoformat()}")
    conn = pg_connect(cfg)
    try:
        d = fetch(conn.cursor())
    finally:
        conn.close()

    html_path = os.path.join(out_dir, "Servers.html")
    er.write(html_path, build_html(d, as_at))
    print(f"[server_report] wrote {html_path} ({d['tiles'][0]:,} servers)")
    xlsx_path = os.path.join(out_dir, "Servers.xlsx")
    build_workbook(d, as_at).save(xlsx_path)
    print(f"[server_report] wrote {xlsx_path}")
    if args.pdf if args.pdf is not None else bool(rep.get("pdf", True)):
        chromium = er.find_chromium(rep.get("chromium_path"))
        if not chromium:
            print("[server_report] no Chromium found -- PDF skipped", file=sys.stderr)
            return 1
        er.html_to_pdf(chromium, html_path, os.path.join(out_dir, "Servers.pdf"))
        print(f"[server_report] wrote {os.path.join(out_dir, 'Servers.pdf')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
