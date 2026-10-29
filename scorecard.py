#!/usr/bin/env python3
"""
Monthly security scorecard: nine measures that show whether security is getting
better, one page per site (the region adds a by-site table), filed next to the
action packs in reports/monthly-YYYY-MM/.

Direction only for now: where each measure stood at the start and end of the
month and which way it moved. No targets or red/amber/green until targets are
agreed (a page of red against targets nobody signed off reads as blame), and no
written commentary until the wording has been reviewed with the services.

Where the numbers come from:
  fix-on-time rates  daily_mttr_metrics: endpoint fixes made in the month, pooled
                     (compared with the previous month)
  everything else    daily_impact_metrics: the per-site counts impact.py writes
                     nightly, read at the snapshot nearest each end of the month
Region totals leave out impact.exclude_sites (default TEST), like the impact report.

    python3 scorecard.py --config config.yaml                    # last month, every site + region
    python3 scorecard.py --config config.yaml --site SITE-A
    python3 scorecard.py --config config.yaml --month 2026-10

Writes reports/monthly-YYYY-MM/<site>-scorecard-YYYY-MM.{html,pdf} (YYYY-MM = run
month, the same folder as that month's action packs); publish.py files the PDF as
<Site>/Monthly/YYYY-MM <Site> Security Scorecard.pdf.
"""
import argparse
import datetime as dt
import html
import os
import sys
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

import config as config_mod
import exec_report as er
from impact_spec import EXCLUDE_SITES

REGION_STEADY = 0.5   # percentage points either way that still count as steady
SITE_STEADY = 2.0     # a small service moves a couple of points on a handful of devices or accounts


class Measure(NamedTuple):
    key: str
    group: str
    name: str
    what: str
    kind: str          # fix | ratio | inverse | sensor | count
    args: Tuple        # metric keys (or severity, for fix)
    problem: str = ""  # the count behind a rate, for the change column: "unsupported devices"


GROUPS = [("patching", "Patching and platforms"), ("visibility", "Visibility"),
          ("people", "People and accounts"), ("external", "Internet-facing")]

MEASURES = [
    Measure("crit_fix", "patching", "Critical flaws fixed on time",
            "Share of critical vulnerabilities fixed within the {critical}-day policy, this month against last",
            "fix", ("critical",)),
    Measure("high_fix", "patching", "High flaws fixed on time",
            "Share of high vulnerabilities fixed within the {high}-day policy, this month against last",
            "fix", ("high",)),
    Measure("srv_patched", "patching", "Servers patched in the last 35 days",
            "Active servers with a confirmed patch inside one monthly cycle",
            "ratio", ("servers_patched_35d", "servers_active"), "servers outside a monthly cycle"),
    Measure("supported_os", "patching", "Devices on a supported operating system",
            "Still receiving security updates from the vendor",
            "inverse", ("unsupported_os", "managed_hosts"), "unsupported devices"),
    Measure("sensor", "visibility", "Machines with a working security sensor",
            "In-use machines with CrowdStrike installed and reporting in (workstations within 30 days, servers 7, "
            "domain controllers 2; a machine still logging on with a silent sensor counts as not working)",
            "sensor", ("managed_hosts", "silent_sensors", "missing_sensors"), "machines without a working sensor"),
    Measure("mfa", "people", "People with multi-factor sign-in",
            "Staff accounts protected by a second step beyond the password",
            "inverse", ("people_no_mfa", "people_accounts"), "people without it"),
    Measure("in_use", "people", "Enabled accounts actually in use",
            "The rest are switched on but unused: leavers and old accounts an attacker could take over",
            "inverse", ("stale_accounts", "enabled_accounts"), "stale accounts"),
    Measure("leaked", "people", "Leaked passwords on live accounts",
            "Passwords found in criminal data dumps, for accounts that are still enabled. Target: none",
            "count", ("leaked_creds",)),
    Measure("ext_overdue", "external", "Serious internet-facing risks overdue",
            "Critical or high risks on public systems open past their fix-by date. Target: none",
            "count", ("ext_crit_high_overdue",)),
]


# ------------------------------------------------------------------ data
def _scope(site: Optional[str], exclude: Tuple[str, ...]) -> Tuple[str, Dict[str, Any]]:
    if site:
        return "site_label = %(site)s", {"site": site}
    return "site_label <> ALL(%(exclude)s)", {"exclude": list(exclude)}


def snapshot_days(cur, since: dt.date, until: dt.date) -> Tuple[Optional[dt.date], Optional[dt.date]]:
    """The snapshots that stand for the start and end of the month. The nightly
    run takes them early in the morning, so the one dated the 1st is the state
    at the start and the one dated the 1st of next month the state at the end;
    the latest on or before each. If history doesn't reach back to the start,
    the earliest inside the month (the table's date column says which)."""
    cur.execute("SELECT max(snapshot_date) FROM daily_impact_metrics WHERE snapshot_date <= %s",
                (until + dt.timedelta(days=1),))
    end = cur.fetchone()[0]
    cur.execute("SELECT max(snapshot_date) FROM daily_impact_metrics WHERE snapshot_date <= %s", (since,))
    start = cur.fetchone()[0]
    if start is None:
        cur.execute("SELECT min(snapshot_date) FROM daily_impact_metrics WHERE snapshot_date BETWEEN %s AND %s",
                    (since, until + dt.timedelta(days=1)))
        start = cur.fetchone()[0]
    if end is None or end < since:
        end = None
    if start is not None and end is not None and start >= end:
        start = None
    return start, end


def metrics_at(cur, day: Optional[dt.date], site: Optional[str], exclude: Tuple[str, ...]) -> Dict[str, int]:
    if day is None:
        return {}
    where, params = _scope(site, exclude)
    cur.execute(f"SELECT metric, sum(value) FROM daily_impact_metrics WHERE snapshot_date = %(day)s AND {where} "
                f"GROUP BY 1", {"day": day, **params})
    return {k: int(v) for k, v in cur.fetchall()}


def fix_rate(cur, sev: str, since: dt.date, until: dt.date, site: Optional[str],
             exclude: Tuple[str, ...]) -> Tuple[Optional[float], int]:
    """Endpoint fixes made in the period and the share inside the SLA, pooled."""
    where, params = _scope(site, exclude)
    cur.execute(f"""SELECT COALESCE(sum(fixed_count), 0), COALESCE(sum(sla_compliant_count), 0)
                    FROM daily_mttr_metrics WHERE snapshot_date BETWEEN %(since)s AND %(until)s
                      AND severity = %(sev)s AND {er.ENDPOINT} AND {where}""",
                {"since": since, "until": until, "sev": sev, **params})
    fixed, met = cur.fetchone()
    return (100.0 * met / fixed if fixed else None), int(fixed)


def value(m: Measure, mx: Dict[str, int]) -> Tuple[Optional[float], Optional[int]]:
    """(the measure, the problem count behind it) from one snapshot's metrics."""
    if any(k not in mx for k in m.args):
        return None, None             # not collected on that day (e.g. a metric added later)
    if m.kind == "count":
        return float(mx[m.args[0]]), mx[m.args[0]]
    if m.kind == "sensor":
        managed, stale, missing = (mx[k] for k in m.args)
        if not managed:
            return None, None         # nothing managed here: 0% would just mean "no devices"
        return 100.0 * (managed - stale) / (managed + missing), stale + missing
    num, den = (mx[k] for k in m.args)
    if not den:
        return None, None
    if m.kind == "ratio":
        return 100.0 * num / den, den - num
    return 100.0 * (den - num) / den, num            # inverse: the share without the problem


def direction(m: Measure, start: Optional[float], end: Optional[float], steady: float) -> str:
    if start is None or end is None:
        return "new"
    if m.kind == "count":
        return "down" if end > start else "up" if end < start else ("stuck" if end else "steady")
    return "up" if end - start > steady else "down" if end - start < -steady else "steady"


def build(cur, site: Optional[str], since: dt.date, until: dt.date, exclude: Tuple[str, ...],
          days: Tuple[Optional[dt.date], Optional[dt.date]], steady: float, prev_ok: bool) -> Dict[str, Any]:
    """prev_ok: vulnerability history covers the whole previous month (see main) -- otherwise its
    fix rates are the start-up bulk load, not a month of patching, and aren't compared with."""
    prev_until = since - dt.timedelta(days=1)
    prev_since = prev_until.replace(day=1)
    m0, m1 = metrics_at(cur, days[0], site, exclude), metrics_at(cur, days[1], site, exclude)
    rows = []
    for m in MEASURES:
        if m.kind == "fix":
            (a, fa) = fix_rate(cur, m.args[0], prev_since, prev_until, site, exclude) if prev_ok else (None, 0)
            (b, fb) = fix_rate(cur, m.args[0], since, until, site, exclude)
            change = f"{fb:,} fixes in {since:%B}" if fb else f"no fixes in {since:%B}"
            if not prev_ok:
                change += f" ({prev_since:%B} wasn't fully collected)"
        else:
            (a, ca), (b, cb) = value(m, m0), value(m, m1)
            change = ""
            if ca is not None and cb is not None:
                d = cb - ca
                if m.kind == "count":
                    change = "no change" if not d else f"{abs(d):,} {'more' if d > 0 else 'fewer'}"
                else:
                    change = f"{abs(d):,} {'more' if d > 0 else 'fewer'} {m.problem}" if d else f"no change in {m.problem}"
        rows.append({"m": m, "start": a, "end": b, "change": change, "dir": direction(m, a, b, steady)})
    return {"rows": rows}


# ------------------------------------------------------------------ html
PILL = {"up": ("up", "↗ Improving"), "down": ("down", "↘ Worsening"), "steady": ("steady", "→ Steady"),
        "stuck": ("stuck", "→ No change"), "new": ("new", "• Too early")}


def _fmt(m: Measure, v: Optional[float]) -> str:
    if v is None:
        return "–"
    if m.kind == "count":
        return f"{v:,.0f}"
    return f"{v:.0f}%" if m.kind == "fix" else f"{v:.1f}%"


def _day(d: Optional[dt.date]) -> str:
    return d.strftime("%d %b") if d else "–"


def css() -> str:
    return er.page_css() + f"""
  .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }}
  .sum {{ border: 1px solid {er.BORDER}; border-left-width: 5px; border-radius: 8px; padding: 10px 14px; }}
  .sum-value {{ font-size: 28px; font-weight: 700; line-height: 1.05; }}
  .sum-label {{ font-size: 12px; color: {er.MUTED}; margin-top: 3px; }}
  .lede {{ font-size: 13px; color: #334155; margin: 14px 0 0; line-height: 1.5; }}
  td {{ vertical-align: top; }}
  th.day {{ white-space: nowrap; }}
  td.val {{ font-size: 15px; font-weight: 700; }}
  td.then {{ color: {er.MUTED}; }}
  tr.group td {{ background: #f8fafc; font-size: 10px; text-transform: uppercase; letter-spacing: .04em;
                 color: {er.MUTED}; font-weight: 700; }}
  .m-name {{ font-weight: 600; }}
  .m-what {{ font-size: 11px; color: {er.MUTED}; margin-top: 2px; line-height: 1.35; }}
  .chg {{ font-size: 11px; color: #334155; }}
  .pill {{ display: inline-block; font-size: 11px; font-weight: 600; border-radius: 999px; padding: 2px 9px;
           white-space: nowrap; }}
  .pill.up {{ color: {er.GOOD}; background: #dcfce7; }}
  .pill.down {{ color: #dc2626; background: #fee2e2; }}
  .pill.steady {{ color: #334155; background: #f1f5f9; }}
  .pill.stuck {{ color: #92400e; background: #fef3c7; }}
  .pill.new {{ color: {er.MUTED}; border: 1px dashed {er.BORDER}; }}
  @page wide {{ size: A4 landscape; margin: 12mm; }}
  .page.wide {{ page: wide; }}
  @media screen {{ .page.wide {{ max-width: 1200px; }} }}
  .matrix th.num, .matrix td.num {{ white-space: nowrap; padding-left: 4px; padding-right: 4px; }}
  .matrix .total {{ border-left: 1px solid {er.FAINT}; font-weight: 700; background: #f8fafc; }}
  .matrix td.hot {{ color: #dc2626; font-weight: 700; }}
  .ar {{ font-size: 11px; font-weight: 700; margin-left: 3px; }}
  .ar.up {{ color: {er.GOOD}; }} .ar.down {{ color: #dc2626; }}
  .note {{ font-size: 11px; color: {er.MUTED}; margin-top: 10px; line-height: 1.45; }}
"""


def header(scope: str, label: str, page: str) -> str:
    generated = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    return f"""<header>
  <div><h1>Security Scorecard &mdash; {html.escape(scope)}</h1>
       <div class="period">{html.escape(label)} &middot; {html.escape(page)}</div></div>
  <div class="meta">Generated {generated}<br>secops-dashboard</div>
</header>"""


def page_main(scope: str, label: str, card: Dict[str, Any], days, sla: Dict[str, int], steady: float,
              page: str) -> str:
    n = {k: sum(1 for r in card["rows"] if r["dir"] in ((k, "stuck") if k == "steady" else (k,)))
         for k in ("up", "steady", "down", "new")}
    cards = "".join(
        f'<div class="sum" style="border-left-color:{c}"><div class="sum-value" style="color:{tc}">{n[k]}</div>'
        f'<div class="sum-label">{t}</div></div>'
        for k, c, tc, t in [("up", er.GOOD, er.GOOD, "improving"), ("steady", er.FAINT, "#334155", "steady"),
                            ("down", "#dc2626", "#dc2626", "worsening"),
                            ("new", er.BORDER, er.MUTED, "too early to call")])
    body = []
    for g, gname in GROUPS:
        body.append(f'<tr class="group"><td colspan="5">{gname}</td></tr>')
        for r in (r for r in card["rows"] if r["m"].group == g):
            m = r["m"]
            cls, label_ = PILL[r["dir"]]
            body.append(
                f'<tr><td><div class="m-name">{html.escape(m.name)}</div>'
                f'<div class="m-what">{html.escape(m.what.format(**{k: v or "?" for k, v in sla.items()}))}</div></td>'
                f'<td class="num then">{_fmt(m, r["start"])}</td><td class="num val">{_fmt(m, r["end"])}</td>'
                f'<td class="chg">{html.escape(r["change"])}</td><td><span class="pill {cls}">{label_}</span></td></tr>')
    return f"""<section class="page">
{header(scope, label, page)}
<div class="summary">{cards}</div>
<p class="lede">Nine measures that show whether security is getting better, each a share (so a large service isn't
  penalised for being large) or a count that should be zero. Direction compares the start of the month with the end;
  a move of less than {steady:g} percentage point{'s' if steady != 1 else ''} counts as steady.</p>
<h2>The measures</h2>
<table>
  <thead><tr><th>Measure</th><th class="num day">{_day(days[0])}</th><th class="num day">{_day(days[1])}</th>
    <th>Change</th><th>Direction</th></tr></thead>
  <tbody>
{chr(10).join(body)}
  </tbody>
</table>
<footer>Measured from the security tools' nightly figures: the columns are the snapshots nearest the start and end of
  the month. The two fix-on-time measures compare last month's fixes with this month's instead, once a whole
  previous month has been collected. "Too early" means
  there isn't a figure at both ends yet. Names, devices and accounts behind each number are in this month's action pack.
  No targets yet: these show direction only until targets are agreed.</footer>
</section>"""


def page_matrix(label: str, by_site: List[Tuple[str, Dict[str, Any]]], region: Dict[str, Any]) -> str:
    """Measures down the side, services across (with the region last), on a landscape page."""
    cols = by_site + [("Region", region)]
    heads = "".join(f'<th class="num{" total" if n == "Region" else ""}">{html.escape(n)}</th>' for n, _ in cols)
    body = []
    for g, gname in GROUPS:
        body.append(f'<tr class="group"><td colspan="{len(cols) + 1}">{gname}</td></tr>')
        for i, m in enumerate(MEASURES):
            if m.group != g:
                continue
            cells = []
            for name, card in cols:
                r = card["rows"][i]
                v = r["end"]
                text = "–" if v is None else f"{v:,.0f}" if m.kind == "count" else f"{v:.0f}%"
                arrow = (f'<span class="ar {r["dir"]}">{"↗" if r["dir"] == "up" else "↘"}</span>'
                         if r["dir"] in ("up", "down") and m.kind != "fix" else "")
                cls = "num" + (" hot" if m.kind == "count" and v else "") + (" total" if name == "Region" else "")
                cells.append(f'<td class="{cls}">{text}{arrow}</td>')
            body.append(f'<tr><td class="m-name">{html.escape(m.name)}</td>{"".join(cells)}</tr>')
    return f"""<section class="page wide">
{header("Whole of region", label, "By health service")}
<p class="lede" style="margin-top:0">Each measure at the end of the month for every health service, in configuration
  order, not ranked. Arrows show a move of more than {SITE_STEADY:g} points over the month (small services swing on a
  handful of devices or accounts, so the bar is higher than the region's {REGION_STEADY:g}). Red counts should be zero.</p>
<h2>The measures by service</h2>
<table class="matrix">
  <thead><tr><th>Measure</th>{heads}</tr></thead>
  <tbody>
{chr(10).join(body)}
  </tbody>
</table>
<footer>For regional leadership: each service's own scorecard shows only its own figures. Region totals leave out test
  sites. Fix-on-time is the month's fixes, pooled. Shares are rounded to whole percentages here; the service's own
  scorecard has one decimal place.</footer>
</section>"""


def document(title: str, pages: List[str]) -> str:
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>
{css()}
</style></head>
<body>
{chr(10).join(pages)}
</body></html>
"""


# ------------------------------------------------------------------ main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--site", help="one site (its label); default is every site plus the region")
    ap.add_argument("--month", help="YYYY-MM to measure (default: last calendar month)")
    ap.add_argument("--out-dir", help="default: reports/monthly-YYYY-MM (run month, next to the action packs)")
    ap.add_argument("--pdf", action=argparse.BooleanOptionalAction, default=None,
                    help="also write a PDF next to each HTML (default: reporting.pdf in config, else on)")
    args = ap.parse_args()
    print(f"[{dt.datetime.now().astimezone().isoformat(timespec='seconds')}] scorecard start: "
          f"{' '.join(sys.argv[1:])}", flush=True)

    cfg = config_mod.load_config(args.config)
    rep = cfg.get("reporting") or {}
    labels = [s["label"] for s in cfg.get("sites", [])] + [cfg.get("ungrouped_label", "Ungrouped")]
    if args.site and args.site not in labels:
        ap.error(f"unknown site {args.site!r}; configured: {', '.join(labels)}")
    exclude = tuple((cfg.get("impact") or {}).get("exclude_sites", EXCLUDE_SITES))
    today = dt.date.today()
    if args.month:
        since = dt.date.fromisoformat(args.month + "-01")
        until = (since.replace(day=28) + dt.timedelta(days=4)).replace(day=1) - dt.timedelta(days=1)
    else:
        p = er.month_period(today)
        since, until = p.since, p.until
    label = since.strftime("%B %Y")
    out_dir = args.out_dir or os.path.join("reports", f"monthly-{today:%Y-%m}")
    make_pdf = args.pdf if args.pdf is not None else bool(rep.get("pdf", True))
    chromium = er.find_chromium(rep.get("chromium_path")) if make_pdf else None
    if make_pdf and not chromium:
        print("[scorecard] no Chromium found -- PDFs skipped", file=sys.stderr)

    from db import pg_connect
    conn = pg_connect(cfg)
    try:
        cur = conn.cursor()
        days = snapshot_days(cur, since, until)
        er.BULK_DATES[:] = sorted(dt.date.fromisoformat(str(d)) for d in rep.get("vuln_bulk_load_dates") or [])
        vulns_from = er.history_start(cur)["vulns"]
        prev_ok = vulns_from is not None and vulns_from < (since - dt.timedelta(days=1)).replace(day=1)
        cur.execute("SELECT severity, threshold_days FROM sla_policy")
        sla = dict(cur.fetchall())
        jobs: List[Optional[str]] = [args.site] if args.site else [None] + labels
        region = build(cur, None, since, until, exclude, days, REGION_STEADY, prev_ok) if None in jobs else None
        by_site = [(s, build(cur, s, since, until, exclude, days, SITE_STEADY, prev_ok))
                   for s in labels if s not in exclude] if None in jobs else []
        written = 0
        for site in jobs:
            if site is None:
                pages = [page_main("Whole of region", label, region, days, sla, REGION_STEADY, "Region"),
                         page_matrix(label, by_site, region)]
            else:
                card = next((c for s, c in by_site if s == site), None) or \
                    build(cur, site, since, until, exclude, days, SITE_STEADY, prev_ok)
                pages = [page_main(site, label, card, days, sla, SITE_STEADY, "Monthly")]
            scope = site or "Whole of region"
            path = os.path.join(out_dir, f"{er.safe_name(site or 'region')}-scorecard-{today:%Y-%m}.html")
            er.write(path, document(f"Security Scorecard -- {scope} -- {label}", pages))
            if chromium:
                er.html_to_pdf(chromium, path, path[:-5] + ".pdf")
            written += 1
        print(f"[scorecard] {label}: wrote {written} scorecard(s) to {out_dir} "
              f"(snapshots {_day(days[0])} -> {_day(days[1])})")
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
