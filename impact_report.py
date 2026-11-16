#!/usr/bin/env python3
"""
Programme impact report: the Impact dashboard as a two-page PDF for
leadership -- what this programme has found and what has changed since Day 0.

  Page 1  Headline   action log outcomes, the Day 0 vs now scorecard, Patch Tuesday cohorts
  Page 2  Actions    the action log: what was found, how, by whom it's owned, where it's at

Whole region (impact.exclude_sites left out). Monthly from cron, or on demand
before a meeting:

    python3 impact_report.py --config config.yaml       # -> reports/impact-YYYY-MM-DD/Impact.{html,pdf}
"""
import argparse
import datetime as dt
import html
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

import config as config_mod
import exec_report as er
from db import pg_connect
from impact_spec import EXCLUDE_SITES, OUTCOMES, OUTCOME_SQL, SCORECARD

GREEN, RED, ORANGE = er.GOOD, er.SEVERITY_COLOR["critical"], er.SEVERITY_COLOR["high"]
OUTCOME_ORDER = {k: i for i, (k, _, _) in enumerate(OUTCOMES)}
SEV_ORDER = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}


def fetch(cur, exclude: Tuple[str, ...]) -> Dict[str, Any]:
    d: Dict[str, Any] = {}
    cur.execute("SELECT min(snapshot_date), max(snapshot_date) FROM daily_impact_metrics")
    d["d0"], d["d1"] = cur.fetchone()
    cur.execute("""SELECT snapshot_date, metric, sum(value) FROM daily_impact_metrics
                   WHERE snapshot_date IN (%s, %s) AND site_label <> ALL(%s) GROUP BY 1, 2""",
                (d["d0"], d["d1"], list(exclude)))
    vals: Dict[Tuple[dt.date, str], int] = {(r[0], r[1]): int(r[2]) for r in cur.fetchall()}
    rows = []
    for key, label, num, den, good in SCORECARD:
        def val(day):
            n = vals.get((day, num))
            if den is None:
                return n
            dd = vals.get((day, den))
            return None if n is None or not dd else round(100.0 * n / dd, 1)
        b, c = val(d["d0"]), val(d["d1"])
        rows.append((label, b, c, den is not None, good))
    d["scorecard"] = rows
    cur.execute("""SELECT cohort, sum(findings), sum(hosts), sum(expired), sum(closed_7), sum(closed_14), sum(closed_30),
                          sum(closed_60), sum(closed_now), max(days_elapsed)
                   FROM patch_cohort_metrics WHERE site_label <> ALL(%s) GROUP BY 1 ORDER BY 1 DESC LIMIT 6""",
                (list(exclude),))
    d["cohorts"] = cur.fetchall()
    cur.execute(f"""SELECT found, what, source, site_label, severity, action, owner_team, status, closed, ticket_ref,
                           {OUTCOME_SQL} AS outcome, review_date
                    FROM impact_actions""")
    # open first, then the ones needing attention, then settled; worst severity, newest first within each
    d["actions"] = sorted(cur.fetchall(), key=lambda a: (OUTCOME_ORDER.get(a[10], 0), SEV_ORDER.get(a[4], 5),
                                                         -(a[0].toordinal() if a[0] else 0)))
    return d


def _fmt(v: Optional[float], rate: bool) -> str:
    if v is None:
        return "&ndash;"
    return f"{v:.1f}%" if rate else f"{int(v):,}"


def _change(b: Optional[float], c: Optional[float], rate: bool, good: str) -> Tuple[str, str]:
    if b is None or c is None:
        return "&ndash;", er.MUTED
    if c == b:
        return "no change", er.MUTED
    delta = c - b
    txt = (f"{'+' if delta > 0 else '&minus;'}{abs(delta):.1f} pts" if rate
           else f"{'+' if delta > 0 else '&minus;'}{abs(int(delta)):,}")
    better = (delta > 0) == (good == "up")
    return txt, (GREEN if better else RED)


def _pct(n: Optional[int], d: int) -> str:
    return "&ndash;" if n is None or not d else f"{100.0 * n / d:.0f}%"


def header(as_at: dt.date, page: str) -> str:
    return f"""<header>
  <div><h1>Security programme &mdash; impact</h1>
       <div class="period">As at {as_at:%d %b %Y} &middot; Page {page}</div></div>
  <div class="meta">Generated {dt.datetime.now():%Y-%m-%d %H:%M}<br>secops-dashboard</div>
</header>"""


def outcome_summary(acts: List[Tuple]) -> Dict[str, int]:
    """Counts per outcome (each action in exactly one), plus the open subsets the tiles show."""
    n = {k: 0 for k, _, _ in OUTCOMES}
    for a in acts:
        n[a[10]] = n.get(a[10], 0) + 1
    n["total"] = len(acts)
    n["open_hi"] = sum(1 for a in acts if a[10] == "open" and a[4] in ("Critical", "High"))
    n["no_owner"] = sum(1 for a in acts if a[10] == "open" and not (a[6] or "").strip())
    return n


def headline(n: Dict[str, int]) -> str:
    """One factual sentence from the counts -- no judgement words."""
    if not n["total"]:
        return "Nothing has been logged in the action log yet."
    acc = n["accepted"] + n["accepted_review"]
    parts = [f"{n['remediated']:,} remediated", f"{acc:,} accepted as risk", f"{n['open']:,} still open"]
    if n["done_unverified"]:
        parts.append(f"{n['done_unverified']:,} marked Done with no evidence recorded")
    return f"{n['total']:,} issue{'s' if n['total'] != 1 else ''} logged: " + ", ".join(parts[:-1]) + " and " + parts[-1] + "."


def status_cell(a: Tuple, as_at: dt.date) -> Tuple[str, str]:
    """(text, colour) for the action table's outcome column."""
    o, closed, review = a[10], a[8], a[11]
    on = lambda x: f" {x:%d %b}" if x else ""
    if o == "remediated":
        return f"Remediated{on(closed)}", GREEN
    if o == "done_unverified":
        return f"Done{on(closed)}, no evidence recorded", ORANGE
    if o == "accepted":
        return f"Risk accepted, review{on(review)}", er.INK
    if o == "accepted_review":
        if review and review < as_at:
            return f"Risk accepted, review overdue ({review:%d %b})", ORANGE
        return "Risk accepted, approver or review date missing", ORANGE
    return (a[7] or "Open"), (ORANGE if a[7] == "In progress" else RED)


def _status_td(a: Tuple, as_at: dt.date) -> str:
    text, color = status_cell(a, as_at)
    return f'<td style="color:{color}">{html.escape(text)}</td>'


def build_html(d: Dict[str, Any], as_at: dt.date) -> str:
    acts = d["actions"]
    n = outcome_summary(acts)
    acc = n["accepted"] + n["accepted_review"]
    days = (d["d1"] - d["d0"]).days if d["d0"] else 0
    tiles = "".join([
        er.tile("Remediated", f"{n['remediated']:,}", GREEN if n["remediated"] else er.INK,
                f"{_pct(n['remediated'], n['total'])} of {n['total']:,} logged"
                + (f"; {n['done_unverified']:,} more marked Done with no evidence" if n["done_unverified"] else "")),
        er.tile("Risk accepted", f"{acc:,}", ORANGE if n["accepted_review"] else er.INK,
                "exposure remains" + (f"; {n['accepted_review']:,} due for review or missing approver / date"
                                      if n["accepted_review"] else "")),
        er.tile("Open / in progress", f"{n['open']:,}", ORANGE if n["open"] else GREEN,
                f"{n['open_hi']:,} critical or high"),
        er.tile("Awaiting owner", f"{n['no_owner']:,}", ORANGE if n["no_owner"] else er.INK,
                "open items with no owner team"),
    ])
    score_rows = ""
    for label, b, c, rate, good in d["scorecard"]:
        txt, color = _change(b, c, rate, good)
        score_rows += (f'<tr><td>{html.escape(label)}</td><td class="num">{_fmt(b, rate)}</td>'
                       f'<td class="num">{_fmt(c, rate)}</td><td class="num" style="color:{color}">{txt}</td></tr>')
    cohort_rows = "".join(
        f'<tr><td>{c[0]:%b %Y} <span style="color:{er.MUTED}">({c[0]:%d %b})</span></td>'
        f'<td class="num">{int(c[1]):,}</td><td class="num">{int(c[2]):,}</td>'
        + "".join(f'<td class="num">{_pct(x, int(c[1]) - int(c[3]))}</td>' for x in c[4:9])
        + f'<td class="num">{int(c[9])}</td></tr>' for c in d["cohorts"])
    act_rows = "".join(
        f'<tr><td>{a[0]:%d %b} </td><td>{html.escape(a[1] or "")}'
        + (f'<div class="tile-sub">{html.escape(a[5])}</div>' if a[5] else "")
        + f'</td><td>{html.escape(a[3] or "")}</td>'
        f'<td style="color:{er.SEVERITY_COLOR.get((a[4] or "").lower(), er.INK)}">{html.escape(a[4] or "")}</td>'
        f'<td>{html.escape(a[6] or "")}</td>'
        + _status_td(a, as_at) + '</tr>'
        for a in acts if a[0])
    day0 = f"{d['d0']:%d %b %Y}" if d["d0"] else "not yet recorded"
    foot = (f"secops-dashboard. Whole region{', excluding ' + ', '.join(EXCLUDE_SITES) if EXCLUDE_SITES else ''}. "
            f"Day 0 = {day0}, the first day these measures were recorded. Live on the Programme impact dashboard; "
            f"the action log is the Impact action log workbook (Metrics &gt; Impact).")
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Security programme impact -- {as_at}</title>
<style>
{er.page_css()}
  .lede {{ font-size: 13px; color: #334155; margin: 6px 0 10px; line-height: 1.5; }}
</style></head><body>
<div class="page">
{header(as_at, "1 of 2 &mdash; Headline")}
<h2>What it has found</h2>
<p class="lede">{html.escape(headline(n))}</p>
<div class="tiles">{tiles}</div>
<p class="legend-row">Each logged item is counted once. Remediated = marked Done with a closed date and a ticket or
evidence note. Accepted risk is not remediation: the exposure remains, so each acceptance needs an approver and a review
date. Awaiting owner is part of the open count.</p>
<h2>Day 0 ({day0}) vs now &mdash; {days} days</h2>
<table><tr><th>Measure</th><th class="num">Day 0</th><th class="num">Now</th><th class="num">Change</th></tr>
{score_rows}</table>
<p class="legend-row">Green = moved the right way, red = the wrong way. Percentages are of the relevant total (active
servers, active devices, open findings, enabled accounts); "pts" = percentage points.</p>
<h2>Time to patch &mdash; Patch Tuesday cohorts</h2>
<table><tr><th>Patch Tuesday</th><th class="num">Findings</th><th class="num">Devices</th>
<th class="num">Fixed in 7 days</th><th class="num">14 days</th><th class="num">30 days</th><th class="num">60 days</th>
<th class="num">Fixed so far</th><th class="num">Days since</th></tr>
{cohort_rows or '<tr><td colspan="9" class="empty">No cohort yet.</td></tr>'}</table>
<p class="legend-row">Each month's Microsoft findings that appeared in the week after Patch Tuesday, on devices already
being assessed, and the share fixed within each window ("&ndash;" until that many days have passed). Each month is
measured the same way, so improvement shows month on month.</p>
<footer>Page 1 of 2 &mdash; {foot}</footer>
</div>
<div class="page">
{header(as_at, "2 of 2 &mdash; Action log")}
<h2>Found and actioned &mdash; open first</h2>
<table><tr><th>Found</th><th>What was found / action</th><th>Site</th><th>Severity</th><th>Owner</th><th>Outcome</th></tr>
{act_rows or '<tr><td colspan="6" class="empty">Nothing logged yet.</td></tr>'}</table>
<footer>Page 2 of 2 &mdash; {foot}</footer>
</div>
</body></html>"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--out-dir", help="default: reports/impact-YYYY-MM-DD")
    ap.add_argument("--pdf", action=argparse.BooleanOptionalAction, default=None)
    args = ap.parse_args()
    print(f"[{dt.datetime.now().astimezone().isoformat(timespec='seconds')}] impact_report start: "
          f"{' '.join(sys.argv[1:])}", flush=True)
    cfg = config_mod.load_config(args.config)
    rep = cfg.get("reporting") or {}
    exclude = tuple((cfg.get("impact") or {}).get("exclude_sites", EXCLUDE_SITES))
    as_at = dt.date.today()
    out_dir = args.out_dir or os.path.join(cfg.get("_config_dir", "."), "reports", f"impact-{as_at.isoformat()}")
    conn = pg_connect(cfg)
    try:
        d = fetch(conn.cursor(), exclude)
    finally:
        conn.close()
    html_path = os.path.join(out_dir, "Impact.html")
    er.write(html_path, build_html(d, as_at))
    print(f"[impact_report] wrote {html_path}")
    if args.pdf if args.pdf is not None else bool(rep.get("pdf", True)):
        chromium = er.find_chromium(rep.get("chromium_path"))
        if not chromium:
            print("[impact_report] no Chromium found -- PDF skipped", file=sys.stderr)
            return 1
        er.html_to_pdf(chromium, html_path, os.path.join(out_dir, "Impact.pdf"))
        print(f"[impact_report] wrote {os.path.join(out_dir, 'Impact.pdf')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
