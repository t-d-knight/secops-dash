#!/usr/bin/env python3
"""
Falcon alerts (endpoint, identity and any other Falcon detection product)
-> security_alerts (source='falcon'). Incremental on updated_timestamp so
status changes (new -> in_progress -> closed) flow through and MTTA/MTTC
can be measured.
"""
from typing import Any, Dict

from collectors.base import RunContext, as_list, norm_severity, parse_ts, upsert_rows
from collectors.falcon_client import FalconClient
from collectors.falcon_hosts import host_site_map
from site_resolver import SiteContext, email_domain

NAME = "falcon_alerts"


def _status(s: Any) -> str:
    s = (s or "").lower()
    return {"new": "new", "in_progress": "in_progress", "reopened": "in_progress",
            "closed": "closed", "true_positive": "closed", "false_positive": "closed",
            "ignored": "closed"}.get(s, s or "new")


def run(ctx: RunContext) -> Dict[str, Any]:
    fc = FalconClient(ctx.cfg, ctx.ccfg)
    hosts = host_site_map(ctx.conn)
    since = ctx.since(NAME, default_days=int(ctx.ccfg.get("lookback_days", 30)))
    fql = f"updated_timestamp:>'{since.strftime('%Y-%m-%dT%H:%M:%SZ')}'"
    if ctx.ccfg.get("filter"):
        fql += "+" + ctx.ccfg["filter"]

    ids = list(fc.iter_offset_ids("/alerts/queries/alerts/v2", {"filter": fql}, limit=1000))
    ctx.log(f"{len(ids)} alerts updated since {since:%Y-%m-%d %H:%M}")

    rows = []
    for i in range(0, len(ids), 1000):
        j = fc.post("/alerts/entities/alerts/v2", {"composite_ids": ids[i:i + 1000]})
        for a in j.get("resources") or []:
            dev = a.get("device") or {}
            aid = dev.get("device_id") or a.get("agent_id")
            user = a.get("user_principal") or a.get("user_name")
            if aid and aid in hosts:
                label, key, by, _ = hosts[aid]
            else:
                m = ctx.resolver.resolve(SiteContext(
                    falcon_tags=as_list(dev.get("tags")),
                    falcon_groups=fc.group_labels(as_list(dev.get("groups"))),
                    ous=as_list(dev.get("ou")),
                    ad_sites=as_list(dev.get("site_name")),
                    ad_domains=as_list(dev.get("machine_domain")) + as_list(a.get("source_account_domain")),
                    hostnames=as_list(dev.get("hostname")),
                    ips=as_list(dev.get("local_ip")),
                    email_domains=as_list(email_domain(user)),
                ))
                label, key, by = m.label, m.key, m.matched_by
            sev_name = a.get("severity_name")
            if not sev_name:
                sc = a.get("severity") or 0
                sev_name = "critical" if sc >= 80 else "high" if sc >= 60 else "medium" if sc >= 40 else "low" if sc >= 20 else "info"
            status = _status(a.get("status"))
            rows.append({
                "source": "falcon",
                "alert_id": a.get("composite_id") or a.get("id"),
                "created_at": parse_ts(a.get("created_timestamp")),
                "updated_at": parse_ts(a.get("updated_timestamp")),
                "severity": norm_severity(sev_name, "low"),
                "severity_score": a.get("severity"),
                "status": status,
                # The verdict lives in `resolution`, a field separate from
                # `status` -- status is pure workflow state (new/in_progress/
                # closed/reopened), resolution is the SOC's triage outcome
                # (true_positive/false_positive/ignored), set independently
                # when the alert is closed. Confirmed against real API
                # responses: status was 'closed' with no distinguishing
                # value while resolution correctly varied per alert -- an
                # earlier version of this code wrongly assumed the verdict
                # lived in `status` itself.
                "disposition": (a.get("resolution") or "").strip().lower() or None,
                "name": a.get("display_name") or a.get("name"),
                "tactic": a.get("tactic"),
                "technique": a.get("technique"),
                "product": a.get("product"),
                "hostname": dev.get("hostname") or a.get("hostname"),
                "user_name": user,
                "source_asset_id": aid,
                "site_label": label,
                "site_tag": key,
                "site_matched_by": by,
                "link": a.get("falcon_host_link"),
            })
    n = upsert_rows(ctx.conn, "security_alerts", rows, ["source", "alert_id"])
    # closed_at = first time we saw it closed (later comments on a closed
    # alert bump updated_at, which mustn't move the close time).
    cur = ctx.conn.cursor()
    cur.execute("UPDATE security_alerts SET closed_at = updated_at "
                "WHERE source = 'falcon' AND status = 'closed' AND closed_at IS NULL")
    cur.execute("UPDATE security_alerts SET closed_at = NULL "
                "WHERE source = 'falcon' AND status <> 'closed' AND closed_at IS NOT NULL")
    ctx.conn.commit()
    return {"rows": n}
