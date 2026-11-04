#!/usr/bin/env python3
"""
Microsoft Entra ID (via Microsoft Graph) -> entra_risky_users,
entra_risk_detections, entra_mfa_registration.

Each feed is independent and optional, because they need different
licences/permissions (application permissions, admin-consented):
  risky_users      IdentityRiskyUser.Read.All     (Entra ID P2)
  risk_detections  IdentityRiskEvent.Read.All     (Entra ID P2)
  mfa_registration AuditLog.Read.All              (Entra ID P1+)
  signins          AuditLog.Read.All              (Entra ID P1+)   opt-in
A feed that 403s is recorded and skipped; the others still run.

signins reads interactive sign-ins straight from Graph (no Log Analytics
workspace needed) and keeps only daily counts per site in azure_log_metrics,
under the same query names the Log Analytics collector uses (signins,
legacy_auth, mfa_failures, risky_signins, ca_failures), so the sign-in
panels fill from either source. Use one source, not both. Graph keeps 30
days of sign-ins, so history only builds from the nightly runs.

Supports several tenants (`tenants:` list) since the estate spans multiple
organisations. Site = the UPN's domain.
"""
import datetime as dt
from typing import Any, Dict, List

from collectors.base import RunContext, TextArray, parse_ts, upsert_rows
from collectors.msgraph import AzureApp, graph_iter
from site_resolver import SiteContext, email_domain

NAME = "entra"
SCOPE = "https://graph.microsoft.com/.default"

# feed -> (Graph path, params or fn(since_iso) -> params). Shared with tools/entra_probe.py.
FEED_QUERIES = {
    "risky_users": ("/identityProtection/riskyUsers",
                    {"$filter": "riskState eq 'atRisk' or riskState eq 'confirmedCompromised'"}),
    "risk_detections": ("/identityProtection/riskDetections",
                        lambda since: {"$filter": f"detectedDateTime ge {since}"}),
    "mfa_registration": ("/reports/authenticationMethods/userRegistrationDetails", None),
    "signins": ("/auditLogs/signIns",
                lambda since: {"$filter": f"createdDateTime ge {since}", "$top": 999}),
}
FEED_ROLES = {
    "risky_users": "IdentityRiskyUser.Read.All",
    "risk_detections": "IdentityRiskEvent.Read.All",
    "mfa_registration": "AuditLog.Read.All",
    "signins": "AuditLog.Read.All",
}
DEFAULT_FEEDS = ["risky_users", "risk_detections", "mfa_registration"]

# Same list as the legacy_auth KQL example (Graph's clientAppUsed values).
LEGACY_CLIENTS = {"Exchange ActiveSync", "IMAP4", "POP3", "Authenticated SMTP", "Other clients",
                  "Exchange Web Services", "MAPI Over HTTP", "Offline Address Book",
                  "Outlook Anywhere (RPC over HTTP)", "AutoDiscover", "Exchange Online PowerShell"}
SIGNIN_QUERIES = ["signins", "legacy_auth", "mfa_failures", "risky_signins", "ca_failures"]


def _iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _site(ctx: RunContext, upn: str):
    return ctx.resolver.resolve(SiteContext(email_domains=[email_domain(upn)] if email_domain(upn) else []))


def _risky_users(ctx, app, tname) -> int:
    rows = []
    path, params = FEED_QUERIES["risky_users"]
    for u in graph_iter(app, path, params):
        upn = u.get("userPrincipalName") or ""
        m = _site(ctx, upn)
        rows.append({
            "tenant": tname, "user_id": u.get("id"), "upn": upn, "display_name": u.get("userDisplayName"),
            "risk_level": u.get("riskLevel"), "risk_state": u.get("riskState"),
            "risk_detail": u.get("riskDetail"),
            "risk_last_updated": parse_ts(u.get("riskLastUpdatedDateTime")),
            "site_label": m.label, "site_tag": m.key, "site_matched_by": m.matched_by,
            "collected_at": ctx.run_started,
        })
    cur = ctx.conn.cursor()
    # current-state list: whoever isn't at risk any more drops off
    cur.execute("DELETE FROM entra_risky_users WHERE tenant = %s", (tname,))
    n = upsert_rows(ctx.conn, "entra_risky_users", rows, ["tenant", "user_id"])
    ctx.conn.commit()
    return n


def _risk_detections(ctx, app, tname) -> int:
    # Watermark from this tenant's own rows, not the collector's last ok/partial
    # run: a partial run where this feed failed must not move the window on.
    floor = ctx.run_started - dt.timedelta(days=int(ctx.ccfg.get("lookback_days", 30)))
    since = floor
    if not ctx.full:
        cur = ctx.conn.cursor()
        cur.execute("SELECT max(detected_at) FROM entra_risk_detections WHERE tenant = %s", (tname,))
        last = cur.fetchone()[0]
        if last:
            since = max(floor, last - dt.timedelta(days=2))  # detections can land a day+ late
    path, params = FEED_QUERIES["risk_detections"]
    rows = []
    for d in graph_iter(app, path, params(_iso(since))):
        upn = d.get("userPrincipalName") or ""
        m = _site(ctx, upn)
        loc = d.get("location") or {}
        rows.append({
            "tenant": tname, "detection_id": d.get("id"), "upn": upn,
            "risk_event_type": d.get("riskEventType"), "risk_level": d.get("riskLevel"),
            "risk_state": d.get("riskState"), "detected_at": parse_ts(d.get("detectedDateTime")),
            "ip_address": d.get("ipAddress"),
            "country": loc.get("countryOrRegion"), "city": loc.get("city"),
            "site_label": m.label, "site_tag": m.key, "site_matched_by": m.matched_by,
        })
    return upsert_rows(ctx.conn, "entra_risk_detections", rows, ["tenant", "detection_id"])


def _mfa_registration(ctx, app, tname) -> int:
    rows = []
    path, params = FEED_QUERIES["mfa_registration"]
    for u in graph_iter(app, path, params):
        if ctx.ccfg.get("members_only", True) and (u.get("userType") or "member").lower() != "member":
            continue
        upn = u.get("userPrincipalName") or ""
        m = _site(ctx, upn)
        rows.append({
            "tenant": tname, "user_id": u.get("id"), "upn": upn,
            "is_admin": u.get("isAdmin"), "is_mfa_capable": u.get("isMfaCapable"),
            "is_mfa_registered": u.get("isMfaRegistered"),
            "is_passwordless_capable": u.get("isPasswordlessCapable"),
            "methods": TextArray([str(x) for x in (u.get("methodsRegistered") or [])]),
            "site_label": m.label, "site_tag": m.key, "site_matched_by": m.matched_by,
            "collected_at": ctx.run_started,
        })
    cur = ctx.conn.cursor()
    cur.execute("DELETE FROM entra_mfa_registration WHERE tenant = %s", (tname,))
    n = upsert_rows(ctx.conn, "entra_mfa_registration", rows, ["tenant", "user_id"])
    ctx.conn.commit()
    return n


def _signin_dims(si: Dict[str, Any]):
    """(query_name, dimension) pairs one sign-in counts towards."""
    code = (si.get("status") or {}).get("errorCode")
    yield "signins", "success" if code == 0 else "failure"
    app = si.get("clientAppUsed") or ""
    if app in LEGACY_CLIENTS:
        yield "legacy_auth", app
    if code == 500121:   # strong auth (MFA) failed or denied
        yield "mfa_failures", "mfa_denied"
    risk = (si.get("riskLevelDuringSignIn") or "").lower()
    if risk in ("medium", "high"):   # 'hidden' without Entra ID P2
        yield "risky_signins", risk
    if si.get("conditionalAccessStatus") == "failure":
        yield "ca_failures", "blocked"


def _signins(ctx, app, tname) -> int:
    """Daily counts per site, in the box's local days. Recomputes whole days
    from `signins_days` back (late sign-ins land), `signins_backfill_days` on
    the first run or with --full (Graph keeps 30). Nothing per-user is stored."""
    cur = ctx.conn.cursor()
    st = getattr(ctx, "_signins", None)
    if st is None:   # one window for the whole run, whichever tenant comes first
        cur.execute("SELECT max(snapshot_date) FROM azure_log_metrics WHERE query_name = 'signins'")
        have = cur.fetchone()[0]
        days = int(ctx.ccfg.get("signins_days", 2))
        if ctx.full or not have:
            days = max(days, min(int(ctx.ccfg.get("signins_backfill_days", 7)), 30))
        st = ctx._signins = {"start_day": ctx.run_started.astimezone().date() - dt.timedelta(days=days),
                             "cleared": False}
    start_day = st["start_day"]
    start = dt.datetime.combine(start_day, dt.time()).astimezone()   # local midnight

    agg: Dict[tuple, float] = {}
    n = 0
    path, params = FEED_QUERIES["signins"]
    for si in graph_iter(app, path, params(_iso(start))):
        t = parse_ts(si.get("createdDateTime"))
        if not t:
            continue
        day = t.astimezone().date()
        if day < start_day:
            continue
        m = _site(ctx, si.get("userPrincipalName") or "")
        for qn, dim in _signin_dims(si):
            k = (day, qn, m.label, m.key, dim)
            agg[k] = agg.get(k, 0) + 1
        n += 1

    # One tenant's run replaces only what it can see: with several tenants the
    # per-site counts are summed, so clear the window once (first tenant) and add.
    if not st["cleared"]:
        cur.execute("DELETE FROM azure_log_metrics WHERE snapshot_date >= %s AND query_name = ANY(%s)",
                    (start_day, SIGNIN_QUERIES))
    for (day, qn, label, key, dim), v in agg.items():
        cur.execute(
            "INSERT INTO azure_log_metrics (snapshot_date, query_name, site_label, site_tag, dimension, value) "
            "VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT (snapshot_date, query_name, site_label, dimension) "
            "DO UPDATE SET value = azure_log_metrics.value + EXCLUDED.value",
            (day, qn, label, key, dim, v),
        )
    ctx.conn.commit()
    st["cleared"] = True   # only once committed: a rolled-back tenant leaves it to the next
    ctx.log(f"{tname}/signins: {n} sign-ins since {start_day} -> {len(agg)} daily rows")
    return n


FEEDS = {"risky_users": _risky_users, "risk_detections": _risk_detections,
         "mfa_registration": _mfa_registration, "signins": _signins}


def run(ctx: RunContext) -> Dict[str, Any]:
    tenants: List[Dict[str, Any]] = ctx.ccfg.get("tenants") or []
    if not tenants:
        raise RuntimeError("collectors.entra.tenants is empty")
    feeds = ctx.ccfg.get("feeds") or DEFAULT_FEEDS
    unknown = [f for f in feeds if f not in FEEDS]
    if unknown:
        raise RuntimeError(f"collectors.entra.feeds: unknown {unknown} (have {list(FEEDS)})")
    stats: Dict[str, Any] = {}
    errors = 0
    for t in tenants:
        tname = t.get("name") or t.get("tenant_id")
        try:
            app = AzureApp(t, SCOPE)
            app.tok.get()
        except Exception as e:
            errors += len(feeds)
            stats[f"{tname}.error"] = str(e)[:300]
            ctx.log(f"{tname}: no token: {e}")
            continue
        for f in feeds:
            try:
                stats[f"{tname}.{f}"] = FEEDS[f](ctx, app, tname)
            except Exception as e:
                ctx.conn.rollback()
                errors += 1
                stats[f"{tname}.{f}.error"] = str(e)[:300]
                ctx.log(f"{tname}/{f} failed: {e}")
    if errors and errors == len(tenants) * len(feeds):
        raise RuntimeError(f"all Entra feeds failed: {stats}")
    stats["partial"] = bool(errors)
    return stats
