#!/usr/bin/env python3
"""
Check Point Harmony Email & Collaboration (HEC / Avanan) security events
-> email_events.

Uses the Infinity Portal "Smart API": an API key created under Infinity
Portal > Global Settings > API Keys with service "Email & Collaboration".
The key's creation screen shows its Authentication URL -- that host is the
`gateway` below (it's region-specific; the global default may not be yours).

Site = the recipient's email domain. HEC events don't carry a clean
recipient field across all event types, so every address found in the
event (minus the sender) is checked against the sites' email_domains.
"""
import re
import uuid
from typing import Any, Dict, List

from collectors.base import RunContext, as_list, jdump, norm_severity, parse_ts, upsert_rows
from http_client import TokenCache, make_session, raise_for_status
from site_resolver import SiteContext, email_domain

NAME = "checkpoint_hec"
_EMAIL_RX = re.compile(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_NUM_SEV = {"5": "critical", "4": "high", "3": "medium", "2": "low", "1": "info", "0": "info"}


class HecClient:
    def __init__(self, ccfg: Dict[str, Any]):
        self.gw = ccfg.get("gateway", "https://cloudinfra-gw.portal.checkpoint.com").rstrip("/")
        self.cid = ccfg.get("client_id")
        self.key = ccfg.get("access_key")
        if not self.cid or not self.key:
            raise RuntimeError("collectors.checkpoint_hec.client_id / access_key missing from secrets.yaml")
        self.s = make_session(timeout=120)
        self.tok = TokenCache(self._auth)

    def _auth(self):
        r = self.s.post(f"{self.gw}/auth/external", json={"clientId": self.cid, "accessKey": self.key})
        raise_for_status(r, "HEC auth")
        d = (r.json() or {}).get("data") or {}
        if not d.get("token"):
            raise RuntimeError(f"HEC auth returned no token: {r.text[:300]}")
        return d["token"], d.get("expiresIn", 1800)

    def query_events(self, request_data: Dict[str, Any]):
        url = f"{self.gw}/app/hec-api/v1.0/event/query"
        scroll = None
        while True:
            body = {"requestData": dict(request_data, **({"scrollId": scroll} if scroll else {}))}
            headers = {"Authorization": f"Bearer {self.tok.get()}", "x-av-req-id": str(uuid.uuid4()),
                       "Content-Type": "application/json"}
            r = self.s.post(url, json=body, headers=headers)
            if r.status_code == 401:
                self.tok.invalidate()
                headers["Authorization"] = f"Bearer {self.tok.get()}"
                r = self.s.post(url, json=body, headers=headers)
            raise_for_status(r, "HEC event query")
            j = r.json() or {}
            data = j.get("responseData") or []
            yield from data
            scroll = (j.get("responseEnvelope") or {}).get("scrollId")
            if not data or not scroll:
                break


def _severity(v: Any) -> str:
    s = str(v).strip().lower() if v is not None else ""
    return _NUM_SEV.get(s) or norm_severity(s, "medium")


def _recipient_domains(ev: Dict[str, Any], sender: str) -> List[str]:
    blob = " ".join(jdump(ev.get(k)) for k in ("description", "data", "additionalData", "recipients")
                    if ev.get(k) is not None)
    sender = (sender or "").lower()
    doms = []
    for addr in _EMAIL_RX.findall(blob):
        if addr.lower() == sender:
            continue
        d = email_domain(addr)
        if d and d not in doms:
            doms.append(d)
    return doms


def run(ctx: RunContext) -> Dict[str, Any]:
    c = HecClient(ctx.ccfg)
    since = ctx.since(NAME, default_days=int(ctx.ccfg.get("lookback_days", 14)))
    req: Dict[str, Any] = {
        "startDate": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "endDate": ctx.run_started.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if ctx.ccfg.get("event_types"):
        req["eventTypes"] = ctx.ccfg["event_types"]   # e.g. ["phishing","malware","suspicious_phishing","dlp"]
    if ctx.ccfg.get("saas"):
        req["saas"] = ctx.ccfg["saas"]

    rows = []
    for ev in c.query_events(req):
        sender = ev.get("senderAddress") or ""
        rdoms = _recipient_domains(ev, sender)
        m = ctx.resolver.resolve(SiteContext(email_domains=rdoms))
        actions = as_list(ev.get("actions"))
        sender_dom = email_domain(sender)
        recipient_dom = rdoms[0] if rdoms else None
        rows.append({
            "source": "checkpoint_hec",
            "event_id": str(ev.get("eventId")),
            "created_at": parse_ts(ev.get("eventCreated")),
            "event_type": (ev.get("type") or "unknown").lower(),
            "severity": _severity(ev.get("severity")),
            "state": (ev.get("state") or "").lower() or None,
            "saas": ev.get("saas"),
            "confidence": str(ev.get("confidenceIndicator")) if ev.get("confidenceIndicator") is not None else None,
            "sender": sender or None,
            "sender_domain": sender_dom,
            "recipient_domain": recipient_dom,
            # inbound/outbound/internal relative to our own configured
            # email_domains -- lets the exec report split threat volume
            # by direction instead of lumping everything together.
            "direction": ctx.resolver.email_direction(sender_dom, recipient_dom),
            "action_taken": (actions[0] or {}).get("actionType") if actions else None,
            "description": (ev.get("description") or "")[:1000] or None,
            "site_label": m.label,
            "site_tag": m.key,
            "site_matched_by": m.matched_by,
            "link": ev.get("entityLink"),
        })
    n = upsert_rows(ctx.conn, "email_events", rows, ["source", "event_id"])
    return {"rows": n, "since": since.isoformat()}
