#!/usr/bin/env python3
"""
Falcon Identity Protection -> identity_entities + identity_risk_factors.

Full pull every run (an identity's risk factors are current-state, not
events), via the Identity Protection GraphQL API. Feeds the "stale /
compromised-password / never-expires / high-risk accounts" views per site,
which is exactly the remediation list the service desk works from.

The query lives in collectors/queries/identity_entities.graphql so fields
can be added from the tenant's GraphQL explorer without code changes.
Risk factor types are stored verbatim (STALE_ACCOUNT, WEAK_PASSWORD, ...)
rather than mapped to a fixed list, so new factor types CrowdStrike adds
show up in Grafana automatically.
"""
import os
from typing import Any, Dict, List

from collectors.base import RunContext, as_list, parse_ts, upsert_rows, TextArray
from collectors.falcon_client import FalconClient
import identity_categories as ic
from site_resolver import SiteContext, email_domain

NAME = "falcon_identity"
GQL_PATH = "/identity-protection/combined/graphql/v1"


def _load_query(ctx: RunContext) -> str:
    path = ctx.ccfg.get("query_file") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "queries", "identity_entities.graphql")
    with open(path) as f:
        q = "\n".join(l for l in f.read().splitlines() if not l.lstrip().startswith("#"))
    types = ", ".join(ctx.ccfg.get("entity_types", ["USER"]))
    return q.replace("__TYPES__", types).replace("__PAGE__", str(int(ctx.ccfg.get("page_size", 1000))))


def run(ctx: RunContext) -> Dict[str, Any]:
    fc = FalconClient(ctx.cfg, ctx.ccfg)
    query = _load_query(ctx)
    rules = ic.kind_rules(ctx.ccfg.get("account_kinds"))
    out_of_scope = {str(o).strip().lower() for o in ctx.ccfg.get("out_of_scope_ous") or []}
    kinds: Dict[str, int] = {}

    entities: List[Dict[str, Any]] = []
    factors: List[Dict[str, Any]] = []
    after = None
    while True:
        j = fc.post(GQL_PATH, {"query": query, "variables": {"after": after}})
        if j.get("errors"):
            raise RuntimeError(f"Identity GraphQL errors: {j['errors'][:3]}")
        block = (j.get("data") or {}).get("entities") or {}
        for n in block.get("nodes") or []:
            ad = next((a for a in as_list(n.get("accounts")) if a and a.get("samAccountName")), {}) or {}
            upn = n.get("secondaryDisplayName")
            # ou is a path that starts with the AD domain ("corp.example.org/SITE-B/
            # Users"): match site rules against the OU segments only, or a rule
            # whose fragment also appears in a domain name matches every account
            # in that domain (it did -- thousands of one site's accounts landed
            # in another).
            segs = [x for x in str(ad.get("ou") or "").split("/") if x.strip()]
            if segs and "." in segs[0]:
                segs = segs[1:]
            m = ctx.resolver.resolve(SiteContext(
                ous=segs,
                ad_domains=as_list(ad.get("domain")),
                email_domains=as_list(email_domain(upn)),
            ))
            eid = n.get("entityId")
            roles = sorted({r.get("type") for r in as_list(n.get("roles")) if r and r.get("type")})
            groups = sorted({g.get("primaryDisplayName") for a in as_list(n.get("accounts")) if a
                             for g in as_list(a.get("containingGroupEntities")) if g and g.get("primaryDisplayName")})
            kind, privileged = ic.classify_account(rules, ad.get("ou"), groups,
                                                   ad.get("samAccountName") or upn or n.get("primaryDisplayName"), roles)
            if out_of_scope and {x.strip().lower() for x in segs} & out_of_scope:
                kind = "out_of_scope"   # departed service: kept, but off the reports and action packs
            kinds[kind] = kinds.get(kind, 0) + 1
            entities.append({
                "source": "falcon_identity",
                "entity_id": eid,
                "display_name": n.get("primaryDisplayName"),
                "upn": upn,
                "domain": ad.get("domain"),
                "sam_account_name": ad.get("samAccountName"),
                "ou": ad.get("ou"),
                "enabled": ad.get("enabled"),
                "entity_type": n.get("type"),
                "risk_score": n.get("riskScore"),
                "risk_severity": (n.get("riskScoreSeverity") or "").lower() or None,
                "password_last_change": parse_ts((ad.get("passwordAttributes") or {}).get("lastChange")),
                "account_created": parse_ts(ad.get("creationTime")),
                "site_label": m.label,
                "site_tag": m.key,
                "site_matched_by": m.matched_by,
                "account_kind": kind,
                "access_account": (None if kind == "out_of_scope" else
                                   ic.classify_access(ctx.ccfg.get("access_domain"), ad.get("domain"), m.label, groups)),
                "is_privileged": privileged,
                "roles": TextArray(roles),
                "ad_groups": TextArray(groups),
                "collected_at": ctx.run_started,
                "retired": False,
            })
            for f in as_list(n.get("riskFactors")):
                if f and f.get("type"):
                    factors.append({
                        "source": "falcon_identity",
                        "entity_id": eid,
                        "factor_type": f["type"],
                        "factor_severity": (f.get("severity") or "").lower() or None,
                    })
        pi = block.get("pageInfo") or {}
        if not pi.get("hasNextPage"):
            break
        after = pi.get("endCursor")

    n = upsert_rows(ctx.conn, "identity_entities", entities, ["source", "entity_id"])
    cur = ctx.conn.cursor()
    # risk factors are current-state: replace wholesale, in the same transaction as the insert
    cur.execute("DELETE FROM identity_risk_factors WHERE source = 'falcon_identity'")
    upsert_rows(ctx.conn, "identity_risk_factors", factors, ["source", "entity_id", "factor_type"])
    cur.execute("UPDATE identity_entities SET retired = TRUE "
                "WHERE source = 'falcon_identity' AND collected_at < %s", (ctx.run_started,))
    ctx.conn.commit()
    return {"entities": n, "risk_factors": len(factors), "account_kinds": kinds}
