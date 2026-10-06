#!/usr/bin/env python3
"""
Multi-signal site resolution. Every collector describes the thing it found
(a host, an identity, an alert, an email event, an external asset) as a
SiteContext with whatever signals it has, and the resolver turns that into
one site label using config.yaml's `sites:` rules.

Signals are checked in `site_resolution.order` (most specific first): the
first signal type that matches ANY site wins. Within one signal type, sites
are checked in config order, so put narrower rules first if they overlap.

    sites:
      - key: "RVH"
        label: "Riverside Health"
        match:
          falcon_tags:   ["SensorGroupingTags/RVH"]     # exact, case-insensitive
          falcon_groups: ["RVH - Workstations"]          # host group NAME, exact
          ou_contains:   ["OU=Riverside Health"]          # substring of the DN/OU path
          ad_sites:      ["RVH-Main"]                    # AD Sites & Services site name (Falcon site_name)
          ad_domains:    ["rvh.local"]                   # AD/NetBIOS domain, exact (FQDN suffix also matches)
          hostname_regex: ["^RVH[-_]"]
          cidrs:         ["10.10.0.0/16"]
          email_domains: ["riversidehealth.test"]       # exact or subdomain

Anything nothing matches lands in `ungrouped_label`, and the matcher that
fired is recorded alongside the label (site_matched_by) so mapping gaps are
visible in Grafana instead of silently piling up in "Ungrouped".
"""
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

DEFAULT_ORDER = [
    "falcon_tags",
    "falcon_groups",
    "ou_contains",
    "ad_sites",
    "ad_domains",
    "hostname_regex",
    "cidrs",
    "email_domains",
]


@dataclass
class SiteContext:
    falcon_tags: List[str] = field(default_factory=list)
    falcon_groups: List[str] = field(default_factory=list)
    ous: List[str] = field(default_factory=list)
    ad_sites: List[str] = field(default_factory=list)
    ad_domains: List[str] = field(default_factory=list)
    hostnames: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    email_domains: List[str] = field(default_factory=list)


@dataclass
class SiteMatch:
    label: str
    key: str
    matched_by: str  # matcher name, or 'none'


def _norm_list(vals: Iterable[Any]) -> List[str]:
    out = []
    for v in vals or []:
        if v is None:
            continue
        s = str(v).strip().lower()
        if s:
            out.append(s)
    return out


def email_domain(addr: Optional[str]) -> Optional[str]:
    if not addr or "@" not in str(addr):
        return None
    return str(addr).rsplit("@", 1)[1].strip().strip(">").lower() or None


class SiteResolver:
    def __init__(self, cfg: Dict[str, Any]):
        self.ungrouped = cfg.get("ungrouped_label", "Ungrouped")
        self.order = (cfg.get("site_resolution") or {}).get("order") or DEFAULT_ORDER
        self.sites: List[Dict[str, Any]] = []
        for s in cfg.get("sites", []) or []:
            m = s.get("match") or {}
            cidrs = []
            for c in m.get("cidrs", []) or []:
                try:
                    cidrs.append(ipaddress.ip_network(str(c), strict=False))
                except ValueError:
                    raise ValueError(f"Site '{s.get('key')}': invalid CIDR '{c}'")
            self.sites.append({
                "key": s["key"],
                "label": s.get("label", s["key"]),
                "falcon_tags": set(_norm_list(m.get("falcon_tags"))),
                "falcon_groups": set(_norm_list(m.get("falcon_groups"))),
                "ou_contains": _norm_list(m.get("ou_contains")),
                "ad_sites": set(_norm_list(m.get("ad_sites"))),
                "ad_domains": _norm_list(m.get("ad_domains")),
                "hostname_regex": [re.compile(p, re.I) for p in (m.get("hostname_regex") or [])],
                "cidrs": cidrs,
                "email_domains": _norm_list(m.get("email_domains")),
                # Legacy (pre-v2) config: a bare `key` was a Tenable tag value.
                # Treat it as a Falcon tag too so an old config still resolves.
                "legacy_tag": str(s["key"]).lower(),
            })

    # -- individual matchers ------------------------------------------------
    @staticmethod
    def _m_falcon_tags(site, ctx: SiteContext) -> bool:
        tags = set(_norm_list(ctx.falcon_tags))
        if site["falcon_tags"] & tags:
            return True
        # also accept the tag's value part, e.g. "SensorGroupingTags/BH" == "bh"
        short = {t.rsplit("/", 1)[-1] for t in tags}
        return bool(site["falcon_tags"] & short)

    @staticmethod
    def _m_falcon_groups(site, ctx: SiteContext) -> bool:
        return bool(site["falcon_groups"] & set(_norm_list(ctx.falcon_groups)))

    @staticmethod
    def _m_ou_contains(site, ctx: SiteContext) -> bool:
        ous = _norm_list(ctx.ous)
        return any(frag in ou for frag in site["ou_contains"] for ou in ous)

    @staticmethod
    def _m_ad_sites(site, ctx: SiteContext) -> bool:
        return bool(site["ad_sites"] & set(_norm_list(ctx.ad_sites)))

    @staticmethod
    def _m_ad_domains(site, ctx: SiteContext) -> bool:
        doms = _norm_list(ctx.ad_domains)
        for d in doms:
            for want in site["ad_domains"]:
                if d == want or d.endswith("." + want):
                    return True
        return False

    @staticmethod
    def _m_hostname_regex(site, ctx: SiteContext) -> bool:
        return any(rx.search(h) for rx in site["hostname_regex"] for h in ctx.hostnames if h)

    @staticmethod
    def _m_cidrs(site, ctx: SiteContext) -> bool:
        if not site["cidrs"]:
            return False
        for ip in ctx.ips or []:
            try:
                addr = ipaddress.ip_address(str(ip).strip())
            except ValueError:
                continue
            if any(addr in net for net in site["cidrs"]):
                return True
        return False

    @staticmethod
    def _m_email_domains(site, ctx: SiteContext) -> bool:
        doms = _norm_list(ctx.email_domains)
        for d in doms:
            for want in site["email_domains"]:
                if d == want or d.endswith("." + want):
                    return True
        return False

    _MATCHERS = {
        "falcon_tags": _m_falcon_tags.__func__,
        "falcon_groups": _m_falcon_groups.__func__,
        "ou_contains": _m_ou_contains.__func__,
        "ad_sites": _m_ad_sites.__func__,
        "ad_domains": _m_ad_domains.__func__,
        "hostname_regex": _m_hostname_regex.__func__,
        "cidrs": _m_cidrs.__func__,
        "email_domains": _m_email_domains.__func__,
    }

    def resolve(self, ctx: SiteContext) -> SiteMatch:
        for matcher in self.order:
            fn = self._MATCHERS.get(matcher)
            if fn is None:
                continue
            for site in self.sites:
                if fn(site, ctx):
                    return SiteMatch(site["label"], site["key"], matcher)
        # legacy fallback: bare site key present as a tag
        tags = set(_norm_list(ctx.falcon_tags))
        short = {t.rsplit("/", 1)[-1] for t in tags}
        for site in self.sites:
            if site["legacy_tag"] in tags or site["legacy_tag"] in short:
                return SiteMatch(site["label"], site["key"], "legacy_key")
        return SiteMatch(self.ungrouped, "UNGROUPED", "none")

    def site_rows(self) -> List[Tuple[str, str]]:
        """(key, label) for every configured site, plus Ungrouped."""
        return [(s["key"], s["label"]) for s in self.sites] + [("UNGROUPED", self.ungrouped)]

    def is_own_domain(self, domain: Optional[str]) -> bool:
        """True if `domain` is (or is a subdomain of) any configured site's
        email_domains -- i.e. it's one of ours, not an external party's."""
        d = (domain or "").strip().lower()
        if not d:
            return False
        for site in self.sites:
            for want in site["email_domains"]:
                if d == want or d.endswith("." + want):
                    return True
        return False

    def email_direction(self, sender_domain: Optional[str], recipient_domain: Optional[str]) -> str:
        """Classify a mail event as inbound/outbound/internal relative to
        our own configured email domains. 'unknown' when neither side
        resolves to a domain we recognize as ours or can be confirmed
        external (e.g. no recipient could be extracted from the event)."""
        s_own = self.is_own_domain(sender_domain)
        r_own = self.is_own_domain(recipient_domain)
        if s_own and r_own:
            return "internal"
        if s_own and not r_own:
            return "outbound"
        if r_own and not s_own:
            return "inbound"
        return "unknown"
