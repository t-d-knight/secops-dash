#!/usr/bin/env python3
"""
What the programme-impact views measure: the nightly counts (METRICS) and the
scorecard built from them (SCORECARD). No database imports, so the Grafana
dashboard builder can use it as well as impact.py / impact_report.py.
"""
from typing import Dict, List, Optional, Tuple

EXCLUDE_SITES = ("TEST",)   # default for impact.exclude_sites: kept out of region totals

# key -> description (what each nightly count is)
METRICS: Dict[str, str] = {
    "servers_active": "Servers + DCs with a sensor seen in 7 days",
    "servers_patched_35d": "...of those, last patch confirmed within 35 days",
    "servers_unpatched_90d": "...last patch confirmed 90+ days ago",
    "servers_up_35d": "...not restarted in 35+ days",
    "dcs_active": "Domain controllers seen in 7 days",
    "dcs_attention": "...not patched in 35+ days or on an unsupported OS",
    "hosts_active": "Managed devices seen in 7 days",
    "hosts_with_kev": "...with an open known-exploited (KEV) vulnerability",
    "kev_open": "Open KEV findings",
    "crit_open": "Open critical findings (seen in the reporting window)",
    "crit_past_sla": "...past the critical SLA",
    "high_open": "Open high findings",
    "high_past_sla": "...past the high SLA",
    "unsupported_os": "Devices on an unsupported OS",
    "missing_sensors": "In-use AD machines with no Falcon sensor",
    "stale_sensors": "Managed hosts silent 7+ days",
    "managed_hosts": "Managed hosts (any last-seen)",
    "enabled_accounts": "Enabled accounts (all kinds)",
    "stale_accounts": "...flagged stale",
    "people_accounts": "People's main accounts",
    "people_no_mfa": "People without MFA",
    "unused_access_accounts": "Unused shared-domain VPN / remote-app accounts",
    "compromise_indicators": "Accounts with compromise indicators",
    "identity_triage": "Identity detections (high/medium) awaiting triage",
    "ext_confirmed_open": "Confirmed external risks open",
    "ext_crit_high_open": "Critical/high external risks open",
    "leaked_creds": "Infostealer leaks naming an enabled account",
}

# What the dashboard / report show: (key, label, numerator, denominator or None, good direction)
SCORECARD: List[Tuple[str, str, str, Optional[str], str]] = [
    ("srv_patched", "Servers patched within 35 days", "servers_patched_35d", "servers_active", "up"),
    ("srv_90", "Servers not patched in 90+ days", "servers_unpatched_90d", None, "down"),
    ("srv_up", "Servers not restarted in 35+ days", "servers_up_35d", None, "down"),
    ("dc_attention", "Domain controllers needing attention", "dcs_attention", None, "down"),
    ("kev_hosts", "Devices with a known-exploited vulnerability", "hosts_with_kev", "hosts_active", "down"),
    ("crit_sla", "Open critical past SLA", "crit_past_sla", "crit_open", "down"),
    ("high_sla", "Open high past SLA", "high_past_sla", "high_open", "down"),
    ("unsupported", "Devices on an unsupported OS", "unsupported_os", None, "down"),
    ("missing", "Machines missing a sensor", "missing_sensors", None, "down"),
    ("stale_sensors", "Sensors silent 7+ days", "stale_sensors", "managed_hosts", "down"),
    ("stale_accts", "Enabled accounts that are stale", "stale_accounts", "enabled_accounts", "down"),
    ("no_mfa", "People without MFA", "people_no_mfa", None, "down"),
    ("access", "Unused VPN / remote-app accounts", "unused_access_accounts", None, "down"),
    ("triage", "Identity detections awaiting triage", "identity_triage", None, "down"),
    ("ext", "Confirmed external risks open", "ext_confirmed_open", None, "down"),
    ("leaks", "Leaked credentials (enabled accounts)", "leaked_creds", None, "down"),
]
