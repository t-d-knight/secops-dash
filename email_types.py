#!/usr/bin/env python3
"""
Check Point Harmony Email & Collaboration (HEC) event_type vocabulary,
split into genuine threats vs bulk/low-signal mail classification.

Confirmed against real production data (2026-10-05): graymail and spam
alone accounted for ~97% of all HEC events (183,371 graymail + 32,200
spam out of ~223,000 total), and panels/tiles that counted every
event_type indiscriminately under a "threats" label were being swamped
by legitimate bulk mail (LinkedIn/Zoom/Canva notification traffic topped
the real "Top sending domains (threats)" panel). This module is the one
place that vocabulary is classified, so exec_report.py and
grafana/build_dashboards.py can't drift apart on what counts as a threat.

If Check Point's `type` field ever sends something not listed here, it
falls into neither bucket -- intentional, so a new/unrecognized type
shows up as a gap to classify rather than silently landing on either
side.
"""

# Security-relevant: phishing/malware/data-exfil attempts, plus
# behavioural account-risk signals (anomaly = e.g. impossible-travel
# logins -- a real account-compromise indicator, not bulk mail).
THREAT_EVENT_TYPES = ("phishing", "suspicious_phishing", "malware", "dlp", "anomaly")

# Real mail volume and SaaS-usage visibility, not inherently malicious.
# Kept as its own visible count rather than silently dropped, so "how
# much mail are we actually processing" doesn't disappear -- it's just
# no longer counted as a "threat".
BULK_EVENT_TYPES = ("graymail", "spam", "shadow_it", "alert")


def sql_in(types) -> str:
    """`event_type IN ('a','b',...)` -- safe here since every value comes
    from the fixed tuples above, never from user/request input."""
    return "(" + ", ".join(f"'{t}'" for t in types) + ")"
