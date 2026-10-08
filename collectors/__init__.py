#!/usr/bin/env python3
"""
Collector registry. Order matters: falcon_hosts runs before the other Falcon
collectors because they reuse its per-host site resolution.
"""
from collectors import (
    azure_log_analytics,
    checkpoint_hec,
    checkpoint_hec_flow,
    dmarc,
    entra,
    falcon_alerts,
    falcon_hosts,
    falcon_identity,
    falcon_spotlight,
    hadrian,
)

REGISTRY = {m.NAME: m for m in (
    falcon_hosts,
    falcon_spotlight,
    falcon_alerts,
    falcon_identity,
    hadrian,
    checkpoint_hec,
    checkpoint_hec_flow,
    entra,
    azure_log_analytics,
    dmarc,
)}
