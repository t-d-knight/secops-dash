#!/usr/bin/env python3
"""
Classes for Falcon Discover "unmanaged" assets -- what collectors/falcon_hosts.py
(classify_unmanaged) assigns to assets.discovery_class, with a label, what to
do about it, and whether it's a real machine that should get a sensor.

One place for the vocabulary so the collector, grafana/build_dashboards.py
and action_pack.py can't drift apart. Dependency-free on purpose (like
email_types.py), so the dashboard builder runs without the collector's
requirements installed.

Discover's unmanaged list (1,298 records on 2026-10-06) is mostly NOT
missing endpoints: ~200 were managed hosts Falcon hadn't linked to their AD
computer object, ~55 service accounts, ~30 appliances -- only the
"actionable" classes are real machines that should get a sensor.
"""
from typing import Dict, List, Tuple

# class -> (label, what to do, actionable)
DISCOVERY_CLASSES: Dict[str, Tuple[str, str, bool]] = {
    "domain_controller_no_sensor": ("Domain controller, no sensor", "Install a sensor now (or retire the DC)", True),
    "server_no_sensor": ("Windows server, no sensor", "Install a sensor, or record why it can't have one", True),
    "workstation_no_sensor": ("Windows workstation, no sensor", "Install a sensor; check it isn't a renamed managed host", True),
    "cloud_no_sensor": ("Cloud instance, no sensor", "Install a sensor", True),
    "vmware_nic": ("VMware NIC seen on network", "VM without a sensor, or an ESXi management interface: identify by IP", True),
    "network_device": ("Device seen on network", "Identify by IP/MAC vendor: PC needing a sensor, or printer/IoT/appliance", True),
    "appliance_ad_account": ("Appliance with an AD account", "Can't take a sensor (ISE, vCenter, NAS...): confirm it's known", False),
    "duplicate_of_managed": ("Same name as a managed host", "Already has a sensor -- Falcon didn't link the AD record", False),
    "secondary_ip_of_managed": ("Extra IP of a managed host", "Shares a managed host's MAC: cluster/listener IP or multi-homed", False),
    "service_account": ("Service account (gMSA/MSA)", "Not a machine", False),
    "cluster_name": ("Cluster / listener name", "Not a machine (SQL AG listener, cluster or DAG name)", False),
    "out_of_scope": ("Outside this Falcon tenant", "Managed in another CID, or a departed service's leftover AD object: "
                     "no sensor needed here (collectors.falcon_hosts.out_of_scope_ous)", False),
    "disabled_ad_account": ("Disabled AD computer account", "Not in use: delete from AD when convenient", False),
    "stale_ad_account": ("AD account, no logon in 60+ days", "Probably gone: confirm and delete from AD", False),
}

ACTIONABLE: List[str] = [k for k, (_, _, act) in DISCOVERY_CLASSES.items() if act]
# The ones a site can act on from a name: AD computer accounts with a known OS.
NAMED_MACHINES: List[str] = ["domain_controller_no_sensor", "server_no_sensor", "workstation_no_sensor",
                             "cloud_no_sensor"]


def sql_in(values) -> str:
    return "(" + ", ".join("'%s'" % v.replace("'", "''") for v in values) + ")"


def sql_case(col: str = "discovery_class", part: int = 0) -> str:
    """CASE expression mapping the class column to its label (part=0) or
    action (part=1), for SQL that can't import this module's dict."""
    whens = " ".join("WHEN '%s' THEN '%s'" % (k, v[part].replace("'", "''")) for k, v in DISCOVERY_CLASSES.items())
    return f"CASE {col} {whens} ELSE COALESCE({col}, 'unclassified') END"
