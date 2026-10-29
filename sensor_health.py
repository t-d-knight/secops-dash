#!/usr/bin/env python3
"""
When a managed host's Falcon sensor counts as "not reporting": one definition
for the nightly rollup, the exec report, the action pack and the dashboards.
Dependency-free (like discovery_classes.py), so the dashboard builder can use it.

A sensor is not reporting when either:
  silent   it hasn't checked in for longer than its type allows. Workstations get
           30 days: laptops go home and people take leave, and Falcon stops listing
           a host after ~45 days anyway, so a shorter limit is mostly noise. Servers
           get 7, domain controllers 2 -- those should never be off.
  in use   it hasn't checked in for IN_USE_GAP_DAYS+, yet Discover saw the same
           machine (its AD computer account, or on the network) at least that long
           after the sensor's last check-in: the machine is in use and the sensor is
           broken or was removed. Counted whatever the type's limit -- the one case
           that's a real gap rather than a machine that's off.

reporting.silent_sensor_days overrides the days per type (workstation, server,
domain_controller); the dashboards are built with the defaults. The older
reporting.stale_sensor_days (one limit for everything) still drives the legacy
daily_asset_metrics.stale_sensors column, which nothing in the reports reads now.

Every SQL helper takes the alias of the managed-host `assets` row: the in-use
check is a correlated subquery, so unqualified column names would resolve to the
inner table.
"""
from typing import Any, Dict, Optional

SILENT_DAYS: Dict[str, int] = {"workstation": 30, "server": 7, "domain_controller": 2}
OTHER_DAYS = 7          # a product type Falcon doesn't report as one of the above
IN_USE_GAP_DAYS = 3


def days(cfg: Optional[Dict[str, Any]] = None) -> Dict[str, int]:
    over = ((cfg or {}).get("reporting") or {}).get("silent_sensor_days") or {}
    return {**SILENT_DAYS, **{k: int(v) for k, v in over.items() if k in SILENT_DAYS}}


def silent_sql(a: str, d: Optional[Dict[str, int]] = None) -> str:
    d = d or SILENT_DAYS
    parts = [f"({a}.product_type = '{k}' AND {a}.last_seen < now() - interval '{int(n)} days')" for k, n in d.items()]
    known = ", ".join(f"'{k}'" for k in d)
    parts.append(f"(COALESCE({a}.product_type, '') NOT IN ({known}) "
                 f"AND {a}.last_seen < now() - interval '{OTHER_DAYS} days')")
    return "(" + " OR ".join(parts) + ")"


def in_use_sql(a: str) -> str:
    return (f"({a}.last_seen < now() - interval '{IN_USE_GAP_DAYS} days' AND EXISTS ("
            f"SELECT 1 FROM assets tw WHERE tw.source = 'falcon_unmanaged' AND NOT tw.retired "
            f"AND tw.discovery_class = 'duplicate_of_managed' AND tw.managed_twin = upper({a}.hostname) "
            f"AND tw.last_seen > {a}.last_seen + interval '{IN_USE_GAP_DAYS} days'))")


def not_reporting_sql(a: str, d: Optional[Dict[str, int]] = None) -> str:
    return f"({silent_sql(a, d)} OR {in_use_sql(a)})"


def machine_seen_sql(a: str) -> str:
    """When Discover last saw the machine (AD logon or network), for the worklists."""
    return (f"(SELECT max(tw.last_seen) FROM assets tw WHERE tw.source = 'falcon_unmanaged' AND NOT tw.retired "
            f"AND tw.discovery_class = 'duplicate_of_managed' AND tw.managed_twin = upper({a}.hostname))")


def describe(d: Optional[Dict[str, int]] = None) -> str:
    d = d or SILENT_DAYS
    return (f"workstations {d['workstation']} days, servers {d['server']}, domain controllers "
            f"{d['domain_controller']}, or any machine still logging on after its sensor went quiet")
