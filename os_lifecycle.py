#!/usr/bin/env python3
"""
Vendor end-of-support dates for the operating systems Falcon reports
(assets.os_version), so the estate page and rollups can count devices on an
unsupported OS -- and those about to be. Dependency-free, like
email_types.py / discovery_classes.py, so SQL can be generated from it.

Dates are the vendor's end of (extended/security) support for the version as
Falcon names it. Windows 11 isn't listed: Falcon reports it without the
feature-update build (23H2/24H2...), and support runs per build, so it can't
be judged here. Override or extend in config.yaml under
reporting.os_end_of_support -- e.g. push Windows 10 out if Extended Security
Updates are bought, or add an OS Falcon starts reporting.
"""
import datetime as dt
from typing import Any, Dict, Optional

D = dt.date
END_OF_SUPPORT: Dict[str, dt.date] = {
    "Windows 7": D(2020, 1, 14),
    "Windows 8.1": D(2023, 1, 10),
    "Windows 10": D(2025, 10, 14),
    "Windows Server 2008": D(2020, 1, 14),
    "Windows Server 2008 R2": D(2020, 1, 14),
    "Windows Server 2012": D(2023, 10, 10),
    "Windows Server 2012 R2": D(2023, 10, 10),
    "Windows Server 2016": D(2027, 1, 12),
    "Windows Server 2019": D(2029, 1, 9),
    "Windows Server 2022": D(2031, 10, 14),
    "Windows Server 2025": D(2034, 10, 10),
    "Oracle Linux 7": D(2024, 12, 31),
    "Oracle Linux 8": D(2029, 7, 31),
    "Oracle Linux 9": D(2032, 6, 30),
    "Red Hat Enterprise Linux 7": D(2024, 6, 30),
    "Red Hat Enterprise Linux 8": D(2029, 5, 31),
    "Red Hat Enterprise Linux 9": D(2032, 5, 31),
    "CentOS 7": D(2024, 6, 30),
}
ENDING_SOON_DAYS = 365


def table(overrides: Optional[Dict[str, Any]] = None) -> Dict[str, dt.date]:
    t = dict(END_OF_SUPPORT)
    for k, v in (overrides or {}).items():
        t[k] = v if isinstance(v, dt.date) else dt.date.fromisoformat(str(v))
    return t


def lookup(os_version: Optional[str], tbl: Dict[str, dt.date]) -> Optional[dt.date]:
    """Exact name first, then the longest listed prefix ("Oracle Linux 8.10"
    -> "Oracle Linux 8")."""
    if not os_version:
        return None
    if os_version in tbl:
        return tbl[os_version]
    best = max((k for k in tbl if os_version.startswith(k + ".") or os_version.startswith(k + " ")),
               key=len, default=None)
    return tbl[best] if best else None


def sql_eos(col: str, tbl: Dict[str, dt.date]) -> str:
    """CASE expression giving the end-of-support date for an os_version
    column (NULL if unknown), same matching as lookup()."""
    whens = []
    for k in sorted(tbl, key=len, reverse=True):   # longest first, so prefixes don't shadow
        name = k.replace("'", "''")
        whens.append(f"WHEN {col} = '{name}' OR {col} LIKE '{name}.%%' OR {col} LIKE '{name} %%' "
                     f"THEN DATE '{tbl[k].isoformat()}'")
    return f"(CASE {' '.join(whens)} END)"
