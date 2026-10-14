#!/usr/bin/env python3
"""
Copy a database dump (backup.sh output) to an SMB share off the box, then
prune dumps there older than backup.offsite.keep_days. Called by backup.sh
after every dump when backup.offsite.enabled is true.

    python3 backup_offsite.py --config config.yaml backups/secops_dashboard-20261014-0902.dump
    python3 backup_offsite.py --config config.yaml --check     # test credentials / write access only

Config (config.yaml):
  backup:
    offsite:
      enabled: true
      keep_days: 14
      smb: {server: ..., share: ..., base_path: ...}

Credentials: backup.offsite.smb.username / password (secrets.yaml) if set,
otherwise the publish.smb ones -- the usual case when both live on the same NAS.
"""
import argparse
import datetime as dt
import os
import re
import sys

from config import load_config
from publish import SmbTarget

DUMP_RE = re.compile(r"^.+-(\d{8})-\d{4}\.dump$")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--check", action="store_true", help="test write access only")
    ap.add_argument("dump", nargs="?")
    args = ap.parse_args()

    cfg = load_config(args.config)
    off = (cfg.get("backup") or {}).get("offsite") or {}
    if not off.get("enabled"):
        print("[offsite] backup.offsite.enabled is false -- nothing to do")
        return 0
    smb_cfg = {k: v for k, v in ((cfg.get("publish") or {}).get("smb") or {}).items()
               if k in ("username", "password", "domain", "port", "encrypt")}
    smb_cfg.update(off.get("smb") or {})
    t = SmbTarget(smb_cfg)

    if args.check:
        t.check()
        print(f"[offsite] writable: {t.describe()}")
        return 0
    if not args.dump:
        ap.error("dump file required (or --check)")

    name = os.path.basename(args.dump)
    t.put(args.dump, name)
    print(f"[offsite] copied {name} -> {t.describe()}")

    keep = int(off.get("keep_days", 14))
    cutoff = (dt.date.today() - dt.timedelta(days=keep)).strftime("%Y%m%d")
    for entry in t.smb.scandir(t.describe()):
        m = DUMP_RE.match(entry.name)
        if m and m.group(1) < cutoff:
            t.smb.remove(t._unc(entry.name))
            print(f"[offsite] pruned {entry.name} (older than {keep} days)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
