#!/usr/bin/env python3
"""
Publish finished reports to a file share -- e.g. a NAS that syncs into a
SharePoint document library -- laid out per site, ready for per-site
permissions:

  <base_path>/<Site>/Weekly/2026-W41 <Site> Security Report.html
  <base_path>/<Site>/Quarterly/2026-Q4 <Site> Security Report.html
  <base_path>/<Site>/Monthly/2026-10 <Site> Action Pack.xlsx
  (the whole-of-region report goes under "Region")

Publishes every finished weekly / quarterly / monthly set under reports/ that
the destination doesn't have yet (tracked in logs/publish-manifest.json by
content hash), so a share that was down for a few days catches up on the next
run. Scratch output -- reports/rolling-*, the committed samples, the Hadrian
tag CSV -- is never published.

Methods (config.yaml `publish.method`):
  smb    SMB2/3 straight to \\\\server\\share via smbprotocol (no mount, no root)
  local  copy into a directory, e.g. a share mounted some other way

Credentials, in order: secrets.yaml (publish.smb.username / password, merged
over config.yaml like every other secret), then the environment variables
SECOPS_SMB_USERNAME / SECOPS_SMB_PASSWORD -- for keeping them out of files,
e.g. set in a root-owned environment file the cron job sources.

    python3 publish.py --config config.yaml            # publish anything new
    python3 publish.py --config config.yaml --dry-run  # show what would be published
    python3 publish.py --config config.yaml --check    # test credentials / write access only
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import sys
from typing import Dict, Iterator, List, Optional, Tuple

import config as config_mod

ROOT = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.path.join(ROOT, "logs", "publish-manifest.json")
# reports/<kind>-<period>/<file> -> (cadence folder, title suffix)
SETS = {
    "week": ("Weekly", "Security Report"),
    "quarter": ("Quarterly", "Security Report"),
    "monthly": ("Monthly", "Action Pack"),
}


def _site_name(stem: str, kind: str) -> str:
    """region.html -> Region; SITE-A.html -> SITE-A; SITE-A-actions-2026-10.xlsx -> SITE-A."""
    name = re.sub(r"-actions-\d{4}-\d{2}$", "", stem) if kind == "monthly" else stem
    return "Region" if name == "region" else name


def candidates(reports_dir: str, formats: Optional[List[str]] = None) -> Iterator[Tuple[str, str]]:
    """(local path, destination path relative to base) for every publishable file."""
    for d in sorted(os.listdir(reports_dir)):
        m = re.match(r"^(week|quarter|monthly)-(.+)$", d)
        full = os.path.join(reports_dir, d)
        if not m or not os.path.isdir(full):
            continue
        kind, period = m.group(1), m.group(2)          # e.g. week / 2026-W41
        folder, title = SETS[kind]
        for f in sorted(os.listdir(full)):
            stem, ext = os.path.splitext(f)
            if ext.lower().lstrip(".") not in (formats or ["pdf", "xlsx"]):
                continue
            site = _site_name(stem, kind)
            yield os.path.join(full, f), "/".join([site, folder, f"{period} {site} {title}{ext}"])


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class LocalTarget:
    def __init__(self, cfg: Dict):
        self.base = cfg["path"]

    def describe(self) -> str:
        return self.base

    def put(self, src: str, rel: str) -> None:
        dest = os.path.join(self.base, *rel.split("/"))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        tmp = dest + ".partial"
        shutil.copyfile(src, tmp)
        os.replace(tmp, dest)        # readers / the sync client never see a half-written file

    def check(self) -> None:
        os.makedirs(self.base, exist_ok=True)
        probe = os.path.join(self.base, ".secops-publish-check")
        with open(probe, "w") as fh:
            fh.write(dt.datetime.now().isoformat())
        os.remove(probe)


class SmbTarget:
    def __init__(self, cfg: Dict):
        try:
            import smbclient  # smbprotocol's high-level API
        except ImportError:
            sys.exit("publish.method smb needs the smbprotocol package: pip install smbprotocol")
        self.smb = smbclient
        self.server = cfg["server"]
        self.share = cfg["share"]
        self.base = (cfg.get("base_path") or "").replace("/", "\\").strip("\\")
        unset = lambda v: not v or str(v).strip().upper() == "CHANGE_ME"   # placeholders in secrets.yaml
        user = cfg.get("username") if not unset(cfg.get("username")) else os.environ.get("SECOPS_SMB_USERNAME")
        password = cfg.get("password") if not unset(cfg.get("password")) else os.environ.get("SECOPS_SMB_PASSWORD")
        if not user or not password:
            sys.exit("SMB credentials missing: set publish.smb.username/password in secrets.yaml "
                     "or SECOPS_SMB_USERNAME/SECOPS_SMB_PASSWORD")
        if cfg.get("domain") and "\\" not in user and "@" not in user:
            user = f"{cfg['domain']}\\{user}"
        self.smb.register_session(self.server, username=user, password=password,
                                  port=int(cfg.get("port", 445)), encrypt=bool(cfg.get("encrypt", True)))

    def _unc(self, rel: str = "") -> str:
        parts = [p for p in self.base.split("\\") + rel.split("/") if p]
        return "\\\\" + "\\".join([self.server, self.share] + parts)

    def describe(self) -> str:
        return self._unc()

    def put(self, src: str, rel: str) -> None:
        dest = self._unc(rel)
        self.smb.makedirs(dest.rsplit("\\", 1)[0], exist_ok=True)
        tmp = dest + ".partial"
        with open(src, "rb") as fin, self.smb.open_file(tmp, mode="wb") as fout:
            shutil.copyfileobj(fin, fout, 1 << 20)
        if hasattr(self.smb, "replace"):
            self.smb.replace(tmp, dest)          # atomic overwrite
        else:
            if self.smb.path.exists(dest):
                self.smb.remove(dest)
            self.smb.rename(tmp, dest)

    def check(self) -> None:
        self.smb.makedirs(self._unc(), exist_ok=True)
        probe = self._unc(".secops-publish-check")
        with self.smb.open_file(probe, mode="w") as fh:
            fh.write(dt.datetime.now().isoformat())
        self.smb.remove(probe)


def target(cfg: Dict):
    method = (cfg.get("method") or "smb").lower()
    if method == "smb":
        return SmbTarget(cfg.get("smb") or {})
    if method == "local":
        return LocalTarget(cfg.get("local") or {})
    sys.exit(f"unknown publish.method {method!r} (smb | local)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--dry-run", action="store_true", help="list what would be published, change nothing")
    ap.add_argument("--check", action="store_true", help="only test that the destination is writable")
    ap.add_argument("--force", action="store_true", help="re-publish everything, ignoring the manifest")
    ap.add_argument("--sets", help="only these kinds, comma-separated: week,quarter,monthly (default: all)")
    args = ap.parse_args()

    cfg = config_mod.load_config(args.config)
    pub = cfg.get("publish") or {}
    if not pub.get("enabled") and not (args.dry_run or args.check):
        print("[publish] publish.enabled is false -- nothing to do")
        return 0
    reports_dir = os.path.join(cfg.get("_config_dir", ROOT), pub.get("reports_dir", "reports"))

    manifest: Dict[str, str] = {}
    if os.path.exists(MANIFEST) and not args.force:
        with open(MANIFEST) as fh:
            manifest = json.load(fh)
    kinds = {k.strip() for k in args.sets.split(",")} if args.sets else set(SETS)
    folders = {SETS[k][0] for k in kinds if k in SETS}
    formats = [f.lower().lstrip(".") for f in pub.get("formats") or ["pdf", "xlsx"]]
    todo = [(src, rel, h) for src, rel in candidates(reports_dir, formats) if rel.split("/")[1] in folders
            for h in [_sha256(src)] if manifest.get(rel) != h]

    if args.dry_run:
        for _, rel, _ in todo:
            print(f"[publish] would publish {rel}")
        print(f"[publish] {len(todo)} file(s) to publish")
        return 0

    try:
        t = target(pub)
        if args.check:
            t.check()
            print(f"[publish] OK: can write to {t.describe()}")
            return 0
    except Exception as e:   # unreachable NAS, bad credentials, no permission: one clear line for the cron log
        print(f"[publish] cannot reach destination: {type(e).__name__}: {e}", file=sys.stderr)
        return 2

    failed: List[str] = []
    for src, rel, h in todo:
        try:
            t.put(src, rel)
            manifest[rel] = h
            print(f"[publish] {rel}")
        except Exception as e:   # one bad file shouldn't stop the rest
            failed.append(rel)
            print(f"[publish] FAILED {rel}: {e}", file=sys.stderr)
    os.makedirs(os.path.dirname(MANIFEST), exist_ok=True)
    with open(MANIFEST + ".tmp", "w") as fh:
        json.dump(manifest, fh, indent=1, sort_keys=True)
    os.replace(MANIFEST + ".tmp", MANIFEST)
    print(f"[publish] {len(todo) - len(failed)} published, {len(failed)} failed -> {t.describe()}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
