#!/usr/bin/env python3
"""
Stop real organisation identifiers reaching git. The repo stays generic
(SITE-A, example.org.au, ...) so it can be shared; real values only ever
live in the untracked config.yaml / secrets.yaml.

The denylist is built from those untracked files -- so the list itself is
never committed -- plus an optional untracked .identifiers.local (one term
or regex per line, '#' comments):
  config.yaml   site keys/labels, falcon host-group names, OU fragments, AD and
                email domains, out-of-scope OUs, the shared access domain,
                the publish server/share/path, the Hadrian organisation id,
                the database host if it isn't localhost
  secrets.yaml  every string value (keys, passwords, client ids)

    tools/check_identifiers.py             # staged changes (what the pre-commit hook runs)
    tools/check_identifiers.py --all       # every tracked file, e.g. after changing the rules
    tools/check_identifiers.py --list      # show the denylist (local terminal only!)

False positives: put "identifier-check: ok" on the line, or add a regex for
the line to .identifiers-allow (committed, so keep it generic -- e.g. a date
format like "HH:mm" when a site key happens to be HH).

Without a config.yaml (someone else's clone) there's nothing to check
against, so it passes quietly.
"""
import argparse
import os
import re
import subprocess
import sys
from typing import Iterable, List, Set, Tuple

ROOT = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True).stdout.strip() \
    or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INLINE_OK = "identifier-check: ok"
# Untracked/ignored anyway, or generated -- never scanned.
SKIP_PATHS = re.compile(r"^(config\.yaml|secrets\.yaml|\.identifiers\.local|reports/|backups/|logs/)")


def _yaml(path: str):
    if not os.path.exists(path):
        return None
    try:
        import yaml
    except ImportError:
        sys.exit("check_identifiers: needs PyYAML (pip install pyyaml)")
    with open(path) as fh:
        return yaml.safe_load(fh) or {}


def _strings(obj) -> Iterable[str]:
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)
    elif isinstance(obj, str):
        yield obj


def denylist() -> Tuple[List[Tuple[str, re.Pattern]], bool]:
    cfg = _yaml(os.path.join(ROOT, "config.yaml"))
    if cfg is None:
        return [], False
    terms: Set[str] = set()
    words: Set[str] = set()          # short codes: whole-word, case-sensitive
    for s in cfg.get("sites") or []:
        for code in (s.get("key"), s.get("label")):
            if code and code.upper() not in ("TEST", "UNGROUPED"):
                (words if len(code) <= 5 else terms).add(code)
        m = s.get("match") or {}
        for k in ("falcon_groups", "ou_contains", "ad_domains", "email_domains", "hostname_regex"):
            terms.update(x for x in m.get(k) or [] if isinstance(x, str) and len(x) >= 4)
    col = cfg.get("collectors") or {}
    terms.update(str(o) for o in (col.get("falcon_hosts") or {}).get("out_of_scope_ous") or {})
    ident = col.get("falcon_identity") or {}
    terms.update(str(o) for o in ident.get("out_of_scope_ous") or [])
    if (ident.get("access_domain") or {}).get("domain"):
        terms.add(ident["access_domain"]["domain"])
    if (col.get("hadrian") or {}).get("organization_id"):
        terms.add(col["hadrian"]["organization_id"])
    smb = (cfg.get("publish") or {}).get("smb") or {}
    terms.update(str(smb[k]) for k in ("server", "base_path") if smb.get(k))
    host = (cfg.get("database") or {}).get("host")
    if host and host not in ("127.0.0.1", "localhost"):
        terms.add(host)
    secrets = _yaml(os.path.join(ROOT, cfg.get("secrets_file") or "secrets.yaml")) or {}
    secret_terms = {s for s in _strings(secrets) if len(s) >= 8 and s.upper() != "CHANGE_ME"}
    local = os.path.join(ROOT, ".identifiers.local")
    patterns: List[Tuple[str, re.Pattern]] = []
    if os.path.exists(local):
        for line in open(local):
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append((line, re.compile(line, re.I)))
    terms = {t for t in terms if t and t.strip() and t.upper() != "CHANGE_ME"}
    patterns += [(t, re.compile(re.escape(t), re.I)) for t in sorted(terms, key=len, reverse=True)]
    # labelled, never shown: these are credentials
    patterns += [("<a secrets.yaml value>", re.compile(re.escape(t))) for t in secret_terms]
    patterns += [(w, re.compile(rf"(?<![A-Za-z0-9]){re.escape(w)}(?![A-Za-z0-9])")) for w in sorted(words)]
    return patterns, True


def allowlist() -> List[re.Pattern]:
    p = os.path.join(ROOT, ".identifiers-allow")
    if not os.path.exists(p):
        return []
    return [re.compile(l.strip()) for l in open(p) if l.strip() and not l.startswith("#")]


def staged_lines() -> Iterable[Tuple[str, int, str]]:
    diff = subprocess.run(["git", "diff", "--cached", "-U0", "--no-color", "--diff-filter=ACMR"],
                          cwd=ROOT, capture_output=True, text=True).stdout
    path, n = None, 0
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else None
        elif line.startswith("@@"):
            n = int(re.search(r"\+(\d+)", line).group(1))
        elif line.startswith("+") and path:
            yield path, n, line[1:]
            n += 1


def tracked_lines() -> Iterable[Tuple[str, int, str]]:
    files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    for f in files:
        try:
            with open(os.path.join(ROOT, f), encoding="utf-8") as fh:
                for i, line in enumerate(fh, 1):
                    yield f, i, line.rstrip("\n")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue    # binary (xlsx/pdf samples) or gone


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--all", action="store_true", help="scan every tracked file, not just staged changes")
    ap.add_argument("--list", action="store_true", help="print the denylist (contains real values!)")
    args = ap.parse_args()

    deny, have_config = denylist()
    if not have_config:
        print("check_identifiers: no config.yaml here -- nothing to check against")
        return 0
    if args.list:
        for label in sorted({label for label, _ in deny}):
            print(label)
        return 0
    allow = allowlist()
    hits = []
    for path, n, text in (tracked_lines() if args.all else staged_lines()):
        if SKIP_PATHS.match(path) or INLINE_OK in text or any(a.search(text) for a in allow):
            continue
        found = sorted({label for label, rx in deny if rx.search(text)})
        if found:
            hits.append((path, n, found))
    if not hits:
        print(f"check_identifiers: clean ({'all tracked files' if args.all else 'staged changes'})")
        return 0
    print("check_identifiers: real identifiers found -- keep the repo generic (SITE-A, example.org.au, ...):")
    for path, n, found in hits:
        # the matched config terms, never the line itself (it may hold a secret)
        print(f"  {path}:{n}: {', '.join(found)}")
    print("Fix them, mark a genuine false positive with 'identifier-check: ok', or add a generic regex to "
          ".identifiers-allow. To see which terms matched: tools/check_identifiers.py --list (local only).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
