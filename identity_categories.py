#!/usr/bin/env python3
"""
The identity-risk categories stakeholders see: actionable groupings of
Falcon Identity Protection risk factors, in place of the ~35 raw factor
types (many of which are investigation detail -- SPNs, krbtgt age, "watched"
accounts). One place for the definitions so rollup_daily_metrics.py (daily
history for trends) and exec_report.py can't drift apart. Dependency-free,
like email_types.py and discovery_classes.py.

Counted as distinct accounts that are enabled or of unknown status
(cloud-only accounts carry no AD enabled flag): a disabled account can't be
used, so it isn't anyone's action item. Factors deliberately left out:
INSUFFICIENT_PASSWORD_ROTATION (no forced password expiry, per current
guidance), SHARED_USER (mostly false positives: without VDI, staff at the
smaller sites hop between ward machines and get flagged as "shared"),
INACTIVE_ACCOUNT (overlaps STALE_ACCOUNT) and the technical ones above --
all still on the Grafana dashboards and in the action packs.
"""
import re
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Sequence, Tuple


class Category(NamedTuple):
    key: str
    group: str            # "compromise" | "exposure"
    label: str
    factors: List[str]    # any of these Falcon risk factors ([] = no factor condition)
    action: str
    kinds: Optional[Tuple[str, ...]] = None   # only these account kinds (None = all)
    where: Optional[str] = None                # extra SQL condition on the ent CTE's columns


GROUPS: Dict[str, str] = {
    "compromise": "Signs of compromise or attack -- act now",
    "exposure": "Exposure -- fix to reduce risk",
}

CATEGORIES: List[Category] = [
    Category("stolen_credentials", "compromise", "Stolen credentials", ["CREDENTIAL_THEFT"],
             "Reset the password and revoke sessions; check recent sign-ins and the device it was taken from."),
    Category("password_attacks", "compromise", "Targeted by password attacks",
             ["PASSWORD_BRUTE_FORCE", "CREDENTIAL_SCANNING"],
             "Confirm MFA is on and the password is strong; block the source if it's ongoing."),
    Category("suspicious_signins", "compromise", "Suspicious sign-ins",
             ["BAD_IP_REPUTATION_USAGE", "GEO_ANOMALY", "SUSPICIOUS_CLOUD_ACTIVITY_ML"],
             "Check with the user; reset and revoke sessions if they don't recognise it."),
    Category("dormant_account_used", "compromise", "Dormant account suddenly in use", ["STALE_ACCOUNT_USAGE"],
             "Confirm who's using it -- a long-unused account waking up is a classic takeover sign."),
    Category("attacker_techniques", "compromise", "Attacker techniques detected",
             ["PASS_THE_HASH", "LATERAL_MOVEMENT", "NTLM_MOVEMENTS", "LDAP_RECONNAISSANCE", "REMOTE_CODE_EXECUTION"],
             "Treat as a possible incident: escalate to the cyber team."),
    Category("no_mfa", "exposure", "People without MFA", ["ACCOUNT_WITHOUT_MFA_CONFIGURED"],
             "Enrol the user. Service accounts and mailboxes are excluded here -- they're a separate review list "
             "in the action pack (often accounts that shouldn't be cloud-synced at all).",
             kinds=("human", "generic")),
    Category("weak_passwords", "exposure", "Weak passwords", ["WEAK_PASSWORD"],
             "Have the user set a stronger password (passphrase)."),
    Category("reused_passwords", "exposure", "Reused passwords", ["DUPLICATE_PASSWORD"],
             "Accounts sharing a password with another account -- often legacy setup or technician shortcuts. "
             "Reset each to a unique password."),
    Category("stale_accounts", "exposure", "Stale accounts", ["STALE_ACCOUNT"],
             "Disable or remove accounts no longer needed (these are still enabled)."),
    Category("privilege_paths", "exposure", "Path to admin rights or hidden privileges",
             ["HAS_ATTACK_PATH", "STEALTHY_PRIVILEGES"],
             "Remove unneeded group memberships and delegated rights."),
    Category("generic_accounts", "exposure", "Generic accounts still enabled", [],
             "Shared logons nobody is accountable for: replace with named accounts, or disable.",
             kinds=("generic",)),
    Category("access_accounts", "exposure", "Extra VPN / remote-app accounts in the shared domain", [],
             "Second accounts in the shared domain that exist only for VPN or remote apps (MANAD). Disable the "
             "unused ones now; the rest go when VPN moves to Azure authentication.",
             where="access_account IS NOT NULL"),
]

# ---------------------------------------------------------- access accounts
# Sites with their own AD domain also have accounts in the shared domain
# purely so staff can use the VPN or remote apps (MANAD over RDS) hosted
# there. Tagged in identity_entities.access_account: 'vpn', 'rds',
# 'vpn+rds', or 'legacy' (neither group -- older provisioning nobody's sure
# of). Config: collectors.falcon_identity.access_domain.
DEFAULT_ACCESS: Dict[str, Any] = {
    "vpn_groups": [r"ssl-vpn.*"],
    "rds_groups": [r".*manad.*", r".*remote (users|desktop).*", r".*terminal server.*", r".*(?<![a-z])(rds|rdp)(?![a-z]).*"],
}
ACCESS_LABEL = {"vpn": "VPN", "rds": "Remote apps (RDS/MANAD)", "vpn+rds": "VPN + remote apps", "legacy": "Legacy / unknown"}


def classify_access(cfg: Optional[Dict[str, Any]], domain: Optional[str], site_label: str,
                    groups: Iterable[str]) -> Optional[str]:
    """None unless the account is in the shared access domain but belongs to
    a site that isn't native to it."""
    if not cfg or not domain or str(domain).lower() != str(cfg.get("domain", "")).lower():
        return None
    if site_label in set(cfg.get("native_sites") or []) or site_label in ("Ungrouped", "TEST"):
        return None
    pats = {k: [re.compile(f"^(?:{p})$", re.I) for p in cfg.get(k) or DEFAULT_ACCESS[k]]
            for k in ("vpn_groups", "rds_groups")}
    groups = [g for g in groups if g]
    vpn = any(p.match(g) for p in pats["vpn_groups"] for g in groups)
    rds = any(p.match(g) for p in pats["rds_groups"] for g in groups)
    return "vpn+rds" if vpn and rds else "vpn" if vpn else "rds" if rds else "legacy"


# ------------------------------------------------------------- account kinds
# What kind of account each identity is (identity_entities.account_kind),
# so categories can skip the ones that don't apply -- e.g. MFA for service
# accounts and shared mailboxes. Signals, in order (first match wins):
#   1. explicit, configured: OU segment / AD group / account name patterns
#      (collectors.falcon_identity.account_kinds in config.yaml, regexes,
#      matched case-insensitively against WHOLE OU segment / group names --
#      "Corporate Services" is a department, "Service Accounts" isn't)
#   2. Falcon's own behavioural classification: MailboxRole,
#      ProgrammaticUserAccountRole
#   3. otherwise "human"
DEFAULT_KIND_RULES: Dict[str, Dict[str, List[str]]] = {
    "mailbox": {"ou": [r".*shared mailboxes", r"exchange resources", r".*meeting rooms", r"resource bookings",
                       r"generic mail accounts"]},
    "service": {"ou": [r".*service accounts"], "name": [r"svc"]},
    "generic": {"ou": [r"generic (users|accounts|logons)"], "group": [r".*generic.*"]},
}
ROLE_KINDS = {"MailboxRole": "mailbox", "ProgrammaticUserAccountRole": "service"}
KIND_ORDER = ("mailbox", "service", "generic")
PRIVILEGED_ROLES = {
    "AdministratorsRole", "DomainAdminsRole", "EnterpriseAdminsRole", "SchemaAdminsRole", "BuiltinAdministratorRole",
    "AccountOperatorsAdminRole", "BackupOperatorsAdminRole", "ServerOperatorsAdminRole", "PrintOperatorsAdminRole",
    "PasswordResetterAdminRole", "PermissionsControllerAdminRole", "PrivilegedGroupControllerAdminRole",
    "EffectiveReplicatorsAdminRole", "ReplicatorsAdminRole", "KrbtgtAccountAdminRole", "DomainControllersAdminRole",
    "OwnerAdminRole", "KeyCredentialAdminRole", "AzureGlobalPrivilegesRole", "AzurePrivilegedRole",
    "AzureCredentialsPrivilegesRole", "AzureSecurityPrivilegesRole", "AdminAccountRole",
}


def kind_rules(cfg_rules: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, List[re.Pattern]]]:
    """Config overrides defaults per kind+signal. `name` patterns are searches
    within the account name ("svc" anywhere); `ou`/`group` must match a whole
    OU segment / group name."""
    merged = {k: dict(v) for k, v in DEFAULT_KIND_RULES.items()}
    for kind, sig in (cfg_rules or {}).items():
        merged.setdefault(kind, {}).update(sig or {})
    return {kind: {sigk: [re.compile(p if sigk == "name" else f"^(?:{p})$", re.I) for p in pats]
                   for sigk, pats in sigs.items()} for kind, sigs in merged.items()}


def classify_account(rules, ou_path: Optional[str], groups: Iterable[str], name: Optional[str],
                     roles: Iterable[str]) -> Tuple[str, bool]:
    """-> (account_kind, is_privileged)."""
    segs = [x.strip() for x in (ou_path or "").replace("\\", "/").split("/") if x.strip()]
    groups, roles = [g for g in groups if g], set(roles)
    privileged = bool(roles & PRIVILEGED_ROLES)
    for kind in KIND_ORDER:
        r = rules.get(kind) or {}
        if (any(p.match(x) for p in r.get("ou", []) for x in segs)
                or any(p.match(g) for p in r.get("group", []) for g in groups)
                or (name and any(p.search(name) for p in r.get("name", [])))):
            return kind, privileged
    for role, kind in ROLE_KINDS.items():
        if role in roles:
            return kind, privileged
    return "human", privileged


ENABLED_FILTER = "e.enabled IS NOT FALSE"


def sql_in(values) -> str:
    return "(" + ", ".join("'%s'" % v.replace("'", "''") for v in values) + ")"


def group_factors(group: str) -> List[str]:
    return [f for c in CATEGORIES if c.group == group for f in c.factors]


def _cond(c: Category) -> str:
    parts = [c.where] if c.where else []
    if c.factors:
        parts.append(f"facs && ARRAY{[f for f in c.factors]}::text[]")
    if c.kinds:
        parts.append(f"account_kind IN {sql_in(c.kinds)}")
    return " AND ".join(parts) or "TRUE"


def counts_sql(site_condition: str = "TRUE", by_site: bool = False) -> str:
    """One query counting every category and group: distinct enabled (or
    unknown-status) accounts. `site_condition` filters e.site_label;
    by_site adds a leading site_label column. Columns follow CATEGORIES,
    then GROUPS. Shared by rollup_daily_metrics.py and exec_report.py so
    the history and the report count the same way."""
    cols = [f"count(*) FILTER (WHERE {_cond(c)})" for c in CATEGORIES]
    cols += ["count(*) FILTER (WHERE " + " OR ".join(f"({_cond(c)})" for c in CATEGORIES if c.group == g) + ")"
             for g in GROUPS]
    lead = "site_label, " if by_site else ""
    return f"""
        WITH ent AS (
            SELECT e.site_label, e.entity_id, COALESCE(e.account_kind, 'human') AS account_kind, e.access_account,
                   COALESCE(array_agg(f.factor_type) FILTER (WHERE f.factor_type IS NOT NULL), '{{}}') AS facs
            FROM identity_entities e
            LEFT JOIN identity_risk_factors f ON f.source = e.source AND f.entity_id = e.entity_id
            WHERE NOT e.retired AND {ENABLED_FILTER} AND ({site_condition})
              AND COALESCE(e.account_kind, 'human') <> 'out_of_scope'
            GROUP BY e.site_label, e.entity_id, e.account_kind, e.access_account)
        SELECT {lead}{", ".join(cols)} FROM ent {"GROUP BY site_label" if by_site else ""}"""


# An infostealer leak only matters if the account it names is one of ours and
# still enabled (matched on UPN or username to the leaked address's local
# part). Most are already-disabled staff accounts or not ours at all (school,
# university and personal addresses), i.e. noise. Hadrian names only the first
# leaked account in the title, so that's what's checked.
ACTIVE_LEAK_SQL = r"""EXISTS (
    SELECT 1 FROM identity_entities ie
    WHERE NOT ie.retired AND ie.enabled IS NOT FALSE
      AND lower(substring(vf.title from '([A-Za-z0-9._%%+''-]+)@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'))
          IN (lower(split_part(ie.upn, '@', 1)), lower(ie.sam_account_name)))"""
# (vf = the vuln_findings row of a Hadrian InfectedDevice risk. %% because
# it's always run through psycopg2 with parameters.)
