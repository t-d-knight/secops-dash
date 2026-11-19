"""
Restricted read access for the Grafana Remediation org (knowledge-base/grafana-access.md).

Grafana OSS can't stop a viewer sending any SQL through a data source, so the
technicians' data source logs in as its own Postgres role, and that role can
only read the `remediation` schema: one view per table the remediation
dashboards (DASHBOARDS) read, named like the table. With the role's
search_path set to `remediation, public`, the dashboards' unqualified SQL
resolves to these views and runs unchanged. Nothing in `public` is granted to
it, so identity, USB, email, alerts and the action log stay out of reach.

FILTERS narrows rows: `assets` drops managed workstations (and with them
workstation last-logon names). Unmanaged machines stay, for missing sensors.

Opt-in: set grafana.remediation_role in config.yaml to a role a DBA has
created (see the doc). Without it, or if the role doesn't exist yet, nothing
happens. ensure_schema() calls ensure_views() last, in its own transaction, so
views dropped by the schema DDL (CASCADE) come straight back; the nightly
dash_* rebuild drops and recreates its views around each table swap.
"""
from typing import Any, Dict, List

from psycopg2 import sql

SCHEMA = "remediation"
# grafana/*.json files without .json: the dashboards the Remediation org gets
DASHBOARDS = ("secops-servers", "secops-patch-compliance", "vuln-dashboard")
# Every relation those dashboards read (tests/run_e2e.py runs their SQL as a
# role that can only see these, so a missing one fails the test).
OBJECTS = (
    "assets", "dim_site", "host_insights", "host_patch_status", "vuln_findings", "sla_policy",
    "dash_asset_risk", "dash_nvd_coverage", "dash_patch_impact", "dash_vuln_kev_epss", "dash_vuln_site_summary",
    "daily_epss_metrics", "daily_kev_metrics", "daily_mttr_metrics", "daily_product_metrics", "daily_site_metrics",
    "daily_sla_metrics", "daily_vuln_flow_metrics",
    "lm_devices", "lm_device_patch", "server_patch_compliance", "server_patch_compliance_status",
)
FILTERS = {
    # servers, DCs, cloud and external assets, and unmanaged machines (missing sensors); not managed workstations
    "assets": "NOT (source = 'falcon' AND product_type = 'workstation')",
}


def role_name(cfg: Dict[str, Any]) -> str:
    return str((cfg.get("grafana") or {}).get("remediation_role") or "").strip()


def _schema_exists(cur) -> bool:
    cur.execute("SELECT 1 FROM pg_namespace WHERE nspname = %s", (SCHEMA,))
    return cur.fetchone() is not None


def _create_view(cur, name: str, grantees: List[str]) -> None:
    where = FILTERS.get(name)
    q = sql.SQL("CREATE VIEW {s}.{v} {opt} AS SELECT * FROM public.{v}").format(
        s=sql.Identifier(SCHEMA), v=sql.Identifier(name),
        opt=sql.SQL("WITH (security_barrier)" if where else ""))
    if where:
        q = q + sql.SQL(" WHERE " + where)
    cur.execute(sql.SQL("DROP VIEW IF EXISTS {s}.{v}").format(s=sql.Identifier(SCHEMA), v=sql.Identifier(name)))
    cur.execute(q)
    for g in grantees:
        cur.execute(sql.SQL("GRANT SELECT ON {s}.{v} TO {g}").format(
            s=sql.Identifier(SCHEMA), v=sql.Identifier(name), g=sql.Identifier(g)))


def set_aside(cur) -> List[str]:
    """Start of ensure_schema(): drop the schema (its views would block the DDL that drops
    and recreates the tables and views underneath) and return the roles that could use it,
    so ensure_views() gives them the same access back in the same transaction."""
    if not _schema_exists(cur):
        return []
    cur.execute("SELECT DISTINCT g.rolname FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) a "
                "JOIN pg_roles g ON g.oid = a.grantee WHERE n.nspname = %s AND a.privilege_type = 'USAGE' "
                "AND g.rolname <> current_user", (SCHEMA,))
    roles = [r[0] for r in cur.fetchall()]
    cur.execute(sql.SQL("DROP SCHEMA {s} CASCADE").format(s=sql.Identifier(SCHEMA)))
    return roles


def ensure_views(cur, cfg: Dict[str, Any], keep_roles: List[str] = ()) -> str:
    """Create or refresh the remediation schema for grafana.remediation_role, plus any
    roles that already had it (`keep_roles`, from set_aside()). Returns a one-line
    status. Never raises: a problem here mustn't stop collectors.
    To withdraw access: unset the role in config and DROP SCHEMA remediation CASCADE."""
    roles = sorted({r for r in [role_name(cfg), *keep_roles] if r})
    if not roles:
        return "remediation access: off (grafana.remediation_role not set)"
    cur.execute("SAVEPOINT remediation_views")
    try:
        cur.execute("SELECT rolname FROM pg_roles WHERE rolname = ANY(%s)", (roles,))
        found = {r[0] for r in cur.fetchall()}
        missing = [r for r in roles if r not in found]
        roles = [r for r in roles if r in found]
        if not roles:
            cur.execute("RELEASE SAVEPOINT remediation_views")
            return (f"remediation access: role {missing[0]!r} doesn't exist yet -- create it "
                    "(knowledge-base/grafana-access.md)")
        cur.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {s}").format(s=sql.Identifier(SCHEMA)))
        cur.execute(sql.SQL("REVOKE ALL ON SCHEMA {s} FROM PUBLIC").format(s=sql.Identifier(SCHEMA)))
        for r in roles:
            cur.execute(sql.SQL("GRANT USAGE ON SCHEMA {s} TO {r}").format(s=sql.Identifier(SCHEMA), r=sql.Identifier(r)))
        for name in OBJECTS:
            _create_view(cur, name, roles)
        cur.execute("RELEASE SAVEPOINT remediation_views")
        return f"remediation access: {len(OBJECTS)} views in schema {SCHEMA} for role(s) {', '.join(roles)}"
    except Exception as e:  # noqa: BLE001 -- report and carry on
        cur.execute("ROLLBACK TO SAVEPOINT remediation_views")
        return f"remediation access: FAILED ({type(e).__name__}: {e})".splitlines()[0]


def grantees(cur, name: str) -> List[str]:
    cur.execute("SELECT DISTINCT grantee FROM information_schema.role_table_grants "
                "WHERE table_schema = %s AND table_name = %s AND privilege_type = 'SELECT' "
                "AND grantee <> current_user", (SCHEMA, name))
    return [r[0] for r in cur.fetchall()]


def drop_view(cur, name: str) -> List[str]:
    """Before a table swap: drop the remediation view on it (it would block DROP TABLE)
    and return who had SELECT on it, for recreate_view()."""
    if name not in OBJECTS or not _schema_exists(cur):
        return []
    g = grantees(cur, name)
    cur.execute(sql.SQL("DROP VIEW IF EXISTS {s}.{v}").format(s=sql.Identifier(SCHEMA), v=sql.Identifier(name)))
    return g


def recreate_view(cur, name: str, grantees_: List[str]) -> None:
    if name in OBJECTS and grantees_ and _schema_exists(cur):
        _create_view(cur, name, grantees_)
