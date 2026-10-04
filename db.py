#!/usr/bin/env python3
"""Shared Postgres connection helper."""
from typing import Any, Dict

try:
    import psycopg2
except ImportError:
    psycopg2 = None


def pg_connect(cfg: Dict[str, Any]):
    """Returns an active psycopg2 connection built from cfg['database']."""
    if psycopg2 is None:
        raise RuntimeError("psycopg2 is not installed in this venv")

    db = cfg.get("database", {})
    return psycopg2.connect(
        host=db.get("host", "127.0.0.1"),
        port=db.get("port", 5432),
        dbname=db.get("name", "secops_dashboard"),
        user=db.get("user", "secops_user"),
        password=db.get("password"),
    )
