#!/usr/bin/env python3
"""Shared config loader: config.yaml + gitignored secrets.yaml.

Every top-level section in secrets.yaml is deep-merged over the matching
section in config.yaml, so a new collector only needs its credentials
added to secrets.yaml -- no change here.
"""
import os
from typing import Any, Dict

import yaml


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        elif _named_list(v) and _named_list(base.get(k)):
            # lists of {name: ...} dicts (e.g. entra tenants) merge by name,
            # so secrets.yaml only has to carry the credential fields
            by_name = {d["name"]: d for d in base[k]}
            for item in v:
                if item["name"] in by_name:
                    _deep_merge(by_name[item["name"]], item)
                else:
                    base[k].append(item)
        else:
            base[k] = v
    return base


def _named_list(v: Any) -> bool:
    return isinstance(v, list) and bool(v) and all(isinstance(i, dict) and "name" in i for i in v)


def load_config(path: str = "config.yaml") -> Dict[str, Any]:
    with open(path, "r") as f:
        cfg = yaml.safe_load(f) or {}

    secrets_rel = cfg.get("secrets_file")
    if secrets_rel:
        base_dir = os.path.dirname(os.path.abspath(path))
        secrets_path = os.path.join(base_dir, secrets_rel)
        if not os.path.isfile(secrets_path):
            raise FileNotFoundError(f"Secrets file not found: {secrets_path}")
        with open(secrets_path, "r") as sf:
            secrets = yaml.safe_load(sf) or {}
        _deep_merge(cfg, secrets)

    cfg["_config_dir"] = os.path.dirname(os.path.abspath(path))
    return cfg


def collector_cfg(cfg: Dict[str, Any], name: str) -> Dict[str, Any]:
    """The `collectors.<name>` block, or {} if absent."""
    return (cfg.get("collectors") or {}).get(name) or {}
