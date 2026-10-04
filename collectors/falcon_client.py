#!/usr/bin/env python3
"""
Shared CrowdStrike Falcon API client (OAuth2 client credentials). One API
client can serve every Falcon collector if it has all the scopes below;
splitting into per-collector clients also works -- each collector reads
`crowdstrike` credentials unless its own block overrides them.

Scopes (API client, READ unless noted):
  Hosts, Host groups              -> falcon_hosts
  Assets (Discover)               -> falcon_hosts (unmanaged assets, optional)
  Vulnerabilities                 -> falcon_spotlight
  Alerts                          -> falcon_alerts
  Identity Protection Entities,
  Identity Protection GraphQL (WRITE -- CrowdStrike's naming; it's read-only use)
                                  -> falcon_identity
"""
from typing import Any, Dict, Iterator, List, Optional

from http_client import TokenCache, make_session, raise_for_status


class FalconClient:
    def __init__(self, cfg: Dict[str, Any], ccfg: Optional[Dict[str, Any]] = None):
        cs = dict(cfg.get("crowdstrike") or {})
        cs.update({k: v for k, v in (ccfg or {}).items() if k in ("client_id", "client_secret", "base_url")})
        self.base = cs.get("base_url", "https://api.us-2.crowdstrike.com").rstrip("/")
        self._cid = cs.get("client_id")
        self._secret = cs.get("client_secret")
        if not self._cid or not self._secret:
            raise RuntimeError("crowdstrike.client_id / client_secret missing from secrets.yaml")
        self.s = make_session(timeout=int(cs.get("timeout", 120)))
        self._tok = TokenCache(self._fetch_token)
        self._group_names: Optional[Dict[str, str]] = None

    def _fetch_token(self):
        r = self.s.post(f"{self.base}/oauth2/token",
                        data={"client_id": self._cid, "client_secret": self._secret})
        raise_for_status(r, "Falcon auth")
        j = r.json()
        return j["access_token"], j.get("expires_in", 1799)

    def _h(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self._tok.get()}", "Accept": "application/json"}

    def get(self, path: str, params: Any = None) -> Dict[str, Any]:
        r = self.s.get(f"{self.base}{path}", headers=self._h(), params=params)
        if r.status_code == 401:
            self._tok.invalidate()
            r = self.s.get(f"{self.base}{path}", headers=self._h(), params=params)
        raise_for_status(r, "Falcon")
        return r.json()

    def post(self, path: str, body: Any, params: Any = None) -> Dict[str, Any]:
        r = self.s.post(f"{self.base}{path}", headers=self._h(), json=body, params=params)
        if r.status_code == 401:
            self._tok.invalidate()
            r = self.s.post(f"{self.base}{path}", headers=self._h(), json=body, params=params)
        raise_for_status(r, "Falcon")
        return r.json()

    # ---- pagination helpers ---------------------------------------------
    def iter_offset_ids(self, path: str, params: Dict[str, Any], limit: int = 500) -> Iterator[str]:
        """Classic offset/total pagination over a /queries/ endpoint."""
        offset = 0
        while True:
            p = dict(params, limit=limit, offset=offset)
            j = self.get(path, p)
            ids = j.get("resources") or []
            yield from ids
            total = (j.get("meta", {}).get("pagination") or {}).get("total")
            offset += len(ids)
            if not ids or (total is not None and offset >= total):
                break

    def iter_scroll_ids(self, path: str, params: Dict[str, Any], limit: int = 5000) -> Iterator[str]:
        """String-offset ("scroll") pagination, e.g. devices-scroll -- no 10k cap."""
        offset: Optional[str] = None
        while True:
            p = dict(params, limit=limit)
            if offset:
                p["offset"] = offset
            j = self.get(path, p)
            ids = j.get("resources") or []
            yield from ids
            offset = (j.get("meta", {}).get("pagination") or {}).get("offset")
            if not ids or not offset:
                break

    def iter_after(self, path: str, params: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
        """`after` cursor pagination (Spotlight combined endpoints)."""
        after: Optional[str] = None
        while True:
            p = dict(params)
            if after:
                p["after"] = after
            j = self.get(path, p)
            res = j.get("resources") or []
            yield from res
            after = (j.get("meta", {}).get("pagination") or {}).get("after")
            if not res or not after:
                break

    # ---- lookups -------------------------------------------------------
    def host_group_names(self) -> Dict[str, str]:
        """group id -> name. Hosts API returns group IDs only."""
        if self._group_names is None:
            names: Dict[str, str] = {}
            offset = 0
            while True:
                j = self.get("/devices/combined/host-groups/v1", {"limit": 500, "offset": offset})
                res = j.get("resources") or []
                for g in res:
                    names[g.get("id")] = g.get("name")
                offset += len(res)
                total = (j.get("meta", {}).get("pagination") or {}).get("total")
                if not res or (total is not None and offset >= total):
                    break
            self._group_names = names
        return self._group_names

    def group_labels(self, groups: List[Any]) -> List[str]:
        """Normalise a groups field that may be ids, names, or {id,name} dicts."""
        out = []
        names = None
        for g in groups or []:
            if isinstance(g, dict):
                if g.get("name"):
                    out.append(g["name"])
                    continue
                g = g.get("id")
            if not g:
                continue
            if names is None:
                try:
                    names = self.host_group_names()
                except Exception:
                    names = {}
            out.append(names.get(g, g))
        return out
