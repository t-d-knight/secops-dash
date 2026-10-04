#!/usr/bin/env python3
"""Shared Entra ID app-only token helper (client credentials) for Graph and
Log Analytics. One app registration can serve both if it holds the
permissions each collector lists."""
from typing import Any, Dict, Iterator

from http_client import TokenCache, make_session, raise_for_status


class AzureApp:
    def __init__(self, tenant: Dict[str, Any], scope: str):
        self.tenant_id = tenant.get("tenant_id")
        self.client_id = tenant.get("client_id")
        self.secret = tenant.get("client_secret")
        if not (self.tenant_id and self.client_id and self.secret):
            raise RuntimeError(f"tenant '{tenant.get('name')}': tenant_id/client_id/client_secret required")
        self.scope = scope
        # overridable for sovereign clouds (and tests)
        self.login_base = tenant.get("login_base", "https://login.microsoftonline.com").rstrip("/")
        self.graph_base = tenant.get("graph_base", "https://graph.microsoft.com/v1.0").rstrip("/")
        self.la_base = tenant.get("loganalytics_base", "https://api.loganalytics.io/v1").rstrip("/")
        self.s = make_session(timeout=180)
        self.tok = TokenCache(self._fetch)

    def _fetch(self):
        r = self.s.post(
            f"{self.login_base}/{self.tenant_id}/oauth2/v2.0/token",
            data={"grant_type": "client_credentials", "client_id": self.client_id,
                  "client_secret": self.secret, "scope": self.scope},
        )
        raise_for_status(r, "Entra token")
        j = r.json()
        return j["access_token"], j.get("expires_in", 3599)

    def headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.tok.get()}", "Accept": "application/json"}


def graph_iter(app: AzureApp, path_or_url: str, params: Dict[str, Any] = None) -> Iterator[Dict[str, Any]]:
    url = path_or_url if path_or_url.startswith("http") else f"{app.graph_base}{path_or_url}"
    first = True
    while url:
        r = app.s.get(url, headers=app.headers(), params=params if first else None)
        raise_for_status(r, "Graph")
        j = r.json()
        yield from j.get("value") or []
        url = j.get("@odata.nextLink")
        first = False
