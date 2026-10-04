#!/usr/bin/env python3
"""
One HTTP session factory for every collector: sane timeouts, and retry with
backoff on 429/5xx (honouring Retry-After), so each collector doesn't grow
its own slightly-different retry loop. Proxy settings come from the usual
HTTPS_PROXY / NO_PROXY environment variables, which requests honours.
"""
import time
from typing import Any, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

DEFAULT_TIMEOUT = 60


class _TimeoutAdapter(HTTPAdapter):
    def __init__(self, *args, timeout: int = DEFAULT_TIMEOUT, **kwargs):
        self._timeout = timeout
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        kwargs.setdefault("timeout", self._timeout)
        return super().send(request, **kwargs)


def make_session(
    *,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = 5,
    verify: Any = True,
    user_agent: str = "secops-dashboard-collector/2.0",
) -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=2,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET", "POST"}),  # vendor query endpoints are read-only POSTs
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = _TimeoutAdapter(max_retries=retry, timeout=timeout)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    s.verify = verify
    s.headers["User-Agent"] = user_agent
    return s


def raise_for_status(r: requests.Response, context: str = "") -> None:
    """raise_for_status, but with the response body in the message -- vendor
    APIs put the actual reason (bad scope, bad filter) in the body."""
    if r.status_code >= 400:
        body = (r.text or "")[:800]
        raise requests.HTTPError(
            f"{context} HTTP {r.status_code} {r.request.method} {r.url}: {body}",
            response=r,
        )


class TokenCache:
    """Tiny bearer-token cache with early refresh."""

    def __init__(self, fetch, skew_seconds: int = 120):
        self._fetch = fetch          # () -> (token, expires_in_seconds)
        self._skew = skew_seconds
        self._token: Optional[str] = None
        self._expires_at = 0.0

    def get(self) -> str:
        if not self._token or time.time() >= self._expires_at - self._skew:
            token, expires_in = self._fetch()
            self._token = token
            self._expires_at = time.time() + float(expires_in or 1800)
        return self._token

    def invalidate(self) -> None:
        self._token = None
