"""Async HTTP client for the Valet control-plane API."""

from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import urlparse

import httpx

_DURATION_RE = re.compile(r"^(\d+)(s|m|h|d)?$")
_MULTIPLIERS = {"s": 1, "m": 60, "h": 3600, "d": 86400, None: 1}


def ttl_seconds(ttl: str) -> int:
    """Convert a duration string like "30m" to seconds."""
    m = _DURATION_RE.match(ttl.strip())
    if not m:
        raise ValetError(f"invalid ttl {ttl!r}")
    return int(m.group(1)) * _MULTIPLIERS[m.group(2)]


class ValetError(Exception):
    """Error from the Valet API. Carries status and the server's error field.

    The agent token is never included in the message.
    """

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status
        self.error = message


class ValetClient:
    def __init__(self, base_url: str | None = None, token: str | None = None, timeout: float = 90.0):
        self.base_url = (base_url or os.environ.get("VALET_ADDR") or "http://127.0.0.1:14400").rstrip("/")
        u = urlparse(self.base_url)
        if (
            u.scheme == "http"
            and u.hostname not in {"127.0.0.1", "localhost", "::1"}
            and os.environ.get("VALET_ALLOW_INSECURE") != "1"
        ):
            raise ValueError(
                "VALET_ADDR uses plain http to a non-loopback host; use https or set VALET_ALLOW_INSECURE=1"
            )
        self.token = token or os.environ.get("VALET_AGENT_TOKEN")
        self._http = httpx.AsyncClient(timeout=timeout)

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _request(self, method: str, path: str, body: dict | None = None) -> Any:
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        resp = await self._http.request(method, self.base_url + path, json=body, headers=headers)
        try:
            data = resp.json()
        except Exception:
            data = None
        if resp.status_code >= 400:
            msg = data.get("error") if isinstance(data, dict) else None
            if self.token:
                msg = (msg or resp.text or "").replace(self.token, "[redacted]")
            raise ValetError(msg or f"http {resp.status_code}", status=resp.status_code)
        return data

    async def list_handles(self) -> list[dict]:
        data = await self._request("GET", "/v1/handles")
        return data.get("handles", []) if isinstance(data, dict) else []

    async def request_grant(
        self,
        handle: str,
        policy: dict | None = None,
        ttl: str | None = None,
        max_uses: int | None = None,
    ) -> dict:
        body: dict[str, Any] = {"handle": handle, "policy": policy or {}}
        if ttl is not None:
            body["ttl"] = ttl_seconds(ttl)
        if max_uses is not None:
            body["max_uses"] = max_uses
        return await self._request("POST", "/v1/grants", body)

    async def browser_fill(
        self,
        grant_token: str,
        cdp_ws_url: str,
        mapping: dict[str, str],
        submit: str | None = None,
    ) -> dict:
        body: dict[str, Any] = {"grant_token": grant_token, "cdp_ws_url": cdp_ws_url, "mapping": mapping}
        if submit is not None:
            body["submit"] = submit
        return await self._request("POST", "/v1/edge/browser/fill", body)

    async def http_call(
        self,
        grant_token: str,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str | None = None,
    ) -> dict:
        payload: dict[str, Any] = {"grant_token": grant_token, "method": method, "url": url}
        if headers:
            payload["headers"] = headers
        if body is not None:
            payload["body"] = body
        return await self._request("POST", "/v1/edge/http/call", payload)
