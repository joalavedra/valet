import httpx
import pytest

from valet.client import ValetClient, ValetError, ttl_seconds

TOKEN = "vlt_secret"


def make_client(handler):
    c = ValetClient("https://valet.test", token=TOKEN)
    c._http = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="")
    return c


@pytest.mark.parametrize("ttl,want", [("30m", 1800), ("10s", 10), ("2h", 7200), ("600", 600)])
def test_ttl_seconds(ttl, want):
    assert ttl_seconds(ttl) == want


def test_ttl_invalid():
    with pytest.raises(ValetError):
        ttl_seconds("banana")


async def test_request_grant_payload():
    got = {}

    def h(r: httpx.Request) -> httpx.Response:
        import json

        got["body"] = json.loads(r.content)
        got["auth"] = r.headers.get("Authorization")
        return httpx.Response(200, json={"token": "g.sig", "grant_id": "g1"})

    c = make_client(h)
    out = await c.request_grant("cred://x/y", policy={"hosts": ["x.com"]}, ttl="30m", max_uses=2)
    assert got["body"]["ttl"] == 1800
    assert got["body"]["max_uses"] == 2
    assert got["body"]["handle"] == "cred://x/y"
    assert got["auth"] == f"Bearer {TOKEN}"
    assert out["token"] == "g.sig"


async def test_error_surfaces_server_error_not_token():
    def h(r: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": f"invalid Authorization: Bearer {TOKEN}"})

    c = make_client(h)
    with pytest.raises(ValetError) as ei:
        await c.list_handles()
    assert ei.value.status == 403
    assert TOKEN not in str(ei.value)
    assert "[redacted]" in str(ei.value)


async def test_browser_fill_payload():
    got = {}

    def h(r: httpx.Request) -> httpx.Response:
        import json

        got["body"] = json.loads(r.content)
        got["path"] = r.url.path
        return httpx.Response(200, json={"status": "ok"})

    c = make_client(h)
    res = await c.browser_fill("g.sig", "ws://127.0.0.1:9222/devtools/page/T1", {"username": "#u"}, "button")
    assert got["path"] == "/v1/edge/browser/fill"
    b = got["body"]
    assert b["grant_token"] == "g.sig"
    assert b["cdp_ws_url"] == "ws://127.0.0.1:9222/devtools/page/T1"
    assert b["mapping"] == {"username": "#u"}
    assert b["submit"] == "button"
    assert res["status"] == "ok"


async def test_http_call_payload():
    got = {}

    def h(r: httpx.Request) -> httpx.Response:
        import json

        got["body"] = json.loads(r.content)
        return httpx.Response(200, json={"status": 200, "body": "ok"})

    c = make_client(h)
    await c.http_call("g", "GET", "https://api.x/v1", headers={"A": "1"})
    assert got["body"]["grant_token"] == "g"
    assert got["body"]["headers"] == {"A": "1"}
