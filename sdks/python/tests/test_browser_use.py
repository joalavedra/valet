"""Adapter tests: invoke valet_login through the real Tools registry."""

import json
import os
from unittest.mock import AsyncMock, create_autospec

import httpx
import pytest

bu = pytest.importorskip("browser_use")

from browser_use import BrowserSession, Tools  # noqa: E402

from valet.browser_use import register_valet_tools  # noqa: E402
from valet.client import ValetClient  # noqa: E402

TOKEN = "vlt_secret"


def fake_session(url="https://the-internet.herokuapp.com/login", cdp="http://127.0.0.1:9222", tid="T1"):
    s = create_autospec(BrowserSession, instance=True)
    s.get_current_page_url = AsyncMock(return_value=url)
    s.cdp_url = cdp
    s.agent_focus_target_id = tid
    return s


def client_with(handler):
    c = ValetClient("http://valet.test", token=TOKEN)
    c._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return c


async def test_valet_login_invocation():
    calls = {}

    def h(r: httpx.Request) -> httpx.Response:
        body = json.loads(r.content)
        if r.url.path == "/v1/grants":
            calls["grant"] = body
            return httpx.Response(200, json={"token": "g.sig"})
        if r.url.path == "/v1/edge/browser/fill":
            calls["fill"] = body
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(404)

    tools = register_valet_tools(Tools(), client_with(h))
    out = await tools.registry.execute_action(
        "valet_login",
        {"handle": "cred://the-internet.herokuapp.com/demo", "mapping": {"username": "#u"}, "submit": "button"},
        browser_session=fake_session(),
    )
    assert out.error is None
    assert "ok" in (out.extracted_content or "")
    assert calls["grant"]["policy"] == {"hosts": ["the-internet.herokuapp.com"], "max_uses": 1}
    assert calls["grant"]["ttl"] == 600
    assert calls["fill"]["cdp_ws_url"] == "ws://127.0.0.1:9222/devtools/page/T1"
    assert calls["fill"]["grant_token"] == "g.sig"
    assert calls["fill"]["submit"] == "button"


async def test_valet_login_ws_scheme_wss():
    def h(r: httpx.Request) -> httpx.Response:
        if r.url.path == "/v1/grants":
            return httpx.Response(200, json={"token": "t"})
        if r.url.path == "/v1/edge/browser/fill":
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(404)

    calls = {}

    def cap(r: httpx.Request) -> httpx.Response:
        if r.url.path == "/v1/edge/browser/fill":
            calls.update(json.loads(r.content))
        return h(r)

    tools = register_valet_tools(Tools(), client_with(cap), cdp_url="https://127.0.0.1:9222")
    await tools.registry.execute_action(
        "valet_login",
        {"handle": "cred://x/y", "mapping": {}},
        browser_session=fake_session(cdp="https://127.0.0.1:9222"),
    )
    assert calls["cdp_ws_url"] == "wss://127.0.0.1:9222/devtools/page/T1"


async def test_valet_login_error_status():
    def h(r: httpx.Request) -> httpx.Response:
        if r.url.path == "/v1/grants":
            return httpx.Response(200, json={"token": "t"})
        return httpx.Response(200, json={"status": "captcha"})

    tools = register_valet_tools(Tools(), client_with(h))
    out = await tools.registry.execute_action(
        "valet_login",
        {"handle": "cred://x/y", "mapping": {}},
        browser_session=fake_session(),
    )
    assert out.error and "captcha" in out.error


async def test_valet_list_handles():
    def h(r: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"handles": [{"handle": "cred://x/y", "type": "login"}]})

    tools = register_valet_tools(Tools(), client_with(h))
    out = await tools.registry.execute_action("valet_list_handles", {})
    assert "cred://x/y" in out.extracted_content


@pytest.mark.skipif(os.environ.get("VALET_E2E") != "1", reason="e2e requires live valet+chrome")
async def test_e2e_login():
    pytest.skip("e2e harness not run in CI")
