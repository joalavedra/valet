"""browser-use adapter: registers Valet actions on a Tools registry.

Import is lazy — the base package works without browser-use installed.
"""


import json
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from .client import ValetClient, ValetError

if TYPE_CHECKING:  # pragma: no cover
    from browser_use.tools.service import Tools


def _page_ws(cdp_url: str, target_id: str) -> str:
    """Derive the page-level devtools websocket URL for a target id."""
    u = urlparse(cdp_url)
    hostport = u.netloc or u.path.split("/")[0]
    scheme = "wss" if u.scheme == "wss" or u.scheme == "https" else "ws"
    return f"{scheme}://{hostport}/devtools/page/{target_id}"


def register_valet_tools(tools: "Tools", client: ValetClient, *, cdp_url: str | None = None) -> "Tools":
    """Register valet_list_handles and valet_login on a browser-use Tools."""
    from browser_use import BrowserSession
    from browser_use.agent.views import ActionResult

    @tools.action("List the credential handles available to this agent via Valet. Returns handle URIs and metadata only — never secret values.")
    async def valet_list_handles() -> ActionResult:
        try:
            handles = await client.list_handles()
        except ValetError as e:
            return ActionResult(error=str(e))
        return ActionResult(
            extracted_content=json.dumps(handles),
            long_term_memory=f"Valet handles: {json.dumps(handles)}",
        )

    @tools.action(
        "Log in to the currently focused page using a Valet credential handle. "
        "Valet types the real credentials into the form fields itself over CDP; "
        "the credentials are NEVER returned to you — only a status string."
    )
    async def valet_login(
        handle: str,
        mapping: dict[str, str],
        submit: str | None = None,
        ttl: str = "10m",
        browser_session: BrowserSession = None,
    ) -> ActionResult:
        try:
            page_url = await browser_session.get_current_page_url()
            host = urlparse(page_url).hostname
            if not host:
                return ActionResult(error="no page focused")
            grant = await client.request_grant(
                handle,
                policy={"hosts": [host], "max_uses": 1},
                ttl=ttl,
            )
            ws_source = cdp_url or browser_session.cdp_url
            ws = _page_ws(ws_source, browser_session.agent_focus_target_id)
            res = await client.browser_fill(grant["token"], ws, mapping, submit)
            status = res.get("status", "unknown")
            if status != "ok":
                return ActionResult(error=f"valet_login status={status}")
            return ActionResult(
                extracted_content=f"valet_login status={status}",
                long_term_memory=f"Logged in via Valet on {host} (status={status}); credentials were typed by Valet, never returned.",
            )
        except ValetError as e:
            return ActionResult(error=str(e))
        except Exception as e:
            return ActionResult(error=f"valet_login failed: {e}")

    return tools
