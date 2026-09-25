"""Example: browser-use agent logs in via Valet — the agent never sees the password.

Requires:
  - `valet server` running with a stored login cred cred://the-internet.herokuapp.com/demo
  - headless Chrome: google-chrome --headless=new --remote-debugging-port=9222 \
      --user-data-dir=/tmp/valet-demo-profile "https://the-internet.herokuapp.com/login"
  - OPENAI_API_KEY set (or pick another LLM)
"""

import asyncio
import os

from browser_use import Agent, BrowserSession, ChatOpenAI, Tools

from valet.browser_use import register_valet_tools
from valet.client import ValetClient


async def main() -> None:
    client = ValetClient()
    session = BrowserSession(cdp_url=os.environ.get("CDP_URL", "http://127.0.0.1:9222"))
    tools = register_valet_tools(Tools(), client, cdp_url=session.cdp_url or "http://127.0.0.1:9222")
    agent = Agent(
        task=(
            "Log in to the-internet.herokuapp.com/login using the Valet handle "
            "cred://the-internet.herokuapp.com/demo; call valet_login with mapping "
            "{username:'#username', password:'#password'} and submit 'button[type=submit]'"
        ),
        llm=ChatOpenAI(model=os.environ.get("VALET_DEMO_MODEL", "gpt-4o-mini")),
        browser_session=session,
        tools=tools,
    )
    await agent.run()


if __name__ == "__main__":
    asyncio.run(main())
