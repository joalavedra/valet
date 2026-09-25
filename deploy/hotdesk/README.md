# Valet inside hotdesk

A drop-in desktop image that bundles `valet` into hotdesk's
`hotdesk-desktop` image — no changes to jamalavedra/hotdesk required.
The `valet server` runs inside the desktop under supervisor, with its
state in the persistent `/home/cua` volume, and Valet's browser edge
talks to the desktop's Chromium via its built-in CDP on `127.0.0.1:9222`.

## Build

```bash
# 1. Build hotdesk's base image once (find its tag with `docker images`)
cd /path/to/hotdesk
docker build -t hotdesk-desktop:dev --build-arg HOTDESK_VERSION=dev desktop/
# or: uv run hotdesk up  # builds hotdesk-desktop:<version> itself

# 2. Build the valet variant
valet-hotdesk build hotdesk-desktop:dev hotdesk-desktop-valet:dev
```

By default the Dockerfile builds valet from this repo's source. To bundle a
published release instead (no Go toolchain stage):

```bash
docker build -f deploy/hotdesk/Dockerfile \
  --build-arg BASE=hotdesk-desktop:dev \
  --build-arg VALET_SRC=release --build-arg VALET_VERSION=0.1.0 \
  -t hotdesk-desktop-valet:dev .
```

## Configure hotdesk

In your workspace's `hotdesk.toml`:

```toml
[project]
image = "hotdesk-desktop-valet:dev"
```

Then `uv run hotdesk apply` / `hotdesk up` as usual. The valet server
starts via supervisor (`hotdesk-valet`, priority 55) listening on
`127.0.0.1:14400` inside the container.

## Provision credentials

All admin commands go through `valet-hotdesk exec <workspace> ...`, which
runs `valet` inside the desktop's container (waits up to 30s for the
supervised server to be ready first):

```bash
valet-hotdesk exec research agent create claude   # prints the agent token once
valet-hotdesk exec research cred add --type login --site the-internet.herokuapp.com --label tomsmith
```

Secrets are encrypted at rest in the desktop's `/home/cua` volume (master
key in `/home/cua/.valet/master.key`) — they're part of the volume, so
they ride along in hotdesk checkpoints and clones.

## Connect an agent

Only hotdesk's gateway port (8001) is published, so agents reach Valet's
MCP over stdio via `docker exec`. MCP client config:

```json
{
  "command": "/path/to/valet/deploy/hotdesk/valet-hotdesk",
  "args": ["mcp", "research"],
  "env": {"VALET_AGENT_TOKEN": "vlt_..."}
}
```

`valet mcp` proxies to the in-container `valet server` at
`http://127.0.0.1:14400` (`VALET_ADDR` default).

## Agent flow

1. Navigate with hotdesk's own browser tools (`browser_navigate`).
2. `request_grant` for the credential handle.
3. `browser_fill` with `page_url` (the tab's URL) — no `cdp_ws_url`
   needed: the server falls back to `VALET_CDP_URL` and picks the tab
   matching `page_url`. Credentials are typed into the page; the agent
   only ever sees handles and a status string.
