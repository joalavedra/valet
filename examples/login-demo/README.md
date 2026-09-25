# login-demo

End-to-end demo of the browser edge: an agent fills the public test login
page at https://the-internet.herokuapp.com/login without ever seeing the
password.

## What it shows

1. `valet server` holds an envelope-encrypted login credential
   (`tomsmith` / `SuperSecretPassword!`, TOTP seed stored but unused on this page).
2. An agent token gets a grant scoped to `the-internet.herokuapp.com`.
3. Headless Chrome runs with `--remote-debugging-port`; the agent hands its
   CDP websocket URL to Valet.
4. Valet verifies the grant, checks the live page host against policy,
   types the real credentials via CDP, clicks submit, and writes an audit
   row. The agent's context only ever contains the handle and selectors.

## Run

```bash
./run.sh
```

Requires the `valet` binary in the repo root (`make build`), `google-chrome`,
`curl`, and `jq` (optional — falls back to grep).

## Files

- `run.sh` — full scripted walkthrough (server, chrome, curl calls).

The demo uses a temporary database under `~/.valet/` and leaves Chrome and
`valet server` stopped when it exits.
